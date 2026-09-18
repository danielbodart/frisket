// Package intercept terminates TLS for the hosts frisket adds credentials to,
// and for nothing else (PLAN.md, decision 4).
//
// The sandbox connected to what it believes is, say, api.github.com: frisket's
// DNS answered that name with the session's service address, and the kernel
// steered the connection here. frisket completes the handshake AS that name,
// with a leaf minted from the per-machine CA the sandbox trusts, reads the
// request, checks it against the route's scope, replaces whatever credential
// the sandbox sent with the real one, and forwards it over a fresh TLS
// connection to the real upstream, verified as any client would verify it.
//
// The credential never enters the sandbox (decision 5): it is added here, on
// the wire, to a request already authorised. A sandbox that goes around
// frisket reaches the real host without it.
package intercept

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielbodart/frisket/internal/steer"
)

// Variables rather than constants only so a test can shrink them and show
// that none of them bounds a stream.
var (
	// handshakeTimeout bounds a ClientHello that never finishes. It is a
	// deadline on the handshake only; nothing after it is timed as a whole.
	handshakeTimeout = 15 * time.Second
	// readHeaderTimeout bounds a request line and headers that never finish.
	// It does not bound a body or a response: a whole-response timeout is
	// ottergate's 15 s, which kills every stream longer than that.
	readHeaderTimeout = 30 * time.Second
	// idleTimeout closes a keep-alive connection with no request on it.
	idleTimeout = 5 * time.Minute
)

// maxLoggedPath bounds the path in a log line.
const maxLoggedPath = 1024

// Decisions, as they appear in the log.
const (
	DecisionAllowed = "allowed"
	DecisionRefused = "refused"
	DecisionFailed  = "failed"
)

// Refusal reasons that are not the scope's.
const (
	ReasonNoSNI           = "no SNI"
	ReasonUnknownName     = "not a route"
	ReasonMisdirected     = "Host does not match SNI"
	ReasonNoCredential    = "credential unavailable"
	ReasonStaleCredential = "credential expired"
)

// Config is everything an Interceptor needs.
type Config struct {
	// CA mints the certificates sandboxes see. Shared across sessions, so a
	// name is minted once per machine rather than once per sandbox.
	CA *CA
	// Routes are the hosts intercepted. A name not here is refused at the
	// handshake.
	Routes []Route
	// Log receives one line per request and one per refused handshake.
	// Injected, never a package logger, so a test can assert on it.
	Log *slog.Logger
	// Now is the clock credential expiry is judged against. Nil is time.Now.
	Now func() time.Time
	// DialContext dials upstreams. Nil is a plain net.Dialer; the daemon
	// passes the egress policy's dialer, so an upstream is held to the same
	// structural refusals as any other connection frisket makes.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Interceptor is a steer.Handler for connections to the service address's
// HTTPS port.
type Interceptor struct {
	ca     *CA
	routes map[string]*route
	log    *slog.Logger
	now    func() time.Time

	tlsConfig *tls.Config
	srv       *http.Server
	ln        *connListener
	served    chan struct{}
	closing   chan struct{}
	closeOnce sync.Once
}

type route struct {
	Route
	host     string
	upstream *url.URL
	scope    *compiled
	strip    []string
	proxy    *httputil.ReverseProxy
	tr       *http.Transport
}

var _ steer.Handler = (*Interceptor)(nil)

// New builds an Interceptor and starts its HTTP server. Close stops it.
func New(cfg Config) (*Interceptor, error) {
	if cfg.CA == nil {
		return nil, errors.New("intercept: no CA")
	}
	if cfg.Log == nil {
		return nil, errors.New("intercept: no logger")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}

	i := &Interceptor{
		ca:      cfg.CA,
		routes:  map[string]*route{},
		log:     cfg.Log,
		now:     cfg.Now,
		ln:      newConnListener(),
		served:  make(chan struct{}),
		closing: make(chan struct{}),
	}
	errLog := slog.NewLogLogger(cfg.Log.Handler(), slog.LevelWarn)

	for _, r := range cfg.Routes {
		up, err := r.validate()
		if err != nil {
			return nil, fmt.Errorf("intercept: %w", err)
		}
		host := normaliseHost(r.Host)
		if _, dup := i.routes[host]; dup {
			return nil, fmt.Errorf("intercept: two routes for %s", host)
		}
		sc, err := compileScope(r.Scope)
		if err != nil {
			return nil, fmt.Errorf("intercept: route %s: %w", r.Name, err)
		}
		rt := &route{Route: r, host: host, upstream: up, scope: sc}
		// Every header a sandbox might have put a credential in. It is not
		// enough to overwrite Authorization: a request carrying the sandbox's
		// own token in a second header would reach the upstream with two
		// identities, and which one wins is the upstream's business.
		rt.strip = append([]string{"Authorization", "Proxy-Authorization", r.Inject.Header()}, r.Strip...)
		rt.tr = upstreamTransport(r, up, dial)
		rt.proxy = &httputil.ReverseProxy{
			Rewrite:      rt.rewrite,
			Transport:    rt.tr,
			ErrorLog:     errLog,
			ErrorHandler: upstreamFailed,
		}
		i.routes[host] = rt
	}

	i.tlsConfig = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: i.getCertificate,
		// Offered deliberately, both: HTTP/2 because the agents' SDKs use it
		// and multiplex on it, HTTP/1.1 because an Upgrade (a websocket) only
		// exists there.
		NextProtos: []string{"h2", "http/1.1"},
	}

	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	i.srv = &http.Server{
		Handler:           http.HandlerFunc(i.serveHTTP),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		Protocols:         &protocols,
		ErrorLog:          errLog,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if ic, ok := tc.NetConn().(*interceptedConn); ok {
					return context.WithValue(ctx, connKey{}, ic)
				}
			}
			return ctx
		},
	}
	go func() {
		defer close(i.served)
		_ = i.srv.Serve(i.ln)
	}()
	return i, nil
}

// upstreamTransport is a route's connection to its real upstream.
func upstreamTransport(r Route, up *url.URL, dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	// A custom dialer or TLS config silently turns off HTTP/2 in
	// net/http, so the protocols are set here rather than inherited. Both:
	// the Transport already forces HTTP/1.1 for a websocket upgrade.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &http.Transport{
		// Never ProxyFromEnvironment. ottergate falls back to the
		// environment's proxy for its upstream, so the credential goes
		// wherever HTTPS_PROXY happens to point.
		Proxy:       nil,
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			RootCAs:    r.UpstreamCAs,
			ServerName: up.Hostname(),
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		// The client's Accept-Encoding goes through untouched and so does the
		// upstream's encoding. With compression left on, the Transport asks
		// for gzip itself and decompresses on the way through, which changes
		// the bytes, drops Content-Length, and puts a decompressor between an
		// SSE stream and the client.
		DisableCompression:    true,
		ExpectContinueTimeout: time.Second,
		Protocols:             &protocols,
		// Deliberately no ResponseHeaderTimeout and no overall timeout: a
		// non-streaming model request can take minutes to produce headers,
		// and a stream can last as long as it likes.
	}
}

// Close stops the server, closes every connection it holds and waits for its
// accept loop to end.
func (i *Interceptor) Close() error {
	var err error
	i.closeOnce.Do(func() {
		close(i.closing)
		err = i.srv.Close()
		<-i.served
		for _, r := range i.routes {
			r.tr.CloseIdleConnections()
		}
	})
	return err
}

// CACertPEM is the certificate sandboxes must trust.
func (i *Interceptor) CACertPEM() []byte { return i.ca.CertPEM() }

// ServeConn terminates TLS on a steered connection and hands it to the HTTP
// server, returning when the connection is finished. The session's slot is
// held for exactly that long.
func (i *Interceptor) ServeConn(ctx context.Context, c *steer.Conn) {
	ic := &interceptedConn{Conn: c, session: c.Session, id: c.ID, done: make(chan struct{})}
	defer ic.Close()

	tc := tls.Server(ic, i.tlsConfig)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		i.logHandshake(c, err)
		return
	}
	// The route is fixed by the handshake, for the life of the connection:
	// getCertificate refused any name without one, so this cannot miss.
	ic.route = i.routes[normaliseHost(tc.ConnectionState().ServerName)]
	if ic.route == nil {
		return
	}
	if !i.ln.push(tc) {
		return
	}
	select {
	case <-ic.done:
	case <-ctx.Done():
	case <-i.closing:
	}
}

// getCertificate mints for a route's name and refuses anything else.
//
// No SNI is refused rather than guessed at: a client connecting by address, or
// one that sent no name, has not said which host it wants, and choosing one
// for it is choosing which credential its request gets.
func (i *Interceptor) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := normaliseHost(hello.ServerName)
	if name == "" {
		return nil, &refusal{reason: ReasonNoSNI}
	}
	if _, ok := i.routes[name]; !ok {
		return nil, &refusal{name: name, reason: ReasonUnknownName}
	}
	return i.ca.Leaf(name)
}

type refusal struct{ name, reason string }

func (r *refusal) Error() string {
	if r.name == "" {
		return "refused: " + r.reason
	}
	return fmt.Sprintf("refused %q: %s", r.name, r.reason)
}

func (i *Interceptor) logHandshake(c *steer.Conn, err error) {
	attrs := []any{"session", c.Session, "conn", c.ID}
	var ref *refusal
	if errors.As(err, &ref) {
		attrs = append(attrs, "sni", ref.name, "decision", DecisionRefused, "reason", ref.reason)
		i.log.Warn("tls", attrs...)
		return
	}
	// Not ours: the client gave up, timed out, or -- the one worth seeing --
	// refused our certificate, which is what a sandbox missing the CA does.
	attrs = append(attrs, "decision", DecisionFailed, "error", err.Error())
	i.log.Warn("tls", attrs...)
}

// serveHTTP is every request on every intercepted connection.
func (i *Interceptor) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ic, _ := r.Context().Value(connKey{}).(*interceptedConn)
	if ic == nil || ic.route == nil {
		// Only reachable if a connection arrived by some path other than
		// ServeConn. Refused, and still logged.
		http.Error(w, "frisket: no route", http.StatusMisdirectedRequest)
		i.log.Error("request", "decision", DecisionRefused, "reason", "no route", "status", http.StatusMisdirectedRequest)
		return
	}
	rt := ic.route

	rec := &record{decision: DecisionAllowed}
	lw := &logWriter{ResponseWriter: w, rec: rec}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &countingBody{ReadCloser: r.Body, n: &rec.reqBytes}
	}

	defer func() {
		p := recover()
		if p != nil {
			// http.ErrAbortHandler is ReverseProxy saying the response broke
			// half-way through. Still exactly one line for the request.
			rec.fail(fmt.Errorf("aborted: %v", p))
		}
		i.logRequest(ic, r, rec, time.Since(start))
		if p != nil {
			panic(p)
		}
	}()

	if normaliseHost(r.Host) != rt.host {
		// One connection, one name: the handshake chose the route and its
		// credential. A request for another name on it -- HTTP/2 connection
		// reuse, or a deliberate mismatch -- is sent back to be asked again.
		rec.refuse(ReasonMisdirected)
		refuse(lw, http.StatusMisdirectedRequest, ReasonMisdirected)
		return
	}
	ok, why := rt.scope.allow(r.Method, r.URL)
	if !ok {
		rec.refuse(why)
		refuse(lw, http.StatusForbidden, why)
		return
	}
	rec.rule = why

	sec, err := rt.Credential.Get()
	if err != nil {
		// Loudly, and never onward without it. 502: frisket could not act for
		// the upstream, which is frisket's failure and not the client's.
		rec.refuse(ReasonNoCredential)
		rec.err = err
		rec.level = slog.LevelError
		refuse(lw, http.StatusBadGateway, ReasonNoCredential)
		return
	}
	if sec.Expired(i.now()) {
		// 503, not 401 (decision 10): a client retries a 503 with backoff and
		// recovers in the same turn once the host refreshes; two 401s fail
		// Claude Code's turn. frisket never refreshes, so waiting is the only
		// thing that fixes this.
		rec.refuse(ReasonStaleCredential)
		rec.level = slog.LevelWarn
		refuse(lw, http.StatusServiceUnavailable, ReasonStaleCredential)
		return
	}

	ctx := context.WithValue(r.Context(), secretKey{}, sec.Value)
	ctx = context.WithValue(ctx, recordKey{}, rec)
	rt.proxy.ServeHTTP(lw, r.WithContext(ctx))
}

func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "frisket: refused: "+reason, status)
}

// rewrite is the only place a credential is put on a request.
func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(rt.upstream)
	for _, h := range rt.strip {
		pr.Out.Header.Del(h)
	}
	secret, _ := pr.In.Context().Value(secretKey{}).(string)
	if secret == "" {
		// Unreachable by construction -- serveHTTP always sets it -- and
		// fail-closed if that ever stops being true: a nil URL fails the
		// round trip, so nothing goes upstream without its credential.
		pr.Out.URL = nil
		return
	}
	pr.Out.Header.Set(rt.Inject.Header(), rt.Inject.Value(secret))
}

// upstreamFailed answers when the upstream could not be reached or answered
// with something unusable.
func upstreamFailed(w http.ResponseWriter, r *http.Request, err error) {
	if rec, ok := r.Context().Value(recordKey{}).(*record); ok {
		// A *url.Error would quote the request URL, query and all.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		rec.fail(err)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "frisket: upstream failed", http.StatusBadGateway)
}

// logRequest writes the request's one line. Metadata only: never a body,
// never a header value, never the query string -- a query is where tokens end
// up when someone puts them in a URL.
func (i *Interceptor) logRequest(ic *interceptedConn, r *http.Request, rec *record, d time.Duration) {
	path := r.URL.EscapedPath()
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath] + "..."
	}
	status := int(rec.status.Load())
	if status == 0 {
		status = http.StatusOK
	}
	attrs := []any{
		"session", ic.session,
		"conn", ic.id,
		"route", ic.route.Name,
		"host", ic.route.host,
		"proto", r.Proto,
		"method", r.Method,
		"path", path,
		"decision", rec.decision,
	}
	if rec.reason != "" {
		attrs = append(attrs, "reason", rec.reason)
	}
	if rec.rule != "" {
		attrs = append(attrs, "rule", rec.rule)
	}
	attrs = append(attrs,
		"status", status,
		"req_bytes", rec.reqBytes.Load(),
		"resp_bytes", rec.respBytes.Load(),
		"duration_ms", d.Milliseconds(),
	)
	if rec.err != nil {
		attrs = append(attrs, "error", rec.err.Error())
	}
	level := rec.level
	if level == 0 && rec.decision == DecisionRefused {
		level = slog.LevelWarn
	}
	i.log.Log(context.Background(), level, "request", attrs...)
}

type (
	connKey   struct{}
	secretKey struct{}
	recordKey struct{}
)

// record is what one request's log line says. Counters are atomic because a
// request body is read by the Transport's goroutine and an upgraded
// connection is copied by two more.
type record struct {
	decision  string
	reason    string
	rule      string
	err       error
	level     slog.Level
	status    atomic.Int64
	reqBytes  atomic.Int64
	respBytes atomic.Int64
}

func (r *record) refuse(reason string) {
	r.decision, r.reason = DecisionRefused, reason
}

// fail records an allowed request that went wrong upstream or on the way
// back. The decision stays "allowed" -- it was -- and the error says what
// happened after.
func (r *record) fail(err error) {
	if r.err == nil {
		r.err = err
	}
	r.level = slog.LevelError
}

// logWriter records the status and counts the body on the way out. It
// unwraps, so http.NewResponseController -- which ReverseProxy uses to flush
// an SSE stream and to hijack for an upgrade -- reaches the real writer.
type logWriter struct {
	http.ResponseWriter
	rec *record
}

func (w *logWriter) WriteHeader(code int) {
	// 1xx are interim (100 Continue, 103 Early Hints); the status that
	// matters is the final one. 101 arrives by Hijack, below.
	if code >= 200 {
		w.rec.status.CompareAndSwap(0, int64(code))
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.rec.status.CompareAndSwap(0, http.StatusOK)
	n, err := w.ResponseWriter.Write(p)
	w.rec.respBytes.Add(int64(n))
	return n, err
}

func (w *logWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack is only called for a protocol switch. The connection is wrapped so
// the bytes that cross it after the switch are still counted.
func (w *logWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.rec.status.CompareAndSwap(0, http.StatusSwitchingProtocols)
	return &countingConn{Conn: c, rec: w.rec}, brw, nil
}

type countingConn struct {
	net.Conn
	rec *record
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.reqBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.rec.respBytes.Add(int64(n))
	return n, err
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// interceptedConn is a steered connection with what the handshake decided
// about it, and a signal for when it is closed -- by the HTTP server, by an
// upgraded stream finishing, or by the session going away.
type interceptedConn struct {
	net.Conn
	session string
	id      uint64
	route   *route
	done    chan struct{}
	once    sync.Once
}

func (c *interceptedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		close(c.done)
	})
	return err
}

// connListener feeds connections that have finished their handshake to the
// one http.Server. There is no public way to serve a single connection with
// net/http, and this keeps one server, one set of timeouts and one HTTP/2
// configuration for all of them.
type connListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.closed:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr { return serviceAddr{} }

type serviceAddr struct{}

func (serviceAddr) Network() string { return "intercept" }
func (serviceAddr) String() string  { return "intercept" }
