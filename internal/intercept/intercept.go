// Package intercept terminates TLS for the hosts frisket adds credentials to,
// and for nothing else (PLAN.md, decision 4).
//
// The sandbox connected to what it believes is, say, api.github.com: frisket's
// DNS answered that name with the session's service address, and the kernel
// steered the connection here. frisket completes the handshake AS that name,
// with a leaf minted from the session's own CA, the one it trusts, reads the
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
	"net/netip"
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

// What happened to a request's credential header, as it appears in the log.
const (
	CredentialInjected = "injected" // the placeholder, replaced with the real credential
	CredentialPassed   = "passed"   // the client's own, sent on untouched
	CredentialNone     = "none"     // there was none
)

// Refusal reasons that are not the scope's.
const (
	ReasonNoSNI           = "no SNI"
	ReasonUnknownName     = "not a route"
	ReasonNotInCA         = "not in the session's CA"
	ReasonMisdirected     = "Host does not match SNI"
	ReasonNoCredential    = "credential unavailable"
	ReasonStaleCredential = "credential expired"
	ReasonNobodyToAsk     = "nobody to ask"
	ReasonDeclined        = "declined"
	ReasonAskFailed       = "asking failed"
	ReasonStoppedWaiting  = "client stopped waiting"
)

// RuleAsked is the rule of a request a person admitted.
const RuleAsked = "asked"

// Asker puts a request the scope would not decide to someone who can. It
// answers true to admit it; false, or an error, refuses it. It is called on
// the request's own goroutine and may take as long as a person does; ctx ends
// when the client stops waiting.
type Asker interface {
	Ask(ctx context.Context, q Question) (bool, error)
}

// Question is one request put to an Asker. Operation is the only prose in it,
// and it comes from the route's configuration, never from the request:
// everything the workload chose -- method, path, query -- is here as the
// request, to be shown as the request.
type Question struct {
	Session string `json:"session"`
	Policy  string `json:"policy"`
	Route   string `json:"route"`
	Method  string `json:"method"`
	Host    string `json:"host"`
	// Path is escaped, exactly as it was sent; Query too, without its "?".
	Path  string `json:"path"`
	Query string `json:"query,omitempty"`
	// Operation is what the request matched, or nil if it matched nothing --
	// in which case nothing is borrowed to describe it.
	Operation *Operation `json:"operation,omitempty"`
}

// Config is everything an Interceptor needs.
type Config struct {
	// Routes are the hosts intercepted. A name not here is refused at the
	// handshake.
	Routes []Route
	// Log receives one line per request and one per refused handshake.
	// Injected, never a package logger, so a test can assert on it.
	Log *slog.Logger
	// Policy is the name the routes are configured under, for a Question.
	Policy string
	// Asker decides what a scope asks about. Nil refuses it: a gate with
	// nobody to ask fails closed, never open.
	Asker Asker
	// Now is the clock credential expiry is judged against. Nil is time.Now.
	Now func() time.Time
	// DialContext dials upstreams. Nil is a plain net.Dialer; the daemon
	// passes the egress policy's dialer, so an upstream is held to the same
	// structural refusals as any other connection frisket makes.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Interceptor is one policy's routes and the HTTP server behind them. For
// gives each session the steer.Handler for its connections to the service
// address's HTTPS port.
type Interceptor struct {
	routes map[string]*route
	log    *slog.Logger
	now    func() time.Time
	policy string
	asker  Asker

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
	proxy    *httputil.ReverseProxy
	tr       *http.Transport
}

var _ steer.Handler = sessionHandler{}

// New builds an Interceptor and starts its HTTP server. Close stops it.
func New(cfg Config) (*Interceptor, error) {
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
		routes:  map[string]*route{},
		log:     cfg.Log,
		now:     cfg.Now,
		policy:  cfg.Policy,
		asker:   cfg.Asker,
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
		rt.tr = upstreamTransport(r, up, dial)
		rt.proxy = &httputil.ReverseProxy{
			Rewrite:        rt.rewrite,
			Transport:      rt.tr,
			ModifyResponse: inspect,
			ErrorLog:       errLog,
			ErrorHandler:   upstreamFailed,
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

// Hosts is the routes' hosts: what a session's CA is constrained to.
func (i *Interceptor) Hosts() []string {
	out := make([]string, 0, len(i.routes))
	for h := range i.routes {
		out = append(out, h)
	}
	return out
}

// For is the handler for one session's connections: the routes are the
// policy's, the certificates are minted from ca, the session's own.
func (i *Interceptor) For(ca *CA) steer.Handler {
	return sessionHandler{i: i, ca: ca}
}

type sessionHandler struct {
	i  *Interceptor
	ca *CA
}

func (h sessionHandler) ServeConn(ctx context.Context, c *steer.Conn) { h.i.serveConn(ctx, c, h.ca) }

// serveConn terminates TLS on a steered connection and hands it to the HTTP
// server, returning when the connection is finished. The session's slot is
// held for exactly that long.
func (i *Interceptor) serveConn(ctx context.Context, c *steer.Conn, ca *CA) {
	ic := &interceptedConn{Conn: c, session: c.Session, id: c.ID, dst: c.Orig, ca: ca, done: make(chan struct{})}
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
	// ONE LINE PER CONNECTION AT LEAST. Each request writes its own, since a
	// request is what a route authorises; a connection that finished its
	// handshake and asked nothing would otherwise leave no line at all.
	if ic.requests.Load() == 0 {
		i.log.Info("tls", "session", ic.session, "conn", ic.id, "dst", ic.dst.String(),
			"sni", ic.route.host, "decision", DecisionAllowed, "requests", 0)
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
	// The connection the handshake is on is the session's, and so is the CA
	// it carries. One made before a route was added does not permit its
	// host, and a leaf from it is one the client would reject.
	ic, ok := hello.Conn.(*interceptedConn)
	if !ok {
		return nil, fmt.Errorf("intercept: a handshake on a %T, not a session's connection", hello.Conn)
	}
	if !ic.ca.Permits(name) {
		return nil, &refusal{name: name, reason: ReasonNotInCA}
	}
	return ic.ca.Leaf(name)
}

type refusal struct{ name, reason string }

func (r *refusal) Error() string {
	if r.name == "" {
		return "refused: " + r.reason
	}
	return fmt.Sprintf("refused %q: %s", r.name, r.reason)
}

func (i *Interceptor) logHandshake(c *steer.Conn, err error) {
	attrs := []any{"session", c.Session, "conn", c.ID, "dst", c.Orig.String()}
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
	ic.requests.Add(1)

	rec := &record{decision: DecisionAllowed}
	if i.log.Enabled(r.Context(), slog.LevelDebug) {
		// Before anything is replaced: what the client sent is the question.
		ours := ""
		if rt.Credential != nil {
			if s, err := rt.Credential.Get(); err == nil {
				ours = s.Value
			}
		}
		rec.detail = &detail{reqHeader: describeHeaders(r.Header, ours), query: queryNames(r.URL.Query())}
		// The request line comes when it finishes, which for a stream is
		// when the stream does: this says it is open meanwhile.
		i.log.Debug("request start", "session", ic.session, "conn", ic.id, "method", r.Method, "path", loggedPath(r))
		rec.detail.responded = func(status int, contentType string) {
			i.log.Debug("response start", "session", ic.session, "conn", ic.id, "path", loggedPath(r),
				"status", status, "content_type", contentType)
		}
	}
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
	v := rt.scope.decide(r.Method, r.URL)
	if v.Operation != nil {
		rec.operation = v.Operation.ID
	}
	switch v.Outcome {
	case Refuse:
		rec.refuse(v.Reason)
		refuse(lw, http.StatusForbidden, v.Reason)
		return
	case Ask:
		if reason := i.ask(r, ic, v); reason != "" {
			rec.refuse(reason)
			refuse(lw, http.StatusForbidden, reason)
			return
		}
		rec.rule = RuleAsked
	default:
		rec.rule = v.Reason
	}

	if !rt.carries(r.Header) {
		// Not the placeholder, so not frisket's to touch: the client's own
		// credential, or none, goes upstream as it was sent. Nor does it need
		// frisket's -- a stale or missing one is no reason to refuse it.
		rec.credential = CredentialPassed
		if r.Header.Get(rt.credentialHeader()) == "" {
			rec.credential = CredentialNone
		}
		rt.proxy.ServeHTTP(lw, r.WithContext(context.WithValue(r.Context(), recordKey{}, rec)))
		return
	}
	rec.credential = CredentialInjected

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

// ask puts a request to the Asker, and returns why it is refused, or "" if
// it was admitted. Before the credential is looked at: what the person is
// asked is whether this request may go, and that does not depend on whether
// the token has since expired.
func (i *Interceptor) ask(r *http.Request, ic *interceptedConn, v Verdict) string {
	if i.asker == nil {
		return ReasonNobodyToAsk
	}
	ok, err := i.asker.Ask(r.Context(), Question{
		Session:   ic.session,
		Policy:    i.policy,
		Route:     ic.route.Name,
		Method:    r.Method,
		Host:      ic.route.host,
		Path:      r.URL.EscapedPath(),
		Query:     r.URL.RawQuery,
		Operation: v.Operation,
	})
	switch {
	case r.Context().Err() != nil:
		// Nobody is waiting for the answer, so there is nothing to admit and
		// nothing wrong with the asker.
		return ReasonStoppedWaiting
	case err != nil:
		// Said in the log where it happened, not in the request's line: the
		// error is the asker's, and may quote whatever it was sent.
		i.log.Error("ask", "session", ic.session, "conn", ic.id, "route", ic.route.Name, "error", err.Error())
		return ReasonAskFailed
	case !ok:
		return ReasonDeclined
	}
	return ""
}

func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "frisket: refused: "+reason, status)
}

// rewrite is the only place a credential is put on a request.
func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(rt.upstream)
	secret, inject := pr.In.Context().Value(secretKey{}).(string)
	if !inject {
		// No placeholder on the request: nothing of frisket's goes on it.
		return
	}
	if secret == "" {
		// Unreachable by construction -- a source never produces an empty
		// credential -- and fail-closed if that ever stops being true: a nil
		// URL fails the round trip, so a placeholder never goes upstream
		// without its credential.
		pr.Out.URL = nil
		return
	}
	pr.Out.Header.Set(rt.Inject.Header(), rt.Inject.Value(secret))
}

// inspect keeps a response's headers, and the start of an error's body, for a
// request whose detail is being kept. It changes nothing the client receives.
func inspect(res *http.Response) error {
	rec, _ := res.Request.Context().Value(recordKey{}).(*record)
	if rec == nil || rec.detail == nil {
		return nil
	}
	rec.detail.respHeader = describeHeaders(res.Header, "")
	rec.detail.responded(res.StatusCode, res.Header.Get("Content-Type"))
	if res.StatusCode >= 400 {
		rec.detail.respBody = peekBody(res)
	}
	return nil
}

// loggedPath is a request's path as the log shows it: no query, and bounded.
func loggedPath(r *http.Request) string {
	path := r.URL.EscapedPath()
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath] + "..."
	}
	return path
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
// up when someone puts them in a URL. At debug level a second line follows
// with the request's detail, whose credentials are described, never shown.
func (i *Interceptor) logRequest(ic *interceptedConn, r *http.Request, rec *record, d time.Duration) {
	path := loggedPath(r)
	status := int(rec.status.Load())
	if status == 0 {
		status = http.StatusOK
	}
	attrs := []any{
		"session", ic.session,
		"conn", ic.id,
		"dst", ic.dst.String(),
		"route", ic.route.Name,
		"host", ic.route.host,
		"proto", r.Proto,
		"method", r.Method,
		"path", path,
		"decision", rec.decision,
	}
	if rec.credential != "" {
		attrs = append(attrs, "credential", rec.credential)
	}
	if rec.reason != "" {
		attrs = append(attrs, "reason", rec.reason)
	}
	if rec.rule != "" {
		attrs = append(attrs, "rule", rec.rule)
	}
	if rec.operation != "" {
		attrs = append(attrs, "operation", rec.operation)
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

	if d := rec.detail; d != nil {
		i.log.Debug("request detail",
			"session", ic.session,
			"conn", ic.id,
			"method", r.Method,
			"path", path,
			"status", status,
			"req_headers", d.reqHeader,
			"query", d.query,
			"resp_headers", d.respHeader,
			"resp_body", d.respBody,
		)
	}
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
	// detail is kept only at debug level.
	detail *detail
	// credential is what happened to the credential header: the placeholder
	// replaced, the client's own passed, or none sent.
	credential string
	decision   string
	reason     string
	rule       string
	// operation is the id of the operation the request matched, if any.
	operation string
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
	session  string
	id       uint64
	dst      netip.AddrPort
	ca       *CA
	route    *route
	requests atomic.Int64
	done     chan struct{}
	once     sync.Once
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
