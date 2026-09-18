package intercept

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/credential"
	"github.com/danielbodart/frisket/internal/steer"
)

// The address the sandbox thought it was dialling: frisket's service address.
var serviceAddr443 = netip.MustParseAddrPort("198.51.100.7:443")

const (
	apiHost     = "api.example.test"
	gitHost     = "git.example.test"
	realToken   = "real-token-7f3a"
	sandboxAuth = "Bearer sandbox-token-91c2"
)

// journal is the injected log writer. THE LOGGER IS NOT SILENCED UNDER TEST:
// "one line per request" and "no header value in the log" are properties, and
// a logger that writes nowhere turns them into hopes.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) String() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.String()
}

func (j *journal) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(j.String(), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// waitLines waits for n lines of msg. The line for a request is written when
// its handler returns, which can be a moment after the client has its answer.
func (j *journal) waitLines(t *testing.T, msg string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := j.lines(t, msg)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d %q lines, have %d:\n%s", n, msg, len(got), j.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// upstream is a fake real host, with its own CA that the sandbox never sees.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.Clone(context.Background()))
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		// Read the body before answering, as a real API does. A handler that
		// answers first races the client still sending, and the request's
		// logged byte count with it.
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "upstream says hello")
	}))
	u.EnableHTTP2 = true
	u.StartTLS()
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) requests() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*http.Request(nil), u.seen...)
}

func (u *upstream) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(u.Certificate())
	return p
}

// tokenFile writes a credential file and watches it.
func tokenFile(t *testing.T, j *journal, content string) (*credential.File, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := credential.WatchFile(path, credential.Trimmed(), slog.New(slog.NewJSONHandler(j, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, path
}

func apiRoute(up *upstream, cred credential.Source) Route {
	return Route{
		Name:        "api",
		Host:        apiHost,
		Upstream:    up.URL,
		UpstreamCAs: up.pool(),
		Credential:  cred,
		Inject:      Bearer(),
		Strip:       []string{"X-Api-Key"},
		Scope: Scope{Paths: []PathRule{
			{Methods: []string{"GET", "POST"}, Prefix: "/v1/messages"},
			{Methods: []string{"GET"}, Prefix: "/v1/stream"},
			{Methods: []string{"POST", "PUT"}, Prefix: "/v1/upload"},
			{Methods: []string{"GET"}, Prefix: "/v1/socket"},
		}},
	}
}

// fixture is frisket as a sandbox meets it: a steered listener, the steer
// session in front of the interceptor, and a client that trusts ONLY
// frisket's CA -- not the upstream's, and not the system's.
type fixture struct {
	ca      *CA
	journal *journal
	addr    string
	ic      *Interceptor
}

func newFixture(t *testing.T, j *journal, routes ...Route) *fixture {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ic, err := New(Config{CA: ca, Routes: routes, Log: slog.New(slog.NewJSONHandler(j, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.Close() })

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	sess := steer.New("sess-test", j)
	// The kernel's answer, as the steering would give it: this connection
	// was going to the service address's HTTPS port.
	sess.Dst = func(*net.TCPConn) netip.AddrPort { return serviceAddr443 }

	// Cleanups run last-registered-first: cancel, then wait for the accept
	// loop, then close the interceptor (registered above).
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		defer close(done)
		_ = sess.Serve(ctx, ln, ic)
	}()
	return &fixture{ca: ca, journal: j, addr: ln.Addr().String(), ic: ic}
}

func (f *fixture) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(f.ca.Certificate())
	return p
}

// client dials frisket whatever the URL says, as steering does, and speaks
// HTTP/1.1 or HTTP/2 as asked -- only that one, so a test that passes on h2
// really was h2.
func (f *fixture) client(t *testing.T, h2 bool) *http.Client {
	t.Helper()
	var p http.Protocols
	p.SetHTTP1(!h2)
	p.SetHTTP2(h2)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", f.addr)
		},
		TLSClientConfig:    &tls.Config{RootCAs: f.roots()},
		Protocols:          &p,
		DisableCompression: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func protos(t *testing.T, fn func(t *testing.T, h2 bool)) {
	t.Run("http1", func(t *testing.T) { fn(t, false) })
	t.Run("http2", func(t *testing.T) { fn(t, true) })
}

func get(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// The sandbox's own Authorization never reaches the upstream; the real
// credential does; and neither appears in the log.
func TestCredentialIsSwappedOnTheWire(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		cred, _ := tokenFile(t, j, realToken+"\n")
		f := newFixture(t, j, apiRoute(up, cred))
		c := f.client(t, h2)

		req := newRequest(t, "POST", "https://"+apiHost+"/v1/messages?beta=true", strings.NewReader(`{"model":"x"}`))
		req.Header.Set("Authorization", sandboxAuth)
		req.Header.Set("X-Api-Key", "sandbox-key-55")
		req.Header.Set("Proxy-Authorization", "Basic c2FuZGJveDpwdw==")
		req.Header.Set("X-Forwarded-For", "10.9.9.9")
		req.Header.Set("Anthropic-Version", "2023-06-01")
		res, body := get(t, c, req)

		if res.StatusCode != 200 || body != "upstream says hello" {
			t.Fatalf("got %d %q", res.StatusCode, body)
		}
		if wantProto := map[bool]int{false: 1, true: 2}[h2]; res.ProtoMajor != wantProto {
			t.Fatalf("spoke %s to frisket, want HTTP/%d", res.Proto, wantProto)
		}
		seen := up.requests()
		if len(seen) != 1 {
			t.Fatalf("upstream saw %d requests", len(seen))
		}
		got := seen[0]
		if a := got.Header.Values("Authorization"); len(a) != 1 || a[0] != "Bearer "+realToken {
			t.Fatalf("upstream Authorization = %q, want exactly the real credential", a)
		}
		for name, vals := range got.Header {
			for _, v := range vals {
				if strings.Contains(v, "sandbox") || strings.Contains(v, "10.9.9.9") {
					t.Fatalf("the sandbox's %s reached the upstream: %q", name, v)
				}
			}
		}
		if got.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Fatal("an ordinary header was not forwarded")
		}
		if got.URL.RawQuery != "beta=true" || got.URL.Path != "/v1/messages" {
			t.Fatalf("upstream got %s", got.URL)
		}

		lines := f.journal.waitLines(t, "request", 1)
		l := lines[0]
		for k, want := range map[string]any{
			"session": "sess-test", "route": "api", "host": apiHost, "method": "POST",
			"path": "/v1/messages", "decision": DecisionAllowed, "rule": "path", "status": float64(200),
			"req_bytes": float64(len(`{"model":"x"}`)), "resp_bytes": float64(len("upstream says hello")),
		} {
			if l[k] != want {
				t.Errorf("log %s = %v, want %v", k, l[k], want)
			}
		}
		if _, ok := l["conn"].(float64); !ok {
			t.Errorf("log has no connection id: %v", l)
		}
		if _, ok := l["duration_ms"].(float64); !ok {
			t.Errorf("log has no duration: %v", l)
		}
		assertNoSecretsLogged(t, f.journal)
	})
}

func assertNoSecretsLogged(t *testing.T, j *journal) {
	t.Helper()
	all := j.String()
	for _, s := range []string{realToken, "sandbox-token", "sandbox-key", "c2FuZGJveDpwdw", "beta=true"} {
		if strings.Contains(all, s) {
			t.Fatalf("the log contains %q:\n%s", s, all)
		}
	}
}

// The connection was steered -- the kernel says so, and steer accepted it --
// and the request on it is still refused, because the request is the
// workload's to choose and the scope is checked against it.
func TestOutOfScopeIsRefusedOnASteeredConnection(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		cred, _ := tokenFile(t, j, realToken)
		f := newFixture(t, j, apiRoute(up, cred))
		c := f.client(t, h2)

		refused := []struct{ method, target, reason string }{
			{"GET", "/v1/models", ReasonOutOfScope},
			{"POST", "/v1/messages-evil", ReasonOutOfScope},
			{"DELETE", "/v1/messages", ReasonOutOfScope},
			{"POST", "/v1/messages/%2e%2e/%2e%2e/admin", ReasonBadPath},
			{"POST", "/v1/messages/x%2F..%2F..%2Fadmin", ReasonBadPath},
		}
		for _, r := range refused {
			req := newRequest(t, r.method, "https://"+apiHost+r.target, nil)
			req.Header.Set("Authorization", sandboxAuth)
			res, _ := get(t, c, req)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s: %d, want 403", r.method, r.target, res.StatusCode)
			}
		}
		if n := len(up.requests()); n != 0 {
			t.Fatalf("upstream saw %d requests; a refusal must not reach it", n)
		}

		lines := f.journal.waitLines(t, "request", len(refused))
		for i, l := range lines {
			if l["decision"] != DecisionRefused || l["reason"] != refused[i].reason || l["status"] != float64(403) || l["level"] != "WARN" {
				t.Errorf("line %d: %v", i, l)
			}
		}
		// And they came through steer, which handed the connection on without
		// a line of its own: the request lines are the connection's.
		if conns := f.journal.lines(t, "connection"); len(conns) != 0 {
			t.Fatalf("steer logged a connection the interceptor served: %v", conns)
		}
		for _, l := range lines {
			if l["session"] != "sess-test" || l["conn"] == nil {
				t.Fatalf("a request line without its session and connection: %v", l)
			}
		}
	})
}

// A git route scoped to owner/repo refuses owner/repo-evil: the repository is
// a path segment, never a string prefix. And push is refused unless allowed.
func TestGitScopeByRepositorySegment(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	route := Route{
		Name: "git", Host: gitHost, Upstream: up.URL, UpstreamCAs: up.pool(),
		Credential: cred, Inject: BasicUser("x-access-token"),
		Scope: Scope{Git: &GitScope{Repos: []Repo{{Owner: "owner", Name: "repo"}}}},
	}
	f := newFixture(t, j, route)
	c := f.client(t, false)

	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{"GET", "/owner/repo.git/info/refs?service=git-upload-pack", 200},
		{"POST", "/owner/repo.git/git-upload-pack", 200},
		{"GET", "/owner/repo-evil.git/info/refs?service=git-upload-pack", 403},
		{"POST", "/owner/repo-evil.git/git-upload-pack", 403},
		{"GET", "/owner/repo.git/info/refs?service=git-receive-pack", 403},
		{"POST", "/owner/repo.git/git-receive-pack", 403},
	} {
		res, _ := get(t, c, newRequest(t, tc.method, "https://"+gitHost+tc.target, nil))
		if res.StatusCode != tc.status {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.target, res.StatusCode, tc.status)
		}
	}
	seen := up.requests()
	if len(seen) != 2 {
		t.Fatalf("upstream saw %d requests, want the 2 in scope", len(seen))
	}
	for _, r := range seen {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "x-access-token" || pass != realToken {
			t.Fatalf("upstream got basic auth %q/%q", user, pass)
		}
		if strings.Contains(r.URL.Path, "evil") || strings.Contains(r.URL.Path, "receive") {
			t.Fatalf("upstream saw %s", r.URL)
		}
	}
	var pushes int
	for _, l := range f.journal.waitLines(t, "request", 6) {
		if l["reason"] == ReasonPush {
			pushes++
		}
	}
	if pushes != 2 {
		t.Fatalf("want both push requests logged as pushes, got %d", pushes)
	}
}

// A route whose credential cannot be produced fails the request, loudly, and
// sends nothing upstream -- never the request without its credential.
func TestMissingCredentialFailsLoudly(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, "") // never written
	f := newFixture(t, j, apiRoute(up, cred))
	c := f.client(t, false)

	req := newRequest(t, "POST", "https://"+apiHost+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", sandboxAuth)
	res, body := get(t, c, req)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(body, ReasonNoCredential) {
		t.Fatalf("got %d %q, want 502 naming the missing credential", res.StatusCode, body)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw %d requests; nothing may go uncredentialed", n)
	}
	l := f.journal.waitLines(t, "request", 1)[0]
	if l["level"] != "ERROR" || l["decision"] != DecisionRefused || l["reason"] != ReasonNoCredential || l["error"] == nil {
		t.Fatalf("not loud enough: %v", l)
	}
}

// An expired credential answers 503, which a client retries with backoff, and
// not 401, which fails the agent's turn.
func TestExpiredCredentialAnswers503(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	write := func(exp time.Time) {
		t.Helper()
		b := fmt.Sprintf(`{"claudeAiOauth":{"accessToken":%q,"expiresAt":%d}}`, realToken, exp.UnixMilli())
		if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(time.Now().Add(-time.Minute))
	cred, err := credential.WatchFile(path,
		credential.JSON{Token: "claudeAiOauth.accessToken", ExpiresMillis: "claudeAiOauth.expiresAt"}.Extract,
		slog.New(slog.NewJSONHandler(j, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cred.Close() })
	f := newFixture(t, j, apiRoute(up, cred))
	c := f.client(t, false)

	res, _ := get(t, c, newRequest(t, "POST", "https://"+apiHost+"/v1/messages", strings.NewReader("{}")))
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expired credential: %d, want 503", res.StatusCode)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("an expired credential was sent upstream %d times", n)
	}

	// The host refreshes; the next request goes through.
	write(time.Now().Add(time.Hour))
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, _ := get(t, c, newRequest(t, "POST", "https://"+apiHost+"/v1/messages", strings.NewReader("{}")))
		if res.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %d after the refresh", res.StatusCode)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if l := f.journal.lines(t, "request")[0]; l["reason"] != ReasonStaleCredential || l["status"] != float64(503) {
		t.Fatalf("first line: %v", l)
	}
}

// A credential file replaced by temp-file-and-rename is used from the next
// request on.
func TestCredentialFileReplacedByRenameIsUsed(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, path := tokenFile(t, j, "token-one")
	f := newFixture(t, j, apiRoute(up, cred))
	c := f.client(t, false)

	get(t, c, newRequest(t, "GET", "https://"+apiHost+"/v1/messages", nil))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		get(t, c, newRequest(t, "GET", "https://"+apiHost+"/v1/messages", nil))
		seen := up.requests()
		if seen[len(seen)-1].Header.Get("Authorization") == "Bearer token-two" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the replaced credential was never used")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := up.requests()[0].Header.Get("Authorization"); got != "Bearer token-one" {
		t.Fatalf("first request carried %q", got)
	}
}

// SSE arrives as it is written, not when the stream ends. The upstream writes
// one event and then holds the response open until the client has it; if
// anything between them buffered, the client would wait for the upstream and
// the upstream for the client, and the test would time out rather than pass.
func TestStreamsArriveIncrementally(t *testing.T) {
	for name, ctype := range map[string]string{
		"sse":            "text/event-stream",
		"unknown length": "application/octet-stream",
	} {
		t.Run(name, func(t *testing.T) {
			protos(t, func(t *testing.T, h2 bool) {
				release := make(chan struct{})
				var released atomic.Int64
				j := &journal{}
				up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", ctype)
					_, _ = io.WriteString(w, "data: one\n\n")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-time.After(10 * time.Second):
					}
					released.Store(time.Now().UnixNano())
					_, _ = io.WriteString(w, "data: two\n\n")
				})
				cred, _ := tokenFile(t, j, realToken)
				f := newFixture(t, j, apiRoute(up, cred))
				c := f.client(t, h2)

				start := time.Now()
				res, err := c.Do(newRequest(t, "GET", "https://"+apiHost+"/v1/stream", nil))
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				br := bufio.NewReader(res.Body)
				first, err := br.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				firstAt := time.Now()
				close(release)
				if first != "data: one\n" {
					t.Fatalf("first line %q", first)
				}
				// The timing assertion: the first event arrived while the
				// upstream was still holding the stream open, and well within
				// the upstream's own ten-second give-up.
				if released.Load() != 0 {
					t.Fatal("the first event arrived only after the upstream finished: the stream was buffered")
				}
				if d := firstAt.Sub(start); d > 5*time.Second {
					t.Fatalf("the first event took %v", d)
				}
				rest, err := io.ReadAll(br)
				if err != nil {
					t.Fatal(err)
				}
				if string(rest) != "\ndata: two\n\n" {
					t.Fatalf("rest %q", rest)
				}
				if time.Now().UnixNano() < released.Load() {
					t.Fatal("the second event arrived before it was written")
				}
			})
		})
	}
}

// A large upload streams through: no limit, no truncation, and no buffering
// of the whole body before the upstream sees the start of it. The client
// sends the first mebibyte and then waits for the upstream to have it; a
// proxy that buffered the body would deadlock the two, and one that
// truncated -- ottergate stops at 5 MiB -- would fail the digest.
func TestLargeUploadStreams(t *testing.T) {
	const size = 64 << 20
	const firstChunk = 1 << 20
	protos(t, func(t *testing.T, h2 bool) {
		gotFirst := make(chan struct{})
		var once sync.Once
		j := &journal{}
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			var n int64
			buf := make([]byte, 64<<10)
			for {
				k, err := r.Body.Read(buf)
				h.Write(buf[:k])
				n += int64(k)
				if n >= firstChunk {
					once.Do(func() { close(gotFirst) })
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
			}
			fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(h.Sum(nil)))
		})
		cred, _ := tokenFile(t, j, realToken)
		f := newFixture(t, j, apiRoute(up, cred))
		c := f.client(t, h2)

		want := sha256.New()
		body := io.MultiReader(
			io.TeeReader(io.LimitReader(pattern{}, firstChunk), want),
			gate(gotFirst),
			io.TeeReader(io.LimitReader(pattern{}, size-firstChunk), want),
		)
		req := newRequest(t, "PUT", "https://"+apiHost+"/v1/upload", body)
		req.ContentLength = -1 // streamed, length unknown: chunked on h1
		res, got := get(t, c, req)
		if res.StatusCode != 200 {
			t.Fatalf("%d %s", res.StatusCode, got)
		}
		if exp := fmt.Sprintf("%d %s", size, hex.EncodeToString(want.Sum(nil))); got != exp {
			t.Fatalf("upstream received %s, want %s", got, exp)
		}
		l := f.journal.waitLines(t, "request", 1)[0]
		if l["req_bytes"] != float64(size) {
			t.Fatalf("logged req_bytes %v, want %d", l["req_bytes"], size)
		}
	})
}

// Every timeout frisket has is on a handshake, a header or an idle
// connection, never on a request as a whole. With all three shrunk to 100 ms,
// a response that takes over a second to stream, and an upload that takes
// over a second to send, both complete.
func TestNoTimeoutBoundsAStream(t *testing.T) {
	defer func(h, r, i time.Duration) { handshakeTimeout, readHeaderTimeout, idleTimeout = h, r, i }(
		handshakeTimeout, readHeaderTimeout, idleTimeout)
	handshakeTimeout, readHeaderTimeout, idleTimeout = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	const gap = 400 * time.Millisecond

	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/event-stream")
			for i := range 3 {
				fmt.Fprintf(w, "data: %d after %d bytes\n\n", i, n)
				w.(http.Flusher).Flush()
				time.Sleep(gap)
			}
		})
		cred, _ := tokenFile(t, j, realToken)
		f := newFixture(t, j, apiRoute(up, cred))

		pr, pw := io.Pipe()
		go func() {
			for range 3 {
				time.Sleep(gap)
				_, _ = pw.Write([]byte("slow"))
			}
			_ = pw.Close()
		}()
		start := time.Now()
		res, body := get(t, f.client(t, h2), newRequest(t, "POST", "https://"+apiHost+"/v1/upload", pr))
		if res.StatusCode != 200 || strings.Count(body, "after 12 bytes") != 3 {
			t.Fatalf("%d %q", res.StatusCode, body)
		}
		if d := time.Since(start); d < 6*gap-gap/2 {
			t.Fatalf("finished in %v; the test did not take as long as it was meant to", d)
		}
	})
}

// pattern is an endless, cheap, non-constant byte stream.
type pattern struct{}

func (pattern) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i*7 + i>>8)
	}
	return len(p), nil
}

// gate is an empty reader that blocks until it is closed.
type gate chan struct{}

func (g gate) Read([]byte) (int, error) {
	select {
	case <-g:
		return 0, io.EOF
	case <-time.After(10 * time.Second):
		return 0, fmt.Errorf("the upstream never saw the first mebibyte: the upload was buffered")
	}
}

// A websocket upgrade goes through: the 101 comes back, bytes cross in both
// directions afterwards, and the upgrade request carried the real credential.
func TestWebsocketUpgrade(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "want an upgrade", 400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fake\r\n\r\n")
		_ = brw.Flush()
		// Echo, upper-cased, so the reply cannot be the request reflected
		// by something in between.
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte(strings.ToUpper(line)))
	})
	cred, _ := tokenFile(t, j, realToken)
	f := newFixture(t, j, apiRoute(up, cred))

	conn, err := tls.Dial("tcp", f.addr, &tls.Config{
		RootCAs: f.roots(), ServerName: apiHost, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /v1/socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: %s\r\n\r\n", apiHost, sandboxAuth)
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("got %d %s", res.StatusCode, b)
	}
	if _, err := io.WriteString(conn, "ping over the socket\n"); err != nil {
		t.Fatal(err)
	}
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if echo != "PING OVER THE SOCKET\n" {
		t.Fatalf("echo %q", echo)
	}
	_ = conn.Close()

	seen := up.requests()
	if len(seen) != 1 || seen[0].Header.Get("Authorization") != "Bearer "+realToken {
		t.Fatalf("the upgrade request did not carry the real credential: %v", seen)
	}
	l := f.journal.waitLines(t, "request", 1)[0]
	if l["status"] != float64(101) || l["decision"] != DecisionAllowed {
		t.Fatalf("log: %v", l)
	}
	if n, _ := l["req_bytes"].(float64); n < float64(len("ping over the socket\n")) {
		t.Fatalf("the upgraded bytes were not counted: %v", l)
	}
}

// No SNI, or a name that is not a route, is refused at the handshake rather
// than guessed at, and logged.
func TestHandshakeRefusesNoSNIAndUnknownNames(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	f := newFixture(t, j, apiRoute(up, cred))

	// No SNI: a client connecting by address sends none.
	if c, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
		c.Close()
		t.Fatal("a handshake with no SNI completed")
	}
	if c, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: f.roots(), ServerName: "evil.example.test"}); err == nil {
		c.Close()
		t.Fatal("a handshake for a name that is not a route completed")
	}
	// The route's name, spelled differently, is still the route.
	c, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: f.roots(), ServerName: "API.Example.Test"})
	if err != nil {
		t.Fatalf("the route's own name was refused: %v", err)
	}
	c.Close()

	lines := f.journal.waitLines(t, "tls", 2)
	want := []struct{ sni, reason string }{{"", ReasonNoSNI}, {"evil.example.test", ReasonUnknownName}}
	for i, l := range lines[:2] {
		if l["decision"] != DecisionRefused || l["reason"] != want[i].reason || l["sni"] != want[i].sni {
			t.Errorf("tls line %d: %v", i, l)
		}
	}
	if len(up.requests()) != 0 {
		t.Fatal("a refused handshake reached the upstream")
	}
}

// A client that does not trust frisket's CA fails the handshake, and that is
// logged too: it is what a sandbox missing the CA looks like from here.
func TestUntrustingClientIsLogged(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	f := newFixture(t, j, apiRoute(up, cred))

	if c, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: up.pool(), ServerName: apiHost}); err == nil {
		c.Close()
		t.Fatal("verified frisket's leaf against the wrong CA")
	}
	l := f.journal.waitLines(t, "tls", 1)[0]
	if l["decision"] != DecisionFailed || !strings.Contains(fmt.Sprint(l["error"]), "certificate") {
		t.Fatalf("tls line: %v", l)
	}
}

// One connection, one name. A request for another host on a connection whose
// handshake chose this route is sent back with 421.
func TestMisdirectedRequestIsRefused(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		cred, _ := tokenFile(t, j, realToken)
		f := newFixture(t, j, apiRoute(up, cred))
		c := f.client(t, h2)

		req := newRequest(t, "GET", "https://"+apiHost+"/v1/messages", nil)
		req.Host = "other.example.test"
		res, _ := get(t, c, req)
		if res.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("got %d, want 421", res.StatusCode)
		}
		if len(up.requests()) != 0 {
			t.Fatal("a misdirected request reached the upstream")
		}
	})
}

// An upstream that cannot be verified is a failed request, not a request
// sent anyway: the credential crosses that hop.
func TestUnverifiableUpstreamFails(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	r := apiRoute(up, cred)
	r.UpstreamCAs = x509.NewCertPool() // trusts nothing
	f := newFixture(t, j, r)

	res, _ := get(t, f.client(t, false), newRequest(t, "GET", "https://"+apiHost+"/v1/messages", nil))
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", res.StatusCode)
	}
	if len(up.requests()) != 0 {
		t.Fatal("the request reached an upstream frisket could not verify")
	}
	l := f.journal.waitLines(t, "request", 1)[0]
	if l["level"] != "ERROR" || !strings.Contains(fmt.Sprint(l["error"]), "certificate") {
		t.Fatalf("log: %v", l)
	}
}

// Exactly one line per request, over many requests on reused connections.
func TestOneLinePerRequest(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		cred, _ := tokenFile(t, j, realToken)
		f := newFixture(t, j, apiRoute(up, cred))
		c := f.client(t, h2)
		const n = 25
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				target := "/v1/messages"
				if i%3 == 0 {
					target = "/v1/nope"
				}
				res, err := c.Do(newRequest(t, "GET", "https://"+apiHost+target, nil))
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			})
		}
		wg.Wait()
		f.journal.waitLines(t, "request", n)
		time.Sleep(50 * time.Millisecond)
		if got := len(f.journal.lines(t, "request")); got != n {
			t.Fatalf("%d lines for %d requests", got, n)
		}
	})
}

func TestNewRefusesBadRoutes(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := credential.Source(nil)
	cred, _ := tokenFile(t, &journal{}, realToken)
	good := Route{Name: "r", Host: "a.test", Upstream: "https://a.test", Credential: cred, Inject: Bearer(),
		Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}}}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for name, mutate := range map[string]func(r *Route){
		"plain http upstream": func(r *Route) { r.Upstream = "http://a.test" },
		"no credential":       func(r *Route) { r.Credential = src },
		"no injector":         func(r *Route) { r.Inject = nil },
		"empty scope":         func(r *Route) { r.Scope = Scope{} },
		"host with port":      func(r *Route) { r.Host = "a.test:443" },
		"no name":             func(r *Route) { r.Name = "" },
	} {
		r := good
		mutate(&r)
		if ic, err := New(Config{CA: ca, Routes: []Route{r}, Log: log}); err == nil {
			_ = ic.Close()
			t.Errorf("%s: built, want a refusal", name)
		}
	}
	if ic, err := New(Config{CA: ca, Routes: []Route{good, good}, Log: log}); err == nil {
		_ = ic.Close()
		t.Error("two routes for one host: built, want a refusal")
	}
	ic, err := New(Config{CA: ca, Routes: []Route{good}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	_ = ic.Close()
}
