package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/steer"
)

const project = "example/shop"

type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(raw, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// engine is a fake Docker daemon on a socket, answering the ownership lookup
// with whatever the test sets, and keeping every query it was asked.
type engine struct {
	mu      sync.Mutex
	status  int
	answer  string
	queries []*http.Request
	tr      *http.Transport
}

func newEngine(t *testing.T) *engine {
	t.Helper()
	// Not t.TempDir: a socket's path must fit in 108 bytes, and a test's
	// name can be most of that.
	dir, err := os.MkdirTemp("", "frisket-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix socket here: %v", err)
	}
	e := &engine{status: http.StatusOK, answer: "[]"}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.queries = append(e.queries, r)
		status, answer := e.status, e.answer
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	e.tr = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	t.Cleanup(e.tr.CloseIdleConnections)
	return e
}

func (e *engine) set(status int, answer string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status, e.answer = status, answer
}

func (e *engine) asked() []*http.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*http.Request(nil), e.queries...)
}

// running is the daemon's list answer: one container, labelled for owner,
// in state, publishing one port.
func running(owner, state, ip string, port int, typ string) string {
	b, _ := json.Marshal([]map[string]any{{
		"Id":     strings.Repeat("ab", 32),
		"Labels": map[string]string{"frisket.project": owner},
		"State":  state,
		"Ports":  []map[string]any{{"IP": ip, "PrivatePort": 5432, "PublicPort": port, "Type": typ}},
	}})
	return string(b)
}

// host is the project's address, stood in for by 127.0.0.2, with an echo
// server on it; and a decoy on 127.0.0.1 at the same port, which is where a
// connection would land if the relay dialled the address it was steered to.
type host struct {
	addr   netip.Addr
	port   uint16
	served atomic.Int64
	decoy  atomic.Int64
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{addr: netip.MustParseAddr("127.0.0.2")}
	ln, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no 127.0.0.2 to listen on: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h.port = netip.MustParseAddrPort(ln.Addr().String()).Port()
	decoy, err := net.Listen("tcp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port).String())
	if err != nil {
		t.Skipf("the stand-in's port is taken on 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { _ = decoy.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.served.Add(1)
			go func() {
				// Echo, then answer the client's half-close with our own.
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	go func() {
		for {
			c, err := decoy.Accept()
			if err != nil {
				return
			}
			h.decoy.Add(1)
			_ = c.Close()
		}
	}()
	return h
}

func (h *host) owned() string {
	return running(project, "running", h.addr.String(), int(h.port), "tcp")
}

// fixture is a real steer.Session serving the relay, its destination
// replaced so no namespace or ruleset is needed.
type fixture struct {
	journal *journal
	ln      net.Listener
	orig    chan netip.AddrPort
	cancel  context.CancelFunc
}

func start(t *testing.T, h *Handler, maxConns int) *fixture {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	f := &fixture{journal: &journal{}, ln: ln, orig: make(chan netip.AddrPort, 8)}
	s := steer.New("sess-r", f.journal)
	s.MaxConns = maxConns
	s.Dst = func(*net.TCPConn) netip.AddrPort { return <-f.orig }
	h.Log = slog.New(slog.NewJSONHandler(f.journal, nil))
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	t.Cleanup(cancel)
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, h)
	}()
	return f
}

// dial connects as the workload would, to orig. A refusal can be quick
// enough that the reset is the dial's own answer, and then there is no
// connection: nil.
func (f *fixture) dial(t *testing.T, orig netip.AddrPort) *net.TCPConn {
	t.Helper()
	f.orig <- orig
	c, err := net.DialTimeout("tcp4", f.ln.Addr().String(), 5*time.Second)
	if err != nil && strings.Contains(err.Error(), "reset") {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c.(*net.TCPConn)
}

// line waits for the one relay line of the connection numbered n.
func (f *fixture) line(t *testing.T, n int) map[string]any {
	t.Helper()
	waitFor(t, "the relay line", func() bool { return len(f.journal.lines(t, "relay")) >= n })
	time.Sleep(20 * time.Millisecond)
	lines := f.journal.lines(t, "relay")
	if len(lines) != n {
		t.Fatalf("%d relay lines for %d connections: %v", len(lines), n, lines)
	}
	return lines[n-1]
}

func expect(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Errorf("line[%q] = %v (%T), want %v (%T); line: %v", k, line[k], line[k], v, v, line)
		}
	}
}

func handler(e *engine, h *host) *Handler {
	return &Handler{Transport: e.tr, APIVersion: "1.56", Project: project, Address: h.addr, Ports: []uint16{h.port}}
}

// isReset is whether the client was answered with a reset, as a closed port
// answers, rather than an orderly close.
func isReset(t *testing.T, c *net.TCPConn) bool {
	t.Helper()
	if c == nil {
		return true
	}
	_, err := io.ReadAll(c)
	return err != nil && strings.Contains(err.Error(), "reset")
}

// A connection to one of the project's ports, while a running container of
// the project publishes it on the project's address, is carried both ways,
// its half-close with it, and said in one line with what moved.
func TestAConnectionToAPublishedPortIsRelayedBothWaysWithItsHalfClose(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, h.owned())
	f := start(t, handler(e, h), 0)

	c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
	if _, err := io.WriteString(c, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q, %v; want the echo and then the host's half-close", b, err)
	}
	line := f.line(t, 1)
	expect(t, line, map[string]any{
		"session":  "sess-r",
		"conn":     float64(1),
		"orig":     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port).String(),
		"to":       netip.AddrPortFrom(h.addr, h.port).String(),
		"project":  project,
		"decision": DecisionRelayed,
		"out":      float64(5),
		"in":       float64(5),
		"idle":     false,
	})
	if _, ok := line["reason"]; ok {
		t.Errorf("a relayed connection's line has a reason: %v", line)
	}
	for _, k := range []string{"peer", "duration"} {
		if _, ok := line[k]; !ok {
			t.Errorf("the line has no %s: %v", k, line)
		}
	}
	if h.decoy.Load() != 0 {
		t.Error("the relay dialled 127.0.0.1, the address it was steered to")
	}
}

// The relay asks the daemon about exactly this project, this port over TCP,
// and running containers only, at the route's highest version.
func TestTheOwnershipQueryNamesTheLabelThePortAndRunning(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	f := start(t, handler(e, h), 0)
	if c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port)); c != nil {
		_, _ = io.ReadAll(c)
	}
	f.line(t, 1)

	asked := e.asked()
	if len(asked) != 1 {
		t.Fatalf("the daemon was asked %d times, want once", len(asked))
	}
	r := asked[0]
	if r.Method != http.MethodGet || r.URL.Path != "/v1.56/containers/json" {
		t.Errorf("asked %s %s", r.Method, r.URL.Path)
	}
	var filters map[string][]string
	if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
		t.Fatalf("filters %q: %v", r.URL.Query().Get("filters"), err)
	}
	want := map[string][]string{
		"label":   {"frisket.project=" + project},
		"publish": {strconv.Itoa(int(h.port)) + "/tcp"},
		"status":  {"running"},
	}
	for k, v := range want {
		if len(filters[k]) != 1 || filters[k][0] != v[0] {
			t.Errorf("filters[%s] = %v, want %v", k, filters[k], v)
		}
	}
	if len(filters) != len(want) {
		t.Errorf("filters = %v, want only %v", filters, want)
	}
}

// Nothing is dialled unless the daemon's own answer shows a running
// container of this project publishing exactly the project's address and
// this port over TCP: frisket checks every one of those itself, so a daemon
// that ignored a filter, or a container that publishes the port somewhere
// else, never sends the connection to whatever else holds the port.
func TestOnlyARunningOwnedContainerPublishingTheAddressAndPortIsRelayedTo(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	f := start(t, handler(e, h), 0)
	cases := map[string]string{
		"no container":           "[]",
		"another project's":      running("evil/x", "running", h.addr.String(), int(h.port), "tcp"),
		"an unlabelled one":      running("", "running", h.addr.String(), int(h.port), "tcp"),
		"owned but not running":  running(project, "exited", h.addr.String(), int(h.port), "tcp"),
		"owned on another IP":    running(project, "running", "127.0.0.1", int(h.port), "tcp"),
		"owned on every address": running(project, "running", "0.0.0.0", int(h.port), "tcp"),
		"owned on another port":  running(project, "running", h.addr.String(), int(h.port)+1, "tcp"),
		"owned over udp":         running(project, "running", h.addr.String(), int(h.port), "udp"),
	}
	n := 0
	for name, answer := range cases {
		e.set(http.StatusOK, answer)
		c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
		n++
		if !isReset(t, c) {
			t.Errorf("%s: the client was not reset", name)
		}
		line := f.line(t, n)
		expect(t, line, map[string]any{"decision": DecisionRefused, "reason": ReasonNotPublished, "out": float64(0), "in": float64(0)})
	}
	if h.served.Load() != 0 || h.decoy.Load() != 0 {
		t.Errorf("a refused connection was dialled: %d to the address, %d to 127.0.0.1", h.served.Load(), h.decoy.Load())
	}
}

// A daemon that cannot say is a refusal, and says so, rather than a dial on
// the chance that the port is the container's.
func TestADaemonThatCannotSayRefusesTheConnection(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	f := start(t, handler(e, h), 0)
	for i, a := range []struct {
		status int
		body   string
	}{
		{http.StatusInternalServerError, `{"message":"boom"}`},
		{http.StatusOK, "not json"},
		{http.StatusFound, h.owned()},
		// Owned, running and published as asked, but not the daemon's ID.
		{http.StatusOK, strings.Replace(h.owned(), strings.Repeat("ab", 32), "", 1)},
		{http.StatusOK, strings.Replace(h.owned(), strings.Repeat("ab", 32), "xyz", 1)},
		{http.StatusOK, strings.Replace(h.owned(), strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1)},
	} {
		e.set(a.status, a.body)
		c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
		if !isReset(t, c) {
			t.Errorf("answer %d (%d): the client was not reset", i, a.status)
		}
		expect(t, f.line(t, i+1), map[string]any{"decision": DecisionRefused, "reason": ReasonLookup})
	}
	if h.served.Load() != 0 {
		t.Error("a connection the daemon could not vouch for was dialled")
	}
}

// Whichever of its addresses the workload dialled, a connection goes to the
// project's address, at the port it was steered for: never to the address it
// named.
func TestEveryLoopbackGoesToTheProjectsAddressAtTheSteeredPort(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, h.owned())
	f := start(t, handler(e, h), 0)
	origs := []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port),
		netip.AddrPortFrom(netip.IPv6Loopback(), h.port),
		netip.AddrPortFrom(h.addr, h.port),
	}
	for i, orig := range origs {
		c := f.dial(t, orig)
		_, _ = io.WriteString(c, "x")
		_ = c.CloseWrite()
		if b, _ := io.ReadAll(c); string(b) != "x" {
			t.Errorf("%v: echoed %q", orig, b)
		}
		expect(t, f.line(t, i+1), map[string]any{"orig": orig.String(), "to": netip.AddrPortFrom(h.addr, h.port).String(), "decision": DecisionRelayed})
	}
	if h.served.Load() != 3 || h.decoy.Load() != 0 {
		t.Errorf("the address served %d, 127.0.0.1 %d; want 3 and 0", h.served.Load(), h.decoy.Load())
	}
}

// Steers takes 127.0.0.1, ::1 and the project's address however they are
// spelt, at any port, and nothing else: the port is the handler's to judge.
func TestTheRelaySteersItsAddressesAtAnyPort(t *testing.T) {
	h := &Handler{Address: netip.MustParseAddr("127.101.170.171")}
	for s, want := range map[string]bool{
		"127.0.0.1:64320":             true,
		"127.0.0.1:1":                 true,
		"[::1]:64320":                 true,
		"[::1%lo]:64320":              true,
		"[::ffff:127.0.0.1]:64320":    true,
		"127.101.170.171:64320":       true,
		"[::ffff:127.101.170.171]:80": true,
		"127.10.146.214:64320":        false,
		"127.0.0.2:64320":             false,
		"192.0.2.2:443":               false,
		"[2001:db8::2]:64320":         false,
	} {
		if got := h.Steers(netip.MustParseAddrPort(s)); got != want {
			t.Errorf("Steers(%s) = %v, want %v", s, got, want)
		}
	}
}

// A port the document does not name -- one a restore dropped, whose ruleset
// still steers it -- is refused before the daemon is asked anything.
func TestAPortNotTheProjectsIsRefusedWithoutALookup(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, running(project, "running", h.addr.String(), int(h.port)+1, "tcp"))
	f := start(t, handler(e, h), 0)
	c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port+1))
	if !isReset(t, c) {
		t.Error("the client was not reset")
	}
	expect(t, f.line(t, 1), map[string]any{"decision": DecisionRefused, "reason": ReasonNotAPort})
	if n := len(e.asked()); n != 0 {
		t.Errorf("the daemon was asked %d times about a port that is not the project's", n)
	}
}

// A check that passes and a dial that does not is a failure, not a refusal,
// and the client is reset as the closed port would have reset it.
func TestARefusedDialAfterAPassingCheckFails(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	// Nothing listens at 127.0.0.3.
	h.addr = netip.MustParseAddr("127.0.0.3")
	e.set(http.StatusOK, h.owned())
	f := start(t, handler(e, h), 0)
	c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
	if !isReset(t, c) {
		t.Error("the client was not reset")
	}
	line := f.line(t, 1)
	expect(t, line, map[string]any{"decision": DecisionFailed, "reason": ReasonDial})
	if _, ok := line["error"]; !ok {
		t.Errorf("a failed dial's line has no error: %v", line)
	}
}

// The session's cap bounds relayed connections as it bounds every other:
// one over it is refused by the session, and never reaches the host.
func TestTheSessionsCapBoundsRelayedConnections(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, h.owned())
	f := start(t, handler(e, h), 1)
	orig := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port)
	first := f.dial(t, orig)
	_, _ = io.WriteString(first, "a")
	if _, err := io.ReadFull(first, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if second := f.dial(t, orig); second != nil {
		if _, err := second.Read(make([]byte, 1)); err == nil {
			t.Error("a connection over the cap was answered")
		}
	}
	waitFor(t, "the refusal", func() bool { return len(f.journal.lines(t, "connection")) == 1 })
	expect(t, f.journal.lines(t, "connection")[0], map[string]any{"reason": steer.ReasonAtCapacity})
	if h.served.Load() != 1 {
		t.Errorf("the host was reached %d times, want once", h.served.Load())
	}
}

// A relayed connection has no idle limit: left idle for many times the
// period in which egress's watchdog, set that short, ends a connection, it
// still carries bytes both ways.
func TestARelayedConnectionIsNeverCutForBeingIdle(t *testing.T) {
	const short = 40 * time.Millisecond
	// What the relay hands the splice, since no wait in a test is as long
	// as egress.DefaultIdle: it must be zero, the splice's none.
	var handed atomic.Int64
	handed.Store(-1)
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, h.owned())
	rh := handler(e, h)
	rh.splice = func(ctx context.Context, client, upstream *net.TCPConn, idle time.Duration) egress.SpliceResult {
		handed.Store(int64(idle))
		return egress.Splice(ctx, client, upstream, idle)
	}
	f := start(t, rh, 0)
	c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
	_ = c.SetDeadline(time.Now().Add(time.Minute))

	// The control: an idle pair spliced by egress with the short idle is
	// ended within the wait.
	_, client := pair(t)
	upstream, _ := pair(t)
	res := make(chan egress.SpliceResult, 1)
	go func() { res <- egress.Splice(context.Background(), client, upstream, short) }()

	time.Sleep(10 * short)
	select {
	case r := <-res:
		if !r.Idle {
			t.Fatalf("egress's splice ended but not for idleness: %+v", r)
		}
	default:
		t.Fatal("egress's splice with a short idle was still up: the wait proves nothing")
	}

	if _, err := io.WriteString(c, "still"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "still" {
		t.Fatalf("after idling, read %q, %v", buf, err)
	}
	if n := len(f.journal.lines(t, "relay")); n != 0 {
		t.Errorf("the idle connection was logged as over: %d lines", n)
	}
	if got := time.Duration(handed.Load()); got != 0 {
		t.Errorf("the relay handed the splice an idle limit of %v, want none (0)", got)
	}
}

// pair is both ends of a real loopback TCP connection.
func pair(t *testing.T) (dialled, accepted *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	ch := make(chan *net.TCPConn, 1)
	go func() {
		c, _ := ln.AcceptTCP()
		ch <- c
	}()
	d, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a == nil {
		t.Fatal("no accept")
	}
	t.Cleanup(func() { _ = d.Close(); _ = a.Close() })
	return d, a
}

// The session's end ends a relayed connection in flight, idle limit or
// none, and its line is written then.
func TestTheSessionsEndEndsARelayedConnection(t *testing.T) {
	e, h := newEngine(t), newHost(t)
	e.set(http.StatusOK, h.owned())
	f := start(t, handler(e, h), 0)
	c := f.dial(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.port))
	_, _ = io.WriteString(c, "a")
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	f.cancel()
	if _, err := io.ReadAll(c); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("the relayed connection outlived its session: %v", err)
	}
	expect(t, f.line(t, 1), map[string]any{"decision": DecisionRelayed, "out": float64(1), "in": float64(1)})
}
