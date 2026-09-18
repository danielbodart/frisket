package steer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// journal is the injected writer. THE LOGGER IS NOT SILENCED UNDER TEST: "one
// line per connection" is a property of frisket, and a logger that writes
// nowhere in a test turns that property into a hope.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

// lines returns the log entries whose msg is one of want, decoded.
func (j *journal) lines(t *testing.T, want string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()

	var out []map[string]any
	for _, l := range bytes.Split([]byte(raw), []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		if m["msg"] == want {
			out = append(out, m)
		}
	}
	return out
}

// waitFor polls until cond holds or the test is out of patience. The accept
// loop runs in its own goroutine, so there is no point in the test where the
// line is guaranteed to have been written except after it has been.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the log")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type fixture struct {
	session *Session
	journal *journal
	ln      net.Listener
	bound   netip.AddrPort
	served  chan *Conn
}

// newFixture starts a session on a real loopback listener. dst replaces the
// destination lookup, so the accept path, the classification and the log can
// be tested without a namespace or a ruleset; nil keeps the real one, under
// which a connection dialled straight at the listener is exactly what the
// workload makes when it finds frisket's port.
//
// Everything the accept loop reads is set before the loop starts: bound is
// known once the listener is, and nothing is filled in afterwards for a
// goroutine that is already running to race on.
func newFixture(t *testing.T, dst func(*net.TCPConn) netip.AddrPort) *fixture {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	bound, err := boundAddrPort(ln.Addr())
	if err != nil {
		t.Fatal(err)
	}

	j := &journal{}
	s := New("sess-1", j)
	s.Dst = dst

	f := &fixture{session: s, journal: j, ln: ln, bound: bound, served: make(chan *Conn, 16)}

	// Registration order matters: cleanups run last-registered-first, so the
	// wait has to be registered BEFORE the cancel that ends the loop it waits
	// for. Getting it the other way round deadlocks the test.
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := f.served
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, HandlerFunc(func(_ context.Context, c *Conn) {
			served <- c
			_, _ = io.WriteString(c, "served\n")
			_ = c.Close()
		}))
	}()
	return f
}

func (f *fixture) dial(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", f.ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the session's listener: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func steeredTo(addr string) func(*net.TCPConn) netip.AddrPort {
	ap := netip.MustParseAddrPort(addr)
	return func(*net.TCPConn) netip.AddrPort { return ap }
}

// A steered connection goes to the handler, which owns its one line: the
// session writes none of its own, or every connection would have two.
func TestASteeredConnectionIsHandedOnWithoutALineOfItsOwn(t *testing.T) {
	f := newFixture(t, steeredTo("140.82.121.3:443"))
	c := f.dial(t)

	var got *Conn
	select {
	case got = <-f.served:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was never called for a steered connection")
	}
	b, _ := io.ReadAll(c)
	if string(b) != "served\n" {
		t.Errorf("client read %q, want %q", b, "served\n")
	}
	if got.Orig.String() != "140.82.121.3:443" || got.Bound != f.bound || got.ID != 1 || got.Session != "sess-1" {
		t.Errorf("the handler was given %+v", got)
	}
	if !got.Verdict.Steered() {
		t.Errorf("verdict = %+v", got.Verdict)
	}
	time.Sleep(50 * time.Millisecond)
	if lines := f.journal.lines(t, "connection"); len(lines) != 0 {
		t.Errorf("the session logged a connection its handler served: %v", lines)
	}
}

// A connection dialled straight at the listener is accepted on a socket bound
// to the listener's own address: the real lookup, nothing replaced. Refused, with a
// line, and never handed on.
func TestUnsteeredConnectionIsRefusedAndLogged(t *testing.T) {
	f := newFixture(t, nil)
	c := f.dial(t)

	// Refusal is a close, with nothing written: there is nothing to say to a
	// connection the ruleset did not send here.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) != 0 {
		t.Errorf("an unsteered connection was answered with %q", b)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read after refusal: %v", err)
	}

	waitFor(t, func() bool { return len(f.journal.lines(t, "connection")) == 1 })
	line := f.journal.lines(t, "connection")[0]
	for k, want := range map[string]any{
		"session":  "sess-1",
		"listener": f.bound.String(),
		"dst":      f.bound.String(),
		"decision": string(Unsteered),
		"action":   ActionRefused,
		"reason":   ReasonOwnAddress,
	} {
		if line[k] != want {
			t.Errorf("line[%q] = %v, want %v (line: %v)", k, line[k], want, line)
		}
	}
	select {
	case c := <-f.served:
		t.Fatalf("the handler was given an unsteered connection to %v", c.Orig)
	case <-time.After(100 * time.Millisecond):
	}
}

// Every steered connection costs a descriptor on the HOST, so an unbounded
// sandbox is descriptor exhaustion for the daemon and through it for every
// other session.
func TestTheSessionCapRefusesAndSaysSo(t *testing.T) {
	block := make(chan struct{})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()

	j := &journal{}
	s := New("sess-cap", j)
	s.MaxConns = 1
	s.Dst = steeredTo("140.82.121.3:443")

	var handled atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, HandlerFunc(func(_ context.Context, c *Conn) {
			handled.Add(1)
			<-block
			_ = c.Close()
		}))
	}()

	first, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, func() bool { return handled.Load() == 1 })

	second, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	waitFor(t, func() bool { return len(j.lines(t, "connection")) == 1 })

	line := j.lines(t, "connection")[0]
	if line["action"] != ActionRefused || line["reason"] != ReasonAtCapacity {
		t.Errorf("the second connection = %v, want a refusal at the cap", line)
	}
	// The refusal still says where it was going: a refusal nobody can explain
	// later is as bad as a silent drop.
	if line["dst"] != "140.82.121.3:443" {
		t.Errorf("the refused line lost the destination: %v", line)
	}
	if line["decision"] != string(Steered) {
		t.Errorf("the cap changed what the ruleset said: %v", line)
	}
	if handled.Load() != 1 {
		t.Errorf("the handler saw %d connections, want 1", handled.Load())
	}

	close(block)
	cancel()
	<-done
}

func TestServeAnnouncesItsListenerAndStopsWithTheContext(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()

	j := &journal{}
	s := New("sess-2", j)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln, HandlerFunc(func(context.Context, *Conn) {})) }()

	waitFor(t, func() bool { return len(j.lines(t, "listening")) == 1 })
	if got := j.lines(t, "listening")[0]["listener"]; got != ln.Addr().String() {
		t.Errorf("listening line names %v, want %v", got, ln.Addr())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after cancel = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop when its context was cancelled; the listener stays open and the namespace stays pinned")
	}
}

// A datagram sent straight at the socket carries no mark and is refused -- with
// a line, because a silent drop is a bug -- and the handler never sees it.
func TestAnUnmarkedDatagramIsRefusedAndLogged(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	rc, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	_ = rc.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVMARK, 1); serr == nil {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
	})
	if serr != nil {
		_ = pc.Close()
		t.Skipf("cannot ask for the mark here: %v", serr)
	}

	j := &journal{}
	s := New("sess-udp", j)
	s.Mark = 1
	var handled atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.ServePacket(ctx, pc, packetFunc(func(context.Context, *Datagram) { handled.Add(1) }))
	}()
	defer func() { cancel(); <-done }()

	cl, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.Write([]byte("direct")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(j.lines(t, "datagram")) == 1 })
	line := j.lines(t, "datagram")[0]
	for k, want := range map[string]any{
		"decision": string(Unsteered),
		"action":   ActionRefused,
		"reason":   ReasonNotMarked,
		"dst":      pc.LocalAddr().String(),
		"mark":     float64(0),
	} {
		if line[k] != want {
			t.Errorf("line[%q] = %v, want %v (line: %v)", k, line[k], want, line)
		}
	}
	if handled.Load() != 0 {
		t.Error("the handler was given an unmarked datagram")
	}
}

type packetFunc func(context.Context, *Datagram)

func (f packetFunc) ServePacket(ctx context.Context, d *Datagram) { f(ctx, d) }
