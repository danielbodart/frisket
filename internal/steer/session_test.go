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

// newFixture starts a session on a real loopback listener with the
// original-destination lookup replaced, so the accept path, the classification
// and the log can be tested without a namespace or a redirect rule.
func newFixture(t *testing.T, orig func(*net.TCPConn) (netip.AddrPort, error)) *fixture {
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
	s.OrigDst = orig

	f := &fixture{session: s, journal: j, ln: ln, bound: bound, served: make(chan *Conn, 16)}

	// Registration order matters: cleanups run last-registered-first, so the
	// wait has to be registered BEFORE the cancel that ends the loop it waits
	// for. Getting it the other way round deadlocks the test.
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, HandlerFunc(func(_ context.Context, c *Conn) {
			// Read Orig several times: it is a field, cached at accept, and
			// nothing here may cause a second conntrack lookup.
			for range 5 {
				_ = c.Orig
			}
			f.served <- c
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

func steeredTo(addr string) func(*net.TCPConn) (netip.AddrPort, error) {
	ap := netip.MustParseAddrPort(addr)
	return func(*net.TCPConn) (netip.AddrPort, error) { return ap, nil }
}

func TestSteeredConnectionIsServedAndLoggedExactlyOnce(t *testing.T) {
	f := newFixture(t, steeredTo("140.82.121.3:443"))
	c := f.dial(t)

	select {
	case <-f.served:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was never called for a steered connection")
	}
	b, _ := io.ReadAll(c)
	if string(b) != "served\n" {
		t.Errorf("client read %q, want %q", b, "served\n")
	}

	waitFor(t, func() bool { return len(f.journal.lines(t, "connection")) == 1 })
	line := f.journal.lines(t, "connection")[0]
	for k, want := range map[string]any{
		"session":  "sess-1",
		"conn":     float64(1),
		"listener": f.bound.String(),
		"dst":      "140.82.121.3:443",
		"decision": string(Steered),
		"action":   ActionAccepted,
	} {
		if line[k] != want {
			t.Errorf("line[%q] = %v, want %v (line: %v)", k, line[k], want, line)
		}
	}
	if _, ok := line["reason"]; ok {
		t.Errorf("a steered connection carries a refusal reason: %v", line)
	}

	// One line per connection, and only one, however long it lived.
	time.Sleep(50 * time.Millisecond)
	if got := len(f.journal.lines(t, "connection")); got != 1 {
		t.Errorf("%d lines for one connection, want 1", got)
	}
}

func TestUnsteeredConnectionIsRefusedAndLogged(t *testing.T) {
	for _, tc := range []struct {
		name       string
		orig       func(*net.TCPConn) (netip.AddrPort, error)
		wantReason string
	}{
		{
			// The workload found the port and dialled it.
			name:       "the listener's own address",
			orig:       nil, // filled in below, once the port is known
			wantReason: ReasonOwnAddress,
		},
		{
			name:       "no conntrack entry",
			orig:       func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPort{}, errors.New("ENOENT") },
			wantReason: ReasonNoConntrack,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f *fixture
			orig := tc.orig
			if orig == nil {
				orig = func(*net.TCPConn) (netip.AddrPort, error) { return f.bound, nil }
			}
			f = newFixture(t, orig)
			c := f.dial(t)

			// Refusal is a close, with nothing written: there is nothing to say
			// to a connection the kernel did not send here.
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
			if line["decision"] != string(Unsteered) || line["action"] != ActionRefused {
				t.Errorf("line = %v, want an unsteered refusal", line)
			}
			if line["reason"] != tc.wantReason {
				t.Errorf("reason = %v, want %q", line["reason"], tc.wantReason)
			}

			select {
			case c := <-f.served:
				t.Fatalf("the handler was given an unsteered connection to %v", c.Orig)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// READ THE ORIGINAL DESTINATION AT ACCEPT AND CACHE IT. Flushing conntrack
// mid-connection makes a second lookup fail or lie, so a connection that has
// been classified must never be classified again.
func TestTheOriginalDestinationIsReadOnlyOnce(t *testing.T) {
	var reads atomic.Int64
	f := newFixture(t, func(c *net.TCPConn) (netip.AddrPort, error) {
		reads.Add(1)
		return netip.MustParseAddrPort("140.82.121.3:443"), nil
	})

	const conns = 4
	for range conns {
		c := f.dial(t)
		select {
		case <-f.served:
		case <-time.After(5 * time.Second):
			t.Fatal("the handler was never called")
		}
		_, _ = io.ReadAll(c)
	}
	if got := reads.Load(); got != conns {
		t.Errorf("the original destination was looked up %d times for %d connections", got, conns)
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
	s.OrigDst = steeredTo("140.82.121.3:443")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, HandlerFunc(func(_ context.Context, c *Conn) {
			<-block
			_ = c.Close()
		}))
	}()

	first, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, func() bool { return len(j.lines(t, "connection")) == 1 })

	second, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	waitFor(t, func() bool { return len(j.lines(t, "connection")) == 2 })

	lines := j.lines(t, "connection")
	if lines[0]["action"] != ActionAccepted {
		t.Errorf("the first connection was not accepted: %v", lines[0])
	}
	if lines[1]["action"] != ActionRefused || lines[1]["reason"] != ReasonAtCapacity {
		t.Errorf("the second connection = %v, want a refusal at the cap", lines[1])
	}
	// The refusal still says where it was going: a refusal nobody can explain
	// later is as bad as a silent drop.
	if lines[1]["dst"] != "140.82.121.3:443" {
		t.Errorf("the refused line lost the destination: %v", lines[1])
	}
	if lines[1]["decision"] != string(Steered) {
		t.Errorf("the cap changed what the kernel said: %v", lines[1])
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
