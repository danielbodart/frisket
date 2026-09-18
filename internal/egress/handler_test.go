package egress

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/steer"
)

// echoServer is the fake upstream: it echoes what it reads, then closes, and
// counts connections so a test can prove a refused one never arrived.
func echoServer(t *testing.T) (netip.AddrPort, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), &n
}

type egressFixture struct {
	journal *journal
	ln      net.Listener
}

// startEgress runs a real steer.Session with the egress Handler behind it,
// the destination replaced so no namespace or ruleset is needed.
func startEgress(t *testing.T, h *Handler, orig netip.AddrPort) *egressFixture {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	j := &journal{}
	s := steer.New("sess-e", j)
	s.Dst = func(*net.TCPConn) netip.AddrPort { return orig }
	h.Log = slog.New(slog.NewJSONHandler(j, nil))
	h.PolicyName = "strict"

	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, h)
	}()
	return &egressFixture{journal: j, ln: ln}
}

// roundTrip sends msg, half-closes, and reads to EOF.
func (f *egressFixture) roundTrip(t *testing.T, msg string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp4", f.ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	b, _ := io.ReadAll(c)
	return string(b)
}

func (f *egressFixture) line(t *testing.T) map[string]any {
	t.Helper()
	waitFor(t, "the egress line", func() bool { return len(f.journal.lines(t, "egress")) >= 1 })
	// One line per connection, however long it lived.
	time.Sleep(30 * time.Millisecond)
	lines := f.journal.lines(t, "egress")
	if len(lines) != 1 {
		t.Fatalf("%d egress lines for one connection, want exactly 1: %v", len(lines), lines)
	}
	return lines[0]
}

func expect(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Errorf("line[%q] = %v (%T), want %v (%T); line: %v", k, line[k], line[k], v, v, line)
		}
	}
}

func TestAResolvedDestinationIsSplicedAndLoggedOnce(t *testing.T) {
	up, conns := echoServer(t)
	res := NewResolved(ResolvedConfig{})
	res.Record("upstream.example", up.Addr(), time.Minute, 7)
	c := testNetworkClassifier(t)
	f := startEgress(t, &Handler{Policy: &Policy{Classifier: c, Resolved: res}, Dialer: &Dialer{Classifier: c}}, up)

	if got := f.roundTrip(t, "hello, upstream"); got != "hello, upstream" {
		t.Fatalf("round trip = %q", got)
	}
	line := f.line(t)
	expect(t, line, map[string]any{
		"session":   "sess-e",
		"conn":      float64(1),
		"policy":    "strict",
		"dst":       up.String(),
		"name":      "upstream.example",
		"dns_query": float64(7),
		"decision":  DecisionAccepted,
		"bytes_out": float64(len("hello, upstream")),
		"bytes_in":  float64(len("hello, upstream")),
	})
	if _, ok := line["duration_ms"].(float64); !ok {
		t.Errorf("no duration on the line: %v", line)
	}
	if _, ok := line["reason"]; ok {
		t.Errorf("an accepted connection carries a reason: %v", line)
	}
	if conns.Load() != 1 {
		t.Errorf("upstream saw %d connections, want 1", conns.Load())
	}
}

// A destination the session never resolved is refused -- a workload that
// dials a literal address, or brings its own resolver, has nothing to show for
// it -- and the upstream never sees a connection.
func TestAnUnresolvedDestinationIsRefused(t *testing.T) {
	up, conns := echoServer(t)
	c := testNetworkClassifier(t)
	f := startEgress(t, &Handler{Policy: &Policy{Classifier: c, Resolved: NewResolved(ResolvedConfig{})}, Dialer: &Dialer{Classifier: c}}, up)

	if got := f.roundTrip(t, "anyone there?"); got != "" {
		t.Fatalf("a refused connection was answered with %q", got)
	}
	expect(t, f.line(t), map[string]any{
		"decision":  DecisionRefused,
		"reason":    ReasonNotResolved,
		"dst":       up.String(),
		"bytes_out": float64(0),
		"bytes_in":  float64(0),
	})
	if conns.Load() != 0 {
		t.Fatalf("the upstream saw %d connections for a refused destination", conns.Load())
	}
}

// Resolved AND structurally refused: refused, structurally, with the name on
// the line as a label -- the line a rebinding attempt should leave.
func TestAResolvedLoopbackAddressIsStillRefused(t *testing.T) {
	up, conns := echoServer(t)
	res := NewResolved(ResolvedConfig{})
	res.Record("rebind.example", up.Addr(), time.Minute, 3)
	c := defaultClassifier(t)
	f := startEgress(t, &Handler{Policy: &Policy{Classifier: c, Resolved: res}, Dialer: &Dialer{Classifier: c}}, up)

	_ = f.roundTrip(t, "x")
	line := f.line(t)
	expect(t, line, map[string]any{"decision": DecisionRefused, "name": "rebind.example"})
	if r, _ := line["reason"].(string); !strings.HasPrefix(r, "structural: "+ReasonLoopback) {
		t.Errorf("reason = %q, want a structural loopback refusal", r)
	}
	if conns.Load() != 0 {
		t.Fatalf("the upstream saw %d connections", conns.Load())
	}
}

// Classify says yes; between that and the dial the host gains the address;
// Control, looking at the address actually being dialled, says no. This is
// what having the check in Control buys.
func TestControlOverridesAStaleDecision(t *testing.T) {
	up, conns := echoServer(t)
	var reads atomic.Int64
	host := HostAddrsFrom(func() ([]netip.Prefix, error) {
		if reads.Add(1) == 1 {
			return nil, nil
		}
		return []netip.Prefix{netip.PrefixFrom(up.Addr(), 32)}, nil
	}, time.Nanosecond, nil)
	var ranges []Range
	for _, r := range DefaultRanges() {
		if r.Reason != ReasonLoopback {
			ranges = append(ranges, r)
		}
	}
	c, err := NewClassifier(ranges, host)
	if err != nil {
		t.Fatal(err)
	}
	res := NewResolved(ResolvedConfig{})
	res.Record("moving.example", up.Addr(), time.Minute, 1)
	f := startEgress(t, &Handler{Policy: &Policy{Classifier: c, Resolved: res}, Dialer: &Dialer{Classifier: c}}, up)

	_ = f.roundTrip(t, "x")
	line := f.line(t)
	expect(t, line, map[string]any{"decision": DecisionRefused})
	if r, _ := line["reason"].(string); !strings.HasPrefix(r, "structural at dial: "+ReasonHostOwned) {
		t.Errorf("reason = %q, want a host-owned refusal at dial", r)
	}
	if conns.Load() != 0 {
		t.Fatalf("the upstream saw %d connections", conns.Load())
	}
}

// Nothing listening: that is "failed", not "refused" -- an outage, not policy.
func TestADeadUpstreamIsAFailureNotARefusal(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	dead := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()

	res := NewResolved(ResolvedConfig{})
	res.Record("gone.example", dead.Addr(), time.Minute, 1)
	c := testNetworkClassifier(t)
	f := startEgress(t, &Handler{Policy: &Policy{Classifier: c, Resolved: res}, Dialer: &Dialer{Classifier: c}}, dead)

	_ = f.roundTrip(t, "x")
	line := f.line(t)
	expect(t, line, map[string]any{"decision": DecisionFailed, "name": "gone.example"})
	if _, ok := line["error"]; !ok {
		t.Errorf("a failed dial has no error on its line: %v", line)
	}
}
