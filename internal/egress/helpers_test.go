package egress

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// The synthetic host: two addresses no real interface has, so "the host's own
// address is refused" is tested without depending on the machine the test
// runs on. TEST-NET-3 and the documentation prefix, neither of which the
// structural table refuses on its own -- so if they are refused, it is because
// the host owns them.
var (
	hostV4 = netip.MustParseAddr("203.0.113.7")
	hostV6 = netip.MustParseAddr("2001:db8:77::7")
)

func testHost() *HostAddrs {
	return StaticHostAddrs(netip.PrefixFrom(hostV4, 32), netip.PrefixFrom(hostV6, 128))
}

func defaultClassifier(t testing.TB) *Classifier {
	t.Helper()
	c, err := NewClassifier(nil, testHost())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testNetworkClassifier is the default table WITHOUT the loopback rows and with
// no host addresses, which is what a test that needs a reachable "upstream" on
// 127.0.0.1 passes -- the ranges-as-data escape hatch PLAN.md asks for, used
// exactly as intended: at construction, never by an allowlist.
func testNetworkClassifier(t testing.TB) *Classifier {
	t.Helper()
	var ranges []Range
	for _, r := range DefaultRanges() {
		if r.Reason != ReasonLoopback {
			ranges = append(ranges, r)
		}
	}
	c, err := NewClassifier(ranges, StaticHostAddrs())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// journal is the injected log writer. THE LOGGER IS NOT SILENCED UNDER TEST:
// "exactly one line per connection" is a property, and a logger that writes
// nowhere under test turns it into a hope.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t testing.TB, msg string) []map[string]any {
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
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// tb is what both *testing.T and *rapid.T provide; testing.TB has a private
// method, so rapid cannot implement it.
type tb interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// tcpPair returns both ends of a real loopback TCP connection. Real sockets,
// not net.Pipe: the splice is only a splice between two *net.TCPConn, and
// half-close only means something on TCP. The caller closes them.
func tcpPair(t tb) (dialled, accepted *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   *net.TCPConn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.AcceptTCP()
		ch <- res{c, err}
	}()
	d, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return d, r.c
}
