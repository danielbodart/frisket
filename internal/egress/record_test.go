package egress

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/danielbodart/frisket/internal/intercept"
	recording "github.com/danielbodart/frisket/internal/record"
)

// recordingHandler is a recording session's egress: its resolved set empty,
// what its DNS resolved for names off the allowlist in unlisted.
func recordingHandler(t *testing.T, c *Classifier, def recording.Answer, asker intercept.Asker) (*Handler, *Resolved, *journal) {
	t.Helper()
	j := &journal{}
	rec, err := recording.New(recording.Config{Policy: "strict", Default: def, Log: slog.New(slog.NewJSONHandler(j, nil))})
	if err != nil {
		t.Fatal(err)
	}
	unlisted := NewResolved(ResolvedConfig{})
	return &Handler{
		Policy: &Policy{Classifier: c, Resolved: NewResolved(ResolvedConfig{})},
		Dialer: &Dialer{Classifier: c},
		Record: &Recording{Recorder: rec, Unlisted: unlisted, Asker: asker, Workspace: "/work"},
	}, unlisted, j
}

// A connection to a name off the allowlist, which the session's DNS
// resolved because it is recording, is the recording's to decide, by name
// and port; admitted, it is dialled as any other.
func TestARecordingSessionDecidesAConnectionToANameOffTheAllowlist(t *testing.T) {
	dst, n := echoServer(t)
	h, unlisted, rj := recordingHandler(t, testNetworkClassifier(t), recording.Allow, nil)
	unlisted.Record("unlisted.example.test", dst.Addr(), 0, 4)
	f := startEgress(t, h, dst)
	if got := f.roundTrip(t, "hello"); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if n.Load() != 1 {
		t.Fatal("never reached the destination")
	}
	waitFor(t, "the egress line", func() bool { return len(f.journal.lines(t, "egress")) == 1 })
	l := f.journal.lines(t, "egress")[0]
	if l["decision"] != DecisionAccepted || l["reason"] != RuleRecorded || l["name"] != "unlisted.example.test" {
		t.Fatalf("egress line %v", l)
	}
	r := rj.lines(t, "record")
	if len(r) != 1 {
		t.Fatalf("%d record lines", len(r))
	}
	for k, v := range map[string]any{"kind": "egress", "name": "unlisted.example.test", "port": float64(dst.Port()),
		"address": dst.String(), "would": "refuse", "rule": recording.RuleNotAllowed, "answer": "allow", "source": "default"} {
		if r[0][k] != v {
			t.Errorf("%s = %v, want %v", k, r[0][k], v)
		}
	}
}

// Refused by its default, or by a person, it never leaves; and a person is
// asked about it as a connection, by its name.
func TestARecordingSessionRefusesAConnectionByItsAnswer(t *testing.T) {
	dst, n := echoServer(t)
	asker := &connAsker{answer: recording.Refuse}
	h, unlisted, rj := recordingHandler(t, testNetworkClassifier(t), "", asker)
	unlisted.Record("unlisted.example.test", dst.Addr(), 0, 4)
	f := startEgress(t, h, dst)
	if got := f.roundTrip(t, "hello"); got != "" {
		t.Fatalf("got %q", got)
	}
	if n.Load() != 0 {
		t.Fatal("reached the destination")
	}
	asked := asker.questions()
	if len(asked) != 1 {
		t.Fatalf("asked %d times", len(asked))
	}
	q := asked[0]
	if q.Kind != intercept.KindEgress || q.Host != "unlisted.example.test" || q.Address != dst.String() || !q.Record || q.ID == "" || q.Workspace != "/work" {
		t.Fatalf("question %+v", q)
	}
	waitFor(t, "the record line", func() bool { return len(rj.lines(t, "record")) == 1 })
	if l := rj.lines(t, "record")[0]; l["answer"] != "refuse" || l["source"] != "human" {
		t.Fatalf("record line %v", l)
	}
}

type connAsker struct {
	mu     sync.Mutex
	answer recording.Answer
	asked  []intercept.Question
}

func (a *connAsker) questions() []intercept.Question {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]intercept.Question(nil), a.asked...)
}

func (a *connAsker) Ask(_ context.Context, q intercept.Question) (recording.Answer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, q)
	return a.answer, nil
}

// An address nobody resolved -- a literal, dialled by itself -- has no name
// to grant and stays refused, written down as that; so does every
// structural refusal but the local network's.
func TestARecordingSessionStillRefusesWhatNoGrantCouldAllow(t *testing.T) {
	dst, n := echoServer(t)
	h, _, rj := recordingHandler(t, testNetworkClassifier(t), recording.Allow, nil)
	f := startEgress(t, h, dst)
	if got := f.roundTrip(t, "hello"); got != "" || n.Load() != 0 {
		t.Fatalf("a literal address: got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj.lines(t, "record")) == 1 })
	if l := rj.lines(t, "record")[0]; l["source"] != "hard" || l["reason"] != ReasonNotResolved || l["address"] != dst.String() {
		t.Fatalf("record line %v", l)
	}

	// Loopback, by a name, under the default table.
	h2, unlisted, rj2 := recordingHandler(t, defaultClassifier(t), recording.Allow, nil)
	unlisted.Record("localhost.example.test", dst.Addr(), 0, 1)
	f2 := startEgress(t, h2, dst)
	if got := f2.roundTrip(t, "hello"); got != "" || n.Load() != 0 {
		t.Fatalf("loopback: got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj2.lines(t, "record")) == 1 })
	if l := rj2.lines(t, "record")[0]; l["source"] != "hard" || l["reason"] != "structural: loopback" || l["name"] != "localhost.example.test" {
		t.Fatalf("record line %v", l)
	}
}

// A private address by a name -- the local network -- is a recording's
// subject like any other, marked lan, unless it is a router of the host's.
func TestARecordingSessionDecidesTheLocalNetworkByName(t *testing.T) {
	gw := netip.MustParseAddr("10.9.0.1")
	c := defaultClassifier(t).WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32)))
	h, unlisted, rj := recordingHandler(t, c, recording.Refuse, nil)
	nas := netip.MustParseAddrPort("10.9.0.20:445")
	unlisted.Record("nas.lan", nas.Addr(), 0, 1)
	f := startEgress(t, h, nas)
	if got := f.roundTrip(t, "hello"); got != "" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj.lines(t, "record")) == 1 })
	if l := rj.lines(t, "record")[0]; l["lan"] != true || l["name"] != "nas.lan" || l["source"] != "default" || l["rule"] != "structural: private" {
		t.Fatalf("record line %v", l)
	}

	h2, unlisted2, rj2 := recordingHandler(t, c, recording.Allow, nil)
	router := netip.AddrPortFrom(gw, 80)
	unlisted2.Record("router.lan", gw, 0, 1)
	f2 := startEgress(t, h2, router)
	if got := f2.roundTrip(t, "hello"); got != "" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj2.lines(t, "record")) == 1 })
	if l := rj2.lines(t, "record")[0]; l["source"] != "hard" || l["reason"] != "structural: "+ReasonGateway {
		t.Fatalf("record line %v", l)
	}
}

func TestClassifyLANAdmitsTheLocalNetworkAndNothingElse(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	ownPrivate := netip.MustParseAddr("192.168.1.50")
	host := StaticHostAddrs(netip.PrefixFrom(hostV4, 32), netip.PrefixFrom(ownPrivate, 32))
	base, err := NewClassifier(nil, host)
	if err != nil {
		t.Fatal(err)
	}
	c := base.WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32)))
	for addr, want := range map[string]string{
		"192.168.1.20":           "",
		"10.1.2.3":               "",
		"172.16.0.9":             "",
		"169.254.10.10":          "",
		"fd12:3456::1":           "",
		"fe80::1":                "",
		"::ffff:192.168.1.20":    "",
		"192.168.1.1":            ReasonGateway,
		"192.168.1.50":           ReasonHostOwned,
		"169.254.169.254":        ReasonMetadata,
		"fd00:ec2::254":          ReasonMetadata,
		"127.0.0.1":              ReasonLoopback,
		"100.64.0.1":             ReasonCGNAT,
		"0.0.0.0":                ReasonUnspecified,
		"224.0.0.1":              ReasonMulticast,
		"::ffff:0:192.168.1.20":  ReasonPrivate, // a v6 spelling stays refused
		"64:ff9b::192.168.1.20":  ReasonPrivate,
		"203.0.113.7":            ReasonHostOwned,
		"93.184.216.34":          "",
		"fec0::1":                ReasonSiteLocal,
		"2002:c0a8:0114::1":      ReasonPrivate,
		"2001:db8:77::7":         "",
		"ff02::1":                ReasonMulticast,
		"::1":                    ReasonLoopback,
		"10.255.255.255":         "",
		"192.168.255.255":        "",
		"172.31.255.255":         "",
		"172.32.0.1":             "",
		"169.254.170.2":          ReasonMetadata,
		"fe80::1%eth0":           "",
		"fd00::1":                "",
		"fc00::1":                "",
		"::":                     ReasonUnspecified,
		"240.0.0.1":              ReasonReserved,
		"64:ff9b:1::1":           ReasonLocalNAT64,
		"::127.0.0.1":            ReasonLoopback,
		"::ffff:127.0.0.1":       ReasonLoopback,
		"::ffff:169.254.169.254": ReasonMetadata,
	} {
		if got := c.ClassifyLAN(netip.MustParseAddr(addr)).Reason; got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
	// Without the host's routers, nothing on the local network.
	if got := base.ClassifyLAN(netip.MustParseAddr("192.168.1.20")).Reason; got != ReasonGatewayUnknown {
		t.Errorf("no gateways: %q", got)
	}
	// And Classify itself is unchanged by it.
	if got := c.Classify(netip.MustParseAddr("192.168.1.20")).Reason; got != ReasonPrivate {
		t.Errorf("Classify: %q", got)
	}
}

// DialLAN checks at the dial, as DialTCP does: a router, or the host's own
// address, is refused before connect.
func TestDialLANChecksTheAddressDialled(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	c := defaultClassifier(t).WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32)))
	d := &Dialer{Classifier: c}
	for _, dst := range []string{"192.168.1.1:80", "127.0.0.1:80", "203.0.113.7:80"} {
		_, err := d.DialLAN(context.Background(), netip.MustParseAddrPort(dst))
		if _, ok := AsRefused(err); !ok {
			t.Errorf("%s: %v, want a refusal", dst, err)
		}
	}
	if err := d.controlLAN("tcp4", "192.168.1.20:80", nil); err != nil {
		t.Errorf("a LAN host: %v", err)
	}
}

// The host's routes, read live, parse: whatever this machine has.
func TestTheHostsGatewaysRead(t *testing.T) {
	if _, err := NewGateways(0).Prefixes(); err != nil {
		t.Skipf("no route dump here: %v", err)
	}
}
