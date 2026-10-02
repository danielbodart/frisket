package egress

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

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
	if got := f.refused(t, "hello"); got != "" {
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

// A question whose client goes while it is open is closed with it, as an
// HTTP or SSH one is: refused for want of an answer, and nothing asked about
// a connection nobody holds.
func TestARecordingSessionsQuestionEndsWithItsConnection(t *testing.T) {
	dst, n := echoServer(t)
	asker := &waitingAsker{asked: make(chan struct{}), ended: make(chan struct{})}
	h, unlisted, rj := recordingHandler(t, testNetworkClassifier(t), "", asker)
	unlisted.Record("unlisted.example.test", dst.Addr(), 0, 4)
	f := startEgress(t, h, dst)
	c, err := net.DialTimeout("tcp4", f.ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-asker.asked:
	case <-time.After(10 * time.Second):
		t.Fatal("never asked")
	}
	_ = c.Close()
	select {
	case <-asker.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the question outlived its connection")
	}
	waitFor(t, "the record line", func() bool { return len(rj.lines(t, "record")) == 1 })
	if l := rj.lines(t, "record")[0]; l["source"] != "unanswered" || l["reason"] != intercept.ReasonStoppedWaiting {
		t.Fatalf("record line %v", l)
	}
	if n.Load() != 0 {
		t.Fatal("reached the destination")
	}
}

// waitingAsker never answers: it waits for its question to be withdrawn.
type waitingAsker struct {
	asked, ended chan struct{}
}

func (a *waitingAsker) Ask(ctx context.Context, _ intercept.Question) (recording.Answer, error) {
	close(a.asked)
	<-ctx.Done()
	close(a.ended)
	return "", ctx.Err()
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
// subject, marked lan and decided as any other is, by the default or by a
// person, unless it is a router of the host's.
func TestARecordingSessionDecidesTheLocalNetworkByName(t *testing.T) {
	// By the default, with nobody asked: the echo server stands for a LAN
	// host, on an address this classifier calls private.
	nas, n := echoServer(t)
	h, unlisted, rj := recordingHandler(t, lanTestClassifier(t), recording.Allow, nil)
	unlisted.Record("nas.lan", nas.Addr(), 0, 1)
	f := startEgress(t, h, nas)
	if got := f.roundTrip(t, "hello"); got != "hello" || n.Load() != 1 {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj.lines(t, "record")) == 1 })
	if l := rj.lines(t, "record")[0]; l["lan"] != true || l["name"] != "nas.lan" || l["source"] != "default" ||
		l["answer"] != "allow" || l["rule"] != "structural: private" {
		t.Fatalf("record line %v", l)
	}

	gw := netip.MustParseAddr("10.9.0.1")
	c := defaultClassifier(t).WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32))).WithHostNetworks(StaticHostAddrs(dockerBridge))
	lanHost := netip.MustParseAddrPort("10.9.0.20:445")
	// By a person, with no default, and the question says lan.
	asker := &connAsker{answer: recording.Refuse}
	h1, unlisted1, rj1 := recordingHandler(t, c, "", asker)
	unlisted1.Record("nas.lan", lanHost.Addr(), 0, 1)
	f1 := startEgress(t, h1, lanHost)
	if got := f1.refused(t, "hello"); got != "" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "the record line", func() bool { return len(rj1.lines(t, "record")) == 1 })
	if l := rj1.lines(t, "record")[0]; l["lan"] != true || l["source"] != "human" || l["answer"] != "refuse" {
		t.Fatalf("record line %v", l)
	}
	if q := asker.questions(); len(q) != 1 || q[0].Address != lanHost.String() || !q[0].LAN {
		t.Fatalf("questions %+v", q)
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
	c := base.WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32))).WithHostNetworks(StaticHostAddrs(dockerBridge, netip.MustParsePrefix("fd99::/64")))
	for addr, want := range map[string]string{
		"192.168.1.20":           "",
		"10.1.2.3":               "",
		"172.16.0.9":             "",
		"172.17.0.2":             ReasonHostNetwork, // a container, on docker0
		"172.17.255.254":         ReasonHostNetwork,
		"fd99::2":                ReasonHostNetwork,
		"fd99:0:0:1::2":          "",
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
	// Without the host's routers, or its own networks, nothing on the local
	// network.
	if got := base.ClassifyLAN(netip.MustParseAddr("192.168.1.20")).Reason; got != ReasonGatewayUnknown {
		t.Errorf("no gateways: %q", got)
	}
	gwOnly := base.WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32)))
	if got := gwOnly.ClassifyLAN(netip.MustParseAddr("192.168.1.20")).Reason; got != ReasonHostNetworkUnknown {
		t.Errorf("no host networks: %q", got)
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
	c := defaultClassifier(t).WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32))).WithHostNetworks(StaticHostAddrs(dockerBridge))
	d := &Dialer{Classifier: c}
	for _, dst := range []string{"192.168.1.1:80", "127.0.0.1:80", "203.0.113.7:80", "172.17.0.2:80"} {
		_, err := d.DialLAN(context.Background(), netip.MustParseAddrPort(dst))
		if _, ok := AsRefused(err); !ok {
			t.Errorf("%s: %v, want a refusal", dst, err)
		}
	}
	if err := d.controlLAN("tcp4", "192.168.1.20:80", nil); err != nil {
		t.Errorf("a LAN host: %v", err)
	}
}

// dockerBridge is Docker's default bridge network: on the host, and only
// there.
var dockerBridge = netip.MustParsePrefix("172.17.0.0/16")

// The host's routes, read live, parse: whatever this machine has.
func TestTheHostsGatewaysRead(t *testing.T) {
	if _, err := NewGateways(0).Prefixes(); err != nil {
		t.Skipf("no route dump here: %v", err)
	}
	if _, err := NewHostNetworks(0).Prefixes(); err != nil {
		t.Skipf("no route dump here: %v", err)
	}
}

// The route parse, on messages laid out as the kernel lays them out: a
// gateway however it is spelled -- RTA_GATEWAY, RTA_VIA, inside a multipath
// route's hops -- and the destination of every unicast route that leaves by
// an interface with no device behind it, a bridge's among them, but not of
// one by a NIC, nor of a route that is not unicast.
func TestParseRoutesKeepsGatewaysAndTheHostsOwnNetworks(t *testing.T) {
	const eth, docker0, wg0, usb = 2, 3, 4, 5
	hw := func(i int) bool { return i == eth || i == usb }
	msg := func(family, dstLen, typ byte, attrs ...[]byte) syscall.NetlinkMessage {
		data := make([]byte, syscall.SizeofRtMsg)
		data[0], data[1], data[4], data[7] = family, dstLen, syscall.RT_TABLE_MAIN, typ
		for _, a := range attrs {
			data = append(data, a...)
		}
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE}, Data: data}
	}
	rta := func(typ uint16, v []byte) []byte {
		l := 4 + len(v)
		b := binary.NativeEndian.AppendUint16(nil, uint16(l))
		b = binary.NativeEndian.AppendUint16(b, typ)
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	dst := func(s string) []byte { return rta(syscall.RTA_DST, netip.MustParseAddr(s).AsSlice()) }
	gw := func(s string) []byte { return rta(syscall.RTA_GATEWAY, netip.MustParseAddr(s).AsSlice()) }
	oif := func(i int) []byte { return rta(syscall.RTA_OIF, binary.NativeEndian.AppendUint32(nil, uint32(i))) }
	via := func(s string) []byte {
		v := binary.NativeEndian.AppendUint16(nil, syscall.AF_INET6)
		return rta(rtaVia, append(v, netip.MustParseAddr(s).AsSlice()...))
	}
	hop := func(i int, attrs ...[]byte) []byte {
		var body []byte
		for _, a := range attrs {
			body = append(body, a...)
		}
		b := binary.NativeEndian.AppendUint16(nil, uint16(sizeofRtNexthop+len(body)))
		b = append(b, 0, 0)
		b = binary.NativeEndian.AppendUint32(b, uint32(i))
		return append(b, body...)
	}
	multipath := func(hops ...[]byte) []byte {
		var v []byte
		for _, h := range hops {
			v = append(v, h...)
		}
		return rta(syscall.RTA_MULTIPATH, v)
	}
	msgs := []syscall.NetlinkMessage{
		msg(syscall.AF_INET, 0, syscall.RTN_UNICAST, gw("10.0.0.1"), oif(eth)),
		msg(syscall.AF_INET, 24, syscall.RTN_UNICAST, dst("10.0.0.0"), oif(eth)),
		msg(syscall.AF_INET, 16, syscall.RTN_UNICAST, dst("172.17.0.0"), oif(docker0)),
		msg(syscall.AF_INET, 30, syscall.RTN_UNICAST, dst("172.28.146.8"), oif(usb)),
		msg(syscall.AF_INET, 24, syscall.RTN_UNICAST, dst("10.66.0.0"), oif(wg0)),
		msg(syscall.AF_INET, 8, syscall.RTN_UNICAST, dst("10.0.0.0"),
			multipath(hop(eth, gw("10.0.0.2")), hop(eth, gw("10.0.0.3")))),
		msg(syscall.AF_INET, 16, syscall.RTN_UNICAST, dst("192.168.0.0"),
			multipath(hop(eth, gw("10.0.0.4")), hop(wg0, gw("10.66.0.1")))),
		msg(syscall.AF_INET, 24, syscall.RTN_UNICAST, dst("192.0.2.0"), via("fe80::1"), oif(eth)),
		msg(syscall.AF_INET, 24, syscall.RTN_BLACKHOLE, dst("198.51.100.0")),
		// Unicast, by nexthop object, spelled the old way too.
		msg(syscall.AF_INET, 24, syscall.RTN_UNICAST, dst("203.0.113.0"),
			rta(rtaNHID, binary.NativeEndian.AppendUint32(nil, 7)), gw("10.0.0.5"), oif(eth)),
	}
	gws, inner, err := parseRoutes(msgs, hw)
	if err != nil {
		t.Fatal(err)
	}
	wantGW := []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32", "10.66.0.1/32", "fe80::1/128", "10.0.0.5/32"}
	wantInner := []string{"172.17.0.0/16", "10.66.0.0/24", "192.168.0.0/16"}
	if fmt.Sprint(gws) != fmt.Sprint(prefixes(wantGW)) {
		t.Errorf("gateways %v, want %v", gws, wantGW)
	}
	if fmt.Sprint(inner) != fmt.Sprint(prefixes(wantInner)) {
		t.Errorf("host networks %v, want %v", inner, wantInner)
	}

	// A route by nexthop object alone names its router nowhere this reads:
	// the read fails, and every LAN address with it.
	_, _, err = parseRoutes([]syscall.NetlinkMessage{
		msg(syscall.AF_INET, 0, syscall.RTN_UNICAST, rta(rtaNHID, binary.NativeEndian.AppendUint32(nil, 7))),
	}, hw)
	if err == nil {
		t.Error("a route by nexthop object alone parsed")
	}
	// As does a multipath hop that runs past its attribute.
	bad := hop(eth)
	binary.NativeEndian.PutUint16(bad, 64)
	if _, _, err = parseRoutes([]syscall.NetlinkMessage{msg(syscall.AF_INET, 0, syscall.RTN_UNICAST, multipath(bad))}, hw); err == nil {
		t.Error("a truncated multipath hop parsed")
	}
}

func prefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
