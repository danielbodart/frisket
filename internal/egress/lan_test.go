package egress

import (
	"net/netip"
	"testing"
)

// lanPolicy is a policy whose document names nas.lan at port, or at every
// port with none, over c.
func lanPolicy(c *Classifier, ports ...uint16) (*Policy, *Resolved) {
	lan := NewResolved(ResolvedConfig{})
	resolved := NewResolved(ResolvedConfig{})
	return &Policy{Classifier: c, Resolved: resolved, LAN: &LAN{Resolved: lan, Ports: map[string][]uint16{"nas.lan": ports}}}, lan
}

// A destination on the local network is admitted only for an address the
// session's DNS gave a lan name, at a port that name may be reached at,
// and never one ClassifyLAN refuses; anything that is not refused only as
// the local network is left as Decide said.
func TestDecideLANAdmitsALANNameAtItsPortsAndNothingElse(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	c := defaultClassifier(t).WithGateways(StaticHostAddrs(netip.PrefixFrom(gw, 32))).WithHostNetworks(StaticHostAddrs(dockerBridge))
	p, lan := lanPolicy(c, 445)
	nas := netip.MustParseAddr("192.168.1.20")
	lan.Record("nas.lan", nas, 0, 1)
	p.Resolved.Record("nas.lan", nas, 0, 1)
	decide := func(dst string) Decision {
		ap := netip.MustParseAddrPort(dst)
		return p.DecideLAN(ap, p.Decide(ap.Addr()))
	}
	if d := decide("192.168.1.20:445"); !d.Allowed || !d.LAN || d.Reason != ReasonLAN || d.Entry.Name != "nas.lan" {
		t.Fatalf("the lan name at its port: %+v", d)
	}
	if d := decide("192.168.1.20:22"); d.Allowed || d.Reason != "structural: "+ReasonPrivate {
		t.Fatalf("another port: %+v", d)
	}
	// A literal address, which no lan name was answered with.
	if d := decide("192.168.1.21:445"); d.Allowed || d.LAN {
		t.Fatalf("an address nobody resolved: %+v", d)
	}
	// An address another name resolved to is no lan name's.
	other := netip.MustParseAddr("192.168.1.30")
	p.Resolved.Record("other.example.test", other, 0, 2)
	if d := decide("192.168.1.30:445"); d.Allowed {
		t.Fatalf("an allowed name that is no lan name: %+v", d)
	}
	// The host's own networks, a router and a metadata service, by a lan
	// name all the same.
	for addr, want := range map[string]string{
		"192.168.1.1":     ReasonGateway,
		"172.17.0.2":      ReasonHostNetwork,
		"169.254.169.254": ReasonMetadata,
	} {
		lan.Record("nas.lan", netip.MustParseAddr(addr), 0, 3)
		if d := decide(addr + ":445"); d.Allowed || d.Reason != "structural: "+want {
			t.Errorf("%s: %+v, want %s", addr, d, want)
		}
	}
	// Loopback and CGNAT are not the local network, whatever name gave them.
	for _, addr := range []string{"127.0.0.1", "100.64.0.1"} {
		lan.Record("nas.lan", netip.MustParseAddr(addr), 0, 4)
		if d := decide(addr + ":445"); d.Allowed || d.LAN {
			t.Errorf("%s: %+v", addr, d)
		}
	}
	// A public address is Decide's alone, by the resolved set.
	pub := netip.MustParseAddr("203.0.113.9")
	lan.Record("nas.lan", pub, 0, 5)
	if d := decide("203.0.113.9:445"); d.Allowed || d.Reason != ReasonNotResolved {
		t.Fatalf("a public address: %+v", d)
	}
	// With no ports, every port.
	every, lan2 := lanPolicy(c)
	lan2.Record("nas.lan", nas, 0, 1)
	if d := every.DecideLAN(netip.AddrPortFrom(nas, 8080), every.Decide(nas)); !d.Allowed {
		t.Fatalf("every port: %+v", d)
	}
	// And a document with no lan names admits nothing there.
	none := &Policy{Classifier: c, Resolved: NewResolved(ResolvedConfig{})}
	none.Resolved.Record("nas.lan", nas, 0, 1)
	if d := none.DecideLAN(netip.AddrPortFrom(nas, 445), none.Decide(nas)); d.Allowed {
		t.Fatalf("no lan names: %+v", d)
	}
}

// Admitted, a lan name's connection is dialled through ClassifyLAN and
// spliced, and its line says so.
func TestALANNameIsReachedOutsideRecording(t *testing.T) {
	nas, n := echoServer(t)
	p, lan := lanPolicy(lanTestClassifier(t), nas.Port())
	lan.Record("nas.lan", nas.Addr(), 0, 1)
	h := &Handler{Policy: p, Dialer: &Dialer{Classifier: p.Classifier}}
	f := startEgress(t, h, nas)
	if got := f.roundTrip(t, "hello"); got != "hello" || n.Load() != 1 {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "the egress line", func() bool { return len(f.journal.lines(t, "egress")) == 1 })
	if l := f.journal.lines(t, "egress")[0]; l["decision"] != DecisionAccepted || l["reason"] != ReasonLAN || l["name"] != "nas.lan" {
		t.Fatalf("egress line %v", l)
	}

	// Another port of the same host is refused.
	p2, lan2 := lanPolicy(lanTestClassifier(t), nas.Port()+1)
	lan2.Record("nas.lan", nas.Addr(), 0, 1)
	f2 := startEgress(t, &Handler{Policy: p2, Dialer: &Dialer{Classifier: p2.Classifier}}, nas)
	if got := f2.refused(t, "hello"); got != "" || n.Load() != 1 {
		t.Fatalf("got %q", got)
	}
}
