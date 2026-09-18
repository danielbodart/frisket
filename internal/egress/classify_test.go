package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"pgregory.net/rapid"
)

// THE DIALER.CONTROL TABLE. The whole structural policy is one function, run on
// the address actually being dialled; this is every shape the review found
// ottergate getting wrong, plus the host's own addresses, plus the addresses
// that must still get through.
func TestControlTable(t *testing.T) {
	d := &Dialer{Classifier: defaultClassifier(t)}
	for _, tc := range []struct {
		addr string
		want string // "" is accepted
	}{
		{"127.0.0.1:443", ReasonLoopback},
		{"127.1.2.3:80", ReasonLoopback},
		{"10.0.0.1:443", ReasonPrivate},
		{"172.16.0.1:443", ReasonPrivate},
		{"172.31.255.255:443", ReasonPrivate},
		{"192.168.1.1:443", ReasonPrivate},
		{"100.64.0.1:443", ReasonCGNAT},
		{"100.127.255.255:443", ReasonCGNAT},
		{"169.254.169.254:80", ReasonLinkLocal}, // the cloud metadata service
		{"0.0.0.0:80", ReasonUnspecified},       // Linux connects this to the local host
		{"0.1.2.3:80", ReasonUnspecified},
		{"224.0.0.1:80", ReasonMulticast},
		{"239.255.255.250:1900", ReasonMulticast},
		{"240.0.0.1:80", ReasonReserved},
		{"255.255.255.255:80", ReasonReserved},

		{"[::1]:443", ReasonLoopback},
		{"[::]:443", ReasonUnspecified},
		{"[fe80::1]:443", ReasonLinkLocal},
		// Prefix.Contains is false for EVERY zoned address; without dropping
		// the zone, the link-local row would not match its own addresses.
		{"[fe80::1%lo]:443", ReasonLinkLocal},
		{"[fd12::1]:443", ReasonULA}, // ottergate's HasPrefix("fd00:") misses this
		{"[fc00::1]:443", ReasonULA},
		{"[fec0::1]:443", ReasonSiteLocal},
		{"[ff02::1]:443", ReasonMulticast},
		{"[64:ff9b:1::1]:443", ReasonLocalNAT64},

		// Every other spelling of a refused v4 address.
		{"[::ffff:10.0.0.1]:443", ReasonPrivate},
		{"[::ffff:127.0.0.1]:443", ReasonLoopback},
		{"[::127.0.0.1]:443", ReasonLoopback},     // v4-compatible
		{"[::ffff:0:7f00:1]:443", ReasonLoopback}, // v4-translated
		{"[2002:7f00:1::]:443", ReasonLoopback},   // 6to4
		{"[2002:a9fe:a9fe::1]:80", ReasonLinkLocal},
		{"[64:ff9b::7f00:1]:443", ReasonLoopback}, // NAT64
		{"[64:ff9b::a00:1]:443", ReasonPrivate},
		{"[2001:0:4136:e378:8000:63bf:80ff:fffe]:443", ReasonLoopback}, // Teredo, client 127.0.0.1

		// The host's own addresses, in every spelling.
		{"203.0.113.7:443", ReasonHostOwned},
		{"[2001:db8:77::7]:443", ReasonHostOwned},
		{"[::ffff:203.0.113.7]:443", ReasonHostOwned},
		{"[2002:cb00:7107::1]:443", ReasonHostOwned},
		{"[64:ff9b::cb00:7107]:443", ReasonHostOwned},

		// What must still get through.
		{"1.1.1.1:443", ""},
		{"140.82.121.3:443", ""},
		{"172.32.0.1:443", ""},  // just past 172.16/12
		{"100.128.0.1:443", ""}, // just past 100.64/10
		{"203.0.113.8:443", ""}, // the host's neighbour is not the host
		{"[2606:4700:4700::1111]:443", ""},
		{"[::ffff:1.1.1.1]:443", ""},
		{"[2002:101:101::1]:443", ""},  // 6to4 of a public address
		{"[64:ff9b::101:101]:443", ""}, // NAT64 of a public address

		{"example.com:443", ReasonUnparseable},
	} {
		err := d.Control("tcp", tc.addr, nil)
		if tc.want == "" {
			if err != nil {
				t.Errorf("Control(%s) = %v, want accepted", tc.addr, err)
			}
			continue
		}
		re, ok := AsRefused(err)
		if !ok {
			t.Errorf("Control(%s) = %v, want refused as %q", tc.addr, err, tc.want)
			continue
		}
		if re.Refusal.Reason != tc.want {
			t.Errorf("Control(%s) refused as %q (%s), want %q", tc.addr, re.Refusal.Reason, re.Refusal, tc.want)
		}
	}
}

func TestAnUnconfiguredDialerRefuses(t *testing.T) {
	var d Dialer
	if _, ok := AsRefused(d.Control("tcp4", "1.1.1.1:443", nil)); !ok {
		t.Fatal("a Dialer with no classifier let a dial through")
	}
}

func TestNewClassifierRefusesRowsThatCannotMatch(t *testing.T) {
	for _, r := range []Range{
		{netip.MustParsePrefix("::ffff:10.0.0.0/104"), ReasonPrivate}, // matches no v4 address
		{netip.Prefix{}, ReasonPrivate},
		{netip.MustParsePrefix("10.0.0.0/8"), ""}, // refuses with no reason to log
	} {
		if _, err := NewClassifier([]Range{r}, StaticHostAddrs()); err == nil {
			t.Errorf("NewClassifier accepted the row %+v", r)
		}
	}
	if _, err := NewClassifier(nil, nil); err == nil {
		t.Error("NewClassifier accepted no host addresses")
	}
}

// fakeDNS answers the Go resolver over a net.Pipe with a fixed A record for
// every name. That is the injected resolver the rebinding test needs: an
// allowed name, as far as the caller knows, that resolves to a private address
// by the time it is dialled.
func fakeDNS(answer netip.Addr, asked *atomic.Int64) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveFakeDNS(server, answer, asked)
			return client, nil
		},
	}
}

func serveFakeDNS(c net.Conn, answer netip.Addr, asked *atomic.Int64) {
	defer c.Close()
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		var q dnsmessage.Message
		if err := q.Unpack(b); err != nil || len(q.Questions) != 1 {
			return
		}
		asked.Add(1)
		r := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
			Questions: q.Questions,
		}
		if q.Questions[0].Type == dnsmessage.TypeA {
			r.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: answer.As4()},
			}}
		}
		out, err := r.Pack()
		if err != nil {
			return
		}
		if _, err := c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)); err != nil {
			return
		}
	}
}

// DNS REBINDING. An allowed name resolves to a private address at dial time.
// The check is in Control, on the address the kernel is about to connect to,
// so it does not matter what the name was or what it resolved to earlier: the
// dial is refused, and the listener really sitting at that address never sees
// a connection.
func TestAllowedNameResolvingPrivateIsRefusedAtDial(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	var asked atomic.Int64
	d := &Dialer{
		Classifier: defaultClassifier(t),
		Resolver:   fakeDNS(netip.MustParseAddr("127.0.0.1"), &asked),
		Timeout:    5 * time.Second,
	}
	c, err := d.DialContext(context.Background(), "tcp4", net.JoinHostPort("allowed.example", strconv.Itoa(port)))
	if err == nil {
		_ = c.Close()
		t.Fatal("dialled an allowed name that resolved to loopback")
	}
	re, ok := AsRefused(err)
	if !ok || re.Refusal.Reason != ReasonLoopback {
		t.Fatalf("dial error = %v, want a loopback refusal", err)
	}
	if asked.Load() == 0 {
		t.Fatal("the injected resolver was never asked, so this proves nothing about resolution")
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the listener behind the refused address accepted %d connections", n)
	}

	// The positive control: the same dial with loopback carved out of the table
	// at construction does connect, so the refusal above was the classifier and
	// not a broken test.
	d.Classifier = testNetworkClassifier(t)
	c, err = d.DialContext(context.Background(), "tcp4", net.JoinHostPort("allowed.example", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("with loopback allowed by the table, the dial failed: %v", err)
	}
	_ = c.Close()
	waitFor(t, "the positive control's connection", func() bool { return accepted.Load() == 1 })
}

// genIn draws an address uniformly from inside p.
func genIn(t *rapid.T, p netip.Prefix, label string) netip.Addr {
	b := p.Addr().AsSlice()
	rnd := rapid.SliceOfN(rapid.Byte(), len(b), len(b)).Draw(t, label)
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				mask := byte(0x80 >> j)
				b[i] = b[i]&^mask | rnd[i]&mask
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// genRefusedV4 is a v4 address the default classifier refuses on its own: a
// v4 row of the table, or a host address.
func genRefusedV4(t *rapid.T) netip.Addr {
	var rows []netip.Prefix
	for _, r := range DefaultRanges() {
		if r.Prefix.Addr().Is4() {
			rows = append(rows, r.Prefix)
		}
	}
	rows = append(rows, netip.PrefixFrom(hostV4, 32))
	return genIn(t, rapid.SampledFrom(rows).Draw(t, "row"), "v4")
}

// spellings is every way of writing v4 as v6 that the classifier knows, with
// the parts that are not the v4 address drawn at random.
func spellings(t *rapid.T, v4 netip.Addr) map[string]netip.Addr {
	a := v4.As4()
	rnd := func(label string, n int) []byte { return rapid.SliceOfN(rapid.Byte(), n, n).Draw(t, label) }
	mk := func(prefix []byte, fill []byte, at int) netip.Addr {
		var b [16]byte
		copy(b[:], prefix)
		copy(b[len(prefix):], fill)
		copy(b[at:], a[:])
		return netip.AddrFrom16(b)
	}
	teredoClient := func() netip.Addr {
		// A public server (65.54.227.120), so the only refused thing in it is
		// the client.
		b := [16]byte{0x20, 0x01, 0, 0, 0x41, 0x36, 0xe3, 0x78}
		copy(b[8:12], rnd("teredo-rest", 4))
		for i := range 4 {
			b[12+i] = a[i] ^ 0xff
		}
		return netip.AddrFrom16(b)
	}
	return map[string]netip.Addr{
		"v4":                 v4,
		SpellingV4Mapped:     netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: a[0], 13: a[1], 14: a[2], 15: a[3]}),
		SpellingV4Compatible: mk(nil, nil, 12),
		SpellingV4Translated: mk([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, nil, 12),
		Spelling6to4:         mk([]byte{0x20, 0x02}, nil, 2),
		SpellingNAT64:        mk([]byte{0, 0x64, 0xff, 0x9b}, nil, 12),
		"teredo-client":      teredoClient(),
		"teredo-server":      mk([]byte{0x20, 0x01, 0, 0}, nil, 4),
		"6to4-random": func() netip.Addr {
			b := [16]byte{0x20, 0x02}
			copy(b[2:6], a[:])
			copy(b[6:], rnd("6to4-rest", 10))
			return netip.AddrFrom16(b)
		}(),
	}
}

// EVERY SPELLING OF A REFUSED ADDRESS IS REFUSED -- and with a zone, which
// netip.Prefix.Contains would otherwise treat as matching nothing.
func TestEverySpellingOfARefusedAddressIsRefused(t *testing.T) {
	rapid.Check(t, propEverySpellingRefused(defaultClassifier(t)))
}

func FuzzEverySpellingOfARefusedAddressIsRefused(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(propEverySpellingRefused(defaultClassifier(f))))
}

func propEverySpellingRefused(c *Classifier) func(*rapid.T) {
	return func(t *rapid.T) {
		v4 := genRefusedV4(t)
		want := c.Classify(v4)
		if !want.Refused() {
			t.Fatalf("generator produced %v, which is not refused", v4)
		}
		for name, a := range spellings(t, v4) {
			forms := []netip.Addr{a}
			if a.Is6() {
				forms = append(forms, a.WithZone(rapid.StringMatching(`[a-z0-9]{1,8}`).Draw(t, "zone")))
			}
			for _, f := range forms {
				r := c.Classify(f)
				if !r.Refused() {
					t.Fatalf("%s spelling %v of refused %v (%s) is accepted", name, f, v4, want)
				}
				if err := (&Dialer{Classifier: c}).Control("tcp", netip.AddrPortFrom(f, 443).String(), nil); err == nil {
					t.Fatalf("Control accepted %v, the %s spelling of %v", f, name, v4)
				}
			}
		}
	}
}

// The native v6 rows, likewise, with and without a zone.
func TestRefusedV6RowsAreRefusedWithAZone(t *testing.T) {
	c := defaultClassifier(t)
	rapid.Check(t, func(t *rapid.T) {
		var rows []Range
		for _, r := range DefaultRanges() {
			if r.Prefix.Addr().Is6() {
				rows = append(rows, r)
			}
		}
		row := rapid.SampledFrom(rows).Draw(t, "row")
		a := genIn(t, row.Prefix, "v6")
		for _, f := range []netip.Addr{a, a.WithZone("eth0")} {
			if r := c.Classify(f); r.Reason != row.Reason {
				t.Fatalf("Classify(%v) = %q, want %q", f, r, row.Reason)
			}
		}
	})
}

// A STRUCTURAL REFUSAL IS NEVER TURNED INTO AN ACCEPTANCE BY ANY ALLOWLIST.
// The resolved set is filled with whatever rapid likes -- including the
// refused address itself, in every spelling, under an allowed-looking name --
// and the decision is still a refusal, and still structural.
func TestAStructuralRefusalIsNeverOverridden(t *testing.T) {
	rapid.Check(t, propNeverOverridden(defaultClassifier(t)))
}

func FuzzAStructuralRefusalIsNeverOverridden(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(propNeverOverridden(defaultClassifier(f))))
}

func propNeverOverridden(c *Classifier) func(*rapid.T) {
	return func(t *rapid.T) {
		res := NewResolved(ResolvedConfig{Cap: 1 << 16})
		p := &Policy{Classifier: c, Resolved: res}

		v4 := genRefusedV4(t)
		sp := spellings(t, v4)
		for i, n := 0, rapid.IntRange(0, 20).Draw(t, "noise"); i < n; i++ {
			b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "noise-addr")
			res.Record("noise.example", netip.AddrFrom16([16]byte(b)), time.Hour, uint64(i))
		}
		for _, a := range sp {
			res.Record("api.github.com", a, time.Hour, 1)
		}
		for name, a := range sp {
			d := p.Decide(a)
			if d.Allowed {
				t.Fatalf("Decide(%v, the %s spelling of %v) = allowed, with it in the resolved set", a, name, v4)
			}
			if !d.Refusal.Refused() || !strings.HasPrefix(d.Reason, "structural") {
				t.Fatalf("Decide(%v) = %+v, want a structural refusal", a, d)
			}
		}
	}
}

// And the other half, so the property above is not satisfied by refusing
// everything: a public address the session resolved is accepted, and one it
// did not resolve is refused as not resolved.
func TestResolvedPublicAddressIsAcceptedAndNothingElse(t *testing.T) {
	c := defaultClassifier(t)
	rapid.Check(t, func(t *rapid.T) {
		a := netip.AddrFrom4([4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "a")))
		if c.Classify(a).Refused() {
			t.Skip("structurally refused; the other property covers it")
		}
		res := NewResolved(ResolvedConfig{})
		p := &Policy{Classifier: c, Resolved: res}
		if d := p.Decide(a); d.Allowed || d.Reason != ReasonNotResolved {
			t.Fatalf("Decide(%v) before resolution = %+v", a, d)
		}
		res.Record("pkg.example", a, time.Minute, 9)
		d := p.Decide(a)
		if !d.Allowed || d.Entry.Name != "pkg.example" || d.Entry.Query != 9 {
			t.Fatalf("Decide(%v) after resolution = %+v", a, d)
		}
		// The kernel may report the v4-mapped spelling; it is the same address.
		if d := p.Decide(netip.AddrFrom16(a.As16())); !d.Allowed {
			t.Fatalf("the v4-mapped spelling of resolved %v was refused: %+v", a, d)
		}
	})
}

func TestTheHostsAddressesAreReadAndRefreshed(t *testing.T) {
	now := time.Unix(1000, 0)
	var owned atomic.Value
	owned.Store([]netip.Prefix{netip.MustParsePrefix("198.51.100.1/32")})
	h := HostAddrsFrom(func() ([]netip.Prefix, error) { return owned.Load().([]netip.Prefix), nil }, time.Second, func() time.Time { return now })
	c, err := NewClassifier(nil, h)
	if err != nil {
		t.Fatal(err)
	}
	later := netip.MustParseAddr("198.51.100.2")
	if r := c.Classify(later); r.Refused() {
		t.Fatalf("%v refused before the host had it: %s", later, r)
	}
	// The host gains an address (a VPN comes up). Until the list is stale the
	// old answer stands; once it is, the new address is refused.
	owned.Store([]netip.Prefix{netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("198.51.100.2/32")})
	now = now.Add(2 * time.Second)
	if r := c.Classify(later); r.Reason != ReasonHostOwned {
		t.Fatalf("after a refresh, %v = %s, want host-owned", later, r)
	}
}

// FAIL CLOSED. If the host's addresses cannot be read, nothing is known not to
// be one of them, and everything is refused.
func TestUnreadableHostAddressesRefuseEverything(t *testing.T) {
	h := HostAddrsFrom(func() ([]netip.Prefix, error) { return nil, errors.New("netlink: EPERM") }, time.Second, nil)
	c, err := NewClassifier(nil, h)
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Classify(netip.MustParseAddr("1.1.1.1")); r.Reason != ReasonHostUnknown {
		t.Fatalf("Classify with no host addresses = %s, want %q", r, ReasonHostUnknown)
	}
}

// The live source, on whatever machine this runs on: every interface address
// the standard library reports is in the list, and a v4 loopback address is
// host-owned when lo has one. In the Nix build sandbox that is lo and nothing
// else, which still exercises the netlink route dump end to end.
func TestTheLiveHostSourceCoversEveryInterfaceAddress(t *testing.T) {
	h := NewHostAddrs(0)
	pfx, err := h.Prefixes()
	if err != nil {
		t.Fatalf("reading the host's addresses: %v", err)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(ipn.IP)
		ip = ip.Unmap()
		found := false
		for _, p := range pfx {
			found = found || p.Contains(ip)
		}
		if !found {
			t.Errorf("interface address %v is not in the host list %v", ip, pfx)
		}
	}
	t.Logf("host-owned: %v", pfx)
}
