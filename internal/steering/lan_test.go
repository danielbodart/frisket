package steering

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/internal/egress"
)

// roleLAN re-runs the test binary in a namespace of its own, with a network
// standing in for the host's LAN, where it loads a `service` steering file's
// ruleset and dials what is on that network.
const roleLAN = "frisket-test-lan"

// The sandbox's network, as pasta would give it one: its own address -- the
// host's, under pasta -- on a private network, and a machine beside it.
// TEST-NET-2 is somewhere public, which `service` always sends direct.
const (
	lanOwn4  = "10.0.0.2"
	lanOwn6  = "fd00:f::2"
	lanPeer4 = "10.0.0.4"
	lanPeer6 = "fd00:f::4"
	public4  = "198.51.100.7"
)

// The `lan` sets lib.steering writes ARE the structural table: every row of
// egress.DefaultRanges and nothing else, so `service` with lan = "frisket"
// steers to frisket exactly what egress refuses by its table, and a row
// added to one without the other fails here. The file is lib.steering's
// own, held to it by the flake's `steering` check.
func TestTheLANSetsAreTheStructuralTable(t *testing.T) {
	p, err := Load("testdata/steering-service-lan.json")
	if err != nil {
		t.Fatal(err)
	}
	if p.LAN != LANFrisket {
		t.Fatalf("lan is %q, want %q", p.LAN, LANFrisket)
	}
	var got []netip.Prefix
	for _, set := range []string{"lan4", "lan6"} {
		m := regexp.MustCompile(`set ` + set + ` \{[^}]*elements = \{ ([^}]*) \}`).FindStringSubmatch(p.Ruleset)
		if m == nil {
			t.Fatalf("no elements for %s in the ruleset:\n%s", set, p.Ruleset)
		}
		for _, e := range strings.Split(m[1], ", ") {
			pf, err := netip.ParsePrefix(e)
			if err != nil {
				t.Fatalf("%s: %v", set, err)
			}
			if pf.Addr().Is4() != (set == "lan4") {
				t.Errorf("%s holds %s, of the other family", set, pf)
			}
			got = append(got, pf)
		}
	}
	var want []netip.Prefix
	for _, r := range egress.DefaultRanges() {
		want = append(want, r.Prefix)
	}
	cmp := func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) }
	slices.SortFunc(got, cmp)
	slices.SortFunc(want, cmp)
	if !slices.Equal(got, want) {
		t.Errorf("the lan sets are\n  %v\nand the structural table is\n  %v", got, want)
	}

	// And `direct`, the default, steers none of it: its ruleset is the one
	// every `service` file had before there was a choice.
	d, err := Load("testdata/steering-service.json")
	if err != nil {
		t.Fatal(err)
	}
	if d.LAN != LANDirect || strings.Contains(d.Ruleset, "lan4") || strings.Contains(d.Ruleset, "lan6") {
		t.Errorf("the default `service` file steers the local network: lan %q\n%s", d.LAN, d.Ruleset)
	}
}

// What lan = "frisket" does in a real namespace, by the ruleset
// lib.steering writes: TCP to a machine on the sandbox's private network is
// steered to the session's listener with the destination it dialled, both
// families, and UDP to it is refused at once; the sandbox's own address and
// loopback are its own still, and somewhere public goes direct. And under
// lan = "direct" the same machine is reached directly, never steered.
func TestTheLocalNetworkIsSteeredOnlyWhenTheFileSaysSo(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft here to load the ruleset with")
	}
	for _, file := range []string{"service-lan", "service"} {
		t.Run(file, func(t *testing.T) { runInside(t, roleLAN, file) })
	}
}

// lanInside is the test, as uid 0 inside the namespace.
func lanInside(file string) error {
	p, err := Load("testdata/steering-" + file + ".json")
	if err != nil {
		return err
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	if err := lanNetwork(); err != nil {
		return err
	}
	lns := map[bool]*net.TCPListener{}
	for _, spec := range p.Listeners {
		if !spec.Stream() {
			continue
		}
		ln, err := transparentListener(spec.Net, spec.Addr)
		if err != nil {
			return err
		}
		defer ln.Close()
		lns[spec.V6()] = ln
	}
	if err := serveJSON(request{Op: opApply, Steps: append(p.RoutingSteps(false), p.RoutingSteps(true)...)}, nil); err != nil {
		return fmt.Errorf("routing: %w", err)
	}
	if err := serveJSON(request{Op: opRuleset, Nft: nft, Ruleset: p.Ruleset}, nil); err != nil {
		return fmt.Errorf("ruleset: %w", err)
	}
	steered := p.LAN == LANFrisket

	// A machine on the network, at a port nothing in this namespace holds.
	for _, dst := range []string{lanPeer4 + ":22", "[" + lanPeer6 + "]:22"} {
		want := netip.MustParseAddrPort(dst)
		arrived, err := dialAndAccept(lns[want.Addr().Is6()], dst)
		if err != nil {
			return err
		}
		switch {
		case steered && !arrived.IsValid():
			return fmt.Errorf("%s was not steered", dst)
		case steered && (arrived.Addr().Unmap() != want.Addr() || arrived.Port() != want.Port()):
			return fmt.Errorf("%s arrived as %s", dst, arrived)
		case !steered && arrived.IsValid():
			return fmt.Errorf("%s was steered under lan %q", dst, p.LAN)
		}
	}

	// The sandbox's own: its address, which pasta makes the host's, and its
	// loopback. Neither reaches the listener, and a server of its own, on
	// every address, is reached at each -- at its own address by way of the
	// `spliced` chain's 127.0.0.1, which the local exemption leaves to it.
	srv, err := net.Listen("tcp", ":8080")
	if err != nil {
		return err
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	for _, own := range []string{lanOwn4 + ":8080", "[" + lanOwn6 + "]:8080", "127.0.0.1:8080", "[::1]:8080"} {
		ap := netip.MustParseAddrPort(own)
		c, err := net.DialTimeout("tcp", own, 2*time.Second)
		if err != nil {
			return fmt.Errorf("the sandbox's own %s: %w", own, err)
		}
		c.Close()
		if a, _ := accepted(lns[ap.Addr().Is6()], 50*time.Millisecond); a.IsValid() {
			return fmt.Errorf("the sandbox's own %s arrived on the session's listener", own)
		}
	}

	// Somewhere public goes direct, whatever the file says: out by the
	// network, where nothing answers.
	if arrived, err := dialAndAccept(lns[false], public4+":80"); err != nil {
		return err
	} else if arrived.IsValid() {
		return fmt.Errorf("%s:80 was steered", public4)
	}

	// UDP to the machine: refused at once under lan = "frisket", by the
	// ruleset's reject; sent, and so silent, under lan = "direct".
	for _, dst := range []string{lanPeer4 + ":5000", "[" + lanPeer6 + "]:5000"} {
		c, err := net.Dial("udp", dst)
		if err != nil {
			return err
		}
		_, werr := c.Write([]byte("x"))
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, rerr := c.Read(make([]byte, 1))
		c.Close()
		err = errors.Join(werr, rerr)
		var ne net.Error
		timedOut := errors.As(rerr, &ne) && ne.Timeout() && werr == nil
		switch {
		case steered && timedOut:
			return fmt.Errorf("UDP to %s was not refused", dst)
		case steered && !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ECONNREFUSED):
			return fmt.Errorf("UDP to %s: %v, want refused", dst, err)
		case !steered && !timedOut:
			return fmt.Errorf("UDP to %s under lan %q: %v, want sent and unanswered", dst, p.LAN, err)
		}
	}
	return nil
}

// dialAndAccept dials dst and says where what arrived on ln -- the session's
// listener -- was going, or nothing if nothing did. A connection that is not
// steered goes out by the dummy and is never answered; it is abandoned.
func dialAndAccept(ln *net.TCPListener, dst string) (netip.AddrPort, error) {
	c, err := net.DialTimeout("tcp", dst, 300*time.Millisecond)
	if err == nil {
		defer c.Close()
	}
	return accepted(ln, 300*time.Millisecond)
}

func accepted(ln *net.TCPListener, wait time.Duration) (netip.AddrPort, error) {
	_ = ln.SetDeadline(time.Now().Add(wait))
	got, err := ln.AcceptTCP()
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return netip.AddrPort{}, nil
		}
		return netip.AddrPort{}, err
	}
	defer got.Close()
	return got.LocalAddr().(*net.TCPAddr).AddrPort(), nil
}

// lanNetwork gives the namespace a network for the local one: a dummy with
// the sandbox's own address in each family and the default routes by it.
// Nothing beyond it answers, which is the point: whatever arrives anywhere
// was steered.
func lanNetwork() error {
	la := netlink.NewLinkAttrs()
	la.Name = "lan0"
	d := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(d); err != nil {
		return fmt.Errorf("dummy: %w", err)
	}
	for _, a := range []string{lanOwn4 + "/24", lanOwn6 + "/64"} {
		addr, err := netlink.ParseAddr(a)
		if err != nil {
			return err
		}
		// Or the v6 address is tentative, and no source at all, for as long
		// as duplicate address detection takes.
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(d, addr); err != nil {
			return fmt.Errorf("address %s: %w", a, err)
		}
	}
	if err := netlink.LinkSetUp(d); err != nil {
		return err
	}
	for _, dst := range []string{"0.0.0.0/0", "::/0"} {
		_, n, _ := net.ParseCIDR(dst)
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: d.Attrs().Index, Dst: n}); err != nil {
			return fmt.Errorf("route %s: %w", dst, err)
		}
	}
	return nil
}
