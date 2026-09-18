package steer

import (
	"net/netip"
	"testing"

	"pgregory.net/rapid"
)

func TestClassify(t *testing.T) {
	bound := netip.MustParseAddrPort("127.0.0.1:15001")
	for _, tc := range []struct {
		name string
		dst  netip.AddrPort
		want Verdict
	}{
		{"steered", netip.MustParseAddrPort("140.82.121.3:443"), Verdict{Steered, ""}},
		// TCP DNS lands on the TCP listener with its own destination.
		{"TCP DNS to loopback", netip.MustParseAddrPort("127.0.0.1:53"), Verdict{Steered, ""}},
		{"dialled the listener", bound, Verdict{Unsteered, ReasonOwnAddress}},
		{"nothing at all", netip.AddrPort{}, Verdict{Unsteered, ReasonNoDestination}},
		// The spelling attack: reach the listener by its v4-mapped name and, if
		// the comparison is textual, be served as though it were steered.
		{"dialled the listener, v4-mapped", netip.MustParseAddrPort("[::ffff:127.0.0.1]:15001"), Verdict{Unsteered, ReasonOwnAddress}},
	} {
		if got := Classify(bound, tc.dst); got != tc.want {
			t.Errorf("%s: Classify(%v, %v) = %+v, want %+v", tc.name, bound, tc.dst, got, tc.want)
		}
	}
}

// THE OWN-ADDRESS TEST IS WRONG FOR UDP, and datagrams do not use it. glibc's
// default nameserver is 127.0.0.1:53, which is exactly where the v4 DNS
// listener is bound, so a legitimate query arrives with the listener's own
// address; only the mark says whether the ruleset sent it.
func TestClassifyDatagram(t *testing.T) {
	own := netip.MustParseAddrPort("127.0.0.1:53")
	for _, tc := range []struct {
		name string
		want uint32
		r    Received
		out  Verdict
	}{
		{"steered, to the listener's own address", 1, Received{Orig: own, Mark: 1, Marked: true}, Verdict{Steered, ""}},
		{"steered, v6 loopback", 1, Received{Orig: netip.MustParseAddrPort("[::1]:53"), Mark: 1, Marked: true}, Verdict{Steered, ""}},
		{"steered elsewhere", 1, Received{Orig: netip.MustParseAddrPort("8.8.8.8:53"), Mark: 1, Marked: true}, Verdict{Steered, ""}},
		{"unmarked", 1, Received{Orig: own, Mark: 0, Marked: true}, Verdict{Unsteered, ReasonNotMarked}},
		{"no mark reported", 1, Received{Orig: own}, Verdict{Unsteered, ReasonNotMarked}},
		{"someone else's mark", 1, Received{Orig: own, Mark: 2, Marked: true}, Verdict{Unsteered, ReasonNotMarked}},
		{"a session with no mark steers nothing", 0, Received{Orig: own, Mark: 0, Marked: true}, Verdict{Unsteered, ReasonNotMarked}},
		{"marked, no destination", 1, Received{Mark: 1, Marked: true}, Verdict{Unsteered, ReasonNoDestination}},
	} {
		if got := ClassifyDatagram(tc.want, tc.r); got != tc.out {
			t.Errorf("%s: ClassifyDatagram(%d, %+v) = %+v, want %+v", tc.name, tc.want, tc.r, got, tc.out)
		}
	}
}

func genAddrPort() *rapid.Generator[netip.AddrPort] {
	return rapid.Custom(func(t *rapid.T) netip.AddrPort {
		port := rapid.Uint16().Draw(t, "port")
		if rapid.Bool().Draw(t, "v6") {
			b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "addr6")
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b)), port)
		}
		b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "addr4")
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b)), port)
	})
}

// NOTHING WITHOUT THE MARK IS STEERED, whatever its address. There is no later
// branch that could reach Steered for an unmarked datagram.
func TestAnUnmarkedDatagramIsNeverSteered(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		want := rapid.Uint32().Draw(t, "want")
		r := Received{Orig: genAddrPort().Draw(t, "orig"), Mark: rapid.Uint32().Draw(t, "mark"), Marked: rapid.Bool().Draw(t, "marked")}
		v := ClassifyDatagram(want, r)
		if v.Steered() && (!r.Marked || r.Mark != want || want == 0) {
			t.Fatalf("ClassifyDatagram(%d, %+v) = %+v", want, r, v)
		}
	})
}

// A connection whose destination is the listener itself was never steered: the
// workload found the socket and dialled it. Refused in every spelling of the
// same address, because a spelling the comparison misses is a connection served
// as if the ruleset had steered it.
func TestTheListenersOwnAddressIsNeverSteered(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bound := genAddrPort().Draw(t, "bound")
		spellings := []netip.AddrPort{bound}
		if a := bound.Addr(); a.Is4() {
			spellings = append(spellings, netip.AddrPortFrom(netip.AddrFrom16(a.As16()), bound.Port()))
		} else if a.Is4In6() {
			spellings = append(spellings, netip.AddrPortFrom(a.Unmap(), bound.Port()))
		}
		if bound.Addr().Is6() {
			spellings = append(spellings, netip.AddrPortFrom(bound.Addr().WithZone("lo"), bound.Port()))
		}
		for _, dst := range spellings {
			v := Classify(bound, dst)
			if v.Steered() {
				t.Fatalf("Classify(%v, %v) = %+v; %v is the listener under another name", bound, dst, v, dst)
			}
			if v.Reason != ReasonOwnAddress {
				t.Fatalf("Classify(%v, %v) reason = %q, want %q", bound, dst, v.Reason, ReasonOwnAddress)
			}
		}
	})
}

// Steered is only ever reached with a usable destination that is not ours, and
// the answer does not depend on when it is asked.
func TestSteeredImpliesARealDestinationElsewhere(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bound := genAddrPort().Draw(t, "bound")
		dst := genAddrPort().Draw(t, "dst")
		v := Classify(bound, dst)
		if again := Classify(bound, dst); again != v {
			t.Fatalf("Classify is not a function: %+v then %+v", v, again)
		}
		if !v.Steered() {
			if v.Decision != Unsteered || v.Reason == "" {
				t.Fatalf("an unsteered verdict with no reason: %+v", v)
			}
			return
		}
		if !dst.IsValid() {
			t.Fatalf("Classify(%v, %v) is steered with no destination", bound, dst)
		}
		if sameAddrPort(bound, dst) {
			t.Fatalf("Classify(%v, %v) is steered at our own address", bound, dst)
		}
	})
}
