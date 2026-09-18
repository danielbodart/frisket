package steer

import (
	"errors"
	"net/netip"
	"testing"

	"pgregory.net/rapid"
)

func TestClassify(t *testing.T) {
	bound := netip.MustParseAddrPort("127.0.0.1:15001")
	for _, tc := range []struct {
		name string
		orig netip.AddrPort
		err  error
		want Verdict
	}{
		{"redirected", netip.MustParseAddrPort("140.82.121.3:443"), nil, Verdict{Steered, ""}},
		{"no conntrack entry", netip.AddrPort{}, errors.New("ENOENT"), Verdict{Unsteered, ReasonNoConntrack}},
		{"dialled the listener", bound, nil, Verdict{Unsteered, ReasonOwnAddress}},
		{"nothing at all", netip.AddrPort{}, nil, Verdict{Unsteered, ReasonNoDestination}},
		// The spelling attack: reach the listener by its v4-mapped name and, if
		// the comparison is textual, be served as though the kernel steered it.
		{"dialled the listener, v4-mapped", netip.MustParseAddrPort("[::ffff:127.0.0.1]:15001"), nil, Verdict{Unsteered, ReasonOwnAddress}},
		// Same address, different port: a redirect to a second listener of
		// ours would look like this, and it IS steered.
		{"same address, other port", netip.MustParseAddrPort("127.0.0.1:15353"), nil, Verdict{Steered, ""}},
	} {
		if got := Classify(bound, tc.orig, tc.err); got != tc.want {
			t.Errorf("%s: Classify(%v, %v, %v) = %+v, want %+v", tc.name, bound, tc.orig, tc.err, got, tc.want)
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

// NOTHING PROMOTES A FAILED LOOKUP TO AN ACCEPTANCE. The error is tested first
// and there is no later branch that could reach Steered, whatever the addresses
// happen to be. This is the ordering ottergate gets wrong one layer up, where
// its allowlist is consulted before its structural refusal.
func TestAFailedLookupIsNeverSteered(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bound := genAddrPort().Draw(t, "bound")
		orig := genAddrPort().Draw(t, "orig")
		v := Classify(bound, orig, errors.New(rapid.String().Draw(t, "err")))
		if v.Steered() {
			t.Fatalf("Classify(%v, %v, err) = %+v", bound, orig, v)
		}
		if v.Reason != ReasonNoConntrack {
			t.Fatalf("reason = %q, want %q", v.Reason, ReasonNoConntrack)
		}
	})
}

// A connection whose original destination is the listener itself was never
// redirected: the workload found the socket and dialled it. Refused in every
// spelling of the same address, because a spelling the comparison misses is a
// connection served as if the kernel had steered it.
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
		for _, orig := range spellings {
			v := Classify(bound, orig, nil)
			if v.Steered() {
				t.Fatalf("Classify(%v, %v, nil) = %+v; %v is the listener under another name", bound, orig, v, orig)
			}
			if v.Reason != ReasonOwnAddress {
				t.Fatalf("Classify(%v, %v, nil) reason = %q, want %q", bound, orig, v.Reason, ReasonOwnAddress)
			}
		}
	})
}

// Steered is only ever reached with a usable destination that is not ours, and
// the answer does not depend on when it is asked.
func TestSteeredImpliesARealDestinationElsewhere(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bound := genAddrPort().Draw(t, "bound")
		orig := genAddrPort().Draw(t, "orig")
		v := Classify(bound, orig, nil)
		if again := Classify(bound, orig, nil); again != v {
			t.Fatalf("Classify is not a function: %+v then %+v", v, again)
		}
		if !v.Steered() {
			if v.Decision != Unsteered || v.Reason == "" {
				t.Fatalf("an unsteered verdict with no reason: %+v", v)
			}
			return
		}
		if !orig.IsValid() {
			t.Fatalf("Classify(%v, %v, nil) is steered with no destination", bound, orig)
		}
		if sameAddrPort(bound, orig) {
			t.Fatalf("Classify(%v, %v, nil) is steered at our own address", bound, orig)
		}
	})
}
