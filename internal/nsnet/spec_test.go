package nsnet

import (
	"net/netip"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestParseSpec(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Spec
	}{
		{"tcp4:127.0.0.1:15001", Spec{TCP4, netip.MustParseAddrPort("127.0.0.1:15001")}},
		{"tcp6:[::1]:15001", Spec{TCP6, netip.MustParseAddrPort("[::1]:15001")}},
		{"udp4:127.0.0.1:15353", Spec{UDP4, netip.MustParseAddrPort("127.0.0.1:15353")}},
		{"udp6:[::1]:15353", Spec{UDP6, netip.MustParseAddrPort("[::1]:15353")}},
	} {
		got, err := ParseSpec(tc.in)
		if err != nil {
			t.Fatalf("ParseSpec(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseSpec(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("String() = %q, want %q", got.String(), tc.in)
		}
	}
}

func TestParseSpecRefusals(t *testing.T) {
	// want is a substring the message must carry; empty means the refusal comes
	// from netip and only the fact of it is ours to assert.
	for _, tc := range []struct{ in, want string }{
		{"tcp4:127.0.0.1", ""},
		{"", "want net:addr:port"},
		{"sctp4:127.0.0.1:1", "want one of"},
		{"tcp4:[::1]:1", "wrong family"},
		{"tcp6:127.0.0.1:1", "wrong family"},
		{"tcp6:[::ffff:127.0.0.1]:1", "v4-mapped"},
		{"tcp4:127.0.0.1:0", "port 0"},
		// The two that are security properties rather than tidiness.
		{"tcp4:0.0.0.0:15001", "indistinguishable"},
		{"tcp6:[::]:15001", "indistinguishable"},
		{"tcp6:[fe80::1%eth0]:1", "zone"},
	} {
		_, err := ParseSpec(tc.in)
		if err == nil {
			t.Errorf("ParseSpec(%q) was accepted", tc.in)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSpec(%q) = %v, want it to mention %q", tc.in, err, tc.want)
		}
	}
}

func TestParseSpecsRoundTrip(t *testing.T) {
	in := "tcp4:127.0.0.1:15001,tcp6:[::1]:15001,udp4:127.0.0.1:15353,udp6:[::1]:15353"
	specs, err := ParseSpecs(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatSpecs(specs); got != in {
		t.Errorf("FormatSpecs = %q, want %q", got, in)
	}
}

// genSpec draws specs that are valid by construction, so the round-trip
// property below is about the spelling and not about the validation.
func genSpec() *rapid.Generator[Spec] {
	return rapid.Custom(func(t *rapid.T) Spec {
		network := rapid.SampledFrom([]string{TCP4, TCP6, UDP4, UDP6}).Draw(t, "net")
		port := rapid.Uint16Range(1, 65535).Draw(t, "port")
		var addr netip.Addr
		if network == TCP6 || network == UDP6 {
			b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "addr6")
			addr = netip.AddrFrom16([16]byte(b))
			// Both are refused on purpose; see Spec.Validate. Substituting
			// keeps the draw cheap and leaves the refusals to their own test.
			if addr.Is4In6() || addr.IsUnspecified() {
				addr = netip.MustParseAddr("2001:db8::1")
			}
		} else {
			b := rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "addr4")
			addr = netip.AddrFrom4([4]byte(b))
			if addr.IsUnspecified() {
				addr = netip.MustParseAddr("127.0.0.1")
			}
		}
		return Spec{Net: network, Addr: netip.AddrPortFrom(addr, port)}
	})
}

// A spec is written on the host and read inside the sandbox's namespace by a
// different process, so the two spellings have to be the same spelling.
func TestSpecRoundTripsThroughItsSpelling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := genSpec().Draw(t, "spec")
		if err := s.Validate(); err != nil {
			t.Fatalf("generated an invalid spec %v: %v", s, err)
		}
		got, err := ParseSpec(s.String())
		if err != nil {
			t.Fatalf("ParseSpec(%q): %v", s.String(), err)
		}
		if got != s {
			t.Fatalf("round trip: %v -> %q -> %v", s, s.String(), got)
		}
	})
}

// Whatever ParseSpec accepts must pass Validate, because Validate is what the
// helper relies on when it binds. A spec that parses and then fails to bind
// inside the namespace is a session aborted for the wrong reason.
func TestParseSpecOnlyEverProducesValidSpecs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "input")
		got, err := ParseSpec(s)
		if err != nil {
			return
		}
		if err := got.Validate(); err != nil {
			t.Fatalf("ParseSpec(%q) accepted %v, which Validate refuses: %v", s, got, err)
		}
		// Not String() == s: netip canonicalises, so "[::0001]:1" comes back
		// spelled "[::1]:1". What has to hold is that the canonical spelling
		// is a fixed point, because that is the one the helper is given.
		again, err := ParseSpec(got.String())
		if err != nil || again != got {
			t.Fatalf("ParseSpec(%q) = %v, but its own spelling %q parses to %v (%v)", s, got, got.String(), again, err)
		}
	})
}

func FuzzParseSpec(f *testing.F) {
	for _, s := range []string{
		"tcp4:127.0.0.1:15001", "udp6:[::1]:53", "", ":", "tcp4:", "tcp4:0.0.0.0:1",
		"tcp6:[::ffff:1.2.3.4]:1", "tcp4:127.0.0.1:65536", "tcp6:[fe80::1%25lo]:1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseSpec(s)
		if err != nil {
			return
		}
		if err := got.Validate(); err != nil {
			t.Fatalf("ParseSpec(%q) accepted %v, which Validate refuses: %v", s, got, err)
		}
		again, err := ParseSpec(got.String())
		if err != nil || again != got {
			t.Fatalf("ParseSpec(%q) = %v, but its own spelling %q parses to %v (%v)", s, got, got.String(), again, err)
		}
	})
}
