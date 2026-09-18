// Package nsnet creates listening sockets inside another network namespace and
// hands them back to a process that never enters it.
//
// A socket belongs to the namespace it was created in, not to the process
// holding it. That is the whole mechanism frisket rests on: a privileged helper
// enters the sandbox's namespace, creates the listeners there, passes the
// descriptors out over SCM_RIGHTS and exits. Everything frisket does afterwards
// -- every upstream dial -- happens in the host's namespace, because frisket
// itself never moved.
//
// Nothing of ours is left inside the sandbox: no relay to kill, no socket
// bind-mounted in, no framing for a hostile workload to forge.
package nsnet

import (
	"fmt"
	"net/netip"
	"strings"
)

// Spec names one listener to create: a network and the address to bind it to,
// spelled the way a flag or a manifest carries it -- "tcp4:127.0.0.1:15001",
// "udp6:[::1]:15353".
//
// The address is always explicit. See Validate for why a wildcard is refused.
type Spec struct {
	// Net is one of "tcp4", "tcp6", "udp4", "udp6". The family is part of the
	// spelling rather than inferred, so a manifest read back from the helper
	// says what was created without having to look at the address.
	Net string

	// Addr is the address to bind, inside the target namespace.
	Addr netip.AddrPort
}

// The four networks a session can ask for. Two listeners per session is the
// whole surface -- one TCP, one DNS -- but each exists per family, because a
// v4 and a v6 redirect land on different sockets and the kernel decides which.
const (
	TCP4 = "tcp4"
	TCP6 = "tcp6"
	UDP4 = "udp4"
	UDP6 = "udp6"
)

// ParseSpec parses "net:addr:port". It is deliberately strict: a spec is
// written by us and read by the privileged helper, so anything ambiguous is a
// bug worth failing on rather than guessing about.
func ParseSpec(s string) (Spec, error) {
	net, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Spec{}, fmt.Errorf("spec %q: want net:addr:port", s)
	}
	addr, err := netip.ParseAddrPort(rest)
	if err != nil {
		return Spec{}, fmt.Errorf("spec %q: %w", s, err)
	}
	sp := Spec{Net: net, Addr: addr}
	if err := sp.Validate(); err != nil {
		return Spec{}, fmt.Errorf("spec %q: %w", s, err)
	}
	return sp, nil
}

// String is the inverse of ParseSpec for every Spec that validates.
func (s Spec) String() string { return s.Net + ":" + s.Addr.String() }

// Stream reports whether this spec wants SOCK_STREAM.
func (s Spec) Stream() bool { return s.Net == TCP4 || s.Net == TCP6 }

// V6 reports whether this spec wants AF_INET6.
func (s Spec) V6() bool { return s.Net == TCP6 || s.Net == UDP6 }

// Validate refuses the specs that would compile but not mean anything.
func (s Spec) Validate() error {
	switch s.Net {
	case TCP4, TCP6, UDP4, UDP6:
	default:
		return fmt.Errorf("network %q: want one of tcp4 tcp6 udp4 udp6", s.Net)
	}
	if !s.Addr.IsValid() {
		return fmt.Errorf("%s: no address", s.Net)
	}
	// An interface name means something different on each side of a setns, and
	// the spec is written on this side and used on the other one. Refuse rather
	// than bind whatever happens to carry that name over there.
	if s.Addr.Addr().Zone() != "" {
		return fmt.Errorf("%s: address carries a zone (%q), which does not survive the namespace", s.Net, s.Addr.Addr().Zone())
	}
	// A v4-mapped address is neither: binding it on an AF_INET6 socket with
	// IPV6_V6ONLY set fails, and it is not an AF_INET address either. Say so
	// here rather than at bind time in another namespace.
	if s.Addr.Addr().Is4In6() {
		return fmt.Errorf("%s: %s is a v4-mapped v6 address; write it as one family or the other", s.Net, s.Addr.Addr())
	}
	if s.V6() != s.Addr.Addr().Is6() {
		return fmt.Errorf("%s: address %s is the wrong family", s.Net, s.Addr.Addr())
	}
	if s.Addr.Port() == 0 {
		// Port 0 would work -- the kernel picks one -- but the ports are also
		// what the nftables rules redirect to, and the two come out of one
		// attrset precisely so they cannot drift. A spec that lets the kernel
		// choose has already drifted.
		return fmt.Errorf("%s: port 0; the redirect rules name the port, so it cannot be the kernel's choice", s.Net)
	}
	// A WILDCARD LISTENER CANNOT TELL STEERED FROM DIRECT. The original
	// destination of a connection that was never redirected is simply the
	// address it arrived on, and steer.Classify refuses a connection whose
	// original destination is the listener's own address. Bound to 0.0.0.0 that
	// comparison never matches, so every direct connection would look steered.
	if s.Addr.Addr().IsUnspecified() {
		return fmt.Errorf("%s: wildcard address %s; a direct connection to a wildcard listener is indistinguishable from a steered one", s.Net, s.Addr.Addr())
	}
	return nil
}

// ParseSpecs parses a comma-separated list, the form the helper takes on its
// command line.
func ParseSpecs(s string) ([]Spec, error) {
	if s == "" {
		return nil, fmt.Errorf("no specs")
	}
	parts := strings.Split(s, ",")
	specs := make([]Spec, 0, len(parts))
	for _, p := range parts {
		sp, err := ParseSpec(p)
		if err != nil {
			return nil, err
		}
		specs = append(specs, sp)
	}
	return specs, nil
}

// FormatSpecs is the inverse of ParseSpecs.
func FormatSpecs(specs []Spec) string {
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.String()
	}
	return strings.Join(out, ",")
}
