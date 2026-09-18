// Package steering is root's half of a session: `frisket steer` and
// `frisket connect`, run from a launcher's hook, in that order.
//
// THE ORDERING IS THE BOUNDARY. A namespace nspawn made with --private-network
// has lo up and an empty route table, so until something provisions egress the
// workload has nowhere to go and nothing to race. Therefore: listeners, then
// rules, then connectivity. Measured: rules first and egress three seconds
// later with no barrier of any kind gave 0 unsteered connections out of 20; the
// other order gave 12 of 12 unsteered.
//
// So the two steps are two commands, and each refuses to run out of turn:
//
//   - steer refuses a namespace that already has an interface besides lo, and
//     installs no rules unless the daemon holds the listeners they redirect to;
//   - connect refuses unless the daemon holds this namespace's session AND the
//     namespace has frisket's table loaded.
//
// Calling them the wrong way round fails loudly rather than working unsteered.
package steering

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
)

// File is the steering file lib.steering writes: ONE attrset produces the
// ruleset and the listener specification, so the ports the rules redirect to
// and the ports the listeners are bound to cannot drift apart.
type File struct {
	Set       string   `json:"set"`
	Table     string   `json:"table"`
	Listeners []string `json:"listeners"`
	Ruleset   string   `json:"ruleset"`
	Service   []string `json:"service"`
	Dummy     *Dummy   `json:"dummy,omitempty"`
}

// Dummy is the `all` set's egress: an interface with a default route per
// family, whose only purpose is to give the kernel somewhere to route to so the
// output hook sees the packet and redirects it.
type Dummy struct {
	Interface string   `json:"interface"`
	Addresses []string `json:"addresses"`
}

// Plan is a steering file, parsed and checked.
type Plan struct {
	Set       string
	Table     string
	Listeners []nsnet.Spec
	Ruleset   string
	Service   []netip.Addr
	Interface string       // `all` only
	Addresses []netip.Addr // `all` only: the dummy's, one per family
}

// Load reads and checks a steering file.
func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("steering file %s: %w", path, err)
	}
	p, err := f.Plan()
	if err != nil {
		return nil, fmt.Errorf("steering file %s: %w", path, err)
	}
	return p, nil
}

// Plan checks f and returns what it means.
func (f File) Plan() (*Plan, error) {
	p := &Plan{Set: f.Set, Table: f.Table, Ruleset: f.Ruleset}
	if f.Set != control.SetAll && f.Set != control.SetService {
		return nil, fmt.Errorf("set %q is neither %q nor %q", f.Set, control.SetAll, control.SetService)
	}
	if !identifier(f.Table) {
		return nil, fmt.Errorf("table %q is not an nftables identifier", f.Table)
	}
	// Connect checks for this table by name before it provisions anything, so
	// a ruleset that does not create it would make connect refuse every time
	// -- and one that creates some other table would be checked by nothing.
	if !strings.Contains(f.Ruleset, "table inet "+f.Table+" ") {
		return nil, fmt.Errorf("the ruleset does not create table inet %s", f.Table)
	}

	// FOUR SOCKETS, one TCP and one DNS listener per family. The ruleset
	// redirects both families, and a redirect with no listener behind it is a
	// port the workload can bind itself.
	seen := map[string]bool{}
	for _, l := range f.Listeners {
		s, err := nsnet.ParseSpec(l)
		if err != nil {
			return nil, err
		}
		if seen[s.Net] {
			return nil, fmt.Errorf("two %s listeners", s.Net)
		}
		seen[s.Net] = true
		// The redirect statement sends to the loopback address of the
		// family, so a listener anywhere else is never reached.
		if !s.Addr.Addr().IsLoopback() {
			return nil, fmt.Errorf("%s is not on loopback, where `redirect` sends", s)
		}
		p.Listeners = append(p.Listeners, s)
	}
	for _, n := range []string{nsnet.TCP4, nsnet.TCP6, nsnet.UDP4, nsnet.UDP6} {
		if !seen[n] {
			return nil, fmt.Errorf("no %s listener; the ruleset redirects both families", n)
		}
	}

	svc, err := onePerFamily("service address", f.Service)
	if err != nil {
		return nil, err
	}
	p.Service = svc

	switch f.Set {
	case control.SetAll:
		if f.Dummy == nil {
			return nil, fmt.Errorf("the %q set has no dummy interface: nothing would give the kernel a route to steer", control.SetAll)
		}
		if !ifname(f.Dummy.Interface) {
			return nil, fmt.Errorf("interface name %q", f.Dummy.Interface)
		}
		// A NON-LINK-LOCAL ADDRESS PER FAMILY. With a route alone, IPv4 picks
		// source 0.0.0.0 and the client resets, and IPv6 hangs until timeout.
		// Measured. A link-local address is no better: it is not a source for
		// a global destination.
		addrs, err := onePerFamily("dummy address", f.Dummy.Addresses)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if a.IsLinkLocalUnicast() {
				return nil, fmt.Errorf("dummy address %s is link-local, and would not be picked as a source", a)
			}
			for _, s := range svc {
				if a == s {
					return nil, fmt.Errorf("dummy address %s is also the service address", a)
				}
			}
		}
		p.Interface, p.Addresses = f.Dummy.Interface, addrs
	case control.SetService:
		if f.Dummy != nil {
			// Egress for this set is someone else's -- pasta, attached by the
			// launcher after the hook -- and a second default route would
			// fight it.
			return nil, fmt.Errorf("the %q set has a dummy interface; its egress is the launcher's", control.SetService)
		}
	}
	return p, nil
}

// onePerFamily parses exactly one v4 and one v6 unicast address.
func onePerFamily(what string, ss []string) ([]netip.Addr, error) {
	var v4, v6 int
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		if a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
			return nil, fmt.Errorf("%s %s is not a plain unicast address", what, a)
		}
		if a.Is4() {
			v4++
		} else {
			v6++
		}
		out = append(out, a)
	}
	if v4 != 1 || v6 != 1 {
		return nil, fmt.Errorf("%s: want one per family, have %d IPv4 and %d IPv6", what, v4, v6)
	}
	return out, nil
}

func identifier(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '_' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func ifname(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ConnectBatch is the `ip -batch` input connect runs: the service address on
// lo, and for `all` the dummy interface, its addresses and -- LAST, because
// they are the egress -- its default routes.
//
// The service address goes on lo so that a missing rule fails closed: a
// connection to it with no redirect is refused by the sandbox's own loopback,
// rather than routed out through whatever egress exists (measured).
func (p *Plan) ConnectBatch() string {
	var b strings.Builder
	for _, a := range p.Service {
		fmt.Fprintf(&b, "address add %s dev lo\n", netip.PrefixFrom(a, a.BitLen()))
	}
	if p.Set != control.SetAll {
		return b.String()
	}
	fmt.Fprintf(&b, "link add %s type dummy\n", p.Interface)
	for _, a := range p.Addresses {
		fmt.Fprintf(&b, "address add %s dev %s", netip.PrefixFrom(a, a.BitLen()), p.Interface)
		if a.Is6() {
			// Or the address is tentative for the length of duplicate
			// address detection, and a v6 client in that window picks no
			// source at all.
			b.WriteString(" nodad")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "link set %s up\n", p.Interface)
	// Spelt as prefixes, because `default` means IPv4 alone.
	fmt.Fprintf(&b, "route add 0.0.0.0/0 dev %s\n", p.Interface)
	fmt.Fprintf(&b, "route add ::/0 dev %s\n", p.Interface)
	return b.String()
}
