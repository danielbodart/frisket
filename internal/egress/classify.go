// Package egress decides whether a steered connection may leave, dials it if
// so, and splices it to its original destination.
//
// Two rules, in this order, and the order is the design:
//
//  1. STRUCTURAL REFUSAL. Loopback, private, link-local, CGNAT, ULA,
//     unspecified, multicast, every other spelling of any of those, and every
//     address the host itself owns. Not configurable per session, and nothing
//     later can override it: there is no code path from "refused here" to
//     "accepted". ottergate consults its allowlist FIRST, which is why its
//     shipped configuration (0.0.0.0/0 allowlisted) lets a sandbox reach
//     169.254.169.254 and anything in 100.64/10.
//  2. THE SESSION'S RESOLVED SET. A connection is accepted only to an address
//     frisket's own DNS resolved, for a name the session is allowed, recently.
//     A workload that resolves names itself, or dials a literal address, has
//     nothing to show for it -- ottergate's name check is skipped for a literal
//     IP, which makes its 23-entry domain allowlist decorative.
//
// Rule 1 is checked twice: once when the connection is classified, so the log
// says why, and again in net.Dialer.Control against the address the kernel is
// actually about to connect to, so nothing that happens in between -- a
// resolver that answers differently the second time, a host address that
// appeared a moment ago -- can slip past it.
package egress

import (
	"fmt"
	"net/netip"
)

// Why an address is refused. They are strings because they are log fields
// first: a refusal that cannot be told apart from another in the log is a
// refusal nobody can explain later.
const (
	ReasonUnspecified = "unspecified"
	ReasonLoopback    = "loopback"
	ReasonPrivate     = "private"
	ReasonCGNAT       = "cgnat"
	ReasonLinkLocal   = "link-local"
	ReasonULA         = "unique-local"
	ReasonSiteLocal   = "site-local"
	ReasonMulticast   = "multicast"
	ReasonReserved    = "reserved"
	ReasonLocalNAT64  = "local-use nat64"
	ReasonHostOwned   = "host-owned"
	// ReasonHostUnknown: the host's own addresses could not be read, so there
	// is no way to know this address is not one of them. Fail closed.
	ReasonHostUnknown = "host addresses unknown"
	// ReasonInvalid: not an address at all. A zero netip.Addr is what a failed
	// parse leaves behind, and it must not fall through every prefix test to
	// "not refused".
	ReasonInvalid = "invalid address"
)

// The ways one v4 address can be written as a v6 one. Each is a spelling a
// classifier that only looks at v4 prefixes would miss: ottergate's refuses
// ::ffff:127.0.0.1 (net.IP.To4 saves it) and accepts ::127.0.0.1,
// 2002:7f00:1:: and 64:ff9b::7f00:1 -- all of which are 127.0.0.1 to something
// on the path that translates them.
const (
	SpellingV4Mapped     = "v4-mapped"     // ::ffff:a.b.c.d, RFC 4291
	SpellingV4Compatible = "v4-compatible" // ::a.b.c.d, RFC 4291 (deprecated; sit still decodes it)
	SpellingV4Translated = "v4-translated" // ::ffff:0:a.b.c.d, RFC 2765 SIIT
	Spelling6to4         = "6to4"          // 2002:aabb:ccdd::/48, RFC 3056
	SpellingNAT64        = "nat64"         // 64:ff9b::a.b.c.d, RFC 6052
	SpellingTeredo       = "teredo"        // 2001:0::/32, RFC 4380: server and (obfuscated) client
)

// Range is one row of the structural table.
type Range struct {
	Prefix netip.Prefix
	Reason string
}

// DefaultRanges is the structural table frisket ships with.
//
// The rows PLAN.md names, plus three that are not optional once you look at
// what Linux does with them: 0.0.0.0/8, because connect(0.0.0.0) on Linux
// reaches the LOCAL host; 240.0.0.0/4, reserved and including the limited
// broadcast address; and fec0::/10, deprecated site-local that a host can still
// have configured. 64:ff9b:1::/48 is refused whole: RFC 8215 reserves it for
// translators the local network runs, so everything in it is "something near
// us, reached by translation", and where the v4 half sits depends on a prefix
// length only that translator knows.
//
// It is data, and returned fresh each call, so a test can point frisket at a
// test network by passing a filtered copy to NewClassifier. It is NOT a
// per-session setting and no allowlist consults it: the table decides once, at
// construction, what is structurally unreachable.
func DefaultRanges() []Range {
	r := func(p, reason string) Range { return Range{netip.MustParsePrefix(p), reason} }
	return []Range{
		r("0.0.0.0/8", ReasonUnspecified),
		r("10.0.0.0/8", ReasonPrivate),
		r("100.64.0.0/10", ReasonCGNAT),
		r("127.0.0.0/8", ReasonLoopback),
		r("169.254.0.0/16", ReasonLinkLocal),
		r("172.16.0.0/12", ReasonPrivate),
		r("192.168.0.0/16", ReasonPrivate),
		r("224.0.0.0/4", ReasonMulticast),
		r("240.0.0.0/4", ReasonReserved),

		r("::/128", ReasonUnspecified),
		r("::1/128", ReasonLoopback),
		r("fe80::/10", ReasonLinkLocal),
		r("fec0::/10", ReasonSiteLocal),
		r("fc00::/7", ReasonULA),
		r("ff00::/8", ReasonMulticast),
		r("64:ff9b:1::/48", ReasonLocalNAT64),
	}
}

// embedding is one way of carrying a v4 address inside a v6 one.
type embedding struct {
	prefix   netip.Prefix
	spelling string
	extract  func(a [16]byte) []netip.Addr
}

func v4At(a [16]byte, off int) netip.Addr {
	return netip.AddrFrom4([4]byte(a[off : off+4]))
}

// embeddings lists every spelling that decodes to a v4 address. v4-mapped is
// not here: it is handled first, by unmapping, because it is not a spelling to
// something on the path -- it IS the v4 address, to our own kernel.
var embeddings = []embedding{
	{netip.MustParsePrefix("::ffff:0:0:0/96"), SpellingV4Translated, func(a [16]byte) []netip.Addr { return []netip.Addr{v4At(a, 12)} }},
	{netip.MustParsePrefix("::/96"), SpellingV4Compatible, func(a [16]byte) []netip.Addr { return []netip.Addr{v4At(a, 12)} }},
	{netip.MustParsePrefix("2002::/16"), Spelling6to4, func(a [16]byte) []netip.Addr { return []netip.Addr{v4At(a, 2)} }},
	{netip.MustParsePrefix("64:ff9b::/96"), SpellingNAT64, func(a [16]byte) []netip.Addr { return []netip.Addr{v4At(a, 12)} }},
	{netip.MustParsePrefix("2001::/32"), SpellingTeredo, func(a [16]byte) []netip.Addr {
		// The server in the clear, the client's mapped address XORed with
		// all-ones. Either one is somewhere a relay would send our bytes.
		var client [4]byte
		for i := range client {
			client[i] = a[12+i] ^ 0xff
		}
		return []netip.Addr{v4At(a, 4), netip.AddrFrom4(client)}
	}},
}

// Refusal says why an address is structurally unreachable. The zero value is
// "not refused".
type Refusal struct {
	// Reason is one of the Reason constants; empty means not refused.
	Reason string
	// Spelling is set when the address was refused because of a v4 address
	// written inside it, and Embedded is that v4 address.
	Spelling string
	Embedded netip.Addr
}

// Refused reports whether this is a refusal at all.
func (r Refusal) Refused() bool { return r.Reason != "" }

func (r Refusal) String() string {
	switch {
	case !r.Refused():
		return "not refused"
	case r.Spelling != "":
		return fmt.Sprintf("%s (%s spelling of %s)", r.Reason, r.Spelling, r.Embedded)
	default:
		return r.Reason
	}
}

// Classifier is the one address classifier. There is exactly one, on
// net/netip, with the table as data and no string handling anywhere: ottergate
// has three that disagree, one of which decides ULA with
// strings.HasPrefix(ip, "fd00:") and so waves fd12::1 through.
type Classifier struct {
	ranges []Range
	host   *HostAddrs
}

// NewClassifier builds a classifier over ranges (DefaultRanges when nil) and
// the host's own addresses.
//
// host is required. A classifier that did not know the host's addresses would
// let a sandbox reach every service the host binds to a public address -- its
// global IPv6 address above all -- and that is exactly the omission this
// refuses to make easy.
func NewClassifier(ranges []Range, host *HostAddrs) (*Classifier, error) {
	if host == nil {
		return nil, fmt.Errorf("egress: a classifier needs the host's own addresses")
	}
	if ranges == nil {
		ranges = DefaultRanges()
	}
	out := make([]Range, 0, len(ranges))
	for _, r := range ranges {
		p, err := canonPrefix(r.Prefix)
		if err != nil {
			return nil, fmt.Errorf("egress: structural range %v: %w", r.Prefix, err)
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("egress: structural range %v has no reason; it would refuse silently", p)
		}
		out = append(out, Range{p, r.Reason})
	}
	return &Classifier{ranges: out, host: host}, nil
}

// canonPrefix refuses prefixes that netip.Prefix.Contains would silently never
// match: a v4-mapped prefix matches no v4 address, and an address with a zone
// matches nothing at all. Either would be a row in the table that does nothing.
func canonPrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("not a valid prefix")
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("a prefix with a zone matches nothing")
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("a v4-mapped prefix matches no v4 address; write it as v4")
	}
	return p.Masked(), nil
}

// Classify says whether a is structurally unreachable, and why.
//
// Canonicalisation comes first and is total: the zone is dropped (Prefix.Contains
// returns false for ANY zoned address, so fe80::1%eth0 would otherwise pass the
// link-local row), a v4-mapped address is the v4 address, and an invalid
// address is refused rather than falling through every test.
func (c *Classifier) Classify(a netip.Addr) Refusal {
	if !a.IsValid() {
		return Refusal{Reason: ReasonInvalid}
	}
	a = a.WithZone("")
	if a.Is4In6() {
		// Not a spelling to report: the kernel connects to the v4 address.
		return c.classify(a.Unmap())
	}
	return c.classify(a)
}

func (c *Classifier) classify(a netip.Addr) Refusal {
	for _, r := range c.ranges {
		if r.Prefix.Contains(a) {
			return Refusal{Reason: r.Reason}
		}
	}
	owned, err := c.host.Contains(a)
	if err != nil {
		return Refusal{Reason: ReasonHostUnknown}
	}
	if owned {
		return Refusal{Reason: ReasonHostOwned}
	}
	if a.Is6() {
		b := a.As16()
		for _, e := range embeddings {
			if !e.prefix.Contains(a) {
				continue
			}
			for _, v4 := range e.extract(b) {
				// One level only: what is extracted is v4, and a v4 address
				// has no further spellings.
				if r := c.classify(v4); r.Refused() {
					return Refusal{Reason: r.Reason, Spelling: e.spelling, Embedded: v4}
				}
			}
		}
	}
	return Refusal{}
}
