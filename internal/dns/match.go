// Package dns is a session's resolver: the place the name allowlist is
// enforced, and the only source of the addresses egress will accept.
//
// frisket parses hostile DNS here, so it does not parse DNS itself. Every byte
// in and out goes through golang.org/x/net/dns/dnsmessage, the parser the
// standard library's own resolver vendors. ottergate hand-rolled one in 296
// lines and it has a remotely reachable panic and parses the single wire label
// "api.github.com" into the name api.github.com, which then matched an exact
// allowlist entry and was logged as that host. dnsmessage rejects a label
// containing a dot outright.
package dns

import (
	"errors"
	"fmt"
	"strings"
)

// maxName is the longest name in presentation form without the trailing dot:
// 255 wire bytes less the length octets and the root.
const maxName = 253

// Normalize is the one spelling a name is compared and logged under: ASCII
// lowercased and trailing dots removed.
//
// ASCII ONLY. strings.ToLower folds Unicode, and U+212A KELVIN SIGN lowercases
// to 'k' -- so a matcher that used it would let a name that is not the allowed
// name compare equal to it. DNS case-insensitivity is defined on ASCII and
// nothing else.
//
// All trailing dots, not one, so that Normalize is idempotent. A pattern with
// two is still refused -- by ParsePattern, which looks at what was written
// before normalising it.
func Normalize(name string) string {
	b := []byte(strings.TrimRight(name, "."))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Pattern is one validated allowlist entry: an exact name, or "*." and a name,
// which matches every name strictly below it.
type Pattern struct {
	Wildcard bool
	// Name is normalised: lowercase, no trailing dot, and for a wildcard the
	// part after "*.".
	Name string
}

func (p Pattern) String() string {
	if p.Wildcard {
		return "*." + p.Name
	}
	return p.Name
}

var (
	errEmpty        = errors.New("empty pattern")
	errBareStar     = errors.New(`bare "*" would match every name; list the names instead`)
	errInteriorStar = errors.New(`"*" is only allowed as the whole first label, as in "*.example.com"`)
)

// ParsePattern validates and normalises one allowlist entry.
//
// The grammar is exactly two shapes: a name, or "*." followed by a name. A name
// is labels of letters, digits, hyphen and underscore, 1 to 63 of them per
// label, no hyphen at either end, 253 in all, and one optional trailing dot.
// Everything else is refused AT LOAD, loudly -- ottergate validates only the
// length, so "*" is accepted and matches everything, and "api.*.com" is
// accepted and matches nothing, which for a blocklist is silently fail-open.
//
// Non-ASCII is refused rather than converted: write the xn-- form. Converting
// would put an IDNA implementation, and its disagreements with every other
// IDNA implementation, between the policy and what it matches.
func ParsePattern(s string) (Pattern, error) {
	if s == "" {
		return Pattern{}, errEmpty
	}
	if s == "*" || s == "*." {
		return Pattern{}, errBareStar
	}
	raw := strings.TrimSuffix(s, ".")
	var p Pattern
	if rest, ok := strings.CutPrefix(raw, "*."); ok {
		p.Wildcard, raw = true, rest
	}
	if strings.Contains(raw, "*") {
		return Pattern{}, fmt.Errorf("pattern %q: %w", s, errInteriorStar)
	}
	if err := validHostname(raw); err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: %w", s, err)
	}
	p.Name = Normalize(raw)
	return p, nil
}

// validHostname checks a name without its trailing dot.
func validHostname(n string) error {
	if n == "" {
		return errors.New("no name")
	}
	if len(n) > maxName {
		return fmt.Errorf("%d bytes, longer than %d", len(n), maxName)
	}
	for label := range strings.SplitSeq(n, ".") {
		if label == "" {
			return errors.New("empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label of %d bytes, longer than 63", len(label))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q begins or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			if !nameByte(label[i]) {
				if label[i] >= 0x80 {
					return fmt.Errorf("label %q is not ASCII; write its xn-- form", label)
				}
				return fmt.Errorf("label %q contains %q", label, label[i])
			}
		}
	}
	return nil
}

func nameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// ValidQueryName reports whether a normalised query name is one frisket will
// consider at all: non-empty labels of name bytes, separated by dots. Laxer than
// a pattern -- a hyphen at the end of a label does exist in the wild, and it
// matches nothing it should not -- but strict about the bytes, because a name
// that is going into a log line must not be able to smuggle quotes, control
// characters or look-alike Unicode into it.
//
// No empty label either. The wire cannot produce one, but Match takes a
// string, and ".google.com" -- or "a..google.com" -- walked dot by dot reaches
// "google.com" and would match "*.google.com" from a name with nothing in the
// wildcard's place.
func ValidQueryName(n string) bool {
	if n == "" || len(n) > maxName {
		return false
	}
	label := 0
	for i := 0; i < len(n); i++ {
		switch {
		case n[i] == '.':
			if label == 0 {
				return false
			}
			label = 0
		case nameByte(n[i]):
			if label++; label > 63 {
				return false
			}
		default:
			return false
		}
	}
	return label > 0
}

// Matcher is a set of patterns. The zero value and nil both match nothing.
type Matcher struct {
	exact map[string]struct{}
	// wild holds each wildcard's suffix. A name matches when some proper
	// suffix of it that starts right after a dot is in this set -- which is
	// ottergate's `HasSuffix(name, "." + suffix)`, the correct shape, done by
	// walking the dots so the cost is the number of labels rather than the
	// number of patterns. The dot is the whole point: "evil-google.com" has
	// "google.com" as a suffix, but not as a suffix that starts after a dot.
	wild     map[string]struct{}
	patterns []Pattern
}

// NewMatcher validates every pattern and fails on the first bad one, naming
// it. A policy with one typo is a policy that does not load, not a policy with
// a hole in it.
func NewMatcher(patterns ...string) (*Matcher, error) {
	m := &Matcher{exact: map[string]struct{}{}, wild: map[string]struct{}{}}
	for _, s := range patterns {
		p, err := ParsePattern(s)
		if err != nil {
			return nil, err
		}
		if p.Wildcard {
			m.wild[p.Name] = struct{}{}
		} else {
			m.exact[p.Name] = struct{}{}
		}
		m.patterns = append(m.patterns, p)
	}
	return m, nil
}

// MustMatcher is NewMatcher for tests and literals.
func MustMatcher(patterns ...string) *Matcher {
	m, err := NewMatcher(patterns...)
	if err != nil {
		panic(err)
	}
	return m
}

// Patterns returns the parsed patterns, in the order given.
func (m *Matcher) Patterns() []Pattern {
	if m == nil {
		return nil
	}
	return append([]Pattern(nil), m.patterns...)
}

// Match reports whether name, in any case and with or without a trailing dot,
// is covered by the set.
func (m *Matcher) Match(name string) bool {
	if m == nil {
		return false
	}
	// One trailing dot is the fully-qualified spelling; two is an empty label,
	// which Normalize would quietly make disappear.
	if strings.HasSuffix(name, "..") {
		return false
	}
	n := Normalize(name)
	if !ValidQueryName(n) {
		return false
	}
	if _, ok := m.exact[n]; ok {
		return true
	}
	for i := 0; i < len(n); i++ {
		if n[i] == '.' {
			if _, ok := m.wild[n[i+1:]]; ok {
				return true
			}
		}
	}
	return false
}
