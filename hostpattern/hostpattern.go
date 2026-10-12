// Package hostpattern is the one grammar every host rule's key is written
// in -- the signer's ssh.hosts, and a version 2 policy document's allow,
// lan and ssh keys -- so that chase, the signer and the gateway read a key
// the same way.
//
// A key is a name, or a pattern in execrule's grammar read a label at a
// time: * alone is any one label, * within a label any run of it (*-ap),
// and ** as the first label one or more labels. A literal key beats a
// pattern; between patterns, more whole literal labels beat fewer, then
// more literal bytes in the labels with a *, then one without ** beats one
// with it.
package hostpattern

import (
	"fmt"
	"strings"
)

const (
	anyLabel  = "*"
	anyLabels = "**"
)

// Check says what is wrong with a key, if anything.
func Check(key string) error {
	if key == "" || strings.ContainsAny(key, ", \t\r\n?!") || strings.HasPrefix(key, "|") {
		return fmt.Errorf("%q is not a name the known hosts file could list, nor a pattern of one", key)
	}
	for i, l := range strings.Split(key, ".") {
		switch {
		case l == "":
			return fmt.Errorf("%q has an empty label", key)
		case l == anyLabels && i != 0:
			return fmt.Errorf("%q: %s is only the first label", key, anyLabels)
		case l != anyLabels && strings.Contains(l, anyLabels):
			return fmt.Errorf("%q: ** is a whole label, never part of one", key)
		}
	}
	return nil
}

// Pattern is a key, compiled.
type Pattern struct {
	key     string
	labels  []string // after any leading **
	tail    bool     // began **: one or more labels before labels
	literal int      // labels with no *
	partial int      // literal bytes in labels with a *
}

// Compile checks and compiles a key.
func Compile(key string) (Pattern, error) {
	if err := Check(key); err != nil {
		return Pattern{}, err
	}
	p := Pattern{key: key, labels: strings.Split(key, ".")}
	if p.labels[0] == anyLabels {
		p.tail, p.labels = true, p.labels[1:]
	}
	for _, l := range p.labels {
		if !strings.Contains(l, "*") {
			p.literal++
		} else {
			p.partial += len(strings.ReplaceAll(l, "*", ""))
		}
	}
	return p, nil
}

// String is the key.
func (p Pattern) String() string { return p.key }

// Literal is whether the key is a name, with no * in it.
func (p Pattern) Literal() bool { return !strings.Contains(p.key, "*") }

// Match is whether name matches, label for label, exactly as written: the
// caller normalises a name's case and trailing dot first, if it should.
func (p Pattern) Match(name string) bool {
	ls := strings.Split(name, ".")
	if p.tail {
		if len(ls) <= len(p.labels) {
			return false
		}
		ls = ls[len(ls)-len(p.labels):]
	} else if len(ls) != len(p.labels) {
		return false
	}
	for i, l := range p.labels {
		if ls[i] == "" || !labelMatch(l, ls[i]) {
			return false
		}
	}
	return true
}

// Below is the literal name every name the key matches is below, at any
// depth, and whether there is one: "example.com" for "**.example.com", ""
// and true for "**" alone. A key that is not ** and literal labels has
// none.
func (p Pattern) Below() (string, bool) {
	if !p.tail || p.literal != len(p.labels) {
		return "", false
	}
	return strings.Join(p.labels, "."), true
}

// CoversBelow is whether the key matches every name below suffix, at any
// depth: ** and labels that match suffix's last ones.
func (p Pattern) CoversBelow(suffix string) bool {
	ls := strings.Split(suffix, ".")
	if !p.tail || len(p.labels) > len(ls) {
		return false
	}
	ls = ls[len(ls)-len(p.labels):]
	for i, l := range p.labels {
		if !labelMatch(l, ls[i]) {
			return false
		}
	}
	return true
}

// labelMatch is whether a label matches a pattern's, whose * is any run
// of bytes, none included.
func labelMatch(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// Narrower is whether p is the more specific of two keys that match the
// same name. A literal key, which matches only itself, is narrower than
// any pattern.
func (p Pattern) Narrower(q Pattern) bool {
	if pl, ql := p.Literal(), q.Literal(); pl != ql {
		return pl
	}
	if p.literal != q.literal {
		return p.literal > q.literal
	}
	if p.partial != q.partial {
		return p.partial > q.partial
	}
	return !p.tail && q.tail
}

// Best is the key of keys that decides name: name itself if it is one,
// else the narrowest pattern that matches it, the lesser key between
// patterns neither narrower than the other unless tie says the other
// wins; "" when none matches. A key that does not compile matches nothing.
func Best(keys []string, name string, tie func(a, b string) bool) string {
	for _, k := range keys {
		if k == name {
			return k
		}
	}
	var best Pattern
	bestKey := ""
	for _, k := range keys {
		p, err := Compile(k)
		if err != nil || !p.Match(name) {
			continue
		}
		switch {
		case bestKey == "", p.Narrower(best):
		case best.Narrower(p):
			continue
		case tie != nil && tie(k, bestKey):
		case tie != nil && tie(bestKey, k):
			continue
		case k > bestKey:
			continue
		}
		best, bestKey = p, k
	}
	return bestKey
}
