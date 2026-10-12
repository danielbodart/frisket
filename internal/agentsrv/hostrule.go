package agentsrv

import (
	"errors"
	"fmt"
	"strings"
)

// A host rule's key is a name as the known hosts file lists it, or a
// pattern in execrule's grammar read a label at a time: * alone is any one
// label, * within a label any run of it (*-ap), and ** as the first label
// one or more labels. A literal key beats a pattern; between patterns, more
// whole literal labels beat fewer, then more literal bytes in the labels
// with a *, then one without ** beats one with it; at a tie ask beats
// allow.
const (
	anyLabel  = "*"
	anyLabels = "**"
)

// CheckHostRule says what is wrong with a host rule's key, if anything.
func CheckHostRule(key string) error {
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

type hostPattern struct {
	labels  []string // after any leading **
	tail    bool     // began **: one or more labels before labels
	literal int      // labels with no *
	partial int      // literal bytes in labels with a *
}

func compileHost(key string) (hostPattern, error) {
	if err := CheckHostRule(key); err != nil {
		return hostPattern{}, err
	}
	p := hostPattern{labels: strings.Split(key, ".")}
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

func (p hostPattern) match(name string) bool {
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

// narrower is whether p is the more specific of two patterns that match
// the same name.
func (p hostPattern) narrower(q hostPattern) bool {
	if p.literal != q.literal {
		return p.literal > q.literal
	}
	if p.partial != q.partial {
		return p.partial > q.partial
	}
	return !p.tail && q.tail
}

// plainName is whether a known hosts name is one a rule may match: not a
// hashed entry, nor a pattern or a negation of the file's own.
func plainName(n string) bool {
	return n != "" && !strings.HasPrefix(n, "|") && !strings.ContainsAny(n, "*?!")
}

// hostRule is the rule that decides name: the most specific key in rules
// that matches it, and that key; "" when none does.
func hostRule(rules map[string]Rule, name string) (Rule, string) {
	if !plainName(name) {
		return "", ""
	}
	if r, ok := rules[name]; ok {
		return r, name
	}
	var best hostPattern
	var bestKey string
	var bestRule Rule
	for k, r := range rules {
		p, err := compileHost(k)
		if err != nil || !p.match(name) {
			continue
		}
		tie := bestKey != "" && !p.narrower(best) && !best.narrower(p)
		if bestKey == "" || p.narrower(best) ||
			tie && (r == Ask && bestRule == Allow || r == bestRule && k < bestKey) {
			best, bestKey, bestRule = p, k, r
		}
	}
	return bestRule, bestKey
}

// hostsAllow is the key that allows one of names, each decided by its most
// specific rule; "" when none is allowed.
func hostsAllow(rules map[string]Rule, names []string) string {
	for _, n := range names {
		if r, k := hostRule(rules, n); r == Allow {
			return k
		}
	}
	return ""
}

var errNoName = errors.New("no plain name")

// ruleName is the name Always writes a rule for: the known hosts file's
// first plain name for the key.
func ruleName(names []string) (string, error) {
	for _, n := range names {
		if plainName(n) && CheckHostRule(n) == nil {
			return n, nil
		}
	}
	return "", errNoName
}
