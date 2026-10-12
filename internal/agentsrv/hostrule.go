package agentsrv

import (
	"errors"
	"strings"

	"github.com/danielbodart/frisket/hostpattern"
)

// CheckHostRule says what is wrong with a host rule's key, if anything: a
// name, or a pattern in hostpattern's grammar.
func CheckHostRule(key string) error { return hostpattern.Check(key) }

// plainName is whether a known hosts name is one a rule may match: not a
// hashed entry, nor a pattern or a negation of the file's own.
func plainName(n string) bool {
	return n != "" && !strings.HasPrefix(n, "|") && !strings.ContainsAny(n, "*?!")
}

// hostRule is the rule that decides name: the most specific key in rules
// that matches it, and that key; "" when none does. A literal key beats a
// pattern, then the narrower pattern (hostpattern.Narrower), and at a tie
// ask beats allow.
func hostRule(rules map[string]Rule, name string) (Rule, string) {
	if !plainName(name) {
		return "", ""
	}
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	k := hostpattern.Best(keys, name, func(a, b string) bool { return rules[a] == Ask && rules[b] == Allow })
	if k == "" {
		return "", ""
	}
	return rules[k], k
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
