package docker

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/dns"
	"pgregory.net/rapid"
)

// Every address is loopback, off 127.0.0.0/16, where 127.0.0.1 and the
// resolver stubs are, and never the broadcast.
func TestEveryDerivedAddressIsAProjectsLoopback(t *testing.T) {
	low := netip.MustParsePrefix("127.0.0.0/16")
	rapid.Check(t, func(rt *rapid.T) {
		a := Address(rapid.String().Draw(rt, "project"))
		if !netip.MustParsePrefix("127.0.0.0/8").Contains(a) || low.Contains(a) || a == netip.MustParseAddr("127.255.255.255") {
			rt.Fatalf("%s", a)
		}
	})
}

// Every name is one frisket's DNS would answer, ends in .internal, and is
// never a reserved name or under one.
func TestEveryDerivedNameIsAValidInternalNameOutsideTheReservedOnes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		owner := rapid.OneOf(
			rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9-]{0,38}`),
			rapid.SampledFrom([]string{"google", "frisket", "Google", "internal"}),
		).Draw(rt, "owner")
		repo := rapid.OneOf(
			rapid.StringMatching(`[a-zA-Z0-9._-]{1,100}`),
			rapid.SampledFrom([]string{"docker", "frisket", "google", "metadata", "Frisket.", "-google-"}),
		).Draw(rt, "repo")
		for _, n := range Names(owner + "/" + repo) {
			if !dns.ValidQueryName(n) || !strings.HasSuffix(n, ".internal") || Reserved(n) {
				rt.Fatalf("%s/%s: %q", owner, repo, n)
			}
			for _, l := range strings.Split(n, ".") {
				if len(l) > 63 {
					rt.Fatalf("%s/%s: %q", owner, repo, n)
				}
			}
		}
		if names := Names(owner + "/" + repo); len(names) > 1 || slices.Contains(names, "frisket.internal") {
			rt.Fatalf("%v", names)
		}
	})
}

// A project's name reads back as the project, lower-cased: Names and
// Project are inverses wherever there is a name.
func TestEveryNameReadsBackAsItsProject(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		owner := rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9-]{0,38}`).Draw(rt, "owner")
		repo := rapid.StringMatching(`[a-zA-Z0-9._-]{1,100}`).Draw(rt, "repo")
		p := lowerASCII(owner + "/" + repo)
		for _, n := range Names(p) {
			if got, ok := Project(n); !ok || got != p {
				rt.Fatalf("%s: %q read back as %q %v", p, n, got, ok)
			}
		}
	})
}
