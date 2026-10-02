package project

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestTheDerivationGivesTheContractsVectors(t *testing.T) {
	a63, a64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	for _, v := range []struct {
		project, address string
		names            []string
	}{
		{"example/shop", "127.101.170.171", []string{"shop.example.internal"}},
		{"example/billing", "127.10.146.214", []string{"billing.example.internal"}},
		{"danielbodart/frisket", "127.103.202.234", []string{"frisket.danielbodart.internal"}},
		{"test/repo-66", "127.211.18.75", []string{"repo-66.test.internal"}},
		{"Example/Shop", "127.101.170.171", []string{"shop.example.internal"}},
		// Nothing is folded, so these two no longer share a name.
		{"bodar/bodar.ts", "127.100.84.99", []string{"bodar.ts.bodar.internal"}},
		{"bodar/bodar-ts", "127.113.253.232", []string{"bodar-ts.bodar.internal"}},
		{"test/" + a63, "127.9.96.222", []string{a63 + ".test.internal"}},
		{"test/" + a64, "127.60.34.62", nil},
		{"test/my_repo", "", []string{"my_repo.test.internal"}},
		{"test/trail-", "", []string{"trail-.test.internal"}},
		{"test/x.-y", "", []string{"x.-y.test.internal"}},
		// A '-' first, which glibc refuses, and an empty label.
		{"test/-lead", "", nil},
		{"test/.github", "", nil},
		{"test/a..b", "", nil},
		{"test/a.", "", nil},
		{"test/_.._", "", nil},
		// An owner whose names are reserved names' has none.
		{"frisket/docker", "", nil},
		{"google/metadata", "", nil},
		{"frisket/frisket", "", nil},
		{"google/google", "", nil},
	} {
		if v.address != "" {
			if got := Address(v.project).String(); got != v.address {
				t.Errorf("%s: %s, want %s", v.project, got, v.address)
			}
		}
		if got := Names(v.project); !slices.Equal(got, v.names) {
			t.Errorf("%s: %q, want %q", v.project, got, v.names)
		}
	}
}

func TestTheEmbeddedReservedListIsExactlyFrisketsAndGooglesInternalApexes(t *testing.T) {
	// The flake's project-reserved check pins lib.project.reserved to the same
	// literal, so neither side of the one file can change without a test failing.
	if want := []string{"frisket.internal", "google.internal"}; !slices.Equal(reserved, want) {
		t.Fatalf("reserved.json gives %q, want %q", reserved, want)
	}
	for _, n := range []string{"frisket.internal", "google.internal", "docker.frisket.internal", "metadata.google.internal"} {
		if !Reserved(n) {
			t.Errorf("%s is not reserved", n)
		}
	}
	for _, n := range []string{"shop.internal", "frisket.danielbodart.internal"} {
		if Reserved(n) {
			t.Errorf("%s is reserved", n)
		}
	}
}

func TestAReservedListThatWouldReserveLessThanItSaysDoesNotParse(t *testing.T) {
	for _, b := range []string{
		``, `{}`, `"frisket.internal"`, `[]`, `null`, `[""]`, `["Frisket.internal"]`,
		`["frisket..internal"]`, `["frisket.internal."]`, `["frisket internal"]`,
		`["internal"]`, `["frisket.local"]`, `["frisket.internal", 1]`,
	} {
		if names, err := parseReserved([]byte(b)); err == nil {
			t.Errorf("%s parsed as %q", b, names)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a list that does not parse did not panic")
			}
		}()
		mustParseReserved([]byte(`[]`))
	}()
}

func Example() {
	fmt.Println(Address("example/shop"), Names("example/shop"))
	// Output: 127.101.170.171 [shop.example.internal]
}

func TestAProjectIsAnOwnerAndARepositoryAsARouteMayNameThem(t *testing.T) {
	for _, p := range []string{"example/shop", "o/r", "bodar/bodar.ts", "a-b/_", strings.Repeat("o", 39) + "/" + strings.Repeat("r", 100), "o/.x", "o/..."} {
		if !Valid(p) {
			t.Errorf("%q was refused", p)
		}
	}
	for _, p := range []string{"", "o", "o/", "/r", "O/r", "o/R", "-o/r", "o/r/x", "o/.", "o/..", "o/r ", strings.Repeat("o", 40) + "/r", "o/" + strings.Repeat("r", 101), "o_x/r"} {
		if Valid(p) {
			t.Errorf("%q was accepted", p)
		}
	}
}

func TestANameIsReadBackAsTheProjectItNames(t *testing.T) {
	for name, want := range map[string]string{
		"shop.example.internal":   "example/shop",
		"Shop.Example.Internal.":  "example/shop",
		"bodar.ts.bodar.internal": "bodar/bodar.ts",
		"my_repo.test.internal":   "test/my_repo",
		"a.b.c.owner-1.internal":  "owner-1/a.b.c",
	} {
		if got, ok := FromName(name); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{
		"", "internal", "shop.internal", "example.internal", ".example.internal",
		"shop.example.internal.x", "shop.example.local", "-lead.test.internal",
		"docker.frisket.internal", "metadata.google.internal", "shop.ex_ample.internal",
		"shop.-example.internal", "a..b.test.internal", strings.Repeat("a", 64) + ".test.internal",
		"shop." + strings.Repeat("o", 40) + ".internal",
	} {
		if got, ok := FromName(name); ok {
			t.Errorf("%q read as %q", name, got)
		}
	}
}
