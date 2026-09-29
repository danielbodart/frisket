package docker

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
		{"example/shop", "127.101.170.171", []string{"shop.internal", "shop.example.internal"}},
		{"example/billing", "127.10.146.214", []string{"billing.internal", "billing.example.internal"}},
		// frisket.internal is the reserved apex.
		{"danielbodart/frisket", "127.103.202.234", []string{"frisket.danielbodart.internal"}},
		{"test/repo-66", "127.211.18.75", []string{"repo-66.internal", "repo-66.test.internal"}},
		{"Example/Shop", "127.101.170.171", []string{"shop.internal", "shop.example.internal"}},
		{"bodar/bodar.ts", "127.100.84.99", []string{"bodar-ts.internal", "bodar-ts.bodar.internal"}},
		{"bodar/bodar-ts", "127.113.253.232", []string{"bodar-ts.internal", "bodar-ts.bodar.internal"}},
		{"test/" + a63, "127.9.96.222", []string{a63 + ".internal", a63 + ".test.internal"}},
		{"test/" + a64, "127.60.34.62", nil},
		{"frisket/docker", "", []string{"docker.internal"}},
		{"google/metadata", "", []string{"metadata.internal"}},
		{"google/shop", "", []string{"shop.internal"}},
		{"frisket/frisket", "", nil},
		{"google/google", "", nil},
		{"test/_.._", "", nil},
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
	// The flake's docker-reserved check pins lib.docker.reserved to the same
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
	// Output: 127.101.170.171 [shop.internal shop.example.internal]
}

func TestAProjectIsAnOwnerAndARepositoryAsARouteMayNameThem(t *testing.T) {
	for _, p := range []string{"example/shop", "o/r", "bodar/bodar.ts", "a-b/_", strings.Repeat("o", 39) + "/" + strings.Repeat("r", 100), "o/.x", "o/..."} {
		if !ValidProject(p) {
			t.Errorf("%q was refused", p)
		}
	}
	for _, p := range []string{"", "o", "o/", "/r", "O/r", "o/R", "-o/r", "o/r/x", "o/.", "o/..", "o/r ", strings.Repeat("o", 40) + "/r", "o/" + strings.Repeat("r", 101), "o_x/r"} {
		if ValidProject(p) {
			t.Errorf("%q was accepted", p)
		}
	}
}
