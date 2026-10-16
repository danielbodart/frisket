package intercept

import (
	"net/url"
	"testing"
)

func v2op(id, class string) *Operation {
	return &Operation{ID: id, Summary: id, Class: class, Category: "c"}
}

func decideV2Case(t *testing.T, s Scope, method, target string) Verdict {
	t.Helper()
	s.V2 = true
	c, err := compileScope(s)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return c.decide(method, u)
}

// An operation answered by its id or category stands where its own
// template does: a pattern narrower than that template overrules it, a
// wider one does not, and one as specific decides only by being the
// stricter. One answered by its class is overruled by any pattern that
// matches, however wide; and a request that is no operation is the
// pattern's, or Unmatched's.
func TestAnOperationsNameStandsWhereItsTemplateDoes(t *testing.T) {
	s := Scope{
		Operations: []Endpoint{
			{PathRule: PathRule{Methods: []string{"POST"}, Path: "/repos/*/*/pulls", Operation: v2op("pulls/create", "write")}, Outcome: Admit, Named: true},
			{PathRule: PathRule{Methods: []string{"POST"}, Path: "/repos/*/*/issues", Operation: v2op("issues/create", "write")}, Outcome: Ask},
			{PathRule: PathRule{Methods: []string{"PUT"}, Path: "/repos/*/*/labels", Operation: v2op("labels/put", "write")}, Outcome: Ask, Named: true},
			{PathRule: PathRule{Methods: []string{"PATCH"}, Path: "/repos/*/*/labels", Operation: v2op("labels/patch", "write")}, Outcome: Refuse, Named: true},
		},
		Paths: []PathRule{
			{Methods: []string{"POST"}, Path: "/repos/o/*/pulls", Refuse: true},
			{Methods: []string{"POST"}, Prefix: "/repos/o", Refuse: true},
			{Methods: []string{"POST"}, Prefix: "/repos/w", Refuse: true},
			{Methods: []string{"PUT"}, Path: "/repos/*/*/labels", Refuse: true},
			{Methods: []string{"PATCH"}, Path: "/repos/*/*/labels"},
			{Methods: []string{"GET"}, Prefix: "/"},
		},
		Unmatched: UnmatchedAsk,
	}
	for _, c := range []struct {
		method, target string
		want           Outcome
		op             string
	}{
		{"POST", "/repos/o/r/pulls", Refuse, "pulls/create"},   // a literal pattern, narrower than its id's template
		{"POST", "/repos/w/r/pulls", Admit, "pulls/create"},    // its id, over a prefix pattern
		{"POST", "/repos/x/r/pulls", Admit, "pulls/create"},    // its id, no pattern matching
		{"PUT", "/repos/x/r/labels", Refuse, "labels/put"},     // as specific as its template, and stricter
		{"PATCH", "/repos/x/r/labels", Refuse, "labels/patch"}, // as specific, and more lenient: its id
		{"POST", "/repos/x/r/issues", Ask, "issues/create"},    // its class, no pattern matching
		{"POST", "/repos/o/r/issues", Refuse, "issues/create"}, // the prefix pattern, over its class
		{"GET", "/anything", Admit, ""},
		{"DELETE", "/anything", Ask, ""}, // unmatched
	} {
		v := decideV2Case(t, s, c.method, c.target)
		got := ""
		if v.Operation != nil {
			got = v.Operation.ID
		}
		if v.Outcome != c.want || got != c.op {
			t.Errorf("%s %s: %d %q, want %d %q", c.method, c.target, v.Outcome, got, c.want, c.op)
		}
	}
}

// Between patterns, a literal beats a *, and an exact path any prefix:
// "/a/*" over "/a/**", "/a/b" over "/a/*".
func TestALiteralPatternBeatsAWiderOne(t *testing.T) {
	s := Scope{Paths: []PathRule{
		{Methods: []string{"GET"}, Prefix: "/a", Refuse: true},
		{Methods: []string{"GET"}, Path: "/a/*", Ask: true},
		{Methods: []string{"GET"}, Path: "/a/b"},
	}}
	for target, want := range map[string]Outcome{"/a/b": Admit, "/a/c": Ask, "/a/c/d": Refuse, "/a": Refuse} {
		if v := decideV2Case(t, s, "GET", target); v.Outcome != want {
			t.Errorf("%s: %d, want %d", target, v.Outcome, want)
		}
	}
}

// A ceiling clamps what a pattern says of an operation's class, and of a
// request that is no operation; an operation's own answer is clamped by
// whoever built it.
func TestACeilingClampsAPatternByTheRequestsClass(t *testing.T) {
	s := Scope{
		Operations: []Endpoint{
			{PathRule: PathRule{Methods: []string{"DELETE"}, Path: "/repos/*/*", Operation: v2op("repos/delete", "guarded")}, Outcome: Refuse},
			{PathRule: PathRule{Methods: []string{"PATCH"}, Path: "/repos/*/*", Operation: v2op("repos/update", "write")}, Outcome: Ask},
			{PathRule: PathRule{Methods: []string{"GET"}, Path: "/repos/*/*", Operation: v2op("repos/get", "read")}, Outcome: Admit},
		},
		Paths:     []PathRule{{Methods: []string{"GET", "PATCH", "DELETE", "POST"}, Prefix: "/"}},
		Unmatched: UnmatchedAdmit,
		Ceiling:   map[string]Outcome{"guarded": Refuse, "write": Ask, "": Ask},
	}
	for _, c := range []struct {
		method, target string
		want           Outcome
	}{
		{"DELETE", "/repos/o/r", Refuse}, // guarded: the pattern's allow, clamped
		{"PATCH", "/repos/o/r", Ask},     // write
		{"GET", "/repos/o/r", Admit},     // read: no ceiling
		{"POST", "/elsewhere", Ask},      // no operation: the pattern, clamped as unmatched
	} {
		if v := decideV2Case(t, s, c.method, c.target); v.Outcome != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.target, v.Outcome, c.want)
		}
	}
}

// Unmatched may admit in version 2, and what it admits is still held to a
// stricter operation that a lenient reading of the request is: a trailing
// slash, another case, a ;parameter.
func TestAnAdmittingUnmatchedStillRefusesALenientSpellingOfARefusedOperation(t *testing.T) {
	s := Scope{
		Operations: []Endpoint{
			{PathRule: PathRule{Methods: []string{"DELETE"}, Path: "/repos/*/*", Operation: v2op("repos/delete", "guarded")}, Outcome: Refuse, Named: true},
		},
		Unmatched: UnmatchedAdmit,
	}
	for target, want := range map[string]Outcome{
		"/repos/o/r":       Refuse,
		"/repos/o/r/":      Refuse,
		"/REPOS/o/r":       Refuse,
		"/repos;x/o/r":     Refuse,
		"/repos/o/r/other": Admit,
	} {
		if v := decideV2Case(t, s, "DELETE", target); v.Outcome != want {
			t.Errorf("%s: %d, want %d", target, v.Outcome, want)
		}
	}
}

// What version 1 refuses to build, it still does: an admitting Unmatched,
// operations and a ceiling are version 2's.
func TestVersion2PartsAreRefusedInAVersion1Scope(t *testing.T) {
	for _, s := range []Scope{
		{Unmatched: UnmatchedAdmit},
		{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}, Ceiling: map[string]Outcome{"": Ask}},
		{Operations: []Endpoint{{PathRule: PathRule{Methods: []string{"GET"}, Prefix: "/", Operation: v2op("x", "read")}}}},
	} {
		if _, err := compileScope(s); err == nil {
			t.Errorf("%+v compiled", s)
		}
	}
}
