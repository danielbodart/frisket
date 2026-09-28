package intercept

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Secret Manager: reading a version's metadata is not reading its value, and
// the two differ only by the verb on the last segment.
func TestAVerbIsMoreSpecificThanAWildcard(t *testing.T) {
	op := func(id string) *Operation { return &Operation{ID: id, Summary: id} }
	versions := "/v1/projects/p/secrets/s/versions/"
	c := mustCompile(t, Scope{Paths: []PathRule{
		{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*/versions/*", Operation: op("get")},
		{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*/versions/*:access", Refuse: true, Operation: op("access")},
		{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*/versions/latest:access", Ask: true, Operation: op("latest")},
		{Methods: []string{"POST"}, Path: "/v1/projects/*/secrets/*:addVersion", Ask: true, Operation: op("add")},
		{Methods: []string{"GET"}, Prefix: "/v1/projects/*/locations/*:list", Operation: op("locations")},
		{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*", Ask: true, Operation: op("secret")},
		{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*:getIamPolicy", Operation: op("policy")},
	}, Unmatched: UnmatchedAsk})
	for _, tc := range []struct {
		method, target string
		outcome        Outcome
		operation      string
	}{
		{"GET", versions + "1", Admit, "get"},
		{"GET", versions + "1:access", Refuse, "access"},
		{"GET", versions + "1:ACCESS", Refuse, "access"},
		{"GET", versions + "1:Access", Refuse, "access"},
		{"GET", versions + "1%3Aaccess", Refuse, "access"},
		{"GET", versions + "1%3aaccess", Refuse, "access"},
		{"GET", versions + "1%253Aaccess", Refuse, "access"},
		{"GET", versions + "1:acc%65ss", Refuse, "access"},
		{"GET", versions + "1:access;x", Refuse, "access"},
		{"GET", versions + "1:access.", Refuse, "access"},
		{"GET", versions + "1:access/", Refuse, "access"},
		{"GET", versions + ":access", Refuse, "access"},
		{"GET", versions + "a:b:access", Refuse, "access"},
		{"GET", versions + "1:accessx", Admit, "get"},
		{"GET", versions + "1%2F2:access", Refuse, "access"},
		{"GET", versions + "latest:access", Ask, "latest"},
		{"GET", versions + "latest%3Aaccess", Refuse, "access"},
		{"GET", versions + "latest", Admit, "get"},
		{"GET", "/v1/projects/p/secrets/s", Ask, "secret"},
		{"GET", "/v1/projects/p/secrets/s:getIamPolicy", Admit, "policy"},
		{"GET", "/v1/projects/p/secrets/s%3AgetIamPolicy", Ask, "secret"},
		{"GET", "/v1/projects/p/secrets/s:getiampolicy", Ask, "secret"},
		{"POST", "/v1/projects/p/secrets/s:addVersion", Ask, "add"},
		{"POST", "/v1/projects/p/secrets/s%3AaddVersion", Ask, ""},
		{"POST", "/v1/projects/p/secrets/s:addversion", Ask, ""},
		{"POST", "/v1/projects/p/secrets/:addVersion", Ask, ""},
		{"POST", "/v1/projects/p/secrets/s:addVersion/x", Ask, ""},
		{"GET", "/v1/projects/p/locations/l:list", Admit, "locations"},
		{"GET", "/v1/projects/p/locations/l:list/more", Admit, "locations"},
		{"GET", "/v1/projects/p/locations/l:lister", Ask, ""},
		{"GET", "/v1/projects/p/locations/l%3Alist", Ask, ""},
	} {
		u, ok := parseTarget(tc.target)
		if !ok {
			t.Fatalf("test target %q does not parse", tc.target)
		}
		v := c.decide(tc.method, u)
		got := ""
		if v.Operation != nil {
			got = v.Operation.ID
		}
		if v.Outcome != tc.outcome || got != tc.operation {
			t.Errorf("%s %s: (%v, %q), want (%v, %q)", tc.method, tc.target, v.Outcome, got, tc.outcome, tc.operation)
		}
	}
}

// Cloud Storage names an object in one segment, its slashes encoded. A rule
// that says so takes them; every other rule still does not, and a stricter
// rule an upstream splitting at them might reach still decides.
func TestEncodedSlashesByOptIn(t *testing.T) {
	op := func(id string) *Operation { return &Operation{ID: id, Summary: id} }
	c := mustCompile(t, Scope{Paths: []PathRule{
		{Methods: []string{"GET"}, Path: "/storage/v1/b/*/o/*", EncodedSlashes: true, Operation: op("get")},
		{Methods: []string{"GET"}, Path: "/download/storage/v1/b/*/o/*", EncodedSlashes: true, Operation: op("download")},
		{Methods: []string{"DELETE"}, Path: "/storage/v1/b/*/o/*", Operation: op("delete")},
		{Methods: []string{"GET"}, Path: "/storage/v1/b/*/o/*/acl/*", Refuse: true, Operation: op("acl")},
	}, Unmatched: UnmatchedAsk})
	for _, tc := range []struct {
		method, target string
		outcome        Outcome
		operation      string
	}{
		{"GET", "/storage/v1/b/bk/o/a.txt", Admit, "get"},
		{"GET", "/storage/v1/b/bk/o/a%2Fb%2Fc.txt", Admit, "get"},
		{"GET", "/storage/v1/b/bk/o/a%2fb", Admit, "get"},
		{"GET", "/storage/v1/b/bk/o/a%5Cb", Admit, "get"},
		{"GET", "/storage/v1/b/bk/o/a%252Fb", Admit, "get"},
		{"GET", "/download/storage/v1/b/bk/o/a%2Fb?alt=media", Admit, "download"},
		{"GET", "/storage/v1/b/bk/o/%2F", Ask, ""},
		{"GET", "/storage/v1/b/bk/o/%2F%2F", Ask, ""},
		{"GET", "/storage/v1/b/bk/o/a%2F..%2Fb", Refuse, ""},
		{"GET", "/storage/v1/b/bk/o/a%2F.", Refuse, ""},
		{"GET", "/storage/v1/b/bk/o/a/b", Ask, ""},
		{"GET", "/storage/v1/b/bk/o/a%2Facl%2Fx", Refuse, "acl"},
		{"GET", "/storage/v1/b/bk/o/a/acl/x", Refuse, "acl"},
		{"DELETE", "/storage/v1/b/bk/o/a", Admit, "delete"},
		{"DELETE", "/storage/v1/b/bk/o/a%2Fb", Ask, ""},
	} {
		u, ok := parseTarget(tc.target)
		if !ok {
			t.Fatalf("test target %q does not parse", tc.target)
		}
		v := c.decide(tc.method, u)
		got := ""
		if v.Operation != nil {
			got = v.Operation.ID
		}
		if v.Outcome != tc.outcome || got != tc.operation {
			t.Errorf("%s %s: (%v, %q), want (%v, %q)", tc.method, tc.target, v.Outcome, got, tc.outcome, tc.operation)
		}
	}
}

func TestVerbConfiguration(t *testing.T) {
	get := []string{"GET"}
	for _, path := range []string{"/a/*:", "/a/*:b.c", "/a/*:b:c", "/a/**:b", "/a/x*:b", "/a/*:b*", "/a/*:*", "/a/*:b%2Fc", "/a/*%3Ab", "/a/x%3ab"} {
		if _, err := compileScope(Scope{Paths: []PathRule{{Methods: get, Path: path}}}); err == nil {
			t.Errorf("%s: compiled, want a refusal", path)
		}
	}
	for _, path := range []string{"/a/*:b", "/a/*:batchGet", "/a/*:b_c-1", "/a/latest:access", "/a/b:c:d", "/a/*:b/c"} {
		if _, err := compileScope(Scope{Paths: []PathRule{{Methods: get, Path: path}}}); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	if _, err := compileScope(Scope{Paths: []PathRule{{Methods: get, Path: "/a/b", EncodedSlashes: true}}}); err == nil {
		t.Error("encoded slashes for a rule with no * compiled")
	}
	if _, err := compileScope(Scope{Paths: []PathRule{{Methods: get, Prefix: "/a/*:b", EncodedSlashes: true}}}); err != nil {
		t.Error(err)
	}
}

// A GraphQL endpoint named with a verb is reached by it however it is spelt.
func TestAGraphQLPathCanHaveAVerb(t *testing.T) {
	c := mustCompile(t, Scope{GraphQL: []GraphQLScope{{Path: "/v1/*:graphql"}}, Unmatched: UnmatchedAsk})
	for target, want := range map[string]bool{
		"/v1/x:graphql":   true,
		"/v1/x%3Agraphql": true,
		"/v1/x:GraphQL":   true,
		"/v1/x:graphql/y": true,
		"/v1/x":           false,
	} {
		u, _ := parseTarget(target)
		if got := c.decide("POST", u).graphql != nil; got != want {
			t.Errorf("POST %s: graphql %v, want %v", target, got, want)
		}
	}
}

var (
	templatePieces = []string{"a", "b", "*", "*:v", "*:V", "*:w", "a:v", "A:v"}
	requestPieces  = []string{
		"a", "b", "A", "x", "a:v", "x:v", "x:V", "x:w", ":v", "x:v:v", "a%3Av", "x%3Av", "x%3av", "x%253Av",
		"x:%76", "x:v;p", "x:v.", "x%2Fy", "x%2Fy:v", "%2F", "x%5Cy", "x%252Fy", "a%2Fb", "..", "%2e", "",
	}
)

func genRules() *rapid.Generator[[]PathRule] {
	return rapid.Custom(func(t *rapid.T) []PathRule {
		rules := make([]PathRule, rapid.IntRange(1, 6).Draw(t, "rules"))
		for i := range rules {
			segs := rapid.SliceOfN(rapid.SampledFrom(templatePieces), 0, 3).Draw(t, "template")
			path := "/" + strings.Join(segs, "/")
			r := PathRule{Methods: []string{"GET"}, Prefix: path, Operation: &Operation{ID: strconv.Itoa(i), Summary: "s"}}
			if len(segs) > 0 && rapid.Bool().Draw(t, "exact") {
				r.Prefix, r.Path = "", path
			}
			r.EncodedSlashes = rapid.Bool().Draw(t, "encodedSlashes")
			switch rapid.IntRange(0, 2).Draw(t, "outcome") {
			case 1:
				r.Ask = true
			case 2:
				r.Refuse = true
			}
			rules[i] = r
		}
		return rules
	})
}

// mostSpecificDecides: a request is never decided by a rule less specific
// than another that matches it, unless the rule deciding is the stricter of
// the two, nor less strictly than a rule it does not outrank; and whatever
// admits a request took a verb only as it was spelt, and an encoded slash
// only where the rule said so.
func mostSpecificDecides(t *rapid.T) {
	var rules []PathRule
	for _, r := range genRules().Draw(t, "rules") {
		if _, err := compilePath(r); err == nil {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return
	}
	c := mustCompile(t, Scope{Paths: rules, Unmatched: UnmatchedAsk})
	target := "/" + strings.Join(rapid.SliceOfN(rapid.SampledFrom(requestPieces), 0, 4).Draw(t, "request"), "/")
	u, ok := parseTarget(target)
	if !ok {
		return
	}
	v := c.decide("GET", u)
	segs, err := splitPath(u.EscapedPath())
	if err != nil {
		if v.Outcome != Refuse || v.Reason != ReasonBadPath {
			t.Fatalf("GET %s: a path splitPath refuses was %v", target, v)
		}
		return
	}
	raw := strings.Split(u.EscapedPath()[1:], "/")
	var matched []*compiledPath
	for _, exact := range []bool{true, false} {
		for i := range c.paths {
			if p := &c.paths[i]; p.exact == exact && p.matches(segs, raw) {
				matched = append(matched, p)
			}
		}
		if len(matched) > 0 {
			break
		}
	}
	if v.Operation == nil {
		if len(matched) > 0 {
			t.Fatalf("GET %s: %v, but %v matched", target, v, matched[0].segs)
		}
		return
	}
	d := &c.paths[slices.IndexFunc(rules, func(r PathRule) bool { return r.Operation == v.Operation })]
	for _, q := range matched {
		if outranks(q, d, len(segs)) && strictness(d.outcome) <= strictness(q.outcome) {
			t.Fatalf("GET %s decided by %v %v, but %v %v matches and is more specific", target, d.outcome, d.segs, q.outcome, q.segs)
		}
		if strictness(q.outcome) > strictness(v.Outcome) && !outranks(d, q, len(segs)) {
			t.Fatalf("GET %s decided %v by %v, but %v %v matches and is as specific", target, v.Outcome, d.segs, q.outcome, q.segs)
		}
	}
	if v.Outcome != Admit {
		return
	}
	for i, tmpl := range d.segs {
		name, isVerb := verb(tmpl)
		if isVerb && !strings.HasSuffix(raw[i], ":"+name) {
			t.Fatalf("GET %s admitted by %v, but its verb was spelt %q", target, d.segs, raw[i])
		}
		if (tmpl == wildcard || isVerb) && !d.encodedSlashes && !oneSegment(segs[i]) {
			t.Fatalf("GET %s admitted by %v, whose * took %q", target, d.segs, raw[i])
		}
	}
}

func TestMostSpecificDecides(t *testing.T) { rapid.Check(t, mostSpecificDecides) }

func FuzzMostSpecificDecides(f *testing.F) { f.Fuzz(rapid.MakeFuzz(mostSpecificDecides)) }
