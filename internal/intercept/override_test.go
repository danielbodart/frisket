package intercept

import (
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// A method override is what an upstream runs, so it is what frisket decides,
// asks about, logs and sends: a GET naming DELETE is a DELETE, and the
// override is gone from what goes upstream.
func TestAMethodOverrideIsTheMethod(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		c := f.client(t, h2)

		for _, tc := range []struct {
			method, target, header, value string
			query                         string
		}{
			{"GET", "/v1/things/a", "X-HTTP-Method-Override", "DELETE", ""},
			{"GET", "/v1/things/a", "X-HTTP-Method", "delete", ""},
			{"GET", "/v1/things/a", "x-method-override", "Delete", ""},
			{"GET", "/v1/things/a", "X_HTTP_METHOD_OVERRIDE", "DELETE", ""},
			{"GET", "/v1/things/a?$httpMethod=DELETE", "", "", ""},
			{"GET", "/v1/things/a?x=1&%24httpMethod=DELETE&y=2", "", "", "x=1&y=2"},
			{"GET", "/v1/things/a?x=1;%2524HTTPMETHOD=delete", "", "", "x=1"},
			{"POST", "/v1/things/a?_method=DELETE&x=%24httpMethod", "", "", "x=%24httpMethod"},
			{"HEAD", "/v1/things/a?$httpMethod=DELETE", "X-HTTP-Method-Override", "DELETE", ""},
		} {
			req := newRequest(t, tc.method, "https://"+apiHost+tc.target, nil)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			asker.questions = nil
			if res, _ := get(t, c, req); res.StatusCode != http.StatusOK {
				t.Errorf("%s %s %s: %d", tc.method, tc.target, tc.header, res.StatusCode)
				continue
			}
			if len(asker.questions) != 1 || asker.questions[0].Method != "DELETE" || asker.questions[0].Query != tc.query ||
				asker.questions[0].Operation != deleteThing {
				t.Errorf("%s %s %s: asked %+v", tc.method, tc.target, tc.header, asker.questions)
			}
			seen := up.requests()
			got := seen[len(seen)-1]
			if got.Method != "DELETE" || got.URL.RawQuery != tc.query {
				t.Errorf("%s %s %s: upstream saw %s ?%s", tc.method, tc.target, tc.header, got.Method, got.URL.RawQuery)
			}
			for h := range got.Header {
				if isOverrideHeader(h) {
					t.Errorf("%s %s: upstream saw %s", tc.method, tc.target, h)
				}
			}
		}

		for _, l := range f.journal.waitLines(t, "request", 9) {
			if l["method"] != "DELETE" || l["method_sent"] == nil || l["rule"] != RuleAsked || l["operation"] != "delete-thing" {
				t.Errorf("log: %v", l)
			}
		}
	})
}

// An override is decided as its method in the other direction too: a POST
// naming GET is a GET, admitted where GET is.
func TestAMethodOverrideCanNameAReadOnlyMethod(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newFixture(t, j, gatedRoute(up, t, j))
	req := newRequest(t, "POST", "https://"+apiHost+"/v1/things?$httpMethod=GET", strings.NewReader("{}"))
	if res, _ := get(t, f.client(t, false), req); res.StatusCode != http.StatusOK {
		t.Fatalf("%d", res.StatusCode)
	}
	if seen := up.requests(); len(seen) != 1 || seen[0].Method != "GET" {
		t.Fatalf("upstream saw %v", seen)
	}
	if l := f.journal.waitLines(t, "request", 1)[0]; l["method"] != "GET" || l["method_sent"] != "POST" || l["rule"] != "path" {
		t.Fatalf("log: %v", l)
	}
}

// Overrides that disagree, or that name no method, are refused: frisket
// cannot know which one an upstream would run.
func TestAMethodOverrideItCannotApplyIsRefused(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
	c := f.client(t, true)
	for _, tc := range []struct {
		target  string
		headers map[string][]string
		reason  string
	}{
		{"/v1/things/a?$httpMethod=POST", map[string][]string{"X-HTTP-Method-Override": {"DELETE"}}, ReasonOverrideConflict},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {"DELETE"}, "X-HTTP-Method": {"GET"}}, ReasonOverrideConflict},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {"DELETE"}, "X_HTTP_METHOD_OVERRIDE": {"GET"}}, ReasonOverrideConflict},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {"DELETE", "PUT"}}, ReasonOverrideConflict},
		{"/v1/things/a?$httpMethod=DELETE&%24httpMethod=GET", nil, ReasonOverrideConflict},
		{"/v1/things/a?_method=PUT&$httpMethod=DELETE", nil, ReasonOverrideConflict},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {"DELETE, GET"}}, ReasonOverrideInvalid},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {"CONNECT"}}, ReasonOverrideInvalid},
		{"/v1/things/a", map[string][]string{"X-HTTP-Method-Override": {""}}, ReasonOverrideInvalid},
		{"/v1/things/a?$httpMethod=", nil, ReasonOverrideInvalid},
		{"/v1/things/a?$httpMethod=DEL%ZZ", nil, ReasonOverrideInvalid},
		{"/v1/things/a?$httpMethod=DE+LETE", nil, ReasonOverrideInvalid},
	} {
		req := newRequest(t, "GET", "https://"+apiHost+tc.target, nil)
		for k, vs := range tc.headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if res, _ := get(t, c, req); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %v: %d, want 400", tc.target, tc.headers, res.StatusCode)
		}
		l := f.journal.lines(t, "request")
		if last := l[len(l)-1]; last["reason"] != tc.reason {
			t.Errorf("%s %v: %v", tc.target, tc.headers, last)
		}
	}
	if len(asker.questions) != 0 || len(up.requests()) != 0 {
		t.Fatalf("asked %d, upstream saw %d", len(asker.questions), len(up.requests()))
	}
}

// Git and GraphQL decide on the method an override names, as path rules do.
func TestGitAndGraphQLDecideOnTheOverride(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	git := Route{
		Name: "git", Host: gitHost, Upstream: up.URL, UpstreamCAs: up.pool(),
		Credential: cred, Inject: BasicUser("x-access-token"), Placeholder: placeholder,
		Scope: Scope{
			Git:   &GitScope{AnyRepo: true},
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}},
		},
	}
	f := newFixture(t, j, git, graphqlRoute(up, t, j, Refuse))
	c := f.client(t, false)

	push := newRequest(t, "GET", "https://"+gitHost+"/owner/repo.git/git-receive-pack", strings.NewReader("0000"))
	push.SetBasicAuth("x-access-token", placeholder)
	push.Header.Set("X-HTTP-Method-Override", "POST")
	if res, _ := get(t, c, push); res.StatusCode != http.StatusForbidden {
		t.Errorf("a push sent as GET: %d", res.StatusCode)
	}

	query := newRequest(t, "POST", "https://"+apiHost+"/graphql", strings.NewReader(`{"query":"{a}"}`))
	query.Header.Set("Content-Type", "application/json")
	query.Header.Set("X-HTTP-Method-Override", "GET")
	if res, _ := get(t, c, query); res.StatusCode != http.StatusForbidden {
		t.Errorf("a GraphQL query overridden to GET: %d", res.StatusCode)
	}

	lines := f.journal.waitLines(t, "request", 2)
	if l := lines[0]; l["reason"] != ReasonPush || l["method"] != "POST" {
		t.Errorf("push: %v", l)
	}
	if l := lines[1]; l["reason"] != ReasonUnclassified || l["method"] != "GET" || l["graphql"] != "unread: not a POST" {
		t.Errorf("graphql: %v", l)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw %d requests", n)
	}
}

func TestOverrideParamsAreStrippedAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		raw, query string
		values     []string
	}{
		{"", "", nil},
		{"a=1&b=2", "a=1&b=2", nil},
		{"a=1;b=2", "a=1;b=2", nil},
		{"$httpMethod=DELETE", "", []string{"DELETE"}},
		{"a=1&$httpMethod=DELETE&b=%24httpMethod", "a=1&b=%24httpMethod", []string{"DELETE"}},
		{"%24httpMethod=POST&a=1", "a=1", []string{"POST"}},
		{"a=1;_METHOD=put;b=2", "a=1;b=2", []string{"put"}},
		{"%2524httpmethod=GET", "", []string{"GET"}},
		{"%5Fmethod=PATCH&x", "x", []string{"PATCH"}},
		{"$httpMethodx=1&x$httpMethod=2", "$httpMethodx=1&x$httpMethod=2", nil},
		{"$httpMethod", "", []string{""}},
	} {
		query, values, ok := stripOverrideParams(tc.raw)
		if !ok || query != tc.query || !reflect.DeepEqual(values, tc.values) {
			t.Errorf("%q: %q %q %v, want %q %q", tc.raw, query, values, ok, tc.query, tc.values)
		}
	}
}
