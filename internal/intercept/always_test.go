package intercept

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"testing"

	recording "github.com/danielbodart/frisket/internal/record"
)

// fakeAlways offers Always on every question, and keeps what it offered
// and what was answered always.
type fakeAlways struct {
	mu       sync.Mutex
	offered  []AlwaysRule
	answered map[string]bool
}

func (a *fakeAlways) key(r AlwaysRule) string { return r.Route + "\x00" + r.Key }

func (a *fakeAlways) Admits(r AlwaysRule) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.answered[a.key(r)]
}

func (a *fakeAlways) Offer(q *Question, r AlwaysRule) func() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.offered = append(a.offered, r)
	q.Always = true
	q.Diff = &Diff{Path: "~/p/chase.json", New: r.Key}
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.answered == nil {
			a.answered = map[string]bool{}
		}
		a.answered[a.key(r)] = true
	}
}

// saying is an Asker that answers each question as answer says.
type saying struct {
	mu        sync.Mutex
	questions []Question
	answer    func(Question) recording.Answer
}

func (s *saying) Ask(_ context.Context, q Question) (recording.Answer, error) {
	s.mu.Lock()
	s.questions = append(s.questions, q)
	s.mu.Unlock()
	return s.answer(q), nil
}

// A request answered Always is admitted, its rule offered as its method
// and exact path, even where it is an operation; the same request is then
// admitted unasked for the rest of the session, and nothing else is -- not
// the same operation on another path.
func TestAlwaysAdmitsTheRuleForTheSession(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &saying{answer: func(q Question) recording.Answer {
		if q.Always && q.Path != "/v2/allowed-once" {
			return recording.Always
		}
		return recording.Allow
	}}
	alw := &fakeAlways{}
	ic, err := New(Config{Routes: []Route{gatedRoute(up, t, j)}, Log: slog.New(slog.NewJSONHandler(j, nil)), Policy: "test-policy", Asker: asker})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.Close() })
	ca, err := NewCA([]string{apiHost})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{ca: ca, journal: j, addr: listen(t, j, "sess-test", ic.ForSession(ca, "/work/test", alw)), ic: ic}
	c := f.client(t, false)

	do := func(method, target string) {
		t.Helper()
		req := newRequest(t, method, "https://"+apiHost+target, nil)
		req.Header.Set("Authorization", sandboxAuth)
		if res, _ := get(t, c, req); res.StatusCode != http.StatusOK {
			t.Errorf("%s %s: %d", method, target, res.StatusCode)
		}
	}
	do("DELETE", "/v1/things/a")
	do("DELETE", "/v1/things/b")
	do("POST", "/v2/other")
	do("POST", "/v2/other")
	do("POST", "/v2/allowed-once")
	do("POST", "/v2/allowed-once")
	do("POST", "/v2/other?x=1")

	if n := len(asker.questions); n != 5 {
		t.Fatalf("asked %d: %+v", n, asker.questions)
	}
	for _, q := range asker.questions {
		if !q.Always || q.Diff == nil {
			t.Errorf("not offered: %+v", q)
		}
	}
	keys := []string{}
	for _, r := range alw.offered {
		keys = append(keys, r.Route+" "+r.Key)
	}
	want := []string{"api DELETE /v1/things/a", "api DELETE /v1/things/b", "api POST /v2/other", "api POST /v2/allowed-once", "api POST /v2/allowed-once"}
	if len(keys) != len(want) {
		t.Fatalf("offered %q", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("offered %q, want %q", keys, want)
		}
	}
	rules := []string{}
	for _, l := range j.waitLines(t, "request", 7) {
		rules = append(rules, l["rule"].(string))
	}
	wantRules := []string{RuleAsked, RuleAsked, RuleAsked, RuleAlways, RuleAsked, RuleAsked, RuleAlways}
	for i := range wantRules {
		if rules[i] != wantRules[i] {
			t.Errorf("rules %q, want %q", rules, wantRules)
			break
		}
	}

	// The rule decides the same request again by any scope: refused by
	// the route's own, which asks, and admitted by one that names it.
	r := alw.offered[2]
	if o, err := r.Decides(Scope{Unmatched: UnmatchedAsk}); err != nil || o != Ask {
		t.Errorf("by the route's: %v %v", o, err)
	}
	if o, err := r.Decides(Scope{Paths: []PathRule{{Methods: []string{"POST"}, Path: "/v2/other"}}}); err != nil || o != Admit {
		t.Errorf("by one naming it: %v %v", o, err)
	}
}

// No Always where a rule could not be written: a request whose path a rule
// would read as a pattern, or no Always for the session.
func TestAlwaysIsNotOfferedForWhatNoRuleCouldName(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &saying{answer: func(Question) recording.Answer { return recording.Allow }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
	c := f.client(t, false)
	req := newRequest(t, "POST", "https://"+apiHost+"/v2/other", nil)
	req.Header.Set("Authorization", sandboxAuth)
	get(t, c, req)
	if len(asker.questions) != 1 || asker.questions[0].Always || asker.questions[0].Diff != nil {
		t.Errorf("questions %+v", asker.questions)
	}
	if _, ok := alwaysRule(&route{Route: Route{Name: "api"}}, req, mustURL(t, "/v2/a*b"), Verdict{Outcome: Ask}); ok {
		t.Error("a path with a * is a rule")
	}
	if _, ok := alwaysRule(&route{Route: Route{Name: "api"}}, req, mustURL(t, "/v2/x"), Verdict{Outcome: Ask, Operations: []*Operation{deleteThing, deleteThing}}); ok {
		t.Error("a request of several operations is a rule")
	}
}

// Always's rule is a request's method and exact path, whatever operation
// it is; a GraphQL field's and git's push, decided before any path, are
// their operation's id.
func TestAlwaysRulesAreExactPathsSaveGraphQLAndGit(t *testing.T) {
	rt := &route{Route: Route{Name: "api"}}
	for _, c := range []struct {
		method, path string
		v            Verdict
		want         string
	}{
		{"DELETE", "/v1/things/a", Verdict{Outcome: Ask, Reason: "path", Operation: deleteThing}, "DELETE /v1/things/a"},
		{"POST", "/v2/other", Verdict{Outcome: Ask, Reason: RuleUnmatched}, "POST /v2/other"},
		{"POST", "/graphql", Verdict{Outcome: Ask, Reason: "graphql", Operation: &Operation{ID: "closePullRequest"}}, "closePullRequest"},
		{"POST", "/o/r.git/git-receive-pack", Verdict{Outcome: Ask, Reason: "git", Operation: ReceivePack}, "git-receive-pack"},
	} {
		req := newRequest(t, c.method, "https://"+apiHost+c.path, nil)
		r, ok := alwaysRule(rt, req, mustURL(t, c.path), c.v)
		if !ok || r.Key != c.want {
			t.Errorf("%s %s: %q %v, want %q", c.method, c.path, r.Key, ok, c.want)
		}
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.ParseRequestURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
