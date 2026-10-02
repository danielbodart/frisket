package intercept

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	recording "github.com/danielbodart/frisket/internal/record"
)

// recordingRoute admits GET under /v1, refuses DELETE of a thing by rule,
// asks about PUT of one, and leaves everything else unmatched, refused.
func recordingRoute(up *upstream, t *testing.T, j *journal) Route {
	cred, _ := tokenFile(t, j, realToken)
	r := apiRoute(up, cred)
	r.Scope = Scope{Paths: []PathRule{
		{Methods: []string{"GET"}, Prefix: "/v1"},
		{Methods: []string{"DELETE"}, Path: "/v1/things/*", Refuse: true, Operation: deleteThing},
		{Methods: []string{"PUT"}, Path: "/v1/things/*", Ask: true, Operation: &Operation{ID: "put-thing", Summary: "Put Thing", Class: "guarded"}},
	}}
	return r
}

func newRecordingFixture(t *testing.T, j *journal, def recording.Answer, asker Asker, routes ...Route) *fixture {
	t.Helper()
	log := slog.New(slog.NewJSONHandler(j, nil))
	rec, err := recording.New(recording.Config{Policy: "test-policy", Default: def, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return newFixtureWith(t, j, Config{Routes: routes, Log: log, Policy: "test-policy", Asker: asker, Recorder: rec})
}

// A recording session with a default admits what its scope refuses or asks
// about -- a guarded operation too: recording is manual mode -- with the
// credential on it, since the person recording is driving, and writes each
// subject down once, with what the scope would have done.
func TestARecordingSessionAdmitsWhatItsScopeWouldNotByItsDefault(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newRecordingFixture(t, j, recording.Allow, nil, recordingRoute(up, t, j))
	c := f.client(t, false)

	for _, r := range []struct{ method, target string }{
		{"GET", "/v1/things/a"},
		{"DELETE", "/v1/things/a"},
		{"DELETE", "/v1/things/b"}, // the same operation: remembered, not written again
		{"PUT", "/v1/things/a"},
		{"POST", "/v2/other"},
		{"POST", "/v2/other"},
	} {
		if res, body := get(t, c, newRequest(t, r.method, "https://"+apiHost+r.target, nil)); res.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d %s", r.method, r.target, res.StatusCode, body)
		}
	}
	seen := up.requests()
	if len(seen) != 6 {
		t.Fatalf("upstream saw %d requests, want 6", len(seen))
	}
	for _, r := range seen {
		if r.Header.Get("Authorization") != "Bearer "+realToken {
			t.Fatalf("%s %s went upstream without the credential", r.Method, r.URL)
		}
	}
	lines := f.journal.waitLines(t, "record", 3)
	want := []map[string]any{
		{"kind": "http", "route": "api", "method": "DELETE", "host": apiHost, "path": "/v1/things/a", "operation": "delete-thing",
			"would": "refuse", "rule": ReasonRefused, "answer": "allow", "source": "default"},
		{"kind": "http", "method": "PUT", "path": "/v1/things/a", "operation": "put-thing",
			"would": "ask", "rule": "path", "answer": "allow", "source": "default"},
		{"kind": "http", "method": "POST", "path": "/v2/other",
			"would": "refuse", "rule": ReasonOutOfScope, "answer": "allow", "source": "default"},
	}
	if len(lines) != len(want) {
		t.Fatalf("%d record lines, want %d: %v", len(lines), len(want), lines)
	}
	for i, w := range want {
		for k, v := range w {
			if lines[i][k] != v {
				t.Errorf("record line %d: %s = %v, want %v", i, k, lines[i][k], v)
			}
		}
	}
	rules := []string{}
	for _, l := range f.journal.waitLines(t, "request", 6) {
		rules = append(rules, l["rule"].(string))
	}
	if !slices.Equal(rules, []string{"path", RuleRecorded, RuleRecorded, RuleRecorded, RuleRecorded, RuleRecorded}) {
		t.Errorf("rules %v", rules)
	}
}

// A default of refuse refuses, as the scope would have, and records it so.
func TestARecordingSessionRefusesByItsDefault(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newRecordingFixture(t, j, recording.Refuse, nil, recordingRoute(up, t, j))
	c := f.client(t, false)
	if res, body := get(t, c, newRequest(t, "PUT", "https://"+apiHost+"/v1/things/a", nil)); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, ReasonRecordRefused) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if l := f.journal.waitLines(t, "record", 1)[0]; l["answer"] != "refuse" || l["source"] != "default" || l["would"] != "ask" {
		t.Fatalf("record line %v", l)
	}
	if len(up.requests()) != 0 {
		t.Fatal("refused, and sent upstream all the same")
	}
}

// With no default each subject is put to a person, the question marked as
// a recording's; their answer is what is done and what is written down, and
// the session does not ask about the same subject twice.
func TestARecordingSessionPutsEachSubjectToAPersonOnce(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &answering{byMethod: map[string]recording.Answer{"DELETE": recording.Ask, "PUT": recording.Refuse, "POST": recording.Allow}}
	f := newRecordingFixture(t, j, "", asker, recordingRoute(up, t, j))
	c := f.client(t, false)
	for _, r := range []struct {
		method, target string
		status         int
	}{
		{"DELETE", "/v1/things/a", http.StatusOK},
		{"DELETE", "/v1/things/b", http.StatusOK},
		{"PUT", "/v1/things/a", http.StatusForbidden},
		{"PUT", "/v1/things/a", http.StatusForbidden},
		{"POST", "/v2/other", http.StatusOK},
	} {
		if res, body := get(t, c, newRequest(t, r.method, "https://"+apiHost+r.target, nil)); res.StatusCode != r.status {
			t.Fatalf("%s %s: %d %s", r.method, r.target, res.StatusCode, body)
		}
	}
	asker.mu.Lock()
	questions := append([]Question(nil), asker.questions...)
	asker.mu.Unlock()
	if len(questions) != 3 {
		t.Fatalf("asked %d times, want once for each of three subjects", len(questions))
	}
	for _, q := range questions {
		if !q.Record || q.ID == "" {
			t.Errorf("question %+v is not marked a recording's", q)
		}
	}
	lines := f.journal.waitLines(t, "record", 3)
	for i, w := range []string{"ask", "refuse", "allow"} {
		if lines[i]["answer"] != w || lines[i]["source"] != "human" {
			t.Errorf("record line %d: %v, want %s from a person", i, lines[i], w)
		}
	}
}

// answering answers a recording's question by its method.
type answering struct {
	byMethod  map[string]recording.Answer
	mu        sync.Mutex
	questions []Question
}

func (a *answering) Ask(_ context.Context, q Question) (recording.Answer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.questions = append(a.questions, q)
	return a.byMethod[q.Method], nil
}

// What no grant could change is refused while recording as in any session:
// a path that is not canonical, and a Host that is not the SNI.
func TestARecordingSessionStillRefusesWhatNoPolicyDecides(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newRecordingFixture(t, j, recording.Allow, nil, recordingRoute(up, t, j))
	c := f.client(t, false)
	if res, _ := get(t, c, newRequest(t, "DELETE", "https://"+apiHost+"/v1/things/../../x", nil)); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a path not canonical: %d", res.StatusCode)
	}
	req := newRequest(t, "GET", "https://"+apiHost+"/v1/x", nil)
	req.Host = "other.example.test"
	if res, _ := get(t, c, req); res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("a Host that is not the SNI: %d", res.StatusCode)
	}
	if len(up.requests()) != 0 {
		t.Fatal("sent upstream")
	}
	if l := f.journal.waitLines(t, "record", 1)[0]; l["source"] != "hard" || l["reason"] != ReasonBadPath {
		t.Fatalf("record line %v", l)
	}
}

func TestNothingOnADockerRouteIsRecordable(t *testing.T) {
	rt := &route{docker: &dockerRoute{}}
	for _, v := range []Verdict{{Outcome: Ask}, {Outcome: Refuse, Reason: ReasonOutOfScope}} {
		if recordable(rt, v) {
			t.Errorf("%+v recordable on a Docker route", v)
		}
	}
	if !recordable(&route{}, Verdict{Outcome: Refuse, Reason: ReasonPush}) || recordable(&route{}, Verdict{Outcome: Refuse, Reason: ReasonBadPath}) {
		t.Error("recordable on another route")
	}
}
