package intercept

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

// answers is an Asker that says what it was told to, and keeps the questions.
type answers struct {
	mu        sync.Mutex
	questions []Question
	answer    func(Question) (bool, error)
}

func (a *answers) Ask(_ context.Context, q Question) (bool, error) {
	a.mu.Lock()
	a.questions = append(a.questions, q)
	a.mu.Unlock()
	return a.answer(q)
}

var deleteThing = &Operation{ID: "delete-thing", Summary: "Delete Thing", Description: "Removes the thing."}

// gatedRoute admits GET under /v1, asks about DELETE of a thing by name, and
// asks about anything else with nothing to say what it is.
func gatedRoute(up *upstream, t *testing.T, j *journal) Route {
	cred, _ := tokenFile(t, j, realToken)
	r := apiRoute(up, cred)
	r.Scope = Scope{
		Paths: []PathRule{
			{Methods: []string{"GET"}, Prefix: "/v1"},
			{Methods: []string{"DELETE"}, Path: "/v1/things/*", Ask: true, Operation: deleteThing},
		},
		Unmatched: UnmatchedAsk,
	}
	return r
}

func TestAPersonDecidesWhatTheScopeAsksAbout(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		asker := &answers{answer: func(q Question) (bool, error) {
			switch q.Method {
			case "DELETE":
				return true, nil
			case "PUT":
				return false, nil
			}
			return false, errors.New("the asker broke")
		}}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		c := f.client(t, h2)

		for _, r := range []struct {
			method, target string
			status         int
		}{
			{"GET", "/v1/things/a", http.StatusOK},
			{"DELETE", "/v1/things/a%2Fb?force=true", http.StatusOK},
			{"PUT", "/v1/things/a", http.StatusForbidden},
			{"POST", "/v2/other", http.StatusForbidden},
			{"DELETE", "/v1/things/../../x", http.StatusForbidden},
		} {
			req := newRequest(t, r.method, "https://"+apiHost+r.target, nil)
			req.Header.Set("Authorization", sandboxAuth)
			if res, _ := get(t, c, req); res.StatusCode != r.status {
				t.Errorf("%s %s: %d, want %d", r.method, r.target, res.StatusCode, r.status)
			}
		}

		// The GET was never asked about, and the bad path never got as far as
		// a person: only the three in between were.
		want := []Question{
			{Session: "sess-test", Policy: "test-policy", Route: "api", Method: "DELETE", Host: apiHost,
				Path: "/v1/things/a%2Fb", Query: "force=true", Operation: deleteThing},
			{Session: "sess-test", Policy: "test-policy", Route: "api", Method: "PUT", Host: apiHost, Path: "/v1/things/a"},
			{Session: "sess-test", Policy: "test-policy", Route: "api", Method: "POST", Host: apiHost, Path: "/v2/other"},
		}
		if !reflect.DeepEqual(asker.questions, want) {
			t.Errorf("questions:\n got %+v\nwant %+v", asker.questions, want)
		}

		// Admitted by a person, the request goes on with the real credential,
		// as one admitted by a rule would.
		seen := up.requests()
		if len(seen) != 2 || seen[1].Method != "DELETE" || seen[1].Header.Get("Authorization") != "Bearer "+realToken {
			t.Fatalf("upstream saw %v", seen)
		}

		lines := f.journal.waitLines(t, "request", 5)
		for i, w := range []map[string]any{
			{"decision": DecisionAllowed, "rule": "path"},
			{"decision": DecisionAllowed, "rule": RuleAsked, "operation": "delete-thing"},
			{"decision": DecisionRefused, "reason": ReasonDeclined},
			{"decision": DecisionRefused, "reason": ReasonAskFailed},
			{"decision": DecisionRefused, "reason": ReasonBadPath},
		} {
			for k, v := range w {
				if lines[i][k] != v {
					t.Errorf("line %d: %s = %v, want %v: %v", i, k, lines[i][k], v, lines[i])
				}
			}
		}
		if l := f.journal.lines(t, "ask"); len(l) != 1 || l[0]["error"] != "the asker broke" {
			t.Errorf("ask lines: %v", l)
		}
	})
}

// No asker is no admission: a gate with nobody to ask fails closed.
func TestNobodyToAskRefuses(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newFixture(t, j, gatedRoute(up, t, j))
	req := newRequest(t, "DELETE", "https://"+apiHost+"/v1/things/a", nil)
	req.Header.Set("Authorization", sandboxAuth)
	if res, _ := get(t, f.client(t, false), req); res.StatusCode != http.StatusForbidden {
		t.Fatalf("%d, want 403", res.StatusCode)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw %d requests", n)
	}
	if l := f.journal.waitLines(t, "request", 1); l[0]["reason"] != ReasonNobodyToAsk || l[0]["operation"] != "delete-thing" {
		t.Fatalf("%v", l[0])
	}
}
