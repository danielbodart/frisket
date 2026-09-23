package intercept

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
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
			{"DELETE", "/v1/things/a%3Ab?force=true", http.StatusOK},
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
			{Session: "sess-test", Workspace: "/work/test", Policy: "test-policy", Route: "api", Method: "DELETE", Host: apiHost,
				Path: "/v1/things/a%3Ab", Query: "force=true", Operation: deleteThing},
			{Session: "sess-test", Workspace: "/work/test", Policy: "test-policy", Route: "api", Method: "PUT", Host: apiHost, Path: "/v1/things/a"},
			{Session: "sess-test", Workspace: "/work/test", Policy: "test-policy", Route: "api", Method: "POST", Host: apiHost, Path: "/v2/other"},
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

// cloudflareShape is Cloudflare's error envelope, which wrangler reads.
var cloudflareShape = &Refusal{
	ContentType: "application/json",
	Body:        `{"success":false,"errors":[{"code":403,"message":"{{message}}"}],"messages":[],"result":null}`,
}

// A refusal in the route's own shape says why, in frisket's words and the
// operation's -- never the request's.
func TestARefusalIsInTheRoutesOwnShape(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	r := gatedRoute(up, t, j)
	r.Refusal = cloudflareShape
	asker := &answers{answer: func(Question) (bool, error) { return false, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, r)
	c := f.client(t, false)

	for _, tc := range []struct{ method, target, message string }{
		{"DELETE", `/v1/things/%22%7D%5D,%22x%22:1`, "frisket: refused: declined (Delete Thing)"},
		{"PUT", "/v1/other", "frisket: refused: declined"},
	} {
		req := newRequest(t, tc.method, "https://"+apiHost+tc.target, nil)
		req.Header.Set("Authorization", sandboxAuth)
		res, body := get(t, c, req)
		if res.StatusCode != http.StatusForbidden || res.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s %s: %d %s", tc.method, tc.target, res.StatusCode, res.Header.Get("Content-Type"))
		}
		var env struct {
			Success bool
			Errors  []struct {
				Code    int
				Message string
			}
		}
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			t.Fatalf("%s %s: not JSON: %q", tc.method, tc.target, body)
		}
		if env.Success || len(env.Errors) != 1 || env.Errors[0].Code != 403 || env.Errors[0].Message != tc.message {
			t.Errorf("%s %s: %+v", tc.method, tc.target, env)
		}
	}
}

func TestARefusalShapeMustHoldItsMessage(t *testing.T) {
	build := func(rf *Refusal) error {
		up := newUpstream(t, nil)
		r := apiRoute(up, nil)
		r.Credential, r.Inject, r.Placeholder = nil, nil, ""
		r.Refusal = rf
		ic, err := New(Config{Routes: []Route{r}, Log: slog.New(slog.NewJSONHandler(&journal{}, nil))})
		if err == nil {
			_ = ic.Close()
		}
		return err
	}
	if err := build(cloudflareShape); err != nil {
		t.Fatalf("a valid shape was refused: %v", err)
	}
	for name, rf := range map[string]*Refusal{
		"no placeholder":               {ContentType: "application/json", Body: `{"message":"no"}`},
		"two placeholders":             {ContentType: "text/plain", Body: "{{message}} {{message}}"},
		"placeholder outside a string": {ContentType: "application/json", Body: `{"message":{{message}}}`},
		"not JSON at all":              {ContentType: "application/problem+json", Body: `{"detail":"{{message}}"`},
		"no content type":              {Body: "{{message}}"},
	} {
		if build(rf) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A header or parameter some APIs read as the real method is refused: frisket
// decides on the request line's, and an admitted GET must not be a DELETE
// upstream.
func TestMethodOverridesAreRefused(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newFixture(t, j, gatedRoute(up, t, j))
	c := f.client(t, false)
	for _, tc := range []struct{ target, header string }{
		{"/v1/things/a", "X-HTTP-Method-Override"},
		{"/v1/things/a", "X-HTTP-Method"},
		{"/v1/things/a", "x-method-override"},
		{"/v1/things/a?_method=DELETE", ""},
	} {
		req := newRequest(t, "GET", "https://"+apiHost+tc.target, nil)
		req.Header.Set("Authorization", sandboxAuth)
		if tc.header != "" {
			req.Header.Set(tc.header, "DELETE")
		}
		if res, _ := get(t, c, req); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403", tc.target, tc.header, res.StatusCode)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw %d requests", n)
	}
}

// An asked request's body is in its question -- the start of it, its length
// and its digest -- and what goes upstream is exactly that body.
func TestAnAskedBodyIsShownAndSentAsShown(t *testing.T) {
	j := &journal{}
	var got []byte
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	})
	asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
	body := `{"type":"A","name":"www","content":"203.0.113.9"}` + strings.Repeat(" ", BodyPreview)
	req := newRequest(t, "POST", "https://"+apiHost+"/v2/records", strings.NewReader(body))
	req.Header.Set("Authorization", sandboxAuth)
	if res, _ := get(t, f.client(t, true), req); res.StatusCode != http.StatusOK {
		t.Fatalf("%d", res.StatusCode)
	}
	if len(asker.questions) != 1 {
		t.Fatalf("%d questions", len(asker.questions))
	}
	q := asker.questions[0]
	sum := sha256.Sum256([]byte(body))
	if !strings.HasPrefix(q.Body, `{"type":"A"`) || len(q.Body) != BodyPreview ||
		q.BodyBytes != int64(len(body)) || q.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("question: %d bytes shown of %d, digest %s", len(q.Body), q.BodyBytes, q.BodySHA256)
	}
	if string(got) != body {
		t.Fatalf("upstream got a different body from the one asked about")
	}
}

// A push asked about is shown as git-receive-pack, with the start of its body,
// which is the refs it would update: what the person is deciding.
func TestAPushAskedAboutShowsTheRefsItUpdates(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	cred, _ := tokenFile(t, j, realToken)
	asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
	route := Route{
		Name: "git", Host: gitHost, Upstream: up.URL, UpstreamCAs: up.pool(),
		Credential: cred, Inject: BasicUser("x-access-token"), Placeholder: placeholder,
		Scope: Scope{Git: &GitScope{AnyRepo: true, Push: Ask}},
	}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, route)
	c := f.client(t, false)

	update := "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main"
	for _, r := range []struct{ method, target, body string }{
		{"GET", "/owner/repo.git/info/refs?service=git-receive-pack", ""},
		{"POST", "/owner/repo.git/git-receive-pack", "0068" + update + "\x00report-status\n0000PACK"},
	} {
		req := newRequest(t, r.method, "https://"+gitHost+r.target, strings.NewReader(r.body))
		req.SetBasicAuth("x-access-token", placeholder)
		if res, _ := get(t, c, req); res.StatusCode != http.StatusOK {
			t.Errorf("%s %s: %d", r.method, r.target, res.StatusCode)
		}
	}
	if len(asker.questions) != 1 {
		t.Fatalf("asked %d questions, want the push alone: %+v", len(asker.questions), asker.questions)
	}
	q := asker.questions[0]
	if q.Operation != ReceivePack || !strings.Contains(q.Body, "refs/heads/main") {
		t.Errorf("question: %+v", q)
	}
	if n := len(up.requests()); n != 2 {
		t.Errorf("upstream saw %d requests, want both", n)
	}
}
