package intercept

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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

// An asked request's question carries the start of its body, whether more
// followed and the length it declared, and what goes upstream is that start
// and then the rest.
func TestAnAskedBodyIsShownByItsStartAndSentWhole(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		var got []byte
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			got, _ = io.ReadAll(r.Body)
		})
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		c := f.client(t, h2)
		small := `{"type":"A","name":"www","content":"203.0.113.9"}`
		for _, tc := range []struct {
			body string
			want Question
		}{
			{small, Question{Body: small, BodyLength: int64(len(small))}},
			{small + strings.Repeat(" ", BodyPreview), Question{Body: (small + strings.Repeat(" ", BodyPreview))[:BodyPreview],
				BodyMore: true, BodyLength: int64(len(small) + BodyPreview)}},
			{strings.Repeat("x", BodyPreview), Question{Body: strings.Repeat("x", BodyPreview), BodyLength: BodyPreview}},
		} {
			asker.questions = nil
			req := newRequest(t, "POST", "https://"+apiHost+"/v2/records", strings.NewReader(tc.body))
			if res, _ := get(t, c, req); res.StatusCode != http.StatusOK {
				t.Fatalf("%d", res.StatusCode)
			}
			q := asker.questions[0]
			if q.Body != tc.want.Body || q.BodyMore != tc.want.BodyMore || q.BodyLength != tc.want.BodyLength {
				t.Errorf("question: %d bytes shown, more %v, length %d; want %d, %v, %d",
					len(q.Body), q.BodyMore, q.BodyLength, len(tc.want.Body), tc.want.BodyMore, tc.want.BodyLength)
			}
			if string(got) != tc.body {
				t.Errorf("upstream got %d bytes, want the %d sent", len(got), len(tc.body))
			}
		}
	})
}

// An asked body has no limit: 64 MiB of unknown length is asked about by its
// start and then streamed, whole.
func TestAnAskedBodyHasNoLimit(t *testing.T) {
	const size = 64 << 20
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(h.Sum(nil)))
		})
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		want := sha256.New()
		req := newRequest(t, "PUT", "https://"+apiHost+"/v2/blob", io.TeeReader(io.LimitReader(pattern{}, size), want))
		req.ContentLength = -1
		res, got := get(t, f.client(t, h2), req)
		if res.StatusCode != http.StatusOK || got != fmt.Sprintf("%d %s", size, hex.EncodeToString(want.Sum(nil))) {
			t.Fatalf("%d %s", res.StatusCode, got)
		}
		q := asker.questions[0]
		if len(q.Body) != BodyPreview || !q.BodyMore || q.BodyLength != 0 {
			t.Fatalf("question: %d bytes shown, more %v, length %d", len(q.Body), q.BodyMore, q.BodyLength)
		}
	})
}

// A body that stops arriving is asked about by what it has sent: the client
// may be waiting for an answer before it sends more. What arrives after is
// sent on behind it once the request is admitted, and nothing is sent before.
func TestABodyThatPausesIsAskedAboutByWhatItSent(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		var got []byte
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			got, _ = io.ReadAll(r.Body)
		})
		pr, pw := io.Pipe()
		asked := make(chan Question, 1)
		asker := &answers{answer: func(q Question) (bool, error) {
			if n := len(up.requests()); n != 0 {
				t.Errorf("upstream saw %d requests before the answer", n)
			}
			asked <- q
			return true, nil
		}}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		done := make(chan *http.Response, 1)
		go func() {
			req := newRequest(t, "PUT", "https://"+apiHost+"/v2/log", pr)
			req.ContentLength = -1
			res, err := f.client(t, h2).Do(req)
			if err != nil {
				t.Error(err)
			}
			done <- res
		}()
		_, _ = pw.Write([]byte("first line\n"))
		var q Question
		select {
		case q = <-asked:
		case <-time.After(5 * time.Second):
			t.Fatal("never asked: the preview waited for a body that had paused")
		}
		if q.Body != "first line\n" || !q.BodyMore {
			t.Fatalf("question: %q, more %v", q.Body, q.BodyMore)
		}
		_, _ = pw.Write([]byte("second line\n"))
		_ = pw.Close()
		res := <-done
		if res == nil {
			return
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if string(got) != "first line\nsecond line\n" {
			t.Fatalf("upstream got %q", got)
		}
	})
}

// A body is waited for until it starts: headers and then, after longer than a
// body may pause, the body are asked about by that body, never by nothing.
func TestABodyThatStartsLateIsAskedAboutByItself(t *testing.T) {
	defer func(d time.Duration) { previewIdle = d }(previewIdle)
	previewIdle = 20 * time.Millisecond
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		var got []byte
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			got, _ = io.ReadAll(r.Body)
		})
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		pr, pw := io.Pipe()
		go func() {
			time.Sleep(20 * previewIdle)
			_, _ = pw.Write([]byte(`{"name":"www"}`))
			_ = pw.Close()
		}()
		req := newRequest(t, "PUT", "https://"+apiHost+"/v2/records", pr)
		req.ContentLength = -1
		if res, _ := get(t, f.client(t, h2), req); res.StatusCode != http.StatusOK {
			t.Fatalf("%d", res.StatusCode)
		}
		if q := asker.questions[0]; q.Body != `{"name":"www"}` || q.BodyMore {
			t.Fatalf("question: %q, more %v", q.Body, q.BodyMore)
		}
		if string(got) != `{"name":"www"}` {
			t.Fatalf("upstream got %q", got)
		}
	})
}

// A body declared and never sent is never asked about: the request waits for
// the client, and goes when it does.
func TestABodyNeverSentIsNeverAskedAbout(t *testing.T) {
	defer func(d time.Duration) { previewIdle = d }(previewIdle)
	previewIdle = 20 * time.Millisecond
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			req := newRequest(t, "PUT", "https://"+apiHost+"/v2/records", pr)
			req.ContentLength = 64
			res, err := f.client(t, h2).Do(req)
			if err == nil {
				res.Body.Close()
			}
			done <- err
		}()
		time.Sleep(20 * previewIdle)
		_ = pw.CloseWithError(errors.New("gave up"))
		if err := <-done; err == nil {
			t.Fatal("a request with no body had an answer")
		}
		if l := f.journal.waitLines(t, "request", 1)[0]; l["reason"] != ReasonStoppedWaiting {
			t.Fatalf("log: %v", l)
		}
		if n := len(asker.questions); n != 0 {
			t.Fatalf("asked %d times", n)
		}
		if n := len(up.requests()); n != 0 {
			t.Fatalf("upstream saw %d requests", n)
		}
	})
}

// A request with no body is asked about at once, with none.
func TestARequestWithNoBodyIsAskedAboutAtOnce(t *testing.T) {
	defer func(d time.Duration) { previewIdle = d }(previewIdle)
	previewIdle = time.Hour
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newUpstream(t, nil)
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
		for _, body := range []io.Reader{nil, strings.NewReader("")} {
			asker.questions = nil
			req := newRequest(t, "POST", "https://"+apiHost+"/v2/records", body)
			if res, _ := get(t, f.client(t, h2), req); res.StatusCode != http.StatusOK {
				t.Fatalf("%d", res.StatusCode)
			}
			if q := asker.questions[0]; q.Body != "" || q.BodyMore || q.BodyLength != 0 {
				t.Fatalf("question: %q, more %v, length %d", q.Body, q.BodyMore, q.BodyLength)
			}
		}
	})
}

// A declined body sends nothing upstream, however much of it there is.
func TestADeclinedBodyGoesNowhere(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &answers{answer: func(Question) (bool, error) { return false, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, gatedRoute(up, t, j))
	req := newRequest(t, "PUT", "https://"+apiHost+"/v2/blob", io.LimitReader(pattern{}, 8<<20))
	req.ContentLength = -1
	if res, _ := get(t, f.client(t, true), req); res.StatusCode != http.StatusForbidden {
		t.Fatalf("%d", res.StatusCode)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw %d requests", n)
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
