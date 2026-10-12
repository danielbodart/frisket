package always_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/internal/always"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/store"
	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh"
)

// fixture is a home with a project in it, an allowed signer's key, and a
// Writer that signs with it and writes as the courier would.
type fixture struct {
	t        *testing.T
	home, ws string
	signer   ssh.Signer
	w        *always.Writer
	log      *bytes.Buffer
	mu       sync.Mutex
	signed   []agentsrv.PolicySignRequest
	notices  []intercept.Question
	failSign error
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	ws := filepath.Join(home, "Projects", "foo")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	signers := filepath.Join(home, "allowed_signers")
	line := `dan namespaces="frisket-policy:*" ` + string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := os.WriteFile(signers, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, home: home, ws: ws, signer: signer, log: &bytes.Buffer{}}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{f: f}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.w = always.New(always.Config{Signer: "/nowhere", Courier: "/nowhere", AllowedSigners: signers, FileName: "chase.json", Home: home},
		log, func(_ context.Context, q intercept.Question) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.notices = append(f.notices, q)
			return nil
		})
	f.w.Fake(f.sign, f.write)
	return f
}

type lockedWriter struct{ f *fixture }

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	return l.f.log.Write(p)
}

func (f *fixture) sign(_ context.Context, req agentsrv.PolicySignRequest) ([]byte, error) {
	f.mu.Lock()
	f.signed = append(f.signed, req)
	fail := f.failSign
	f.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	ns, err := projpolicy.Namespace(req.Root, f.home)
	if err != nil {
		return nil, err
	}
	return projpolicy.Sign(rand.Reader, f.signer, ns, req.New)
}

// write is the courier's: compare and swap on the old digest, then both.
func (f *fixture) write(_ context.Context, root, old string, b, sig []byte) error {
	path := filepath.Join(root, "chase.json")
	cur, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cur = nil
	}
	if projpolicy.Digest(cur) != old {
		return errors.New("the policy file changed since it was read")
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	return os.WriteFile(path+projpolicy.SigSuffix, sig, 0o644)
}

// file writes the project's file, signed or not.
func (f *fixture) file(body string, signed bool) {
	f.t.Helper()
	path := filepath.Join(f.ws, "chase.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
	os.Remove(path + projpolicy.SigSuffix)
	if signed {
		sig, err := projpolicy.Sign(rand.Reader, f.signer, "frisket-policy:~/Projects/foo", []byte(body))
		if err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(path+projpolicy.SigSuffix, sig, 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

func hostKey(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// document is a session's: api asks about a delete and anything it does
// not name, and offers Always; capped is the same with a ceiling that
// holds writes at ask; plain offers none; gw is a machine that asks about
// every command, and offers Always.
func document(t *testing.T) []byte {
	route := func(always bool, ceiling map[string]string) map[string]any {
		r := map[string]any{
			"host": "api.test", "upstream": "https://api.test", "credentialFile": "/srv/token", "placeholder": "p",
			"paths": map[string]any{
				"GET /v1/**":          map[string]any{"operation": map[string]any{"id": "read", "class": "read", "summary": "Read"}},
				"DELETE /v1/things/*": map[string]any{"operation": map[string]any{"id": "delete-thing", "class": "write", "summary": "Delete Thing"}},
				"POST /v1/things":     map[string]any{"operation": map[string]any{"id": "make-thing", "class": "write", "summary": "Make Thing"}},
			},
			"writes": "ask", "unmatched": "ask", "guarded": "ask",
		}
		if always {
			r["always"] = true
		}
		if ceiling != nil {
			r["ceiling"] = ceiling
		}
		return r
	}
	capped := route(true, map[string]string{"writes": "ask"})
	capped["host"] = "capped.test"
	plain := route(false, nil)
	plain["host"] = "plain.test"
	doc := map[string]any{
		"version": 2, "name": "test",
		"allow":  map[string]any{"api.test": true, "capped.test": true, "plain.test": true},
		"routes": map[string]any{"api": route(true, nil), "capped": capped, "plain": plain},
		"ssh": map[string]any{
			"gw": map[string]any{"address": "192.0.2.1:22", "user": "root", "hostKeys": []string{hostKey(t)},
				"agent": "/run/agent", "unmatched": "ask", "always": true},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) session(doc []byte) *always.Session {
	f.t.Helper()
	l, err := policy.Load(doc)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.w.Session("s1", "test", f.ws, doc, l, store.RouteScope)
}

func httpRule(route, key, method, target string) intercept.AlwaysRule {
	return intercept.AlwaysRule{Route: route, Key: key, Decides: func(s intercept.Scope) (intercept.Outcome, error) {
		a, err := intercept.Answer(s, method, target)
		return a.Outcome, err
	}}
}

func sshRule(route, command string) intercept.AlwaysRule {
	return intercept.AlwaysRule{Route: route, SSH: true, Key: command, Command: command}
}

func (f *fixture) read() (string, []byte) {
	b, err := os.ReadFile(filepath.Join(f.ws, "chase.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(f.ws, "chase.json.sig"))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b), sig
}

// Always is offered with the file as it is and with the one rule added,
// admits at once when answered, and is signed, approved, into the file,
// which the next offer is made over.
func TestAlwaysOffersTheRuleAndWritesIt(t *testing.T) {
	f := newFixture(t)
	s := f.session(document(t))
	if s == nil {
		t.Fatal("no session")
	}
	rule := httpRule("api", "delete-thing", "DELETE", "/v1/things/7")
	var q intercept.Question
	save := s.Offer(&q, rule)
	want := "{\n  \"frisket\": {\n    \"routes\": {\n      \"api\": {\n        \"operations\": {\n          \"delete-thing\": \"allow\"\n        }\n      }\n    }\n  },\n  \"version\": 2\n}\n"
	if save == nil || !q.Always || q.Diff == nil || q.Diff.Path != "~/Projects/foo/chase.json" || q.Diff.Old != "" || q.Diff.New != want {
		t.Fatalf("offered %+v %+v", q, q.Diff)
	}
	if s.Admits(rule) {
		t.Fatal("admitted before it was answered")
	}
	save()
	if !s.Admits(rule) {
		t.Fatal("not admitted once answered")
	}
	s.Wait()
	got, sig := f.read()
	if got != want {
		t.Errorf("file %q", got)
	}
	signers, _ := projpolicy.ReadAllowedSigners(filepath.Join(f.home, "allowed_signers"))
	if _, err := projpolicy.Verify([]byte(got), sig, "frisket-policy:~/Projects/foo", signers, "dan", time.Now()); err != nil {
		t.Error(err)
	}
	if len(f.signed) != 1 || !f.signed[0].Approved || f.signed[0].Root != f.ws || f.signed[0].Name != "chase.json" {
		t.Errorf("signed %+v", f.signed)
	}
	if !strings.Contains(f.log.String(), `"outcome":"written"`) {
		t.Errorf("log %s", f.log.String())
	}

	// A request no operation names is its method and exact path; the
	// next offer is over the file just written.
	other := httpRule("api", "PATCH /v1/other", "PATCH", "/v1/other")
	q = intercept.Question{}
	save = s.Offer(&q, other)
	if save == nil || q.Diff.Old != want || !strings.Contains(q.Diff.New, `"PATCH /v1/other": "allow"`) || !strings.Contains(q.Diff.New, `"delete-thing": "allow"`) {
		t.Fatalf("second offer %+v", q.Diff)
	}
	save()
	s.Wait()
	if got, _ := f.read(); got != q.Diff.New {
		t.Errorf("file %q", got)
	}

	// An SSH command, its literal words.
	cmd := sshRule("gw", "uci show wireless")
	q = intercept.Question{}
	save = s.Offer(&q, cmd)
	if save == nil || !strings.Contains(q.Diff.New, "\"gw\": {\n        \"exec\": {\n          \"uci show wireless\": \"allow\"") {
		t.Fatalf("ssh offer %+v", q.Diff)
	}
	save()
	s.Wait()
	if !s.Admits(cmd) || s.Admits(sshRule("gw", "uci show network")) || s.Admits(httpRule("api", "make-thing", "POST", "/v1/things")) {
		t.Error("admits what was not answered")
	}
	// The written file's frisket section is a layer the session's document
	// takes, as the next launch would merge it.
	got, _ = f.read()
	var file map[string]json.RawMessage
	json.Unmarshal([]byte(got), &file)
	if _, err := policy.CheckProjectLayer(file["frisket"], document(t)); err != nil {
		t.Error(err)
	}
}

// Always is not offered where the rule would not stand, nor where the file
// may not be written over unseen.
func TestAlwaysIsNotOfferedWhereItWouldNotStand(t *testing.T) {
	f := newFixture(t)
	s := f.session(document(t))
	for name, rule := range map[string]intercept.AlwaysRule{
		"a route the host did not mark":      httpRule("plain", "delete-thing", "DELETE", "/v1/things/7"),
		"a ceiling holding writes at ask":    httpRule("capped", "delete-thing", "DELETE", "/v1/things/7"),
		"a command the rule would not match": sshRule("gw", "uci show **"),
		"no machine":                         sshRule("nas", "ls"),
		"no key":                             {Route: "api"},
	} {
		var q intercept.Question
		if save := s.Offer(&q, rule); save != nil || q.Always || q.Diff != nil {
			t.Errorf("%s: offered %+v", name, q)
		}
	}
	var q intercept.Question
	q.Record = true
	if s.Offer(&q, httpRule("api", "delete-thing", "DELETE", "/v1/things/7")) != nil {
		t.Error("a recording's question offered Always")
	}

	canonical := "{\n  \"version\": 2\n}\n"
	for name, setup := range map[string]func(){
		"unsigned": func() { f.file(canonical, false) },
		"signed elsewhere": func() {
			f.file(canonical, true)
			os.WriteFile(filepath.Join(f.ws, "chase.json"), []byte("{\n  \"version\": 2,\n  \"x\": 1\n}\n"), 0o644)
		},
		"not canonical":     func() { f.file(`{"version":2}`, true) },
		"chase.jsonc there": func() { os.WriteFile(filepath.Join(f.ws, "chase.jsonc"), []byte("{}"), 0o644) },
	} {
		os.Remove(filepath.Join(f.ws, "chase.json"))
		os.Remove(filepath.Join(f.ws, "chase.jsonc"))
		setup()
		var q intercept.Question
		if s.Offer(&q, httpRule("api", "delete-thing", "DELETE", "/v1/things/7")) != nil {
			t.Errorf("%s: offered", name)
		}
	}
	os.Remove(filepath.Join(f.ws, "chase.jsonc"))
	f.file(canonical, true)
	q = intercept.Question{}
	if s.Offer(&q, httpRule("api", "delete-thing", "DELETE", "/v1/things/7")) == nil || q.Diff.Old != canonical {
		t.Errorf("a signed canonical file: not offered, %+v", q.Diff)
	}

	// No session at all: version 1, no workspace, nothing marked.
	v1 := []byte(`{"name":"t","allow":["api.test"]}`)
	if l, _ := policy.Load(v1); f.w.Session("s", "t", f.ws, v1, l, store.RouteScope) != nil {
		t.Error("a version 1 document offers Always")
	}
	l, _ := policy.Load(document(t))
	if f.w.Session("s", "t", "", document(t), l, store.RouteScope) != nil {
		t.Error("no workspace offers Always")
	}
	var none *always.Writer
	if none.Session("s", "t", f.ws, document(t), l, store.RouteScope) != nil {
		t.Error("no writer offers Always")
	}
}

// A sign that fails still admits, for the session, and says so: in the
// journal and in a notice.
func TestAlwaysNotSavedStillAdmitsAndSaysSo(t *testing.T) {
	f := newFixture(t)
	f.failSign = errors.New("no key here is an allowed signer")
	s := f.session(document(t))
	rule := httpRule("api", "delete-thing", "DELETE", "/v1/things/7")
	var q intercept.Question
	save := s.Offer(&q, rule)
	if save == nil {
		t.Fatal("not offered")
	}
	save()
	s.Wait()
	if !s.Admits(rule) {
		t.Error("not admitted")
	}
	if _, err := os.Stat(filepath.Join(f.ws, "chase.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("written: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.log.String(), `"outcome":"not saved"`) {
		t.Errorf("log %s", f.log.String())
	}
	if len(f.notices) != 1 || f.notices[0].Kind != intercept.KindNotice || f.notices[0].Workspace != f.ws ||
		!strings.Contains(f.notices[0].Text, "no key here is an allowed signer") {
		t.Errorf("notices %+v", f.notices)
	}
}
