package agentsrv

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/hostpattern"
	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAHostPatternMatchesALabelOrMore(t *testing.T) {
	for _, c := range []struct {
		key, name string
		want      bool
	}{
		{"gateway", "gateway", true},
		{"gateway", "gateway.lan", false},
		{"*-ap", "kitchen-ap", true}, // * in a label is any run of it
		{"*-ap", "kitchen-ap.lan", false},
		{"*-ap", "-ap", true},
		{"*.bodar.com", "nas.bodar.com", true},
		{"*.bodar.com", "a.nas.bodar.com", false},
		{"*.bodar.com", "bodar.com", false},
		{"**.bodar.com", "a.nas.bodar.com", true},
		{"**.bodar.com", "nas.bodar.com", true},
		{"**.bodar.com", "bodar.com", false},
		{"nas.*.com", "nas.bodar.com", true},
		{"*", "gateway", true},
		{"*", "github.com", false},
		{"**", "github.com", true},
	} {
		p, err := hostpattern.Compile(c.key)
		if err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		if got := p.Match(c.name); got != c.want {
			t.Errorf("%s matching %s: %v", c.key, c.name, got)
		}
	}
	for _, bad := range []string{"", "a**b", "**-ap.lan", "a.**", "a..b", "a,b", "|1|x", "a?b", "!a", "a b"} {
		if CheckHostRule(bad) == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestALiteralBeatsAPatternAndANarrowerPatternAWider(t *testing.T) {
	rules := map[string]Rule{
		"**.example":    Allow,
		"*.example":     Ask,
		"a.b.example":   Ask,
		"*.b.example":   Allow,
		"git.b.example": Allow,
		"**.b.example":  Ask,
		"x.*.example":   Allow,
		"*.y.example":   Ask,
		"*-ap.example":  Allow,
		"*-*.example":   Ask,
	}
	for name, want := range map[string]Rule{
		"z.example":       Ask,   // *.example beats **.example: no **
		"q.z.example":     Allow, // only **.example
		"a.b.example":     Ask,   // the literal
		"git.b.example":   Allow, // the literal
		"c.b.example":     Allow, // *.b.example: two literal labels
		"d.c.b.example":   Ask,   // **.b.example
		"x.y.example":     Ask,   // x.*.example and *.y.example tie: ask
		"k-ap.example":    Allow, // *-ap.example: more of the label literal than *-*
		"k-x.example":     Ask,   // *-*.example over *.example: some of it literal
		"|1|aGFzaA==|eA=": "",    // a hashed name matches nothing
	} {
		if got, _ := hostRule(rules, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// fakeCourier answers read for each anchor pid and records writes.
type fakeCourier struct {
	mu       sync.Mutex
	reads    map[int]*courier.Response
	writes   []courier.Request
	conflict bool
	notes    []string
}

func (f *fakeCourier) read(_ context.Context, pid int, _ uint64) (*courier.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.reads[pid]
	if !ok {
		return nil, errors.New("no such anchor")
	}
	c := *r
	return &c, nil
}

func (f *fakeCourier) write(_ context.Context, root, old string, b, sig []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, courier.Request{Op: courier.OpWrite, Root: root, OldDigest: old, Bytes: b, Sig: sig})
	if f.conflict {
		return courier.ErrChanged
	}
	return nil
}

func (f *fakeCourier) notify(_ context.Context, _, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notes = append(f.notes, text)
	return nil
}

const home = "/home/dan"

// withPolicy configures a project policy read from fc, signed by key(0)
// unless unsigned, an allowed signers file naming key(0), and every peer
// in the host's user namespace.
func withPolicy(fc *fakeCourier) func(*Server) {
	return func(s *Server) {
		dir := filepath.Dir(s.KnownHosts)
		pub, _ := ssh.NewPublicKey(s.Keys[0].Signer.Public())
		line := `dan namespaces="frisket-policy:*" ` + string(ssh.MarshalAuthorizedKey(pub))
		if err := os.WriteFile(filepath.Join(dir, "allowed_signers"), []byte(line), 0o644); err != nil {
			panic(err)
		}
		s.Policy = &Policy{Courier: "/nonexistent", AllowedSigners: filepath.Join(dir, "allowed_signers"), FileName: "chase.json", Home: home}
		s.read, s.write, s.notify = fc.read, fc.write, fc.notify
		s.inHost = func(*net.UnixConn) error { return nil }
	}
}

// file is a project's policy file as the courier reads it: signed by the
// first key in root's namespace when signed, else unsigned.
func (h *harness) file(root string, body string, signed bool) *courier.Response {
	h.t.Helper()
	ns, err := projpolicy.Namespace(root, home)
	if err != nil {
		h.t.Fatal(err)
	}
	r := &courier.Response{Root: root, Namespace: ns, Bytes: []byte(body), Digest: projpolicy.Digest([]byte(body))}
	if signed {
		if r.Sig, err = signPolicy(h.s.Keys[0], ns, r.Bytes); err != nil {
			h.t.Fatal(err)
		}
	}
	return r
}

const foo = home + "/Projects/foo"

// project is a canonical policy file with these ssh.hosts.
func project(hosts string) string {
	b, err := projpolicy.Format([]byte(`{"version": 2, "signer": {"ssh": {"hosts": ` + hosts + `}}}`))
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestAVerifiedProjectsRuleSignsAsProject(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	fc.reads[100] = h.file(foo, project(`{"github.com": "allow"}`), true)
	if err := wait(t, h.login(claude(100), h.github, false)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"project"`) || !strings.Contains(h.log.String(), `"project":"`+foo+`"`) {
		t.Errorf("logged %s", h.log)
	}
}

func TestAProjectsPatternSignsAsProject(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	fc.reads[100] = h.file(foo, project(`{"*.com": "allow"}`), true)
	if err := wait(t, h.login(claude(100), h.github, false)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"project"`) {
		t.Errorf("logged %s", h.log)
	}
}

func TestAProjectMergesOverTheHostsRules(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, func(s *Server) {
		withPolicy(fc)(s)
		s.Hosts = map[string]Rule{"github.com": Allow}
	})
	// A rule the project sets to ask, or deletes, is asked.
	for i, hosts := range []string{`{"github.com": "ask"}`, `{"github.com": null}`} {
		fc.reads[100] = h.file(foo, project(hosts), true)
		done := h.login(claude(100), h.github, false)
		a := h.next()
		a.reply <- answered{}
		if wait(t, done) == nil {
			t.Errorf("%d: a refused sign was made", i)
		}
	}
	// The host's literal beats the project's wider pattern.
	fc.reads[100] = h.file(foo, project(`{"*.com": "ask"}`), true)
	if err := wait(t, h.login(claude(100), h.github, false)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"host"`) {
		t.Errorf("logged %s", h.log)
	}
}

func TestAnUnverifiedProjectIsIgnoredWithOneLine(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	for name, r := range map[string]*courier.Response{
		"unsigned": h.file(foo, project(`{"github.com": "allow"}`), false),
		"edited": func() *courier.Response {
			r := h.file(foo, project(`{"github.com": "ask"}`), true)
			r.Bytes = []byte(project(`{"github.com": "allow"}`))
			r.Digest = projpolicy.Digest(r.Bytes)
			return r
		}(),
		"another project's": func() *courier.Response {
			r := h.file(home+"/Projects/bar", project(`{"github.com": "allow"}`), true)
			r.Root = foo
			return r
		}(),
		"a host-only key": h.file(foo, "{\n  \"signer\": {\n    \"terminal\": \"allow\"\n  }\n}\n", true),
	} {
		fc.reads[100] = r
		for range 2 {
			done := h.login(claude(100), h.github, false)
			a := h.next()
			if a.q.Always || a.q.Diff != nil {
				t.Errorf("%s: Always offered over a file that does not verify: %+v", name, a.q)
			}
			a.reply <- answered{}
			if wait(t, done) == nil {
				t.Errorf("%s: a refused sign was made", name)
			}
		}
		if n := strings.Count(h.log.String(), `"msg":"project policy ignored"`); n != 1 {
			t.Errorf("%s: %d lines", name, n)
		}
		h.log.mu.Lock()
		h.log.b.Reset()
		h.log.mu.Unlock()
	}
}

func TestAProjectNeverCoversAForwardedSignOrACutChain(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	fc.reads[100] = h.file(foo, project(`{"github.com": "allow"}`), true)
	done := h.login(claude(100), h.github, true)
	a := h.next()
	if !strings.Contains(a.q.Text, "\nforwarded\n") || a.q.Always {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)

	done = h.login(links(claude(100).Chain[:4]...), h.github, false)
	a = h.next()
	if a.q.Always {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}

func TestTheCourierAbsentIsAsBefore(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	done := h.login(claude(100), h.github, false)
	a := h.next()
	if a.q.Always || !a.q.Grantable {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
	if !strings.Contains(h.log.String(), `"msg":"project policy unread"`) {
		t.Errorf("logged %s", h.log)
	}
}

func TestAProjectsSSHSIGRuleSignsAsProject(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, func(s *Server) { withPolicy(fc)(s); s.SSHSIG = nil })
	fc.reads[100] = h.file(foo, "{\n  \"signer\": {\n    \"sshsig\": {\n      \"git\": \"allow\"\n    }\n  }\n}\n", true)
	data, _ := os.ReadFile(filepath.Join("testdata", "sshsig-git.bin"))
	if err := wait(t, h.dial(claude(100)).signAsync(h.key(0), data)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"project"`) {
		t.Errorf("logged %s", h.log)
	}
}

func alwaysAnswer() answered {
	return answered{a: galleyask.Answer{Allowed: true, Always: true}}
}

func TestAlwaysShowsTheRuleItWritesAndWritesIt(t *testing.T) {
	for _, c := range []struct {
		name    string
		current *string
		want    string
	}{
		{"no file yet", nil, "{\n  \"signer\": {\n    \"ssh\": {\n      \"hosts\": {\n        \"github.com\": \"allow\"\n      }\n    }\n  },\n  \"version\": 2\n}\n"},
		{"a signed file", ptr(project(`{"gitlab.com": "ask"}`)), "{\n  \"signer\": {\n    \"ssh\": {\n      \"hosts\": {\n        \"github.com\": \"allow\",\n        \"gitlab.com\": \"ask\"\n      }\n    }\n  },\n  \"version\": 2\n}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fc := &fakeCourier{reads: map[int]*courier.Response{}}
			h := newHarness(t, 1, withPolicy(fc))
			old := ""
			fc.reads[100] = &courier.Response{Root: foo, Namespace: "frisket-policy:~/Projects/foo"}
			if c.current != nil {
				old = *c.current
				fc.reads[100] = h.file(foo, old, true)
			}
			done := h.login(claude(100), h.github, false)
			a := h.next()
			if !a.q.Always || !a.q.Grantable || a.q.Diff == nil {
				t.Fatalf("asked %+v", a.q)
			}
			if a.q.Diff.Path != "~/Projects/foo/chase.json" || a.q.Diff.Old != old || a.q.Diff.New != c.want {
				t.Errorf("diff %+v", a.q.Diff)
			}
			if a.q.AlwaysText != "Always allows github.com from ~/Projects/foo, signed into its chase.json." {
				t.Errorf("always text %q", a.q.AlwaysText)
			}
			a.reply <- alwaysAnswer()
			if err := wait(t, done); err != nil {
				t.Fatal(err)
			}
			if len(fc.writes) != 1 {
				t.Fatalf("writes %+v", fc.writes)
			}
			w := fc.writes[0]
			if w.Root != foo || w.OldDigest != projpolicy.Digest(fc.reads[100].Bytes) || string(w.Bytes) != c.want {
				t.Errorf("wrote %+v", w)
			}
			signers, _ := projpolicy.ReadAllowedSigners(h.s.Policy.AllowedSigners)
			if _, err := projpolicy.Verify(w.Bytes, w.Sig, "frisket-policy:~/Projects/foo", signers, "dan", time.Now()); err != nil {
				t.Errorf("the signature: %v", err)
			}
			if !strings.Contains(h.log.String(), `"source":"always"`) || !strings.Contains(h.log.String(), `"outcome":"written"`) {
				t.Errorf("logged %s", h.log)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestAlwaysIsNotOfferedOverAFileItMayNotWrite(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}}
	h := newHarness(t, 1, withPolicy(fc))
	notCanonical := h.file(foo, `{"version": 2}`, true)
	for name, r := range map[string]*courier.Response{
		"not canonical": notCanonical,
		"unsigned":      h.file(foo, project(`{}`), false),
		"no root":       {},
	} {
		fc.reads[100] = r
		done := h.login(claude(100), h.github, false)
		a := h.next()
		if a.q.Always || a.q.Diff != nil {
			t.Errorf("%s: asked %+v", name, a.q)
		}
		a.reply <- answered{}
		wait(t, done)
	}

	// Nor with no key the allowed signers let sign there.
	h = newHarness(t, 1, func(s *Server) {
		withPolicy(fc)(s)
		os.WriteFile(s.Policy.AllowedSigners, nil, 0o644)
	})
	fc.reads[100] = &courier.Response{Root: foo}
	done := h.login(claude(100), h.github, false)
	a := h.next()
	if a.q.Always {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}

func TestAlwaysWhoseWriteConflictsStillSignsOnceAndSaysSo(t *testing.T) {
	fc := &fakeCourier{reads: map[int]*courier.Response{}, conflict: true}
	h := newHarness(t, 1, withPolicy(fc))
	fc.reads[100] = &courier.Response{Root: foo}
	done := h.login(claude(100), h.github, false)
	h.next().reply <- alwaysAnswer()
	if err := wait(t, done); err != nil {
		t.Fatalf("the sign asked for: %v", err)
	}
	if !strings.Contains(h.log.String(), `"outcome":"not saved"`) || !strings.Contains(h.log.String(), "changed since it was read") {
		t.Errorf("logged %s", h.log)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fc.mu.Lock()
		n := len(fc.notes)
		fc.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(fc.notes) != 1 || !strings.Contains(fc.notes[0], "allowed once") {
		t.Errorf("notes %q", fc.notes)
	}
	// Nothing was granted: the next is asked.
	done = h.login(claude(100), h.github, false)
	h.next().reply <- answered{}
	wait(t, done)
}

func policySign(t *testing.T, c *client, req PolicySignRequest) PolicySignResponse {
	t.Helper()
	b, _ := json.Marshal(req)
	out, err := c.Extension(PolicySignExtension, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[0] != agentSuccess {
		t.Fatalf("reply %q", out)
	}
	var r PolicySignResponse
	if err := json.Unmarshal(out[1:], &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func policySignAsync(t *testing.T, c *client, req PolicySignRequest) <-chan PolicySignResponse {
	done := make(chan PolicySignResponse, 1)
	go func() { done <- policySign(t, c, req) }()
	return done
}

func TestPolicySignShowsTheDiffAndSignsOnAllow(t *testing.T) {
	fc := &fakeCourier{}
	h := newHarness(t, 1, withPolicy(fc))
	old := project(`{"a.example": "allow"}`)
	ns := "frisket-policy:~/Projects/foo"
	oldSig, _ := signPolicy(h.s.Keys[0], ns, []byte(old))
	widened := project(`{"*.example": "allow"}`)

	for _, c := range []struct {
		name    string
		req     PolicySignRequest
		showOld string
		says    string
	}{
		{"a verified old", PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(widened), Old: []byte(old), OldSig: oldSig}, old, ""},
		{"unsigned", PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(widened)}, "", "The old file was unsigned"},
		{"an old that is not what was signed", PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(widened), Old: []byte(widened), OldSig: oldSig}, "", "The old signature does not verify"},
	} {
		done := policySignAsync(t, h.dial(tab()), c.req)
		a := h.next()
		if a.q.Always || a.q.Grantable || a.q.Diff == nil || a.q.Diff.Path != "~/Projects/foo/chase.json" ||
			a.q.Diff.Old != c.showOld || a.q.Diff.New != widened || a.q.Title != "sign ~/Projects/foo/chase.json" {
			t.Errorf("%s: asked %+v", c.name, a.q)
		}
		if c.says != "" && !strings.Contains(a.q.Text, c.says) {
			t.Errorf("%s: text %q", c.name, a.q.Text)
		}
		a.reply <- answered{a: galleyask.Answer{Allowed: true}}
		r := <-done
		signers, _ := projpolicy.ReadAllowedSigners(h.s.Policy.AllowedSigners)
		if _, err := projpolicy.Verify([]byte(widened), r.Sig, ns, signers, "dan", time.Now()); err != nil || r.Error != "" {
			t.Errorf("%s: %+v: %v", c.name, r, err)
		}
	}

	done := policySignAsync(t, h.dial(tab()), PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(widened)})
	h.next().reply <- answered{}
	if r := <-done; r.Sig != nil || r.Error != "refused" {
		t.Errorf("refused: %+v", r)
	}
}

func TestPolicySignRefusesWhatItMayNotSign(t *testing.T) {
	fc := &fakeCourier{}
	sandboxed := false
	h := newHarness(t, 1, func(s *Server) {
		withPolicy(fc)(s)
		s.inHost = func(*net.UnixConn) error {
			if sandboxed {
				return errors.New("pid 7 is in another user namespace and may not use this socket")
			}
			return nil
		}
	})
	good := PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(project(`{}`))}
	for name, req := range map[string]PolicySignRequest{
		"not canonical":   {Root: foo, Name: "chase.json", New: []byte(`{"version":2}`)},
		"another name":    {Root: foo, Name: "other.json", New: good.New},
		"a relative root": {Root: "Projects/foo", Name: "chase.json", New: good.New},
	} {
		if r := policySign(t, h.dial(tab()), req); r.Error == "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	h.frisket.Store(true)
	if r := policySign(t, h.dial(claude(100)), good); !strings.Contains(r.Error, "frisket's main process") {
		t.Errorf("frisket: %+v", r)
	}
	h.frisket.Store(false)
	sandboxed = true
	if r := policySign(t, h.dial(tab()), good); !strings.Contains(r.Error, "another user namespace") {
		t.Errorf("sandboxed: %+v", r)
	}
	h.nothingAsked()

	// With no policy configured, nothing is signed.
	h = newHarness(t, 1, nil)
	if r := policySign(t, h.dial(tab()), good); r.Error == "" {
		t.Errorf("no policy: %+v", r)
	}
}

// frisket's main process sends a rule a person answered Always in its own
// question as approved, and it is signed unasked; nobody else's approved
// is taken, and frisket's main process sends nothing else.
func TestPolicySignSignsFrisketsApprovedUnasked(t *testing.T) {
	fc := &fakeCourier{}
	h := newHarness(t, 1, withPolicy(fc))
	ns := "frisket-policy:~/Projects/foo"
	approved := PolicySignRequest{Root: foo, Name: "chase.json", New: []byte(project(`{"a.example": "allow"}`)), Approved: true}
	signers, _ := projpolicy.ReadAllowedSigners(h.s.Policy.AllowedSigners)

	h.frisket.Store(true)
	r := policySign(t, h.dial(claude(100)), approved)
	if _, err := projpolicy.Verify(approved.New, r.Sig, ns, signers, "dan", time.Now()); err != nil || r.Error != "" {
		t.Errorf("approved: %+v: %v", r, err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"always"`) {
		t.Errorf("log: %s", h.log.String())
	}
	// Its canonical form and namespace are held to as anyone's are.
	bad := approved
	bad.New = []byte(`{"version":2}`)
	if r := policySign(t, h.dial(claude(100)), bad); r.Error == "" {
		t.Errorf("not canonical: %+v", r)
	}

	h.frisket.Store(false)
	for _, who := range []*peer.Requester{tab(), claude(100)} {
		if r := policySign(t, h.dial(who), approved); r.Sig != nil || !strings.Contains(r.Error, "only frisket's main process") {
			t.Errorf("approved from another: %+v", r)
		}
	}
	h.nothingAsked()
}

// A policy's git signing socket, the only one a sandbox is given, refuses
// policy-sign as it does every extension.
func TestTheGitSigningSocketRefusesPolicySign(t *testing.T) {
	g := &Git{Policy: "strict", UID: uid, Upstream: "/nonexistent", Log: slog.New(slog.DiscardHandler)}
	c := &gitConn{g: g}
	if _, err := c.Extension(PolicySignExtension, nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("got %v", err)
	}
}
