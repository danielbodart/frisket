package sudogate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"github.com/danielbodart/frisket/sudo"
	"golang.org/x/crypto/ssh"
)

// run is a sudo of argv, the program in bin, run as root by bash under
// the claude with pid 100.
func run(argv ...string) sudoCmd {
	return sudoCmd{links: claude(100), program: bin + argv[0], argv: argv, info: []string{"runas_user=root"}}
}

func withRules(t *testing.T, exec map[string]sudo.Rule) *harness {
	t.Helper()
	h := newHarness(t)
	h.g.Exec = exec
	if err := h.g.init(); err != nil {
		t.Fatal(err)
	}
	return h
}

// decisions are the gate's decision records so far.
func (h *harness) decisions() []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(h.log.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "decision" && m["outcome"] != nil {
			out = append(out, m)
		}
	}
	return out
}

func (h *harness) last() map[string]any {
	h.t.Helper()
	d := h.decisions()
	if len(d) == 0 {
		h.t.Fatal("no decision")
	}
	return d[len(d)-1]
}

func TestAnAllowRuleRunsTheCommandWithNoQuestionAndNoPassword(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "journalctl **": {RunAs: "root", Answer: sudo.Allow}})
	c := h.sudo(500)
	c.send(approval(run("journalctl", "-u", "foo")))
	c.want(replyYes, "")
	h.none()
	d := h.last()
	if d["outcome"] != "allow" || d["source"] != "host rule" || d["rule"] != bin+"journalctl **" || d["answer"] != "allow" {
		t.Errorf("%v", d)
	}
}

func TestARefuseRuleRefusesWithTheRule(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "reboot **": {Answer: sudo.Refuse}})
	c := h.sudo(500)
	c.send(approval(run("reboot")))
	c.want(replyNo, "refused by the host rule "+bin+"reboot **")
	h.none()
	if d := h.last(); d["outcome"] != "refuse" || d["source"] != "host rule" {
		t.Errorf("%v", d)
	}
}

func TestAnAskRuleIsAQuestionWithNoPassword(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "systemctl restart *": {Answer: sudo.Ask}})
	for _, tc := range []struct {
		answer answered
		kind   byte
		msg    string
	}{{allow(900), replyYes, ""}, {answered{}, replyNo, "refused"}} {
		c := h.sudo(500)
		c.send(approval(run("systemctl", "restart", "foo")))
		a := h.next()
		if a.q.Password || a.q.Grantable || a.q.Level != "normal" ||
			!strings.HasPrefix(a.q.Text, "asked, with no password, by the host rule "+bin+"systemctl restart *\n\n"+bin+"systemctl restart foo") {
			t.Fatalf("%+v", a.q)
		}
		a.reply <- tc.answer
		c.want(tc.kind, tc.msg)
		d := h.last()
		if d["source"] != "galley" || d["rule_source"] != "host rule" || d["rule"] != bin+"systemctl restart *" {
			t.Errorf("%v", d)
		}
	}
	if len(h.g.windows) != 0 {
		t.Errorf("an ask rule opened a window: %v", h.g.windows)
	}
}

// An ask rule is the rule's question even inside a window: no pin, and a
// new window does not turn it into the window's question.
func TestAnAskRuleIsItsOwnQuestionInsideAWindow(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "id **": {Answer: sudo.Ask}})
	h.openWindow(100, 900)
	c := h.sudo(500)
	c.send(approval(run("id", "-u")))
	a := h.next()
	if a.q.Password || !strings.HasPrefix(a.q.Text, "asked, with no password") {
		t.Fatalf("%+v", a.q)
	}
	a.reply <- allow(901)
	c.want(replyYes, "")
}

func TestNoRuleMatchingIsTheDialogAsBefore(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "journalctl **": {Answer: sudo.Allow}})
	c := h.sudo(500)
	c.send(approval(run("systemctl", "restart", "foo")))
	if a := h.next(); !a.q.Password || !a.q.Grantable {
		t.Errorf("%+v", a.q)
	}
}

// Danger, warnings and what the gate cannot see whole are never a rule's,
// whatever the rule says: each is asked as it is with no rules.
func TestARuleNeverDecidesDangerAWarningOrWhatItCannotRead(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{
		bin + "systemctl **":        {Answer: sudo.Allow},
		bin + "sh **":               {Answer: sudo.Allow},
		bin + "bash **":             {Answer: sudo.Allow},
		bin + "env **":              {Answer: sudo.Allow},
		bin + "id **":               {Answer: sudo.Allow},
		"/home/dan/bin/x **":        {Answer: sudo.Allow},
		bin + "lpq **":              {Answer: sudo.Allow},
		"/run/wrappers/bin/ping **": {Answer: sudo.Refuse},
	})
	envFoo := run("id", "-u")
	envFoo.envp = []string{"FOO=bar"}
	truncated := run("id", "-u")
	truncated.truncated = true
	cutRun := run("id", "-u")
	cutRun.links = cut
	lp := run("lpq")
	lp.info = []string{"runas_user=lp"}
	shell := run("bash")
	shell.settings = []string{"run_shell=true"}
	for name, tc := range map[string]struct {
		cmd   sudoCmd
		level string
	}{
		"a guard unit":          {run("systemctl", "stop", "sshd.service"), "danger"},
		"a guard unit's status": {run("systemctl", "status", "frisket.service"), "danger"},
		"outside the dirs":      {sudoCmd{links: claude(100), program: "/home/dan/bin/x", argv: []string{"x"}, info: []string{"runas_user=root"}}, "danger"},
		"unreadable sh -c":      {run("sh", "-c", `"$(printf x)"`), "danger"},
		"a readable sh -c":      {run("sh", "-c", "id -u"), "normal"},
		"sudo -s":               {shell, "danger"},
		"env":                   {run("env", "id"), "normal"},
		"a cut chain":           {cutRun, "warning"},
		"a variable":            {envFoo, "normal"},
		"truncated":             {truncated, "normal"},
		"another runAs":         {lp, "normal"},
	} {
		c := h.sudo(500)
		c.send(approval(tc.cmd))
		a := h.next()
		if !a.q.Password || a.q.Level != tc.level || strings.Contains(a.q.Text, "asked, with no password") {
			t.Errorf("%s: %+v", name, a.q)
		}
		a.reply <- answered{}
		c.want(replyNo, "cancelled")
	}
	// Danger outranks a refusal too: it is asked, never refused unasked.
	c := h.sudo(500)
	c.send(approval(sudoCmd{links: claude(100), program: "/run/wrappers/bin/ping", argv: []string{"ping", "x"}, info: []string{"runas_user=root"},
		envp: []string{"LD_PRELOAD=/tmp/x"}}))
	if a := h.next(); !a.q.Password {
		t.Errorf("%+v", a.q)
	} else {
		a.reply <- answered{}
		c.want(replyNo, "cancelled")
	}
}

func TestRemoteModeIsNoRulesBusiness(t *testing.T) {
	h := withRules(t, map[string]sudo.Rule{bin + "id **": {Answer: sudo.Refuse}})
	cmd := run("id", "-u")
	cmd.remote = true
	c := h.dial(peer.Proc{UID: 0, Pid: 500, Start: 5000, PPid: 200})
	c.send(append(frame(kindCheckIn), nil...))
	c.read()
	c.send(approval(cmd))
	if k, m := c.read(); k == replyNo && strings.Contains(m, "rule") {
		t.Errorf("a remote sudo was decided by a rule: %q", m)
	}
	for _, d := range h.decisions() {
		if d["source"] == "host rule" {
			t.Errorf("%v", d)
		}
	}
}

// A project's signed chase.json, as the courier would return it.
type fakeProject struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	signers []byte
	resp    *courier.Response
	err     error
	reads   []proc
}

const home = "/home/dan"

func newProject(t *testing.T) *fakeProject {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := `dan namespaces="frisket-policy:*" ` + string(ssh.MarshalAuthorizedKey(k))
	return &fakeProject{key: priv, signers: []byte(line)}
}

// file sets the project's file at root to doc, signed in namespace (root's
// own when ""), or unsigned.
func (p *fakeProject) file(t *testing.T, root string, doc any, signed bool, namespace string) {
	t.Helper()
	b, err := projpolicy.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	resp := &courier.Response{Root: root, Bytes: b, Digest: projpolicy.Digest(b)}
	if signed {
		if namespace == "" {
			namespace, _ = projpolicy.Namespace(root, home)
		}
		s, err := ssh.NewSignerFromKey(p.key)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Sig, err = projpolicy.Sign(rand.Reader, s, namespace, b); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	p.resp = resp
	p.mu.Unlock()
}

func withProject(t *testing.T, exec map[string]sudo.Rule) (*harness, *fakeProject) {
	t.Helper()
	h := newHarness(t)
	p := newProject(t)
	h.g.Exec = exec
	h.g.Policy = &Policy{Courier: "/nonexistent", AllowedSigners: "/nonexistent", FileName: "chase.json", Home: home, UID: 1000}
	h.g.read = func(_ context.Context, pid int, start uint64) (*courier.Response, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.reads = append(p.reads, proc{pid, start})
		if p.err != nil {
			return nil, p.err
		}
		if p.resp == nil {
			return &courier.Response{}, nil
		}
		return p.resp, nil
	}
	h.g.signers = func() ([]byte, error) { return p.signers, nil }
	if err := h.g.init(); err != nil {
		t.Fatal(err)
	}
	return h, p
}

func sudoSection(exec map[string]any) map[string]any {
	return map[string]any{"version": 2, "sudo": map[string]any{"exec": exec}}
}

func rule(answer string) map[string]any { return map[string]any{"runAs": "root", "answer": answer} }

// sudoOf runs cmd as a sudo and returns what the plugin was told, or
// "asked" with the question answered Refuse.
func (h *harness) sudoOf(cmd sudoCmd) string {
	h.t.Helper()
	c := h.sudo(500)
	c.send(approval(cmd))
	got := make(chan string, 1)
	go func() {
		k, m := c.read()
		got <- string(k) + " " + m
	}()
	select {
	case a := <-h.questions:
		a.reply <- answered{}
		<-got
		if a.q.Password {
			return "dialog"
		}
		return "asked"
	case r := <-got:
		return r
	}
}

func TestAProjectRuleOverridesTheHostsAndANarrowerOneBeatsAWider(t *testing.T) {
	h, p := withProject(t, map[string]sudo.Rule{
		bin + "journalctl **": {Answer: sudo.Allow},
		bin + "systemctl **":  {Answer: sudo.Ask},
		bin + "dmesg **":      {Answer: sudo.Allow},
	})
	p.file(t, home+"/proj", sudoSection(map[string]any{
		bin + "journalctl **":       rule("refuse"),
		bin + "systemctl status **": rule("allow"),
		bin + "dmesg **":            nil,
		bin + "uptime":              map[string]any{"answer": "allow"},
	}), true, "")
	for _, tc := range []struct {
		cmd    sudoCmd
		want   string
		source string
	}{
		{run("journalctl", "-u", "x"), "N refused by the project rule " + bin + "journalctl **", "project rule"},
		{run("systemctl", "status", "x"), "Y ", "project rule"},
		{run("systemctl", "restart", "x"), "asked", "host rule"},
		{run("dmesg"), "dialog", ""},
		{run("uptime"), "Y ", "project rule"},
	} {
		if got := h.sudoOf(tc.cmd); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.cmd.argv, got, tc.want)
			continue
		}
		d := h.last()
		src := d["source"]
		if src == "galley" {
			src = d["rule_source"]
		}
		if tc.source != "" && src != tc.source {
			t.Errorf("%v: source %v", tc.cmd.argv, d)
		}
		if tc.source == "project rule" && d["root"] != home+"/proj" {
			t.Errorf("%v: root %v", tc.cmd.argv, d)
		}
	}
	// The courier was asked about the process that ran sudo: bash, 101.
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) == 0 || p.reads[0] != (proc{101, 300}) {
		t.Errorf("reads %v", p.reads)
	}
}

func TestAProjectAllowNeverDecidesDanger(t *testing.T) {
	h, p := withProject(t, nil)
	p.file(t, home+"/proj", sudoSection(map[string]any{bin + "systemctl **": rule("allow")}), true, "")
	if got := h.sudoOf(run("systemctl", "stop", "galley.service")); got != "dialog" {
		t.Errorf("got %q", got)
	}
	if got := h.sudoOf(run("systemctl", "stop", "foo.service")); got != "Y " {
		t.Errorf("got %q", got)
	}
}

func TestAFileThatDoesNotVerifyIsIgnoredWithOneLine(t *testing.T) {
	host := map[string]sudo.Rule{bin + "journalctl **": {Answer: sudo.Allow}}
	section := sudoSection(map[string]any{bin + "journalctl **": rule("refuse"), bin + "uptime": rule("allow")})
	for name, set := range map[string]func(*testing.T, *fakeProject){
		"unsigned":          func(t *testing.T, p *fakeProject) { p.file(t, home+"/proj", section, false, "") },
		"another namespace": func(t *testing.T, p *fakeProject) { p.file(t, home+"/proj", section, true, "frisket-policy:~/other") },
		"another signer": func(t *testing.T, p *fakeProject) {
			p.file(t, home+"/proj", section, true, "")
			p.signers = []byte(nil)
		},
		"a host-only key": func(t *testing.T, p *fakeProject) {
			p.file(t, home+"/proj", map[string]any{"sudo": map[string]any{"exec": section["sudo"].(map[string]any)["exec"], "danger": map[string]any{}}}, true, "")
		},
		"a rule that is not one": func(t *testing.T, p *fakeProject) {
			p.file(t, home+"/proj", sudoSection(map[string]any{"journalctl **": rule("allow")}), true, "")
		},
		"a field in another case": func(t *testing.T, p *fakeProject) {
			p.file(t, home+"/proj", sudoSection(map[string]any{bin + "uptime": map[string]any{"runas": "root", "answer": "allow"}}), true, "")
		},
		"a misspelt field": func(t *testing.T, p *fakeProject) {
			p.file(t, home+"/proj", sudoSection(map[string]any{bin + "uptime": map[string]any{"answr": "allow"}}), true, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, p := withProject(t, host)
			set(t, p)
			for range 2 {
				if got := h.sudoOf(run("journalctl", "-u", "x")); got != "Y " {
					t.Errorf("got %q", got)
				}
				if d := h.last(); d["source"] != "host rule" {
					t.Errorf("%v", d)
				}
			}
			if got := h.sudoOf(run("uptime")); got != "dialog" {
				t.Errorf("uptime: %q", got)
			}
			if n := strings.Count(h.log.String(), `"msg":"project policy ignored"`); n != 1 {
				t.Errorf("%d ignored lines:\n%s", n, h.log.String())
			}
		})
	}
}

func TestNoProjectOrNoCourierIsTheHostsRules(t *testing.T) {
	h, p := withProject(t, map[string]sudo.Rule{bin + "journalctl **": {Answer: sudo.Allow}})
	if got := h.sudoOf(run("journalctl")); got != "Y " {
		t.Errorf("no project: %q", got)
	}
	p.mu.Lock()
	p.err = errors.New("courier down")
	p.mu.Unlock()
	if got := h.sudoOf(run("journalctl")); got != "Y " {
		t.Errorf("courier down: %q", got)
	}
	if !strings.Contains(h.log.String(), `"msg":"project policy unread"`) {
		t.Errorf("no unread line:\n%s", h.log.String())
	}
	// A project with no sudo section leaves the host's rules as they are.
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
	p.file(t, home+"/proj", map[string]any{"version": 2}, true, "")
	if got := h.sudoOf(run("journalctl")); got != "Y " {
		t.Errorf("no section: %q", got)
	}
	if strings.Contains(h.log.String(), `"msg":"project policy ignored"`) {
		t.Errorf("a file with no sudo section was ignored:\n%s", h.log.String())
	}
}

// The courier is asked about the user's process nearest sudo: past a
// runuser of root's that ran it, and about nobody when there is none.
func TestTheProjectIsTheUsersProcessNearestSudo(t *testing.T) {
	h, p := withProject(t, nil)
	p.file(t, home+"/proj", sudoSection(map[string]any{bin + "uptime": rule("allow")}), true, "")
	runuser := run("uptime")
	runuser.links = append([]peer.Link{{Pid: 150, PPid: 101, Start: 400, UID: 0, Comm: "runuser", Cmdline: []string{"runuser"}}}, claude(100)...)
	if got := h.sudoOf(runuser); got != "Y " {
		t.Errorf("under runuser: %q", got)
	}
	rootOnly := run("uptime")
	rootOnly.links = []peer.Link{
		{Pid: 150, PPid: 1, Start: 400, UID: 0, Comm: "runuser", Cmdline: []string{"runuser"}},
		{Pid: 1, Start: 1, Comm: "systemd", Cmdline: []string{"/sbin/init"}},
	}
	if got := h.sudoOf(rootOnly); got != "dialog" {
		t.Errorf("no process of the user's: %q", got)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) != 1 || p.reads[0] != (proc{101, 300}) {
		t.Errorf("reads %v", p.reads)
	}
}
