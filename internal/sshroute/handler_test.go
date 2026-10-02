package sshroute

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/policy"
)

func shrink(t *testing.T, v *time.Duration, d time.Duration) {
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

func only(t *testing.T, lines []map[string]any) map[string]any {
	t.Helper()
	if len(lines) != 1 {
		t.Fatalf("%d ssh lines, want 1: %v", len(lines), lines)
	}
	return lines[0]
}

func TestTheHandlerSteersItsRoutesAddressesAtTheirPortsAlone(t *testing.T) {
	f := newFixture(t, options{})
	for _, tc := range []struct {
		orig string
		want bool
	}{
		{"10.0.0.5:22", true},
		{"[::ffff:10.0.0.5]:22", true},
		{"10.0.0.5:2222", false},
		{"10.0.0.6:22", false},
		{"127.0.0.1:22", false},
	} {
		if got := f.h.Steers(netip.MustParseAddrPort(tc.orig)); got != tc.want {
			t.Errorf("Steers(%s) = %v, want %v", tc.orig, got, tc.want)
		}
	}
}

func TestAnAllowedCommandRunsAndReturnsItsOutputAndStatus(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	r := run(t, c, "echo hello  world", nil)
	if r.err != nil || r.stdout != "hello world\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	r = run(t, c, "fail 3", nil)
	if r.err != nil || r.stderr != "failing\n" || r.status != 3 {
		t.Errorf("got %+v", r)
	}
	if got := f.sshd.commands(); len(got) != 2 || got[0] != "echo hello  world" {
		t.Errorf("upstream ran %q: the command goes as it was sent", got)
	}
	if f.sshd.dials() != 1 {
		t.Errorf("%d logins for one connection, want one shared", f.sshd.dials())
	}
	waitFor(t, "two lines", func() bool { return len(f.sshLines()) == 2 })
	l := f.sshLines()[0]
	for k, want := range map[string]any{
		"session": "s1", "dst": "10.0.0.5:22", "route": "server", "user": "dan", "client_user": "agent",
		"command": "echo hello  world", "decision": "allowed", "rule": "echo **", "exit_status": float64(0),
		"stdout_bytes": float64(12), "stderr_bytes": float64(0), "stdin_bytes": float64(0),
	} {
		if l[k] != want {
			t.Errorf("%s = %v, want %v", k, l[k], want)
		}
	}
	if _, ok := l["duration_ms"]; !ok {
		t.Error("no duration_ms")
	}
}

func TestARefusedCommandNeverReachesTheMachineAndSaysWhy(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	r := run(t, c, "echo secret token", nil)
	if r.err != nil || r.status != exitRefused || !strings.Contains(r.stderr, "frisket: server: refused by rule") || r.stdout != "" {
		t.Errorf("got %+v", r)
	}
	if got := f.sshd.commands(); len(got) != 0 {
		t.Errorf("upstream ran %q", got)
	}
	if f.sshd.dials() != 0 {
		t.Error("frisket logged in upstream for a command it refused")
	}
	l := only(t, f.sshLines())
	if l["decision"] != "refused" || l["rule"] != "echo secret **" || l["reason"] != intercept.ReasonRefused || l["level"] != "WARN" {
		t.Errorf("line %v", l)
	}
}

func TestUnderUnmatchedRefuseACommandNoRuleNamesIsRefused(t *testing.T) {
	f := newFixture(t, options{route: func(r *policy.SSHRoute) { r.Unmatched = "refuse" }})
	r := run(t, f.connect(), "reboot", nil)
	if r.status != exitRefused || !strings.Contains(r.stderr, intercept.ReasonOutOfScope) {
		t.Errorf("got %+v", r)
	}
	if l := only(t, f.sshLines()); l["rule"] != "unmatched" || l["reason"] != intercept.ReasonOutOfScope {
		t.Errorf("line %v", l)
	}
}

// A command a shell would read as more than its words is never admitted by
// a rule, even one that admits everything: it is asked about, with the
// command exactly as it would run.
func TestAnUnreadableCommandIsAskedAboutEvenUnderARuleForEverything(t *testing.T) {
	a := &answers{}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{{Command: "**"}}
	}})
	shrink(t, &previewIdle, 20*time.Millisecond)
	r := run(t, f.connect(), "echo a; echo $(id)", nil)
	if r.status != exitRefused || !strings.Contains(r.stderr, intercept.ReasonDeclined) {
		t.Errorf("got %+v", r)
	}
	q := a.questions()
	if len(q) != 1 || q[0].Command != "echo a; echo $(id)" || q[0].Kind != "ssh" {
		t.Errorf("questions %+v", q)
	}
	if len(f.sshd.commands()) != 0 {
		t.Error("ran a command nobody admitted")
	}
	if l := only(t, f.sshLines()); l["rule"] != "unmatched" || l["asked"] != true || l["reason"] != intercept.ReasonDeclined {
		t.Errorf("line %v", l)
	}
}

// A command of several simple commands is asked about with the operation
// that decided it and every one its parts were decided by, from the
// route's own rules, and logged with their ids.
func TestACompoundCommandIsAskedAboutWithEveryOperationItHolds(t *testing.T) {
	a := &answers{}
	look := &policy.Operation{ID: "list", Summary: "List a directory", Class: "read", Category: "navigate"}
	restart := &policy.Operation{ID: "restart", Summary: "Restart a service", Class: "write", Category: "services"}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{
			{Command: "ls **", Operation: look},
			{Command: "systemctl restart *", Ask: true, Operation: restart},
		}
	}})
	shrink(t, &previewIdle, 20*time.Millisecond)
	r := run(t, f.connect(), "ls /etc && systemctl restart nginx", nil)
	if r.status != exitRefused || !strings.Contains(r.stderr, intercept.ReasonDeclined) {
		t.Errorf("got %+v", r)
	}
	q := a.questions()
	if len(q) != 1 || q[0].Operation == nil || q[0].Operation.ID != "restart" || q[0].Operation.Class != "write" ||
		len(q[0].Operations) != 2 || q[0].Operations[0].ID != "list" || q[0].Operations[1].ID != "restart" {
		t.Fatalf("questions %+v", q)
	}
	if l := only(t, f.sshLines()); l["rule"] != "systemctl restart *" || l["operation"] != "list,restart" || l["asked"] != true {
		t.Errorf("line %v", l)
	}
}

// An argument naming a secret refuses a command a rule admits, before
// anything reaches the machine, and the line says which rule.
func TestAnArgRuleRefusesACommandItsCommandRuleAdmits(t *testing.T) {
	f := newFixture(t, options{route: func(r *policy.SSHRoute) {
		r.Exec = append(r.Exec, policy.ExecRule{Arg: ".ssh", Refuse: true,
			Operation: &policy.Operation{ID: "secrets", Summary: "Read a secret", Class: "guarded"}})
	}})
	r := run(t, f.connect(), "echo /home/dan/.ssh/id_ed25519", nil)
	if r.status != exitRefused || !strings.Contains(r.stderr, "refused by rule") {
		t.Errorf("got %+v", r)
	}
	if len(f.sshd.commands()) != 0 {
		t.Error("ran a refused command")
	}
	if l := only(t, f.sshLines()); l["rule"] != "[arg .ssh]" || l["operation"] != "secrets" || l["decision"] != "refused" {
		t.Errorf("line %v", l)
	}
}

func TestACommandThatIsNotUTF8IsRefusedSinceNobodyCouldBeShownIt(t *testing.T) {
	a := &answers{yes: true}
	f := newFixture(t, options{asker: a})
	r := run(t, f.connect(), "echo \xff", nil)
	if r.status != exitRefused || !strings.Contains(r.stderr, ReasonNotUTF8) || len(a.questions()) != 0 {
		t.Errorf("got %+v", r)
	}
	if l := only(t, f.sshLines()); l["command"] != `echo \xff` {
		t.Errorf("command logged as %q", l["command"])
	}
}

func TestAnAskedCommandRunsWhenAdmittedWithItsWholeStdinAfterThePreview(t *testing.T) {
	a := &answers{yes: true}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{{Command: "cat", Ask: true}}
	}})
	stdin := bytes.Repeat([]byte("0123456789abcdef"), 1<<14) // 256 KiB
	r := runEager(t, f.connect(), "cat", stdin)
	if r.err != nil || r.status != 0 || r.stdout != string(stdin) {
		t.Errorf("status %d, %d bytes back of %d, err %v", r.status, len(r.stdout), len(stdin), r.err)
	}
	q := a.questions()
	if len(q) != 1 {
		t.Fatalf("questions %+v", q)
	}
	want := intercept.Question{
		Session: "s1", Policy: "p", Route: "server", Host: "server",
		Body: string(stdin[:intercept.BodyPreview]), BodyMore: true,
		Kind: "ssh", Address: "10.0.0.5:22", User: "dan", Command: "cat",
	}
	if q[0].Session != want.Session || q[0].Policy != want.Policy || q[0].Route != want.Route || q[0].Host != want.Host ||
		q[0].Body != want.Body || q[0].BodyMore != want.BodyMore || q[0].Kind != want.Kind ||
		q[0].Address != want.Address || q[0].User != want.User || q[0].Command != want.Command || q[0].Method != "" || q[0].Path != "" {
		t.Errorf("question %+v", q[0])
	}
	l := only(t, f.sshLines())
	if l["decision"] != "allowed" || l["asked"] != true || l["stdin_bytes"] != float64(len(stdin)) || l["stdout_bytes"] != float64(len(stdin)) {
		t.Errorf("line %v", l)
	}
}

func TestAShortStdinThatEndsIsPreviewedWhole(t *testing.T) {
	a := &answers{yes: true}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{{Command: "cat", Ask: true}}
	}})
	r := runEager(t, f.connect(), "cat", []byte("deb http://x stable main\n"))
	if r.stdout != "deb http://x stable main\n" {
		t.Errorf("got %+v", r)
	}
	if q := a.questions(); len(q) != 1 || q[0].Body != "deb http://x stable main\n" || q[0].BodyMore {
		t.Errorf("questions %+v", q)
	}
}

// ssh without -n holds stdin open and sends nothing: the question goes after
// the idle bound with an empty preview, rather than waiting for ever.
func TestAnAskedCommandWithStdinHeldOpenAndSilentIsStillAsked(t *testing.T) {
	a := &answers{yes: true}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{{Command: "sudo **", Ask: true}}
	}})
	shrink(t, &previewIdle, 50*time.Millisecond)
	s, err := f.connect().NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out bytes.Buffer
	s.Stdout = &out
	done := make(chan error, 1)
	go func() { done <- s.Run("sudo echo hi") }()
	select {
	case err := <-done:
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 127 {
			t.Errorf("got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command hung waiting for stdin that never came")
	}
	if q := a.questions(); len(q) != 1 || q[0].Body != "" || !q[0].BodyMore {
		t.Errorf("questions %+v", q)
	}
	if got := f.sshd.commands(); len(got) != 1 || got[0] != "sudo echo hi" {
		t.Errorf("upstream ran %q", got)
	}
}

func TestADeclinedOrUnaskableCommandIsRefusedWithTheReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		asker  intercept.Asker
		reason string
	}{
		{"declined", &answers{}, intercept.ReasonDeclined},
		{"nobody to ask", nil, intercept.ReasonNobodyToAsk},
		{"busy", &answers{err: intercept.ErrBusy}, intercept.ReasonBusy},
		{"the asker failing", &answers{err: errors.New("dialog crashed")}, intercept.ReasonAskFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, options{asker: tc.asker})
			shrink(t, &previewIdle, 10*time.Millisecond)
			r := run(t, f.connect(), "sudo reboot", nil)
			if r.status != exitRefused || !strings.Contains(r.stderr, tc.reason) {
				t.Errorf("got %+v", r)
			}
			if len(f.sshd.commands()) != 0 {
				t.Error("ran it")
			}
			if l := only(t, f.sshLines()); l["reason"] != tc.reason || l["decision"] != "refused" {
				t.Errorf("line %v", l)
			}
			if tc.reason == intercept.ReasonAskFailed {
				if asks := f.j.lines(t, "ask"); len(asks) != 1 || asks[0]["error"] != "dialog crashed" {
					t.Errorf("ask lines %v", asks)
				}
			}
		})
	}
}

// A client that goes while a person is deciding takes the question with it,
// and the connection's other channels go on meanwhile: the request waiting
// on the person holds up nothing else.
func TestAQuestionEndsWithItsClientAndHoldsUpNothingMeanwhile(t *testing.T) {
	a := &answers{block: true, gone: make(chan struct{})}
	f := newFixture(t, options{asker: a})
	shrink(t, &previewIdle, 10*time.Millisecond)
	c := f.connect()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"sudo reboot"})) }()
	waitFor(t, "the question", func() bool { return len(a.questions()) == 1 })
	// More requests than a channel's queue holds, on the waiting channel:
	// were they not taken, the connection's reader would stall on them.
	env := ssh.Marshal(struct{ Name, Value string }{"A", "b"})
	for range 40 {
		if _, err := ch.SendRequest("env", false, env); err != nil {
			t.Fatal(err)
		}
	}
	if r := run(t, c, "echo still here", nil); r.stdout != "still here\n" {
		t.Errorf("another channel, meanwhile: %+v", r)
	}
	_ = ch.Close()
	select {
	case <-a.gone:
	case <-time.After(10 * time.Second):
		t.Fatal("the question outlived its channel")
	}
	waitFor(t, "the refusal's line", func() bool { return len(f.sshLines()) == 2 })
	for _, l := range f.sshLines() {
		if l["command"] == "sudo reboot" && l["reason"] != intercept.ReasonStoppedWaiting {
			t.Errorf("line %v", l)
		}
	}
}

func TestAMachinePresentingAKeyTheRouteDoesNotPinIsRefused(t *testing.T) {
	other := newSigner(t)
	f := newFixture(t, options{route: func(r *policy.SSHRoute) {
		r.HostKeys = []string{authorized(other.PublicKey())}
	}})
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, ReasonHostKey) || r.stdout != "" {
		t.Errorf("got %+v", r)
	}
	if len(f.sshd.commands()) != 0 {
		t.Error("ran a command on a machine that is not the route's")
	}
	l := only(t, f.sshLines())
	if l["decision"] != "failed" || l["reason"] != ReasonHostKey || !strings.Contains(l["error"].(string), "SHA256:") {
		t.Errorf("line %v", l)
	}
}

// A machine with an ECDSA key that nobody pinned, which x/crypto would ask
// for before ed25519, is asked for the ed25519 key the route pins.
func TestAMachineIsAskedForThePinnedKeyTypeOverOneItPrefers(t *testing.T) {
	f := newFixture(t, options{hostKeys: []ssh.Signer{newECDSASigner(t), newSigner(t)}})
	if r := run(t, f.connect(), "echo hi", nil); r.stdout != "hi\n" {
		t.Errorf("got %+v", r)
	}
}

func TestForwardingAndEveryChannelButASessionIsRefused(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	if _, err := c.Dial("tcp", "10.0.0.9:80"); err == nil {
		t.Error("direct-tcpip opened")
	}
	var oce *ssh.OpenChannelError
	if _, _, err := c.OpenChannel("auth-agent@openssh.com", nil); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Errorf("auth-agent: %v", err)
	}
	if _, err := c.Listen("tcp", "127.0.0.1:8080"); err == nil {
		t.Error("tcpip-forward accepted")
	}
	if ok, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil || ok {
		t.Errorf("keepalive: %v %v", ok, err)
	}
	if f.sshd.dials() != 0 {
		t.Error("frisket logged in upstream for a forward")
	}
	lines := f.sshLines()
	if len(lines) != 2 || lines[0]["channel_type"] != "direct-tcpip" || lines[1]["channel_type"] != "auth-agent@openssh.com" || lines[0]["reason"] != ReasonChannelType {
		t.Errorf("lines %v", lines)
	}
}

func TestAPtyAShellAndASubsystemAreRefusedAndTheCommandStillRuns(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Error("pty granted")
	}
	if err := s.Shell(); err == nil {
		t.Error("shell granted")
	}
	s.Close()
	s, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestSubsystem("sftp"); err == nil {
		t.Error("sftp granted")
	}
	s.Close()
	s, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	out, err := s.Output("echo hi")
	if err != nil || string(out) != "hi\n" {
		t.Errorf("%q %v", out, err)
	}
	f.sshd.mu.Lock()
	pty := f.sshd.pty
	f.sshd.mu.Unlock()
	if pty != 0 {
		t.Error("a pty reached the machine")
	}
}

func TestAConnectionThatRanNoCommandStillWritesALine(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Shell()
	_ = s.Close()
	_ = c.Close()
	waitFor(t, "the line", func() bool { return len(f.sshLines()) == 1 })
	l := f.sshLines()[0]
	if l["decision"] != "allowed" || l["channels"] != float64(1) || l["client_user"] != "agent" || l["route"] != "server" {
		t.Errorf("line %v", l)
	}
}

func TestTheClientsUserNameIsLoggedBoundedAndEscaped(t *testing.T) {
	f := newFixture(t, options{})
	user := "a\nb" + strings.Repeat("u", 4000)
	c := f.connectAs(user)
	run(t, c, "echo hi", nil)
	if _, _, err := c.OpenChannel("direct-tcpip", nil); err == nil {
		t.Error("a forward was opened")
	}
	_ = c.Close()
	// A connection that runs nothing writes its own line, with the name too.
	_ = f.connectAs(user).Close()
	waitFor(t, "three lines", func() bool { return len(f.sshLines()) == 3 })
	want := `a\x0ab` + strings.Repeat("u", maxLoggedUser-3) + "..."
	for _, l := range f.sshLines() {
		if l["client_user"] != want {
			t.Errorf("client_user = %q, want %q", l["client_user"], want)
		}
	}
}

func TestAFailedHandshakeWritesALine(t *testing.T) {
	f := newFixture(t, options{})
	shrink(t, &handshakeTimeout, 100*time.Millisecond)
	c, done := f.serve(context.Background())
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler held a connection that was not SSH")
	}
	if l := only(t, f.sshLines()); l["decision"] != "failed" || l["reason"] != ReasonHandshake {
		t.Errorf("line %v", l)
	}
}

func TestTheSessionEndingEndsItsConnections(t *testing.T) {
	f := newFixture(t, options{})
	ctx, cancel := context.WithCancel(context.Background())
	_, done := f.serve(ctx)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler outlived its session")
	}
}

func TestAnExitSignalComesBackAndASignalGoesThrough(t *testing.T) {
	f := newFixture(t, options{})
	s, err := f.connect().NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start("wait"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the command to run", func() bool { return len(f.sshd.commands()) == 1 })
	if err := s.Signal(ssh.SIGTERM); err != nil {
		t.Fatal(err)
	}
	var ee *ssh.ExitError
	if err := s.Wait(); !errors.As(err, &ee) || ee.Signal() != "TERM" {
		t.Errorf("got %v", err)
	}
	waitFor(t, "the line", func() bool { return len(f.sshLines()) == 1 })
	if l := f.sshLines()[0]; l["exit_signal"] != "TERM" {
		t.Errorf("line %v", l)
	}
}

// A machine that goes silent mid-command -- powered off, cut off -- never
// answers the close of the command's channel. The sandbox leaving ends the
// connection all the same, and promptly: the login upstream is closed, not
// waited on, so nothing it holds pins the connection, or the session's
// teardown behind it.
func TestASilentMachineDoesNotOutliveTheSandboxsConnection(t *testing.T) {
	f := newFixture(t, options{})
	silence := f.wedged()
	sandbox, done := f.serve(context.Background())
	conn, chans, reqs, err := ssh.NewClientConn(sandbox, "server:22", &ssh.ClientConfig{
		User:            "agent",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := ssh.NewClient(conn, chans, reqs)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("wait"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the command to run", func() bool { return len(f.sshd.commands()) == 1 })
	silence()
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still waiting on a machine that went silent")
	}
	if l := only(t, f.sshLines()); l["reason"] != nil {
		t.Errorf("the sandbox leaving was put down to the machine: %v", l)
	}
}

// A machine that goes silent while the sandbox waits on it is found out, as
// ssh's ServerAliveInterval finds it, and the command fails, saying so --
// rather than waiting for as long as the kernel retransmits.
func TestASilentMachineFailsTheCommandWaitingOnIt(t *testing.T) {
	f := newFixture(t, options{})
	shrink(t, &keepaliveInterval, 20*time.Millisecond)
	shrink(t, &keepaliveTimeout, 50*time.Millisecond)
	silence := f.wedged()
	c := f.connect()
	results := make(chan result, 1)
	go func() { results <- run(t, c, "wait", nil) }()
	waitFor(t, "the command to run", func() bool { return len(f.sshd.commands()) == 1 })
	silence()
	var r result
	select {
	case r = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("the command is still waiting on a machine that went silent")
	}
	if r.status != exitUpstream || !strings.Contains(r.stderr, "frisket: server: "+ReasonUpstream) {
		t.Errorf("got %+v", r)
	}
	if l := only(t, f.sshLines()); l["decision"] != "failed" || l["reason"] != ReasonUpstream || l["error"] == nil {
		t.Errorf("line %v", l)
	}
}

// A machine that goes mid-command -- rebooted, reset -- leaves the command
// with no exit status. That is a failure, said to whoever ran it and on the
// line, never a command that ran and simply said nothing.
func TestAMachineThatGoesMidCommandFailsItSayingSo(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	results := make(chan result, 1)
	go func() { results <- run(t, c, "wait", nil) }()
	waitFor(t, "the command to run", func() bool { return len(f.sshd.commands()) == 1 })
	f.sshd.drop()
	r := <-results
	if r.err != nil || r.status != exitUpstream || !strings.Contains(r.stderr, "frisket: server: "+ReasonUpstream) {
		t.Errorf("got %+v", r)
	}
	l := only(t, f.sshLines())
	if l["decision"] != "failed" || l["reason"] != ReasonUpstream || l["exit_status"] != float64(exitUpstream) || l["rule"] != "wait" {
		t.Errorf("line %v", l)
	}
	if e, _ := l["error"].(string); !strings.Contains(e, errNoExit.Error()) {
		t.Errorf("error %q", e)
	}
	// The next command logs in again.
	if r := run(t, c, "echo back", nil); r.status != 0 || r.stdout != "back\n" {
		t.Errorf("after the machine came back: %+v", r)
	}
}

// stdout and stderr share a window: both, a megabyte each, come back whole.
func TestStdoutAndStderrComeBackWholeAndApart(t *testing.T) {
	f := newFixture(t, options{})
	r := run(t, f.connect(), "both 1048576", nil)
	if r.err != nil || r.status != 0 || r.stdout != strings.Repeat("o", 1<<20) || r.stderr != strings.Repeat("e", 1<<20) {
		t.Errorf("status %d, %d out, %d err, %v", r.status, len(r.stdout), len(r.stderr), r.err)
	}
}

func TestAnUpstreamThatCannotBeReachedFailsTheCommand(t *testing.T) {
	f := newFixture(t, options{})
	f.h.dial = func(context.Context, netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("no route to host")
	}
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, "no route to host") {
		t.Errorf("got %+v", r)
	}
	if l := only(t, f.sshLines()); l["reason"] != ReasonUpstream {
		t.Errorf("line %v", l)
	}
}

func TestTheAgentOffersOnlyTheIdentityNamed(t *testing.T) {
	_, mine, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name     string
		identity ed25519.PrivateKey
		ok       bool
	}{
		{"the identity the agent holds", mine, true},
		{"one it does not", other, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, _ := ssh.NewSignerFromKey(tc.identity)
			f := newFixture(t, options{userKey: mine, route: func(r *policy.SSHRoute) {
				r.Identity = ssh.FingerprintSHA256(id.PublicKey())
			}})
			r := run(t, f.connect(), "echo hi", nil)
			if tc.ok && r.stdout != "hi\n" {
				t.Errorf("got %+v", r)
			}
			if !tc.ok && (r.status != exitUpstream || !strings.Contains(r.stderr, "agent holds no key")) {
				t.Errorf("got %+v", r)
			}
		})
	}
}

func TestAKeyFileLogsInAndAnEncryptedOneSaysSo(t *testing.T) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	plain, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ssh.MarshalPrivateKeyWithPassphrase(k, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plainPath, encPath := filepath.Join(dir, "id"), filepath.Join(dir, "id_enc")
	if err := os.WriteFile(plainPath, pem.EncodeToMemory(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encPath, pem.EncodeToMemory(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, options{userKey: k, route: func(r *policy.SSHRoute) { r.Agent, r.KeyFile = "", plainPath }})
	if r := run(t, f.connect(), "echo hi", nil); r.stdout != "hi\n" {
		t.Errorf("plain: %+v", r)
	}

	f = newFixture(t, options{userKey: k, route: func(r *policy.SSHRoute) { r.Agent, r.KeyFile = "", encPath }})
	if r := run(t, f.connect(), "echo hi", nil); r.status != exitUpstream || !strings.Contains(r.stderr, "encrypted") {
		t.Errorf("encrypted: %+v", r)
	}
}

func TestASecondCommandOnAChannelIsRefused(t *testing.T) {
	f := newFixture(t, options{})
	c := f.connect()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	payload := ssh.Marshal(struct{ Command string }{"cat"})
	if ok, err := ch.SendRequest("exec", true, payload); !ok || err != nil {
		t.Fatalf("first exec: %v %v", ok, err)
	}
	if ok, _ := ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"echo two"})); ok {
		t.Error("a second exec was accepted")
	}
	_ = ch.CloseWrite()
	_, _ = io.Copy(io.Discard, ch)
	_ = ch.Close()
	if got := f.sshd.commands(); len(got) != 1 {
		t.Errorf("upstream ran %q", got)
	}
}

func TestALoggedCommandIsBoundedAndEscaped(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ls -l", "ls -l"},
		{"a\nb\x1b[31m", `a\x0ab\x1b[31m`},
		{`a\x0a`, `a\\x0a`},
		{"caf\xc3\xa9 \xff", "café \\xff"},
		{strings.Repeat("a", 2000), strings.Repeat("a", 1024) + "..."},
	} {
		if got := loggedCommand(tc.in); got != tc.want {
			t.Errorf("loggedCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
