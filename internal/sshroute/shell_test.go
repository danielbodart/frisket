package sshroute

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/policy"
)

// cli is a fake device's shell, as a router's or a modem's is: it ignores
// the command an exec carries and greets with a banner and a prompt, echoes
// what is typed as a line editor does, ends a line at a carriage return,
// and prints its lines ended \r\n.
//
//	echo WORDS...  prints the words
//	slow           prints a line, pauses, and prints another
//	quiet          prints nothing
//	bye            prints a line and closes the session
//	flood          prints more than frisket holds
//	confirm        asks "Really? " with no prompt after it, and takes the
//	               next line typed as the answer
//	exit           closes the session
//
// With hang, it never answers a line at all.
type cli struct {
	prompt string
	hang   bool
	pause  time.Duration

	mu    sync.Mutex
	terms []string
	execs []string
	typed []string
}

func (k *cli) lines() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.typed...)
}

func (k *cli) serve(_ *sshd, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	started := false
	start := func() {
		if !started {
			started = true
			go k.run(ch)
		}
	}
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			var p ptyRequest
			_ = ssh.Unmarshal(r.Payload, &p)
			k.mu.Lock()
			k.terms = append(k.terms, p.Term)
			k.mu.Unlock()
			_ = r.Reply(true, nil)
		case "exec":
			var p struct{ Command string }
			_ = ssh.Unmarshal(r.Payload, &p)
			k.mu.Lock()
			k.execs = append(k.execs, p.Command)
			k.mu.Unlock()
			_ = r.Reply(true, nil)
			start()
		case "shell":
			_ = r.Reply(true, nil)
			start()
		default:
			_ = r.Reply(false, nil)
		}
	}
}

func (k *cli) run(ch ssh.Channel) {
	fmt.Fprint(ch, "No entry for terminal type \"dumb\";\r\nusing dumb terminal settings.\r\n"+k.prompt)
	var line []byte
	confirming := false
	b := make([]byte, 1)
	for {
		if _, err := ch.Read(b); err != nil {
			return
		}
		if b[0] != '\r' {
			line = append(line, b[0])
			_, _ = ch.Write(b)
			continue
		}
		_, _ = ch.Write([]byte("\r\n"))
		typed := string(line)
		line = nil
		k.mu.Lock()
		k.typed = append(k.typed, typed)
		k.mu.Unlock()
		if k.hang {
			continue
		}
		if confirming {
			confirming = false
			fmt.Fprintf(ch, "answered %s\r\n%s", typed, k.prompt)
			continue
		}
		w := strings.Fields(typed)
		switch {
		case len(w) == 0:
		case w[0] == "exit":
			exit(ch, 0)
			return
		case w[0] == "echo":
			fmt.Fprintf(ch, "%s\r\n", strings.Join(w[1:], " "))
		case w[0] == "slow":
			fmt.Fprint(ch, "a\r\n")
			time.Sleep(k.pause)
			fmt.Fprint(ch, "b\r\n")
		case w[0] == "quiet":
		case w[0] == "bye":
			fmt.Fprint(ch, "bye\r\n")
			exit(ch, 0)
			return
		case w[0] == "confirm":
			confirming = true
			fmt.Fprint(ch, "Really? ")
			continue
		case w[0] == "flood":
			_, _ = ch.Write(bytes.Repeat([]byte("x"), maxShellOutput+1))
		default:
			fmt.Fprint(ch, "unknown command\r\n")
		}
		fmt.Fprint(ch, k.prompt)
	}
}

// shortShell shrinks the shell's waits for a test.
func shortShell(t *testing.T) {
	t.Helper()
	loginIdle, idle, settle, timeout, exitWait := shellLoginIdle, shellIdle, shellSettle, shellTimeout, shellExitWait
	shellLoginIdle, shellIdle, shellSettle, shellTimeout, shellExitWait =
		100*time.Millisecond, 400*time.Millisecond, 30*time.Millisecond, 3*time.Second, 200*time.Millisecond
	t.Cleanup(func() {
		shellLoginIdle, shellIdle, shellSettle, shellTimeout, shellExitWait = loginIdle, idle, settle, timeout, exitWait
	})
}

func shellFixture(t *testing.T, k *cli, o options) *fixture {
	t.Helper()
	return shellFixtureServing(t, k.serve, o)
}

// shellFixtureServing is shellFixture, with each session served by serve.
func shellFixtureServing(t *testing.T, serve func(*sshd, ssh.Channel, <-chan *ssh.Request), o options) *fixture {
	t.Helper()
	shortShell(t)
	o.sshd = func(d *sshd) { d.shell = func(ch ssh.Channel, reqs <-chan *ssh.Request) { serve(d, ch, reqs) } }
	edit := o.route
	o.route = func(r *policy.SSHRoute) {
		r.Shell = true
		r.Exec = []policy.ExecRule{
			{Command: "echo **"}, {Command: "slow"}, {Command: "quiet"}, {Command: "bye"}, {Command: "flood"}, {Command: "confirm"},
			{Command: "reboot", Ask: true},
		}
		if edit != nil {
			edit(r)
		}
	}
	return newFixture(t, o)
}

func TestAShellRouteTypesTheCommandAndGivesBackWhatItPrinted(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	f := shellFixture(t, k, options{})
	c := f.connect()
	r := run(t, c, "echo hello  world", nil)
	if r.err != nil || r.stdout != "hello world\n" || r.stderr != "" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	r = run(t, c, "quiet", nil)
	if r.err != nil || r.stdout != "" || r.status != 0 {
		t.Errorf("a command that prints nothing: %+v", r)
	}
	if got := k.lines(); strings.Join(got, "|") != "echo hello  world|exit|quiet|exit" {
		t.Errorf("typed %q: each command, as it was sent, and exit after it", got)
	}
	if len(k.execs) != 0 || strings.Join(k.terms, ",") != "dumb,dumb" {
		t.Errorf("execs %q, terms %q: a shell on a dumb terminal, and never an exec", k.execs, k.terms)
	}
	if f.sshd.dials() != 1 {
		t.Errorf("%d logins for one connection, want one shared", f.sshd.dials())
	}
	waitFor(t, "two lines", func() bool { return len(f.sshLines()) == 2 })
	l := f.sshLines()[0]
	for k, want := range map[string]any{
		"route": "server", "command": "echo hello  world", "decision": "allowed", "rule": "echo **",
		"exit_status": float64(0), "stdout_bytes": float64(12), "stdin_bytes": float64(0),
	} {
		if l[k] != want {
			t.Errorf("%s = %v, want %v", k, l[k], want)
		}
	}
}

// The sandbox's stdin is never typed: it would be commands nobody decided.
func TestAShellRouteNeverTypesTheSandboxsStdin(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	f := shellFixture(t, k, options{})
	r := runEager(t, f.connect(), "echo hi", []byte("reboot\rreboot\n"))
	if r.err != nil || r.stdout != "hi\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	if got := k.lines(); strings.Join(got, "|") != "echo hi|exit" {
		t.Errorf("typed %q", got)
	}
}

// What a shell route cannot read -- an operator, a quote, a redirection, a
// control byte, a line too long -- is refused before anything is typed, and
// never put to the asker, even one that would admit it: typed byte for byte,
// a carriage return in it would end the line and type a second command, and
// a person shown it could not tell.
func TestAShellRouteRefusesWhatItCannotReadBeforeTypingAnything(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	a := &answers{yes: true}
	f := shellFixture(t, k, options{asker: a})
	c := f.connect()
	for _, command := range []string{
		"echo a; reboot", "echo a && reboot", "echo a | reboot", "echo 'a'", "echo a >/dev/null",
		"echo a\rreboot", "echo a" + strings.Repeat(" ", 1000) + "\rreboot", "reboot\x15echo a", "echo a\nreboot",
		"echo " + strings.Repeat("a", 300),
	} {
		r := run(t, c, command, nil)
		if r.status != exitRefused || !strings.Contains(r.stderr, ReasonUnreadable) {
			t.Errorf("%q: %+v", command, r)
		}
	}
	if got := k.lines(); len(got) != 0 || f.sshd.dials() != 0 {
		t.Errorf("typed %q in %d logins", got, f.sshd.dials())
	}
	if qs := a.questions(); len(qs) != 0 {
		t.Errorf("asked %+v", qs)
	}
	waitFor(t, "the lines", func() bool { return len(f.sshLines()) == 10 })
	if l := f.sshLines()[5]; l["decision"] != "refused" || l["rule"] != "unmatched" || l["reason"] != ReasonUnreadable {
		t.Errorf("line %v", l)
	}
}

// A question about a shell route's command shows no stdin, since none is
// sent; admitted, it is typed like any other.
func TestAnAskedShellCommandIsAskedWithNoStdinAndRunsWhenAdmitted(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	a := &answers{yes: true}
	f := shellFixture(t, k, options{asker: a})
	r := runEager(t, f.connect(), "reboot", []byte("held open"))
	if r.status != 0 || r.stdout != "unknown command\n" {
		t.Errorf("got %+v", r)
	}
	qs := a.questions()
	if len(qs) != 1 || qs[0].Command != "reboot" || !qs[0].Shell || qs[0].Body != "" || qs[0].BodyMore {
		t.Errorf("asked %+v", qs)
	}
	if got := k.lines(); strings.Join(got, "|") != "reboot|exit" {
		t.Errorf("typed %q", got)
	}
}

// A pause in the output that does not end with the prompt is waited out,
// so long as it is shorter than shellIdle.
func TestAShellCommandIsWaitedForThroughAPause(t *testing.T) {
	k := &cli{prompt: "ZySH> ", pause: 150 * time.Millisecond}
	f := shellFixture(t, k, options{})
	if r := run(t, f.connect(), "slow", nil); r.stdout != "a\nb\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
}

// A command that goes quiet without the prompt coming back -- waiting on a
// question, a pager, or still running -- is given nothing more: exit typed
// then would be its answer. Its output is given, with the failure said,
// since it is not known to be whole.
func TestAShellCommandWhosePromptDoesNotComeBackIsTypedNothingMore(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	f := shellFixture(t, k, options{})
	r := run(t, f.connect(), "confirm", nil)
	if r.status != exitUpstream || r.stdout != "Really? " || !strings.Contains(r.stderr, "prompt did not come back") {
		t.Errorf("got %+v", r)
	}
	if got := k.lines(); strings.Join(got, "|") != "confirm" {
		t.Errorf("typed %q", got)
	}
}

// Output past the bound is dropped from there on, never a later chunk that
// fits spliced on after the gap.
func TestAScreenKeepsNothingOnceOverItsBound(t *testing.T) {
	sc := newScreen()
	_, _ = sc.Write([]byte("start"))
	_, _ = sc.Write(bytes.Repeat([]byte("x"), maxShellOutput))
	_, _ = sc.Write([]byte("later"))
	if n, _, err := sc.wait(0, "", time.Hour, time.Now().Add(time.Second)); err != errShellOutput || string(sc.bytes(0, n)) != "start" {
		t.Errorf("kept %q, %v", sc.bytes(0, n), err)
	}
}

// A shell with no prompt frisket can find finishes a command once it is
// quiet, and is closed with nothing more typed: with no prompt to see, a
// command still waiting on a question cannot be told from one done.
func TestAShellWithNoPromptFinishesACommandOnceItIsQuiet(t *testing.T) {
	k := &cli{}
	f := shellFixture(t, k, options{})
	start := time.Now()
	r := run(t, f.connect(), "echo hi", nil)
	if r.stdout != "hi\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	if d := time.Since(start); d < shellIdle {
		t.Errorf("finished in %v, before shellIdle", d)
	}
	if got := k.lines(); strings.Join(got, "|") != "echo hi" {
		t.Errorf("typed %q", got)
	}
}

func TestAShellThatClosesAfterTheCommandStillGivesWhatItPrinted(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	f := shellFixture(t, k, options{})
	if r := run(t, f.connect(), "bye", nil); r.stdout != "bye\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	if got := k.lines(); strings.Join(got, "|") != "bye" {
		t.Errorf("typed %q", got)
	}
}

func TestAShellThatNeverFinishesFailsTheCommand(t *testing.T) {
	k := &cli{prompt: "ZySH> ", hang: true}
	// Output, but never quiet: the timeout, not the idle, ends it.
	f := shellFixtureServing(t, func(d *sshd, ch ssh.Channel, reqs <-chan *ssh.Request) {
		go func() {
			for {
				if _, err := ch.Write([]byte(".")); err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		k.serve(d, ch, reqs)
	}, options{})
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, "did not finish in time") {
		t.Errorf("got status %d, stderr %q", r.status, r.stderr)
	}
	waitFor(t, "a line", func() bool { return len(f.sshLines()) == 1 })
	if l := f.sshLines()[0]; l["decision"] != "failed" || l["reason"] != ReasonUpstream {
		t.Errorf("line %v", l)
	}
}

func TestAShellCommandPrintingMoreThanFrisketHoldsFails(t *testing.T) {
	k := &cli{prompt: "ZySH> "}
	f := shellFixture(t, k, options{})
	r := run(t, f.connect(), "flood", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, "printed more than") {
		t.Errorf("got status %d, stderr %q", r.status, r.stderr)
	}
}

func TestAShellRouteDeviceThatRefusesATerminalFailsTheCommand(t *testing.T) {
	// An sshd that grants a terminal and refuses a shell.
	f := shellFixtureServing(t, (*sshd).session, options{})
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, "refused a shell") {
		t.Errorf("got status %d, stderr %q", r.status, r.stderr)
	}
}

func TestTheEchoAndThePromptAreTakenOffWhereTheyAreFound(t *testing.T) {
	for _, tc := range []struct{ out, command, prompt, want string }{
		{"show x\r\nline 1\r\nline 2\r\nZySH> ", "show x", "ZySH> ", "line 1\nline 2\n"},
		{"ZySH> show x\r\nok\r\nZySH> ", "show x", "ZySH> ", "ok\n"},
		{"line 1\r\nZySH> ", "show x", "ZySH> ", "line 1\n"},
		{"show x\r\nok\r\n> ", "show x", "ZySH> ", "ok\n> "},
		{"show x", "show x", "", ""},
		{"show  x\r\nok\r\n", " show  x ", "", "ok\n"},
	} {
		if got := string(cleaned([]byte(tc.out), tc.command, tc.prompt)); got != tc.want {
			t.Errorf("cleaned(%q, %q, %q) = %q, want %q", tc.out, tc.command, tc.prompt, got, tc.want)
		}
	}
	for greeting, want := range map[string]string{
		"banner\r\nZySH> ": "ZySH> ",
		"ZySH> ":           "ZySH> ",
		"banner\r\n":       "",
		"":                 "",
		"banner\r\n" + strings.Repeat("p", maxPrompt+1): "",
	} {
		if got := promptOf([]byte(greeting)); got != want {
			t.Errorf("promptOf(%q) = %q, want %q", greeting, got, want)
		}
	}
}
