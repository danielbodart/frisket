package sshroute

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/policy"
)

// login is a fake machine's login shell: it keeps the terminal it was
// given and every resize, and answers each line typed into it.
//
//	say WORDS...  prints the words, on stdout
//	warn WORDS... prints the words, on stderr
//	exit N        exits N
//
// A signal kills it, with that signal.
type loginShell struct {
	mu      sync.Mutex
	pty     *ptyRequest
	resizes [][2]uint32
	shells  int
	refused []string
}

func (m *loginShell) serve(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	signals := make(chan string, 1)
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			var p ptyRequest
			if err := ssh.Unmarshal(r.Payload, &p); err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			m.mu.Lock()
			m.pty = &p
			m.mu.Unlock()
			_ = r.Reply(true, nil)
		case "window-change":
			var p struct{ Columns, Rows, Width, Height uint32 }
			_ = ssh.Unmarshal(r.Payload, &p)
			m.mu.Lock()
			m.resizes = append(m.resizes, [2]uint32{p.Columns, p.Rows})
			m.mu.Unlock()
		case "signal":
			var p struct{ Signal string }
			_ = ssh.Unmarshal(r.Payload, &p)
			select {
			case signals <- p.Signal:
			default:
			}
		case "shell":
			m.mu.Lock()
			m.shells++
			m.mu.Unlock()
			_ = r.Reply(true, nil)
			go m.run(ch, signals)
		default:
			m.mu.Lock()
			m.refused = append(m.refused, r.Type)
			m.mu.Unlock()
			_ = r.Reply(false, nil)
		}
	}
}

func (m *loginShell) run(ch ssh.Channel, signals <-chan string) {
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(ch)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	fmt.Fprint(ch, "$ ")
	for {
		select {
		case sig := <-signals:
			_ = ch.CloseWrite()
			_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
				Signal     string
				CoreDumped bool
				Error      string
				Lang       string
			}{Signal: sig}))
			_ = ch.Close()
			return
		case l, ok := <-lines:
			if !ok {
				exit(ch, 0) // EOF: as a shell does at ^D
				return
			}
			w := strings.Fields(l)
			switch {
			case len(w) > 0 && w[0] == "say":
				fmt.Fprintln(ch, strings.Join(w[1:], " "))
			case len(w) > 0 && w[0] == "warn":
				fmt.Fprintln(ch.Stderr(), strings.Join(w[1:], " "))
			case len(w) == 2 && w[0] == "exit":
				var n uint32
				fmt.Sscan(w[1], &n)
				exit(ch, n)
				return
			}
			fmt.Fprint(ch, "$ ")
		}
	}
}

func (m *loginShell) state() (pty *ptyRequest, resizes [][2]uint32, shells int, refused []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pty, append([][2]uint32(nil), m.resizes...), m.shells, append([]string(nil), m.refused...)
}

func interactiveFixture(t *testing.T, answer string, o options) (*fixture, *loginShell) {
	t.Helper()
	m := &loginShell{}
	o.route = func(r *policy.SSHRoute) { r.Interactive = answer }
	o.sshd = func(d *sshd) { d.shell = m.serve }
	return newFixture(t, o), m
}

// shellSession is the sandbox's interactive ssh: a terminal if term is
// set, a shell, and its three streams.
type shellSession struct {
	s      *ssh.Session
	stdin  io.WriteCloser
	out    *bufio.Reader
	stderr *bytes.Buffer
}

func openShell(t *testing.T, c *ssh.Client, term string) (*shellSession, error) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	s.Stderr = &errb
	if term != "" {
		if err := s.RequestPty(term, 40, 120, ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 38400}); err != nil {
			return nil, err
		}
	}
	if err := s.Shell(); err != nil {
		return nil, err
	}
	return &shellSession{s: s, stdin: in, out: bufio.NewReader(out), stderr: &errb}, nil
}

// expect reads stdout up to and including want.
func (s *shellSession) expect(t *testing.T, want string) {
	t.Helper()
	var got []byte
	for !bytes.HasSuffix(got, []byte(want)) {
		b, err := s.out.ReadByte()
		if err != nil {
			t.Fatalf("waiting for %q, read %q: %v", want, got, err)
		}
		got = append(got, b)
	}
}

func exitOf(err error) (int, string) {
	var ee *ssh.ExitError
	if err == nil {
		return 0, ""
	}
	if errors.As(err, &ee) {
		return ee.ExitStatus(), ee.Signal()
	}
	return -1, fmt.Sprint(err)
}

// By default a machine's interactive answer is refuse: the shell is
// refused as a command is, on its stderr with status 126, nothing reaches
// the machine, and a terminal asked for is refused before it.
func TestAnInteractiveShellIsRefusedByDefault(t *testing.T) {
	rec, rj := recorderFor(t, record.Allow)
	a := &answers{yes: true}
	f, m := interactiveFixture(t, "", options{asker: a, recorder: rec})
	c := f.connect()
	if _, err := openShell(t, c, "xterm"); err == nil {
		t.Fatal("a terminal was given")
	}
	ss, err := openShell(t, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := exitOf(ss.s.Wait()); status != exitRefused || !strings.Contains(ss.stderr.String(), ReasonInteractive) {
		t.Errorf("status %d, stderr %q", status, ss.stderr.String())
	}
	if _, _, shells, _ := m.state(); shells != 0 || f.sshd.dials() != 0 || len(a.questions()) != 0 {
		t.Errorf("%d shells, %d dials, %d questions", shells, f.sshd.dials(), len(a.questions()))
	}
	l := f.sshLines()
	if len(l) != 1 || l[0]["interactive"] != true || l[0]["decision"] != "refused" || l[0]["rule"] != RuleInteractive || l[0]["reason"] != ReasonInteractive {
		t.Errorf("lines %v", l)
	}
	// A recording session writes it down as no grant's to change, and
	// asks nobody: the answer is the host's.
	if l := rj.lines(t, "record"); len(l) != 1 || l[0]["source"] != "hard" || l[0]["reason"] != ReasonInteractive || l[0]["route"] != "server" {
		t.Errorf("record lines %v", l)
	}
}

// Asked, a shell is one question, of its own kind, saying whether a
// terminal was asked for and offering no Always; allowed, it runs, and
// refused, nothing reaches the machine.
func TestAnInteractiveShellAskedIsOneQuestion(t *testing.T) {
	a := &answers{yes: true}
	f, m := interactiveFixture(t, "ask", options{asker: a, always: &offering{}})
	c := f.connect()
	ss, err := openShell(t, c, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	ss.expect(t, "$ ")
	fmt.Fprintln(ss.stdin, "say hello")
	ss.expect(t, "hello\n$ ")
	fmt.Fprintln(ss.stdin, "exit 3")
	if status, _ := exitOf(ss.s.Wait()); status != 3 {
		t.Errorf("status %d", status)
	}
	q := a.questions()
	if len(q) != 1 {
		t.Fatalf("%d questions", len(q))
	}
	if q[0].Kind != intercept.KindInteractive || !q[0].PTY || q[0].Route != "server" || q[0].Host != "server" ||
		q[0].User != "dan" || q[0].Address != routeAddr.String() || q[0].Command != "" || q[0].Always || q[0].Diff != nil || q[0].ID == "" {
		t.Errorf("question %+v", q[0])
	}
	if l := f.sshLines(); len(l) != 2 || l[0]["phase"] != "start" || l[0]["asked"] != true || l[1]["phase"] != "end" || l[1]["exit_status"] != float64(3) {
		t.Errorf("lines %v", l)
	}

	a.mu.Lock()
	a.yes = false
	a.mu.Unlock()
	ss, err = openShell(t, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := exitOf(ss.s.Wait()); status != exitRefused || !strings.Contains(ss.stderr.String(), intercept.ReasonDeclined) {
		t.Errorf("status %d, stderr %q", status, ss.stderr.String())
	}
	if q := a.questions(); len(q) != 2 || q[1].PTY {
		t.Errorf("questions %+v", q)
	}
	if _, _, shells, _ := m.state(); shells != 1 {
		t.Errorf("%d shells", shells)
	}
}

// offering is a session's Always that would offer on any question: an
// interactive shell's is never offered it all the same.
type offering struct{}

func (offering) Offer(q *intercept.Question, _ intercept.AlwaysRule) func() {
	q.Always = true
	q.Diff = &intercept.Diff{}
	return func() {}
}

func (offering) Admits(intercept.AlwaysRule) bool { return false }

// Allowed, a shell asks nobody, and is relayed faithfully: the terminal as
// asked for and every resize, stdin, stdout and stderr, EOF and the exit
// status. Only its first and last lines are logged, and nothing typed.
func TestAnInteractiveShellAllowedIsRelayed(t *testing.T) {
	a := &answers{yes: true}
	f, m := interactiveFixture(t, "allow", options{asker: a})
	c := f.connect()
	ss, err := openShell(t, c, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	ss.expect(t, "$ ")
	if err := ss.s.WindowChange(50, 132); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(ss.stdin, "warn careful")
	fmt.Fprintln(ss.stdin, "say topsecretword")
	ss.expect(t, "topsecretword\n$ ")
	_ = ss.stdin.Close()
	if status, _ := exitOf(ss.s.Wait()); status != 0 {
		t.Errorf("status %d", status)
	}
	if ss.stderr.String() != "careful\n" {
		t.Errorf("stderr %q", ss.stderr.String())
	}
	pty, resizes, _, _ := m.state()
	// The modes as the client sent them: ISPEED 38400 among them.
	if pty == nil || pty.Term != "xterm" || pty.Rows != 40 || pty.Columns != 120 ||
		!strings.Contains(pty.Modes, string([]byte{ssh.TTY_OP_ISPEED, 0, 0, 0x96, 0})) {
		t.Errorf("pty %+v", pty)
	}
	if len(resizes) != 1 || resizes[0] != [2]uint32{132, 50} {
		t.Errorf("resizes %v", resizes)
	}
	if len(a.questions()) != 0 {
		t.Error("asked")
	}
	l := f.sshLines()
	if len(l) != 2 {
		t.Fatalf("lines %v", l)
	}
	start, end := l[0], l[1]
	if start["phase"] != "start" || start["pty"] != true || start["decision"] != "allowed" || start["rule"] != RuleInteractive || start["asked"] != nil {
		t.Errorf("start %v", start)
	}
	if end["phase"] != "end" || end["exit_status"] != float64(0) || end["duration_ms"] == nil || end["interactive"] != true {
		t.Errorf("end %v", end)
	}
	f.j.mu.Lock()
	logged := f.j.buf.String()
	f.j.mu.Unlock()
	if strings.Contains(logged, "topsecretword") || strings.Contains(logged, "careful") {
		t.Error("the journal holds what was typed")
	}
}

// A terminal resized while a person is asked is asked for at the size it
// is by then; and a signal kills the shell, which says so.
func TestAnInteractiveShellsResizeWhileAskedAndSignal(t *testing.T) {
	a := &answers{yes: true}
	f, m := interactiveFixture(t, "ask", options{asker: a})
	c := f.connect()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan string, 1)
	go func() {
		for r := range reqs {
			if r.Type == "exit-signal" {
				var p struct{ Signal string }
				_ = ssh.Unmarshal(r.Payload, &p)
				statuses <- p.Signal
			}
		}
		close(statuses)
	}()
	go func() { _, _ = io.Copy(io.Discard, ch) }()
	pty := ssh.Marshal(ptyRequest{Term: "vt100", Columns: 80, Rows: 24, Modes: "\x00"})
	if ok, err := ch.SendRequest("pty-req", true, pty); !ok || err != nil {
		t.Fatalf("pty: %v %v", ok, err)
	}
	if err := sendNoReply(ch, "window-change", ssh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 30, 0, 0})); err != nil {
		t.Fatal(err)
	}
	if ok, err := ch.SendRequest("shell", true, nil); !ok || err != nil {
		t.Fatalf("shell: %v %v", ok, err)
	}
	waitFor(t, "the shell", func() bool { _, _, n, _ := m.state(); return n == 1 })
	if p, _, _, _ := m.state(); p.Term != "vt100" || p.Columns != 100 || p.Rows != 30 {
		t.Errorf("pty %+v", p)
	}
	if err := sendNoReply(ch, "signal", ssh.Marshal(struct{ Signal string }{"TERM"})); err != nil {
		t.Fatal(err)
	}
	if sig := <-statuses; sig != "TERM" {
		t.Errorf("signal %q", sig)
	}
	waitFor(t, "the end line", func() bool { return len(f.sshLines()) == 2 })
	if end := f.sshLines()[1]; end["exit_signal"] != "TERM" || end["phase"] != "end" {
		t.Errorf("end %v", end)
	}
}

func sendNoReply(ch ssh.Channel, name string, payload []byte) error {
	_, err := ch.SendRequest(name, false, payload)
	return err
}

// A machine whose interactive answer is not refuse gives a command a
// terminal too, as `ssh -t server htop` asks: the command is still decided
// by its words, and nobody is asked about the terminal.
func TestACommandOnAnInteractiveMachineMayHaveATerminal(t *testing.T) {
	a := &answers{yes: false}
	f := newFixture(t, options{asker: a, route: func(r *policy.SSHRoute) { r.Interactive = "ask" }})
	c := f.connect()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Output("echo hi"); err != nil || string(out) != "hi\n" {
		t.Errorf("%q %v", out, err)
	}
	f.sshd.mu.Lock()
	pty := f.sshd.pty
	f.sshd.mu.Unlock()
	if pty != 1 || len(a.questions()) != 0 {
		t.Errorf("%d ptys, %d questions", pty, len(a.questions()))
	}
	if l := f.sshLines(); len(l) != 1 || l[0]["pty"] != true || l[0]["command"] != "echo hi" {
		t.Errorf("lines %v", l)
	}
	// One the rules ask about is still asked about, and refused here.
	s2, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	_ = s2.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	if err := s2.Run("sudo reboot"); err == nil {
		t.Error("ran")
	}
	if q := a.questions(); len(q) != 1 || q[0].Kind != "ssh" || q[0].Command != "sudo reboot" {
		t.Errorf("questions %+v", q)
	}
}

// Whatever the machine's interactive answer, sftp, forwarding of every
// kind, an agent, X11 and env are refused as ever.
func TestAnInteractiveMachineStillRefusesSubsystemsForwardsAndEnv(t *testing.T) {
	f, m := interactiveFixture(t, "allow", options{})
	c := f.connect()
	s, err := c.NewSession()
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
	if err := s.Setenv("LANG", "C"); err == nil {
		t.Error("env granted")
	}
	if ok, _ := s.SendRequest("auth-agent-req@openssh.com", true, nil); ok {
		t.Error("agent forwarding granted")
	}
	if ok, _ := s.SendRequest("x11-req", true, ssh.Marshal(struct {
		Single           bool
		Protocol, Cookie string
		Screen           uint32
	}{false, "MIT-MAGIC-COOKIE-1", "00", 0})); ok {
		t.Error("X11 granted")
	}
	if _, _, err := c.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}{"127.0.0.1", 22, "127.0.0.1", 1})); err == nil {
		t.Error("a forward was opened")
	}
	if ok, _, _ := c.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 8080})); ok {
		t.Error("a remote forward was granted")
	}
	// The shell itself still opens, with none of it.
	ss, err := openShell(t, c, "")
	if err != nil {
		t.Fatal(err)
	}
	ss.expect(t, "$ ")
	fmt.Fprintln(ss.stdin, "exit 0")
	if status, _ := exitOf(ss.s.Wait()); status != 0 {
		t.Errorf("status %d", status)
	}
	if _, _, _, refused := m.state(); len(refused) != 0 {
		t.Errorf("the machine was asked %v", refused)
	}
}

// A ceiling clamps a machine's interactive answer as it does any other:
// a tier that may never open a shell -- strict -- says so in a ceiling no
// project's layer may lift, and the route compiled from it refuses.
func TestACeilingRefusingInteractiveRefusesTheShell(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ap"
	l, err := policy.Load([]byte(`{"version": 2, "name": "strict", "ceiling": {"interactive": "refuse"},
	  "ssh": {"server": {"address": "192.168.1.1", "user": "root", "hostKeys": ["` + key + `"], "agent": "/run/a", "interactive": "allow"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := Compile(l.Policy.SSH, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].interactive != "refuse" {
		t.Errorf("interactive %q", routes[0].interactive)
	}
	if _, err := Compile([]policy.SSHRoute{{Name: "x", Address: "192.168.1.1", User: "u", HostKeys: []string{key}, Agent: "/run/a", Interactive: "sometimes"}}, Reserved{}); err == nil {
		t.Error("an answer that is none compiled")
	}
}
