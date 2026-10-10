package agentsrv

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	uid  = 1000
	pts0 = 136 << 8
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type asked struct {
	q         galleyask.Question
	reply     chan answered
	withdrawn chan struct{}
}

type harness struct {
	t          *testing.T
	s          *Server
	path       string
	requesters chan *peer.Requester
	questions  chan *asked
	log        *lockedBuffer
	github     ssh.Signer
	server     ssh.Signer
	frisket    atomic.Bool
}

func newHarness(t *testing.T, keys int, configure func(*Server)) *harness {
	t.Helper()
	log.SetOutput(io.Discard)
	dir, err := os.MkdirTemp("", "agentsrv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{
		t: t, path: filepath.Join(dir, "agent"),
		requesters: make(chan *peer.Requester, 16), questions: make(chan *asked, 16),
		log: &lockedBuffer{}, github: hostKey(t), server: hostKey(t),
	}
	known := "github.com " + string(ssh.MarshalAuthorizedKey(h.github.PublicKey())) +
		"@cert-authority * " + string(ssh.MarshalAuthorizedKey(h.server.PublicKey()))
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(known), 0o644); err != nil {
		t.Fatal(err)
	}
	h.s = &Server{
		User: "dan", UID: uid, Terminal: Allow, SSHSIG: map[string]Rule{"git": Allow},
		KnownHosts: filepath.Join(dir, "known_hosts"), Grants: grant.New(),
		Log: slog.New(slog.NewJSONHandler(h.log, nil)),
		who: func(*net.UnixConn) (*peer.Requester, error) { return <-h.requesters, nil },
		ask: h.ask,
	}
	h.s.frisket = func(*peer.Requester) bool { return h.frisket.Load() }
	for range keys {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		h.s.Keys = append(h.s.Keys, Key{Signer: k, Comment: "dan@test"})
	}
	if configure != nil {
		configure(h.s)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go h.s.Serve(ln)
	return h
}

func (h *harness) ask(ctx context.Context, user string, q galleyask.Question) (galleyask.Answer, error) {
	a := &asked{q: q, reply: make(chan answered, 1), withdrawn: make(chan struct{})}
	h.questions <- a
	select {
	case r := <-a.reply:
		return r.a, r.err
	case <-ctx.Done():
		close(a.withdrawn)
		return galleyask.Answer{}, ctx.Err()
	}
}

func hostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type client struct {
	agent.ExtendedAgent
	c net.Conn
}

func (h *harness) dial(r *peer.Requester) *client {
	h.t.Helper()
	h.requesters <- r
	c, err := net.Dial("unix", h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return &client{agent.NewClient(c), c}
}

func (h *harness) key(i int) ssh.PublicKey {
	pub, err := ssh.NewPublicKey(h.s.Keys[i].Signer.Public())
	if err != nil {
		h.t.Fatal(err)
	}
	return pub
}

func (c *client) bind(t *testing.T, host ssh.Signer, sid []byte, fwd bool) error {
	t.Helper()
	sig, err := host.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Extension("session-bind@openssh.com", bindMsg(host.PublicKey(), sid, ssh.Marshal(sig), fwd))
	return err
}

func bindMsg(host ssh.PublicKey, sid, sig []byte, fwd bool) []byte {
	return ssh.Marshal(struct {
		Key, Sid, Sig []byte
		Fwd           bool
	}{host.Marshal(), sid, sig, fwd})
}

func userauthData(sid []byte, key, host ssh.PublicKey) []byte {
	method := methodPublickey
	if host != nil {
		method = methodHostbound
	}
	b := ssh.Marshal(struct {
		Sid                   []byte
		Msg                   byte
		User, Service, Method string
		Sig                   bool
		Alg                   string
		Pub                   []byte
	}{sid, msgUserauthRequest, "dan", "ssh-connection", method, true, key.Type(), key.Marshal()})
	if host != nil {
		b = append(b, ssh.Marshal(struct{ K []byte }{host.Marshal()})...)
	}
	return b
}

func (c *client) signAsync(key ssh.PublicKey, data []byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := c.SignWithFlags(key, data, 0)
		done <- err
	}()
	return done
}

func (h *harness) next() *asked {
	h.t.Helper()
	select {
	case a := <-h.questions:
		return a
	case <-time.After(10 * time.Second):
		h.t.Fatal("nothing was asked")
		return nil
	}
}

func (h *harness) nothingAsked() {
	h.t.Helper()
	select {
	case a := <-h.questions:
		h.t.Fatalf("asked %+v", a.q)
	default:
	}
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the sign never finished")
		return nil
	}
}

func allowFor(d time.Duration) answered {
	return answered{a: galleyask.Answer{Allowed: true, For: d}}
}

func links(ls ...peer.Link) *peer.Requester {
	for i := range ls {
		ls[i].UID = uid
	}
	return peer.FromLinks(ls)
}

var (
	pid1        = peer.Link{Pid: 1, Sid: 1, Start: 1, Comm: "systemd"}
	systemdUser = peer.Link{Pid: 10, PPid: 1, Sid: 10, Start: 10, Comm: "systemd", Cmdline: []string{"systemd", "--user"}}
	kgx         = peer.Link{Pid: 20, PPid: 10, Sid: 20, Start: 20, Comm: ".kgx-wrapped"}
	tabShell    = peer.Link{Pid: 30, PPid: 20, Sid: 30, TTY: pts0, Start: 30, Comm: "bash", Cmdline: []string{"/run/current-system/sw/bin/bash"}}
)

func tab() *peer.Requester {
	return links(peer.Link{Pid: 31, PPid: 30, Sid: 30, TTY: pts0, Start: 31, Comm: "ssh", Cmdline: []string{"ssh", "github.com"}},
		tabShell, kgx, systemdUser, pid1)
}

func claude(pid int) *peer.Requester {
	return links(
		peer.Link{Pid: pid + 3, PPid: pid + 2, Sid: pid + 1, Start: 103, Comm: "ssh", Cmdline: []string{"ssh", "git@github.com"}},
		peer.Link{Pid: pid + 2, PPid: pid + 1, Sid: pid + 1, Start: 102, Comm: "git", Cmdline: []string{"git", "push"}},
		peer.Link{Pid: pid + 1, PPid: pid, Sid: pid + 1, Start: 101, Comm: "bash", Cmdline: []string{"bash", "-c", "git push"}},
		peer.Link{Pid: pid, PPid: 30, Sid: 30, TTY: pts0, Start: 100, Comm: ".claude-unwrapp"},
		tabShell, kgx, systemdUser, pid1)
}

func systemdRun() *peer.Requester {
	return links(peer.Link{Pid: 500, PPid: 10, Sid: 500, Start: 500, Comm: "ssh", Cmdline: []string{"ssh", "github.com"}},
		systemdUser, pid1)
}

func TestAForgedBindIsRefused(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(claude(100))
	sid := []byte("session-1")
	sig, err := hostKey(t).Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extension("session-bind@openssh.com", bindMsg(h.github.PublicKey(), sid, ssh.Marshal(sig), false)); err == nil {
		t.Fatal("a bind signed by another key was accepted")
	}

	done := c.signAsync(h.key(0), userauthData(sid, h.key(0), nil))
	a := h.next()
	if a.q.Grantable || !strings.Contains(a.q.Title, "unverified") {
		t.Errorf("after a forged bind, asked %+v", a.q)
	}
	a.reply <- answered{a: galleyask.Answer{Allowed: true}}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestASignForAnotherSessionThanTheLastBindIsRefused(t *testing.T) {
	h := newHarness(t, 1, nil)
	h.frisket.Store(true)
	c := h.dial(claude(100))
	if err := c.bind(t, h.github, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if err := c.bind(t, h.github, []byte("second"), false); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, c.signAsync(h.key(0), userauthData([]byte("first"), h.key(0), nil))); err == nil {
		t.Error("a sign for the first session was made after the second bind")
	}
	h.nothingAsked()
	if err := wait(t, c.signAsync(h.key(0), userauthData([]byte("second"), h.key(0), nil))); err != nil {
		t.Errorf("a sign for the last session: %v", err)
	}
}

func TestAHostboundRequestWhoseHostKeyIsNotTheBoundKeyIsRefused(t *testing.T) {
	h := newHarness(t, 1, nil)
	h.frisket.Store(true)
	c := h.dial(claude(100))
	sid := []byte("session")
	if err := c.bind(t, h.github, sid, false); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, c.signAsync(h.key(0), userauthData(sid, h.key(0), h.server.PublicKey()))); err == nil {
		t.Error("a hostbound request naming another host key was signed")
	}
	h.nothingAsked()
	if err := wait(t, c.signAsync(h.key(0), userauthData(sid, h.key(0), h.github.PublicKey()))); err != nil {
		t.Errorf("a hostbound request naming the bound key: %v", err)
	}
}

func TestAnyForwardingBindMarksTheConnectionForwarded(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(tab())
	if err := c.bind(t, h.github, []byte("hop"), true); err != nil {
		t.Fatal(err)
	}
	if err := c.bind(t, h.github, []byte("far"), false); err != nil {
		t.Fatal(err)
	}
	done := c.signAsync(h.key(0), userauthData([]byte("far"), h.key(0), nil))
	a := h.next()
	if !strings.Contains(a.q.Text, "\nforwarded\n") {
		t.Errorf("asked %q", a.q.Text)
	}
	a.reply <- answered{}
	if err := wait(t, done); err == nil {
		t.Error("a refused sign was made")
	}
}

func TestSSHSIGShowsItsNamespace(t *testing.T) {
	for _, ns := range []string{"git", "file"} {
		data, err := os.ReadFile(filepath.Join("testdata", "sshsig-"+ns+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := parseSSHSIG(data)
		if err != nil || s.namespace != ns {
			t.Fatalf("%s: got %+v, %v", ns, s, err)
		}
	}

	h := newHarness(t, 1, func(s *Server) { s.SSHSIG = nil })
	data, _ := os.ReadFile(filepath.Join("testdata", "sshsig-git.bin"))
	done := h.dial(claude(100)).signAsync(h.key(0), data)
	a := h.next()
	if !strings.Contains(a.q.Text, `SSHSIG namespace "git"`) {
		t.Errorf("asked %q", a.q.Text)
	}
	a.reply <- answered{}
	wait(t, done)
}

func TestAPeerThatIsNotTheConfiguredUserIsRefusedBeforeAnyMessage(t *testing.T) {
	h := newHarness(t, 1, nil)
	r := claude(100)
	r.PeerUID = 0
	if _, err := h.dial(r).List(); err == nil {
		t.Error("root's list was answered")
	}
	if !strings.Contains(h.log.String(), "peer uid 0 is not dan") {
		t.Errorf("logged:\n%s", h.log.String())
	}
}

type panicky struct {
	crypto.Signer
	panicked atomic.Bool
}

func (p *panicky) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !p.panicked.Swap(true) {
		panic("boom")
	}
	return p.Signer.Sign(r, digest, opts)
}

func TestAPanicInOneRequestDoesNotStopTheNext(t *testing.T) {
	h := newHarness(t, 1, func(s *Server) { s.Keys[0].Signer = &panicky{Signer: s.Keys[0].Signer} })
	h.frisket.Store(true)
	c := h.dial(claude(100))
	data := userauthData([]byte("sid"), h.key(0), nil)
	if err := wait(t, c.signAsync(h.key(0), data)); err == nil {
		t.Error("a sign that panicked succeeded")
	}
	if err := wait(t, c.signAsync(h.key(0), data)); err != nil {
		t.Errorf("the next sign: %v", err)
	}
	if err := wait(t, h.dial(claude(100)).signAsync(h.key(0), data)); err != nil {
		t.Errorf("the next connection's sign: %v", err)
	}
}

func TestNoKeysAnswersAnEmptyList(t *testing.T) {
	h := newHarness(t, 0, nil)
	keys, err := h.dial(claude(100)).List()
	if err != nil || len(keys) != 0 {
		t.Errorf("got %v, %v", keys, err)
	}
}

func TestTerminalAskAsksATabToAKnownHost(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(tab())
	if err := c.bind(t, h.github, []byte("sid"), false); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()

	h = newHarness(t, 1, func(s *Server) { s.Terminal = Ask })
	c = h.dial(tab())
	if err := c.bind(t, h.github, []byte("sid"), false); err != nil {
		t.Fatal(err)
	}
	done := c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
	a := h.next()
	if !a.q.Grantable || a.q.Title != "ssh to github.com" || a.q.Level != "normal" {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{a: galleyask.Answer{Allowed: true}}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAGitSignatureIsSilentByDefaultAndAnUnlistedNamespaceIsAllowOnce(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(claude(100))
	git, _ := os.ReadFile(filepath.Join("testdata", "sshsig-git.bin"))
	if err := wait(t, c.signAsync(h.key(0), git)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()

	file, _ := os.ReadFile(filepath.Join("testdata", "sshsig-file.bin"))
	done := c.signAsync(h.key(0), file)
	a := h.next()
	if a.q.Grantable || !strings.Contains(a.q.Text, `SSHSIG namespace "file"`) {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{a: galleyask.Answer{Allowed: true}}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAForwardedSignIsAskedEvenFromATabToAKnownHost(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(tab())
	if err := c.bind(t, h.github, []byte("sid"), true); err != nil {
		t.Fatal(err)
	}
	done := c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
	a := h.next()
	if !a.q.Grantable || !strings.Contains(a.q.Text, "forwarded") {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}

func TestADirectGrantNeverCoversAForwardedSignNorTheReverse(t *testing.T) {
	for _, first := range []bool{false, true} {
		h := newHarness(t, 1, nil)
		sign := func(fwd bool) <-chan error {
			c := h.dial(claude(100))
			if err := c.bind(t, h.github, []byte("sid"), fwd); err != nil {
				t.Fatal(err)
			}
			return c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
		}
		done := sign(first)
		h.next().reply <- allowFor(15 * time.Minute)
		if err := wait(t, done); err != nil {
			t.Fatal(err)
		}
		if err := wait(t, sign(first)); err != nil {
			t.Fatal(err)
		}
		h.nothingAsked()

		done = sign(!first)
		a := h.next()
		a.reply <- answered{}
		if err := wait(t, done); err == nil {
			t.Errorf("a grant made with forwarded %v covered a sign with forwarded %v", first, !first)
		}
	}
}

func TestANewGrantSignsTheWaitingRowsItCovers(t *testing.T) {
	h := newHarness(t, 2, nil)
	sign := func(r *peer.Requester, host ssh.Signer, key int, fwd bool) (<-chan error, *asked) {
		c := h.dial(r)
		if err := c.bind(t, host, []byte("sid"), fwd); err != nil {
			t.Fatal(err)
		}
		done := c.signAsync(h.key(key), userauthData([]byte("sid"), h.key(key), nil))
		return done, h.next()
	}
	answering, question := sign(claude(100), h.github, 0, false)
	covered, coveredRow := sign(claude(100), h.github, 0, false)
	var stay []*asked
	for _, row := range []struct {
		r    *peer.Requester
		host ssh.Signer
		key  int
		fwd  bool
	}{
		{claude(100), h.server, 0, false},
		{claude(100), h.github, 1, false},
		{claude(200), h.github, 0, false},
		{claude(100), h.github, 0, true},
	} {
		_, a := sign(row.r, row.host, row.key, row.fwd)
		stay = append(stay, a)
	}

	question.reply <- allowFor(15 * time.Minute)
	if err := wait(t, answering); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, covered); err != nil {
		t.Fatal(err)
	}
	<-coveredRow.withdrawn
	time.Sleep(100 * time.Millisecond)
	for i, a := range stay {
		select {
		case <-a.withdrawn:
			t.Errorf("row %d was withdrawn: %+v", i, a.q)
		default:
		}
	}
}

func TestHangUpWithdrawsTheRow(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(claude(100))
	c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
	a := h.next()
	c.c.Close()
	select {
	case <-a.withdrawn:
	case <-time.After(10 * time.Second):
		t.Fatal("the row stayed after the requester hung up")
	}
}

func TestAWarningChainIsAllowOnceWithTheWarningLevel(t *testing.T) {
	h := newHarness(t, 1, nil)
	c := h.dial(systemdRun())
	if err := c.bind(t, h.github, []byte("sid"), false); err != nil {
		t.Fatal(err)
	}
	done := c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
	a := h.next()
	if a.q.Grantable || a.q.Level != "warning" || !strings.HasPrefix(a.q.Text, "launched through systemd --user\n") {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{err: galleyask.ErrNobody}
	if err := wait(t, done); err == nil {
		t.Error("signed with nobody to ask")
	}
}

func TestTextEscapesControlAndBidiCharactersAndCutsEachArgument(t *testing.T) {
	if got := clean("a\x1b[2J\u202eb\n"); got != `a\u001b[2J\u202eb\u000a` {
		t.Errorf("got %q", got)
	}
	if got := clean(strings.Repeat("é", 1500)); len([]rune(got)) != maxArg {
		t.Errorf("cut to %d characters", len([]rune(got)))
	}
}

func FuzzNoAgentMessageCrashesTheParser(f *testing.F) {
	for _, name := range []string{"sshsig-git.bin", "sshsig-file.bin"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(k)
	sig, _ := host.Sign(rand.Reader, []byte("sid"))
	f.Add(bindMsg(host.PublicKey(), []byte("sid"), ssh.Marshal(sig), true))
	f.Add(userauthData([]byte("sid"), host.PublicKey(), host.PublicKey()))
	f.Add(userauthData([]byte("sid"), host.PublicKey(), nil))

	s := &Server{Log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	f.Fuzz(func(t *testing.T, b []byte) {
		c := &conn{s: s, r: &peer.Requester{}}
		if _, err := c.Extension("session-bind@openssh.com", b); err != nil && strings.HasPrefix(err.Error(), "panic") {
			t.Fatal(err)
		}
		c.binds = append(c.binds, &bind{hostKey: host.PublicKey(), sid: []byte("sid")})
		_, _ = c.classify(b)
		_, _ = parseUserauth(b)
		_, _ = parseSSHSIG(b)
	})
}
