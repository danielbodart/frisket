package sshroute

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/steer"
	"github.com/danielbodart/frisket/policy"
)

// routeAddr is where the sandbox believes the machine is. Nothing listens
// there: the fixture's Dial takes every upstream dial to the fake sshd.
var routeAddr = netip.MustParseAddrPort("10.0.0.5:22")

type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(raw, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func newSigner(t *testing.T) ssh.Signer {
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

func newECDSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authorized(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// sshd is a fake machine: an SSH server on loopback that knows a handful of
// commands, logs in one user by one key, and keeps every command it ran.
//
//	echo WORDS...  prints the words
//	cat            copies stdin to stdout
//	fail N         prints to stderr and exits N
//	wait           runs until it is signalled, and dies of the signal
//	both N         prints N bytes to stdout and N to stderr
type sshd struct {
	t        *testing.T
	ln       net.Listener
	hostKeys []ssh.Signer
	user     string
	key      ssh.PublicKey

	// configure changes how the machine logs a user in, and shell, if set,
	// serves each session channel in place of session: both are set before
	// it serves anything.
	configure func(*ssh.ServerConfig)
	shell     func(ch ssh.Channel, reqs <-chan *ssh.Request)

	mu    sync.Mutex
	ran   []string
	pty   int
	dial  int
	conns []net.Conn
}

// drop ends every connection the machine has, as a machine rebooting does:
// whatever was running says nothing more.
func (d *sshd) drop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
}

func newSSHD(t *testing.T, user string, key ssh.PublicKey, setup func(*sshd), hostKeys ...ssh.Signer) *sshd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &sshd{t: t, ln: ln, hostKeys: hostKeys, user: user, key: key}
	if setup != nil {
		setup(d)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go d.serve()
	return d
}

func (d *sshd) commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.ran...)
}

func (d *sshd) dials() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dial
}

func (d *sshd) serve() {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == d.user && bytes.Equal(k.Marshal(), d.key.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("not this key")
		},
	}
	for _, k := range d.hostKeys {
		cfg.AddHostKey(k)
	}
	if d.configure != nil {
		d.configure(cfg)
	}
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.mu.Lock()
		d.dial++
		d.conns = append(d.conns, c)
		d.mu.Unlock()
		go func() {
			defer c.Close()
			_, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				if nc.ChannelType() != "session" {
					_ = nc.Reject(ssh.UnknownChannelType, "no")
					continue
				}
				ch, creqs, err := nc.Accept()
				if err != nil {
					continue
				}
				if d.shell != nil {
					go d.shell(ch, creqs)
					continue
				}
				go d.session(ch, creqs)
			}
		}()
	}
}

func (d *sshd) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	signals := make(chan string, 1)
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			d.mu.Lock()
			d.pty++
			d.mu.Unlock()
			_ = r.Reply(true, nil)
		case "signal":
			var p struct{ Signal string }
			_ = ssh.Unmarshal(r.Payload, &p)
			select {
			case signals <- p.Signal:
			default:
			}
		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(r.Payload, &p); err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			d.mu.Lock()
			d.ran = append(d.ran, p.Command)
			d.mu.Unlock()
			_ = r.Reply(true, nil)
			go d.run(ch, p.Command, signals)
		default:
			_ = r.Reply(false, nil)
		}
	}
}

func exit(ch ssh.Channel, status uint32) {
	_ = ch.CloseWrite()
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	_ = ch.Close()
}

func (d *sshd) run(ch ssh.Channel, command string, signals <-chan string) {
	w := strings.Fields(command)
	switch {
	case len(w) > 0 && w[0] == "echo":
		fmt.Fprintln(ch, strings.Join(w[1:], " "))
		exit(ch, 0)
	case len(w) == 1 && w[0] == "cat":
		_, _ = io.Copy(ch, ch)
		exit(ch, 0)
	case len(w) == 2 && w[0] == "fail":
		var n uint32
		fmt.Sscan(w[1], &n)
		fmt.Fprintln(ch.Stderr(), "failing")
		exit(ch, n)
	case len(w) == 1 && w[0] == "wait":
		sig := <-signals
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Error      string
			Lang       string
		}{Signal: sig}))
		_ = ch.Close()
	case len(w) == 2 && w[0] == "both":
		var n int
		fmt.Sscan(w[1], &n)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = ch.Write(bytes.Repeat([]byte("o"), n)) }()
		go func() { defer wg.Done(); _, _ = ch.Stderr().Write(bytes.Repeat([]byte("e"), n)) }()
		wg.Wait()
		exit(ch, 0)
	default:
		fmt.Fprintln(ch.Stderr(), "command not found")
		exit(ch, 127)
	}
}

// keyring is an ssh-agent on a socket, as the user's would be.
func keyring(t *testing.T, keys ...ed25519.PrivateKey) string {
	t.Helper()
	ring := agent.NewKeyring()
	for _, k := range keys {
		if err := ring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	// Short: a socket's path is bounded at 108 bytes, and t.TempDir's
	// carries the test's whole name.
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = agent.ServeAgent(ring, c)
			}()
		}
	}()
	return path
}

// answers is an Asker that says what it is told to, and keeps the
// questions; block holds every answer until the asking side stops waiting.
type answers struct {
	mu    sync.Mutex
	yes   bool
	err   error
	block bool
	asked []intercept.Question
	gone  chan struct{}
}

func (a *answers) Ask(ctx context.Context, q intercept.Question) (bool, error) {
	a.mu.Lock()
	a.asked = append(a.asked, q)
	block, yes, err := a.block, a.yes, a.err
	a.mu.Unlock()
	if block {
		<-ctx.Done()
		if a.gone != nil {
			close(a.gone)
		}
		return false, ctx.Err()
	}
	return yes, err
}

func (a *answers) questions() []intercept.Question {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]intercept.Question(nil), a.asked...)
}

// fixture is a session with one SSH route to a fake machine, and a way for
// the sandbox to connect to it.
type fixture struct {
	t     *testing.T
	j     *journal
	ca    ssh.Signer
	h     *Handler
	sshd  *sshd
	route *Route
	ids   uint64
}

type options struct {
	route    func(*policy.SSHRoute)
	asker    intercept.Asker
	hostKeys []ssh.Signer
	// userKey is the user's key, in the agent and on the machine; nil is a
	// new one.
	userKey ed25519.PrivateKey
	// sshd sets the fake machine up before it serves.
	sshd func(*sshd)
}

func newFixture(t *testing.T, o options) *fixture {
	t.Helper()
	userKey := o.userKey
	if userKey == nil {
		var err error
		if _, userKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	userSigner, err := ssh.NewSignerFromKey(userKey)
	if err != nil {
		t.Fatal(err)
	}
	hostKeys := o.hostKeys
	if hostKeys == nil {
		hostKeys = []ssh.Signer{newSigner(t)}
	}
	d := newSSHD(t, "dan", userSigner.PublicKey(), o.sshd, hostKeys...)
	pr := policy.SSHRoute{
		Name:     "server",
		Address:  routeAddr.String(),
		User:     "dan",
		HostKeys: []string{authorized(hostKeys[len(hostKeys)-1].PublicKey())},
		Agent:    keyring(t, userKey),
		Exec: []policy.ExecRule{
			{Command: "echo **"},
			{Command: "cat"},
			{Command: "fail *"},
			{Command: "wait"},
			{Command: "both *"},
			{Command: "echo secret **", Refuse: true},
			{Command: "sudo **", Ask: true},
		},
	}
	if o.route != nil {
		o.route(&pr)
	}
	routes, err := Compile([]policy.SSHRoute{pr}, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := DeriveCA([]byte("a TLS CA's key, as PKCS#8"))
	if err != nil {
		t.Fatal(err)
	}
	j := &journal{}
	h, err := New(Config{
		Routes: routes,
		CA:     ca,
		Expiry: time.Now().Add(time.Hour),
		Asker:  o.asker,
		Policy: "p",
		Log:    slog.New(slog.NewJSONHandler(j, nil)),
		Dial: func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
			if to != routeAddr {
				return nil, fmt.Errorf("dialled %s, not the route's address", to)
			}
			var nd net.Dialer
			return nd.DialContext(ctx, "tcp", d.ln.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, j: j, ca: ca, h: h, sshd: d, route: routes[0]}
}

// pipe is a steered connection to orig: the sandbox's end, and the
// session's, as steer would hand it to the handler.
func (f *fixture) pipe(orig netip.AddrPort) (net.Conn, *steer.Conn) {
	f.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		f.t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		f.t.Fatal(err)
	}
	f.ids++
	return client, &steer.Conn{TCPConn: server.(*net.TCPConn), Session: "s1", ID: f.ids, Orig: orig}
}

// serve hands a steered connection to the handler, and returns the
// sandbox's end and a channel closed when the handler has finished with it.
func (f *fixture) serve(ctx context.Context) (net.Conn, <-chan struct{}) {
	client, sc := f.pipe(routeAddr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.h.ServeConn(ctx, sc)
	}()
	f.t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			f.t.Error("the handler did not finish with its connection")
		}
	})
	return client, done
}

// connect is the sandbox's ssh, trusting the session's CA alone, as its
// known_hosts says.
func (f *fixture) connect() *ssh.Client {
	f.t.Helper()
	return f.connectAs("agent")
}

// connectAs is connect, with the user name the client gives.
func (f *fixture) connectAs(user string) *ssh.Client {
	f.t.Helper()
	c, _ := f.serve(context.Background())
	checker := &ssh.CertChecker{
		IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
			return bytes.Equal(k.Marshal(), f.ca.PublicKey().Marshal())
		},
	}
	conn, chans, reqs, err := ssh.NewClientConn(c, "server:22", &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: checker.CheckHostKey,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	f.t.Cleanup(func() { _ = client.Close() })
	return client
}

// result is what the sandbox saw of one command.
type result struct {
	stdout, stderr string
	status         int
	signal         string
	err            error
}

func run(t *testing.T, c *ssh.Client, command string, stdin io.Reader) result {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr, s.Stdin = &out, &errb, stdin
	err = s.Run(command)
	r := result{stdout: out.String(), stderr: errb.String()}
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee):
		r.status, r.signal = ee.ExitStatus(), ee.Signal()
	case err != nil:
		r.err = err
	}
	return r
}

func (f *fixture) sshLines() []map[string]any {
	f.t.Helper()
	return f.j.lines(f.t, "ssh")
}

// runEager runs command as OpenSSH does: stdin sent as soon as the channel is
// open, before the exec is answered -- x/crypto's own Session waits for the
// answer first, and so never shows a preview anything.
func runEager(t *testing.T, c *ssh.Client, command string, stdin []byte) result {
	t.Helper()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	go func() {
		_, _ = ch.Write(stdin)
		_ = ch.CloseWrite()
	}()
	var r result
	statuses := make(chan result, 1)
	go func() {
		var s result
		for req := range reqs {
			switch req.Type {
			case "exit-status":
				var p struct{ Status uint32 }
				_ = ssh.Unmarshal(req.Payload, &p)
				s.status = int(p.Status)
			case "exit-signal":
				var p struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}
				_ = ssh.Unmarshal(req.Payload, &p)
				s.signal = p.Signal
			}
		}
		statuses <- s
	}()
	if ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{command})); !ok || err != nil {
		r.err = fmt.Errorf("exec refused: %v", err)
		return r
	}
	var out, errb bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&out, ch) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errb, ch.Stderr()) }()
	wg.Wait()
	_ = ch.Close()
	s := <-statuses
	s.stdout, s.stderr = out.String(), errb.String()
	return s
}

// wedge is an upstream connection that can go silent, as a machine powered
// off or cut off does: nothing it is sent arrives, nothing comes back, and
// nothing says it has gone -- until frisket closes it.
type wedge struct {
	net.Conn
	silent atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func (w *wedge) Read(p []byte) (int, error) {
	for {
		n, err := w.Conn.Read(p)
		if !w.silent.Load() {
			return n, err
		}
		if err != nil {
			<-w.closed
			return 0, net.ErrClosed
		}
	}
}

func (w *wedge) Write(p []byte) (int, error) {
	if w.silent.Load() {
		return len(p), nil
	}
	return w.Conn.Write(p)
}

func (w *wedge) Close() error {
	w.once.Do(func() { close(w.closed) })
	return w.Conn.Close()
}

// wedged makes every upstream the fixture dials from now on one that can go
// silent, and returns what silences them all.
func (f *fixture) wedged() (silence func()) {
	var mu sync.Mutex
	var all []*wedge
	dial := f.h.dial
	f.h.dial = func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
		c, err := dial(ctx, to)
		if err != nil {
			return nil, err
		}
		w := &wedge{Conn: c, closed: make(chan struct{})}
		mu.Lock()
		all = append(all, w)
		mu.Unlock()
		return w, nil
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		for _, w := range all {
			w.silent.Store(true)
		}
	}
}
