package sudogate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
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
	t         *testing.T
	dir       string
	g         *Gate
	path      string
	peers     chan peer.Proc
	questions chan *asked
	log       *lockedBuffer
	clock     atomic.Int64
	mu        sync.Mutex
	dead      map[proc]bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "sudogate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{
		t: t, dir: dir, path: filepath.Join(dir, "gate.sock"),
		peers: make(chan peer.Proc), questions: make(chan *asked, 16),
		log: &lockedBuffer{}, dead: map[proc]bool{},
	}
	h.clock.Store(int64(time.Hour))
	h.g = &Gate{
		User: "dan", Log: slog.New(slog.NewJSONHandler(h.log, nil)),
		who: func(*net.UnixConn) (peer.Proc, error) { return <-h.peers, nil },
		ask: h.ask,
		alive: func(pid int, start uint64) bool {
			h.mu.Lock()
			defer h.mu.Unlock()
			return !h.dead[proc{pid, start}]
		},
		now:        func() time.Duration { return time.Duration(h.clock.Load()) },
		remoteKeys: filepath.Join(dir, "remote-keys"),
		hostKeys:   filepath.Join(dir, "ssh_host_*_key.pub"),
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := h.g.init(); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go h.g.serve(c)
		}
	}()
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

func (h *harness) none() {
	h.t.Helper()
	select {
	case a := <-h.questions:
		h.t.Fatalf("asked %q", a.q.Title)
	case <-time.After(50 * time.Millisecond):
	}
}

func (h *harness) advance(d time.Duration) { h.clock.Add(int64(d)) }

type client struct {
	t *testing.T
	c *net.UnixConn
}

func (h *harness) dial(p peer.Proc) *client {
	h.t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.path, Net: "unix"})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	h.peers <- p
	return &client{t: h.t, c: c}
}

// sudo is a client that has checked in as the sudo with pid.
func (h *harness) sudo(pid int) *client {
	h.t.Helper()
	c := h.dial(peer.Proc{UID: 0, Pid: pid, Start: uint64(pid) * 10, PPid: 200})
	c.send(frame(kindCheckIn))
	c.want(replyYes, "")
	return c
}

func (c *client) send(b []byte) {
	c.t.Helper()
	if _, err := c.c.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) read() (byte, string) {
	c.t.Helper()
	var h [3]byte
	if _, err := io.ReadFull(c.c, h[:]); err != nil {
		c.t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(h[1:]))
	if _, err := io.ReadFull(c.c, msg); err != nil {
		c.t.Fatal(err)
	}
	return h[0], string(msg)
}

func (c *client) want(kind byte, msg string) {
	c.t.Helper()
	k, m := c.read()
	if k != kind || m != msg {
		c.t.Fatalf("got %q %q, want %q %q", k, m, kind, msg)
	}
}

func frame(kind byte, records ...[]byte) []byte {
	body := bytes.Join(records, nil)
	b := append([]byte(magic), version, kind)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

func record(tag byte, b []byte) []byte {
	r := binary.BigEndian.AppendUint32([]byte{tag}, uint32(len(b)))
	return append(r, b...)
}

func linkRecord(l peer.Link) []byte {
	be := binary.BigEndian
	b := be.AppendUint32(nil, uint32(l.Pid))
	b = be.AppendUint32(b, uint32(l.PPid))
	b = be.AppendUint64(b, l.Start)
	b = be.AppendUint32(b, uint32(l.UID))
	b = be.AppendUint32(b, l.TTY)
	b = be.AppendUint16(b, uint16(len(l.Comm)))
	b = append(b, l.Comm...)
	cmdline := strings.Join(l.Cmdline, "\x00")
	b = be.AppendUint16(b, uint16(len(cmdline)))
	return record('k', append(b, cmdline...))
}

// claude is sudo's parent bash under the claude with pid, under systemd.
func claude(pid int) []peer.Link {
	return []peer.Link{
		{Pid: pid + 1, PPid: pid, Start: 300, UID: 1000, Comm: "bash", Cmdline: []string{"bash", "-c", "sudo x"}},
		{Pid: pid, PPid: 1, Start: 200, UID: 1000, Comm: ".claude-unwrapp", Cmdline: []string{"claude"}},
		{Pid: 1, Start: 1, Comm: "systemd", Cmdline: []string{"/sbin/init"}},
	}
}

var cut = []peer.Link{{Pid: 201, PPid: 200, Start: 300, UID: 1000, Comm: "bash", Cmdline: []string{"bash"}}}

type sudoCmd struct {
	links    []peer.Link
	program  string
	argv     []string
	envp     []string
	settings []string
	info     []string
	userInfo []string
	remote   bool
}

func approval(s sudoCmd) []byte {
	var recs [][]byte
	for _, l := range s.links {
		recs = append(recs, linkRecord(l))
	}
	recs = append(recs, record('u', []byte("user=dan")), record('c', []byte("command="+s.program)))
	for _, u := range s.userInfo {
		recs = append(recs, record('u', []byte(u)))
	}
	for _, c := range s.info {
		recs = append(recs, record('c', []byte(c)))
	}
	if s.remote {
		recs = append(recs, record('m', nil))
	}
	for _, st := range s.settings {
		recs = append(recs, record('s', []byte(st)))
	}
	for _, a := range s.argv {
		recs = append(recs, record('a', []byte(a)))
	}
	for _, e := range s.envp {
		recs = append(recs, record('e', []byte(e)))
	}
	return frame(kindApproval, recs...)
}

func verified(ok bool) []byte {
	b := byte(0)
	if ok {
		b = 1
	}
	return frame(kindVerify, record('r', []byte{b}))
}

const bin = "/run/current-system/sw/bin/"

func restart(links []peer.Link, unit string) sudoCmd {
	return sudoCmd{links: links, program: bin + "systemctl", argv: []string{"systemctl", "restart", unit}}
}

func password(pw string, d time.Duration, galley int) answered {
	a := galleyask.Answer{Allowed: true, Password: []byte(pw), For: d}
	a.Galley.Pid, a.Galley.Start = galley, uint64(galley)*10
	return answered{a: a}
}

func allow(galley int) answered {
	a := galleyask.Answer{Allowed: true}
	a.Galley.Pid, a.Galley.Start = galley, uint64(galley)*10
	return answered{a: a}
}

// openWindow runs one sudo from the claude with pid through the dialog and
// a verified password, opening a 15 minute window pinned to galley.
func (h *harness) openWindow(pid, galley int) {
	h.t.Helper()
	c := h.sudo(pid + 50)
	c.send(approval(restart(claude(pid), "open")))
	a := h.next()
	a.reply <- password("hunter2", 15*time.Minute, galley)
	c.want(replyPassword, "hunter2")
	c.send(verified(true))
	if k, m := c.read(); k != replyYes || !strings.Contains(m, "password remembered for this claude until") {
		h.t.Fatalf("got %q %q", k, m)
	}
	c.c.Close()
}

func TestOnlyARootPeerChecksIn(t *testing.T) {
	h := newHarness(t)
	c := h.dial(peer.Proc{UID: 1000, Pid: 500, Start: 5000})
	c.send(frame(kindCheckIn))
	c.want(replyNo, "")
	if h.g.checkedIn(proc{500, 5000}) {
		t.Error("a non-root peer checked in")
	}
	h.sudo(500)
	if !h.g.checkedIn(proc{500, 5000}) {
		t.Error("a root peer did not check in")
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for range 5000 {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("never")
}

func TestGIsYesOnlyWhenThePeersParentIsALiveCheckIn(t *testing.T) {
	h := newHarness(t)
	s := h.sudo(500)
	g := func(p peer.Proc) byte {
		c := h.dial(p)
		c.send(frame(kindParent))
		k, _ := c.read()
		return k
	}
	if k := g(peer.Proc{UID: 0, Pid: 600, PPid: 500, PPidStart: 5000}); k != replyYes {
		t.Errorf("the check-in's child got %q", k)
	}
	if k := g(peer.Proc{UID: 1000, Pid: 600, PPid: 500, PPidStart: 5000}); k != replyNo {
		t.Errorf("a non-root peer got %q", k)
	}
	if k := g(peer.Proc{UID: 0, Pid: 600, PPid: 501, PPidStart: 5010}); k != replyNo {
		t.Errorf("a peer whose parent never checked in got %q", k)
	}
	if k := g(peer.Proc{UID: 0, Pid: 600, PPid: 500, PPidStart: 4999}); k != replyNo {
		t.Errorf("a peer whose parent is a reused pid got %q", k)
	}
	s.c.Close()
	eventually(t, func() bool { return !h.g.checkedIn(proc{500, 5000}) })
	if k := g(peer.Proc{UID: 0, Pid: 600, PPid: 500, PPidStart: 5000}); k != replyNo {
		t.Errorf("a closed check-in's child got %q", k)
	}
}

func TestAnAOrVOffACheckInConnectionIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, req := range [][]byte{approval(restart(claude(100), "foo")), verified(true)} {
		c := h.dial(peer.Proc{UID: 0, Pid: 500, Start: 5000})
		c.send(req)
		c.want(replyNo, "")
	}
	c := h.sudo(501)
	c.send(verified(true))
	c.want(replyNo, "")
	c.send(frame(kindCheckIn))
	c.want(replyNo, "")
	h.none()

	c = h.sudo(502)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- answered{}
	c.want(replyNo, "cancelled")
	c.send(approval(restart(claude(100), "foo")))
	c.want(replyNo, "")
	h.none()
}

func TestAWrongPasswordBringsTheDialogBack(t *testing.T) {
	h := newHarness(t)
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	a := h.next()
	if !a.q.Password || !a.q.Grantable || strings.Contains(a.q.Text, "Wrong password") {
		t.Fatalf("first dialog %+v", a.q)
	}
	a.reply <- password("hunter2", 2*time.Hour, 900)
	c.want(replyPassword, "hunter2")
	c.send(verified(false))
	a = h.next()
	if !a.q.Password || !strings.HasPrefix(a.q.Text, "Wrong password, try again\n\n") {
		t.Fatalf("second dialog %+v", a.q)
	}
	a.reply <- password("correct", 15*time.Minute, 900)
	c.want(replyPassword, "correct")
	c.send(verified(true))
	if k, m := c.read(); k != replyYes || !strings.HasPrefix(m, "frisket-sudo: password remembered for this claude until ") {
		t.Fatalf("got %q %q", k, m)
	}
	if w := h.g.windows[proc{100, 200}]; w.until != time.Hour+15*time.Minute {
		t.Errorf("the window ends at %v", w.until)
	}
	if strings.Contains(h.log.String(), "hunter2") || strings.Contains(h.log.String(), "correct") {
		t.Errorf("logged a password:\n%s", h.log.String())
	}
}

func TestAnEmptyOrUnsendablePasswordBringsTheDialogBack(t *testing.T) {
	h := newHarness(t)
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	for _, pw := range []string{"", "a\nb", "a\x00b", strings.Repeat("x", maxPassword+1)} {
		h.next().reply <- password(pw, 0, 900)
	}
	h.next().reply <- password("pw", 0, 900)
	c.want(replyPassword, "pw")
}

func TestCancelAndNobodyAreRefusals(t *testing.T) {
	h := newHarness(t)
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- answered{}
	c.want(replyNo, "cancelled")
	c = h.sudo(501)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- answered{err: galleyask.ErrNobody}
	c.want(replyNo, "no one to ask; use a terminal")
}

func TestHangUpWithdrawsTheRowAndEndsTheCheckIn(t *testing.T) {
	h := newHarness(t)
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	a := h.next()
	c.c.Close()
	select {
	case <-a.withdrawn:
	case <-time.After(10 * time.Second):
		t.Fatal("the row was never withdrawn")
	}
	eventually(t, func() bool { return !h.g.checkedIn(proc{500, 5000}) })
}

func TestANewWindowTurnsTheClaudesWaitingDialogsIntoQuestions(t *testing.T) {
	h := newHarness(t)
	rows := map[string]*asked{}
	post := func(pid int, cmd sudoCmd) *client {
		c := h.sudo(pid)
		c.send(approval(cmd))
		a := h.next()
		rows[a.q.Title] = a
		return c
	}
	opener := post(500, restart(claude(100), "a"))
	same := post(501, restart(claude(100), "b"))
	post(502, restart(claude(300), "c"))
	post(503, restart(claude(100), "sshd.service"))

	rows["sudo systemctl restart a"].reply <- password("pw", 15*time.Minute, 900)
	opener.want(replyPassword, "pw")
	opener.send(verified(true))
	opener.read()

	<-rows["sudo systemctl restart b"].withdrawn
	q := h.next()
	if q.q.Title != "sudo systemctl restart b" || q.q.Password || q.q.Grantable {
		t.Fatalf("posted again as %+v", q.q)
	}
	q.reply <- allow(900)
	same.want(replyYes, "")
	h.none()
	for _, title := range []string{"sudo systemctl restart c", "sudo systemctl restart sshd.service"} {
		select {
		case <-rows[title].withdrawn:
			t.Errorf("%s was withdrawn", title)
		default:
		}
	}
}

func TestOnlyAVerifiedDialogPasswordOpensAWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(h *harness)
	}{
		{"a failed verify", func(h *harness) {
			c := h.sudo(500)
			c.send(approval(restart(claude(100), "foo")))
			h.next().reply <- password("pw", 15*time.Minute, 900)
			c.want(replyPassword, "pw")
			c.send(verified(false))
			h.next().reply <- answered{}
			c.want(replyNo, "cancelled")
		}},
		{"a danger dialog", func(h *harness) {
			c := h.sudo(500)
			c.send(approval(restart(claude(100), "frisket.service")))
			h.next().reply <- password("pw", 15*time.Minute, 900)
			c.want(replyPassword, "pw")
			c.send(verified(true))
			c.want(replyYes, "")
		}},
		{"a Cut chain", func(h *harness) {
			c := h.sudo(500)
			c.send(approval(restart(cut, "foo")))
			h.next().reply <- password("pw", 15*time.Minute, 900)
			c.want(replyPassword, "pw")
			c.send(verified(true))
			c.want(replyYes, "")
		}},
		{"a time of 0", func(h *harness) {
			c := h.sudo(500)
			c.send(approval(restart(claude(100), "foo")))
			h.next().reply <- password("pw", 0, 900)
			c.want(replyPassword, "pw")
			c.send(verified(true))
			c.want(replyYes, "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.run(h)
			if len(h.g.windows) != 0 {
				t.Errorf("windows %v", h.g.windows)
			}
		})
	}
	t.Run("a question's Allow", func(t *testing.T) {
		h := newHarness(t)
		h.openWindow(100, 900)
		before := h.g.windows[proc{100, 200}]
		h.advance(time.Minute)
		c := h.sudo(500)
		c.send(approval(restart(claude(100), "foo")))
		h.next().reply <- allow(900)
		c.want(replyYes, "")
		if after := h.g.windows[proc{100, 200}]; after != before || len(h.g.windows) != 1 {
			t.Errorf("window %v became %v", before, after)
		}
	})
}

func TestADangerOrCutDialogHasNoTimeField(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		cmd   sudoCmd
		level string
	}{
		{restart(claude(100), "sshd.service"), "danger"},
		{restart(cut, "foo"), "warning"},
		{restart(cut, "galley.service"), "danger"},
	} {
		c := h.sudo(500)
		c.send(approval(tc.cmd))
		a := h.next()
		if !a.q.Password || a.q.Grantable || a.q.Level != tc.level {
			t.Errorf("%v: %+v", tc.cmd.argv, a.q)
		}
		a.reply <- answered{}
		c.read()
	}
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	if a := h.next(); !a.q.Password || !a.q.Grantable || a.q.Level != "normal" {
		t.Errorf("a normal dialog %+v", a.q)
	}
}

func TestTheWindowCountsOnlyAnswersFromThePinnedGalley(t *testing.T) {
	h := newHarness(t)
	h.openWindow(100, 900)
	before := h.g.windows[proc{100, 200}]
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	a := h.next()
	if a.q.Password {
		t.Fatalf("inside the window %+v", a.q)
	}
	a.reply <- allow(901)
	c.want(replyNo, "refused")
	if h.g.windows[proc{100, 200}] != before {
		t.Error("the window changed")
	}
	if log := h.log.String(); !strings.Contains(log, `"source":"not the pinned galley"`) || !strings.Contains(log, `"pin_pid":900`) {
		t.Errorf("the journal does not name the pin:\n%s", h.log.String())
	}
	c = h.sudo(501)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- allow(900)
	c.want(replyYes, "")
	c = h.sudo(502)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- answered{}
	c.want(replyNo, "refused")
}

func TestTheWindowEndsWithItsGalleyProcessItsAnchorOrItsTime(t *testing.T) {
	asks := func(h *harness, links []peer.Link) galleyask.Question {
		c := h.sudo(500)
		c.send(approval(restart(links, "foo")))
		a := h.next()
		a.reply <- answered{}
		c.read()
		return a.q
	}
	h := newHarness(t)
	h.openWindow(100, 900)
	if q := asks(h, claude(100)); q.Password {
		t.Fatal("the window is not open")
	}
	reused := claude(100)
	reused[1].Start = 250
	reused[0].Start = 300
	if q := asks(h, reused); !q.Password {
		t.Error("a reused anchor pid is inside the window")
	}
	h.advance(15 * time.Minute)
	if q := asks(h, claude(100)); !q.Password {
		t.Error("the window outlived its time")
	}

	h = newHarness(t)
	h.openWindow(100, 900)
	h.mu.Lock()
	h.dead[proc{900, 9000}] = true
	h.mu.Unlock()
	if q := asks(h, claude(100)); !q.Password {
		t.Error("the window outlived its galley process")
	}
}

func TestTheDialogShowsTheResolvedCommandAndTheChainInItsTable(t *testing.T) {
	h := newHarness(t)
	c := h.sudo(500)
	c.send(approval(restart(claude(100), "foo")))
	a := h.next()
	rows := [][]string{{"100", "claude"}, {"101", "bash -c sudo x"}}
	if a.q.Title != "sudo systemctl restart foo" || a.q.Text != "/run/current-system/sw/bin/systemctl restart foo" ||
		!reflect.DeepEqual(a.q.Chain.Rows, rows) || a.q.Chain.Summary != "claude ← sudo x" {
		t.Errorf("got %q %q %+v", a.q.Title, a.q.Text, a.q.Chain)
	}
	a.reply <- answered{}
	c.read()
	c = h.sudo(501)
	c.send(approval(restart(claude(100), "sshd.service")))
	a = h.next()
	want := "touches a unit that guards this machine\n\n/run/current-system/sw/bin/systemctl restart sshd.service"
	if a.q.Text != want {
		t.Errorf("got %q", a.q.Text)
	}
	a.reply <- answered{}
	c.read()
}

func (h *harness) describe(cmd sudoCmd) *sudoReq {
	h.t.Helper()
	req, err := readRequest(bytes.NewReader(approval(cmd)))
	if err != nil {
		h.t.Fatal(err)
	}
	a, err := h.g.describe(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

func TestTheGuardUnitsAreDanger(t *testing.T) {
	h := newHarness(t)
	for _, argv := range [][]string{
		{"systemctl", "stop", "frisket.service"},
		{"systemctl", "status", "galley"},
		{"systemctl", "restart", "sshd.service"},
		{"systemctl", "--user", "stop", "nftables.service"},
		{"systemctl", "start", "debug-shell.service"},
	} {
		a := h.describe(sudoCmd{links: claude(100), program: bin + "systemctl", argv: argv})
		if len(a.danger) != 1 || a.danger[0] != "touches a unit that guards this machine" {
			t.Errorf("%q: %q", argv, a.danger)
		}
	}
	if a := h.describe(restart(claude(100), "foo")); len(a.danger) != 0 {
		t.Errorf("restart foo: %q", a.danger)
	}
}

func TestAProgramOutsideTheRootOwnedDirsIsDanger(t *testing.T) {
	for _, p := range []string{
		bin + "systemctl", "/run/wrappers/bin/mount", "/etc/profiles/per-user/dan/bin/make-usb",
	} {
		if !rootOwned(p, "dan") {
			t.Errorf("%s is not root-owned", p)
		}
	}
	for _, p := range []string{
		"systemctl", bin + "../../../home/dan/bin/cat", "/run/current-system/sw/./bin/ls", "/run/current-system/sw/bin//ls",
		bin + "sub/ls", "/nix/store/abc-coreutils/bin/ls", "/home/dan/bin/systemctl",
		"/etc/profiles/per-user/bob/bin/ls", "/run/current-system/sw/bin/", bin,
	} {
		if rootOwned(p, "dan") {
			t.Errorf("%s is root-owned", p)
		}
	}
	rapid.Check(t, func(t *rapid.T) {
		p := rapid.StringOfN(rapid.SampledFrom([]rune("/.ab")), 0, 40, -1).Draw(t, "rest")
		p = rapid.SampledFrom([]string{bin, "/run/wrappers/bin/", "/etc/profiles/per-user/dan/bin/", ""}).Draw(t, "dir") + p
		if filepath.Clean(p) != p && rootOwned(p, "dan") {
			t.Fatalf("%q is not clean and passed", p)
		}
	})
	h := newHarness(t)
	a := h.describe(sudoCmd{links: claude(100), program: "/home/dan/bin/systemctl", argv: []string{"systemctl", "restart", "foo"}})
	if len(a.danger) != 1 || a.danger[0] != "runs /home/dan/bin/systemctl, outside the root-owned directories" {
		t.Errorf("got %q", a.danger)
	}
}

func TestShellAndEnvWrappersAreClassifiedByEveryInnerCommand(t *testing.T) {
	h := newHarness(t)
	const guard = "touches a unit that guards this machine"
	for _, tc := range []struct {
		cmd  sudoCmd
		want []string
	}{
		{sudoCmd{program: bin + "sh", argv: []string{"sh", "-c", "systemctl stop sshd"}}, []string{guard}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-c", "ls && /bin/systemctl status galley.service"}}, []string{guard}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-c", "ls; id"}}, nil},
		{sudoCmd{program: bin + "sh", argv: []string{"sh", "-c", "$(printf x)"}}, []string{unreadable}},
		{sudoCmd{program: bin + "env", argv: []string{"env", "systemctl", "stop", "frisket"}}, []string{guard}},
		{sudoCmd{program: bin + "env", argv: []string{"env", "FOO=1", "id"}}, []string{unreadable}},
		{sudoCmd{program: bin + "env", argv: []string{"env", "-i", "id"}}, []string{unreadable}},
		{sudoCmd{program: bin + "env", argv: []string{"env", "sh", "-c", "env systemctl stop sshd"}}, []string{guard}},
		{sudoCmd{program: bin + "bash", argv: []string{"-bash", "-c", `systemctl stop sshd\.service`}, settings: []string{"login_shell=true"}}, []string{guard}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-c", `ls\ \-l`}, settings: []string{"run_shell=true"}}, nil},
		{sudoCmd{program: bin + "zsh", argv: []string{"zsh", "-c", `systemctl\ stop\ sshd`}, settings: []string{"run_shell=true"}}, []string{guard}},
		{sudoCmd{program: bin + "zsh", argv: []string{"zsh"}, settings: []string{"run_shell=true"}}, []string{unreadable}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-ec", "systemctl stop sshd"}}, []string{unreadable}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-x", "-c", "systemctl stop sshd"}}, []string{unreadable}},
		{sudoCmd{program: bin + "sh", argv: []string{"sh", "-c", "--", "systemctl stop sshd"}}, []string{unreadable}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "-c", `"$0" stop sshd`, "systemctl"}}, []string{unreadable}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash"}}, []string{unreadable}},
		{sudoCmd{program: bin + "bash", argv: []string{"bash", "/tmp/x.sh"}}, []string{unreadable}},
		{sudoCmd{program: bin + "env", argv: []string{"env", "bash", "-lc", "id"}}, []string{unreadable}},
		{sudoCmd{program: bin + "dash", argv: []string{"dash", "-c", "systemctl stop sshd"}}, []string{guard}},
		{sudoCmd{program: bin + "ksh", argv: []string{"ksh", "-c", "id"}}, nil},
		{sudoCmd{program: bin + "fish", argv: []string{"fish", "-c", "systemctl stop sshd"}}, []string{guard}},
		{sudoCmd{program: bin + "mksh", argv: []string{"mksh", "-c", "id", "arg0"}}, []string{unreadable}},
		{sudoCmd{program: bin + "zsh", argv: []string{"zsh", "-c"}}, []string{unreadable}},
		{sudoCmd{program: bin + "dash", argv: []string{"dash", "-s"}}, []string{unreadable}},
		{sudoCmd{program: bin + "fish", argv: []string{"fish", "/tmp/x.fish"}}, []string{unreadable}},
		{sudoCmd{program: bin + "ksh", argv: []string{"ksh", "-c", "-x"}}, []string{unreadable}},
	} {
		tc.cmd.links = claude(100)
		a := h.describe(tc.cmd)
		if strings.Join(a.danger, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: got %q, want %q", tc.cmd.argv, a.danger, tc.want)
		}
	}
}

func TestTheRequestLimitCountsTheHeaderAsThePluginDoes(t *testing.T) {
	fits := frame(kindApproval, record('e', make([]byte, maxRequest-10-5)))
	if _, err := readRequest(bytes.NewReader(fits)); err != nil {
		t.Errorf("a request of exactly %d bytes: %v", len(fits), err)
	}
	over := frame(kindApproval, record('e', make([]byte, maxRequest-10-4)))
	if _, err := readRequest(bytes.NewReader(over)); err == nil {
		t.Errorf("a request of %d bytes was read", len(over))
	}
}

func TestALinksCmdlineHasNoTrailingNulAndItsCommAtMost64Bytes(t *testing.T) {
	l := peer.Link{Pid: 7, Comm: "bash", Cmdline: []string{"a", ""}}
	req, err := readRequest(bytes.NewReader(frame(kindApproval, linkRecord(l))))
	if err != nil || strings.Join(req.links[0].Cmdline, "|") != "a|" {
		t.Errorf("got %v %q", err, req.links[0].Cmdline)
	}
	l.Comm = strings.Repeat("c", 65)
	if _, err := readRequest(bytes.NewReader(frame(kindApproval, linkRecord(l)))); err == nil {
		t.Error("a comm of 65 bytes was read")
	}
}

func TestEnvironmentVariablesAreTextLines(t *testing.T) {
	h := newHarness(t)
	cmd := restart(claude(100), "foo")
	cmd.envp = []string{"HOME=/root", "PATH=/bin", "LC_ALL=C", "SUDO_USER=dan", "TERM=xterm", "LESSOPEN=|x %s", "LD_PRELOAD=/tmp/x.so", "FOO=" + strings.Repeat("y", 2000)}
	a := h.describe(cmd)
	if len(a.env) != 3 || a.env[0] != "LESSOPEN=|x %s" || a.env[1] != "LD_PRELOAD=/tmp/x.so" ||
		!strings.HasPrefix(a.env[2], "FOO=y") || len(a.env[2]) != 1000 {
		t.Errorf("got %q", a.env)
	}
	if len(a.danger) != 0 {
		t.Errorf("danger %q", a.danger)
	}
	if q := a.question(false, false); !strings.Contains(q.Text, "\nLESSOPEN=|x %s\nLD_PRELOAD=/tmp/x.so\nFOO=") || q.Level != "normal" {
		t.Errorf("text %q", q.Text)
	}
}

func FuzzNoRequestCrashesTheGate(f *testing.F) {
	links := claude(100)
	f.Add(frame(kindCheckIn))
	f.Add(frame(kindParent))
	f.Add(append(frame(kindCheckIn), approval(restart(links, "foo"))...))
	f.Add(append(append(frame(kindCheckIn), approval(restart(links, "sshd"))...), verified(true)...))
	f.Add(append(frame(kindCheckIn), verified(false)...))
	f.Add(approval(restart(links, "foo")))
	f.Add(verified(true))
	f.Add(append(frame(kindCheckIn), frame(kindApproval, record('k', []byte{1, 2, 3}), record('t', nil))...))
	f.Add(append(frame(kindCheckIn), frame(kindApproval, record('c', []byte("command=x")), record('a', nil))...))
	f.Add([]byte("FSUD\x02A\xff\xff\xff\xff"))
	remote := remoteCmd("foo")
	remoteCheckIn := frame(kindCheckIn, record('m', nil))
	f.Add(append(remoteCheckIn, approval(remote)...))
	f.Add(append(append(remoteCheckIn, approval(remote)...), frame(kindSign, record('f', []byte("refused")))...))
	f.Add(append(append(remoteCheckIn, approval(remote)...), frame(kindSign, record('p', []byte("p")), record('g', []byte("g")))...))
	f.Add(append(append(remoteCheckIn, approval(restart(links, "foo"))...), verified(true)...))
	f.Add(append(frame(kindCheckIn), frame(kindSign, record('f', nil))...))
	dir := f.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		f.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "remote-keys"), ssh.MarshalAuthorizedKey(pub), 0o644)
	os.WriteFile(filepath.Join(dir, "ssh_host_ecdsa_key.pub"), ssh.MarshalAuthorizedKey(pub), 0o644)
	f.Fuzz(func(t *testing.T, b []byte) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		gc, err := net.FileConn(os.NewFile(uintptr(fds[0]), "gate"))
		if err != nil {
			t.Fatal(err)
		}
		defer gc.Close()
		cc, err := net.FileConn(os.NewFile(uintptr(fds[1]), "client"))
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		go func() {
			defer cc.(*net.UnixConn).CloseWrite()
			for len(b) >= 10 {
				n := 10 + uint64(binary.BigEndian.Uint32(b[6:10]))
				if n > uint64(len(b)) {
					break
				}
				if _, err := cc.Write(b[:n]); err != nil {
					return
				}
				b = b[n:]
				var h [5]byte
				if _, err := io.ReadFull(cc, h[:3]); err != nil {
					return
				}
				size := int64(binary.BigEndian.Uint16(h[1:3]))
				if h[0] == replyMessage {
					if _, err := io.ReadFull(cc, h[3:]); err != nil {
						return
					}
					size = int64(binary.BigEndian.Uint32(h[1:]))
				}
				if _, err := io.CopyN(io.Discard, cc, size); err != nil {
					return
				}
			}
			cc.Write(b)
		}()
		log := &lockedBuffer{}
		g := &Gate{
			User: "dan", Log: slog.New(slog.NewJSONHandler(log, nil)),
			ask: func(context.Context, string, galleyask.Question) (galleyask.Answer, error) {
				return password("pw", time.Minute, 900).a, nil
			},
			alive:      func(int, uint64) bool { return true },
			now:        func() time.Duration { return time.Hour },
			remoteKeys: filepath.Join(dir, "remote-keys"),
			hostKeys:   filepath.Join(dir, "ssh_host_*_key.pub"),
		}
		if err := g.init(); err != nil {
			t.Fatal(err)
		}
		(&session{g: g, c: gc.(*net.UnixConn), peer: peer.Proc{Pid: 500, Start: 5000, PPid: 500, PPidStart: 5000}}).run()
		if strings.Contains(log.String(), "panicked") {
			t.Fatal(log.String())
		}
	})
}
