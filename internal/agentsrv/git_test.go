package agentsrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

type gitHarness struct {
	t        *testing.T
	dir      string
	path     string
	upstream string
	log      *lockedBuffer
	peerUID  atomic.Uint32
	key      ssh.PublicKey
}

func newGitHarness(t *testing.T) *gitHarness {
	t.Helper()
	dir, err := os.MkdirTemp("", "agentsrv-git")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &gitHarness{t: t, dir: dir, path: filepath.Join(dir, "agent"), upstream: filepath.Join(dir, "upstream"), log: &lockedBuffer{}}
	h.peerUID.Store(uid)

	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: k, Comment: "dan@test"}); err != nil {
		t.Fatal(err)
	}
	if h.key, err = ssh.NewPublicKey(k.Public()); err != nil {
		t.Fatal(err)
	}
	up := h.listen(h.upstream)
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = agent.ServeAgent(keyring, c)
			}()
		}
	}()

	g := &Git{
		Policy: "strict", UID: uid, Upstream: h.upstream,
		Log:  slog.New(slog.NewJSONHandler(h.log, nil)),
		cred: func(*net.UnixConn) (*unix.Ucred, error) { return &unix.Ucred{Pid: 4242, Uid: h.peerUID.Load()}, nil },
	}
	go g.Serve(h.listen(h.path))
	return h
}

func (h *gitHarness) listen(path string) *net.UnixListener {
	h.t.Helper()
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { ln.Close() })
	return ln
}

func (h *gitHarness) dial() *client {
	h.t.Helper()
	c, err := net.Dial("unix", h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return &client{agent.NewClient(c), c}
}

func sshsigData(t *testing.T, ns string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sshsig-"+ns+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGitPassesTheUpstreamIdentitiesThrough(t *testing.T) {
	h := newGitHarness(t)
	keys, err := h.dial().List()
	if err != nil || len(keys) != 1 || string(keys[0].Blob) != string(h.key.Marshal()) || keys[0].Comment != "dan@test" {
		t.Fatalf("got %v, %v", keys, err)
	}
	if !strings.Contains(h.log.String(), `"policy":"strict","pid":4242,"op":"identities"`) {
		t.Errorf("logged:\n%s", h.log.String())
	}
}

func TestGitSignsAGitSSHSIGThroughTheUpstream(t *testing.T) {
	h := newGitHarness(t)
	data := sshsigData(t, "git")
	sig, err := h.dial().SignWithFlags(h.key, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.key.Verify(data, sig); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
	if !strings.Contains(h.log.String(), `"op":"sign","namespace":"git","outcome":"forwarded"`) {
		t.Errorf("logged:\n%s", h.log.String())
	}
}

func TestGitRefusesEveryOtherSign(t *testing.T) {
	h := newGitHarness(t)
	for name, data := range map[string][]byte{
		"file":     sshsigData(t, "file"),
		"userauth": userauthData([]byte("sid"), h.key, nil),
		"garbage":  []byte("SSHSIG"),
	} {
		if _, err := h.dial().SignWithFlags(h.key, data, 0); err == nil {
			t.Errorf("%s was signed", name)
		}
	}
	log := h.log.String()
	if !strings.Contains(log, `"namespace":"file","outcome":"refuse"`) || !strings.Contains(log, `"reason":"not SSHSIG"`) || strings.Contains(log, "forwarded") {
		t.Errorf("logged:\n%s", log)
	}
}

func TestGitRefusesKeyManagementAndExtensions(t *testing.T) {
	h := newGitHarness(t)
	c := h.dial()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	for name, err := range map[string]error{
		"add":        c.Add(agent.AddedKey{PrivateKey: k}),
		"remove":     c.Remove(h.key),
		"remove all": c.RemoveAll(),
		"lock":       c.Lock([]byte("pw")),
		"unlock":     c.Unlock([]byte("pw")),
	} {
		if err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
	sig, _ := hostKey(t).Sign(rand.Reader, []byte("sid"))
	if _, err := c.Extension("session-bind@openssh.com", bindMsg(hostKey(t).PublicKey(), []byte("sid"), ssh.Marshal(sig), false)); err == nil {
		t.Error("session-bind succeeded")
	}
	if _, err := c.Extension("query", nil); err == nil {
		t.Error("query succeeded")
	}
	if keys, err := c.List(); err != nil || len(keys) != 1 {
		t.Errorf("the upstream's keys changed: %v, %v", keys, err)
	}
}

func TestGitRefusesAPeerWithAnotherUID(t *testing.T) {
	h := newGitHarness(t)
	h.peerUID.Store(0)
	if _, err := h.dial().List(); err == nil {
		t.Error("root's list was answered")
	}
	if !strings.Contains(h.log.String(), "peer uid 0 is not 1000") {
		t.Errorf("logged:\n%s", h.log.String())
	}
}

// hold replaces the upstream with one that reads a request and answers
// nothing, and says when the proxy hangs up on it.
func (h *gitHarness) hold(closeAfterRead bool) (received, hungUp <-chan struct{}) {
	h.t.Helper()
	ln := h.listen(h.upstream)
	got, gone := make(chan struct{}), make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var n [4]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(n[:]))); err != nil {
			return
		}
		close(got)
		if closeAfterRead {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		close(gone)
	}()
	return got, gone
}

func TestGitHangsUpOnTheUpstreamWhenTheRequesterDoes(t *testing.T) {
	h := newGitHarness(t)
	received, hungUp := h.hold(false)
	c := h.dial()
	done := c.signAsync(h.key, sshsigData(t, "git"))
	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("the sign never reached the upstream")
	}
	c.c.Close()
	select {
	case <-hungUp:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream connection stayed open after the requester hung up")
	}
	wait(t, done)
}

func TestGitFailsTheSignWhenTheUpstreamHangsUp(t *testing.T) {
	h := newGitHarness(t)
	h.hold(true)
	if err := wait(t, h.dial().signAsync(h.key, sshsigData(t, "git"))); err == nil {
		t.Error("signed with no upstream answer")
	}
	if !strings.Contains(h.log.String(), `"outcome":"fail"`) {
		t.Errorf("logged:\n%s", h.log.String())
	}
}
