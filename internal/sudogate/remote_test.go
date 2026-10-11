package sudogate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/internal/sudomsg"
	"golang.org/x/crypto/ssh"
)

func agentKey(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func edKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (h *harness) write(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func authorized(k ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(k))
}

// remote sets up remote mode with the listed keys and two host keys, which
// it returns.
func (h *harness) remote(listed ...ssh.Signer) []ssh.PublicKey {
	h.t.Helper()
	var lines []string
	for _, k := range listed {
		lines = append(lines, authorized(k.PublicKey()))
	}
	h.write("remote-keys", strings.Join(lines, ""))
	hosts := []ssh.PublicKey{edKey(h.t), edKey(h.t)}
	h.write("ssh_host_ed25519_key.pub", authorized(hosts[0]))
	h.write("ssh_host_rsa_key.pub", authorized(hosts[1]))
	return hosts
}

// remoteSudo is a client that has checked in as a remote sudo.
func (h *harness) remoteSudo(pid int) *client {
	h.t.Helper()
	c := h.dial(peer.Proc{UID: 0, Pid: pid, Start: uint64(pid) * 10, PPid: 200})
	c.send(frame(kindCheckIn, record('m', nil)))
	c.want(replyYes, "")
	return c
}

// sshd is a remote sudo's parent bash under sshd-session.
func sshd() []peer.Link {
	return []peer.Link{
		{Pid: 401, PPid: 400, Start: 401, UID: 1000, Comm: "bash", Cmdline: []string{"bash", "-c", "sudo x"}},
		{Pid: 400, PPid: 399, Start: 400, UID: 1000, Comm: "sshd-session", Cmdline: []string{"sshd-session: dan@notty"}},
		{Pid: 399, PPid: 1, Start: 399, UID: 0, Comm: "sshd-session", Cmdline: []string{"sshd-session: dan [priv]"}},
		{Pid: 1, Start: 1, Comm: "systemd", Cmdline: []string{"/sbin/init"}},
	}
}

func remoteCmd(unit string) sudoCmd {
	return sudoCmd{
		links: sshd(), program: bin + "systemctl", argv: []string{"systemctl", "restart", unit},
		info: []string{"runas_user=root", "cwd=/home/dan/src"}, userInfo: []string{"cwd=/home/dan"}, remote: true,
	}
}

type challengeReply struct {
	raw  []byte
	msg  *sudomsg.Message
	keys [][]byte
}

func (c *client) readMessage() challengeReply {
	c.t.Helper()
	var h [5]byte
	if _, err := io.ReadFull(c.c, h[:]); err != nil {
		c.t.Fatal(err)
	}
	if h[0] != replyMessage {
		c.t.Fatalf("got %q, not 'M'", h[0])
	}
	body := make([]byte, binary.BigEndian.Uint32(h[1:]))
	if _, err := io.ReadFull(c.c, body); err != nil {
		c.t.Fatal(err)
	}
	var head struct {
		Msg  []byte
		N    uint32
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(body, &head); err != nil {
		c.t.Fatal(err)
	}
	r := challengeReply{raw: head.Msg}
	rest := head.Rest
	for range head.N {
		var k struct {
			K    []byte
			Rest []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(rest, &k); err != nil {
			c.t.Fatal(err)
		}
		r.keys = append(r.keys, k.K)
		rest = k.Rest
	}
	if len(rest) != 0 {
		c.t.Fatalf("%d bytes after the keys", len(rest))
	}
	m, err := sudomsg.Parse(head.Msg)
	if err != nil {
		c.t.Fatal(err)
	}
	r.msg = m
	return r
}

func signed(t *testing.T, k ssh.Signer, msg []byte) []byte {
	t.Helper()
	sig, err := k.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	return frame(kindSign, record('p', k.PublicKey().Marshal()), record('g', ssh.Marshal(sig)))
}

func failed(reason string) []byte {
	return frame(kindSign, record('f', []byte(reason)))
}

func TestTheMessageNamesEveryHostKeyAndTheResolvedCommand(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	hosts := h.remote(k)
	c := h.remoteSudo(500)
	cmd := remoteCmd("foo")
	cmd.argv = []string{"restart-alias", "restart", "foo"}
	c.send(approval(cmd))
	r := c.readMessage()
	want := &sudomsg.Message{
		Nonce:    r.msg.Nonce,
		HostKeys: [][]byte{hosts[0].Marshal(), hosts[1].Marshal()},
		User:     "dan", RunAs: "root", Cwd: "/home/dan/src",
		Argv: []string{bin + "systemctl", "restart", "foo"},
	}
	if !reflect.DeepEqual(r.msg, want) {
		t.Errorf("got %+v\nwant %+v", r.msg, want)
	}
	if len(r.keys) != 1 || !bytes.Equal(r.keys[0], k.PublicKey().Marshal()) {
		t.Errorf("listed %x", r.keys)
	}
	h.none()

	c = h.remoteSudo(501)
	cmd.info = []string{"runas_user=lp"}
	c.send(approval(cmd))
	if m := c.readMessage().msg; m.Cwd != "/home/dan" || m.RunAs != "lp" {
		t.Errorf("without command_info cwd: %+v", m)
	}
}

func TestARemoteAIsClassifiedAsALocalOne(t *testing.T) {
	h := newHarness(t)
	h.remote(agentKey(t))
	for _, tc := range []struct {
		cmd     sudoCmd
		level   string
		reasons []string
	}{
		{remoteCmd("foo"), "", nil},
		{remoteCmd("sshd.service"), "danger", []string{"touches a unit that guards this machine"}},
		{func() sudoCmd { c := remoteCmd("foo"); c.links = cut; return c }(), "warning", []string{"the process chain was cut short"}},
		{func() sudoCmd {
			c := remoteCmd("foo")
			c.envp = []string{"PATH=/bin", "LD_PRELOAD=/tmp/x.so"}
			return c
		}(), "", []string{"LD_PRELOAD=/tmp/x.so"}},
		{func() sudoCmd { c := remoteCmd("foo"); c.program = "/home/dan/bin/systemctl"; return c }(), "danger", []string{"runs /home/dan/bin/systemctl, outside the root-owned directories"}},
	} {
		c := h.remoteSudo(500)
		c.send(approval(tc.cmd))
		m := c.readMessage().msg
		if m.Level != tc.level || strings.Join(m.Reasons, "|") != strings.Join(tc.reasons, "|") {
			t.Errorf("%s %q: level %q reasons %q", tc.cmd.program, tc.cmd.argv, m.Level, m.Reasons)
		}
	}
	h.none()
}

func TestASignatureFromAListedKeyIsYes(t *testing.T) {
	h := newHarness(t)
	other, k := agentKey(t), agentKey(t)
	h.remote(other, k)
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	r := c.readMessage()
	c.send(signed(t, k, r.raw))
	c.want(replyYes, "")
	log := h.log.String()
	for _, want := range []string{`"outcome":"allow"`, `"key":"` + ssh.FingerprintSHA256(k.PublicKey()) + `"`, `"runas":"root"`, `"cwd":"/home/dan/src"`} {
		if !strings.Contains(log, want) {
			t.Errorf("the journal lacks %s:\n%s", want, log)
		}
	}
}

func TestAnUnlistedKeyOrABadSignatureIsNo(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	h.remote(k)
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	r := c.readMessage()
	c.send(signed(t, agentKey(t), r.raw))
	c.want(replyNo, "frisket-sudo: not a listed key")

	c = h.remoteSudo(501)
	c.send(approval(remoteCmd("foo")))
	r = c.readMessage()
	c.send(signed(t, k, append(r.raw, 0)))
	c.want(replyNo, "signature did not verify")

	c = h.remoteSudo(502)
	c.send(approval(remoteCmd("foo")))
	c.readMessage()
	c.send(frame(kindSign, record('p', k.PublicKey().Marshal()), record('g', []byte("junk"))))
	c.want(replyNo, "signature did not verify")
}

func TestAnFRecordIsNoWithItsReason(t *testing.T) {
	h := newHarness(t)
	h.remote(agentKey(t))
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	c.readMessage()
	c.send(failed("no listed key in the forwarded agent"))
	c.want(replyNo, "frisket-sudo: no listed key in the forwarded agent")

	c = h.remoteSudo(501)
	c.send(approval(remoteCmd("foo")))
	c.readMessage()
	c.send(failed(strings.Repeat("x", maxMessage)))
	if k, m := c.read(); k != replyNo || len(m) != maxMessage || !strings.HasPrefix(m, "frisket-sudo: xxx") {
		t.Errorf("got %q %d bytes", k, len(m))
	}
}

func TestTheNonceIsSpentOnceAndDiesWithTheCheckIn(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	h.remote(k)
	c := h.remoteSudo(500)
	c.send(signed(t, k, []byte("anything")))
	c.want(replyNo, "")
	c.send(approval(remoteCmd("foo")))
	r := c.readMessage()
	c.send(failed("agent refused"))
	c.want(replyNo, "frisket-sudo: agent refused")
	c.send(signed(t, k, r.raw))
	c.want(replyNo, "")

	c = h.remoteSudo(501)
	c.send(approval(remoteCmd("foo")))
	r = c.readMessage()
	c.send(signed(t, k, r.raw))
	c.want(replyYes, "")
	c.send(signed(t, k, r.raw))
	c.want(replyNo, "")

	c = h.remoteSudo(502)
	c.send(signed(t, k, r.raw))
	c.want(replyNo, "")
	c.send(approval(remoteCmd("foo")))
	fresh := c.readMessage()
	if bytes.Equal(fresh.msg.Nonce, r.msg.Nonce) {
		t.Fatal("a nonce was made twice")
	}
	c.send(signed(t, k, r.raw))
	c.want(replyNo, "signature did not verify")
}

func TestRemoteModeIsOffWithNoParseableKeys(t *testing.T) {
	h := newHarness(t)
	h.remote()
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "remote sudo is off on this host")

	h.write("remote-keys", "# a comment\n\nnot a key\n")
	c = h.remoteSudo(501)
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "remote sudo is off on this host")
	if !strings.Contains(h.log.String(), `"msg":"remote key skipped","path":"`+filepath.Join(h.dir, "remote-keys")+`","line":3`) {
		t.Errorf("the skipped line is not journaled:\n%s", h.log.String())
	}

	k := agentKey(t)
	h.write("remote-keys", "not a key\n"+authorized(k.PublicKey()))
	c = h.remoteSudo(502)
	c.send(approval(remoteCmd("foo")))
	if r := c.readMessage(); len(r.keys) != 1 || !bytes.Equal(r.keys[0], k.PublicKey().Marshal()) {
		t.Errorf("listed %x", r.keys)
	}

	os.Remove(filepath.Join(h.dir, "ssh_host_ed25519_key.pub"))
	os.Remove(filepath.Join(h.dir, "ssh_host_rsa_key.pub"))
	c = h.remoteSudo(503)
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "no host keys in /etc/ssh")
	h.none()
}

func TestAVOnARemoteCheckInAndAnAWhoseModeDiffersFromItsCAreRefused(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	h.remote(k)
	c := h.remoteSudo(500)
	c.send(verified(true))
	c.want(replyNo, "")
	local := remoteCmd("foo")
	local.remote = false
	c.send(approval(local))
	c.want(replyNo, "")
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "")

	c = h.sudo(501)
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "")
	c.send(signed(t, k, []byte("x")))
	c.want(replyNo, "")

	c = h.sudo(502)
	c.send(approval(restart(claude(100), "foo")))
	h.next().reply <- password("pw", 0, 900)
	c.want(replyPassword, "pw")
	c.send(signed(t, k, []byte("x")))
	c.want(replyNo, "")
	h.none()
}

func TestARemoteCommandOverTheAgentLimitIsRefused(t *testing.T) {
	h := newHarness(t)
	h.remote(agentKey(t))
	c := h.remoteSudo(500)
	cmd := remoteCmd("foo")
	cmd.argv = append(cmd.argv, strings.Repeat("x", sudomsg.MaxSize))
	c.send(approval(cmd))
	c.want(replyNo, "command too long for the gate")
}

func TestARemoteMessageWhoseSignRequestIsOverTheAgentLimitIsRefused(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	h.remote(k)
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	base := len(c.readMessage().raw)
	room := sudomsg.MaxSize - (1 + 4 + len(k.PublicKey().Marshal()) + 4 + 4) - base - 4
	for _, tc := range []struct {
		n    int
		fits bool
	}{{room, true}, {room + 1, false}} {
		c := h.remoteSudo(501)
		cmd := remoteCmd("foo")
		cmd.argv = append(cmd.argv, strings.Repeat("x", tc.n))
		c.send(approval(cmd))
		if tc.fits {
			c.readMessage()
		} else {
			c.want(replyNo, "command too long for the gate")
		}
	}
}

func TestAnMReplyOverItsLimitIsNo(t *testing.T) {
	h := newHarness(t)
	h.remote()
	h.write("remote-keys", strings.Repeat(authorized(edKey(t)), 25000))
	c := h.remoteSudo(500)
	c.send(approval(remoteCmd("foo")))
	c.want(replyNo, "too many remote keys for the gate")
}

func TestAMalformedRemoteFrameClosesTheConnection(t *testing.T) {
	h := newHarness(t)
	k := agentKey(t)
	h.remote(k)
	for name, req := range map[string][]byte{
		"'m' with a body in 'C'": frame(kindCheckIn, record('m', []byte{1})),
		"'m' twice in 'C'":       frame(kindCheckIn, record('m', nil), record('m', nil)),
		"another record in 'C'":  frame(kindCheckIn, record('t', nil)),
		"version 1":              append([]byte(magic), 1, kindCheckIn, 0, 0, 0, 0),
	} {
		c := h.dial(peer.Proc{UID: 0, Pid: 500, Start: 5000})
		c.send(req)
		if n, err := c.c.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("%s: read %d, %v", name, n, err)
		}
	}
	sig := record('g', []byte("sig"))
	pub := record('p', k.PublicKey().Marshal())
	for name, req := range map[string][]byte{
		"'f' with 'p'":       frame(kindSign, record('f', []byte("x")), pub),
		"'p' without 'g'":    frame(kindSign, pub),
		"'g' twice":          frame(kindSign, pub, sig, sig),
		"an empty 'S'":       frame(kindSign),
		"an unprintable 'f'": frame(kindSign, record('f', []byte("a\nb"))),
		"a long 'f'":         frame(kindSign, record('f', bytes.Repeat([]byte("x"), maxMessage+1))),
		"'m' in 'A' twice":   frame(kindApproval, record('c', []byte("command=/bin/x")), record('m', nil), record('m', nil)),
	} {
		c := h.remoteSudo(501)
		if name != "'m' in 'A' twice" {
			c.send(approval(remoteCmd("foo")))
			c.readMessage()
		}
		c.send(req)
		if n, err := c.c.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("%s: read %d, %v", name, n, err)
		}
	}
}
