package agentsrv

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/sudomsg"
	"golang.org/x/crypto/ssh"
)

func sudoMessage(t *testing.T, level string, reasons []string, hosts ...ssh.PublicKey) []byte {
	t.Helper()
	m := &sudomsg.Message{
		Nonce: bytes.Repeat([]byte{7}, sudomsg.NonceSize),
		User:  "dan", RunAs: "root", Cwd: "/home/dan",
		Argv:  []string{"/run/current-system/sw/bin/systemctl", "stop", "sshd.service"},
		Level: level, Reasons: reasons,
	}
	for _, h := range hosts {
		m.HostKeys = append(m.HostKeys, h.Marshal())
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// forwarded is claude running ssh -A to host, whose forwarded channel
// connects to the agent.
func (h *harness) forwarded(host ssh.Signer) *client {
	h.t.Helper()
	c := h.dial(claude(100))
	if err := c.bind(h.t, host, []byte("sid"), true); err != nil {
		h.t.Fatal(err)
	}
	return c
}

func TestARemoteSudoSignIsAskedOnlyWhenForwardedAndBoundToOneOfItsHostKeys(t *testing.T) {
	h := newHarness(t, 1, nil)
	msg := sudoMessage(t, "", nil, hostKey(t).PublicKey(), h.server.PublicKey())

	refused := func(name string, c *client) {
		t.Helper()
		if err := wait(t, c.signAsync(h.key(0), msg)); err == nil {
			t.Errorf("%s: signed", name)
		}
		h.nothingAsked()
	}
	refused("unbound", h.dial(claude(100)))
	direct := h.dial(claude(100))
	if err := direct.bind(t, h.server, []byte("sid"), false); err != nil {
		t.Fatal(err)
	}
	refused("a direct bind", direct)
	refused("bound to another host", h.forwarded(h.github))
	lastDirect := h.forwarded(h.server)
	if err := lastDirect.bind(t, h.server, []byte("onward"), false); err != nil {
		t.Fatal(err)
	}
	refused("a forwarded bind followed by a direct one", lastDirect)
	if !strings.Contains(h.log.String(), "remote sudo bound to "+ssh.FingerprintSHA256(h.github.PublicKey())) {
		t.Errorf("the journal lacks the reason:\n%s", h.log.String())
	}

	done := h.forwarded(h.server).signAsync(h.key(0), msg)
	h.next().reply <- answered{a: galleyask.Answer{Allowed: true}}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

func appendString(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}

func TestARemoteSudoMessageThatDoesNotParseStrictlyIsRefused(t *testing.T) {
	h := newHarness(t, 1, nil)
	h.frisket.Store(true)
	host := string(h.server.PublicKey().Marshal())
	build := func(nonce string, hosts []string, level string, extra string) []byte {
		b := appendString(nil, sudomsg.Magic)
		b = appendString(b, nonce)
		b = binary.BigEndian.AppendUint32(b, uint32(len(hosts)))
		for _, k := range hosts {
			b = appendString(b, k)
		}
		for _, s := range []string{"dan", "root", "/"} {
			b = appendString(b, s)
		}
		b = binary.BigEndian.AppendUint32(b, 1)
		b = appendString(b, "/bin/id")
		b = appendString(b, level)
		b = binary.BigEndian.AppendUint32(b, 0)
		return append(b, extra...)
	}
	nonce := strings.Repeat("n", sudomsg.NonceSize)
	good := build(nonce, []string{host}, "", "")
	for name, msg := range map[string][]byte{
		"a short nonce":    build(nonce[1:], []string{host}, "", ""),
		"no host keys":     build(nonce, nil, "", ""),
		"a bad key blob":   build(nonce, []string{host, "junk"}, "", ""),
		"an unknown level": build(nonce, []string{host}, "normal", ""),
		"a missing field":  good[:len(good)-4],
		"trailing bytes":   build(nonce, []string{host}, "", "x"),
	} {
		if err := wait(t, h.forwarded(h.server).signAsync(h.key(0), msg)); err == nil {
			t.Errorf("%s: signed", name)
		}
		h.nothingAsked()
	}
	done := h.forwarded(h.server).signAsync(h.key(0), good)
	h.next().reply <- answered{}
	if err := wait(t, done); err == nil {
		t.Error("a refused remote sudo was signed")
	}
}

func TestARemoteSudoSignIsNeverSilentNorGranted(t *testing.T) {
	h := newHarness(t, 1, nil)
	msg := sudoMessage(t, "", nil, h.github.PublicKey())
	ask := func(name string, c *client, answer answered) {
		t.Helper()
		done := c.signAsync(h.key(0), msg)
		a := h.next()
		if a.q.Grantable || a.q.Password || a.q.Allow != "Allow" {
			t.Errorf("%s: asked %+v", name, a.q)
		}
		a.reply <- answer
		if err := wait(t, done); (err == nil) != answer.a.Allowed {
			t.Errorf("%s: %v", name, err)
		}
	}
	h.frisket.Store(true)
	ask("frisket's main process", h.forwarded(h.github), answered{})
	h.frisket.Store(false)

	tabConn := h.dial(tab())
	if err := tabConn.bind(t, h.github, []byte("sid"), true); err != nil {
		t.Fatal(err)
	}
	ask("a terminal chain", tabConn, answered{})

	r := claude(100)
	h.s.Grants.Grant(grant.Key{
		Anchor: grant.Anchor{Pid: r.Anchor.Pid, Start: r.Anchor.Start},
		Host:   ssh.FingerprintSHA256(h.github.PublicKey()), KeyFP: ssh.FingerprintSHA256(h.key(0)), Fwd: true,
	}, grant.Now()+time.Hour)
	ask("under a live grant", h.forwarded(h.github), answered{})

	ask("an Allow for 15 minutes", h.forwarded(h.github), allowFor(15*time.Minute))
	ask("after that Allow", h.forwarded(h.github), answered{})
}

func TestTheRemoteSudoQuestionNamesTheHostTheCommandAndTheLevel(t *testing.T) {
	h := newHarness(t, 1, nil)
	fp := ssh.FingerprintSHA256(h.key(0))
	for _, tc := range []struct {
		host    ssh.Signer
		title   string
		level   string
		reasons []string
		text    string
		wantLvl string
	}{
		{h.github, "sudo on github.com", "", nil,
			"/run/current-system/sw/bin/systemctl stop sshd.service\ndan as root in /home/dan\nkey " + fp + " (dan@test)", "normal"},
		{h.server, "sudo on " + ssh.FingerprintSHA256(h.server.PublicKey()), "danger", []string{"touches a unit that guards this machine", "LD_PRELOAD=/tmp/\x1bx.so"},
			"touches a unit that guards this machine\nLD_PRELOAD=/tmp/\\u001bx.so\n\n/run/current-system/sw/bin/systemctl stop sshd.service\ndan as root in /home/dan\nkey " + fp + " (dan@test)", "danger"},
		{h.github, "sudo on github.com", "warning", []string{"the process chain was cut short"},
			"the process chain was cut short\n\n/run/current-system/sw/bin/systemctl stop sshd.service\ndan as root in /home/dan\nkey " + fp + " (dan@test)", "warning"},
	} {
		done := h.forwarded(tc.host).signAsync(h.key(0), sudoMessage(t, tc.level, tc.reasons, tc.host.PublicKey()))
		a := h.next()
		if a.q.Title != tc.title || a.q.Text != tc.text || a.q.Level != tc.wantLvl {
			t.Errorf("asked %q %q\n%q", a.q.Title, a.q.Level, a.q.Text)
		}
		a.reply <- answered{}
		wait(t, done)
	}
	if !strings.Contains(h.log.String(), `"class":"remote sudo"`) || !strings.Contains(h.log.String(), `"nonce":"0707`) {
		t.Errorf("the journal lacks the message:\n%s", h.log.String())
	}
}

func TestAnotherForwardedBoundSignIsAskedAllowOnceAndAnUnboundOneRefused(t *testing.T) {
	h := newHarness(t, 1, nil)
	h.frisket.Store(true)
	challenge := make([]byte, 32)
	rand.Read(challenge)

	if err := wait(t, h.dial(claude(100)).signAsync(h.key(0), challenge)); err == nil {
		t.Error("an unbound sign was made")
	}
	direct := h.dial(claude(100))
	if err := direct.bind(t, h.github, []byte("sid"), false); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, direct.signAsync(h.key(0), challenge)); err == nil {
		t.Error("a direct bound sign was made")
	}
	h.nothingAsked()

	c := h.forwarded(h.github)
	done := c.signAsync(h.key(0), challenge)
	a := h.next()
	if a.q.Title != "agent signature on github.com" || a.q.Grantable || a.q.Allow != "" ||
		!strings.Contains(a.q.Text, "\nforwarded\nbound to github.com") {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- allowFor(15 * time.Minute)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	done = c.signAsync(h.key(0), challenge)
	h.next().reply <- answered{}
	if err := wait(t, done); err == nil {
		t.Error("an Allow made a grant")
	}
}

func TestACutClientChainRaisesARemoteSudoToWarningAndSaysSo(t *testing.T) {
	h := newHarness(t, 1, nil)
	for _, tc := range []struct{ level, want string }{{"", "warning"}, {"danger", "danger"}} {
		c := h.dial(links(claude(100).Chain[:4]...))
		if err := c.bind(t, h.github, []byte("sid"), true); err != nil {
			t.Fatal(err)
		}
		done := c.signAsync(h.key(0), sudoMessage(t, tc.level, nil, h.github.PublicKey()))
		a := h.next()
		if a.q.Level != tc.want || !strings.HasPrefix(a.q.Text, "the process chain was cut short\n") {
			t.Errorf("asked %q %q", a.q.Level, a.q.Text)
		}
		a.reply <- answered{}
		wait(t, done)
	}
}
