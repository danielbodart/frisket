package agentsrv

import (
	"os"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
)

func allowGitHub(s *Server) { s.Hosts = map[string]Rule{"github.com": Allow} }

// login binds c to host, direct or forwarded, and asks for a userauth sign.
func (h *harness) login(r *peer.Requester, host ssh.Signer, fwd bool) <-chan error {
	h.t.Helper()
	c := h.dial(r)
	if err := c.bind(h.t, host, []byte("sid"), fwd); err != nil {
		h.t.Fatal(err)
	}
	return c.signAsync(h.key(0), userauthData([]byte("sid"), h.key(0), nil))
}

func TestAnAllowedHostSignsAClaudesLoginWithoutAsking(t *testing.T) {
	h := newHarness(t, 1, allowGitHub)
	if err := wait(t, h.login(claude(100), h.github, false)); err != nil {
		t.Fatal(err)
	}
	h.nothingAsked()
	if !strings.Contains(h.log.String(), `"source":"host"`) {
		t.Errorf("logged %s", h.log)
	}
}

func TestAHostSetToAskOrUnlistedIsAsked(t *testing.T) {
	for _, hosts := range []map[string]Rule{nil, {"github.com": Ask}, {"gitlab.com": Allow}} {
		h := newHarness(t, 1, func(s *Server) { s.Hosts = hosts })
		done := h.login(claude(100), h.github, false)
		a := h.next()
		if !a.q.Grantable || a.q.Title != "ssh to github.com" {
			t.Errorf("%v: asked %+v", hosts, a.q)
		}
		a.reply <- answered{}
		if err := wait(t, done); err == nil {
			t.Errorf("%v: a refused sign was made", hosts)
		}
	}
}

func TestAHostRuleNeverCoversAForwardedSign(t *testing.T) {
	h := newHarness(t, 1, allowGitHub)
	for _, r := range []*peer.Requester{claude(100), tab()} {
		done := h.login(r, h.github, true)
		a := h.next()
		if !strings.Contains(a.q.Text, "\nforwarded\n") {
			t.Errorf("asked %+v", a.q)
		}
		a.reply <- answered{}
		if err := wait(t, done); err == nil {
			t.Error("a refused forwarded sign was made")
		}
	}
}

func TestAHostRuleNeverCoversAnUnknownHost(t *testing.T) {
	h := newHarness(t, 1, allowGitHub)
	stranger := hostKey(t)
	done := h.login(claude(100), stranger, false)
	a := h.next()
	if a.q.Title != "ssh to unknown host "+ssh.FingerprintSHA256(stranger.PublicKey()) {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}

// A host key known under another name is not github.com's, whatever the
// connection was meant for.
func TestAHostRuleCoversOnlyTheKeyListedUnderItsName(t *testing.T) {
	h := newHarness(t, 1, allowGitHub)
	other := hostKey(t)
	f, err := os.OpenFile(h.s.KnownHosts, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\ngithub.com.evil.example,|1|c2FsdA==|aGFzaA== " + string(ssh.MarshalAuthorizedKey(other.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	f.Close()
	done := h.login(claude(100), other, false)
	a := h.next()
	if !strings.HasPrefix(a.q.Title, "ssh to github.com.evil.example") {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}

func TestAHostRuleNeverCoversACutChain(t *testing.T) {
	h := newHarness(t, 1, allowGitHub)
	done := h.login(links(claude(100).Chain[:4]...), h.github, false)
	a := h.next()
	if a.q.Level != "warning" {
		t.Errorf("asked %+v", a.q)
	}
	a.reply <- answered{}
	wait(t, done)
}
