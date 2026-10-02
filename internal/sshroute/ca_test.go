package sshroute

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/policy"
)

// A restored session derives the CA its sandbox already trusts: the same
// TLS key is the same SSH CA, and another key another CA.
func TestTheSSHCAIsDerivedFromTheTLSKeyAlone(t *testing.T) {
	a1, err := DeriveCA([]byte("key one"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := DeriveCA([]byte("key one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveCA([]byte("key two"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1.PublicKey().Marshal(), a2.PublicKey().Marshal()) {
		t.Error("the same key derived two CAs")
	}
	if bytes.Equal(a1.PublicKey().Marshal(), b.PublicKey().Marshal()) {
		t.Error("two keys derived one CA")
	}
	if a1.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("CA is %s", a1.PublicKey().Type())
	}
	if _, err := DeriveCA(nil); err == nil {
		t.Error("derived a CA from nothing")
	}
}

// The host certificate names the route and its address, is valid from a
// little before now until the TLS CA expires, and is signed by the CA.
func TestAHostCertificateNamesItsRouteAndAddress(t *testing.T) {
	routes, err := Compile([]policy.SSHRoute{goodRoute(t)}, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	ca, key := newSigner(t), newSigner(t)
	now := time.Unix(1_800_000_000, 0)
	expiry := now.Add(365 * 24 * time.Hour)
	s, err := hostSigner(ca, key, routes[0], now, expiry)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatalf("host key is a %T", s.PublicKey())
	}
	if c.CertType != ssh.HostCert || c.KeyId != "server" ||
		strings.Join(c.ValidPrincipals, ",") != "server,10.0.0.5" ||
		c.ValidAfter != uint64(now.Add(-5*time.Minute).Unix()) || c.ValidBefore != uint64(expiry.Unix()) ||
		!bytes.Equal(c.SignatureKey.Marshal(), ca.PublicKey().Marshal()) {
		t.Errorf("certificate %+v", c)
	}
	checker := ssh.CertChecker{
		IsHostAuthority: func(k ssh.PublicKey, _ string) bool { return bytes.Equal(k.Marshal(), ca.PublicKey().Marshal()) },
		Clock:           func() time.Time { return now },
	}
	for _, addr := range []string{"server:22", "10.0.0.5:22"} {
		if err := checker.CheckHostKey(addr, nil, c); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if err := checker.CheckHostKey("other:22", nil, c); err == nil {
		t.Error("the certificate vouched for another name")
	}
}

func TestTheSandboxFilesTrustTheCAAndNameEachRoute(t *testing.T) {
	ca := newSigner(t)
	kh := string(KnownHosts(ca.PublicKey()))
	want := "@cert-authority * " + authorized(ca.PublicKey()) + " frisket\n"
	if kh != want {
		t.Errorf("known hosts %q, want %q", kh, want)
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(kh)); err != nil {
		t.Errorf("known hosts does not parse: %v", err)
	}

	a, b := goodRoute(t), goodRoute(t)
	b.Name, b.Address, b.User = "gateway", "[fd00::1]:2222", "root"
	routes, err := Compile([]policy.SSHRoute{a, b}, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(SSHConfig(routes))
	wantConfig := "Host server\n\tHostName 10.0.0.5\n\tPort 22\n\tUser dan\n" +
		"\nHost gateway\n\tHostName fd00::1\n\tPort 2222\n\tUser root\n"
	if got != wantConfig {
		t.Errorf("ssh_config %q, want %q", got, wantConfig)
	}
}
