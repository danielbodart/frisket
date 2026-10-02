package sshroute

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// caInfo names what the derivation is for, and its version: a different
// derivation is a different name, never a different key under this one.
const caInfo = "frisket ssh ca v1"

// DeriveCA is the session's SSH CA, ed25519, derived from its TLS CA's
// private key, PKCS#8 DER. Derived rather than made, so that the session's
// record keeps one key, in the format it always has, and a session restored
// across a restart has the SSH CA its sandbox's known_hosts already trusts.
// HKDF over the whole key: knowing the SSH CA says nothing of the TLS one.
func DeriveCA(pkcs8 []byte) (ssh.Signer, error) {
	if len(pkcs8) == 0 {
		return nil, errors.New("sshroute: no TLS CA key to derive the SSH CA from")
	}
	seed, err := hkdf.Key(sha256.New, pkcs8, nil, caInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("sshroute: deriving the SSH CA: %w", err)
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}

// certSkew is how far before now a host certificate is valid from: a
// sandbox whose clock is a little behind the host's still accepts it.
const certSkew = 5 * time.Minute

// hostSigner is the route's host key with its certificate, signed by ca,
// for its name and its address -- what ssh compares the certificate with is
// the name it was given, or the address with CheckHostIP. It is the only key
// the sandbox is offered: one it can only trust through the CA.
func hostSigner(ca, key ssh.Signer, r *Route, now, expiry time.Time) (ssh.Signer, error) {
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	before := uint64(ssh.CertTimeInfinity)
	if !expiry.IsZero() {
		before = uint64(expiry.Unix())
	}
	cert := &ssh.Certificate{
		Key:             key.PublicKey(),
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.HostCert,
		KeyId:           r.Name,
		ValidPrincipals: []string{r.Name, r.Address.Addr().String()},
		ValidAfter:      uint64(now.Add(-certSkew).Unix()),
		ValidBefore:     before,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, fmt.Errorf("sshroute: signing %s's host certificate: %w", r.Name, err)
	}
	return ssh.NewCertSigner(cert, key)
}

// KnownHosts is the sandbox's ssh_known_hosts: the CA, trusted for host
// certificates of any name. Any name, because the certificate names its
// route and its address, and the CA signs for nothing else.
func KnownHosts(ca ssh.PublicKey) []byte {
	key := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(ca)), "\n")
	return []byte("@cert-authority * " + key + " frisket\n")
}

// SSHConfig is the sandbox's ssh_config fragment: a Host block for each
// route, so `ssh <name> <command>` reaches it by the address the session
// steers, as the user it logs in as.
func SSHConfig(routes []*Route) []byte {
	var b strings.Builder
	for i, r := range routes {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "Host %s\n\tHostName %s\n\tPort %d\n\tUser %s\n", r.Name, r.Address.Addr(), r.Address.Port(), r.User)
	}
	return []byte(b.String())
}
