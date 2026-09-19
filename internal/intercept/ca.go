package intercept

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// A session's CA lasts longer than any session does. It is never written
	// anywhere but the session's record, dies with the session, and caps its
	// leaves' lifetimes -- so a CA that ended first would end the session's
	// interception with it.
	caLifetime = 365 * 24 * time.Hour
	// A leaf lives a week and is re-minted a day before it ends, so no
	// connection is ever handed a certificate about to expire under it.
	leafLifetime = 7 * 24 * time.Hour
	leafRenew    = 24 * time.Hour
	// Clients and the host disagree about the time by more than nothing, and a
	// certificate that is "not yet valid" to a sandbox is a refusal nobody can
	// explain from frisket's side.
	backdate = time.Hour
	// DefaultLeafCacheSize bounds the minted certificates held. Names are
	// already bounded by the routes, since an unknown name is refused before
	// anything is minted; the bound is here so that stays true if that ever
	// changes.
	DefaultLeafCacheSize = 256
)

// CA is one session's certificate authority, and the leaf certificates minted
// from it.
//
// ONE PER SESSION (PLAN.md, decision 4). It is made when the session is
// opened, trusted by that session alone, and its key exists in the daemon's
// memory and the session's sealed record in systemd's fd store -- never in a
// file. So a stolen key impersonates to one sandbox, for as long as it runs.
//
// IT IS NAME-CONSTRAINED to the session's intercepted hosts: a critical X.509
// Name Constraints extension (RFC 5280, 4.2.1.10) permits those DNS names and
// no IP address at all, so a client rejects a leaf frisket mints for any other
// name by its own mistake.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	// Now is the clock leaves are minted against; tests move it.
	Now func() time.Time

	mu    sync.Mutex
	max   int
	lru   *list.List // of *leaf, most recently used at the front
	byKey map[string]*list.Element
}

type leaf struct {
	name     string
	cert     *tls.Certificate
	notAfter time.Time
}

// NewCA makes a CA constrained to hosts.
func NewCA(hosts []string) (*CA, error) {
	names, err := constrainedNames(hosts)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			Organization: []string{"frisket"},
			CommonName:   "frisket sandbox CA",
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// It signs leaves and nothing else: no intermediate can be made under
		// it, so the key is the only thing that can mint for a sandbox.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	constrain(tmpl, names)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, key), nil
}

func newCA(cert *x509.Certificate, key crypto.Signer) *CA {
	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:     key,
		Now:     time.Now,
		max:     DefaultLeafCacheSize,
		lru:     list.New(),
		byKey:   map[string]*list.Element{},
	}
}

// Marshal is the CA as ParseCA reads it: the key and the certificate, PEM.
// It is the key, so it goes where the key may go -- the session's record --
// and nowhere else.
func (ca *CA) Marshal() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), ca.certPEM...), nil
}

// ParseCA reads back what Marshal wrote, for a session restored across a
// restart: the same CA, so the sandbox's trust in it still holds.
//
// It refuses what could only mint leaves the sandbox rejects -- an expired
// certificate, a certificate for another key -- because that failure would
// surface in the sandbox, as a handshake error pointing nowhere near here.
func ParseCA(b []byte) (*CA, error) {
	kb, rest := pem.Decode(b)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, errors.New("intercept: CA: no PEM PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("intercept: CA key cannot sign")
	}
	cb, rest := pem.Decode(rest)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("intercept: CA: no PEM certificate after the key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("intercept: CA: trailing data after the certificate")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("intercept: CA certificate is not a CA")
	}
	if now := time.Now(); now.After(cert.NotAfter) {
		return nil, fmt.Errorf("intercept: CA certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("intercept: CA certificate is not the key's")
	}
	return newCA(cert, key), nil
}

// Bundle is roots with the CA certificate after them: the one file of roots a
// runtime whose setting REPLACES its own (SSL_CERT_FILE, REQUESTS_CA_BUNDLE)
// is pointed at. Pointed at the CA alone, such a client trusts the
// intercepted hosts and nothing else.
func Bundle(roots, certPEM []byte) ([]byte, error) {
	// A file of no certificates would make a bundle that trusts only the
	// intercepted hosts, and every other name would fail inside the sandbox
	// with an error that points nowhere near here.
	if !x509.NewCertPool().AppendCertsFromPEM(roots) {
		return nil, errors.New("intercept: the roots hold no PEM certificates")
	}
	out := make([]byte, 0, len(roots)+1+len(certPEM))
	out = append(out, roots...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, certPEM...), nil
}

// constrainedNames is hosts normalised, without duplicates, in order: the
// set's one spelling, so the same set always gives the same certificate
// fields.
func constrainedNames(hosts []string) ([]string, error) {
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		n := strings.TrimSuffix(strings.ToLower(h), ".")
		if n == "" || strings.ContainsAny(n, "*:[]/ ") {
			return nil, fmt.Errorf("intercept: %q is not a host name to constrain the CA to", h)
		}
		names = append(names, n)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// constrain gives tmpl its name constraints: the DNS names permitted, and no
// IP address -- a leaf naming an address would otherwise be unconstrained,
// since a DNS constraint says nothing about one. X.509 permits a name and the
// names below it, so "api.example.com" also admits "x.api.example.com"; it
// has no way to say one name alone. With no names at all, every DNS name is
// excluded instead: an empty permitted list is no constraint at all.
func constrain(tmpl *x509.Certificate, names []string) {
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = names
	if len(names) == 0 {
		// Go and OpenSSL both read the empty name as matching every name. No
		// leaf is ever minted from a CA with nothing to intercept, so no
		// other client has to agree.
		tmpl.ExcludedDNSDomains = []string{""}
	}
	tmpl.ExcludedIPRanges = []*net.IPNet{
		{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ae, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ae.Equal(b)
}

// CertPEM is the CA certificate, for the sandbox. It is the one thing a
// sandbox is told (PLAN.md): which authority to trust.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Certificate is the parsed CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// Hosts is the set of names the CA is constrained to, in order.
func (ca *CA) Hosts() []string { return slices.Clone(ca.cert.PermittedDNSDomains) }

// Permits reports whether host is one of the names the CA was made for. A
// leaf for any other host is one every client rejects.
func (ca *CA) Permits(host string) bool {
	return slices.Contains(ca.cert.PermittedDNSDomains, normaliseHost(host))
}

// SetCacheSize changes the bound on minted leaves held.
func (ca *CA) SetCacheSize(n int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if n < 1 {
		n = 1
	}
	ca.max = n
	ca.evict()
}

// Leaf returns a certificate for name, minting one if none is cached or the
// cached one is near its end. The caller has already decided name is a route:
// this mints for whatever it is given, and a name outside the constraints
// gets a leaf that clients reject.
func (ca *CA) Leaf(name string) (*tls.Certificate, error) {
	now := ca.Now()
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if el, ok := ca.byKey[name]; ok {
		l := el.Value.(*leaf)
		if now.Add(leafRenew).Before(l.notAfter) {
			ca.lru.MoveToFront(el)
			return l.cert, nil
		}
		ca.lru.Remove(el)
		delete(ca.byKey, name)
	}

	// Minting under the lock: a P-256 key and a signature are tens of
	// microseconds, and holding it means a burst of handshakes for one name
	// mints one certificate rather than one each.
	cert, notAfter, err := ca.mint(name, now)
	if err != nil {
		return nil, err
	}
	ca.byKey[name] = ca.lru.PushFront(&leaf{name: name, cert: cert, notAfter: notAfter})
	ca.evict()
	return cert, nil
}

func (ca *CA) evict() {
	for ca.lru.Len() > ca.max {
		el := ca.lru.Back()
		ca.lru.Remove(el)
		delete(ca.byKey, el.Value.(*leaf).name)
	}
}

// cached reports how many leaves are held, for tests of the bound.
func (ca *CA) cached() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.lru.Len()
}

func (ca *CA) mint(name string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, time.Time{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, notAfter, nil
}

// serial is 128 random bits, positive, as the baseline requirements ask.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		// crypto/rand does not fail on Linux; if it ever does, nothing that
		// follows is safe to do either.
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}
