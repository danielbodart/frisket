package intercept

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

// testHosts is what the CA in most of these tests is constrained to.
var testHosts = []string{"api.example.test", "a.test", "b.test", "c.test", "d.test", "e.test"}

func TestACAIsALeafOnlyCAOfItsOwn(t *testing.T) {
	ca, err := NewCA(testHosts)
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Certificate()
	if !c.IsCA || !c.MaxPathLenZero || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("not a leaf-only CA: IsCA=%v MaxPathLenZero=%v usage=%v", c.IsCA, c.MaxPathLenZero, c.KeyUsage)
	}
	// Outlives any session: a CA that ended first would end the session's
	// interception with it.
	if c.NotAfter.Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("the CA ends at %s", c.NotAfter)
	}
	other, err := NewCA(testHosts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ca.CertPEM(), other.CertPEM()) || publicKeysEqual(ca.key.Public(), other.key.Public()) {
		t.Fatal("two sessions were given the same CA")
	}
}

// A restored session keeps its CA: Marshal and ParseCA are the same CA, whose
// leaves the sandbox's trust still verifies.
func TestACAIsTheSameCAAfterARoundTrip(t *testing.T) {
	ca, err := NewCA(testHosts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseCA(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.CertPEM(), ca.CertPEM()) || !slices.Equal(back.Hosts(), ca.Hosts()) {
		t.Fatal("the CA read back is not the CA written")
	}
	leaf, err := back.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.example.test"}); err != nil {
		t.Fatalf("a leaf of the CA read back does not verify against the original: %v", err)
	}
}

func TestParseCARefusesWhatCouldNotBeTheSessionsCA(t *testing.T) {
	ca, _ := NewCA(testHosts)
	other, _ := NewCA(testHosts)
	good, _ := ca.Marshal()
	otherPEM, _ := other.Marshal()
	key, _ := pem.Decode(good)
	keyPEM := pem.EncodeToMemory(key)
	for name, b := range map[string][]byte{
		"nothing":                     nil,
		"not PEM":                     []byte("nope"),
		"a key alone":                 keyPEM,
		"a certificate alone":         ca.CertPEM(),
		"a certificate for other key": append(append([]byte{}, keyPEM...), other.CertPEM()...),
		"trailing data":               append(append([]byte{}, good...), otherPEM...),
	} {
		if _, err := ParseCA(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestABundleIsTheRootsWithTheCAAfterThem(t *testing.T) {
	ca, _ := NewCA(testHosts)
	other, _ := NewCA([]string{"other.test"})
	// Without a final newline, which the bundle must not glue the CA onto.
	roots := bytes.TrimRight(other.CertPEM(), "\n")
	bundle, err := Bundle(roots, ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatal("the bundle parses to nothing")
	}
	for _, c := range []*CA{ca, other} {
		host := c.Hosts()[0]
		leaf, err := c.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			t.Fatalf("a leaf for %s does not verify through the bundle: %v", host, err)
		}
	}
	if _, err := Bundle([]byte("not a certificate\n"), ca.CertPEM()); err == nil {
		t.Fatal("roots with no certificates in them were accepted")
	}
}

func TestLeafVerifiesForItsNameOnly(t *testing.T) {
	ca, err := NewCA(testHosts)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	opts := x509.VerifyOptions{Roots: roots, DNSName: "api.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Fatalf("the leaf does not verify against the CA: %v", err)
	}
	opts.DNSName = "evil.example.test"
	if _, err := cert.Leaf.Verify(opts); err == nil {
		t.Fatal("the leaf verifies for a name it was not minted for")
	}
	if cert.Leaf.IsCA {
		t.Fatal("a leaf is a CA")
	}
}

func TestLeafCacheIsBoundedAndRenews(t *testing.T) {
	ca, err := NewCA(testHosts)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca.Now = func() time.Time { return now }
	ca.SetCacheSize(3)

	first, _ := ca.Leaf("a.test")
	if again, _ := ca.Leaf("a.test"); again != first {
		t.Fatal("the same name minted twice while the first was fresh")
	}
	for _, n := range []string{"b.test", "c.test", "d.test", "e.test"} {
		if _, err := ca.Leaf(n); err != nil {
			t.Fatal(err)
		}
	}
	if got := ca.cached(); got != 3 {
		t.Fatalf("cache holds %d, bound is 3", got)
	}
	if again, _ := ca.Leaf("a.test"); again == first {
		t.Fatal("the least recently used leaf was not evicted")
	}

	e, _ := ca.Leaf("e.test")
	now = now.Add(leafLifetime - leafRenew + time.Minute)
	renewed, _ := ca.Leaf("e.test")
	if renewed == e {
		t.Fatal("a leaf within a day of expiry was handed out again")
	}
	if !renewed.Leaf.NotAfter.After(e.Leaf.NotAfter) {
		t.Fatal("the renewed leaf does not outlive the old one")
	}
}

// handshake is a Go client that trusts only ca, connecting to a server that
// presents cert, asking for name.
func handshake(t *testing.T, ca *CA, cert *tls.Certificate, name string) error {
	t.Helper()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		c.Close()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp4", ln.Addr().String(),
		&tls.Config{RootCAs: roots, ServerName: name})
	if err == nil {
		c.Close()
	}
	return err
}

func notAuthorizedForName(err error) bool {
	var inv x509.CertificateInvalidError
	return errors.As(err, &inv) && inv.Reason == x509.CANotAuthorizedForThisName
}

// THE CA IS CONSTRAINED TO THE INTERCEPTED HOSTS, critically, so a client
// accepts a leaf for one of them and rejects a leaf the same CA signs for
// any other name -- which is frisket minting the wrong name by its own bug,
// or a stolen key minting whatever it likes -- and any leaf naming an address.
func TestAClientTrustsTheCAOnlyForTheInterceptedHosts(t *testing.T) {
	ca, err := NewCA([]string{"API.Example.Test.", "git.example.test", "api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Certificate()
	if !c.PermittedDNSDomainsCritical || !slices.Equal(c.PermittedDNSDomains, []string{"api.example.test", "git.example.test"}) {
		t.Fatalf("constraints: critical %v, permitted %v", c.PermittedDNSDomainsCritical, c.PermittedDNSDomains)
	}
	if !slices.Equal(ca.Hosts(), c.PermittedDNSDomains) || !ca.Permits("API.example.test") || ca.Permits("evil.example.test") {
		t.Fatalf("Hosts %v; Permits disagrees with them", ca.Hosts())
	}

	ok, err := ca.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ca, ok, "api.example.test"); err != nil {
		t.Fatalf("a leaf for an intercepted host was rejected: %v", err)
	}

	// The CA signs it -- Leaf mints whatever it is given -- and the client
	// refuses it for the name constraints, not merely a name mismatch.
	wrong, err := ca.Leaf("evil.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ca, wrong, "evil.example.test"); !notAuthorizedForName(err) {
		t.Fatalf("a leaf for a host outside the constraints: %v, want the CA not authorised for the name", err)
	}

	// A leaf naming an address says nothing a DNS constraint covers, so
	// addresses are excluded outright.
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		leaf := signed(t, ca, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP(ip)}})
		roots := x509.NewCertPool()
		roots.AddCert(c)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); !notAuthorizedForName(err) {
			t.Fatalf("a leaf for %s: %v, want the CA not authorised for the name", ip, err)
		}
	}
}

// With nothing intercepted, the CA permits no name at all.
func TestACAForNoHostsPermitsNothing(t *testing.T) {
	ca, err := NewCA(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ca, leaf, "api.example.test"); !notAuthorizedForName(err) {
		t.Fatalf("a CA for no hosts: %v, want the CA not authorised for the name", err)
	}
}

// signed is tmpl as a leaf of ca's, for leaves Leaf would never make.
func signed(t *testing.T, ca *CA, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, ca.key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheCARefusesAHostThatIsNotAName(t *testing.T) {
	for _, bad := range []string{"", "*.example.test", "*", "a.test:443", "[::1]", "a b.test"} {
		if _, err := NewCA([]string{bad}); err == nil {
			t.Errorf("a CA was made for %q", bad)
		}
	}
}
