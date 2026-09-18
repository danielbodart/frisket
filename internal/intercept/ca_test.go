package intercept

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testHosts is what the CA in most of these tests is constrained to.
var testHosts = []string{"api.example.test", "a.test", "b.test", "c.test", "d.test", "e.test"}

func TestCAIsCreatedOnceAndPersisted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir, testHosts)
	if err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("CA key mode %04o, want 0600", perm)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("CA directory: %v, %v", st.Mode(), err)
	}

	again, err := LoadOrCreateCA(dir, testHosts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca.CertPEM(), again.CertPEM()) {
		t.Fatal("a second start generated a different CA; every sandbox's trust would break on restart")
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, ca.CertPEM()) {
		t.Fatal("the exported certificate is not the one on disk")
	}
	c := ca.Certificate()
	if !c.IsCA || !c.MaxPathLenZero || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("not a leaf-only CA: IsCA=%v MaxPathLenZero=%v usage=%v", c.IsCA, c.MaxPathLenZero, c.KeyUsage)
	}
}

func TestCARefusesWhatItCannotTrust(t *testing.T) {
	good := t.TempDir()
	if _, err := LoadOrCreateCA(good, testHosts); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if _, err := LoadOrCreateCA(other, testHosts); err != nil {
		t.Fatal(err)
	}
	copyFile := func(t *testing.T, from, to string, mode os.FileMode) {
		t.Helper()
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(to, mode); err != nil {
			t.Fatal(err)
		}
	}

	for name, setup := range map[string]func(t *testing.T, dir string){
		"key readable by others": func(t *testing.T, dir string) {
			copyFile(t, filepath.Join(good, CAKeyFile), filepath.Join(dir, CAKeyFile), 0o644)
			copyFile(t, filepath.Join(good, CACertFile), filepath.Join(dir, CACertFile), 0o644)
		},
		"key without certificate": func(t *testing.T, dir string) {
			copyFile(t, filepath.Join(good, CAKeyFile), filepath.Join(dir, CAKeyFile), 0o600)
		},
		"certificate without key": func(t *testing.T, dir string) {
			copyFile(t, filepath.Join(good, CACertFile), filepath.Join(dir, CACertFile), 0o644)
		},
		"certificate for another key": func(t *testing.T, dir string) {
			copyFile(t, filepath.Join(good, CAKeyFile), filepath.Join(dir, CAKeyFile), 0o600)
			copyFile(t, filepath.Join(other, CACertFile), filepath.Join(dir, CACertFile), 0o644)
		},
		"key is a symlink": func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(good, CAKeyFile), filepath.Join(dir, CAKeyFile)); err != nil {
				t.Fatal(err)
			}
			copyFile(t, filepath.Join(good, CACertFile), filepath.Join(dir, CACertFile), 0o644)
		},
		"key is not PEM": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, CAKeyFile), []byte("nope"), 0o600); err != nil {
				t.Fatal(err)
			}
			copyFile(t, filepath.Join(good, CACertFile), filepath.Join(dir, CACertFile), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			before := listDir(t, dir)
			// For other hosts, too: a CA that cannot be loaded is refused,
			// never replaced.
			if _, err := LoadOrCreateCA(dir, []string{"other.test"}); err == nil {
				t.Fatal("loaded, want a refusal")
			}
			if after := listDir(t, dir); after != before {
				t.Fatalf("a refused CA was replaced: %s -> %s", before, after)
			}
		})
	}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range ents {
		info, _ := e.Info()
		fmt.Fprintf(&b, "%s:%d:%v ", e.Name(), info.Size(), info.ModTime().UnixNano())
	}
	return b.String()
}

func TestLeafVerifiesForItsNameOnly(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), testHosts)
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
	ca, err := LoadOrCreateCA(t.TempDir(), testHosts)
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
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"API.Example.Test.", "git.example.test", "api.example.test"})
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
	ca, err := LoadOrCreateCA(t.TempDir(), nil)
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

// THE CA IS REPLACED WHEN THE INTERCEPTED HOSTS CHANGE, AND KEPT WHEN THEY DO
// NOT -- in any spelling or order. A replacement is a whole new CA, its key
// 0600 in a 0700 directory, with nothing of the old one left behind.
func TestTheCAIsReplacedWhenTheHostsChangeAndKeptWhenNot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	load := func(hosts ...string) *CA {
		t.Helper()
		ca, err := LoadOrCreateCA(dir, hosts)
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	key := func() []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	first := load("a.test", "b.test")
	firstKey := key()
	if first.Replaced() {
		t.Fatal("a first CA says it replaced one")
	}
	if again := load("B.test.", "a.test", "a.test"); !bytes.Equal(again.CertPEM(), first.CertPEM()) || again.Replaced() {
		t.Fatal("the same hosts, spelt differently, made a new CA")
	}

	second := load("a.test", "b.test", "c.test")
	if bytes.Equal(second.CertPEM(), first.CertPEM()) || bytes.Equal(key(), firstKey) || !second.Replaced() {
		t.Fatal("a new host did not make a new CA")
	}
	if !slices.Equal(second.Hosts(), []string{"a.test", "b.test", "c.test"}) {
		t.Fatalf("the new CA is constrained to %v", second.Hosts())
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil || !bytes.Equal(onDisk, second.CertPEM()) {
		t.Fatalf("the certificate on disk is not the new CA's: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dir, CAKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("new CA key: %v, %v", st.Mode(), err)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("new CA directory: %v, %v", st.Mode(), err)
	}
	if _, err := os.Lstat(nextDir(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the old CA was left beside the new: %v", err)
	}
	if kept := load("c.test", "b.test", "a.test"); !bytes.Equal(kept.CertPEM(), second.CertPEM()) || kept.Replaced() {
		t.Fatal("the new CA was not kept on the next start")
	}

	// A host removed is a change too: the CA must stop permitting it.
	if third := load("a.test"); third.Permits("c.test") || !third.Replaced() {
		t.Fatal("a removed host is still permitted")
	}

	// An interrupted replacement's leftovers -- the old CA, key and all --
	// are removed on the next start.
	if err := os.MkdirAll(nextDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nextDir(dir), CAKeyFile), firstKey, 0o600); err != nil {
		t.Fatal(err)
	}
	load("a.test")
	if _, err := os.Lstat(nextDir(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an old CA's key survived a start: %v", err)
	}
}

func TestTheCARefusesAHostThatIsNotAName(t *testing.T) {
	for _, bad := range []string{"", "*.example.test", "*", "a.test:443", "[::1]", "a b.test"} {
		if _, err := LoadOrCreateCA(t.TempDir(), []string{bad}); err == nil {
			t.Errorf("a CA was made for %q", bad)
		}
	}
}
