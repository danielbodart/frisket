package intercept

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestThePublicFilesAreTheCertificateAndTheRootsWithIt(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077))
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), testHosts)
	if err != nil {
		t.Fatal(err)
	}
	// Any other CA stands in for the host's roots; written without a final
	// newline, which the bundle must not glue the next certificate onto.
	other, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), []string{"other.test"})
	if err != nil {
		t.Fatal(err)
	}
	rootsPath := filepath.Join(t.TempDir(), "roots.crt")
	if err := os.WriteFile(rootsPath, bytes.TrimRight(other.CertPEM(), "\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "public")
	for range 2 { // and again over what the first wrote, as every start does
		if err := WritePublic(dir, ca.CertPEM(), rootsPath); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{CABundleFile, CACertFile}) {
		t.Fatalf("public directory holds %v", names)
	}
	for _, p := range []string{dir, filepath.Join(dir, CACertFile), filepath.Join(dir, CABundleFile)} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644)
		if st.IsDir() {
			want = 0o755
		}
		if st.Mode().Perm() != want {
			t.Fatalf("%s has mode %04o, want %04o", p, st.Mode().Perm(), want)
		}
	}

	cert, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert, ca.CertPEM()) {
		t.Fatal("ca.crt is not the CA's certificate")
	}
	bundle, err := os.ReadFile(filepath.Join(dir, CABundleFile))
	if err != nil {
		t.Fatal(err)
	}
	// Both verify through the bundle: the CA's leaves, and the roots'.
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
}

func TestThePublicFilesAreRefusedWhereTheyWouldExposeTheKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir, testHosts)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, CACertFile)
	if err := WritePublic(dir, ca.CertPEM(), roots); err == nil || !strings.Contains(err.Error(), CAKeyFile) {
		t.Fatalf("writing the public files into the CA's own directory: %v", err)
	}
}

func TestThePublicFilesRefuseRootsWithNoCertificates(t *testing.T) {
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), testHosts)
	if err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WritePublic(filepath.Join(t.TempDir(), "public"), ca.CertPEM(), empty); err == nil {
		t.Fatal("roots with no certificates in them were accepted")
	}
}
