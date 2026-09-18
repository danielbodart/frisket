package intercept

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAIsCreatedOnceAndPersisted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir)
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

	again, err := LoadOrCreateCA(dir)
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
	if _, err := LoadOrCreateCA(good); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if _, err := LoadOrCreateCA(other); err != nil {
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
			if _, err := LoadOrCreateCA(dir); err == nil {
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
	ca, err := LoadOrCreateCA(t.TempDir())
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
	ca, err := LoadOrCreateCA(t.TempDir())
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
