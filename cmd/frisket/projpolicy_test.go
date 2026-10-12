package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh"
)

func TestPolicyVerifySaysWhetherAndWhy(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects", "foo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(k)
	signers := filepath.Join(home, "allowed_signers")
	line := `dan namespaces="frisket-policy:*" ` + string(ssh.MarshalAuthorizedKey(s.PublicKey()))
	if err := os.WriteFile(signers, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n  \"version\": 2\n}\n")
	path := filepath.Join(root, "chase.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	verify := func() (string, error) {
		var out bytes.Buffer
		err := runPolicy([]string{"verify", "-allowed-signers", signers, "-home", home, path}, &out)
		return out.String(), err
	}
	if _, err := verify(); err == nil || !strings.Contains(err.Error(), "no chase.json.sig") {
		t.Errorf("unsigned: %v", err)
	}
	sig, err := projpolicy.Sign(rand.Reader, s, "frisket-policy:~/Projects/foo", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(); err != nil || !strings.Contains(out, "signed by dan in frisket-policy:~/Projects/foo") {
		t.Errorf("signed: %q, %v", out, err)
	}
	var out bytes.Buffer
	if err := runPolicy([]string{"signers", signers}, &out); err != nil || !strings.Contains(out.String(), "line 1: dan ssh-ed25519, namespaces frisket-policy:*") {
		t.Errorf("signers: %q, %v", out.String(), err)
	}
}

func TestPolicyFmtRewritesOrChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chase.json")
	if err := os.WriteFile(path, []byte(`{"b":1,"a":{}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runPolicy([]string{"fmt", "-check", path}, &out); err == nil {
		t.Error("-check passed a file that is not canonical")
	}
	if err := runPolicy([]string{"fmt", path}, &out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "{\n  \"a\": {},\n  \"b\": 1\n}\n" {
		t.Errorf("got %q", got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	if err := runPolicy([]string{"fmt", "-check", path}, &out); err != nil {
		t.Error(err)
	}
	if err := os.WriteFile(path, []byte(`{"a":1.5}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runPolicy([]string{"fmt", path}, &out); err == nil {
		t.Error("a float was formatted")
	}
}
