package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// fakeSigner answers policy-sign with sig, recording what it was sent.
type fakeSigner struct {
	agent.ExtendedAgent
	got chan agentsrv.PolicySignRequest
	sig []byte
}

func (f *fakeSigner) Extension(typ string, contents []byte) ([]byte, error) {
	if typ != agentsrv.PolicySignExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	var req agentsrv.PolicySignRequest
	if err := json.Unmarshal(contents, &req); err != nil {
		return nil, err
	}
	f.got <- req
	b, _ := json.Marshal(agentsrv.PolicySignResponse{Sig: f.sig})
	return append([]byte{6}, b...), nil
}

func serveFake(t *testing.T, f *fakeSigner) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "policysign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); agent.ServeAgent(f, c) }()
		}
	}()
	return sock
}

func TestPolicySignSendsTheFileAndWritesTheSignature(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "chase.json")
	f := &fakeSigner{ExtendedAgent: agent.NewKeyring().(agent.ExtendedAgent), got: make(chan agentsrv.PolicySignRequest, 1), sig: []byte("SIG\n")}
	sock := serveFake(t, f)
	sign := func(args ...string) error {
		var out bytes.Buffer
		return runPolicy(append([]string{"sign", "-agent", sock}, append(args, path)...), &out)
	}

	if err := os.WriteFile(path, []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sign(); err == nil || !strings.Contains(err.Error(), "frisket policy fmt") {
		t.Errorf("not canonical: %v", err)
	}

	body := []byte("{\n  \"version\": 2\n}\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sign(); err != nil {
		t.Fatal(err)
	}
	if got := <-f.got; got.Root != root || got.Name != "chase.json" || !bytes.Equal(got.New, body) || got.Old != nil || got.OldSig != nil {
		t.Errorf("sent %+v", got)
	}
	if b, _ := os.ReadFile(path + ".sig"); string(b) != "SIG\n" {
		t.Errorf("wrote %q", b)
	}

	// Signed before: the old bytes go with the old signature.
	old := filepath.Join(root, "old.json")
	os.WriteFile(old, []byte("OLD"), 0o644)
	if err := sign("-old", old); err != nil {
		t.Fatal(err)
	}
	if got := <-f.got; string(got.Old) != "OLD" || string(got.OldSig) != "SIG\n" {
		t.Errorf("sent %+v", got)
	}
}
