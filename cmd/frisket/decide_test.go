package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/policy"
)

func sshDocument(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Name: "t", Policy: policy.Policy{Allow: []string{}, SSH: []policy.SSHRoute{{
		Name: "server", Address: "192.168.1.10", User: "ops", Agent: "/run/agent",
		HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))},
		Exec: []policy.ExecRule{
			{Command: "ls **"},
			{Command: "rm **", Refuse: true},
			{Arg: ".ssh", Refuse: true},
		},
		Env:       []string{"LANG"},
		Unmatched: "ask",
	}}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCheckExecAnswersEachCommandAsTheRouteDecidesIt(t *testing.T) {
	f := sshDocument(t)
	var out bytes.Buffer
	in := strings.NewReader("ls -la\nrm x\nls /root/.ssh\nawk x\nls $(id)\nLANG=C ls\nLD_PRELOAD=x ls\n")
	if err := decideCommands(f, "server", in, &out); err != nil {
		t.Fatal(err)
	}
	want := "allow\tls **\nrefuse\trm **\nrefuse\t[arg .ssh]\nask\tunmatched\nask\tunmatched\nallow\tls **\nask\tunmatched\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out.String(), want)
	}
}

func TestCheckExecRefusesARouteTheDocumentDoesNotHave(t *testing.T) {
	err := decideCommands(sshDocument(t), "gateway", strings.NewReader("ls\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `no SSH route "gateway"`) {
		t.Errorf("%v", err)
	}
}
