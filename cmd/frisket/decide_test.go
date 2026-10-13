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
	"github.com/danielbodart/quoin/execrule"
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
		Spec: execrule.Spec{
			Exec: []policy.ExecRule{
				{Command: "ls **"},
				{Command: "rm **", Refuse: true},
				{Arg: ".ssh", Refuse: true},
			},
			Env:       []string{"LANG"},
			Unmatched: "ask",
		},
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

// check -http answers each request line as the route's scope does, and
// says what a body still decides.
func TestCheckHTTPAnswersEachRequest(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("POST /repos/o/r/pulls\nDELETE /repos/o/r/\nPOST /graphql\nPUT /x\n")
	if err := decideRequests("../../tests/fixtures/github.v2.json", "api", in, &out); err != nil {
		t.Fatal(err)
	}
	want := "allow\tpath\tpulls/create\n" +
		"refuse\trefused by rule\trepos/delete\n" +
		"refuse\tgraphql body unread\t-\tgraphql decides\n" +
		"ask\tunmatched\t-\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out.String(), want)
	}
}

// check -layer project merges a project's layer over its base and checks
// both: the section chase.json keeps it under, and a host field refused.
func TestCheckLayerProject(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := "../../tests/fixtures/github.v2.json"
	good := write("chase.json", `{"frisket": {"routes": {"api": {"operations": {"repos/delete": "ask"}}}}, "flong": {}}`)
	if err := checkLayer("project", base, "frisket", good, checkDeps); err != nil {
		t.Errorf("a project's answer: %v", err)
	}
	bad := write("bad.json", `{"routes": {"api": {"upstream": "https://elsewhere.test"}}}`)
	if err := checkLayer("project", base, "", bad, checkDeps); err == nil || !strings.Contains(err.Error(), "x-scope host") {
		t.Errorf("a host field: %v", err)
	}
	if err := checkLayer("project", "", "", good, checkDeps); err == nil {
		t.Error("no base was accepted")
	}
	if err := checkLayer("tier", base, "", good, checkDeps); err == nil {
		t.Error("a tier layer was accepted")
	}
}
