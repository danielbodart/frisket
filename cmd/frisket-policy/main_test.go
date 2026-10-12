package main

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeRefusesToStartWithoutTheCourierFd(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if os.Getuid() == 0 {
		t.Skip("as root, serve refuses before the socket")
	}
	path := writeConfig(t, `{"fileName": "chase.json", "allowedSigners": "/etc/frisket/allowed_signers", "peers": {"x.service": "`+me.Username+`"}}`)
	err = runServe([]string{"-config", path})
	if err == nil || !strings.Contains(err.Error(), "no socket named courier") {
		t.Errorf("got %v", err)
	}
}

func TestAConfigReadsEverySetting(t *testing.T) {
	path := writeConfig(t, `{
		"fileName": "chase.json", "allowedSigners": "/etc/frisket/allowed_signers",
		"peers": {"frisket-signer.service": "ssh-signer", "frisket-sudo.service": "sudo-gate"}
	}`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &config{
		FileName: "chase.json", AllowedSigners: "/etc/frisket/allowed_signers",
		Peers: map[string]string{"frisket-signer.service": "ssh-signer", "frisket-sudo.service": "sudo-gate"},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v", c)
	}
	if err := runCheck([]string{path}); err != nil {
		t.Error(err)
	}
}

func TestAConfigThatWouldSilentlyNotApplyIsRefused(t *testing.T) {
	const s = `"allowedSigners": "/etc/frisket/allowed_signers"`
	for _, bad := range []string{
		`{` + s + `}`,
		`{"fileName": "", ` + s + `}`,
		`{"fileName": "a/chase.json", ` + s + `}`,
		`{"fileName": "..", ` + s + `}`,
		`{"fileName": "chase.json.sig", ` + s + `}`,
		`{"fileName": "chase.json"}`,
		`{"fileName": "chase.json", "allowedSigners": "etc/allowed_signers"}`,
		`{"fileName": "chase.json", "allowedSigners": "/etc//allowed_signers"}`,
		`{"fileName": "chase.json", ` + s + `, "peers": {"frisket-signer": "ssh-signer"}}`,
		`{"fileName": "chase.json", ` + s + `, "peers": {"a/b.service": "ssh-signer"}}`,
		`{"fileName": "chase.json", ` + s + `, "peers": {"frisket-signer.service": ""}}`,
		`{"fileName": "chase.json", ` + s + `, "peer": {}}`,
		`{"fileName": "chase.json", ` + s + `} {}`,
	} {
		if err := runCheck([]string{writeConfig(t, bad)}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// The schema names the same keys the decoder reads.
func TestTheSchemaMatchesTheConfig(t *testing.T) {
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for k := range s.Properties {
		got = append(got, k)
	}
	for f := range reflect.TypeFor[config]().Fields() {
		want = append(want, f.Tag.Get("json"))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("schema has %v, config has %v", got, want)
	}
}
