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

	"github.com/danielbodart/frisket/internal/agentsrv"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeRefusesToStartWithoutTheAgentFd(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	path := writeConfig(t, `{"forUser": "`+me.Username+`", "terminal": "allow"}`)
	err = runServe([]string{"-config", path})
	if err == nil || !strings.Contains(err.Error(), "no socket named agent") {
		t.Errorf("got %v", err)
	}
}

func TestAConfigReadsEverySetting(t *testing.T) {
	path := writeConfig(t, `{
		"forUser": "dan", "terminal": "ask",
		"sshsig": {"git": "allow", "file": "ask"},
		"ssh": {"hosts": {"github.com": "allow", "gitlab.com": "ask"}}
	}`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &config{
		ForUser: "dan", Terminal: agentsrv.Ask,
		SSHSIG: map[string]agentsrv.Rule{"git": agentsrv.Allow, "file": agentsrv.Ask},
		SSH:    sshConfig{Hosts: map[string]agentsrv.Rule{"github.com": agentsrv.Allow, "gitlab.com": agentsrv.Ask}},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v", c)
	}
	if err := runCheck([]string{path}); err != nil {
		t.Error(err)
	}
}

func TestAConfigThatWouldSilentlyNotApplyIsRefused(t *testing.T) {
	for _, bad := range []string{
		`{"terminal": "allow"}`,
		`{"forUser": "dan"}`,
		`{"forUser": "dan", "terminal": "refuse"}`,
		`{"forUser": "dan", "terminal": "allow", "sshsig": {"git": "yes"}}`,
		`{"forUser": "dan", "terminal": "allow", "sshsig": {"": "allow"}}`,
		`{"forUser": "dan", "terminal": "allow", "ssh": {"hosts": {"github.com": "refuse"}}}`,
		`{"forUser": "dan", "terminal": "allow", "ssh": {"hosts": {"github.com,evil": "allow"}}}`,
		`{"forUser": "dan", "terminal": "allow", "ssh": {"hosts": {"": "allow"}}}`,
		`{"forUser": "dan", "terminal": "allow", "ssh": {"host": {"github.com": "allow"}}}`,
		`{"forUser": "dan", "terminal": "allow", "hosts": {"github.com": "allow"}}`,
		`{"forUser": "dan", "terminal": "allow"} {}`,
	} {
		if err := runCheck([]string{writeConfig(t, bad)}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// The schema names the same keys the decoder reads.
func TestTheSchemaMatchesTheConfig(t *testing.T) {
	var s struct {
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatal(err)
	}
	keys := func(typ reflect.Type) []string {
		var ks []string
		for f := range typ.Fields() {
			ks = append(ks, f.Tag.Get("json"))
		}
		slices.Sort(ks)
		return ks
	}
	var top, ssh []string
	for k := range s.Properties {
		top = append(top, k)
	}
	for k := range s.Properties["ssh"].Properties {
		ssh = append(ssh, k)
	}
	slices.Sort(top)
	slices.Sort(ssh)
	if want := keys(reflect.TypeFor[config]()); !slices.Equal(top, want) {
		t.Errorf("schema has %v, config has %v", top, want)
	}
	if want := keys(reflect.TypeFor[sshConfig]()); !slices.Equal(ssh, want) {
		t.Errorf("schema's ssh has %v, config's has %v", ssh, want)
	}
}
