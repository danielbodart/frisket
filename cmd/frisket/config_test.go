package main

import (
	"encoding/json"
	"os"
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

func TestAConfigReadsEverySetting(t *testing.T) {
	path := writeConfig(t, `{
		"dns": ["192.0.2.53"], "logLevel": "debug", "controlSocket": "/run/x/control.sock",
		"policyRoots": ["/etc/frisket/policies", "/run/user/1000/chase"],
		"asker": "/nix/store/x-ask", "askerConcurrent": 4, "askerPerSession": 2,
		"recordDir": "/var/lib/frisket/records", "maxConnections": 64,
		"gitSigning": {"agent": "/run/frisket-signer/agent", "policies": ["trusted", "work"]}
	}`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &config{
		DNS: []string{"192.0.2.53"}, LogLevel: "debug", ControlSocket: "/run/x/control.sock",
		PolicyRoots: []string{"/etc/frisket/policies", "/run/user/1000/chase"},
		Asker:       "/nix/store/x-ask", AskerConcurrent: 4, AskerPerSession: 2,
		RecordDir: "/var/lib/frisket/records", MaxConnections: 64,
		GitSigning: gitSigningConfig{Agent: "/run/frisket-signer/agent", Policies: []string{"trusted", "work"}},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v", c)
	}
	if err := runCheck([]string{"-config", path}); err != nil {
		t.Error(err)
	}
}

// What a flag's default was, a field left out is.
func TestAnEmptyConfigIsTheDefaults(t *testing.T) {
	c, err := loadConfig(writeConfig(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	want := &config{LogLevel: "info", ControlSocket: "/run/frisket/control.sock", AskerConcurrent: 1, AskerPerSession: 1}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v", c)
	}
}

func TestAConfigThatWouldSilentlyNotApplyIsRefused(t *testing.T) {
	for _, bad := range []string{
		`{"policies": {}}`,
		`{"dns": [], "maxConns": 4}`,
		`{"logLevel": "loud"}`,
		`{"logLevel": "info+2"}`,
		`{"controlSocket": "control.sock"}`,
		`{"policyRoots": ["relative"]}`,
		`{"policyRoots": ["/etc/../tmp"]}`,
		`{"asker": "ask"}`,
		`{"askerConcurrent": -1}`,
		`{"askerPerSession": -1}`,
		`{"recordDir": "/var/lib/frisket/records/"}`,
		`{"maxConnections": -1}`,
		`{"gitSigning": {"policies": ["trusted"]}}`,
		`{"gitSigning": {"agent": "/a", "policies": ["../x"]}}`,
		`{"gitSigning": {"agent": "/a", "policies": ["trusted", "trusted"]}}`,
		`{"gitSigning": {"agent": "/a", "policy": ["trusted"]}}`,
		`{} {}`,
	} {
		if err := runCheck([]string{"-config", writeConfig(t, bad)}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

func TestCheckConfigTakesNoDocuments(t *testing.T) {
	path := writeConfig(t, `{}`)
	for _, argv := range [][]string{{"-config", path, "doc.json"}, {"-config", path, "-exec", "r"}} {
		if err := runCheck(argv); err == nil {
			t.Errorf("%q was accepted", argv)
		}
	}
}

func TestServeRefusesABadConfigBeforeTheSocket(t *testing.T) {
	err := runServe([]string{"-config", writeConfig(t, `{"asker-concurrent": 2}`)})
	if err == nil || !strings.Contains(err.Error(), `unknown field "asker-concurrent"`) {
		t.Errorf("got %v", err)
	}
	if err := runServe([]string{"-config", writeConfig(t, `{}`), "-log-level", "loud"}); err == nil || !strings.Contains(err.Error(), "-log-level") {
		t.Errorf("got %v", err)
	}
}

// The schema names the same keys the decoder reads.
func TestTheSchemaMatchesTheConfig(t *testing.T) {
	var s struct {
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
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
	var top, git []string
	for k := range s.Properties {
		top = append(top, k)
	}
	for k := range s.Properties["gitSigning"].Properties {
		git = append(git, k)
	}
	slices.Sort(top)
	slices.Sort(git)
	if want := keys(reflect.TypeFor[config]()); !slices.Equal(top, want) {
		t.Errorf("schema has %v, config has %v", top, want)
	}
	if want := keys(reflect.TypeFor[gitSigningConfig]()); !slices.Equal(git, want) {
		t.Errorf("schema's gitSigning has %v, config's has %v", git, want)
	}
	if err := runSchema(nil); err == nil {
		t.Error("schema with no -config was accepted")
	}
}
