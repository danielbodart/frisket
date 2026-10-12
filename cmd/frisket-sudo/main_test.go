package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/sudo"
	"golang.org/x/crypto/ssh"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func key(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func line(k ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k)), "\n")
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestServeRefusesToStartWithoutTheGateFd(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	err := runServe([]string{"-config", writeConfig(t, `{"forUser": "dan"}`)})
	if err == nil || !strings.Contains(err.Error(), "no socket named gate") {
		t.Errorf("got %v", err)
	}
}

func TestServeRefusesABadConfigBeforeTheSocket(t *testing.T) {
	err := runServe([]string{"-config", writeConfig(t, `{"user": "dan"}`)})
	if err == nil || !strings.Contains(err.Error(), `unknown field "user"`) {
		t.Errorf("got %v", err)
	}
}

func TestAConfigReadsEverySetting(t *testing.T) {
	a, b := key(t), key(t)
	path := writeConfig(t, `{
		"forUser": "dan",
		"remoteKeys": [`+quote(line(a)+" alice@laptop")+`, `+quote(line(b))+`],
		"danger": {"reboot **": {"reason": "reboots this machine"},
		           "systemctl **": {"args": {"postgresql*": "touches the database"}}}
	}`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]sudo.Extra{
		"reboot **":    {Reason: "reboots this machine"},
		"systemctl **": {Args: map[string]string{"postgresql*": "touches the database"}},
	}
	if c.ForUser != "dan" || len(c.RemoteKeys) != 2 || !reflect.DeepEqual(c.Danger, want) {
		t.Errorf("got %+v", c)
	}
	if len(c.keys) != 2 || !slices.Equal(c.keys[0].Marshal(), a.Marshal()) || !slices.Equal(c.keys[1].Marshal(), b.Marshal()) {
		t.Errorf("keys %v", c.keys)
	}
	if err := runCheck([]string{path}); err != nil {
		t.Error(err)
	}
}

func TestAConfigThatWouldSilentlyNotApplyIsRefused(t *testing.T) {
	k := line(key(t))
	for _, bad := range []string{
		`{}`,
		`{"forUser": ""}`,
		`{"user": "dan"}`,
		`{"forUser": "dan", "remoteKeys": ["not a key"]}`,
		`{"forUser": "dan", "remoteKeys": [` + quote(k+"\n"+k) + `]}`,
		`{"forUser": "dan", "remoteKeys": ` + quote(k) + `}`,
		`{"forUser": "dan", "danger": {"reboot": {}}}`,
		`{"forUser": "dan", "danger": {"reboot": {"reason": ""}}}`,
		`{"forUser": "dan", "danger": {"reboot": {"why": "x"}}}`,
		`{"forUser": "dan", "danger": {"reboot": "x"}}`,
		`{"forUser": "dan", "danger": {"** reboot": {"reason": "x"}}}`,
		`{"forUser": "dan", "danger": {"systemctl **": {"args": {"frisket*": "x"}}}}`,
		`{"forUser": "dan", "danger": {"systemctl **": {"args": {"": "x"}}}}`,
		`{"forUser": "dan"} {}`,
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
		Required   []string                   `json:"required"`
		Defs       struct {
			Danger struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"danger"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatal(err)
	}
	keys := func(typ reflect.Type) []string {
		var ks []string
		for f := range typ.Fields() {
			if tag := f.Tag.Get("json"); tag != "" {
				ks = append(ks, strings.Split(tag, ",")[0])
			}
		}
		slices.Sort(ks)
		return ks
	}
	props := func(m map[string]json.RawMessage) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return ks
	}
	if got, want := props(s.Properties), keys(reflect.TypeFor[config]()); !slices.Equal(got, want) {
		t.Errorf("schema has %v, config has %v", got, want)
	}
	if got, want := props(s.Defs.Danger.Properties), keys(reflect.TypeFor[sudo.Extra]()); !slices.Equal(got, want) {
		t.Errorf("schema's danger has %v, sudo.Extra has %v", got, want)
	}
	if !slices.Equal(s.Required, []string{"forUser"}) {
		t.Errorf("required %v", s.Required)
	}
}
