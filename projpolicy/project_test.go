package projpolicy

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestTheNamespaceNamesTheRootFromHome(t *testing.T) {
	for _, c := range []struct{ root, home, want string }{
		{"/home/dan/Projects/foo", "/home/dan", "frisket-policy:~/Projects/foo"},
		{"/home/dan/Projects/foo/", "/home/dan/", "frisket-policy:~/Projects/foo"},
		{"/home/dan/Projects/../x", "/home/dan", "frisket-policy:~/x"},
		{"/home/dan", "/home/dan", "frisket-policy:~"},
		{"/home/danny/x", "/home/dan", "frisket-policy:/home/danny/x"},
		{"/srv/x/", "/home/dan", "frisket-policy:/srv/x"},
		{"/srv/x", "", "frisket-policy:/srv/x"},
		{"/", "/", "frisket-policy:~"},
		{"/a b/c", "/", "frisket-policy:~/a b/c"},
	} {
		got, err := Namespace(c.root, c.home)
		if err != nil || got != c.want {
			t.Errorf("Namespace(%q, %q) = %q, %v; want %q", c.root, c.home, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{"x", "/home/dan"}, {"/x", "home"}} {
		if _, err := Namespace(bad[0], bad[1]); err == nil {
			t.Errorf("Namespace(%q, %q) was accepted", bad[0], bad[1])
		}
	}
}

func TestFindIsTheNearestAncestorBoundedAtHome(t *testing.T) {
	top := t.TempDir()
	home := filepath.Join(top, "home")
	mk := func(p string) string {
		p = filepath.Join(top, p)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	put := func(dir string) { write(t, filepath.Join(dir, "chase.json"), "{}\n") }
	proj := mk("home/Projects/foo")
	deep := mk("home/Projects/foo/a/b")
	inner := mk("home/Projects/foo/a/inner")
	bare := mk("home/Projects/bare/x")
	outside := mk("srv/x")
	put(proj)
	put(inner)
	put(filepath.Join(top, "srv"))
	put(top)

	for _, c := range []struct{ dir, want string }{
		{proj, proj}, {deep, proj}, {inner, inner}, {filepath.Join(inner, "."), inner},
	} {
		got, err := Find(c.dir, home, "chase.json")
		if err != nil || got != c.want {
			t.Errorf("Find(%s) = %q, %v; want %q", c.dir, got, err, c.want)
		}
	}
	for _, dir := range []string{bare, outside, top, filepath.Join(top, "homeless")} {
		if got, err := Find(dir, home, "chase.json"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Find(%s) = %q, %v; want not found", dir, got, err)
		}
	}
	put(home)
	if got, err := Find(bare, home, "chase.json"); err != nil || got != home {
		t.Errorf("home's own file: %q, %v", got, err)
	}

	link := mk("home/Projects/link/sub")
	if err := os.Symlink(filepath.Join(proj, "chase.json"), filepath.Join(top, "home/Projects/link/chase.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(link, home, "chase.json"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("a symlinked policy file was passed over or taken: %v", err)
	}
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := Find(proj, home, name); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
}

func TestLoadSaysWhetherTheSignatureVerifiesAndWhyNot(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects", "foo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	s := goSigners(t)["ecdsa"]
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	all := signers(t, `dan namespaces="frisket-policy:*" `+pub)
	path := filepath.Join(root, "chase.json")
	write(t, path, message)

	p, err := Load(root, home, "chase.json", all)
	if err != nil || p.Verified || p.Why != "no chase.json.sig" || p.Sig != nil {
		t.Fatalf("unsigned: %+v, %v", p, err)
	}
	sig, err := Sign(rand.Reader, s, "frisket-policy:~/Projects/foo", []byte(message))
	if err != nil {
		t.Fatal(err)
	}
	write(t, path+".sig", string(sig))
	p, err = Load(root, home, "chase.json", all)
	if err != nil || !p.Verified || p.Namespace != "frisket-policy:~/Projects/foo" ||
		!reflect.DeepEqual(p.Principals, []string{"dan"}) || p.Digest != Digest([]byte(message)) {
		t.Fatalf("signed: %+v, %v", p, err)
	}

	// The same file and signature moved to another project do not verify.
	other := filepath.Join(home, "Projects", "bar")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(other, "chase.json"), message)
	write(t, filepath.Join(other, "chase.json.sig"), string(sig))
	p, err = Load(other, home, "chase.json", all)
	if err != nil || p.Verified || !strings.Contains(p.Why, "not \"frisket-policy:~/Projects/bar\"") {
		t.Fatalf("moved: %+v, %v", p, err)
	}

	write(t, path, message+"\n")
	if p, _ = Load(root, home, "chase.json", all); p.Verified {
		t.Error("an edited file verified")
	}
	write(t, path, message)
	if p, _ = Load(root, home, "chase.json", signers(t, "")); p.Verified || !strings.Contains(p.Why, "not an allowed signer") {
		t.Errorf("no signers: %+v", p)
	}
	if _, err := Load(filepath.Join(home, "none"), home, "chase.json", all); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no file: %v", err)
	}
}

func TestFormatIsCanonical(t *testing.T) {
	in := `{"z": 1, "a": {"y": [3, {"b": true, "a": null}], "x": "<&>"}, "m": -0, "é": "é"}`
	want := `{
  "a": {
    "x": "<&>",
    "y": [
      3,
      {
        "a": null,
        "b": true
      }
    ]
  },
  "m": -0,
  "z": 1,
  "é": "é"
}
`
	got, err := Format([]byte(in))
	if err != nil || string(got) != want {
		t.Fatalf("got %s, %v", got, err)
	}
	if !Canonical(got) || Canonical([]byte(in)) {
		t.Error("Canonical disagrees with Format")
	}
	again, _ := Format(got)
	if string(again) != string(got) {
		t.Error("Format is not idempotent")
	}
	if got, _ := Format([]byte(`{}`)); string(got) != "{}\n" {
		t.Errorf("empty: %q", got)
	}
	for _, bad := range []string{
		``, `{"a": 1, "a": 2}`, `{"a": {"b": 1, "b": 1}}`, `{"a": 1.5}`, `{"a": 1e3}`, `{"a": 01}`,
		`{} {}`, `{"a": 1`, "{\"a\": \"\xff\"}", `[1, 2.0]`,
	} {
		if _, err := Format([]byte(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// RFC 7396's own examples, Appendix A.
func TestMergePatchIsRFC7396(t *testing.T) {
	for _, c := range [][3]string{
		{`{"a":"b"}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"b"}`, `{"b":"c"}`, `{"a":"b","b":"c"}`},
		{`{"a":"b"}`, `{"a":null}`, `{}`},
		{`{"a":"b","b":"c"}`, `{"a":null}`, `{"b":"c"}`},
		{`{"a":["b"]}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"c"}`, `{"a":["b"]}`, `{"a":["b"]}`},
		{`{"a":{"b":"c"}}`, `{"a":{"b":"d","c":null}}`, `{"a":{"b":"d"}}`},
		{`{"a":[{"b":"c"}]}`, `{"a":[1]}`, `{"a":[1]}`},
		{`["a","b"]`, `["c","d"]`, `["c","d"]`},
		{`{"a":"b"}`, `["c"]`, `["c"]`},
		{`{"a":"foo"}`, `null`, `null`},
		{`{"a":"foo"}`, `"bar"`, `"bar"`},
		{`{"e":null}`, `{"a":1}`, `{"a":1,"e":null}`},
		{`[1,2]`, `{"a":"b","c":null}`, `{"a":"b"}`},
		{`{}`, `{"a":{"bb":{"ccc":null}}}`, `{"a":{"bb":{}}}`},
	} {
		target, err := Decode([]byte(c[0]))
		if err != nil {
			t.Fatal(err)
		}
		patch, err := Decode([]byte(c[1]))
		if err != nil {
			t.Fatal(err)
		}
		before, _ := json.Marshal(target)
		got, _ := json.Marshal(MergePatch(target, patch))
		var want any
		_ = json.Unmarshal([]byte(c[2]), &want)
		wantB, _ := json.Marshal(want)
		if string(got) != string(wantB) {
			t.Errorf("%s + %s = %s, want %s", c[0], c[1], got, wantB)
		}
		if after, _ := json.Marshal(target); string(after) != string(before) {
			t.Errorf("%s + %s changed the target to %s", c[0], c[1], after)
		}
	}
}
