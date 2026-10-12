package projpolicy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshKeygen is stock ssh-keygen, the oracle these tests hold the package
// to. The flake's check sets FRISKET_REQUIRE_SSH_KEYGEN, so there a missing
// one fails rather than skips.
func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("FRISKET_REQUIRE_SSH_KEYGEN") != "" {
			t.Fatal("ssh-keygen is required: ", err)
		}
		t.Skip("no ssh-keygen: ", err)
	}
	return p
}

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stockKey makes a key with ssh-keygen and returns its private key path
// and its public key line.
func stockKey(t *testing.T, kg, typ string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_"+typ)
	args := []string{"-q", "-t", typ, "-N", "", "-C", "test", "-f", path}
	if typ == "rsa" {
		args = append(args, "-b", "2048")
	}
	if out, err := run(t, kg, args...); err != nil {
		t.Fatalf("ssh-keygen -t %s: %v\n%s", typ, err, out)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.TrimSpace(string(pub))
}

func write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signers(t *testing.T, body string) *AllowedSigners {
	t.Helper()
	s, err := ParseAllowedSigners([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const ns = "frisket-policy:~/Projects/foo"

var message = "{\n  \"version\": 2\n}\n"

func TestStockSignaturesVerify(t *testing.T) {
	kg := sshKeygen(t)
	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		for _, hash := range []string{"", "sha256", "sha512"} {
			t.Run(typ+"/"+hash, func(t *testing.T) {
				key, pub := stockKey(t, kg, typ)
				dir := t.TempDir()
				msg := write(t, filepath.Join(dir, "chase.json"), message)
				args := []string{"-Y", "sign", "-f", key, "-n", ns}
				if hash != "" {
					args = append(args, "-O", "hashalg="+hash)
				}
				if out, err := run(t, kg, append(args, msg)...); err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
				sig, err := os.ReadFile(msg + ".sig")
				if err != nil {
					t.Fatal(err)
				}
				s, err := ParseSignature(sig)
				if err != nil {
					t.Fatal(err)
				}
				if want := hash; want != "" && s.HashAlg != want {
					t.Errorf("hash %s, want %s", s.HashAlg, want)
				}
				all := signers(t, `dan namespaces="frisket-policy:*" `+pub)
				who, err := Verify([]byte(message), sig, ns, all, "dan", time.Now())
				if err != nil || len(who) != 1 || who[0] != "dan" {
					t.Fatalf("got %v, %v", who, err)
				}
				if _, err := Verify([]byte(message+" "), sig, ns, all, "", time.Now()); err == nil {
					t.Error("a changed byte verified")
				}
				if _, err := Verify([]byte(message), sig, ns+"/sub", all, "", time.Now()); err == nil {
					t.Error("another project's namespace verified")
				}
			})
		}
	}
}

func goSigners(t *testing.T) map[string]ssh.Signer {
	t.Helper()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	out := map[string]ssh.Signer{}
	for name, k := range map[string]any{"ed25519": ed, "ecdsa": ec, "rsa": rs} {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

func TestSignaturesMadeHereVerifyWithStock(t *testing.T) {
	kg := sshKeygen(t)
	for name, s := range goSigners(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sig, err := Sign(rand.Reader, s, ns, []byte(message))
			if err != nil {
				t.Fatal(err)
			}
			msg := write(t, filepath.Join(dir, "chase.json"), message)
			write(t, msg+".sig", string(sig))
			pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
			allowed := write(t, filepath.Join(dir, "allowed_signers"), `dan namespaces="frisket-policy:*" `+pub+"\n")
			cmd := exec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "dan", "-n", ns, "-s", msg+".sig")
			cmd.Stdin = strings.NewReader(message)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, out)
			}
			if _, err := Verify([]byte(message), sig, ns, signers(t, `dan `+pub), "dan", time.Now()); err != nil {
				t.Error(err)
			}
		})
	}
}

// Every line shape, principal, namespace and time is decided as ssh-keygen
// -Y verify decides it.
func TestAllowedSignersAgreeWithStock(t *testing.T) {
	kg := sshKeygen(t)
	key, pub := stockKey(t, kg, "ed25519")
	_, other := stockKey(t, kg, "ed25519")
	dir := t.TempDir()
	msg := write(t, filepath.Join(dir, "chase.json"), message)
	for _, n := range []string{ns, "git", "frisket-policy:/srv/x"} {
		out, err := run(t, kg, "-Y", "sign", "-f", key, "-n", n, msg)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if err := os.Rename(msg+".sig", msg+"."+strings.ReplaceAll(strings.ReplaceAll(n, "/", "_"), "~", "T")+".sig"); err != nil {
			t.Fatal(err)
		}
	}
	sigFor := func(n string) string {
		return msg + "." + strings.ReplaceAll(strings.ReplaceAll(n, "/", "_"), "~", "T") + ".sig"
	}
	lines := []string{
		"dan " + pub,
		"dan " + other,
		`dan namespaces="frisket-policy:*" ` + pub,
		`dan namespaces="git" ` + pub,
		`dan NAMESPACES="frisket-policy:~/*" ` + pub,
		`dan namespaces="frisket-*,!frisket-policy:/*" ` + pub,
		`dan namespaces="git,frisket-policy:~/Projects/fo?" ` + pub,
		"dan,!eve " + pub,
		"d?n " + pub,
		"* " + pub,
		"*,!dan " + pub,
		`"bob,dan" ` + pub,
		`dan valid-after="20300101" ` + pub,
		`dan valid-before="20250101Z" ` + pub,
		`dan valid-after="20250101",valid-before="20270101" ` + pub,
		`dan valid-after="202601011200Z" ` + pub,
		`dan namespaces="frisket-policy:*",valid-before="20260601" ` + pub,
	}
	type when struct{ flag, ours string }
	for i, line := range lines {
		allowed := write(t, filepath.Join(dir, fmt.Sprintf("allowed_%d", i)), "# a comment\n\n"+line+"\n")
		parsed, err := ReadAllowedSigners(allowed)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		for _, principal := range []string{"dan", "eve", "bob"} {
			for _, n := range []string{ns, "git", "frisket-policy:/srv/x"} {
				for _, at := range []string{"20240101", "20260101", "20260101130000", "20261231", "20310101"} {
					sig, err := os.ReadFile(sigFor(n))
					if err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(kg, "-Y", "verify", "-f", allowed, "-I", principal, "-n", n, "-s", sigFor(n), "-O", "verify-time="+at+"Z")
					cmd.Stdin = strings.NewReader(message)
					out, err := cmd.CombinedOutput()
					stock := err == nil
					now, perr := parseTime(at + "Z")
					if perr != nil {
						t.Fatal(perr)
					}
					_, verr := Verify([]byte(message), sig, n, parsed, principal, now)
					if ours := verr == nil; ours != stock {
						t.Errorf("%s -I %s -n %s at %s: ssh-keygen says %v (%s), we say %v (%v)", line, principal, n, at, stock, strings.TrimSpace(string(out)), ours, verr)
					}
				}
			}
		}
	}
}

func TestAllowedSignersRefusesWhatWouldSilentlyNotApply(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(ed)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	for _, bad := range []string{
		"dan",
		"dan cert-authority " + pub,
		"dan cert-authority,namespaces=\"git\" " + pub,
		"dan principals=\"x\" " + pub,
		"dan namespaces " + pub,
		"dan namespaces=\"git\",namespaces=\"file\" " + pub,
		"dan valid-after=\"2026\" " + pub,
		"dan valid-before=\"20260101\",valid-after=\"20270101\" " + pub,
		"dan ssh-ed25519 AAAAnotbase64",
		"\"dan " + pub,
		"\"dan\"" + pub,
	} {
		if _, err := ParseAllowedSigners([]byte(bad + "\n")); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	got := signers(t, "# c\n\n  dan "+pub+" a comment\n")
	if len(got.Lines) != 1 || got.Lines[0].Line != 3 || got.Lines[0].Principals != "dan" {
		t.Errorf("got %+v", got.Lines)
	}
}

func TestMatchPatternIsOpenSSHs(t *testing.T) {
	for _, c := range []struct {
		s, p string
		want bool
	}{
		{"", "", true}, {"a", "", false}, {"", "*", true}, {"abc", "a*c", true},
		{"abc", "a?c", true}, {"ac", "a?c", false}, {"a/b/c", "a*", true},
		{"frisket-policy:~/x", "frisket-policy:*", true}, {"abcbc", "*bc", true},
		{"abcbd", "*bc", false}, {"aXbXc", "a*b*c", true}, {"ab", "a**b", true},
		{"Dan", "dan", false}, {"abc", "*?", true}, {"", "?", false},
	} {
		if got := MatchPattern(c.s, c.p); got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v", c.s, c.p, got)
		}
	}
	for _, c := range []struct {
		s, list string
		want    int
	}{
		{"dan", "dan", 1}, {"dan", "bob,dan", 1}, {"dan", "!dan", -1}, {"dan", "*,!dan", -1},
		{"dan", "!eve", 0}, {"dan", "!eve,d*", 1}, {"git", "frisket-*", 0}, {"dan", "", 0},
	} {
		if got := MatchPatternList(c.s, c.list); got != c.want {
			t.Errorf("MatchPatternList(%q, %q) = %d", c.s, c.list, got)
		}
	}
}

func TestAMalformedSignatureIsRefused(t *testing.T) {
	s := goSigners(t)["ed25519"]
	good, err := Sign(rand.Reader, s, ns, []byte(message))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignature(good); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(good), "\n")
	for name, bad := range map[string]string{
		"empty":     "",
		"no begin":  strings.Join(lines[1:], "\n"),
		"no end":    strings.Join(lines[:len(lines)-2], "\n"),
		"prefix":    "x\n" + string(good),
		"base64":    lines[0] + "\n!!!!\n" + lines[len(lines)-2] + "\n",
		"truncated": lines[0] + "\n" + lines[1] + "\n" + lines[len(lines)-2] + "\n",
	} {
		if _, err := ParseSignature([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
