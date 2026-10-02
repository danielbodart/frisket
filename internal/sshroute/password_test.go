package sshroute

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/policy"
)

// logins is what a password-only machine was given, by either method.
type logins struct {
	mu          sync.Mutex
	passwords   []string
	interactive [][]string
}

func (l *logins) add(pw string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.passwords = append(l.passwords, pw)
}

func (l *logins) addAnswers(a []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.interactive = append(l.interactive, a)
}

func (l *logins) got() ([]string, [][]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.passwords...), append([][]string(nil), l.interactive...)
}

const thePassword = "correct horse"

func passwordFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// passwordFixture is a machine that takes no key: by "password" if
// password, and by "keyboard-interactive" with challenge if it is set.
func passwordFixture(t *testing.T, file string, password bool, challenge func(ssh.KeyboardInteractiveChallenge, *logins) error) (*fixture, *logins) {
	t.Helper()
	l := &logins{}
	f := newFixture(t, options{
		sshd: func(d *sshd) {
			d.configure = func(cfg *ssh.ServerConfig) {
				cfg.PublicKeyCallback = nil
				if password {
					cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
						l.add(string(pw))
						if c.User() == "dan" && string(pw) == thePassword {
							return &ssh.Permissions{}, nil
						}
						return nil, errors.New("wrong password")
					}
				}
				if challenge != nil {
					cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if err := challenge(ch, l); err != nil {
							return nil, err
						}
						return &ssh.Permissions{}, nil
					}
				}
			}
		},
		route: func(r *policy.SSHRoute) { r.Agent, r.PasswordFile = "", file },
	})
	return f, l
}

// askPassword is a PAM-like challenge: one hidden prompt for the password.
func askPassword(ch ssh.KeyboardInteractiveChallenge, l *logins) error {
	a, err := ch("", "", []string{"Password: "}, []bool{false})
	if err != nil {
		return err
	}
	l.addAnswers(a)
	if len(a) != 1 || a[0] != thePassword {
		return errors.New("wrong password")
	}
	return nil
}

func TestAPasswordFileLogsInByPasswordReadAtEachLogin(t *testing.T) {
	file := passwordFile(t, thePassword+"\n")
	f, l := passwordFixture(t, file, true, nil)
	if r := run(t, f.connect(), "echo hi", nil); r.stdout != "hi\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	if err := os.WriteFile(file, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || strings.Contains(r.stderr, "wrong") || strings.Contains(r.stderr, thePassword) {
		t.Errorf("a password changed since: %+v", r)
	}
	if pw, _ := l.got(); strings.Join(pw, "|") != thePassword+"|wrong" {
		t.Errorf("the machine was given %q: the file, less its newline, read at each login", pw)
	}
	if strings.Contains(f.j.buf.String(), "wrong") || strings.Contains(f.j.buf.String(), thePassword) {
		t.Error("the log holds a password")
	}
}

func TestAPasswordFileIsTakenWithOrWithoutItsNewline(t *testing.T) {
	for _, content := range []string{thePassword, thePassword + "\n", thePassword + "\r\n"} {
		f, l := passwordFixture(t, passwordFile(t, content), true, nil)
		if r := run(t, f.connect(), "echo hi", nil); r.status != 0 {
			t.Errorf("%q: %+v", content, r)
		}
		if pw, _ := l.got(); len(pw) != 1 || pw[0] != thePassword {
			t.Errorf("%q: given %q", content, pw)
		}
	}
}

func TestAPasswordFileThatCannotBeReadFailsTheLoginSayingWhyAndNotWhat(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("p", maxPasswordFile+1)
	for _, tc := range []struct {
		name, content, want string
	}{
		{"missing", "", "password file"},
		{"empty", "\n", "is empty"},
		{"too long", big, "over"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(dir, tc.name)
			if tc.name != "missing" {
				if err := os.WriteFile(file, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f, l := passwordFixture(t, file, true, nil)
			r := run(t, f.connect(), "echo hi", nil)
			if r.status != exitUpstream || !strings.Contains(r.stderr, tc.want) || strings.Contains(r.stderr, "ppp") {
				t.Errorf("got status %d, stderr %q", r.status, r.stderr)
			}
			// Where frisket keeps the credential is the journal's, never
			// the sandbox's.
			if strings.Contains(r.stderr, dir) {
				t.Errorf("stderr %q names the file", r.stderr)
			}
			waitFor(t, "a line", func() bool { return len(f.sshLines()) == 1 })
			if l := f.sshLines()[0]; !strings.Contains(fmt.Sprint(l["error"]), file) {
				t.Errorf("the line's error %v does not name the file", l["error"])
			}
			if pw, _ := l.got(); len(pw) != 0 || f.sshd.dials() != 0 {
				t.Errorf("the machine was dialled %d times and given %q", f.sshd.dials(), pw)
			}
		})
	}
}

func TestAMachineOfferingOnlyKeyboardInteractiveIsGivenThePasswordWhereItIsHidden(t *testing.T) {
	f, l := passwordFixture(t, passwordFile(t, thePassword+"\n"), false, func(ch ssh.KeyboardInteractiveChallenge, l *logins) error {
		// A round that asks nothing first, as an instruction alone.
		if _, err := ch("", "Welcome", nil, nil); err != nil {
			return err
		}
		return askPassword(ch, l)
	})
	if r := run(t, f.connect(), "echo hi", nil); r.stdout != "hi\n" || r.status != 0 {
		t.Errorf("got %+v", r)
	}
	if _, a := l.got(); len(a) != 1 {
		t.Errorf("answers %q", a)
	}
}

// A prompt that echoes, or a second hidden one after the password, is the
// machine asking for something else: the login ends, and the password goes
// nowhere it was not asked for.
func TestKeyboardInteractiveAnswersOnlyOneRoundOfHiddenPrompts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		challenge func(ssh.KeyboardInteractiveChallenge, *logins) error
		want      string
		answered  int
	}{
		{"a prompt that echoes", func(ch ssh.KeyboardInteractiveChallenge, l *logins) error {
			a, err := ch("", "", []string{"Username: ", "Password: "}, []bool{true, false})
			if err == nil {
				l.addAnswers(a)
			}
			return err
		}, "echoes", 0},
		{"a second hidden round", func(ch ssh.KeyboardInteractiveChallenge, l *logins) error {
			if err := askPassword(ch, l); err != nil {
				return err
			}
			a, err := ch("", "", []string{"Verification code: "}, []bool{false})
			if err == nil {
				l.addAnswers(a)
			}
			return err
		}, "again", 1},
		{"rounds without end", func(ch ssh.KeyboardInteractiveChallenge, l *logins) error {
			for {
				if _, err := ch("", "more", nil, nil); err != nil {
					return err
				}
			}
		}, "rounds", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, l := passwordFixture(t, passwordFile(t, thePassword), false, tc.challenge)
			r := run(t, f.connect(), "echo hi", nil)
			if r.status != exitUpstream || !strings.Contains(r.stderr, tc.want) || strings.Contains(r.stderr, thePassword) {
				t.Errorf("got status %d, stderr %q", r.status, r.stderr)
			}
			if _, a := l.got(); len(a) != tc.answered {
				t.Errorf("answered %q", a)
			}
		})
	}
}

// A password refused by "password" is not offered again by
// "keyboard-interactive": a device that locks an account counts each.
func TestAWrongPasswordIsTriedOnce(t *testing.T) {
	f, l := passwordFixture(t, passwordFile(t, "wrong"), true, askPassword)
	if r := run(t, f.connect(), "echo hi", nil); r.status != exitUpstream {
		t.Errorf("got %+v", r)
	}
	pw, a := l.got()
	if len(pw) != 1 || len(a) != 0 {
		t.Errorf("given %d passwords and %d answers, want the one password", len(pw), len(a))
	}
}

// A password the machine refused is not tried again while the file still
// holds it, for passwordCoolOff: a workload running a command in a loop
// would otherwise try it once a connection, and a device that locks an
// account counts each. Another password in the file is tried at once.
func TestARefusedPasswordIsNotTriedAgainUntilTheFileChangesOrItCoolsOff(t *testing.T) {
	coolOff := passwordCoolOff
	t.Cleanup(func() { passwordCoolOff = coolOff })
	file := passwordFile(t, "stale\n")
	f, l := passwordFixture(t, file, true, nil)
	for range 3 {
		if r := run(t, f.connect(), "echo hi", nil); r.status != exitUpstream {
			t.Errorf("got %+v", r)
		}
	}
	r := run(t, f.connect(), "echo hi", nil)
	if r.status != exitUpstream || !strings.Contains(r.stderr, "refused this password") || strings.Contains(r.stderr, file) {
		t.Errorf("got %+v", r)
	}
	if pw, _ := l.got(); strings.Join(pw, "|") != "stale" || f.sshd.dials() != 1 {
		t.Errorf("the machine was dialled %d times and given %q", f.sshd.dials(), pw)
	}
	passwordCoolOff = 0
	run(t, f.connect(), "echo hi", nil)
	if pw, _ := l.got(); strings.Join(pw, "|") != "stale|stale" {
		t.Errorf("once cooled off, given %q", pw)
	}
	passwordCoolOff = time.Hour
	if err := os.WriteFile(file, []byte(thePassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(t, f.connect(), "echo hi", nil); r.stdout != "hi\n" || r.status != 0 {
		t.Errorf("another password: %+v", r)
	}
	if strings.Contains(f.j.buf.String(), "stale") || strings.Contains(f.j.buf.String(), thePassword) {
		t.Error("the log holds a password")
	}
}
