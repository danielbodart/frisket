package galleyask

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeGalley listens where Ask dials, answers one item with reply (none when
// empty) and reports the item's line and the client's hang-up.
type fakeGalley struct {
	user   string
	items  chan []byte
	closed chan struct{}
}

func startGalley(t *testing.T, reply string, inGalleyCgroup bool) *fakeGalley {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortDir(t)
	oldDir, oldCgroup := socketDir, galleyCgroup
	t.Cleanup(func() { socketDir, galleyCgroup = oldDir, oldCgroup })
	socketDir = dir
	own := ownCgroup(t)
	galleyCgroup = func(int) (uint64, error) {
		if inGalleyCgroup {
			return own, nil
		}
		return own + 1, nil
	}

	l, err := net.Listen("unix", filepath.Join(dir, me.Username+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	g := &fakeGalley{user: me.Username, items: make(chan []byte, 1), closed: make(chan struct{})}
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, err := r.ReadBytes('\n')
		if err == nil {
			g.items <- line
			if reply != "" {
				c.Write([]byte(reply + "\n"))
			}
		}
		for err == nil {
			_, err = r.ReadByte()
		}
		close(g.closed)
	}()
	return g
}

// shortDir is a directory whose socket paths fit a sun_path, which a test's
// own TempDir, named after the test, may not.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "galleyask")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func ownCgroup(t *testing.T) uint64 {
	t.Helper()
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_CGROUPID}
	if err := unix.IoctlPidfdInfo(pidfd, &info); err != nil {
		t.Fatal(err)
	}
	return info.Cgroupid
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

func TestAnAnswerFromAPeerOutsideGalleysCgroupIsNobody(t *testing.T) {
	g := startGalley(t, golden(t, "answer-extra.json"), false)
	_, err := Ask(context.Background(), g.user, Question{Title: "ssh to server"})
	if !errors.Is(err, ErrNobody) {
		t.Fatalf("got %v, want nobody", err)
	}
	if !strings.Contains(err.Error(), "not galley.service") {
		t.Errorf("%v does not name the cgroup", err)
	}
	<-g.closed
	select {
	case line := <-g.items:
		t.Fatalf("posted %s", line)
	default:
	}
}

func TestNoSocketIsNobody(t *testing.T) {
	g := startGalley(t, "", true)
	socketDir = shortDir(t)
	if _, err := Ask(context.Background(), g.user, Question{}); !errors.Is(err, ErrNobody) {
		t.Fatalf("got %v, want nobody", err)
	}
}

func TestTheQuestionsEncodeToTheGoldenBytes(t *testing.T) {
	for file, q := range map[string]Question{
		"signer-form.json": {Title: "ssh to github.com", Level: "normal", Grantable: true,
			Text: "claude (pid 5113) ← bash ← git push ← ssh\nkey SHA256:… (dan@dan-blade)\nA grant covers github.com from this claude."},
		"signer-question.json": {Title: "ssh to server", Level: "warning",
			Text: "launched through systemd --user\nsystemd --user ← ssh"},
		"sudo-dialog.json": {Title: "sudo systemctl restart foo", Level: "normal", Grantable: true, Password: true,
			Text: "claude (pid 5113) ← bash\n\n/run/current-system/sw/bin/systemctl restart foo"},
		"sudo-dialog-warning.json": {Title: "sudo systemctl restart foo", Level: "warning", Password: true,
			Text: "launched through systemd --user\nsystemd --user ← bash\n\n/run/current-system/sw/bin/systemctl restart foo"},
		"sudo-dialog-danger.json": {Title: "sudo systemctl stop sshd.service", Level: "danger", Password: true,
			Text: "touches a unit that guards this machine\n\nclaude (pid 5113) ← bash\n/run/current-system/sw/bin/systemctl stop sshd.service"},
	} {
		t.Run(file, func(t *testing.T) {
			g := startGalley(t, golden(t, "answer-cancel.json"), true)
			if _, err := Ask(context.Background(), g.user, q); err != nil {
				t.Fatal(err)
			}
			got := strings.ReplaceAll(string(<-g.items), "Password for "+g.user, "Password for dan")
			if want := golden(t, file) + "\n"; got != want {
				t.Errorf("sent\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestEveryGoldenAnswerLineDecodesToItsResult(t *testing.T) {
	signer := Question{Grantable: true}
	dialog := Question{Grantable: true, Password: true}
	for _, c := range []struct {
		file    string
		q       Question
		allowed bool
		for_    time.Duration
		pw      string
		nobody  bool
	}{
		{"answer-extra.json", signer, true, 0, "", false},
		{"answer-extra.json", Question{}, true, 0, "", false},
		{"answer-extra.json", dialog, false, 0, "", false},
		{"answer-allow-for.json", signer, true, 15 * time.Minute, "", false},
		{"answer-allow-for.json", Question{}, false, 0, "", false},
		{"answer-sudo-dialog.json", dialog, true, 15 * time.Minute, "hunter2", false},
		{"answer-sudo-dialog-once.json", Question{Password: true}, true, 0, "hunter2", false},
		{"answer-cancel.json", signer, false, 0, "", false},
		{"answer-close.json", dialog, false, 0, "", false},
		{"answer-error.json", signer, false, 0, "", true},
	} {
		t.Run(c.file, func(t *testing.T) {
			g := startGalley(t, golden(t, c.file), true)
			a, err := Ask(context.Background(), g.user, c.q)
			if c.nobody {
				if !errors.Is(err, ErrNobody) {
					t.Fatalf("got %v, want nobody", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.Allowed != c.allowed || a.For != c.for_ || string(a.Password) != c.pw {
				t.Errorf("got allowed %v for %v password %q", a.Allowed, a.For, a.Password)
			}
			if a.Galley.Pid != os.Getpid() || a.Galley.Start == 0 {
				t.Errorf("galley pid %d start %d, want pid %d", a.Galley.Pid, a.Galley.Start, os.Getpid())
			}
		})
	}
}

func TestGalleyGoingAwayBeforeAnAnswerIsNobody(t *testing.T) {
	g := startGalley(t, "", true)
	l, err := net.Listen("unix", filepath.Join(shortDir(t), g.user+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	socketDir = filepath.Dir(l.Addr().String())
	go func() {
		c, err := l.Accept()
		if err == nil {
			bufio.NewReader(c).ReadBytes('\n')
			c.Close()
		}
	}()
	if _, err := Ask(context.Background(), g.user, Question{}); !errors.Is(err, ErrNobody) {
		t.Fatalf("got %v, want nobody", err)
	}
}

func TestTheTimeFieldParsesClampsAndLogsNoRawText(t *testing.T) {
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	defer slog.SetDefault(old)

	for _, c := range []struct {
		number, unit string
		want         time.Duration
	}{
		{"15", "minutes", 15 * time.Minute},
		{"2", "hours", 2 * time.Hour},
		{"15", "", 15 * time.Minute},
		{"0", "minutes", 0},
		{"hunter2", "minutes", 0},
		{"-5", "minutes", 0},
		{"5", "days", 0},
		{"100", "hours", 24 * time.Hour},
		{"9999999999", "minutes", 24 * time.Hour},
	} {
		if got := duration(c.number, c.unit); got != c.want {
			t.Errorf("%q %q is %v, want %v", c.number, c.unit, got, c.want)
		}
	}
	if n := strings.Count(log.String(), "time not understood"); n != 3 {
		t.Errorf("logged %d times:\n%s", n, log.String())
	}
	if strings.Contains(log.String(), "hunter2") {
		t.Errorf("logged the text:\n%s", log.String())
	}
}

func TestHangUpWithdrawsTheRow(t *testing.T) {
	g := startGalley(t, "", true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := Ask(ctx, g.user, Question{Title: "ssh to server"})
		done <- err
	}()
	<-g.items
	cancel()
	<-g.closed
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancelled", err)
	}
}

func TestThePasswordIsNeverLogged(t *testing.T) {
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	defer slog.SetDefault(old)

	g := startGalley(t, `{"answer":"ok","fields":[{"text":"hunter2"},{"text":"hunter2"},{"text":"hunter2"}]}`, true)
	a, err := Ask(context.Background(), g.user, Question{Grantable: true, Password: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Password, []byte("hunter2")) || a.For != 0 {
		t.Fatalf("got %q for %v", a.Password, a.For)
	}
	if !strings.Contains(log.String(), "time not understood") || strings.Contains(log.String(), "hunter2") {
		t.Errorf("logged:\n%s", log.String())
	}
}
