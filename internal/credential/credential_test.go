package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// journal is the injected log writer. Not silenced under test: that a
// credential is never logged is a property, and it is asserted on.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) String() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.String()
}

func (j *journal) logger() *slog.Logger { return slog.New(slog.NewJSONHandler(j, nil)) }

func (j *journal) lines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(j.String(), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

// replace writes content the way Claude Code, codex and gh do: a temporary
// file in the same directory, then a rename over the old name.
func replace(t *testing.T, path, content string) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// tempDir is t.TempDir with its symlinks resolved, so a TMPDIR reached through
// a link does not quietly put every test here into polling mode.
func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func value(f *File) string {
	s, err := f.Get()
	if err != nil {
		return "error: " + err.Error()
	}
	return s.Value
}

// The file is replaced by temp-file-and-rename, which is how every credential
// file this reads is written. A watch on the file itself would still be on
// the old inode after the first rename and never see another change.
func TestFileFollowsRenameReplacement(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "token")
	replace(t, path, "first\n")

	j := &journal{}
	f, err := WatchFile(path, Trimmed(), j.logger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if got := value(f); got != "first" {
		t.Fatalf("initial read: %q", got)
	}
	// Twice, because the second rename is the one a file watch misses.
	for _, next := range []string{"second", "third"} {
		replace(t, path, next+"\n")
		eventually(t, "the "+next+" token", func() bool { return value(f) == next })
	}
	if f.watch.Polling() {
		t.Fatal("fell back to polling on an ordinary directory; the watch is not what picked the change up")
	}

	for _, secret := range []string{"first", "second", "third"} {
		if strings.Contains(j.String(), secret) {
			t.Fatalf("the log contains a credential: %s", j.String())
		}
	}
	loads := 0
	for _, l := range j.lines(t) {
		if l["msg"] == "credential" && l["outcome"] == "loaded" {
			loads++
		}
	}
	if loads != 3 {
		t.Fatalf("want one line per distinct credential loaded, got %d:\n%s", loads, j.String())
	}
}

// An in-place write (no rename) is picked up too, through IN_CLOSE_WRITE.
func TestFileFollowsInPlaceWrite(t *testing.T) {
	path := filepath.Join(tempDir(t), "token")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := WatchFile(path, Trimmed(), (&journal{}).logger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := os.WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the rewritten token", func() bool { return value(f) == "two" })
}

// A deleted file fails every Get from then on, and a file that appears later
// is picked up: absent is a state, not a configuration error.
func TestFileMissingFailsAndRecovers(t *testing.T) {
	path := filepath.Join(tempDir(t), "token")
	j := &journal{}
	f, err := WatchFile(path, Trimmed(), j.logger())
	if err != nil {
		t.Fatalf("a missing file must not stop the source being built: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := f.Get(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing file: want ErrUnavailable, got %v", err)
	}
	replace(t, path, "arrived")
	eventually(t, "the file to appear", func() bool { return value(f) == "arrived" })

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deletion to be noticed", func() bool {
		_, err := f.Get()
		return errors.Is(err, ErrUnavailable)
	})
	if s, _ := f.Get(); s.Value != "" {
		t.Fatal("a failed Get still returned a value")
	}
	var unavailable int
	for _, l := range j.lines(t) {
		if l["outcome"] == "unavailable" {
			unavailable++
			if l["level"] != "ERROR" {
				t.Fatalf("an unavailable credential must be logged loudly: %v", l)
			}
		}
	}
	if unavailable != 2 {
		t.Fatalf("want an error line for each time it became unavailable, got %d:\n%s", unavailable, j.String())
	}
}

// A directory reached through a symlink is watched by polling, because inotify
// would stay on whatever the link named when the watch was made -- and sops-nix
// switches /run/secrets by replacing exactly such a link.
func TestFileThroughSymlinkedDirectoryPolls(t *testing.T) {
	root := tempDir(t)
	gen1 := filepath.Join(root, "gen1")
	gen2 := filepath.Join(root, "gen2")
	for dir, tok := range map[string]string{gen1: "one", gen2: "two"} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "token"), []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "secrets")
	if err := os.Symlink(gen1, link); err != nil {
		t.Fatal(err)
	}

	f, err := WatchFile(filepath.Join(link, "token"), Trimmed(), (&journal{}).logger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if got := value(f); got != "one" {
		t.Fatalf("got %q", got)
	}

	// Switch the generation the way sops-nix does: a new link renamed over
	// the old one.
	tmp := filepath.Join(root, "secrets.tmp")
	if err := os.Symlink(gen2, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
	if got := value(f); got != "two" {
		t.Fatalf("after the switch: got %q", got)
	}
}

func TestWatchFileRefusesAnUnwatchableDirectory(t *testing.T) {
	_, err := WatchFile(filepath.Join(tempDir(t), "nope", "token"), Trimmed(), (&journal{}).logger())
	if err == nil {
		t.Fatal("a directory that does not exist is configuration, and must fail loudly")
	}
}

// Close must return promptly even with nothing happening in the directory: a
// Read blocked in a raw syscall would hang it forever.
func TestFileCloseDoesNotHang(t *testing.T) {
	path := filepath.Join(tempDir(t), "token")
	f, err := WatchFile(path, Trimmed(), (&journal{}).logger())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}

func TestJSONExtractsTokenAndExpiry(t *testing.T) {
	exp := time.UnixMilli(1_900_000_000_123)
	raw := fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"tok-abc","refreshToken":"never-used","expiresAt":%d}}`, exp.UnixMilli())
	s, err := JSON{Token: "claudeAiOauth.accessToken", ExpiresMillis: "claudeAiOauth.expiresAt"}.Extract([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Value != "tok-abc" || !s.Expires.Equal(exp) {
		t.Fatalf("got %q expiring %v", s.Value, s.Expires)
	}
	if !s.Expired(exp) || s.Expired(exp.Add(-time.Millisecond)) {
		t.Fatal("expiry is the instant given, no earlier and no later")
	}
}

func TestJSONRefusals(t *testing.T) {
	j := JSON{Token: "a.token", ExpiresMillis: "a.exp"}
	for name, raw := range map[string]string{
		"not json":        `{"a": "sk-secret-in-a-broken-file`,
		"missing token":   `{"a":{"exp":1}}`,
		"token not text":  `{"a":{"token":5,"exp":1}}`,
		"empty token":     `{"a":{"token":"","exp":1}}`,
		"token with CRLF": `{"a":{"token":"x\r\nX-Evil: 1","exp":1}}`,
		"missing expiry":  `{"a":{"token":"t"}}`,
		"expiry as text":  `{"a":{"token":"t","exp":"soon"}}`,
		"expiry fraction": `{"a":{"token":"t","exp":1.5}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := j.Extract([]byte(raw))
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("want ErrUnavailable, got %v", err)
			}
			if strings.Contains(err.Error(), "sk-secret") {
				t.Fatalf("the error quotes the file: %v", err)
			}
		})
	}
}

// A Secret formatted by accident -- %v in a log call, a test failure -- must
// not print its value.
func TestSecretDoesNotFormatItsValue(t *testing.T) {
	s := Secret{Value: "sk-live-123", Expires: time.Unix(1, 0)}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, s); strings.Contains(out, "sk-live") {
			t.Fatalf("%s printed the value: %s", f, out)
		}
	}
}
