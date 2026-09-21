package ask

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/intercept"
)

// script writes an asker. Tests run it with /bin/sh, which the Nix build
// sandbox has; nothing else from the host is assumed.
func script(t *testing.T, body string) string {
	t.Helper()
	sh, err := os.Stat("/bin/sh")
	if err != nil || sh.IsDir() {
		t.Skip("no /bin/sh to run an asker with")
	}
	p := filepath.Join(t.TempDir(), "asker")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustCommand(t *testing.T, path string) *Command {
	t.Helper()
	c, err := NewCommand(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var question = intercept.Question{
	Session: "s", Policy: "p", Route: "cloudflare", Method: "DELETE", Host: "api.example.test",
	Path: "/zones/z/dns_records/r", Query: "a=b",
	Operation: &intercept.Operation{ID: "del", Summary: "Delete DNS Record", Description: "Permanently removes it."},
}

// The question is one JSON document on stdin, and the exit status is the
// answer.
func TestTheQuestionIsJSONOnStdinAndTheAnswerIsTheExitStatus(t *testing.T) {
	dir := t.TempDir()
	got := filepath.Join(dir, "question.json")
	for status, want := range map[string]bool{"0": true, "1": false} {
		c := mustCommand(t, script(t, `cat > `+got+`; exit `+status))
		ok, err := c.Ask(context.Background(), question)
		if err != nil || ok != want {
			t.Fatalf("exit %s: (%v, %v), want (%v, nil)", status, ok, err, want)
		}
		b, err := os.ReadFile(got)
		if err != nil {
			t.Fatal(err)
		}
		var q intercept.Question
		if err := json.Unmarshal(b, &q); err != nil {
			t.Fatalf("stdin was not JSON: %q", b)
		}
		if !reflect.DeepEqual(q, question) {
			t.Fatalf("the asker read %+v", q)
		}
	}
}

// Anything but 0 or 1 refuses, and says why: an asker that cannot ask is not
// a person saying no.
func TestAnAskerThatFailsRefusesAndSaysSo(t *testing.T) {
	c := mustCommand(t, script(t, `echo "no display" >&2; exit 5`))
	ok, err := c.Ask(context.Background(), question)
	if ok || err == nil || !strings.Contains(err.Error(), "no display") {
		t.Fatalf("(%v, %v)", ok, err)
	}
}

func TestAnAskerMustBeAnExecutableAbsolutePath(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "asker")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"asker", notExec, t.TempDir(), "/nonexistent/asker"} {
		if _, err := NewCommand(p); err == nil {
			t.Errorf("%s: accepted", p)
		}
	}
}

// One question at a time: while one is open, the rest wait their turn.
func TestOneQuestionAtATime(t *testing.T) {
	dir := t.TempDir()
	c := mustCommand(t, script(t, `
		if ! mkdir `+dir+`/open 2>/dev/null; then exit 7; fi
		sleep 0.05
		rmdir `+dir+`/open`))
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := range 5 {
		wg.Go(func() {
			q := question
			q.Session = fmt.Sprintf("s%d", i)
			ok, err := c.Ask(context.Background(), q)
			if err != nil {
				t.Errorf("two questions were open at once: %v", err)
			}
			if ok {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 5 {
		t.Fatalf("%d of 5 admitted", admitted.Load())
	}
}

// A client that stops waiting takes its question with it: the asker is told
// to go, and one queued behind it is never asked at all.
func TestAClientThatStopsWaitingTakesItsQuestionWithIt(t *testing.T) {
	dir := t.TempDir()
	c := mustCommand(t, script(t, `
		touch `+dir+`/asked.$$
		trap 'touch `+dir+`/told; exit 1' TERM
		sleep 30 & wait`))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	go func() { _, err := c.Ask(ctx, question); done <- err }()
	waitFor(t, func() bool { m, _ := filepath.Glob(dir + "/asked.*"); return len(m) == 1 })
	other := question
	other.Session = "another"
	go func() { _, err := c.Ask(ctx, other); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	for range 2 {
		if err := <-done; err != context.Canceled {
			t.Fatalf("%v, want context.Canceled", err)
		}
	}
	if m, _ := filepath.Glob(dir + "/asked.*"); len(m) != 1 {
		t.Fatalf("%d questions asked, want only the first", len(m))
	}
	waitFor(t, func() bool { _, err := os.Stat(dir + "/told"); return err == nil })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func init() { gap = 20 * time.Millisecond }

// A session with a question waiting has another refused at once: no sandbox
// can queue ahead of another's, or bury one question among many.
func TestOneQuestionPerSession(t *testing.T) {
	dir := t.TempDir()
	c := mustCommand(t, script(t, `touch `+dir+`/asked; while [ ! -e `+dir+`/go ]; do sleep 0.01; done`))
	done := make(chan error, 1)
	go func() { _, err := c.Ask(context.Background(), question); done <- err }()
	waitFor(t, func() bool { _, err := os.Stat(dir + "/asked"); return err == nil })
	if _, err := c.Ask(context.Background(), question); !errors.Is(err, intercept.ErrBusy) {
		t.Fatalf("a second question from the same session: %v, want ErrBusy", err)
	}
	if err := os.WriteFile(dir+"/go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Answered, the session may ask again.
	if ok, err := c.Ask(context.Background(), question); !ok || err != nil {
		t.Fatalf("after its question was answered: (%v, %v)", ok, err)
	}
}

// Between one question closing and the next opening there is a pause, so an
// answer meant for one cannot land on the next.
func TestAPauseBetweenQuestions(t *testing.T) {
	dir := t.TempDir()
	c := mustCommand(t, script(t, `date +%s%N >> `+dir+`/times`))
	for i := range 3 {
		q := question
		q.Session = fmt.Sprintf("s%d", i)
		if _, err := c.Ask(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(dir + "/times")
	if err != nil {
		t.Fatal(err)
	}
	var prev int64
	for i, l := range strings.Fields(string(b)) {
		var n int64
		fmt.Sscan(l, &n)
		if i > 0 && time.Duration(n-prev) < gap {
			t.Fatalf("question %d opened %v after the last, want at least %v", i, time.Duration(n-prev), gap)
		}
		prev = n
	}
}
