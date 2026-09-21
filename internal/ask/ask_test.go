package ask

import (
	"context"
	"encoding/json"
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
	for range 5 {
		wg.Go(func() {
			ok, err := c.Ask(context.Background(), question)
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
	go func() { _, err := c.Ask(ctx, question); done <- err }()
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
