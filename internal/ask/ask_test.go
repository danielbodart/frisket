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
	"github.com/danielbodart/frisket/internal/record"
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
	c, err := NewCommand(path, Limits{})
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
	for status, want := range map[string]record.Answer{"0": record.Allow, "1": record.Refuse} {
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
	if ok != record.Refuse || err == nil || !strings.Contains(err.Error(), "no display") {
		t.Fatalf("(%v, %v)", ok, err)
	}
}

func TestAnAskerMustBeAnExecutableAbsolutePath(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "asker")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"asker", notExec, t.TempDir(), "/nonexistent/asker"} {
		if _, err := NewCommand(p, Limits{}); err == nil {
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
			if ok.Admits() {
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
	if ok, err := c.Ask(context.Background(), question); ok != record.Allow || err != nil {
		t.Fatalf("after its question was answered: (%v, %v)", ok, err)
	}
}

// On an exit of 0 or 1 the asker may say its answer on stdout, which stands
// in place of the status: ask, as zenity's extra button prints its label
// and exits 1, admits. Anything else there, or an answer beside any other
// status, is the asker failing, never a yes.
func TestAnAskerMaySayItsAnswerOnStdout(t *testing.T) {
	for _, tc := range []struct {
		body string
		want record.Answer
		fail bool
	}{
		{`exit 0`, record.Allow, false},
		{`exit 1`, record.Refuse, false},
		{`echo Ask; exit 1`, record.Ask, false},
		{`echo ALLOW; exit 1`, record.Allow, false},
		{`printf ' refuse \n'; exit 0`, record.Refuse, false},
		{`echo; exit 1`, record.Refuse, false},
		{`echo always; exit 0`, record.Refuse, true},
		{`printf 'allow\nask\n'; exit 0`, record.Refuse, true},
		{`head -c 100 /dev/zero | tr '\0' ' '; echo allow; exit 0`, record.Refuse, true},
		{`echo allow; exit 2`, record.Refuse, true},
	} {
		c := mustCommand(t, script(t, `cat >/dev/null; `+tc.body))
		got, err := c.Ask(context.Background(), question)
		if got != tc.want || (err != nil) != tc.fail {
			t.Errorf("%s: (%v, %v), want %v, failing %v", tc.body, got, err, tc.want, tc.fail)
		}
	}
}

// -asker-concurrent: as many questions open at once as it says, and no more.
func TestAsManyQuestionsOpenAsTheDaemonSays(t *testing.T) {
	dir := t.TempDir()
	c, err := NewCommand(script(t, `
		touch `+dir+`/open.$$
		n=$(ls `+dir+` | grep -c '^open')
		[ "$n" -le 2 ] || touch `+dir+`/over
		while [ ! -e `+dir+`/go ]; do sleep 0.01; done
		rm `+dir+`/open.$$`), Limits{Concurrent: 2})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			q := question
			q.Session = fmt.Sprintf("s%d", i)
			if a, err := c.Ask(context.Background(), q); a != record.Allow || err != nil {
				t.Errorf("(%v, %v)", a, err)
			}
		})
	}
	waitFor(t, func() bool { m, _ := filepath.Glob(dir + "/open.*"); return len(m) == 2 })
	time.Sleep(50 * time.Millisecond)
	if m, _ := filepath.Glob(dir + "/open.*"); len(m) != 2 {
		t.Fatalf("%d open, want 2", len(m))
	}
	if err := os.WriteFile(dir+"/go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := os.Stat(dir + "/over"); err == nil {
		t.Fatal("more than two were open at once")
	}
}

// A recording session's second question waits its turn rather than being
// refused: someone is there to answer each, and in order.
func TestARecordingSessionsQuestionsQueue(t *testing.T) {
	dir := t.TempDir()
	c := mustCommand(t, script(t, `touch `+dir+`/asked.$$; while [ ! -e `+dir+`/go ]; do sleep 0.01; done; echo ask`))
	q := question
	q.Record = true
	done := make(chan record.Answer, 2)
	go func() { a, _ := c.Ask(context.Background(), q); done <- a }()
	waitFor(t, func() bool { m, _ := filepath.Glob(dir + "/asked.*"); return len(m) == 1 })
	go func() { a, _ := c.Ask(context.Background(), q); done <- a }()
	// Not refused: still waiting.
	select {
	case a := <-done:
		t.Fatalf("the second question was answered %v while the first was open", a)
	case <-time.After(50 * time.Millisecond):
	}
	// The same session without record is still refused at once.
	plain := question
	if _, err := c.Ask(context.Background(), plain); !errors.Is(err, intercept.ErrBusy) {
		t.Fatalf("%v, want ErrBusy", err)
	}
	if err := os.WriteFile(dir+"/go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if a := <-done; a != record.Ask {
			t.Fatalf("%v, want ask", a)
		}
	}
	if m, _ := filepath.Glob(dir + "/asked.*"); len(m) != 2 {
		t.Fatalf("%d asked, want both", len(m))
	}
}

// -asker-per-session lets a session have more than one question waiting.
func TestASessionMayHaveAsManyWaitingAsTheDaemonSays(t *testing.T) {
	dir := t.TempDir()
	c, err := NewCommand(script(t, `touch `+dir+`/asked.$$; while [ ! -e `+dir+`/go ]; do sleep 0.01; done`),
		Limits{Concurrent: 2, PerSession: 2})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for range 2 {
		go func() { _, err := c.Ask(context.Background(), question); done <- err }()
	}
	waitFor(t, func() bool { m, _ := filepath.Glob(dir + "/asked.*"); return len(m) == 2 })
	if _, err := c.Ask(context.Background(), question); !errors.Is(err, intercept.ErrBusy) {
		t.Fatalf("a third: %v, want ErrBusy", err)
	}
	if err := os.WriteFile(dir+"/go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
