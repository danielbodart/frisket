package sshroute

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/policy"
)

// fakeAlways offers Always on every question, keeping what it offered and
// what was answered always.
type fakeAlways struct {
	mu       sync.Mutex
	offered  []intercept.AlwaysRule
	answered map[string]bool
}

func (a *fakeAlways) Admits(r intercept.AlwaysRule) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.answered[r.Route+"\x00"+r.Key]
}

func (a *fakeAlways) Offer(q *intercept.Question, r intercept.AlwaysRule) func() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.offered = append(a.offered, r)
	q.Always, q.Diff = true, &intercept.Diff{Path: "~/p/chase.json", New: r.Key}
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.answered == nil {
			a.answered = map[string]bool{}
		}
		a.answered[r.Route+"\x00"+r.Key] = true
	}
}

// alwaysAsker answers always where it is offered, and allow elsewhere.
type alwaysAsker struct {
	mu    sync.Mutex
	asked []intercept.Question
}

func (a *alwaysAsker) Ask(_ context.Context, q intercept.Question) (record.Answer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, q)
	if q.Always {
		return record.Always, nil
	}
	return record.Allow, nil
}

// A command answered Always runs, its rule the command's literal words;
// the same command then runs unasked for the rest of the session, and
// another is asked about. A command no literal rule could name -- quoted,
// several, a glob -- is asked about with no Always.
func TestAlwaysAdmitsTheCommandForTheSession(t *testing.T) {
	a := &alwaysAsker{}
	alw := &fakeAlways{}
	f := newFixture(t, options{asker: a, always: alw, route: func(r *policy.SSHRoute) {
		r.Exec = []policy.ExecRule{{Command: "echo **", Ask: true}}
	}})
	shrink(t, &previewIdle, 20*time.Millisecond)
	for _, cmd := range []string{"echo hi there", "echo hi there", "echo other", "echo 'a b'", "echo a && echo b"} {
		if r := run(t, f.connect(), cmd, nil); r.status != 0 {
			t.Errorf("%s: %+v", cmd, r)
		}
	}
	if len(a.asked) != 4 {
		t.Fatalf("asked %d: %+v", len(a.asked), a.asked)
	}
	for i, offered := range []bool{true, true, false, false} {
		if a.asked[i].Always != offered {
			t.Errorf("question %d (%s): always %v", i, a.asked[i].Command, a.asked[i].Always)
		}
	}
	if len(alw.offered) != 2 || alw.offered[0].Key != "echo hi there" || !alw.offered[0].SSH ||
		alw.offered[0].Route != "server" || alw.offered[0].Command != "echo hi there" || alw.offered[1].Key != "echo other" {
		t.Errorf("offered %+v", alw.offered)
	}
	lines := f.sshLines()
	if len(lines) != 5 || lines[1]["rule"] != intercept.RuleAlways || lines[1]["asked"] == true || lines[0]["asked"] != true {
		t.Errorf("lines %v", lines)
	}
	if !plainWord("a.b/c-d_e@f%g+h=i:j,k") || plainWord("a*") || plainWord("[arg") || plainWord("") {
		t.Error("plainWord")
	}
}
