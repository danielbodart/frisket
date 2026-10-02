package sshroute

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/policy"
)

func recorderFor(t *testing.T, def record.Answer) (*record.Recorder, *journal) {
	t.Helper()
	j := &journal{}
	rec, err := record.New(record.Config{Policy: "p", Default: def, Log: slog.New(slog.NewJSONHandler(j, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return rec, j
}

// A recording session runs what the rules refuse or ask about, by its
// default, and writes each command down once: who it runs as, where, its
// words, and what the rules would have done.
func TestARecordingSessionRunsWhatTheRulesWouldNotByItsDefault(t *testing.T) {
	rec, rj := recorderFor(t, record.Allow)
	f := newFixture(t, options{recorder: rec})
	c := f.connect()
	// The fake machine knows no reboot, and says so: it ran there.
	for _, command := range []string{"echo secret x", "reboot", "reboot"} {
		if r := run(t, c, command, nil); r.status == exitRefused || r.err != nil {
			t.Fatalf("%q: %+v", command, r)
		}
	}
	if got := strings.Join(f.sshd.commands(), "|"); got != "echo secret x|reboot|reboot" {
		t.Fatalf("ran %q", got)
	}
	lines := rj.lines(t, "record")
	if len(lines) != 2 {
		t.Fatalf("%d record lines, want one per command", len(lines))
	}
	for i, w := range []map[string]any{
		{"kind": "ssh", "route": "server", "user": "dan", "address": routeAddr.String(), "command": "echo secret x",
			"would": "refuse", "rule": "echo secret **", "answer": "allow", "source": "default"},
		{"command": "reboot", "would": "ask", "rule": "unmatched"},
	} {
		for k, v := range w {
			if lines[i][k] != v {
				t.Errorf("line %d: %s = %v, want %v", i, k, lines[i][k], v)
			}
		}
	}
	waitFor(t, "the lines", func() bool { return len(f.sshLines()) == 3 })
	if l := f.sshLines()[0]; l["decision"] != "allowed" || l["rule"] != intercept.RuleRecorded {
		t.Errorf("ssh line %v", l)
	}
}

// With no default a person answers, with the question marked a
// recording's; on an exec route each time, as an ask is answered, since
// what a command is given on its stdin is no part of what was answered, but
// written down once.
func TestARecordingSessionAsksAboutEachExecCommandEachTime(t *testing.T) {
	rec, rj := recorderFor(t, "")
	a := &answers{yes: true}
	f := newFixture(t, options{asker: a, recorder: rec})
	shrink(t, &previewIdle, 20*time.Millisecond)
	c := f.connect()
	for range 2 {
		if r := run(t, c, "reboot", nil); r.status != 127 {
			t.Fatalf("%+v", r)
		}
	}
	q := a.questions()
	if len(q) != 2 || !q[0].Record || q[0].ID == "" || q[0].Command != "reboot" || q[1].ID != q[0].ID {
		t.Fatalf("questions %+v", q)
	}
	if l := rj.lines(t, "record"); len(l) != 1 || l[0]["source"] != "human" || l[0]["answer"] != "allow" {
		t.Fatalf("record lines %v", l)
	}
}

// On a shell route, which gives a command no stdin, a person's allow is
// the answer for the rest of the session.
func TestARecordingSessionAsksAboutEachShellCommandOnce(t *testing.T) {
	rec, rj := recorderFor(t, "")
	k := &cli{prompt: "ZySH> "}
	a := &answers{yes: true}
	f := shellFixture(t, k, options{asker: a, recorder: rec})
	c := f.connect()
	for range 2 {
		if r := run(t, c, "reboot", nil); r.status == exitRefused {
			t.Fatalf("%+v", r)
		}
	}
	if q := a.questions(); len(q) != 1 {
		t.Fatalf("asked %d times", len(q))
	}
	if l := rj.lines(t, "record"); len(l) != 1 || l[0]["source"] != "human" || l[0]["answer"] != "allow" {
		t.Fatalf("record lines %v", l)
	}
}

// A command an exec route's rules cannot read is no recording's: no rule
// could name it, so it is decided as the route's unmatched decides it --
// refused, written down as hard, whatever the default.
func TestARecordingSessionLeavesAnUnreadableExecCommandToItsRoute(t *testing.T) {
	rec, rj := recorderFor(t, record.Allow)
	f := newFixture(t, options{recorder: rec, route: func(r *policy.SSHRoute) { r.Unmatched = "refuse" }})
	c := f.connect()
	if r := run(t, c, "A=1 reboot", nil); r.status != exitRefused {
		t.Fatalf("%+v", r)
	}
	if got := f.sshd.commands(); len(got) != 0 {
		t.Fatalf("ran %q", got)
	}
	if l := rj.lines(t, "record"); len(l) != 1 || l[0]["source"] != "hard" || l[0]["reason"] != ReasonUnreadable {
		t.Fatalf("record lines %v", l)
	}
	// One it can read is the recording's.
	if r := run(t, c, "reboot", nil); r.status == exitRefused {
		t.Fatalf("%+v", r)
	}
}

// What a shell route cannot read stays refused while recording, never
// asked about and never typed, and is written down as that.
func TestARecordingSessionStillRefusesWhatAShellRouteCannotRead(t *testing.T) {
	rec, rj := recorderFor(t, record.Allow)
	k := &cli{prompt: "ZySH> "}
	a := &answers{yes: true}
	f := shellFixture(t, k, options{asker: a, recorder: rec})
	c := f.connect()
	if r := run(t, c, "echo a\rreboot", nil); r.status != exitRefused || !strings.Contains(r.stderr, ReasonUnreadable) {
		t.Fatalf("%+v", r)
	}
	if got := k.lines(); len(got) != 0 || len(a.questions()) != 0 {
		t.Fatalf("typed %q, asked %d", got, len(a.questions()))
	}
	if l := rj.lines(t, "record"); len(l) != 1 || l[0]["source"] != "hard" || l[0]["reason"] != ReasonUnreadable || l[0]["shell"] != true {
		t.Fatalf("record lines %v", l)
	}
	// A readable one the rules ask about is the recording's, and typed.
	if r := run(t, c, "reboot", nil); r.status == exitRefused {
		t.Fatalf("%+v", r)
	}
}
