// Package ask puts a request to a person, by running a command the machine's
// owner chose. frisket defines the contract and ships no dialog: what prompts,
// and how, belongs to whoever runs the machine.
//
// The contract, deliberately small:
//
//   - the command runs as the daemon does, once per question, with nothing on
//     its command line;
//   - the question arrives as one JSON document on stdin, an
//     intercept.Question;
//   - exit status 0 admits the request, 1 declines it, and anything else
//     refuses it too and is reported as the asker failing;
//   - on an exit status of 0 or 1, and only then, the asker may print one
//     line on stdout, at most 64 bytes: allow, ask or refuse, in any case,
//     which is the answer in place of the status. ask admits the request
//     as allow does, and a recording session records it as one to ask
//     about; a question with `record` set is the one to offer it for, as
//     zenity's --extra-button=Ask does, printing its label and exiting 1.
//     Nothing on stdout leaves the status to answer; anything else there is
//     the asker failing, so that an asker that says something frisket does
//     not know never has it read as a yes;
//   - one question at a time, daemon-wide -- or as many as the daemon is
//     told, -asker-concurrent -- while one is open every other waits its
//     turn, so a person never faces a pile of dialogs;
//   - one question per session -- or -asker-per-session -- a session with
//     that many waiting has any other refused at once, so no sandbox can
//     fill the queue ahead of another's, or bury one question among many.
//     A recording session's waits its turn instead: a person is there to
//     answer each, and a refusal for being busy would be recorded as
//     nothing at all.
package ask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
)

// waitDelay is how long an asker has to go once told to, before it is killed.
var waitDelay = 5 * time.Second

// maxStderr bounds what of an asker's stderr is kept for its error.
const maxStderr = 1024

// maxStdout bounds an asker's answer on stdout: one word, a line break and
// some space around it. More is the asker failing.
const maxStdout = 64

// Limits are how many questions may be open at once, daemon-wide, and how
// many one session may have queued or open. Zero is one, for each.
type Limits struct {
	Concurrent int
	PerSession int
}

// Command is an intercept.Asker that runs a program.
type Command struct {
	path string
	// turn is held for the whole of a question, from the program's start to
	// its end: Concurrent tokens, the one-at-a-time invariant at one.
	turn       chan struct{}
	perSession int

	mu      sync.Mutex
	waiting map[string]*slots // sessions with a question queued or open
}

// slots are one session's questions queued or open, and how many are using
// them.
type slots struct {
	held  chan struct{}
	users int
}

var _ intercept.Asker = (*Command)(nil)

// NewCommand checks that path is an absolute path to something executable.
// Checked once, at start, so a misconfigured asker stops the daemon rather
// than refusing every question later for a reason nobody sees.
func NewCommand(path string, l Limits) (*Command, error) {
	if l.Concurrent < 0 || l.PerSession < 0 {
		return nil, fmt.Errorf("asker limits %d and %d: neither may be negative", l.Concurrent, l.PerSession)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("asker %q is not an absolute path", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("asker: %w", err)
	}
	if fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("asker %s is not executable", path)
	}
	return &Command{
		path:       path,
		turn:       make(chan struct{}, max(l.Concurrent, 1)),
		perSession: max(l.PerSession, 1),
		waiting:    map[string]*slots{},
	}, nil
}

// session takes a place among q's session's questions: at once, or ErrBusy;
// or, for a recording session's, when one is free. release gives it back.
func (c *Command) session(ctx context.Context, q intercept.Question) (release func(), err error) {
	c.mu.Lock()
	s := c.waiting[q.Session]
	if s == nil {
		s = &slots{held: make(chan struct{}, c.perSession)}
		c.waiting[q.Session] = s
	}
	s.users++
	c.mu.Unlock()
	done := func() {
		c.mu.Lock()
		if s.users--; s.users == 0 {
			delete(c.waiting, q.Session)
		}
		c.mu.Unlock()
	}
	if q.Record {
		select {
		case s.held <- struct{}{}:
		case <-ctx.Done():
			done()
			return nil, ctx.Err()
		}
	} else {
		select {
		case s.held <- struct{}{}:
		default:
			done()
			return nil, intercept.ErrBusy
		}
	}
	return func() { <-s.held; done() }, nil
}

// Ask waits its turn, then runs the program with the question on stdin.
//
// A client that stops waiting takes its question with it: while queued, it is
// never asked; while being asked, the program is sent SIGTERM -- its whole
// process group, so a dialog it started goes too -- and killed if it has not
// gone after waitDelay.
func (c *Command) Ask(ctx context.Context, q intercept.Question) (record.Answer, error) {
	release, err := c.session(ctx, q)
	if err != nil {
		return record.Refuse, err
	}
	defer release()

	select {
	case c.turn <- struct{}{}:
	case <-ctx.Done():
		return record.Refuse, ctx.Err()
	}
	defer func() { <-c.turn }()
	if err := ctx.Err(); err != nil {
		return record.Refuse, err
	}

	doc, err := json.Marshal(q)
	if err != nil {
		return record.Refuse, err
	}
	cmd := exec.CommandContext(ctx, c.path)
	cmd.Stdin = bytes.NewReader(doc)
	stdout := &bounded{max: maxStdout + 1}
	cmd.Stdout = stdout
	stderr := &bounded{max: maxStderr}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = waitDelay

	err = cmd.Run()
	var exit *exec.ExitError
	var answer record.Answer
	switch {
	case err == nil:
		answer = record.Allow
	case ctx.Err() != nil:
		return record.Refuse, ctx.Err()
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		answer = record.Refuse
	}
	if answer != "" {
		return c.said(answer, stdout.String())
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		return record.Refuse, fmt.Errorf("asker %s: %w: %s", c.path, err, s)
	}
	return record.Refuse, fmt.Errorf("asker %s: %w", c.path, err)
}

// said is the answer of an asker that exited 0 or 1, by status: what it
// printed on stdout, if it printed anything, and the status otherwise.
func (c *Command) said(status record.Answer, out string) (record.Answer, error) {
	if len(out) > maxStdout {
		return record.Refuse, fmt.Errorf("asker %s: more than %d bytes on stdout, where one answer goes", c.path, maxStdout)
	}
	if strings.TrimSpace(out) == "" {
		return status, nil
	}
	if a, ok := record.ParseAnswer(out); ok {
		return a, nil
	}
	return record.Refuse, fmt.Errorf("asker %s: %q on stdout is not allow, ask or refuse", c.path, out)
}

// bounded keeps the first max bytes written to it and discards the rest,
// without ever failing the write: a chatty asker is not a broken one.
type bounded struct {
	buf bytes.Buffer
	max int
}

func (b *bounded) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *bounded) String() string { return b.buf.String() }
