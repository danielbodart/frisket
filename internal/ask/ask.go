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
//   - one question at a time, daemon-wide: while one is open every other waits
//     its turn, so a person never faces a pile of dialogs.
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
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/intercept"
)

// waitDelay is how long an asker has to go once told to, before it is killed.
var waitDelay = 5 * time.Second

// maxStderr bounds what of an asker's stderr is kept for its error.
const maxStderr = 1024

// Command is an intercept.Asker that runs a program.
type Command struct {
	path string
	// turn is held for the whole of a question, from the program's start to
	// its end: the one-at-a-time invariant.
	turn chan struct{}
}

var _ intercept.Asker = (*Command)(nil)

// NewCommand checks that path is an absolute path to something executable.
// Checked once, at start, so a misconfigured asker stops the daemon rather
// than refusing every question later for a reason nobody sees.
func NewCommand(path string) (*Command, error) {
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
	return &Command{path: path, turn: make(chan struct{}, 1)}, nil
}

// Ask waits its turn, then runs the program with the question on stdin.
//
// A client that stops waiting takes its question with it: while queued, it is
// never asked; while being asked, the program is sent SIGTERM -- its whole
// process group, so a dialog it started goes too -- and killed if it has not
// gone after waitDelay.
func (c *Command) Ask(ctx context.Context, q intercept.Question) (bool, error) {
	select {
	case c.turn <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-c.turn }()
	if err := ctx.Err(); err != nil {
		return false, err
	}

	doc, err := json.Marshal(q)
	if err != nil {
		return false, err
	}
	cmd := exec.CommandContext(ctx, c.path)
	cmd.Stdin = bytes.NewReader(doc)
	stderr := &bounded{max: maxStderr}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = waitDelay

	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, ctx.Err()
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		return false, fmt.Errorf("asker %s: %w: %s", c.path, err, s)
	}
	return false, fmt.Errorf("asker %s: %w", c.path, err)
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
