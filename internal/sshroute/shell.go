package sshroute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/intercept"
)

// A Shell route's device ignores the command an exec carries: its login
// shell is its own CLI, which only reads what is typed into it. So frisket
// opens that shell on a terminal, waits for it to finish greeting, types the
// command, waits for its output to finish, types exit, and gives the sandbox
// what the command printed, as the output of the exec it asked for.
//
// Variables only so a test can shrink them.
var (
	// shellLoginIdle is how long the shell may print nothing before it is
	// taken to be waiting for a command: its banner and prompt are done.
	shellLoginIdle = 1500 * time.Millisecond
	// shellIdle is how long a command may print nothing before it is taken
	// to have finished, where its output does not end with the prompt the
	// shell greeted with.
	shellIdle = 3 * time.Second
	// shellSettle is how long output that ends with the prompt must stay
	// quiet before the command is taken to have finished: the prompt back
	// is the shell waiting for the next command, and a prompt that is only
	// the end of a burst of output is followed by more.
	shellSettle = 250 * time.Millisecond
	// shellTimeout bounds the whole conversation, from opening the shell to
	// its output.
	shellTimeout = 60 * time.Second
	// shellExitWait is how long the shell has to close once exit is typed,
	// before frisket closes it.
	shellExitWait = 2 * time.Second
)

// shellNewline ends a typed line, as a terminal's Enter does: a carriage
// return, which the device's terminal turns into a newline if it wants one.
const shellNewline = "\r"

// shellTerm is the terminal frisket says it is: one that does nothing but
// print, so that a device's line editor draws nothing on it but text.
const shellTerm = "dumb"

// maxShellOutput bounds what a command may print, which frisket holds whole
// before it gives it back: a device's CLI prints a page or two.
const maxShellOutput = 1 << 20

// maxPrompt bounds what is taken as the shell's prompt.
const maxPrompt = 128

var (
	errShellTimeout  = errors.New("the device's shell did not finish in time")
	errShellOutput   = fmt.Errorf("the command printed more than %d bytes", maxShellOutput)
	errShellClosed   = errors.New("the device's shell closed before it was given the command")
	errShellNoPrompt = errors.New("the device's prompt did not come back: its output may be cut short, and the command may still be running or waiting for input")
)

// ptyRequest is RFC 4254's pty-req. A size of zero is none, and the
// device's own default: the modem this was checked against printed a
// hundred lines of xdslctl unpaged on one.
type ptyRequest struct {
	Term                   string
	Columns, Rows          uint32
	WidthPixels, HeightPix uint32
	Modes                  string
}

// shell runs an admitted command on a Shell route, answering the sandbox's
// exec before it returns; the conversation goes on in a goroutine of its
// own.
func (c *channel) shell(r *ssh.Request, client *login, command string, line *execLine, start time.Time) {
	up, upReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonUpstream, err
		c.refuse(r, line, start, exitUpstream)
		return
	}
	go func() {
		for q := range upReqs {
			if q.WantReply {
				_ = q.Reply(false, nil)
			}
		}
	}()
	// No terminal modes but the end of them: the device's own.
	pty := ssh.Marshal(ptyRequest{Term: shellTerm, Modes: "\x00"})
	for _, req := range []struct {
		name    string
		payload []byte
	}{{"pty-req", pty}, {"shell", nil}} {
		ok, err := up.SendRequest(req.name, true, req.payload)
		if err != nil || !ok {
			_ = up.Close()
			if err == nil {
				err = fmt.Errorf("the device refused a %s", req.name)
			}
			line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonExecFailed, err
			c.refuse(r, line, start, exitUpstream)
			return
		}
	}
	_ = r.Reply(true, nil)
	line.decision = intercept.DecisionAllowed
	c.done = make(chan struct{})
	go c.converse(up, command, line, start)
}

// converse types command into the device's shell and gives the sandbox
// what it printed. The sandbox's stdin is never read: whatever it sent
// would be typed into the shell too, as commands nobody decided.
func (c *channel) converse(up ssh.Channel, command string, line *execLine, start time.Time) {
	defer close(c.done)
	// The client leaving ends the shell: a command it is no longer there to
	// read is not kept running for it.
	stop := context.AfterFunc(c.ctx, func() { _ = up.Close() })
	defer stop()
	deadline := time.Now().Add(shellTimeout)
	sc := newScreen()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(sc, up) }()
	go func() { defer wg.Done(); _, _ = io.Copy(sc, up.Stderr()) }()
	go func() { wg.Wait(); sc.close() }()

	out, err := func() ([]byte, error) {
		greeted, _, err := sc.wait(0, "", shellLoginIdle, deadline)
		if errors.Is(err, io.EOF) {
			return nil, errShellClosed
		}
		if err != nil {
			return nil, err
		}
		prompt := promptOf(sc.bytes(0, greeted))
		if _, err := io.WriteString(up, command+shellNewline); err != nil {
			return nil, fmt.Errorf("typing the command: %w", err)
		}
		end, prompted, err := sc.wait(greeted, prompt, shellIdle, deadline)
		out := cleaned(sc.bytes(greeted, end), command, prompt)
		if errors.Is(err, io.EOF) {
			// The shell closed after the command, which may have been
			// what the command did.
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if !prompted {
			// Quiet, but with no prompt back: exit typed now could be the
			// answer to whatever the command is waiting on -- a question, a
			// pager, a value -- which nobody decided. The shell is closed
			// with nothing more typed into it. Where the device greeted
			// with a prompt and it has not come back, its output is not
			// known to be whole, and is not given as though it were.
			if prompt != "" {
				return out, errShellNoPrompt
			}
			return out, nil
		}
		if _, err := io.WriteString(up, "exit"+shellNewline); err == nil {
			_, _, _ = sc.wait(end, "", shellExitWait, time.Now().Add(shellExitWait))
		}
		return out, nil
	}()
	_ = up.Close()
	_, _ = counting{c.ch, &line.stdout}.Write(out)
	status := uint32(0)
	if err != nil {
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonUpstream, err
		status = exitUpstream
		fmt.Fprintf(counting{c.ch.Stderr(), &line.stderr}, "frisket: %s: %s: %s\n", c.s.route.Name, line.reason, err)
	}
	_ = c.ch.CloseWrite()
	_, _ = c.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	line.exitStatus = &status
	c.log(line, start)
	_ = c.ch.Close()
}

// promptOf is the shell's prompt, from what it printed before it was given
// a command: its last line, if it is a short one, or "" for none.
func promptOf(greeting []byte) string {
	i := bytes.LastIndexByte(greeting, '\n')
	p := string(greeting[i+1:])
	p = strings.TrimLeft(p, "\r")
	if strings.TrimSpace(p) == "" || len(p) > maxPrompt {
		return ""
	}
	return p
}

// cleaned is what a command printed, as the sandbox is given it: the
// shell's echo of the command taken off its start and the prompt it ended
// with off its end, each where it is found, and its lines ended "\n" rather
// than the terminal's "\r\n". Best effort: the device draws its own echo and
// prompt, and a device that draws them otherwise has them left in.
func cleaned(out []byte, command, prompt string) []byte {
	typed := strings.TrimSpace(command)
	first, rest, found := bytes.Cut(out, []byte("\n"))
	if bytes.HasSuffix(bytes.TrimRight(first, "\r "), []byte(typed)) {
		if found {
			out = rest
		} else {
			out = nil
		}
	}
	if prompt != "" {
		out, _ = bytes.CutSuffix(out, []byte(prompt))
	}
	return bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
}

// screen is everything a shell printed, and when it last printed.
type screen struct {
	mu   sync.Mutex
	buf  []byte
	last time.Time
	eof  bool
	over bool
	more chan struct{}
}

func newScreen() *screen {
	return &screen{last: time.Now(), more: make(chan struct{}, 1)}
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	// Once over, nothing more is kept: a later chunk that fits would be
	// spliced on after the gap, as though it followed what was kept.
	if s.over || len(s.buf)+len(p) > maxShellOutput {
		s.over = true
	} else {
		s.buf = append(s.buf, p...)
	}
	s.last = time.Now()
	s.mu.Unlock()
	s.signal()
	return len(p), nil
}

func (s *screen) close() {
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
	s.signal()
}

func (s *screen) signal() {
	select {
	case s.more <- struct{}{}:
	default:
	}
}

func (s *screen) bytes(from, to int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.buf[from:to])
}

// wait is how much the shell has printed once it has finished printing
// since from, and whether it ended with prompt: when what it printed since
// ends with prompt and has been quiet for shellSettle, or has been quiet for
// idle whatever it ends with.
// Quiet is counted from from's own time too, so a shell that prints nothing
// has finished once idle has passed. It ends early with io.EOF where the
// shell closed, and with an error at deadline or once the output is over
// its bound.
func (s *screen) wait(from int, prompt string, idle time.Duration, deadline time.Time) (int, bool, error) {
	since := time.Now()
	for {
		s.mu.Lock()
		n, last, eof, over := len(s.buf), s.last, s.eof, s.over
		prompted := prompt != "" && n > from && bytes.HasSuffix(s.buf[from:n], []byte(prompt))
		s.mu.Unlock()
		if last.Before(since) {
			last = since
		}
		now := time.Now()
		switch {
		case over:
			return n, false, errShellOutput
		case eof:
			return n, false, io.EOF
		case prompted && now.Sub(last) >= shellSettle:
			return n, true, nil
		case now.Sub(last) >= idle:
			return n, false, nil
		case !now.Before(deadline):
			return n, false, errShellTimeout
		}
		next := last.Add(idle)
		if prompted {
			next = last.Add(shellSettle)
		}
		if deadline.Before(next) {
			next = deadline
		}
		t := time.NewTimer(next.Sub(now))
		select {
		case <-s.more:
		case <-t.C:
		}
		t.Stop()
	}
}
