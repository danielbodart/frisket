package sshroute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/intercept"
)

// Exit statuses frisket gives a command it did not run: 126, the shell's
// "found but not run", for one refused, and 255, ssh's own, for a machine
// frisket could not reach or log in to.
const (
	exitRefused  = 126
	exitUpstream = 255
)

// Why a command was not run, beyond the scope's and the asker's reasons.
const (
	ReasonHandshake   = "handshake failed"
	ReasonChannelType = "not a session channel"
	ReasonNotUTF8     = "command is not UTF-8"
	ReasonHostKey     = "host key not pinned"
	ReasonUpstream    = "upstream failed"
	ReasonExecFailed  = "upstream refused the command"
	ReasonMalformed   = "malformed exec"
)

// queue is a channel's requests, held for the one goroutine that answers
// them in order. Unbounded, because what feeds it must never wait: x/crypto
// hands a channel's requests over from the connection's one reader, and a
// request not taken stalls every channel on the connection, keepalives and
// all, while a person decides about a command.
type queue struct {
	mu     sync.Mutex
	items  []*ssh.Request
	closed bool
	ready  chan struct{}
}

func newQueue() *queue { return &queue{ready: make(chan struct{}, 1)} }

func (q *queue) push(r *ssh.Request) {
	q.mu.Lock()
	q.items = append(q.items, r)
	q.mu.Unlock()
	q.signal()
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.signal()
}

func (q *queue) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// next is the oldest request, or nil once the channel has closed and every
// request before that is taken.
func (q *queue) next() *ssh.Request {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			r := q.items[0]
			q.items[0] = nil
			q.items = q.items[1:]
			q.mu.Unlock()
			return r
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil
		}
		<-q.ready
	}
}

// channel is one session channel and the one command it may run.
type channel struct {
	s   *conn
	n   uint64
	ch  ssh.Channel
	ctx context.Context
	// up is the command's channel upstream, once it runs. Only the
	// goroutine answering requests reads or writes it.
	up ssh.Channel
	// done is closed when the command has finished and its line is written.
	done chan struct{}
}

// session serves one session channel: its requests, answered in order by
// this goroutine alone, while another takes them as they come.
func (s *conn) session(n uint64, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	q := newQueue()
	go func() {
		for r := range reqs {
			if r.Type == "window-change" && !r.WantReply {
				continue // no pty to resize, and nothing to answer
			}
			q.push(r)
		}
		q.close()
		// The client closed the channel, or the connection: whatever is
		// waiting on its behalf -- a question, a preview -- stops.
		cancel()
	}()
	c := &channel{s: s, n: n, ch: ch, ctx: ctx}
	exec := false
	for r := q.next(); r != nil; r = q.next() {
		switch r.Type {
		case "exec":
			if exec {
				// One command to a channel, as sshd allows.
				_ = r.Reply(false, nil)
				continue
			}
			exec = true
			c.exec(r)
		case "signal":
			if c.up != nil {
				_, _ = c.up.SendRequest("signal", false, r.Payload)
			}
			_ = r.Reply(false, nil)
		default:
			// pty-req, env, shell, subsystem, x11-req,
			// auth-agent-req@openssh.com and the rest: there is no shell,
			// no terminal and nothing forwarded. A pty refused is a warning
			// to ssh, which goes on to the command.
			_ = r.Reply(false, nil)
		}
	}
	if c.done != nil {
		<-c.done
	}
	_ = ch.Close()
}

// execLine is one command's line, filled in as it goes.
type execLine struct {
	command    string
	decision   string
	rule       string
	operation  string
	asked      bool
	reason     string
	exitStatus *uint32
	exitSignal string
	stdin      atomic.Int64
	stdout     atomic.Int64
	stderr     atomic.Int64
	err        error
}

// exec decides a command and runs it, refuses it, or fails it. It answers
// the request before it returns; a command that runs goes on in goroutines
// of its own, so that the requests after it -- a signal -- are answered.
func (c *channel) exec(r *ssh.Request) {
	start := time.Now()
	line := &execLine{}
	var p struct{ Command string }
	if err := ssh.Unmarshal(r.Payload, &p); err != nil {
		_ = r.Reply(false, nil)
		line.decision, line.reason, line.err = intercept.DecisionRefused, ReasonMalformed, err
		c.log(line, start)
		return
	}
	line.command = p.Command
	rt := c.s.route
	if !utf8.ValidString(p.Command) {
		// A command a person cannot be shown as it is cannot be put to one.
		line.decision, line.rule, line.reason = intercept.DecisionRefused, intercept.RuleUnmatched, ReasonNotUTF8
		c.refuse(r, line, start, exitRefused)
		return
	}
	d := rt.Decide(p.Command)
	line.rule, line.operation = d.Rule, d.operationIDs()
	var stdin io.Reader = c.ch
	switch d.Outcome {
	case intercept.Refuse:
		line.decision, line.reason = intercept.DecisionRefused, intercept.ReasonRefused
		if d.Rule == intercept.RuleUnmatched {
			line.reason = intercept.ReasonOutOfScope
		}
		c.refuse(r, line, start, exitRefused)
		return
	case intercept.Ask:
		line.asked = true
		reason, rest := c.ask(p.Command, d)
		if reason != "" {
			line.decision, line.reason = intercept.DecisionRefused, reason
			c.refuse(r, line, start, exitRefused)
			return
		}
		stdin = rest
	}

	client, err := c.s.client(c.ctx)
	if err != nil {
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonUpstream, err
		if hostKeyError(err) {
			line.reason = ReasonHostKey
		}
		c.refuse(r, line, start, exitUpstream)
		return
	}
	up, upReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonUpstream, err
		c.refuse(r, line, start, exitUpstream)
		return
	}
	// The exec as the client sent it, byte for byte: what was decided is
	// exactly what runs.
	ok, err := up.SendRequest("exec", true, r.Payload)
	if err != nil || !ok {
		_ = up.Close()
		_ = r.Reply(false, nil)
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonExecFailed, err
		c.log(line, start)
		return
	}
	_ = r.Reply(true, nil)
	line.decision = intercept.DecisionAllowed
	c.up = up
	c.done = make(chan struct{})
	go c.proxy(client, up, upReqs, stdin, line, start)
}

// errNoExit is a command's channel upstream closed with no exit status, on
// a login that is still there.
var errNoExit = errors.New("the command ended with no exit status")

// proxy carries a running command both ways, and closes the sandbox's
// channel only once everything upstream sent has been sent on.
func (c *channel) proxy(client *login, up ssh.Channel, upReqs <-chan *ssh.Request, stdin io.Reader, line *execLine, start time.Time) {
	defer close(c.done)
	// The client leaving ends the command's channel: a command it is no
	// longer there to read is not kept running for it.
	stop := context.AfterFunc(c.ctx, func() { _ = up.Close() })
	defer stop()
	go func() {
		_, _ = io.Copy(counting{up, &line.stdin}, stdin)
		_ = up.CloseWrite()
	}()
	var wg sync.WaitGroup
	wg.Add(3)
	// stdout and stderr together: they share the channel's window, and one
	// not read stalls the other. The sandbox is sent EOF once both are done,
	// and the machine has closed the command's channel, and not before: EOF
	// ends stderr too, and stderr sent after it is lost -- ssh drops the
	// connection over it -- and whether the command ended with no status,
	// which is said on stderr, is known only once the channel has closed.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(counting{c.ch, &line.stdout}, up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(counting{c.ch.Stderr(), &line.stderr}, up.Stderr())
	}()
	var status *uint32
	var signal string
	go func() {
		defer wg.Done()
		for r := range upReqs {
			switch r.Type {
			case "exit-status":
				var p struct{ Status uint32 }
				if ssh.Unmarshal(r.Payload, &p) == nil {
					status = &p.Status
				}
			case "exit-signal":
				var p struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}
				if ssh.Unmarshal(r.Payload, &p) == nil {
					signal = p.Signal
				}
			case "eow@openssh.com":
			default:
				// A keepalive, or anything else the machine asks of its
				// client, is frisket's to answer, and the sandbox's to
				// never see.
				_ = r.Reply(false, nil)
				continue
			}
			_, _ = c.ch.SendRequest(r.Type, false, r.Payload)
		}
	}()
	wg.Wait()
	_ = up.Close()
	line.exitStatus, line.exitSignal = status, signal
	if status == nil && signal == "" && c.ctx.Err() == nil {
		// The machine went -- rebooted, reset, closed -- before the command
		// said how it ended. Said as a failure, on the line and to whoever
		// ran it, as a login that failed is: a command that ends with no
		// status and no word is indistinguishable from one that ran. A
		// client that left is not this: it closed the command itself.
		line.decision, line.reason, line.err = intercept.DecisionFailed, ReasonUpstream, errNoExit
		if err := client.ended(); err != nil {
			line.err = fmt.Errorf("%w: %w", errNoExit, err)
		}
		fmt.Fprintf(c.ch.Stderr(), "frisket: %s: %s: %s\n", c.s.route.Name, line.reason, line.err)
		_ = c.ch.CloseWrite()
		_, _ = c.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exitUpstream}))
		failed := uint32(exitUpstream)
		line.exitStatus = &failed
	} else {
		_ = c.ch.CloseWrite()
	}
	c.log(line, start)
	_ = c.ch.Close()
}

// refuse answers a command frisket will not run as a command that ran and
// failed: the reason on its stderr and an exit status, so whoever ran it
// sees why, where `exec request failed` would say nothing.
func (c *channel) refuse(r *ssh.Request, line *execLine, start time.Time, status uint32) {
	_ = r.Reply(true, nil)
	what := line.reason
	if line.err != nil {
		what += ": " + line.err.Error()
	}
	fmt.Fprintf(c.ch.Stderr(), "frisket: %s: %s\n", c.s.route.Name, what)
	_ = c.ch.CloseWrite()
	_, _ = c.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	line.exitStatus = &status
	c.log(line, start)
	_ = c.ch.Close()
}

// ask puts the command to the asker with the start of its stdin, and
// returns why it is refused, or "" and the stdin to send, the preview
// first.
func (c *channel) ask(command string, d Decision) (string, io.Reader) {
	h := c.s.h
	if h.asker == nil {
		return intercept.ReasonNobodyToAsk, nil
	}
	head, more, rest, err := intercept.Preview(c.ctx, c.ch, previewIdle, true)
	if err != nil {
		return intercept.ReasonStoppedWaiting, nil
	}
	rt := c.s.route
	q := intercept.Question{
		Session:   c.s.c.Session,
		Workspace: h.workspace,
		Policy:    h.policy,
		Route:     rt.Name,
		Host:      rt.Name,
		Body:      string(head),
		BodyMore:  more,
		Kind:      "ssh",
		Address:   rt.Address.String(),
		User:      rt.User,
		Command:   command,
		// What the rules call the command, from the route's own document:
		// the operation of the simple command that decided, and of each
		// of them where there are several.
		Operation:  d.Operation,
		Operations: d.Operations,
	}
	reason, err := intercept.AskAbout(c.ctx, h.asker, q)
	if err != nil {
		// Its own line, not the command's: the error is the asker's, and
		// may quote whatever it was sent.
		h.log.Error("ask", "session", c.s.c.Session, "conn", c.s.c.ID, "channel", c.n, "route", rt.Name, "error", err.Error())
	}
	return reason, rest
}

// counting is a writer that adds what it wrote to n.
type counting struct {
	w io.Writer
	n *atomic.Int64
}

func (c counting) Write(p []byte) (int, error) {
	k, err := c.w.Write(p)
	c.n.Add(int64(k))
	return k, err
}
