// Package sudogate decides each no-tty sudo that frisket-sudo's plugin sends
// it: check-ins, one galley item per command, and each claude's password
// window, pinned to the galley process that took the password.
package sudogate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/sudo"
)

type Gate struct {
	User string
	Log  *slog.Logger

	who   func(*net.UnixConn) (peer.Proc, error)
	ask   func(context.Context, string, galleyask.Question) (galleyask.Answer, error)
	alive func(pid int, start uint64) bool
	now   func() time.Duration

	danger   *execrule.Rules
	mu       sync.Mutex
	checkins map[proc]int
	windows  map[proc]window
	changed  chan struct{}
}

type proc struct {
	pid   int
	start uint64
}

type window struct {
	until  time.Duration
	galley proc
}

func (g *Gate) Serve(ln *net.UnixListener) error {
	if err := g.init(); err != nil {
		return err
	}
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go g.serve(c)
	}
}

func (g *Gate) init() error {
	if g.who == nil {
		g.who = peer.ProcOf
	}
	if g.ask == nil {
		g.ask = galleyask.Ask
	}
	if g.alive == nil {
		g.alive = peer.Alive
	}
	if g.now == nil {
		g.now = grant.Now
	}
	danger, err := sudo.Danger()
	if err != nil {
		return fmt.Errorf("danger.json: %w", err)
	}
	g.danger = danger
	g.checkins = map[proc]int{}
	g.windows = map[proc]window{}
	g.changed = make(chan struct{})
	return nil
}

func (g *Gate) serve(c *net.UnixConn) {
	defer c.Close()
	defer func() {
		if p := recover(); p != nil {
			g.Log.Error("connection panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	who, err := g.who(c)
	if err != nil {
		g.Log.Warn("refused", "reason", err.Error())
		return
	}
	(&session{g: g, c: c, peer: who}).run()
}

type session struct {
	g       *Gate
	c       *net.UnixConn
	peer    peer.Proc
	asked   bool
	pending *sudoReq
}

func (s *session) run() {
	req, err := readRequest(s.c)
	if err != nil {
		s.g.Log.Warn("refused", "reason", err.Error(), "pid", s.peer.Pid)
		return
	}
	if s.peer.UID != 0 {
		s.g.Log.Warn("refused", "reason", fmt.Sprintf("peer uid %d is not root", s.peer.UID), "pid", s.peer.Pid)
		s.reply(replyNo, "")
		return
	}
	switch req.kind {
	case kindParent:
		parent := proc{s.peer.PPid, s.peer.PPidStart}
		ok := s.g.checkedIn(parent)
		s.g.Log.Info("decision", "kind", "G", "pid", s.peer.Pid, "parent", s.peer.PPid, "checked_in", ok)
		if ok {
			s.reply(replyYes, "")
		} else {
			s.reply(replyNo, "")
		}
		return
	case kindCheckIn:
	default:
		s.reply(replyNo, "")
		return
	}
	me := proc{s.peer.Pid, s.peer.Start}
	s.g.checkIn(me)
	defer s.g.checkOut(me)
	s.g.Log.Info("check-in", "pid", me.pid)
	if s.reply(replyYes, "") != nil {
		return
	}
	for {
		req, err := readRequest(s.c)
		if err != nil {
			return
		}
		switch {
		case req.kind == kindApproval && !s.asked:
			s.asked = true
			s.approve(req)
		case req.kind == kindVerify && s.pending != nil:
			s.verify(req)
		default:
			s.reply(replyNo, "")
		}
	}
}

func (s *session) reply(kind byte, msg string) error {
	return writeReply(s.c, kind, []byte(msg))
}

func (g *Gate) checkIn(p proc) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.checkins[p]++
}

func (g *Gate) checkOut(p proc) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.checkins[p]--; g.checkins[p] <= 0 {
		delete(g.checkins, p)
	}
}

func (g *Gate) checkedIn(p proc) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return p.start != 0 && g.checkins[p] > 0
}

// sudoReq is one 'A': the command as the gate shows and classifies it, and
// once a dialog's password has gone out in 'W', that dialog's answer.
type sudoReq struct {
	r         *peer.Requester
	program   string
	argv      []string
	title     string
	command   string
	danger    []string
	env       []string
	truncated bool

	answer     galleyask.Answer
	answeredAt time.Duration
}

func (g *Gate) describe(req *request) (*sudoReq, error) {
	info := map[string]string{}
	for _, c := range req.command {
		if k, v, ok := strings.Cut(c, "="); ok {
			info[k] = v
		}
	}
	settings := map[string]string{}
	for _, c := range req.settings {
		if k, v, ok := strings.Cut(c, "="); ok {
			settings[k] = v
		}
	}
	program := info["command"]
	if program == "" {
		return nil, errors.New("no command in command_info")
	}
	a := &sudoReq{r: peer.FromLinks(req.links), program: program, argv: req.argv, truncated: req.truncated}
	words := []string{filepath.Base(program)}
	if len(req.argv) > 1 {
		words = append(words, req.argv[1:]...)
	}
	shown := make([]string, len(words))
	for i, w := range words {
		shown[i] = galleyask.Clean(w)
	}
	a.title = "sudo " + strings.Join(shown, " ")
	a.command = strings.Join(append([]string{galleyask.Clean(program)}, shown[1:]...), " ")

	if !rootOwned(program, g.User) {
		a.danger = append(a.danger, outsideLine(program))
	}
	shell := settings["run_shell"] == "true" || settings["login_shell"] == "true"
	if shell && len(words) >= 3 && words[1] == "-c" {
		words[2] = unescape(words[2])
	}
	for _, d := range dangers(g.danger, words, shell) {
		if !slices.Contains(a.danger, d) {
			a.danger = append(a.danger, d)
		}
	}
	a.env = envLines(req.envp)
	return a, nil
}

// keyed is whether a's chain has a claude a window can be keyed on.
func (a *sudoReq) keyed() bool {
	return !a.r.Cut && !a.r.SessionRoot && a.r.Anchor != nil
}

// grantable is whether a verified password for a may open a window.
func (a *sudoReq) grantable() bool {
	return len(a.danger) == 0 && a.keyed()
}

func (a *sudoReq) question(inWindow, wrong bool) galleyask.Question {
	level := "normal"
	switch {
	case len(a.danger) > 0:
		level = "danger"
	case a.r.Cut || a.r.SessionRoot:
		level = "warning"
	}
	var lines []string
	if len(a.danger) > 0 {
		lines = append(lines, a.danger...)
		lines = append(lines, "")
	}
	lines = append(lines, galleyask.Warnings(a.r)...)
	lines = append(lines, chainLine(a.r))
	if len(a.danger) == 0 {
		lines = append(lines, "")
	}
	lines = append(lines, a.command)
	lines = append(lines, a.env...)
	if wrong && !inWindow {
		lines = append(lines, "wrong password")
	}
	return galleyask.Question{
		Title: a.title, Text: strings.Join(lines, "\n"), Level: level,
		Password: !inWindow, Grantable: !inWindow && a.grantable(),
	}
}

// chainLine runs from the anchor, with its pid, or the top of the chain,
// down to sudo's parent.
func chainLine(r *peer.Requester) string {
	top := len(r.Chain) - 1
	for i := range r.Chain {
		if &r.Chain[i] == r.Anchor {
			top = i
		}
	}
	var parts []string
	for i := top; i >= 0; i-- {
		l := r.Chain[i]
		if &r.Chain[i] == r.Anchor {
			parts = append(parts, fmt.Sprintf("%s (pid %d)", galleyask.Name(l), l.Pid))
			continue
		}
		parts = append(parts, galleyask.Name(l))
	}
	return strings.Join(parts, " ← ")
}

// window is the galley process a's claude's window is pinned to, or nil
// when a is not inside a window.
func (g *Gate) window(a *sudoReq) *proc {
	if !a.keyed() {
		return nil
	}
	g.mu.Lock()
	w, ok := g.windows[proc{a.r.Anchor.Pid, a.r.Anchor.Start}]
	g.mu.Unlock()
	if !ok || g.now() >= w.until || !g.alive(w.galley.pid, w.galley.start) {
		return nil
	}
	return &w.galley
}

func (g *Gate) open(anchor proc, w window) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, old := range g.windows {
		if old.until <= now {
			delete(g.windows, k)
		}
	}
	g.windows[anchor] = w
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *Gate) windowsChanged() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.changed
}

func (s *session) approve(req *request) {
	a, err := s.g.describe(req)
	if err != nil {
		s.g.Log.Warn("refused", "reason", err.Error(), "pid", s.peer.Pid)
		s.reply(replyNo, "bad request")
		return
	}
	s.decide(a, false)
}

func (s *session) verify(req *request) {
	a := s.pending
	s.pending = nil
	if req.verified[0] == 0 {
		s.record(a, "refuse", "wrong password", nil)
		s.decide(a, true)
		return
	}
	if a.answer.For <= 0 || !a.grantable() {
		s.record(a, "allow", "verified", nil)
		s.reply(replyYes, "")
		return
	}
	until := a.answeredAt + a.answer.For
	pin := proc{a.answer.Galley.Pid, a.answer.Galley.Start}
	s.g.open(proc{a.r.Anchor.Pid, a.r.Anchor.Start}, window{until: until, galley: pin})
	at := time.Now().Add(until - s.g.now()).Format("15:04")
	s.record(a, "allow", "verified", []any{"window_until", at})
	s.reply(replyYes, "frisket-sudo: password remembered for this claude until "+at)
}

// decide asks about a, outside a window with the dialog and inside one with
// the question, and replies.
func (s *session) decide(a *sudoReq, wrong bool) {
	for {
		got, pin, hungUp, err := s.post(a, wrong)
		switch {
		case hungUp:
			clear(got.Password)
			s.record(a, "refuse", "hung up", nil)
		case err != nil:
			s.record(a, "refuse", "nobody", []any{"err", err.Error()})
			s.reply(replyNo, "no one to ask; use a terminal")
		case pin != nil:
			a.answer = got
			if !got.Allowed {
				s.record(a, "refuse", "galley", nil)
				s.reply(replyNo, "refused")
			} else if (proc{got.Galley.Pid, got.Galley.Start}) != *pin {
				s.record(a, "refuse", "not the pinned galley", []any{"pin_pid", pin.pid, "pin_start", pin.start})
				s.reply(replyNo, "refused")
			} else {
				s.record(a, "allow", "window", nil)
				s.reply(replyYes, "")
			}
		case !got.Allowed:
			a.answer = got
			s.record(a, "refuse", "cancelled", nil)
			s.reply(replyNo, "cancelled")
		case len(got.Password) == 0 || len(got.Password) > maxPassword || bytes.ContainsAny(got.Password, "\x00\n"):
			clear(got.Password)
			continue
		default:
			password := got.Password
			got.Password = nil
			a.answer, a.answeredAt = got, s.g.now()
			s.record(a, "password", "galley", []any{"password", fmt.Sprintf("%d bytes", len(password))})
			s.pending = a
			_ = writeReply(s.c, replyPassword, password)
			clear(password)
		}
		return
	}
}

type answered struct {
	a   galleyask.Answer
	err error
}

// post puts a's dialog or question until it is answered or the requester
// hangs up. A dialog that a new window for its claude covers is withdrawn
// and put again as the question; a danger dialog stays. pin is the window's
// galley process when it was the question.
func (s *session) post(a *sudoReq, wrong bool) (got galleyask.Answer, pin *proc, hungUp bool, err error) {
	for {
		changed := s.g.windowsChanged()
		pin = s.g.window(a)
		q := a.question(pin != nil, wrong)
		ctx, cancel := context.WithCancel(context.Background())
		stop, werr := galleyask.WatchHangUp(s.c, s.g.Log, cancel)
		if werr != nil {
			cancel()
			return galleyask.Answer{}, nil, false, werr
		}
		answers := make(chan answered, 1)
		go func() {
			var r answered
			defer func() { answers <- r }()
			defer func() {
				if p := recover(); p != nil {
					s.g.Log.Error("request panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
					r.err = fmt.Errorf("panic: %v", p)
				}
			}()
			r.a, r.err = s.g.ask(ctx, s.g.User, q)
		}()
		again := false
	wait:
		for {
			select {
			case r := <-answers:
				got, err = r.a, r.err
				break wait
			case <-changed:
				changed = s.g.windowsChanged()
				if pin == nil && len(a.danger) == 0 && s.g.window(a) != nil {
					cancel()
					r := <-answers
					clear(r.a.Password)
					again = true
					break wait
				}
			}
		}
		stop()
		hungUp = ctx.Err() != nil && !again
		cancel()
		if !again {
			return got, pin, hungUp, err
		}
	}
}

func (s *session) record(a *sudoReq, outcome, source string, extra []any) {
	attrs := []any{
		"chain", a.r.Chain, "anchor", a.r.Anchor, "cut", a.r.Cut, "session_root", a.r.SessionRoot,
		"pid", s.peer.Pid, "program", a.program, "argv", a.argv, "danger", a.danger, "env", a.env,
		"truncated", a.truncated, "outcome", outcome, "source", source, "for", a.answer.For.String(),
		"galley_pid", a.answer.Galley.Pid, "galley_cgroup", a.answer.Galley.Cgroup,
	}
	s.g.Log.Info("decision", append(attrs, extra...)...)
}
