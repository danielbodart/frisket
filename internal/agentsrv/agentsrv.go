// Package agentsrv serves the SSH agent protocol for frisket-signer: each
// connection's session binds, the userauth and SSHSIG parsers, and the fixed
// order in which a sign is made silently or asked.
package agentsrv

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"unicode"

	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

type Rule string

const (
	Allow Rule = "allow"
	Ask   Rule = "ask"
)

type Key struct {
	Signer  crypto.Signer
	Comment string
}

type Server struct {
	User       string
	UID        int
	Terminal   Rule
	SSHSIG     map[string]Rule
	Keys       []Key
	KnownHosts string
	Grants     *grant.Grants
	Log        *slog.Logger

	who     func(*net.UnixConn) (*peer.Requester, error)
	frisket func(*peer.Requester) bool
	ask     func(context.Context, string, galleyask.Question) (galleyask.Answer, error)
}

const (
	maxBinds = 16
	maxArg   = 1000
)

const (
	classBound   = "bound userauth"
	classUnbound = "unbound userauth"
	classSSHSIG  = "sshsig"
)

var errRefused = errors.New("refused")

func (s *Server) Serve(ln *net.UnixListener) error {
	if s.who == nil {
		s.who = peer.FromConn
	}
	if s.frisket == nil {
		s.frisket = func(r *peer.Requester) bool { return r.IsMainOf("frisket.service", s.UID) }
	}
	if s.ask == nil {
		s.ask = galleyask.Ask
	}
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c *net.UnixConn) {
	defer c.Close()
	defer func() {
		if p := recover(); p != nil {
			s.Log.Error("connection panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	r, err := s.who(c)
	if err != nil {
		s.Log.Warn("refused", "reason", err.Error())
		return
	}
	if r.PeerUID != s.UID {
		s.Log.Warn("refused", "reason", fmt.Sprintf("peer uid %d is not %s", r.PeerUID, s.User), "chain", r.Chain)
		return
	}
	_ = agent.ServeAgent(&conn{s: s, c: c, r: r}, c)
}

type conn struct {
	s     *Server
	c     *net.UnixConn
	r     *peer.Requester
	binds []*bind
}

type request struct {
	class     string
	namespace string
	host      ssh.PublicKey
	claimed   []byte
	fwd       bool

	key       Key
	keyFP     string
	dest      string
	known     bool
	grantable bool
	grant     grant.Key
	question  galleyask.Question
}

type verdict struct {
	sign   bool
	source string
	err    error
	answer galleyask.Answer
}

func (c *conn) List() (keys []*agent.Key, err error) {
	defer c.refusePanic(&err)
	for _, k := range c.s.Keys {
		pub, err := ssh.NewPublicKey(k.Signer.Public())
		if err != nil {
			return nil, err
		}
		keys = append(keys, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: k.Comment})
	}
	c.s.Log.Info("identities", "keys", len(keys), "chain", c.r.Chain, "anchor", c.r.Anchor)
	return keys, nil
}

func (c *conn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *conn) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (sig *ssh.Signature, err error) {
	defer c.refusePanic(&err)
	req, err := c.classify(data)
	if err != nil {
		c.s.Log.Warn("refused", "reason", err.Error(), "chain", c.r.Chain, "anchor", c.r.Anchor)
		return nil, err
	}
	var ok bool
	if req.key, ok = c.find(key); !ok {
		c.s.Log.Warn("refused", "reason", "not a key this agent holds", "key", ssh.FingerprintSHA256(key))
		return nil, errRefused
	}
	c.describe(req)
	v := c.decide(req)
	c.record(req, v)
	if !v.sign {
		return nil, errRefused
	}
	signer, err := ssh.NewSignerFromSigner(req.key.Signer)
	if err == nil {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		c.s.Log.Error("sign failed", "key", req.keyFP, "err", err.Error())
		return nil, err
	}
	return sig, nil
}

func (c *conn) Extension(typ string, contents []byte) (_ []byte, err error) {
	defer c.refusePanic(&err)
	if typ != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	if len(c.binds) >= maxBinds {
		return nil, errors.New("too many session binds")
	}
	b, err := parseBind(contents)
	if err != nil {
		c.s.Log.Warn("session-bind refused", "err", err.Error(), "chain", c.r.Chain)
		return nil, err
	}
	c.binds = append(c.binds, b)
	return nil, nil
}

func (c *conn) Add(agent.AddedKey) error       { return errRefused }
func (c *conn) Remove(ssh.PublicKey) error     { return errRefused }
func (c *conn) RemoveAll() error               { return errRefused }
func (c *conn) Lock([]byte) error              { return errRefused }
func (c *conn) Unlock([]byte) error            { return errRefused }
func (c *conn) Signers() ([]ssh.Signer, error) { return nil, errRefused }

func (c *conn) refusePanic(err *error) {
	if p := recover(); p != nil {
		c.s.Log.Error("request panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		*err = fmt.Errorf("panic: %v", p)
	}
}

func (c *conn) find(key ssh.PublicKey) (Key, bool) {
	want := key.Marshal()
	for _, k := range c.s.Keys {
		pub, err := ssh.NewPublicKey(k.Signer.Public())
		if err == nil && bytes.Equal(pub.Marshal(), want) {
			return k, true
		}
	}
	return Key{}, false
}

func (c *conn) classify(data []byte) (*request, error) {
	req := &request{}
	for _, b := range c.binds {
		req.fwd = req.fwd || b.fwd
	}
	if s, err := parseSSHSIG(data); err == nil {
		req.class, req.namespace = classSSHSIG, s.namespace
		return req, nil
	}
	u, err := parseUserauth(data)
	if err != nil {
		return nil, errors.New("neither a userauth request nor SSHSIG")
	}
	if len(c.binds) == 0 {
		req.class, req.claimed = classUnbound, u.hostKey
		return req, nil
	}
	last := c.binds[len(c.binds)-1]
	if !bytes.Equal(u.sid, last.sid) {
		return nil, errors.New("session id is not the last bind's")
	}
	if u.hostKey != nil && !bytes.Equal(u.hostKey, last.hostKey.Marshal()) {
		return nil, errors.New("host key is not the bound key")
	}
	req.class, req.host = classBound, last.hostKey
	return req, nil
}

func (c *conn) decide(req *request) verdict {
	r := c.r
	if req.class != classSSHSIG && c.s.frisket(r) {
		return verdict{sign: true, source: "frisket"}
	}
	if req.class == classBound && !req.fwd && r.Terminal && req.known && c.s.Terminal == Allow {
		return verdict{sign: true, source: "terminal"}
	}
	if req.class == classSSHSIG && !req.fwd && c.s.SSHSIG[req.namespace] == Allow {
		return verdict{sign: true, source: "sshsig"}
	}
	if req.grantable && c.s.Grants.Use(req.grant) {
		return verdict{sign: true, source: "grant"}
	}
	return c.ask(req)
}

type answered struct {
	a   galleyask.Answer
	err error
}

// ask puts the question until it is answered, the requester hangs up, or a
// new grant covers it.
func (c *conn) ask(req *request) verdict {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return verdict{source: "nobody", err: err}
	}
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		defer c.refusePanic(new(error))
		c.watchHangUp(stop, cancel)
	}()
	defer func() {
		one := binary.NativeEndian.AppendUint64(nil, 1)
		_, _ = unix.Write(stop, one)
		<-watching
		unix.Close(stop)
	}()

	answers := make(chan answered, 1)
	go func() {
		var got answered
		defer func() { answers <- got }()
		defer c.refusePanic(&got.err)
		got.a, got.err = c.s.ask(ctx, c.s.User, req.question)
	}()
	for {
		changed := c.s.Grants.Changed()
		if req.grantable && c.s.Grants.Use(req.grant) {
			cancel()
			c.keep(req, <-answers)
			return verdict{sign: true, source: "grant"}
		}
		select {
		case got := <-answers:
			switch {
			case got.err != nil && ctx.Err() != nil:
				return verdict{source: "hung up"}
			case got.err != nil:
				return verdict{source: "nobody", err: got.err}
			case !got.a.Allowed:
				return verdict{source: "galley", answer: got.a}
			}
			c.keep(req, got)
			return verdict{sign: true, source: "galley", answer: got.a}
		case <-changed:
		}
	}
}

func (c *conn) keep(req *request, got answered) {
	if req.grantable && got.err == nil && got.a.Allowed && got.a.For > 0 {
		c.s.Grants.Grant(req.grant, grant.Now()+got.a.For)
	}
}

func (c *conn) watchHangUp(stop int, cancel func()) {
	rc, err := c.c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}, {Fd: int32(stop), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(fds, -1); err != unix.EINTR {
				break
			}
		}
		if fds[0].Revents != 0 {
			cancel()
		}
	})
}

func (c *conn) record(req *request, v verdict) {
	outcome := "refuse"
	if v.sign {
		outcome = "sign"
	}
	attrs := []any{
		"chain", c.r.Chain, "anchor", c.r.Anchor,
		"cut", c.r.Cut, "session_root", c.r.SessionRoot, "terminal", c.r.Terminal,
		"destination", req.dest, "key", req.keyFP, "class", req.class, "namespace", req.namespace,
		"forwarded", req.fwd, "lines", strings.Split(req.question.Text, "\n"),
		"outcome", outcome, "source", v.source, "for", v.answer.For.String(),
		"galley_pid", v.answer.Galley.Pid, "galley_cgroup", v.answer.Galley.Cgroup,
	}
	if v.err != nil {
		attrs = append(attrs, "err", v.err.Error())
	}
	c.s.Log.Info("decision", attrs...)
}

// describe fills in what the decision and the question need: the key, the
// destination, the grant key and the question's text.
func (c *conn) describe(req *request) {
	r := c.r
	pub, _ := ssh.NewPublicKey(req.key.Signer.Public())
	req.keyFP = ssh.FingerprintSHA256(pub)

	var title string
	var lines []string
	if r.SessionRoot {
		lines = append(lines, "launched through "+sessionRoot(r.Anchor))
	}
	if r.Cut {
		lines = append(lines, "the process chain was cut short")
	}
	lines = append(lines, chainText(r), fmt.Sprintf("key %s (%s)", req.keyFP, clean(req.key.Comment)))
	if req.fwd {
		lines = append(lines, "forwarded")
	}
	switch req.class {
	case classBound:
		fp := ssh.FingerprintSHA256(req.host)
		names := c.knownHosts()[fp]
		req.known = len(names) > 0
		if req.known {
			for i, n := range names {
				names[i] = clean(n)
			}
			req.dest = strings.Join(names, ", ")
		} else {
			req.dest = "unknown host " + fp
			lines = append(lines, "unknown host key")
		}
		title = "ssh to " + req.dest
		req.grantable = !r.Cut && !r.SessionRoot && r.Anchor != nil
	case classUnbound:
		title = "ssh to an unverified host"
		lines = append(lines, "unbound: ssh did not say which host this is for")
		if req.claimed != nil {
			sum := sha256.Sum256(req.claimed)
			req.dest = "claims SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			lines = append(lines, req.dest)
		}
	case classSSHSIG:
		title = "SSHSIG signature"
		lines = append(lines, fmt.Sprintf("SSHSIG namespace %q", clean(req.namespace)))
	}
	if req.grantable {
		req.grant = grant.Key{
			Anchor: grant.Anchor{Pid: r.Anchor.Pid, Start: r.Anchor.Start},
			Host:   ssh.FingerprintSHA256(req.host), KeyFP: req.keyFP, Fwd: req.fwd,
		}
		what := req.dest
		if req.fwd {
			what = "forwarded signs to " + req.dest
		}
		lines = append(lines, fmt.Sprintf("A grant covers %s from %s (pid %d).", what, clean(r.Anchor.Comm), r.Anchor.Pid))
	}
	level := "normal"
	if r.Cut || r.SessionRoot {
		level = "warning"
	}
	req.question = galleyask.Question{Title: title, Text: strings.Join(lines, "\n"), Level: level, Grantable: req.grantable}
}

func (c *conn) knownHosts() map[string][]string {
	names := map[string][]string{}
	b, err := os.ReadFile(c.s.KnownHosts)
	if err != nil {
		c.s.Log.Warn("known hosts unreadable", "err", err.Error())
		return names
	}
	for line := range bytes.Lines(b) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil || marker != "" {
			continue
		}
		fp := ssh.FingerprintSHA256(key)
		names[fp] = append(names[fp], hosts...)
	}
	return names
}

func sessionRoot(a *peer.Link) string {
	switch {
	case a.Pid == 1:
		return "pid 1"
	case a.Comm == ".kgx-wrapped":
		return "the terminal server"
	}
	return "systemd --user"
}

// chainText runs from the anchor, or the top of the chain, down to the leaf.
func chainText(r *peer.Requester) string {
	top := len(r.Chain) - 1
	for i := range r.Chain {
		if &r.Chain[i] == r.Anchor {
			top = i
		}
	}
	var parts []string
	for i := top; i >= 0; i-- {
		l := r.Chain[i]
		if i == top {
			parts = append(parts, fmt.Sprintf("%s (pid %d)", clean(l.Comm), l.Pid))
			continue
		}
		args := make([]string, len(l.Cmdline))
		for j, a := range l.Cmdline {
			args[j] = clean(a)
		}
		if len(args) == 0 {
			args = []string{clean(l.Comm)}
		}
		parts = append(parts, strings.Join(args, " "))
	}
	return strings.Join(parts, " ← ")
}

// clean cuts s at maxArg characters and escapes control, bidi and line
// separator characters.
func clean(s string) string {
	if r := []rune(s); len(r) > maxArg {
		s = string(r[:maxArg])
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
