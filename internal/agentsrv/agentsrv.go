// Package agentsrv serves the SSH agent protocol: for frisket-signer, each
// connection's session binds, the userauth, SSHSIG and remote sudo parsers,
// and the fixed order in which a sign is made silently or asked; and for
// frisket, a policy's git signing socket in front of the signer.
package agentsrv

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strings"

	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/internal/sudomsg"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

const maxBinds = 16

const (
	classBound      = "bound userauth"
	classUnbound    = "unbound userauth"
	classSSHSIG     = "sshsig"
	classRemoteSudo = "remote sudo"
	classForwarded  = "forwarded"
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
	sudo      *sudomsg.Message

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
	req, err := c.classify(key, data)
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

func (c *conn) classify(key ssh.PublicKey, data []byte) (*request, error) {
	req := &request{}
	for _, b := range c.binds {
		req.fwd = req.fwd || b.fwd
	}
	if sudomsg.HasMagic(data) {
		return c.remoteSudo(req, data)
	}
	if s, err := parseSSHSIG(data); err == nil {
		req.class, req.namespace = classSSHSIG, s.namespace
		return req, nil
	}
	u, err := parseUserauth(data)
	if err != nil {
		if len(c.binds) == 0 || !req.fwd {
			return nil, errors.New("neither a userauth request nor SSHSIG, and not a forwarded bound sign")
		}
		req.class, req.host = classForwarded, c.binds[len(c.binds)-1].hostKey
		return req, nil
	}
	if !bytes.Equal(u.key, key.Marshal()) {
		return nil, errors.New("the request names another key")
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

// remoteSudo classifies a sign over a remote sudo's message: parsed
// strictly, on a connection whose last bind is forwarded and to one of the
// message's host keys.
func (c *conn) remoteSudo(req *request, data []byte) (*request, error) {
	m, err := sudomsg.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("remote sudo: %w", err)
	}
	if len(c.binds) == 0 {
		return nil, errors.New("remote sudo on an unbound connection")
	}
	last := c.binds[len(c.binds)-1]
	if !last.fwd {
		return nil, errors.New("remote sudo on a connection that is not forwarded")
	}
	bound := last.hostKey.Marshal()
	for _, k := range m.HostKeys {
		if bytes.Equal(k, bound) {
			req.class, req.host, req.sudo, req.fwd = classRemoteSudo, last.hostKey, m, true
			return req, nil
		}
	}
	return nil, fmt.Errorf("remote sudo bound to %s, not one of the message's host keys", ssh.FingerprintSHA256(last.hostKey))
}

func (c *conn) decide(req *request) verdict {
	r := c.r
	if req.class == classRemoteSudo || req.class == classForwarded {
		return c.ask(req)
	}
	if (req.class == classBound || req.class == classUnbound) && c.s.frisket(r) {
		return verdict{sign: true, source: "frisket"}
	}
	if req.class == classBound && !req.fwd && r.Terminal && !r.Cut && req.known && c.s.Terminal == Allow {
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
	stop, err := galleyask.WatchHangUp(c.c, c.s.Log, cancel)
	if err != nil {
		return verdict{source: "nobody", err: err}
	}
	defer stop()

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
	if m := req.sudo; m != nil {
		attrs = append(attrs, "user", m.User, "runas", m.RunAs, "cwd", m.Cwd, "argv", m.Argv,
			"level", m.Level, "reasons", m.Reasons, "nonce", hex.EncodeToString(m.Nonce))
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
	keyLine := fmt.Sprintf("key %s (%s)", req.keyFP, galleyask.Clean(req.key.Comment))
	if req.class == classRemoteSudo {
		c.describeRemoteSudo(req, keyLine)
		return
	}

	var title string
	lines := galleyask.Warnings(r)
	lines = append(lines, keyLine)
	if req.fwd {
		lines = append(lines, "forwarded")
	}
	switch req.class {
	case classForwarded:
		req.dest = c.hostName(req.host)
		title = "agent signature on " + req.dest
		lines = append(lines, "bound to "+req.dest)
	case classBound:
		names := c.hostNames(req.host)
		req.known = len(names) > 0
		if req.known {
			req.dest = strings.Join(names, ", ")
		} else {
			req.dest = "unknown host " + ssh.FingerprintSHA256(req.host)
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
		lines = append(lines, fmt.Sprintf("SSHSIG namespace %q", galleyask.Clean(req.namespace)))
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
		lines = append(lines, fmt.Sprintf("A grant covers %s from %s (pid %d).", what, galleyask.Name(*r.Anchor), r.Anchor.Pid))
	}
	level := "normal"
	if r.Cut || r.SessionRoot {
		level = "warning"
	}
	req.question = galleyask.Question{Title: title, Text: strings.Join(lines, "\n"), Level: level, Grantable: req.grantable, Chain: galleyask.Chain(r)}
}

func (c *conn) describeRemoteSudo(req *request, keyLine string) {
	m := req.sudo
	req.dest = c.hostName(req.host)
	var lines []string
	for _, r := range m.Reasons {
		lines = append(lines, galleyask.Clean(r))
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	if w := galleyask.Warnings(c.r); len(w) > 0 {
		lines = append(lines, w...)
		lines = append(lines, "")
	}
	lines = append(lines, galleyask.Command(m.Argv, galleyask.Width)...)
	lines = append(lines,
		fmt.Sprintf("%s as %s in %s", galleyask.Clean(m.User), galleyask.Clean(m.RunAs), galleyask.Clean(m.Cwd)),
		keyLine)
	level := m.Level
	if level == "" {
		level = "normal"
		if c.r.Cut || c.r.SessionRoot {
			level = "warning"
		}
	}
	req.question = galleyask.Question{Title: "sudo on " + req.dest, Text: strings.Join(lines, "\n"), Level: level, Allow: "Allow", Chain: galleyask.Chain(c.r)}
}

// hostNames are key's names in the known hosts file.
func (c *conn) hostNames(key ssh.PublicKey) []string {
	names := c.knownHosts()[ssh.FingerprintSHA256(key)]
	for i, n := range names {
		names[i] = galleyask.Clean(n)
	}
	return names
}

// hostName is key's names, else its fingerprint.
func (c *conn) hostName(key ssh.PublicKey) string {
	if names := c.hostNames(key); len(names) > 0 {
		return strings.Join(names, ", ")
	}
	return ssh.FingerprintSHA256(key)
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
