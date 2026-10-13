// Package gitsign serves a policy's git signing socket: an SSH agent a
// sandbox signs its git commits through, which lists an upstream agent's
// identities and passes on its signature over an SSHSIG blob in the git
// namespace, and refuses everything else.
//
// It is frisket's own, for the sockets `frisket serve` makes at
// /run/frisket-sign/POLICY/agent, and asks nobody: a sign in the git
// namespace is passed on, whatever the upstream then does with it, and any
// other is refused here. The upstream is usually quoin-signer
// (https://github.com/danielbodart/quoin), which decides a git sign by its
// own config; what this socket adds is that nothing but a git sign reaches
// it from a sandbox -- no forwarded login, no raw SSHSIG in another
// namespace, and no policy-sign@quoin (policysign.Extension), which, like
// every extension, session-bind among them, is refused.
//
// The namespace is read by projpolicy.ParseSignedData, quoin's own reading
// of the blob an SSHSIG signs, so this socket and the signer behind it read
// the namespace of a sign exactly alike.
package gitsign

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"unicode"

	"github.com/danielbodart/quoin/peer"
	"github.com/danielbodart/quoin/projpolicy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

// Namespace is the one SSHSIG namespace the socket passes a sign on in.
const Namespace = "git"

var errRefused = errors.New("refused")

// Server serves one policy's git signing socket: the upstream agent's
// identities, and its signature over an SSHSIG blob in the git namespace.
// Everything else is refused, the session-bind extension among them: there
// are no forwarded signs through it.
type Server struct {
	// Policy names the policy, in every journal line.
	Policy string
	// UID is the only peer uid served: frisket's own user's. A sandbox's
	// peer is in another user namespace, so SO_PEERCRED's uid, as the
	// kernel maps it into ours, is all there is to go on.
	UID int
	// Upstream is the agent's socket, dialled for each request.
	Upstream string
	Log      *slog.Logger

	cred func(*net.UnixConn) (*unix.Ucred, error)
}

// Serve answers each connection ln accepts, until ln fails.
func (g *Server) Serve(ln *net.UnixListener) error {
	if g.cred == nil {
		g.cred = peer.Cred
	}
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go g.serve(c)
	}
}

func (g *Server) serve(c *net.UnixConn) {
	defer c.Close()
	defer func() {
		if p := recover(); p != nil {
			g.Log.Error("connection panicked", "policy", g.Policy, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	cred, err := g.cred(c)
	if err != nil {
		g.Log.Warn("refused", "policy", g.Policy, "reason", err.Error())
		return
	}
	if int(cred.Uid) != g.UID {
		g.Log.Warn("refused", "policy", g.Policy, "pid", cred.Pid, "reason", fmt.Sprintf("peer uid %d is not %d", cred.Uid, g.UID))
		return
	}
	_ = agent.ServeAgent(&conn{g: g, c: c, pid: int(cred.Pid)}, c)
}

type conn struct {
	g   *Server
	c   *net.UnixConn
	pid int
}

func (c *conn) List() (keys []*agent.Key, err error) {
	err = c.upstream(func(a agent.ExtendedAgent) (err error) {
		keys, err = a.List()
		return err
	})
	c.record("identities", "", err)
	return keys, err
}

func (c *conn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *conn) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (sig *ssh.Signature, err error) {
	namespace, _, err := projpolicy.ParseSignedData(data)
	if err != nil {
		c.refuse("sign", "", "not SSHSIG")
		return nil, errRefused
	}
	if namespace != Namespace {
		c.refuse("sign", namespace, "not the git namespace")
		return nil, errRefused
	}
	err = c.upstream(func(a agent.ExtendedAgent) (err error) {
		sig, err = a.SignWithFlags(key, data, flags)
		return err
	})
	c.record("sign", namespace, err)
	return sig, err
}

func (c *conn) Extension(typ string, _ []byte) ([]byte, error) {
	c.refuse("extension "+clean(typ), "", "")
	return nil, agent.ErrExtensionUnsupported
}

func (c *conn) Add(agent.AddedKey) error       { return c.refuse("add", "", "") }
func (c *conn) Remove(ssh.PublicKey) error     { return c.refuse("remove", "", "") }
func (c *conn) RemoveAll() error               { return c.refuse("remove all", "", "") }
func (c *conn) Lock([]byte) error              { return c.refuse("lock", "", "") }
func (c *conn) Unlock([]byte) error            { return c.refuse("unlock", "", "") }
func (c *conn) Signers() ([]ssh.Signer, error) { return nil, errRefused }

// upstream dials the upstream agent for one request, and hangs up on it if
// the requester hangs up first.
func (c *conn) upstream(f func(agent.ExtendedAgent) error) error {
	u, err := net.Dial("unix", c.g.Upstream)
	if err != nil {
		return err
	}
	defer u.Close()
	stop, err := watchHangUp(c.c, c.g.Log, func() { u.Close() })
	if err != nil {
		return err
	}
	defer stop()
	return f(agent.NewClient(u))
}

func (c *conn) refuse(op, namespace, reason string) error {
	c.g.Log.Info("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", clean(namespace), "outcome", "refuse", "reason", reason)
	return errRefused
}

func (c *conn) record(op, namespace string, err error) {
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			err = errors.New("the requester hung up")
		}
		c.g.Log.Warn("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", namespace, "outcome", "fail", "err", err.Error())
		return
	}
	c.g.Log.Info("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", namespace, "outcome", "forwarded")
}

// maxText bounds what of a requester's string -- an extension's name, a
// namespace -- reaches the journal.
const maxText = 1000

// clean cuts s at maxText characters and escapes control, bidi and line
// separator characters: what a sandbox names is logged as text, never as
// something that rewrites the line it is in.
func clean(s string) string {
	if r := []rune(s); len(r) > maxText {
		s = string(r[:maxText])
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
