package agentsrv

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"

	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

// Git serves one policy's git signing socket: the upstream agent's
// identities, and its signature over an SSHSIG blob in the git namespace.
// Everything else is refused, the session-bind extension among them: there
// are no forwarded signs through it.
type Git struct {
	Policy   string
	UID      int
	Upstream string
	Log      *slog.Logger

	cred func(*net.UnixConn) (*unix.Ucred, error)
}

func (g *Git) Serve(ln *net.UnixListener) error {
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

func (g *Git) serve(c *net.UnixConn) {
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
	_ = agent.ServeAgent(&gitConn{g: g, c: c, pid: int(cred.Pid)}, c)
}

type gitConn struct {
	g   *Git
	c   *net.UnixConn
	pid int
}

func (c *gitConn) List() (keys []*agent.Key, err error) {
	err = c.upstream(func(a agent.ExtendedAgent) (err error) {
		keys, err = a.List()
		return err
	})
	c.record("identities", "", err)
	return keys, err
}

func (c *gitConn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *gitConn) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (sig *ssh.Signature, err error) {
	s, err := parseSSHSIG(data)
	if err != nil {
		c.refuse("sign", "", "not SSHSIG")
		return nil, errRefused
	}
	if s.namespace != "git" {
		c.refuse("sign", s.namespace, "not the git namespace")
		return nil, errRefused
	}
	err = c.upstream(func(a agent.ExtendedAgent) (err error) {
		sig, err = a.SignWithFlags(key, data, flags)
		return err
	})
	c.record("sign", s.namespace, err)
	return sig, err
}

func (c *gitConn) Extension(typ string, _ []byte) ([]byte, error) {
	c.refuse("extension "+clean(typ), "", "")
	return nil, agent.ErrExtensionUnsupported
}

func (c *gitConn) Add(agent.AddedKey) error       { return c.refuse("add", "", "") }
func (c *gitConn) Remove(ssh.PublicKey) error     { return c.refuse("remove", "", "") }
func (c *gitConn) RemoveAll() error               { return c.refuse("remove all", "", "") }
func (c *gitConn) Lock([]byte) error              { return c.refuse("lock", "", "") }
func (c *gitConn) Unlock([]byte) error            { return c.refuse("unlock", "", "") }
func (c *gitConn) Signers() ([]ssh.Signer, error) { return nil, errRefused }

// upstream dials the upstream agent for one request, and hangs up on it if
// the requester hangs up first.
func (c *gitConn) upstream(f func(agent.ExtendedAgent) error) error {
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

func (c *gitConn) refuse(op, namespace, reason string) error {
	c.g.Log.Info("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", clean(namespace), "outcome", "refuse", "reason", reason)
	return errRefused
}

func (c *gitConn) record(op, namespace string, err error) {
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			err = errors.New("the requester hung up")
		}
		c.g.Log.Warn("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", namespace, "outcome", "fail", "err", err.Error())
		return
	}
	c.g.Log.Info("decision", "policy", c.g.Policy, "pid", c.pid, "op", op, "namespace", namespace, "outcome", "forwarded")
}
