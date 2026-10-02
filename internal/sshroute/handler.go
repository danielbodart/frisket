// Package sshroute serves a session's SSH routes: the machines its document
// lets it run commands on, by SSH, without a key of its own.
//
// The session's ruleset steers each route's address and port to frisket,
// which completes the SSH handshake as the route -- with a host key whose
// certificate the session's SSH CA signed, the one the sandbox's
// known_hosts trusts -- and asks nothing of the client: the sandbox has no
// key, and needs none. Each command the client asks to run is decided by
// the route's rules, admitted, asked about or refused; one admitted runs on
// the machine over frisket's own login, with the user's key, to a host key
// the route pins. Nothing else on the connection goes anywhere: no shell, no
// pty, no forwarding, no agent.
package sshroute

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/internal/steer"
)

// handshakeTimeout bounds the sandbox's side of the handshake. A variable
// only so a test can shrink it.
var handshakeTimeout = 15 * time.Second

// serverVersion is what frisket's side announces: which it is, and nothing
// of which version.
const serverVersion = "SSH-2.0-frisket"

// Config is everything a session's Handler needs.
type Config struct {
	// Routes are the session's, from Compile.
	Routes []*Route
	// CA signs each route's host certificate: the session's, from
	// DeriveCA. Expiry is when the certificates stop being valid -- the TLS
	// CA's, whose lifetime the SSH CA shares -- and zero is never.
	CA     ssh.Signer
	Expiry time.Time
	// Asker decides what the rules ask about. Nil refuses it.
	Asker intercept.Asker
	// Recorder makes the session a recording one: what the rules refuse or
	// ask about is the recorder's to decide, but for a command a Shell
	// route cannot read. Nil without a record block.
	Recorder *record.Recorder
	// Policy and Workspace are the session's, for a question.
	Policy    string
	Workspace string
	// Log is the session's; it gets a line per command, and one for a
	// connection that ran none.
	Log *slog.Logger
	// Dial reaches a route's machine. Nil is a plain dial to exactly the
	// route's address and port.
	Dial Dialer
	// Now is the clock the certificates start from. Nil is time.Now.
	Now func() time.Time
}

// Handler serves one session's SSH routes.
type Handler struct {
	routes    map[netip.AddrPort]*served
	asker     intercept.Asker
	recorder  *record.Recorder
	policy    string
	workspace string
	log       *slog.Logger
	dial      Dialer
}

// served is a route with the server side it is answered by.
type served struct {
	*Route
	server *ssh.ServerConfig
}

var _ steer.Handler = (*Handler)(nil)

// New prepares a session's routes: a host key for the session, and a
// certificate for it per route. The key is made here, and is the session's
// for as long as these handlers are; only the CA is trusted for it, so a
// session restored with a new key is trusted all the same.
func New(cfg Config) (*Handler, error) {
	if cfg.CA == nil {
		return nil, errors.New("sshroute: no CA")
	}
	if cfg.Log == nil {
		return nil, errors.New("sshroute: no log")
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	h := &Handler{
		routes:    map[netip.AddrPort]*served{},
		asker:     cfg.Asker,
		recorder:  cfg.Recorder,
		policy:    cfg.Policy,
		workspace: cfg.Workspace,
		log:       cfg.Log,
		dial:      cfg.Dial,
	}
	if h.dial == nil {
		h.dial = pinnedDial
	}
	if len(cfg.Routes) == 0 {
		return h, nil
	}
	key, err := newHostKey()
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.Routes {
		k := normal(r.Address)
		if _, dup := h.routes[k]; dup {
			return nil, fmt.Errorf("sshroute: two routes at %s", r.Address)
		}
		signer, err := hostSigner(cfg.CA, key, r, now(), cfg.Expiry)
		if err != nil {
			return nil, err
		}
		sc := &ssh.ServerConfig{
			// The sandbox has no key and needs none: which session it is is
			// decided by the listener it reached, and what it may do by the
			// route. Any user name is accepted, and logged as what the
			// client said, never as who the command runs as.
			NoClientAuth:  true,
			ServerVersion: serverVersion,
		}
		sc.AddHostKey(signer)
		h.routes[k] = &served{Route: r, server: sc}
	}
	return h, nil
}

func normal(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// Steers is whether orig is one of the session's routes, at its port,
// compared as addresses rather than spellings.
func (h *Handler) Steers(orig netip.AddrPort) bool {
	_, ok := h.routes[normal(orig)]
	return ok
}

// ServeConn owns c and closes it.
func (h *Handler) ServeConn(ctx context.Context, c *steer.Conn) {
	start := time.Now()
	defer c.Close()
	rt := h.routes[normal(c.Orig)]
	if rt == nil {
		h.logConn(connLine{conn: c, decision: intercept.DecisionRefused, reason: intercept.ReasonUnknownName}, start)
		return
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewServerConn(c, rt.server)
	if err != nil {
		h.logConn(connLine{conn: c, route: rt.Name, decision: intercept.DecisionFailed, reason: ReasonHandshake, err: err}, start)
		return
	}
	defer sc.Close()
	_ = c.SetDeadline(time.Time{})

	// Global requests are drained, every one refused: tcpip-forward and its
	// kind are forwarding, and a keepalive is answered all the same -- any
	// answer is the peer being alive.
	go ssh.DiscardRequests(reqs)

	cctx, cancel := context.WithCancel(ctx)
	// The user name is the workload's text, kept only to be logged, so it is
	// kept as the log shows it.
	s := &conn{h: h, route: rt, c: c, clientUser: loggedUser(sc.User()), ctx: cctx}
	// The login upstream ends with the connection, before its channels are
	// waited for, not after: a channel's own close is only a message, and a
	// machine that went silent -- rebooted, powered off, cut off -- never
	// answers it, so the channels it holds end only when its connection does.
	stopUp := context.AfterFunc(cctx, s.closeUpstream)
	defer stopUp()
	defer s.closeUpstream()
	var wg sync.WaitGroup
	for nc := range chans {
		n := s.channels.Add(1)
		if nc.ChannelType() != "session" {
			// direct-tcpip, streamlocal, x11, auth-agent, tun: everything
			// but a session is a way through frisket to somewhere else.
			_ = nc.Reject(ssh.Prohibited, "frisket: only commands, on a session channel")
			s.logChannelRefused(n, nc.ChannelType())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(n, nc)
		}()
	}
	// The client is gone: nothing still running has anyone to answer.
	cancel()
	wg.Wait()
	// ONE LINE PER CONNECTION AT LEAST. Each command writes its own; a
	// connection that ran none -- a shell refused, a forward refused, a
	// client that only looked at the host key -- would otherwise leave no
	// line at all.
	if s.lines.Load() == 0 {
		h.logConn(connLine{conn: c, route: rt.Name, clientUser: s.clientUser, decision: intercept.DecisionAllowed, channels: s.channels.Load()}, start)
	}
}

// conn is one sandbox connection to a route, and the login upstream it
// shares between its channels.
type conn struct {
	h          *Handler
	route      *served
	c          *steer.Conn
	clientUser string
	// ctx ends with the connection.
	ctx      context.Context
	channels atomic.Uint64
	// lines is how many lines the connection's channels wrote.
	lines atomic.Uint64

	mu       sync.Mutex
	upstream *login
}

// login is a login upstream, and how it ended once it has.
type login struct {
	*ssh.Client
	// gone is closed when the connection has ended, err set before it.
	gone chan struct{}
	err  error
}

// ended is why the login ended -- the machine's connection failing, or
// frisket closing it -- or nil while it has not.
func (l *login) ended() error {
	select {
	case <-l.gone:
		if l.err == nil {
			return net.ErrClosed
		}
		return l.err
	default:
		return nil
	}
}

// client is the connection's login upstream, made on the first command that
// runs and shared by the rest; one that has since failed is made again.
func (s *conn) client(ctx context.Context) (*login, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upstream != nil {
		return s.upstream, nil
	}
	c, err := s.route.dialUpstream(ctx, s.h.dial)
	if err != nil {
		return nil, err
	}
	l := &login{Client: c, gone: make(chan struct{})}
	s.upstream = l
	go func() {
		l.err = c.Wait()
		close(l.gone)
		s.mu.Lock()
		if s.upstream == l {
			s.upstream = nil
		}
		s.mu.Unlock()
	}()
	go keepalive(l, keepaliveInterval, keepaliveTimeout)
	return l, nil
}

func (s *conn) closeUpstream() {
	s.mu.Lock()
	l := s.upstream
	s.upstream = nil
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
}

// How often a login upstream is asked whether it is still there, and how
// long it has to answer. Variables only so a test can shrink them.
var (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 30 * time.Second
)

// keepalive closes a login whose machine stops answering, as ssh's
// ServerAliveInterval does: a machine powered off or cut off sends nothing,
// not even a reset, and a command waiting on it -- or a channel being
// opened, or an exec waiting for its answer -- would otherwise wait for as
// long as the kernel retransmits, or for ever if nothing was in flight. Any
// answer is an answer, a refusal included.
func keepalive(l *login, interval, timeout time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.gone:
			return
		case <-t.C:
		}
		answered := make(chan struct{})
		go func() {
			_, _, _ = l.SendRequest("keepalive@openssh.com", true, nil)
			close(answered)
		}()
		late := time.NewTimer(timeout)
		select {
		case <-answered:
			late.Stop()
		case <-l.gone:
			late.Stop()
			return
		case <-late.C:
			_ = l.Close()
			return
		}
	}
}

// newHostKey is a session's host key, ed25519.
func newHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
