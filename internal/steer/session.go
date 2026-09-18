package steer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
)

// DefaultMaxConns caps the connections one session may have open at once.
// Every steered connection now costs a descriptor ON THE HOST -- frisket holds
// one end of each -- so an unbounded sandbox is a file-descriptor exhaustion
// attack on the daemon, and through it on every other session.
const DefaultMaxConns = 512

// What a refusal's line says happened. Kept apart from Decision on purpose:
// Decision is what the RULESET says about the connection, and Action is what
// frisket did about it. A refusal for exceeding the cap is not a statement
// that the ruleset did not steer it.
const (
	ActionAccepted = "accepted"
	ActionRefused  = "refused"
)

// ReasonAtCapacity is the refusal that is ours rather than the ruleset's.
const ReasonAtCapacity = "session connection cap"

// Session is one sandbox's identity on this side of the boundary.
//
// AUTHORISATION IS BY LISTENER. There is no uid namespace, so every process on
// both sides is the same uid and SO_PEERCRED says nothing; nothing is asserted
// by the client and nothing is looked up by path. Which socket a connection
// arrived on IS which session it came from, fixed when the listeners were
// created in that namespace.
//
// ONE LINE PER CONNECTION, AND THIS IS NOT WHERE IT IS WRITTEN for anything
// that is served: the handler that serves a connection or a query owns its
// outcome, and a second line here would make every connection two. Session
// writes the line only for what it refuses -- unsteered, or over the cap --
// because nothing else ever sees those.
type Session struct {
	// ID names the session in every log line it produces.
	ID string

	// Log is injected and is never nil after New. It is not a package-level
	// logger and it is not silenced under test: "exactly one line per
	// connection" is a property, and a property has to be assertable.
	Log *slog.Logger

	// MaxConns caps concurrent connections; zero means DefaultMaxConns.
	MaxConns int

	// Mark is the firewall mark the ruleset puts on every packet it steers.
	// A datagram without it is refused; see ClassifyDatagram.
	Mark uint32

	// Dst is the destination lookup, injectable so a test can steer a
	// loopback connection somewhere without a ruleset. Nil means LocalDst.
	Dst func(*net.TCPConn) netip.AddrPort

	seq  atomic.Uint64
	live atomic.Int64
}

// New builds a session logging JSON to w. The writer is the injection point:
// a test passes a buffer, the daemon passes stderr or the journal.
func New(id string, w io.Writer) *Session {
	return &Session{ID: id, Log: slog.New(slog.NewJSONHandler(w, nil))}
}

// Conn is one accepted connection and everything decided about it at accept.
type Conn struct {
	*net.TCPConn

	Session string
	// ID is unique within the session and rises; it is what joins this
	// connection's line to whatever else is logged about it.
	ID uint64
	// Bound is the listener's own address, inside the sandbox's namespace.
	Bound netip.AddrPort
	// Peer is the workload's address.
	Peer netip.AddrPort
	// Orig is where the workload was really going: the accepted socket's
	// local address, which TPROXY left as the client dialled it.
	Orig netip.AddrPort
	// Verdict is the classification of Orig against Bound.
	Verdict Verdict
}

// Handler is given every connection the ruleset steered. It owns the
// connection, must close it, and writes its one line.
type Handler interface {
	ServeConn(ctx context.Context, c *Conn)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, c *Conn)

func (f HandlerFunc) ServeConn(ctx context.Context, c *Conn) { f(ctx, c) }

// Serve accepts on ln until it is closed or ctx is cancelled, refusing -- and
// logging -- everything the ruleset did not steer here, and handing the rest
// to h.
//
// It closes ln when ctx is done, so a cancelled context ends the loop; closing
// ln from outside ends it too, and a double close is harmless.
func (s *Session) Serve(ctx context.Context, ln net.Listener, h Handler) error {
	bound, err := boundAddrPort(ln.Addr())
	if err != nil {
		return err
	}
	s.Log.Info("listening",
		"session", s.ID,
		"listener", bound.String(),
		"network", ln.Addr().Network(),
	)

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			s.Log.Error("accept failed", "session", s.ID, "listener", bound.String(), "error", err.Error())
			return err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			return fmt.Errorf("listener %s produced a %T, not a TCP connection", bound, c)
		}
		go s.serveConn(ctx, bound, tc, h)
	}
}

func (s *Session) serveConn(ctx context.Context, bound netip.AddrPort, tc *net.TCPConn, h Handler) {
	lookup := s.Dst
	if lookup == nil {
		lookup = LocalDst
	}
	dst := lookup(tc)
	peer, _ := boundAddrPort(tc.RemoteAddr())

	c := &Conn{
		TCPConn: tc,
		Session: s.ID,
		ID:      s.seq.Add(1),
		Bound:   bound,
		Peer:    peer,
		Orig:    dst,
		Verdict: Classify(bound, dst),
	}

	reason := c.Verdict.Reason
	// The cap is checked after the classification so that the line still says
	// where the connection was going. An unsteered connection is refused
	// whatever the count is, and does not consume a slot.
	if c.Verdict.Steered() {
		limit := s.MaxConns
		if limit <= 0 {
			limit = DefaultMaxConns
		}
		if s.live.Add(1) > int64(limit) {
			s.live.Add(-1)
			reason = ReasonAtCapacity
		} else {
			defer s.live.Add(-1)
		}
	}

	if reason != "" {
		s.Log.Info("connection",
			"session", s.ID,
			"conn", c.ID,
			"listener", bound.String(),
			"peer", peer.String(),
			"dst", dst.String(),
			"decision", string(c.Verdict.Decision),
			"action", ActionRefused,
			"reason", reason,
		)
		_ = tc.Close()
		return
	}
	// The handler owns the connection from here, including closing it and
	// its line, so the slot is released when it returns.
	h.ServeConn(ctx, c)
}

// Datagram is one datagram the ruleset steered, and the means to answer it.
type Datagram struct {
	Session string
	// Peer is the workload's address; Orig is where it sent the datagram,
	// and where the reply must appear to come from.
	Peer, Orig netip.AddrPort
	// Payload is steer's buffer, reused for the next datagram as soon as
	// ServePacket returns: a handler that answers later copies it first.
	Payload []byte

	reply func(b []byte) error
}

// NewDatagram builds a datagram whose reply goes through send, for handlers
// tested without a transparent socket.
func NewDatagram(session string, peer, orig netip.AddrPort, payload []byte, send func([]byte) error) *Datagram {
	return &Datagram{Session: session, Peer: peer, Orig: orig, Payload: payload, reply: send}
}

// Reply sends b to Peer from Orig. Safe to call after ServePacket has
// returned, and from any goroutine.
func (d *Datagram) Reply(b []byte) error { return d.reply(b) }

// PacketHandler is given every datagram the ruleset steered, and writes each
// one's line.
type PacketHandler interface {
	ServePacket(ctx context.Context, d *Datagram)
}

// ServePacket reads datagrams until pc is closed, refusing -- and logging --
// every one the ruleset did not mark, and handing the rest to h.
//
// There is no accept for UDP, so each datagram is classified on its own, by
// the mark it carries (see ClassifyDatagram), and its original destination
// comes with it as a control message. The reply is sent from that
// destination, through the same transparent socket.
func (s *Session) ServePacket(ctx context.Context, pc net.PacketConn, h PacketHandler) error {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("packet conn is a %T, not a UDP connection", pc)
	}
	bound, err := boundAddrPort(pc.LocalAddr())
	if err != nil {
		return err
	}
	s.Log.Info("listening",
		"session", s.ID,
		"listener", bound.String(),
		"network", pc.LocalAddr().Network(),
	)

	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()

	// 64 KiB is the largest datagram there is, so a short read is never a
	// truncated query we would then mis-parse.
	buf := make([]byte, 64<<10)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, peer, err := uc.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			s.Log.Error("read failed", "session", s.ID, "listener", bound.String(), "error", err.Error())
			return err
		}
		peer = netip.AddrPortFrom(canon(peer.Addr()), peer.Port())
		r, cerr := ParseControl(oob[:oobn])
		verdict := ClassifyDatagram(s.Mark, r)
		if cerr != nil {
			verdict = Verdict{Unsteered, ReasonBadControl}
		}
		if !verdict.Steered() {
			attrs := []any{
				"session", s.ID,
				"conn", s.seq.Add(1),
				"listener", bound.String(),
				"peer", peer.String(),
				"dst", r.Orig.String(),
				"bytes", n,
				"decision", string(verdict.Decision),
				"action", ActionRefused,
				"reason", verdict.Reason,
			}
			if r.Marked {
				attrs = append(attrs, "mark", r.Mark)
			}
			if cerr != nil {
				attrs = append(attrs, "error", cerr.Error())
			}
			s.Log.Info("datagram", attrs...)
			continue
		}
		orig := r.Orig
		h.ServePacket(ctx, &Datagram{
			Session: s.ID,
			Peer:    peer,
			Orig:    orig,
			Payload: buf[:n],
			reply: func(b []byte) error {
				_, _, err := uc.WriteMsgUDPAddrPort(b, pktinfo(orig.Addr()), peer)
				return err
			},
		})
	}
}

// boundAddrPort canonicalises a net.Addr into a netip.AddrPort. TCPAddr.AddrPort
// hands back a v4-mapped address for a v4 socket held as v6, which would then
// not compare equal to the address the kernel reported; canon undoes that.
func boundAddrPort(a net.Addr) (netip.AddrPort, error) {
	switch v := a.(type) {
	case *net.TCPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(canon(ap.Addr()), ap.Port()), nil
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(canon(ap.Addr()), ap.Port()), nil
	}
	return netip.AddrPort{}, fmt.Errorf("address %v (%T) is not an IP address", a, a)
}
