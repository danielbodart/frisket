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

// What a connection's line says happened to it. Kept apart from Decision on
// purpose: Decision is what the KERNEL says about the connection, and Action is
// what frisket did about it. A refusal for exceeding the cap is not a statement
// that the kernel did not steer it.
const (
	ActionAccepted = "accepted"
	ActionRefused  = "refused"
)

// ReasonAtCapacity is the refusal that is ours rather than the kernel's.
const ReasonAtCapacity = "session connection cap"

// Session is one sandbox's identity on this side of the boundary.
//
// AUTHORISATION IS BY LISTENER. There is no uid namespace, so every process on
// both sides is the same uid and SO_PEERCRED says nothing; nothing is asserted
// by the client and nothing is looked up by path. Which socket a connection
// arrived on IS which session it came from, fixed when the listeners were
// created in that namespace.
type Session struct {
	// ID names the session in every log line it produces.
	ID string

	// Log is injected and is never nil after New. It is not a package-level
	// logger and it is not silenced under test: "exactly one line per
	// connection" is a property, and a property has to be assertable.
	Log *slog.Logger

	// MaxConns caps concurrent connections; zero means DefaultMaxConns.
	MaxConns int

	// OrigDst is the original-destination lookup, injectable so a test can
	// count how many times it runs. Nil means steer.OriginalDst.
	OrigDst func(*net.TCPConn) (netip.AddrPort, error)

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
	// connection's line to whatever else is logged about it later.
	ID uint64
	// Bound is the listener's own address, inside the sandbox's namespace.
	Bound netip.AddrPort
	// Peer is the workload's address.
	Peer netip.AddrPort
	// Orig is where the workload was really going. READ ONCE, AT ACCEPT, AND
	// CACHED HERE: the lookup is a conntrack lookup, and flushing conntrack
	// mid-connection invalidates it. There is deliberately no method that
	// re-reads it.
	Orig netip.AddrPort
	// Verdict is the classification of Orig against Bound.
	Verdict Verdict
}

// Handler is given every connection the kernel steered. It owns the connection
// and must close it.
type Handler interface {
	ServeConn(ctx context.Context, c *Conn)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, c *Conn)

func (f HandlerFunc) ServeConn(ctx context.Context, c *Conn) { f(ctx, c) }

// Serve accepts on ln until it is closed or ctx is cancelled, logging exactly
// one line per connection and refusing everything the kernel did not steer
// here.
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
	lookup := s.OrigDst
	if lookup == nil {
		lookup = OriginalDst
	}
	orig, lookupErr := lookup(tc)
	peer, _ := boundAddrPort(tc.RemoteAddr())

	c := &Conn{
		TCPConn: tc,
		Session: s.ID,
		ID:      s.seq.Add(1),
		Bound:   bound,
		Peer:    peer,
		Orig:    orig,
		Verdict: Classify(bound, orig, lookupErr),
	}

	action, reason := ActionAccepted, c.Verdict.Reason
	if !c.Verdict.Steered() {
		action = ActionRefused
	}

	// The cap is checked after the classification so that the line still says
	// where the connection was going. An unsteered connection is refused
	// whatever the count is, and does not consume a slot.
	if action == ActionAccepted {
		limit := s.MaxConns
		if limit <= 0 {
			limit = DefaultMaxConns
		}
		if s.live.Add(1) > int64(limit) {
			s.live.Add(-1)
			action, reason = ActionRefused, ReasonAtCapacity
		} else {
			defer s.live.Add(-1)
		}
	}

	attrs := []any{
		"session", s.ID,
		"conn", c.ID,
		"listener", bound.String(),
		"peer", peer.String(),
		"dst", orig.String(),
		"decision", string(c.Verdict.Decision),
		"action", action,
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if lookupErr != nil {
		// The error is a log field, not an event of its own: one line per
		// connection means one line, including the ones that failed.
		attrs = append(attrs, "error", lookupErr.Error())
	}
	s.Log.Info("connection", attrs...)

	if action == ActionRefused {
		_ = tc.Close()
		return
	}
	// The handler owns the connection from here, including closing it, so the
	// slot is released when it returns.
	h.ServeConn(ctx, c)
}

// ServePacket reads datagrams until pc is closed, logging one line each with
// the destination the kernel recorded.
//
// Step 0 has no DNS, so the payload is dropped. What this proves is the other
// half of the mechanism: for UDP there is no accept and no conntrack lookup to
// make, so the pre-NAT destination arrives attached to each datagram, because
// the socket asked for it when it was created in the sandbox's namespace.
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
		orig, lookupErr := OriginalDstFromCmsg(oob[:oobn])
		verdict := Classify(bound, orig, lookupErr)

		action, reason := ActionAccepted, verdict.Reason
		if !verdict.Steered() {
			action = ActionRefused
		}
		attrs := []any{
			"session", s.ID,
			"conn", s.seq.Add(1),
			"listener", bound.String(),
			"peer", peer.String(),
			"dst", orig.String(),
			"bytes", n,
			"decision", string(verdict.Decision),
			"action", action,
		}
		if reason != "" {
			attrs = append(attrs, "reason", reason)
		}
		if lookupErr != nil {
			attrs = append(attrs, "error", lookupErr.Error())
		}
		s.Log.Info("datagram", attrs...)

		if action == ActionAccepted && h != nil {
			h.ServePacket(ctx, uc, peer, orig, buf[:n])
		}
	}
}

// PacketHandler is given every datagram the kernel steered.
type PacketHandler interface {
	ServePacket(ctx context.Context, uc *net.UDPConn, peer, orig netip.AddrPort, payload []byte)
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
