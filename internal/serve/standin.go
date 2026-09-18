package serve

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/steer"
)

// StandInPolicy is the name the stand-in answers to.
const StandInPolicy = "standin"

// StandIn is the policy for the integration step, and nothing after it: the
// real egress, interception and DNS are built beside this and swapped in by
// name. Until then:
//
//   - egress is an UNRESTRICTED splice to the original destination, logged --
//     which proves the steering end to end, and is exactly what the egress
//     policy exists to replace;
//   - interception refuses, and says so;
//   - DNS refuses, with a REFUSED answer so a client fails at once instead of
//     timing out, and says so.
//
// It is named, not default: a session gets it only by asking for "standin",
// and the first line of every such session says what that means.
func StandIn() Policy {
	return PolicyFunc(func(s control.Session, log *slog.Logger) (Handlers, error) {
		log.Warn("stand-in policy: egress is an unrestricted splice; interception and DNS refuse",
			"session", s.Name, "policy", s.Policy)
		return Handlers{
			Egress:    &splice{log: log, dialer: net.Dialer{Timeout: 10 * time.Second}},
			Intercept: refuse{log: log, what: "intercept", why: "interception is not built yet"},
			DNS:       refuseDNS{log: log, session: s.Name},
		}, nil
	})
}

// splice dials the original destination from the host and copies both ways.
type splice struct {
	log    *slog.Logger
	dialer net.Dialer
}

func (s *splice) ServeConn(ctx context.Context, c *steer.Conn) {
	defer c.Close()
	start := time.Now()
	up, err := s.dialer.DialContext(ctx, "tcp", c.Orig.String())
	if err != nil {
		s.log.Info("egress", "session", c.Session, "conn", c.ID, "dst", c.Orig.String(),
			"action", "failed", "error", err.Error())
		return
	}
	defer up.Close()

	// Cancelling the session closes both ends, so a session's teardown does
	// not wait on a peer that never speaks again.
	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
		_ = up.Close()
	})
	defer stop()

	out, in := pipe(up.(*net.TCPConn), c.TCPConn)
	s.log.Info("egress", "session", c.Session, "conn", c.ID, "dst", c.Orig.String(),
		"action", "spliced", "bytes_out", out, "bytes_in", in,
		"duration_ms", time.Since(start).Milliseconds())
}

// pipe copies both directions until BOTH are done, half-closing each side as
// its source finishes. Closing the whole connection when the first direction
// ends truncates the other -- the bug ottergate has in both of its proxy paths.
func pipe(up, down *net.TCPConn) (out, in int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		out, _ = io.Copy(up, down)
		_ = up.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		in, _ = io.Copy(down, up)
		_ = down.CloseWrite()
	}()
	wg.Wait()
	return out, in
}

// refuse logs and closes.
type refuse struct {
	log  *slog.Logger
	what string
	why  string
}

func (r refuse) ServeConn(_ context.Context, c *steer.Conn) {
	r.log.Info(r.what, "session", c.Session, "conn", c.ID, "dst", c.Orig.String(),
		"action", "refused", "reason", r.why)
	_ = c.Close()
}

// refuseDNS answers every query REFUSED, over UDP and TCP, reading nothing of
// it but the two bytes of its id and the opcode bits it copies back. It is not
// a DNS parser and does not pretend to be one; the real one is dnsmessage, in
// its own package.
type refuseDNS struct {
	log     *slog.Logger
	session string
}

func refused(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	var resp [12]byte
	copy(resp[0:2], query[0:2]) // id
	// QR, the query's opcode and RD; RCODE 5, REFUSED. Every count zero.
	resp[2] = 0x80 | query[2]&0x79
	resp[3] = 0x05
	return resp[:]
}

func (r refuseDNS) ServePacket(_ context.Context, d *steer.Datagram) {
	attrs := []any{"session", r.session, "transport", "udp", "peer", d.Peer.String(), "dst", d.Orig.String(),
		"action", "refused", "reason", "DNS is not built yet"}
	if resp := refused(d.Payload); resp != nil {
		if err := d.Reply(resp); err != nil && !errors.Is(err, net.ErrClosed) {
			attrs = append(attrs, "error", err.Error())
		}
	}
	r.log.Info("dns", attrs...)
}

// ServeConn answers each RFC 7766 frame on the connection REFUSED, and logs
// the connection once.
func (r refuseDNS) ServeConn(_ context.Context, c *steer.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	n := 0
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			break
		}
		q := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, q); err != nil {
			break
		}
		resp := refused(q)
		if resp == nil {
			break
		}
		if _, err := c.Write(append([]byte{0, byte(len(resp))}, resp...)); err != nil {
			break
		}
		n++
	}
	r.log.Info("dns", "session", r.session, "conn", c.ID, "transport", "tcp", "peer", c.Peer.String(),
		"dst", c.Orig.String(), "queries", n, "action", "refused", "reason", "DNS is not built yet")
}
