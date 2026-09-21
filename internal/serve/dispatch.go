// Package serve is `frisket serve`: the daemon that holds every session's
// listeners from the host, and decides what happens to each connection the
// kernel steered to them.
package serve

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/steer"
)

// Handlers are what a policy gives one session. Each owns what it is handed,
// including closing it and writing its one line.
type Handlers struct {
	// Egress gets every steered connection whose destination is neither DNS
	// nor frisket's service address.
	Egress steer.Handler
	// Intercept gets every steered connection to the service address:
	// frisket's own services, and the hosts frisket's DNS resolved to it
	// because it adds their credentials.
	Intercept steer.Handler
	// DNS gets every steered datagram, and every TCP connection to port 53.
	DNS DNSHandler
	// Authority is the session's CA as the policy serialises it: kept in the
	// session's record, and given back to Handlers when the session is
	// restored, so a restored session keeps the CA its sandbox trusts. It is
	// the key, so it goes nowhere else.
	Authority []byte
	// CACert is that CA's certificate, PEM: what root puts in the sandbox.
	CACert []byte
}

// DNSHandler answers DNS over both transports.
type DNSHandler interface {
	steer.Handler
	steer.PacketHandler
}

// Policy builds a session's handlers when the session is created. Everything
// a handler needs to know about its session -- the policy's parameters, the
// service address, the session's name for its log lines -- is in s, fixed by
// root at creation and never asserted by the client (PLAN.md decision 8).
//
// authority is nil for a new session, and the policy makes it a CA; for a
// session restored across a restart it is the Authority an earlier call
// returned, and the policy uses that CA again.
type Policy interface {
	Handlers(s control.Session, authority []byte, log *slog.Logger) (Handlers, error)
}

// Policies opens the policy a session names by its path. The session holds
// what Open returns until it ends, and then calls release, once: a source
// that shares one built policy between sessions knows from that when the last
// of them is gone.
type Policies interface {
	Open(path string) (p Policy, release func(), err error)
}

// PolicyMap is a fixed set of policies by path, never released.
type PolicyMap map[string]Policy

func (m PolicyMap) Open(path string) (Policy, func(), error) {
	p, ok := m[path]
	if !ok {
		return nil, nil, fmt.Errorf("no policy at %s", path)
	}
	return p, func() {}, nil
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(s control.Session, authority []byte, log *slog.Logger) (Handlers, error)

func (f PolicyFunc) Handlers(s control.Session, authority []byte, log *slog.Logger) (Handlers, error) {
	return f(s, authority, log)
}

// Dispatch is the one routing rule, and it routes by DESTINATION alone -- the
// address the client dialled, which TPROXY left on the packet and the kernel
// put on the accepted socket, and which the workload cannot forge. Nothing
// here reads a byte of the connection: routing by the first bytes would be
// protocol sniffing, rejected in PLAN.md as dishonest, and a workload chooses
// its first bytes.
//
//   - port 53, any address            -> DNS
//   - the session's service address   -> Intercept
//   - anything else                   -> Egress
//   - every datagram                  -> DNS
//
// DNS first, as it is first in the ruleset: TCP DNS to the service address is
// still DNS, and so is TCP DNS to 127.0.0.1, which reaches the TCP listener
// with its own destination rather than a port nobody holds.
type Dispatch struct {
	Service []netip.Addr
	Handlers
}

// ServeConn routes one steered connection.
func (d Dispatch) ServeConn(ctx context.Context, c *steer.Conn) {
	switch {
	case c.Orig.Port() == DNSPort:
		d.DNS.ServeConn(ctx, c)
	case d.IsService(c.Orig.Addr()):
		d.Intercept.ServeConn(ctx, c)
	default:
		d.Egress.ServeConn(ctx, c)
	}
}

// DNSPort is the port every set steers to frisket's DNS.
const DNSPort = 53

// ServePacket hands one steered datagram to the DNS handler.
func (d Dispatch) ServePacket(ctx context.Context, dg *steer.Datagram) {
	d.DNS.ServePacket(ctx, dg)
}

// IsService compares as addresses, not spellings: ::ffff:192.0.2.2 is the v4
// service address, and a zone names an interface rather than a host. Getting
// it wrong sends frisket's own traffic to egress, which would try to dial the
// service address from the host: a credential route that silently never
// matches.
func (d Dispatch) IsService(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, s := range d.Service {
		if s.Unmap().WithZone("") == a {
			return true
		}
	}
	return false
}
