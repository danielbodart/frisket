// Package serve is `frisket serve`: the daemon that holds every session's
// listeners from the host, and decides what happens to each connection the
// kernel steered to them.
package serve

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/steer"
)

// Handlers are what a policy gives one session. Each owns what it is handed,
// including closing it.
type Handlers struct {
	// Egress gets every steered connection whose original destination is
	// anywhere but frisket's service address.
	Egress steer.Handler
	// Intercept gets every steered connection whose original destination IS
	// the service address: frisket's own services, and the hosts frisket's
	// DNS resolved to it because it adds their credentials.
	Intercept steer.Handler
	// DNS gets every steered datagram. Nil logs and drops.
	DNS steer.PacketHandler
}

// Policy builds a session's handlers when the session is created. Everything
// a handler needs to know about its session -- the policy's parameters, the
// service address, the session's name for its log lines -- is in s, fixed by
// root at creation and never asserted by the client (PLAN.md decision 8).
type Policy interface {
	Handlers(s control.Session, log *slog.Logger) (Handlers, error)
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(s control.Session, log *slog.Logger) (Handlers, error)

func (f PolicyFunc) Handlers(s control.Session, log *slog.Logger) (Handlers, error) { return f(s, log) }

// Dispatch is the one routing rule, and it routes by ORIGINAL DESTINATION
// alone -- the address the kernel recorded when it rewrote the packet, which
// the workload cannot forge. Nothing here reads a byte of the connection:
// routing by the first bytes would be protocol sniffing, rejected in PLAN.md as
// dishonest, and a workload chooses its first bytes.
//
//   - the session's service address -> Intercept
//   - anything else                   -> Egress
//   - every datagram (DNS)            -> DNS
type Dispatch struct {
	Service []netip.Addr
	Handlers
}

// ServeConn routes one steered connection.
func (d Dispatch) ServeConn(ctx context.Context, c *steer.Conn) {
	if d.IsService(c.Orig.Addr()) {
		d.Intercept.ServeConn(ctx, c)
		return
	}
	d.Egress.ServeConn(ctx, c)
}

// ServePacket hands one steered datagram to the DNS handler.
func (d Dispatch) ServePacket(ctx context.Context, uc *net.UDPConn, peer, orig netip.AddrPort, payload []byte) {
	if d.DNS != nil {
		d.DNS.ServePacket(ctx, uc, peer, orig, payload)
	}
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
