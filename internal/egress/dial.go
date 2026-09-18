package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// DefaultDialTimeout bounds connection establishment only. It is not an I/O
// deadline -- those are idle deadlines, in Splice.
const DefaultDialTimeout = 10 * time.Second

// ReasonUnparseable: Control was handed an address it could not parse. Go
// always hands it "ip:port", so this should never happen, and if it does the
// answer is no.
const ReasonUnparseable = "unparseable dial address"

// ReasonUnconfigured: a Dialer with no classifier. It refuses rather than
// dialling unchecked.
const ReasonUnconfigured = "no classifier"

// RefusedError is what a dial returns when Control refused the address the
// kernel was about to connect to. errors.As finds it through the *net.OpError
// the dialer wraps it in.
type RefusedError struct {
	Network string
	Address string
	Refusal Refusal
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("egress refused %s %s: %s", e.Network, e.Address, e.Refusal)
}

// Dialer makes frisket's upstream connections, with the structural check in
// net.Dialer.Control.
//
// CONTROL, BECAUSE IT SEES THE ADDRESS ACTUALLY BEING DIALLED. It runs after
// name resolution, on each address the dialer tries, immediately before
// connect(2), on the socket that will connect. A check anywhere earlier checks
// an address that may not be the one used: a name that resolved to 93.184.216.34
// for the policy can resolve to 127.0.0.1 for the dial (DNS rebinding), and
// only the last look is the one that counts.
type Dialer struct {
	Classifier *Classifier
	// Resolver is used only when dialling by name, and is injectable so a test
	// can make an allowed name resolve to a private address.
	Resolver *net.Resolver
	// Timeout bounds the connect; zero means DefaultDialTimeout.
	Timeout time.Duration
}

// Control is the net.Dialer hook. Exported so the table test can drive it
// directly, with no socket, and so any other dialer frisket builds -- the
// interception path's upstream, for one -- can use the same check.
func (d *Dialer) Control(network, address string, _ syscall.RawConn) error {
	if d == nil || d.Classifier == nil {
		// Fail closed: a Dialer nobody configured refuses, it does not dial.
		return &RefusedError{network, address, Refusal{Reason: ReasonUnconfigured}}
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &RefusedError{network, address, Refusal{Reason: ReasonUnparseable}}
	}
	if r := d.Classifier.Classify(ap.Addr()); r.Refused() {
		return &RefusedError{network, address, r}
	}
	return nil
}

func (d *Dialer) dialer() *net.Dialer {
	t := d.Timeout
	if t <= 0 {
		t = DefaultDialTimeout
	}
	return &net.Dialer{Timeout: t, Resolver: d.Resolver, Control: d.Control}
}

// DialContext dials through the structural check. It accepts a name, for
// callers that have one; egress itself only ever dials the kernel's original
// destination, a literal address.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer().DialContext(ctx, network, address)
}

// DialTCP dials a literal destination and returns the raw *net.TCPConn, which
// is what lets io.Copy use splice(2) on Linux: wrap it in anything and the
// bytes go through userspace.
func (d *Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	c, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("dial %s produced a %T, not a TCP connection", dst, c)
	}
	return tc, nil
}

// AsRefused unwraps a dial error to the refusal inside it, if any.
func AsRefused(err error) (*RefusedError, bool) {
	var re *RefusedError
	ok := errors.As(err, &re)
	return re, ok
}
