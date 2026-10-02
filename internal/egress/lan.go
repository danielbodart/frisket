package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// What a recording session's destination on the local network is refused
// for, beyond the structural table's reasons.
const (
	// ReasonGateway: a router of the host's, by its routing tables. Its
	// management address is never a recording's to reach.
	ReasonGateway = "gateway"
	// ReasonGatewayUnknown: the host's routes could not be read, so there is
	// no way to know this address is not a router. Fail closed.
	ReasonGatewayUnknown = "gateways unknown"
	// ReasonMetadata: a cloud's instance metadata service, which answers
	// with the machine's own credentials.
	ReasonMetadata = "metadata service"
)

// metadata are the instance metadata services' addresses: link-local, so
// on the local network by the table, and the one thing there that hands out
// a credential for the asking.
var metadata = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("169.254.170.2/32"), // ECS task metadata
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// WithGateways is c, knowing the host's routers too: what ClassifyLAN keeps
// a recording session from. A classifier without them refuses every LAN
// address.
func (c *Classifier) WithGateways(g *HostAddrs) *Classifier {
	out := *c
	out.gateways = g
	return &out
}

// ClassifyLAN is Classify for a recording session's destination, which may
// be on the local network: an address refused only as private (RFC 1918),
// unique-local or link-local -- written as itself, not inside a v6 spelling
// -- is not refused, unless the host owns it, a router of the host's has it,
// or it is a metadata service's. Everything else is Classify's answer:
// loopback, CGNAT, multicast, the host's own addresses and the rest stay
// refused here as everywhere.
func (c *Classifier) ClassifyLAN(a netip.Addr) Refusal {
	r := c.Classify(a)
	if !lan(r) {
		return r
	}
	a = a.WithZone("").Unmap()
	for _, p := range metadata {
		if p.Contains(a) {
			return Refusal{Reason: ReasonMetadata}
		}
	}
	// The table is consulted before the host's addresses, so an address in
	// it that the host also owns was refused as private, not as the host's:
	// asked again here.
	owned, err := c.host.Contains(a)
	if err != nil {
		return Refusal{Reason: ReasonHostUnknown}
	}
	if owned {
		return Refusal{Reason: ReasonHostOwned}
	}
	if c.gateways == nil {
		return Refusal{Reason: ReasonGatewayUnknown}
	}
	gw, err := c.gateways.Contains(a)
	switch {
	case err != nil:
		return Refusal{Reason: ReasonGatewayUnknown}
	case gw:
		return Refusal{Reason: ReasonGateway}
	}
	return Refusal{}
}

// lan is whether r refuses an address only for being on the local network.
func lan(r Refusal) bool {
	if r.Spelling != "" {
		return false
	}
	switch r.Reason {
	case ReasonPrivate, ReasonULA, ReasonLinkLocal:
		return true
	}
	return false
}

// controlLAN is Control for a recording session's admitted destination on
// the local network: ClassifyLAN, on the address actually being dialled.
func (d *Dialer) controlLAN(network, address string, _ syscall.RawConn) error {
	if d == nil || d.Classifier == nil {
		return &RefusedError{network, address, Refusal{Reason: ReasonUnconfigured}}
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &RefusedError{network, address, Refusal{Reason: ReasonUnparseable}}
	}
	if r := d.Classifier.ClassifyLAN(ap.Addr()); r.Refused() {
		return &RefusedError{network, address, r}
	}
	return nil
}

// DialLAN is DialTCP for a recording session's destination on the local
// network, checked by ClassifyLAN at the dial as DialTCP checks by Classify.
func (d *Dialer) DialLAN(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	t := d.Timeout
	if t <= 0 {
		t = DefaultDialTimeout
	}
	c, err := (&net.Dialer{Timeout: t, Control: d.controlLAN}).DialContext(ctx, "tcp", dst.String())
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

// NewGateways reads the host's routers live: every route's gateway, in any
// table, re-read when older than maxAge (DefaultHostMaxAge when <= 0).
func NewGateways(maxAge time.Duration) *HostAddrs {
	if maxAge <= 0 {
		maxAge = DefaultHostMaxAge
	}
	return HostAddrsFrom(readGateways, maxAge, nil)
}

func readGateways() ([]netip.Prefix, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("route dump: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("route dump: %w", err)
	}
	return parseGateways(msgs)
}

// parseGateways keeps each route's RTA_GATEWAY, as a single address.
func parseGateways(msgs []syscall.NetlinkMessage) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type == syscall.NLMSG_ERROR {
			return nil, fmt.Errorf("route dump: kernel returned an error message")
		}
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			return nil, fmt.Errorf("route attributes: %w", err)
		}
		for _, a := range attrs {
			if a.Attr.Type != syscall.RTA_GATEWAY {
				continue
			}
			if ip, ok := netip.AddrFromSlice(a.Value); ok {
				ip = ip.Unmap()
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out, nil
}
