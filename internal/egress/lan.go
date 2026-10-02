package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
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
	// ReasonHostNetwork: on a network that exists only inside the host --
	// a bridge for its containers or machines, a tunnel, a VPN -- by its
	// routing tables. Another project's containers are there, and a name
	// for any address is to be had from a public wildcard DNS service, so a
	// name is no boundary.
	ReasonHostNetwork = "host network"
	// ReasonHostNetworkUnknown: the host's routes could not be read, or no
	// classifier was given them. Fail closed.
	ReasonHostNetworkUnknown = "host networks unknown"
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

// WithHostNetworks is c, knowing the networks that are the host's own too,
// NewHostNetworks': what else ClassifyLAN keeps a recording session from. A
// classifier without them refuses every LAN address.
func (c *Classifier) WithHostNetworks(n *HostAddrs) *Classifier {
	out := *c
	out.inner = n
	return &out
}

// ClassifyLAN is Classify for a recording session's destination, which may
// be on the local network: an address refused only as private (RFC 1918),
// unique-local or link-local -- written as itself, not inside a v6 spelling
// -- is not refused, unless the host owns it, a router of the host's has it,
// it is on a network only the host is on, or it is a metadata service's. Everything else is Classify's answer:
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
	if c.inner == nil {
		return Refusal{Reason: ReasonHostNetworkUnknown}
	}
	in, err := c.inner.Contains(a)
	switch {
	case err != nil:
		return Refusal{Reason: ReasonHostNetworkUnknown}
	case in:
		return Refusal{Reason: ReasonHostNetwork}
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
// table and by any spelling the kernel gives it -- RTA_GATEWAY, RTA_VIA,
// and each hop of a multipath route -- re-read when older than maxAge
// (DefaultHostMaxAge when <= 0).
func NewGateways(maxAge time.Duration) *HostAddrs {
	if maxAge <= 0 {
		maxAge = DefaultHostMaxAge
	}
	return HostAddrsFrom(func() ([]netip.Prefix, error) {
		g, _, err := readRoutes()
		return g, err
	}, maxAge, nil)
}

// NewHostNetworks reads the networks that are the host's own, live: the
// destination of every unicast route, in any table, that leaves by an
// interface with no device behind it -- a Docker, podman or libvirt bridge,
// a veth, a tunnel, a VPN, a dummy, loopback. Those are networks that exist
// only inside the host, its containers' and its machines', not the local
// network a recording reaches; and an interface frisket cannot tell is
// hardware -- a bond, a VLAN, one that came up since the read -- counts as
// one of them, failing closed. Re-read when older than maxAge
// (DefaultHostMaxAge when <= 0).
func NewHostNetworks(maxAge time.Duration) *HostAddrs {
	if maxAge <= 0 {
		maxAge = DefaultHostMaxAge
	}
	return HostAddrsFrom(func() ([]netip.Prefix, error) {
		_, inner, err := readRoutes()
		return inner, err
	}, maxAge, nil)
}

func readRoutes() (gateways, inner []netip.Prefix, err error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, nil, fmt.Errorf("route dump: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, nil, fmt.Errorf("route dump: %w", err)
	}
	hw, err := hardwareLinks()
	if err != nil {
		return nil, nil, err
	}
	return parseRoutes(msgs, hw)
}

// hardwareLinks is whether each interface, by its index, has a device
// behind it: a NIC, wired, wireless or on USB, as sysfs says. Read before
// the routes, so an interface that comes between the two reads is not one.
func hardwareLinks() (func(index int) bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}
	hw := map[int]bool{}
	for _, i := range ifs {
		_, err := os.Stat("/sys/class/net/" + i.Name + "/device")
		switch {
		case err == nil:
			hw[i.Index] = true
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("interface %s: %w", i.Name, err)
		}
	}
	return func(index int) bool { return hw[index] }, nil
}

// Route attributes syscall does not name.
const (
	rtaVia  = 18 // struct rtvia: a gateway of another family
	rtaNHID = 30 // a nexthop object, by id
	// sizeofRtNexthop is struct rtnexthop: len(2) flags(1) hops(1)
	// ifindex(4), each hop's attributes after it.
	sizeofRtNexthop = 8
)

// parseRoutes keeps every route's gateways, and the destinations of the
// unicast routes that leave by an interface that is not hardware. The rtmsg
// header is read by offset, as parseLocalRoutes reads it.
//
// A route by a nexthop object (RTA_NH_ID) names its gateway only in the
// object, unless the kernel also spells it the old way, which it does by
// default (net.ipv4.nexthop_compat_mode); one that does not fails the read,
// since its router could not be known not to be the address dialled.
func parseRoutes(msgs []syscall.NetlinkMessage, hardware func(index int) bool) (gateways, inner []netip.Prefix, err error) {
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type == syscall.NLMSG_ERROR {
			return nil, nil, fmt.Errorf("route dump: kernel returned an error message")
		}
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		family, dstLen, typ := m.Data[0], int(m.Data[1]), m.Data[7]
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			return nil, nil, fmt.Errorf("route attributes: %w", err)
		}
		var (
			dst   netip.Addr
			oifs  []int
			byObj bool
			gws   []netip.Addr
		)
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_DST:
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					dst = ip
				}
			case syscall.RTA_GATEWAY, rtaVia:
				if ip, ok := gatewayAddr(a.Attr.Type, a.Value); ok {
					gws = append(gws, ip)
				}
			case syscall.RTA_OIF:
				if len(a.Value) == 4 {
					oifs = append(oifs, int(int32(binary.NativeEndian.Uint32(a.Value))))
				}
			case syscall.RTA_MULTIPATH:
				hops, hopGWs, err := parseMultipath(a.Value)
				if err != nil {
					return nil, nil, err
				}
				oifs, gws = append(oifs, hops...), append(gws, hopGWs...)
			case rtaNHID:
				byObj = true
			}
		}
		if byObj && len(oifs) == 0 && len(gws) == 0 {
			return nil, nil, fmt.Errorf("route dump: a route by nexthop object only, whose gateway this cannot read")
		}
		for _, gw := range gws {
			gw = gw.Unmap()
			gateways = append(gateways, netip.PrefixFrom(gw, gw.BitLen()))
		}
		if typ != syscall.RTN_UNICAST {
			continue
		}
		if !dst.IsValid() {
			switch family {
			case syscall.AF_INET:
				dst = netip.IPv4Unspecified()
			case syscall.AF_INET6:
				dst = netip.IPv6Unspecified()
			default:
				continue
			}
		}
		dst = dst.Unmap()
		if dstLen > dst.BitLen() {
			continue
		}
		// A route naming no interface at all is not known to leave by
		// hardware, so it is the host's.
		virtual := len(oifs) == 0
		for _, o := range oifs {
			if !hardware(o) {
				virtual = true
			}
		}
		if virtual {
			inner = append(inner, netip.PrefixFrom(dst, dstLen).Masked())
		}
	}
	return gateways, inner, nil
}

// gatewayAddr is a gateway attribute's address: RTA_GATEWAY's as it is,
// RTA_VIA's after its family.
func gatewayAddr(typ uint16, v []byte) (netip.Addr, bool) {
	if typ == rtaVia {
		if len(v) < 2 {
			return netip.Addr{}, false
		}
		v = v[2:]
	}
	return netip.AddrFromSlice(v)
}

// parseMultipath reads RTA_MULTIPATH's hops: each one's interface, and its
// gateway where it has one.
func parseMultipath(b []byte) (oifs []int, gws []netip.Addr, err error) {
	for len(b) >= sizeofRtNexthop {
		n := int(binary.NativeEndian.Uint16(b[0:2]))
		if n < sizeofRtNexthop || n > len(b) {
			return nil, nil, fmt.Errorf("route dump: a multipath hop of %d bytes", n)
		}
		oifs = append(oifs, int(int32(binary.NativeEndian.Uint32(b[4:8]))))
		attrs, err := parseAttrs(b[sizeofRtNexthop:n])
		if err != nil {
			return nil, nil, err
		}
		for _, a := range attrs {
			if a.Attr.Type == syscall.RTA_GATEWAY || a.Attr.Type == rtaVia {
				if ip, ok := gatewayAddr(a.Attr.Type, a.Value); ok {
					gws = append(gws, ip)
				}
			}
		}
		b = b[min(rtaAlign(n), len(b)):]
	}
	return oifs, gws, nil
}

// parseAttrs reads a run of rtattrs, as syscall does for a message's own.
func parseAttrs(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var out []syscall.NetlinkRouteAttr
	for len(b) >= syscall.SizeofRtAttr {
		n := int(binary.NativeEndian.Uint16(b[0:2]))
		if n < syscall.SizeofRtAttr || n > len(b) {
			return nil, fmt.Errorf("route dump: an attribute of %d bytes", n)
		}
		out = append(out, syscall.NetlinkRouteAttr{
			Attr:  syscall.RtAttr{Len: uint16(n), Type: binary.NativeEndian.Uint16(b[2:4])},
			Value: b[syscall.SizeofRtAttr:n],
		})
		b = b[min(rtaAlign(n), len(b)):]
	}
	return out, nil
}

func rtaAlign(n int) int { return (n + syscall.RTA_ALIGNTO - 1) &^ (syscall.RTA_ALIGNTO - 1) }
