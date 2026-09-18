// Package steer reads what the kernel says about a connection or a datagram
// that arrived on a session's listener: where the client was really going, and
// whether the ruleset put it there at all.
//
// Nothing here trusts the workload. Steering is TPROXY: the kernel hands the
// packet to frisket's transparent socket WITHOUT rewriting it, so for TCP the
// destination is the accepted socket's own local address, and for UDP it comes
// with each datagram as IP_ORIGDSTADDR, beside the firewall mark the ruleset
// put on it. A sandbox chooses where to connect; it cannot choose what frisket
// is told about it, and it cannot set a mark.
package steer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

var errShortSockaddr = errors.New("sockaddr truncated")

// parseSockaddr decodes a `struct sockaddr_in` or `sockaddr_in6` exactly as the
// kernel laid it out. Kept separate from the control-message walk so it can be
// tested and fuzzed without a socket, and because the layout is the part that
// is easy to get subtly wrong.
//
//	sockaddr_in  : family u16 (host order) | port u16 (network order) | addr[4]
//	sockaddr_in6 : family u16 (host order) | port u16 (network order) |
//	               flowinfo u32 | addr[16] | scope_id u32
//
// The family is native-endian because it is a C `unsigned short` the kernel
// wrote; the port is big-endian because it is `in_port_t`, already in network
// order. Reading the family little-endian happens to work on amd64 and is wrong
// everywhere else, so it is spelled NativeEndian here.
func parseSockaddr(b []byte) (netip.AddrPort, error) {
	if len(b) < 4 {
		return netip.AddrPort{}, fmt.Errorf("%w: %d bytes", errShortSockaddr, len(b))
	}
	family := binary.NativeEndian.Uint16(b[0:2])
	port := binary.BigEndian.Uint16(b[2:4])
	switch family {
	case unix.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, fmt.Errorf("%w: AF_INET in %d bytes", errShortSockaddr, len(b))
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port), nil
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, fmt.Errorf("%w: AF_INET6 in %d bytes", errShortSockaddr, len(b))
		}
		// Unmap, so ::ffff:10.0.0.1 and 10.0.0.1 are one address everywhere
		// downstream -- in the log, in the classifier, and in the egress
		// policy, where the two spellings of one address being two things is
		// how an allowlist gets walked past.
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("sockaddr family %d is neither AF_INET nor AF_INET6", family)
	}
}

// Received is what the kernel attached to one datagram.
type Received struct {
	// Orig is where the workload sent it. TPROXY leaves the packet's
	// destination alone, so this is the address the client dialled --
	// 8.8.8.8:53, or 127.0.0.1:53 for glibc's default resolver.
	Orig netip.AddrPort
	// Mark is the firewall mark the packet carried, and Marked says the
	// kernel reported one at all. SO_RCVMARK reports every datagram's mark,
	// zero included, so an unmarked datagram still has Marked set.
	Mark   uint32
	Marked bool
}

// ParseControl reads the original destination (IP_ORIGDSTADDR or
// IPV6_ORIGDSTADDR) and the mark (SO_MARK, delivered because the helper set
// SO_RCVMARK) out of one datagram's control messages. Anything else is
// ignored. The kernel writes these, not the workload, so the property that
// matters is that a malformed buffer is an error and never a panic.
func ParseControl(oob []byte) (Received, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return Received{}, fmt.Errorf("control message: %w", err)
	}
	var r Received
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR,
			m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR:
			if r.Orig, err = parseSockaddr(m.Data); err != nil {
				return Received{}, err
			}
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_MARK:
			if len(m.Data) < 4 {
				return Received{}, fmt.Errorf("SO_MARK in %d bytes", len(m.Data))
			}
			r.Mark, r.Marked = binary.NativeEndian.Uint32(m.Data), true
		}
	}
	return r, nil
}

// pktinfo is the control message that makes a reply leave FROM src: the
// address the client sent its datagram to. The socket is transparent, so the
// kernel lets it send from an address that is not its own; without this the
// reply would come from 127.0.0.1:53, and a connected client -- which accepts
// only what comes from the exact address it dialled -- would drop it.
//
// PKTINFO sets the source ADDRESS and not the port. The port is the socket's,
// which is why a UDP listener is bound on the original port (53) and not on a
// high one: measured, a listener on :15353 serving a query to :5353 logged a
// successful send and the client timed out.
func pktinfo(src netip.Addr) []byte {
	src = src.Unmap()
	if src.Is4() {
		return unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: src.As4()})
	}
	return unix.PktInfo6(&unix.Inet6Pktinfo{Addr: src.As16()})
}

// LocalDst is a steered connection's destination: the accepted socket's own
// local address. TPROXY assigns the packet to frisket's listener without
// rewriting it, so the socket the kernel creates for the connection is bound to
// the address and port the client dialled -- getsockname is the original
// destination, read from a socket the workload never touches. There is no
// conntrack entry to look up, and nothing to cache that could go stale.
func LocalDst(c *net.TCPConn) netip.AddrPort {
	ap, err := boundAddrPort(c.LocalAddr())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}
