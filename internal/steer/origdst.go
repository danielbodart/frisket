// Package steer reads what the kernel says about a connection that arrived on
// a session's listener: where the client was really going, and whether the
// kernel put it here at all.
//
// Nothing here trusts the workload. The original destination comes out of the
// conntrack entry the kernel made when it rewrote the packet, so a sandbox can
// choose where to connect but cannot choose what frisket is told about it.
package steer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

const (
	// SO_ORIGINAL_DST, from linux/netfilter_ipv4.h, at level SOL_IP.
	soOriginalDst = 80
	// IP6T_SO_ORIGINAL_DST, from linux/netfilter_ipv6/ip6_tables.h, at level
	// SOL_IPV6. The same number as the v4 option and a different option: the
	// level is what distinguishes them.
	ip6tSoOriginalDst = 80
	// IPV6_RECVORIGDSTADDR, from linux/in6.h. x/sys/unix has the v4 spelling
	// (unix.IP_RECVORIGDSTADDR) and not this one.
	ipv6RecvOrigDstAddr = 74
)

var errShortSockaddr = errors.New("sockaddr truncated")

// parseSockaddr decodes a `struct sockaddr_in` or `sockaddr_in6` exactly as the
// kernel laid it out. Kept separate from the getsockopt call so it can be
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
		// downstream -- in the log, in the classifier, and eventually in the
		// egress policy, where the two spellings of one address being two
		// things is how an allowlist gets walked past.
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("sockaddr family %d is neither AF_INET nor AF_INET6", family)
	}
}

// OriginalDst returns the address the client dialled, before the kernel's
// redirect rewrote it to this listener.
//
// READ IT ONCE, AT ACCEPT, AND CACHE IT. The answer comes from the conntrack
// entry, and flushing conntrack mid-connection makes the lookup fail or lie.
// Session.Serve does exactly that and stores the result on the Conn; nothing
// should call this again for a connection it has already seen.
//
// An error here is not a failure to be retried: the ordinary cause is that
// there was no redirect, i.e. the workload connected to the listener directly.
// Classify turns that into a refusal.
func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	// The family comes from the socket we are holding, not from the answer:
	// each listener is bound to one family and IPV6_V6ONLY keeps it that way,
	// so there is no case where a v4 connection arrives on the v6 listener.
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("local address is a %T, not a TCP address", c.LocalAddr())
	}
	v6 := local.IP.To4() == nil

	var out netip.AddrPort
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		out, opErr = originalDst(int(fd), v6)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return out, opErr
}

func originalDst(fd int, v6 bool) (netip.AddrPort, error) {
	if !v6 {
		// getsockopt writes a sockaddr_in, 16 bytes. IPv6Mreq is 20, which is
		// the smallest fixed-size buffer x/sys/unix will hand back, and its
		// first field is a bare [16]byte -- so Multiaddr IS the sockaddr.
		mreq, err := unix.GetsockoptIPv6Mreq(fd, unix.SOL_IP, soOriginalDst)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("getsockopt SOL_IP/SO_ORIGINAL_DST: %w", err)
		}
		return parseSockaddr(mreq.Multiaddr[:])
	}
	// AND NOT GetsockoptIPv6Mreq HERE. A sockaddr_in6 is 28 bytes and an
	// IPv6Mreq is 20, so the kernel's copy is truncated and the address comes
	// back with its last eight bytes missing -- silently, because getsockopt
	// reports the length it actually wrote and nothing checks it. IPv6MTUInfo
	// is 32 bytes and begins with a RawSockaddrInet6, which is the right shape
	// by accident and the only one in x/sys/unix that is. Measured.
	info, err := unix.GetsockoptIPv6MTUInfo(fd, unix.SOL_IPV6, ip6tSoOriginalDst)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("getsockopt SOL_IPV6/IP6T_SO_ORIGINAL_DST: %w", err)
	}
	return parseSockaddr(rawSockaddrInet6Bytes(info.Addr))
}

// rawSockaddrInet6Bytes puts the struct back the way the kernel wrote it, so
// one parser serves both families. Every field is written NativeEndian because
// that is how the kernel filled the struct; parseSockaddr then reads the port
// big-endian, which is where the network order is undone.
func rawSockaddrInet6Bytes(sa unix.RawSockaddrInet6) []byte {
	var b [28]byte
	binary.NativeEndian.PutUint16(b[0:2], sa.Family)
	binary.NativeEndian.PutUint16(b[2:4], sa.Port)
	binary.NativeEndian.PutUint32(b[4:8], sa.Flowinfo)
	copy(b[8:24], sa.Addr[:])
	binary.NativeEndian.PutUint32(b[24:28], sa.Scope_id)
	return b[:]
}

// OriginalDstFromCmsg pulls the pre-NAT destination of a redirected datagram
// out of the control messages that came with it. UDP has no conntrack lookup to
// make at accept time -- there is no accept -- so the kernel attaches the
// address to each datagram, which is what IP_RECVORIGDSTADDR asked for when the
// socket was created.
func OriginalDstFromCmsg(oob []byte) (netip.AddrPort, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("control message: %w", err)
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_RECVORIGDSTADDR,
			m.Header.Level == unix.SOL_IPV6 && m.Header.Type == ipv6RecvOrigDstAddr:
			return parseSockaddr(m.Data)
		}
	}
	return netip.AddrPort{}, errors.New("no original destination in the control messages")
}
