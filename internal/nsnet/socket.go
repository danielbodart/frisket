package nsnet

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// IPV6_RECVORIGDSTADDR is missing from x/sys/unix (it has the v4 spelling,
// unix.IP_RECVORIGDSTADDR, but not this one). From linux/in6.h.
const ipv6RecvOrigDstAddr = 74

// createSocket makes one listener on the CURRENT THREAD, with raw syscalls, so
// that whatever namespace the thread is in is the namespace the socket belongs
// to. Going through net.Listen would work too, but it hides the socket options
// below, and one of them is a security property.
func createSocket(s Spec) (fd int, err error) {
	if err := s.Validate(); err != nil {
		return -1, err
	}
	domain := unix.AF_INET
	if s.V6() {
		domain = unix.AF_INET6
	}
	typ := unix.SOCK_DGRAM
	if s.Stream() {
		typ = unix.SOCK_STREAM
	}
	fd, err = unix.Socket(domain, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("socket %s: %w", s, err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()

	// SO_REUSEADDR AND NOTHING ELSE. SO_REUSEPORT would let the workload -- the
	// first process in the namespace, running before we get here -- bind the
	// same address and take a share of its own steered traffic, silently. With
	// SO_REUSEADDR alone a workload that got there first makes the bind below
	// fail, which aborts the session loudly, which is the behaviour we want.
	// There is no code path in frisket that sets SO_REUSEPORT; see
	// TestSocketOptionsRefuseReuseport.
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return -1, fmt.Errorf("SO_REUSEADDR %s: %w", s, err)
	}

	if domain == unix.AF_INET6 {
		// Without this a v6 socket also answers v4, and then one listener
		// carries both families and the log cannot say which the client used.
		// The specs name a family each; keep the sockets that way.
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return -1, fmt.Errorf("IPV6_V6ONLY %s: %w", s, err)
		}
	}

	if typ == unix.SOCK_DGRAM {
		// A redirected datagram arrives with its destination already rewritten,
		// so the pre-NAT address comes back as a control message or not at all.
		// TCP has SO_ORIGINAL_DST for the same job; see the steer package.
		level, opt := unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR
		if domain == unix.AF_INET6 {
			level, opt = unix.IPPROTO_IPV6, ipv6RecvOrigDstAddr
		}
		if err = unix.SetsockoptInt(fd, level, opt, 1); err != nil {
			return -1, fmt.Errorf("RECVORIGDSTADDR %s: %w", s, err)
		}
	}

	sa, err := sockaddr(s)
	if err != nil {
		return -1, err
	}
	if err = unix.Bind(fd, sa); err != nil {
		return -1, fmt.Errorf("bind %s: %w", s, err)
	}
	if typ == unix.SOCK_STREAM {
		if err = unix.Listen(fd, unix.SOMAXCONN); err != nil {
			return -1, fmt.Errorf("listen %s: %w", s, err)
		}
	}
	return fd, nil
}

func sockaddr(s Spec) (unix.Sockaddr, error) {
	a := s.Addr.Addr()
	if s.V6() {
		sa := &unix.SockaddrInet6{Port: int(s.Addr.Port())}
		sa.Addr = a.As16()
		return sa, nil
	}
	sa := &unix.SockaddrInet4{Port: int(s.Addr.Port())}
	sa.Addr = a.As4()
	return sa, nil
}

// DefaultLoopbackTimeout is how long waitLoopback will keep trying. Measured
// the interface comes up in well under a millisecond; this is generous because
// the cost of waiting is a few milliseconds at session creation and the cost of
// not waiting is a session that fails for a reason nobody can reproduce.
const DefaultLoopbackTimeout = 2 * time.Second

// waitLoopback blocks until `lo` is up in the CURRENT namespace.
//
// A namespace made with --private-network has lo present but not necessarily up
// yet, and ::1 does not exist until it is: binding it before then fails with
// EADDRNOTAVAIL, which reads like a configuration error and is really a race.
// 127.0.0.1 has the same problem. So wait and retry, rather than assume and
// blame the caller.
//
// net.Interfaces reads netlink on the calling thread, so this must run on the
// thread that did the setns -- which it does, because the helper locks it.
func waitLoopback(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		up, err := loopbackUp()
		if err == nil && up {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			if last != nil {
				return fmt.Errorf("waiting for lo to come up: %w", last)
			}
			return fmt.Errorf("lo is still down after %s; the namespace is not ready for a loopback listener", timeout)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func loopbackUp() (bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Flags&net.FlagUp != 0, nil
		}
	}
	return false, errors.New("no loopback interface in this namespace")
}
