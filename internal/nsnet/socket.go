package nsnet

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// createSocket makes one listener on the CURRENT THREAD, with raw syscalls, so
// that whatever namespace the thread is in is the namespace the socket belongs
// to. Going through net.Listen would work too, but it hides the socket options
// below, and several of them are security properties.
//
// It runs as root, in the helper, and some of what it sets needs to be: the
// daemon that holds the socket afterwards is not root and could not set
// IP_TRANSPARENT itself (measured: EPERM for a uid with no capabilities). The
// flag belongs to the socket, so it travels across SCM_RIGHTS with it.
func createSocket(s Spec) (fd int, err error) {
	if err := s.Validate(); err != nil {
		return -1, err
	}
	domain, level := unix.AF_INET, unix.SOL_IP
	if s.V6() {
		domain, level = unix.AF_INET6, unix.SOL_IPV6
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
	set := func(name string, level, opt int) {
		if err == nil {
			if e := unix.SetsockoptInt(fd, level, opt, 1); e != nil {
				err = fmt.Errorf("%s %s: %w", name, s, e)
			}
		}
	}

	// NEVER SO_REUSEPORT. It would let the workload -- the first process in
	// the namespace, running before we get here -- bind the same address and
	// take a share of its own steered traffic, silently. There is no code
	// path in frisket that sets it; see TestSocketsCarryTheirOptions.
	//
	// SO_REUSEADDR on TCP only. On TCP it lets a listener rebind past
	// TIME_WAIT and nothing more: a workload that already holds the port still
	// makes the bind below fail, which aborts the session loudly. On UDP it is
	// something else entirely -- two sockets that both set it may bind the
	// same address and port -- so it is never set there.
	if typ == unix.SOCK_STREAM {
		set("SO_REUSEADDR", unix.SOL_SOCKET, unix.SO_REUSEADDR)
	}

	if domain == unix.AF_INET6 {
		// Without this a v6 socket also answers v4, and then one listener
		// carries both families and the log cannot say which the client used.
		// The specs name a family each; keep the sockets that way.
		set("IPV6_V6ONLY", unix.SOL_IPV6, unix.IPV6_V6ONLY)
	}

	// TRANSPARENT, on every listener: TPROXY hands a packet only to a socket
	// that has it (nft_tproxy checks, and skips any other), and it is what lets
	// a socket accept a connection for -- and answer a datagram from -- an
	// address that is not its own. Needs CAP_NET_ADMIN, which root has here
	// and the workload does not; the ownership of the namespace is what keeps
	// the workload from setting it on a socket of its own.
	if domain == unix.AF_INET6 {
		set("IPV6_TRANSPARENT", unix.SOL_IPV6, unix.IPV6_TRANSPARENT)
	} else {
		set("IP_TRANSPARENT", unix.SOL_IP, unix.IP_TRANSPARENT)
	}

	if typ == unix.SOCK_DGRAM {
		// A datagram has no accept and no socket of its own to read the
		// destination from, so the kernel attaches it to each one. TPROXY left
		// the packet unrewritten, so it is the address the client dialled.
		if domain == unix.AF_INET6 {
			set("IPV6_RECVORIGDSTADDR", level, unix.IPV6_RECVORIGDSTADDR)
		} else {
			set("IP_RECVORIGDSTADDR", level, unix.IP_RECVORIGDSTADDR)
		}
		// And the firewall mark, which is how a datagram is known to have
		// been steered (steer.ClassifyDatagram). Set here, by root, because
		// kernels between 1f86123b9749 and its 2023 revert made SO_RCVMARK
		// privileged; on current kernels the daemon could set it, and this
		// works on both.
		set("SO_RCVMARK", unix.SOL_SOCKET, unix.SO_RCVMARK)
	}
	if err != nil {
		return -1, err
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
