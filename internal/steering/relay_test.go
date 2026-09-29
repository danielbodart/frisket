package steering

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// roleRelay re-runs the test binary in a namespace of its own, where it loads
// a steering file's ruleset with a Docker project's relay destinations and
// dials them.
const roleRelay = "frisket-test-relay"

// The destinations of data-lab's one port, as the daemon answers open with
// them, and another project's address.
const (
	relayPort    = 64320
	relayAddress = "127.1.191.78"
	otherAddress = "127.6.18.253"
)

// A session's Docker ports on its own loopback, and at its project's address,
// are steered to frisket's TCP listener with the destination the client
// dialled, in both sets, by the ruleset lib.steering writes (testdata, which
// the flake's steering check holds to lib.steering) with steer's elements.
// The next port, and another project's address, are left to the sandbox's
// own loopback, where nothing listens; nor does anything listen on the port,
// so pasta's -t auto has nothing to republish.
func TestARelayedPortReachesTheSessionsListenerWithItsDestination(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft here to load the ruleset with")
	}
	for _, set := range []string{"all", "service"} {
		t.Run(set, func(t *testing.T) { runInside(t, roleRelay, set) })
	}
}

// relayInside is the test, as uid 0 inside the namespace.
func relayInside(set string) error {
	p, err := Load("testdata/steering-" + set + ".json")
	if err != nil {
		return err
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	lns := map[bool]*net.TCPListener{}
	for _, spec := range p.Listeners {
		if !spec.Stream() {
			continue
		}
		ln, err := transparentListener(spec.Net, spec.Addr)
		if err != nil {
			return err
		}
		defer ln.Close()
		lns[spec.V6()] = ln
	}
	if err := serveJSON(request{Op: opApply, Steps: append(p.RoutingSteps(false), p.RoutingSteps(true)...)}, nil); err != nil {
		return fmt.Errorf("routing: %w", err)
	}
	port := strconv.Itoa(relayPort)
	ruleset, err := p.WithRelay([]string{"127.0.0.1:" + port, relayAddress + ":" + port, "[::1]:" + port})
	if err != nil {
		return err
	}
	if err := serveJSON(request{Op: opRuleset, Nft: nft, Ruleset: ruleset}, nil); err != nil {
		return fmt.Errorf("ruleset: %w", err)
	}

	for _, dst := range []string{"127.0.0.1:" + port, "[::1]:" + port, relayAddress + ":" + port} {
		want := netip.MustParseAddrPort(dst)
		c, err := net.DialTimeout("tcp", dst, 2*time.Second)
		if err != nil {
			return fmt.Errorf("%s was not steered: %w", dst, err)
		}
		ln := lns[want.Addr().Is6()]
		_ = ln.SetDeadline(time.Now().Add(2 * time.Second))
		got, err := ln.AcceptTCP()
		c.Close()
		if err != nil {
			return fmt.Errorf("%s: nothing arrived on the session's listener: %w", dst, err)
		}
		orig := got.LocalAddr().(*net.TCPAddr).AddrPort()
		got.Close()
		if orig.Addr().Unmap() != want.Addr() || orig.Port() != want.Port() {
			return fmt.Errorf("%s arrived as %s", dst, orig)
		}
	}

	for _, dst := range []string{"127.0.0.1:" + strconv.Itoa(relayPort+1), otherAddress + ":" + port} {
		c, err := net.DialTimeout("tcp4", dst, 2*time.Second)
		if err == nil {
			c.Close()
			return fmt.Errorf("%s connected, and nothing but the relay's steering could have taken it", dst)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("%s: %w, want refused by the sandbox's own loopback", dst, err)
		}
		_ = lns[false].SetDeadline(time.Now().Add(100 * time.Millisecond))
		if got, err := lns[false].AcceptTCP(); err == nil {
			got.Close()
			return fmt.Errorf("%s arrived on the session's listener", dst)
		}
	}

	listening, err := listeningPorts()
	if err != nil {
		return err
	}
	if listening[relayPort] {
		return fmt.Errorf("something listens on %d inside the session, for pasta to republish", relayPort)
	}
	if !listening[int(lns[false].Addr().(*net.TCPAddr).Port)] {
		return errors.New("/proc/net/tcp shows no listener at all, not even the session's own: it was not read right")
	}
	return nil
}

// transparentListener is a TCP listener as nsnet makes a session's: bound on
// loopback, with the TRANSPARENT flag tproxy needs, v6 only in v6.
func transparentListener(network string, addr netip.AddrPort) (*net.TCPListener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if addr.Addr().Is6() {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
		})
		return errors.Join(err, serr)
	}}
	ln, err := lc.Listen(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}
	return ln.(*net.TCPListener), nil
}

// listeningPorts are the local ports of every TCP socket in LISTEN in this
// namespace, both families, as /proc/net/tcp and tcp6 show them.
func listeningPorts() (map[int]bool, error) {
	ports := map[int]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // the header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(hexPort, 16, 16)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s: %q: %w", path, fields[1], err)
			}
			ports[int(n)] = true
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return ports, nil
}
