package nsnet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/steer"
	"golang.org/x/sys/unix"
)

// The test binary plays three parts: the tests, the privileged helper (because
// Open re-runs whatever executable it is, which under `go test` is this one),
// and a parked process inside a fresh namespace for the tests to aim at.
const (
	roleHelper = "frisket-test-helper"
	rolePark   = "frisket-test-park"
	roleWhere  = "frisket-test-whereami"
)

// inUserNS marks the re-executed self, so it does not re-execute again.
const inUserNS = "FRISKET_TEST_IN_USER_NAMESPACE"

// whyNoNamespaces is set when this process could not get the privilege the
// namespace tests need, and is what they skip with.
var whyNoNamespaces string

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case roleHelper:
			if err := RunHelper(os.Args[2:], os.Stderr, testServe); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		case rolePark:
			park()
			os.Exit(0)
		case roleWhere:
			ns, err := os.Readlink("/proc/self/ns/net")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(ns)
			os.Exit(0)
		}
	}

	// SETNS WANTS CAP_SYS_ADMIN IN BOTH USER NAMESPACES -- the one that owns
	// the target, AND the caller's own (netns_install checks both). frisket in
	// production is root on the host and has both; an unprivileged test has
	// neither, and cannot get the second one by joining a user namespace either,
	// because setns(CLONE_NEWUSER) refuses a multi-threaded caller and every Go
	// program is multi-threaded before main runs. Measured: `nsenter -t PID -n`
	// as an ordinary user fails with EPERM, and the same command inside
	// `unshare -Ur` succeeds.
	//
	// So the test binary re-runs itself as uid 0 of a user namespace of its own
	// -- `unshare -Ur` -- which is the second capability, and the sandbox it
	// then creates is a child of that namespace, which is the first.
	if os.Getenv(inUserNS) == "" {
		if code, ok := rerunInUserNamespace(); ok {
			os.Exit(code)
		}
		whyNoNamespaces = "this kernel will not make an unprivileged user namespace, so there is nothing to hold sockets in"
	}
	os.Exit(m.Run())
}

func rerunInUserNamespace() (int, bool) {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), inUserNS+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// Unprivileged user namespaces must deny setgroups before a gid map can
		// be written, and Go does that for us when this stays false.
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		return 0, false
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), true
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, true
}

// ---------------------------------------------------------------- the parked side

// park is a process living inside a fresh user+network namespace, answering one
// command per line so a test can act from IN THERE: bring lo up, or connect to
// a listener frisket is holding from out here.
func park() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		reply := "unknown command"
		switch {
		case len(fields) == 1 && fields[0] == "lo-up":
			reply = report(loopbackUpHere())
		case len(fields) == 3 && fields[0] == "dial":
			reply = dialOnce(fields[1], fields[2])
		case len(fields) == 4 && fields[0] == "udp":
			reply = udpOnce(fields[1], fields[2], fields[3])
		case len(fields) == 5 && fields[0] == "udpmark":
			reply = udpMarked(fields[1], fields[2], fields[3], fields[4])
		}
		fmt.Fprintln(out, reply)
		_ = out.Flush()
	}
}

func report(err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return "ok"
}

// loopbackUpHere brings lo up in this process's namespace, the way whatever
// provisions the sandbox would. SIOCSIFFLAGS rather than netlink because it is
// ten lines and this is a test fixture, not the product.
func loopbackUpHere() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func dialOnce(network, addr string) string {
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(io.LimitReader(c, 256))
	if err != nil {
		return "error: " + err.Error()
	}
	return "ok " + strings.TrimSpace(string(b))
}

func udpOnce(network, addr, payload string) string {
	c, err := net.Dial(network, addr)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	if _, err := c.Write([]byte(payload)); err != nil {
		return "error: " + err.Error()
	}
	return "ok"
}

// udpMarked sends one datagram with a firewall mark on it, as the ruleset
// would put there, and waits for the answer on a CONNECTED socket -- which
// drops anything that does not come from the exact address and port it
// dialled, as a real resolver client does. Setting the mark needs
// CAP_NET_ADMIN over the namespace, which this parked process has as root of
// the user namespace that owns it, and a workload does not.
func udpMarked(network, addr, payload, mark string) string {
	var m int
	if _, err := fmt.Sscan(mark, &m); err != nil {
		return "error: " + err.Error()
	}
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, m) }); err != nil {
			return err
		}
		return serr
	}}
	c, err := d.Dial(network, addr)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	if _, err := c.Write([]byte(payload)); err != nil {
		return "error: " + err.Error()
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 256)
	n, err := c.Read(b)
	if err != nil {
		return "error: " + err.Error()
	}
	return "ok " + string(b[:n])
}

// ---------------------------------------------------------------- the fixture

type sandbox struct {
	path string // /proc/<pid>/ns/net
	in   io.WriteCloser
	out  *bufio.Reader
}

// newSandbox starts a parked process in a new user and network namespace --
// `unshare -Urn`, done with clone flags rather than the binary so the test
// depends on nothing outside the Go toolchain.
//
// Entering it needs CAP_SYS_ADMIN in the user namespace that OWNS it, and this
// process has exactly that without being root: the new user namespace's parent
// is ours and its owner uid is ours, which is the rule that makes unprivileged
// nested namespaces work at all.
func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	if whyNoNamespaces != "" {
		t.Skip(whyNoNamespaces)
	}
	cmd := exec.Command(os.Args[0], rolePark)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		// No unprivileged user namespaces here -- a hardened kernel, or a
		// sandbox that already used up the nesting. Nothing to test, and
		// nothing wrong either.
		t.Skipf("cannot create a user+network namespace, so there is nothing to hold sockets in: %v", err)
	}
	s := &sandbox{
		path: fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid),
		in:   in,
		out:  bufio.NewReader(out),
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if _, err := os.Readlink(s.path); err != nil {
		t.Skipf("cannot see the namespace at %s: %v", s.path, err)
	}
	return s
}

func (s *sandbox) do(t *testing.T, format string, a ...any) string {
	t.Helper()
	if _, err := fmt.Fprintf(s.in, format+"\n", a...); err != nil {
		t.Fatalf("talking to the parked process: %v", err)
	}
	line, err := s.out.ReadString('\n')
	if err != nil {
		t.Fatalf("reading from the parked process: %v", err)
	}
	return strings.TrimSpace(line)
}

func (s *sandbox) loUp(t *testing.T) {
	t.Helper()
	if got := s.do(t, "lo-up"); got != "ok" {
		t.Fatalf("bringing lo up in the sandbox: %s", got)
	}
}

func testHelper() Helper { return Helper{Verb: roleHelper} }

// testServe is the test helper's requests: where this thread is, where a
// program it starts is, and a request that fails.
func testServe(req json.RawMessage) (any, error) {
	var op string
	if err := json.Unmarshal(req, &op); err != nil {
		return nil, err
	}
	switch op {
	case "where":
		return os.Readlink("/proc/thread-self/ns/net")
	case "run":
		out, err := exec.Command(os.Args[0], roleWhere).Output()
		return strings.TrimSpace(string(out)), err
	}
	return nil, fmt.Errorf("no request %q", op)
}

// open enters, takes the listeners, and ends the helper: the listeners
// outlive it.
func open(ctx context.Context, h Helper, args HelperArgs) (*Set, error) {
	e, err := Enter(ctx, h, args)
	if err != nil {
		return nil, err
	}
	if err := e.Close(); err != nil {
		_ = e.Set.Close()
		return nil, err
	}
	return e.Set, nil
}

func mustSpecs(t *testing.T, s string) []Spec {
	t.Helper()
	specs, err := ParseSpecs(s)
	if err != nil {
		t.Fatal(err)
	}
	return specs
}

func countFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd to count: %v", err)
	}
	return len(ents)
}

func sockOpt(t *testing.T, sock *Sock, level, opt int) int {
	t.Helper()
	var raw syscall.RawConn
	var err error
	if sock.Listener != nil {
		raw, err = sock.Listener.(*net.TCPListener).SyscallConn()
	} else {
		raw, err = sock.Packet.(*net.UDPConn).SyscallConn()
	}
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var opErr error
	if err := raw.Control(func(fd uintptr) { v, opErr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if opErr != nil {
		t.Fatalf("getsockopt level=%d opt=%d: %v", level, opt, opErr)
	}
	return v
}

// ---------------------------------------------------------------- the invariants

// THE OPTIONS ARE ASSERTED ON THE SOCKETS THAT CAME BACK through SCM_RIGHTS,
// made by the helper inside a sandbox, rather than on the source -- the source
// is not what the kernel reads -- and rather than on a socket made here, where
// this process has no CAP_NET_ADMIN over the namespace and could not set
// IP_TRANSPARENT at all.
//
//   - SO_REUSEPORT never: the workload is the first process in the namespace
//     and could bind frisket's port before the helper does; with it, the
//     workload would take a share of its own steered traffic, silently.
//   - SO_REUSEADDR on TCP only: on UDP it lets a second socket bind the same
//     address and port.
//   - IP_TRANSPARENT everywhere, or tproxy skips the socket.
//   - SO_RCVMARK and ORIGDSTADDR on UDP, or a datagram can be neither
//     classified nor answered.
//   - IPV6_V6ONLY on v6, so one socket never carries two families.
func TestSocketsCarryTheirOptions(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)
	set, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: mustSpecs(t, "tcp4:127.0.0.1:15001,tcp6:[::1]:15001,udp4:127.0.0.1:53,udp6:[::1]:53")})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	for _, sock := range set.Socks {
		v6, stream := sock.Spec.V6(), sock.Spec.Stream()
		want := map[string][3]int{
			"SO_REUSEPORT": {unix.SOL_SOCKET, unix.SO_REUSEPORT, 0},
			"SO_REUSEADDR": {unix.SOL_SOCKET, unix.SO_REUSEADDR, b2i(stream)},
		}
		if v6 {
			want["IPV6_V6ONLY"] = [3]int{unix.SOL_IPV6, unix.IPV6_V6ONLY, 1}
			want["IPV6_TRANSPARENT"] = [3]int{unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1}
		} else {
			want["IP_TRANSPARENT"] = [3]int{unix.SOL_IP, unix.IP_TRANSPARENT, 1}
		}
		if !stream {
			want["SO_RCVMARK"] = [3]int{unix.SOL_SOCKET, unix.SO_RCVMARK, 1}
			if v6 {
				want["IPV6_RECVORIGDSTADDR"] = [3]int{unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1}
			} else {
				want["IP_RECVORIGDSTADDR"] = [3]int{unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1}
			}
		}
		for name, w := range want {
			if got := sockOpt(t, sock, w[0], w[1]); got != w[2] {
				t.Errorf("%s: %s = %d, want %d", sock.Spec, name, got, w[2])
			}
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// The whole mechanism, end to end: the listeners are created in the sandbox's
// namespace, held from here, reachable from in there and from nowhere else.
func TestListenersLiveInTheSandboxAndAreHeldFromHere(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)

	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}

	specs := mustSpecs(t, "tcp4:127.0.0.1:15001,tcp6:[::1]:15001,udp4:127.0.0.1:53")
	set, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: specs})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()

	if set.Netns == host {
		t.Fatalf("the helper made the sockets in the host's namespace (%s); nothing was entered", host)
	}
	if len(set.Socks) != len(specs) {
		t.Fatalf("got %d sockets, want %d", len(set.Socks), len(specs))
	}

	for _, sock := range set.Socks {
		if sock.Listener == nil {
			continue
		}
		go func() {
			c, err := sock.Listener.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprintf(c, "held-%s\n", sock.Spec.Net)
		}()
	}

	if got := sb.do(t, "dial tcp4 127.0.0.1:15001"); got != "ok held-tcp4" {
		t.Errorf("dialling the v4 listener from inside the sandbox: %s", got)
	}
	if got := sb.do(t, "dial tcp6 [::1]:15001"); got != "ok held-tcp6" {
		t.Errorf("dialling the v6 listener from inside the sandbox: %s", got)
	}

	// A datagram, to prove the other half: FilePacketConn, and the socket
	// options the helper set before it handed the descriptor over.
	var udp *net.UDPConn
	for _, sock := range set.Socks {
		if sock.Packet != nil {
			udp = sock.Packet.(*net.UDPConn)
		}
	}
	if udp == nil {
		t.Fatal("no packet conn in the set")
	}
	if got := sb.do(t, "udp udp4 127.0.0.1:53 hello"); got != "ok" {
		t.Fatalf("sending a datagram from inside the sandbox: %s", got)
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := udp.ReadFrom(buf)
	if err != nil {
		t.Fatalf("reading the sandbox's datagram from the host: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("datagram = %q, want %q", buf[:n], "hello")
	}

	// And NOTHING on the host's own loopback reaches them. These are the same
	// addresses and ports, in a different namespace.
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:15001", time.Second); err == nil {
		c.Close()
		t.Error("127.0.0.1:15001 is reachable from the host; the socket is not in the sandbox's namespace")
	}
}

// A DATAGRAM, STEERED AND ANSWERED, through everything but the ruleset: the
// helper's socket in the sandbox, held from here and served by steer. A
// datagram carrying the ruleset's mark is handed on, and the answer -- sent
// with PKTINFO naming the address the client dialled -- reaches a CONNECTED
// client, which drops anything from any other address. One without the mark
// is refused and logged. Both are to 127.0.0.1:53, the listener's own address,
// because that is where glibc's default resolver sends: the address cannot be
// what decides.
func TestAMarkedDatagramIsAnsweredAndAnUnmarkedOneRefused(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)
	set, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: mustSpecs(t, "udp4:127.0.0.1:53,udp6:[::1]:53")})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()

	var log lockedBuffer
	s := steer.New("sess-udp", &log)
	s.Mark = 1
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	for _, sock := range set.Socks {
		go func() {
			_ = s.ServePacket(ctx, sock.Packet, echo{})
		}()
	}

	if got := sb.do(t, "udpmark udp4 127.0.0.1:53 hello 1"); got != "ok echo hello to 127.0.0.1:53" {
		t.Errorf("a marked v4 datagram: %s", got)
	}
	if got := sb.do(t, "udpmark udp6 [::1]:53 hello 1"); got != "ok echo hello to [::1]:53" {
		t.Errorf("a marked v6 datagram: %s", got)
	}
	if got := sb.do(t, "udpmark udp4 127.0.0.1:53 direct 0"); !strings.HasPrefix(got, "error") {
		t.Errorf("an unmarked datagram was answered: %s", got)
	}
	if !strings.Contains(log.String(), `"reason":"`+steer.ReasonNotMarked+`"`) {
		t.Errorf("the unmarked datagram left no refusal in the log:\n%s", log.String())
	}
}

type echo struct{}

func (echo) ServePacket(_ context.Context, d *steer.Datagram) {
	_ = d.Reply([]byte(fmt.Sprintf("echo %s to %s", d.Payload, d.Orig)))
}

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A workload that took the port first must make session creation FAIL, loudly.
// Two Opens for the same address is the same thing to the kernel as a workload
// that got there first, and is reproducible without one.
func TestOpenAbortsWhenThePortIsTaken(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)

	specs := mustSpecs(t, "tcp4:127.0.0.1:15001")
	first, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: specs})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: specs})
	if err == nil {
		second.Close()
		t.Fatal("the second session bound the same address; SO_REUSEPORT must be off and the bind must fail")
	}
	if !strings.Contains(err.Error(), "bind") || !strings.Contains(err.Error(), "127.0.0.1:15001") {
		t.Errorf("error = %v, want it to name the bind and the address", err)
	}

	// And the failure did not disturb the session that already holds it.
	go func() {
		c, err := first.Socks[0].Listener.Accept()
		if err == nil {
			fmt.Fprintln(c, "still-here")
			c.Close()
		}
	}()
	if got := sb.do(t, "dial tcp4 127.0.0.1:15001"); got != "ok still-here" {
		t.Errorf("the first session stopped working: %s", got)
	}
}

// ::1 does not exist until lo is up, and a namespace is handed over before that
// has necessarily happened. Waiting is the fix; failing with EADDRNOTAVAIL and
// blaming the caller is the bug.
func TestOpenWaitsForLoopbackAndSaysSoWhenItNeverComes(t *testing.T) {
	sb := newSandbox(t) // lo deliberately left down

	_, err := open(t.Context(), testHelper(), HelperArgs{
		Netns:     sb.path,
		Specs:     mustSpecs(t, "tcp6:[::1]:15001"),
		LoTimeout: 150 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("bound ::1 with lo down, which the kernel does not allow")
	}
	if !strings.Contains(err.Error(), "lo") {
		t.Errorf("error = %v, want it to name lo rather than the bind it never reached", err)
	}
}

func TestOpenRetriesUntilLoopbackIsUp(t *testing.T) {
	sb := newSandbox(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Long enough that Open is certainly already waiting.
		time.Sleep(200 * time.Millisecond)
		sb.loUp(t)
	}()

	set, err := open(t.Context(), testHelper(), HelperArgs{
		Netns:     sb.path,
		Specs:     mustSpecs(t, "tcp6:[::1]:15001"),
		LoTimeout: 10 * time.Second,
	})
	<-done
	if err != nil {
		t.Fatalf("Open gave up instead of retrying: %v", err)
	}
	set.Close()
}

// CLOSING EVERY DESCRIPTOR IS TEARDOWN. A listener pins the namespace it was
// created in and the user namespace that owns it, and neither lsns nor
// `ip netns` shows the pin -- so a descriptor this process forgot about is a
// namespace alive for the daemon's lifetime, with nothing to find it by.
//
// Counting /proc/self/fd is the assertion that a leak would actually fail:
// a forgotten *os.File, a socketpair end, a dup left over from FileListener.
// That the namespace itself goes away is not observable from here once the
// process in it is gone, and is a NixOS test (see PLAN.md, "Lifecycle").
func TestCloseReleasesEveryDescriptor(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)

	specs := mustSpecs(t, "tcp4:127.0.0.1:15001,tcp6:[::1]:15001,udp4:127.0.0.1:53")
	cycle := func() {
		set, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: specs})
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := set.Close(); err != nil {
			t.Fatalf("second Close: %v; teardown is called from the clean path and the killed one", err)
		}
	}
	cycle() // warm up: the first one populates caches and the runtime's own fds
	before := countFDs(t)
	for range 3 {
		cycle()
	}
	if after := countFDs(t); after != before {
		t.Errorf("%d descriptors open before three open/close cycles, %d after: a pinned namespace with no handle on it", before, after)
	}
}

func TestClosedListenerRefusesFurtherAccepts(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)

	set, err := open(t.Context(), testHelper(), HelperArgs{Netns: sb.path, Specs: mustSpecs(t, "tcp4:127.0.0.1:15001")})
	if err != nil {
		t.Fatal(err)
	}
	ln := set.Socks[0].Listener
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestOpenReportsTheHelpersOwnError(t *testing.T) {
	// A namespace path that is not one: the helper's setns fails, and the
	// message the caller sees has to be the helper's, not "exit status 1".
	_, err := open(context.Background(), testHelper(), HelperArgs{
		Netns: "/proc/self/ns/net-does-not-exist",
		Specs: mustSpecs(t, "tcp4:127.0.0.1:15001"),
	})
	if err == nil {
		t.Fatal("entering a namespace that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "net-does-not-exist") {
		t.Errorf("error = %v, want it to name the path it could not enter", err)
	}
}

// ---------------------------------------------------------------- the ordering

// The first half of "listeners, then rules, then connectivity", checked from
// inside: a namespace that already has an interface besides lo has had egress
// provisioned first, or is not a sandbox's at all.
func TestRequireIsolatedRefusesAnythingButLoopback(t *testing.T) {
	lo := net.Interface{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp}
	if err := requireIsolated([]net.Interface{lo}); err != nil {
		t.Errorf("lo alone was refused: %v", err)
	}
	for _, other := range []net.Interface{
		{Index: 2, Name: "frisket0", Flags: net.FlagUp},
		{Index: 2, Name: "eth0", Flags: 0}, // down still counts: it is one command from up
	} {
		err := requireIsolated([]net.Interface{lo, other})
		if err == nil {
			t.Errorf("%s was accepted beside lo", other.Name)
			continue
		}
		if !strings.Contains(err.Error(), other.Name) {
			t.Errorf("error = %v, want it to name %s", err, other.Name)
		}
	}
}

func TestOpenIsolatedAcceptsANamespaceWithOnlyLoopback(t *testing.T) {
	sb := newSandbox(t)
	sb.loUp(t)
	set, err := open(t.Context(), testHelper(), HelperArgs{
		Netns:    sb.path,
		Specs:    mustSpecs(t, "tcp4:127.0.0.1:15001"),
		Isolated: true,
	})
	if err != nil {
		t.Fatalf("a namespace holding only lo was refused: %v", err)
	}
	set.Close()
}

// One entry does a whole step: the helper answers from inside the namespace,
// as does a program it starts, and nothing else changes namespace -- the test
// process asking is still where it was. With no listeners asked for, it makes
// none and waits for no lo, which is connect's case.
func TestTheHelperAnswersFromInsideTheNamespace(t *testing.T) {
	sb := newSandbox(t) // lo left down: nothing here binds
	want, err := os.Readlink(sb.path)
	if err != nil {
		t.Fatal(err)
	}
	here, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Enter(t.Context(), testHelper(), HelperArgs{Netns: sb.path, LoTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if len(e.Set.Socks) != 0 || e.Set.Netns != want {
		t.Errorf("entered %s holding %d listeners, want %s and none", e.Set.Netns, len(e.Set.Socks), want)
	}
	for _, op := range []string{"where", "run", "where"} {
		var got string
		if err := e.Do(t.Context(), op, &got); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if got != want {
			t.Errorf("%s: answered from %s, want the sandbox's %s", op, got, want)
		}
	}
	if err := e.Do(t.Context(), "nonsense", nil); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("a failed request: %v, want the helper's own error", err)
	}
	if err := e.Close(); err != nil {
		t.Errorf("ending the helper: %v", err)
	}
	if err := e.Do(t.Context(), "where", nil); err == nil {
		t.Error("a request after Close was answered")
	}
	if after, _ := os.Readlink("/proc/self/ns/net"); after != here {
		t.Errorf("this process moved from %s to %s", here, after)
	}
}
