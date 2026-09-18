package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/internal/steer"
	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------- fixtures

// journal is the injected writer, never silenced: "one line per connection" is
// a property, and a property has to be assertable.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(raw, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func countFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(ents)
}

// fakeSystemd is PID 1's fd store: it keeps its own copy of everything stored,
// as PID 1 does, so a test can hand them to a second daemon.
type fakeSystemd struct {
	mu     sync.Mutex
	store  map[string][]*os.File
	order  []string
	ready  int
	events []string
}

func newFakeSystemd() *fakeSystemd { return &fakeSystemd{store: map[string][]*os.File{}} }

func (f *fakeSystemd) Ready(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ready++
	return nil
}
func (f *fakeSystemd) Stopping() error { return nil }
func (f *fakeSystemd) Store(name string, files ...*os.File) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, file := range files {
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f.store[name] = append(f.store[name], os.NewFile(uintptr(fd), name))
	}
	f.order = append(f.order, name)
	f.events = append(f.events, "store "+name)
	return nil
}
func (f *fakeSystemd) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	control.CloseAll(f.store[name])
	delete(f.store, name)
	f.events = append(f.events, "remove "+name)
	return nil
}

// passed is what PID 1 would pass a restarted daemon: every stored file, under
// its name. Dups, so the store keeps its own.
func (f *fakeSystemd) passed(t *testing.T) []sdnotify.FD {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sdnotify.FD
	for _, name := range f.order {
		for _, file := range f.store[name] {
			fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, sdnotify.FD{Name: name, File: os.NewFile(uintptr(fd), name)})
		}
	}
	return out
}

func (f *fakeSystemd) held(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.store[name])
}

// recorder is a policy whose handlers note what they were given.
type recorder struct {
	mu        sync.Mutex
	egress    []netip.AddrPort
	intercept []netip.AddrPort
	block     chan struct{} // if set, egress holds the connection until closed
}

func (r *recorder) policy() Policy {
	return PolicyFunc(func(control.Session, *slog.Logger) (Handlers, error) {
		return Handlers{
			Egress: steer.HandlerFunc(func(ctx context.Context, c *steer.Conn) {
				r.mu.Lock()
				r.egress = append(r.egress, c.Orig)
				r.mu.Unlock()
				fmt.Fprintln(c, "egress")
				if r.block != nil {
					_, _ = io.Copy(io.Discard, c) // until the session closes it
				}
				_ = c.Close()
			}),
			Intercept: steer.HandlerFunc(func(ctx context.Context, c *steer.Conn) {
				r.mu.Lock()
				r.intercept = append(r.intercept, c.Orig)
				r.mu.Unlock()
				fmt.Fprintln(c, "intercept")
				_ = c.Close()
			}),
		}, nil
	})
}

var service4 = netip.MustParseAddr("192.0.2.2")

// daemonFixture runs a Daemon on a real control socket. Its own-namespace
// cookie is set to a value no namespace has, so listeners made here on
// loopback stand in for listeners made in a sandbox; the test that the real
// check refuses them is separate.
type daemonFixture struct {
	d       *Daemon
	journal *journal
	path    string
	cancel  context.CancelFunc
	done    chan error
}

func startDaemon(t *testing.T, sd Notifier, rec *recorder, orig func(*net.TCPConn) (netip.AddrPort, error), inherited []sdnotify.FD) *daemonFixture {
	t.Helper()
	return startDaemonWith(t, nil, sd, rec, orig, inherited)
}

// startDaemonWith lets a test change the daemon before it runs, rather than
// racing it afterwards.
func startDaemonWith(t *testing.T, configure func(*Daemon), sd Notifier, rec *recorder, orig func(*net.TCPConn) (netip.AddrPort, error), inherited []sdnotify.FD) *daemonFixture {
	t.Helper()
	j := &journal{}
	d := &Daemon{
		Log:        slog.New(slog.NewJSONHandler(j, nil)),
		Policies:   map[string]Policy{"recorder": rec.policy(), StandInPolicy: StandIn()},
		Notify:     sd,
		ControlUID: os.Getuid(),
		own:        1,
		origDst:    orig,
	}
	if configure != nil {
		configure(d)
	}
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.ListenUnix(control.Network, &net.UnixAddr{Name: path, Net: control.Network})
	if err != nil {
		t.Skipf("no seqpacket socket here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &daemonFixture{d: d, journal: j, path: path, cancel: cancel, done: make(chan error, 1)}
	go func() { f.done <- d.Run(ctx, ln, inherited) }()
	// An answer on the control socket means adoption is over: the accept
	// loop starts after it. (A refusal is an answer too.)
	waitFor(t, "the daemon to answer", func() bool {
		_, err := control.Call(context.Background(), path, control.Request{Op: control.OpList}, nil)
		return err == nil || strings.Contains(err.Error(), "may not use")
	})
	t.Cleanup(f.stop)
	return f
}

func (f *daemonFixture) stop() {
	f.cancel()
	<-f.done
	f.done <- nil // so a second stop does not block
}

// listeners makes a session's worth of loopback sockets and the session that
// describes them.
func listeners(t *testing.T, name string) (control.Session, []*os.File, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	lf, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pc.(*net.UDPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := pc.LocalAddr().String()
	_ = pc.Close()
	info := control.Session{
		Name:   name,
		Policy: "recorder",
		Set:    control.SetAll,
		Service: []netip.Addr{
			service4,
			netip.MustParseAddr("2001:db8::2"),
		},
		Listeners: []string{
			"tcp4:" + ln.Addr().String(),
			"udp4:" + udpAddr,
		},
		Netns: "net:[1]",
	}
	return info, []*os.File{lf, pf}, ln
}

// ---------------------------------------------------------------- dispatch

func TestDispatchRoutesByOriginalDestination(t *testing.T) {
	d := Dispatch{Service: []netip.Addr{service4, netip.MustParseAddr("2001:db8::2")}}
	for addr, want := range map[string]bool{
		"192.0.2.2":        true,
		"::ffff:192.0.2.2": true, // a spelling, not another host
		"2001:db8::2":      true,
		"2001:db8::2%eth0": true, // a zone names an interface, not a host
		"192.0.2.3":        false,
		"203.0.113.20":     false,
		"2001:db8::3":      false,
	} {
		if got := d.IsService(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsService(%s) = %v, want %v", addr, got, want)
		}
	}
}

// Nothing that is not the service address is ever routed to interception,
// whatever its spelling: interception is where credentials are added.
func TestDispatchNeverInterceptsAnythingElse(t *testing.T) {
	d := Dispatch{Service: []netip.Addr{service4}}
	rapid.Check(t, func(t *rapid.T) {
		var a netip.Addr
		if rapid.Bool().Draw(t, "v6") {
			a = netip.AddrFrom16([16]byte(rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "b")))
		} else {
			a = netip.AddrFrom4([4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "b")))
		}
		if d.IsService(a) != (a.Unmap() == service4) {
			t.Fatalf("IsService(%s) = %v", a, d.IsService(a))
		}
	})
}

// ---------------------------------------------------------------- sessions

// The whole life of a session: opened with its descriptors, stored with
// systemd before it is served, each steered connection dispatched by its
// original destination, and closed -- every descriptor, the live connections
// included, and the store entry with them.
func TestASessionIsServedStoredAndClosedCompletely(t *testing.T) {
	sd := newFakeSystemd()
	rec := &recorder{block: make(chan struct{})}
	var nextOrig = make(chan netip.AddrPort, 4)
	f := startDaemon(t, sd, rec, func(*net.TCPConn) (netip.AddrPort, error) { return <-nextOrig, nil }, nil)

	before := countFDs(t)
	info, files, ln := listeners(t, "netless-1-2")
	addr := ln.Addr().String()
	_ = ln.Close() // the File is a dup; the daemon gets that one
	if _, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files); err != nil {
		t.Fatal(err)
	}
	control.CloseAll(files)

	if got := sd.held("netless-1-2"); got != 3 {
		t.Errorf("systemd holds %d descriptors for the session, want its 2 listeners and its record", got)
	}

	// Steered to somewhere else: egress. Steered to the service address:
	// interception.
	nextOrig <- netip.MustParseAddrPort("203.0.113.20:80")
	held, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	line, _ := readLine(held)
	if line != "egress" {
		t.Errorf("a connection to 203.0.113.20 went to %q", line)
	}
	nextOrig <- netip.AddrPortFrom(service4, 443)
	c2, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	if line, _ := readLine(c2); line != "intercept" {
		t.Errorf("a connection to the service address went to %q", line)
	}
	c2.Close()

	// Two listeners, the one live connection and the record. Waited for,
	// because the intercepted connection is closed by its handler a moment
	// after the client has read its line.
	var st control.Response
	waitFor(t, "the session to hold 4 descriptors", func() bool {
		st, err = control.Call(context.Background(), f.path, control.Request{Op: control.OpList}, nil)
		return err == nil && len(st.Sessions) == 1 && st.Sessions[0].Descriptors == 4
	})

	resp, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpClose, Name: "netless-1-2"}, nil)
	if err != nil || !resp.Closed {
		t.Fatalf("close: %+v %v", resp, err)
	}
	// The live connection was closed with it: an accepted socket belongs to
	// the sandbox's namespace and pins it like the listener does.
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Error("a live connection survived its session's close")
	}
	held.Close()
	if got := sd.held("netless-1-2"); got != 0 {
		t.Errorf("systemd still holds %d of the closed session's descriptors", got)
	}
	if _, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
		t.Error("the closed session's listener still accepts")
	}
	waitFor(t, "every descriptor to close", func() bool { return countFDs(t) <= before })

	// And closing it again is not an error, because teardown runs from the
	// clean path and the killed one.
	if resp, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpClose, Name: "netless-1-2"}, nil); err != nil || resp.Closed {
		t.Errorf("second close: %+v %v", resp, err)
	}
	if n := len(f.journal.lines(t, "session closed")); n != 1 {
		t.Errorf("%d 'session closed' lines, want 1", n)
	}
}

func readLine(c net.Conn) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	return strings.TrimSpace(string(buf[:n])), err
}

// A listener in frisket's own namespace means the helper never entered the
// sandbox's. Refused before systemd ever sees it, and every descriptor that
// came with the request is closed.
func TestListenersInTheDaemonsOwnNamespaceAreRefused(t *testing.T) {
	sd := newFakeSystemd()
	own, err := ownCookie()
	if err != nil {
		t.Skipf("no SO_NETNS_COOKIE here: %v", err)
	}
	f := startDaemonWith(t, func(d *Daemon) { d.own = own }, sd, &recorder{}, nil, nil)

	before := countFDs(t)
	info, files, ln := listeners(t, "netless-3-4")
	_ = ln.Close()
	_, err = control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
	control.CloseAll(files)
	if err == nil || !strings.Contains(err.Error(), "own network namespace") {
		t.Fatalf("err = %v, want the own-namespace refusal", err)
	}
	if len(sd.events) != 0 {
		t.Errorf("systemd was told %v about a refused session", sd.events)
	}
	waitFor(t, "the refused descriptors to close", func() bool { return countFDs(t) <= before })
}

func TestOpenRefusesWhatItCannotHoldAsDescribed(t *testing.T) {
	sd := newFakeSystemd()
	f := startDaemon(t, sd, &recorder{}, nil, nil)
	for name, mutate := range map[string]func(*control.Session, []*os.File) []*os.File{
		"an unknown policy": func(s *control.Session, fs []*os.File) []*os.File { s.Policy = "nonesuch"; return fs },
		"a listener bound elsewhere": func(s *control.Session, fs []*os.File) []*os.File {
			s.Listeners[0] = "tcp4:127.0.0.1:1"
			return fs
		},
		"descriptors in the wrong order": func(s *control.Session, fs []*os.File) []*os.File {
			return []*os.File{fs[1], fs[0]}
		},
		"a descriptor missing": func(s *control.Session, fs []*os.File) []*os.File { return fs[:1] },
	} {
		info, files, ln := listeners(t, "netless-5-6")
		_ = ln.Close()
		sent := mutate(&info, files)
		_, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, sent)
		control.CloseAll(files)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(sd.events) != 0 {
		t.Errorf("systemd was told %v about refused sessions", sd.events)
	}
	if len(f.d.List()) != 0 {
		t.Errorf("refused sessions are held: %+v", f.d.List())
	}
}

// Nobody but the configured uid is answered.
func TestTheControlSocketAnswersOnlyItsOwner(t *testing.T) {
	f := startDaemonWith(t, func(d *Daemon) { d.ControlUID = os.Getuid() + 1 }, nil, &recorder{}, nil, nil)
	if _, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpList}, nil); err == nil || !strings.Contains(err.Error(), "may not use") {
		t.Errorf("err = %v, want a refusal of this uid", err)
	}
}

// A restart hands the stored listeners to the next process, which adopts them
// as the same sessions -- matched to their specs by what the kernel says they
// are, since the store promises no order -- and serves them.
func TestARestartAdoptsTheStoredSessions(t *testing.T) {
	sd := newFakeSystemd()
	rec := &recorder{}
	orig := func(*net.TCPConn) (netip.AddrPort, error) { return netip.MustParseAddrPort("203.0.113.20:80"), nil }
	first := startDaemon(t, sd, rec, orig, nil)
	info, files, ln := listeners(t, "netless-7-8")
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := control.Call(context.Background(), first.path, control.Request{Op: control.OpOpen, Session: &info}, files); err != nil {
		t.Fatal(err)
	}
	control.CloseAll(files)
	first.stop()

	// Stopping is not closing: the store still has it.
	if got := sd.held("netless-7-8"); got != 3 {
		t.Fatalf("after a stop systemd holds %d, want 3", got)
	}

	passed := sd.passed(t)
	// Reversed, because nothing promises the order they come back in.
	for i, j := 0, len(passed)-1; i < j; i, j = i+1, j-1 {
		passed[i], passed[j] = passed[j], passed[i]
	}
	second := startDaemon(t, sd, rec, orig, passed)
	st := second.d.List()
	if len(st) != 1 || st[0].Name != "netless-7-8" || !st[0].Restored || st[0].Policy != "recorder" {
		t.Fatalf("after a restart: %+v", st)
	}
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if line, _ := readLine(c); line != "egress" {
		t.Errorf("the restored session answered %q", line)
	}
	if n := len(second.journal.lines(t, "session restored")); n != 1 {
		t.Errorf("%d 'session restored' lines", n)
	}
}

// A stored entry that does not add up -- here, a record whose listeners are
// not among the descriptors -- is dropped from the store and closed, not held
// as a namespace pin nobody can serve.
func TestAStoredSessionThatDoesNotAddUpIsDropped(t *testing.T) {
	sd := newFakeSystemd()
	info, files, ln := listeners(t, "netless-9-10")
	_ = ln.Close()
	info.Listeners[0] = "tcp4:127.0.0.1:1"
	meta, err := newRecord(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Store("netless-9-10", append(files, meta)...); err != nil {
		t.Fatal(err)
	}
	control.CloseAll(append(files, meta))

	f := startDaemon(t, sd, &recorder{}, nil, sd.passed(t))
	if st := f.d.List(); len(st) != 0 {
		t.Errorf("held %+v", st)
	}
	if got := sd.held("netless-9-10"); got != 0 {
		t.Errorf("systemd still holds %d of an unusable session", got)
	}
	if n := len(f.journal.lines(t, "session not restored")); n != 1 {
		t.Errorf("%d 'session not restored' lines, want 1", n)
	}
}

func TestTheRecordIsSealed(t *testing.T) {
	f, err := newRecord(control.Session{Name: "a", Policy: "p"})
	if err != nil {
		t.Skipf("no memfd here: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("x"), 0); err == nil {
		t.Error("a sealed record was written to")
	}
	got, err := readRecord(f)
	if err != nil || got.Name != "a" {
		t.Errorf("read back %+v, %v", got, err)
	}
}

// ---------------------------------------------------------------- the stand-in

// The splice waits for both directions: the client half-closes, and the reply
// that follows still arrives.
func TestTheStandInSpliceSurvivesAHalfClose(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c) // until the client's half-close arrives
		fmt.Fprintf(c, "got %d bytes", len(b))
	}()

	j := &journal{}
	log := slog.New(slog.NewJSONHandler(j, nil))
	h, err := StandIn().Handlers(control.Session{Name: "s"}, log)
	if err != nil {
		t.Fatal(err)
	}
	down, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer down.Close()
	go func() {
		c, err := down.Accept()
		if err != nil {
			return
		}
		h.Egress.ServeConn(context.Background(), &steer.Conn{
			TCPConn: c.(*net.TCPConn), Session: "s", ID: 1,
			Orig: netip.MustParseAddrPort(up.Addr().String()),
		})
	}()
	c, err := net.Dial("tcp4", down.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if string(b) != "got 5 bytes" {
		t.Errorf("reply after a half-close = %q", b)
	}
	waitFor(t, "the egress line", func() bool { return len(j.lines(t, "egress")) == 1 })
	l := j.lines(t, "egress")[0]
	if l["dst"] != up.Addr().String() || l["bytes_out"] != float64(5) || l["bytes_in"] != float64(11) {
		t.Errorf("egress line = %v", l)
	}
}

func TestTheStandInDNSAnswersRefused(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer srv.Close()
	j := &journal{}
	h, _ := StandIn().Handlers(control.Session{Name: "s"}, slog.New(slog.NewJSONHandler(j, nil)))
	cl, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'f', 'o', 'o', 0, 0, 1, 0, 1}
	h.DNS.ServePacket(context.Background(), srv, netip.MustParseAddrPort(cl.LocalAddr().String()), netip.MustParseAddrPort("192.0.2.2:53"), query)
	_ = cl.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := cl.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 12 || buf[0] != 0xab || buf[1] != 0xcd || buf[2]&0x80 == 0 || buf[3]&0x0f != 5 {
		t.Errorf("answer = % x, want the query's id, QR set and RCODE REFUSED", buf[:n])
	}
	if len(j.lines(t, "dns")) != 1 {
		t.Error("the refusal was not logged")
	}
}
