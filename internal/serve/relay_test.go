package serve

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/relay"
	"github.com/danielbodart/frisket/internal/steer"
)

// openAs opens a session whose policy gives it project's Docker route with
// ports, or no Docker route when project is empty, and returns the answer.
func openAs(t *testing.T, f *daemonFixture, name, project, ports string) (control.Response, error) {
	t.Helper()
	info, files, ln := listeners(t, name)
	_ = ln.Close()
	defer control.CloseAll(files)
	if project != "" {
		info.Params = map[string]string{"project": project, "ports": ports}
	}
	return control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
}

// told is what systemd has been told so far, read under its lock: the
// daemon tells it from another goroutine, and a socket is no happens-before
// the race detector sees.
func (f *fakeSystemd) told() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

// held is the names of the sessions the daemon holds.
func held(f *daemonFixture) []string {
	var names []string
	for _, st := range f.d.List() {
		names = append(names, st.Name)
	}
	return names
}

// Open answers with what the session's ruleset is to steer for its Docker
// project, in the policy's order, spelt as netip spells them; a session with
// no Docker route is answered with none.
func TestOpenAnswersWithTheRelayDestinationsItsPolicyGives(t *testing.T) {
	f := startDaemon(t, newFakeSystemd(), &recorder{}, nil, nil)
	resp, err := openAs(t, f, "docker-1", "example/shop", "64320,64321")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"127.0.0.1:64320", "127.101.170.171:64320", "[::1]:64320",
		"127.0.0.1:64321", "127.101.170.171:64321", "[::1]:64321",
	}
	if !slices.Equal(resp.Relay, want) {
		t.Errorf("open answered relay %v, want %v", resp.Relay, want)
	}
	if len(resp.CACert) == 0 {
		t.Error("open answered with the relay and no CA")
	}

	resp, err = openAs(t, f, "plain-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Relay) != 0 {
		t.Errorf("a session with no Docker route was answered relay %v", resp.Relay)
	}
}

// A relayed port that is one of the session's own listeners' would steer a
// connection to the listener's own address, which steer.Classify refuses;
// one that is 53 would be taken by DNS. Either refuses the session, before
// systemd is told of it.
func TestOpenRefusesARelayPortThatIsAListenersOrDNSs(t *testing.T) {
	sd := newFakeSystemd()
	f := startDaemon(t, sd, &recorder{}, nil, nil)

	info, files, ln := listeners(t, "docker-2")
	port := ln.Addr().(interface{ AddrPort() netip.AddrPort }).AddrPort().Port()
	_ = ln.Close()
	info.Params = map[string]string{"project": "example/shop", "ports": "64320," + strconv.Itoa(int(port))}
	_, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
	control.CloseAll(files)
	if err == nil || !strings.Contains(err.Error(), "is the port of its listener") {
		t.Errorf("a relay port that is the listener's: err = %v", err)
	}

	if _, err := openAs(t, f, "docker-3", "example/shop", "53"); err == nil || !strings.Contains(err.Error(), "DNS's") {
		t.Errorf("a relay port of 53: err = %v", err)
	}
	if told := sd.told(); len(told) != 0 {
		t.Errorf("systemd was told %v about refused sessions", told)
	}
	if got := held(f); len(got) != 0 {
		t.Errorf("refused sessions are held: %v", got)
	}
}

// collide is a derivation that puts every project at one address, as two
// slugs searched to hash alike would be.
func collide(string) netip.Addr { return netip.MustParseAddr("127.101.170.171") }

// Two projects at one address both run, opened or adopted: in the trusted
// tier that is rarer than it is worth refusing, and each session's relay
// still reaches only what a container with its own project's label
// publishes there (internal/relay).
func TestTwoProjectsAtOneAddressBothRun(t *testing.T) {
	sd := newFakeSystemd()
	rec := &recorder{derive: collide}
	first := startDaemon(t, sd, rec, nil, nil)
	for _, s := range []struct{ name, project string }{{"shop-1", "example/shop"}, {"other-1", "other/x"}, {"shop-2", "example/shop"}} {
		if _, err := openAs(t, first, s.name, s.project, "64320"); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	first.stop()

	second := startDaemon(t, sd, rec, nil, sd.passed(t))
	if got, want := held(second), []string{"other-1", "shop-1", "shop-2"}; !slices.Equal(got, want) {
		t.Errorf("after a restart, held %v, want %v", got, want)
	}
	if _, err := openAs(t, second, "other-2", "other/x", "64320"); err != nil {
		t.Errorf("another session at the shared address: %v", err)
	}
}

// A session restored across a restart whose policy now relays a port that is
// its listener's, or 53, is dropped rather than served: the document changed
// while the daemon was down, and steer.Classify's soundness rests on no relay
// port being a listener's.
func TestAdoptionChecksRelayPorts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports func(listener uint16) string
		want  string
	}{
		{"listener", func(p uint16) string { return strconv.Itoa(int(p)) }, "is the port of its listener"},
		{"dns", func(uint16) string { return "53" }, "DNS's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := newFakeSystemd()
			first := startDaemon(t, sd, &recorder{}, nil, nil)
			info, files, ln := listeners(t, "docker-1")
			port := ln.Addr().(interface{ AddrPort() netip.AddrPort }).AddrPort().Port()
			_ = ln.Close()
			info.Params = map[string]string{"project": "example/shop", "ports": "64320"}
			_, err := control.Call(context.Background(), first.path, control.Request{Op: control.OpOpen, Session: &info}, files)
			control.CloseAll(files)
			if err != nil {
				t.Fatal(err)
			}
			first.stop()

			rec := &recorder{ports: func(control.Session) string { return tc.ports(port) }}
			second := startDaemon(t, sd, rec, nil, sd.passed(t))
			if got := held(second); len(got) != 0 {
				t.Errorf("after a restart, held %v, want none", got)
			}
			lines := second.journal.lines(t, "session not restored")
			if len(lines) != 1 {
				t.Fatalf("%d 'session not restored' lines, want 1", len(lines))
			}
			if e, _ := lines[0]["error"].(string); !strings.Contains(e, tc.want) {
				t.Errorf("session not restored for %v, want %q", lines[0], tc.want)
			}
			if n := sd.held("docker-1"); n != 0 {
				t.Errorf("systemd still holds %d descriptors of the dropped session", n)
			}
		})
	}
}

// ---------------------------------------------------------------- relay

// routed is a Dispatch whose handlers each answer with their name, and a
// relay whose Steers is the real one, for the project's address.
func routed(withRelay bool) (Dispatch, *[]string) {
	var got []string
	note := func(name string) steer.HandlerFunc {
		return func(_ context.Context, c *steer.Conn) { got = append(got, name) }
	}
	d := Dispatch{Service: []netip.Addr{service4}, Handlers: Handlers{
		Egress:    note("egress"),
		Intercept: note("intercept"),
		DNS:       dnsNoting{note("dns")},
	}}
	if withRelay {
		d.Relay = relayNoting{&relay.Handler{Address: netip.MustParseAddr("127.101.170.171")}, note("relay")}
	}
	return d, &got
}

type dnsNoting struct{ steer.HandlerFunc }

func (dnsNoting) ServePacket(context.Context, *steer.Datagram) {}

type relayNoting struct {
	*relay.Handler
	serve steer.HandlerFunc
}

func (r relayNoting) ServeConn(ctx context.Context, c *steer.Conn) { r.serve(ctx, c) }

// The relay takes what is steered to both loopbacks and the project's
// address, at any port, after DNS and before the service address: port 53
// to 127.0.0.1 is still DNS, and the service address still interception.
// Without a Docker route there is no relay, and loopback that arrived anyway
// goes to Egress, whose classifier refuses it.
func TestDispatchRoutesLoopbackToTheRelayAfterDNS(t *testing.T) {
	for _, tc := range []struct {
		orig  string
		relay bool
		want  string
	}{
		{"127.0.0.1:53", true, "dns"},
		{"[::1]:53", true, "dns"},
		{"127.101.170.171:53", true, "dns"},
		{"127.0.0.1:64320", true, "relay"},
		{"[::1]:64320", true, "relay"},
		{"[::ffff:127.0.0.1]:64320", true, "relay"},
		{"127.101.170.171:64320", true, "relay"},
		{"127.101.170.171:64399", true, "relay"}, // the relay judges the port
		{"192.0.2.2:443", true, "intercept"},
		{"192.0.2.2:53", true, "dns"},
		{"127.10.146.214:64320", true, "egress"},
		{"203.0.113.20:80", true, "egress"},
		{"127.0.0.1:64320", false, "egress"},
		{"[::1]:64320", false, "egress"},
		{"127.0.0.1:53", false, "dns"},
	} {
		d, got := routed(tc.relay)
		d.ServeConn(context.Background(), &steer.Conn{Orig: netip.MustParseAddrPort(tc.orig)})
		if len(*got) != 1 || (*got)[0] != tc.want {
			t.Errorf("relay %v, %s went to %v, want %s", tc.relay, tc.orig, *got, tc.want)
		}
	}
}

// fakeEngine is a Docker daemon on a socket that reports one running
// container of project publishing at on TCP, and counts what it is asked.
func fakeEngine(t *testing.T, project string, at netip.AddrPort) (http.RoundTripper, *atomic.Int64) {
	t.Helper()
	dir, err := os.MkdirTemp("", "frisket-serve-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix socket here: %v", err)
	}
	var asked atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"Id":     strings.Repeat("cd", 32),
			"Labels": map[string]string{"frisket.project": project},
			"State":  "running",
			"Ports":  []map[string]any{{"IP": at.Addr().String(), "PublicPort": at.Port(), "Type": "tcp"}},
		}})
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return tr, &asked
}

// standIn is an echo server on 127.0.0.2, standing in for the project's
// address on the host.
func standIn(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no 127.0.0.2 to listen on: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// realRelay gives a session the real relay, to the stand-in for its
// address, with the ports its policy names now.
func realRelay(tr http.RoundTripper, at netip.AddrPort) func(*Docker, *slog.Logger) RelayHandler {
	return func(dk *Docker, log *slog.Logger) RelayHandler {
		var ports []uint16
		for _, d := range dk.Relay {
			if !slices.Contains(ports, d.Port()) {
				ports = append(ports, d.Port())
			}
		}
		return &relay.Handler{Transport: tr, APIVersion: "1.56", Project: dk.Project, Address: at.Addr(), Ports: ports, Log: log}
	}
}

// openRelayed opens a session of shop with ports, and returns the
// address its listener is at.
func openRelayed(t *testing.T, f *daemonFixture, name, ports string) string {
	t.Helper()
	info, files, ln := listeners(t, name)
	addr := ln.Addr().String()
	_ = ln.Close()
	defer control.CloseAll(files)
	info.Params = map[string]string{"project": "example/shop", "ports": ports}
	if _, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files); err != nil {
		t.Fatal(err)
	}
	return addr
}

// echoes is whether a connection to addr carries a byte there and back.
func echoes(t *testing.T, addr string) (net.Conn, bool) {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		// A refusal quick enough to reset the dial itself.
		return nil, false
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return c, false
	}
	_, err = io.ReadFull(c, make([]byte, 1))
	return c, err == nil
}

// A relayed connection is the session's like any other: closing the session
// ends it, in flight, and its line is written.
func TestClosingASessionEndsARelayedConnection(t *testing.T) {
	at := standIn(t)
	tr, _ := fakeEngine(t, "example/shop", at)
	orig := make(chan netip.AddrPort, 4)
	f := startDaemon(t, newFakeSystemd(), &recorder{relay: realRelay(tr, at)}, func(*net.TCPConn) netip.AddrPort { return <-orig }, nil)
	addr := openRelayed(t, f, "docker-1", strconv.Itoa(int(at.Port())))

	orig <- netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), at.Port())
	c, ok := echoes(t, addr)
	if !ok {
		t.Fatal("the relayed connection did not echo")
	}
	if resp, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpClose, Name: "docker-1"}, nil); err != nil || !resp.Closed {
		t.Fatalf("close: %+v %v", resp, err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Errorf("a relayed connection survived its session's close: %v", err)
	}
	waitFor(t, "the relay line", func() bool { return len(f.journal.lines(t, "relay")) == 1 })
	if l := f.journal.lines(t, "relay")[0]; l["decision"] != relay.DecisionRelayed || l["session"] != "docker-1" {
		t.Errorf("relay line %v", l)
	}
}

// A session restored under a document that has dropped one of its ports is
// refused that port, though its ruleset still steers it, and before the
// daemon is asked; the port it kept is still relayed.
func TestARestoredSessionIsRefusedAPortItsDocumentDropped(t *testing.T) {
	at := standIn(t)
	tr, asked := fakeEngine(t, "example/shop", at)
	dropped := at.Port() + 1
	if at.Port() == 65535 {
		dropped = at.Port() - 1
	}
	sd := newFakeSystemd()
	first := startDaemon(t, sd, &recorder{relay: realRelay(tr, at)}, nil, nil)
	addr := openRelayed(t, first, "docker-1", strconv.Itoa(int(at.Port()))+","+strconv.Itoa(int(dropped)))
	first.stop()

	orig := make(chan netip.AddrPort, 4)
	rec := &recorder{relay: realRelay(tr, at), ports: func(control.Session) string { return strconv.Itoa(int(at.Port())) }}
	second := startDaemon(t, sd, rec, func(*net.TCPConn) netip.AddrPort { return <-orig }, sd.passed(t))
	if st := second.d.List(); len(st) != 1 || !st[0].Restored {
		t.Fatalf("after a restart: %+v", st)
	}

	orig <- netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dropped)
	if _, ok := echoes(t, addr); ok {
		t.Error("a dropped port was relayed")
	}
	waitFor(t, "the refusal", func() bool { return len(second.journal.lines(t, "relay")) == 1 })
	if l := second.journal.lines(t, "relay")[0]; l["decision"] != relay.DecisionRefused || l["reason"] != relay.ReasonNotAPort {
		t.Errorf("a dropped port's line: %v", l)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the daemon was asked %d times about a dropped port", n)
	}

	orig <- netip.AddrPortFrom(netip.MustParseAddr("::1"), at.Port())
	if _, ok := echoes(t, addr); !ok {
		t.Error("the port the document kept was not relayed after the restore")
	}
}
