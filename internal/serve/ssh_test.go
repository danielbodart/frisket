package serve

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/steer"
)

// openSSH opens a session whose policy gives it SSH routes at dests, with
// params beside them, and returns the answer and the session's TCP
// listener's address.
func openSSH(t *testing.T, f *daemonFixture, name, dests string, params map[string]string) (control.Response, string, error) {
	t.Helper()
	info, files, ln := listeners(t, name)
	addr := ln.Addr().String()
	_ = ln.Close()
	defer control.CloseAll(files)
	info.Params = map[string]string{"ssh": dests}
	for k, v := range params {
		info.Params[k] = v
	}
	resp, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
	return resp, addr, err
}

// Open answers with an SSH route's destinations in the relay's list, after
// the Docker project's, and with the sandbox's two files; a session with no
// SSH route is given neither file.
func TestOpenAnswersWithSSHDestinationsAndTheirFiles(t *testing.T) {
	f := startDaemon(t, newFakeSystemd(), &recorder{}, nil, nil)
	resp, _, err := openSSH(t, f, "ssh-1", "10.0.0.5:22,[fd00::5]:2222", map[string]string{"project": "example/shop", "ports": "64320"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:64320", "127.101.170.171:64320", "[::1]:64320", "10.0.0.5:22", "[fd00::5]:2222"}
	if !slices.Equal(resp.Relay, want) {
		t.Errorf("open answered relay %v, want %v", resp.Relay, want)
	}
	if !strings.HasPrefix(string(resp.SSHKnownHosts), "@cert-authority ") || string(resp.SSHConfig) != "Host server\n" {
		t.Errorf("open answered known_hosts %q and ssh_config %q", resp.SSHKnownHosts, resp.SSHConfig)
	}

	resp, err = openAs(t, f, "plain-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.SSHKnownHosts != nil || resp.SSHConfig != nil {
		t.Errorf("a session with no SSH route was answered %q and %q", resp.SSHKnownHosts, resp.SSHConfig)
	}
}

// An SSH route the session's own listeners, its DNS or its service address
// would take first refuses the session, before systemd is told of it: the
// store keeps a route off loopback and the default service address, and
// this is the same check against what the session was really given.
func TestOpenRefusesAnSSHRouteAtAListenerDNSOrTheServiceAddress(t *testing.T) {
	sd := newFakeSystemd()
	f := startDaemon(t, sd, &recorder{}, nil, nil)
	for _, tc := range []struct {
		name  string
		dests func(listener string) string
		want  string
	}{
		{"a listener's", func(l string) string { return l }, "is its listener"},
		{"DNS's port", func(string) string { return "10.0.0.5:53" }, "DNS's port"},
		{"the v4 service address", func(string) string { return "192.0.2.2:22" }, "service address"},
		{"the v6 service address", func(string) string { return "[2001:db8::2]:22" }, "service address"},
		{"the service address, mapped", func(string) string { return "[::ffff:192.0.2.2]:22" }, "service address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, files, ln := listeners(t, "ssh-2")
			l := ln.Addr().String()
			_ = ln.Close()
			info.Params = map[string]string{"ssh": tc.dests(l)}
			_, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
			control.CloseAll(files)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
	if told := sd.told(); len(told) != 0 {
		t.Errorf("systemd was told %v about refused sessions", told)
	}
	if got := held(f); len(got) != 0 {
		t.Errorf("refused sessions are held: %v", got)
	}
}

// Destinations with nothing to serve them would fall to Egress: the policy
// that gives them so is refused, as one with no egress handler is.
func TestOpenRefusesSSHRoutesWithNoHandler(t *testing.T) {
	f := startDaemon(t, newFakeSystemd(), &recorder{noSSHHandler: true}, nil, nil)
	if _, _, err := openSSH(t, f, "ssh-3", "10.0.0.5:22", nil); err == nil || !strings.Contains(err.Error(), "without their handler") {
		t.Errorf("err = %v", err)
	}
}

// A session restored under a document whose SSH route is now at its
// service address is dropped rather than served, as one whose relayed port
// became its listener's is.
func TestAdoptionChecksSSHDestinations(t *testing.T) {
	sd := newFakeSystemd()
	first := startDaemon(t, sd, &recorder{}, nil, nil)
	if _, _, err := openSSH(t, first, "ssh-4", "10.0.0.5:22", nil); err != nil {
		t.Fatal(err)
	}
	first.stop()

	rec := &recorder{sshDests: func(control.Session) string { return "192.0.2.2:22" }}
	second := startDaemon(t, sd, rec, nil, sd.passed(t))
	if got := held(second); len(got) != 0 {
		t.Errorf("after a restart, held %v, want none", got)
	}
	lines := second.journal.lines(t, "session not restored")
	if len(lines) != 1 {
		t.Fatalf("%d 'session not restored' lines, want 1", len(lines))
	}
	if e, _ := lines[0]["error"].(string); !strings.Contains(e, "service address") {
		t.Errorf("session not restored for %v", lines[0])
	}
}

// A restored session's SSH route is still served by SSH, under the
// document as it reads now.
func TestARestoredSessionsSSHRouteIsStillServed(t *testing.T) {
	sd := newFakeSystemd()
	first := startDaemon(t, sd, &recorder{}, nil, nil)
	_, addr, err := openSSH(t, first, "ssh-5", "10.0.0.5:22", nil)
	if err != nil {
		t.Fatal(err)
	}
	first.stop()

	orig := make(chan netip.AddrPort, 2)
	second := startDaemon(t, sd, &recorder{}, func(*net.TCPConn) netip.AddrPort { return <-orig }, sd.passed(t))
	if st := second.d.List(); len(st) != 1 || !st[0].Restored {
		t.Fatalf("after a restart: %+v", st)
	}
	for _, tc := range []struct{ orig, want string }{
		{"10.0.0.5:22", "ssh"},
		// Another port of the same private address is not the route.
		{"10.0.0.5:2222", "egress"},
	} {
		orig <- netip.MustParseAddrPort(tc.orig)
		if got := answer(t, addr); got != tc.want {
			t.Errorf("%s went to %q, want %q", tc.orig, got, tc.want)
		}
	}
}

// answer is the line a connection to addr is answered with: the name of
// the handler it reached.
func answer(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// An SSH route's exact address and port go to SSH, after DNS and before
// everything else: port 53 is DNS's whatever the address, and another port
// of the route's address, or another address, is Egress's, which refuses a
// private one structurally.
func TestDispatchRoutesAnSSHRoutesDestinationToSSHAfterDNS(t *testing.T) {
	for _, tc := range []struct {
		orig string
		ssh  bool
		want string
	}{
		{"10.0.0.5:22", true, "ssh"},
		{"[::ffff:10.0.0.5]:22", true, "ssh"},
		{"[fd00::5]:2222", true, "ssh"},
		{"10.0.0.5:2222", true, "egress"},
		{"10.0.0.6:22", true, "egress"},
		{"10.0.0.5:53", true, "dns"},
		{"127.0.0.1:64320", true, "relay"},
		{"192.0.2.2:443", true, "intercept"},
		{"10.0.0.5:22", false, "egress"},
	} {
		d, got := routed(true)
		if tc.ssh {
			dests := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.5:22"), netip.MustParseAddrPort("[fd00::5]:2222")}
			d.SSH = sshNoting{dests: dests, serve: func(context.Context, *steer.Conn) { *got = append(*got, "ssh") }}
		}
		d.ServeConn(context.Background(), &steer.Conn{Orig: netip.MustParseAddrPort(tc.orig)})
		if len(*got) != 1 || (*got)[0] != tc.want {
			t.Errorf("ssh %v, %s went to %v, want %s", tc.ssh, tc.orig, *got, tc.want)
		}
	}
}
