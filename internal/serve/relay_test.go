package serve

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
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
	resp, err := openAs(t, f, "docker-1", "triptease/data-lab", "64320,64321")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"127.0.0.1:64320", "127.1.191.78:64320", "[::1]:64320",
		"127.0.0.1:64321", "127.1.191.78:64321", "[::1]:64321",
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
	info.Params = map[string]string{"project": "triptease/data-lab", "ports": "64320," + strconv.Itoa(int(port))}
	_, err := control.Call(context.Background(), f.path, control.Request{Op: control.OpOpen, Session: &info}, files)
	control.CloseAll(files)
	if err == nil || !strings.Contains(err.Error(), "is the port of its listener") {
		t.Errorf("a relay port that is the listener's: err = %v", err)
	}

	if _, err := openAs(t, f, "docker-3", "triptease/data-lab", "53"); err == nil || !strings.Contains(err.Error(), "DNS's") {
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
func collide(string) netip.Addr { return netip.MustParseAddr("127.1.191.78") }

// Two projects never share an address: a session whose project's address a
// session of another project holds is refused, before systemd is told of it.
// Two sessions of one project share theirs, as they share its objects.
func TestOpenRefusesAnAddressAnotherProjectHolds(t *testing.T) {
	sd := newFakeSystemd()
	f := startDaemon(t, sd, &recorder{derive: collide}, nil, nil)
	if _, err := openAs(t, f, "data-lab-1", "triptease/data-lab", "64320"); err != nil {
		t.Fatal(err)
	}
	stored := sd.told()

	_, err := openAs(t, f, "evil-1", "evil/x", "64320")
	if err == nil || !strings.Contains(err.Error(), "address held by another project") {
		t.Errorf("another project at a held address: err = %v", err)
	}
	if told := sd.told(); !slices.Equal(told, stored) {
		t.Errorf("systemd was told %v about the refused session", told[len(stored):])
	}

	if _, err := openAs(t, f, "data-lab-2", "triptease/data-lab", "64320"); err != nil {
		t.Errorf("a second session of the same project: %v", err)
	}
	// One with no Docker route holds no address, and is held off none.
	if _, err := openAs(t, f, "plain-2", "", ""); err != nil {
		t.Errorf("a session with no Docker route: %v", err)
	}
	if got, want := held(f), []string{"data-lab-1", "data-lab-2", "plain-2"}; !slices.Equal(got, want) {
		t.Errorf("held %v, want %v", got, want)
	}

	// Once every session of the project is closed, its address is free.
	for _, name := range []string{"data-lab-1", "data-lab-2"} {
		if _, err := f.d.Close(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openAs(t, f, "evil-2", "evil/x", "64320"); err != nil {
		t.Errorf("another project, once the address is free: %v", err)
	}
}

// A session restored across a restart holds its project's address as one
// opened by this process does.
func TestAnAdoptedSessionHoldsItsAddressToo(t *testing.T) {
	sd := newFakeSystemd()
	rec := &recorder{derive: collide}
	first := startDaemon(t, sd, rec, nil, nil)
	if _, err := openAs(t, first, "data-lab-1", "triptease/data-lab", "64320"); err != nil {
		t.Fatal(err)
	}
	first.stop()

	second := startDaemon(t, sd, rec, nil, sd.passed(t))
	if st := second.d.List(); len(st) != 1 || !st[0].Restored {
		t.Fatalf("after a restart: %+v", st)
	}
	if _, err := openAs(t, second, "evil-1", "evil/x", "64320"); err == nil || !strings.Contains(err.Error(), "address held by another project") {
		t.Errorf("another project at an adopted session's address: err = %v", err)
	}
	if _, err := openAs(t, second, "data-lab-2", "triptease/data-lab", "64320"); err != nil {
		t.Errorf("a second session of the adopted one's project: %v", err)
	}
}

// Of two stored sessions of different projects at one address, the second
// adopted is dropped rather than served beside the first: the documents
// changed while the daemon was down, and I10 holds whatever order they come
// back in.
func TestAdoptionRefusesAnAddressAnotherAdoptedProjectHolds(t *testing.T) {
	sd := newFakeSystemd()
	first := startDaemon(t, sd, &recorder{}, nil, nil)
	for _, s := range []struct{ name, project string }{{"data-lab-1", "triptease/data-lab"}, {"evil-1", "evil/x"}} {
		if _, err := openAs(t, first, s.name, s.project, "64320"); err != nil {
			t.Fatal(err)
		}
	}
	first.stop()

	second := startDaemon(t, sd, &recorder{derive: collide}, nil, sd.passed(t))
	if got := held(second); len(got) != 1 {
		t.Fatalf("after a restart at one address, held %v, want one of them", got)
	}
	if n := len(second.journal.lines(t, "session not restored")); n != 1 {
		t.Errorf("%d 'session not restored' lines, want 1", n)
	}
	var stored int
	for _, name := range []string{"data-lab-1", "evil-1"} {
		if sd.held(name) > 0 {
			stored++
		}
	}
	if stored != 1 {
		t.Errorf("systemd still holds %d of the two sessions, want only the one restored", stored)
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
			info.Params = map[string]string{"project": "triptease/data-lab", "ports": "64320"}
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
