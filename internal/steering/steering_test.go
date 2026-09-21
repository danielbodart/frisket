package steering

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/nsmount"
	"github.com/danielbodart/frisket/internal/nsnet"
)

const ruleset = "table inet frisket {\n}\n"

func allFile() File {
	return File{
		Set:        "all",
		Table:      "frisket",
		Listeners:  []string{"tcp4:127.0.0.1:15001", "tcp6:[::1]:15001", "udp4:127.0.0.1:53", "udp6:[::1]:53"},
		Ruleset:    ruleset,
		Service:    []string{"192.0.2.2", "2001:db8::2"},
		Mark:       1,
		RouteTable: 100,
		Dummy:      &Dummy{Interface: "frisket0", Addresses: []string{"192.0.2.1", "2001:db8::1"}},
	}
}

func TestPlanRefusesAFileThatWouldSteerBadly(t *testing.T) {
	if _, err := allFile().Plan(); err != nil {
		t.Fatalf("the default `all` file was refused: %v", err)
	}
	svc := allFile()
	svc.Set, svc.Dummy = "service", nil
	if _, err := svc.Plan(); err != nil {
		t.Fatalf("the default `service` file was refused: %v", err)
	}
	for name, mutate := range map[string]func(*File){
		"an unknown set":              func(f *File) { f.Set = "most" },
		"a ruleset without its table": func(f *File) { f.Ruleset = "table inet other {\n}\n" },
		"a missing family's listener": func(f *File) { f.Listeners = f.Listeners[:3] },
		"two TCP listeners in one family": func(f *File) {
			f.Listeners = append(f.Listeners, "tcp4:127.0.0.1:15002")
		},
		"a listener off loopback, where tproxy never sends": func(f *File) {
			f.Listeners[0] = "tcp4:192.0.2.1:15001"
		},
		// PKTINFO sets a reply's source address and not its port.
		"a UDP listener off the port it answers from": func(f *File) { f.Listeners[2] = "udp4:127.0.0.1:15353" },
		// TCP DNS to 127.0.0.1:53 would look like a direct connection.
		"a TCP listener on a port the ruleset steers": func(f *File) { f.Listeners[0] = "tcp4:127.0.0.1:53" },
		"a mark every unmarked packet has":            func(f *File) { f.Mark = 0 },
		"the kernel's main table":                     func(f *File) { f.RouteTable = 254 },
		"no route table":                              func(f *File) { f.RouteTable = 0 },
		"one service address":                         func(f *File) { f.Service = f.Service[:1] },
		"`all` with no dummy":                         func(f *File) { f.Dummy = nil },
		"a dummy with a route and no v6":              func(f *File) { f.Dummy.Addresses = f.Dummy.Addresses[:1] },
		// A route alone half-works: IPv4 picks source 0.0.0.0 and IPv6 hangs.
		// A link-local address is not picked as a source for a global
		// destination either.
		"a link-local dummy address": func(f *File) { f.Dummy.Addresses[1] = "fe80::1" },
		"a dummy on the service address": func(f *File) {
			f.Dummy.Addresses[0] = "192.0.2.2"
		},
		"`service` with a dummy fighting pasta's route": func(f *File) { f.Set = "service" },
		"an interface name nft would split":             func(f *File) { f.Dummy.Interface = "a b" },
	} {
		f := allFile()
		mutate(&f)
		if _, err := f.Plan(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The service address before anything else, the dummy's routes after
// everything else: the routes ARE the egress.
func TestConnectBatchPutsTheRoutesLast(t *testing.T) {
	p, err := allFile().Plan()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(p.ConnectBatch()), "\n")
	want := []string{
		"address add 192.0.2.2/32 dev lo",
		"address add 2001:db8::2/128 dev lo",
		"link add frisket0 type dummy",
		"address add 192.0.2.1/32 dev frisket0",
		"address add 2001:db8::1/128 dev frisket0 nodad",
		"link set frisket0 up",
		"route add 0.0.0.0/0 dev frisket0",
		"route add ::/0 dev frisket0",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("batch =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	f := allFile()
	f.Set, f.Dummy = "service", nil
	sp, _ := f.Plan()
	if got := sp.ConnectBatch(); strings.Contains(got, "route") || strings.Contains(got, "dummy") {
		t.Errorf("the `service` set provisions egress of its own:\n%s", got)
	}
}

// fakeRoot records the steps a Steerer takes, in order, and fails the one it
// is told to.
type fakeRoot struct {
	steps   []string
	fail    string
	held    []control.Status
	links   string
	rules   string
	routes  string
	mounted []nsmount.File
}

func (f *fakeRoot) steerer() *Steerer {
	return &Steerer{
		open: func(_ context.Context, args nsnet.HelperArgs) (*nsnet.Set, error) {
			f.steps = append(f.steps, "listeners")
			if !args.Isolated {
				f.steps = append(f.steps, "NOT-ISOLATED")
			}
			if f.fail == "listeners" {
				return nil, errors.New("bind 127.0.0.1:15001: address already in use")
			}
			return &nsnet.Set{Netns: "net:[1]"}, nil
		},
		call: func(_ context.Context, req control.Request, files []*os.File) (control.Response, error) {
			f.steps = append(f.steps, "daemon "+req.Op)
			if f.fail == "daemon "+req.Op {
				return control.Response{}, errors.New("refused")
			}
			return control.Response{Sessions: f.held, Closed: true, CACert: []byte("the session's CA\n")}, nil
		},
		mount: func(mntns, dir string, files []nsmount.File) error {
			step := "mount " + mntns + " " + dir
			f.steps = append(f.steps, step)
			if f.fail == "mount" {
				return errors.New("failed")
			}
			f.mounted = files
			return nil
		},
		run: func(_ context.Context, netns, stdin, program string, args ...string) (string, error) {
			step := program + " " + strings.Join(args, " ")
			f.steps = append(f.steps, step)
			if f.fail == step {
				return "", errors.New("failed")
			}
			switch step {
			case "ip -o link show":
				return f.links, nil
			case "ip -4 rule show", "ip -6 rule show":
				return f.rules, nil
			case "ip -4 route show table 100", "ip -6 route show table 100":
				return f.routes, nil
			}
			return "", nil
		},
	}
}

// roots is a host CA bundle for a test: any certificate will do.
func roots(t *testing.T) (path string, pem []byte) {
	t.Helper()
	ca, err := intercept.NewCA([]string{"root.test"})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "ca-bundle.crt")
	if err := os.WriteFile(path, ca.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, ca.CertPEM()
}

// The sandbox is given the CA the daemon made for its session, and the host's
// roots with it; and without the roots nothing is made at all.
func TestSteerGivesTheSandboxItsCAAndTheRootsWithIt(t *testing.T) {
	p, _ := allFile().Plan()
	rootsPath, rootsPEM := roots(t)
	f := &fakeRoot{}
	if err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: rootsPath}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		CACertFile:   "the session's CA\n",
		CABundleFile: string(rootsPEM) + "the session's CA\n",
	}
	if len(f.mounted) != len(want) {
		t.Fatalf("mounted %d files", len(f.mounted))
	}
	for _, m := range f.mounted {
		if want[m.Name] != string(m.Data) {
			t.Errorf("%s = %q, want %q", m.Name, m.Data, want[m.Name])
		}
	}

	f = &fakeRoot{}
	err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: filepath.Join(t.TempDir(), "missing")})
	if err == nil || len(f.steps) != 0 {
		t.Fatalf("steer without the host's roots: %v, steps %v", err, f.steps)
	}
}

func TestSteerInstallsRulesOnlyOnceTheDaemonHoldsTheListeners(t *testing.T) {
	p, _ := allFile().Plan()
	rootsPath, _ := roots(t)
	sess := Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: rootsPath}
	mount := "mount /proc/1/ns/mnt /etc/frisket"
	for _, c := range []struct {
		fail string
		want []string
	}{
		{"", []string{"listeners", "daemon open", "ip -4 -batch -", "ip -6 -batch -", "nft -f -", mount}},
		// A workload that took the port first: no listener, so no rules.
		{"listeners", []string{"listeners"}},
		// The daemon refused (an unknown policy, say): no rules either.
		{"daemon open", []string{"listeners", "daemon open"}},
		// The routing or the rules failed: the session they were for is closed.
		{"ip -6 -batch -", []string{"listeners", "daemon open", "ip -4 -batch -", "ip -6 -batch -", "daemon close"}},
		{"nft -f -", []string{"listeners", "daemon open", "ip -4 -batch -", "ip -6 -batch -", "nft -f -", "daemon close"}},
		// A sandbox that cannot be given its CA is closed, not run without it.
		{"mount", []string{"listeners", "daemon open", "ip -4 -batch -", "ip -6 -batch -", "nft -f -", mount, "daemon close"}},
	} {
		f := &fakeRoot{fail: c.fail}
		err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess)
		if (err != nil) != (c.fail != "") {
			t.Errorf("failing %q: err = %v", c.fail, err)
		}
		if strings.Join(f.steps, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("failing %q: steps = %v, want %v", c.fail, f.steps, c.want)
		}
		if err != nil && c.fail != "nft -f -" && c.fail != "ip -6 -batch -" && c.fail != "mount" && !strings.Contains(err.Error(), "no rules were installed") {
			t.Errorf("failing %q: the error does not say no rules were installed: %v", c.fail, err)
		}
	}
}

const loOnly = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"

func TestNonLoopbackReadsIPLinkOutput(t *testing.T) {
	out := loOnly + "2: frisket0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500\n3: eth0@if9: <UP> mtu 1500\n"
	if got := strings.Join(nonLoopback(out), ","); got != "frisket0,eth0" {
		t.Errorf("nonLoopback = %q", got)
	}
	if got := nonLoopback(loOnly); len(got) != 0 {
		t.Errorf("lo alone gave %v", got)
	}
}

func TestConnectRefusesToRunOutOfTurn(t *testing.T) {
	p, _ := allFile().Plan()
	here, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Skip(err)
	}
	ours := []control.Status{{Session: control.Session{Name: "s", Netns: here}}}
	const rules = "0:\tfrom all lookup local\n32765:\tfrom all fwmark 0x1 lookup 100\n32766:\tfrom all lookup main\n"
	const routes = "local default dev lo scope host\n"
	checks := []string{"daemon list", "nft list table inet frisket",
		"ip -4 rule show", "ip -4 route show table 100", "ip -6 rule show", "ip -6 route show table 100"}
	for _, c := range []struct {
		name string
		f    fakeRoot
		want []string
		ok   bool
	}{
		{"in order", fakeRoot{held: ours, links: loOnly, rules: rules, routes: routes}, append(checks, "ip -o link show", "ip -batch -"), true},
		// Something provisioned egress between steer and connect.
		{"after something else gave it egress", fakeRoot{held: ours, rules: rules, routes: routes, links: loOnly + "2: eth0@if7: <BROADCAST,MULTICAST> mtu 1500\n"}, append(checks, "ip -o link show"), false},
		{"before steer", fakeRoot{}, []string{"daemon list"}, false},
		{"another namespace's session", fakeRoot{held: []control.Status{{Session: control.Session{Name: "s", Netns: "net:[1]"}}}}, []string{"daemon list"}, false},
		{"before the rules", fakeRoot{held: ours, fail: "nft list table inet frisket"}, []string{"daemon list", "nft list table inet frisket"}, false},
		// Marks with nowhere to go: in `service`, out through pasta.
		{"without the mark's rule", fakeRoot{held: ours, links: loOnly, rules: "32766:\tfrom all lookup main\n", routes: routes}, checks[:3], false},
		{"without the table's route", fakeRoot{held: ours, links: loOnly, rules: rules}, checks[:4], false},
	} {
		err := c.f.steerer().Connect(context.Background(), "/proc/self/ns/net", p, "s")
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if strings.Join(c.f.steps, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("%s: steps = %v, want %v", c.name, c.f.steps, c.want)
		}
	}
}

func TestRoutingBatchSendsTheMarkBackOntoLoopback(t *testing.T) {
	p, err := allFile().Plan()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.RoutingBatch(false), "rule add fwmark 1 lookup 100\nroute add local 0.0.0.0/0 dev lo table 100\n"; got != want {
		t.Errorf("v4 batch =\n%s\nwant\n%s", got, want)
	}
	if got, want := p.RoutingBatch(true), "rule add fwmark 1 lookup 100\nroute add local ::/0 dev lo table 100\n"; got != want {
		t.Errorf("v6 batch =\n%s\nwant\n%s", got, want)
	}
}

func TestTheRoutingReadersReadIPOutput(t *testing.T) {
	for out, want := range map[string]bool{
		"32765:\tfrom all fwmark 0x1 lookup 100\n": true,
		"32765:\tfrom all fwmark 0x2 lookup 100\n": false,
		"32765:\tfrom all fwmark 0x1 lookup 101\n": false,
		"32766:\tfrom all lookup main\n":           false,
	} {
		if got := hasMarkRule(out, 1, 100); got != want {
			t.Errorf("hasMarkRule(%q) = %v", out, got)
		}
	}
	for out, want := range map[string]bool{
		"local default dev lo scope host\n":              true,
		"local default dev lo metric 1024 pref medium\n": true,
		"default dev frisket0 scope link\n":              false,
		"":                                               false,
	} {
		if got := hasLocalDefault(out); got != want {
			t.Errorf("hasLocalDefault(%q) = %v", out, got)
		}
	}
}
