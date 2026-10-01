package steering

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/intercept"
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
func TestConnectStepsPutTheRoutesLast(t *testing.T) {
	p, err := allFile().Plan()
	if err != nil {
		t.Fatal(err)
	}
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
	if got := spell(p.ConnectSteps()); got != strings.Join(want, "\n") {
		t.Errorf("steps =\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}

	f := allFile()
	f.Set, f.Dummy = "service", nil
	sp, _ := f.Plan()
	if got := spell(sp.ConnectSteps()); strings.Contains(got, "route add") || strings.Contains(got, "dummy") {
		t.Errorf("the `service` set provisions egress of its own:\n%s", got)
	}
	// route_localnet, for what pasta forwards in, in `service` alone: `all`
	// has no network for anything to come in by.
	if got := spell(sp.ConnectSteps()); !strings.HasSuffix(got, "\nsysctl net.ipv4.conf.all.route_localnet=1") {
		t.Errorf("the `service` set does not set route_localnet last:\n%s", got)
	}
	if got := spell(p.ConnectSteps()); strings.Contains(got, "route_localnet") {
		t.Errorf("the `all` set sets route_localnet:\n%s", got)
	}
}

func spell(steps []Step) string {
	lines := make([]string, len(steps))
	for i, st := range steps {
		lines[i] = st.String()
	}
	return strings.Join(lines, "\n")
}

// fakeRoot records the steps a Steerer takes, in order, and fails the one it
// is told to.
type fakeRoot struct {
	steps   []string
	fail    string
	held    []control.Status
	links   []string
	rules   []ruleInfo
	routes  []routeInfo
	mounted request
	// relay is what the fake daemon answers open with, and loaded the
	// ruleset the helper was given.
	relay  []string
	loaded string
}

// The steps' names, as the tests below spell them.
const (
	routing = "apply rule add fwmark 1 lookup 100"
	connect = "apply address add 192.0.2.2/32 dev lo"
	mount   = "mount /proc/1/ns/mnt /etc/frisket"
)

func (f *fakeRoot) name(r request) string {
	switch r.Op {
	case opApply:
		return "apply " + r.Steps[0].String()
	case opMount:
		return "mount " + r.Mntns + " " + r.Dir
	case opTable:
		return "table inet " + r.Name
	case opRules, opRoutes:
		return r.Op + " " + family(r.V6)
	}
	return r.Op
}

func (f *fakeRoot) Do(_ context.Context, req, result any) error {
	r := req.(request)
	step := f.name(r)
	f.steps = append(f.steps, step)
	if f.fail == step {
		return errors.New("failed")
	}
	switch r.Op {
	case opMount:
		f.mounted = r
	case opRuleset:
		f.loaded = r.Ruleset
	case opLinks:
		*result.(*[]string) = f.links
	case opRules:
		*result.(*[]ruleInfo) = f.rules
	case opRoutes:
		*result.(*[]routeInfo) = f.routes
	}
	return nil
}

func (f *fakeRoot) Close() error { return nil }

func (f *fakeRoot) steerer() *Steerer {
	return &Steerer{
		// Any executable will do: it is only resolved.
		Nft: "/proc/self/exe",
		enter: func(_ context.Context, args nsnet.HelperArgs) (*nsnet.Set, inside, error) {
			if len(args.Specs) == 0 {
				f.steps = append(f.steps, "enter")
				return &nsnet.Set{Netns: "net:[1]"}, f, nil
			}
			f.steps = append(f.steps, "listeners")
			if !args.Isolated {
				f.steps = append(f.steps, "NOT-ISOLATED")
			}
			if f.fail == "listeners" {
				return nil, nil, errors.New("bind 127.0.0.1:15001: address already in use")
			}
			return &nsnet.Set{Netns: "net:[1]"}, f, nil
		},
		call: func(_ context.Context, req control.Request, files []*os.File) (control.Response, error) {
			f.steps = append(f.steps, "daemon "+req.Op)
			if f.fail == "daemon "+req.Op {
				return control.Response{}, errors.New("refused")
			}
			return control.Response{Sessions: f.held, Closed: true, CACert: []byte("the session's CA\n"), Relay: f.relay}, nil
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
	if string(f.mounted.CACert) != "the session's CA\n" || f.mounted.Roots != rootsPath {
		t.Fatalf("asked to mount %q with the roots at %s", f.mounted.CACert, f.mounted.Roots)
	}
	files, err := caFiles(f.mounted.Roots, f.mounted.CACert)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		CACertFile:   "the session's CA\n",
		CABundleFile: string(rootsPEM) + "the session's CA\n",
	}
	if len(files) != len(want) {
		t.Fatalf("mounted %d files", len(files))
	}
	for _, m := range files {
		if want[m.Name] != string(m.Data) {
			t.Errorf("%s = %q, want %q", m.Name, m.Data, want[m.Name])
		}
	}

	f = &fakeRoot{}
	err = f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: filepath.Join(t.TempDir(), "missing")})
	if err == nil || len(f.steps) != 0 {
		t.Fatalf("steer without the host's roots: %v, steps %v", err, f.steps)
	}

	// Roots that hold no certificate would give a bundle trusting only the
	// intercepted hosts.
	empty := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(empty, []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := caFiles(empty, []byte("the session's CA\n")); err == nil {
		t.Error("a bundle was made from roots with no certificates")
	}
}

func TestSteerInstallsRulesOnlyOnceTheDaemonHoldsTheListeners(t *testing.T) {
	p, _ := allFile().Plan()
	rootsPath, _ := roots(t)
	sess := Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: rootsPath}
	for _, c := range []struct {
		fail string
		want []string
	}{
		{"", []string{"listeners", "daemon open", routing, "ruleset", mount}},
		// A workload that took the port first: no listener, so no rules.
		{"listeners", []string{"listeners"}},
		// The daemon refused (an unknown policy, say): no rules either.
		{"daemon open", []string{"listeners", "daemon open"}},
		// The routing or the rules failed: the session they were for is closed.
		{routing, []string{"listeners", "daemon open", routing, "daemon close"}},
		{"ruleset", []string{"listeners", "daemon open", routing, "ruleset", "daemon close"}},
		// A sandbox that cannot be given its CA is closed, not run without it.
		{mount, []string{"listeners", "daemon open", routing, "ruleset", mount, "daemon close"}},
	} {
		f := &fakeRoot{fail: c.fail}
		err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess)
		if (err != nil) != (c.fail != "") {
			t.Errorf("failing %q: err = %v", c.fail, err)
		}
		if strings.Join(f.steps, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("failing %q: steps = %v, want %v", c.fail, f.steps, c.want)
		}
		if err != nil && c.fail != "ruleset" && c.fail != routing && c.fail != mount && !strings.Contains(err.Error(), "no rules were installed") {
			t.Errorf("failing %q: the error does not say no rules were installed: %v", c.fail, err)
		}
	}
}

// Both families, each a rule and its table's one route.
func TestRoutingStepsSendTheMarkBackOntoLoopback(t *testing.T) {
	p, err := allFile().Plan()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := spell(p.RoutingSteps(false)), "rule add fwmark 1 lookup 100\nroute add local 0.0.0.0/0 dev lo table 100"; got != want {
		t.Errorf("v4 steps =\n%s\nwant\n%s", got, want)
	}
	if got, want := spell(p.RoutingSteps(true)), "rule add fwmark 1 lookup 100\nroute add local ::/0 dev lo table 100"; got != want {
		t.Errorf("v6 steps =\n%s\nwant\n%s", got, want)
	}
	for _, v6 := range []bool{false, true} {
		if st := p.RoutingSteps(v6)[0]; st.V6 != v6 {
			t.Errorf("the %s rule is for the other family", family(v6))
		}
	}
}

func TestNonLoopbackIsEverythingButLo(t *testing.T) {
	if got := strings.Join(nonLoopback([]string{"lo", "frisket0", "eth0"}), ","); got != "frisket0,eth0" {
		t.Errorf("nonLoopback = %q", got)
	}
	if got := nonLoopback([]string{"lo"}); len(got) != 0 {
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
	rules := []ruleInfo{{Table: 255, Mask: ^uint32(0)}, {Mark: 1, Mask: ^uint32(0), Table: 100}, {Table: 254, Mask: ^uint32(0)}}
	routes := []routeInfo{{Local: true, Default: true, Dev: "lo"}}
	lo := []string{"lo"}
	checks := []string{"daemon list", "enter", "table inet frisket",
		"rules -4", "routes -4", "rules -6", "routes -6"}
	for _, c := range []struct {
		name string
		f    fakeRoot
		want []string
		ok   bool
	}{
		{"in order", fakeRoot{held: ours, links: lo, rules: rules, routes: routes}, append(checks, "links", connect), true},
		// Something provisioned egress between steer and connect.
		{"after something else gave it egress", fakeRoot{held: ours, rules: rules, routes: routes, links: []string{"lo", "eth0"}}, append(checks, "links"), false},
		{"before steer", fakeRoot{}, []string{"daemon list"}, false},
		{"another namespace's session", fakeRoot{held: []control.Status{{Session: control.Session{Name: "s", Netns: "net:[1]"}}}}, []string{"daemon list"}, false},
		{"before the rules", fakeRoot{held: ours, fail: "table inet frisket"}, checks[:3], false},
		// Marks with nowhere to go: in `service`, out through pasta.
		{"without the mark's rule", fakeRoot{held: ours, links: lo, rules: rules[2:], routes: routes}, checks[:4], false},
		// Part of the mark is not the mark.
		{"with the mark under a mask", fakeRoot{held: ours, links: lo, rules: []ruleInfo{{Mark: 1, Mask: 0xff, Table: 100}}, routes: routes}, checks[:4], false},
		{"without the table's route", fakeRoot{held: ours, links: lo, rules: rules}, checks[:5], false},
		{"with the table's default route not local", fakeRoot{held: ours, links: lo, rules: rules, routes: []routeInfo{{Default: true, Dev: "lo"}}}, checks[:5], false},
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

// A ruleset with the relay's sets, as lib.steering writes them.
const relayRuleset = `table inet frisket {
  set relay4 { type ipv4_addr . inet_service; }
  set relay6 { type ipv6_addr . inet_service; }
  chain steer {
  }
}
`

// The relay's destinations the daemon answers open with go into the
// ruleset's sets in the one load that brings the rules, each family in its
// own set; with none, the ruleset loaded is the file's, byte for byte.
func TestSteerFillsTheRelaySetsInTheSameLoadAsTheRules(t *testing.T) {
	rootsPath, _ := roots(t)
	sess := Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: rootsPath}
	file := allFile()
	file.Ruleset = relayRuleset
	p, err := file.Plan()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRoot{relay: []string{
		"127.0.0.1:64320", "127.101.170.171:64320", "[::1]:64320",
		"127.0.0.1:64321", "127.101.170.171:64321", "[::1]:64321",
	}}
	if err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess); err != nil {
		t.Fatal(err)
	}
	want := relayRuleset +
		"add element inet frisket relay4 { 127.0.0.1 . 64320, 127.101.170.171 . 64320, 127.0.0.1 . 64321, 127.101.170.171 . 64321 }\n" +
		"add element inet frisket relay6 { ::1 . 64320, ::1 . 64321 }\n"
	if f.loaded != want {
		t.Errorf("loaded\n%s\nwant\n%s", f.loaded, want)
	}

	for _, rs := range []string{relayRuleset, ruleset} {
		file.Ruleset = rs
		p, err := file.Plan()
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeRoot{}
		if err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess); err != nil {
			t.Fatal(err)
		}
		if f.loaded != rs {
			t.Errorf("with no relay, loaded\n%q\nwant the file's\n%q", f.loaded, rs)
		}
	}
}

// A steering file from before the relay steers none of a Docker project's
// ports, so a session that has some is refused: nothing is loaded, and the
// session the daemon opened is closed.
func TestSteerRefusesARelayWithAFileThatHasNoRelaySets(t *testing.T) {
	rootsPath, _ := roots(t)
	sess := Session{Name: "s", Policy: "/etc/frisket/policies/research.json", Mntns: "/proc/1/ns/mnt", Roots: rootsPath}
	p, _ := allFile().Plan()
	f := &fakeRoot{relay: []string{"127.0.0.1:64320", "127.101.170.171:64320", "[::1]:64320"}}
	err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess)
	if err == nil || !strings.Contains(err.Error(), "the steering file has no relay sets; rebuild it with this frisket") ||
		!strings.Contains(err.Error(), "the session was closed") {
		t.Errorf("err = %v", err)
	}
	if want := []string{"listeners", "daemon open", routing, "daemon close"}; !slices.Equal(f.steps, want) {
		t.Errorf("steps = %v, want %v", f.steps, want)
	}
}

// What the daemon answers is parsed before it goes into text nft reads as
// root: anything but an address and a port is refused, not pasted.
func TestARelayDestinationIsParsedNotPasted(t *testing.T) {
	file := allFile()
	file.Ruleset = relayRuleset
	p, err := file.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"127.0.0.1:64320 }; flush ruleset; add element inet frisket relay4 { 1.2.3.4 . 1",
		"127.0.0.1", "localhost:64320", "[fe80::1%eth0]:64320", "127.0.0.1:0", "",
	} {
		if got, err := p.WithRelay([]string{bad}); err == nil {
			t.Errorf("%q was loaded as\n%s", bad, got)
		}
	}
	// A mapped v4 address is v4, in the v4 set.
	got, err := p.WithRelay([]string{"[::ffff:127.101.170.171]:64320"})
	if err != nil || !strings.HasSuffix(got, "add element inet frisket relay4 { 127.101.170.171 . 64320 }\n") {
		t.Errorf("a mapped address: %v\n%s", err, got)
	}
}
