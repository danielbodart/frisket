package steering

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
)

const ruleset = "table inet frisket {\n}\n"

func allFile() File {
	return File{
		Set:       "all",
		Table:     "frisket",
		Listeners: []string{"tcp4:127.0.0.1:15001", "tcp6:[::1]:15001", "udp4:127.0.0.1:15353", "udp6:[::1]:15353"},
		Ruleset:   ruleset,
		Service:   []string{"192.0.2.2", "2001:db8::2"},
		Dummy:     &Dummy{Interface: "frisket0", Addresses: []string{"192.0.2.1", "2001:db8::1"}},
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
		"a listener off loopback, where redirect never sends": func(f *File) {
			f.Listeners[0] = "tcp4:192.0.2.1:15001"
		},
		"one service address":            func(f *File) { f.Service = f.Service[:1] },
		"`all` with no dummy":            func(f *File) { f.Dummy = nil },
		"a dummy with a route and no v6": func(f *File) { f.Dummy.Addresses = f.Dummy.Addresses[:1] },
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
	steps []string
	fail  string
	held  []control.Status
	links string
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
			return control.Response{Sessions: f.held, Closed: true}, nil
		},
		run: func(_ context.Context, netns, stdin, program string, args ...string) (string, error) {
			step := program + " " + strings.Join(args, " ")
			f.steps = append(f.steps, step)
			if f.fail == step {
				return "", errors.New("failed")
			}
			if step == "ip -o link show" {
				return f.links, nil
			}
			return "", nil
		},
	}
}

func TestSteerInstallsRulesOnlyOnceTheDaemonHoldsTheListeners(t *testing.T) {
	p, _ := allFile().Plan()
	sess := Session{Name: "s", Policy: "standin"}
	for _, c := range []struct {
		fail string
		want []string
	}{
		{"", []string{"listeners", "daemon open", "nft -f -"}},
		// A workload that took the port first: no listener, so no rules.
		{"listeners", []string{"listeners"}},
		// The daemon refused (an unknown policy, say): no rules either.
		{"daemon open", []string{"listeners", "daemon open"}},
		// The rules failed: the session they were for is closed.
		{"nft -f -", []string{"listeners", "daemon open", "nft -f -", "daemon close"}},
	} {
		f := &fakeRoot{fail: c.fail}
		err := f.steerer().Steer(context.Background(), "/proc/1/ns/net", p, sess)
		if (err != nil) != (c.fail != "") {
			t.Errorf("failing %q: err = %v", c.fail, err)
		}
		if strings.Join(f.steps, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("failing %q: steps = %v, want %v", c.fail, f.steps, c.want)
		}
		if err != nil && c.fail != "nft -f -" && !strings.Contains(err.Error(), "no rules were installed") {
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
	for _, c := range []struct {
		name string
		f    fakeRoot
		want []string
		ok   bool
	}{
		{"in order", fakeRoot{held: ours, links: loOnly}, []string{"daemon list", "nft list table inet frisket", "ip -o link show", "ip -batch -"}, true},
		// Something provisioned egress between steer and connect.
		{"after something else gave it egress", fakeRoot{held: ours, links: loOnly + "2: eth0@if7: <BROADCAST,MULTICAST> mtu 1500\n"}, []string{"daemon list", "nft list table inet frisket", "ip -o link show"}, false},
		{"before steer", fakeRoot{}, []string{"daemon list"}, false},
		{"another namespace's session", fakeRoot{held: []control.Status{{Session: control.Session{Name: "s", Netns: "net:[1]"}}}}, []string{"daemon list"}, false},
		{"before the rules", fakeRoot{held: ours, fail: "nft list table inet frisket"}, []string{"daemon list", "nft list table inet frisket"}, false},
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
