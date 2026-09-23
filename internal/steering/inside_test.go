package steering

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// roleInside marks the test binary re-run as uid 0 of a user and network
// namespace of its own, where it can make what steer and connect make.
const roleInside = "frisket-test-inside"

// exitUnprivileged is the re-run's exit when the namespace grants it nothing:
// Ubuntu's AppArmor, with kernel.apparmor_restrict_unprivileged_userns, lets
// an unprivileged user namespace be made and then refuses every capability
// in it, so bringing lo up is refused.
const exitUnprivileged = 77

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == roleInside {
		if err := loUp(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			if errors.Is(err, syscall.EPERM) {
				os.Exit(exitUnprivileged)
			}
			os.Exit(1)
		}
		if err := stepsInside(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// What steer and connect make over netlink is what connect's checks read back
// as in order, in a real namespace: the requests go through Serve as JSON, as
// they do from the helper.
func TestTheStepsAreWhatConnectChecksFor(t *testing.T) {
	cmd := exec.Command(os.Args[0], roleInside)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Skipf("cannot create a user+network namespace to make them in: %v", err)
	}
	if exit != nil && exit.ExitCode() == exitUnprivileged {
		t.Skipf("a user+network namespace, but no privilege in it: %s", out)
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func serveJSON(r request, result any) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	got, err := Serve(raw)
	if err != nil || result == nil {
		return err
	}
	b, err := json.Marshal(got)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, result)
}

// loUp brings lo up: the first thing made in the namespace, and so where one
// that grants nothing says so.
func loUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bringing lo up: %w", err)
	}
	return nil
}

func stepsInside() error {
	p, err := allFile().Plan()
	if err != nil {
		return err
	}

	// Before: nothing to find.
	var rs []ruleInfo
	if err := serveJSON(request{Op: opRules}, &rs); err != nil {
		return err
	}
	if hasMarkRule(rs, p.Mark, p.RouteTable) {
		return errors.New("a fresh namespace already has the mark's rule")
	}
	if err := serveJSON(request{Op: opTable, Name: p.Table}, nil); err == nil {
		return errors.New("a fresh namespace has table inet frisket")
	}

	if err := serveJSON(request{Op: opApply, Steps: append(p.RoutingSteps(false), p.RoutingSteps(true)...)}, nil); err != nil {
		return fmt.Errorf("routing: %w", err)
	}
	for _, v6 := range []bool{false, true} {
		var rs []ruleInfo
		if err := serveJSON(request{Op: opRules, V6: v6}, &rs); err != nil {
			return err
		}
		if !hasMarkRule(rs, p.Mark, p.RouteTable) {
			return fmt.Errorf("%s: no mark rule in %+v", family(v6), rs)
		}
		var routes []routeInfo
		if err := serveJSON(request{Op: opRoutes, V6: v6, Table: p.RouteTable}, &routes); err != nil {
			return err
		}
		if !hasLocalDefault(routes) {
			return fmt.Errorf("%s: no local default on lo in %+v", family(v6), routes)
		}
	}

	var names []string
	if err := serveJSON(request{Op: opLinks}, &names); err != nil {
		return err
	}
	if extra := nonLoopback(names); len(extra) > 0 {
		return fmt.Errorf("before connect, %v besides lo", extra)
	}
	if err := serveJSON(request{Op: opApply, Steps: p.ConnectSteps()}, nil); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := serveJSON(request{Op: opLinks}, &names); err != nil {
		return err
	}
	if !slices.Equal(nonLoopback(names), []string{"frisket0"}) {
		return fmt.Errorf("after connect, %v besides lo", nonLoopback(names))
	}
	for _, v6 := range []bool{false, true} {
		var routes []routeInfo
		if err := serveJSON(request{Op: opRoutes, V6: v6, Table: 254}, &routes); err != nil {
			return err
		}
		if !slices.Contains(routes, routeInfo{Default: true, Dev: "frisket0"}) {
			return fmt.Errorf("%s: no default route by frisket0 in %+v", family(v6), routes)
		}
	}
	// A step that cannot be made says which.
	err = serveJSON(request{Op: opApply, Steps: p.ConnectSteps()}, nil)
	if err == nil || !strings.Contains(err.Error(), "address add 192.0.2.2/32 dev lo") {
		return fmt.Errorf("connect twice: %v, want the step that failed named", err)
	}
	return nil
}
