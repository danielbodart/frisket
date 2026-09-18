// Command frisket keeps credentials out of sandboxes.
//
// Two halves, one binary. `frisket serve` is the daemon, running as the user
// whose credentials it holds; it can never enter a sandbox's namespace. `frisket
// steer` and `frisket connect` are root's, run from a launcher's hook: they
// create a session's listeners inside the sandbox, hand them to the daemon, and
// steer the sandbox to them -- in that order, which is the security property.
// See PLAN.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/nsnet"
	"github.com/danielbodart/frisket/internal/policy"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/internal/serve"
	"github.com/danielbodart/frisket/internal/steering"
)

// version is stamped at build time. scripts/version.sh derives the real one
// from the repository; a build without it says so rather than claiming a number.
var version = "dev"

const usage = `frisket -- credentials on the wire, never in the sandbox

  frisket serve -config FILE -state DIR [-control PATH]
        The daemon. Holds every session's listeners from the host and serves
        each connection and query steered to them under the session's policy:
        DNS against the allowlist, egress to what that DNS resolved, and
        interception for the routes' hosts. FILE holds the policies; DIR holds
        the machine's CA, made on first start. Under systemd it is
        socket-activated, and keeps its sessions across a restart in the
        service's file-descriptor store.

  frisket steer -netns PATH -steering FILE -name NAME -policy POLICY [-param K=V]...
        Root's first step, from a launcher's hook: create the session's
        listeners inside the network namespace at PATH, hand them to the daemon,
        then install the policy routing and load the ruleset that steers to
        them. Provisions NO egress.

  frisket connect -netns PATH -steering FILE -name NAME
        Root's second step: the service address on lo, and for the "all" set
        the dummy interface and its default routes. Refuses unless the daemon
        holds this namespace's session and its policy routing and ruleset are
        in place.

  frisket close -name NAME
        End a session: the daemon closes every descriptor it holds and drops it
        from the fd store. Closing one that is not open succeeds.

  frisket sessions        What the daemon holds, one JSON object per line.
  frisket steering FILE   Check a steering file and print what it will do.

  frisket helper ...      Not run by hand: creates listeners inside a namespace.
  frisket nsexec ...      Not run by hand: runs nft or ip inside a namespace.
  frisket version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		err = runServe(args)
	case "steer":
		err = runSteer(args)
	case "connect":
		err = runConnect(args)
	case "close":
		err = runClose(args)
	case "sessions":
		err = runSessions(args)
	case "steering":
		err = runSteering(args)
	case "helper":
		err = nsnet.RunHelper(args, os.Stderr)
	case "nsexec":
		// Returns only on failure: on success this process IS the program.
		err = nsnet.RunExec(args, os.Stderr)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "frisket: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "frisket %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

// lockedWriter serialises writes, so the daemon's lines and every session's
// lines -- one slog handler, many goroutines -- never interleave mid-line.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("control", control.DefaultPath, "control socket to create when systemd has not passed one")
	uid := fs.Int("control-uid", 0, "the only uid the control socket answers")
	maxConns := fs.Int("max-conns", 0, "concurrent connections per session (0: the default)")
	configPath := fs.String("config", "", "the policies, as the NixOS module writes them")
	state := fs.String("state", "", "the daemon's state directory; the CA is made in ca/ inside it")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *configPath == "" || *state == "" {
		return errors.New("-config and -state are both required")
	}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{w: os.Stderr}, nil))

	// Everything the policies need is built before the control socket is
	// touched, so a configuration that does not hold stops the daemon at
	// start -- loudly, in the journal -- rather than refusing every session
	// later for a reason nobody sees.
	cfg, err := policy.Load(*configPath)
	if err != nil {
		return err
	}
	ca, err := intercept.LoadOrCreateCA(filepath.Join(*state, "ca"))
	if err != nil {
		return err
	}
	classifier, dialer, err := policy.Dialer()
	if err != nil {
		return err
	}
	policies, err := policy.Build(cfg, policy.Deps{CA: ca, Classifier: classifier, Dialer: dialer, Log: log})
	if err != nil {
		return err
	}
	defer policies.Close()

	inherited, err := sdnotify.Listen()
	if err != nil {
		return err
	}
	var ctl *net.UnixListener
	var stored []sdnotify.FD
	for _, fd := range inherited {
		if fd.Name != serve.ControlName {
			stored = append(stored, fd)
			continue
		}
		ln, err := net.FileListener(fd.File)
		_ = fd.File.Close()
		if err != nil {
			return fmt.Errorf("the control socket systemd passed: %w", err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			return fmt.Errorf("the control socket systemd passed is a %T", ln)
		}
		ctl = ul
	}
	if ctl == nil {
		if ctl, err = listenControl(*path); err != nil {
			return err
		}
	}

	d := &serve.Daemon{
		Log:        log,
		Policies:   policies.Policies,
		ControlUID: *uid,
		MaxConns:   *maxConns,
	}
	// Assigned only when present: a nil *Notifier in the interface would be
	// a non-nil Notifier that fails every call.
	if n := sdnotify.FromEnv(); n != nil {
		d.Notify = n
	}
	names := make([]string, 0, len(policies.Policies))
	for n := range policies.Policies {
		names = append(names, n)
	}
	sort.Strings(names)
	log.Info("frisket serve", "version", version, "control", ctl.Addr().String(), "stored", len(stored),
		"policies", names, "ca", filepath.Join(*state, "ca", intercept.CACertFile))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx, ctl, stored)
}

// listenControl makes the control socket when systemd did not: root-only, from
// the moment it exists. The umask is what makes that true at bind time; a
// chmod afterwards would leave a window with the socket open to everyone.
func listenControl(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix(control.Network, &net.UnixAddr{Name: path, Net: control.Network})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("control socket %s: %w", path, err)
	}
	return ln, nil
}

// params is a repeated -param key=value.
type params map[string]string

func (p params) String() string { return fmt.Sprint(map[string]string(p)) }
func (p params) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("%q: want key=value", s)
	}
	if _, dup := p[k]; dup {
		return fmt.Errorf("%q given twice", k)
	}
	p[k] = v
	return nil
}

func rootFlags(fs *flag.FlagSet) (s *steering.Steerer, netns, file, name *string) {
	s = &steering.Steerer{}
	fs.StringVar(&s.Control, "control", control.DefaultPath, "the daemon's control socket")
	fs.StringVar(&s.Nft, "nft", "nft", "nft, resolved on the host before entering the namespace")
	fs.StringVar(&s.IP, "ip", "ip", "ip, likewise")
	netns = fs.String("netns", "", "path to the sandbox's network namespace")
	file = fs.String("steering", "", "the steering file lib.steering wrote")
	name = fs.String("name", "", "the session's name")
	return
}

func root(ctx context.Context) (context.Context, context.CancelFunc) {
	// Bounded: this runs inside a launcher that is holding a session open for
	// it, and a hook that hangs is a session that never starts.
	return context.WithTimeout(ctx, 30*time.Second)
}

func runSteer(argv []string) error {
	fs := flag.NewFlagSet("steer", flag.ContinueOnError)
	s, netns, file, name := rootFlags(fs)
	policy := fs.String("policy", "", "the policy the daemon applies to the session")
	ps := params{}
	fs.Var(ps, "param", "a policy parameter, key=value; repeatable")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *netns == "" || *file == "" || *name == "" || *policy == "" {
		return errors.New("-netns, -steering, -name and -policy are all required")
	}
	plan, err := steering.Load(*file)
	if err != nil {
		return err
	}
	ctx, cancel := root(context.Background())
	defer cancel()
	return s.Steer(ctx, *netns, plan, steering.Session{Name: *name, Policy: *policy, Params: ps})
}

func runConnect(argv []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	s, netns, file, name := rootFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *netns == "" || *file == "" || *name == "" {
		return errors.New("-netns, -steering and -name are all required")
	}
	plan, err := steering.Load(*file)
	if err != nil {
		return err
	}
	ctx, cancel := root(context.Background())
	defer cancel()
	return s.Connect(ctx, *netns, plan, *name)
}

func runClose(argv []string) error {
	fs := flag.NewFlagSet("close", flag.ContinueOnError)
	s := &steering.Steerer{}
	fs.StringVar(&s.Control, "control", control.DefaultPath, "the daemon's control socket")
	name := fs.String("name", "", "the session's name")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx, cancel := root(context.Background())
	defer cancel()
	closed, err := s.Close(ctx, *name)
	if err != nil {
		return err
	}
	if !closed {
		fmt.Fprintf(os.Stderr, "frisket close: no session %s open\n", *name)
	}
	return nil
}

func runSessions(argv []string) error {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	s := &steering.Steerer{}
	fs.StringVar(&s.Control, "control", control.DefaultPath, "the daemon's control socket")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx, cancel := root(context.Background())
	defer cancel()
	st, err := s.Sessions(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, x := range st {
		if err := enc.Encode(x); err != nil {
			return err
		}
	}
	return nil
}

func runSteering(argv []string) error {
	if len(argv) != 1 {
		return errors.New("want one steering file")
	}
	p, err := steering.Load(argv[0])
	if err != nil {
		return err
	}
	fmt.Printf("set %s, table inet %s\n", p.Set, p.Table)
	fmt.Printf("listeners %s\n", nsnet.FormatSpecs(p.Listeners))
	fmt.Printf("service %v\n", p.Service)
	fmt.Printf("mark %#x, route table %d\n", p.Mark, p.RouteTable)
	fmt.Printf("steer, ip -4:\n%s", p.RoutingBatch(false))
	fmt.Printf("steer, ip -6:\n%s", p.RoutingBatch(true))
	fmt.Printf("connect:\n%s", p.ConnectBatch())
	return nil
}
