// Command frisket keeps credentials out of sandboxes.
//
// Two halves, one binary. `frisket serve` is the daemon, running as the user
// whose credentials it holds; it can never enter a sandbox's namespace. `frisket
// steer` and `frisket connect` are the launcher's, run from its hook as the
// same user, entering the sandbox through the user namespace that owns it:
// they create a session's listeners inside the sandbox, hand them to the
// daemon, and steer the sandbox to them -- in that order, which is the
// security property.
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/ask"
	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/nsmount"
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

  frisket serve -config FILE [-control PATH]
        The daemon. Holds every session's listeners from the host and serves
        each connection and query steered to them under the session's policy:
        DNS against the allowlist, egress to what that DNS resolved, and
        interception for the routes' hosts, with a CA of the session's own.
        FILE says where names are resolved; each session names its own policy
        document, read when it opens and again if it is restored. Under
        systemd it is socket-activated, and
        keeps its sessions -- and their CAs -- across a restart in the
        service's file-descriptor store.

  frisket steer -netns PATH -mntns PATH -roots BUNDLE -steering FILE -name NAME -policy DOCUMENT [-param K=V]...
        The launcher's first step, from its hook: create the session's
        listeners inside the network namespace, hand them to the daemon, then
        install the policy routing and load the ruleset that steers to them.
        Then mount the session's CA read-only at /etc/frisket in the mount
        namespace: ca.crt, and ca-bundle.crt, BUNDLE with the CA after it.
        Provisions NO egress.

  frisket connect -netns PATH -steering FILE -name NAME
        The launcher's second step: the service address on lo, and for the
        "all" set the dummy interface and its default routes. Refuses unless
        the daemon holds this namespace's session and its policy routing and
        ruleset are in place.

        Both take -userns PATH -nsenter NSENTER from a caller that is not
        root: every step inside the sandbox runs under NSENTER, in the user
        namespace at PATH that owns the sandbox's. Without them the caller is
        root and enters directly.

  frisket close -name NAME
        End a session: the daemon closes every descriptor it holds and drops it
        from the fd store. Closing one that is not open succeeds.

  frisket check DOCUMENT...
        Check policy documents as a session opening one would: everything but
        whether its credential files exist yet.

  frisket sessions        What the daemon holds, one JSON object per line.
  frisket steering FILE   Check a steering file and print what it will do.

  frisket helper ...      Not run by hand: creates listeners inside a namespace.
  frisket nsexec ...      Not run by hand: runs nft or ip inside a namespace.
  frisket nsmount ...     Not run by hand: mounts the session's CA, entered.
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
	case "check":
		err = runCheck(args)
	case "helper":
		err = nsnet.RunHelper(args, os.Stderr)
	case "nsmount":
		err = runNsmount(args)
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
	uid := fs.Int("control-uid", os.Getuid(), "the only uid the control socket answers (default: the daemon's own)")
	maxConns := fs.Int("max-conns", 0, "concurrent connections per session (0: the default)")
	configPath := fs.String("config", "", "the policies, as the NixOS module writes them")
	var roots stringList
	fs.Var(&roots, "policy-root", "a directory policy documents may be read from; repeatable (none: anywhere)")
	policyDir := fs.String("policy-dir", "/etc/frisket/policies", "where a session stored under a policy name, before policies were documents, finds that policy")
	askerPath := fs.String("asker", "", "the program a request a route asks about is put to (none: those requests are refused)")
	var level slog.Level
	fs.TextVar(&level, "log-level", slog.LevelInfo, "debug adds each intercepted request's headers, credentials described and never shown")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("-config is required")
	}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{w: os.Stderr}, &slog.HandlerOptions{Level: level}))

	// Everything the policies share is built before the control socket is
	// touched, so a configuration that does not hold stops the daemon at
	// start. The policies themselves are each session's to name, and are
	// read when it opens: `frisket check` is how a document is refused
	// before any session is.
	cfg, err := policy.Load(*configPath)
	if err != nil {
		return err
	}
	classifier, dialer, err := policy.Dialer()
	if err != nil {
		return err
	}
	deps := policy.Deps{Classifier: classifier, Dialer: dialer, Log: log, Roots: roots}
	if *askerPath != "" {
		// Only when there is one: a nil *ask.Command in the interface would
		// be an asker that panics rather than no asker at all.
		asker, err := ask.NewCommand(*askerPath)
		if err != nil {
			return err
		}
		deps.Asker = asker
	}
	policies, err := policy.NewStore(cfg, deps)
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
		Policies:   policies,
		ControlUID: *uid,
		MaxConns:   *maxConns,
		PolicyDir:  *policyDir,
	}
	// Assigned only when present: a nil *Notifier in the interface would be
	// a non-nil Notifier that fails every call.
	if n := sdnotify.FromEnv(); n != nil {
		d.Notify = n
	}
	log.Info("frisket serve", "version", version, "control", ctl.Addr().String(), "stored", len(stored))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx, ctl, stored)
}

// listenControl makes the control socket when systemd did not: owner-only, from
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
	fs.StringVar(&s.Helper.Userns, "userns", "", "the user namespace that owns the sandbox's, for a caller that is not root (flong's $userns)")
	fs.StringVar(&s.Helper.Nsenter, "nsenter", "", "util-linux's nsenter, by absolute path; required with -userns")
	netns = fs.String("netns", "", "path to the sandbox's network namespace")
	file = fs.String("steering", "", "the steering file lib.steering wrote")
	name = fs.String("name", "", "the session's name")
	return
}

// checkEnter refuses an nsenter that is not an absolute path. It runs with the
// caller's authority over the sandbox, so which one runs is the host's
// configuration to say, never this process's PATH.
func checkEnter(s *steering.Steerer) error {
	if s.Helper.Rootless() && !filepath.IsAbs(s.Helper.Nsenter) {
		return fmt.Errorf("-userns needs -nsenter, by absolute path; got %q", s.Helper.Nsenter)
	}
	return nil
}

func root(ctx context.Context) (context.Context, context.CancelFunc) {
	// Bounded: this runs inside a launcher that is holding a session open for
	// it, and a hook that hangs is a session that never starts.
	return context.WithTimeout(ctx, 30*time.Second)
}

func runCheck(argv []string) error {
	if len(argv) == 0 {
		return errors.New("name at least one policy document")
	}
	// Nothing is dialled and nothing resolved: the host's addresses and its
	// resolver are no part of whether a document holds together, and a build
	// sandbox has neither.
	classifier, err := egress.NewClassifier(nil, egress.StaticHostAddrs())
	if err != nil {
		return err
	}
	deps := policy.Deps{
		Classifier: classifier,
		Dialer:     &egress.Dialer{Classifier: classifier},
		Upstream:   &dns.Upstream{},
		// A credential file that is not there yet is logged by its watcher,
		// and is not the document's fault.
		Log: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	for _, path := range argv {
		if err := policy.Check(path, deps); err != nil {
			return err
		}
	}
	return nil
}

func runSteer(argv []string) error {
	fs := flag.NewFlagSet("steer", flag.ContinueOnError)
	s, netns, file, name := rootFlags(fs)
	policy := fs.String("policy", "", "the policy document the daemon serves the session under, by its absolute path")
	mntns := fs.String("mntns", "", "the sandbox's mount namespace, where the session's CA is put: /proc/<pid>/ns/mnt")
	roots := fs.String("roots", "", "the host's CA bundle, which the session's bundle is made from")
	ps := params{}
	fs.Var(ps, "param", "a policy parameter, key=value; repeatable")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *netns == "" || *mntns == "" || *roots == "" || *file == "" || *name == "" || *policy == "" {
		return errors.New("-netns, -mntns, -roots, -steering, -name and -policy are all required")
	}
	if err := checkEnter(s); err != nil {
		return err
	}
	plan, err := steering.Load(*file)
	if err != nil {
		return err
	}
	ctx, cancel := root(context.Background())
	defer cancel()
	return s.Steer(ctx, *netns, plan, steering.Session{Name: *name, Policy: *policy, Params: ps, Mntns: *mntns, Roots: *roots})
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
	if err := checkEnter(s); err != nil {
		return err
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

// runNsmount is steer's last step for a caller that is not root, re-run under
// nsenter in the user namespace that owns the sandbox's: the files arrive on
// stdin, as JSON, and never touch the host's filesystem.
func runNsmount(argv []string) error {
	fs := flag.NewFlagSet("nsmount", flag.ContinueOnError)
	mntns := fs.String("mntns", "", "the sandbox's mount namespace")
	dir := fs.String("dir", "", "where the files are mounted inside it")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	var files []nsmount.File
	if err := json.NewDecoder(os.Stdin).Decode(&files); err != nil {
		return fmt.Errorf("nsmount: the files on stdin: %w", err)
	}
	return nsmount.AttachEntered(*mntns, *dir, files)
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

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(s string) error {
	if !filepath.IsAbs(s) {
		return fmt.Errorf("%q is not an absolute path", s)
	}
	*l = append(*l, filepath.Clean(s))
	return nil
}
