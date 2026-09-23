package nsnet

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// HelperFD is the descriptor the helper writes its result to: one end of a
// socketpair the holder made. Not stdout, because the payload carries
// SCM_RIGHTS and stdout may be a pipe, a terminal or a log file.
const HelperFD = 3

// Manifest is what the helper sends alongside the descriptors, so the holder
// knows what it received without having to trust its own argument list.
type Manifest struct {
	// Netns is /proc/thread-self/ns/net as the helper saw it AFTER the setns:
	// "net:[4026533500]". It is the only evidence in the exchange that the
	// sockets are not the host's, and it goes into the session's first log line.
	Netns string `json:"netns"`

	// Specs are in descriptor order. The holder matches them positionally.
	Specs []string `json:"specs"`

	// Helper is the pid that created them. Recorded for the log, so a failed
	// session can be found in a journal.
	Helper int `json:"helper"`
}

// HelperArgs are the helper's command line, shared by the side that builds it
// and the side that parses it so the two cannot drift.
type HelperArgs struct {
	Netns     string        // path to a network namespace; empty means "stay here"
	Specs     []Spec        // the listeners to create, if any
	LoTimeout time.Duration // how long to wait for lo to come up, if there are any

	// Isolated refuses a namespace that already has any interface besides lo.
	// See requireIsolated: it is the first half of the ordering, checked from
	// inside, by the only code that is ever in there.
	Isolated bool
}

func (a HelperArgs) flags() []string {
	args := []string{"-lo-timeout", a.LoTimeout.String()}
	if len(a.Specs) > 0 {
		args = append(args, "-spec", FormatSpecs(a.Specs))
	}
	if a.Netns != "" {
		args = append(args, "-net", a.Netns)
	}
	if a.Isolated {
		args = append(args, "-isolated")
	}
	return args
}

// Serve answers one request, inside the namespace, on the thread that entered
// it. What the requests are is the caller's business: nsnet only carries them.
type Serve func(req json.RawMessage) (result any, err error)

// RunHelper is the privileged half, and the only code in frisket that ever
// changes namespace. It runs as a FORKED PROCESS rather than a goroutine, and
// that is a security property, not a style choice: measured, doing the setns
// in-process and then unlocking the thread let the Go runtime schedule ordinary
// goroutines onto a thread still inside the sandbox, and 13 of 200 of frisket's
// own upstream connections left through the sandbox's network. A separate
// process that exits cannot do that to us.
//
// It enters the namespace, waits for lo, creates the listeners, sends them back
// over HelperFD with a manifest, and then answers requests with serve, from
// inside, until the other end closes: one entry per step, however much the
// step does in there. Anything that fails must fail the whole session: a
// session with some of its listeners is a session with a hole.
func RunHelper(argv []string, stderr io.Writer, serve Serve) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(stderr)
	netns := fs.String("net", "", "path to the network namespace to enter; empty stays in this one")
	specs := fs.String("spec", "", "comma-separated listeners, e.g. tcp4:127.0.0.1:15001,udp6:[::1]:53")
	loTimeout := fs.Duration("lo-timeout", DefaultLoopbackTimeout, "how long to wait for lo to come up")
	isolated := fs.Bool("isolated", false, "refuse a namespace with any interface besides lo")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	var parsed []Spec
	if *specs != "" {
		var err error
		if parsed, err = ParseSpecs(*specs); err != nil {
			return err
		}
	}

	// LOCKED AND NEVER UNLOCKED. setns moves one thread, and the sockets below
	// -- and every request after them -- must be made on that thread. This
	// process exits when the requests end, so nothing is leaked by refusing to
	// unlock -- and see the note above for what unlocking costs when the
	// process does not exit.
	runtime.LockOSThread()

	if *netns != "" {
		if err := enterNetns(*netns); err != nil {
			return err
		}
	}
	here, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("reading this thread's network namespace: %w", err)
	}

	// Only a bind needs lo; a step with no listeners to make does not wait.
	if len(parsed) > 0 {
		if err := waitLoopback(*loTimeout); err != nil {
			return err
		}
	}
	if *isolated {
		ifs, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("listing this namespace's interfaces: %w", err)
		}
		if err := requireIsolated(ifs); err != nil {
			return err
		}
	}
	if err := handOver(here, parsed); err != nil {
		return err
	}
	return answer(serve)
}

// handOver creates the listeners and sends them, with the manifest, over
// HelperFD. Its copies are closed before it returns: once sent, the
// descriptors live in the receiving socket's queue, and every copy kept here
// is another pin on the namespace for as long as the requests go on.
func handOver(here string, specs []Spec) error {
	fds := make([]int, 0, len(specs))
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	m := Manifest{Netns: here, Helper: os.Getpid()}
	for _, s := range specs {
		fd, err := createSocket(s)
		if err != nil {
			return err
		}
		fds = append(fds, fd)
		m.Specs = append(m.Specs, s.String())
	}

	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	if err := unix.Sendmsg(HelperFD, payload, rights, nil, 0); err != nil {
		return fmt.Errorf("handing %d descriptors back on fd %d: %w", len(fds), HelperFD, err)
	}
	return nil
}

// answer serves requests from HelperFD until the other end closes it. Blocking
// reads and writes, on this thread, so every request is served where the
// setns put it. A request that fails is answered with its error, and the
// caller decides what that means for the session.
func answer(serve Serve) error {
	f := os.NewFile(HelperFD, "requests")
	defer f.Close()
	dec, enc := json.NewDecoder(f), json.NewEncoder(f)
	for {
		var req json.RawMessage
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading a request: %w", err)
		}
		var r reply
		result, err := serve(req)
		if err == nil && result != nil {
			r.Result, err = json.Marshal(result)
		}
		if err != nil {
			r.Error = err.Error()
		}
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("answering a request: %w", err)
		}
	}
}

func enterNetns(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening network namespace %s: %w", path, err)
	}
	defer f.Close()
	if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
		if errors.Is(err, unix.EPERM) {
			// The usual cause, and worth naming: a namespace is enterable by
			// whoever has CAP_SYS_ADMIN in the user namespace that OWNS it.
			return fmt.Errorf("setns %s: %w (no CAP_SYS_ADMIN in the user namespace that owns it)", path, err)
		}
		return fmt.Errorf("setns %s: %w", path, err)
	}
	return nil
}

// requireIsolated refuses a namespace that has anything but loopback in it.
//
// LISTENERS, THEN RULES, THEN CONNECTIVITY, and this is the check that the
// third has not already happened. A namespace nspawn made with
// --private-network holds lo and nothing else, so until something provisions
// egress the workload has nowhere to go and no race to win. An interface here
// means egress came first -- measured, that order leaves 12 of 12 connections
// unsteered -- or that the namespace is not a sandbox's at all: a container
// without privateNetwork shares the host's, and steering it would steer the
// host. Either way the session is refused before a listener exists, so no
// rules follow it.
//
// An interface rather than a route, because a route needs an interface to
// point at other than lo, and nothing inside could have made one: the
// namespace is owned by the initial user namespace, so every write is EPERM.
func requireIsolated(ifs []net.Interface) error {
	var extra []string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback == 0 {
			extra = append(extra, i.Name)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("the namespace already has %v besides lo; egress is provisioned after the rules and never before, so this session is refused", extra)
	}
	return nil
}
