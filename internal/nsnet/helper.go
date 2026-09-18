package nsnet

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

	// Helper is the pid that created them, already gone by the time this is
	// read. Recorded for the log, so a failed session can be found in a journal.
	Helper int `json:"helper"`
}

// HelperArgs are the helper's command line, shared by the side that builds it
// and the side that parses it so the two cannot drift.
type HelperArgs struct {
	Netns     string        // path to a network namespace; empty means "stay here"
	Specs     []Spec        // the listeners to create
	LoTimeout time.Duration // how long to wait for lo to come up
}

func (a HelperArgs) flags() []string {
	args := []string{"-spec", FormatSpecs(a.Specs), "-lo-timeout", a.LoTimeout.String()}
	if a.Netns != "" {
		args = append(args, "-net", a.Netns)
	}
	return args
}

// RunHelper is the privileged half, and the only code in frisket that ever
// changes namespace. It runs as a FORKED PROCESS rather than a goroutine, and
// that is a security property, not a style choice: measured, doing the setns
// in-process and then unlocking the thread let the Go runtime schedule ordinary
// goroutines onto a thread still inside the sandbox, and 13 of 200 of frisket's
// own upstream connections left through the sandbox's network. A separate
// process that exits cannot do that to us.
//
// It enters the namespace, waits for lo, creates the listeners, sends them back
// over HelperFD with a manifest, and returns. Anything that fails must fail the
// whole session: a session with some of its listeners is a session with a hole.
func RunHelper(argv []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(stderr)
	netns := fs.String("net", "", "path to the network namespace to enter; empty stays in this one")
	specs := fs.String("spec", "", "comma-separated listeners, e.g. tcp4:127.0.0.1:15001,udp6:[::1]:15353")
	loTimeout := fs.Duration("lo-timeout", DefaultLoopbackTimeout, "how long to wait for lo to come up")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	parsed, err := ParseSpecs(*specs)
	if err != nil {
		return err
	}

	// LOCKED AND NEVER UNLOCKED. setns moves one thread, and the sockets below
	// must be created on that thread. This process exits a moment later, so
	// nothing is leaked by refusing to unlock -- and see the note above for what
	// unlocking costs when the process does not exit.
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

	if err := waitLoopback(*loTimeout); err != nil {
		return err
	}

	fds := make([]int, 0, len(parsed))
	defer func() {
		// Once sent, the descriptors live in the receiving socket's queue, so
		// closing ours is correct either way -- and on the failure path it is
		// the difference between an aborted session and a pinned namespace.
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	m := Manifest{Netns: here, Helper: os.Getpid()}
	for _, s := range parsed {
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
	if err := unix.Sendmsg(HelperFD, payload, unix.UnixRights(fds...), nil, 0); err != nil {
		return fmt.Errorf("handing %d descriptors back on fd %d: %w", len(fds), HelperFD, err)
	}
	return nil
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
