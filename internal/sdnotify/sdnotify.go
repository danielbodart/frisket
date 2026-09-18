// Package sdnotify speaks the two halves of systemd's protocol that frisket
// needs, with the standard library and nothing else: sd_notify, including
// handing descriptors to the service's file-descriptor store, and the
// LISTEN_FDS convention by which they come back.
//
// WHY THE FD STORE. A session's listeners live in a sandbox's network
// namespace and cannot be reopened from a path: nothing outside the sandbox can
// create them again without root entering the namespace, and root's hook has
// long since returned. So the only way a `nixos-rebuild switch` or a crash does
// not sever a session that has been running for hours is for PID 1 to hold a
// copy across the gap. They are stored when the session is created, not at
// shutdown, so a crash is covered too.
package sdnotify

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Notifier sends to $NOTIFY_SOCKET. The zero value is not usable; FromEnv
// returns nil when there is no socket, and a nil *Notifier is a valid "not
// under systemd" that callers check for rather than silently skip.
type Notifier struct {
	addr string
}

// FromEnv returns the notifier for this process, or nil if systemd did not
// give it one.
func FromEnv() *Notifier {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	return &Notifier{addr: addr}
}

// New returns a notifier for an explicit socket, for tests.
func New(addr string) *Notifier { return &Notifier{addr: addr} }

// Send writes one state message, with files attached as SCM_RIGHTS.
//
// One datagram per message, which is what makes FDSTORE atomic: every
// descriptor of a session and the name they are stored under arrive together
// or not at all.
func (n *Notifier) Send(state string, files ...*os.File) error {
	if n == nil {
		return errors.New("not running under systemd: no NOTIFY_SOCKET")
	}
	if strings.HasPrefix(n.addr, "vsock:") {
		return fmt.Errorf("NOTIFY_SOCKET %q is a vsock address; only unix sockets are spoken here", n.addr)
	}
	// Unconnected, and sendmsg with the address, because Go refuses
	// WriteMsgUnix on a connected datagram socket. x/sys spells a leading '@'
	// as an abstract socket, which is how systemd writes one.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket for NOTIFY_SOCKET: %w", err)
	}
	defer unix.Close(fd)

	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			rc, err := f.SyscallConn()
			if err != nil {
				return err
			}
			if err := rc.Control(func(fd uintptr) { fds[i] = int(fd) }); err != nil {
				return err
			}
		}
		oob = unix.UnixRights(fds...)
	}
	err = unix.Sendmsg(fd, []byte(state), oob, &unix.SockaddrUnix{Name: n.addr}, 0)
	// The numbers above are only meaningful while the files are open, and a
	// finaliser closing one before the kernel copied it would send whatever
	// had reused the number.
	runtime.KeepAlive(files)
	if err != nil {
		return fmt.Errorf("sd_notify %q: %w", firstLine(state), err)
	}
	return nil
}

// Ready says the service has finished starting: every stored session has been
// adopted and the control socket is accepting.
func (n *Notifier) Ready(status string) error {
	return n.Send("READY=1\nSTATUS=" + status)
}

// Stopping says the service is on its way down.
func (n *Notifier) Stopping() error { return n.Send("STOPPING=1") }

// Store hands files to the fd store under name. Every file sent with the same
// name comes back under it, in LISTEN_FDNAMES.
//
// Systemd caps the store at FileDescriptorStoreMax= and closes what does not
// fit, logging it in its own journal but saying nothing to us. That cap is a
// module option sized from the session count, and the NixOS test counts the
// store rather than trusting it.
func (n *Notifier) Store(name string, files ...*os.File) error {
	return n.Send("FDSTORE=1\nFDNAME="+name, files...)
}

// Remove drops every file stored under name. Teardown must do this as well as
// closing its own copies: PID 1's copy pins the sandbox's namespace exactly as
// ours does.
func (n *Notifier) Remove(name string) error {
	return n.Send("FDSTOREREMOVE=1\nFDNAME=" + name)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// FD is one inherited descriptor and the name systemd gave it: a socket unit's
// FileDescriptorName=, or the FDNAME it was stored under.
type FD struct {
	Name string
	File *os.File
}

// listenFDsStart is SD_LISTEN_FDS_START.
const listenFDsStart = 3

// Listen returns the descriptors systemd passed this process, and unsets the
// variables so nothing this process starts believes they are its own.
//
// LISTEN_PID is checked, not assumed: the variables are inherited by anything
// this process forks, and a child reading them would adopt descriptors that
// are not there -- or, worse, that are something else by then.
func Listen() ([]FD, error) {
	defer func() {
		_ = os.Unsetenv("LISTEN_PID")
		_ = os.Unsetenv("LISTEN_FDS")
		_ = os.Unsetenv("LISTEN_FDNAMES")
	}()
	return parseListen(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES"), os.Getpid(), listenFDsStart)
}

func parseListen(pidVar, fdsVar, namesVar string, self, start int) ([]FD, error) {
	if pidVar == "" && fdsVar == "" {
		return nil, nil
	}
	pid, err := strconv.Atoi(pidVar)
	if err != nil {
		return nil, fmt.Errorf("LISTEN_PID=%q: %w", pidVar, err)
	}
	if pid != self {
		return nil, nil
	}
	n, err := strconv.Atoi(fdsVar)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("LISTEN_FDS=%q is not a count", fdsVar)
	}
	var names []string
	if namesVar != "" {
		names = strings.Split(namesVar, ":")
	}
	out := make([]FD, 0, n)
	for i := range n {
		fd := start + i
		// Inherited without close-on-exec, by design of the protocol. Set
		// here, first, so that nothing this process ever starts carries a
		// sandbox's listener with it -- a pin on that namespace in a process
		// nothing here knows about.
		unix.CloseOnExec(fd)
		name := "unknown"
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		out = append(out, FD{Name: name, File: os.NewFile(uintptr(fd), name)})
	}
	return out, nil
}
