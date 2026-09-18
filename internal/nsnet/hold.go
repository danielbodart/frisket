package nsnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Helper says how to re-enter this program as the privileged helper. frisket
// runs itself: one binary, one code path, and no second thing to keep in step.
// Tests set Verb to their own sentinel so the test binary can play the helper.
type Helper struct {
	// Exe is the executable to run. Empty means this one.
	Exe string
	// Verb is the subcommand that dispatches to RunHelper. Empty means "helper".
	Verb string
}

func (h Helper) argv(args HelperArgs) ([]string, error) {
	exe := h.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("finding this executable to re-run as the helper: %w", err)
		}
	}
	verb := h.Verb
	if verb == "" {
		verb = "helper"
	}
	return append([]string{exe, verb}, args.flags()...), nil
}

// Sock is one listener that lives in another namespace and is held from here.
// Exactly one of Listener and Packet is non-nil.
type Sock struct {
	Spec     Spec
	Listener net.Listener
	Packet   net.PacketConn
}

func (s *Sock) Close() error {
	if s.Listener != nil {
		return s.Listener.Close()
	}
	return s.Packet.Close()
}

// Set is everything one session holds inside one namespace.
//
// CLOSING IT IS TEARDOWN, and the only teardown there is. A listening socket
// pins the namespace it was created in, and the user namespace that owns it,
// invisibly -- neither lsns nor `ip netns` shows the pin, so this Set is the
// only handle on it. Leak it and the namespace lives as long as the daemon.
type Set struct {
	Netns     string // "net:[...]" as the helper saw it, after the setns
	HelperPID int
	Socks     []*Sock
}

// Close closes every descriptor and is safe to call twice, because teardown is
// called from both the clean path and the killed one. Errors are joined rather
// than returned first-wins: a close that failed in the middle must not leave
// the rest open.
func (s *Set) Close() error {
	var errs []error
	for _, sock := range s.Socks {
		if sock == nil {
			continue
		}
		if err := sock.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	s.Socks = nil
	return errors.Join(errs...)
}

// helperResultTimeout bounds the wait for the helper's message. The helper has
// already exited by the time we read, so this only ever fires when it exited
// without sending -- and then a hung session creation is worse than an error.
const helperResultTimeout = 10 * time.Second

// Open creates the session's listeners inside the namespace at args.Netns and
// returns them held from here. It forks the helper, waits for it to exit, and
// takes the descriptors out of the socketpair it left behind.
//
// A failure anywhere aborts the whole set: half a set is a session with a hole
// in it, and the bind that failed is very likely a workload that took the port
// first, which is exactly the case that must not be papered over.
func Open(ctx context.Context, h Helper, args HelperArgs) (_ *Set, err error) {
	if len(args.Specs) == 0 {
		return nil, errors.New("no listeners asked for")
	}
	for _, s := range args.Specs {
		if err := s.Validate(); err != nil {
			return nil, err
		}
	}
	if args.LoTimeout == 0 {
		args.LoTimeout = DefaultLoopbackTimeout
	}
	argv, err := h.argv(args)
	if err != nil {
		return nil, err
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair for the helper: %w", err)
	}
	ours := os.NewFile(uintptr(pair[0]), "helper-result")
	theirs := os.NewFile(uintptr(pair[1]), "helper-result-child")
	defer ours.Close()
	defer theirs.Close()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{theirs} // becomes HelperFD in the helper
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helper %v: %w: %s", argv[1:], err, bytes.TrimSpace(stderr.Bytes()))
	}
	// Close our copy of the child's end BEFORE reading, or a helper that sent
	// nothing leaves the read below waiting on a socket we are holding open
	// ourselves.
	_ = theirs.Close()

	m, files, err := receive(ours, len(args.Specs))
	if err != nil {
		return nil, fmt.Errorf("helper %v: %w: %s", argv[1:], err, bytes.TrimSpace(stderr.Bytes()))
	}
	defer func() {
		// Anything not converted into a net type below is still ours to close.
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()

	set := &Set{Netns: m.Netns, HelperPID: m.Helper}
	defer func() {
		if err != nil {
			_ = set.Close()
		}
	}()
	if len(m.Specs) != len(args.Specs) {
		return nil, fmt.Errorf("helper made %d listeners, asked for %d", len(m.Specs), len(args.Specs))
	}
	for i, want := range args.Specs {
		// Positional, and checked: the descriptors carry no names, so the only
		// thing tying fd i to spec i is that both sides count the same way.
		if m.Specs[i] != want.String() {
			return nil, fmt.Errorf("helper made %s where %s was asked for", m.Specs[i], want)
		}
		sock := &Sock{Spec: want}
		if want.Stream() {
			ln, err := net.FileListener(files[i])
			if err != nil {
				return nil, fmt.Errorf("adopting %s: %w", want, err)
			}
			sock.Listener = ln
		} else {
			pc, err := net.FilePacketConn(files[i])
			if err != nil {
				return nil, fmt.Errorf("adopting %s: %w", want, err)
			}
			sock.Packet = pc
		}
		// net.File* dups; the original is a second descriptor on the same
		// socket, and a second descriptor is a second pin on the namespace.
		_ = files[i].Close()
		files[i] = nil
		set.Socks = append(set.Socks, sock)
	}
	return set, nil
}

// receive reads the manifest and the descriptors out of the socketpair.
func receive(ours *os.File, want int) (Manifest, []*os.File, error) {
	conn, err := net.FileConn(ours)
	if err != nil {
		return Manifest{}, nil, err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Manifest{}, nil, fmt.Errorf("helper socket is a %T, not a unix socket", conn)
	}
	_ = uc.SetReadDeadline(time.Now().Add(helperResultTimeout))

	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*want))

	// ReadMsgUnix cannot ask for MSG_CMSG_CLOEXEC, so the descriptors arrive
	// inheritable and we set the flag ourselves. ForkLock is held across both
	// so a helper being forked for another session in the meantime cannot
	// inherit this session's listeners -- which would pin its namespace in a
	// process nothing here can see.
	syscall.ForkLock.RLock()
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	var fds []int
	if err == nil {
		fds, err = parseRights(oob[:oobn])
		for _, fd := range fds {
			unix.CloseOnExec(fd)
		}
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("reading the helper's result: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return Manifest{}, nil, fmt.Errorf("helper manifest: %w", err)
	}
	if len(fds) != want {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return Manifest{}, nil, fmt.Errorf("helper sent %d descriptors, asked for %d", len(fds), want)
	}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		name := fmt.Sprintf("fd%d", i)
		if i < len(m.Specs) {
			name = m.Specs[i]
		}
		files[i] = os.NewFile(uintptr(fd), name)
	}
	return m, files, nil
}

func parseRights(oob []byte) ([]int, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("control message: %w", err)
	}
	var fds []int
	for _, msg := range msgs {
		got, err := unix.ParseUnixRights(&msg)
		if err != nil {
			return nil, fmt.Errorf("SCM_RIGHTS: %w", err)
		}
		fds = append(fds, got...)
	}
	return fds, nil
}
