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
	// Userns is the user namespace that owns the sandbox's namespaces, for a
	// caller that is not root: the helper is then started under Nsenter, which
	// joins Userns, and the sandbox's network namespace with it, before the
	// helper starts. Go cannot do that itself:
	// setns(CLONE_NEWUSER) refuses a multi-threaded caller, and a Go program
	// is multi-threaded before main runs -- init() included -- and frisket is
	// built without cgo, so there is no constructor to do it earlier either.
	// Empty is a root caller, which enters with setns directly.
	Userns string
	// Nsenter is util-linux's nsenter, by absolute path: resolved on the host
	// by whoever configured it, never looked up here.
	Nsenter string
}

// Rootless says the sandbox is entered through Nsenter.
func (h Helper) Rootless() bool { return h.Userns != "" }

// enter is the argv prefix that runs a program in Userns and in the network
// namespace at netns.
func (h Helper) enter(netns string) []string {
	return []string{h.Nsenter, "--user=" + h.Userns, "--net=" + netns, "--"}
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
	if h.Rootless() {
		// nsenter has joined the network namespace already, so the helper
		// stays where it starts.
		netns := args.Netns
		args.Netns = ""
		return append(append(h.enter(netns), exe, verb), args.flags()...), nil
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

// helperResultTimeout bounds the wait for the helper's manifest, beyond the
// time it may spend waiting for lo: a hung session creation is worse than an
// error.
const helperResultTimeout = 10 * time.Second

// Entered is a helper inside a namespace: the listeners it made there, held
// from here, and the helper itself, still inside and serving requests until
// Close. A step enters once and does all its work inside through Do, rather
// than paying for a process -- and, rootless, for nsenter -- per command.
type Entered struct {
	// Set is the listeners asked for, already handed over and closed on the
	// helper's side. Empty, but for Netns and HelperPID, when none were.
	Set *Set

	argv   []string
	cmd    *exec.Cmd
	conn   *net.UnixConn
	dec    *json.Decoder
	stderr bytes.Buffer
	ended  bool
	endErr error
}

// Enter starts the helper inside the namespace at args.Netns, takes the
// listeners it made there, and leaves it running for Do.
//
// A failure anywhere aborts the whole set: half a set is a session with a hole
// in it, and the bind that failed is very likely a workload that took the port
// first, which is exactly the case that must not be papered over.
func Enter(ctx context.Context, h Helper, args HelperArgs) (_ *Entered, err error) {
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
	ours := os.NewFile(uintptr(pair[0]), "helper")
	theirs := os.NewFile(uintptr(pair[1]), "helper-child")
	defer ours.Close()
	defer theirs.Close()
	c, err := net.FileConn(ours)
	if err != nil {
		return nil, err
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("helper socket is a %T, not a unix socket", c)
	}

	e := &Entered{argv: argv, conn: conn}
	e.cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
	e.cmd.Stderr = &e.stderr
	e.cmd.ExtraFiles = []*os.File{theirs} // becomes HelperFD in the helper
	if err := e.cmd.Start(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("helper %v: %w", argv[1:], err)
	}
	// Close our copy of the child's end, or a helper that exits without
	// sending leaves the read below waiting on a socket we hold open ourselves.
	_ = theirs.Close()
	defer func() {
		if err != nil {
			_ = e.Close()
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(args.LoTimeout + helperResultTimeout))
	m, files, err := receive(conn, len(args.Specs))
	if err != nil {
		return nil, e.failed(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	e.dec = json.NewDecoder(conn)
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
	e.Set = set
	return e, nil
}

// reply is the helper's answer to one request: an error, or a result.
type reply struct {
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Do sends req to the helper, inside, and decodes what it answers into
// result, which may be nil. An error the helper answered with is returned as
// its message alone; a helper that is gone is an error with its stderr.
func (e *Entered) Do(ctx context.Context, req, result any) error {
	if e.ended {
		return errors.New("the helper has already ended")
	}
	deadline, _ := ctx.Deadline()
	_ = e.conn.SetDeadline(deadline)
	if err := json.NewEncoder(e.conn).Encode(req); err != nil {
		return e.failed(err)
	}
	var r reply
	if err := e.dec.Decode(&r); err != nil {
		return e.failed(err)
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	if result != nil && r.Result != nil {
		return json.Unmarshal(r.Result, result)
	}
	return nil
}

// Close ends the conversation: the helper reads the end of its requests and
// exits, and Close waits for it. Safe to call twice. It does not close Set,
// whose listeners outlive the helper.
func (e *Entered) Close() error {
	if !e.ended {
		e.ended = true
		_ = e.conn.Close()
		if err := e.cmd.Wait(); err != nil {
			e.endErr = fmt.Errorf("helper %v: %w: %s", e.argv[1:], err, bytes.TrimSpace(e.stderr.Bytes()))
		}
	}
	return e.endErr
}

// failed is err, from talking to a helper that stopped answering, with what
// the helper said as it went -- which is the error worth reading.
func (e *Entered) failed(err error) error {
	if end := e.Close(); end != nil {
		return end
	}
	return fmt.Errorf("helper %v: %w: %s", e.argv[1:], err, bytes.TrimSpace(e.stderr.Bytes()))
}

// receive reads the manifest and the descriptors from the helper.
func receive(uc *net.UnixConn, want int) (Manifest, []*os.File, error) {
	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*max(want, 1)))

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
