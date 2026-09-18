package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
	"github.com/danielbodart/frisket/internal/steer"
	"golang.org/x/sys/unix"
)

// session is one sandbox's listeners, held from here, and what is being done
// with them.
type session struct {
	info     control.Session
	restored bool
	log      *slog.Logger

	socks []*nsnet.Sock
	// meta is the session's record, a sealed memfd stored beside its listeners
	// under the same FDNAME, so the one datagram that stores a session stores
	// what it is too. A successor adopting the store needs both, and a state
	// directory would be a second place that could disagree with the first.
	meta *os.File

	cancel  context.CancelFunc
	serving sync.WaitGroup
	conns   tracker
}

// descriptors is how many this session holds in the sandbox's namespace, or
// about it: listeners, live connections and the record.
func (s *session) descriptors() int {
	n := len(s.socks) + s.conns.count()
	if s.meta != nil {
		n++
	}
	return n
}

// start serves every listener until the session is closed.
func (s *session) start(parent context.Context, d Dispatch, maxConns int, dst func(*net.TCPConn) netip.AddrPort) {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	st := &steer.Session{ID: s.info.Name, Log: s.log, MaxConns: maxConns, Mark: s.info.Mark, Dst: dst}
	s.conns.next = d
	for _, sock := range s.socks {
		s.serving.Add(1)
		go func() {
			defer s.serving.Done()
			var err error
			if sock.Listener != nil {
				err = st.Serve(ctx, sock.Listener, &s.conns)
			} else {
				err = st.ServePacket(ctx, sock.Packet, d)
			}
			if err != nil {
				s.log.Error("listener stopped", "session", s.info.Name, "listener", sock.Spec.String(), "error", err.Error())
			}
		}()
	}
}

// closeAll closes every descriptor the session holds, and is the only
// teardown there is. A listener pins the sandbox's namespace and the user
// namespace that owns it, and so does every connection accepted on one -- an
// accepted socket belongs to the listener's namespace -- and neither lsns nor
// `ip netns` shows the pin. Returns how many were closed.
func (s *session) closeAll(wait time.Duration) int {
	n := s.descriptors()
	s.conns.closeAll()
	for _, sock := range s.socks {
		_ = sock.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.meta != nil {
		_ = s.meta.Close()
	}
	done := make(chan struct{})
	go func() {
		s.serving.Wait()
		s.conns.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		// Every descriptor is already closed; what is late is a handler
		// returning. Said, so a handler that ignores its context is visible.
		s.log.Warn("handlers still running after close", "session", s.info.Name)
	}
	return n
}

// tracker is the Handler every TCP listener is served with: it records each
// live connection so that closing the session can close them, and refuses
// any that arrive after it has.
type tracker struct {
	next steer.Handler

	mu     sync.Mutex
	live   map[*steer.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

func (t *tracker) ServeConn(ctx context.Context, c *steer.Conn) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = c.Close()
		return
	}
	if t.live == nil {
		t.live = make(map[*steer.Conn]struct{})
	}
	t.live[c] = struct{}{}
	t.wg.Add(1)
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.live, c)
		t.mu.Unlock()
		t.wg.Done()
	}()
	t.next.ServeConn(ctx, c)
}

func (t *tracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.live)
}

func (t *tracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for c := range t.live {
		_ = c.Close()
	}
}

func (t *tracker) wait() { t.wg.Wait() }

// ---------------------------------------------------------------- what arrived

// sockInfo is what the kernel says a received descriptor is. Nothing about a
// listener is taken from the request that carried it: the request says what
// the descriptors should be, and this says what they are.
type sockInfo struct {
	typ       int
	family    int
	addr      netip.AddrPort
	listening bool
	reuseport bool
	cookie    uint64 // the network namespace's cookie
}

// inspect asks the kernel about f. A descriptor that is not a socket -- the
// session record, on adoption -- reports ENOTSOCK.
func inspect(f *os.File) (sockInfo, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return sockInfo{}, err
	}
	var si sockInfo
	var opErr error
	err = rc.Control(func(fd uintptr) {
		s := int(fd)
		if si.typ, opErr = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_TYPE); opErr != nil {
			return
		}
		if si.family, opErr = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_DOMAIN); opErr != nil {
			return
		}
		var v int
		if v, opErr = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); opErr != nil {
			return
		}
		si.listening = v == 1
		if v, opErr = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT); opErr != nil {
			return
		}
		si.reuseport = v != 0
		if si.cookie, opErr = unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE); opErr != nil {
			opErr = fmt.Errorf("SO_NETNS_COOKIE: %w", opErr)
			return
		}
		var sa unix.Sockaddr
		if sa, opErr = unix.Getsockname(s); opErr != nil {
			return
		}
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			si.addr = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
		case *unix.SockaddrInet6:
			si.addr = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port))
		default:
			opErr = fmt.Errorf("bound to a %T, not an IP address", sa)
		}
	})
	if err != nil {
		return sockInfo{}, err
	}
	return si, opErr
}

// matches reports whether si is the socket spec describes.
func (si sockInfo) matches(spec nsnet.Spec) error {
	wantType, wantFamily := unix.SOCK_DGRAM, unix.AF_INET
	if spec.Stream() {
		wantType = unix.SOCK_STREAM
	}
	if spec.V6() {
		wantFamily = unix.AF_INET6
	}
	switch {
	case si.typ != wantType || si.family != wantFamily:
		return fmt.Errorf("%s arrived as socket type %d family %d", spec, si.typ, si.family)
	case si.addr != spec.Addr:
		return fmt.Errorf("%s arrived bound to %s", spec, si.addr)
	case spec.Stream() && !si.listening:
		return fmt.Errorf("%s arrived not listening", spec)
	case si.reuseport:
		// Never. A listener with SO_REUSEPORT lets the workload bind beside it
		// and take a share of its own steered traffic (PLAN.md decision 11).
		return fmt.Errorf("%s arrived with SO_REUSEPORT set", spec)
	}
	return nil
}

// ownCookie is the cookie of this process's network namespace, read off a
// socket made here for the purpose.
func ownCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	c, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("SO_NETNS_COOKIE: %w", err)
	}
	return c, nil
}

// adoptSockets checks each file against its spec and converts it to the net
// type that serves it. Every file is closed on return: net.File* dups, and a
// second descriptor on the same socket is a second pin on the namespace.
//
// All of a session's sockets must share one namespace, and it must not be
// ours. A listener in the daemon's own namespace means the helper never
// entered the sandbox's: it would listen on the HOST's loopback while the
// sandbox's rules steer to a port nobody holds there.
func adoptSockets(specs []nsnet.Spec, files []*os.File, own uint64) (socks []*nsnet.Sock, err error) {
	defer control.CloseAll(files)
	defer func() {
		if err != nil {
			for _, s := range socks {
				_ = s.Close()
			}
			socks = nil
		}
	}()
	if len(files) != len(specs) {
		return nil, fmt.Errorf("%d descriptors for %d listeners", len(files), len(specs))
	}
	infos := make([]sockInfo, len(specs))
	for i, spec := range specs {
		if infos[i], err = inspect(files[i]); err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
		if err := infos[i].matches(spec); err != nil {
			return nil, err
		}
	}
	if err := sameForeignNamespace(specs, infos, own); err != nil {
		return nil, err
	}
	for i, spec := range specs {
		sock := &nsnet.Sock{Spec: spec}
		if spec.Stream() {
			if sock.Listener, err = net.FileListener(files[i]); err != nil {
				return socks, fmt.Errorf("adopting %s: %w", spec, err)
			}
		} else {
			if sock.Packet, err = net.FilePacketConn(files[i]); err != nil {
				return socks, fmt.Errorf("adopting %s: %w", spec, err)
			}
		}
		socks = append(socks, sock)
	}
	return socks, nil
}

// sameForeignNamespace refuses sockets that are not all in one namespace, or
// that are in ours.
func sameForeignNamespace(specs []nsnet.Spec, infos []sockInfo, own uint64) error {
	for i, si := range infos {
		if si.cookie == own {
			return fmt.Errorf("%s is in frisket's own network namespace, not a sandbox's; the helper did not enter it", specs[i])
		}
		if si.cookie != infos[0].cookie {
			return fmt.Errorf("%s is in a different network namespace from %s", specs[i], specs[0])
		}
	}
	return nil
}

// ---------------------------------------------------------------- the record

// newRecord writes s into a sealed memfd: once written it cannot be changed,
// by us or by anything that later holds a copy.
func newRecord(s control.Session) (*os.File, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate("frisket-session-"+s.Name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd for session %s: %w", s.Name, err)
	}
	f := os.NewFile(uintptr(fd), "frisket-session-"+s.Name)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		f.Close()
		return nil, fmt.Errorf("sealing session %s's record: %w", s.Name, err)
	}
	return f, nil
}

// readRecord reads a session record back from the store.
func readRecord(f *os.File) (control.Session, error) {
	buf := make([]byte, 64<<10)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return control.Session{}, err
	}
	var s control.Session
	if err := json.Unmarshal(buf[:n], &s); err != nil {
		return control.Session{}, fmt.Errorf("session record: %w", err)
	}
	return s, nil
}
