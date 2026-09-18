package steering

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
)

// Steerer runs root's steps. The zero value's seams are the real ones; tests
// replace them to watch the order.
type Steerer struct {
	Helper  nsnet.Helper
	Control string // the daemon's control socket
	Nft     string // nft, by name or path, resolved on the host
	IP      string // ip, likewise

	open func(ctx context.Context, args nsnet.HelperArgs) (*nsnet.Set, error)
	call func(ctx context.Context, req control.Request, files []*os.File) (control.Response, error)
	run  func(ctx context.Context, netns, stdin, program string, args ...string) (string, error)
}

func (s *Steerer) openSet(ctx context.Context, args nsnet.HelperArgs) (*nsnet.Set, error) {
	if s.open != nil {
		return s.open(ctx, args)
	}
	return nsnet.Open(ctx, s.Helper, args)
}

func (s *Steerer) callDaemon(ctx context.Context, req control.Request, files []*os.File) (control.Response, error) {
	if s.call != nil {
		return s.call(ctx, req, files)
	}
	path := s.Control
	if path == "" {
		path = control.DefaultPath
	}
	return control.Call(ctx, path, req, files)
}

// runIn runs program inside the namespace with stdin, and returns its stdout.
// Its stderr is in the error, because an nft or ip failure is only useful with
// the line number it names.
func (s *Steerer) runIn(ctx context.Context, netns, stdin, program string, args ...string) (string, error) {
	if s.run != nil {
		return s.run(ctx, netns, stdin, program, args...)
	}
	cmd, err := nsnet.Command(ctx, s.Helper, netns, program, args...)
	if err != nil {
		return "", err
	}
	var out, errb bytes.Buffer
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Session is what steer is asked to create.
type Session struct {
	Name   string
	Policy string
	Params map[string]string
}

// Steer creates the session's listeners inside the namespace at netns, hands
// them to the daemon, and only then loads the ruleset that redirects to them.
// It does NOT provision egress: that is Connect, and it is the caller's next
// step.
//
// Every failure before the rules is a session with no rules, which with no
// egress either is a sandbox with nowhere to go -- closed, not open. A failure
// loading the rules closes the session it had just created, so nothing is left
// holding listeners for a namespace that was never steered to them.
func (s *Steerer) Steer(ctx context.Context, netns string, p *Plan, sess Session) error {
	// 1. Listeners, inside, from a namespace that has no egress yet.
	set, err := s.openSet(ctx, nsnet.HelperArgs{Netns: netns, Specs: p.Listeners, Isolated: true})
	if err != nil {
		return fmt.Errorf("creating session %s's listeners: %w; no rules were installed", sess.Name, err)
	}
	defer set.Close()

	files := make([]*os.File, 0, len(set.Socks))
	defer func() { control.CloseAll(files) }()
	for _, sock := range set.Socks {
		f, err := sockFile(sock)
		if err != nil {
			return fmt.Errorf("session %s: %w; no rules were installed", sess.Name, err)
		}
		files = append(files, f)
	}

	// 2. Handed to the daemon, which must be holding them before any rule
	// points at them.
	listeners := make([]string, len(p.Listeners))
	for i, l := range p.Listeners {
		listeners[i] = l.String()
	}
	req := control.Request{Op: control.OpOpen, Session: &control.Session{
		Name:      sess.Name,
		Policy:    sess.Policy,
		Params:    sess.Params,
		Set:       p.Set,
		Service:   p.Service,
		Listeners: listeners,
		Netns:     set.Netns,
	}}
	if _, err := s.callDaemon(ctx, req, files); err != nil {
		return fmt.Errorf("handing session %s's listeners to frisket: %w; no rules were installed", sess.Name, err)
	}
	// Ours are copies now, and every copy pins the namespace: closed before
	// the rules, so a steer that dies loading them leaves only the daemon's.
	control.CloseAll(files)
	files = nil
	_ = set.Close()

	// 3. The rules.
	if _, err := s.runIn(ctx, netns, p.Ruleset, or(s.Nft, "nft"), "-f", "-"); err != nil {
		_, cerr := s.callDaemon(ctx, control.Request{Op: control.OpClose, Name: sess.Name}, nil)
		if cerr != nil {
			return fmt.Errorf("loading session %s's ruleset: %w; and closing the session failed too: %v", sess.Name, err, cerr)
		}
		return fmt.Errorf("loading session %s's ruleset: %w; the session was closed", sess.Name, err)
	}
	return nil
}

// sockFile is a descriptor for sock to send: a dup, closed by the caller.
func sockFile(sock *nsnet.Sock) (*os.File, error) {
	switch {
	case sock.Listener != nil:
		if l, ok := sock.Listener.(*net.TCPListener); ok {
			return l.File()
		}
	case sock.Packet != nil:
		if c, ok := sock.Packet.(*net.UDPConn); ok {
			return c.File()
		}
	}
	return nil, fmt.Errorf("%s is not a TCP listener or a UDP socket", sock.Spec)
}

// ErrOutOfOrder is what Connect says when it is called before Steer finished.
var ErrOutOfOrder = errors.New("connect runs after steer, never before")

// Connect provisions the namespace's connectivity -- the service address on
// lo, and for `all` the dummy interface and its default routes -- and refuses
// to unless everything that must precede it is in place: the daemon holds this
// session, the session is THIS namespace's, and the namespace has frisket's
// table loaded.
func (s *Steerer) Connect(ctx context.Context, netns string, p *Plan, name string) error {
	resp, err := s.callDaemon(ctx, control.Request{Op: control.OpList}, nil)
	if err != nil {
		return fmt.Errorf("asking frisket about session %s: %w; no egress was provisioned", name, err)
	}
	var st *control.Status
	for i := range resp.Sessions {
		if resp.Sessions[i].Name == name {
			st = &resp.Sessions[i]
		}
	}
	if st == nil {
		return fmt.Errorf("frisket holds no session %s: %w; no egress was provisioned", name, ErrOutOfOrder)
	}
	// The namespace at the path we were given is the one the listeners were
	// made in, as the helper saw it from inside after its setns.
	here, err := os.Readlink(netns)
	if err != nil {
		return fmt.Errorf("reading %s: %w; no egress was provisioned", netns, err)
	}
	if here != st.Netns {
		return fmt.Errorf("session %s's listeners are in %s, and %s is %s; no egress was provisioned", name, st.Netns, netns, here)
	}
	if _, err := s.runIn(ctx, netns, "", or(s.Nft, "nft"), "list", "table", "inet", p.Table); err != nil {
		return fmt.Errorf("session %s has no table inet %s loaded (%v): %w; no egress was provisioned", name, p.Table, err, ErrOutOfOrder)
	}
	// And nothing has given it egress already. Whatever runs between steer
	// and here -- a consumer's own rules -- must not provision any, and a
	// second egress beside the dummy, or before pasta, is a way round the
	// rules nobody meant to build.
	links, err := s.runIn(ctx, netns, "", or(s.IP, "ip"), "-o", "link", "show")
	if err != nil {
		return fmt.Errorf("listing session %s's interfaces: %w; no egress was provisioned", name, err)
	}
	if extra := nonLoopback(links); len(extra) > 0 {
		return fmt.Errorf("session %s's namespace already has %v besides lo: %w; no egress was provisioned", name, extra, ErrOutOfOrder)
	}
	if _, err := s.runIn(ctx, netns, p.ConnectBatch(), or(s.IP, "ip"), "-batch", "-"); err != nil {
		return fmt.Errorf("provisioning session %s's egress: %w", name, err)
	}
	return nil
}

// nonLoopback reads `ip -o link show` and returns every interface but lo:
// "2: eth0@if7: <...>" is eth0.
func nonLoopback(out string) []string {
	var extra []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimSuffix(f[1], ":"), "@")
		if name != "lo" {
			extra = append(extra, name)
		}
	}
	return extra
}

// Close ends a session. Closing one that is not open succeeds: teardown runs
// from the clean path and from the next launch's sweep, and must be safe for
// state that is already gone.
func (s *Steerer) Close(ctx context.Context, name string) (bool, error) {
	resp, err := s.callDaemon(ctx, control.Request{Op: control.OpClose, Name: name}, nil)
	if err != nil {
		return false, fmt.Errorf("closing session %s: %w", name, err)
	}
	return resp.Closed, nil
}

// Sessions lists what the daemon holds.
func (s *Steerer) Sessions(ctx context.Context) ([]control.Status, error) {
	resp, err := s.callDaemon(ctx, control.Request{Op: control.OpList}, nil)
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}
