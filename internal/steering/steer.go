package steering

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
)

// Where a session's CA is, inside the sandbox: a read-only tmpfs of its own
// at CADir, holding the certificate and the bundle.
const (
	CADir        = "/etc/frisket"
	CACertFile   = "ca.crt"
	CABundleFile = "ca-bundle.crt"
)

// Steerer runs the launcher's steps. The zero value's seams are the real ones; tests
// replace them to watch the order.
type Steerer struct {
	Helper  nsnet.Helper
	Control string // the daemon's control socket
	Nft     string // nft, by name or path, resolved on the host

	enter func(ctx context.Context, args nsnet.HelperArgs) (*nsnet.Set, inside, error)
	call  func(ctx context.Context, req control.Request, files []*os.File) (control.Response, error)
}

// inside is a helper in the session's namespace, answering requests (Serve).
type inside interface {
	Do(ctx context.Context, req, result any) error
	Close() error
}

// enterNs starts the helper inside the namespace, making args.Specs there
// first. Each step enters once, and does the rest of its work inside through
// the helper it gets back.
func (s *Steerer) enterNs(ctx context.Context, args nsnet.HelperArgs) (*nsnet.Set, inside, error) {
	if s.enter != nil {
		return s.enter(ctx, args)
	}
	e, err := nsnet.Enter(ctx, s.Helper, args)
	if err != nil {
		return nil, nil, err
	}
	return e.Set, e, nil
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

// nftPath is nft, resolved against this process's PATH, so the answer is the
// host's.
func (s *Steerer) nftPath() (string, error) {
	nft := s.Nft
	if nft == "" {
		nft = "nft"
	}
	path, err := exec.LookPath(nft)
	if err != nil {
		return "", fmt.Errorf("finding %s: %w", nft, err)
	}
	return filepath.Abs(path)
}

// Session is what steer is asked to create, and where its CA goes.
type Session struct {
	Name   string
	Policy string
	Params map[string]string
	// Mntns is the sandbox's mount namespace, /proc/<pid>/ns/mnt, where the
	// session's CA is put.
	Mntns string
	// Roots is the host's CA bundle, which the session's bundle is made from.
	Roots string
}

// Steer creates the session's listeners inside the namespace at netns, hands
// them to the daemon, and only then installs the policy routing and loads the
// ruleset that steers to them -- and then puts the CA the daemon made for the
// session into the sandbox. It does NOT provision egress: that is Connect,
// and it is the caller's next step.
//
// Every failure before the rules is a session with no rules, which with no
// egress either is a sandbox with nowhere to go -- closed, not open. A failure
// loading the rules closes the session it had just created, so nothing is left
// holding listeners for a namespace that was never steered to them.
func (s *Steerer) Steer(ctx context.Context, netns string, p *Plan, sess Session) error {
	// Opened first, so a missing file is refused before anything exists.
	roots, err := os.Open(sess.Roots)
	if err != nil {
		return fmt.Errorf("session %s: the host's roots: %w; no rules were installed", sess.Name, err)
	}
	roots.Close()
	nft, err := s.nftPath()
	if err != nil {
		return fmt.Errorf("session %s: %w; no rules were installed", sess.Name, err)
	}

	// 1. Listeners, inside, from a namespace that has no egress yet. The
	// helper that made them stays in there for the rest of this step.
	set, in, err := s.enterNs(ctx, nsnet.HelperArgs{Netns: netns, Specs: p.Listeners, Isolated: true})
	if err != nil {
		return fmt.Errorf("creating session %s's listeners: %w; no rules were installed", sess.Name, err)
	}
	// Its exit is not checked: every request it made was answered by then,
	// and a failed one has already failed the step.
	defer in.Close()
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
		Mark:      p.Mark,
		Listeners: listeners,
		Netns:     set.Netns,
	}}
	opened, err := s.callDaemon(ctx, req, files)
	if err != nil {
		return fmt.Errorf("handing session %s's listeners to frisket: %w; no rules were installed", sess.Name, err)
	}
	// Ours are copies now, and every copy pins the namespace: closed before
	// the rules, so a steer that dies loading them leaves only the daemon's.
	control.CloseAll(files)
	files = nil
	_ = set.Close()

	// 3. The rules: the policy routing first, so that from the moment
	// anything is marked, a marked packet has somewhere to go -- lo -- and
	// then the ruleset. Nothing has egress yet, so neither can be raced.
	closeOnFailure := func(step string, err error) error {
		_, cerr := s.callDaemon(ctx, control.Request{Op: control.OpClose, Name: sess.Name}, nil)
		if cerr != nil {
			return fmt.Errorf("%s for session %s: %w; and closing the session failed too: %v", step, sess.Name, err, cerr)
		}
		return fmt.Errorf("%s for session %s: %w; the session was closed", step, sess.Name, err)
	}
	routing := append(p.RoutingSteps(false), p.RoutingSteps(true)...)
	if err := in.Do(ctx, request{Op: opApply, Steps: routing}, nil); err != nil {
		return closeOnFailure("installing the policy routing", err)
	}
	if err := in.Do(ctx, request{Op: opRuleset, Nft: nft, Ruleset: p.Ruleset}, nil); err != nil {
		return closeOnFailure("loading the ruleset", err)
	}

	// 4. The session's CA, in the sandbox: the certificate the daemon made
	// for it, and the host's roots with it, on a read-only tmpfs of their own.
	// Before the payload starts, which waits for this hook; a sandbox that
	// cannot be given its CA is closed rather than run distrusting it.
	if len(opened.CACert) == 0 {
		return closeOnFailure("putting the CA in the sandbox", errors.New("frisket made the session no CA"))
	}
	if err := in.Do(ctx, request{Op: opMount, Mntns: sess.Mntns, Dir: CADir, Entered: s.Helper.Rootless(), CACert: opened.CACert, Roots: sess.Roots}, nil); err != nil {
		return closeOnFailure("putting the CA in the sandbox", err)
	}
	return nil
}

func family(v6 bool) string {
	if v6 {
		return "-6"
	}
	return "-4"
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
// policy routing and table loaded.
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
	// Entered only now, so a session out of turn is refused before anything
	// goes inside; and once, for every check and change below.
	_, in, err := s.enterNs(ctx, nsnet.HelperArgs{Netns: netns})
	if err != nil {
		return fmt.Errorf("entering session %s's namespace: %w; no egress was provisioned", name, err)
	}
	defer in.Close()
	if err := in.Do(ctx, request{Op: opTable, Name: p.Table}, nil); err != nil {
		return fmt.Errorf("session %s has no table inet %s loaded (%v): %w; no egress was provisioned", name, p.Table, err, ErrOutOfOrder)
	}
	// The policy routing, both families. Without it a marked packet follows
	// the ordinary routes, and in the `service` set that is out through the
	// sandbox's own network; the ruleset's guard drops it there, but the
	// guard is the second line and this is the first.
	for _, v6 := range []bool{false, true} {
		var rs []ruleInfo
		err := in.Do(ctx, request{Op: opRules, V6: v6}, &rs)
		if err == nil && !hasMarkRule(rs, p.Mark, p.RouteTable) {
			err = fmt.Errorf("no rule sending fwmark %#x to table %d", p.Mark, p.RouteTable)
		}
		if err != nil {
			return fmt.Errorf("session %s's %s policy routing: %v: %w; no egress was provisioned", name, family(v6), err, ErrOutOfOrder)
		}
		var routes []routeInfo
		err = in.Do(ctx, request{Op: opRoutes, V6: v6, Table: p.RouteTable}, &routes)
		if err == nil && !hasLocalDefault(routes) {
			err = fmt.Errorf("table %d has no local default route on lo", p.RouteTable)
		}
		if err != nil {
			return fmt.Errorf("session %s's %s policy routing: %v: %w; no egress was provisioned", name, family(v6), err, ErrOutOfOrder)
		}
	}
	// And nothing has given it egress already. Whatever runs between steer
	// and here -- a consumer's own rules -- must not provision any, and a
	// second egress beside the dummy, or before pasta, is a way round the
	// rules nobody meant to build.
	var names []string
	if err := in.Do(ctx, request{Op: opLinks}, &names); err != nil {
		return fmt.Errorf("listing session %s's interfaces: %w; no egress was provisioned", name, err)
	}
	if extra := nonLoopback(names); len(extra) > 0 {
		return fmt.Errorf("session %s's namespace already has %v besides lo: %w; no egress was provisioned", name, extra, ErrOutOfOrder)
	}
	if err := in.Do(ctx, request{Op: opApply, Steps: p.ConnectSteps()}, nil); err != nil {
		return fmt.Errorf("provisioning session %s's egress: %w", name, err)
	}
	return nil
}

// hasMarkRule reports whether a rule sends mark, the whole of it, to table.
func hasMarkRule(rs []ruleInfo, mark uint32, table int) bool {
	for _, r := range rs {
		if r.Mark == mark && r.Mask == ^uint32(0) && r.Table == table {
			return true
		}
	}
	return false
}

// hasLocalDefault reports whether routes hold `local default dev lo`.
func hasLocalDefault(routes []routeInfo) bool {
	for _, r := range routes {
		if r.Local && r.Default && r.Dev == "lo" {
			return true
		}
	}
	return false
}

// nonLoopback is every interface but lo.
func nonLoopback(names []string) []string {
	var extra []string
	for _, n := range names {
		if n != "lo" {
			extra = append(extra, n)
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
