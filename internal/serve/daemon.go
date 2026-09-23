package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/nsnet"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"golang.org/x/sys/unix"
)

// ControlName is the FileDescriptorName= of the socket unit's control socket,
// so it can be told apart from stored sessions in LISTEN_FDNAMES.
const ControlName = "control"

// closeWait bounds how long closing a session waits for its handlers to return
// after every descriptor is already closed.
const closeWait = 5 * time.Second

// Notifier is the part of sd_notify the daemon uses. Nil means "not under
// systemd", and then sessions do not survive a restart -- which is said once,
// loudly, at start.
type Notifier interface {
	Ready(status string) error
	Stopping() error
	Store(name string, files ...*os.File) error
	Remove(name string) error
}

// Daemon holds every session.
type Daemon struct {
	// Log is injected. Every line the daemon and its sessions write goes
	// through it, so a test can hold it to "one line per connection".
	Log *slog.Logger
	// Policies opens a session's policy from its path. A session whose
	// policy cannot be opened is refused, and so never gets rules: a missing
	// or broken policy fails closed.
	Policies Policies
	// Notify is systemd, or nil.
	Notify Notifier
	// ControlUID is the only peer uid the control socket answers: the
	// daemon's own user in production, who runs the launchers. The socket
	// unit makes the socket that user's, 0600, as well, and this is the check
	// that does not depend on a file mode.
	ControlUID int
	// MaxConns caps each session's concurrent connections.
	MaxConns int
	// PolicyDir is where a session stored before policies were documents
	// finds its policy: its record names one, and it is read as
	// PolicyDir/<name>.json. Empty: such a session is not restored.
	PolicyDir string

	// own is this process's network namespace cookie; zero means "read it at
	// Run". A listener in this namespace is refused.
	own uint64
	// userns is this process's user namespace, read at Run: the only one a
	// control peer may be in.
	userns nsKey
	// dst replaces the destination lookup, for tests that have no ruleset.
	dst func(*net.TCPConn) netip.AddrPort

	mu       sync.Mutex
	ctx      context.Context
	sessions map[string]*session
}

// Run serves the control socket and every session until ctx is done.
// inherited is what systemd passed at start: the control socket, if socket
// activated, is not among them -- the caller takes it out -- and everything
// else is a stored session to adopt.
//
// On the way out every descriptor is closed but NOTHING IS REMOVED FROM THE
// STORE: stopping the daemon is not closing its sessions. PID 1 still holds
// them, the sandboxes' namespaces stay alive across the gap, and the next
// start adopts them.
func (d *Daemon) Run(ctx context.Context, ctl *net.UnixListener, inherited []sdnotify.FD) error {
	if d.own == 0 {
		c, err := ownCookie()
		if err != nil {
			return fmt.Errorf("reading this process's namespace: %w", err)
		}
		d.own = c
	}
	u, err := ownUserns()
	if err != nil {
		return fmt.Errorf("reading this process's user namespace: %w", err)
	}
	d.userns = u
	d.mu.Lock()
	d.ctx = ctx
	d.sessions = make(map[string]*session)
	d.mu.Unlock()

	d.adopt(inherited)

	if d.Notify == nil {
		d.Log.Warn("not running under systemd: sessions will not survive a restart of this process")
	} else if err := d.Notify.Ready(fmt.Sprintf("%d sessions", d.count())); err != nil {
		d.Log.Error("sd_notify READY", "error", err.Error())
	}

	stop := context.AfterFunc(ctx, func() { _ = ctl.Close() })
	defer stop()
	var wg sync.WaitGroup
	for {
		c, err := ctl.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			d.Log.Error("control accept", "error", err.Error())
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.handle(c)
		}()
	}
	wg.Wait()

	if d.Notify != nil {
		_ = d.Notify.Stopping()
	}
	d.mu.Lock()
	all := d.sessions
	d.sessions = nil
	d.mu.Unlock()
	for _, s := range all {
		s.closeAll(closeWait)
	}
	return nil
}

func (d *Daemon) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

// handle answers one control connection: one request, one response.
func (d *Daemon) handle(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := d.checkPeer(c); err != nil {
		d.Log.Warn("control refused", "error", err.Error())
		// Read and discard the request first -- closing any descriptors it
		// carried -- or closing a socket with unread data resets it, and the
		// refusal never arrives.
		if _, files, rerr := control.ReadRequest(c); rerr == nil {
			control.CloseAll(files)
		}
		_ = control.WriteResponse(c, control.Response{Error: err.Error()})
		return
	}
	req, files, err := control.ReadRequest(c)
	if err != nil {
		_ = control.WriteResponse(c, control.Response{Error: err.Error()})
		return
	}
	var resp control.Response
	switch req.Op {
	case control.OpOpen:
		if req.Session == nil {
			control.CloseAll(files)
			resp.Error = "open without a session"
			break
		}
		cert, err := d.Open(*req.Session, files)
		if err != nil {
			resp.Error = err.Error()
		}
		resp.CACert = cert
	case control.OpClose:
		control.CloseAll(files)
		closed, err := d.Close(req.Name)
		resp.Closed = closed
		if err != nil {
			resp.Error = err.Error()
		}
	case control.OpList:
		control.CloseAll(files)
		resp.Sessions = d.List()
	default:
		control.CloseAll(files)
		resp.Error = fmt.Sprintf("unknown operation %q", req.Op)
	}
	if err := control.WriteResponse(c, resp); err != nil {
		d.Log.Warn("control response", "op", req.Op, "error", err.Error())
	}
}

// Open creates a session from listeners root made inside a sandbox. It owns
// files from the moment it is called: every one is either held by the session
// or closed before this returns.
//
// Stored in the fd store BEFORE it is served and before the caller is told it
// exists -- so the caller's next step, the rules, never lands on a session a
// crash could lose.
//
// Returns the certificate of the session's CA, made here, for the caller to
// put in the sandbox.
func (d *Daemon) Open(info control.Session, files []*os.File) (caCert []byte, err error) {
	defer func() {
		if err != nil {
			control.CloseAll(files)
			d.Log.Error("session refused", "session", info.Name, "policy", info.Policy, "error", err.Error())
		}
	}()
	if err := info.Validate(); err != nil {
		return nil, err
	}
	policy, release, err := d.Policies.Open(info.Policy)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", info.Name, err)
	}
	// Released here unless a session came to hold it.
	held := false
	defer func() {
		if !held {
			release()
		}
	}()
	specs, err := parseSpecs(info.Listeners)
	if err != nil {
		return nil, err
	}
	if len(files) != len(specs) {
		return nil, fmt.Errorf("session %s: %d descriptors for %d listeners", info.Name, len(files), len(specs))
	}

	d.mu.Lock()
	if d.sessions == nil {
		d.mu.Unlock()
		return nil, errors.New("frisket is stopping")
	}
	if _, dup := d.sessions[info.Name]; dup {
		d.mu.Unlock()
		return nil, fmt.Errorf("session %s is already open", info.Name)
	}
	// Reserved while it is being built, so two opens of one name cannot both
	// get past the check above.
	d.sessions[info.Name] = nil
	d.mu.Unlock()
	defer func() {
		if err != nil {
			d.mu.Lock()
			if d.sessions != nil && d.sessions[info.Name] == nil {
				delete(d.sessions, info.Name)
			}
			d.mu.Unlock()
		}
	}()

	// Checked before anything is stored, against the kernel rather than the
	// request. adoptSockets checks all of this again; this copy is so that a
	// session that would be refused never reaches PID 1.
	infos := make([]sockInfo, len(specs))
	for i, spec := range specs {
		if infos[i], err = inspect(files[i]); err != nil {
			return nil, fmt.Errorf("session %s: %s: %w", info.Name, spec, err)
		}
		if err := infos[i].matches(spec); err != nil {
			return nil, fmt.Errorf("session %s: %w", info.Name, err)
		}
	}
	if err := sameForeignNamespace(specs, infos, d.own); err != nil {
		return nil, fmt.Errorf("session %s: %w", info.Name, err)
	}

	// The handlers before the record, because the record carries the CA the
	// policy makes with them.
	h, err := d.handlers(info, policy, nil)
	if err != nil {
		return nil, err
	}
	meta, err := newRecord(info, h.Authority)
	if err != nil {
		return nil, err
	}
	stored := false
	if d.Notify != nil {
		if err := d.Notify.Store(info.Name, append(append([]*os.File{}, files...), meta)...); err != nil {
			meta.Close()
			return nil, fmt.Errorf("session %s: storing its listeners with systemd: %w", info.Name, err)
		}
		stored = true
	}

	socks, err := adoptSockets(specs, files, d.own)
	files = nil // adoptSockets closed them, whatever happened
	if err != nil {
		meta.Close()
		if stored {
			_ = d.Notify.Remove(info.Name)
		}
		return nil, fmt.Errorf("session %s: %w", info.Name, err)
	}
	s := &session{info: info, log: d.Log, socks: socks, meta: meta, release: release}
	held = true
	if err := d.serve(s, h); err != nil {
		s.closeAll(closeWait)
		if stored {
			_ = d.Notify.Remove(info.Name)
		}
		return nil, err
	}
	d.Log.Info("session opened",
		"session", info.Name,
		"policy", info.Policy,
		"set", info.Set,
		"netns", info.Netns,
		"listeners", info.Listeners,
		"stored", stored,
	)
	return h.CACert, nil
}

// handlers asks the policy for the session's handlers and its CA.
func (d *Daemon) handlers(info control.Session, policy Policy, authority []byte) (Handlers, error) {
	h, err := policy.Handlers(info, authority, d.Log)
	if err != nil {
		return Handlers{}, fmt.Errorf("session %s: policy %s: %w", info.Name, info.Policy, err)
	}
	if h.Egress == nil || h.Intercept == nil || h.DNS == nil {
		return Handlers{}, fmt.Errorf("session %s: policy %s has no handler for egress, interception or DNS", info.Name, info.Policy)
	}
	if len(h.Authority) == 0 || len(h.CACert) == 0 {
		return Handlers{}, fmt.Errorf("session %s: policy %s gave the session no CA", info.Name, info.Policy)
	}
	return h, nil
}

// serve starts the session with its handlers.
func (d *Daemon) serve(s *session, h Handlers) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		return errors.New("frisket is stopping")
	}
	s.start(d.ctx, Dispatch{Service: s.info.Service, Handlers: h}, d.MaxConns, d.dst)
	d.sessions[s.info.Name] = s
	return nil
}

// Close ends a session: every descriptor it holds is closed, and its entry in
// the fd store is dropped, because PID 1's copy pins the sandbox's namespace
// exactly as ours does. Closing a session that is not open is not an error --
// teardown runs from the clean path and from a later launch's sweep, and must
// be safe to run for state that is already gone -- and says so with closed.
func (d *Daemon) Close(name string) (closed bool, err error) {
	if err := control.ValidName(name); err != nil {
		return false, err
	}
	d.mu.Lock()
	s, ok := d.sessions[name]
	if ok && s != nil {
		delete(d.sessions, name)
	}
	d.mu.Unlock()
	if !ok || s == nil {
		d.Log.Info("session close", "session", name, "action", "none", "reason", "no such session")
		return false, nil
	}
	n := s.closeAll(closeWait)
	var storeErr error
	if d.Notify != nil {
		storeErr = d.Notify.Remove(name)
	}
	attrs := []any{"session", name, "descriptors", n}
	if storeErr != nil {
		attrs = append(attrs, "error", storeErr.Error())
	}
	d.Log.Info("session closed", attrs...)
	if storeErr != nil {
		return true, fmt.Errorf("session %s closed, but systemd still holds its listeners: %w", name, storeErr)
	}
	return true, nil
}

// List reports every session, in name order.
func (d *Daemon) List() []control.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]control.Status, 0, len(d.sessions))
	for _, s := range d.sessions {
		if s == nil {
			continue
		}
		out = append(out, control.Status{Session: s.info, Descriptors: s.descriptors(), Restored: s.restored})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// adopt rebuilds the sessions systemd kept in the fd store across a restart.
// Each is a name, a sealed record and its listeners; one that does not add up
// is dropped from the store and every descriptor of it closed, because a
// session nobody can serve is only a pinned namespace.
func (d *Daemon) adopt(inherited []sdnotify.FD) {
	groups := map[string][]*os.File{}
	var order []string
	for _, fd := range inherited {
		if _, seen := groups[fd.Name]; !seen {
			order = append(order, fd.Name)
		}
		groups[fd.Name] = append(groups[fd.Name], fd.File)
	}
	for _, name := range order {
		files := groups[name]
		if err := d.adoptOne(name, files); err != nil {
			d.Log.Error("session not restored", "session", name, "descriptors", len(files), "error", err.Error())
			if d.Notify != nil && control.ValidName(name) == nil {
				_ = d.Notify.Remove(name)
			}
		}
	}
}

func (d *Daemon) adoptOne(name string, files []*os.File) (err error) {
	// Whatever is not handed to the session is closed.
	defer func() { control.CloseAll(files) }()

	var meta *os.File
	var socks []*os.File
	var infos []sockInfo
	for i, f := range files {
		si, err := inspect(f)
		if errors.Is(err, unix.ENOTSOCK) {
			if meta != nil {
				return errors.New("two session records")
			}
			meta, files[i] = f, nil
			continue
		}
		if err != nil {
			return err
		}
		socks = append(socks, f)
		infos = append(infos, si)
	}
	if meta == nil {
		return errors.New("no session record")
	}
	info, authority, err := readRecord(meta)
	if err != nil {
		meta.Close()
		return err
	}
	if info.Name != name {
		meta.Close()
		return fmt.Errorf("record names session %q", info.Name)
	}
	// Opened under a policy named rather than a document: the name is the
	// document of that name, so a switch to this daemon does not cut off a
	// session that was running before it.
	if d.PolicyDir != "" && control.ValidName(info.Policy) == nil {
		info.Policy = filepath.Join(d.PolicyDir, info.Policy+".json")
	}
	if err := info.Validate(); err != nil {
		meta.Close()
		return err
	}
	// Read again, not remembered: a document that changed while the daemon
	// was down serves the session as it reads now.
	policy, release, err := d.Policies.Open(info.Policy)
	if err != nil {
		meta.Close()
		return err
	}
	held := false
	defer func() {
		if !held {
			release()
		}
	}()
	specs, err := parseSpecs(info.Listeners)
	if err != nil {
		meta.Close()
		return err
	}
	// The store gives them back in no promised order, so each is matched to
	// its spec by what the kernel says it is.
	ordered := make([]*os.File, len(specs))
	for i, spec := range specs {
		for j, si := range infos {
			if socks[j] != nil && si.matches(spec) == nil {
				ordered[i], socks[j] = socks[j], nil
				break
			}
		}
		if ordered[i] == nil {
			control.CloseAll(ordered)
			meta.Close()
			return fmt.Errorf("no stored listener for %s", spec)
		}
	}
	for _, f := range socks {
		if f != nil {
			control.CloseAll(ordered)
			meta.Close()
			return errors.New("a stored socket matches none of the record's listeners")
		}
	}
	// Everything is now either in ordered or meta; files must not close it.
	for i := range files {
		files[i] = nil
	}
	// A record from before sessions had CAs of their own: the sandbox trusts
	// a CA this daemon does not have, so the policy makes a new one that
	// nothing in the sandbox trusts. Everything but interception still works,
	// and the session is kept rather than cut off.
	if len(authority) == 0 {
		d.Log.Warn("session restored without its CA: its intercepted hosts fail until it is relaunched", "session", name)
	}
	h, err := d.handlers(info, policy, authority)
	if err != nil {
		control.CloseAll(ordered)
		meta.Close()
		return err
	}
	socksHeld, err := adoptSockets(specs, ordered, d.own)
	if err != nil {
		meta.Close()
		return err
	}
	s := &session{info: info, restored: true, log: d.Log, socks: socksHeld, meta: meta, release: release}
	held = true
	d.mu.Lock()
	d.sessions[name] = nil
	d.mu.Unlock()
	if err := d.serve(s, h); err != nil {
		s.closeAll(closeWait)
		d.mu.Lock()
		delete(d.sessions, name)
		d.mu.Unlock()
		return err
	}
	d.Log.Info("session restored", "session", name, "policy", info.Policy, "set", info.Set,
		"netns", info.Netns, "listeners", info.Listeners)
	return nil
}

func parseSpecs(ls []string) ([]nsnet.Spec, error) {
	specs := make([]nsnet.Spec, len(ls))
	for i, l := range ls {
		s, err := nsnet.ParseSpec(l)
		if err != nil {
			return nil, err
		}
		specs[i] = s
	}
	return specs, nil
}
