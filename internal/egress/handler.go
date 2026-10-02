package egress

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/internal/intercept"
	recording "github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/internal/steer"
)

// What the egress line says happened. "failed" is kept apart from "refused":
// refused is policy saying no, failed is the upstream not answering, and a log
// that lumps them together cannot tell an attack from an outage.
const (
	DecisionAccepted = "accepted"
	DecisionRefused  = "refused"
	DecisionFailed   = "failed"
)

// ReasonNotResolved: the address was not in the session's resolved set. The
// workload dialled a literal address, used its own resolver, or held on to an
// answer past its (clamped) lifetime.
const ReasonNotResolved = "not resolved by this session"

// Policy is the per-session egress decision: the structural classifier, then
// the session's resolved set.
type Policy struct {
	Classifier *Classifier
	Resolved   *Resolved
	// LAN is what the session may reach on the local network, or nil for a
	// document that names nothing there.
	LAN *LAN
}

// LAN is a document's names on the local network, for one session: the
// addresses its DNS gave for them, kept apart from the resolved set, and
// the ports each may be reached at.
type LAN struct {
	Resolved *Resolved
	// Ports are each name's ports: empty for every port. A name not here
	// is no LAN name.
	Ports map[string][]uint16
}

// ReasonLAN is the reason on an egress line for a connection admitted to
// the local network by the document's lan names.
const ReasonLAN = "lan"

// Decision is Policy's answer for one destination.
type Decision struct {
	Allowed bool
	// Reason is empty when allowed.
	Reason string
	// Refusal is set when the refusal was structural.
	Refusal Refusal
	// Entry is the session's DNS answer for this address, if there is one. It
	// is looked up even when the address is refused, because "refused, and it
	// was api.example.com that resolved to it" is the most useful line a
	// rebinding attempt can leave in the log -- but it is a LABEL there, and
	// nothing reads it to make the decision.
	Entry    Entry
	Resolved bool
	// LAN is a destination on the local network admitted by the document's
	// lan names, which is dialled through ClassifyLAN.
	LAN bool
}

// Decide applies the policy to dst.
//
// Structural first, and nothing after it can undo it: a refused address stays
// refused whatever the resolved set holds. The other order is ottergate's, and
// with 0.0.0.0/0 on its allowlist it accepts 169.254.169.254.
func (p *Policy) Decide(dst netip.Addr) Decision {
	refusal := p.Classifier.Classify(dst)
	entry, resolved := p.Resolved.Lookup(dst)
	d := Decision{Refusal: refusal, Entry: entry, Resolved: resolved}
	switch {
	case refusal.Refused():
		d.Reason = "structural: " + refusal.String()
	case !resolved:
		d.Reason = ReasonNotResolved
	default:
		d.Allowed = true
	}
	return d
}

// DecideLAN is d, for dst, unless d refused it only as on the local
// network -- private, unique-local or link-local, written as itself -- and
// the session's DNS gave dst's address for one of the document's lan names,
// which may be reached at dst's port: then it is admitted, if ClassifyLAN
// does not refuse it as the host's own address, a router of the host's, on
// a network only the host is on, or a metadata service. Only by name: an
// address no lan name resolved to, a literal IP among them, stays refused.
func (p *Policy) DecideLAN(dst netip.AddrPort, d Decision) Decision {
	if d.Allowed || p.LAN == nil || !lan(d.Refusal) {
		return d
	}
	e, ok := p.LAN.Resolved.Lookup(dst.Addr())
	if !ok {
		return d
	}
	ports, named := p.LAN.Ports[e.Name]
	if !named || len(ports) > 0 && !slices.Contains(ports, dst.Port()) {
		return d
	}
	d.Entry, d.Resolved = e, true
	if r := p.Classifier.ClassifyLAN(dst.Addr()); r.Refused() {
		d.Refusal, d.Reason = r, "structural: "+r.String()
		return d
	}
	d.Allowed, d.Reason, d.LAN = true, ReasonLAN, true
	return d
}

// Handler is the steer.Handler for egress: decide, dial, splice, and log
// exactly one line when the connection is over.
type Handler struct {
	Policy *Policy
	Dialer *Dialer
	// PolicyName labels the line; it is the session's named policy.
	PolicyName string
	// Log is injected, never a package logger: "one line per connection" is
	// asserted by tests through it.
	Log *slog.Logger
	// Idle is the splice's idle limit; zero means DefaultIdle.
	Idle time.Duration
	// Record makes the session a recording one. Nil without a record block.
	Record *Recording
}

// Recording is what a recording session's egress decides with: the names
// its DNS resolved that the policy does not allow, kept apart from the
// resolved set, and who decides a connection to one.
type Recording struct {
	Recorder *recording.Recorder
	// Unlisted are the addresses the session's DNS resolved for names the
	// policy does not allow.
	Unlisted *Resolved
	// Asker is put a connection to when the recorder has no default.
	Asker     intercept.Asker
	Workspace string
}

// RuleRecorded is the reason on an egress line for a connection a recording
// session admitted that its policy would have refused.
const RuleRecorded = "recorded"

var _ steer.Handler = (*Handler)(nil)

// ServeConn owns c and closes it.
func (h *Handler) ServeConn(ctx context.Context, c *steer.Conn) {
	start := time.Now()
	defer c.Close()

	dst := c.Orig
	d := h.Policy.DecideLAN(dst, h.Policy.Decide(dst.Addr()))
	line := egressLine{conn: c, policy: h.PolicyName, decision: d}

	lanDst := false
	if !d.Allowed && h.Record != nil {
		if e, ok := h.Record.Unlisted.Lookup(dst.Addr()); ok && !d.Resolved {
			// Named on the line as the session's DNS named it, though the
			// policy does not allow it.
			line.decision.Entry = e
		}
		var reason string
		reason, lanDst = h.record(ctx, c, d)
		switch reason {
		case "":
			line.decision.Allowed, line.decision.Reason = true, RuleRecorded
		case d.Reason:
		default:
			line.decision.Reason += "; " + reason
		}
	}
	if !line.decision.Allowed {
		line.outcome = DecisionRefused
		h.log(line, start)
		return
	}

	dial := h.Dialer.DialTCP
	if lanDst || line.decision.LAN {
		dial = h.Dialer.DialLAN
	}
	up, err := dial(ctx, dst)
	if err != nil {
		if re, ok := AsRefused(err); ok {
			// Classify said yes a moment ago and Control, looking at the
			// address actually being dialled, said no: the host gained that
			// address in between. Control wins; that is why it is there.
			line.outcome = DecisionRefused
			line.decision.Refusal = re.Refusal
			line.decision.Reason = "structural at dial: " + re.Refusal.String()
		} else {
			line.outcome = DecisionFailed
			line.err = err
		}
		h.log(line, start)
		return
	}
	defer up.Close()

	idle := h.Idle
	if idle == 0 {
		idle = DefaultIdle
	}
	line.outcome = DecisionAccepted
	line.splice = Splice(ctx, c.TCPConn, up, idle)
	line.err = line.splice.Err
	h.log(line, start)
}

type egressLine struct {
	conn     *steer.Conn
	policy   string
	decision Decision
	outcome  string
	splice   SpliceResult
	err      error
}

func (h *Handler) log(l egressLine, start time.Time) {
	attrs := []any{
		"session", l.conn.Session,
		"conn", l.conn.ID,
		"policy", l.policy,
		"peer", l.conn.Peer.String(),
		"dst", l.conn.Orig.String(),
	}
	if l.decision.Resolved || l.decision.Entry.Name != "" {
		attrs = append(attrs, "name", l.decision.Entry.Name, "dns_query", l.decision.Entry.Query)
	}
	attrs = append(attrs, "decision", l.outcome)
	if l.decision.Reason != "" {
		attrs = append(attrs, "reason", l.decision.Reason)
	}
	attrs = append(attrs,
		"bytes_out", l.splice.Out,
		"bytes_in", l.splice.In,
		"duration_ms", float64(time.Since(start).Microseconds())/1000,
	)
	if l.splice.Idle {
		attrs = append(attrs, "idle", true)
	}
	if l.err != nil {
		attrs = append(attrs, "error", l.err.Error())
	}
	h.Log.Info("egress", attrs...)
}

// record decides, in a recording session, a connection the policy refused:
// one to an address the session's DNS resolved for a name off the
// allowlist, or for any name to an address on the local network. It
// returns why it stays refused, or "" if it is admitted, and whether the
// destination is on the local network, to be dialled as such. A connection
// to an address nobody resolved, and every other structural refusal, stays
// refused, and is written down as that.
func (h *Handler) record(ctx context.Context, c *steer.Conn, d Decision) (reason string, lanDst bool) {
	rc := h.Record
	dst := c.Orig
	l := recording.Line{
		Session: c.Session,
		Kind:    recording.KindEgress,
		Port:    dst.Port(),
		Address: dst.String(),
		Would:   string(recording.Refuse),
		Rule:    d.Reason,
	}
	name := d.Entry.Name
	unlisted, listed := rc.Unlisted.Lookup(dst.Addr())
	if !d.Resolved && listed {
		name = unlisted.Name
	}
	resolved := d.Resolved || listed
	switch {
	case !resolved:
		// A literal address, or an answer held past its life: there is no
		// name to grant, and no address is granted by itself.
		rc.Recorder.Hard(l, "address "+dst.String(), d.Reason)
		return d.Reason, false
	case d.Refusal.Refused():
		if r := h.Policy.Classifier.ClassifyLAN(dst.Addr()); r.Refused() {
			l.Name = name
			rc.Recorder.Hard(l, "address "+dst.String(), "structural: "+r.String())
			return "structural: " + r.String(), false
		}
		lanDst = true
	default:
		l.Rule = recording.RuleNotAllowed
	}
	l.Name, l.LAN = name, lanDst
	key := name + ":" + strconv.Itoa(int(dst.Port()))
	if lanDst {
		key += " lan"
	}
	res := rc.Recorder.Decide(ctx, l, key, func(ctx context.Context) (recording.Answer, string, error) {
		// Nothing reads the workload's side while it waits, so nothing
		// would notice it go: a question about a connection nobody holds
		// any more would stay open, and hold the asker's turn, until
		// somebody answered it.
		ctx, stop := whileOpen(ctx, c.TCPConn)
		defer stop()
		q := intercept.Question{
			Session:   c.Session,
			Workspace: rc.Workspace,
			Policy:    h.PolicyName,
			Kind:      intercept.KindEgress,
			Host:      name,
			Address:   dst.String(),
			Record:    true,
			LAN:       lanDst,
			ID:        recording.ID(c.Session, recording.KindEgress, key),
		}
		a, reason, err := intercept.AskAbout(ctx, rc.Asker, q)
		if err != nil {
			h.Log.Error("ask", "session", c.Session, "conn", c.ID, "dst", dst.String(), "error", err.Error())
		}
		a, reason = intercept.RecordAnswer(a, reason)
		return a, reason, nil
	})
	switch {
	case res.Answer.Admits():
		return "", lanDst
	case res.Reason != "":
		return res.Reason, lanDst
	}
	return intercept.ReasonRecordRefused, lanDst
}

// whileOpen is ctx, cancelled too once the workload has closed its side of
// c -- shut down its writing, or gone, which a socket cannot tell apart --
// as net/http's request context is once its client's side ends. Nothing is
// read: what the workload sent waits in the socket for the splice. Stop it
// before c is closed, which waits for the watch to let go.
func whileOpen(ctx context.Context, c *net.TCPConn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	if c == nil {
		return ctx, cancel
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return ctx, cancel
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rc.Control(func(fd uintptr) {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
			for ctx.Err() == nil {
				n, err := unix.Poll(fds, int(closeWatch/time.Millisecond))
				switch {
				case err == unix.EINTR:
				case err != nil:
					return
				case n > 0 && fds[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0:
					cancel()
					return
				}
			}
		})
	}()
	return ctx, func() {
		cancel()
		<-done
	}
}

// closeWatch is how often whileOpen looks up from its poll to see whether
// it is still wanted.
const closeWatch = 100 * time.Millisecond
