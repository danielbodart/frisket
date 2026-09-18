package egress

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

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
}

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
}

var _ steer.Handler = (*Handler)(nil)

// ServeConn owns c and closes it.
func (h *Handler) ServeConn(ctx context.Context, c *steer.Conn) {
	start := time.Now()
	defer c.Close()

	dst := c.Orig
	d := h.Policy.Decide(dst.Addr())
	line := egressLine{conn: c, policy: h.PolicyName, decision: d}

	if !d.Allowed {
		line.outcome = DecisionRefused
		h.log(line, start)
		return
	}

	up, err := h.Dialer.DialTCP(ctx, dst)
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
	if l.decision.Resolved {
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
