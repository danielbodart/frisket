// Package record is a recording session's other half: what its policy would
// refuse or ask about, decided by a default or by a person, remembered for
// the rest of the session, and written down as it happens -- one JSON line
// for each subject, precise enough to become a grant entry.
//
// A session records when its document has a record block, which chase
// writes at launch and only for `chase record`: someone is at the keyboard,
// doing the one thing that was refused, to find out what it needs. So a
// recording session is manual mode. Whatever the policy decides -- a path
// rule's refusal, an unmatched request, a guarded operation, an SSH
// command's ask, a name off the allowlist -- is the recorder's to decide
// instead. What no policy decides is not: a structural refusal, a
// credential or placeholder that does not hold, a Host that is not the SNI,
// a method override, a git request git would never send, a command the
// rules cannot read, anything on a Docker route, and a connection to an
// address nobody resolved stay exactly what they are in every session, and
// are written down as `hard`. Nor is the local network the default's: only
// a person answers for a LAN host.
//
// The package is a leaf: intercept, sshroute, egress and dns call it, and it
// calls none of them. A person is asked through a function the caller
// passes, built on its own Asker.
package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Answer is what is done with a subject, and what is recorded for it: allow
// and ask both admit it now, and differ only in what the grant will say.
type Answer string

const (
	Allow  Answer = "allow"
	Ask    Answer = "ask"
	Refuse Answer = "refuse"
)

// Admits is whether the subject goes ahead now.
func (a Answer) Admits() bool { return a == Allow || a == Ask }

// ParseAnswer reads an answer, in any case, around any space; ok is false
// for anything else, the empty string included.
func ParseAnswer(s string) (Answer, bool) {
	switch a := Answer(strings.ToLower(strings.TrimSpace(s))); a {
	case Allow, Ask, Refuse:
		return a, true
	}
	return "", false
}

// AllowIf is a yes-or-no as an answer: allow, or refuse.
func AllowIf(ok bool) Answer {
	if ok {
		return Allow
	}
	return Refuse
}

// Kinds of subject.
const (
	KindHTTP   = "http"
	KindSSH    = "ssh"
	KindEgress = "egress"
	KindDNS    = "dns"
)

// Where a line's answer came from.
const (
	// SourceDefault is the record block's default, with nobody asked.
	SourceDefault = "default"
	// SourceHuman is a person's answer, through the asker.
	SourceHuman = "human"
	// SourceUnanswered is a subject that was put to a person and refused
	// for want of an answer: the asker failed, the session already had a
	// question waiting, nobody was there, or the client stopped waiting.
	// Never remembered, so the next time is asked again.
	SourceUnanswered = "unanswered"
	// SourceHard is a refusal no recording overrides.
	SourceHard = "hard"
	// SourceTelemetry is a DNS name the policy does not allow, resolved
	// anyway so that the connection it is for can be decided. Nothing was
	// decided at DNS.
	SourceTelemetry = "telemetry"
)

// Bounds on what a line quotes of the workload's choosing.
const (
	maxPath    = 2048
	maxCommand = 4096
)

// Line is one subject, as the sink and the journal have it. Which fields
// are set depends on Kind:
//
//   - http: route, method, host, path, and operation where a rule matched
//     (its id; every id, comma-joined, for a request holding several), and
//     graphql where the request was read as GraphQL;
//   - ssh: route, user, address, command, operation as for http, and shell
//     for a shell route;
//   - egress: name and port, address the ip:port dialled, and lan for a
//     private or link-local destination;
//   - dns: name.
//
// would is what the policy would have done, refuse or ask, and rule what
// said so; answer and source are what was done instead, and reason why a
// refusal was one where it was not an answer.
type Line struct {
	Time      time.Time `json:"time"`
	Session   string    `json:"session"`
	Policy    string    `json:"policy"`
	Kind      string    `json:"kind"`
	Route     string    `json:"route,omitempty"`
	Method    string    `json:"method,omitempty"`
	Host      string    `json:"host,omitempty"`
	Path      string    `json:"path,omitempty"`
	Name      string    `json:"name,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	Address   string    `json:"address,omitempty"`
	User      string    `json:"user,omitempty"`
	Command   string    `json:"command,omitempty"`
	Shell     bool      `json:"shell,omitempty"`
	LAN       bool      `json:"lan,omitempty"`
	Operation string    `json:"operation,omitempty"`
	GraphQL   string    `json:"graphql,omitempty"`
	Would     string    `json:"would"`
	Rule      string    `json:"rule,omitempty"`
	Answer    Answer    `json:"answer"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason,omitempty"`
}

// bounded is s cut to n bytes, with "..." saying so. The sink is JSON, which
// escapes whatever else the workload chose.
func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// attrs are the line's fields for the journal, the empty ones left out.
func (l Line) attrs() []any {
	out := []any{"session", l.Session, "policy", l.Policy, "kind", l.Kind}
	add := func(k, v string) {
		if v != "" {
			out = append(out, k, v)
		}
	}
	add("route", l.Route)
	add("method", l.Method)
	add("host", l.Host)
	add("path", l.Path)
	add("name", l.Name)
	if l.Port != 0 {
		out = append(out, "port", l.Port)
	}
	add("address", l.Address)
	add("user", l.User)
	add("command", l.Command)
	if l.Shell {
		out = append(out, "shell", true)
	}
	if l.LAN {
		out = append(out, "lan", true)
	}
	add("operation", l.Operation)
	add("graphql", l.GraphQL)
	out = append(out, "would", l.Would)
	add("rule", l.Rule)
	out = append(out, "answer", string(l.Answer), "source", l.Source)
	add("reason", l.Reason)
	return out
}

// ID is a question's id: the same for the same subject in the same session,
// and different for any other, so a queue of questions can tell a second
// asking of one subject from a new one. Not a secret, and not a name: hex.
func ID(session, kind, key string) string {
	h := sha256.Sum256([]byte(session + "\x00" + kind + "\x00" + key))
	return hex.EncodeToString(h[:16])
}

// Config is a recorder's.
type Config struct {
	// Policy labels every line.
	Policy string
	// Default answers every subject. Empty puts each to a person.
	Default Answer
	// Sink is where lines are appended, as well as the journal; nil is the
	// journal alone.
	Sink *Sink
	// Log is the daemon's; each line goes to it as a "record" line.
	Log *slog.Logger
	// Now is the clock lines are stamped with. Nil is time.Now.
	Now func() time.Time
}

// maxMemo bounds what a recorder remembers of one session's decided
// subjects. Past it, subjects are still decided and written down, and a
// person may be asked about one again.
const maxMemo = 1 << 16

// maxNoise bounds the lines a session's hard refusals and DNS telemetry may
// write, apart from maxMemo: a sandbox resolving random names, or dialling
// every address in a range, writes a line for each, and those are lines no
// grant comes of. Past it they go to the journal alone and are not
// remembered, so the subjects a grant is made from -- answered by a default
// or a person -- always have room.
const maxNoise = 1 << 12

// Recorder decides and records the subjects of every session served under
// one document. It remembers each answer for the rest of its session.
type Recorder struct {
	cfg Config

	mu   sync.Mutex
	memo map[string]*entry
	// decided and noise count each session's remembered subjects, and its
	// noise lines, against maxMemo and maxNoise.
	decided map[string]int
	noise   map[string]int
}

// entry is one subject's answer, or the wait for it. Its fields are the
// recorder's lock's once done is closed, since a later answer may change
// them.
type entry struct {
	done   chan struct{}
	answer Answer
	// answered is false when the one asking got no answer; whoever waited
	// on it then decides again.
	answered bool
}

// New makes a recorder. The sink, if any, is the recorder's to close.
func New(cfg Config) (*Recorder, error) {
	if cfg.Log == nil {
		return nil, fmt.Errorf("record: no log")
	}
	switch cfg.Default {
	case "", Allow, Ask, Refuse:
	default:
		return nil, fmt.Errorf("record: default %q: allow, ask, refuse, or empty to ask a person", cfg.Default)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Recorder{cfg: cfg, memo: map[string]*entry{}, decided: map[string]int{}, noise: map[string]int{}}, nil
}

// Close closes the sink.
func (r *Recorder) Close() error {
	if r == nil || r.cfg.Sink == nil {
		return nil
	}
	return r.cfg.Sink.Close()
}

// Interactive is whether subjects are put to a person: the record block has
// no default.
func (r *Recorder) Interactive() bool { return r.cfg.Default == "" }

// Default is the record block's default answer, or "" when each subject is
// put to a person.
func (r *Recorder) Default() Answer { return r.cfg.Default }

// personal is whether a subject is put to a person: every one when there is
// no default, and one on the local network whatever the default. A default
// is an answer given before anything was seen, and the local network -- a
// NAS, a printer, a device's admin page -- is reached by a name anybody's
// wildcard DNS gives for any address, so a sandbox would choose what the
// default admitted.
func (r *Recorder) personal(l Line) bool { return r.Interactive() || l.LAN }

// Asking puts a subject to a person: their answer, or why there was none --
// the reason a refusal gives -- with the asker's own error, for the caller's
// log, if it failed.
type Asking func(ctx context.Context) (answer Answer, reason string, err error)

// Result is what was done with a subject.
type Result struct {
	Answer Answer
	Source string
	// Reason is why a subject went unanswered, and is "" when it was.
	Reason string
	// Err is the asker's failure, for the caller to log where it happened.
	Err error
}

// Decide answers a subject the policy would refuse or ask about: from the
// session's memory, from the default, or from a person by ask. key names the
// subject within its kind; l is its line, with would and rule filled in, and
// the rest filled in here. The first answer of a subject is written down and
// remembered. Two at once wait for one answer: a person is never asked the
// same thing twice over.
//
// A person's allow or refuse is the answer for the rest of the session, with
// nothing more written. A person's ask is what it says, as a grant's ask
// would be: each later request of the subject is put to them again, with
// what that one carries, and an answer then that differs from the one
// remembered replaces it and is written down -- so a subject's last line is
// its answer.
func (r *Recorder) Decide(ctx context.Context, l Line, key string, ask Asking) Result {
	return r.decide(ctx, l, key, ask, false)
}

// DecideEach is Decide for a subject whose key does not hold all that is
// decided -- what an SSH command is given on its stdin, what a GraphQL
// request hides or frisket cannot read -- so that a person's answer for one
// is never one for the next: each is put to them, as if every answer were
// ask, though the subject is still written down only as its answer changes.
// A default still answers each, being the same answer whatever it is shown.
func (r *Recorder) DecideEach(ctx context.Context, l Line, key string, ask Asking) Result {
	return r.decide(ctx, l, key, ask, true)
}

func (r *Recorder) decide(ctx context.Context, l Line, key string, ask Asking, each bool) Result {
	k := memoKey(l.Session, l.Kind, key)
	for {
		r.mu.Lock()
		e, ok := r.memo[k]
		if !ok {
			e = &entry{done: make(chan struct{})}
			if r.decided[l.Session] < maxMemo {
				r.memo[k] = e
				r.decided[l.Session]++
			}
			r.mu.Unlock()
			return r.answer(ctx, k, e, l, ask)
		}
		r.mu.Unlock()
		select {
		case <-e.done:
		case <-ctx.Done():
			return Result{Answer: Refuse, Source: SourceUnanswered, Reason: ReasonStoppedWaiting}
		}
		r.mu.Lock()
		answered, answer := e.answered, e.answer
		r.mu.Unlock()
		switch {
		case !answered:
			continue
		case r.personal(l) && (each || answer == Ask):
			return r.again(ctx, e, l, ask)
		}
		return Result{Answer: answer, Source: SourceMemo}
	}
}

// SourceMemo is a Result's source for an answer the session already gave:
// never on a line, since only the first is written.
const SourceMemo = "memo"

// ReasonStoppedWaiting is a subject whose client went before its answer.
const ReasonStoppedWaiting = "client stopped waiting"

func (r *Recorder) answer(ctx context.Context, k string, e *entry, l Line, ask Asking) Result {
	res := Result{Answer: r.cfg.Default, Source: SourceDefault}
	if r.personal(l) {
		res = r.ask(ctx, ask)
	}
	r.mu.Lock()
	if res.Source != SourceUnanswered {
		e.answer, e.answered = res.Answer, true
	} else if r.memo[k] == e {
		delete(r.memo, k)
		r.decided[l.Session]--
	}
	r.mu.Unlock()
	close(e.done)
	l.Answer, l.Source, l.Reason = res.Answer, res.Source, res.Reason
	r.write(l, true)
	return res
}

// again puts a subject already answered to a person once more: an answer
// that differs from the remembered one replaces it, and is written down; one
// that does not, or none at all, is this request's alone.
func (r *Recorder) again(ctx context.Context, e *entry, l Line, ask Asking) Result {
	res := r.ask(ctx, ask)
	if res.Source == SourceUnanswered {
		return res
	}
	r.mu.Lock()
	changed := e.answer != res.Answer
	e.answer = res.Answer
	r.mu.Unlock()
	if changed {
		l.Answer, l.Source = res.Answer, res.Source
		r.write(l, true)
	}
	return res
}

// ask is a person's answer, or a refusal for want of one.
func (r *Recorder) ask(ctx context.Context, ask Asking) Result {
	a, reason, err := ask(ctx)
	if reason != "" || !validAnswer(a) {
		return Result{Answer: Refuse, Source: SourceUnanswered, Reason: reason, Err: err}
	}
	return Result{Answer: a, Source: SourceHuman, Err: err}
}

func validAnswer(a Answer) bool { return a == Allow || a == Ask || a == Refuse }

// Hard writes down a refusal no recording overrides, once per subject per
// session: what the session would need, and cannot have by a grant.
func (r *Recorder) Hard(l Line, key, reason string) {
	l.Would, l.Answer, l.Source, l.Reason = string(Refuse), Refuse, SourceHard, reason
	r.once(memoKey(l.Session, "hard "+l.Kind, key), l)
}

// Resolved writes down a name the policy does not allow, resolved for the
// session anyway, once per name per session.
func (r *Recorder) Resolved(session, name string) {
	r.once(memoKey(session, KindDNS, name), Line{
		Session: session, Kind: KindDNS, Name: name,
		Would: string(Refuse), Rule: RuleNotAllowed, Answer: Allow, Source: SourceTelemetry,
	})
}

// Unresolved writes down a name the policy does not allow, refused at DNS
// with no lookup, once per name per session: a session recording with a
// default of refuse, which keeps its names on the host as any other session
// does. Telemetry still, since nothing was put to the recording -- there
// was no address to decide a connection to.
func (r *Recorder) Unresolved(session, name string) {
	r.once(memoKey(session, KindDNS, name), Line{
		Session: session, Kind: KindDNS, Name: name,
		Would: string(Refuse), Rule: RuleNotAllowed, Answer: Refuse, Source: SourceTelemetry,
		Reason: ReasonNotLookedUp,
	})
}

// ReasonNotLookedUp is an unresolved name's reason.
const ReasonNotLookedUp = "not looked up"

// RuleNotAllowed is the rule of a name off the allowlist.
const RuleNotAllowed = "not allowed"

// once writes a line no grant comes of, once per subject per session, and
// at most maxNoise of them per session: past that, to the journal alone.
func (r *Recorder) once(k string, l Line) {
	r.mu.Lock()
	if _, seen := r.memo[k]; seen {
		r.mu.Unlock()
		return
	}
	over := r.noise[l.Session] >= maxNoise
	if !over {
		r.noise[l.Session]++
		done := make(chan struct{})
		close(done)
		r.memo[k] = &entry{done: done, answer: l.Answer, answered: true}
	}
	r.mu.Unlock()
	r.write(l, !over)
}

// write puts a line in the journal, and in the sink too if sink, stamped
// and bounded.
func (r *Recorder) write(l Line, sink bool) {
	l.Time = r.cfg.Now().UTC()
	l.Policy = r.cfg.Policy
	l.Path = bounded(l.Path, maxPath)
	l.Command = bounded(l.Command, maxCommand)
	level := slog.LevelInfo
	if !l.Answer.Admits() {
		level = slog.LevelWarn
	}
	r.cfg.Log.Log(context.Background(), level, "record", l.attrs()...)
	if r.cfg.Sink != nil && sink {
		if err := r.cfg.Sink.Write(l); err != nil {
			r.cfg.Log.Error("record sink", "session", l.Session, "policy", l.Policy, "error", err.Error())
		}
	}
}

func memoKey(session, kind, key string) string {
	return session + "\x00" + kind + "\x00" + key
}
