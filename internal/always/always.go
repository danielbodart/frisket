// Package always is "Always" on the questions a container session's routes
// ask: the rule a person answers Always admits what it names for the rest
// of the session at once, and is signed into the project file the session
// was launched from -- its workspace's chase.json, say -- so that the next
// launch, which merges that file's frisket section over the session's
// document, admits it too.
//
// Always is offered only where the rule would stand: the session's
// document is version 2, the route or machine is one the host marked
// `always` (one whose answers a project's file is merged into, as no
// strict tier's are), the file is absent or verifies and is canonical, and
// the document with the rule merged in by frisket's own project-layer
// check admits the request asked about. The rule is the specific one: the
// request's operation id, else its method and exact path; the SSH
// command's literal words.
//
// What is written is signed by frisket-signer's policy-sign@frisket, asked
// by frisket's main process as approved -- the person's answer in this
// question is the approval, so the signer asks nothing more -- and written
// by the courier, whose write takes the old digest, since frisket itself
// cannot write the home. A sign or write that fails still admits the
// request once, with a journal line and a notice.
package always

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/frisket/projpolicy"
	"github.com/danielbodart/galley/wire"
)

// Config is where Always signs and writes, daemon-wide.
type Config struct {
	// Signer is frisket-signer's agent socket, whose policy-sign@frisket
	// signs the new file.
	Signer string
	// Courier is frisket-policy's socket, whose write replaces the file.
	Courier string
	// AllowedSigners is what a file must verify against.
	AllowedSigners string
	// FileName is the project file's, chase.json.
	FileName string
	// Home names a root's namespace, as the signer and courier name it.
	Home string
}

// Writer is Always for the daemon: each session's comes from it.
type Writer struct {
	cfg Config
	log *slog.Logger
	// notify says text to the person, through the asker.
	notify func(ctx context.Context, q intercept.Question) error

	// For tests: what signs and writes.
	sign  func(ctx context.Context, req agentsrv.PolicySignRequest) ([]byte, error)
	write func(ctx context.Context, root, oldDigest string, b, sig []byte) error
	now   func() time.Time
}

const timeout = 10 * time.Second

// New makes a Writer. notify may be nil, when there is nobody to tell.
func New(cfg Config, log *slog.Logger, notify func(ctx context.Context, q intercept.Question) error) *Writer {
	return &Writer{
		cfg: cfg, log: log, notify: notify,
		sign: func(ctx context.Context, req agentsrv.PolicySignRequest) ([]byte, error) {
			return agentsrv.PolicySign(ctx, cfg.Signer, req)
		},
		write: func(ctx context.Context, root, old string, b, sig []byte) error {
			_, err := courier.Write(ctx, cfg.Courier, root, old, b, sig)
			return err
		},
		now: time.Now,
	}
}

// Session is one session's Always: an intercept.Always.
type Session struct {
	w         *Writer
	name      string
	policy    string
	workspace string
	// doc is the session's document, which a rule is merged over to see
	// that it stands.
	doc []byte
	// routes and machines are those whose questions offer Always.
	routes, machines map[string]bool
	// scope builds a route's scope from a document, as a session would.
	scope func(doc *policy.Lowered, route string) (intercept.Scope, error)

	// mu is held while a file is read and while one is written: an offer
	// waits for the write before it, so it reads what was written.
	mu sync.Mutex
	// answered are the rules answered Always in this session.
	answered sync.Map
}

var _ intercept.Always = (*Session)(nil)

// Session is Always for one session: name and workspace are its own, doc
// its document's bytes, version 2, and lowered the same read. nil when the
// session has nothing Always may be offered for, or no workspace to write
// into.
func (w *Writer) Session(name, policyName, workspace string, doc []byte, lowered *policy.Lowered,
	scope func(*policy.Lowered, string) (intercept.Scope, error)) *Session {
	if w == nil || lowered == nil || workspace == "" || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace ||
		len(lowered.Always)+len(lowered.SSHAlways) == 0 {
		return nil
	}
	if v, err := policy.Version(doc); err != nil || v != 2 {
		return nil
	}
	return &Session{w: w, name: name, policy: policyName, workspace: workspace, doc: doc,
		routes: lowered.Always, machines: lowered.SSHAlways, scope: scope}
}

func ruleID(r intercept.AlwaysRule) string {
	kind := "http"
	if r.SSH {
		kind = "ssh"
	}
	return kind + "\x00" + r.Route + "\x00" + r.Key
}

// Admits is whether rule was answered Always in this session.
func (s *Session) Admits(rule intercept.AlwaysRule) bool {
	_, ok := s.answered.Load(ruleID(rule))
	return ok
}

// offer is what an answer of always writes.
type offer struct {
	root, namespace, path string
	old                   string // the file's digest, "" for none
	cur, new              []byte
}

// Offer sets q's Diff and Always where rule may be written and would stand.
func (s *Session) Offer(q *intercept.Question, rule intercept.AlwaysRule) func() {
	if rule.Key == "" || q.Record {
		return nil
	}
	if rule.SSH && !s.machines[rule.Route] || !rule.SSH && !s.routes[rule.Route] {
		return nil
	}
	s.mu.Lock()
	o, why := s.prepare(rule)
	s.mu.Unlock()
	if o == nil {
		s.w.log.Debug("always not offered", "session", s.name, "route", rule.Route, "rule", rule.Key, "why", why)
		return nil
	}
	q.Diff = &intercept.Diff{Path: o.path, Old: string(o.cur), New: string(o.new)}
	q.Always = true
	return func() { s.save(rule, o) }
}

// prepare reads the workspace's file and makes the new one, or says why
// Always is not offered.
func (s *Session) prepare(rule intercept.AlwaysRule) (*offer, string) {
	cfg := s.w.cfg
	signers, err := projpolicy.ReadAllowedSigners(cfg.AllowedSigners)
	if err != nil {
		return nil, err.Error()
	}
	root := s.workspace
	ns, err := projpolicy.Namespace(root, cfg.Home)
	if err != nil {
		return nil, err.Error()
	}
	name, _ := projpolicy.RootName(root, cfg.Home)
	o := &offer{root: root, namespace: ns, path: strings.TrimSuffix(name, "/") + "/" + cfg.FileName}
	var doc any = map[string]any{"version": json.Number("2")}
	p, err := projpolicy.Load(root, cfg.Home, cfg.FileName, signers)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// A file's commented form beside it, chase.jsonc to chase.json, is
		// an older grant the new file would take the place of.
		if _, err := os.Lstat(filepath.Join(root, cfg.FileName+"c")); err == nil {
			return nil, cfg.FileName + "c is there, and " + cfg.FileName + " would replace it"
		}
		o.cur = nil
	case err != nil:
		return nil, err.Error()
	case !p.Verified:
		// An edit nobody signed is not one to sign over unseen.
		return nil, cfg.FileName + " does not verify: " + p.Why
	case !projpolicy.Canonical(p.Bytes):
		return nil, cfg.FileName + " is not canonical"
	default:
		if doc, err = projpolicy.Decode(p.Bytes); err != nil {
			return nil, err.Error()
		}
		if _, ok := doc.(map[string]any); !ok {
			return nil, cfg.FileName + " is not a JSON object"
		}
		o.cur, o.old = p.Bytes, p.Digest
	}
	patch := patchFor(rule)
	o.new, err = projpolicy.Encode(projpolicy.MergePatch(doc, patch))
	if err != nil {
		return nil, err.Error()
	}
	if string(o.new) == string(o.cur) {
		return nil, "the file has the rule already"
	}
	if len(o.cur) > wire.MaxDiff || len(o.new) > wire.MaxDiff {
		return nil, "the file is too big to show"
	}
	if why := s.stands(rule, patch["frisket"]); why != "" {
		return nil, why
	}
	return o, ""
}

// patchFor is the merge patch that writes rule into a project file.
func patchFor(rule intercept.AlwaysRule) map[string]any {
	if rule.SSH {
		return map[string]any{"frisket": map[string]any{"ssh": map[string]any{
			rule.Route: map[string]any{"exec": map[string]any{rule.Key: "allow"}}}}}
	}
	return map[string]any{"frisket": map[string]any{"routes": map[string]any{
		rule.Route: map[string]any{"operations": map[string]any{rule.Key: "allow"}}}}}
}

// stands is "" when the session's document with layer merged over it, as
// frisket's project-layer check merges a project's section, admits what
// rule is about; otherwise why not.
func (s *Session) stands(rule intercept.AlwaysRule, layer any) string {
	lb, err := json.Marshal(layer)
	if err != nil {
		return err.Error()
	}
	merged, err := policy.CheckProjectLayer(lb, s.doc)
	if err != nil {
		return "the rule does not apply: " + err.Error()
	}
	l, err := policy.Load(merged)
	if err != nil {
		return "the rule does not apply: " + err.Error()
	}
	if rule.SSH {
		for _, r := range l.Policy.SSH {
			if r.Name != rule.Route {
				continue
			}
			rules, err := execrule.Compile(r)
			if err != nil {
				return err.Error()
			}
			if d := rules.Decide(rule.Command); d.Outcome != execrule.Allow {
				return fmt.Sprintf("with the rule the command is still %s", d.Outcome)
			}
			return ""
		}
		return "no machine " + rule.Route
	}
	if rule.Decides == nil || s.scope == nil {
		return "nothing to decide the request again by"
	}
	sc, err := s.scope(l, rule.Route)
	if err != nil {
		return err.Error()
	}
	out, err := rule.Decides(sc)
	switch {
	case err != nil:
		return err.Error()
	case out != intercept.Admit:
		return fmt.Sprintf("with the rule the request is still %s", out)
	}
	return ""
}

// save is an answer of always: the rule admits at once, and the file is
// signed and written meanwhile, the next offer waiting for it.
func (s *Session) save(rule intercept.AlwaysRule, o *offer) {
	s.answered.Store(ruleID(rule), true)
	s.mu.Lock()
	go func() {
		defer s.mu.Unlock()
		s.write(rule, o)
	}()
}

func (s *Session) write(rule intercept.AlwaysRule, o *offer) {
	w := s.w
	attrs := []any{"session", s.name, "workspace", s.workspace, "route", rule.Route, "rule", rule.Key,
		"old", o.old, "digest", projpolicy.Digest(o.new)}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sig, err := w.sign(ctx, agentsrv.PolicySignRequest{
		Root: o.root, Name: w.cfg.FileName, New: o.new, Approved: true,
	})
	if err == nil {
		err = s.verify(o, sig)
	}
	if err == nil {
		err = w.write(ctx, o.root, o.old, o.new, sig)
	}
	if err == nil {
		w.log.Info("always", append(attrs, "outcome", "written")...)
		return
	}
	w.log.Warn("always", append(attrs, "outcome", "not saved", "err", err.Error())...)
	if w.notify == nil {
		return
	}
	text := fmt.Sprintf("The rule %s for %s was not saved into %s: %s\nIt is allowed for the rest of this session, and asked about again in the next.",
		rule.Key, rule.Route, o.path, err.Error())
	n := intercept.Question{Session: s.name, Workspace: s.workspace, Policy: s.policy, Route: rule.Route,
		Kind: intercept.KindNotice, Text: text, ID: "always " + ruleID(rule)}
	if err := w.notify(ctx, n); err != nil {
		w.log.Info("always notice not shown", "session", s.name, "err", err.Error())
	}
}

// verify holds the signer's signature to the allowed signers before it is
// written, as the courier and every reader will.
func (s *Session) verify(o *offer, sig []byte) error {
	signers, err := projpolicy.ReadAllowedSigners(s.w.cfg.AllowedSigners)
	if err != nil {
		return err
	}
	if _, err := projpolicy.Verify(o.new, sig, o.namespace, signers, "", s.w.now()); err != nil {
		return fmt.Errorf("the signature does not verify: %w", err)
	}
	return nil
}
