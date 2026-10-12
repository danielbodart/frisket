package sudogate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"github.com/danielbodart/frisket/sudo"
)

// Policy is where the gate finds the signed policy of the project a sudo
// is run in: the courier that reads it from the user's home, the allowed
// signers it must verify against, the file's name, the home its
// namespace is named from, and the user's uid, whose process nearest sudo
// the courier is asked about. A Gate with none reads only the host's rules.
type Policy struct {
	Courier        string
	AllowedSigners string
	FileName       string
	Home           string
	UID            int
}

const courierTimeout = 3 * time.Second

// Where a rule came from, as the journal and the question say.
const (
	hostRule    = "host rule"
	projectRule = "project rule"
)

// ruled is the exec rule that decides a sudo: its answer and pattern, and
// whether it is the host's or the project's, at root.
type ruled struct {
	sudo.Match
	source string
	root   string
}

func (r *ruled) attrs() []any {
	attrs := []any{"rule", r.Pattern, "answer", r.Answer}
	if r.root != "" {
		attrs = append(attrs, "root", r.root)
	}
	return attrs
}

// project is a project's policy file as the gate reads it: its rules, the
// host's with its sudo section merged over them, or none when it does not
// apply, with why.
type project struct {
	root    string
	rules   *sudo.ExecRules
	project map[string]bool // the patterns the project's section sets
	why     string
}

type projectCache struct {
	mu sync.Mutex
	m  map[string]*project
}

const maxCached = 64

func (pc *projectCache) get(k string) *project {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.m[k]
}

func (pc *projectCache) put(k string, p *project) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.m == nil || len(pc.m) >= maxCached {
		pc.m = map[string]*project{}
	}
	pc.m[k] = p
}

// ruleable is whether an exec rule may decide a: never a danger or a
// warning, which are always asked as they are with no rules; never a
// command the gate did not see whole, or one run with a variable outside
// the allowlist; and only a program run as itself -- not a shell, sudo -s
// or -i, or env, whose command is another's. Fixed here, whatever any rule
// says.
func (a *sudoReq) ruleable() bool {
	return a.level() == "normal" && !a.truncated && len(a.env) == 0 && !a.shell
}

// words are the resolved command as a rule matches it: the program's
// absolute path, then its arguments.
func (a *sudoReq) words() []string {
	words := []string{a.program}
	if len(a.argv) > 1 {
		words = append(words, a.argv[1:]...)
	}
	return words
}

// rule is the exec rule that decides a, the project's merged over the
// host's, if one does.
func (g *Gate) rule(a *sudoReq) (*ruled, bool) {
	if !a.ruleable() {
		return nil, false
	}
	rules, source, root := g.exec, map[string]bool(nil), ""
	if p := g.project(a); p != nil && p.rules != nil {
		rules, source, root = p.rules, p.project, p.root
	}
	m, ok := rules.Decide(a.runas, a.words())
	if !ok {
		return nil, false
	}
	r := &ruled{Match: m, source: hostRule}
	if source[m.Pattern] {
		r.source, r.root = projectRule, root
	}
	return r, true
}

// project is the policy of the project the sudo is run in -- the courier
// finds it above the working directory of the user's process nearest sudo:
// the one that ran it, or, where that was root's (runuser), the nearest
// above -- read and verified; nil when there is no policy configured, no
// process to ask about, no project, or the courier could not say.
func (g *Gate) project(a *sudoReq) *project {
	if g.Policy == nil {
		return nil
	}
	i := slices.IndexFunc(a.r.Chain, func(l peer.Link) bool { return l.UID == g.Policy.UID })
	if i < 0 {
		return nil
	}
	caller := a.r.Chain[i]
	ctx, cancel := context.WithTimeout(context.Background(), courierTimeout)
	defer cancel()
	resp, err := g.read(ctx, caller.Pid, caller.Start)
	if err != nil {
		g.Log.Info("project policy unread", "err", err.Error(), "pid", caller.Pid)
		return nil
	}
	if resp.Root == "" || resp.Digest == "" {
		return nil
	}
	sb, err := g.signers()
	if err != nil {
		g.Log.Warn("project policy unread", "root", resp.Root, "err", err.Error())
		return nil
	}
	key := strings.Join([]string{resp.Root, resp.Digest, string(resp.Sig), projpolicy.Digest(sb)}, "\x00")
	if p := g.projects.get(key); p != nil {
		return p
	}
	p, err := g.load(resp, sb)
	if err != nil {
		g.Log.Warn("project policy unread", "root", resp.Root, "err", err.Error())
		return nil
	}
	if p.why != "" {
		g.Log.Info("project policy ignored", "root", p.root, "digest", resp.Digest, "why", p.why)
	}
	g.projects.put(key, p)
	return p
}

// load reads what the courier found, verified against the allowed signers,
// and merges its sudo section over the host's rules as RFC 7396 says. A
// file that does not verify, or whose sudo section is not one a project
// may set, has no rules, and why says so.
func (g *Gate) load(resp *courier.Response, signersFile []byte) (*project, error) {
	root := resp.Root
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("root %q is not absolute and clean", root)
	}
	ns, err := projpolicy.Namespace(root, g.Policy.Home)
	if err != nil {
		return nil, err
	}
	signers, err := projpolicy.ParseAllowedSigners(signersFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.Policy.AllowedSigners, err)
	}
	if projpolicy.Digest(resp.Bytes) != resp.Digest {
		return nil, errors.New("the courier's digest is not its bytes'")
	}
	p := &project{root: root}
	if resp.Sig == nil {
		p.why = "no " + g.Policy.FileName + projpolicy.SigSuffix
		return p, nil
	}
	if _, err := projpolicy.Verify(resp.Bytes, resp.Sig, ns, signers, "", g.wall()); err != nil {
		p.why = "its signature does not verify: " + err.Error()
		return p, nil
	}
	v, err := projpolicy.Decode(resp.Bytes)
	if err != nil {
		p.why = err.Error()
		return p, nil
	}
	doc, ok := v.(map[string]any)
	if !ok {
		p.why = "it is not a JSON object"
		return p, nil
	}
	section, ok := doc["sudo"]
	if !ok || section == nil {
		return p, nil
	}
	exec, err := projectExec(section)
	if err != nil {
		p.why = "sudo: " + err.Error()
		return p, nil
	}
	merged, _ := projpolicy.MergePatch(anyRules(g.Exec), exec).(map[string]any)
	rules, err := ruleMap(merged)
	if err == nil {
		p.rules, err = sudo.CompileExec(rules)
	}
	if err != nil {
		p.why = "sudo: " + err.Error()
		return p, nil
	}
	p.project = map[string]bool{}
	for k, r := range exec {
		if r != nil {
			p.project[k] = true
		}
	}
	return p, nil
}

// projectExec reads a project's sudo section, which may set exec alone:
// each pattern a rule, or null to take the host's away.
func projectExec(section any) (map[string]any, error) {
	s, ok := section.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	for _, k := range slices.Sorted(maps.Keys(s)) {
		if k != "exec" {
			return nil, fmt.Errorf("%q: a project may set exec alone", k)
		}
	}
	exec, ok := s["exec"].(map[string]any)
	if !ok {
		if s["exec"] == nil {
			return map[string]any{}, nil
		}
		return nil, errors.New("exec: not a JSON object")
	}
	for _, k := range slices.Sorted(maps.Keys(exec)) {
		if exec[k] == nil {
			continue
		}
		if _, err := decodeRule(exec[k]); err != nil {
			return nil, fmt.Errorf("exec.%s: %w", k, err)
		}
	}
	return exec, nil
}

func decodeRule(v any) (sudo.Rule, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return sudo.Rule{}, err
	}
	var r sudo.Rule
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return sudo.Rule{}, err
	}
	return r, nil
}

func anyRules(m map[string]sudo.Rule) map[string]any {
	out := map[string]any{}
	for k, r := range m {
		rule := map[string]any{"answer": r.Answer}
		if r.RunAs != "" {
			rule["runAs"] = r.RunAs
		}
		out[k] = rule
	}
	return out
}

func ruleMap(m map[string]any) (map[string]sudo.Rule, error) {
	out := map[string]sudo.Rule{}
	for k, v := range m {
		r, err := decodeRule(v)
		if err != nil {
			return nil, fmt.Errorf("exec.%s: %w", k, err)
		}
		out[k] = r
	}
	return out, nil
}

func (g *Gate) policyDefaults() {
	if g.Policy == nil {
		return
	}
	if g.read == nil {
		g.read = func(ctx context.Context, pid int, start uint64) (*courier.Response, error) {
			return courier.Read(ctx, g.Policy.Courier, pid, start)
		}
	}
	if g.signers == nil {
		g.signers = func() ([]byte, error) { return os.ReadFile(g.Policy.AllowedSigners) }
	}
}

// ruleLine opens the question an ask rule puts.
func (r *ruled) line() string {
	return fmt.Sprintf("asked, with no password, by the %s %s", r.source, galleyask.Clean(r.Pattern))
}
