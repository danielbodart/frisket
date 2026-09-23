package intercept

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// Scope is what a route's credential may be used for. A request is admitted,
// asked about, or refused: by the git scope if it is git-shaped, by the most
// specific path rule that matches it, by the GitHub API scope, and otherwise
// by Unmatched. An empty scope that refuses what it does not match admits
// nothing, and New refuses to build a route with one.
//
// It is checked against the real request line, after TLS, on every request
// (PLAN.md, decision 6). The connection being steered here says only where
// the workload was going; the request is entirely the workload's, and anything
// in the sandbox can open a connection to an intercepted host and ask frisket
// to add the credential.
type Scope struct {
	// Paths decide a request whose method is listed and whose path is at or
	// under Prefix, or is exactly Path.
	Paths []PathRule
	// Git admits git's smart-HTTP protocol, GitHub-shaped, for a set of
	// repositories or all of them.
	Git *GitScope
	// GitHubAPI admits GitHub REST calls under /repos/{owner}/{repo}.
	// PROVISIONAL: see GitHubAPIScope.
	GitHubAPI *GitHubAPIScope
	// Unmatched is what happens to a request nothing above decides: refused,
	// the default, or asked about. Ask is how a route is secure by default
	// without being closed by default -- an endpoint nobody has classified is
	// not refused, it is put to a person.
	Unmatched Unmatched
}

// Unmatched is a scope's answer to a request no rule matches.
type Unmatched int

const (
	UnmatchedRefuse Unmatched = iota
	UnmatchedAsk
)

// PathRule decides the listed methods at a path: exactly Path, or Prefix and
// everything under it. One of the two, never both.
//
// Both are matched by SEGMENT, never as a string: a prefix "/backend-api/codex"
// matches "/backend-api/codex/responses" and not "/backend-api/codex-evil". A
// string prefix is the mistake git's insteadOf makes, where `owner/repo` also
// matches `owner/repo-evil`. A segment that is "*" alone matches any one
// segment that is not empty; a "*" anywhere else is refused, so a template
// cannot say more than one segment's worth.
//
// Where several rules match, the most specific decides, as OpenAPI resolves a
// request to one operation: segment by segment from the left, a literal beats
// a "*", and either beats being past the end of a prefix. Between rules that
// are equally specific the stricter decides: refusing beats asking, and asking
// beats admitting.
type PathRule struct {
	Methods []string
	Prefix  string
	Path    string
	// Ask puts a matching request to a person instead of admitting it.
	Ask bool
	// Refuse refuses a matching request: a hole in a broader rule, or a
	// route that exists only so what it matches goes nowhere. Not with Ask.
	Refuse bool
	// Operation is what the rule is, in its API's own words, for the person
	// being asked. Nil: the rule has none, and the question says so.
	Operation *Operation
}

// Operation is one of an API's operations as its own description names it.
// It is the only prose a question carries: everything else in a question is
// the request, shown as the request.
type Operation struct {
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
	// Class is what kind of operation the consumer judged it -- "read",
	// "write" or "guarded" -- and Category is the API's own grouping of it.
	// Carried to the person being asked and never matched on: the rule's
	// outcome is what decides.
	Class    string `json:"class,omitempty"`
	Category string `json:"category,omitempty"`
}

// GitScope admits git over HTTPS as GitHub serves it: /{owner}/{repo}[.git]
// followed by info/refs, git-upload-pack or git-receive-pack, and nothing
// else -- no web UI, no LFS, no dumb protocol.
type GitScope struct {
	// Repos are the repositories admitted, unless AnyRepo, and then none may
	// be listed.
	Repos   []Repo
	AnyRepo bool
	// Push decides git-receive-pack. Refuse, the zero value: fetch and clone
	// work and a push is refused at its first request, the ref advertisement
	// -- which is the one agents-container enforced by inspecting `git`'s
	// command line. Here it is the request line, which a workload cannot route
	// around by running git some other way. Ask admits the advertisement,
	// which says no more than a fetch's does, and asks at the push itself,
	// whose body opens with the refs it would update: one question, showing
	// what it is about. Admit admits both.
	Push Outcome
}

// ReceivePack is what a push is, for the person asked about one.
var ReceivePack = &Operation{
	ID:          "git-receive-pack",
	Summary:     "Push to a repository",
	Description: "Updates the refs listed at the start of the body, to commits it carries.",
	Class:       "write",
}

// GitHubAPIScope admits /repos/{owner}/{repo} and everything under it, with
// the listed methods, for the listed repositories.
//
// Only that shape: /repositories/{id}, /graphql, /search and /user are not
// repository-scoped by their path and are refused unless a PathRule admits
// them deliberately.
//
// PROVISIONAL: gh's route is an open question, and no policy
// uses this.
type GitHubAPIScope struct {
	Repos   []Repo
	Methods []string
}

// Repo is one GitHub repository.
type Repo struct {
	Owner string
	Name  string
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

// ParseRepo parses "owner/repo".
func ParseRepo(s string) (Repo, error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok {
		return Repo{}, fmt.Errorf("repository %q is not owner/name", s)
	}
	r := Repo{Owner: owner, Name: name}
	return r, r.validate()
}

// validate holds a repository to GitHub's own alphabet. Anything else is a
// configuration mistake, and a name like ".." or "a/b" in the set would be
// matched against request segments as though it were a name.
func (r Repo) validate() error {
	for _, part := range []string{r.Owner, r.Name} {
		if part == "" || strings.Trim(part, ".") == "" {
			return fmt.Errorf("repository %q: empty or dots-only component", r.String())
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return fmt.Errorf("repository %q: character %q is not one GitHub allows", r.String(), c)
			}
		}
	}
	return nil
}

// Refusal reasons, as they appear in the log.
const (
	ReasonBadPath    = "path not canonical"
	ReasonOutOfScope = "out of scope"
	ReasonPush       = "push not allowed"
	ReasonRefused    = "refused by rule"
)

// Outcome is what a scope decides about one request.
type Outcome int

const (
	Refuse Outcome = iota
	Admit
	Ask
)

// Verdict is a scope's decision about one request. Reason is which part of
// the scope decided -- "path", "git", "github-api", or RuleUnmatched for a
// request no rule matched -- or, refused, why.
type Verdict struct {
	Outcome   Outcome
	Reason    string
	Operation *Operation
}

// RuleUnmatched is the reason for a request asked about because nothing
// matched it.
const RuleUnmatched = "unmatched"

// wildcard is the template segment that matches any one segment.
const wildcard = "*"

// compiled is a Scope checked and prepared once, when the route is built.
type compiled struct {
	paths     []compiledPath
	git       *GitScope
	api       *GitHubAPIScope
	unmatched Unmatched
}

type compiledPath struct {
	methods []string
	// segs is the template; exact says whether it is the whole path or a
	// prefix of it.
	segs      []string
	folded    []string
	exact     bool
	outcome   Outcome
	operation *Operation
}

// strictness orders outcomes: admitting, then asking, then refusing.
func strictness(o Outcome) int {
	switch o {
	case Admit:
		return 0
	case Ask:
		return 1
	}
	return 2
}

// verdict is what the rule decides about a request it matched.
func (p *compiledPath) verdict() Verdict {
	switch p.outcome {
	case Refuse:
		return Verdict{Outcome: Refuse, Reason: ReasonRefused, Operation: p.operation}
	case Ask:
		return Verdict{Outcome: Ask, Reason: "path", Operation: p.operation}
	}
	return Verdict{Outcome: Admit, Reason: "path", Operation: p.operation}
}

func compileScope(s Scope) (*compiled, error) {
	c := &compiled{unmatched: s.Unmatched}
	if s.Unmatched != UnmatchedRefuse && s.Unmatched != UnmatchedAsk {
		return nil, fmt.Errorf("unmatched %d is neither refuse nor ask", s.Unmatched)
	}
	for _, p := range s.Paths {
		cp, err := compilePath(p)
		if err != nil {
			return nil, err
		}
		c.paths = append(c.paths, cp)
	}
	if s.Git != nil {
		if s.Git.AnyRepo != (len(s.Git.Repos) == 0) {
			return nil, errors.New("git scope needs repositories, or any repository, and not both")
		}
		if s.Git.Push != Refuse && s.Git.Push != Ask && s.Git.Push != Admit {
			return nil, fmt.Errorf("git push %d is not refuse, ask or admit", s.Git.Push)
		}
		for _, r := range s.Git.Repos {
			if err := r.validate(); err != nil {
				return nil, err
			}
		}
		g := *s.Git
		c.git = &g
	}
	if s.GitHubAPI != nil {
		if len(s.GitHubAPI.Repos) == 0 || len(s.GitHubAPI.Methods) == 0 {
			return nil, errors.New("GitHub API scope needs repositories and methods")
		}
		for _, r := range s.GitHubAPI.Repos {
			if err := r.validate(); err != nil {
				return nil, err
			}
		}
		a := GitHubAPIScope{Repos: s.GitHubAPI.Repos, Methods: upper(s.GitHubAPI.Methods)}
		c.api = &a
	}
	if len(c.paths) == 0 && c.git == nil && c.api == nil && c.unmatched == UnmatchedRefuse {
		return nil, errors.New("scope admits nothing")
	}
	return c, nil
}

func compilePath(p PathRule) (compiledPath, error) {
	written, exact := p.Prefix, false
	switch {
	case p.Path != "" && p.Prefix != "":
		return compiledPath{}, fmt.Errorf("path rule %q has a prefix %q too: a rule is one or the other", p.Path, p.Prefix)
	case p.Path != "":
		written, exact = p.Path, true
	}
	if len(p.Methods) == 0 {
		return compiledPath{}, fmt.Errorf("path rule %q lists no methods", written)
	}
	if !strings.HasPrefix(written, "/") {
		return compiledPath{}, fmt.Errorf("path rule %q does not start with /", written)
	}
	segs, err := splitPath(written)
	if err != nil {
		return compiledPath{}, fmt.Errorf("path rule %q: %w", written, err)
	}
	if n := len(segs); n > 0 && segs[n-1] == "" {
		switch {
		case !exact:
			// "/" is the whole host; "/a/" is written as "/a". A trailing
			// empty segment in a prefix would demand a trailing slash on
			// every request.
			segs = segs[:n-1]
		case n > 1:
			// An exact "/a/" would match only "/a/", and never "/a": say "/a".
			return compiledPath{}, fmt.Errorf("path rule %q ends in a slash", written)
		}
	}
	if slices.Contains(segs[:max(len(segs)-1, 0)], "") || (!exact && slices.Contains(segs, "")) {
		return compiledPath{}, fmt.Errorf("path rule %q has an empty segment", written)
	}
	for _, seg := range segs {
		if seg != wildcard && strings.Contains(seg, wildcard) {
			return compiledPath{}, fmt.Errorf("path rule %q: a * is a whole segment or nothing", written)
		}
	}
	if p.Ask && p.Refuse {
		return compiledPath{}, fmt.Errorf("path rule %q both asks and refuses", written)
	}
	if o := p.Operation; o != nil && (o.ID == "" || o.Summary == "") {
		return compiledPath{}, fmt.Errorf("path rule %q: an operation needs an id and a summary", written)
	}
	folded := make([]string, len(segs))
	for i, seg := range segs {
		folded[i] = seg
		if seg != wildcard {
			folded[i] = fold(seg)
		}
	}
	outcome := Admit
	switch {
	case p.Ask:
		outcome = Ask
	case p.Refuse:
		outcome = Refuse
	}
	return compiledPath{methods: upper(p.Methods), segs: segs, folded: folded, exact: exact, outcome: outcome, operation: p.Operation}, nil
}

func upper(ms []string) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = strings.ToUpper(m)
	}
	return out
}

// decide decides a request.
//
// Methods are compared exactly, and a request's method is not upper-cased
// first: "get" is not GET to every server, and a method the rule does not name
// is not matched rather than interpreted.
//
// A path that is not canonical is refused whatever Unmatched says. Asking a
// person about a request that could mean two different paths is asking them
// to approve whichever one the upstream picks.
func (c *compiled) decide(method string, u *url.URL) Verdict {
	segs, err := splitPath(u.EscapedPath())
	if err != nil {
		return Verdict{Outcome: Refuse, Reason: ReasonBadPath}
	}
	// Git first, and its refusal stands: a route admitting GET everywhere
	// beside a git scope without push still refuses receive-pack's ref
	// advertisement, which is where a push is meant to stop.
	if c.git != nil {
		if v, ok := c.git.decide(method, segs, u.RawQuery); ok {
			return v
		}
	}
	if best := c.best(method, segs, true); best != nil {
		return c.verdict(method, segs, best)
	}
	if best := c.best(method, segs, false); best != nil {
		return c.verdict(method, segs, best)
	}
	if c.api != nil && slices.Contains(c.api.Methods, method) &&
		len(segs) >= 3 && segs[0] == "repos" && inRepos(c.api.Repos, segs[1], segs[2]) {
		if stricter := c.stricterLeniently(method, segs, Admit); len(stricter) > 0 {
			return stricter[0].verdict()
		}
		return Verdict{Outcome: Admit, Reason: "github-api"}
	}
	if c.unmatched == UnmatchedAsk {
		return Verdict{Outcome: Ask, Reason: RuleUnmatched}
	}
	return Verdict{Outcome: Refuse, Reason: ReasonOutOfScope}
}

// best is the most specific rule of one kind that matches: exact rules, which
// name one operation each, or prefixes. Exact rules are consulted first and
// prefixes only when none matched, so a broad prefix never outranks an
// operation somebody named: a prefix with a literal where the operation has
// a "*" is still not the operation.
func (c *compiled) best(method string, segs []string, exact bool) *compiledPath {
	var best *compiledPath
	for i := range c.paths {
		p := &c.paths[i]
		if p.exact != exact || !slices.Contains(p.methods, method) || !p.matches(segs) {
			continue
		}
		if best == nil {
			best = p
			continue
		}
		switch cmp := p.specificity(best, len(segs)); {
		case cmp > 0, cmp == 0 && strictness(p.outcome) > strictness(best.outcome):
			best = p
		}
	}
	return best
}

// verdict is the rule's answer -- unless a stricter rule matches a lenient
// reading of the same request without being outranked by it. A request spelt
// so that the stricter rule misses -- a trailing slash, a ;parameter, another
// case, a trailing dot -- is one an upstream may well read as that rule's
// operation, and what a rule lets through is the one outcome that must not
// depend on how literally the upstream reads its paths.
func (c *compiled) verdict(method string, segs []string, best *compiledPath) Verdict {
	for _, p := range c.stricterLeniently(method, segs, best.outcome) {
		if !outranks(best, p, len(segs)) {
			return p.verdict()
		}
	}
	return best.verdict()
}

// outranks is whether a rule is more specific than a stricter one, as decide
// ranks them: an operation over a prefix, and between two of a kind, segment
// by segment.
func outranks(rule, stricter *compiledPath, n int) bool {
	if rule.exact != stricter.exact {
		return rule.exact
	}
	return rule.specificity(stricter, n) > 0
}

// stricterLeniently is every rule stricter than `than` that matches the
// request however leniently an upstream might read it: the strictest first,
// and among those the most specific.
func (c *compiled) stricterLeniently(method string, segs []string, than Outcome) []*compiledPath {
	// Two readings: a slash a segment decodes to is part of it, or -- to an
	// upstream that decodes before it splits -- the end of it.
	var whole, split []string
	for _, s := range segs {
		whole = append(whole, fold(s))
		for _, piece := range strings.FieldsFunc(decode(s), func(r rune) bool { return r == '/' || r == '\\' }) {
			split = append(split, foldDecoded(piece))
		}
	}
	// A trailing slash is nothing, to a lenient reader.
	if n := len(whole); n > 0 && whole[n-1] == "" {
		whole = whole[:n-1]
	}
	var out []*compiledPath
	for i := range c.paths {
		p := &c.paths[i]
		if strictness(p.outcome) > strictness(than) && slices.Contains(p.methods, method) &&
			(p.matchesFolded(whole) || p.matchesFolded(split)) {
			out = append(out, p)
		}
	}
	n := max(len(whole), len(split))
	slices.SortStableFunc(out, func(a, b *compiledPath) int {
		if d := strictness(b.outcome) - strictness(a.outcome); d != 0 {
			return d
		}
		if a.exact != b.exact {
			if a.exact {
				return -1
			}
			return 1
		}
		return -a.specificity(b, n)
	})
	return out
}

// matchesFolded is matches, against folded segments and the rule's folded
// literals.
func (p *compiledPath) matchesFolded(segs []string) bool {
	if len(segs) < len(p.folded) || p.exact && len(segs) != len(p.folded) {
		return false
	}
	for i, t := range p.folded {
		if t == wildcard {
			if segs[i] == "" {
				return false
			}
		} else if segs[i] != t {
			return false
		}
	}
	return true
}

// fold is a segment as the most lenient upstream might read it: decoded as
// often as it decodes, cut at a ;parameter, trailing dots and spaces trimmed,
// and ASCII lower case.
func fold(seg string) string { return foldDecoded(decode(seg)) }

// decode is a segment decoded as often as it decodes.
func decode(seg string) string {
	for range maxDecodes {
		next, err := url.PathUnescape(seg)
		if err != nil || next == seg {
			break
		}
		seg = next
	}
	return seg
}

// foldDecoded is fold, for a segment already decoded.
func foldDecoded(seg string) string {
	seg, _, _ = strings.Cut(seg, ";")
	seg = strings.TrimRight(seg, ". ")
	return strings.ToLower(seg)
}

// matches is whether a request's segments are this template: all of them for
// an exact rule, the first of them for a prefix.
func (p *compiledPath) matches(segs []string) bool {
	if len(segs) < len(p.segs) || p.exact && len(segs) != len(p.segs) {
		return false
	}
	for i, t := range p.segs {
		if t == wildcard {
			// Any one segment, but one: not the trailing empty one a
			// trailing slash leaves, and not one that an upstream decoding
			// it once more would read as two.
			if !oneSegment(segs[i]) {
				return false
			}
		} else if segs[i] != t {
			return false
		}
	}
	return true
}

// oneSegment is whether a decoded segment is one segment to any reading of
// it: not empty, and no slash or backslash however many times it is decoded.
// A literal needs no such check -- it matches only itself -- but a wildcard
// that took "a%2Fb" would name an operation the upstream might not be asked
// for. Such a request matches no template, and so is decided as unmatched.
func oneSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for range maxDecodes {
		if strings.ContainsAny(seg, `/\`) {
			return false
		}
		next, err := url.PathUnescape(seg)
		if err != nil || next == seg {
			return true
		}
		seg = next
	}
	return false
}

// specificity compares two rules that both matched a request of n segments:
// positive if p is the more specific, negative if q is, zero if neither.
func (p *compiledPath) specificity(q *compiledPath, n int) int {
	for i := range n {
		if d := p.rank(i) - q.rank(i); d != 0 {
			return d
		}
	}
	return 0
}

// rank is how specifically a rule matches the segment at i: a literal, a
// wildcard, or nothing at all, past the end of a prefix.
func (p *compiledPath) rank(i int) int {
	switch {
	case i >= len(p.segs):
		return 0
	case p.segs[i] == wildcard:
		return 1
	}
	return 2
}

// decide for git is false when the request is not git-shaped at all, so the
// caller goes on to the other rules; true, with the verdict, when the request
// IS a git request, refused if something about it is out of scope.
func (g *GitScope) decide(method string, segs []string, rawQuery string) (Verdict, bool) {
	if len(segs) < 3 {
		return Verdict{}, false
	}
	name, _ := cutSuffixFold(segs[1], ".git")
	if !g.AnyRepo && !inRepos(g.Repos, segs[0], name) {
		return Verdict{}, false
	}
	admit := Verdict{Outcome: Admit, Reason: "git"}
	outOfScope := Verdict{Outcome: Refuse, Reason: ReasonOutOfScope}
	rest := segs[2:]
	switch {
	case method == http.MethodGet && len(rest) == 2 && rest[0] == "info" && rest[1] == "refs":
		// The ref advertisement says which service it is for in the query.
		// Exactly one value, parsed strictly: a second `service=` or a query
		// Go cannot parse is a disagreement between us and the upstream about
		// which service this is, and that is refused rather than resolved.
		q, err := url.ParseQuery(rawQuery)
		if err != nil || len(q["service"]) != 1 {
			return outOfScope, true
		}
		switch q.Get("service") {
		case "git-upload-pack":
			return admit, true
		case "git-receive-pack":
			if g.Push == Refuse {
				return Verdict{Outcome: Refuse, Reason: ReasonPush}, true
			}
			return admit, true
		}
		return outOfScope, true
	case method == http.MethodPost && len(rest) == 1 && rawQuery != "":
		// git never sends a query with a POST. One that arrives is somebody
		// asking a server that might read `service=` from it to disagree
		// with the path about which service this is.
		return outOfScope, true
	case method == http.MethodPost && len(rest) == 1 && rest[0] == "git-upload-pack":
		return admit, true
	case method == http.MethodPost && len(rest) == 1 && rest[0] == "git-receive-pack":
		switch g.Push {
		case Admit:
			return admit, true
		case Ask:
			return Verdict{Outcome: Ask, Reason: "git", Operation: ReceivePack}, true
		}
		return Verdict{Outcome: Refuse, Reason: ReasonPush}, true
	}
	return Verdict{}, false
}

// inRepos matches owner and name against the set, as whole segments and
// case-insensitively, because GitHub treats Owner/Repo and owner/repo as the
// same repository. ASCII-only folding: strings.EqualFold would also fold the
// Kelvin sign into k, and the upstream does not.
func inRepos(repos []Repo, owner, name string) bool {
	for _, r := range repos {
		if asciiEqualFold(r.Owner, owner) && asciiEqualFold(r.Name, name) {
			return true
		}
	}
	return false
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 0x80 || y >= 0x80 {
			return false
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func cutSuffixFold(s, suffix string) (string, bool) {
	if len(s) >= len(suffix) && asciiEqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// errBadPath is every reason a request path is refused before any scope is
// consulted.
var errBadPath = errors.New("path not canonical")

// maxDecodes bounds how many times a segment is percent-decoded when looking
// for what an over-eager upstream might make of it.
const maxDecodes = 4

// splitPath splits an escaped request path into segments, each decoded once
// -- which is what a correct upstream sees -- and refuses any path that some
// upstream could read as a different path from the one this matched.
//
// FRISKET DOES NOT NORMALISE A PATH AND FORWARD THE RESULT. It refuses what
// would need normalising, and forwards exactly the bytes it checked. Checking
// one spelling and sending another is how a scope is escaped: "/repos/o/r/..
// /../x/y" is under /repos/o/r to a string match and is /x/y to the upstream.
// So a segment is refused when, after decoding it as many times as anything
// might, any part of it -- split on / and \, cut at ; as Tomcat does -- is
// nothing but dots, whatever dot it was spelled with. Empty segments are
// refused except at the end, so "//" cannot line segments up differently for
// a server that collapses it. Control characters and invalid UTF-8 are
// refused outright.
//
// What is left through is ordinary: a percent-encoded slash inside a segment
// ("feature%2Fx", which gh sends for a branch name) is one segment here and
// cannot climb, because no part of it is dots.
func splitPath(escaped string) ([]string, error) {
	if !strings.HasPrefix(escaped, "/") {
		return nil, errBadPath
	}
	raw := strings.Split(escaped[1:], "/")
	segs := make([]string, len(raw))
	for i, r := range raw {
		if r == "" && i != len(raw)-1 {
			return nil, errBadPath
		}
		seg, err := url.PathUnescape(r)
		if err != nil {
			return nil, errBadPath
		}
		if hazardous(seg) {
			return nil, errBadPath
		}
		segs[i] = seg
	}
	return segs, nil
}

func hazardous(seg string) bool {
	for range maxDecodes {
		if hazardousOnce(seg) {
			return true
		}
		next, err := url.PathUnescape(seg)
		if err != nil || next == seg {
			return false
		}
		seg = next
	}
	// Still decoding to something new after this many rounds: nothing
	// legitimate is percent-encoded five times over.
	return true
}

func hazardousOnce(seg string) bool {
	// Invalid UTF-8 is refused because an overlong encoding is a dot to the
	// servers that decode it leniently: %c0%ae is the classic.
	if !utf8.ValidString(seg) {
		return true
	}
	for i := 0; i < len(seg); i++ {
		if c := seg[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	for part := range strings.FieldsFuncSeq(seg, func(r rune) bool { return r == '/' || r == '\\' }) {
		part, _, _ = strings.Cut(part, ";")
		if dotsOnly(part) {
			return true
		}
	}
	return false
}

// dotsOnly is "." and ".." and every spelling a server might fold into them:
// "...", ". .", and the fullwidth and one-dot-leader characters that NFKC
// turns into a full stop, which IIS-style normalisation applies.
func dotsOnly(s string) bool {
	dots := 0
	for _, r := range s {
		switch r {
		case '.', '．', '․', '﹒':
			dots++
		case ' ':
		default:
			return false
		}
	}
	return dots > 0
}
