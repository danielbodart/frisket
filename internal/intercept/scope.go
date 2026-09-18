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

// Scope is what a route's credential may be used for. A request is admitted
// if any part of the scope admits it, and refused otherwise: an empty scope
// admits nothing, and New refuses to build a route with one.
//
// It is checked against the real request line, after TLS, on every request
// (PLAN.md, decision 6). The connection being steered here says only where
// the workload was going; the request is entirely the workload's, and anything
// in the sandbox can open a connection to an intercepted host and ask frisket
// to add the credential.
type Scope struct {
	// Paths admit a request whose method is listed and whose path is at or
	// under Prefix.
	Paths []PathRule
	// Git admits git's smart-HTTP protocol, GitHub-shaped, for a set of
	// repositories.
	Git *GitScope
	// GitHubAPI admits GitHub REST calls under /repos/{owner}/{repo}.
	GitHubAPI *GitHubAPIScope
}

// PathRule admits the listed methods at or under a path prefix.
//
// The prefix is matched by SEGMENT, never as a string: "/backend-api/codex"
// admits "/backend-api/codex/responses" and not "/backend-api/codex-evil".
// A string prefix is the mistake git's insteadOf makes, where `owner/repo`
// also matches `owner/repo-evil`.
type PathRule struct {
	Methods []string
	Prefix  string
}

// GitScope admits git over HTTPS as GitHub serves it: /{owner}/{repo}[.git]
// followed by info/refs, git-upload-pack or git-receive-pack, and nothing
// else -- no web UI, no LFS, no dumb protocol.
type GitScope struct {
	Repos []Repo
	// Push admits git-receive-pack. Without it, fetch and clone work and a
	// push is refused at its first request, the ref advertisement -- which is
	// the one agents-container enforced by inspecting `git`'s command line.
	// Here it is the request line, which a workload cannot route around by
	// running git some other way.
	Push bool
}

// GitHubAPIScope admits /repos/{owner}/{repo} and everything under it, with
// the listed methods, for the listed repositories.
//
// Only that shape: /repositories/{id}, /graphql, /search and /user are not
// repository-scoped by their path and are refused unless a PathRule admits
// them deliberately.
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
)

// compiled is a Scope checked and prepared once, when the route is built.
type compiled struct {
	paths []compiledPath
	git   *GitScope
	api   *GitHubAPIScope
}

type compiledPath struct {
	methods []string
	prefix  []string
}

func compileScope(s Scope) (*compiled, error) {
	c := &compiled{}
	for _, p := range s.Paths {
		if len(p.Methods) == 0 {
			return nil, fmt.Errorf("path rule %q lists no methods", p.Prefix)
		}
		if !strings.HasPrefix(p.Prefix, "/") {
			return nil, fmt.Errorf("path rule %q does not start with /", p.Prefix)
		}
		segs, err := splitPath(p.Prefix)
		if err != nil {
			return nil, fmt.Errorf("path rule %q: %w", p.Prefix, err)
		}
		// "/" is the whole host; "/a/" is written as "/a". A trailing empty
		// segment in a prefix would demand a trailing slash on every request.
		if n := len(segs); n > 0 && segs[n-1] == "" {
			segs = segs[:n-1]
		}
		if slices.Contains(segs, "") {
			return nil, fmt.Errorf("path rule %q has an empty segment", p.Prefix)
		}
		c.paths = append(c.paths, compiledPath{methods: upper(p.Methods), prefix: segs})
	}
	if s.Git != nil {
		if len(s.Git.Repos) == 0 {
			return nil, errors.New("git scope lists no repositories")
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
	if len(c.paths) == 0 && c.git == nil && c.api == nil {
		return nil, errors.New("scope admits nothing")
	}
	return c, nil
}

func upper(ms []string) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = strings.ToUpper(m)
	}
	return out
}

// allow decides a request. It returns the reason for a refusal, or which part
// of the scope admitted it.
//
// Methods are compared exactly, and a request's method is not upper-cased
// first: "get" is not GET to every server, and a method the rule does not name
// is refused rather than interpreted.
func (c *compiled) allow(method string, u *url.URL) (bool, string) {
	segs, err := splitPath(u.EscapedPath())
	if err != nil {
		return false, ReasonBadPath
	}
	for _, p := range c.paths {
		if slices.Contains(p.methods, method) && hasPrefix(segs, p.prefix) {
			return true, "path"
		}
	}
	if c.api != nil && slices.Contains(c.api.Methods, method) &&
		len(segs) >= 3 && segs[0] == "repos" && inRepos(c.api.Repos, segs[1], segs[2]) {
		return true, "github-api"
	}
	if c.git != nil {
		if ok, reason := c.git.allow(method, segs, u.RawQuery); ok || reason != "" {
			return ok, reason
		}
	}
	return false, ReasonOutOfScope
}

// allow for git returns ("", false) when the request is not git-shaped at
// all, so the caller reports it as out of scope; it names a reason only when
// the request IS a git request and something about it is refused.
func (g *GitScope) allow(method string, segs []string, rawQuery string) (bool, string) {
	if len(segs) < 3 {
		return false, ""
	}
	name, _ := cutSuffixFold(segs[1], ".git")
	if !inRepos(g.Repos, segs[0], name) {
		return false, ""
	}
	rest := segs[2:]
	switch {
	case method == http.MethodGet && len(rest) == 2 && rest[0] == "info" && rest[1] == "refs":
		// The ref advertisement says which service it is for in the query.
		// Exactly one value, parsed strictly: a second `service=` or a query
		// Go cannot parse is a disagreement between us and the upstream about
		// which service this is, and that is refused rather than resolved.
		q, err := url.ParseQuery(rawQuery)
		if err != nil || len(q["service"]) != 1 {
			return false, ReasonOutOfScope
		}
		switch q.Get("service") {
		case "git-upload-pack":
			return true, "git"
		case "git-receive-pack":
			if g.Push {
				return true, "git"
			}
			return false, ReasonPush
		}
		return false, ReasonOutOfScope
	case method == http.MethodPost && len(rest) == 1 && rawQuery != "":
		// git never sends a query with a POST. One that arrives is somebody
		// asking a server that might read `service=` from it to disagree
		// with the path about which service this is.
		return false, ReasonOutOfScope
	case method == http.MethodPost && len(rest) == 1 && rest[0] == "git-upload-pack":
		return true, "git"
	case method == http.MethodPost && len(rest) == 1 && rest[0] == "git-receive-pack":
		if g.Push {
			return true, "git"
		}
		return false, ReasonPush
	}
	return false, ""
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

func hasPrefix(segs, prefix []string) bool {
	return len(segs) >= len(prefix) && slices.Equal(segs[:len(prefix)], prefix)
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
