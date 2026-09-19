package intercept

import (
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var (
	ownerRepo = Repo{Owner: "owner", Name: "repo"}

	testScope = Scope{
		Paths:     []PathRule{{Methods: []string{"GET", "POST"}, Prefix: "/v1/messages"}},
		GitHubAPI: &GitHubAPIScope{Repos: []Repo{ownerRepo}, Methods: []string{"GET"}},
		Git:       &GitScope{Repos: []Repo{ownerRepo}},
	}
)

func mustCompile(t interface {
	Helper()
	Fatal(...any)
}, s Scope) *compiled {
	t.Helper()
	c, err := compileScope(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// parseTarget reads a request target the way net/http's server does, so a
// test decides exactly what a request from the sandbox would decide.
func parseTarget(target string) (*url.URL, bool) {
	u, err := url.ParseRequestURI(target)
	return u, err == nil
}

func TestScopeDecisions(t *testing.T) {
	c := mustCompile(t, testScope)
	push := mustCompile(t, Scope{Git: &GitScope{Repos: []Repo{ownerRepo}, Push: true}})
	anyRepo := mustCompile(t, Scope{Git: &GitScope{AnyRepo: true}})
	readOnly := mustCompile(t, Scope{
		Paths: []PathRule{{Methods: []string{"GET", "HEAD"}, Prefix: "/"}},
		Git:   &GitScope{AnyRepo: true},
	})

	for _, tc := range []struct {
		scope  *compiled
		method string
		target string
		ok     bool
		reason string
	}{
		{c, "POST", "/v1/messages", true, "path"},
		{c, "POST", "/v1/messages/", true, "path"},
		{c, "POST", "/v1/messages/count_tokens", true, "path"},
		{c, "POST", "/v1/%6dessages", true, "path"},
		{c, "POST", "/v1/messages-evil", false, ReasonOutOfScope},
		{c, "POST", "/v1/messages.", false, ReasonOutOfScope},
		{c, "POST", "/v1/Messages", false, ReasonOutOfScope},
		{c, "DELETE", "/v1/messages", false, ReasonOutOfScope},
		{c, "post", "/v1/messages", false, ReasonOutOfScope},
		{c, "POST", "/v1/models", false, ReasonOutOfScope},
		{c, "POST", "/v1//messages", false, ReasonBadPath},
		{c, "POST", "//v1/messages", false, ReasonBadPath},
		{c, "POST", "/v1/messages/../../admin", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%2e%2e/%2e%2e/admin", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%2E./x", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%252e%252e/x", false, ReasonBadPath},
		{c, "POST", "/v1/messages/x%2F..%2F..%2Fadmin", false, ReasonBadPath},
		{c, "POST", "/v1/messages/x%5C..%5Cadmin", false, ReasonBadPath},
		{c, "POST", "/v1/messages/..;/admin", false, ReasonBadPath},
		{c, "POST", "/v1/messages/.../x", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%EF%BC%8E%EF%BC%8E/x", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%c0%ae%c0%ae/x", false, ReasonBadPath},
		{c, "POST", "/v1/messages/%00", false, ReasonBadPath},

		{c, "GET", "/repos/owner/repo", true, "github-api"},
		{c, "GET", "/repos/owner/repo/pulls/1", true, "github-api"},
		{c, "GET", "/repos/Owner/REPO/issues", true, "github-api"},
		{c, "GET", "/repos/owner/repo/branches/feature%2Fx", true, "github-api"},
		{c, "GET", "/repos/owner/repo/compare/main...feature", true, "github-api"},
		{c, "GET", "/repos/owner/repo-evil", false, ReasonOutOfScope},
		{c, "GET", "/repos/owner/rep", false, ReasonOutOfScope},
		{c, "GET", "/repos/owner/repo.git", false, ReasonOutOfScope},
		{c, "GET", "/repos/owner%2Frepo/x", false, ReasonOutOfScope},
		{c, "GET", "/repos/owner/rep%E2%84%AA", false, ReasonOutOfScope},
		{c, "GET", "/repos/owner/repo/../../other/repo", false, ReasonBadPath},
		{c, "POST", "/repos/owner/repo/issues", false, ReasonOutOfScope},
		{c, "POST", "/graphql", false, ReasonOutOfScope},
		{c, "GET", "/repositories/1234", false, ReasonOutOfScope},

		{c, "GET", "/owner/repo.git/info/refs?service=git-upload-pack", true, "git"},
		{c, "GET", "/owner/repo/info/refs?service=git-upload-pack", true, "git"},
		{c, "GET", "/Owner/Repo.GIT/info/refs?service=git-upload-pack", true, "git"},
		{c, "POST", "/owner/repo.git/git-upload-pack", true, "git"},
		{c, "GET", "/owner/repo-evil.git/info/refs?service=git-upload-pack", false, ReasonOutOfScope},
		{c, "POST", "/owner/repo-evil/git-upload-pack", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git.git/info/refs?service=git-upload-pack", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git/info/refs?service=git-receive-pack", false, ReasonPush},
		{c, "POST", "/owner/repo.git/git-receive-pack", false, ReasonPush},
		{c, "GET", "/owner/repo.git/info/refs", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git/info/refs?service=git-upload-pack&service=git-receive-pack", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git/info/refs?service=git-upload-pack;x", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git/HEAD", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo.git/objects/info/packs", false, ReasonOutOfScope},
		{c, "POST", "/owner/repo.git/info/lfs/objects/batch", false, ReasonOutOfScope},
		{c, "GET", "/owner/repo", false, ReasonOutOfScope},
		{c, "POST", "/owner/repo.git/git-upload-pack?service=git-receive-pack", false, ReasonOutOfScope},

		{push, "GET", "/owner/repo.git/info/refs?service=git-receive-pack", true, "git"},
		{push, "POST", "/owner/repo.git/git-receive-pack", true, "git"},
		{push, "POST", "/owner/repo-evil.git/git-receive-pack", false, ReasonOutOfScope},

		{anyRepo, "GET", "/someone/else.git/info/refs?service=git-upload-pack", true, "git"},
		{anyRepo, "POST", "/someone/else/git-upload-pack", true, "git"},
		{anyRepo, "GET", "/someone/else.git/info/refs?service=git-receive-pack", false, ReasonPush},
		{anyRepo, "POST", "/someone/else.git/git-receive-pack", false, ReasonPush},
		{anyRepo, "POST", "/someone/else.git/info/lfs/objects/batch", false, ReasonOutOfScope},
		{anyRepo, "GET", "/someone/else", false, ReasonOutOfScope},
		{anyRepo, "POST", "/someone/../else/git-upload-pack", false, ReasonBadPath},

		// GET everywhere, and git without push: the git scope's refusal stands.
		{readOnly, "GET", "/someone/else/releases/download/v1/x.tar.gz", true, "path"},
		{readOnly, "GET", "/someone/else.git/info/refs?service=git-upload-pack", true, "git"},
		{readOnly, "POST", "/someone/else.git/git-upload-pack", true, "git"},
		{readOnly, "GET", "/someone/else.git/info/refs?service=git-receive-pack", false, ReasonPush},
		{readOnly, "POST", "/someone/else.git/git-receive-pack", false, ReasonPush},
		{readOnly, "POST", "/someone/else.git/info/lfs/objects/batch", false, ReasonOutOfScope},
		{readOnly, "POST", "/graphql", false, ReasonOutOfScope},
	} {
		u, ok := parseTarget(tc.target)
		if !ok {
			t.Fatalf("test target %q does not parse", tc.target)
		}
		got, reason := tc.scope.allow(tc.method, u)
		if got != tc.ok || reason != tc.reason {
			t.Errorf("%s %s: got (%v, %q), want (%v, %q)", tc.method, tc.target, got, reason, tc.ok, tc.reason)
		}
	}
}

// net/http refuses a bad escape before a handler sees it; splitPath refuses
// it too, rather than relying on that.
func TestSplitPathRefusesBadEscapes(t *testing.T) {
	for _, p := range []string{"/v1/messages/%zz", "/a/%", "/a/%2", "v1", ""} {
		if _, err := splitPath(p); err == nil {
			t.Errorf("splitPath(%q) accepted", p)
		}
	}
}

func TestScopeConfigurationRefusals(t *testing.T) {
	for name, s := range map[string]Scope{
		"empty":                 {},
		"path without methods":  {Paths: []PathRule{{Prefix: "/v1"}}},
		"relative prefix":       {Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "v1"}}},
		"dotted prefix":         {Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/v1/../x"}}},
		"git without repos":     {Git: &GitScope{}},
		"git with any and some": {Git: &GitScope{AnyRepo: true, Repos: []Repo{ownerRepo}}},
		"api without methods":   {GitHubAPI: &GitHubAPIScope{Repos: []Repo{ownerRepo}}},
		"repo of dots":          {Git: &GitScope{Repos: []Repo{{Owner: "owner", Name: ".."}}}},
		"repo with slash":       {Git: &GitScope{Repos: []Repo{{Owner: "owner", Name: "a/b"}}}},
	} {
		if _, err := compileScope(s); err == nil {
			t.Errorf("%s: compiled, want a refusal", name)
		}
	}
}

// climbs is the most aggressive reading of a path any upstream might make:
// percent-decoded until nothing changes (leniently, leaving a bad escape as it
// is), backslashes as slashes, ;parameters dropped, the fullwidth dots folded,
// trailing dots and spaces stripped as Windows does, empty segments collapsed,
// and dot-segments resolved. It reports the segments that reading arrives at,
// and whether any dot-segment climbed.
func climbs(escaped string) (segs []string, popped bool) {
	s := escaped
	for range 8 {
		n := lenientUnescape(s)
		if n == s {
			break
		}
		s = n
	}
	s = strings.NewReplacer("\\", "/", "．", ".", "․", ".", "﹒", ".").Replace(s)
	for seg := range strings.SplitSeq(s, "/") {
		seg, _, _ = strings.Cut(seg, ";")
		trimmed := strings.TrimRight(seg, ". ")
		if trimmed == "" {
			if strings.Count(seg, ".") >= 2 {
				popped = true
				if len(segs) > 0 {
					segs = segs[:len(segs)-1]
				}
			}
			continue
		}
		segs = append(segs, trimmed)
	}
	return segs, popped
}

func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// Pieces that have escaped a path scope somewhere, plus ordinary ones for them
// to hide among.
var pathPieces = []string{
	"v1", "messages", "repos", "owner", "Owner", "repo", "REPO", "repo-evil", "repo.git",
	"info", "refs", "git-upload-pack", "git-receive-pack", "admin", "a", "",
	".", "..", "...", ". .", "%2e", "%2e%2e", "%2E.", ".%2e", "%252e%252e", "%25252e%25252e",
	"..;", "..;x", "..%3b", "x%2F..", "x%2f..%2f..", "%2f", "a%2Fb", "..\\", "%5c..", "x%5C..%5C..",
	"%EF%BC%8E%EF%BC%8E", "．．", "%c0%ae%c0%ae", "messages.", "repo.", "messages..",
	"%00", "%0a", "%25", "%zz", "..%00", "own%65r", "rep%6f", "%6dessages", "rep%6f.git",
}

// genTarget starts, usually, from somewhere a scope admits and then adds
// pieces to it, because a path generated at random from nothing is almost
// never admitted and a property over refused paths proves nothing.
func genTarget() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		base := rapid.SampledFrom([]string{
			"", "/v1/messages", "/v1", "/repos/owner/repo", "/repos/owner",
			"/owner/repo.git", "/owner/repo", "/owner/repo.git/info",
		}).Draw(t, "base")
		tail := rapid.SliceOfN(rapid.OneOf(
			rapid.SampledFrom(pathPieces),
			rapid.StringMatching(`[a-zA-Z0-9._%;\\-]{0,6}`),
		), 0, 6).Draw(t, "tail")
		q := rapid.SampledFrom([]string{
			"", "?service=git-upload-pack", "?service=git-receive-pack",
			"?service=git-upload-pack&service=git-receive-pack",
		}).Draw(t, "query")
		return base + "/" + strings.Join(tail, "/") + q
	})
}

// scopeCannotBeEscaped: whatever path is admitted, the most aggressive reading
// of it any upstream might make is still inside the scope that admitted it,
// and never climbed a dot-segment on the way.
func scopeCannotBeEscaped(t *rapid.T) {
	c := mustCompile(t, testScope)
	target := genTarget().Draw(t, "target")
	method := rapid.SampledFrom([]string{"GET", "POST", "get", "PUT"}).Draw(t, "method")
	u, ok := parseTarget(target)
	if !ok {
		return
	}
	admitted, rule := c.allow(method, u)
	if !admitted {
		return
	}
	segs, popped := climbs(u.EscapedPath())
	if popped {
		t.Fatalf("%s %s admitted by %s, but a dot-segment climbs: %v", method, target, rule, segs)
	}
	switch rule {
	case "path":
		if method != "GET" && method != "POST" {
			t.Fatalf("%s admitted for a rule without it", method)
		}
		if len(segs) < 2 || segs[0] != "v1" || segs[1] != "messages" {
			t.Fatalf("%s %s admitted under /v1/messages, but reads as %v", method, target, segs)
		}
	case "github-api":
		if method != "GET" || len(segs) < 3 || segs[0] != "repos" ||
			!asciiEqualFold(segs[1], "owner") || !asciiEqualFold(segs[2], "repo") {
			t.Fatalf("%s %s admitted for owner/repo, but reads as %v", method, target, segs)
		}
	case "git":
		name, _ := cutSuffixFold(safeIndex(segs, 1), ".git")
		if len(segs) < 3 || !asciiEqualFold(segs[0], "owner") || !asciiEqualFold(name, "repo") {
			t.Fatalf("%s %s admitted for owner/repo, but reads as %v", method, target, segs)
		}
		if strings.Contains(u.RawQuery, "receive-pack") || strings.Contains(u.Path, "receive-pack") {
			t.Fatalf("%s %s is a push, admitted without Push", method, target)
		}
	default:
		t.Fatalf("admitted by unknown rule %q", rule)
	}
}

func safeIndex(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}

func TestScopeCannotBeEscaped(t *testing.T) { rapid.Check(t, scopeCannotBeEscaped) }

func FuzzScopeCannotBeEscaped(f *testing.F) { f.Fuzz(rapid.MakeFuzz(scopeCannotBeEscaped)) }

// A repository set scoped to owner/repo never admits a repository whose name
// merely starts with "repo" -- the insteadOf mistake -- in either shape.
func TestRepoIsMatchedAsASegmentNeverAPrefix(t *testing.T) {
	c := mustCompile(t, testScope)
	rapid.Check(t, func(t *rapid.T) {
		suffix := rapid.StringMatching(`[A-Za-z0-9._-]{1,12}`).Draw(t, "suffix")
		name := "repo" + suffix
		targets := []string{"/repos/owner/" + name, "/repos/owner/" + name + "/pulls"}
		// "repo.git" is the same repository to git; any other suffix is not.
		if !asciiEqualFold(suffix, ".git") {
			targets = append(targets,
				"/owner/"+name+"/info/refs?service=git-upload-pack",
				"/owner/"+name+".git/info/refs?service=git-upload-pack",
				"/owner/"+name+"/git-upload-pack",
			)
		}
		for _, target := range targets {
			u, ok := parseTarget(target)
			if !ok {
				continue
			}
			for _, m := range []string{"GET", "POST"} {
				if ok, rule := c.allow(m, u); ok {
					t.Fatalf("%s %s admitted by %s for a scope of owner/repo", m, target, rule)
				}
			}
		}
	})
}

// FuzzSplitPath holds the path parser to one promise on any input at all:
// a path it accepts never climbs, however aggressively it is read, contains
// no control character, and has no empty segment except a trailing one.
func FuzzSplitPath(f *testing.F) {
	for _, p := range pathPieces {
		f.Add("/" + p)
		f.Add("/v1/messages/" + p + "/x")
	}
	f.Add("/")
	f.Add("")
	f.Add("/a//b")
	f.Fuzz(func(t *testing.T, escaped string) {
		segs, err := splitPath(escaped)
		if err != nil {
			return
		}
		if _, popped := climbs(escaped); popped {
			t.Fatalf("splitPath accepted %q, which climbs", escaped)
		}
		for i, s := range segs {
			if s == "" && i != len(segs)-1 {
				t.Fatalf("splitPath accepted %q with an empty segment at %d", escaped, i)
			}
			if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				t.Fatalf("splitPath accepted %q with a control character", escaped)
			}
		}
	})
}
