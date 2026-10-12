package policy_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/store"
	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/frisket/projpolicy"
)

func lowered(t *testing.T, doc string) *policy.Lowered {
	t.Helper()
	l, err := policy.Load([]byte(doc))
	if err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	return l
}

func ask(t *testing.T, l *policy.Lowered, route, method, target string) string {
	t.Helper()
	s, err := store.RouteScope(l, route)
	if err != nil {
		t.Fatal(err)
	}
	a, err := intercept.Answer(s, method, target)
	if err != nil {
		t.Fatal(err)
	}
	return a.Outcome.String()
}

const github = `{
  "version": 2, "name": "p",
  "allow": {"api.github.com": true},
  "writes": "refuse", "guarded": "ask",
  "routes": {"api": {
    "host": "api.github.com", "upstream": "https://api.github.com",
    "paths": {
      "POST /repos/*/*/pulls":  {"operation": {"id": "pulls/create",  "summary": "s", "class": "write",   "category": "pulls"}},
      "POST /repos/*/*/issues": {"operation": {"id": "issues/create", "summary": "s", "class": "write",   "category": "issues"}},
      "POST /repos/*/*/labels": {"operation": {"id": "labels/create", "summary": "s", "class": "write",   "category": "labels"}},
      "PATCH /repos/*/*":       {"operation": {"id": "repos/update",  "summary": "s", "class": "write",   "category": "repos"}},
      "DELETE /repos/*/*":      {"operation": {"id": "repos/delete",  "summary": "s", "class": "guarded", "category": "repos"}},
      "GET /repos/*/*":         {"operation": {"id": "repos/get",     "summary": "s", "class": "read",    "category": "repos"}}
    },
    "operations": {
      "pulls/create": "allow",
      "category:issues": "refuse",
      "POST /repos/o/**": "ask",
      "POST /repos/o/r/issues": "allow",
      "POST /repos/o/*/labels": "allow",
      "GET /user": "allow"
    },
    "writes": "ask"
  }}
}`

// An id decides before a category, a category before any pattern, the
// most specific pattern before the operation's class, the route's class
// answer before the document's, and the document's before the built-in.
func TestAnAnswerIsTheMostSpecificThatSays(t *testing.T) {
	l := lowered(t, github)
	for _, c := range []struct{ method, target, want, why string }{
		{"POST", "/repos/o/r/pulls", "allow", "its id, over the pattern POST /repos/o/**"},
		{"POST", "/repos/o/r/issues", "refuse", "its category, over the literal pattern"},
		{"POST", "/repos/o/r/labels", "allow", "the narrower pattern, over POST /repos/o/**"},
		{"POST", "/repos/x/r/labels", "ask", "no pattern: the route's writes"},
		{"PATCH", "/repos/o/r", "ask", "the route's writes"},
		{"DELETE", "/repos/x/r", "ask", "the document's guarded"},
		{"GET", "/repos/x/r", "allow", "a read"},
		{"GET", "/user", "allow", "a pattern, for what is no operation"},
		{"POST", "/repos/o/r/forks", "ask", "the prefix pattern"},
		{"GET", "/elsewhere", "refuse", "unmatched: the built-in"},
	} {
		if got := ask(t, l, "api", c.method, c.target); got != c.want {
			t.Errorf("%s %s: %s, want %s (%s)", c.method, c.target, got, c.want, c.why)
		}
	}
}

// A ceiling clamps every answer of its class, an id's too, and of a route
// and the document's the stricter holds.
func TestACeilingClampsEveryAnswerOfItsClass(t *testing.T) {
	var d map[string]any
	if err := json.Unmarshal([]byte(github), &d); err != nil {
		t.Fatal(err)
	}
	d["ceiling"] = map[string]any{"writes": "refuse"}
	api := d["routes"].(map[string]any)["api"].(map[string]any)
	api["ceiling"] = map[string]any{"writes": "ask", "guarded": "refuse", "unmatched": "ask"}
	api["operations"].(map[string]any)["repos/delete"] = "allow"
	api["unmatched"] = "allow"
	b, _ := json.Marshal(d)
	l := lowered(t, string(b))
	for _, c := range []struct{ method, target, want string }{
		{"POST", "/repos/o/r/pulls", "refuse"}, // id allow; the document's writes ceiling over the route's
		{"DELETE", "/repos/o/r", "refuse"},     // id allow; guarded ceiling
		{"GET", "/user", "ask"},                // pattern allow; unmatched ceiling
		{"GET", "/elsewhere", "ask"},           // unmatched allow, clamped
		{"GET", "/repos/o/r", "allow"},         // a read has no ceiling
	} {
		if got := ask(t, l, "api", c.method, c.target); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.method, c.target, got, c.want)
		}
	}
}

// Layers merge by RFC 7396: the tier over frisket's defaults, the project
// over the tier, a null deleting what a layer under it said.
func TestLayersMergeAndANullDeletes(t *testing.T) {
	tier := `{"routes": {"api": {"operations": {"pulls/create": null, "repos/delete": "refuse"}}},
	          "allow": {"old.example": true}}`
	project := `{"routes": {"api": {"operations": {"repos/delete": null, "category:issues": null, "issues/create": "ask"}}},
	             "allow": {"old.example": null, "pypi.org": true}}`
	base, err := merge(github, tier)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := policy.CheckProjectLayer([]byte(project), base)
	if err != nil {
		t.Fatal(err)
	}
	l := lowered(t, string(merged))
	for _, c := range []struct{ method, target, want string }{
		{"POST", "/repos/o/r/pulls", "ask"},  // the tier deleted its id: the pattern POST /repos/o/**
		{"POST", "/repos/x/r/pulls", "ask"},  // and elsewhere the route's writes
		{"DELETE", "/repos/x/r", "ask"},      // the project deleted the tier's refuse: the document's guarded
		{"POST", "/repos/x/r/issues", "ask"}, // the category gone, its id
		{"POST", "/repos/o/r/issues", "ask"}, // the id beats the literal pattern
	} {
		if got := ask(t, l, "api", c.method, c.target); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.method, c.target, got, c.want)
		}
	}
	if slices.Contains(l.Policy.Allow, "old.example") || !slices.Contains(l.Policy.Allow, "pypi.org") {
		t.Errorf("allow %v", l.Policy.Allow)
	}
}

func merge(base, patch string) ([]byte, error) {
	b, err := projpolicy.Decode([]byte(base))
	if err != nil {
		return nil, err
	}
	p, err := projpolicy.Decode([]byte(patch))
	if err != nil {
		return nil, err
	}
	return projpolicy.Encode(projpolicy.MergePatch(b, p))
}

// A project layer answers; it never says what a route is, where it goes,
// what it carries, or how far it may be answered, and it adds no route.
func TestAProjectLayerSetsNothingOfTheHosts(t *testing.T) {
	base := []byte(github)
	for _, c := range []struct{ layer, want string }{
		{`{"routes": {"api": {"upstream": "https://evil.example"}}}`, "routes.api.upstream: the host's"},
		{`{"routes": {"api": {"credentialFile": "/home/me/token"}}}`, "routes.api.credentialFile: the host's"},
		{`{"routes": {"api": {"paths": {"GET /x": {"operation": {"id": "x", "summary": "x", "class": "read"}}}}}}`, "routes.api.paths: the host's"},
		{`{"routes": {"api": {"ceiling": null}}}`, "routes.api.ceiling: the host's"},
		{`{"ceiling": {"writes": "allow"}}`, "ceiling: the host's"},
		{`{"record": {"default": "allow"}}`, "record: the host's"},
		{`{"name": "other"}`, "name: the host's"},
		{`{"routes": {"new": {"operations": {"GET /**": "allow"}}}}`, "routes.new: the base defines no such route"},
		{`{"routes": {"api": null}}`, "routes.api: deleting a route"},
		{`{"ssh": {"server": {"exec": {"ls": "allow"}}}}`, "ssh.server: the base defines no such route"},
		{`{"routes": {"api": {"operashuns": {}}}}`, "routes.api.operashuns: no such field"},
		{`{"routes": {"api": {"operations": {"GET /a/../b": "allow"}}}}`, "a dot segment"},
		{`{"routes": {"api": {"operations": {"POST /repos/*/*/pulls": "refuse"}}}}`, "pulls/create is answered by name"},
		{`{"routes": {"api": {"operations": {"nosuch/op": "allow"}}}}`, "no such operation"},
		{`{"allow": {"*-Ap.lan": true}}`, "a capital"},
		{`{"ssh": {"*-ap": {"exec": {"ls": "allow"}}}}`, "matches no SSH route"},
		{`{"version": 1}`, "version 1"},
		{`{"routes": {"api": {"always": true}}}`, "routes.api.always: the host's"},
	} {
		_, err := policy.CheckProjectLayer([]byte(c.layer), base)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.layer, err, c.want)
		}
	}
	if _, err := policy.CheckProjectLayer([]byte(`{"version": 2, "allow": {"pypi.org": true}, "writes": "allow",
		"routes": {"api": {"operations": {"GET /repos/o/**": "allow", "repos/delete": "refuse"}, "guarded": "refuse"}}}`), base); err != nil {
		t.Errorf("a project's answers: %v", err)
	}
}

// Keys of allow, lan and ssh take hostpattern's grammar: one label, a run
// of one, or ** for any depth; an SSH pattern's answers apply to every
// machine it matches, the machine's own beating it and a narrower pattern
// a wider one.
func TestHostPatternsInAllowLanAndSSH(t *testing.T) {
	l := lowered(t, `{"version": 2, "name": "p",
	  "allow": {"*.example.com": true, "*-ap.lan": true, "**.deep.test": true, "exact.test": true, "off.test": false},
	  "lan": {"*-ap.lan": {"ports": [22]}, "nas.lan": {}},
	  "ssh": {
	    "kitchen-ap": {"address": "192.168.1.2", "user": "root",
	      "hostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ap"],
	      "passwordFile": "/run/secrets/ap", "exec": {"uci show **": "ask"}},
	    "*-ap": {"exec": {"uci show **": "allow", "logread **": "allow"}, "unmatched": "refuse"},
	    "**": {"exec": {"logread **": "refuse", "reboot": "refuse"}}
	  }}`)
	m, err := dns.NewMatcher(l.Policy.Allow...)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddHostPatterns(l.AllowPatterns...); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"a.example.com": true, "a.b.example.com": false, "example.com": false,
		"kitchen-ap.lan": true, "kitchen.lan": false,
		"x.deep.test": true, "x.y.deep.test": true, "deep.test": false,
		"exact.test": true, "off.test": false,
	} {
		if got := m.Match(name); got != want {
			t.Errorf("allow %s: %v", name, got)
		}
	}
	if !reflect.DeepEqual(l.LANPatterns, map[string][]int{"*-ap.lan": {22}}) || len(l.Policy.LAN) != 1 {
		t.Errorf("lan %v %v", l.LANPatterns, l.Policy.LAN)
	}
	if len(l.Policy.SSH) != 1 {
		t.Fatalf("ssh routes %+v", l.Policy.SSH)
	}
	rules, err := execrule.Compile(l.Policy.SSH[0])
	if err != nil {
		t.Fatal(err)
	}
	for command, want := range map[string]string{
		"uci show wireless": "ask",    // the machine's own
		"logread -f":        "allow",  // *-ap over **
		"reboot":            "refuse", // ** alone says
		"ls":                "refuse", // *-ap's unmatched
	} {
		if got := rules.Decide(command).Outcome.String(); got != want {
			t.Errorf("%s: %s, want %s", command, got, want)
		}
	}
}

// A document says what it says once: a key twice, a null, an id or a
// category no operation has, an answer that is none, a version that is
// neither.
func TestAVersion2DocumentIsReadStrictly(t *testing.T) {
	for _, c := range []struct{ doc, want string }{
		{`{"version": 2, "name": "p", "allow": {"a.test": true, "a.test": false}}`, "twice"},
		{`{"version": 2, "name": "p", "allow": {"a.test": null}}`, "allow.a.test is null"},
		{`{"version": 3, "name": "p"}`, "1 or 2"},
		{`{"version": 2, "name": "p", "writes": "maybe"}`, "allow, ask or refuse"},
		{`{"version": 2, "name": "p", "alow": {}}`, "unknown field"},
		{`{"version": 2, "name": "p", "routes": {"r": {"host": "r.test", "upstream": "https://r.test", "operations": {"x/y": "allow"}}}}`, "no such operation"},
		{`{"version": 2, "name": "p", "routes": {"r": {"host": "r.test", "upstream": "https://r.test", "operations": {"category:x": "allow"}}}}`, "category"},
		{`{"version": 2, "name": "p", "routes": {"r": {"host": "r.test", "upstream": "https://r.test", "operations": {"get /x": "allow"}}}}`, "capitals"},
		{`{"version": 2, "name": "p", "routes": {"r": {"host": "r.test", "upstream": "https://r.test", "operations": {"GET /**/x": "allow"}}}}`, "last segment"},
		{`{"version": 2, "name": "p", "routes": {"r": {"host": "*.r.test", "upstream": "https://r.test"}}}`, "**.name"},
		{`{"version": 2, "name": "p", "ssh": {"*-ap": {"address": "10.0.0.1"}}}`, "a pattern is no machine"},
	} {
		_, err := policy.Load([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.doc, err, c.want)
		}
	}
	for doc, want := range map[string]int{`{"name": "p", "allow": []}`: 1, `{"version": 1, "name": "p", "allow": []}`: 1, `{"version": 2}`: 2} {
		if v, err := policy.Version([]byte(doc)); err != nil || v != want {
			t.Errorf("%s: version %d %v", doc, v, err)
		}
	}
}

// The schema is read off the types Decode reads, and marks the host's
// fields: every one a project layer is refused, and none it may set.
func TestTheSchemaMarksTheHostsFields(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(policy.SchemaV2(), &s); err != nil {
		t.Fatal(err)
	}
	var host []string
	var walk func(v any, at string)
	walk = func(v any, at string) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		if m["x-scope"] == "host" {
			host = append(host, at)
		}
		if p, ok := m["properties"].(map[string]any); ok {
			for k, x := range p {
				walk(x, strings.TrimPrefix(at+"."+k, "."))
			}
		}
		if a, ok := m["additionalProperties"].(map[string]any); ok {
			walk(a, at+".*")
		}
	}
	walk(s, "")
	slices.Sort(host)
	want := []string{
		"ceiling", "name", "record",
		"routes.*.always", "routes.*.basicUser", "routes.*.ceiling", "routes.*.credentialFile", "routes.*.credentialJSON",
		"routes.*.docker", "routes.*.encodedSlashes", "routes.*.git", "routes.*.graphql", "routes.*.header",
		"routes.*.host", "routes.*.paths", "routes.*.placeholder", "routes.*.refusal", "routes.*.sessionKey",
		"routes.*.upstream", "routes.*.upstreamCA",
		"ssh.*.address", "ssh.*.agent", "ssh.*.always", "ssh.*.ceiling", "ssh.*.commands", "ssh.*.hostKeys", "ssh.*.identity",
		"ssh.*.keyFile", "ssh.*.passwordFile", "ssh.*.shell", "ssh.*.user",
	}
	if !slices.Equal(host, want) {
		t.Errorf("host fields %v\nwant %v", host, want)
	}
	props := s["properties"].(map[string]any)
	for _, k := range []string{"version", "name", "allow", "lan", "routes", "ssh", "record", "writes", "guarded", "unmatched", "ceiling"} {
		if _, ok := props[k]; !ok {
			t.Errorf("schema has no %s", k)
		}
	}
	if len(props) != 11 {
		t.Errorf("schema has %d top-level keys", len(props))
	}
}

// Always is offered for the routes and machines the host marks, never a
// pattern's, which is no machine.
func TestAlwaysIsTheHostsMarkOfARouteOrMachine(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ap"
	l := lowered(t, `{"version": 2, "name": "p", "allow": {"a.test": true, "b.test": true},
	  "routes": {"a": {"host": "a.test", "upstream": "https://a.test", "always": true},
	             "b": {"host": "b.test", "upstream": "https://b.test"}},
	  "ssh": {"gw": {"address": "192.168.1.1", "user": "root", "hostKeys": ["`+key+`"], "agent": "/run/a", "always": true},
	          "nas": {"address": "192.168.1.2", "user": "root", "hostKeys": ["`+key+`"], "agent": "/run/a"}}}`)
	if !reflect.DeepEqual(l.Always, map[string]bool{"a": true}) || !reflect.DeepEqual(l.SSHAlways, map[string]bool{"gw": true}) {
		t.Errorf("always %v, ssh %v", l.Always, l.SSHAlways)
	}
	if l := lowered(t, github); l.Always != nil || l.SSHAlways != nil {
		t.Errorf("unmarked: %v %v", l.Always, l.SSHAlways)
	}
	_, err := policy.Load([]byte(`{"version": 2, "name": "p", "ssh": {"*-ap": {"always": true}}}`))
	if err == nil || !strings.Contains(err.Error(), "a pattern is no machine") {
		t.Errorf("a pattern's always: %v", err)
	}
}
