package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/quoin/execrule"
)

// fixtures are tests/fixtures: each NAME.v1.json beside NAME.v2.json, the
// version 2 document a person would write for it, and NAME.requests, what
// both are asked.
const fixtures = "../../tests/fixtures"

// Every version 1 document in tests/fixtures has its version 2 equivalent
// beside it, and both build, and every request its .requests file makes
// is decided the same under each: a name on the allowlist or not, an HTTP
// request by its route (as a session's scope answers it before its body is
// read), and a command by its SSH route; and the GraphQL endpoints, which
// decide from the body, and the lan names come out the same.
func TestEveryVersion1FixtureDecidesTheSameAsItsVersion2(t *testing.T) {
	v1s, err := filepath.Glob(filepath.Join(fixtures, "*.v1.json"))
	if err != nil || len(v1s) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, v1Path := range v1s {
		name := strings.TrimSuffix(filepath.Base(v1Path), ".v1.json")
		t.Run(name, func(t *testing.T) {
			one, two := loadFixture(t, v1Path), loadFixture(t, filepath.Join(fixtures, name+".v2.json"))
			for _, p := range []string{v1Path, filepath.Join(fixtures, name+".v2.json")} {
				if err := Check(copyDocument(t, p), deps(t, &counting{})); err != nil {
					t.Fatalf("%s does not build: %v", p, err)
				}
			}
			reqs, err := os.ReadFile(filepath.Join(fixtures, name+".requests"))
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for line := range strings.Lines(string(reqs)) {
				line = strings.TrimRight(line, "\n")
				if line == "" {
					continue
				}
				n++
				kind, rest, _ := strings.Cut(line, " ")
				switch kind {
				case "name":
					if a, b := allows(t, one, rest), allows(t, two, rest); a != b {
						t.Errorf("%s: version 1 %v, version 2 %v", line, a, b)
					}
				case "http":
					route, req, _ := strings.Cut(rest, " ")
					method, target, _ := strings.Cut(req, " ")
					a, b := answer(t, one, route, method, target), answer(t, two, route, method, target)
					if a != b {
						t.Errorf("%s: version 1 %+v, version 2 %+v", line, a, b)
					}
				case "ssh":
					route, command, _ := strings.Cut(rest, " ")
					a, b := command1(t, one, route, command), command1(t, two, route, command)
					if a != b {
						t.Errorf("%s: version 1 %s, version 2 %s", line, a, b)
					}
				default:
					t.Fatalf("%s: no such kind of request", line)
				}
			}
			if n == 0 {
				t.Fatal("no requests")
			}
			if a, b := graphqlOf(one), graphqlOf(two); a != b {
				t.Errorf("graphql: version 1\n%s\nversion 2\n%s", a, b)
			}
			if a, b := lanOf(one), lanOf(two); !reflect.DeepEqual(a, b) {
				t.Errorf("lan: version 1 %v, version 2 %v", a, b)
			}
		})
	}
}

func loadFixture(t *testing.T, path string) *policy.Lowered {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	l, err := policy.Load(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return l
}

// copyDocument is a fixture where Check will read one: the test's own,
// with the mode a policy document must have.
func copyDocument(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

func allows(t *testing.T, l *policy.Lowered, name string) bool {
	t.Helper()
	m, err := dns.NewMatcher(l.Policy.Allow...)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddHostPatterns(l.AllowPatterns...); err != nil {
		t.Fatal(err)
	}
	return m.Match(name)
}

func answer(t *testing.T, l *policy.Lowered, route, method, target string) intercept.Answered {
	t.Helper()
	s, err := RouteScope(l, route)
	if err != nil {
		t.Fatal(err)
	}
	a, err := intercept.Answer(s, method, target)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return a
}

func command1(t *testing.T, l *policy.Lowered, route, command string) string {
	t.Helper()
	i := slices.IndexFunc(l.Policy.SSH, func(r policy.SSHRoute) bool { return r.Name == route })
	if i < 0 {
		t.Fatalf("no ssh route %s", route)
	}
	rules, err := execrule.Compile(l.Policy.SSH[i].Spec)
	if err != nil {
		t.Fatal(err)
	}
	d := rules.Decide(command)
	id := "-"
	if d.Operation != nil {
		id = d.Operation.ID
	}
	return d.Outcome.String() + " " + d.Rule + " " + id
}

// graphqlOf is every route's GraphQL endpoints, each field by name with
// what it answers, in one order.
func graphqlOf(l *policy.Lowered) string {
	var out []string
	for _, r := range l.Policy.Routes {
		for _, g := range r.GraphQL {
			line := func(what string, f policy.GraphQLField) string {
				id := "-"
				if f.Operation != nil {
					id = f.Operation.ID
				}
				return strings.Join([]string{r.Name, g.Path, what, f.Field, answerOf(f.Ask, f.Refuse), id}, " ")
			}
			out = append(out, strings.Join([]string{r.Name, g.Path, "unmatched", g.Unmatched}, " "))
			if g.Query != nil {
				out = append(out, line("query", *g.Query))
			}
			for _, f := range g.Mutations {
				out = append(out, line("mutation", f))
			}
			for _, f := range g.Subscriptions {
				out = append(out, line("subscription", f))
			}
		}
	}
	slices.Sort(out)
	return strings.Join(out, "\n")
}

func answerOf(ask, refuse bool) string {
	switch {
	case refuse:
		return "refuse"
	case ask:
		return "ask"
	}
	return "allow"
}

func lanOf(l *policy.Lowered) map[string][]int {
	out := map[string][]int{}
	for _, h := range l.Policy.LAN {
		out[h.Name] = h.Ports
	}
	for k, ports := range l.LANPatterns {
		out[k] = ports
	}
	return out
}

// The fixtures are canonical JSON's content, if not its layout: each one
// reads as the version its name says.
func TestEachFixtureIsTheVersionItsNameSays(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join(fixtures, "*.json"))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		v, err := policy.Version(b)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		want := 1
		if strings.HasSuffix(p, ".v2.json") {
			want = 2
		}
		if v != want || !json.Valid(b) {
			t.Errorf("%s: version %d", p, v)
		}
	}
}

// A version 2 lan key may be a pattern: one with a literal label, matching
// no route's host, whose narrowest match gives a name its ports.
func TestALanPatternIsALanNameByItsNarrowestMatch(t *testing.T) {
	set, err := lanPatterns(map[string][]int{"*-ap.lan": {22}, "**.lan": {80, 80}}, policy.Policy{}, []string{"api.test"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]uint16{"kitchen-ap.lan": {22}, "nas.lan": {80}, "a.b.lan": {80}} {
		if got, ok := set.match(name); !ok || !slices.Equal(got, want) {
			t.Errorf("%s: %v %v, want %v", name, got, ok, want)
		}
	}
	if _, ok := set.match("other.test"); ok {
		t.Error("other.test is a lan name")
	}
	for keys, want := range map[string]string{"**": "no literal label", "*.*": "no literal label", "*.test": "matches api.test", "*.LAN": "capital"} {
		_, err := lanPatterns(map[string][]int{keys: nil}, policy.Policy{}, []string{"api.test"})
		if err == nil || !strings.Contains(err.Error(), want) && !strings.Contains(err.Error(), "lower-case") {
			t.Errorf("%s: %v, want %q", keys, err, want)
		}
	}
}
