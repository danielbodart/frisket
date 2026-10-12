package intercept

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// Every scope every test in this package builds is built a second time as
// a version 2 document would say it, and every request decided under the
// one is decided under the other: TestMain fails the run if any is decided
// differently. What version 1 says, version 2 says the same way.
//
// The translation is the general one: each path rule is an endpoint
// pattern with its own answer, and each one with an operation is also that
// operation, answered by its class with nothing a pattern would not
// overrule, so that what decides is the most specific pattern, exactly as
// the most specific rule decides in version 1.
func v1AsV2(s Scope) Scope {
	v2 := s
	v2.V2 = true
	v2.Operations = nil
	for _, p := range s.Paths {
		if p.Operation == nil {
			continue
		}
		e := p
		e.Ask, e.Refuse = false, false
		v2.Operations = append(v2.Operations, Endpoint{PathRule: e, Outcome: Admit})
	}
	return v2
}

var twins struct {
	sync.Mutex
	decided int
	differ  []string
}

func TestMain(m *testing.M) {
	twinOf = v1AsV2
	checkTwin = func(method string, u *url.URL, v1, v2 Verdict) {
		twins.Lock()
		defer twins.Unlock()
		twins.decided++
		if d := differs(v1, v2); d != "" {
			twins.differ = append(twins.differ, fmt.Sprintf("%s %s: %s", method, u.EscapedPath(), d))
		}
	}
	code := m.Run()
	if len(twins.differ) > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d requests decided differently under version 2:\n", len(twins.differ), twins.decided)
		for _, d := range twins.differ {
			fmt.Fprintln(os.Stderr, "  "+d)
		}
		code = 1
	} else if code == 0 && testing.Verbose() {
		fmt.Fprintf(os.Stderr, "%d requests decided the same under version 2\n", twins.decided)
	}
	os.Exit(code)
}

// differs says how two verdicts differ in anything a request's handling
// reads, or "".
func differs(a, b Verdict) string {
	id := func(o *Operation) string {
		if o == nil {
			return "-"
		}
		return o.ID
	}
	kind := func(v Verdict) string {
		switch d := v.deferred.(type) {
		case nil:
			return "-"
		case *compiledGraphQL:
			return "graphql " + strings.Join(d.path.segs, "/")
		case *dockerRule:
			return "docker " + id(d.operation)
		}
		return fmt.Sprintf("%T", v.deferred)
	}
	switch {
	case a.Outcome != b.Outcome, a.Reason != b.Reason, a.structural != b.structural, a.unseen != b.unseen, a.status != b.status:
		return fmt.Sprintf("v1 %d %q, v2 %d %q", a.Outcome, a.Reason, b.Outcome, b.Reason)
	case id(a.Operation) != id(b.Operation):
		return fmt.Sprintf("operation v1 %s, v2 %s", id(a.Operation), id(b.Operation))
	case kind(a) != kind(b):
		return fmt.Sprintf("deferred v1 %s, v2 %s", kind(a), kind(b))
	}
	return ""
}

// The twin is held to something: a scope that tells version 2 apart from
// version 1 by its answer, decided both ways, is caught.
func TestTheTwinCatchesADifference(t *testing.T) {
	s := Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}}
	v1, err := compileScope(s)
	if err != nil {
		t.Fatal(err)
	}
	other := s
	other.V2, other.Paths = true, []PathRule{{Methods: []string{"GET"}, Prefix: "/", Refuse: true}}
	v2, err := compileScope(other)
	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{Path: "/x"}
	if d := differs(v1.decided("GET", u), v2.decided("GET", u)); d == "" {
		t.Error("an admission and a refusal were not told apart")
	}
}
