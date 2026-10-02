package sshroute

import (
	"testing"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/policy"
)

// A route decides by execrule, and says so in intercept's terms: its
// outcomes, its unmatched, and its operations, every one where there are
// several, joined by commas for the log as a GraphQL request's are.
func TestARouteDecidesByExecruleInInterceptsTerms(t *testing.T) {
	op := func(id string) *policy.Operation { return &policy.Operation{ID: id, Summary: id} }
	r := goodRoute(t)
	r.Unmatched = "refuse"
	r.Env = []string{"LANG"}
	r.Exec = []policy.ExecRule{
		{Command: "ls **", Operation: op("list")},
		{Command: "cd *", Operation: op("cd")},
		{Command: "touch **", Ask: true},
		{Command: "rm **", Refuse: true, Operation: op("remove")},
	}
	routes, err := Compile([]policy.SSHRoute{r}, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		outcome intercept.Outcome
		rule    string
		logged  string
	}{
		{"ls", intercept.Admit, "ls **", "list"},
		{"LANG=C ls", intercept.Admit, "ls **", "list"},
		{"touch x", intercept.Ask, "touch **", ""},
		{"cd / && ls", intercept.Admit, "cd *", "cd,list"},
		{"ls && rm x && cd /", intercept.Refuse, "rm **", "list,remove,cd"},
		{"pwd", intercept.Refuse, intercept.RuleUnmatched, ""},
		{"LD_PRELOAD=x ls", intercept.Refuse, intercept.RuleUnmatched, ""},
	} {
		d := routes[0].Decide(tc.command)
		if d.Outcome != tc.outcome || d.Rule != tc.rule || d.operationIDs() != tc.logged {
			t.Errorf("%q: got %v by %q logged %q, want %v by %q logged %q", tc.command, d.Outcome, d.Rule, d.operationIDs(), tc.outcome, tc.rule, tc.logged)
		}
	}
}
