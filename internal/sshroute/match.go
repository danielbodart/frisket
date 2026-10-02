package sshroute

import (
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/intercept"
)

// Decision is what a route's rules say about one command, in the terms the
// rest of frisket asks and logs in: execrule's decision, which is what
// decides, with its outcome and operations as intercept's.
type Decision struct {
	Outcome    intercept.Outcome
	Rule       string
	Operation  *intercept.Operation
	Operations []*intercept.Operation
}

// decision is execrule's decision in intercept's terms.
func decision(d execrule.Decision) Decision {
	out := Decision{Outcome: intercept.Refuse, Rule: d.Rule}
	switch d.Outcome {
	case execrule.Allow:
		out.Outcome = intercept.Admit
	case execrule.Ask:
		out.Outcome = intercept.Ask
	}
	if d.Rule == execrule.RuleUnmatched {
		out.Rule = intercept.RuleUnmatched
	}
	if d.Operation != nil {
		out.Operation = (*intercept.Operation)(d.Operation)
	}
	for _, o := range d.Operations {
		out.Operations = append(out.Operations, (*intercept.Operation)(o))
	}
	return out
}

// operationIDs are the decision's operations as a log line names them: every
// one where there are several, joined by commas, as a GraphQL request's are.
func (d Decision) operationIDs() string {
	if len(d.Operations) > 0 {
		ids := make([]string, len(d.Operations))
		for i, o := range d.Operations {
			ids[i] = o.ID
		}
		return strings.Join(ids, ",")
	}
	if d.Operation != nil {
		return d.Operation.ID
	}
	return ""
}
