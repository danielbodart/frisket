package intercept

import (
	"net/url"
	"slices"
)

// decideV2 decides a request by a version 2 scope's paths, after git and
// GraphQL have had theirs, as decide does a version 1 scope's.
//
// What a request is comes first: the most specific of the route's
// operations that matches it, ranked as path rules are. An operation
// answered by its id or category stands where its own template does: the
// most specific endpoint pattern that matches the request overrules it
// only by being more specific than that template, or as specific and
// stricter. An operation answered by its class is overruled by any
// pattern that matches, however wide. A pattern decides no more leniently
// than the ceiling lets one answer the operation's class, or, matching
// none, an unmatched request; and a request that is no operation and
// matches no pattern is Unmatched's.
//
// As in version 1, what is admitted never depends on how literally the
// upstream reads its paths: an operation or a pattern that matches the
// request as an upstream might read it leniently -- decoded, case-folded,
// a ;parameter or trailing dot dropped, an encoded slash taken either way
// -- and not as it was sent, and that answers more strictly, decides
// instead, the strictest first, unless what decided is more specific. One
// that matches the request as sent has had its say already, by the order
// above, which a lenient reading does not undo.
func (c *compiled) decideV2(method string, segs, raw []string) Verdict {
	strict := func(p *compiledPath) bool { return p.matches(segs, raw) }
	d := c.v2Decide(method, len(segs), strict)
	if !d.matched {
		d = c.v2Fallback(method, segs)
	}
	class := ""
	if d.op != nil && d.op.operation != nil {
		class = d.op.operation.Class
	}
	whole, split := lenient(segs)
	n := max(len(whole), len(split))
	type candidate struct {
		p       *compiledPath
		outcome Outcome
		op      bool
	}
	var stricter []candidate
	for _, rules := range []struct {
		ps []compiledPath
		op bool
	}{{c.ops, true}, {c.paths, false}} {
		for i := range rules.ps {
			p := &rules.ps[i]
			if !slices.Contains(p.methods, method) || strict(p) || !(p.matchesFolded(whole) || p.matchesFolded(split)) {
				continue
			}
			o := p.outcome
			if !rules.op {
				o = c.clamp(o, class)
			}
			if strictness(o) > strictness(d.outcome) && (d.decider == nil || !outranks(d.decider, p, n)) {
				stricter = append(stricter, candidate{p, o, rules.op})
			}
		}
	}
	if len(stricter) > 0 {
		s := slices.MinFunc(stricter, func(a, b candidate) int {
			if x := strictness(b.outcome) - strictness(a.outcome); x != 0 {
				return x
			}
			if a.p.exact != b.p.exact {
				if a.p.exact {
					return -1
				}
				return 1
			}
			return -a.p.specificity(b.p, n)
		})
		l := v2Decision{matched: true, outcome: s.outcome, decider: s.p, op: d.op}
		if s.op {
			l.op = s.p
		}
		d = l
	}
	return d.verdict()
}

// v2Decision is what decided a request, as decideV2 reads it.
type v2Decision struct {
	matched bool
	outcome Outcome
	// decider is the operation or pattern that decided; nil for Unmatched
	// or the GitHub API scope.
	decider *compiledPath
	// op is the operation the request is, nil for none.
	op *compiledPath
	// reason is a verdict's Reason where nothing matched.
	reason string
}

// v2Decide is a request's answer by what match matches, or not matched.
func (c *compiled) v2Decide(method string, n int, match func(*compiledPath) bool) v2Decision {
	op := bestOf(c.ops, method, n, match)
	class := ""
	if op != nil && op.operation != nil {
		class = op.operation.Class
	}
	if p := bestOf(c.paths, method, n, match); p != nil {
		pattern := v2Decision{matched: true, outcome: c.clamp(p.outcome, class), decider: p, op: op}
		if op == nil || !op.named || outranks(p, op, n) {
			return pattern
		}
		// An operation answered by its id or category stands where its own
		// template does: a pattern narrower than that template overrules it,
		// a wider one does not, and between the two equally specific, the
		// stricter decides.
		if !outranks(op, p, n) && strictness(pattern.outcome) > strictness(op.outcome) {
			return pattern
		}
	}
	if op != nil {
		return v2Decision{matched: true, outcome: op.outcome, decider: op, op: op}
	}
	return v2Decision{}
}

// v2Fallback is a request no operation or pattern matched: the GitHub API
// scope's, if it admits it, and otherwise Unmatched's.
func (c *compiled) v2Fallback(method string, segs []string) v2Decision {
	if c.api != nil && slices.Contains(c.api.Methods, method) &&
		len(segs) >= 3 && segs[0] == "repos" && inRepos(c.api.Repos, segs[1], segs[2]) {
		return v2Decision{outcome: Admit, reason: "github-api"}
	}
	switch c.unmatched {
	case UnmatchedAdmit:
		return v2Decision{outcome: Admit, reason: RuleUnmatched}
	case UnmatchedAsk:
		return v2Decision{outcome: Ask, reason: RuleUnmatched}
	}
	return v2Decision{outcome: Refuse, reason: ReasonOutOfScope}
}

// clamp is o, made no more lenient than the ceiling for class.
func (c *compiled) clamp(o Outcome, class string) Outcome {
	if ceil, ok := c.ceiling[class]; ok && strictness(ceil) > strictness(o) {
		return ceil
	}
	return o
}

// bestOf is the most specific rule of rules that matches, exact rules
// first, as best ranks a version 1 scope's.
func bestOf(rules []compiledPath, method string, n int, match func(*compiledPath) bool) *compiledPath {
	for _, exact := range []bool{true, false} {
		var best *compiledPath
		for i := range rules {
			p := &rules[i]
			if p.exact != exact || !slices.Contains(p.methods, method) || !match(p) {
				continue
			}
			if best == nil {
				best = p
				continue
			}
			switch cmp := p.specificity(best, n); {
			case cmp > 0, cmp == 0 && strictness(p.outcome) > strictness(best.outcome):
				best = p
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}

// verdict is the decision as a Verdict: the operation the request is, or
// failing one the pattern's, shown whatever decided.
func (d v2Decision) verdict() Verdict {
	if d.decider == nil {
		switch d.outcome {
		case Admit:
			return Verdict{Outcome: Admit, Reason: d.reason}
		case Ask:
			return Verdict{Outcome: Ask, Reason: RuleUnmatched}
		}
		return Verdict{Outcome: Refuse, Reason: ReasonOutOfScope}
	}
	op := d.decider.operation
	if op == nil && d.op != nil {
		op = d.op.operation
	}
	switch d.outcome {
	case Refuse:
		return Verdict{Outcome: Refuse, Reason: ReasonRefused, Operation: op}
	case Ask:
		return Verdict{Outcome: Ask, Reason: "path", Operation: op}
	}
	if d.op != nil && d.op.docker != nil {
		return d.op.docker.verdict()
	}
	if d.decider.docker != nil {
		return d.decider.docker.verdict()
	}
	return Verdict{Outcome: Admit, Reason: "path", Operation: op}
}

// Answered is what a scope answers one request, before anything is read of
// its body.
type Answered struct {
	Outcome Outcome
	// Reason is which part of the scope decided, or why it refused.
	Reason string
	// Operation is the id of the operation shown, "" for none.
	Operation string
	// Deferred is what still decides, from the body or the daemon: "graphql"
	// or "docker"; "" for nothing.
	Deferred string
}

// Answer is what s answers method and target, a path and query as a
// request line has them, as a route's scope would at the request, but for
// what its body or a Docker daemon still decides: how whoever writes a
// route's answers tests them, by frisket's own reading of a request.
func Answer(s Scope, method, target string) (Answered, error) {
	c, err := compileScope(s)
	if err != nil {
		return Answered{}, err
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return Answered{}, err
	}
	v := c.decide(method, u)
	a := Answered{Outcome: v.Outcome, Reason: v.Reason}
	if v.Operation != nil {
		a.Operation = v.Operation.ID
	}
	switch d := v.deferred.(type) {
	case *compiledGraphQL:
		a.Deferred = "graphql"
	case *dockerRule:
		a.Deferred = "docker"
		if d.operation != nil {
			a.Operation = d.operation.ID
		}
	}
	return a, nil
}

// String is the outcome in the words a document's answers are written in.
func (o Outcome) String() string {
	switch o {
	case Admit:
		return "allow"
	case Ask:
		return "ask"
	}
	return "refuse"
}
