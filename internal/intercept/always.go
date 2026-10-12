package intercept

import (
	"net/http"
	"net/url"
	"strings"
)

// Always is one session's "Always": the rules a person has answered Always
// in it, which admit what they name for the rest of the session, and the
// offer of Always on a question, which writes the rule into the project
// file the session was launched from.
type Always interface {
	// Admits is whether rule was answered Always in this session.
	Admits(rule AlwaysRule) bool
	// Offer sets q's Diff and Always where rule may be written into the
	// session's project file, and would admit what it names there; save,
	// when it is offered, is what an answer of always does: the rule
	// admits at once, in this session, and is signed into the file.
	Offer(q *Question, rule AlwaysRule) (save func())
}

// AlwaysRule is what Always answers: the specific rule a question is
// about, never a pattern.
type AlwaysRule struct {
	// Route is the route's or SSH machine's name.
	Route string
	// SSH is a command on an SSH route; otherwise an HTTP request.
	SSH bool
	// Key is the rule's key: an HTTP request's operation id, or failing
	// one its "METHOD /path", exactly as sent; an SSH command's words.
	Key string
	// Command is the SSH command, as sent, to be decided again.
	Command string
	// Decides is the request decided again by a scope, for an HTTP rule:
	// what a scope with the rule in it would answer the same request.
	Decides func(Scope) (Outcome, error)
}

// Diff is a change to a file, as a question shows it: Old empty for a file
// that is new.
type Diff struct {
	Path string `json:"path"`
	Old  string `json:"old"`
	New  string `json:"new"`
}

// RuleAlways is the rule of a request a rule answered Always admitted.
const RuleAlways = "always"

// KindNotice is a Question's Kind for something said rather than asked:
// Text is all of it, and its answer is no one's.
const KindNotice = "notice"

// alwaysRule is the rule an Always would write for a request the scope
// asked about: its operation's id, else its method and exact path; none
// for a Docker route, whose requests the Engine's rules decide too, or a
// request holding several operations, which one rule would not admit.
func alwaysRule(rt *route, r *http.Request, decided *url.URL, v Verdict) (AlwaysRule, bool) {
	if rt.docker != nil || len(v.Operations) > 1 {
		return AlwaysRule{}, false
	}
	key := r.Method + " " + decided.EscapedPath()
	if v.Operation != nil && v.Operation.ID != "" {
		key = v.Operation.ID
	} else if strings.ContainsAny(decided.EscapedPath(), "*") {
		// A literal path with a * in it would be read as a pattern.
		return AlwaysRule{}, false
	}
	method, target := r.Method, decided.RequestURI()
	return AlwaysRule{
		Route: rt.Name,
		Key:   key,
		Decides: func(s Scope) (Outcome, error) {
			c, err := compileScope(s)
			if err != nil {
				return Refuse, err
			}
			u, err := url.ParseRequestURI(target)
			if err != nil {
				return Refuse, err
			}
			v := c.decide(method, u)
			if v.deferred != nil {
				// The body, which the question's preview has already held,
				// read again by the same reading.
				v = v.deferred.decide(r)
			}
			return v.Outcome, nil
		},
	}, true
}
