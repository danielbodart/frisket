package intercept

import (
	"context"
	"net/http"
	"strings"

	recording "github.com/danielbodart/frisket/internal/record"
)

// recordable is whether a recording session decides what the scope said of
// a request in place of the scope: whatever a rule or Unmatched decided --
// a rule's refusal or question, a push, a GraphQL field or what could not be
// seen of one -- but not a path that is not canonical, a git request git
// would never send, nor a body that never came, which no grant could
// change, and nothing at all on a Docker route, whose refusals keep a
// session to its own project and are never a person's to wave through.
func recordable(rt *route, v Verdict) bool {
	if rt.docker != nil || v.structural {
		return false
	}
	switch v.Outcome {
	case Ask:
		return true
	case Refuse:
		switch v.Reason {
		case ReasonOutOfScope, ReasonRefused, ReasonPush, ReasonUnclassified:
			return true
		}
	}
	return false
}

// record decides a request the scope refused or asked about, in a recording
// session, and returns why it is refused, or "" if it is admitted.
func (i *Interceptor) record(r *http.Request, ic *interceptedConn, v Verdict) string {
	key := httpKey(ic.route.Name, r.Method, r.URL.EscapedPath(), v)
	decide := i.recorder.Decide
	if v.unseen {
		// Its key is the path and why it could not be read, which is not
		// what it would run: each is put to the person on its own.
		decide = i.recorder.DecideEach
	}
	res := decide(r.Context(), httpLine(ic, r, v), key, func(ctx context.Context) (recording.Answer, string, error) {
		// The request's own context, which Decide's is: the question goes
		// when the client does.
		a, reason := RecordAnswer(i.askPerson(r, ic, v, true))
		return a, reason, nil
	})
	switch {
	case res.Answer.Admits():
		return ""
	case res.Reason != "":
		return res.Reason
	}
	return ReasonRecordRefused
}

// hard is whether a refusal no recording overrides is one to write down as
// hard: not one for want of something that may be there the next time -- a
// body the client stopped sending, a daemon that could not be asked whose
// an object is, an object that does not exist -- which says nothing of what
// a grant could or could not change.
func hard(reason string) bool {
	switch reason {
	case ReasonStoppedWaiting, ReasonLookup, ReasonAbsent:
		return false
	}
	return true
}

// RecordAnswer is an Asker's answer as a recording takes it: a person's
// refusal is an answer, to be remembered and written down as one, and only
// the want of an answer -- the asker failing, nobody there, the client gone
// -- leaves a reason.
func RecordAnswer(a recording.Answer, reason string) (recording.Answer, string) {
	if reason == ReasonDeclined {
		return recording.Refuse, ""
	}
	return a, reason
}

// httpKey names a request's subject within its session: the operation it
// matched, where a rule matched it, so that a person answering for one
// operation is not asked again for each object it names; otherwise its exact
// path. A GraphQL request's is what it was read as, beside either.
func httpKey(route, method, path string, v Verdict) string {
	what := "path " + path
	if ids := operationIDs(v); ids != "" && v.Reason != RuleUnmatched && v.Reason != ReasonOutOfScope {
		what = "operation " + ids
	}
	return route + "\x00" + method + "\x00" + what + "\x00" + v.GraphQL
}

// operationIDs are a verdict's operations' ids, comma-joined, as a log line
// names them.
func operationIDs(v Verdict) string {
	if len(v.Operations) > 0 {
		ids := make([]string, len(v.Operations))
		for i, o := range v.Operations {
			ids[i] = o.ID
		}
		return strings.Join(ids, ",")
	}
	if v.Operation != nil {
		return v.Operation.ID
	}
	return ""
}

// httpLine is a request's record line, before it is answered.
func httpLine(ic *interceptedConn, r *http.Request, v Verdict) recording.Line {
	would := recording.Refuse
	if v.Outcome == Ask {
		would = recording.Ask
	}
	return recording.Line{
		Session:   ic.session,
		Kind:      recording.KindHTTP,
		Route:     ic.route.Name,
		Method:    r.Method,
		Host:      ic.sni,
		Path:      r.URL.EscapedPath(),
		Operation: operationIDs(v),
		GraphQL:   v.GraphQL,
		Would:     string(would),
		Rule:      v.Reason,
	}
}
