package intercept

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/internal/graphql"
)

// GraphQLScope is a GraphQL endpoint: one path, at which the body says what
// a request does. A query is decided by Query, and a mutation or subscription
// by the rule for each field at its root. A request is decided by the
// strictest of everything its document holds -- every field of every
// operation -- so no rule is loosened by what else is sent beside it. It
// decides every request at its path, whatever the method, before any path
// rule does; and at a path that may reach the same handler read leniently,
// under it or with an extension -- /graphql/, /GraphQL, /graphql/v4,
// /graphql.json -- which must not reach it as whatever a path rule says.
//
// frisket knows GraphQL, and nothing of an API's schema: the fields and what
// each is come from the configuration, and a field it does not name is
// Unmatched, as a path no rule names is.
//
// What frisket cannot see is not Unmatched's to admit. A request that may run
// something its document does not show -- a body that is not one JSON object
// graphql.Read reads, or one over maxClassifiedBody; a key graphql.Read does
// not know, a persisted query's hash among them; anything but a POST of
// application/json with no query string and no Content-Encoding -- is asked
// about, or refused where Unmatched refuses. Beside what the document does
// show, the strictest decides.
type GraphQLScope struct {
	// Path is the endpoint's, exactly: segments, and "*" alone for any one.
	Path string
	// Query decides a query; nil, and a query is Unmatched.
	Query *GraphQLRule
	// Mutations and Subscriptions decide each field by name.
	Mutations     map[string]GraphQLRule
	Subscriptions map[string]GraphQLRule
	// Unmatched decides a field or a query no rule names: refused, the zero
	// value, asked about, or admitted. What frisket cannot see is asked about
	// where this admits.
	Unmatched Outcome
}

// GraphQLRule decides one kind of GraphQL operation, or one field.
type GraphQLRule struct {
	// Outcome is Refuse, Ask or Admit.
	Outcome   Outcome
	Operation *Operation
}

// maxClassifiedBody bounds the body read to classify a GraphQL request:
// every one is read before it is decided, and none is asked about, so this is
// what a sandbox can make frisket hold per request. A larger body is
// Unmatched; asked about, the rest of it is read then, up to maxAskedBody.
const maxClassifiedBody = 1 << 20

// ReasonUnclassified is a GraphQL request refused because frisket could not
// be certain what it does, and the endpoint refuses what it cannot classify.
const ReasonUnclassified = "GraphQL request not classified"

type compiledGraphQL struct {
	path      compiledPath
	query     *GraphQLRule
	fields    map[string]map[string]GraphQLRule
	unmatched Outcome
}

func compileGraphQL(g GraphQLScope) (compiledGraphQL, error) {
	p, err := compilePath(PathRule{Methods: []string{http.MethodPost}, Path: g.Path})
	if err != nil {
		return compiledGraphQL{}, fmt.Errorf("graphql: %w", err)
	}
	if !validOutcome(g.Unmatched) {
		return compiledGraphQL{}, fmt.Errorf("graphql %s: unmatched %d is not refuse, ask or admit", g.Path, g.Unmatched)
	}
	c := compiledGraphQL{
		path:      p,
		query:     g.Query,
		fields:    map[string]map[string]GraphQLRule{"mutation": g.Mutations, "subscription": g.Subscriptions},
		unmatched: g.Unmatched,
	}
	check := func(what string, r GraphQLRule) error {
		if !validOutcome(r.Outcome) {
			return fmt.Errorf("graphql %s %s: outcome %d is not refuse, ask or admit", g.Path, what, r.Outcome)
		}
		if o := r.Operation; o != nil && (o.ID == "" || o.Summary == "") {
			return fmt.Errorf("graphql %s %s: an operation needs an id and a summary", g.Path, what)
		}
		return nil
	}
	if g.Query != nil {
		if err := check("query", *g.Query); err != nil {
			return compiledGraphQL{}, err
		}
	}
	for kind, rules := range c.fields {
		for field, r := range rules {
			if field == "" {
				return compiledGraphQL{}, fmt.Errorf("graphql %s: a %s with no field", g.Path, kind)
			}
			if err := check(kind+" "+field, r); err != nil {
				return compiledGraphQL{}, err
			}
		}
	}
	return c, nil
}

// near is whether a path, read leniently, may reach the endpoint: its path,
// under it -- /graphql/v4 -- or it with an extension -- /graphql.json -- all
// of which a framework may route to one handler.
func (g *compiledGraphQL) near(segs []string) bool {
	t := g.path.folded
	if len(segs) < len(t) {
		return false
	}
	for i, want := range t {
		seg := segs[i]
		if i == len(t)-1 {
			seg, _, _ = strings.Cut(seg, ".")
		}
		if want == wildcard && seg == "" || want != wildcard && seg != want {
			return false
		}
	}
	return true
}

func validOutcome(o Outcome) bool { return o == Refuse || o == Ask || o == Admit }

// decide reads the request's body and decides it. What is read is what goes
// upstream: the body is replaced with the bytes read, and anything past them.
func (g *compiledGraphQL) decide(r *http.Request) Verdict {
	switch {
	case r.Method != http.MethodPost:
		return g.unclassified("not a POST")
	case r.URL.RawQuery != "":
		// Some servers read query and operationName from the URL too.
		return g.unclassified("a query string")
	case len(r.Header.Values("Content-Encoding")) > 0:
		return g.unclassified("a Content-Encoding")
	case !isJSON(r.Header.Values("Content-Type")):
		return g.unclassified("not application/json")
	}
	body, whole, err := readUpTo(r, maxClassifiedBody)
	if err != nil {
		return Verdict{Outcome: Refuse, Reason: ReasonStoppedWaiting}
	}
	if !whole {
		return g.unclassified(fmt.Sprintf("over %d bytes", maxClassifiedBody))
	}
	req, err := graphql.Read(body)
	if err != nil {
		return g.unclassified(err.Error())
	}
	return g.classify(req)
}

// classify decides a request by the strictest of everything it holds: each
// operation's query rule or fields, and what it may run unseen.
func (g *compiledGraphQL) classify(req graphql.Request) Verdict {
	var (
		decided *Verdict
		ops     []*Operation
		read    []string
		unnamed []string
	)
	consider := func(v Verdict) {
		// The strictest decides; between equals, the first.
		if decided == nil || strictness(v.Outcome) > strictness(decided.Outcome) {
			decided = &v
		}
		if o := v.Operation; o != nil && !slices.Contains(ops, o) {
			ops = append(ops, o)
		}
	}
	for _, op := range req.Operations {
		if op.Type == "query" {
			read = append(read, "query")
			if g.query == nil {
				unnamed = append(unnamed, "query")
				consider(g.unknown())
			} else {
				consider(ruled(*g.query))
			}
			continue
		}
		read = append(read, op.Type+" "+strings.Join(op.Fields, ","))
		for _, f := range op.Fields {
			if rule, ok := g.fields[op.Type][f]; ok {
				consider(ruled(rule))
			} else {
				unnamed = append(unnamed, f)
				consider(g.unknown())
			}
		}
	}
	if req.Unseen != "" {
		read = append(read, "unseen: "+req.Unseen)
		consider(g.unseen())
	}
	if decided == nil {
		return g.unclassified("no field")
	}
	v := *decided
	if len(ops) > 1 {
		v.Operations = ops
	}
	if len(unnamed) > 0 {
		read = append(read, "unnamed "+strings.Join(unnamed, ","))
	}
	v.GraphQL = clip(strings.Join(read, "; "))
	return v
}

// ruled is a rule's verdict.
func ruled(r GraphQLRule) Verdict {
	if r.Outcome == Refuse {
		return Verdict{Outcome: Refuse, Reason: ReasonRefused, Operation: r.Operation}
	}
	return Verdict{Outcome: r.Outcome, Reason: "graphql", Operation: r.Operation}
}

// unknown is the verdict for a query or field no rule names, as an
// unmatched path's is.
func (g *compiledGraphQL) unknown() Verdict {
	switch g.unmatched {
	case Ask:
		return Verdict{Outcome: Ask, Reason: RuleUnmatched}
	case Admit:
		return Verdict{Outcome: Admit, Reason: RuleUnmatched}
	}
	return Verdict{Outcome: Refuse, Reason: ReasonOutOfScope}
}

// unseen is the verdict for what a request may run that frisket cannot see:
// Unmatched's, but never admitted -- an admission there would be of
// whatever the sandbox chose to hide.
func (g *compiledGraphQL) unseen() Verdict {
	if g.unmatched == Refuse {
		return Verdict{Outcome: Refuse, Reason: ReasonUnclassified}
	}
	return Verdict{Outcome: Ask, Reason: RuleUnmatched}
}

// unclassified is the verdict for a request frisket cannot read at all.
func (g *compiledGraphQL) unclassified(why string) Verdict {
	v := g.unseen()
	v.GraphQL = clip("unread: " + why)
	return v
}

// clip bounds what a GraphQL request was read as, which names what the
// request holds, before it goes in the log.
func clip(s string) string {
	const most = 200
	if len(s) > most {
		return s[:most] + "..."
	}
	return s
}

// isJSON is whether a request's Content-Type is application/json, alone or
// with charset=utf-8, and said once.
func isJSON(values []string) bool {
	if len(values) != 1 {
		return false
	}
	t, params, err := mime.ParseMediaType(values[0])
	if err != nil || t != "application/json" {
		return false
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}

// readUpTo reads a request's body up to max bytes, and puts back what it
// read in front of whatever it did not: whole says whether that was all.
func readUpTo(r *http.Request, max int) (body []byte, whole bool, err error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true, nil
	}
	body, err = io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > max {
		r.Body = readCloser{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
		return nil, false, nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return body, true, nil
}

// readCloser reads from one place and closes another.
type readCloser struct {
	io.Reader
	io.Closer
}
