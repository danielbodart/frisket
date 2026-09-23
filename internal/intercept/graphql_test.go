package intercept

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

var (
	graphqlQuery = &Operation{ID: "graphql-query", Summary: "A GraphQL query", Class: "read"}
	closePR      = &Operation{ID: "closePullRequest", Summary: "Close a pull request.", Class: "write", Category: "pulls"}
	addComment   = &Operation{ID: "addComment", Summary: "Adds a comment to an Issue or Pull Request.", Class: "write", Category: "issues"}
	deleteRepo   = &Operation{ID: "deleteRepository", Summary: "Delete a repository.", Class: "guarded", Category: "repos"}
)

// graphqlRoute is GitHub's GraphQL endpoint as chase would describe it, beside
// a rule admitting everything else -- a tier allowing what it has not
// classified -- which must not admit a GraphQL request by another spelling.
func graphqlRoute(up *upstream, t *testing.T, j *journal, unmatched Outcome) Route {
	cred, _ := tokenFile(t, j, realToken)
	r := apiRoute(up, cred)
	r.Scope = Scope{
		Paths: []PathRule{{Methods: []string{"GET", "POST"}, Prefix: "/"}},
		GraphQL: []GraphQLScope{{
			Path:  "/graphql",
			Query: &GraphQLRule{Outcome: Admit, Operation: graphqlQuery},
			Mutations: map[string]GraphQLRule{
				"closePullRequest": {Outcome: Ask, Operation: closePR},
				"addComment":       {Outcome: Ask, Operation: addComment},
				"deleteRepository": {Outcome: Refuse, Operation: deleteRepo},
			},
			Unmatched: unmatched,
		}},
	}
	return r
}

func TestAGraphQLRequestIsDecidedByWhatItHolds(t *testing.T) {
	j := &journal{}
	var got []string
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
	})
	asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, graphqlRoute(up, t, j, Ask))
	c := f.client(t, true)

	big := `{"query":"{a}","variables":{"pad":"` + strings.Repeat("x", maxClassifiedBody) + `"}}`
	for _, tc := range []struct {
		name, method, target, contentType, encoding, body string
		status                                            int
		asked                                             bool
		operation                                         *Operation
		operations                                        []*Operation
	}{
		{name: "a query", body: `{"query":"query Q($o: String!) { repository(owner: $o) { id } }","variables":{"o":"me"}}`,
			status: 200},
		{name: "a mutation", body: `{"query":"mutation M($i: ClosePullRequestInput!){closePullRequest(input: $i){pullRequest{id}}}","variables":{"i":{}}}`,
			status: 200, asked: true, operation: closePR},
		{name: "two mutations", body: `{"query":"mutation { closePullRequest(input: {}) { x } a: addComment(input: {}) { x } }"}`,
			status: 200, asked: true, operation: closePR, operations: []*Operation{closePR, addComment}},
		{name: "the strictest decides", body: `{"query":"mutation { closePullRequest(input: {}) { x } deleteRepository(input: {}) { x } }"}`,
			status: 403},
		{name: "a field nobody named", body: `{"query":"mutation { transferRepository(input: {}) { x } }"}`,
			status: 200, asked: true},
		{name: "a named field and an unnamed one", body: `{"query":"mutation { addComment(input: {}) { x } transferRepository(input: {}) { x } }"}`,
			status: 200, asked: true, operation: addComment},
		{name: "hidden in a fragment", body: `{"query":"mutation { ...F } fragment F on Mutation { deleteRepository(input: {}) { x } }"}`,
			status: 403},
		{name: "a CR alone", body: "{\"query\":\"query { a }\\r# x\\rmutation M { deleteRepository(input: {}) { x } }\"}",
			status: 200, asked: true},
		{name: "a GET", method: "GET", target: "/graphql?query=%7Ba%7D", status: 200, asked: true},
		{name: "a query string", target: "/graphql?query=mutation%7Bb%7D", body: `{"query":"{a}"}`, status: 200, asked: true},
		{name: "not JSON", contentType: "application/graphql", body: `{a}`, status: 200, asked: true},
		{name: "compressed", encoding: "gzip", body: `{"query":"{a}"}`, status: 200, asked: true},
		{name: "a batch", body: `[{"query":"{a}"}]`, status: 200, asked: true},
		{name: "a persisted query", body: `{"query":"{a}","extensions":{"persistedQuery":{"sha256Hash":"00"}}}`, status: 200, asked: true},
		// Paths that may reach the same handler are the endpoint's, whatever
		// a path rule says of them.
		{name: "a trailing slash", target: "/graphql/", body: `{"query":"mutation { deleteRepository(input: {}) { x } }"}`,
			status: 403},
		{name: "another case", target: "/GraphQL", body: `{"query":"mutation { closePullRequest(input: {}) { x } }"}`,
			status: 200, asked: true, operation: closePR},
		{name: "under the endpoint", target: "/graphql/v4", body: `{"query":"mutation { deleteRepository(input: {}) { x } }"}`,
			status: 403},
		{name: "with an extension", target: "/graphql.json", body: `{"query":"mutation { deleteRepository(input: {}) { x } }"}`,
			status: 403},
		{name: "a query and a mutation", body: `{"query":"query Q { a } mutation M { closePullRequest(input: {}) { x } }","operationName":"Q"}`,
			status: 200, asked: true, operation: closePR, operations: []*Operation{graphqlQuery, closePR}},
		{name: "over the size classified", body: big, status: 200, asked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asker.questions, got = nil, nil
			method, target, ct := tc.method, tc.target, tc.contentType
			if method == "" {
				method = "POST"
			}
			if target == "" {
				target = "/graphql"
			}
			if ct == "" && method == "POST" {
				ct = "application/json; charset=utf-8"
			}
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newRequest(t, method, "https://"+apiHost+target, body)
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			res, _ := get(t, c, req)
			if res.StatusCode != tc.status {
				t.Fatalf("%d, want %d", res.StatusCode, tc.status)
			}
			if asked := len(asker.questions) == 1; asked != tc.asked || len(asker.questions) > 1 {
				t.Fatalf("asked %d questions, want asked %v", len(asker.questions), tc.asked)
			}
			if tc.asked {
				q := asker.questions[0]
				if q.Operation != tc.operation || !sameOperations(q.Operations, tc.operations) {
					t.Errorf("asked about %+v and %+v, want %+v and %+v", q.Operation, q.Operations, tc.operation, tc.operations)
				}
			}
			if tc.status == 200 && (len(got) != 1 || got[0] != tc.body) {
				t.Errorf("upstream got a body other than the one sent")
			}
		})
	}
}

func sameOperations(a, b []*Operation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// An endpoint that refuses what it cannot classify refuses it, and says so;
// and the log says what each request was read as.
func TestAGraphQLRequestNotClassifiedIsRefusedWhereUnmatchedIs(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	f := newFixtureAsking(t, j, slog.LevelInfo, nil, graphqlRoute(up, t, j, Refuse))
	c := f.client(t, true)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"query":"{a}"}`, 200},
		{`{"query":"mutation { transferRepository(input: {}) { x } }"}`, 403},
		{`[{"query":"{a}"}]`, 403},
	} {
		req := newRequest(t, "POST", "https://"+apiHost+"/graphql", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		if res, _ := get(t, c, req); res.StatusCode != tc.status {
			t.Errorf("%s: %d, want %d", tc.body, res.StatusCode, tc.status)
		}
	}
	lines := j.waitLines(t, "request", 3)
	for i, want := range []struct{ reason, graphql string }{
		{"", "query"},
		{ReasonOutOfScope, "mutation transferRepository; unnamed transferRepository"},
		{ReasonUnclassified, "unread: not a JSON object"},
	} {
		if lines[i]["graphql"] != want.graphql || (want.reason != "" && lines[i]["reason"] != want.reason) {
			t.Errorf("line %d: %v, want reason %q and graphql %q", i, lines[i], want.reason, want.graphql)
		}
	}
}

// Where what no rule names is allowed, a rule that refuses or asks still
// decides whatever the document shows, however it is sent -- and what the
// document does not show is asked about, never admitted: an admission there
// would be of whatever the sandbox chose to hide.
func TestNothingAllowedAsUnmatchedLoosensARule(t *testing.T) {
	j := &journal{}
	up := newUpstream(t, nil)
	asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, graphqlRoute(up, t, j, Admit))
	c := f.client(t, true)
	deleteRepo := `mutation { deleteRepository(input: {}) { clientMutationId } }`
	for _, tc := range []struct {
		name, body string
		status     int
		asked      bool
	}{
		{"a refused field beside a key frisket does not know", `{"query":"` + deleteRepo + `","extensions":{}}`, 403, false},
		{"a refused field in another operation", `{"query":"query Q { a } ` + deleteRepo[:8] + ` M ` + deleteRepo[9:] + `","operationName":"Q"}`, 403, false},
		{"a refused field beside a field nobody named", `{"query":"mutation { transferRepository(input: {}) { x } deleteRepository(input: {}) { x } }"}`, 403, false},
		{"an asked field beside a key frisket does not know", `{"query":"mutation { closePullRequest(input: {}) { x } }","id":"x"}`, 200, true},
		{"a field nobody named", `{"query":"mutation { transferRepository(input: {}) { x } }"}`, 200, false},
		{"two queries", `{"query":"query A { a } query B { b }","operationName":"A"}`, 200, false},
		{"a query, and a persisted one", `{"query":"{a}","extensions":{"persistedQuery":{"sha256Hash":"00"}}}`, 200, true},
		{"a body frisket will not read", `{"query":"{ a }\r# x\r` + deleteRepo + `"}`, 200, true},
		{"a body over what is read", `{"query":"` + deleteRepo + `","variables":{"pad":"` + strings.Repeat("x", maxClassifiedBody) + `"}}`, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asker.questions = nil
			req := newRequest(t, "POST", "https://"+apiHost+"/graphql", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			res, _ := get(t, c, req)
			if res.StatusCode != tc.status || (len(asker.questions) == 1) != tc.asked {
				t.Fatalf("%d, asked %d times; want %d, asked %v", res.StatusCode, len(asker.questions), tc.status, tc.asked)
			}
		})
	}
}
