package graphql

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// What gh and wrangler sent, captured off the wire: every one is read, as one
// operation with nothing unseen, and a mutation is named by its field.
func TestWhatRealClientsSendIsRead(t *testing.T) {
	var clients []struct{ Client, Query, Body string }
	load(t, "testdata/clients.json", &clients)
	mutations := map[string]string{
		"PullRequestClose":     "closePullRequest",
		"PullRequestMerge":     "mergePullRequest",
		"IssueCreate":          "createIssue",
		"PullRequestReviewAdd": "addPullRequestReview",
		"CommentCreate":        "addComment",
	}
	seen := 0
	for _, c := range clients {
		r, err := Read([]byte(c.Body))
		if err != nil || len(r.Operations) != 1 || r.Unseen != "" {
			t.Errorf("%s: %+v %v\n%s", c.Client, r, err, c.Body)
			continue
		}
		op := r.Operations[0]
		if field, ok := mutations[op.Name]; ok {
			seen++
			if op.Type != "mutation" || !reflect.DeepEqual(op.Fields, []string{field}) {
				t.Errorf("%s: %+v, want the mutation %s", c.Client, op, field)
			}
		} else if op.Type != "query" {
			t.Errorf("%s: %+v, want a query", c.Client, op)
		}
	}
	if seen != len(mutations) {
		t.Errorf("saw %d of the %d mutations", seen, len(mutations))
	}
}

// graphql-ruby is GitHub's reader. Whatever frisket accepts, it must read the
// same way: the same operations, of the same types, with the same fields at
// their roots. frisket may refuse what graphql-ruby reads -- that asks -- but
// never read a document as something else. scripts/graphql-oracle makes the
// documents, to find where two readers disagree.
func TestGitHubsReaderReadsWhatFrisketAccepts(t *testing.T) {
	var oracle struct {
		Version string `json:"graphql-ruby"`
		Cases   []struct {
			Doc  string
			Ruby []Operation
		}
	}
	load(t, "testdata/ruby.json", &oracle)
	accepted := 0
	for _, c := range oracle.Cases {
		ops, err := Parse(c.Doc)
		if err != nil {
			continue
		}
		accepted++
		if c.Ruby == nil {
			// graphql-ruby refuses it, so it runs nothing: a disagreement,
			// and not a dangerous one. It is a block string holding """.
			if !strings.Contains(c.Doc, `\"""`) {
				t.Errorf("frisket reads %q, which graphql-ruby %s refuses", c.Doc, oracle.Version)
			}
			continue
		}
		for i := range c.Ruby {
			// frisket names each field once.
			var once []string
			for _, f := range c.Ruby[i].Fields {
				if !slices.Contains(once, f) {
					once = append(once, f)
				}
			}
			c.Ruby[i].Fields = once
			if c.Ruby[i].Fields == nil {
				c.Ruby[i].Fields = []string{}
			}
		}
		for i := range ops {
			if ops[i].Fields == nil {
				ops[i].Fields = []string{}
			}
		}
		if !reflect.DeepEqual(ops, c.Ruby) {
			t.Errorf("%q:\n frisket      %+v\n graphql-ruby %+v", c.Doc, ops, c.Ruby)
		}
	}
	if accepted < 1000 {
		t.Errorf("frisket accepted only %d of the documents: the oracle tests little", accepted)
	}
}

// Every way to run a mutation while seeming not to is either named or refused.
func TestAMutationCannotPassAsAQuery(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		want      []Operation // nil: refused
	}{
		{"shorthand", `{viewer{login}}`, []Operation{{"query", "", []string{"viewer"}}}},
		{"an alias is not the field", `mutation { a: closePullRequest(input: {}) { x } }`,
			[]Operation{{"mutation", "", []string{"closePullRequest"}}}},
		{"a spread at the root", `mutation { ...F } fragment F on Mutation { deleteIssue { x } }`,
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"a spread of a spread", `mutation { ...F } fragment F on Mutation { ...G } fragment G on Mutation { deleteIssue }`,
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"an inline fragment", `mutation { ... on Mutation { deleteIssue } }`,
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"an inline fragment with no type", `mutation { ... { deleteIssue } }`,
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"skipped counts as run", `mutation { ...F @include(if: false) } fragment F on Mutation { deleteIssue }`,
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"keywords as fields", `{ mutation query subscription fragment }`,
			[]Operation{{"query", "", []string{"mutation", "query", "subscription", "fragment"}}}},
		{"several fields", `mutation M { a b c }`, []Operation{{"mutation", "M", []string{"a", "b", "c"}}}},
		{"each field once", `mutation { a b: a ...F ... { a } } fragment F on Mutation { a b }`,
			[]Operation{{"mutation", "", []string{"a", "b"}}}},
		{"a fragment spread twice, and its own twice", fanOut(30),
			[]Operation{{"mutation", "", []string{"deleteIssue"}}}},
		{"a subscription", `subscription { s }`, []Operation{{"subscription", "", []string{"s"}}}},
		{"a query and a mutation", `query Q { a } mutation M { b }`,
			[]Operation{{"query", "Q", []string{"a"}}, {"mutation", "M", []string{"b"}}}},

		// A lone CR ends a comment to the spec, and not to graphql-ruby.
		{"CR alone", "query { a }\r# x\rmutation M { b }", nil},
		{"CR alone in a comment", "mutation { # c\rx: on }", nil},
		{"U+2028", "{ a } # x\u2028 mutation { b }", nil},
		{"BOM", "\ufeffmutation { a }", nil},
		{"NBSP", "mutation\u00a0{ a }", nil},
		{"NUL", "{ a }\x00", nil},
		{"an escaped surrogate", `{ a(x: "\ud800") }`, nil},
		{"a draft escape", `{ a(x: "\u{1F600}") }`, nil},
		{"a spread of nothing", `mutation { ...Nope }`, nil},
		{"a spread of itself", `query { ...F } fragment F on Query { ...G } fragment G on Query { ...F }`, nil},
		{"an anonymous operation among others", `{ a } mutation { b }`, nil},
		{"two named alike", `query Q { a } mutation Q { b }`, nil},
		{"a type system definition", `extend type Mutation { a }`, nil},
		{"trailing", `{ a } garbage`, nil},
		{"empty", ``, nil},
		{"an empty selection", `{}`, nil},
		{"too deep", strings.Repeat("{a", MaxDepth+1) + strings.Repeat("}", MaxDepth+1), nil},
		{"too much to follow", "mutation {" + strings.Repeat(" ...F", maxFollowed) + " } fragment F on Mutation { a }", nil},
		{"a block string holding a quote at its end", `{ a(x: """a"""") }`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops, err := Parse(tc.doc)
			switch {
			case tc.want == nil && err == nil:
				t.Fatalf("read as %+v, want refused", ops)
			case tc.want != nil && err != nil:
				t.Fatalf("refused: %v", err)
			case !reflect.DeepEqual(ops, tc.want):
				t.Fatalf("%+v, want %+v", ops, tc.want)
			}
		})
	}
}

// A body is read for every operation its document holds, and says when it may
// run something else; what cannot be read at all is refused.
func TestABodyIsReadForEverythingItShows(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       string // each operation's fields, ";" between; "" for refused
		unseen     bool
	}{
		{"query alone", `{"query":"{a}"}`, "a", false},
		{"variables", `{"query":"mutation($i: I!){b(input: $i){c}}","variables":{"i":{"x":[1,null]}}}`, "b", false},
		{"operationName its own", `{"query":"mutation M {b}","operationName":"M"}`, "b", false},
		{"operationName null", `{"query":"mutation M {b}","operationName":null}`, "b", false},
		{"operationName another", `{"query":"mutation M {b}","operationName":"N"}`, "b", false},
		{"two operations", `{"query":"query Q {a} mutation M {b}","operationName":"Q"}`, "a;b", false},
		{"an escaped key", `{"qu\u0065ry":"{a}"}`, "a", false},
		{"a persisted query", `{"query":"{a}","extensions":{"persistedQuery":{"version":1,"sha256Hash":"00"}}}`, "a", true},
		{"a document id", `{"id":"abc","query":"{a}"}`, "a", true},
		{"another case", `{"Query":"mutation{b}","query":"{a}"}`, "a", true},

		{"operationName a number", `{"query":"{a}","operationName":1}`, "", false},
		{"a batch", `[{"query":"{a}"}]`, "", false},
		{"a key twice", `{"query":"{a}","query":"mutation{b}"}`, "", false},
		{"no query", `{"variables":{}}`, "", false},
		{"query null", `{"query":null}`, "", false},
		{"query a number", `{"query":1}`, "", false},
		{"trailing", `{"query":"{a}"} {"query":"mutation{b}"}`, "", false},
		{"not UTF-8", "{\"query\":\"{a(x: \\\"\xff\\\")}\"}", "", false},
		{"a lone surrogate", `{"query":"{a(x: \"\ud800\")}"}`, "", false},
		{"a surrogate in a key", `{"quer\udc00y":"{a}"}`, "", false},
		{"a BOM", "\ufeff{\"query\":\"{a}\"}", "", false},
		{"not JSON", `query=mutation{b}`, "", false},
		{"a document it will not read", `{"query":"{a}\r# x\rmutation{b}"}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Read([]byte(tc.body))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("read as %+v, want refused", r)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			var got []string
			for _, op := range r.Operations {
				got = append(got, strings.Join(op.Fields, ","))
			}
			if strings.Join(got, ";") != tc.want || (r.Unseen != "") != tc.unseen {
				t.Fatalf("%+v, want %s, unseen %v", r, tc.want, tc.unseen)
			}
		})
	}
}

// Whatever arrives, reading it ends, and says the same thing twice.
func FuzzRead(f *testing.F) {
	var clients []struct{ Body string }
	b, err := os.ReadFile("testdata/clients.json")
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(b, &clients); err != nil {
		f.Fatal(err)
	}
	for _, c := range clients {
		f.Add([]byte(c.Body))
	}
	f.Add([]byte(`{"query":"mutation { ...F } fragment F on Mutation { a }"}`))
	f.Add([]byte(`{"query":` + strconv.Quote(fanOut(8)) + `}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		a, errA := Read(body)
		b, errB := Read(body)
		if (errA == nil) != (errB == nil) || !reflect.DeepEqual(a, b) {
			t.Fatalf("read twice, differently: %+v %v, %+v %v", a, errA, b, errB)
		}
	})
}

// fanOut is a chain of n fragments, each spreading the next twice: 2^n
// fields, each the same one, to anything that follows every spread.
func fanOut(n int) string {
	var b strings.Builder
	b.WriteString("mutation { ...F0 }")
	for i := range n {
		fmt.Fprintf(&b, " fragment F%d on Mutation { ...F%d ...F%d }", i, i+1, i+1)
	}
	fmt.Fprintf(&b, " fragment F%d on Mutation { deleteIssue }", n)
	return b.String()
}

func load(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
