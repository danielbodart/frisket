package graphql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Request is what a GraphQL-over-HTTP JSON body holds.
type Request struct {
	// Operations are every operation in the document. The server runs one of
	// them at most -- the one operationName names, or the only one -- so a
	// request is as strict as the strictest of them.
	Operations []Operation
	// Unseen, if not empty, is why the body may run something its document
	// does not show: a key frisket does not know. Some are somebody else's
	// protocol, and decide what runs -- `extensions.persistedQuery` beside an
	// innocent `query` runs whatever the server stored under its hash -- and a
	// key in another case may be `query` to the server: Go's decoder would
	// match "Query" to it, and the upstream's might not.
	Unseen string
}

// Read reads a GraphQL-over-HTTP JSON body: one object holding `query`, a
// string, and perhaps `operationName`, a string or null, and `variables`,
// which cannot change what an operation is. Any other key is Unseen. What it
// cannot read at all is an error: a body that is not one such object -- a
// batch is an array -- a key twice, or a document Parse refuses.
func Read(body []byte) (Request, error) {
	if !utf8.Valid(body) {
		return Request{}, errors.New("not UTF-8")
	}
	if escapedSurrogate(body) {
		// Go decodes a lone one to U+FFFD, which another decoder may not.
		return Request{}, errors.New("an escaped surrogate")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return Request{}, errors.New("not a JSON object")
	}
	var (
		query  *string
		unseen string
		seen   = map[string]bool{}
	)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return Request{}, fmt.Errorf("not JSON: %w", err)
		}
		key, _ := t.(string)
		if seen[key] {
			return Request{}, fmt.Errorf("%q twice", key)
		}
		seen[key] = true
		switch key {
		case "query":
			var s string
			if err := dec.Decode(&s); err != nil {
				return Request{}, errors.New("query is not a string")
			}
			query = &s
		case "operationName":
			// null is as good as absent. A name no operation has runs
			// nothing.
			var name *string
			if err := dec.Decode(&name); err != nil {
				return Request{}, errors.New("operationName is not a string")
			}
		default:
			if key != "variables" && unseen == "" {
				unseen = fmt.Sprintf("key %q", key)
			}
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return Request{}, fmt.Errorf("not JSON: %w", err)
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return Request{}, fmt.Errorf("not JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Request{}, errors.New("more after the object")
	}
	if query == nil {
		return Request{}, errors.New("no query")
	}
	ops, err := Parse(*query)
	if err != nil {
		return Request{}, err
	}
	return Request{Operations: ops, Unseen: unseen}, nil
}

// escapedSurrogate is whether a JSON text holds \uD800 to \uDFFF anywhere. A
// backslash is only ever inside a string in valid JSON, so the text is walked
// escape by escape without parsing it.
func escapedSurrogate(b []byte) bool {
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if b[i+1] == 'u' && i+5 < len(b) && (b[i+2]|0x20) == 'd' && hexVal(b[i+3]) >= 8 {
			return true
		}
		i++
	}
	return false
}
