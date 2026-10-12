package policy

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/danielbodart/frisket/projpolicy"
)

// DocumentV2 is a version 2 policy document: the shape every layer of a
// session's policy is written in -- frisket's defaults, a tier, the host's,
// a signed project's -- and merged by RFC 7396 JSON Merge Patch
// (projpolicy.MergePatch), so every collection a layer adds to or takes
// from is an object keyed by what each entry is, which a layer patches key
// by key and deletes from with null. Arrays are replaced whole, and are
// kept for what no layer but the host's sets.
//
// Answers are "allow", "ask" or "refuse", stricter in that order. A
// request is decided at the time it is made, the most specific answer
// first (see RouteV2), and is then clamped to the ceiling: an answer more
// lenient than the ceiling for its class is the ceiling's.
//
// A field tagged scope:"host" is the host's alone, which a project layer
// may never set (`frisket check -layer project`, and `frisket schema`'s
// x-scope). A document read is whole: it has no null anywhere, which only
// a layer has, to delete with.
type DocumentV2 struct {
	// Version is 2.
	Version int    `json:"version"`
	Name    string `json:"name" scope:"host"`
	// Allow is the name allowlist, each key a name or a hostpattern: "**"
	// for every name, "**.example.com" for every name below example.com,
	// "*.example.com" for one label below it, "*-ap.lan" for any run of a
	// label. true allows; false is the same as absent.
	Allow map[string]bool `json:"allow,omitempty"`
	// LAN are the names on the local network a session may reach (see
	// LANHost), each a name or a hostpattern that names it on the
	// allowlist matches.
	LAN map[string]LANHostV2 `json:"lan,omitempty"`
	// Routes are the intercepted hosts, by route name.
	Routes map[string]RouteV2 `json:"routes,omitempty"`
	// SSH are the machines a session may run commands on, by route name. A
	// key that is a hostpattern is no machine: its answers apply to every
	// route whose name it matches, a route's own beating a pattern's and a
	// narrower pattern's a wider one's.
	SSH    map[string]SSHRouteV2 `json:"ssh,omitempty"`
	Record *Record               `json:"record,omitempty" scope:"host"`
	// Answers here are every route's, where the route does not say.
	Answers
	// Ceiling is every route's ceiling, beside each route's own.
	Ceiling *Answers `json:"ceiling,omitempty" scope:"host"`
}

// Answers are what each class of operation is answered with: Writes an
// operation of class "write", Guarded one of class "guarded", and
// Unmatched a request no operation describes, or one whose operation has
// no class, which is answered and clamped as unmatched. An operation of class
// "read" is allowed unless something names it. Each is "allow", "ask" or
// "refuse"; empty is the next layer out's, and at the last the built-in:
// writes ask, guarded refuse, unmatched refuse (an SSH route's ask).
type Answers struct {
	Writes    string `json:"writes,omitempty"`
	Guarded   string `json:"guarded,omitempty"`
	Unmatched string `json:"unmatched,omitempty"`
}

// LANHostV2 is a lan name's ports: empty for every port.
type LANHostV2 struct {
	Ports []int `json:"ports,omitempty"`
}

// RouteV2 is one intercepted host. What it may do is answered at each
// request, the first of these that has an answer deciding:
//
//  1. Operations by the id of the operation the request is -- the most
//     specific of Paths that matches it, or a GraphQL field, or git's push,
//     "git-receive-pack" -- then by "category:<its category>";
//  2. Operations by the most specific endpoint pattern that matches the
//     request, "METHOD[,METHOD] /path": a literal beats a pattern, a *
//     segment one segment, and a trailing /** the rest;
//  3. the route's answer for the operation's class, or Unmatched for a
//     request no operation describes;
//  4. the document's;
//  5. the built-in.
//
// The answer is then clamped to the route's ceiling and the document's
// for the operation's class, or Unmatched's for a request no operation
// describes. A GraphQL endpoint and git decide every request at their
// paths before any endpoint pattern, as in version 1.
type RouteV2 struct {
	Host           string          `json:"host" scope:"host"`
	Upstream       string          `json:"upstream" scope:"host"`
	UpstreamCA     string          `json:"upstreamCA,omitempty" scope:"host"`
	CredentialFile string          `json:"credentialFile,omitempty" scope:"host"`
	CredentialJSON *CredentialJSON `json:"credentialJSON,omitempty" scope:"host"`
	Header         string          `json:"header,omitempty" scope:"host"`
	BasicUser      string          `json:"basicUser,omitempty" scope:"host"`
	Placeholder    string          `json:"placeholder,omitempty" scope:"host"`
	Refusal        *Refusal        `json:"refusal,omitempty" scope:"host"`
	SessionKey     *SessionKey     `json:"sessionKey,omitempty" scope:"host"`
	Docker         *DockerRoute    `json:"docker,omitempty" scope:"host"`
	// Paths are what the route's requests are: by "METHOD[,METHOD] /path",
	// in the endpoint patterns' grammar, the operation each is. Its class
	// says which answer and which ceiling are its own, which is why it is
	// the host's to say.
	Paths map[string]EndpointV2 `json:"paths,omitempty" scope:"host"`
	// EncodedSlashes are path templates, "/storage/v1/b/*/o/*", whose "*"
	// takes a segment holding an encoded slash, wherever an endpoint of
	// Paths or a pattern of Operations is written with one; or such a key
	// itself, "GET /storage/v1/b/*/o/*", for that endpoint or pattern alone.
	EncodedSlashes map[string]bool `json:"encodedSlashes,omitempty" scope:"host"`
	// Git admits git's smart-HTTP protocol for the repositories it names,
	// "owner/name" or "*" for all; a push is the operation
	// "git-receive-pack", of class "write".
	Git *GitV2 `json:"git,omitempty" scope:"host"`
	// GraphQL are the route's GraphQL endpoints, by path.
	GraphQL map[string]GraphQLV2 `json:"graphql,omitempty" scope:"host"`
	// Operations answer requests: by an operation's id, by
	// "category:<name>", or by an endpoint pattern.
	Operations map[string]string `json:"operations,omitempty"`
	Answers
	Ceiling *Answers `json:"ceiling,omitempty" scope:"host"`
}

// EndpointV2 is what an endpoint is: its operation, and, on a Docker
// route, what an admitted request of it is checked for.
type EndpointV2 struct {
	Operation *Operation  `json:"operation"`
	Docker    *DockerRule `json:"docker,omitempty"`
}

// GitV2 is the repositories git may be used with.
type GitV2 struct {
	Repos map[string]bool `json:"repos"`
}

// GraphQLV2 is a GraphQL endpoint: what its query is, and each field at a
// mutation's or subscription's root, by name. A field is answered as any
// operation is, by its operation's id (the field's name where it has
// none), then its category, then its class; a field it does not name, or
// a query where Query is absent, is Unmatched's -- the endpoint's, else
// the route's, else the document's.
type GraphQLV2 struct {
	Query         *GraphQLFieldV2           `json:"query,omitempty"`
	Mutations     map[string]GraphQLFieldV2 `json:"mutations,omitempty"`
	Subscriptions map[string]GraphQLFieldV2 `json:"subscriptions,omitempty"`
	Unmatched     string                    `json:"unmatched,omitempty"`
}

// GraphQLFieldV2 is what a field, or every query, is.
type GraphQLFieldV2 struct {
	Operation *Operation `json:"operation,omitempty"`
}

// SSHRouteV2 is one machine, as SSHRoute is in version 1, but for how its
// commands are answered: Exec by rule, each key an exec rule as execrule
// names one -- a command pattern ("systemctl status *", "uci show **"), or
// one and an argument glob ("less ** [arg +*]"), or a glob alone for every
// command ("[arg .ssh]"). An arg rule only tightens: answered "allow" it
// is no rule. Commands says what a rule is, by the same key: a rule there
// that Exec does not answer is answered by its class.
type SSHRouteV2 struct {
	Address      string   `json:"address,omitempty" scope:"host"`
	User         string   `json:"user,omitempty" scope:"host"`
	HostKeys     []string `json:"hostKeys,omitempty" scope:"host"`
	Agent        string   `json:"agent,omitempty" scope:"host"`
	KeyFile      string   `json:"keyFile,omitempty" scope:"host"`
	PasswordFile string   `json:"passwordFile,omitempty" scope:"host"`
	Identity     string   `json:"identity,omitempty" scope:"host"`
	Shell        bool     `json:"shell,omitempty" scope:"host"`
	// Env are the variables a command may set for itself (SSHRoute.Env).
	Env      map[string]bool      `json:"env,omitempty"`
	Exec     map[string]string    `json:"exec,omitempty"`
	Commands map[string]Operation `json:"commands,omitempty" scope:"host"`
	Answers
	Ceiling *Answers `json:"ceiling,omitempty" scope:"host"`
}

// Version is a document's version: 1, absent or 0 for version 1, which
// chase still writes, and 2.
func Version(b []byte) (int, error) {
	var v struct {
		Version *json.Number `json:"version"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, err
	}
	if v.Version == nil {
		return 1, nil
	}
	n, err := v.Version.Int64()
	switch {
	case err != nil, n != 1 && n != 2:
		return 0, fmt.Errorf("version %s: 1 or 2", v.Version.String())
	}
	return int(n), nil
}

// DecodeV2 reads a whole version 2 document: strictly, as Decode does,
// and refusing a key twice in one object, which a map would otherwise
// take the last of, and a null anywhere, which is a layer's.
func DecodeV2(b []byte) (DocumentV2, error) {
	v, err := projpolicy.Decode(b)
	if err != nil {
		return DocumentV2{}, err
	}
	if at := nullAt(v, ""); at != "" {
		return DocumentV2{}, fmt.Errorf("%s is null: a null deletes in a layer, and a document has none", at)
	}
	var d DocumentV2
	if err := Decode(b, &d); err != nil {
		return DocumentV2{}, err
	}
	if d.Version != 2 {
		return DocumentV2{}, errors.New("not a version 2 document")
	}
	return d, nil
}

// nullAt is where in v a null is, or "".
func nullAt(v any, at string) string {
	switch v := v.(type) {
	case nil:
		if at == "" {
			return "the document"
		}
		return at
	case map[string]any:
		for k, x := range v {
			key := k
			if at != "" {
				key = at + "." + k
			}
			if w := nullAt(x, key); w != "" {
				return w
			}
		}
	case []any:
		for i, x := range v {
			if w := nullAt(x, fmt.Sprintf("%s[%d]", at, i)); w != "" {
				return w
			}
		}
	}
	return ""
}
