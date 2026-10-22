// Package policy is a frisket policy document as data: the types a document's
// JSON decodes into, and the strict decoder that reads one. It is public so
// that what writes documents -- chase, composing a session's policy at launch
// -- builds them from these same types rather than a copy that could drift,
// and a field frisket does not know is a compile error there instead of a
// document frisket refuses on someone's machine.
//
// What a document means, and whether frisket would serve it, is decided when
// the daemon builds it (frisket check runs the same build without serving).
//
// A document is version 1, Document, which chase still writes, or version
// 2, DocumentV2, with "version": 2: the shape every layer of a policy is
// written in and merged by JSON Merge Patch, every collection a map, whose
// routes answer operations by id, category, endpoint pattern and class at
// each request, under a ceiling. Load reads either; docs/policy.md says
// what version 2 means.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/danielbodart/frisket/project"
	"github.com/danielbodart/quoin/execrule"
)

// Document is a policy as its file holds it: the policy, and a name for the
// log lines and questions of the sessions served under it.
type Document struct {
	// Version is absent, or 1: a version 2 document is a DocumentV2.
	Version int    `json:"version,omitempty"`
	Name    string `json:"name"`
	Policy
}

// Policy is one policy, as data.
type Policy struct {
	// Allow is the name allowlist: exact names, "*.suffix" for every name
	// below suffix, and "*" alone for every name. A name not on it is
	// answered NXDOMAIN without an upstream lookup, and so has no address
	// egress would accept.
	Allow []string `json:"allow"`
	// Routes are the intercepted hosts' credentials and scopes, and a route's
	// host is what makes a name intercepted: it is answered with the session's
	// service address, so its connections reach interception. There is no
	// second list of intercepted names -- one would only repeat the routes'
	// hosts, since a name with no route is a dead end at the handshake and a
	// route for a name not intercepted is never reached. Each host must also
	// be allowed: interception is how an allowed host gets its credential, not
	// a way round the allowlist. A host is a name, or "*.suffix" for every
	// name below it; a name's exact route serves it, and failing that the
	// nearest wildcard above it.
	Routes []Route `json:"routes,omitempty"`
	// SSH are the machines the session may run commands on, each its own
	// list rather than a route: a route is an HTTPS host the session's DNS
	// answers with the service address, and an SSH route is neither -- it is
	// reached at its own address, which no name resolves to.
	SSH []SSHRoute `json:"ssh,omitempty"`
	// LAN are the names on the local network the session may reach, by
	// name alone (see LANHost). Absent, a private, unique-local or
	// link-local address is refused, whatever name gave it.
	LAN []LANHost `json:"lan,omitempty"`
	// Record makes every session served under the document a recording one
	// (see Record). Absent, the policy decides, as it always has.
	Record *Record `json:"record,omitempty"`
}

// Record is a recording session's: chase writes one into the document it
// launches `chase record` with, and never otherwise. Whatever the policy
// would refuse or ask about -- a route's request, an SSH route's command, a
// connection to a name off the allowlist -- is answered by Default instead,
// or put to a person, and written down as one JSON line, so that what the
// session needed can become a grant. What the policy allows is served as
// ever. What no policy decides -- a structural refusal, a credential or
// placeholder that does not hold, a Host that is not the SNI, a method
// override, a command a shell route cannot read, anything on a Docker
// route, a connection to an address nobody resolved -- is refused as in any
// session, and written down as that.
//
//	{"record": {"default": "allow", "sink": "/var/lib/frisket/records/chase-trusted-1.jsonl"}}
type Record struct {
	// Default is "allow", "ask" or "refuse": the answer to every subject,
	// with nobody asked. allow and ask both admit it, and differ only in
	// what is recorded; refuse refuses it. Empty puts each subject to the
	// asker, with `record` set in the question, and its answer -- allow,
	// ask or refuse -- does the same.
	Default string `json:"default,omitempty"`
	// Sink is a file the lines are appended to, as well as the journal,
	// which rate-limits: by its absolute path, directly in the daemon's
	// -record-dir, created 0600 and bounded at 64 MiB. Empty: the journal
	// alone.
	Sink string `json:"sink,omitempty"`
}

// LANHost is a name on the local network -- a NAS, a printer, a device's
// admin page -- that a session may reach at a private (RFC 1918),
// unique-local or link-local address its DNS gives for it. Only by the
// name: a connection is admitted to an address the session's DNS gave for
// Name, at one of Ports, and to nothing else -- a literal IP is refused as
// ever. Never the host's own addresses, a router of the host's, a network
// only the host is on -- a container bridge, a tunnel -- or a metadata
// service: the same exclusions as a recording session's. Name must be on
// the allowlist, and is the name exactly: no wildcard, since a name below
// one is anybody's to give any address.
//
//	{"lan": [{"name": "nas.home.arpa", "ports": [445]}, {"name": "printer.lan"}]}
type LANHost struct {
	// Name is an exact DNS name, lower-case, with no trailing dot.
	Name string `json:"name"`
	// Ports are the TCP ports it may be reached at, 1 to 65535. Empty is
	// every port.
	Ports []int `json:"ports,omitempty"`
}

// SSHRoute is one machine a session may run commands on, by SSH, as User.
// frisket terminates the sandbox's SSH, logs in to Address with the user's
// own key or password, and decides each command the sandbox asks to run: no
// credential ever enters the sandbox, and no shell is opened for it unless
// Interactive admits one. The
// machine's login shell must be of the POSIX family, fish or csh: a command
// is decided by the words those shells read in it, and Windows' cmd.exe
// reads others -- or the route is a Shell route, which reads far less.
type SSHRoute struct {
	// Name is the route's Host alias in the sandbox's ssh_config, and the
	// principal its host certificate names: [a-z0-9][a-z0-9.-]*.
	Name string `json:"name"`
	// Address is a literal IP, v4:port or [v6]:port; the port is 22 when
	// absent. Never a name: what the session reaches is fixed here, not by
	// whatever a resolver says later.
	Address string `json:"address"`
	// User is who the commands run as on the machine.
	User string `json:"user"`
	// HostKeys are the machine's own keys, "ssh-ed25519 AAAA... [comment]",
	// as authorized_keys and known_hosts write them, with no host or marker:
	// the machine must present one of these exactly. They are the whole of
	// the trust in it -- nothing is learnt on first use, and nobody is ever
	// asked about a key.
	HostKeys []string `json:"hostKeys"`
	// Agent is the absolute path of an ssh-agent's socket, KeyFile of an
	// unencrypted private key, and PasswordFile of a file holding a password,
	// for a machine that takes no key: what frisket logs in with. Exactly one.
	// Each is read at login, and never by the sandbox.
	Agent        string `json:"agent,omitempty"`
	KeyFile      string `json:"keyFile,omitempty"`
	PasswordFile string `json:"passwordFile,omitempty"`
	// Identity is a key's "SHA256:..." fingerprint: the one key offered,
	// where an agent holds several and a server counts every one it is
	// offered against its limit. Never with PasswordFile.
	Identity string `json:"identity,omitempty"`
	// Spec is how the route decides a command, in execrule's own type, so
	// that what decides and what a document says are one definition: Shell,
	// for a device whose login shell ignores the command an exec carries --
	// a router's or a modem's CLI -- which frisket opens on a terminal
	// instead, types the command into, and gives back what it printed, with
	// none of the command's stdin sent; Exec, the rules each simple command
	// is decided by, the most literal pattern it matches made stricter by
	// every arg rule that matches it; Env, the variables a command may set
	// for itself and still be decided as the command it runs; and
	// Unmatched, "ask", the default here, unlike a route's, or "refuse", for
	// a simple command no rule matches and every command a shell would read
	// as anything but its words. Its fields are the route's own JSON keys,
	// as they always were.
	execrule.Spec
	// Interactive is "allow", "ask" or "refuse", and "" is refuse: whether
	// the sandbox may open an interactive shell on the machine, which
	// frisket then relays as it is, deciding nothing typed into it. Only a
	// version 2 document says it (Answers.Interactive), lowered with its
	// ceilings applied; version 1 has no word for it.
	Interactive string `json:"-"`
}

// ExecRule decides the simple commands Command matches: admitted, asked
// about, or refused. It is execrule's Rule, the one definition the rules
// are compiled from and a document written with.
type ExecRule = execrule.Rule

// Route is one intercepted host, as data: a bearer token, Basic with a fixed
// user, or a bare header, from a file -- the whole of it, or a field of its
// JSON -- or no credential at all; scoped by method and path prefix, by
// git's smart-HTTP protocol per repository, and by GraphQL operation.
type Route struct {
	Name string `json:"name"`
	// Host is the name the sandbox connects to, or "*.suffix".
	Host string `json:"host"`
	// Upstream is where its requests go: https://host[:port][/base]. For a
	// wildcard route, https://*.suffix[:port]: the name each request was
	// made to. For a Docker route, unix:///path: the daemon's socket.
	Upstream string `json:"upstream"`
	// UpstreamCA is a PEM bundle to verify the upstream with, instead of the
	// host's roots.
	UpstreamCA string `json:"upstreamCA,omitempty"`
	// CredentialFile holds the token, alone, whitespace trimmed -- or, with
	// CredentialJSON, a JSON document that names it. It is read by the
	// daemon, on the host, and re-read when it is replaced. Empty is a route
	// with no credential, which only holds requests to its scope, and then
	// nothing else about a credential may be set.
	CredentialFile string `json:"credentialFile,omitempty"`
	// CredentialJSON reads CredentialFile as JSON: the token and its expiry
	// at dotted paths. Nil is the bare token.
	CredentialJSON *CredentialJSON `json:"credentialJSON,omitempty"`
	// Header is the header the token goes in, bare. Empty means
	// `Authorization: Bearer <token>`.
	Header string `json:"header,omitempty"`
	// BasicUser puts the token in `Authorization: Basic` as the password,
	// under this user: git over HTTPS. Not with Header.
	BasicUser string `json:"basicUser,omitempty"`
	// Placeholder is what the sandbox holds in the credential's place, and
	// the only value frisket replaces: anything else is sent on as it came.
	Placeholder string `json:"placeholder,omitempty"`
	// Paths, Git and GraphQL are the route's scope: a request any of them
	// admits goes upstream, one they ask about goes to the asker, and
	// Unmatched decides the rest.
	Paths   []PathRule    `json:"paths,omitempty"`
	Git     *GitRule      `json:"git,omitempty"`
	GraphQL []GraphQLRule `json:"graphql,omitempty"`
	// Unmatched is "refuse", the default, or "ask".
	Unmatched string `json:"unmatched,omitempty"`
	// Refusal is the API's own error shape, for frisket's refusals. Nil is
	// plain text.
	Refusal *Refusal `json:"refusal,omitempty"`
	// SessionKey is a key made for the session, which its clients sign
	// with: grants it signed are answered with the placeholder, and a bearer
	// JWT it signed is the placeholder.
	SessionKey *SessionKey `json:"sessionKey,omitempty"`
	// Docker makes the route a Docker Engine's, whose upstream is
	// unix:///path/to/docker.sock. Only a session's own document has one:
	// the module's upstream is https alone.
	Docker *DockerRoute `json:"docker,omitempty"`
}

// DockerRoute is a Docker Engine route's project, as the host derived it,
// and what follows from it: the versions, images and ports its requests may
// name, the address and names its ports are reached by, and the tables its
// bodies are judged by.
type DockerRoute struct {
	Project     string      `json:"project"`
	APIVersions APIVersions `json:"apiVersions"`
	Images      []string    `json:"images"`
	// Builds are the repositories, and namespaces ending in '/', of the
	// images the project builds, which a container may run by any tag.
	Builds []string `json:"builds,omitempty"`
	// Address and Names must be frisket's own derivation from Project.
	Address string   `json:"address"`
	Ports   []int    `json:"ports"`
	Names   []string `json:"names"`
	MaxBody int64    `json:"maxBody"`
	// Bodies are the body tables, by operation, in the flat format of
	// internal/dockerapi.
	Bodies map[string]json.RawMessage `json:"bodies,omitempty"`
}

// DockerRoute is the document's Docker route, or nil. build holds a document
// to one.
func (p Policy) DockerRoute() *DockerRoute {
	for _, r := range p.Routes {
		if r.Docker != nil {
			return r.Docker
		}
	}
	return nil
}

// RelayDestinations are what a session's ruleset steers to frisket for its
// Docker project's ports: for each port P, in the route's order,
// 127.0.0.1:P, the project's address at P, and [::1]:P. The address is
// frisket's own derivation from the project, never taken from the document
// alone; build refuses a route whose address is not that anyway. Empty
// without a Docker route.
func (p Policy) RelayDestinations() []netip.AddrPort {
	d := p.DockerRoute()
	if d == nil {
		return nil
	}
	addr := project.Address(d.Project)
	out := make([]netip.AddrPort, 0, 3*len(d.Ports))
	for _, port := range d.Ports {
		if port < 0 || port > 65535 {
			continue // refused by build; never a destination
		}
		pp := uint16(port)
		out = append(out,
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), pp),
			netip.AddrPortFrom(addr, pp),
			netip.AddrPortFrom(netip.IPv6Loopback(), pp),
		)
	}
	return out
}

// SSHDestinations are what a session's ruleset steers to frisket for its SSH
// routes: each route's address and port, in the routes' order. One that is
// not an address at all is left out; whether the rest may be reached is
// build's to decide, and a document it refuses is never served.
func (p Policy) SSHDestinations() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(p.SSH))
	for _, r := range p.SSH {
		if ap, err := r.AddrPort(); err == nil {
			out = append(out, ap)
		}
	}
	return out
}

// AddrPort is the route's Address, read as a literal IP with an optional
// port, 22 when absent. Whether frisket would reach it is build's to decide.
func (r SSHRoute) AddrPort() (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(r.Address); err == nil {
		if ap.Port() == 0 {
			return netip.AddrPort{}, fmt.Errorf("address %q: port 0", r.Address)
		}
		return ap, nil
	}
	a, err := netip.ParseAddr(r.Address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: a literal IP, v4:port or [v6]:port, never a name", r.Address)
	}
	return netip.AddrPortFrom(a, DefaultSSHPort), nil
}

// DefaultSSHPort is an SSH route's port when its address names none.
const DefaultSSHPort = 22

// APIVersions are "1.NN", min to max, and the paths asked with no version.
type APIVersions struct {
	Min         string   `json:"min"`
	Max         string   `json:"max"`
	Unversioned []string `json:"unversioned,omitempty"`
}

// DockerRule is what an admitting rule on a Docker route checks.
type DockerRule struct {
	Owned   string                `json:"owned"`
	Param   int                   `json:"param,omitempty"`
	Query   map[string]QueryCheck `json:"query,omitempty"`
	Body    string                `json:"body,omitempty"`
	Upgrade string                `json:"upgrade,omitempty"`
}

// QueryCheck is a check's name, "bool", or one of {"filters": [...]} and
// {"enum": [...]}.
type QueryCheck struct {
	Check   string
	Filters []string
	Enum    []string
}

func (q *QueryCheck) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err == nil {
		if name == "filters" || name == "enum" {
			return fmt.Errorf("query check %q takes a list: {%q: [...]}", name, name)
		}
		*q = QueryCheck{Check: name}
		return nil
	}
	var obj struct {
		Filters []string `json:"filters"`
		Enum    []string `json:"enum"`
	}
	if err := Decode(b, &obj); err != nil {
		return fmt.Errorf("query check: a name, or {\"filters\": [...]} or {\"enum\": [...]}: %w", err)
	}
	switch {
	case obj.Filters != nil && obj.Enum == nil:
		*q = QueryCheck{Check: "filters", Filters: obj.Filters}
	case obj.Enum != nil && obj.Filters == nil:
		*q = QueryCheck{Check: "enum", Enum: obj.Enum}
	default:
		return errors.New(`query check: {"filters": [...]} or {"enum": [...]}, one of them`)
	}
	return nil
}

func (q QueryCheck) MarshalJSON() ([]byte, error) {
	switch q.Check {
	case "filters":
		return json.Marshal(map[string][]string{"filters": q.Filters})
	case "enum":
		return json.Marshal(map[string][]string{"enum": q.Enum})
	}
	return json.Marshal(q.Check)
}

// SessionKey is the public half of the session's key, the issuer every JWT
// it signs names, and the token URLs, "host/path", answered here.
type SessionKey struct {
	PublicKey string   `json:"publicKey"`
	Issuer    string   `json:"issuer"`
	Grants    []string `json:"grants,omitempty"`
}

// Refusal is a refusal's content type, and a body holding "{{message}}"
// once.
type Refusal struct {
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

// GitRule admits git's smart-HTTP protocol, as GitHub serves it, for some
// repositories or all of them: clone and fetch, and push as it says.
type GitRule struct {
	// Repos are "owner/name", or "*" alone for every repository.
	Repos []string `json:"repos"`
	// Push is "refuse", the default, "ask" or "allow".
	Push string `json:"push,omitempty"`
}

// GraphQLRule is a GraphQL endpoint, decided by what each request's body
// holds: a query by Query, and a mutation or subscription by the rule for
// each field at its root, the strictest of them deciding.
type GraphQLRule struct {
	// Path is the endpoint's, exactly, with "*" segments.
	Path string `json:"path"`
	// Query decides every query. Absent, a query is unmatched.
	Query *GraphQLField `json:"query,omitempty"`
	// Mutations and Subscriptions decide each field they name.
	Mutations     []GraphQLField `json:"mutations,omitempty"`
	Subscriptions []GraphQLField `json:"subscriptions,omitempty"`
	// Unmatched is "refuse", the default, "ask" or "allow": for a query or a
	// field no rule names. What frisket cannot see is asked about where this
	// allows.
	Unmatched string `json:"unmatched,omitempty"`
}

// GraphQLField decides one field at a mutation's or subscription's root, or,
// with no field, every query: admitted, asked about, or refused.
type GraphQLField struct {
	Field     string     `json:"field,omitempty"`
	Ask       bool       `json:"ask,omitempty"`
	Refuse    bool       `json:"refuse,omitempty"`
	Operation *Operation `json:"operation,omitempty"`
}

// CredentialJSON is where a JSON credential file keeps its token, and when
// that token expires: `claudeAiOauth.accessToken` and `claudeAiOauth.expiresAt`
// for Claude Code's. The expiry is what turns a stale token into a 503, which
// the client retries, instead of the upstream's 401, which fails its turn.
type CredentialJSON struct {
	Token string `json:"token"`
	// ExpiresMillis names milliseconds since the epoch. Empty: the file does
	// not say, and the token is never reported expired.
	ExpiresMillis string `json:"expiresMillis,omitempty"`
	// ExpiresJWT names a JWT whose `exp` claim is the expiry -- usually the
	// token itself, which is where codex keeps it. Not with ExpiresMillis.
	ExpiresJWT string `json:"expiresJWT,omitempty"`
}

// PathRule is one scope rule: the methods, at exactly Path or at and under
// Prefix, either of them with "*" and "*:verb" segments; admitted, asked
// about, or refused.
type PathRule struct {
	Methods []string `json:"methods"`
	Prefix  string   `json:"prefix,omitempty"`
	Path    string   `json:"path,omitempty"`
	// EncodedSlashes lets a "*" take a segment holding "%2F".
	EncodedSlashes bool       `json:"encodedSlashes,omitempty"`
	Ask            bool       `json:"ask,omitempty"`
	Refuse         bool       `json:"refuse,omitempty"`
	Operation      *Operation `json:"operation,omitempty"`
	// Docker is what an admitting rule on a Docker route checks.
	Docker *DockerRule `json:"docker,omitempty"`
}

// Operation is what a rule is, in its API's own words: what a person is shown
// when they are asked about a request that matched it. It is execrule's, so
// an SSH rule's and a path rule's are the one type: an id and a summary,
// and a description, a class ("read", "write" or "guarded") and the API's
// own category, shown to the person asked and never matched on.
type Operation = execrule.Operation

// Decode refuses any field it does not know, and anything after the one
// value: a misspelt key in a policy is a rule that silently does not apply.
func Decode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one JSON value")
	}
	return nil
}
