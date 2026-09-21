// Package policy turns the daemon's configuration -- policies as data, written
// by the NixOS module -- into the handlers each session is served with: the
// real egress, DNS and interception, wired together.
//
// A policy is a document at a path, which a session names: the names a
// session may resolve, the names among them that are intercepted, and the
// routes that say what an intercepted name's requests may do and which
// credential they carry. Every session gets its own DNS server and its own
// resolved set -- an answer given to one sandbox is not a permission for
// another -- and its own CA, constrained to the policy's route hosts. Sessions
// whose documents are the same, byte for byte, share one interceptor and its
// credential watchers, and the last of them to end closes them.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/credential"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/serve"
	"golang.org/x/sys/unix"
)

// Config is the daemon's configuration file. Policies are not in it: each is
// a document of its own, which a session names by its path.
type Config struct {
	// DNS is where frisket resolves the names a session is allowed. Empty
	// means whatever the host's /etc/resolv.conf names, followed as it changes.
	DNS []string `json:"dns,omitempty"`
}

// Document is a policy as its file holds it: the policy, and a name for the
// log lines and questions of the sessions served under it.
type Document struct {
	Name string `json:"name"`
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
	// a way round the allowlist. Exact names only: a route serves one host.
	Routes []Route `json:"routes,omitempty"`
}

// Route is one intercepted host, as data: a bearer token, Basic with a fixed
// user, or a bare header, from a file -- the whole of it, or a field of its
// JSON -- or no credential at all; scoped by method and path prefix, and by
// git's smart-HTTP protocol per repository.
type Route struct {
	Name string `json:"name"`
	// Host is the name the sandbox connects to.
	Host string `json:"host"`
	// Upstream is where its requests go: https://host[:port][/base].
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
	// Paths and Git are the route's scope: a request either admits goes
	// upstream, one a path rule asks about goes to the asker, and Unmatched
	// decides the rest.
	Paths []PathRule `json:"paths,omitempty"`
	Git   *GitRule   `json:"git,omitempty"`
	// Unmatched is "refuse", the default, or "ask".
	Unmatched string `json:"unmatched,omitempty"`
	// Refusal is the API's own error shape, for frisket's refusals. Nil is
	// plain text.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Refusal is a refusal's content type, and a body holding "{{message}}"
// once.
type Refusal struct {
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

// GitRule admits git's smart-HTTP protocol, as GitHub serves it, for some
// repositories or all of them: clone and fetch, and push only if it says so.
type GitRule struct {
	// Repos are "owner/name", or "*" alone for every repository.
	Repos []string `json:"repos"`
	Push  bool     `json:"push,omitempty"`
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
// Prefix, either of them with "*" segments; admitted, asked about, or
// refused.
type PathRule struct {
	Methods   []string   `json:"methods"`
	Prefix    string     `json:"prefix,omitempty"`
	Path      string     `json:"path,omitempty"`
	Ask       bool       `json:"ask,omitempty"`
	Refuse    bool       `json:"refuse,omitempty"`
	Operation *Operation `json:"operation,omitempty"`
}

// Operation is what a rule is, in its API's own words: what a person is shown
// when they are asked about a request that matched it.
type Operation struct {
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
}

// Load reads the daemon's configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decode(b, &c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// decode refuses any field it does not know, and anything after the one
// value: a misspelt key in a policy is a rule that silently does not apply.
func decode(b []byte, v any) error {
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

// interceptHosts is a policy's intercepted names -- its routes' hosts -- each
// an exact name.
func interceptHosts(p Policy) ([]string, error) {
	hosts := make([]string, 0, len(p.Routes))
	for _, r := range p.Routes {
		pat, err := dns.ParsePattern(r.Host)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Name, err)
		}
		// One name per route, so a wildcard could never be served: every name
		// it matched would resolve to the service address and fail at the
		// handshake.
		if pat.Any || pat.Wildcard {
			return nil, fmt.Errorf("route %s: %s is a wildcard, and a route is for one host", r.Name, pat)
		}
		hosts = append(hosts, pat.Name)
	}
	return hosts, nil
}

// Deps is what every policy shares: the one classifier and dialer every
// upstream connection goes through.
type Deps struct {
	Classifier *egress.Classifier
	Dialer     *egress.Dialer
	// Upstream answers the names sessions are allowed. Nil builds one from
	// Config.DNS, or follows the host's resolv.conf when that is empty.
	Upstream dns.Exchanger
	// Log is the daemon's; credential watchers and interceptors write to it.
	Log *slog.Logger
	// Asker decides what a route asks about, for every policy. Nil refuses
	// it.
	Asker intercept.Asker

	// Roots are the directories a policy document may be read from. Empty:
	// anywhere, which only a check or a test should want.
	Roots []string

	// checking builds a document without watching its credential files.
	checking bool
}

// unchecked is the credential of a route built only to be checked.
type unchecked struct{}

func (unchecked) Get() (credential.Secret, error) {
	return credential.Secret{}, errors.New("a policy being checked has no credentials")
}

// maxDocument bounds a policy document. Cloudflare's, every operation of
// its API with its description, is about a megabyte.
const maxDocument = 64 << 20

// Store opens policies from their documents for serve.Daemon, building each
// once for however many sessions are served under it.
type Store struct {
	deps    Deps
	up      dns.Exchanger
	closeUp func() error

	mu    sync.Mutex
	built map[[sha256.Size]byte]*built
}

type built struct {
	policy  serve.Policy
	closers []func() error
	refs    int
}

var _ serve.Policies = (*Store)(nil)

// NewStore makes the store every session's policy is opened from, resolving
// allowed names where c says.
func NewStore(c *Config, d Deps) (*Store, error) {
	if d.Classifier == nil || d.Dialer == nil || d.Log == nil {
		return nil, errors.New("policy: a classifier, a dialer and a logger are all required")
	}
	s := &Store{deps: d, up: d.Upstream, closeUp: func() error { return nil }, built: map[[sha256.Size]byte]*built{}}
	if s.up == nil {
		up, closeUp, err := upstream(c.DNS, d.Log)
		if err != nil {
			return nil, err
		}
		s.up, s.closeUp = up, closeUp
	}
	return s, nil
}

// Open reads the document at path and returns its policy, built now or shared
// with the sessions already served under the same bytes. A document that does
// not read, or does not hold together, is refused: the session it was for
// never gets rules.
func (s *Store) Open(path string) (serve.Policy, func(), error) {
	if !underRoots(path, s.deps.Roots) {
		return nil, nil, fmt.Errorf("policy %s: not under %s", path, strings.Join(s.deps.Roots, " or "))
	}
	b, err := readDocument(path)
	if err != nil {
		return nil, nil, err
	}
	key := sha256.Sum256(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.built == nil {
		return nil, nil, errors.New("policy: the store is closed")
	}
	e := s.built[key]
	if e == nil {
		var doc Document
		if err := decode(b, &doc); err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", path, err)
		}
		p, closers, err := build(doc.Name, doc.Policy, s.deps, s.up)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", path, err)
		}
		e = &built{policy: p, closers: closers}
		s.built[key] = e
	}
	e.refs++
	var once sync.Once
	return e.policy, func() { once.Do(func() { s.release(key, e) }) }, nil
}

func (s *Store) release(key [sha256.Size]byte, e *built) {
	s.mu.Lock()
	e.refs--
	last := e.refs == 0 && s.built != nil && s.built[key] == e
	if last {
		delete(s.built, key)
	}
	s.mu.Unlock()
	if last {
		if err := closeAll(e.closers); err != nil {
			s.deps.Log.Warn("policy closed", "error", err.Error())
		}
	}
}

// Close stops every policy still built and the upstream DNS follower.
func (s *Store) Close() error {
	s.mu.Lock()
	all := s.built
	s.built = nil
	s.mu.Unlock()
	var errs []error
	for _, e := range all {
		errs = append(errs, closeAll(e.closers))
	}
	errs = append(errs, s.closeUp())
	return errors.Join(errs...)
}

// Check reads and builds a document and closes it again: the whole of what a
// session opening it would be refused for, said before one does.
func Check(path string, d Deps) error {
	d.checking = true
	s, err := NewStore(&Config{}, d)
	if err != nil {
		return err
	}
	defer s.Close()
	_, release, err := s.Open(path)
	if err != nil {
		return err
	}
	release()
	return nil
}

// underRoots is whether path is inside one of roots, or roots is empty.
func underRoots(path string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	for _, r := range roots {
		if strings.HasPrefix(path, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

// readDocument reads a policy document, bounded: a regular file, owned by
// root or by the daemon's own user, that nobody else can write. A document
// says which credential goes to which host, so one that another user could
// have written is not one to act on. The last component is not followed if
// it is a link, and a FIFO does not block the open.
func readDocument(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("policy %s: not a regular file", path)
	case st.Uid != 0 && int(st.Uid) != os.Getuid():
		return nil, fmt.Errorf("policy %s: owned by uid %d, neither root nor this daemon's", path, st.Uid)
	case st.Mode&0o022 != 0:
		return nil, fmt.Errorf("policy %s: writable by others", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDocument+1))
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if len(b) > maxDocument {
		return nil, fmt.Errorf("policy %s: larger than %d bytes", path, maxDocument)
	}
	return b, nil
}

func closeAll(closers []func() error) error {
	var errs []error
	for i := len(closers) - 1; i >= 0; i-- {
		errs = append(errs, closers[i]())
	}
	return errors.Join(errs...)
}

// build builds one policy and everything behind it, returning what closes
// it. Nothing is left running if it fails.
func build(name string, p Policy, d Deps, up dns.Exchanger) (_ serve.Policy, closers []func() error, err error) {
	defer func() {
		if err != nil {
			_ = closeAll(closers)
			closers = nil
		}
	}()
	if err := control.ValidName(name); err != nil {
		return nil, nil, fmt.Errorf("policy %w", err)
	}
	allow, err := dns.NewMatcher(p.Allow...)
	if err != nil {
		return nil, closers, fmt.Errorf("allow: %w", err)
	}
	hosts, err := interceptHosts(p)
	if err != nil {
		return nil, closers, err
	}
	icpt, err := dns.NewMatcher(hosts...)
	if err != nil {
		return nil, closers, fmt.Errorf("intercept: %w", err)
	}
	for _, h := range hosts {
		if !allow.Match(h) {
			return nil, closers, fmt.Errorf("route for %s: not on the allowlist; interception is how an allowed host gets its credential, not a way round the allowlist", h)
		}
	}

	routes := make([]intercept.Route, 0, len(p.Routes))
	for _, r := range p.Routes {
		ir, closer, err := route(r, d)
		if err != nil {
			return nil, closers, fmt.Errorf("route %s: %w", r.Name, err)
		}
		closers = append(closers, closer)
		routes = append(routes, ir)
	}

	ic, err := intercept.New(intercept.Config{
		Routes: routes,
		Log:    d.Log,
		Policy: name,
		Asker:  d.Asker,
		// The upstream is dialled through the same structural check as every
		// other connection frisket makes: a route pointed at the host's own
		// address, or at the metadata service, is refused at the dial.
		DialContext: d.Dialer.DialContext,
	})
	if err != nil {
		return nil, closers, err
	}
	closers = append(closers, ic.Close)

	return serve.PolicyFunc(func(s control.Session, authority []byte, log *slog.Logger) (serve.Handlers, error) {
		ca, authority, err := sessionCA(hosts, authority)
		if err != nil {
			return serve.Handlers{}, err
		}
		// Restored, under a policy that has gained a route since: the
		// sandbox trusts a CA that cannot vouch for the new host, so its
		// handshakes are refused, and said so, until it is relaunched.
		for _, h := range hosts {
			if !ca.Permits(h) {
				log.Warn("session CA does not cover a route's host: relaunch the session to intercept it",
					"session", s.Name, "policy", name, "host", h)
			}
		}
		resolved := egress.NewResolved(egress.ResolvedConfig{})
		srv, err := dns.New(dns.Config{
			Session:   s.Name,
			Policy:    name,
			Allow:     allow,
			Intercept: icpt,
			Service:   s.Service,
			Upstream:  up,
			Resolved:  resolved,
			Log:       log,
		})
		if err != nil {
			return serve.Handlers{}, err
		}
		return serve.Handlers{
			Egress: &egress.Handler{
				Policy:     &egress.Policy{Classifier: d.Classifier, Resolved: resolved},
				Dialer:     d.Dialer,
				PolicyName: name,
				Log:        log,
			},
			Intercept: ic.For(ca, s.Params["workspace"]),
			DNS:       srv,
			Authority: authority,
			CACert:    ca.CertPEM(),
		}, nil
	}), closers, nil
}

// sessionCA is a new session's CA, constrained to hosts, or a restored
// session's own, read back from its record -- with what to keep in the record.
func sessionCA(hosts []string, authority []byte) (*intercept.CA, []byte, error) {
	if authority != nil {
		ca, err := intercept.ParseCA(authority)
		return ca, authority, err
	}
	ca, err := intercept.NewCA(hosts)
	if err != nil {
		return nil, nil, err
	}
	b, err := ca.Marshal()
	return ca, b, err
}

// route builds one route and the watcher behind its credential, if it has one.
func route(r Route, d Deps) (intercept.Route, func() error, error) {
	out := intercept.Route{Name: r.Name, Host: r.Host, Upstream: r.Upstream}
	if rf := r.Refusal; rf != nil {
		out.Refusal = &intercept.Refusal{ContentType: rf.ContentType, Body: rf.Body}
	}
	switch r.Unmatched {
	case "", "refuse":
		if len(r.Paths) == 0 && r.Git == nil {
			return intercept.Route{}, nil, errors.New("no paths and no git: a route with no scope admits nothing")
		}
	case "ask":
		out.Scope.Unmatched = intercept.UnmatchedAsk
	default:
		return intercept.Route{}, nil, fmt.Errorf("unmatched %q: refuse or ask", r.Unmatched)
	}
	for _, p := range r.Paths {
		rule := intercept.PathRule{Methods: p.Methods, Prefix: p.Prefix, Path: p.Path, Ask: p.Ask, Refuse: p.Refuse}
		if o := p.Operation; o != nil {
			rule.Operation = &intercept.Operation{ID: o.ID, Summary: o.Summary, Description: o.Description}
		}
		out.Scope.Paths = append(out.Scope.Paths, rule)
	}
	if g := r.Git; g != nil {
		scope, err := gitScope(*g)
		if err != nil {
			return intercept.Route{}, nil, err
		}
		out.Scope.Git = scope
	}
	if r.UpstreamCA != "" {
		pool, err := intercept.LoadCAs(r.UpstreamCA)
		if err != nil {
			return intercept.Route{}, nil, fmt.Errorf("upstream CA: %w", err)
		}
		out.UpstreamCAs = pool
	}

	if r.CredentialFile == "" {
		// Scope only: what the client sends goes on as it came, if the scope
		// admits it. Anything that would say otherwise is refused.
		if r.Placeholder != "" || r.CredentialJSON != nil || r.Header != "" || r.BasicUser != "" {
			return intercept.Route{}, nil, errors.New("no credential file, so no placeholder, credentialJSON, header or basicUser")
		}
		return out, func() error { return nil }, nil
	}
	out.Placeholder = r.Placeholder
	switch {
	case r.Header != "" && r.BasicUser != "":
		return intercept.Route{}, nil, errors.New("header and basicUser: a token goes in one place")
	case r.BasicUser != "":
		if strings.ContainsAny(r.BasicUser, ":\r\n") {
			return intercept.Route{}, nil, errors.New("basicUser holds a colon or a line break")
		}
		out.Inject = intercept.BasicUser(r.BasicUser)
	case r.Header != "":
		if strings.EqualFold(r.Header, "Authorization") {
			return intercept.Route{}, nil, errors.New(`header "Authorization" is the default, with Bearer; name another header for a bare token, or basicUser for Basic`)
		}
		out.Inject = intercept.HeaderNamed(r.Header)
	default:
		out.Inject = intercept.Bearer()
	}
	extract := credential.Trimmed()
	if j := r.CredentialJSON; j != nil {
		if j.Token == "" {
			return intercept.Route{}, nil, errors.New("credentialJSON names no token")
		}
		if j.ExpiresMillis != "" && j.ExpiresJWT != "" {
			return intercept.Route{}, nil, errors.New("expiresMillis and expiresJWT: a token expires once")
		}
		extract = credential.JSON{Token: j.Token, ExpiresMillis: j.ExpiresMillis, ExpiresJWT: j.ExpiresJWT}.Extract
	}
	if d.checking {
		// Checking a document, not serving it: the file is somebody else's
		// to have made by the time a session needs it.
		out.Credential = unchecked{}
		return out, func() error { return nil }, nil
	}
	f, err := credential.WatchFile(r.CredentialFile, extract, d.Log)
	if err != nil {
		return intercept.Route{}, nil, err
	}
	out.Credential = f
	return out, f.Close, nil
}

// gitScope reads a git rule's repositories: "*" alone for all of them, or
// each "owner/name".
func gitScope(g GitRule) (*intercept.GitScope, error) {
	if len(g.Repos) == 1 && g.Repos[0] == "*" {
		return &intercept.GitScope{AnyRepo: true, Push: g.Push}, nil
	}
	s := &intercept.GitScope{Push: g.Push}
	for _, name := range g.Repos {
		repo, err := intercept.ParseRepo(name)
		if err != nil {
			return nil, fmt.Errorf("git: %w (or \"*\" alone, for every repository)", err)
		}
		s.Repos = append(s.Repos, repo)
	}
	if len(s.Repos) == 0 {
		return nil, errors.New(`git lists no repositories: name them, or "*" for every one`)
	}
	return s, nil
}

// upstream is the configured servers, fixed, or with none configured whatever
// the host's resolv.conf names, followed as it changes.
func upstream(conf []string, log *slog.Logger) (dns.Exchanger, func() error, error) {
	if len(conf) == 0 {
		rc, err := dns.FollowResolvConf(dns.HostResolvConf, dns.Upstream{}, log)
		if err != nil {
			return nil, nil, err
		}
		return rc, rc.Close, nil
	}
	servers, err := upstreamServers(conf)
	if err != nil {
		return nil, nil, err
	}
	return &dns.Upstream{Servers: servers}, func() error { return nil }, nil
}

// upstreamServers parses the configured servers.
func upstreamServers(conf []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(conf))
	for _, s := range conf {
		ap, err := dns.ParseServer(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, nil
}

// Dialer is the daemon's one dialer, for egress and for interception's
// upstreams alike, with the host's own addresses read live.
func Dialer() (*egress.Classifier, *egress.Dialer, error) {
	c, err := egress.NewClassifier(nil, egress.NewHostAddrs(0))
	if err != nil {
		return nil, nil, err
	}
	// The default resolver, which in a static binary is Go's own, reading the
	// host's resolv.conf: an upstream named in a route is the operator's
	// choice, resolved as the host resolves it, and Control checks whatever
	// address that gives.
	return c, &egress.Dialer{Classifier: c}, nil
}
