// Package store turns the daemon's configuration -- policies as data, written
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
package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/danielbodart/frisket/policy"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/danielbodart/frisket/docker"
	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/credential"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/dockerapi"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/relay"
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

// Load reads the daemon's configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := policy.Decode(b, &c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// interceptHosts is a policy's intercepted names -- its routes' hosts -- each
// a name or "*.suffix".
func interceptHosts(p policy.Policy) ([]string, error) {
	hosts := make([]string, 0, len(p.Routes))
	for _, r := range p.Routes {
		pat, err := dns.ParsePattern(r.Host)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Name, err)
		}
		if pat.Any {
			return nil, fmt.Errorf("route %s: * is every name, and a route is for a name or the names below one", r.Name)
		}
		hosts = append(hosts, pat.String())
	}
	return hosts, nil
}

// allowCovers is whether every name host stands for is allowed: a name by
// matching, and "*.suffix" by "*", or by a wildcard at or above suffix.
func allowCovers(allow *dns.Matcher, host string) bool {
	suffix, wild := strings.CutPrefix(host, "*.")
	if !wild {
		return allow.Match(host)
	}
	for _, p := range allow.Patterns() {
		if p.Any || p.Wildcard && (p.Name == suffix || strings.HasSuffix(suffix, "."+p.Name)) {
			return true
		}
	}
	return false
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
		var doc policy.Document
		if err := policy.Decode(b, &doc); err != nil {
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
func build(name string, p policy.Policy, d Deps, up dns.Exchanger) (_ serve.Policy, closers []func() error, err error) {
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
		if !allowCovers(allow, h) {
			return nil, closers, fmt.Errorf("route for %s: not on the allowlist; interception is how an allowed host gets its credential, not a way round the allowlist", h)
		}
	}
	if err := dockerNames(p, hosts); err != nil {
		return nil, closers, err
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

	// What the daemon keeps apart and steer steers: the same for every
	// session under this document.
	dr := p.DockerRoute()
	var dock *serve.Docker
	var ports []uint16
	var names map[string]netip.Addr
	if dr != nil {
		dock = &serve.Docker{Project: dr.Project, Address: docker.Address(dr.Project), Relay: p.RelayDestinations()}
		// The session's own names, answered with the project's address --
		// frisket's derivation, which build has already held the document's
		// to.
		names = make(map[string]netip.Addr, len(dr.Names))
		for _, n := range dr.Names {
			names[dns.Normalize(n)] = dock.Address
		}
		for _, port := range dr.Ports {
			ports = append(ports, uint16(port)) // held between 1024 and 65535 by dockerRoute
		}
	}

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
			Names:     names,
			Upstream:  up,
			Resolved:  resolved,
			Log:       log,
		})
		if err != nil {
			return serve.Handlers{}, err
		}
		h := serve.Handlers{
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
			Docker:    dock,
		}
		// Built from the document as it reads now, so a session restored
		// under one that has dropped a port is refused it here, though its
		// ruleset still steers it.
		if dr != nil {
			h.Relay = &relay.Handler{
				Transport:  ic.DockerTransport(),
				APIVersion: dr.APIVersions.Max,
				Project:    dr.Project,
				Address:    dock.Address,
				Ports:      ports,
				Log:        log,
			}
		}
		return h, nil
	}), closers, nil
}

// dockerNames holds a document to one Docker route, and that route's names
// clear of every route's host. A name the session answers with its project's
// address must never be one the session's CA vouches for, or one below a
// wildcard route: the one is plain TCP to a relay, the other TLS to frisket,
// and a name cannot be both.
func dockerNames(p policy.Policy, hosts []string) error {
	var dr *policy.Route
	for i := range p.Routes {
		if p.Routes[i].Docker == nil {
			continue
		}
		if dr != nil {
			return fmt.Errorf("routes %s and %s are both Docker routes, and a document has at most one", dr.Name, p.Routes[i].Name)
		}
		dr = &p.Routes[i]
	}
	if dr == nil {
		return nil
	}
	for _, n := range dr.Docker.Names {
		name := dns.Normalize(n)
		for _, h := range hosts {
			suffix, wild := strings.CutPrefix(h, "*.")
			if name == h || wild && strings.HasSuffix(name, "."+suffix) {
				return fmt.Errorf("route %s: name %s is route %s's, or under it, and the project's address cannot be answered for it", dr.Name, n, h)
			}
		}
	}
	return nil
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
func route(r policy.Route, d Deps) (intercept.Route, func() error, error) {
	out := intercept.Route{Name: r.Name, Host: r.Host, Upstream: r.Upstream}
	if rf := r.Refusal; rf != nil {
		out.Refusal = &intercept.Refusal{ContentType: rf.ContentType, Body: rf.Body}
	}
	switch r.Unmatched {
	case "", "refuse":
		if len(r.Paths) == 0 && r.Git == nil && len(r.GraphQL) == 0 {
			return intercept.Route{}, nil, errors.New("no paths, no git and no graphql: a route with no scope admits nothing")
		}
	case "ask":
		out.Scope.Unmatched = intercept.UnmatchedAsk
	default:
		return intercept.Route{}, nil, fmt.Errorf("unmatched %q: refuse or ask", r.Unmatched)
	}
	for _, p := range r.Paths {
		rule := intercept.PathRule{Methods: p.Methods, Prefix: p.Prefix, Path: p.Path, EncodedSlashes: p.EncodedSlashes, Ask: p.Ask, Refuse: p.Refuse}
		o, err := operation(p.Operation)
		if err != nil {
			return intercept.Route{}, nil, err
		}
		rule.Operation = o
		if d := p.Docker; d != nil {
			rule.Docker = &intercept.DockerRule{Owned: d.Owned, Param: d.Param, Body: d.Body, Upgrade: d.Upgrade}
			if d.Query != nil {
				rule.Docker.Query = map[string]intercept.QueryCheck{}
				for k, c := range d.Query {
					rule.Docker.Query[k] = intercept.QueryCheck{Check: c.Check, Filters: c.Filters, Enum: c.Enum}
				}
			}
		}
		out.Scope.Paths = append(out.Scope.Paths, rule)
	}
	if r.Docker != nil || strings.HasPrefix(r.Upstream, "unix:") {
		return dockerRoute(r, out)
	}
	for _, g := range r.GraphQL {
		scope, err := graphqlScope(g)
		if err != nil {
			return intercept.Route{}, nil, err
		}
		out.Scope.GraphQL = append(out.Scope.GraphQL, scope)
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
		if r.Placeholder != "" || r.CredentialJSON != nil || r.Header != "" || r.BasicUser != "" || r.SessionKey != nil {
			return intercept.Route{}, nil, errors.New("no credential file, so no placeholder, credentialJSON, header, basicUser or sessionKey")
		}
		return out, func() error { return nil }, nil
	}
	out.Placeholder = r.Placeholder
	if k := r.SessionKey; k != nil {
		key, err := intercept.ParsePublicKey(k.PublicKey)
		if err != nil {
			return intercept.Route{}, nil, err
		}
		out.SessionKey = &intercept.SessionKey{Key: key, Issuer: k.Issuer, Grants: k.Grants}
	}
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

// dockerRoute finishes a Docker Engine's route: its hop to the daemon is
// plain HTTP over a socket, so nothing of a credential may be set, and its
// tables are compiled against frisket's floor here, so a document weaker
// than the floor never loads. The rest is checked by
// intercept, which builds it.
func dockerRoute(r policy.Route, out intercept.Route) (intercept.Route, func() error, error) {
	if r.CredentialFile != "" || r.Placeholder != "" || r.Header != "" || r.BasicUser != "" ||
		r.SessionKey != nil || r.CredentialJSON != nil || r.UpstreamCA != "" {
		return intercept.Route{}, nil, errors.New("a Docker route's hop is plain HTTP over the daemon's socket: no credentialFile, placeholder, header, basicUser, sessionKey, credentialJSON or upstreamCA")
	}
	d := r.Docker
	if d == nil {
		return intercept.Route{}, nil, errors.New("a unix upstream is only a Docker route's, with a docker block")
	}
	// route() returns here before it reads git or graphql, so a scope of
	// either would otherwise be dropped without a word.
	if r.Git != nil || len(r.GraphQL) > 0 {
		return intercept.Route{}, nil, errors.New("a Docker route has path rules only: no git or graphql")
	}
	addr, err := netip.ParseAddr(d.Address)
	if err != nil || !addr.Is4() {
		return intercept.Route{}, nil, fmt.Errorf("docker address %q is not a dotted-quad IPv4 address", d.Address)
	}
	ports := make([]uint16, len(d.Ports))
	for i, p := range d.Ports {
		if p < 1024 || p > 65535 {
			return intercept.Route{}, nil, fmt.Errorf("docker port %d is not between 1024 and 65535", p)
		}
		ports[i] = uint16(p)
	}
	bodies := map[string]*dockerapi.Table{}
	for name, raw := range d.Bodies {
		t, err := dockerapi.Compile(name, raw)
		if err != nil {
			return intercept.Route{}, nil, err
		}
		bodies[name] = t
	}
	out.Docker = &intercept.DockerRoute{
		Project:     d.Project,
		APIVersions: intercept.APIVersions{Min: d.APIVersions.Min, Max: d.APIVersions.Max, Unversioned: d.APIVersions.Unversioned},
		Images:      d.Images,
		Address:     addr,
		Ports:       ports,
		Names:       d.Names,
		MaxBody:     d.MaxBody,
		Bodies:      bodies,
	}
	return out, func() error { return nil }, nil
}

// operation is a rule's operation, its class one of the three.
func operation(o *policy.Operation) (*intercept.Operation, error) {
	if o == nil {
		return nil, nil
	}
	switch o.Class {
	case "", "read", "write", "guarded":
	default:
		return nil, fmt.Errorf("operation %s: class %q: read, write or guarded", o.ID, o.Class)
	}
	return &intercept.Operation{ID: o.ID, Summary: o.Summary, Description: o.Description, Class: o.Class, Category: o.Category}, nil
}

// graphqlScope reads a GraphQL endpoint's rules.
func graphqlScope(g policy.GraphQLRule) (intercept.GraphQLScope, error) {
	s := intercept.GraphQLScope{Path: g.Path}
	switch g.Unmatched {
	case "", "refuse":
		s.Unmatched = intercept.Refuse
	case "ask":
		s.Unmatched = intercept.Ask
	case "allow":
		s.Unmatched = intercept.Admit
	default:
		return s, fmt.Errorf("graphql %s: unmatched %q: refuse, ask or allow", g.Path, g.Unmatched)
	}
	rule := func(what string, f policy.GraphQLField) (intercept.GraphQLRule, error) {
		if f.Ask && f.Refuse {
			return intercept.GraphQLRule{}, fmt.Errorf("graphql %s %s both asks and refuses", g.Path, what)
		}
		o, err := operation(f.Operation)
		if err != nil {
			return intercept.GraphQLRule{}, err
		}
		r := intercept.GraphQLRule{Outcome: intercept.Admit, Operation: o}
		switch {
		case f.Ask:
			r.Outcome = intercept.Ask
		case f.Refuse:
			r.Outcome = intercept.Refuse
		}
		return r, nil
	}
	if q := g.Query; q != nil {
		if q.Field != "" {
			return s, fmt.Errorf("graphql %s: a query is decided whole, not by field %q", g.Path, q.Field)
		}
		r, err := rule("query", *q)
		if err != nil {
			return s, err
		}
		s.Query = &r
	}
	fields := func(kind string, list []policy.GraphQLField) (map[string]intercept.GraphQLRule, error) {
		out := map[string]intercept.GraphQLRule{}
		for _, f := range list {
			if f.Field == "" {
				return nil, fmt.Errorf("graphql %s: a %s with no field", g.Path, kind)
			}
			if _, ok := out[f.Field]; ok {
				return nil, fmt.Errorf("graphql %s: %s %s twice", g.Path, kind, f.Field)
			}
			r, err := rule(kind+" "+f.Field, f)
			if err != nil {
				return nil, err
			}
			out[f.Field] = r
		}
		return out, nil
	}
	var err error
	if s.Mutations, err = fields("mutation", g.Mutations); err != nil {
		return s, err
	}
	if s.Subscriptions, err = fields("subscription", g.Subscriptions); err != nil {
		return s, err
	}
	return s, nil
}

// gitScope reads a git rule's repositories: "*" alone for all of them, or
// each "owner/name".
func gitScope(g policy.GitRule) (*intercept.GitScope, error) {
	var push intercept.Outcome
	switch g.Push {
	case "", "refuse":
		push = intercept.Refuse
	case "ask":
		push = intercept.Ask
	case "allow":
		push = intercept.Admit
	default:
		return nil, fmt.Errorf("git push %q: refuse, ask or allow", g.Push)
	}
	if len(g.Repos) == 1 && g.Repos[0] == "*" {
		return &intercept.GitScope{AnyRepo: true, Push: push}, nil
	}
	s := &intercept.GitScope{Push: push}
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
