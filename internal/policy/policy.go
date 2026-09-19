// Package policy turns the daemon's configuration -- policies as data, written
// by the NixOS module -- into the handlers each session is served with: the
// real egress, DNS and interception, wired together.
//
// A policy is three lists and nothing else: the names a session may resolve,
// the names among them that are intercepted, and the routes that say what an
// intercepted name's requests may do and which credential they carry. Every
// session of a policy gets its own DNS server and its own resolved set --
// an answer given to one sandbox is not a permission for another -- and
// shares the policy's interceptor, its credential watchers and the daemon's
// CA.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/credential"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/serve"
)

// Config is the daemon's configuration file.
type Config struct {
	// DNS is where frisket resolves the names a session is allowed. Empty
	// means whatever the host's /etc/resolv.conf names, followed as it changes.
	DNS []string `json:"dns,omitempty"`
	// Policies by name. A session names one; one it names that is not here
	// is refused, and so never gets rules.
	Policies map[string]Policy `json:"policies"`
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

// Route is one intercepted host, as data. This is the generic route: a bearer
// token or a bare header, from a file -- the whole of it, or a field of its
// JSON -- scoped by method and path prefix.
// Tool-shaped routes are designed one tool at a time (PLAN.md, "Per-tool
// routes") and none is expressed here.
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
	// daemon, on the host, and re-read when it is replaced.
	CredentialFile string `json:"credentialFile"`
	// CredentialJSON reads CredentialFile as JSON: the token and its expiry
	// at dotted paths. Nil is the bare token.
	CredentialJSON *CredentialJSON `json:"credentialJSON,omitempty"`
	// Header is the header the token goes in, bare. Empty means
	// `Authorization: Bearer <token>`.
	Header string `json:"header,omitempty"`
	// Placeholder is what the sandbox holds in the credential's place, and
	// the only value frisket replaces: anything else is sent on as it came.
	Placeholder string `json:"placeholder"`
	// Paths is the route's scope: requests with a listed method at or under a
	// prefix, matched by segment. Nothing else is admitted.
	Paths []PathRule `json:"paths"`
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
}

// PathRule is one scope rule.
type PathRule struct {
	Methods []string `json:"methods"`
	Prefix  string   `json:"prefix"`
}

// Load reads a configuration file, refusing any field it does not know: a
// misspelt key in a policy is a rule that silently does not apply.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// Intercepted is every policy's intercepted hosts, normalised, once each, in
// order: what the machine's CA is constrained to. Each is checked as Build
// checks it, so the CA is never made for a name no route could serve.
func (c *Config) Intercepted() ([]string, error) {
	var out []string
	for name, p := range c.Policies {
		hosts, err := interceptHosts(p)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
		out = append(out, hosts...)
	}
	sort.Strings(out)
	return slices.Compact(out), nil
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

// Deps is what every policy shares: the machine's CA, and the one classifier
// and dialer every upstream connection goes through.
type Deps struct {
	// CA is constrained to Config.Intercepted; a route for a host it does not
	// permit is refused.
	CA         *intercept.CA
	Classifier *egress.Classifier
	Dialer     *egress.Dialer
	// Upstream answers the names sessions are allowed. Nil builds one from
	// Config.DNS, or follows the host's resolv.conf when that is empty.
	Upstream dns.Exchanger
	// Log is the daemon's; credential watchers and interceptors write to it.
	Log *slog.Logger
}

// Set is every policy, built, and what must be closed when the daemon stops.
type Set struct {
	Policies map[string]serve.Policy
	closers  []func() error
}

// Close stops every interceptor and watcher.
func (s *Set) Close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i](); err != nil {
			errs = append(errs, err)
		}
	}
	s.closers = nil
	return errors.Join(errs...)
}

// Build checks c and builds every policy in it. Nothing is built unless all of
// it is valid: a daemon with half its policies is one whose sessions are
// refused for reasons nobody configured.
func Build(c *Config, d Deps) (_ *Set, err error) {
	if d.CA == nil || d.Classifier == nil || d.Dialer == nil || d.Log == nil {
		return nil, errors.New("policy: a CA, a classifier, a dialer and a logger are all required")
	}
	set := &Set{Policies: map[string]serve.Policy{}}
	defer func() {
		if err != nil {
			_ = set.Close()
		}
	}()
	up := d.Upstream
	if up == nil {
		if up, err = upstream(c.DNS, d.Log, set); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(c.Policies))
	for name := range c.Policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p, err := build(name, c.Policies[name], d, up, set)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
		set.Policies[name] = p
	}
	return set, nil
}

func build(name string, p Policy, d Deps, up dns.Exchanger, set *Set) (serve.Policy, error) {
	if err := control.ValidName(name); err != nil {
		return nil, err
	}
	allow, err := dns.NewMatcher(p.Allow...)
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	hosts, err := interceptHosts(p)
	if err != nil {
		return nil, err
	}
	icpt, err := dns.NewMatcher(hosts...)
	if err != nil {
		return nil, fmt.Errorf("intercept: %w", err)
	}
	for _, h := range hosts {
		if !allow.Match(h) {
			return nil, fmt.Errorf("route for %s: not on the allowlist; interception is how an allowed host gets its credential, not a way round the allowlist", h)
		}
	}

	routes := make([]intercept.Route, 0, len(p.Routes))
	for _, r := range p.Routes {
		ir, closer, err := route(r, d.Log)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Name, err)
		}
		set.closers = append(set.closers, closer)
		routes = append(routes, ir)
	}

	ic, err := intercept.New(intercept.Config{
		CA:     d.CA,
		Routes: routes,
		Log:    d.Log,
		// The upstream is dialled through the same structural check as every
		// other connection frisket makes: a route pointed at the host's own
		// address, or at the metadata service, is refused at the dial.
		DialContext: d.Dialer.DialContext,
	})
	if err != nil {
		return nil, err
	}
	set.closers = append(set.closers, ic.Close)

	return serve.PolicyFunc(func(s control.Session, log *slog.Logger) (serve.Handlers, error) {
		resolved := egress.NewResolved(egress.ResolvedConfig{})
		srv, err := dns.New(dns.Config{
			Session:   s.Name,
			Policy:    s.Policy,
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
				PolicyName: s.Policy,
				Log:        log,
			},
			Intercept: ic,
			DNS:       srv,
		}, nil
	}), nil
}

// route builds one generic route and the watcher behind its credential.
func route(r Route, log *slog.Logger) (intercept.Route, func() error, error) {
	if r.CredentialFile == "" {
		return intercept.Route{}, nil, errors.New("no credential file")
	}
	if len(r.Paths) == 0 {
		return intercept.Route{}, nil, errors.New("no paths: a route with no scope admits nothing")
	}
	out := intercept.Route{Name: r.Name, Host: r.Host, Upstream: r.Upstream, Placeholder: r.Placeholder, Inject: intercept.Bearer()}
	if r.Header != "" {
		if strings.EqualFold(r.Header, "Authorization") {
			return intercept.Route{}, nil, errors.New(`header "Authorization" is the default, with Bearer; name another header for a bare token`)
		}
		out.Inject = intercept.HeaderNamed(r.Header)
	}
	for _, p := range r.Paths {
		out.Scope.Paths = append(out.Scope.Paths, intercept.PathRule{Methods: p.Methods, Prefix: p.Prefix})
	}
	if r.UpstreamCA != "" {
		pool, err := intercept.LoadCAs(r.UpstreamCA)
		if err != nil {
			return intercept.Route{}, nil, fmt.Errorf("upstream CA: %w", err)
		}
		out.UpstreamCAs = pool
	}
	extract := credential.Trimmed()
	if j := r.CredentialJSON; j != nil {
		if j.Token == "" {
			return intercept.Route{}, nil, errors.New("credentialJSON names no token")
		}
		extract = credential.JSON{Token: j.Token, ExpiresMillis: j.ExpiresMillis}.Extract
	}
	f, err := credential.WatchFile(r.CredentialFile, extract, log)
	if err != nil {
		return intercept.Route{}, nil, err
	}
	out.Credential = f
	return out, f.Close, nil
}

// upstream is the configured servers, fixed, or with none configured whatever
// the host's resolv.conf names, followed as it changes.
func upstream(conf []string, log *slog.Logger, set *Set) (dns.Exchanger, error) {
	if len(conf) == 0 {
		rc, err := dns.FollowResolvConf(dns.HostResolvConf, dns.Upstream{}, log)
		if err != nil {
			return nil, err
		}
		set.closers = append(set.closers, rc.Close)
		return rc, nil
	}
	servers, err := upstreamServers(conf)
	if err != nil {
		return nil, err
	}
	return &dns.Upstream{Servers: servers}, nil
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
