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
	// means the host's own /etc/resolv.conf, read once at start.
	DNS []string `json:"dns,omitempty"`
	// Policies by name. A session names one; one it names that is not here
	// is refused, and so never gets rules.
	Policies map[string]Policy `json:"policies"`
}

// Policy is one policy, as data.
type Policy struct {
	// Allow is the name allowlist: exact names, "*.suffix" for every name
	// below suffix, and "*" alone for every name. A name not on it is
	// refused at DNS without an upstream lookup, and so has no address egress
	// would accept.
	Allow []string `json:"allow"`
	// Intercept names are answered with the session's service address, so
	// their connections reach interception. Each must also be allowed --
	// interception is how an allowed host gets its credential, not a way round
	// the allowlist -- and each must have a route, or its TLS is refused at
	// the handshake and the name is a dead end. Exact names only: a route
	// serves one host.
	Intercept []string `json:"intercept,omitempty"`
	// Routes are the intercepted hosts' credentials and scopes.
	Routes []Route `json:"routes,omitempty"`
}

// Route is one intercepted host, as data. This is the generic route: a bearer
// token or a bare header, from a file, scoped by method and path prefix.
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
	// CredentialFile holds the token, alone, whitespace trimmed. It is read by
	// the daemon, on the host, and re-read when it is replaced.
	CredentialFile string `json:"credentialFile"`
	// Header is the header the token goes in, bare. Empty means
	// `Authorization: Bearer <token>`.
	Header string `json:"header,omitempty"`
	// Strip names further request headers to remove before injecting.
	Strip []string `json:"strip,omitempty"`
	// Paths is the route's scope: requests with a listed method at or under a
	// prefix, matched by segment. Nothing else is admitted.
	Paths []PathRule `json:"paths"`
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

// Deps is what every policy shares: the machine's CA, and the one classifier
// and dialer every upstream connection goes through.
type Deps struct {
	CA         *intercept.CA
	Classifier *egress.Classifier
	Dialer     *egress.Dialer
	// Upstream answers the names sessions are allowed. Nil builds one from
	// Config.DNS.
	Upstream dns.Exchanger
	// Log is the daemon's; credential watchers and interceptors write to it.
	Log *slog.Logger
}

// Set is every policy, built, and what must be closed when the daemon stops.
type Set struct {
	Policies map[string]serve.Policy
	closers  []func() error
}

// Close stops every interceptor and credential watcher.
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
	up := d.Upstream
	if up == nil {
		servers, err := upstreamServers(c.DNS)
		if err != nil {
			return nil, err
		}
		up = &dns.Upstream{Servers: servers}
	}
	set := &Set{Policies: map[string]serve.Policy{}}
	defer func() {
		if err != nil {
			_ = set.Close()
		}
	}()
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
	icpt, err := dns.NewMatcher(p.Intercept...)
	if err != nil {
		return nil, fmt.Errorf("intercept: %w", err)
	}
	routed := map[string]bool{}
	for _, r := range p.Routes {
		routed[dns.Normalize(r.Host)] = true
	}
	for _, pat := range icpt.Patterns() {
		// One name per route, so a wildcard could never be served: every name
		// it matched would resolve to the service address and fail at the
		// handshake.
		if pat.Any || pat.Wildcard {
			return nil, fmt.Errorf("intercept %s: a wildcard, and a route is for one host", pat)
		}
		if !allow.Match(pat.Name) {
			return nil, fmt.Errorf("intercept %s is not on the allowlist; interception is how an allowed host gets its credential, not a way round the allowlist", pat)
		}
		if !routed[pat.Name] {
			return nil, fmt.Errorf("intercept %s has no route", pat)
		}
	}

	routes := make([]intercept.Route, 0, len(p.Routes))
	for _, r := range p.Routes {
		host := dns.Normalize(r.Host)
		if !icpt.Match(host) {
			return nil, fmt.Errorf("route %s: %s is not intercepted, so no connection would ever reach it", r.Name, r.Host)
		}
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
	out := intercept.Route{Name: r.Name, Host: r.Host, Upstream: r.Upstream, Strip: r.Strip, Inject: intercept.Bearer()}
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
	f, err := credential.WatchFile(r.CredentialFile, credential.Trimmed(), log)
	if err != nil {
		return intercept.Route{}, nil, err
	}
	out.Credential = f
	return out, f.Close, nil
}

// upstreamServers parses the configured servers, or the host's resolv.conf
// when there are none. A server is an address, with :53 assumed.
func upstreamServers(conf []string) ([]netip.AddrPort, error) {
	if len(conf) == 0 {
		b, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("no DNS servers configured, and the host's: %w", err)
		}
		conf = ResolvConfServers(string(b))
		if len(conf) == 0 {
			return nil, errors.New("no DNS servers configured, and /etc/resolv.conf names none")
		}
	}
	out := make([]netip.AddrPort, 0, len(conf))
	for _, s := range conf {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("DNS server %q: want an address, or address:port", s)
			}
			ap = netip.AddrPortFrom(a, 53)
		}
		out = append(out, ap)
	}
	return out, nil
}

// ResolvConfServers returns the nameserver lines of a resolv.conf. The file is
// the host's own, written by root, and this reads one keyword out of it.
func ResolvConfServers(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			// A zone (fe80::1%eth0) names an interface on the host; keep it
			// for netip to parse or refuse.
			out = append(out, f[1])
		}
	}
	return out
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
