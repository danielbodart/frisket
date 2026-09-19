package intercept

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/danielbodart/frisket/internal/credential"
)

// Route is one intercepted host: the name frisket answers TLS as, where the
// request really goes, which credential it carries and what it may be used
// for. It is data, so a test can point it at a fake upstream with its own CA.
type Route struct {
	// Name identifies the route in the log.
	Name string
	// Host is the name the sandbox connects to, and the only name a
	// certificate is minted for on this route. Compared case-insensitively
	// and without a trailing dot.
	Host string
	// Upstream is where requests go: https://host[:port][/base]. Never plain
	// HTTP -- the credential crosses this hop.
	Upstream string
	// UpstreamCAs verifies the upstream. Nil means the host's roots.
	UpstreamCAs *x509.CertPool
	// Credential is what is injected; a route that cannot produce it fails
	// the request. Nil is a route that only holds requests to its scope, with
	// no injector and no placeholder: what the client sends goes upstream as
	// it came, and only if the scope admits it.
	Credential credential.Source
	// Inject puts the credential on the request.
	Inject Injector
	// Placeholder is what the sandbox is given in the credential's place. A
	// request carrying exactly it, in Inject's header, has it replaced with
	// the real credential; that is the only change frisket makes. A request
	// carrying anything else -- a token of the client's own, like the session
	// token Claude Code's Remote Control is handed -- or nothing goes upstream
	// as it was sent. Nothing is ever stripped.
	Placeholder string
	// Scope is what the credential may be used for.
	Scope Scope
}

// Injector puts a credential on an outgoing request.
type Injector interface {
	// Header is the header the credential goes in, and where the sandbox's
	// placeholder is looked for.
	Header() string
	// Value is the header's value for secret.
	Value(secret string) string
}

// Bearer is `Authorization: Bearer <token>`: the Anthropic, OpenAI and GitHub
// APIs.
func Bearer() Injector { return bearer{} }

// BasicUser is `Authorization: Basic base64(user:<token>)`: git over HTTPS,
// the only form GitHub accepts a token in for git, under any user.
func BasicUser(user string) Injector { return basic{user: user} }

// HeaderNamed puts the token, bare, in a header of its own: `x-api-key`.
func HeaderNamed(name string) Injector { return header{name: http.CanonicalHeaderKey(name)} }

type bearer struct{}

func (bearer) Header() string        { return "Authorization" }
func (bearer) Value(s string) string { return "Bearer " + s }

type basic struct{ user string }

func (basic) Header() string { return "Authorization" }
func (b basic) Value(s string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(b.user+":"+s))
}

type header struct{ name string }

func (h header) Header() string      { return h.name }
func (header) Value(s string) string { return s }

// LoadCAs reads a PEM bundle for Route.UpstreamCAs.
func LoadCAs(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificates", path)
	}
	return pool, nil
}

// normaliseHost is how a name from SNI, a Host header or a route is compared:
// lower-case, no trailing dot, no port. The trailing dot matters because
// "api.github.com." and "api.github.com" are the same name to DNS and would
// otherwise be two routes, or one refused.
func normaliseHost(h string) string {
	if strings.HasPrefix(h, "[") {
		// An IP literal is never a route; leave it unmatched.
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func (r *Route) validate() (*url.URL, error) {
	if r.Name == "" {
		return nil, errors.New("route has no name")
	}
	host := normaliseHost(r.Host)
	if host == "" || host != strings.ToLower(strings.TrimSuffix(r.Host, ".")) {
		return nil, fmt.Errorf("route %s: host %q is not a bare name", r.Name, r.Host)
	}
	u, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("route %s: upstream: %w", r.Name, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("route %s: upstream %q must be https://host[:port][/path]", r.Name, r.Upstream)
	}
	if r.Credential == nil {
		// A placeholder here would go upstream as it came: a configuration
		// that says something frisket would not do.
		if r.Inject != nil || r.Placeholder != "" {
			return nil, fmt.Errorf("route %s: an injector or placeholder with no credential", r.Name)
		}
		return u, nil
	}
	if r.Inject == nil || r.Inject.Header() == "" {
		return nil, fmt.Errorf("route %s: no injector", r.Name)
	}
	if r.Placeholder == "" || strings.ContainsAny(r.Placeholder, " \t\r\n") {
		return nil, fmt.Errorf("route %s: a placeholder is required, one word: the only value frisket replaces", r.Name)
	}
	return u, nil
}

// credentialHeader is where the log looks for a client's own credential:
// Authorization, on a route that injects none.
func (r *Route) credentialHeader() string {
	if r.Inject == nil {
		return "Authorization"
	}
	return r.Inject.Header()
}

// carries reports whether a request holds the placeholder, exactly, as the
// whole of the credential header or after its scheme: `Bearer <placeholder>`,
// gh's `token <placeholder>`, or git's Basic auth with it as the password. One value only -- two is not a request
// frisket can put one credential on.
func (r *Route) carries(h http.Header) bool {
	if r.Credential == nil {
		return false
	}
	vals := h.Values(r.Inject.Header())
	if len(vals) != 1 {
		return false
	}
	if vals[0] == r.Placeholder {
		return true
	}
	scheme, tok, ok := strings.Cut(vals[0], " ")
	if !ok {
		return false
	}
	if strings.EqualFold(scheme, "Basic") {
		// git's shape: the placeholder is the password, under whatever user.
		if b, err := base64.StdEncoding.DecodeString(tok); err == nil {
			_, pass, ok := strings.Cut(string(b), ":")
			return ok && pass == r.Placeholder
		}
	}
	return tok == r.Placeholder
}
