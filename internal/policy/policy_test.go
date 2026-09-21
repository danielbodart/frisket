package policy

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/serve"
	"github.com/danielbodart/frisket/internal/steer"
)

type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

// counting is an upstream that answers nothing and counts: "a name not allowed
// is never looked up" is a count of zero.
type counting struct {
	mu    sync.Mutex
	asked []string
}

func (c *counting) Exchange(_ context.Context, q dnsmessage.Question) (*dnsmessage.Message, dns.Trace, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked = append(c.asked, q.Name.String())
	return &dnsmessage.Message{Header: dnsmessage.Header{Response: true}}, dns.Trace{}, nil
}

func deps(t *testing.T, up dns.Exchanger) Deps {
	t.Helper()
	c, err := egress.NewClassifier(nil, egress.StaticHostAddrs())
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Classifier: c, Dialer: &egress.Dialer{Classifier: c}, Upstream: up, Log: slog.New(slog.NewJSONHandler(&journal{}, nil))}
}

func valid(t *testing.T) Policy {
	t.Helper()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Policy{
		Allow: []string{"allowed.test", "api.test", "*.cdn.test"},
		Routes: []Route{{
			Name: "api", Host: "api.test", Upstream: "https://api.test", CredentialFile: token, Placeholder: "proxy-injected",
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/v1"}},
		}},
	}
}

func TestBuildRefusesAPolicyThatDoesNotHoldTogether(t *testing.T) {
	set, err := Build(&Config{Policies: map[string]Policy{"p": valid(t)}}, deps(t, &counting{}))
	if err != nil {
		t.Fatalf("a valid policy was refused: %v", err)
	}
	_ = set.Close()

	for name, mutate := range map[string]func(*Policy){
		// Interception is how an allowed host gets its credential, not a way
		// round the allowlist.
		"a route for a name not on the allowlist": func(p *Policy) { p.Allow = []string{"allowed.test"} },
		"a route for a wildcard":                  func(p *Policy) { p.Routes[0].Host = "*.cdn.test" },
		"a route for *":                           func(p *Policy) { p.Allow = []string{"*"}; p.Routes[0].Host = "*" },
		"a route with no scope":                   func(p *Policy) { p.Routes[0].Paths = nil },
		"a placeholder with no credential":        func(p *Policy) { p.Routes[0].CredentialFile = "" },
		"basicUser with no credential": func(p *Policy) {
			p.Routes[0].CredentialFile, p.Routes[0].Placeholder, p.Routes[0].BasicUser = "", "", "x-access-token"
		},
		"a header and basicUser":                       func(p *Policy) { p.Routes[0].Header = "X-Api-Key"; p.Routes[0].BasicUser = "u" },
		"a basicUser with a colon":                     func(p *Policy) { p.Routes[0].BasicUser = "a:b" },
		"git with no repositories":                     func(p *Policy) { p.Routes[0].Git = &GitRule{} },
		"git with * among repositories":                func(p *Policy) { p.Routes[0].Git = &GitRule{Repos: []string{"*", "owner/repo"}} },
		"git with a repository that is not owner/name": func(p *Policy) { p.Routes[0].Git = &GitRule{Repos: []string{"owner"}} },
		"git with a wildcard owner":                    func(p *Policy) { p.Routes[0].Git = &GitRule{Repos: []string{"owner/*"}} },
		"a JSON credential that names no token":        func(p *Policy) { p.Routes[0].CredentialJSON = &CredentialJSON{} },
		"a JSON credential that expires twice": func(p *Policy) {
			p.Routes[0].CredentialJSON = &CredentialJSON{Token: "t", ExpiresMillis: "e", ExpiresJWT: "t"}
		},
		"a route with no placeholder":              func(p *Policy) { p.Routes[0].Placeholder = "" },
		"a plain-HTTP upstream":                    func(p *Policy) { p.Routes[0].Upstream = "http://api.test" },
		"a * inside an allowlist name":             func(p *Policy) { p.Allow = append(p.Allow, "api.*.test") },
		"a * glued to an allowlist name":           func(p *Policy) { p.Allow = append(p.Allow, "*cdn.test") },
		"Authorization named as a bare header":     func(p *Policy) { p.Routes[0].Header = "authorization" },
		"unmatched that is neither refuse nor ask": func(p *Policy) { p.Routes[0].Unmatched = "admit" },
		"a rule with a path and a prefix":          func(p *Policy) { p.Routes[0].Paths[0].Path = "/v1/x" },
		"a * inside a template segment":            func(p *Policy) { p.Routes[0].Paths[0].Prefix = "/v1/x*" },
		"an operation with no summary": func(p *Policy) {
			p.Routes[0].Paths[0].Operation = &Operation{ID: "op"}
		},
	} {
		p := valid(t)
		mutate(&p)
		if set, err := Build(&Config{Policies: map[string]Policy{"p": p}}, deps(t, &counting{})); err == nil {
			_ = set.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Build(&Config{Policies: map[string]Policy{"a:b": valid(t)}}, deps(t, &counting{})); err == nil {
		t.Error("a policy name that cannot be a session's was accepted")
	}
}

// git's routes: Basic with the token as the password, under a fixed user, and
// a git scope; and a route with no credential, which only holds its scope.
func TestGitRoutesBuild(t *testing.T) {
	p := valid(t)
	p.Allow = append(p.Allow, "git.test", "anon.test")
	p.Routes = append(p.Routes,
		Route{
			Name: "git", Host: "git.test", Upstream: "https://git.test",
			CredentialFile: p.Routes[0].CredentialFile, Placeholder: "proxy-injected", BasicUser: "x-access-token",
			Git: &GitRule{Repos: []string{"owner/repo", "Owner/Other.js"}, Push: true},
		},
		Route{
			Name: "anon", Host: "anon.test", Upstream: "https://anon.test",
			Paths: []PathRule{{Methods: []string{"GET", "HEAD"}, Prefix: "/"}},
			Git:   &GitRule{Repos: []string{"*"}},
		},
	)
	set, err := Build(&Config{Policies: map[string]Policy{"p": p}}, deps(t, &counting{}))
	if err != nil {
		t.Fatal(err)
	}
	_ = set.Close()
}

// A route for a wildcard is refused: every name it matched would resolve to
// the service address and fail at the handshake.
func TestARouteIsForOneHost(t *testing.T) {
	for _, bad := range []string{"*", "*.test", "a.*.test"} {
		if _, err := interceptHosts(Policy{Routes: []Route{{Name: "r", Host: bad}}}); err == nil {
			t.Errorf("a route for %q was accepted", bad)
		}
	}
}

// A misspelt key is a rule that silently does not apply, so it is refused.
func TestLoadRefusesUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"policies":{"p":{"allow":["a.test"],"intercepts":["a.test"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "intercepts") {
		t.Errorf("Load = %v, want the unknown field named", err)
	}
}

// A route's JSON credential is read at the paths its configuration names, from
// the key the NixOS module writes, with the expiry that makes a stale token a
// 503.
func TestARouteReadsItsCredentialFromJSON(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(creds, []byte(`{"claudeAiOauth":{"accessToken":"tok","expiresAt":1789766901894}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(`{"policies":{"p":{"allow":["api.test"],"routes":[{
		"name":"claude","host":"api.test","upstream":"https://api.test","credentialFile":`+strconv.Quote(creds)+`,"placeholder":"p",
		"credentialJSON":{"token":"claudeAiOauth.accessToken","expiresMillis":"claudeAiOauth.expiresAt"},
		"paths":[{"methods":["POST"],"prefix":"/v1"}]}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(config)
	if err != nil {
		t.Fatal(err)
	}
	r, closer, err := route(cfg.Policies["p"].Routes[0], slog.New(slog.NewJSONHandler(&journal{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	s, err := r.Credential.Get()
	if err != nil {
		t.Fatal(err)
	}
	if s.Value != "tok" || !s.Expires.Equal(time.UnixMilli(1789766901894)) {
		t.Errorf("credential = %q expiring %v, want the token at claudeAiOauth.accessToken expiring at claudeAiOauth.expiresAt", s.Value, s.Expires)
	}
}

// Each session gets its own DNS, answering the intercepted name with ITS
// service address and NXDOMAIN for what is not allowed, without asking
// upstream, and its own egress, which refuses what its DNS did not resolve.
func TestASessionIsServedByTheRealHandlers(t *testing.T) {
	up := &counting{}
	set, err := Build(&Config{Policies: map[string]Policy{"p": valid(t)}}, deps(t, up))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	var log journal
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}
	h, err := set.Policies["p"].Handlers(control.Session{Name: "s", Policy: "p", Service: svc}, nil, slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if h.Egress == nil || h.Intercept == nil || h.DNS == nil {
		t.Fatalf("handlers = %+v", h)
	}

	ask := func(name string) *dnsmessage.Message { return ask(t, h, name) }
	m := ask("api.test.")
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 2} {
		t.Errorf("the intercepted name answered %+v, want the session's service address", m.Answers)
	}
	if m := ask("denied.test."); m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("a name not allowed answered %v", m.RCode)
	}
	up.mu.Lock()
	asked := append([]string(nil), up.asked...)
	up.mu.Unlock()
	if len(asked) != 0 {
		t.Errorf("upstream was asked %v; neither an intercepted nor a refused name goes upstream", asked)
	}

	// A second session's handlers are its own: nothing resolved for one is a
	// permission for the other.
	h2, err := set.Policies["p"].Handlers(control.Session{Name: "s2", Policy: "p", Service: svc}, nil, slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if h2.DNS == h.DNS || h2.Egress == h.Egress {
		t.Error("two sessions share a DNS server or an egress handler")
	}

	// And its own CA, constrained to the policy's route hosts: one
	// sandbox's trust vouches for nothing another is served.
	for _, h := range []serve.Handlers{h, h2} {
		ca, err := intercept.ParseCA(h.Authority)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ca.CertPEM(), h.CACert) || !slices.Equal(ca.Hosts(), []string{"api.test"}) {
			t.Fatalf("the session's CA is constrained to %v", ca.Hosts())
		}
	}
	if bytes.Equal(h.CACert, h2.CACert) || bytes.Equal(h.Authority, h2.Authority) {
		t.Error("two sessions share a CA")
	}

	// Restored, a session is given its own CA back, not a new one.
	again, err := set.Policies["p"].Handlers(control.Session{Name: "s", Policy: "p", Service: svc}, h.Authority, slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.CACert, h.CACert) || !bytes.Equal(again.Authority, h.Authority) {
		t.Error("a restored session was given a CA its sandbox does not trust")
	}
}

// ask sends one A query to a session's DNS and returns the reply.
func ask(t *testing.T, h serve.Handlers, name string) *dnsmessage.Message {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	got := make(chan []byte, 1)
	h.DNS.ServePacket(context.Background(), steer.NewDatagram("s", netip.MustParseAddrPort("192.0.2.1:4000"), netip.MustParseAddrPort("127.0.0.1:53"), q,
		func(b []byte) error { got <- append([]byte(nil), b...); return nil }))
	var m dnsmessage.Message
	if err := m.Unpack(<-got); err != nil {
		t.Fatal(err)
	}
	return &m
}

// A TRUSTED POLICY ALLOWS EVERY NAME AND STILL INTERCEPTS SOME: "*" sends any
// name upstream, and the intercepted one is still answered with the service
// address and never asked about.
func TestEveryNameCanBeAllowedWhileSomeAreIntercepted(t *testing.T) {
	up := &counting{}
	p := valid(t)
	p.Allow = []string{"*"}
	set, err := Build(&Config{Policies: map[string]Policy{"p": p}}, deps(t, up))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	h, err := set.Policies["p"].Handlers(control.Session{Name: "s", Policy: "p", Service: svc}, nil, slog.New(slog.NewJSONHandler(&journal{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if m := ask(t, h, "api.test."); len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 2} {
		t.Errorf("the intercepted name answered %+v, want the service address", m.Answers)
	}
	if m := ask(t, h, "anything.unlisted.example."); m.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("an unlisted name answered %v under *", m.RCode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.asked) != 1 || up.asked[0] != "anything.unlisted.example." {
		t.Errorf("upstream was asked %v, want the unlisted name alone", up.asked)
	}
}

func TestConfiguredDNSServers(t *testing.T) {
	servers, err := upstreamServers([]string{"203.0.113.20", "[::1]:5353"})
	if err != nil {
		t.Fatal(err)
	}
	if servers[0].String() != "203.0.113.20:53" || servers[1].String() != "[::1]:5353" {
		t.Errorf("upstreamServers = %v", servers)
	}
	if _, err := upstreamServers([]string{"resolver.example"}); err == nil {
		t.Error("a name was accepted as a DNS server; the resolver has no resolver to resolve it with")
	}
}

// A route described operation by operation, as the NixOS module writes it:
// templates, rules that ask, the operations' own words, and asking about the
// rest -- which, alone, is a scope.
func TestARouteOfOperationsLoadsAndBuilds(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "frisket.json")
	if err := os.WriteFile(conf, []byte(`{"policies": {"p": {
		"allow": ["api.test", "other.test"],
		"routes": [
			{"name": "api", "host": "api.test", "upstream": "https://api.test",
			 "credentialFile": "`+token+`", "placeholder": "proxy-injected", "unmatched": "ask",
			 "paths": [
				{"methods": ["GET", "HEAD"], "path": "/client/v4/zones/*/dns_records/*",
				 "operation": {"id": "get-record", "summary": "DNS Record Details"}},
				{"methods": ["DELETE"], "path": "/client/v4/zones/*/dns_records/*", "ask": true,
				 "operation": {"id": "delete-record", "summary": "Delete DNS Record", "description": "Permanently removes it."}}
			 ]},
			{"name": "other", "host": "other.test", "upstream": "https://other.test",
			 "credentialFile": "`+token+`", "placeholder": "proxy-injected", "unmatched": "ask"}
		]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	set, err := Build(c, deps(t, &counting{}))
	if err != nil {
		t.Fatal(err)
	}
	_ = set.Close()
}
