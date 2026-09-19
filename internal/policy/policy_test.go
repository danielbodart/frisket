package policy

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
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
	ca, err := intercept.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), []string{"api.test"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := egress.NewClassifier(nil, egress.StaticHostAddrs())
	if err != nil {
		t.Fatal(err)
	}
	return Deps{CA: ca, Classifier: c, Dialer: &egress.Dialer{Classifier: c}, Upstream: up, Log: slog.New(slog.NewJSONHandler(&journal{}, nil))}
}

func valid(t *testing.T) Policy {
	t.Helper()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Policy{
		Allow:     []string{"allowed.test", "api.test", "*.cdn.test"},
		Intercept: []string{"api.test"},
		Routes: []Route{{
			Name: "api", Host: "api.test", Upstream: "https://api.test", CredentialFile: token, Placeholder: "frisket-injects-the-real-one",
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
		"an intercepted name not on the allowlist": func(p *Policy) { p.Allow = []string{"allowed.test"} },
		"an intercepted name with no route":        func(p *Policy) { p.Intercept = append(p.Intercept, "allowed.test") },
		"a wildcard intercept":                     func(p *Policy) { p.Intercept = append(p.Intercept, "*.cdn.test") },
		"a bare * intercept":                       func(p *Policy) { p.Allow = []string{"*"}; p.Intercept = append(p.Intercept, "*") },
		"a route for a name not intercepted":       func(p *Policy) { p.Intercept = nil },
		"a route with no scope":                    func(p *Policy) { p.Routes[0].Paths = nil },
		"a route with no credential":               func(p *Policy) { p.Routes[0].CredentialFile = "" },
		"a JSON credential that names no token":    func(p *Policy) { p.Routes[0].CredentialJSON = &CredentialJSON{} },
		"a route with no placeholder":              func(p *Policy) { p.Routes[0].Placeholder = "" },
		"a plain-HTTP upstream":                    func(p *Policy) { p.Routes[0].Upstream = "http://api.test" },
		"a * inside an allowlist name":             func(p *Policy) { p.Allow = append(p.Allow, "api.*.test") },
		"a * glued to an allowlist name":           func(p *Policy) { p.Allow = append(p.Allow, "*cdn.test") },
		"Authorization named as a bare header":     func(p *Policy) { p.Routes[0].Header = "authorization" },
		"a route for a host the CA does not permit": func(p *Policy) {
			p.Allow = append(p.Allow, "other.test")
			p.Intercept = []string{"other.test"}
			p.Routes[0].Host, p.Routes[0].Upstream = "other.test", "https://other.test"
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

// The CA is made for every policy's intercepted hosts: each once, normalised,
// in order -- and never for a wildcard.
func TestInterceptedIsEveryPolicysHosts(t *testing.T) {
	c := &Config{Policies: map[string]Policy{
		"a": {Intercept: []string{"API.test.", "git.test"}},
		"b": {Intercept: []string{"api.test", "b.test"}},
		"c": {},
	}}
	got, err := c.Intercepted()
	if err != nil || strings.Join(got, ",") != "api.test,b.test,git.test" {
		t.Fatalf("Intercepted = %v, %v", got, err)
	}
	for _, bad := range []string{"*", "*.test", "a.*.test"} {
		c := &Config{Policies: map[string]Policy{"a": {Intercept: []string{bad}}}}
		if got, err := c.Intercepted(); err == nil {
			t.Errorf("Intercepted with %q = %v", bad, got)
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
	if err := os.WriteFile(config, []byte(`{"policies":{"p":{"allow":["api.test"],"intercept":["api.test"],"routes":[{
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
	h, err := set.Policies["p"].Handlers(control.Session{Name: "s", Policy: "p", Service: svc}, slog.New(slog.NewJSONHandler(&log, nil)))
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
	h2, err := set.Policies["p"].Handlers(control.Session{Name: "s2", Policy: "p", Service: svc}, slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if h2.DNS == h.DNS || h2.Egress == h.Egress {
		t.Error("two sessions share a DNS server or an egress handler")
	}
	if h2.Intercept != h.Intercept {
		t.Error("two sessions of one policy have different interceptors; routes and their credentials are the policy's")
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
	h, err := set.Policies["p"].Handlers(control.Session{Name: "s", Policy: "p", Service: svc}, slog.New(slog.NewJSONHandler(&journal{}, nil)))
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
