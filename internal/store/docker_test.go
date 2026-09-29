package store

import (
	"context"
	"encoding/json"
	"github.com/danielbodart/frisket/policy"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/relay"
	"github.com/danielbodart/frisket/internal/serve"
	"github.com/danielbodart/frisket/internal/steer"
)

// dockerPolicy is a session's document with shop's Docker route, as
// chase writes it: every Engine operation, and the body tables.
func dockerPolicy(t *testing.T) policy.Policy {
	t.Helper()
	var paths []policy.PathRule
	if err := json.Unmarshal(readFile(t, "../intercept/testdata/engine-operations.json"), &paths); err != nil {
		t.Fatal(err)
	}
	var bodies map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, "../dockerapi/testdata/fields.json"), &bodies); err != nil {
		t.Fatal(err)
	}
	return policy.Policy{
		Allow: []string{"docker.frisket.internal"},
		Routes: []policy.Route{{
			Name:      "docker",
			Host:      "docker.frisket.internal",
			Upstream:  "unix:///run/user/1000/docker.sock",
			Unmatched: "refuse",
			Refusal:   &policy.Refusal{ContentType: "application/json", Body: `{"message":"{{message}}"}`},
			Paths:     paths,
			Docker: &policy.DockerRoute{
				Project:     "example/shop",
				APIVersions: policy.APIVersions{Min: "1.55", Max: "1.56", Unversioned: []string{"/_ping"}},
				Images:      []string{"postgres:18", "docker.io/library/postgres:18"},
				Address:     "127.101.170.171",
				Ports:       []int{64320, 64321, 64322},
				Names:       []string{"shop.internal", "shop.example.internal"},
				MaxBody:     262144,
				Bodies:      bodies,
			},
		}},
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A session's document with a Docker route loads, written as JSON and read
// back as the daemon reads it; so does one beside routes whose hosts are
// under .internal but are not the project's names.
func TestADockerRouteLoads(t *testing.T) {
	if err := check(t, "p", dockerPolicy(t)); err != nil {
		t.Fatal(err)
	}
	p := dockerPolicy(t)
	p.Allow = append(p.Allow, "metadata.google.internal", "*.frisket.internal", "docker.internal")
	p.Routes = append(p.Routes,
		policy.Route{Name: "gce", Host: "metadata.google.internal", Upstream: "https://metadata.google.internal",
			Paths: []policy.PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
		policy.Route{Name: "frisket", Host: "*.frisket.internal", Upstream: "https://*.frisket.internal",
			Paths: []policy.PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
		// frisket/docker's name, not shop's.
		policy.Route{Name: "other", Host: "docker.internal", Upstream: "https://docker.internal",
			Paths: []policy.PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
	)
	if err := check(t, "p", p); err != nil {
		t.Fatal(err)
	}
}

// A Docker route that could be a way round what it is for fails to load, and
// so the session it was for never starts: a credential on a hop that is plain
// HTTP, an address or names not the project's own, tables weaker than
// frisket's floor, a second Docker route, and a name the session would answer
// with the project's address that some route is for.
func TestBuildRefusesABadDockerRoute(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wildcard := func(p *policy.Policy, host string) {
		p.Allow = append(p.Allow, host)
		p.Routes = append(p.Routes, policy.Route{Name: "w", Host: host, Upstream: "https://" + host,
			Paths: []policy.PathRule{{Methods: []string{"GET"}, Prefix: "/"}}})
	}
	for name, mutate := range map[string]func(*policy.Policy){
		"a credential file": func(p *policy.Policy) { p.Routes[0].CredentialFile = token },
		"a placeholder":     func(p *policy.Policy) { p.Routes[0].Placeholder = "x" },
		"a header":          func(p *policy.Policy) { p.Routes[0].Header = "X-Registry-Auth" },
		"a basic user":      func(p *policy.Policy) { p.Routes[0].BasicUser = "u" },
		"a JSON credential": func(p *policy.Policy) { p.Routes[0].CredentialJSON = &policy.CredentialJSON{Token: "t"} },
		"a session key": func(p *policy.Policy) {
			p.Routes[0].SessionKey = &policy.SessionKey{PublicKey: sessionKeyPEM(t), Issuer: "i"}
		},
		"an upstream CA":    func(p *policy.Policy) { p.Routes[0].UpstreamCA = token },
		"no docker block":   func(p *policy.Policy) { p.Routes[0].Docker = nil },
		"unmatched ask":     func(p *policy.Policy) { p.Routes[0].Unmatched = "ask" },
		"a graphql scope":   func(p *policy.Policy) { p.Routes[0].GraphQL = []policy.GraphQLRule{{}} },
		"a git scope":       func(p *policy.Policy) { p.Routes[0].Git = &policy.GitRule{} },
		"a docker on https": func(p *policy.Policy) { p.Routes[0].Upstream = "https://docker.frisket.internal" },
		"an IPv6 address":   func(p *policy.Policy) { p.Routes[0].Docker.Address = "::1" },
		"a padded address":  func(p *policy.Policy) { p.Routes[0].Docker.Address = "127.101.170.0171" },
		"another's address": func(p *policy.Policy) { p.Routes[0].Docker.Address = "127.10.146.214" },
		"a port past 65535": func(p *policy.Policy) { p.Routes[0].Docker.Ports = []int{65536 + 64320} },
		"a port of 80":      func(p *policy.Policy) { p.Routes[0].Docker.Ports = []int{80} },
		"names under .docker": func(p *policy.Policy) {
			p.Routes[0].Docker.Names = []string{"shop.docker", "shop.example.docker"}
		},
		"a table weaker than the floor": func(p *policy.Policy) {
			p.Routes[0].Docker.Bodies["ExecCreate"] = json.RawMessage(`{"Privileged": "any"}`)
		},
		"a table frisket has no floor for": func(p *policy.Policy) {
			p.Routes[0].Docker.Bodies["ContainerUpdate"] = json.RawMessage(`{}`)
		},
		"two Docker routes": func(p *policy.Policy) {
			other := dockerPolicy(t).Routes[0]
			other.Name, other.Host = "docker2", "docker2.frisket.internal"
			p.Allow = append(p.Allow, other.Host)
			p.Routes = append(p.Routes, other)
		},
		"a name under a wildcard route":       func(p *policy.Policy) { wildcard(p, "*.internal") },
		"a long name under a wildcard route":  func(p *policy.Policy) { wildcard(p, "*.example.internal") },
		"a name that is a route's host":       func(p *policy.Policy) { wildcard(p, "shop.internal") },
		"a long name that is a route's host":  func(p *policy.Policy) { wildcard(p, "shop.example.internal") },
		"a name that is a route's, spelt big": func(p *policy.Policy) { wildcard(p, "Shop.Internal.") },
	} {
		p := dockerPolicy(t)
		mutate(&p)
		if err := check(t, "p", p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A query check is a name, or a list under filters or enum, and nothing
// else; and it is written back as it was read.
func TestAQueryCheckIsANameOrAList(t *testing.T) {
	for _, bad := range []string{`"filters"`, `"enum"`, `{}`, `{"filters":["a"],"enum":["b"]}`, `{"filters":["a"],"x":1}`, `1`, `["a"]`} {
		var q policy.QueryCheck
		if err := json.Unmarshal([]byte(bad), &q); err == nil {
			t.Errorf("%s was read as %+v", bad, q)
		}
	}
	for _, good := range []string{`"bool"`, `{"filters":["label","name"]}`, `{"enum":["not-running","removed"]}`} {
		var q policy.QueryCheck
		if err := json.Unmarshal([]byte(good), &q); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
		if got := string(mustJSON(t, q)); got != good {
			t.Errorf("%s was written back as %s", good, got)
		}
	}
	if !strings.Contains(string(mustJSON(t, dockerPolicy(t))), `"filters":{"filters":["label"`) {
		t.Error("a document's filters check was not written as a list")
	}
}

// A session reaches each of its project's ports at 127.0.0.1, at the
// project's own address and at ::1, in that order, port by port; a document
// with no Docker route steers nothing for a relay.
func TestRelayDestinationsAreEachPortOnBothLoopbacksAndTheProjectsAddress(t *testing.T) {
	p := dockerPolicy(t)
	p.Routes[0].Docker.Ports = []int{64320, 64321}
	var got []string
	for _, d := range p.RelayDestinations() {
		got = append(got, d.String())
	}
	want := []string{
		"127.0.0.1:64320", "127.101.170.171:64320", "[::1]:64320",
		"127.0.0.1:64321", "127.101.170.171:64321", "[::1]:64321",
	}
	if !slices.Equal(got, want) {
		t.Errorf("relay destinations = %v, want %v", got, want)
	}
	if got := valid(t).RelayDestinations(); len(got) != 0 {
		t.Errorf("a document with no Docker route relays %v", got)
	}
	p.Routes[0].Docker.Ports = nil
	if got := p.RelayDestinations(); len(got) != 0 {
		t.Errorf("a Docker route with no ports relays %v", got)
	}
}

// A session's handlers say which project it is, at which address, and what
// its ruleset steers for the relay: what the daemon keeps projects apart by
// and answers open with. A session with no Docker route says nothing.
func TestASessionsHandlersCarryItsDockerProject(t *testing.T) {
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}
	log := slog.New(slog.NewJSONHandler(&journal{}, nil))
	p := dockerPolicy(t)
	h, err := open(t, &counting{}, "p", p).Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if h.Docker == nil {
		t.Fatal("a session with a Docker route has no Docker project")
	}
	if h.Docker.Project != "example/shop" || h.Docker.Address != netip.MustParseAddr("127.101.170.171") ||
		!slices.Equal(h.Docker.Relay, p.RelayDestinations()) {
		t.Errorf("docker = %+v", *h.Docker)
	}
	h, err = open(t, &counting{}, "p", valid(t)).Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if h.Docker != nil {
		t.Errorf("a session with no Docker route has %+v", *h.Docker)
	}
}

// A built session with shop's route answers shop's names with its
// address, though its allowlist names only the route's host, and asks the
// upstream nothing; another project's name is refused as any name is.
func TestADockerSessionAnswersItsOwnNames(t *testing.T) {
	up := &counting{}
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	h, err := open(t, up, "p", dockerPolicy(t)).Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, slog.New(slog.NewJSONHandler(&journal{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"shop.internal.", "Shop.example.internal."} {
		m := ask(t, h, name)
		if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 101, 170, 171} {
			t.Errorf("%s answered %+v, want 127.101.170.171", name, m.Answers)
		}
	}
	if m := ask(t, h, "billing.internal."); m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("another project's name answered %v", m.RCode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.asked) != 0 {
		t.Errorf("upstream was asked %v", up.asked)
	}
}

// steerOne sends one connection through a real steer.Session to the
// session's Dispatch, as if the ruleset had steered it to orig, and returns
// the lines logged under msg once there is one.
func steerOne(t *testing.T, h serve.Handlers, svc []netip.Addr, orig netip.AddrPort, j *journal, msg string) map[string]any {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	s := steer.New("s", j)
	s.Dst = func(*net.TCPConn) netip.AddrPort { return orig }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, serve.Dispatch{Service: svc, Handlers: h})
	}()
	defer func() { cancel(); <-done }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadAll(c)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if lines := linesOf(t, j, msg); len(lines) == 1 {
			return lines[0]
		} else if len(lines) > 1 || time.Now().After(deadline) {
			t.Fatalf("%d %s lines for one connection", len(lines), msg)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func linesOf(t *testing.T, j *journal, msg string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(raw, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// A session with a Docker route is given a relay for its project's address
// and ports, which asks the route's own socket before it dials: here the
// daemon reports no container, and the connection is refused with no dial.
// A session without one has no relay, and loopback that reached it anyway
// goes to egress, which refuses it.
func TestADockerSessionRelaysThroughItsRoutesSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "frisket-policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix socket here: %v", err)
	}
	var asked atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.56/containers/json" {
			asked.Add(1)
		}
		_, _ = io.WriteString(w, "[]")
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}
	var j journal
	log := slog.New(slog.NewJSONHandler(&j, nil))
	p := dockerPolicy(t)
	p.Routes[0].Upstream = "unix://" + sock
	h, err := open(t, &counting{}, "p", p).Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	rl, ok := h.Relay.(*relay.Handler)
	if !ok {
		t.Fatalf("a Docker session's relay is %T", h.Relay)
	}
	if rl.Project != "example/shop" || rl.Address != netip.MustParseAddr("127.101.170.171") ||
		!slices.Equal(rl.Ports, []uint16{64320, 64321, 64322}) || rl.APIVersion != "1.56" || rl.Idle != 0 {
		t.Errorf("relay = %+v", *rl)
	}
	line := steerOne(t, h, svc, netip.MustParseAddrPort("127.0.0.1:64320"), &j, "relay")
	if line["decision"] != relay.DecisionRefused || line["reason"] != relay.ReasonNotPublished {
		t.Errorf("relay line %v", line)
	}
	if asked.Load() != 1 {
		t.Errorf("the route's socket was asked %d times, want once", asked.Load())
	}

	var j2 journal
	h, err = open(t, &counting{}, "p", valid(t)).Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, slog.New(slog.NewJSONHandler(&j2, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if h.Relay != nil {
		t.Fatalf("a session with no Docker route has relay %v", h.Relay)
	}
	line = steerOne(t, h, svc, netip.MustParseAddrPort("127.0.0.1:64320"), &j2, "egress")
	if line["decision"] != egress.DecisionRefused || !strings.Contains(line["reason"].(string), "loopback") {
		t.Errorf("loopback with no relay: %v", line)
	}
}
