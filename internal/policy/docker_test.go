package policy

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
)

// dockerPolicy is a session's document with data-lab's Docker route, as
// chase writes it: every Engine operation, and the body tables.
func dockerPolicy(t *testing.T) Policy {
	t.Helper()
	var paths []PathRule
	if err := json.Unmarshal(readFile(t, "../intercept/testdata/engine-operations.json"), &paths); err != nil {
		t.Fatal(err)
	}
	var bodies map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, "../docker/testdata/fields.json"), &bodies); err != nil {
		t.Fatal(err)
	}
	return Policy{
		Allow: []string{"docker.frisket.internal"},
		Routes: []Route{{
			Name:      "docker",
			Host:      "docker.frisket.internal",
			Upstream:  "unix:///run/user/1000/docker.sock",
			Unmatched: "refuse",
			Refusal:   &Refusal{ContentType: "application/json", Body: `{"message":"{{message}}"}`},
			Paths:     paths,
			Docker: &DockerRoute{
				Project:     "triptease/data-lab",
				APIVersions: APIVersions{Min: "1.55", Max: "1.56", Unversioned: []string{"/_ping"}},
				Images:      []string{"postgres:18", "docker.io/library/postgres:18"},
				Address:     "127.1.191.78",
				Ports:       []int{64320, 64321, 64322},
				Names:       []string{"data-lab.internal", "data-lab.triptease.internal"},
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
		Route{Name: "gce", Host: "metadata.google.internal", Upstream: "https://metadata.google.internal",
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
		Route{Name: "frisket", Host: "*.frisket.internal", Upstream: "https://*.frisket.internal",
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
		// frisket/docker's name, not data-lab's.
		Route{Name: "other", Host: "docker.internal", Upstream: "https://docker.internal",
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
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
	wildcard := func(p *Policy, host string) {
		p.Allow = append(p.Allow, host)
		p.Routes = append(p.Routes, Route{Name: "w", Host: host, Upstream: "https://" + host,
			Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}})
	}
	for name, mutate := range map[string]func(*Policy){
		"a credential file": func(p *Policy) { p.Routes[0].CredentialFile = token },
		"a placeholder":     func(p *Policy) { p.Routes[0].Placeholder = "x" },
		"a header":          func(p *Policy) { p.Routes[0].Header = "X-Registry-Auth" },
		"a basic user":      func(p *Policy) { p.Routes[0].BasicUser = "u" },
		"a JSON credential": func(p *Policy) { p.Routes[0].CredentialJSON = &CredentialJSON{Token: "t"} },
		"a session key":     func(p *Policy) { p.Routes[0].SessionKey = &SessionKey{PublicKey: sessionKeyPEM(t), Issuer: "i"} },
		"an upstream CA":    func(p *Policy) { p.Routes[0].UpstreamCA = token },
		"no docker block":   func(p *Policy) { p.Routes[0].Docker = nil },
		"unmatched ask":     func(p *Policy) { p.Routes[0].Unmatched = "ask" },
		"a graphql scope":   func(p *Policy) { p.Routes[0].GraphQL = []GraphQLRule{{}} },
		"a git scope":       func(p *Policy) { p.Routes[0].Git = &GitRule{} },
		"a docker on https": func(p *Policy) { p.Routes[0].Upstream = "https://docker.frisket.internal" },
		"an IPv6 address":   func(p *Policy) { p.Routes[0].Docker.Address = "::1" },
		"a padded address":  func(p *Policy) { p.Routes[0].Docker.Address = "127.001.191.78" },
		"another's address": func(p *Policy) { p.Routes[0].Docker.Address = "127.6.18.253" },
		"a port past 65535": func(p *Policy) { p.Routes[0].Docker.Ports = []int{65536 + 64320} },
		"a port of 80":      func(p *Policy) { p.Routes[0].Docker.Ports = []int{80} },
		"names under .docker": func(p *Policy) {
			p.Routes[0].Docker.Names = []string{"data-lab.docker", "data-lab.triptease.docker"}
		},
		"a table weaker than the floor": func(p *Policy) {
			p.Routes[0].Docker.Bodies["ExecCreate"] = json.RawMessage(`{"Privileged": "any"}`)
		},
		"a table frisket has no floor for": func(p *Policy) {
			p.Routes[0].Docker.Bodies["ContainerUpdate"] = json.RawMessage(`{}`)
		},
		"two Docker routes": func(p *Policy) {
			other := dockerPolicy(t).Routes[0]
			other.Name, other.Host = "docker2", "docker2.frisket.internal"
			p.Allow = append(p.Allow, other.Host)
			p.Routes = append(p.Routes, other)
		},
		"a name under a wildcard route":       func(p *Policy) { wildcard(p, "*.internal") },
		"a long name under a wildcard route":  func(p *Policy) { wildcard(p, "*.triptease.internal") },
		"a name that is a route's host":       func(p *Policy) { wildcard(p, "data-lab.internal") },
		"a long name that is a route's host":  func(p *Policy) { wildcard(p, "data-lab.triptease.internal") },
		"a name that is a route's, spelt big": func(p *Policy) { wildcard(p, "Data-Lab.Internal.") },
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
		var q QueryCheck
		if err := json.Unmarshal([]byte(bad), &q); err == nil {
			t.Errorf("%s was read as %+v", bad, q)
		}
	}
	for _, good := range []string{`"bool"`, `{"filters":["label","name"]}`, `{"enum":["not-running","removed"]}`} {
		var q QueryCheck
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
		"127.0.0.1:64320", "127.1.191.78:64320", "[::1]:64320",
		"127.0.0.1:64321", "127.1.191.78:64321", "[::1]:64321",
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
	if h.Docker.Project != "triptease/data-lab" || h.Docker.Address != netip.MustParseAddr("127.1.191.78") ||
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
