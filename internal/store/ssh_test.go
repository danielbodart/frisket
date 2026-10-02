package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/serve"
	"github.com/danielbodart/frisket/internal/steer"
	"github.com/danielbodart/frisket/policy"
)

// hostKey is a machine's public key as a document pins it.
func hostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// withSSH is a valid policy with one SSH route, whose agent is nowhere: a
// document is built without it.
func withSSH(t *testing.T) policy.Policy {
	t.Helper()
	p := valid(t)
	p.SSH = []policy.SSHRoute{{
		Name:     "server",
		Address:  "10.0.0.5",
		User:     "core",
		HostKeys: []string{hostKey(t)},
		Agent:    "/nonexistent/agent.sock",
		Exec:     []policy.ExecRule{{Command: "uptime"}},
	}}
	return p
}

// An SSH route is held to the rest of its document: its name is never a
// name the session answers with an address, and its address never one the
// ruleset steers to frisket for something else.
func TestSSHRoutesAreCheckedAgainstTheRestOfTheirDocument(t *testing.T) {
	if err := check(t, "p", withSSH(t)); err != nil {
		t.Fatalf("a valid document with an SSH route was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*policy.Policy)
		want   string
	}{
		{"a name that is an intercepted host", func(p *policy.Policy) { p.SSH[0].Name = "api.test" }, "api.test"},
		{"a name under a wildcard route", func(p *policy.Policy) {
			p.Routes = append(p.Routes, policy.Route{Name: "cdn", Host: "*.cdn.test", Upstream: "https://*.cdn.test", Paths: []policy.PathRule{{Methods: []string{"GET"}, Prefix: "/"}}})
			p.SSH[0].Name = "box.cdn.test"
		}, "*.cdn.test"},
		{"the dummy's address", func(p *policy.Policy) { p.SSH[0].Address = "192.0.2.1" }, "frisket's own"},
		{"the service address", func(p *policy.Policy) { p.SSH[0].Address = "192.0.2.2:22" }, "frisket's own"},
		{"the service's v6 address", func(p *policy.Policy) { p.SSH[0].Address = "[2001:db8::2]:2222" }, "frisket's own"},
		{"port 53", func(p *policy.Policy) { p.SSH[0].Address = "10.0.0.5:53" }, "DNS"},
		{"a name", func(p *policy.Policy) { p.SSH[0].Address = "server.lan" }, "never a name"},
		{"two routes at one destination", func(p *policy.Policy) {
			r := p.SSH[0]
			r.Name, r.Address = "again", "10.0.0.5:22"
			p.SSH = append(p.SSH, r)
		}, "route server's too"},
		{"two routes of one name", func(p *policy.Policy) {
			r := p.SSH[0]
			r.Address = "10.0.0.6"
			p.SSH = append(p.SSH, r)
		}, "another route's"},
		{"a route with no rule admitting anything", func(p *policy.Policy) {
			p.SSH[0].Exec, p.SSH[0].Unmatched = nil, "refuse"
		}, "refuses every command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withSSH(t)
			tc.mutate(&p)
			err := check(t, "p", p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// A Docker route's names and its project's address are the session's, and
// an SSH route takes neither.
func TestAnSSHRouteStaysClearOfTheDockerRoute(t *testing.T) {
	route := func(name, address string) policy.Policy {
		p := dockerPolicy(t)
		p.SSH = []policy.SSHRoute{{Name: name, Address: address, User: "core", HostKeys: []string{hostKey(t)}, Agent: "/run/user/1000/gcr/ssh"}}
		return p
	}
	if err := check(t, "p", route("server", "10.0.0.5")); err != nil {
		t.Fatalf("an SSH route beside a Docker route was refused: %v", err)
	}
	if err := check(t, "p", route("shop.example.internal", "10.0.0.5")); err == nil || !strings.Contains(err.Error(), "shop.example.internal") {
		t.Errorf("an SSH route named as the project: err = %v", err)
	}
	if err := check(t, "p", route("server", "127.101.170.171:2222")); err == nil {
		t.Error("an SSH route at the project's address was accepted")
	}
}

// Checking a document reads neither the agent's socket nor a key file:
// both are the serving machine's, and a build has neither.
func TestAnSSHRouteIsCheckedWithoutItsAgentOrKeyFile(t *testing.T) {
	p := withSSH(t)
	if err := check(t, "p", p); err != nil {
		t.Fatalf("checked with an agent that is nowhere: %v", err)
	}
	p.SSH[0].Agent, p.SSH[0].KeyFile = "", "/nonexistent/id_ed25519"
	if err := check(t, "p", p); err != nil {
		t.Fatalf("checked with a key file that is nowhere: %v", err)
	}
}

// handshake is the sandbox's ssh reaching route at orig, trusting only the
// CA in knownHosts, as /etc/frisket/ssh_known_hosts says.
func handshake(t *testing.T, h serve.SSHHandler, orig netip.AddrPort, knownHosts []byte) error {
	t.Helper()
	marker, _, ca, _, rest, err := ssh.ParseKnownHosts(knownHosts)
	if err != nil || marker != "cert-authority" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("known_hosts %q: marker %q, err %v", knownHosts, marker, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeConn(context.Background(), &steer.Conn{TCPConn: server.(*net.TCPConn), Session: "s", ID: 1, Orig: orig})
	}()
	defer func() { _ = client.Close(); <-done }()
	checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool { return bytes.Equal(k.Marshal(), ca.Marshal()) }}
	conn, _, _, err := ssh.NewClientConn(client, "server:22", &ssh.ClientConfig{User: "agent", HostKeyCallback: checker.CheckHostKey, Timeout: 10 * time.Second})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// A session with SSH routes is given a handler for them, the destinations
// its ruleset steers, and the sandbox's two files. Its SSH CA is derived
// from its TLS CA, so restored from its record it is the CA the sandbox
// already trusts; another session's is another CA.
func TestASessionsSSHCAComesFromItsTLSCAAndSurvivesARestore(t *testing.T) {
	pol := open(t, &counting{}, "p", withSSH(t))
	log := slog.New(slog.NewJSONHandler(&journal{}, nil))
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	h, err := pol.Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort("10.0.0.5:22")
	if h.SSH == nil || h.SSHRoutes == nil {
		t.Fatal("a session with an SSH route has no SSH handler")
	}
	if got := h.SSHRoutes.Destinations; len(got) != 1 || got[0] != dst {
		t.Errorf("destinations %v, want %s", got, dst)
	}
	if !h.SSH.Steers(dst) || h.SSH.Steers(netip.MustParseAddrPort("10.0.0.5:2222")) {
		t.Error("the handler does not steer exactly the route's address and port")
	}
	if want := "Host server\n\tHostName 10.0.0.5\n\tPort 22\n\tUser core\n"; string(h.SSHRoutes.Config) != want {
		t.Errorf("ssh_config %q, want %q", h.SSHRoutes.Config, want)
	}
	if err := handshake(t, h.SSH, dst, h.SSHRoutes.KnownHosts); err != nil {
		t.Fatalf("the sandbox does not trust its own route: %v", err)
	}

	again, err := pol.Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, h.Authority, log)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.SSHRoutes.KnownHosts, h.SSHRoutes.KnownHosts) {
		t.Error("a restored session has an SSH CA its sandbox does not trust")
	}
	if err := handshake(t, again.SSH, dst, h.SSHRoutes.KnownHosts); err != nil {
		t.Errorf("a restored session's route is not trusted by what its sandbox was given: %v", err)
	}

	other, err := pol.Handlers(control.Session{Name: "s2", Policy: "/p.json", Service: svc}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.SSHRoutes.KnownHosts, h.SSHRoutes.KnownHosts) {
		t.Error("two sessions share an SSH CA")
	}
	if err := handshake(t, other.SSH, dst, h.SSHRoutes.KnownHosts); err == nil {
		t.Error("one session's sandbox trusts another session's route")
	}
}

// A session with no SSH route has neither the handler nor the files.
func TestASessionWithNoSSHRouteHasNoSSHHandler(t *testing.T) {
	pol := open(t, &counting{}, "p", valid(t))
	h, err := pol.Handlers(control.Session{Name: "s", Policy: "/p.json", Service: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}, nil, slog.New(slog.NewJSONHandler(&journal{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if h.SSH != nil || h.SSHRoutes != nil {
		t.Errorf("SSH %v, routes %+v", h.SSH, h.SSHRoutes)
	}
}
