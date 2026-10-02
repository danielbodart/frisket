package sshroute

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/policy"
)

func rsaSigner(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func goodRoute(t *testing.T) policy.SSHRoute {
	t.Helper()
	return policy.SSHRoute{
		Name:     "server",
		Address:  "10.0.0.5",
		User:     "dan",
		HostKeys: []string{authorized(newSigner(t).PublicKey()) + " root@server"},
		Agent:    "/run/user/1000/gcr/ssh",
	}
}

func TestARouteCompilesToItsAddressAtPort22ByDefault(t *testing.T) {
	routes, err := Compile([]policy.SSHRoute{goodRoute(t)}, Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	if got := routes[0].Address; got != netip.MustParseAddrPort("10.0.0.5:22") {
		t.Errorf("address %s", got)
	}
	if d := routes[0].Decide("ls"); d.Rule != intercept.RuleUnmatched || d.Outcome != intercept.Ask {
		t.Errorf("an SSH route with no rules asks by default, got %+v", d)
	}
}

// Every way a document can be wrong about a route is refused when it is
// built, naming the field: a route frisket half-understood is a rule that
// does not apply.
func TestARouteIsRefusedNamingWhatIsWrong(t *testing.T) {
	cert := func() string {
		ca, host := newSigner(t), newSigner(t)
		c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
		if err := c.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return authorized(c)
	}
	reserved := Reserved{
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("127.77.1.9")},
		Hosts: []string{"api.github.com", "*.internal"},
	}
	for _, tc := range []struct {
		name string
		edit func(*policy.SSHRoute)
		want string
	}{
		{"an empty name", func(r *policy.SSHRoute) { r.Name = "" }, "name"},
		{"an upper-case name", func(r *policy.SSHRoute) { r.Name = "Server" }, "name"},
		{"a name with a space", func(r *policy.SSHRoute) { r.Name = "my server" }, "name"},
		{"a name that is an address", func(r *policy.SSHRoute) { r.Name = "10.0.0.5" }, "is an address"},
		{"a name that is an intercepted host", func(r *policy.SSHRoute) { r.Name = "api.github.com" }, "api.github.com"},
		{"a name under a wildcard route", func(r *policy.SSHRoute) { r.Name = "db.internal" }, "*.internal"},
		{"a host name for an address", func(r *policy.SSHRoute) { r.Address = "server.lan" }, "never a name"},
		{"an address with a zone", func(r *policy.SSHRoute) { r.Address = "fd00::5%eth0" }, "zone"},
		{"a mapped address", func(r *policy.SSHRoute) { r.Address = "[::ffff:10.0.0.5]:22" }, "as IPv4"},
		{"the unspecified address", func(r *policy.SSHRoute) { r.Address = "0.0.0.0" }, "unspecified"},
		{"loopback", func(r *policy.SSHRoute) { r.Address = "127.0.0.1:22" }, "loopback"},
		{"v6 loopback", func(r *policy.SSHRoute) { r.Address = "::1" }, "loopback"},
		{"the metadata service", func(r *policy.SSHRoute) { r.Address = "169.254.169.254" }, "link-local"},
		{"v6 link-local", func(r *policy.SSHRoute) { r.Address = "fe80::1" }, "link-local"},
		{"multicast", func(r *policy.SSHRoute) { r.Address = "224.0.0.1" }, "multicast"},
		{"broadcast", func(r *policy.SSHRoute) { r.Address = "255.255.255.255" }, "broadcast"},
		{"port 0", func(r *policy.SSHRoute) { r.Address = "10.0.0.5:0" }, "port 0"},
		{"port 53", func(r *policy.SSHRoute) { r.Address = "10.0.0.5:53" }, "port 53"},
		{"the service address", func(r *policy.SSHRoute) { r.Address = "192.0.2.2" }, "frisket's own"},
		{"the v6 service address", func(r *policy.SSHRoute) { r.Address = "[2001:db8::2]:2222" }, "frisket's own"},
		{"the Docker project's address", func(r *policy.SSHRoute) { r.Address = "127.77.1.9" }, "loopback"},
		{"no user", func(r *policy.SSHRoute) { r.User = "" }, "user"},
		{"a user with a space", func(r *policy.SSHRoute) { r.User = "dan b" }, "user"},
		{"a user with a quote", func(r *policy.SSHRoute) { r.User = `o"ps` }, "user"},
		{"a user with a token", func(r *policy.SSHRoute) { r.User = "a%b" }, "user"},
		{"a user with a comment", func(r *policy.SSHRoute) { r.User = "a#b" }, "user"},
		{"a user that is an option", func(r *policy.SSHRoute) { r.User = "-oProxyCommand" }, "user"},
		{"a user with a control character", func(r *policy.SSHRoute) { r.User = "dan\x00" }, "user"},
		{"a user longer than a login name", func(r *policy.SSHRoute) { r.User = strings.Repeat("d", maxUser+1) }, "user"},
		{"no host keys", func(r *policy.SSHRoute) { r.HostKeys = nil }, "no hostKeys"},
		{"a host key that is not one", func(r *policy.SSHRoute) { r.HostKeys = []string{"ssh-ed25519 notbase64"} }, "hostKeys[0]"},
		{"a known_hosts line with its host", func(r *policy.SSHRoute) {
			r.HostKeys = []string{"10.0.0.5 " + authorized(newSigner(t).PublicKey())}
		}, "no host"},
		{"a cert-authority marker", func(r *policy.SSHRoute) {
			r.HostKeys = []string{"@cert-authority * " + authorized(newSigner(t).PublicKey())}
		}, "hostKeys[0]"},
		{"two keys on one line", func(r *policy.SSHRoute) {
			r.HostKeys = []string{authorized(newSigner(t).PublicKey()) + "\n" + authorized(newSigner(t).PublicKey())}
		}, "one line"},
		{"a certificate", func(r *policy.SSHRoute) { r.HostKeys = []string{cert()} }, "certificate"},
		{"a key listed twice", func(r *policy.SSHRoute) { r.HostKeys = append(r.HostKeys, r.HostKeys[0]) }, "twice"},
		{"agent and key file", func(r *policy.SSHRoute) { r.KeyFile = "/home/dan/.ssh/id_ed25519" }, "more than one of agent, keyFile and passwordFile"},
		{"agent and password file", func(r *policy.SSHRoute) { r.PasswordFile = "/run/secrets/p" }, "more than one of"},
		{"key file and password file", func(r *policy.SSHRoute) {
			r.Agent, r.KeyFile, r.PasswordFile = "", "/home/dan/.ssh/id_ed25519", "/run/secrets/p"
		}, "more than one of"},
		{"none", func(r *policy.SSHRoute) { r.Agent = "" }, "nothing to log in with"},
		{"a relative password file", func(r *policy.SSHRoute) { r.Agent, r.PasswordFile = "", "secrets/p" }, "passwordFile"},
		{"an identity with a password file", func(r *policy.SSHRoute) {
			r.Agent, r.PasswordFile, r.Identity = "", "/run/secrets/p", "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
		}, "identity with passwordFile"},
		{"env names on a shell route", func(r *policy.SSHRoute) { r.Shell, r.Env = true, []string{"LANG"} }, "shell route"},
		{"a relative agent", func(r *policy.SSHRoute) { r.Agent = "gcr/ssh" }, "agent"},
		{"an unclean key file", func(r *policy.SSHRoute) { r.Agent, r.KeyFile = "", "/home/dan/../dan/.ssh/id" }, "keyFile"},
		{"an identity that is not a fingerprint", func(r *policy.SSHRoute) { r.Identity = "MD5:aa:bb" }, "identity"},
		{"an unmatched that is neither", func(r *policy.SSHRoute) { r.Unmatched = "allow" }, "unmatched"},
		{"a rule that asks and refuses", func(r *policy.SSHRoute) { r.Exec = []policy.ExecRule{{Command: "ls", Ask: true, Refuse: true}} }, "both"},
		{"a rule listed twice", func(r *policy.SSHRoute) { r.Exec = []policy.ExecRule{{Command: "ls"}, {Command: "ls", Refuse: true}} }, "twice"},
		{"a bad pattern", func(r *policy.SSHRoute) { r.Exec = []policy.ExecRule{{Command: "ls;"}} }, "exec rule"},
		{"an assignment first", func(r *policy.SSHRoute) { r.Exec = []policy.ExecRule{{Command: "LD_PRELOAD=x **"}} }, "assignment"},
		{"an arg rule that admits", func(r *policy.SSHRoute) { r.Exec = []policy.ExecRule{{Arg: "*.log"}} }, "only asks or refuses"},
		{"an arg rule listed twice", func(r *policy.SSHRoute) {
			r.Exec = []policy.ExecRule{{Arg: ".ssh", Refuse: true}, {Arg: ".ssh", Ask: true}}
		}, `"[arg .ssh]" is listed twice`},
		{"an operation with no summary", func(r *policy.SSHRoute) {
			r.Exec = []policy.ExecRule{{Command: "ls", Operation: &policy.Operation{ID: "ls"}}}
		}, "id and a summary"},
		{"only asking arg rules under refuse", func(r *policy.SSHRoute) {
			r.Unmatched, r.Exec = "refuse", []policy.ExecRule{{Arg: ".ssh", Ask: true}}
		}, "refuses every command"},
		{"no rules under refuse", func(r *policy.SSHRoute) { r.Unmatched = "refuse" }, "refuses every command"},
		{"an env name that changes what runs", func(r *policy.SSHRoute) { r.Env = []string{"PATH"} }, `env[0] "PATH"`},
		{"only refusing rules under refuse", func(r *policy.SSHRoute) {
			r.Unmatched, r.Exec = "refuse", []policy.ExecRule{{Command: "rm **", Refuse: true}}
		}, "refuses every command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := goodRoute(t)
			tc.edit(&r)
			_, err := Compile([]policy.SSHRoute{r}, reserved)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error saying %q", err, tc.want)
			}
		})
	}
}

func TestTwoRoutesMayNotShareANameOrAnAddress(t *testing.T) {
	a, b := goodRoute(t), goodRoute(t)
	b.Address = "10.0.0.6"
	if _, err := Compile([]policy.SSHRoute{a, b}, Reserved{}); err == nil || !strings.Contains(err.Error(), "another route's") {
		t.Errorf("same name: %v", err)
	}
	b.Name, b.Address = "other", "10.0.0.5:22"
	if _, err := Compile([]policy.SSHRoute{a, b}, Reserved{}); err == nil || !strings.Contains(err.Error(), "route server's too") {
		t.Errorf("same address: %v", err)
	}
	b.Address = "10.0.0.5:2222"
	if _, err := Compile([]policy.SSHRoute{a, b}, Reserved{}); err != nil {
		t.Errorf("another port is another route: %v", err)
	}
}

// The upstream is asked for the pinned keys' algorithms and no others: a
// machine that also has a key nobody pinned must present the one that is.
func TestTheHostKeyAlgorithmsAreThePinnedKeysOwn(t *testing.T) {
	_, rsaKey := rsaSigner(t)
	for _, tc := range []struct {
		name string
		keys []ssh.PublicKey
		want []string
	}{
		{"ed25519", []ssh.PublicKey{newSigner(t).PublicKey()}, []string{ssh.KeyAlgoED25519}},
		{"ecdsa", []ssh.PublicKey{newECDSASigner(t).PublicKey()}, []string{ssh.KeyAlgoECDSA256}},
		{"rsa, SHA-2 first and SHA-1 last", []ssh.PublicKey{rsaKey, newSigner(t).PublicKey()},
			[]string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoED25519, ssh.KeyAlgoRSA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := goodRoute(t)
			r.HostKeys = nil
			for _, k := range tc.keys {
				r.HostKeys = append(r.HostKeys, authorized(k))
			}
			routes, err := Compile([]policy.SSHRoute{r}, Reserved{})
			if err != nil {
				t.Fatal(err)
			}
			if got := routes[0].algorithms; !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// Compile opens nothing: frisket check runs where neither the agent nor the
// key file exists.
func TestCompilingNeverTouchesTheCredential(t *testing.T) {
	r := goodRoute(t)
	r.Agent = "/nonexistent/agent.sock"
	if _, err := Compile([]policy.SSHRoute{r}, Reserved{}); err != nil {
		t.Errorf("agent: %v", err)
	}
	r.Agent, r.KeyFile = "", "/nonexistent/id_ed25519"
	if _, err := Compile([]policy.SSHRoute{r}, Reserved{}); err != nil {
		t.Errorf("key file: %v", err)
	}
}

// A login name is let through as it is: ssh_config writes it unquoted, and
// these are all a name it reads as one word.
func TestALoginNameIsAnyUserSSHConfigReadsAsOneWord(t *testing.T) {
	for _, user := range []string{"core", "dan.bodart", "svc_deploy", "git-ro", "dan@CORP.EXAMPLE", "_admin", "1000"} {
		r := goodRoute(t)
		r.User = user
		routes, err := Compile([]policy.SSHRoute{r}, Reserved{})
		if err != nil {
			t.Errorf("%s: %v", user, err)
			continue
		}
		if want := "\tUser " + user + "\n"; !strings.Contains(string(SSHConfig(routes)), want) {
			t.Errorf("%s: ssh_config %q", user, SSHConfig(routes))
		}
	}
}

// longestRoutes are as many routes as a document may have, each as long as
// it may be written: the most Open's answer can carry for them.
func longestRoutes(t *testing.T, n int) []policy.SSHRoute {
	t.Helper()
	key := authorized(newSigner(t).PublicKey())
	out := make([]policy.SSHRoute, n)
	for i := range out {
		out[i] = policy.SSHRoute{
			Name:     fmt.Sprintf("%03d", i) + strings.Repeat("a", maxName-3),
			Address:  fmt.Sprintf("[fdff:ffff:ffff:ffff:ffff:ffff:ffff:%04x]:65535", i),
			User:     strings.Repeat("u", maxUser),
			HostKeys: []string{key},
			Agent:    "/run/user/1000/gcr/ssh",
		}
	}
	return out
}

func TestADocumentWithMoreRoutesThanASessionMayHaveIsRefused(t *testing.T) {
	if _, err := Compile(longestRoutes(t, maxRoutes), Reserved{}); err != nil {
		t.Fatalf("%d routes: %v", maxRoutes, err)
	}
	_, err := Compile(longestRoutes(t, maxRoutes+1), Reserved{})
	if err == nil || !strings.HasPrefix(err.Error(), "ssh: ") {
		t.Errorf("%d routes: err = %v, want one naming ssh", maxRoutes+1, err)
	}
}

// Open answers with every route's Host block and destination in one control
// message, and the bound on routes is what keeps that answer whole: a
// document check passes must not fail at launch for its answer's length.
func TestOpensAnswerForTheMostRoutesADocumentMayHaveFitsOneControlMessage(t *testing.T) {
	routes, err := Compile(longestRoutes(t, maxRoutes), Reserved{})
	if err != nil {
		t.Fatal(err)
	}
	_, ca := rsaSigner(t)
	resp := control.Response{
		// More than any CA certificate a session is given, in PEM.
		CACert:        make([]byte, 4<<10),
		SSHKnownHosts: KnownHosts(ca),
		SSHConfig:     SSHConfig(routes),
	}
	for _, r := range routes {
		resp.Relay = append(resp.Relay, r.Address.String())
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > control.MaxMessage {
		t.Errorf("Open's answer for %d routes is %d bytes, more than the %d a control message holds", maxRoutes, len(b), control.MaxMessage)
	}
}
