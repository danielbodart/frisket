package intercept

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"pgregory.net/rapid"
)

// namedUpstream is a fake real host answering TLS as whatever name it is
// asked for, under a CA of its own, and the dialler that reaches it for any
// name -- saying which name and port frisket dialled.
type namedUpstream struct {
	*upstream
	ca     *CA
	mu     sync.Mutex
	dialed []string
}

func newNamedUpstream(t *testing.T, suffix string) *namedUpstream {
	t.Helper()
	ca, err := NewCA([]string{suffix})
	if err != nil {
		t.Fatal(err)
	}
	n := &namedUpstream{ca: ca}
	u := &upstream{}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.Clone(context.Background()))
		u.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "upstream says hello")
	}))
	u.EnableHTTP2 = true
	u.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return ca.Leaf(h.ServerName) }}
	u.StartTLS()
	t.Cleanup(u.Close)
	n.upstream = u
	return n
}

func (n *namedUpstream) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(n.ca.Certificate())
	return p
}

func (n *namedUpstream) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, n.Listener.Addr().String())
}

func (n *namedUpstream) lastDialed() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.dialed) == 0 {
		return ""
	}
	return n.dialed[len(n.dialed)-1]
}

func newNamedFixture(t *testing.T, j *journal, up *namedUpstream, routes ...Route) *fixture {
	t.Helper()
	return newFixtureWith(t, j, Config{
		Routes:      routes,
		Log:         slog.New(slog.NewJSONHandler(j, nil)),
		Policy:      "test-policy",
		DialContext: up.dial,
	})
}

// A WILDCARD ROUTE SERVES EVERY NAME BELOW ITS SUFFIX, at any depth, each as
// the name the client asked for: that name's leaf, that name upstream,
// verified as that name. A name's exact route wins over it, and the nearest
// wildcard above a name wins over one further up.
func TestAWildcardRouteServesEachNameAsTheNameAsked(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newNamedUpstream(t, "wild.test")
		cred, _ := tokenFile(t, j, realToken)
		f := newNamedFixture(t, j, up,
			Route{
				Name: "wild", Host: "*.wild.test", Upstream: "https://*.wild.test:8443", UpstreamCAs: up.pool(),
				Credential: cred, Inject: Bearer(), Placeholder: placeholder,
				Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
			},
			Route{
				Name: "mtls", Host: "*.mtls.wild.test", Upstream: "https://*.mtls.wild.test", UpstreamCAs: up.pool(),
				Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/", Refuse: true}}},
			},
			Route{
				Name: "only", Host: "only.wild.test", Upstream: "https://only.wild.test:8443", UpstreamCAs: up.pool(),
				Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/only"}}},
			},
		)
		c := f.client(t, h2)

		for _, name := range []string{"storage.wild.test", "eu.rep.wild.test", "a.b.c.d.wild.test"} {
			res, body := get(t, c, newRequest(t, "GET", "https://"+name+"/v1/x", nil))
			if res.StatusCode != 200 || body != "upstream says hello" {
				t.Fatalf("%s: %d %q", name, res.StatusCode, body)
			}
			seen := up.requests()
			last := seen[len(seen)-1]
			if last.TLS.ServerName != name || last.Host != name+":8443" || last.Header.Get("Authorization") != "Bearer "+realToken {
				t.Errorf("%s reached the upstream as SNI %q, Host %q, Authorization %q", name, last.TLS.ServerName, last.Host, last.Header.Get("Authorization"))
			}
			if got := up.lastDialed(); got != name+":8443" {
				t.Errorf("%s was dialled at %q", name, got)
			}
		}

		before := len(up.requests())
		for name, path := range map[string]string{"iam.mtls.wild.test": "/v1/x", "a.b.mtls.wild.test": "/v1/x", "only.wild.test": "/v1/x"} {
			if res, _ := get(t, c, newRequest(t, "GET", "https://"+name+path, nil)); res.StatusCode != http.StatusForbidden {
				t.Errorf("%s%s: %d, want the nearer route's refusal", name, path, res.StatusCode)
			}
		}
		if res, _ := get(t, c, newRequest(t, "GET", "https://only.wild.test/only", nil)); res.StatusCode != 200 {
			t.Errorf("the exact route's own scope: %d", res.StatusCode)
		}
		if seen := up.requests(); len(seen) != before+1 || seen[before].Header.Get("Authorization") != sandboxAuth {
			t.Errorf("the exact route, which has no credential, sent %d requests", len(seen)-before)
		}

		hosts := map[string]bool{}
		for _, l := range j.lines(t, "request") {
			hosts[l["host"].(string)+" "+l["route"].(string)] = true
		}
		for _, want := range []string{"eu.rep.wild.test wild", "a.b.mtls.wild.test mtls", "only.wild.test only"} {
			if !hosts[want] {
				t.Errorf("no request line for %s: %v", want, hosts)
			}
		}
	})
}

// The suffix itself is not below it, and a name that merely ends in it is not
// either: neither is served.
func TestAWildcardDoesNotServeItsSuffixOrALookalike(t *testing.T) {
	j := &journal{}
	up := newNamedUpstream(t, "wild.test")
	cred, _ := tokenFile(t, j, realToken)
	f := newNamedFixture(t, j, up, Route{
		Name: "wild", Host: "*.wild.test", Upstream: "https://*.wild.test", UpstreamCAs: up.pool(),
		Credential: cred, Inject: Bearer(), Placeholder: placeholder,
		Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
	})
	for _, name := range []string{"wild.test", "evil-wild.test", "wild.test.evil"} {
		if c, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: f.roots(), ServerName: name}); err == nil {
			c.Close()
			t.Errorf("a handshake for %s completed", name)
		}
	}
	for _, l := range j.waitLines(t, "tls", 3) {
		if l["decision"] != DecisionRefused || l["reason"] != ReasonUnknownName {
			t.Errorf("tls line: %v", l)
		}
	}
	if len(up.requests()) != 0 {
		t.Fatal("a refused handshake reached the upstream")
	}
}

// One connection, one name, under a wildcard too: its handshake chose the
// name the request goes to, and a request for another -- even one the same
// route serves -- is sent back with 421.
func TestARequestForAnotherNameOnAWildcardConnectionIsMisdirected(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newNamedUpstream(t, "wild.test")
		cred, _ := tokenFile(t, j, realToken)
		f := newNamedFixture(t, j, up, Route{
			Name: "wild", Host: "*.wild.test", Upstream: "https://*.wild.test", UpstreamCAs: up.pool(),
			Credential: cred, Inject: Bearer(), Placeholder: placeholder,
			Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}},
		})
		req := newRequest(t, "GET", "https://a.wild.test/v1", nil)
		req.Host = "b.wild.test"
		if res, _ := get(t, f.client(t, h2), req); res.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("got %d, want 421", res.StatusCode)
		}
		if len(up.requests()) != 0 {
			t.Fatal("a misdirected request reached the upstream")
		}
		if l := j.waitLines(t, "request", 1)[0]; l["reason"] != ReasonMisdirected || l["host"] != "a.wild.test" {
			t.Errorf("request line: %v", l)
		}
	})
}

func TestNewRefusesBadWildcardRoutes(t *testing.T) {
	cred, _ := tokenFile(t, &journal{}, realToken)
	good := Route{Name: "r", Host: "*.a.test", Upstream: "https://*.a.test", Credential: cred, Inject: Bearer(), Placeholder: placeholder,
		Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/"}}}}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for name, mutate := range map[string]func(r *Route){
		"every name":                          func(r *Route) { r.Host = "*" },
		"a star inside":                       func(r *Route) { r.Host = "a.*.test" },
		"a star glued on":                     func(r *Route) { r.Host = "*a.test" },
		"two stars":                           func(r *Route) { r.Host = "**.a.test" },
		"an upstream of another name":         func(r *Route) { r.Upstream = "https://a.test" },
		"an upstream of another suffix":       func(r *Route) { r.Upstream = "https://*.b.test" },
		"an upstream wildcard further up":     func(r *Route) { r.Upstream = "https://*.test" },
		"an upstream with a path":             func(r *Route) { r.Upstream = "https://*.a.test/v1" },
		"a plain-HTTP upstream":               func(r *Route) { r.Upstream = "http://*.a.test" },
		"an exact route to a wildcard":        func(r *Route) { r.Host = "x.a.test" },
		"an exact route to a wildcard's port": func(r *Route) { r.Host = "x.a.test"; r.Upstream = "https://*.a.test:8443" },
	} {
		r := good
		mutate(&r)
		if ic, err := New(Config{Routes: []Route{r}, Log: log}); err == nil {
			_ = ic.Close()
			t.Errorf("%s: built, want a refusal", name)
		}
	}
	if ic, err := New(Config{Routes: []Route{good, good}, Log: log}); err == nil {
		_ = ic.Close()
		t.Error("two routes for one wildcard: built, want a refusal")
	}
	exact := good
	exact.Host, exact.Upstream = "a.test", "https://a.test"
	sub := good
	sub.Host, sub.Upstream = "*.x.a.test", "https://*.x.a.test:8443"
	ic, err := New(Config{Routes: []Route{good, exact, sub}, Log: log})
	if err != nil {
		t.Fatalf("a wildcard, its suffix and a wildcard below it: %v", err)
	}
	_ = ic.Close()
}

// THE ROUTE FOR A NAME IS ITS OWN, OR THE NEAREST WILDCARD ABOVE IT, and
// nothing else: never the wildcard's suffix itself, never a name that is not
// a name.
func TestLookupIsExactThenTheNearestWildcard(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		label := rapid.SampledFrom([]string{"a", "b", "c"})
		name := func(t *rapid.T, what string, min int) string {
			return strings.Join(rapid.SliceOfN(label, min, 4).Draw(t, what), ".")
		}
		i := &Interceptor{routes: map[string]*route{}, wild: map[string]*route{}}
		for _, n := range rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return name(t, "exact", 1) }), 0, 4).Draw(t, "exacts") {
			i.routes[n] = &route{host: n}
		}
		for _, n := range rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return name(t, "suffix", 1) }), 0, 4).Draw(t, "suffixes") {
			i.wild[n] = &route{host: "*." + n, wild: true}
		}
		q := name(t, "query", 1)

		var want *route
		if r, ok := i.routes[q]; ok {
			want = r
		} else {
			best := ""
			for s, r := range i.wild {
				if strings.HasSuffix(q, "."+s) && len(s) > len(best) {
					best, want = s, r
				}
			}
		}
		if got := i.lookup(q); got != want {
			t.Fatalf("lookup(%q) = %v, want %v", q, got, want)
		}
		for _, bad := range []string{"." + q, "x.." + q, q + ".", q + ":443", "*." + q, ""} {
			if r := i.lookup(bad); r != nil {
				t.Fatalf("lookup(%q) = %v, for what is not a name", bad, r)
			}
		}
	})
}
