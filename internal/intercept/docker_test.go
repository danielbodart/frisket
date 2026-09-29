package intercept

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/internal/credential"
	"github.com/danielbodart/frisket/internal/docker"
)

const (
	dockerHost    = "docker.frisket.internal"
	dockerProject = "triptease/data-lab"
	execID        = "38f66d86a5c74f0d7e5401fe2675d4b1a7556ea7aa1c4f6cb8cf40b7aafc1ab2"
	containerID   = "fdd16f31d6ce54c159845ce34fa35e5a4a7f37cd3852bdb712190bd34cf3bf7e"
)

// engineRules are chase's rules for Engine API 1.56, as it generates them
// from moby's spec: every operation, the admitted ones with their docker
// blocks and the rest refused.
func engineRules(t testing.TB) []PathRule {
	t.Helper()
	b, err := os.ReadFile("testdata/engine-operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw []struct {
		Methods   []string
		Path      string
		Refuse    bool
		Operation *Operation
		Docker    *struct {
			Owned   string
			Param   int
			Query   map[string]json.RawMessage
			Body    string
			Upgrade string
		}
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var rules []PathRule
	for _, r := range raw {
		rule := PathRule{Methods: r.Methods, Path: r.Path, Refuse: r.Refuse, Operation: r.Operation}
		if d := r.Docker; d != nil {
			rule.Docker = &DockerRule{Owned: d.Owned, Param: d.Param, Body: d.Body, Upgrade: d.Upgrade}
			for k, q := range d.Query {
				if rule.Docker.Query == nil {
					rule.Docker.Query = map[string]QueryCheck{}
				}
				var name string
				if json.Unmarshal(q, &name) == nil {
					rule.Docker.Query[k] = QueryCheck{Check: name}
					continue
				}
				var obj struct{ Filters, Enum []string }
				if err := json.Unmarshal(q, &obj); err != nil {
					t.Fatal(err)
				}
				c := QueryCheck{Check: "filters", Filters: obj.Filters}
				if obj.Enum != nil {
					c = QueryCheck{Check: "enum", Enum: obj.Enum}
				}
				rule.Docker.Query[k] = c
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// engineTables are chase's body tables, compiled against frisket's floor.
func engineTables(t testing.TB) map[string]*docker.Table {
	t.Helper()
	b, err := os.ReadFile("../docker/testdata/fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]*docker.Table{}
	for name, r := range raw {
		tb, err := docker.Compile(name, r)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = tb
	}
	return out
}

// newUnixUpstream is data-lab's Docker route, to the daemon at socket.
func newUnixUpstream(t testing.TB, socket string) Route {
	t.Helper()
	return Route{
		Name:     "docker",
		Host:     dockerHost,
		Upstream: "unix://" + socket,
		Refusal:  &Refusal{ContentType: "application/json", Body: `{"message":"{{message}}"}`},
		Scope:    Scope{Paths: engineRules(t)},
		Docker: &DockerRoute{
			Project:     dockerProject,
			APIVersions: APIVersions{Min: "1.55", Max: "1.56", Unversioned: []string{"/_ping"}},
			Images:      []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18"},
			Address:     docker.Address(dockerProject),
			Ports:       []uint16{64320, 64321},
			Names:       docker.Names(dockerProject),
			MaxBody:     256 << 10,
			Bodies:      engineTables(t),
		},
	}
}

// dockerFixture is frisket serving data-lab's Docker route, with an egress
// dialer that fails the test if anything asks it for a connection: the
// socket is dialled by the route's own transport, and by nothing else.
func dockerFixture(t *testing.T, routes ...Route) (*fixture, *daemon, *journal) {
	t.Helper()
	d := newDaemon(t)
	j := &journal{}
	if len(routes) == 0 {
		routes = []Route{newUnixUpstream(t, d.socket)}
	}
	f := newFixtureWith(t, j, Config{
		Routes: routes,
		Log:    slog.New(slog.NewJSONHandler(j, nil)),
		Policy: "test-policy",
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			t.Errorf("the egress dialer was asked for %s %s", network, addr)
			return nil, errors.New("not this dialer")
		},
	})
	return f, d, j
}

func dockerRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+dockerHost+target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func (f *fixture) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	return get(t, f.client(t, false), req)
}

// refusedFor asserts a refusal, in the route's own JSON shape, for reason.
func refusedFor(t *testing.T, res *http.Response, body, reason string) {
	t.Helper()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", res.StatusCode, body)
	}
	var m struct{ Message string }
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("refusal is not the route's JSON: %q", body)
	}
	if !strings.Contains(m.Message, reason) {
		t.Fatalf("refusal %q does not say %q", m.Message, reason)
	}
}

// The route's requests reach the daemon over its socket, addressed to
// "docker", with the version they were sent with; its own transport dials
// the socket, and the egress dialer is never asked.
func TestADockerRouteIsServedOverItsOwnSocket(t *testing.T) {
	f, d, j := dockerFixture(t)
	res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/version", nil))
	if res.StatusCode != http.StatusOK || body != "{}" {
		t.Fatalf("status %d, body %q", res.StatusCode, body)
	}
	seen := d.requests()
	if len(seen) != 1 || seen[0].path != "/v1.55/version" || seen[0].host != "docker" {
		t.Fatalf("the daemon saw %+v", seen)
	}
	line := j.waitLines(t, "request", 1)[0]
	if line["api"] != "1.55" || line["operation"] != "SystemVersion" || line["decision"] != DecisionAllowed {
		t.Fatalf("logged %v", line)
	}
}

// The handshake for a Docker route offers HTTP/1.1 alone: a client that will
// speak only h2 is not served, and one that offers both is given HTTP/1.1.
func TestADockerRouteIsHTTP1Only(t *testing.T) {
	f, d, _ := dockerFixture(t)
	if _, err := f.client(t, true).Do(dockerRequest(t, "GET", "/v1.55/version", nil)); err == nil {
		t.Fatal("an h2-only client was served")
	}
	conn, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: f.roots(), ServerName: dockerHost, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q", got)
	}
	if len(d.requests()) != 0 {
		t.Fatal("something reached the daemon")
	}
}

// A request names a version the route allows, spelt exactly, or is one of
// the few paths asked with none. Anything that looks like a version to any
// reading of it, and is not one of the route's, spelt as the route spells
// it, is refused; so is any escape at all.
func TestTheAPIVersionIsTheRoutesExactly(t *testing.T) {
	f, d, _ := dockerFixture(t)
	for _, target := range []string{"/v1.55/version", "/v1.56/version", "/_ping", "/v1.55/_ping"} {
		res, body := f.do(t, dockerRequest(t, "GET", target, nil))
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d: %s", target, res.StatusCode, body)
		}
	}
	res, _ := f.do(t, dockerRequest(t, "HEAD", "/_ping", nil))
	if res.StatusCode != http.StatusOK {
		t.Errorf("HEAD /_ping: status %d", res.StatusCode)
	}
	before := len(d.requests())
	for target, reason := range map[string]string{
		"/v1.54/version":     ReasonAPIVersion,
		"/v1.57/version":     ReasonAPIVersion,
		"/V1.55/version":     ReasonAPIVersion,
		"/v1.055/version":    ReasonAPIVersion,
		"/v1.55.0/version":   ReasonAPIVersion,
		"/v1.55./version":    ReasonAPIVersion,
		"/v1.55;x/version":   ReasonAPIVersion,
		"/v/version":         ReasonAPIVersion,
		"/v2.1/version":      ReasonAPIVersion,
		"/v1.55/vers%69on":   ReasonBadPath,
		"/%761.55/version":   ReasonBadPath,
		"/v1.55/_ping%2F":    ReasonBadPath,
		"/containers/json":   ReasonUnversioned,
		"/version":           ReasonUnversioned,
		"/_ping/":            ReasonUnversioned,
		"/v1.55/nonexistent": ReasonOutOfScope,
	} {
		res, body := f.do(t, dockerRequest(t, "GET", target, nil))
		refusedFor(t, res, body, reason)
	}
	if n := len(d.requests()); n != before {
		t.Fatalf("%d refused requests reached the daemon", n-before)
	}
}

// Only the keys a rule lists, each once; a list's filters only by the keys it
// allows, and narrowed to the project's label; and what goes upstream is the
// query frisket re-encoded.
func TestAQueryIsTheRulesKeysOnceEach(t *testing.T) {
	f, d, _ := dockerFixture(t)
	for _, target := range []string{
		"/v1.55/containers/json?all=1&all=1",
		"/v1.55/containers/json?all=1&frisket=1",
		"/v1.55/containers/json?all=yes",
		"/v1.55/containers/json?limit=1e3",
		"/v1.55/containers/json?filters=" + url.QueryEscape(`{"before":{"x":true}}`),
		"/v1.55/containers/json?filters=" + url.QueryEscape(`{"label":{"x":1}}`),
		"/v1.55/containers/json?filters=[1]",
		"/v1.55/containers/json?all=1;size=1",
		"/v1.55/version?x=1",
	} {
		res, body := f.do(t, dockerRequest(t, "GET", target, nil))
		refusedFor(t, res, body, docker.ReasonQuery)
	}
	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the daemon", n)
	}

	filters := url.QueryEscape(`{"label":{"com.docker.compose.project=frisket-capture":true},"name":["db"]}`)
	for target, want := range map[string]map[string]map[string]bool{
		"/v1.55/containers/json?all=1&filters=" + filters: {
			"label": {"com.docker.compose.project=frisket-capture": true, "frisket.project=" + dockerProject: true},
			"name":  {"db": true},
		},
		"/v1.56/containers/json": {"label": {"frisket.project=" + dockerProject: true}},
	} {
		res, body := f.do(t, dockerRequest(t, "GET", target, nil))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, res.StatusCode, body)
		}
		seen := d.requests()
		q, err := url.ParseQuery(seen[len(seen)-1].query)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]map[string]bool
		if err := json.Unmarshal([]byte(q.Get("filters")), &got); err != nil {
			t.Fatalf("%s: filters %q", target, q.Get("filters"))
		}
		if b1, _ := json.Marshal(got); string(b1) != string(mustMarshal(t, want)) {
			t.Errorf("%s: filters %s, want %s", target, b1, mustMarshal(t, want))
		}
		if strings.Contains(target, "all=1") && q.Get("all") != "1" {
			t.Errorf("%s: all went as %q", target, q.Get("all"))
		}
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An operation that takes no body is sent none: not a form, which moby would
// read as more query, and not a chunked one. An empty /start, which carries
// no Content-Type at all, passes.
func TestAnOperationThatTakesNoBodyIsSentNone(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.container(containerID, "data-lab-db-1", dockerProject)

	form := dockerRequest(t, "POST", "/v1.55/images/create?fromImage=postgres&tag=18", strings.NewReader("fromSrc=-"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, body := f.do(t, form)
	refusedFor(t, res, body, ReasonNoBody)

	chunked := dockerRequest(t, "POST", "/v1.55/containers/"+containerID+"/start", io.MultiReader(strings.NewReader("x")))
	res, body = f.do(t, chunked)
	refusedFor(t, res, body, ReasonNoBody)

	json := dockerRequest(t, "POST", "/v1.55/containers/"+containerID+"/stop", strings.NewReader("{}"))
	json.Header.Set("Content-Type", "application/json")
	res, body = f.do(t, json)
	refusedFor(t, res, body, ReasonNoBody)
	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the daemon", n)
	}

	res, body = f.do(t, dockerRequest(t, "POST", "/v1.55/containers/"+containerID+"/start", nil))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an empty /start: status %d: %s", res.StatusCode, body)
	}
	seen := d.requests()
	if len(seen) != 1 || seen[0].body != "" || seen[0].header.Get("Content-Type") != "" {
		t.Fatalf("the daemon saw %+v", seen)
	}
}

// Only the protocol a rule names is switched to: never on an operation that
// names none, and never h2c or a websocket, even where tcp is allowed.
func TestAnUpgradeIsOnlyTheRulesOwn(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.container(containerID, "data-lab-db-1", dockerProject)
	d.exec(execID, containerID)

	inspect := dockerRequest(t, "GET", "/v1.55/containers/"+containerID+"/json", nil)
	inspect.Header.Set("Connection", "Upgrade")
	inspect.Header.Set("Upgrade", "tcp")
	res, body := f.do(t, inspect)
	refusedFor(t, res, body, ReasonUpgrade)

	for _, up := range []string{"h2c", "websocket", "tcp, h2c"} {
		start := dockerRequest(t, "POST", "/v1.55/exec/"+execID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`))
		start.Header.Set("Content-Type", "application/json")
		start.Header.Set("Connection", "Upgrade")
		start.Header.Set("Upgrade", up)
		if up == "h2c" {
			start.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
		}
		res, body := f.do(t, start)
		refusedFor(t, res, body, ReasonUpgrade)
	}
	// Two Upgrade lines, even of tcp and one other, and a Connection that
	// asks to upgrade with no Upgrade to say to what, are both refused.
	twice := dockerRequest(t, "POST", "/v1.55/exec/"+execID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`))
	twice.Header.Set("Content-Type", "application/json")
	twice.Header.Set("Connection", "Upgrade")
	twice.Header["Upgrade"] = []string{"tcp", "h2c"}
	res, body = f.do(t, twice)
	refusedFor(t, res, body, ReasonUpgrade)
	bare := dockerRequest(t, "POST", "/v1.55/exec/"+execID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`))
	bare.Header.Set("Content-Type", "application/json")
	bare.Header.Set("Connection", "Upgrade")
	res, body = f.do(t, bare)
	refusedFor(t, res, body, ReasonUpgrade)

	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the daemon", n)
	}

	start := dockerRequest(t, "POST", "/v1.55/exec/"+execID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`))
	start.Header.Set("Content-Type", "application/json")
	start.Header.Set("Connection", "Upgrade")
	start.Header.Set("Upgrade", "tcp")
	res, body = f.do(t, start)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ExecStart with Upgrade: tcp: status %d: %s", res.StatusCode, body)
	}
	if seen := d.requests(); len(seen) != 1 || seen[0].header.Get("Upgrade") != "tcp" {
		t.Fatalf("the daemon saw %+v", seen)
	}
}

// A pull is of one listed image, however the client spells it: fromImage
// with its tag, or fromImage tagged and no tag. Never every tag, never a tag
// twice, and never an import.
func TestAPullIsOfOneListedImage(t *testing.T) {
	f, d, j := dockerFixture(t)
	for i, q := range []string{
		"fromImage=postgres&tag=18",
		"fromImage=postgres%3A18",
		"fromImage=docker.io%2Flibrary%2Fpostgres&tag=18",
		"fromImage=library%2Fpostgres%3A18&platform=linux%2Famd64",
	} {
		res, body := f.do(t, dockerRequest(t, "POST", "/v1.55/images/create?"+q, nil))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", q, res.StatusCode, body)
		}
		if got := d.requests()[i].query; got != mustReencode(t, q) {
			t.Errorf("%s went as %s", q, got)
		}
	}
	for q, reason := range map[string]string{
		"fromImage=postgres&tag=17":                    ReasonImage,
		"fromImage=postgres":                           ReasonImage,
		"fromImage=postgres%3A18&tag=18":               ReasonImage,
		"fromImage=postgres&tag=18&tag=18":             docker.ReasonQuery,
		"fromImage=postgres&tag=18&fromSrc=-":          docker.ReasonQuery,
		"fromSrc=-&repo=postgres&tag=18":               docker.ReasonQuery,
		"tag=18":                                       ReasonImage,
		"fromImage=localhost%3A5000%2Fpostgres&tag=18": ReasonImage,
		"fromImage=Postgres&tag=18":                    ReasonImage,
	} {
		res, body := f.do(t, dockerRequest(t, "POST", "/v1.55/images/create?"+q, nil))
		refusedFor(t, res, body, reason)
	}
	if n := len(d.requests()); n != 4 {
		t.Fatalf("%d requests reached the daemon, want 4", n)
	}
	for _, l := range j.lines(t, "request") {
		if l["operation"] != "ImageCreate" {
			t.Errorf("logged %v", l)
		}
	}
}

// A pull whose fromImage already carries a tag, and that gives a tag too, is
// refused as a tag given twice, even where the reference the two make is
// listed: moby would replace fromImage's tag, not pull what was listed.
func TestAPullNeverGivesATagTwice(t *testing.T) {
	f, d, j := dockerFixture(t)
	digest := "sha256:" + strings.Repeat("0123456789abcdef", 4)
	rt := f.ic.routes[dockerHost].docker
	rt.Images = append(slices.Clone(rt.Images), "postgres:18@"+digest)
	res, body := f.do(t, dockerRequest(t, "POST", "/v1.55/images/create?fromImage=postgres%3A18&tag="+digest, nil))
	refusedFor(t, res, body, ReasonImage)
	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d requests reached the daemon", n)
	}
	lines := j.lines(t, "request")
	if len(lines) != 1 || !strings.Contains(fmt.Sprint(lines[0]["docker"]), "tagged twice") {
		t.Fatalf("logged %v, want a tag given twice", lines)
	}
}

func mustReencode(t *testing.T, q string) string {
	t.Helper()
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	return v.Encode()
}

// An image is named in a path by the route's own string for it, exactly.
func TestAnInspectedImageIsListedExactly(t *testing.T) {
	f, d, _ := dockerFixture(t)
	res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/images/postgres:18/json?manifests=1", nil))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	for _, target := range []string{"/v1.55/images/Postgres:18/json", "/v1.55/images/postgres:18./json", "/v1.55/images/alpine:3/json"} {
		res, body := f.do(t, dockerRequest(t, "GET", target, nil))
		refusedFor(t, res, body, ReasonImage)
	}
	// Several segments are not one "*": moby would read them as one name.
	res, body = f.do(t, dockerRequest(t, "GET", "/v1.55/images/docker.io/library/postgres:18/json", nil))
	refusedFor(t, res, body, ReasonOutOfScope)
	if n := len(d.requests()); n != 1 {
		t.Fatalf("%d requests reached the daemon, want 1", n)
	}
}

// The daemon's Api-Version is capped at the route's highest, so a client
// negotiating down from _ping speaks no newer than the rules; an older one
// stands.
func TestTheDaemonsVersionIsCappedAtTheRoutes(t *testing.T) {
	f, _, _ := dockerFixture(t)
	res, _ := f.do(t, dockerRequest(t, "HEAD", "/_ping", nil))
	if got := res.Header.Get("Api-Version"); got != "1.56" {
		t.Fatalf("_ping said %q", got)
	}
	res, _ = f.do(t, dockerRequest(t, "GET", "/v1.55/version", nil))
	if got := res.Header.Get("Api-Version"); got != "1.40" {
		t.Fatalf("version said %q", got)
	}
}

// A JSON body goes upstream re-encoded and as application/json, whatever the
// client's headers said: a Connection naming Content-Type strips the
// client's before frisket sees what goes out, and a body re-encoded is sent
// without the client's Content-Encoding.
func TestAReencodedBodyIsSentAsJSON(t *testing.T) {
	f, d, j := dockerFixture(t)
	req := dockerRequest(t, "POST", "/v1.55/volumes/create", strings.NewReader(`{"Name": "", "Labels": {"a": "b"}}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Content-Encoding", "identity")
	req.Header.Set("Connection", "Content-Type")
	res, body := f.do(t, req)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	seen := d.requests()
	if len(seen) != 1 {
		t.Fatalf("the daemon saw %+v", seen)
	}
	if got := seen[0].header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q", got)
	}
	if got := seen[0].header.Values("Content-Encoding"); len(got) != 0 {
		t.Errorf("Content-Encoding %q", got)
	}
	want := `{"Labels":{"a":"b","frisket.project":"triptease/data-lab"},"Name":""}`
	if seen[0].body != want {
		t.Errorf("body %s, want %s", seen[0].body, want)
	}
	if line := j.waitLines(t, "request", 1)[0]; line["docker"] != "stamped" || line["operation"] != "VolumeCreate" {
		t.Errorf("logged %v", line)
	}
}

// A body is judged only as JSON, framed as JSON, and within maxBody.
func TestABodyIsJSONFramedAsJSON(t *testing.T) {
	f, d, _ := dockerFixture(t)
	for name, c := range map[string]struct {
		body, contentType, encoding, reason string
	}{
		"gzip":         {`{}`, "application/json", "gzip", docker.ReasonBody},
		"text":         {`{}`, "text/plain", "", docker.ReasonBody},
		"no type":      {`{}`, "", "", docker.ReasonBody},
		"empty":        {``, "application/json", "", docker.ReasonUnreadable},
		"twice":        {`{"Name":"a","Name":"b"}`, "application/json", "", docker.ReasonUnreadable},
		"over maxBody": {`{"Labels":{"a":"` + strings.Repeat("x", 256<<10) + `"}}`, "application/json", "", docker.ReasonBody},
		"privileged":   {`{"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}`, "application/json", "", docker.ReasonBody},
	} {
		req := dockerRequest(t, "POST", "/v1.55/volumes/create", strings.NewReader(c.body))
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		if c.encoding != "" {
			req.Header.Set("Content-Encoding", c.encoding)
		}
		res, body := f.do(t, req)
		if res.StatusCode != http.StatusForbidden || !strings.Contains(body, c.reason) {
			t.Errorf("%s: status %d: %s", name, res.StatusCode, body)
		}
	}
	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the daemon", n)
	}
}

// A refusal tells the client frisket's reason and the operation, and, for a
// body, the table's own path; what the request held goes to the log alone.
func TestARefusalHoldsNothingTheRequestSent(t *testing.T) {
	f, _, j := dockerFixture(t)
	const mark = "zqxmarkzqx"
	for _, req := range []*http.Request{
		dockerRequest(t, "GET", "/v1.55/containers/json?"+mark+"=1", nil),
		dockerRequest(t, "GET", "/v1.55/containers/json?filters="+url.QueryEscape(`{"`+mark+`":["x"]}`), nil),
		dockerRequest(t, "GET", "/v1.55/images/"+mark+":1/json", nil),
		dockerRequest(t, "POST", "/v1.55/images/create?fromImage="+mark+"&tag=1", nil),
		dockerRequest(t, "GET", "/v1."+mark+"/version", nil),
		func() *http.Request {
			r := dockerRequest(t, "POST", "/v1.55/volumes/create", strings.NewReader(`{"`+mark+`":1}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}(),
		func() *http.Request {
			r := dockerRequest(t, "POST", "/v1.55/containers/create", strings.NewReader(`{"Image":"`+mark+`:1","HostConfig":{"NetworkMode":"none"}}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}(),
		func() *http.Request {
			r := dockerRequest(t, "GET", "/v1.55/containers/"+containerID+"/json", nil)
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", mark)
			return r
		}(),
	} {
		res, body := f.do(t, req)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d: %s", req.URL, res.StatusCode, body)
		}
		if strings.Contains(body, mark) {
			t.Errorf("%s: the refusal says %s", req.URL, body)
		}
	}
	lines := j.waitLines(t, "request", 8)
	quoted := 0
	for _, l := range lines {
		if d, _ := l["docker"].(string); strings.Contains(d, mark) {
			quoted++
		}
	}
	if quoted == 0 {
		t.Errorf("no log line says what was refused:\n%s", j.String())
	}
}

// The object a path names is taken as the client sent it, not as the scope
// read it: a name differing only in case, or by a trailing dot, is its own
// name, asked about as itself; and what goes upstream in its place is the
// full ID the daemon gave for it.
func TestAnObjectIsNamedByItsOwnSegment(t *testing.T) {
	f, d, _ := dockerFixture(t)
	names := []string{"MyDB.", "mydb", "JSON", "Create.", "Prune"}
	for i, name := range names {
		d.container(strings.Repeat(fmt.Sprintf("%x", i+1), 64), name, dockerProject)
	}
	d.container(containerID, "data-lab-db-1", dockerProject)
	for i, name := range names {
		res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/containers/"+name+"/json", nil))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", name, res.StatusCode, body)
		}
		seen := d.requests()
		if got, want := seen[len(seen)-1].path, "/v1.55/containers/"+strings.Repeat(fmt.Sprintf("%x", i+1), 64)+"/json"; got != want {
			t.Errorf("%s went as %s, want %s", name, got, want)
		}
		if asked := d.lookups(); asked[len(asked)-1].path != "/v1.56/containers/"+name+"/json" {
			t.Errorf("%s was asked about as %q", name, asked[len(asked)-1].path)
		}
	}
	res, body := f.do(t, dockerRequest(t, "POST", "/v1.56/containers/data-lab-db-1/stop?t=10", nil))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	seen := d.requests()
	if last := seen[len(seen)-1]; last.path != "/v1.56/containers/"+containerID+"/stop" || last.query != "t=10" {
		t.Errorf("went as %s?%s", last.path, last.query)
	}
	for _, bad := range []string{"-x", "a:b", "a;b", strings.Repeat("a", 256)} {
		res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/containers/"+bad+"/json", nil))
		refusedFor(t, res, body, ReasonParam)
	}
	res, body = f.do(t, dockerRequest(t, "GET", "/v1.55/exec/"+strings.ToUpper(execID)+"/json", nil))
	refusedFor(t, res, body, ReasonParam)
}

// A daemon that cannot be reached is a 502, and neither it nor the log line
// says where its socket is.
func TestAnUnreachableDaemonIsA502WithoutItsPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "frisket-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "gone.sock")
	f, _, j := dockerFixture(t, newUnixUpstream(t, socket))
	res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/version", nil))
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	j.waitLines(t, "request", 1)
	if strings.Contains(body, dir) || strings.Contains(j.String(), dir) {
		t.Fatalf("the socket's path was said:\n%s\n%s", body, j.String())
	}
}

// Every rule chase generates admits its own operation's requests whatever
// name fills its "*": no refusing rule, read leniently -- folded to lower
// case, its trailing dots gone -- outranks it for a name that differs from
// a refused operation's literal only in its spelling.
func TestNoRefusedOperationOutranksAnAdmittedOneByFolding(t *testing.T) {
	rules := engineRules(t)
	c, err := compileScope(Scope{Paths: rules})
	if err != nil {
		t.Fatal(err)
	}
	var literals []string
	for _, r := range rules {
		for seg := range strings.SplitSeq(r.Path[1:], "/") {
			if seg != wildcard {
				literals = append(literals, seg)
			}
		}
	}
	for _, r := range rules {
		if r.Refuse {
			continue
		}
		segs := strings.Split(r.Path[1:], "/")
		for i, seg := range segs {
			if seg != wildcard {
				continue
			}
			for _, lit := range literals {
				for _, name := range []string{strings.ToUpper(lit), lit + ".", strings.ToUpper(lit) + "..", "X" + lit} {
					filled := append([]string(nil), segs...)
					filled[i] = name
					for _, m := range r.Methods {
						u := &url.URL{Path: "/" + strings.Join(filled, "/")}
						v := c.decide(m, u)
						if v.deferred == nil || v.Operation == nil || v.Operation.ID != r.Operation.ID {
							t.Errorf("%s %s is %v (%s), not %s", m, u.Path, v.Outcome, v.Reason, r.Operation.ID)
						}
					}
				}
			}
		}
	}
}

// The route is refused whole where it could be a way round what it is for.
func TestNewRefusesBadDockerRoutes(t *testing.T) {
	socket := "/run/user/1000/docker.sock"
	rule := func(r *Route, id string) *PathRule {
		for i := range r.Scope.Paths {
			if r.Scope.Paths[i].Operation.ID == id {
				return &r.Scope.Paths[i]
			}
		}
		t.Fatalf("no rule %s", id)
		return nil
	}
	valid := newUnixUpstream(t, socket)
	if _, err := New(Config{Routes: []Route{valid}, Log: slog.New(slog.DiscardHandler)}); err != nil {
		t.Fatalf("a valid Docker route was refused: %v", err)
	}
	for name, mutate := range map[string]func(r *Route) []Route{
		"a unix upstream with a host":     func(r *Route) []Route { r.Upstream = "unix://host" + socket; return nil },
		"a unix upstream with a query":    func(r *Route) []Route { r.Upstream += "?x=1"; return nil },
		"a unix upstream with a fragment": func(r *Route) []Route { r.Upstream += "#x"; return nil },
		"a relative unix upstream":        func(r *Route) []Route { r.Upstream = "unix:docker.sock"; return nil },
		"an unclean unix upstream":        func(r *Route) []Route { r.Upstream = "unix:///run/user/../docker.sock"; return nil },
		"an escaped unix upstream":        func(r *Route) []Route { r.Upstream = "unix:///run/docker%2Esock"; return nil },
		"a unix upstream with a user":     func(r *Route) []Route { r.Upstream = "unix://u@" + socket; return nil },
		"a credential": func(r *Route) []Route {
			r.Credential, r.Inject, r.Placeholder = staticSecret("t"), Bearer(), placeholder
			return nil
		},
		"an upstream CA":          func(r *Route) []Route { r.UpstreamCAs = x509.NewCertPool(); return nil },
		"a wildcard":              func(r *Route) []Route { r.Host = "*.frisket.internal"; return nil },
		"no docker block":         func(r *Route) []Route { r.Docker = nil; return nil },
		"a docker block on https": func(r *Route) []Route { r.Upstream = "https://docker.example.test"; return nil },
		"a docker rule on https": func(r *Route) []Route {
			r.Upstream, r.Docker = "https://docker.example.test", nil
			return nil
		},
		"unmatched ask": func(r *Route) []Route { r.Scope.Unmatched = UnmatchedAsk; return nil },
		"an asking rule": func(r *Route) []Route {
			rule(r, "ContainerTop").Refuse, rule(r, "ContainerTop").Ask = false, true
			return nil
		},
		"a rule with no operation": func(r *Route) []Route { rule(r, "ContainerTop").Operation = nil; return nil },
		"an admitting rule without docker": func(r *Route) []Route {
			rule(r, "ContainerTop").Refuse = false
			return nil
		},
		"a refusing rule with docker": func(r *Route) []Route {
			rule(r, "ContainerTop").Docker = &DockerRule{Owned: "container", Param: 1}
			return nil
		},
		"an admitting prefix": func(r *Route) []Route {
			p := rule(r, "SystemVersion")
			p.Prefix, p.Path = p.Path, ""
			return nil
		},
		"a missing table": func(r *Route) []Route { delete(r.Docker.Bodies, "ExecCreate"); return nil },
		"a table under another name": func(r *Route) []Route {
			r.Docker.Bodies["ExecCreate"] = r.Docker.Bodies["ExecStart"]
			return nil
		},
		"a create judged by another table": func(r *Route) []Route {
			rule(r, "VolumeCreate").Docker.Body = "NetworkCreate"
			return nil
		},
		"a create's table on another operation": func(r *Route) []Route {
			rule(r, "ContainerExec").Docker.Body = "ContainerCreate"
			return nil
		},
		"an untagged image":                      func(r *Route) []Route { r.Docker.Images = []string{"postgres"}; return nil },
		"an image from localhost":                func(r *Route) []Route { r.Docker.Images = []string{"localhost/postgres:18"}; return nil },
		"an image from a port":                   func(r *Route) []Route { r.Docker.Images = []string{"registry:5000/postgres:18"}; return nil },
		"an image from an address":               func(r *Route) []Route { r.Docker.Images = []string{"10.0.0.1/postgres:18"}; return nil },
		"an image from a short loopback address": func(r *Route) []Route { r.Docker.Images = []string{"127.1/postgres:18"}; return nil },
		"an image from an octal loopback address": func(r *Route) []Route {
			r.Docker.Images = []string{"0177.0.0.1/postgres:18"}
			return nil
		},
		"an image from a hex loopback address": func(r *Route) []Route { r.Docker.Images = []string{"0x7f.1/postgres:18"}; return nil },
		"an image from localhost with a dot":   func(r *Route) []Route { r.Docker.Images = []string{"localhost./postgres:18"}; return nil },
		"an image from a name for loopback":    func(r *Route) []Route { r.Docker.Images = []string{"localtest.me/x:1"}; return nil },
		"an image from a host in /etc/hosts":   func(r *Route) []Route { r.Docker.Images = []string{"Dan-desktop/x:1"}; return nil },
		"an image with a space":                func(r *Route) []Route { r.Docker.Images = []string{"postgres: 18"}; return nil },
		"an image with a bad digest":           func(r *Route) []Route { r.Docker.Images = []string{"postgres@sha256:abc"}; return nil },
		"no images":                            func(r *Route) []Route { r.Docker.Images = nil; return nil },
		"65 ports": func(r *Route) []Route {
			r.Docker.Ports = nil
			for p := range 65 {
				r.Docker.Ports = append(r.Docker.Ports, uint16(50000+p))
			}
			return nil
		},
		"port 80":      func(r *Route) []Route { r.Docker.Ports = []uint16{80}; return nil },
		"a port twice": func(r *Route) []Route { r.Docker.Ports = []uint16{64320, 64320}; return nil },
		"two Docker routes": func(r *Route) []Route {
			other := newUnixUpstream(t, "/run/user/1000/other.sock")
			other.Name, other.Host = "docker2", "docker2.frisket.internal"
			return []Route{other}
		},
		"another project's address": func(r *Route) []Route {
			r.Docker.Address = docker.Address("triptease/finance-api")
			return nil
		},
		"names that are not the project's": func(r *Route) []Route {
			r.Docker.Names = []string{"data-lab.docker", "data-lab.triptease.docker"}
			return nil
		},
		"no names": func(r *Route) []Route { r.Docker.Names = nil; return nil },
		"a project that is not owner/repo": func(r *Route) []Route {
			r.Docker.Project, r.Docker.Address, r.Docker.Names = "data-lab", docker.Address("data-lab"), docker.Names("data-lab")
			return nil
		},
		"a project of dots": func(r *Route) []Route {
			r.Docker.Project, r.Docker.Address, r.Docker.Names = "a/..", docker.Address("a/.."), docker.Names("a/..")
			return nil
		},
		"a version with a leading zero": func(r *Route) []Route { r.Docker.APIVersions.Min = "1.055"; return nil },
		"a min above max": func(r *Route) []Route {
			r.Docker.APIVersions.Min, r.Docker.APIVersions.Max = "1.56", "1.55"
			return nil
		},
		"a versioned unversioned path": func(r *Route) []Route { r.Docker.APIVersions.Unversioned = []string{"/v1.55/_ping"}; return nil },
		"an escaped unversioned path":  func(r *Route) []Route { r.Docker.APIVersions.Unversioned = []string{"/_p%69ng"}; return nil },
		"no maxBody":                   func(r *Route) []Route { r.Docker.MaxBody = 0; return nil },
		"a maxBody over a megabyte":    func(r *Route) []Route { r.Docker.MaxBody = 1<<20 + 1; return nil },
		"an owned kind nobody knows":   func(r *Route) []Route { rule(r, "SystemVersion").Docker.Owned = "everything"; return nil },
		"a param that is not a *":      func(r *Route) []Route { rule(r, "ContainerInspect").Docker.Param = 0; return nil },
		"a param past the path":        func(r *Route) []Route { rule(r, "ContainerInspect").Docker.Param = 3; return nil },
		"a param on a kind with none":  func(r *Route) []Route { rule(r, "SystemVersion").Docker.Param = 1; return nil },
		"an upgrade to a websocket":    func(r *Route) []Route { rule(r, "ExecStart").Docker.Upgrade = "websocket"; return nil },
		"a list with no filters": func(r *Route) []Route {
			delete(rule(r, "ContainerList").Docker.Query, "filters")
			return nil
		},
		"filters on what is not a list": func(r *Route) []Route {
			rule(r, "SystemVersion").Docker.Query = map[string]QueryCheck{"filters": {Check: "filters", Filters: []string{"label"}}}
			return nil
		},
		"a pull with no image": func(r *Route) []Route {
			delete(rule(r, "ImageCreate").Docker.Query, "fromImage")
			return nil
		},
		"an image name that is not a pull's": func(r *Route) []Route {
			rule(r, "SystemVersion").Docker.Query = map[string]QueryCheck{"fromImage": {Check: "imageName"}}
			return nil
		},
		"a check nobody knows": func(r *Route) []Route {
			rule(r, "SystemVersion").Docker.Query = map[string]QueryCheck{"x": {Check: "anything"}}
			return nil
		},
		"an enum of nothing": func(r *Route) []Route {
			rule(r, "SystemVersion").Docker.Query = map[string]QueryCheck{"x": {Check: "enum"}}
			return nil
		},
	} {
		r := newUnixUpstream(t, socket)
		extra := mutate(&r)
		if name == "a docker rule on https" {
			r.Scope.Paths = []PathRule{{Methods: []string{"GET"}, Path: "/x", Docker: &DockerRule{Owned: "none"}}}
		}
		_, err := New(Config{Routes: append([]Route{r}, extra...), Log: slog.New(slog.DiscardHandler)})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type staticSecret string

func (s staticSecret) Get() (credential.Secret, error) {
	return credential.Secret{Value: string(s)}, nil
}
