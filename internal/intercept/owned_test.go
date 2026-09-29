package intercept

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/docker"
)

const (
	otherProject = "triptease/finance-api"
	networkID    = "372e029d9dd22674f10f3dfb1ba4aa9f9fa8a8de46589f67eab8fa3425d7915c"
	anonVolume   = "a43153268aa27b711843120e030d35d73b89d312f1942a11027a2eae1aaf28e8"
)

func jsonRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := dockerRequest(t, method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// createContainer is a ContainerCreate body on network, with hostConfig's
// other fields and the rest of the body besides.
func createContainer(network, hostConfig, rest string) string {
	hc := `"NetworkMode":` + jsonString(network)
	if hostConfig != "" {
		hc += "," + hostConfig
	}
	body := `{"Image":"postgres:18","HostConfig":{` + hc + `}`
	if rest != "" {
		body += "," + rest
	}
	return body + "}"
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// status asserts a response's status, and for a refusal that its message
// says reason.
func status(t *testing.T, what string, res *http.Response, body string, want int, reason string) {
	t.Helper()
	if res.StatusCode != want {
		t.Errorf("%s: status %d, want %d: %s", what, res.StatusCode, want, body)
		return
	}
	if reason != "" && !strings.Contains(body, reason) {
		t.Errorf("%s: %s does not say %q", what, body, reason)
	}
}

func lastLine(t *testing.T, j *journal, n int) map[string]any {
	t.Helper()
	lines := j.waitLines(t, "request", n)
	return lines[n-1]
}

// An object this project owns is acted on by the full ID the daemon gave for
// it, whatever name or prefix the client used, and a volume by its name; the
// log says what was found.
func TestAnOwnedObjectIsActedOnByItsFullID(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.container(containerID, "data-lab-db-1", dockerProject)
	d.network(networkID, "data-lab_default", dockerProject)
	d.volume("pgdata", labelled(dockerProject))

	for i, c := range []struct{ method, target, want, account string }{
		{"GET", "/v1.55/containers/data-lab-db-1/json", "/v1.55/containers/" + containerID + "/json", "container=fdd16f31d6ce owned"},
		{"POST", "/v1.55/containers/fdd16f31d6ce/start", "/v1.55/containers/" + containerID + "/start", "container=fdd16f31d6ce owned"},
		{"GET", "/v1.55/networks/data-lab_default", "/v1.55/networks/" + networkID, "network=372e029d9dd2 owned"},
		{"DELETE", "/v1.55/networks/372e029d", "/v1.55/networks/" + networkID, "network=372e029d9dd2 owned"},
		{"GET", "/v1.55/volumes/pgdata", "/v1.55/volumes/pgdata", "volume=pgdata owned"},
	} {
		res, body := f.do(t, dockerRequest(t, c.method, c.target, nil))
		if res.StatusCode >= 300 {
			t.Fatalf("%s %s: status %d: %s", c.method, c.target, res.StatusCode, body)
		}
		seen := d.requests()
		if got := seen[len(seen)-1].path; got != c.want {
			t.Errorf("%s %s went as %s, want %s", c.method, c.target, got, c.want)
		}
		if line := lastLine(t, j, i+1); line["docker"] != c.account || line["decision"] != DecisionAllowed {
			t.Errorf("%s %s logged %v", c.method, c.target, line)
		}
	}
}

// An object that exists without this project's label -- another project's,
// or one made outside frisket -- is refused, and the request never reaches
// the daemon; only frisket's question about it does.
func TestAnotherProjectsObjectOrAnUnlabelledOneIsRefused(t *testing.T) {
	f, d, j := dockerFixture(t)
	other := strings.Repeat("ab", 32)
	bare := strings.Repeat("cd", 32)
	d.container(other, "finance-db-1", otherProject)
	d.container(bare, "core-data-local-db2", "")
	d.network(strings.Repeat("ef", 32), "finance_default", otherProject)
	d.network(strings.Repeat("01", 32), "bridge2", "")
	d.volume("finance-data", labelled(otherProject))
	d.volume("host-made", nil)
	d.volume("forged", map[string]string{"frisket.project ": dockerProject, "Frisket.project": dockerProject})
	d.exec(execID, other)

	targets := []struct{ method, target string }{
		{"GET", "/v1.55/containers/finance-db-1/json"},
		{"POST", "/v1.55/containers/" + other + "/stop"},
		{"DELETE", "/v1.55/containers/core-data-local-db2?force=1"},
		{"GET", "/v1.55/networks/finance_default"},
		{"DELETE", "/v1.55/networks/bridge2"},
		{"GET", "/v1.55/volumes/finance-data"},
		{"DELETE", "/v1.55/volumes/host-made"},
		{"GET", "/v1.55/volumes/forged"},
		{"GET", "/v1.55/exec/" + execID + "/json"},
	}
	for _, c := range targets {
		res, body := f.do(t, dockerRequest(t, c.method, c.target, nil))
		refusedFor(t, res, body, ReasonNotOwned)
	}
	if seen := d.requests(); len(seen) != 0 {
		t.Fatalf("refused requests reached the daemon: %+v", seen)
	}
	if n := len(d.lookups()); n != len(targets)+1 {
		t.Errorf("%d lookups, want %d", n, len(targets)+1)
	}
	for _, l := range j.waitLines(t, "request", len(targets)) {
		if acct, _ := l["docker"].(string); !strings.HasSuffix(acct, "not this project's") {
			t.Errorf("logged %v", l)
		}
	}
}

// What a path names that does not exist is answered with the daemon's own
// 404 -- its status, type and body -- which is how Compose learns to create
// it; the request itself never reaches the daemon.
func TestAnAbsentObjectIsAnsweredWithTheDaemonsOwn404(t *testing.T) {
	f, d, j := dockerFixture(t)
	for i, c := range []struct{ target, message, account string }{
		{"/v1.55/volumes/core-data-local-db2", "get core-data-local-db2: no such volume", "volume=core-data-local-db2 absent"},
		{"/v1.55/networks/frisket-capture_default", "network frisket-capture_default not found", "network=frisket-capture_default absent"},
		{"/v1.55/containers/gone/json", "No such container: gone", "container=gone absent"},
		{"/v1.55/exec/" + execID + "/json", "No such exec instance: " + execID, "exec=38f66d86a5c7 absent"},
	} {
		res, body := f.do(t, dockerRequest(t, "GET", c.target, nil))
		if res.StatusCode != http.StatusNotFound || res.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: status %d, type %q: %s", c.target, res.StatusCode, res.Header.Get("Content-Type"), body)
		}
		var m struct{ Message string }
		if err := json.Unmarshal([]byte(body), &m); err != nil || m.Message != c.message {
			t.Errorf("%s: body %q", c.target, body)
		}
		if n := len(d.lookups()); n != i+1 {
			t.Errorf("%s: %d lookups, want %d", c.target, n, i+1)
		}
		line := lastLine(t, j, i+1)
		if line["decision"] != DecisionRefused || line["status"] != float64(404) || line["docker"] != c.account {
			t.Errorf("%s: logged %v", c.target, line)
		}
	}
	if seen := d.requests(); len(seen) != 0 {
		t.Fatalf("requests for absent objects reached the daemon: %+v", seen)
	}
}

// An exec is acted on only when the daemon says its container is this
// project's: the exec is asked about, then its container.
func TestAnExecIsActedOnOnlyWhenItsContainerIsOwned(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.container(containerID, "data-lab-db-1", dockerProject)
	d.exec(execID, containerID)
	res, body := f.do(t, dockerRequest(t, "GET", "/v1.55/exec/"+execID+"/json", nil))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	asked := d.lookups()
	if len(asked) != 2 || asked[0].path != "/v1.56/exec/"+execID+"/json" || asked[1].path != "/v1.56/containers/"+containerID+"/json" {
		t.Errorf("asked %+v", asked)
	}
	if seen := d.requests(); len(seen) != 1 || seen[0].path != "/v1.55/exec/"+execID+"/json" {
		t.Errorf("forwarded %+v", seen)
	}
	if line := lastLine(t, j, 1); line["docker"] != "exec=38f66d86a5c7 container=fdd16f31d6ce owned" {
		t.Errorf("logged %v", line)
	}

	theirs := strings.Repeat("9", 64)
	d.container(strings.Repeat("ab", 32), "finance-db-1", otherProject)
	d.exec(theirs, strings.Repeat("ab", 32))
	res, body = f.do(t, jsonRequest(t, "POST", "/v1.55/exec/"+theirs+"/start", `{"Detach":true}`))
	refusedFor(t, res, body, ReasonNotOwned)
	if n := len(d.requests()); n != 1 {
		t.Errorf("%d requests reached the daemon, want 1", n)
	}
}

// VolumeCreate on a name that exists returns that volume, so a name is
// created only where it is absent or already this project's.
func TestAVolumeIsCreatedOnlyWhereItIsAbsentOrOwned(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.volume("ours", labelled(dockerProject))
	d.volume("theirs", labelled(otherProject))
	d.volume("bare", nil)
	for i, c := range []struct {
		name    string
		status  int
		account string
	}{
		{"fresh", http.StatusCreated, "stamped; volume=fresh absent"},
		{"ours", http.StatusCreated, "stamped; volume=ours owned"},
		{"theirs", http.StatusForbidden, "stamped; volume=theirs not this project's"},
		{"bare", http.StatusForbidden, "stamped; volume=bare not this project's"},
	} {
		res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/volumes/create", `{"Name":"`+c.name+`"}`))
		status(t, c.name, res, body, c.status, "")
		if line := lastLine(t, j, i+1); line["docker"] != c.account {
			t.Errorf("%s: logged %v", c.name, line)
		}
	}
	if n := len(d.requests()); n != 2 {
		t.Errorf("%d creates reached the daemon, want 2", n)
	}
}

// A bind is of a volume that exists and is this project's: the daemon would
// make an absent one without the label, and another's is another's data.
func TestABindIsOfAVolumeThisProjectOwns(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.volume("ours", labelled(dockerProject))
	d.volume("theirs", labelled(otherProject))
	for _, c := range []struct {
		volume string
		status int
		reason string
	}{
		{"absent", http.StatusForbidden, ReasonAbsent},
		{"theirs", http.StatusForbidden, ReasonNotOwned},
		{"ours", http.StatusCreated, ""},
	} {
		res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create?name=pg",
			createContainer("none", `"Binds":["`+c.volume+`:/var/lib/postgresql:rw"]`, "")))
		status(t, c.volume, res, body, c.status, c.reason)
	}
	if n := len(d.requests()); n != 1 {
		t.Errorf("%d creates reached the daemon, want 1", n)
	}
	if line := lastLine(t, j, 3); line["docker"] != "stamped; bind ours owned" {
		t.Errorf("logged %v", line)
	}
}

// A volume a create names twice, as a bind and as a mount, is asked about
// once.
func TestAVolumeNamedTwiceInOneCreateIsAskedAboutOnce(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.volume("ours", labelled(dockerProject))
	res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create?name=pg", createContainer("none",
		`"Binds":["ours:/var/lib/postgresql:rw"],"Mounts":[{"Type":"volume","Source":"ours","Target":"/backup"}]`, "")))
	status(t, "create", res, body, http.StatusCreated, "")
	if asked := d.lookups(); len(asked) != 1 || asked[0].path != "/v1.56/volumes/ours" {
		t.Errorf("asked %+v", asked)
	}
}

// A container joins only networks this project owns, whether it names them
// as its NetworkMode or as an endpoint.
func TestANetworkAContainerJoinsIsThisProjects(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.network(networkID, "data-lab_default", dockerProject)
	d.network(strings.Repeat("ef", 32), "finance_default", otherProject)
	d.network(strings.Repeat("01", 32), "made-by-hand", "")
	endpoint := func(n string) string {
		return `"NetworkingConfig":{"EndpointsConfig":{"` + n + `":{"Aliases":["db"]}}}`
	}
	for name, c := range map[string]struct {
		body   string
		status int
		reason string
	}{
		"another's mode":     {createContainer("finance_default", "", ""), http.StatusForbidden, ReasonNotOwned},
		"an unlabelled mode": {createContainer("made-by-hand", "", ""), http.StatusForbidden, ReasonNotOwned},
		"an absent mode":     {createContainer("nowhere", "", ""), http.StatusForbidden, ReasonAbsent},
		"another's endpoint": {createContainer("data-lab_default", "", endpoint("finance_default")), http.StatusForbidden, ReasonNotOwned},
	} {
		res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create", c.body))
		status(t, name, res, body, c.status, c.reason)
	}
	if n := len(d.requests()); n != 0 {
		t.Fatalf("%d refused creates reached the daemon", n)
	}
	before := len(d.lookups())
	res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create", createContainer("data-lab_default", "", endpoint("data-lab_default"))))
	status(t, "owned", res, body, http.StatusCreated, "")
	// One network, named twice, is asked about once.
	if asked := d.lookups()[before:]; len(asked) != 1 || asked[0].path != "/v1.56/networks/data-lab_default" {
		t.Errorf("asked %+v", asked)
	}
}

// Compose recreates a container with the anonymous volume the old one had,
// by its daemon-given name: that passes when a container of this project's
// mounts it, and not when only another project's does.
func TestAnAnonymousVolumeCarriesOverARecreateOnlyFromThisProjectsContainer(t *testing.T) {
	f, d, _ := dockerFixture(t)
	anon := map[string]string{"com.docker.volume.anonymous": ""}
	theirs := strings.Repeat("b", 64)
	unmounted := strings.Repeat("c", 64)
	d.volume(anonVolume, anon)
	d.volume(theirs, anon)
	d.volume(unmounted, anon)
	d.volume("named-bare", nil)
	d.container(containerID, "data-lab-db-1", dockerProject, anonVolume, "named-bare")
	d.container(strings.Repeat("ab", 32), "finance-db-1", otherProject, theirs)
	mount := func(src string) string {
		return `"Mounts":[{"Type":"volume","Source":"` + src + `","Target":"/var/lib/postgresql/data","VolumeOptions":{}}]`
	}
	res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create?name=data-lab-db-1-new", createContainer("none", mount(anonVolume), "")))
	status(t, "ours", res, body, http.StatusCreated, "")
	asked := d.lookups()
	if len(asked) != 2 || asked[1].path != "/v1.56/containers/json" {
		t.Fatalf("asked %+v", asked)
	}
	q, _ := url.ParseQuery(asked[1].query)
	var filters map[string][]string
	if err := json.Unmarshal([]byte(q.Get("filters")), &filters); err != nil || q.Get("all") != "1" ||
		len(filters["volume"]) != 1 || filters["volume"][0] != anonVolume ||
		len(filters["label"]) != 1 || filters["label"][0] != docker.LabelKey+"="+dockerProject {
		t.Errorf("asked %s", asked[1].query)
	}
	for name, src := range map[string]string{
		"mounted only by another project's": theirs,
		"mounted by nobody":                 unmounted,
		"named, and not anonymous":          "named-bare",
	} {
		res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create", createContainer("none", mount(src), "")))
		status(t, name, res, body, http.StatusForbidden, ReasonNotOwned)
	}
	// A daemon that lists another project's container past the label filter
	// does not make it this project's.
	d.answer(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("User-Agent") != lookupAgent || !strings.HasSuffix(r.URL.Path, "/containers/json") {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"Id":"`+strings.Repeat("ab", 32)+`","Labels":{"`+docker.LabelKey+`":"`+otherProject+`"},`+
			`"Mounts":[{"Type":"volume","Name":"`+anonVolume+`"}]}]`)
		return true
	})
	res, body = f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create", createContainer("none", mount(anonVolume), "")))
	status(t, "listed past the filter", res, body, http.StatusForbidden, ReasonNotOwned)
	if n := len(d.requests()); n != 1 {
		t.Errorf("%d creates reached the daemon, want 1", n)
	}
}

// Everything created through frisket carries this project's label, so that
// what it made is what it may act on after.
func TestEveryCreateIsStampedWithThisProject(t *testing.T) {
	f, d, _ := dockerFixture(t)
	for _, c := range []struct{ target, body, then string }{
		{"/v1.55/volumes/create", `{"Name":"pgdata"}`, "/v1.55/volumes/pgdata"},
		{"/v1.55/networks/create", `{"Name":"data-lab_default"}`, "/v1.55/networks/data-lab_default"},
		{"/v1.55/containers/create?name=pg", createContainer("none", "", `"Labels":null`), "/v1.55/containers/pg/json"},
	} {
		res, body := f.do(t, jsonRequest(t, "POST", c.target, c.body))
		status(t, c.target, res, body, http.StatusCreated, "")
		seen := d.requests()
		var sent struct{ Labels map[string]string }
		if err := json.Unmarshal([]byte(seen[len(seen)-1].body), &sent); err != nil || sent.Labels[docker.LabelKey] != dockerProject {
			t.Errorf("%s sent %s", c.target, seen[len(seen)-1].body)
		}
		res, body = f.do(t, dockerRequest(t, "GET", c.then, nil))
		status(t, c.then, res, body, http.StatusOK, "")
	}
}

// An image may carry a frisket.project label of its own, which a container
// inherits; the stamp in the body is what the container ends up with.
func TestAnImagesLabelNeverOutranksTheStamp(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.mu.Lock()
	d.images["postgres:18"] = labelled(otherProject)
	d.mu.Unlock()
	res, body := f.do(t, jsonRequest(t, "POST", "/v1.55/containers/create?name=pg", createContainer("none", "", "")))
	status(t, "create", res, body, http.StatusCreated, "")
	res, body = f.do(t, dockerRequest(t, "POST", "/v1.55/containers/pg/start", nil))
	status(t, "start", res, body, http.StatusOK, "")
}

// Where the daemon cannot say whose an object is -- an error, an answer too
// large, a redirect, or an answer without a proper ID -- the request is a 502
// and goes nowhere.
func TestADaemonThatCannotSayWhoseIsA502(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.container(containerID, "data-lab-db-1", dockerProject)
	cases := map[string]func(w http.ResponseWriter){
		"500": func(w http.ResponseWriter) { http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError) },
		"an answer over 4 MiB": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"Id":"`+containerID+`","Config":{"Labels":{"frisket.project":"`+dockerProject+`"}},"x":"`)
			_, _ = io.WriteString(w, strings.Repeat("x", maxLookup))
			_, _ = io.WriteString(w, `"}`)
		},
		"a 404 over 64 KiB": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, strings.Repeat("x", maxAbsent+1))
		},
		"a redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "/v1.56/containers/other/json")
			w.WriteHeader(http.StatusFound)
		},
		"a short ID": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"Id":"fdd16f31d6ce","Config":{"Labels":{"frisket.project":"`+dockerProject+`"}}}`)
		},
		"not JSON": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"Id":`) },
	}
	n := 0
	for name, reply := range cases {
		d.answer(func(w http.ResponseWriter, r *http.Request) bool {
			if r.Header.Get("User-Agent") != lookupAgent {
				return false
			}
			reply(w)
			return true
		})
		res, body := f.do(t, dockerRequest(t, "POST", "/v1.55/containers/data-lab-db-1/stop", nil))
		status(t, name, res, body, http.StatusBadGateway, ReasonLookup)
		n++
		if line := lastLine(t, j, n); line["reason"] != ReasonLookup || !strings.Contains(line["docker"].(string), "lookup failed") {
			t.Errorf("%s: logged %v", name, line)
		}
	}
	if seen := d.requests(); len(seen) != 0 {
		t.Fatalf("requests reached the daemon: %+v", seen)
	}
}

// A name is held from when it is checked until the daemon has answered what
// was done with it: a VolumeCreate of a name a DELETE holds is not even
// asked about until the DELETE is answered, and then finds it gone.
func TestANameIsHeldFromItsCheckUntilItsUse(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.volume("shared", labelled(dockerProject))
	entered, gate := make(chan struct{}), make(chan struct{})
	d.answer(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "DELETE" {
			close(entered)
			<-gate
		}
		return false
	})
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	wg.Go(func() {
		res, _ := f.do(t, dockerRequest(t, "DELETE", "/v1.55/volumes/shared?force=1", nil))
		statuses[0] = res.StatusCode
	})
	<-entered
	wg.Go(func() {
		res, _ := f.do(t, jsonRequest(t, "POST", "/v1.55/volumes/create", `{"Name":"shared"}`))
		statuses[1] = res.StatusCode
	})
	key := nameKey{socket: d.socket, kind: "volume", name: "shared"}
	deadline := time.Now().Add(5 * time.Second)
	for heldNames.waiting(key) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("the create never waited for the name")
		}
		time.Sleep(time.Millisecond)
	}
	if n := len(d.lookups()); n != 1 {
		t.Fatalf("the create was asked about while the DELETE held its name: %d lookups", n)
	}
	close(gate)
	wg.Wait()
	if statuses[0] != http.StatusNoContent || statuses[1] != http.StatusCreated {
		t.Fatalf("statuses %v", statuses)
	}
	var order []string
	for _, s := range d.all() {
		order = append(order, s.method+" "+s.path)
	}
	want := []string{
		"GET /v1.56/volumes/shared", "DELETE /v1.55/volumes/shared",
		"GET /v1.56/volumes/shared", "POST /v1.55/volumes/create",
	}
	if strings.Join(order, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the daemon saw\n%s\nwant\n%s", strings.Join(order, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range j.waitLines(t, "request", 2) {
		if l["operation"] == "VolumeCreate" && l["docker"] != "stamped; volume=shared absent" {
			t.Errorf("logged %v", l)
		}
	}
	if heldNames.waiting(key) != 0 {
		t.Error("the name is still held")
	}
}

// A name is let go when the daemon's response headers arrive, not when its
// body ends: a VolumeCreate of a name whose inspect is still streaming its
// body goes through.
func TestANameIsLetGoWhenTheDaemonAnswers(t *testing.T) {
	f, d, _ := dockerFixture(t)
	d.volume("shared", labelled(dockerProject))
	entered, gate := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(gate)
		wg.Wait()
	}()
	d.answer(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" || r.Header.Get("User-Agent") == lookupAgent || !strings.HasSuffix(r.URL.Path, "/volumes/shared") {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"Name":"shared",`)
		w.(http.Flusher).Flush()
		close(entered)
		<-gate
		_, _ = io.WriteString(w, `"Driver":"local"}`)
		return true
	})
	wg.Go(func() { _, _ = f.do(t, dockerRequest(t, "GET", "/v1.55/volumes/shared", nil)) })
	<-entered
	created := make(chan int, 1)
	wg.Go(func() {
		res, _ := f.do(t, jsonRequest(t, "POST", "/v1.55/volumes/create", `{"Name":"shared"}`))
		created <- res.StatusCode
	})
	select {
	case s := <-created:
		if s != http.StatusCreated {
			t.Fatalf("create status %d", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the create waited on a name whose use the daemon had already answered")
	}
}

// capture is Docker CLI 29.8.0 and Compose 5.4.0's own traffic for `up`, an
// exec into each database, and `down -v`, as the rootless daemon saw it.
type capture struct {
	Requests []struct {
		Seq         int
		Method      string
		Target      string
		Header      map[string]string
		Body        *string
		ID          string
		ContainerID string
	}
}

// The captured session, replayed in order against a daemon that starts
// empty, is admitted whole: every request reaches the daemon but the two
// inspects Compose makes before it creates what they name, which are
// answered with the daemon's 404 as they were; and every port is published
// on the project's own address.
func TestTheCaptureIsAdmittedInOrder(t *testing.T) {
	f, d, j := dockerFixture(t)
	b, err := os.ReadFile("testdata/capture-compose-5.4.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var c capture
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	absentFirst := map[int]bool{13: true, 14: true}
	for _, e := range c.Requests {
		if e.ID != "" {
			d.nextIDs(e.ID)
		}
		var body io.Reader
		if e.Body != nil {
			body = strings.NewReader(*e.Body)
		}
		req := dockerRequest(t, e.Method, e.Target, body)
		for k, v := range e.Header {
			req.Header.Set(k, v)
		}
		res, got := f.do(t, req)
		switch {
		case absentFirst[e.Seq]:
			status(t, e.Target, res, got, http.StatusNotFound, "")
		case res.StatusCode >= 300:
			t.Fatalf("%d %s %s: status %d: %s", e.Seq, e.Method, e.Target, res.StatusCode, got)
		}
		if e.ContainerID != "" {
			var inspected struct{ ContainerID string }
			if err := json.Unmarshal([]byte(got), &inspected); err != nil || inspected.ContainerID != e.ContainerID {
				t.Errorf("%d: the exec's container is %s, want %s", e.Seq, got, e.ContainerID)
			}
		}
	}
	lines := j.waitLines(t, "request", len(c.Requests))
	for i, l := range lines {
		want := DecisionAllowed
		if absentFirst[c.Requests[i].Seq] {
			want = DecisionRefused
		}
		if l["decision"] != want {
			t.Errorf("%d: logged %v", c.Requests[i].Seq, l)
		}
	}
	seen := d.requests()
	if len(seen) != len(c.Requests)-len(absentFirst) {
		t.Fatalf("%d requests reached the daemon, want %d", len(seen), len(c.Requests)-len(absentFirst))
	}
	published := 0
	for _, s := range seen {
		if !strings.HasSuffix(s.path, "/containers/create") {
			continue
		}
		var sent struct {
			Labels     map[string]string
			HostConfig struct {
				PortBindings map[string][]struct{ HostIp, HostPort string }
			}
		}
		if err := json.Unmarshal([]byte(s.body), &sent); err != nil {
			t.Fatal(err)
		}
		if sent.Labels[docker.LabelKey] != dockerProject {
			t.Errorf("created unstamped: %s", s.body)
		}
		for port, bindings := range sent.HostConfig.PortBindings {
			for _, pb := range bindings {
				published++
				if pb.HostIp != "127.1.191.78" {
					t.Errorf("%s published on %q", port, pb.HostIp)
				}
			}
		}
	}
	if published != 2 {
		t.Errorf("%d ports published, want 2", published)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.containers) != 0 || len(d.volumes) != 0 || len(d.networks) != 0 {
		t.Errorf("down -v left %d containers, %d volumes, %d networks", len(d.containers), len(d.volumes), len(d.networks))
	}
}

// A container joins the network frisket checked, never whatever holds its
// name when it starts. The daemon keeps what a create names and resolves it
// again at every start, after the name's lock is let go: so this project
// makes a network and a container on it, not started, deletes the network,
// which has no endpoint yet, and another project makes its own under the
// same name. The create went upstream naming the network by its ID, so the
// start finds no such network, and the other project's is joined by
// nothing.
func TestAContainerJoinsTheNetworkThatWasCheckedNotAnotherOfItsName(t *testing.T) {
	fa, d, _ := dockerFixture(t)
	rb := newUnixUpstream(t, d.socket)
	rb.Docker.Project = otherProject
	rb.Docker.Address = docker.Address(otherProject)
	rb.Docker.Names = docker.Names(otherProject)
	fb, _ := dockerFixtureOn(t, rb)

	const theirs = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	d.nextIDs(networkID)
	res, body := fa.do(t, jsonRequest(t, "POST", "/v1.55/networks/create", `{"Name":"shared_default"}`))
	status(t, "this project's network", res, body, http.StatusCreated, "")
	endpoint := `"NetworkingConfig":{"EndpointsConfig":{"shared_default":{"Aliases":["db"]}}}`
	res, body = fa.do(t, jsonRequest(t, "POST", "/v1.55/containers/create?name=shared-db-1", createContainer("shared_default", "", endpoint)))
	status(t, "a container on it", res, body, http.StatusCreated, "")
	var created struct{ Id string }
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	reqs := d.requests()
	var sent struct {
		HostConfig       struct{ NetworkMode string }
		NetworkingConfig struct {
			EndpointsConfig map[string]struct{ Aliases []string }
		}
	}
	if err := json.Unmarshal([]byte(reqs[len(reqs)-1].body), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.HostConfig.NetworkMode != networkID {
		t.Errorf("NetworkMode went upstream as %q", sent.HostConfig.NetworkMode)
	}
	if ep, ok := sent.NetworkingConfig.EndpointsConfig[networkID]; len(sent.NetworkingConfig.EndpointsConfig) != 1 || !ok || len(ep.Aliases) != 1 {
		t.Errorf("EndpointsConfig went upstream as %+v", sent.NetworkingConfig.EndpointsConfig)
	}

	res, body = fa.do(t, jsonRequest(t, "DELETE", "/v1.55/networks/shared_default", ""))
	status(t, "the network deleted", res, body, http.StatusNoContent, "")
	d.nextIDs(theirs)
	res, body = fb.do(t, jsonRequest(t, "POST", "/v1.55/networks/create", `{"Name":"shared_default"}`))
	status(t, "another project's network of the same name", res, body, http.StatusCreated, "")

	res, body = fa.do(t, jsonRequest(t, "POST", "/v1.55/containers/shared-db-1/start", ""))
	status(t, "the start", res, body, http.StatusNotFound, networkID+" not found")
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.containers {
		if slices.Contains(c.joined, theirs) {
			t.Errorf("container %s joined the other project's network", short(c.id))
		}
	}
}
