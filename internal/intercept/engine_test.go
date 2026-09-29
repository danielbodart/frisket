package intercept

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/danielbodart/frisket/internal/docker"
)

// daemon is a fake Engine on a unix socket. It keeps containers, volumes,
// networks and execs as the daemon would, answers inspects of them, and
// records every request that reaches it -- frisket's own lookups apart from
// what frisket forwarded -- and what each create made.
type daemon struct {
	socket string

	mu         sync.Mutex
	seen       []seenRequest
	containers []*fakeObject
	volumes    []*fakeObject
	networks   []*fakeObject
	// execs are each exec's container.
	execs map[string]string
	// images are each image's own labels, which a container made from it
	// inherits.
	images map[string]map[string]string
	// ids are what the next creates are given, in order; after them, fresh
	// ones.
	ids []string
	// hook, if it answers a request, answers it in the daemon's place.
	hook func(w http.ResponseWriter, r *http.Request) bool
}

type seenRequest struct {
	method, path, query, host string
	header                    http.Header
	body                      string
	// lookup is frisket asking, not forwarding.
	lookup bool
}

// fakeObject is a container, volume or network. A container's volumes are
// what it mounts.
type fakeObject struct {
	id, name string
	labels   map[string]string
	volumes  []string
}

func newDaemon(t *testing.T) *daemon {
	t.Helper()
	// A unix socket's path is at most 107 bytes, which a test's TempDir can
	// pass.
	dir, err := os.MkdirTemp("", "frisket-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &daemon{
		socket: filepath.Join(dir, "docker.sock"),
		execs:  map[string]string{},
		images: map[string]map[string]string{},
	}
	ln, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(d.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d
}

// labelled is a project's label, or none for "".
func labelled(project string) map[string]string {
	if project == "" {
		return nil
	}
	return map[string]string{docker.LabelKey: project}
}

func (d *daemon) container(id, name, project string, volumes ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers = append(d.containers, &fakeObject{id: id, name: name, labels: labelled(project), volumes: volumes})
}

func (d *daemon) volume(name string, labels map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.volumes = append(d.volumes, &fakeObject{name: name, labels: labels})
}

func (d *daemon) network(id, name, project string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.networks = append(d.networks, &fakeObject{id: id, name: name, labels: labelled(project)})
}

func (d *daemon) exec(id, container string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.execs[id] = container
}

// nextIDs are the Ids the next creates are given.
func (d *daemon) nextIDs(ids ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids = append(d.ids, ids...)
}

func (d *daemon) answer(hook func(w http.ResponseWriter, r *http.Request) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hook = hook
}

// requests are what frisket forwarded.
func (d *daemon) requests() []seenRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []seenRequest
	for _, s := range d.seen {
		if !s.lookup {
			out = append(out, s)
		}
	}
	return out
}

// lookups are what frisket asked.
func (d *daemon) lookups() []seenRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []seenRequest
	for _, s := range d.seen {
		if s.lookup {
			out = append(out, s)
		}
	}
	return out
}

// all is everything that reached the daemon, in order.
func (d *daemon) all() []seenRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

func (d *daemon) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	d.seen = append(d.seen, seenRequest{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery,
		host: r.Host, header: r.Header.Clone(), body: string(body), lookup: r.Header.Get("User-Agent") == lookupAgent})
	hook := d.hook
	d.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/_ping") {
		w.Header().Set("Api-Version", "1.57")
		_, _ = io.WriteString(w, "OK")
		return
	}
	w.Header().Set("Api-Version", "1.40")
	w.Header().Set("Content-Type", "application/json")

	d.mu.Lock()
	defer d.mu.Unlock()
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if strings.HasPrefix(segs[0], "v1.") {
		segs = segs[1:]
	}
	route := r.Method + " " + segs[0]
	if len(segs) > 1 {
		route += " " + map[bool]string{true: segs[1], false: "*"}[segs[1] == "create" || segs[1] == "json"]
	}
	if len(segs) > 2 {
		route += " " + segs[2]
	}
	reply := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	missing := func(what string) { reply(http.StatusNotFound, map[string]string{"message": "No such " + what}) }

	switch route {
	case "GET containers * json":
		c := find(d.containers, segs[1])
		if c == nil {
			missing("container: " + segs[1])
			return
		}
		reply(http.StatusOK, map[string]any{"Id": c.id, "Name": "/" + c.name, "Config": map[string]any{"Labels": c.labels}})
	case "GET containers json":
		reply(http.StatusOK, d.list(r.URL.Query().Get("filters")))
	case "POST containers create":
		var req struct {
			Image      string
			Labels     map[string]string
			HostConfig struct {
				Binds  []string
				Mounts []struct{ Type, Source string }
			}
		}
		_ = json.Unmarshal(body, &req)
		// The image's labels are the container's, under its own.
		labels := map[string]string{}
		for k, v := range d.images[req.Image] {
			labels[k] = v
		}
		for k, v := range req.Labels {
			labels[k] = v
		}
		c := &fakeObject{id: d.id(), name: r.URL.Query().Get("name"), labels: labels}
		for _, b := range req.HostConfig.Binds {
			c.volumes = append(c.volumes, strings.Split(b, ":")[0])
		}
		for _, m := range req.HostConfig.Mounts {
			if m.Type == "volume" {
				c.volumes = append(c.volumes, m.Source)
			}
		}
		d.containers = append(d.containers, c)
		reply(http.StatusCreated, map[string]any{"Id": c.id, "Warnings": []string{}})
	case "POST containers * exec":
		c := find(d.containers, segs[1])
		if c == nil {
			missing("container: " + segs[1])
			return
		}
		id := d.id()
		d.execs[id] = c.id
		reply(http.StatusCreated, map[string]string{"Id": id})
	case "DELETE containers *":
		c := find(d.containers, segs[1])
		if c == nil {
			missing("container: " + segs[1])
			return
		}
		d.containers = slices.DeleteFunc(d.containers, func(o *fakeObject) bool { return o == c })
		w.WriteHeader(http.StatusNoContent)
	case "GET exec * json":
		c, ok := d.execs[segs[1]]
		if !ok {
			missing("exec instance: " + segs[1])
			return
		}
		reply(http.StatusOK, map[string]any{"ID": segs[1], "ContainerID": c, "Running": false})
	case "GET volumes *":
		v := findName(d.volumes, segs[1])
		if v == nil {
			reply(http.StatusNotFound, map[string]string{"message": "get " + segs[1] + ": no such volume"})
			return
		}
		reply(http.StatusOK, map[string]any{"Name": v.name, "Driver": "local", "Labels": v.labels})
	case "POST volumes create":
		var req struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(body, &req)
		if req.Name == "" {
			req.Name = d.id()
		}
		v := findName(d.volumes, req.Name)
		if v == nil {
			v = &fakeObject{name: req.Name, labels: req.Labels}
			d.volumes = append(d.volumes, v)
		}
		reply(http.StatusCreated, map[string]any{"Name": v.name, "Labels": v.labels})
	case "DELETE volumes *":
		v := findName(d.volumes, segs[1])
		if v == nil {
			reply(http.StatusNotFound, map[string]string{"message": "get " + segs[1] + ": no such volume"})
			return
		}
		d.volumes = slices.DeleteFunc(d.volumes, func(o *fakeObject) bool { return o == v })
		w.WriteHeader(http.StatusNoContent)
	case "GET networks *":
		n := find(d.networks, segs[1])
		if n == nil {
			reply(http.StatusNotFound, map[string]string{"message": "network " + segs[1] + " not found"})
			return
		}
		reply(http.StatusOK, map[string]any{"Name": n.name, "Id": n.id, "Labels": n.labels})
	case "POST networks create":
		var req struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(body, &req)
		n := &fakeObject{id: d.id(), name: req.Name, labels: req.Labels}
		d.networks = append(d.networks, n)
		reply(http.StatusCreated, map[string]string{"Id": n.id, "Warning": ""})
	case "DELETE networks *":
		n := find(d.networks, segs[1])
		if n == nil {
			reply(http.StatusNotFound, map[string]string{"message": "network " + segs[1] + " not found"})
			return
		}
		d.networks = slices.DeleteFunc(d.networks, func(o *fakeObject) bool { return o == n })
		w.WriteHeader(http.StatusNoContent)
	default:
		_, _ = io.WriteString(w, "{}")
	}
}

// id is the next Id a create is given.
func (d *daemon) id() string {
	if len(d.ids) > 0 {
		id := d.ids[0]
		d.ids = d.ids[1:]
		return id
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// list is the containers a list's label and volume filters select, as the
// daemon lists them.
func (d *daemon) list(filters string) []map[string]any {
	var f map[string]json.RawMessage
	_ = json.Unmarshal([]byte(filters), &f)
	values := func(key string) []string {
		var arr []string
		if json.Unmarshal(f[key], &arr) == nil {
			return arr
		}
		var set map[string]bool
		_ = json.Unmarshal(f[key], &set)
		for k := range set {
			arr = append(arr, k)
		}
		return arr
	}
	out := []map[string]any{}
	for _, c := range d.containers {
		ok := true
		for _, l := range values("label") {
			k, v, eq := strings.Cut(l, "=")
			got, has := c.labels[k]
			ok = ok && has && (!eq || got == v)
		}
		for _, v := range values("volume") {
			ok = ok && slices.Contains(c.volumes, v)
		}
		if !ok {
			continue
		}
		var mounts []map[string]string
		for _, v := range c.volumes {
			mounts = append(mounts, map[string]string{"Type": "volume", "Name": v})
		}
		out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.name}, "Labels": c.labels, "Mounts": mounts})
	}
	return out
}

// find is an object by its Id, its name, or a prefix of one Id.
func find(objs []*fakeObject, ref string) *fakeObject {
	var prefixed []*fakeObject
	for _, o := range objs {
		if o.id == ref || o.name == ref {
			return o
		}
		if o.id != "" && strings.HasPrefix(o.id, ref) {
			prefixed = append(prefixed, o)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0]
	}
	return nil
}

func findName(objs []*fakeObject, name string) *fakeObject {
	for _, o := range objs {
		if o.name == name {
			return o
		}
	}
	return nil
}
