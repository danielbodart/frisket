package dockerapi

import (
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	projaddr "github.com/danielbodart/frisket/project"
)

const project = "example/shop"

var route = Route{
	Project: project,
	Address: netip.MustParseAddr("127.101.170.171"),
	Ports:   []uint16{64320, 64321, 64322, 64323, 64324, 64325, 64328, 64329},
	Images:  []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18"},
}

type capture struct {
	Bodies []struct {
		Seq       int
		Operation string
		Body      string
	}
	Filters []struct {
		Seq       int
		Operation string
		Filters   string
	}
}

func load(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// tables compiles chase's tables, in the flat format Compile reads.
func tables(t testing.TB) map[string]*Table {
	t.Helper()
	b, err := os.ReadFile("testdata/fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]*Table{}
	for name, r := range raw {
		tb, err := Compile(name, r)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = tb
	}
	return out
}

func rawTable(t testing.TB, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return raw[name]
}

func captured(t testing.TB, seq int) map[string]any {
	t.Helper()
	var c capture
	b, err := os.ReadFile("testdata/compose-5.4.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for _, body := range c.Bodies {
		if body.Seq == seq {
			tree, err := Read([]byte(body.Body))
			if err != nil {
				t.Fatal(err)
			}
			return tree
		}
	}
	t.Fatalf("no body %d", seq)
	return nil
}

// The bodies Compose 5.4.0 sent for an `up`, an `exec` and a `down` against a
// real daemon: every one is admitted, each create is stamped, each published
// port lands on the project's address, and the names the daemon must be asked
// about are the ones the bodies hold.
func TestEveryBodyComposeSentIsAdmitted(t *testing.T) {
	var c capture
	load(t, "testdata/compose-5.4.0.json", &c)
	tabs := tables(t)
	wantLookups := map[int][]Lookup{
		15: {{"volume", "core-data-local-db2", Create}},
		16: {{"network", "frisket-capture_default", Create}},
		17: {{"network", "frisket-capture_default", Attach}},
		18: {{"volume", "core-data-local-db2", Bind}, {"network", "frisket-capture_default", Attach}},
	}
	wantPort := map[int]string{17: "64320", 18: "64321"}
	if len(c.Bodies) != 12 {
		t.Fatalf("%d bodies, want the capture's 12", len(c.Bodies))
	}
	for _, b := range c.Bodies {
		got, err := tabs[b.Operation].Check([]byte(b.Body), route)
		if err != nil {
			t.Errorf("%d %s: %v", b.Seq, b.Operation, err)
			continue
		}
		if !slices.Equal(got.Lookups, wantLookups[b.Seq]) {
			t.Errorf("%d: lookups %v, want %v", b.Seq, got.Lookups, wantLookups[b.Seq])
		}
		out, err := Read(got.Body)
		if err != nil {
			t.Fatalf("%d: the output does not read back: %v", b.Seq, err)
		}
		if stamps[b.Operation] {
			if l := out["Labels"].(map[string]any)[LabelKey]; l != project {
				t.Errorf("%d: label %v", b.Seq, l)
			}
		} else if _, ok := out["Labels"]; ok {
			t.Errorf("%d: an %s was labelled", b.Seq, b.Operation)
		}
		if p, ok := wantPort[b.Seq]; ok {
			bindings := out["HostConfig"].(map[string]any)["PortBindings"].(map[string]any)["5432/tcp"]
			want := []any{map[string]any{"HostIp": "127.101.170.171", "HostPort": p}}
			if !reflect.DeepEqual(bindings, want) {
				t.Errorf("%d: bindings %v", b.Seq, bindings)
			}
			if !slices.Contains(got.Account, "hostip 5432/tcp->127.101.170.171:"+p) {
				t.Errorf("%d: account %v", b.Seq, got.Account)
			}
		}
		// Apart from the label and the address, what goes upstream is what
		// was sent.
		in, _ := Read([]byte(b.Body))
		if stamps[b.Operation] {
			labels := out["Labels"].(map[string]any)
			delete(labels, LabelKey)
			if len(labels) == 0 {
				out["Labels"] = in["Labels"]
			}
		}
		if _, ok := wantPort[b.Seq]; ok {
			bindings := in["HostConfig"].(map[string]any)["PortBindings"].(map[string]any)["5432/tcp"].([]any)
			bindings[0].(map[string]any)["HostIp"] = "127.101.170.171"
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("%d: changed beyond the label and address", b.Seq)
		}
	}
}

// Each filter Compose sent keeps every term it had and gains the project's.
func TestEveryFilterComposeSentIsMergedWithTheLabel(t *testing.T) {
	var c capture
	load(t, "testdata/compose-5.4.0.json", &c)
	allowed := map[string][]string{
		"ContainerList": {"label", "name", "id", "status", "health", "exited"},
		"VolumeList":    {"label", "name", "dangling", "driver"},
		"NetworkList":   {"label", "name", "id", "driver", "type", "scope", "dangling"},
	}
	for _, f := range c.Filters {
		got, err := MergeFilter(f.Filters, allowed[f.Operation], project)
		if err != nil {
			t.Errorf("%d: %v", f.Seq, err)
			continue
		}
		var in map[string]map[string]bool
		var out map[string]map[string]bool
		json.Unmarshal([]byte(f.Filters), &in)
		if err := json.Unmarshal([]byte(got), &out); err != nil {
			t.Fatal(err)
		}
		in["label"][LabelKey+"="+project] = true
		if !reflect.DeepEqual(in, out) {
			t.Errorf("%d: %s", f.Seq, got)
		}
	}
}

func TestAListWithNoFilterGetsOnlyTheLabel(t *testing.T) {
	got, err := MergeFilter("", []string{"label"}, project)
	if err != nil || got != `{"label":{"frisket.project=example/shop":true}}` {
		t.Errorf("%s %v", got, err)
	}
}

func TestAFilterInTheOlderArrayFormIsNormalisedToTheObject(t *testing.T) {
	got, err := MergeFilter(`{"name":["db"],"label":["a=b"]}`, []string{"label", "name"}, project)
	want := `{"label":{"a=b":true,"frisket.project=example/shop":true},"name":{"db":true}}`
	if err != nil || got != want {
		t.Errorf("%s %v", got, err)
	}
}

func TestAFilterThatIsNotAllowedOrNotASetIsRefused(t *testing.T) {
	for _, f := range []string{
		`{"before":{"abc":true}}`,
		`{"since":["abc"]}`,
		`{"label":"a=b"}`,
		`{"label":{"a":"yes"}}`,
		`{"label":[1]}`,
		`{"label":{"a":true},"label":{"b":true}}`,
		`[]`,
		`{"label":{}} x`,
	} {
		_, err := MergeFilter(f, []string{"label", "name"}, project)
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != ReasonQuery {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// set puts v at a dotted path in a tree, making objects on the way.
func set(tree map[string]any, path string, v any) {
	segs := strings.Split(path, ".")
	m := tree
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[s] = next
		}
		m = next
	}
	m[segs[len(segs)-1]] = v
}

// label sets a label, whose key may hold dots.
func label(tree map[string]any, k string, v any) {
	labels, ok := tree["Labels"].(map[string]any)
	if !ok {
		labels = map[string]any{}
		tree["Labels"] = labels
	}
	labels[k] = v
}

func del(tree map[string]any, path string) {
	segs := strings.Split(path, ".")
	m := tree
	for _, s := range segs[:len(segs)-1] {
		m = m[s].(map[string]any)
	}
	delete(m, segs[len(segs)-1])
}

func encode(t testing.TB, tree any) []byte {
	t.Helper()
	b, err := Encode(tree)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func binding(ip any, port string) map[string]any {
	b := map[string]any{"HostPort": port}
	if ip != nil {
		b["HostIp"] = ip
	}
	return b
}

// Everything a body must not reach the host by, each a change to a body Compose
// really sent, so that each case differs from an admitted body in one thing.
func TestWhatReachesTheHostIsRefused(t *testing.T) {
	tabs := tables(t)
	other := projaddr.Address("example/billing").String()
	containerCases := []struct {
		name   string
		change func(map[string]any)
		reason string
	}{
		{"a bind of a host path", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"/etc:/x"}) }, ReasonBody},
		{"a bind of ~", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"~:/x"}) }, ReasonBody},
		{"a bind of ./x", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"./x:/x"}) }, ReasonBody},
		{"a bind with the z mode", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"vol:/x:z"}) }, ReasonBody},
		{"a bind with no destination", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"vol"}) }, ReasonBody},
		{"Privileged", func(b map[string]any) { set(b, "HostConfig.Privileged", true) }, ReasonBody},
		{"CapAdd", func(b map[string]any) { set(b, "HostConfig.CapAdd", []any{"SYS_ADMIN"}) }, ReasonBody},
		{"a bind mount", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "bind", "Source": "/", "Target": "/host"}})
		}, ReasonBody},
		{"a volume mount with a label in its options", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x",
				"VolumeOptions": map[string]any{"Labels": map[string]any{"a": "b"}}}})
		}, ReasonBody},
		{"a volume mount with a driver config", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x",
				"VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "local", "Options": map[string]any{"type": "none", "o": "bind", "device": "/"}}}}})
		}, ReasonBody},
		{"a mount with a field no mount may have", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x", "BindOptions": map[string]any{}}})
		}, ReasonBody},
		{"a tmpfs mount with a source", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "tmpfs", "Source": "/etc", "Target": "/x"}})
		}, ReasonBody},
		{"a tmpfs mount with volume options", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "tmpfs", "Target": "/x", "VolumeOptions": map[string]any{"NoCopy": true}}})
		}, ReasonBody},
		{"a tmpfs mount with mount options", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "tmpfs", "Target": "/x",
				"TmpfsOptions": map[string]any{"Options": []any{[]any{"exec"}}}}})
		}, ReasonBody},
		{"a volume mount with tmpfs options", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x",
				"TmpfsOptions": map[string]any{"SizeBytes": json.Number("1")}}})
		}, ReasonBody},
		{"a mount target holding :", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x:ro"}})
		}, ReasonBody},
		{"a mount target holding NUL", func(b map[string]any) {
			set(b, "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "vol", "Target": "/x\x00"}})
		}, ReasonBody},
		{"a Tmpfs key holding :", func(b map[string]any) { set(b, "HostConfig.Tmpfs", map[string]any{"/x:rw": ""}) }, ReasonBody},
		{"a Volumes key holding :", func(b map[string]any) { b["Volumes"] = map[string]any{"/data:/host": map[string]any{}} }, ReasonBody},
		{"a Volumes key holding NUL", func(b map[string]any) { b["Volumes"] = map[string]any{"/data\x00": map[string]any{}} }, ReasonBody},
		{"a bind target holding NUL", func(b map[string]any) { set(b, "HostConfig.Binds", []any{"vol:/x\x00"}) }, ReasonBody},
		{"MaskedPaths []", func(b map[string]any) { set(b, "HostConfig.MaskedPaths", []any{}) }, ReasonBody},
		{"ReadonlyPaths []", func(b map[string]any) { set(b, "HostConfig.ReadonlyPaths", []any{}) }, ReasonBody},
		{"NetworkMode \"\"", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "") }, ReasonBody},
		{"NetworkMode absent", func(b map[string]any) { del(b, "HostConfig.NetworkMode") }, ReasonBody},
		{"NetworkMode null", func(b map[string]any) { set(b, "HostConfig.NetworkMode", nil) }, ReasonBody},
		{"NetworkMode default", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "default") }, ReasonBody},
		{"NetworkMode bridge", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "bridge") }, ReasonBody},
		{"NetworkMode host", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "host") }, ReasonBody},
		{"NetworkMode Host", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "Host") }, ReasonBody},
		{"NetworkMode container:x", func(b map[string]any) { set(b, "HostConfig.NetworkMode", "container:x") }, ReasonBody},
		{"HostConfig absent", func(b map[string]any) { delete(b, "HostConfig") }, ReasonBody},
		{"HostConfig null", func(b map[string]any) { b["HostConfig"] = nil }, ReasonBody},
		{"an EndpointsConfig key of host", func(b map[string]any) {
			set(b, "NetworkingConfig.EndpointsConfig", map[string]any{"host": map[string]any{}})
		}, ReasonBody},
		{"PublishAllPorts", func(b map[string]any) { set(b, "HostConfig.PublishAllPorts", true) }, ReasonBody},
		{"a binding [{}]", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{map[string]any{}}})
		}, ReasonBody},
		{"a binding [null]", func(b map[string]any) { set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{nil}}) }, ReasonBody},
		{"a binding []", func(b map[string]any) { set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{}}) }, ReasonBody},
		{"a binding null", func(b map[string]any) { set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": nil}) }, ReasonBody},
		{"HostPort \"\"", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("", "")}})
		}, ReasonBody},
		{"a HostPort range", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("", "64320-64321")}})
		}, ReasonBody},
		{"an unlisted HostPort", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("", "64326")}})
		}, ReasonBody},
		{"a HostPort as a number", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{map[string]any{"HostPort": json.Number("64320")}}})
		}, ReasonBody},
		{"a key that is not a port", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcpx": []any{binding("", "64320")}})
		}, ReasonBody},
		{"HostIp ::", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("::", "64320")}})
		}, ReasonHostIP},
		{"HostIp ::1", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("::1", "64320")}})
		}, ReasonHostIP},
		{"HostIp [::]", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("[::]", "64320")}})
		}, ReasonHostIP},
		{"HostIp 10.0.0.1", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("10.0.0.1", "64320")}})
		}, ReasonHostIP},
		{"HostIp 127.0.0.2", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("127.0.0.2", "64320")}})
		}, ReasonHostIP},
		{"HostIp another project's address", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding(other, "64320")}})
		}, ReasonHostIP},
		{"HostIp null", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{map[string]any{"HostIp": nil, "HostPort": "64320"}}})
		}, ReasonHostIP},
		{"Tmpfs options", func(b map[string]any) { set(b, "HostConfig.Tmpfs", map[string]any{"/x": "exec,size=1g"}) }, ReasonBody},
		{"a Tmpfs key that is not a path", func(b map[string]any) { set(b, "HostConfig.Tmpfs", map[string]any{"x": ""}) }, ReasonBody},
		{"LogConfig syslog", func(b map[string]any) { set(b, "HostConfig.LogConfig.Type", "syslog") }, ReasonBody},
		{"LogConfig.Config", func(b map[string]any) {
			set(b, "HostConfig.LogConfig.Config", map[string]any{"max-size": "1m"})
		}, ReasonBody},
		{"RestartPolicy always", func(b map[string]any) { set(b, "HostConfig.RestartPolicy.Name", "always") }, ReasonBody},
		{"Dns", func(b map[string]any) { set(b, "HostConfig.Dns", []any{"1.1.1.1"}) }, ReasonBody},
		{"DnsOptions", func(b map[string]any) { set(b, "HostConfig.DnsOptions", []any{"ndots:1"}) }, ReasonBody},
		{"DnsSearch", func(b map[string]any) { set(b, "HostConfig.DnsSearch", []any{"example.com"}) }, ReasonBody},
		{"a label frisket.project", func(b map[string]any) { label(b, LabelKey, "example/billing") }, ReasonBody},
		{"a label Frisket.X", func(b map[string]any) { label(b, "Frisket.X", "y") }, ReasonBody},
		{"a label that is not a string", func(b map[string]any) { label(b, "x", true) }, ReasonBody},
		{"\"privileged\": true", func(b map[string]any) { set(b, "HostConfig.privileged", true) }, ReasonBody},
		{"\"privileged\": false", func(b map[string]any) { set(b, "HostConfig.privileged", false) }, ReasonBody},
		{"a hostIp beside its HostIp", func(b map[string]any) {
			set(b, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{map[string]any{"HostIp": "", "HostPort": "64320", "hostIp": ""}}})
		}, ReasonBody},
		{"an image not listed", func(b map[string]any) { b["Image"] = "alpine:3" }, ReasonBody},
		{"no image", func(b map[string]any) { delete(b, "Image") }, ReasonBody},
		{"an endpoint's IPAddress", func(b map[string]any) {
			set(b, "NetworkingConfig.EndpointsConfig.frisket-capture_default.IPAddress", "10.0.0.2")
		}, ReasonBody},
		{"an unknown field at the root", func(b map[string]any) { b["Platform"] = "" }, ReasonBody},
	}
	for _, c := range containerCases {
		body := captured(t, 17)
		c.change(body)
		expectRefused(t, tabs["ContainerCreate"], c.name, encode(t, body), c.reason)
	}

	volume := func(change func(map[string]any)) []byte {
		b := captured(t, 15)
		change(b)
		return encode(t, b)
	}
	network := func(change func(map[string]any)) []byte {
		b := captured(t, 16)
		change(b)
		return encode(t, b)
	}
	for name, body := range map[string][]byte{
		"a VolumeCreate binding a host path": volume(func(b map[string]any) {
			b["DriverOpts"] = map[string]any{"type": "none", "o": "bind", "device": "/"}
		}),
		"a VolumeCreate with another driver":   volume(func(b map[string]any) { b["Driver"] = "nfs" }),
		"a VolumeCreate with an all-hex Name":  volume(func(b map[string]any) { b["Name"] = "deadbeef" }),
		"a VolumeCreate with a frisket. label": volume(func(b map[string]any) { label(b, "FRISKET.project", "x") }),
		"a NetworkCreate with Options": network(func(b map[string]any) {
			b["Options"] = map[string]any{"com.docker.network.bridge.host_binding_ipv4": "0.0.0.0"}
		}),
		"a NetworkCreate with an all-hex Name":  network(func(b map[string]any) { b["Name"] = "0123abcd" }),
		"a NetworkCreate with the host driver":  network(func(b map[string]any) { b["Driver"] = "host" }),
		"a NetworkCreate with a frisket. label": network(func(b map[string]any) { label(b, LabelKey, project) }),
	} {
		op := "VolumeCreate"
		if strings.HasPrefix(name, "a NetworkCreate") {
			op = "NetworkCreate"
		}
		expectRefused(t, tabs[op], name, body, ReasonBody)
	}
	expectRefused(t, tabs["ExecCreate"], "a privileged exec",
		[]byte(`{"User":"","Privileged":true,"Cmd":["sh"]}`), ReasonBody)
}

// A body that is not exactly one plain object is refused before any table.
func TestABodyThatCannotBeReadOneWayIsRefused(t *testing.T) {
	tabs := tables(t)
	for name, body := range map[string]string{
		"a duplicate key":            `{"Detach":false,"Detach":true}`,
		"a duplicate key deep":       `{"ConsoleSize":[{"a":1,"a":2}]}`,
		"a trailing value":           `{"Detach":false}{}`,
		"a trailing byte":            `{"Detach":false} x`,
		"invalid UTF-8":              "{\"Detach\":\"\xff\"}",
		"a BOM":                      "\xef\xbb\xbf{\"Detach\":false}",
		"an array":                   `[]`,
		"nothing":                    ``,
		"a string":                   `"x"`,
		"a truncated object":         `{"Detach":false`,
		"a key without a value":      `{"Detach"}`,
		"a case twin at the root":    `{"Detach":false,"detach":false}`,
		"an unknown field with zero": `{"Stream":false}`,
	} {
		expectRefused(t, tabs["ExecStart"], name, []byte(body), "")
	}
}

// 32 deep is the most there may be, the outermost object being 1, in objects
// or in arrays; 33 is unreadable, whatever a table would say of it.
func TestABodyNestedMoreThan32DeepIsUnreadable(t *testing.T) {
	objects := func(n int) string { return strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1) }
	arrays := func(n int) string { return `{"a":` + strings.Repeat(`[`, n-1) + strings.Repeat(`]`, n-1) + `}` }
	for name, body := range map[string]string{"objects": objects(32), "arrays": arrays(32)} {
		if _, err := Read([]byte(body)); err != nil {
			t.Errorf("32 deep in %s: %v", name, err)
		}
	}
	for name, body := range map[string]string{"objects": objects(33), "arrays": arrays(33)} {
		_, err := Read([]byte(body))
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != ReasonUnreadable {
			t.Errorf("33 deep in %s: %v", name, err)
		}
	}
	// Through a table, on a key it lists, only the reader can refuse.
	expectRefused(t, tables(t)["ExecStart"], "33 deep under ConsoleSize",
		[]byte(`{"ConsoleSize":`+strings.Repeat(`[`, 32)+strings.Repeat(`]`, 32)+`}`), ReasonUnreadable)
	if _, err := tables(t)["ExecStart"].Check([]byte(`{"ConsoleSize":`+strings.Repeat(`[`, 31)+strings.Repeat(`]`, 31)+`}`), route); err != nil {
		t.Errorf("32 deep under ConsoleSize: %v", err)
	}
}

// A zero field is zero by the number's digits: 0 in any spelling passes, and
// a number that is not 0 -- however close, 1e-400 included -- is refused.
func TestAZeroFieldReadsNumbersByTheirDigits(t *testing.T) {
	tb := tables(t)["ContainerCreate"]
	for _, n := range []string{"0", "0.0", "-0", "0e5", "-0.000E-3"} {
		body := captured(t, 17)
		set(body, "HostConfig.CpuQuota", json.Number(n))
		if _, err := tb.Check(encode(t, body), route); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"1e-400", "0.1", "-1", "1", "0.0000001", "10e-1"} {
		body := captured(t, 17)
		set(body, "HostConfig.CpuQuota", json.Number(n))
		expectRefused(t, tb, "CpuQuota "+n, encode(t, body), ReasonBody)
	}
}

// expectRefused checks a body is refused, with the reason if one is given,
// and that the message the client reads holds nothing of the body but what
// the table itself names.
func expectRefused(t *testing.T, tb *Table, name string, body []byte, reason string) {
	t.Helper()
	_, err := tb.Check(body, route)
	var r *Refusal
	if !errors.As(err, &r) {
		t.Errorf("%s: admitted, or not a refusal: %v", name, err)
		return
	}
	if reason != "" && r.Reason != reason {
		t.Errorf("%s: %q, want %q", name, r.Error(), reason)
	}
	if r.Log == "" {
		t.Errorf("%s: no log", name)
	}
	for _, leak := range []string{"SYS_ADMIN", "/etc", "10.0.0", "::", "syslog", "always", "1.1.1.1", "alpine", "Frisket.X", "privileged\"", "hostIp", "exec,size", "finance", "deadbeef", "0123abcd", "nfs", "Platform", "64326"} {
		if strings.Contains(r.Error(), leak) {
			t.Errorf("%s: the message %q quotes the request", name, r.Error())
		}
	}
}

func portBindings(t *testing.T, body map[string]any) (map[string]any, Checked) {
	t.Helper()
	got, err := tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Read(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	return out["HostConfig"].(map[string]any)["PortBindings"].(map[string]any), got
}

// An unspecified, any-address or 127.0.0.1 HostIp is the project's address
// upstream, so nothing is published on an address another project's session
// could reach.
func TestAHostIpThatSaysNothingOrLoopbackBecomesTheProjectsAddress(t *testing.T) {
	for _, ip := range []any{nil, "", "0.0.0.0", "127.0.0.1", "127.101.170.171"} {
		body := captured(t, 17)
		set(body, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding(ip, "64320")}})
		pb, _ := portBindings(t, body)
		want := []any{map[string]any{"HostIp": "127.101.170.171", "HostPort": "64320"}}
		if !reflect.DeepEqual(pb["5432/tcp"], want) {
			t.Errorf("%v: %v", ip, pb)
		}
	}
}

func TestTwoBindingsOfOneHostPortCollapseIntoOne(t *testing.T) {
	body := captured(t, 17)
	set(body, "HostConfig.PortBindings", map[string]any{
		"5432/tcp": []any{binding("", "64320"), binding("127.0.0.1", "64320"), binding(nil, "64321")},
	})
	pb, got := portBindings(t, body)
	want := []any{
		map[string]any{"HostIp": "127.101.170.171", "HostPort": "64320"},
		map[string]any{"HostIp": "127.101.170.171", "HostPort": "64321"},
	}
	if !reflect.DeepEqual(pb["5432/tcp"], want) {
		t.Errorf("%v", pb)
	}
	if !slices.Contains(got.Account, "hostip 5432/tcp->127.101.170.171:64320 collapsed") {
		t.Errorf("the log does not say so: %v", got.Account)
	}
}

// frisket makes Labels to stamp when a create has none, or null.
func TestACreateWithNoLabelsIsStamped(t *testing.T) {
	tabs := tables(t)
	for _, c := range []struct {
		op   string
		body string
	}{
		{"VolumeCreate", `{"Name":"v","Labels":null}`},
		{"VolumeCreate", `{}`},
		{"NetworkCreate", `{"Name":"n","Labels":null}`},
		{"ContainerCreate", `{"Image":"postgres:18","Labels":null,"HostConfig":{"NetworkMode":"none"}}`},
		{"ContainerCreate", `{"Image":"postgres:18","HostConfig":{"NetworkMode":"none"}}`},
	} {
		got, err := tabs[c.op].Check([]byte(c.body), route)
		if err != nil {
			t.Errorf("%s %s: %v", c.op, c.body, err)
			continue
		}
		out, _ := Read(got.Body)
		if !reflect.DeepEqual(out["Labels"], map[string]any{LabelKey: project}) {
			t.Errorf("%s %s: %s", c.op, c.body, got.Body)
		}
	}
}

func TestAnExecIsNotStamped(t *testing.T) {
	got, err := tables(t)["ExecStart"].Check([]byte(`{"Detach":false}`), route)
	if err != nil || string(got.Body) != `{"Detach":false}` {
		t.Errorf("%s %v", got.Body, err)
	}
}

// A mount of a volume is looked up as a mount, which may be anonymous (a
// recreate carries the daemon's 64-hex name, as in capture seq 2); a
// tmpfs with only a size and a mode needs nothing looked up.
func TestVolumeAndTmpfsMountsAreAdmitted(t *testing.T) {
	const anon = "a43153268aa27b711843120e030d35d73b89d312f1942a11027a2eae1aaf28e8"
	body := captured(t, 17)
	set(body, "HostConfig.Mounts", []any{
		map[string]any{"Type": "volume", "Source": anon, "Target": "/var/lib/postgresql", "VolumeOptions": map[string]any{"NoCopy": true}},
		map[string]any{"Type": "tmpfs", "Target": "/tmp", "TmpfsOptions": map[string]any{"SizeBytes": json.Number("1024"), "Mode": json.Number("1777")}},
	})
	got, err := tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.Lookups, Lookup{"volume", anon, Mount}) {
		t.Errorf("%v", got.Lookups)
	}
}

// Only a whole anonymous-volume name is taken as one: a shorter or longer
// run of hex is refused as a mount's source.
func TestAnAllHexMountSourceMustBeAWholeAnonymousVolumeName(t *testing.T) {
	anon := "a43153268aa27b711843120e030d35d73b89d312f1942a11027a2eae1aaf28e8"
	for _, src := range []string{anon[:12], anon + "0"} {
		body := captured(t, 17)
		set(body, "HostConfig.Mounts", []any{
			map[string]any{"Type": "volume", "Source": src, "Target": "/data"},
		})
		if _, err := tables(t)["ContainerCreate"].Check(encode(t, body), route); err == nil {
			t.Errorf("%s admitted", src)
		}
	}
}

// Binds keep refusing an all-hex name, anonymous or not.
func TestAnAllHexBindSourceIsRefused(t *testing.T) {
	body := captured(t, 17)
	set(body, "HostConfig.Binds", []any{"a43153268aa27b711843120e030d35d73b89d312f1942a11027a2eae1aaf28e8:/data"})
	if _, err := tables(t)["ContainerCreate"].Check(encode(t, body), route); err == nil {
		t.Error("admitted")
	}
}

func TestTheRefusalLogNamesTheRequestsKeyQuotedAndClipped(t *testing.T) {
	body := captured(t, 17)
	set(body, "HostConfig.privileged", true)
	_, err := tables(t)["ContainerCreate"].Check(encode(t, body), route)
	var r *Refusal
	if !errors.As(err, &r) || r.Log != `field=HostConfig."privileged" unknown` {
		t.Fatalf("%#v", err)
	}
	if r.Error() != "body not allowed: a field under ContainerCreate's HostConfig that its table does not list" {
		t.Errorf("%q", r.Error())
	}
	body = captured(t, 17)
	body[strings.Repeat("k", 300)] = 1
	_, err = tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if !errors.As(err, &r) || r.Log != `field="`+strings.Repeat("k", 128)+`" unknown` {
		t.Fatalf("%#v", err)
	}
	body = captured(t, 17)
	set(body, "HostConfig.Privileged", true)
	_, err = tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if !errors.As(err, &r) || r.Log != "field=HostConfig.Privileged not zero" ||
		r.Error() != "body not allowed: ContainerCreate's HostConfig.Privileged not zero" {
		t.Fatalf("%#v", err)
	}
	body = captured(t, 17)
	set(body, "HostConfig.PortBindings", map[string]any{"5432/tcp": []any{binding("::", "64320")}})
	_, err = tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if !errors.As(err, &r) || r.Log != `hostip 5432/tcp="::" not allowed` ||
		r.Error() != "hostip not allowed: ContainerCreate's HostConfig.PortBindings" {
		t.Fatalf("%#v", err)
	}
}

// weaken compiles a copy of a table with one path's spec replaced, or removed
// when spec is nil.
func weaken(t *testing.T, name string, path string, spec any) error {
	t.Helper()
	raw := maps.Clone(rawTable(t, name))
	if spec == nil {
		delete(raw, path)
	} else {
		raw[path] = spec
	}
	_, err := Compile(name, encode(t, raw))
	return err
}

// floorPaths are the floor's paths, written out here rather than
// taken from the code's floors, so that a path the code drops is missed.
var floorPaths = func() map[string][]string {
	container := []string{"Image", "HostConfig.NetworkMode", "Labels", "HostConfig.Binds", "HostConfig.Mounts",
		"HostConfig.PortBindings", "NetworkingConfig.EndpointsConfig", "HostConfig.MaskedPaths",
		"HostConfig.ReadonlyPaths", "HostConfig.Tmpfs.*", "HostConfig.LogConfig.Type", "HostConfig.LogConfig.Config",
		"HostConfig.RestartPolicy.Name"}
	for _, p := range []string{"PublishAllPorts", "VolumeDriver", "VolumesFrom", "Privileged", "CapAdd",
		"SecurityOpt", "Devices", "DeviceRequests", "DeviceCgroupRules", "PidMode", "IpcMode", "UTSMode",
		"UsernsMode", "CgroupnsMode", "Cgroup", "CgroupParent", "Runtime", "Sysctls", "Annotations", "Links",
		"StorageOpt", "Isolation", "ExtraHosts", "Dns", "DnsOptions", "DnsSearch", "ContainerIDFile"} {
		container = append(container, "HostConfig."+p)
	}
	for _, p := range []string{"IPAMConfig", "Links", "DriverOpts", "MacAddress", "IPAddress", "NetworkID", "EndpointID"} {
		container = append(container, "NetworkingConfig.EndpointsConfig.*."+p)
	}
	return map[string][]string{
		"ContainerCreate": container,
		"ExecCreate":      {"Privileged"},
		"ExecStart":       nil,
		"VolumeCreate":    {"Driver", "DriverOpts", "ClusterVolumeSpec", "Labels", "Name"},
		"NetworkCreate":   {"Driver", "Options", "IPAM", "ConfigFrom", "ConfigOnly", "Ingress", "Labels", "Name"},
	}
}()

func TestTheFloorIsTheContracts(t *testing.T) {
	for name, want := range floorPaths {
		var got []string
		for _, r := range floors[name] {
			got = append(got, r.path)
		}
		slices.Sort(got)
		want = slices.Sorted(slices.Values(want))
		if !slices.Equal(got, want) {
			t.Errorf("%s: floor %q, want %q", name, got, want)
		}
	}
	if len(floors) != len(floorPaths) {
		t.Errorf("floors for %d operations, want %d", len(floors), len(floorPaths))
	}
}

// Every path of the floor, made `any`, fails to compile; so does an `any` at
// any ancestor of one, which would let it through unjudged.
func TestATableWeakerThanTheFloorAtAnyPathFailsToCompile(t *testing.T) {
	for name, paths := range floorPaths {
		for _, path := range paths {
			if err := weaken(t, name, path, "any"); err == nil {
				t.Errorf("%s: %s any compiled", name, path)
			}
			segs := strings.Split(path, ".")
			for i := 1; i < len(segs); i++ {
				anc := strings.Join(segs[:i], ".")
				raw := map[string]any{}
				for p, s := range rawTable(t, name) {
					if !strings.HasPrefix(p, anc+".") {
						raw[p] = s
					}
				}
				raw[anc] = "any"
				if _, err := Compile(name, encode(t, raw)); err == nil {
					t.Errorf("%s: %s any, above %s, compiled", name, anc, path)
				}
			}
		}
	}
	for _, c := range []struct{ name, path string }{
		{"ContainerCreate", "HostConfig.MaskedPaths"},
		{"ContainerCreate", "HostConfig.Privileged"},
		{"ContainerCreate", "HostConfig.Binds"},
		{"ContainerCreate", "Labels"},
		{"VolumeCreate", "DriverOpts"},
		{"NetworkCreate", "Options"},
		{"ExecCreate", "Privileged"},
	} {
		if err := weaken(t, c.name, c.path, map[string]any{"enum": []any{"", true}}); err == nil {
			t.Errorf("%s: %s as an enum compiled", c.name, c.path)
		}
	}
	for _, c := range []struct {
		name, path string
		spec       any
	}{
		{"ContainerCreate", "HostConfig.MaskedPaths", "zero"},
		{"ContainerCreate", "HostConfig.LogConfig.Type", map[string]any{"enum": []any{"", "syslog"}}},
		{"ContainerCreate", "HostConfig.RestartPolicy.Name", map[string]any{"enum": []any{"always"}}},
		{"ContainerCreate", "HostConfig.Tmpfs", "struct"},
		{"ContainerCreate", "NetworkingConfig.EndpointsConfig", "map/absPath"},
		{"ContainerCreate", "HostConfig.Binds", "mounts"},
		{"VolumeCreate", "Driver", map[string]any{"enum": []any{"", "local", "nfs"}}},
		{"NetworkCreate", "Driver", map[string]any{"enum": []any{"host"}}},
		{"VolumeCreate", "Name", "any"},
	} {
		if err := weaken(t, c.name, c.path, c.spec); err == nil {
			t.Errorf("%s: %s %v compiled", c.name, c.path, c.spec)
		}
	}
}

// folds are the spellings of a name that encoding/json, and so moby, reads as
// it: lower and upper case, and the two non-ASCII letters that fold to ASCII,
// U+017F for s and U+212A for k.
func folds(seg string) []string {
	var out []string
	for _, f := range []string{strings.ToLower(seg), strings.ToUpper(seg),
		strings.ReplaceAll(strings.ReplaceAll(seg, "s", "\u017f"), "S", "\u017f"),
		strings.ReplaceAll(strings.ReplaceAll(seg, "k", "\u212a"), "K", "\u212a")} {
		if f != seg && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// A table that spells a floor path, or any struct above one, in a case the
// daemon folds to it -- and so leaves the path itself out -- fails to compile,
// however it judges the other spelling.
func TestATableNamingAFloorPathInAnotherCaseFailsToCompile(t *testing.T) {
	for name, paths := range floorPaths {
		for _, path := range paths {
			segs := strings.Split(path, ".")
			for i, seg := range segs {
				if seg == "*" {
					continue
				}
				prefix := strings.Join(segs[:i+1], ".")
				for _, f := range folds(seg) {
					folded := strings.Join(append(append(slices.Clone(segs[:i]), f), segs[i+1:]...), ".")
					fprefix := strings.Join(append(slices.Clone(segs[:i]), f), ".")
					raw := map[string]any{}
					for p, s := range rawTable(t, name) {
						switch {
						case p == prefix:
							raw[fprefix] = s
						case strings.HasPrefix(p, prefix+"."):
							raw[fprefix+strings.TrimPrefix(p, prefix)] = s
						default:
							raw[p] = s
						}
					}
					// The ancestors of the folded spelling, so that it places.
					for j := i + 1; j < len(segs); j++ {
						anc := strings.Join(append(append(slices.Clone(segs[:i]), f), segs[i+1:j]...), ".")
						if _, ok := raw[anc]; !ok {
							if segs[j] == "*" {
								raw[anc] = "map/absPath"
							} else {
								raw[anc] = "struct"
							}
						}
					}
					raw[folded] = "any"
					if _, err := Compile(name, encode(t, raw)); err == nil {
						t.Errorf("%s: %q any, for %s, compiled", name, folded, path)
					}
				}
			}
		}
	}
	// The probe's cases, each once more by name.
	for _, c := range []struct{ name, exact, folded string }{
		{"ContainerCreate", "HostConfig.Privileged", "HostConfig.privileged"},
		{"ContainerCreate", "HostConfig.Binds", "HostConfig.binds"},
		{"ContainerCreate", "HostConfig.SecurityOpt", "HostConfig.\u017fecurityOpt"},
		{"ContainerCreate", "Labels", "labels"},
	} {
		raw := maps.Clone(rawTable(t, c.name))
		delete(raw, c.exact)
		raw[c.folded] = "any"
		if _, err := Compile(c.name, encode(t, raw)); err == nil {
			t.Errorf("%s: %q any compiled", c.name, c.folded)
		}
	}
}

// Even past a table, a body with Labels in another case is never stamped:
// the daemon would read whichever of the two came last.
func TestABodyWithLabelsInAnotherCaseIsNotStamped(t *testing.T) {
	raw := `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Labels":"labels","Env":"any"}`
	tb, err := Compile("ContainerCreate", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var tree = map[string]any{"Image": "postgres:18", "HostConfig": map[string]any{"NetworkMode": "none"},
		"labels": map[string]any{LabelKey: "example/billing"}}
	if err := stamp(tree, project); err == nil {
		t.Errorf("stamped beside %v", tree["labels"])
	}
	expectRefused(t, tb, "labels beside Labels", encode(t, tree), ReasonBody)
}

func TestATableMissingImageOrNetworkModeFailsToCompile(t *testing.T) {
	if err := weaken(t, "ContainerCreate", "Image", nil); err == nil {
		t.Error("no Image compiled")
	}
	if err := weaken(t, "ContainerCreate", "HostConfig.NetworkMode", nil); err == nil {
		t.Error("no NetworkMode compiled")
	}
}

// Stricter is allowed: zero where the floor has a spec, a left-out path, a
// smaller enum.
func TestATableStricterThanTheFloorCompiles(t *testing.T) {
	for _, c := range []struct {
		name, path string
		spec       any
	}{
		{"ContainerCreate", "HostConfig.Binds", "zero"},
		{"ContainerCreate", "HostConfig.Mounts", nil},
		{"ContainerCreate", "HostConfig.PortBindings", "null"},
		{"ContainerCreate", "HostConfig.LogConfig.Type", map[string]any{"enum": []any{"json-file"}}},
		{"ContainerCreate", "HostConfig.Privileged", "null"},
	} {
		if err := weaken(t, c.name, c.path, c.spec); err != nil {
			t.Errorf("%s: %s %v: %v", c.name, c.path, c.spec, err)
		}
	}
}

func TestAMalformedTableFailsToCompile(t *testing.T) {
	for name, table := range map[string]string{
		"a case twin of a sibling": `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","HostConfig.networkMode":"zero"}`,
		"a Unicode case twin":      `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Kind":"any","\u212aind":"any"}`,
		"a child of a leaf":        `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Env":"any","Env.X":"zero"}`,
		"a child with no parent":   `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Healthcheck.Test":"any"}`,
		"a map with no *":          `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Volumes":"map/absPath"}`,
		"a named child of a map":   `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Volumes":"map/absPath","Volumes.*":"zero","Volumes.x":"zero"}`,
		"* under a struct":         `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","HostConfig.*":"zero"}`,
		"an unknown spec":          `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Env":"anything"}`,
		"an unknown key check":     `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Volumes":"map/any","Volumes.*":"zero"}`,
		"an enum of objects":       `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Env":{"enum":[{}]}}`,
		"an empty segment":         `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","HostConfig.":"zero"}`,
		"a path twice":             `{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network","Env":"any","Env":"zero"}`,
	} {
		if _, err := Compile("ContainerCreate", []byte(table)); err == nil {
			t.Errorf("%s compiled", name)
		}
	}
	if _, err := Compile("ImageBuild", []byte(`{}`)); err == nil {
		t.Error("a table frisket has no floor for compiled")
	}
	if _, err := Compile("ContainerCreate", []byte(`{"Image":"image","HostConfig":"struct","HostConfig.NetworkMode":"network"}`)); err != nil {
		t.Errorf("the smallest ContainerCreate: %v", err)
	}
}

// A create goes upstream naming every network it attaches to by the ID the
// daemon gave for it, in NetworkMode and as each key of EndpointsConfig,
// with each endpoint's own settings kept: the daemon resolves a name again
// at every start, when it may be another project's network.
func TestANetworkAContainerAttachesToGoesUpstreamAsItsID(t *testing.T) {
	const a, b = "372e029d9dd22674f10f3dfb1ba4aa9f9fa8a8de46589f67eab8fa3425d7915c",
		"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	body := captured(t, 17)
	eps := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)
	eps["other_net"] = map[string]any{"Aliases": []any{"x"}}
	got, err := tables(t)["ContainerCreate"].Check(encode(t, body), route)
	if err != nil {
		t.Fatal(err)
	}
	out, err := got.Attached(map[string]string{"frisket-capture_default": a, "other_net": b})
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := Read(out)
	if mode := sent["HostConfig"].(map[string]any)["NetworkMode"]; mode != a {
		t.Errorf("NetworkMode %v", mode)
	}
	sentEps := sent["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)
	if !reflect.DeepEqual(slices.Sorted(maps.Keys(sentEps)), []string{a, b}) {
		t.Errorf("EndpointsConfig keys %v", slices.Sorted(maps.Keys(sentEps)))
	}
	if aliases := sentEps[a].(map[string]any)["Aliases"]; !reflect.DeepEqual(aliases, []any{"frisket-capture-test-db-1", "test-db"}) {
		t.Errorf("the endpoint lost its aliases: %v", aliases)
	}
	if sent["Labels"].(map[string]any)[LabelKey] != project {
		t.Errorf("unstamped: %s", out)
	}
}

// "none" is no network, and is sent as it came; a network with no ID given
// for it is refused rather than sent by its name.
func TestAttachedKeepsNoneAndRefusesANetworkWithNoID(t *testing.T) {
	tabs := tables(t)
	got, err := tabs["ContainerCreate"].Check([]byte(`{"Image":"postgres:18","HostConfig":{"NetworkMode":"none"}}`), route)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := got.Attached(nil); err != nil || !strings.Contains(string(out), `"NetworkMode":"none"`) {
		t.Errorf("%s %v", out, err)
	}
	got, err = tabs["ContainerCreate"].Check([]byte(`{"Image":"postgres:18","HostConfig":{"NetworkMode":"n"}}`), route)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range []map[string]string{nil, {"n": ""}, {"n": "abc"}, {"n": strings.Repeat("A", 64)}} {
		var r *Refusal
		if _, err := got.Attached(ids); !errors.As(err, &r) {
			t.Errorf("%v: %v", ids, err)
		}
	}
}
