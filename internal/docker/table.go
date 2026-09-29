package docker

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// kind is what a spec in a table says of the value at its path.
type kind int

const (
	kStruct kind = iota
	kMap
	kAny
	kZero
	kNull
	kImage
	kLabels
	kObjectName
	kBinds
	kMounts
	kNetwork
	kPortBindings
	kEnum
)

var kindNames = map[string]kind{
	"struct":       kStruct,
	"any":          kAny,
	"zero":         kZero,
	"null":         kNull,
	"image":        kImage,
	"labels":       kLabels,
	"objectName":   kObjectName,
	"binds":        kBinds,
	"mounts":       kMounts,
	"network":      kNetwork,
	"portBindings": kPortBindings,
}

// keyCheck is what every key of a map spec must pass.
type keyCheck int

const (
	keyAbsPath keyCheck = iota
	keyPort
	keyNetwork
)

var keyChecks = map[string]keyCheck{
	"absPath": keyAbsPath,
	"port":    keyPort,
	"network": keyNetwork,
}

// node is one path of a table, with its children.
type node struct {
	kind kind
	key  keyCheck // for kMap
	enum []any    // for kEnum: strings, json.Numbers, bools and nil
	// children are a struct's fields, by their exact name.
	children map[string]*node
	// elem judges every value of a map: the path's "*".
	elem *node
	// path is the table's own path to here, "*" and all: the only way a
	// refusal the client reads may say where.
	path string
}

// required is whether an absent value is judged as "", so that a body cannot
// leave the daemon to choose: an image, or a network mode, whose default is
// the bridge every container made outside frisket shares.
func (n *node) required() bool { return n.kind == kImage || n.kind == kNetwork }

// Table is a compiled body table: what one operation's body may hold.
type Table struct {
	name string
	root *node
}

// Name is the operation the table judges: ContainerCreate, ExecCreate,
// ExecStart, VolumeCreate or NetworkCreate.
func (t *Table) Name() string { return t.name }

// Compile reads a table in the flat format of the contract's section 1.4 --
// one object mapping a path, `Field(.Field)*` with `*` for any key of a map,
// to a spec -- and checks it against frisket's floor for the operation it is
// named for. A name frisket has no floor for does not compile, so a table
// cannot escape the floor by what it is called; the route ties each rule's
// operation to the table named for it.
func Compile(name string, raw []byte) (*Table, error) {
	f, ok := floors[name]
	if !ok {
		return nil, fmt.Errorf("no body table is called %q", name)
	}
	entries, err := Read(raw)
	if err != nil {
		return nil, fmt.Errorf("table %s: %w", name, err)
	}
	root := &node{kind: kStruct, children: map[string]*node{}}
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	// A parent before its children: fewer segments first.
	sort.Slice(paths, func(i, j int) bool {
		si, sj := strings.Count(paths[i], "."), strings.Count(paths[j], ".")
		if si != sj {
			return si < sj
		}
		return paths[i] < paths[j]
	})
	for _, p := range paths {
		if err := place(root, p, entries[p]); err != nil {
			return nil, fmt.Errorf("table %s: %s: %w", name, p, err)
		}
	}
	if err := complete(root); err != nil {
		return nil, fmt.Errorf("table %s: %w", name, err)
	}
	for _, rule := range f {
		if err := rule.check(root); err != nil {
			return nil, fmt.Errorf("table %s is weaker than frisket's floor: %w", name, err)
		}
	}
	return &Table{name: name, root: root}, nil
}

// place puts the spec for path p under root, whose ancestors of p are already
// placed.
func place(root *node, p string, spec any) error {
	segs := strings.Split(p, ".")
	parent := root
	for i, s := range segs[:len(segs)-1] {
		child := parent.child(s)
		if child == nil {
			return fmt.Errorf("no spec for %s, which it is under", strings.Join(segs[:i+1], "."))
		}
		parent = child
	}
	last := segs[len(segs)-1]
	n, err := parseSpec(spec)
	if err != nil {
		return err
	}
	n.path = p
	switch parent.kind {
	case kStruct:
		if last == "" || last == "*" {
			return fmt.Errorf("a struct's field must be a name")
		}
		for sib := range parent.children {
			// moby matches a key to a field in any case, so two fields that
			// differ only in case are one field to the daemon and two here.
			if strings.EqualFold(sib, last) {
				return fmt.Errorf("the same field as %s, in another case", sib)
			}
		}
		parent.children[last] = n
	case kMap:
		if last != "*" {
			return fmt.Errorf("a map's only child is *")
		}
		parent.elem = n
	default:
		return fmt.Errorf("under a spec that has no fields")
	}
	return nil
}

func (n *node) child(seg string) *node {
	switch n.kind {
	case kStruct:
		return n.children[seg]
	case kMap:
		if seg == "*" {
			return n.elem
		}
	}
	return nil
}

// complete checks that every map says how its values are judged.
func complete(n *node) error {
	switch n.kind {
	case kStruct:
		for _, c := range n.children {
			if err := complete(c); err != nil {
				return err
			}
		}
	case kMap:
		if n.elem == nil {
			return fmt.Errorf("%s: a map with no %s.*", n.path, n.path)
		}
		return complete(n.elem)
	}
	return nil
}

func parseSpec(spec any) (*node, error) {
	switch s := spec.(type) {
	case string:
		if k, ok := kindNames[s]; ok {
			n := &node{kind: k}
			if k == kStruct {
				n.children = map[string]*node{}
			}
			return n, nil
		}
		if check, ok := strings.CutPrefix(s, "map/"); ok {
			if key, ok := keyChecks[check]; ok {
				return &node{kind: kMap, key: key}, nil
			}
		}
		return nil, fmt.Errorf("no spec is called %q", s)
	case map[string]any:
		values, ok := s["enum"].([]any)
		if len(s) != 1 || !ok {
			return nil, fmt.Errorf(`an object spec is {"enum": [...]}`)
		}
		for _, v := range values {
			switch v.(type) {
			case string, json.Number, bool, nil:
			default:
				return nil, fmt.Errorf("an enum lists scalars only")
			}
		}
		return &node{kind: kEnum, enum: values}, nil
	}
	return nil, fmt.Errorf("a spec is a name or an enum")
}

// floorRule is one path of frisket's floor: what a table must hold there, or
// something stricter.
type floorRule struct {
	path string
	// allowed are the specs that do. For an enum, allowed is empty and
	// values bounds it.
	allowed []kind
	values  []string
	// required is that the path must be in the table, not merely left out:
	// a leaf that judges an absent value.
	required bool
	// key, where allowed holds kMap, is the key check that map must have.
	key keyCheck
}

// check finds the path in the table. The path may be left out, because a key
// a struct does not list refuses anyway; but then everything above it must be
// a struct or map that walks down to it -- a name under a struct, `*` under a
// map -- or a zero or null that refuses whatever holds it. An `any` above a
// floor path would let whatever is under it through unjudged.
//
// moby reads a key as a field in any case, by encoding/json's simple folding
// (strings.EqualFold's), so a table naming a floor path in another case --
// "privileged", or "ſecurityOpt" with U+017F -- names that field to the
// daemon while leaving the path itself out here. Such a spelling fails.
func (r floorRule) check(root *node) error {
	n := root
	for _, seg := range strings.Split(r.path, ".") {
		switch {
		case n.kind == kZero || n.kind == kNull:
			return r.missing()
		case n.kind == kStruct && seg != "*":
			for _, name := range sortedKeys(n.children) {
				if name != seg && strings.EqualFold(name, seg) {
					return fmt.Errorf("%s: the table names it %s, in another case, which the daemon reads as it",
						r.path, quote(join(n.path, name)))
				}
			}
			n = n.children[seg]
		case n.kind == kMap && seg == "*":
			n = n.elem
		default:
			return fmt.Errorf("%s: %s is a spec that does not walk down to it", r.path, n.path)
		}
		if n == nil {
			return r.missing()
		}
	}
	if len(r.values) > 0 {
		if n.kind != kEnum {
			return fmt.Errorf("%s must be an enum within %q", r.path, r.values)
		}
		for _, v := range n.enum {
			s, ok := v.(string)
			if !ok || !slices.Contains(r.values, s) {
				return fmt.Errorf("%s must be an enum within %q", r.path, r.values)
			}
		}
		return nil
	}
	if !slices.Contains(r.allowed, n.kind) || n.kind == kMap && n.key != r.key {
		return fmt.Errorf("%s must be one of %s", r.path, kindList(r.allowed))
	}
	return nil
}

func (r floorRule) missing() error {
	if r.required {
		return fmt.Errorf("%s must be in the table", r.path)
	}
	return nil
}

func kindList(ks []kind) string {
	var names []string
	for _, k := range ks {
		for name, v := range kindNames {
			if v == k {
				names = append(names, name)
			}
		}
		if k == kMap {
			names = append(names, "map/network")
		}
	}
	return strings.Join(names, ", ")
}

// floors are frisket's floors, by operation: the contract's section 1.5.
var floors = map[string][]floorRule{
	"ContainerCreate": containerFloor(),
	"ExecCreate":      {zeroAt("Privileged")},
	"ExecStart":       nil,
	"VolumeCreate": {
		enumAt("Driver", "", "local"),
		// A DriverOpts of {type: none, o: bind, device: /} is a bind mount.
		zeroAt("DriverOpts"), zeroAt("ClusterVolumeSpec"),
		exactly("Labels", kLabels), exactly("Name", kObjectName),
	},
	"NetworkCreate": {
		enumAt("Driver", "", "bridge"),
		zeroAt("Options"), zeroAt("IPAM"), zeroAt("ConfigFrom"), zeroAt("ConfigOnly"), zeroAt("Ingress"),
		exactly("Labels", kLabels), exactly("Name", kObjectName),
	},
}

func containerFloor() []floorRule {
	f := []floorRule{
		{path: "Image", allowed: []kind{kImage}, required: true},
		{path: "HostConfig.NetworkMode", allowed: []kind{kNetwork}, required: true},
		exactly("Labels", kLabels),
		orZero("HostConfig.Binds", kBinds),
		orZero("HostConfig.Mounts", kMounts),
		orZero("HostConfig.PortBindings", kPortBindings),
		// Its keys are networks, each looked up and locked as NetworkMode's is.
		{path: "NetworkingConfig.EndpointsConfig", allowed: []kind{kMap, kZero, kNull}, key: keyNetwork},
		// [] unmasks every path the runtime masks, /proc/kcore and the rest.
		exactly("HostConfig.MaskedPaths", kNull),
		exactly("HostConfig.ReadonlyPaths", kNull),
		zeroAt("HostConfig.Tmpfs.*"),
		// The daemon runs in the host's network namespace, so a syslog, gelf
		// or fluentd driver would dial the host's loopback or its sockets.
		enumAt("HostConfig.LogConfig.Type", "", "json-file", "local"),
		zeroAt("HostConfig.LogConfig.Config"),
		enumAt("HostConfig.RestartPolicy.Name", "", "no", "on-failure"),
	}
	for _, p := range []string{"PublishAllPorts", "VolumeDriver", "VolumesFrom", "Privileged", "CapAdd",
		"SecurityOpt", "Devices", "DeviceRequests", "DeviceCgroupRules", "PidMode", "IpcMode", "UTSMode",
		"UsernsMode", "CgroupnsMode", "Cgroup", "CgroupParent", "Runtime", "Sysctls", "Annotations", "Links",
		"StorageOpt", "Isolation", "ExtraHosts", "Dns", "DnsOptions", "DnsSearch", "ContainerIDFile"} {
		f = append(f, zeroAt("HostConfig."+p))
	}
	for _, p := range []string{"IPAMConfig", "Links", "DriverOpts", "MacAddress", "IPAddress", "NetworkID", "EndpointID"} {
		f = append(f, zeroAt("NetworkingConfig.EndpointsConfig.*."+p))
	}
	return f
}

func zeroAt(path string) floorRule { return floorRule{path: path, allowed: []kind{kZero, kNull}} }

func exactly(path string, k kind) floorRule { return floorRule{path: path, allowed: []kind{k}} }

func orZero(path string, k kind) floorRule {
	return floorRule{path: path, allowed: []kind{k, kZero, kNull}}
}

func enumAt(path string, values ...string) floorRule { return floorRule{path: path, values: values} }
