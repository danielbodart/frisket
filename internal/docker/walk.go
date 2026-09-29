package docker

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// LabelKey is the label frisket stamps on everything it lets be created, and
// the only thing ownership rests on.
const LabelKey = "frisket.project"

// Route is what a table is judged against, beside the table: the route's
// project, its loopback address, the host ports it may publish and the
// images it may run.
type Route struct {
	Project string
	Address netip.Addr
	Ports   []uint16
	Images  []string
}

// Use is what the daemon must say of a name a body holds before the body may
// go upstream.
type Use int

const (
	// Bind is a volume in HostConfig.Binds. It must exist and be owned: the
	// daemon would create an absent one, without the label.
	Bind Use = iota
	// Mount is a volume in HostConfig.Mounts. It must be owned, or be
	// anonymous and mounted by an owned container, which is how Compose
	// carries an anonymous volume over a recreate.
	Mount
	// Attach is a network in NetworkMode or a key of EndpointsConfig. It must
	// exist and be owned.
	Attach
	// Create is the Name of a VolumeCreate or NetworkCreate. It is locked;
	// a volume's must be absent or owned, since VolumeCreate on an existing
	// name returns that volume.
	Create
)

// Lookup is one name a body holds that must be locked and looked up.
type Lookup struct {
	// Kind is "volume" or "network".
	Kind string
	Name string
	Use  Use
}

// Checked is a body that passed its table.
type Checked struct {
	// Body is what goes upstream: the tree that was judged, labelled and
	// rewritten, re-encoded.
	Body []byte
	// Lookups are the names to lock and look up, once each, in the order
	// the body gave them.
	Lookups []Lookup
	// Account is what frisket did, for the log line's docker attribute:
	// "stamped", "hostip 5432/tcp->127.1.191.78:64320" and the like. It
	// holds no value from an `any` field.
	Account []string
}

// stamps are the operations whose objects frisket labels.
var stamps = map[string]bool{"ContainerCreate": true, "VolumeCreate": true, "NetworkCreate": true}

// Check reads body and judges it against the table and the route. A body
// that fails is a *Refusal.
func (t *Table) Check(body []byte, rt Route) (Checked, error) {
	tree, err := Read(body)
	if err != nil {
		return Checked{}, err
	}
	w := &walker{table: t, route: rt}
	if err := w.value(t.root, tree, true, ""); err != nil {
		return Checked{}, err
	}
	if stamps[t.name] {
		if err := stamp(tree, rt.Project); err != nil {
			return Checked{}, err
		}
		w.account = append(w.account, "stamped")
	}
	out, err := Encode(tree)
	if err != nil {
		return Checked{}, err
	}
	return Checked{Body: out, Lookups: w.lookups, Account: w.account}, nil
}

// stamp sets the project's label, making Labels if it is absent or null.
func stamp(tree map[string]any, project string) error {
	// The floor keeps a table from listing Labels in another case, which
	// the daemon would read as Labels, and the last of the two it met.
	for k := range tree {
		if k != "Labels" && strings.EqualFold(k, "Labels") {
			return &Refusal{Reason: ReasonBody, Detail: "Labels in another case", Log: "field=" + quote(k) + " is Labels in another case"}
		}
	}
	switch labels := tree["Labels"].(type) {
	case nil:
		tree["Labels"] = map[string]any{LabelKey: project}
	case map[string]any:
		labels[LabelKey] = project
	default:
		// The floor keeps Labels a labels spec, which refuses this first.
		return &Refusal{Reason: ReasonBody, Detail: "Labels is not an object", Log: "field=Labels not an object"}
	}
	return nil
}

type walker struct {
	table   *Table
	route   Route
	lookups []Lookup
	account []string
}

// lookup records a name, once.
func (w *walker) lookup(l Lookup) {
	if !slices.Contains(w.lookups, l) {
		w.lookups = append(w.lookups, l)
	}
}

// refuse is a refusal at a node: the client reads the table's path, and the
// log the request's.
func (w *walker) refuse(n *node, at, what string) *Refusal {
	return &Refusal{
		Reason: ReasonBody,
		Detail: fmt.Sprintf("%s's %s %s", w.table.name, n.path, what),
		Log:    fmt.Sprintf("field=%s %s", at, what),
	}
}

func join(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

// value judges v, the value at request path at, by n. present is whether the
// key was there at all: an absent required leaf is judged as "".
func (w *walker) value(n *node, v any, present bool, at string) error {
	if !present {
		if n.required() {
			return w.leaf(n, "", at)
		}
		if n.kind == kStruct {
			return w.absentStruct(n, at)
		}
		return nil
	}
	switch n.kind {
	case kStruct:
		if v == nil {
			return w.absentStruct(n, at)
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return w.refuse(n, at, "is not an object")
		}
		for _, k := range sortedKeys(obj) {
			if _, listed := n.children[k]; !listed {
				where := "a field " + w.table.name + "'s table does not list"
				if n.path != "" {
					where = fmt.Sprintf("a field under %s's %s that its table does not list", w.table.name, n.path)
				}
				return &Refusal{Reason: ReasonBody, Detail: where, Log: "field=" + join(at, quote(k)) + " unknown"}
			}
		}
		for _, name := range sortedKeys(n.children) {
			child, ok := obj[name]
			if err := w.value(n.children[name], child, ok, join(at, name)); err != nil {
				return err
			}
		}
		return nil
	case kMap:
		if v == nil {
			return nil
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return w.refuse(n, at, "is not an object")
		}
		for _, k := range sortedKeys(obj) {
			kat := join(at, logKey(k))
			if !w.mapKey(n.key, k) {
				return &Refusal{Reason: ReasonBody, Detail: fmt.Sprintf("%s's %s has a key it does not allow", w.table.name, n.path), Log: "field=" + kat + " key not allowed"}
			}
			if err := w.value(n.elem, obj[k], true, kat); err != nil {
				return err
			}
		}
		return nil
	}
	return w.leaf(n, v, at)
}

// absentStruct judges an absent or null struct: only its required leaves
// have anything to say.
func (w *walker) absentStruct(n *node, at string) error {
	for _, name := range sortedKeys(n.children) {
		if err := w.value(n.children[name], nil, false, join(at, name)); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) mapKey(k keyCheck, key string) bool {
	switch k {
	case keyAbsPath:
		return absPath(key)
	case keyPort:
		return portKey(key)
	case keyNetwork:
		return w.network(key)
	}
	return false
}

func (w *walker) leaf(n *node, v any, at string) error {
	switch n.kind {
	case kAny:
		return nil
	case kZero:
		if !zero(v) {
			return w.refuse(n, at, "not zero")
		}
	case kNull:
		if v != nil {
			return w.refuse(n, at, "not null")
		}
	case kEnum:
		if !slices.ContainsFunc(n.enum, func(e any) bool { return sameScalar(e, v) }) {
			return w.refuse(n, at, "not one of its values")
		}
	case kImage:
		s, ok := v.(string)
		if !ok || !slices.Contains(w.route.Images, s) {
			r := w.refuse(n, at, "not a listed image")
			if ok {
				r.Log = "image=" + quote(s) + " not listed"
			}
			return r
		}
	case kLabels:
		return w.labels(n, v, at)
	case kObjectName:
		s, ok := v.(string)
		if !ok || s != "" && !objectName(s) {
			return w.refuse(n, at, "not a name")
		}
		if s != "" && n.path == "Name" && (w.table.name == "VolumeCreate" || w.table.name == "NetworkCreate") {
			w.lookup(Lookup{Kind: kindOf(w.table.name), Name: s, Use: Create})
		}
	case kNetwork:
		s, ok := v.(string)
		if !ok || !w.network(s) {
			return w.refuse(n, at, "not a network of this project's")
		}
	case kBinds:
		return w.binds(n, v, at)
	case kMounts:
		return w.mounts(n, v, at)
	case kPortBindings:
		return w.portBindings(n, v, at)
	default:
		return w.refuse(n, at, "has no spec")
	}
	return nil
}

func kindOf(table string) string {
	if table == "NetworkCreate" {
		return "network"
	}
	return "volume"
}

// network judges a network mode, or a key of EndpointsConfig, and records it
// to be looked up. "none" is no network. The daemon's own -- default, bridge,
// host -- are shared with every container made outside frisket, and
// container:<id> joins another's namespace.
func (w *walker) network(s string) bool {
	if s == "none" {
		return true
	}
	if !objectName(s) {
		return false
	}
	for _, shared := range []string{"default", "bridge", "host"} {
		if strings.EqualFold(s, shared) {
			return false
		}
	}
	w.lookup(Lookup{Kind: "network", Name: s, Use: Attach})
	return true
}

func (w *walker) labels(n *node, v any, at string) error {
	if v == nil {
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return w.refuse(n, at, "not an object of strings")
	}
	for _, k := range sortedKeys(obj) {
		if _, ok := obj[k].(string); !ok {
			return w.refuse(n, at, "not an object of strings")
		}
		// Only frisket writes frisket's labels, in any case.
		if len(k) >= 8 && strings.EqualFold(k[:8], "frisket.") {
			r := w.refuse(n, at, "holds a label only frisket may set")
			r.Log = "label=" + quote(k) + " is frisket's"
			return r
		}
	}
	return nil
}

var bindMode = regexp.MustCompile(`^(rw|ro)$`)

func (w *walker) binds(n *node, v any, at string) error {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return w.refuse(n, at, "not a list of binds")
	}
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return w.refuse(n, at, "not a list of binds")
		}
		parts := strings.Split(s, ":")
		// A volume's name, never a path or ~: a bind of the host's own files.
		if len(parts) < 2 || len(parts) > 3 || !objectName(parts[0]) || !absPath(parts[1]) ||
			len(parts) == 3 && !bindMode.MatchString(parts[2]) {
			r := w.refuse(n, at, "holds a bind that is not <volume>:<path>[:rw|ro]")
			r.Log = fmt.Sprintf("field=%s[%d] bind %s not allowed", at, i, quote(s))
			return r
		}
		w.lookup(Lookup{Kind: "volume", Name: parts[0], Use: Bind})
	}
	return nil
}

func (w *walker) mounts(n *node, v any, at string) error {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return w.refuse(n, at, "not a list of mounts")
	}
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return w.refuse(n, at, "not a list of mounts")
		}
		mat := fmt.Sprintf("%s[%d]", at, i)
		for _, k := range sortedKeys(m) {
			switch k {
			case "Type", "Source", "Target", "ReadOnly", "VolumeOptions", "TmpfsOptions":
			default:
				r := w.refuse(n, at, "holds a mount with a field it does not allow")
				r.Log = "field=" + join(mat, quote(k)) + " unknown"
				return r
			}
		}
		if t, ok := m["Target"].(string); !ok || !absPath(t) {
			return w.refuse(n, mat+".Target", "holds a mount whose target is not an absolute path")
		}
		if ro, ok := m["ReadOnly"]; ok && ro != nil {
			if _, ok := ro.(bool); !ok {
				return w.refuse(n, mat+".ReadOnly", "holds a mount whose ReadOnly is not a bool")
			}
		}
		switch m["Type"] {
		case "volume":
			src, ok := m["Source"].(string)
			if !ok || !(objectName(src) || anonVol.MatchString(src)) {
				return w.refuse(n, mat+".Source", "holds a volume mount whose source is not a volume's name")
			}
			if !onlyKeys(m["VolumeOptions"], map[string]func(any) bool{"NoCopy": isBoolOrNull}) {
				return w.refuse(n, mat+".VolumeOptions", "holds volume options other than NoCopy")
			}
			if !zero(m["TmpfsOptions"]) {
				return w.refuse(n, mat+".TmpfsOptions", "holds tmpfs options on a volume")
			}
			w.lookup(Lookup{Kind: "volume", Name: src, Use: Mount})
		case "tmpfs":
			if !zero(m["Source"]) || !zero(m["VolumeOptions"]) {
				return w.refuse(n, mat, "holds a tmpfs mount with a source or volume options")
			}
			if !onlyKeys(m["TmpfsOptions"], map[string]func(any) bool{"SizeBytes": isNumberOrNull, "Mode": isNumberOrNull}) {
				return w.refuse(n, mat+".TmpfsOptions", "holds tmpfs options other than SizeBytes and Mode")
			}
		default:
			r := w.refuse(n, mat+".Type", "holds a mount that is neither a volume nor a tmpfs")
			if t, ok := m["Type"].(string); ok {
				r.Log = fmt.Sprintf("field=%s.Type %s not allowed", mat, quote(t))
			}
			return r
		}
	}
	return nil
}

// onlyKeys is whether v is null or an object holding no key but those given,
// each of whose values passes its check.
func onlyKeys(v any, allowed map[string]func(any) bool) bool {
	if v == nil {
		return true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for k, x := range m {
		check, ok := allowed[k]
		if !ok || !check(x) {
			return false
		}
	}
	return true
}

func isBoolOrNull(v any) bool {
	_, ok := v.(bool)
	return ok || v == nil
}

func isNumberOrNull(v any) bool {
	_, ok := v.(json.Number)
	return ok || v == nil
}

var hostPort = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// portBindings judges the published ports and rewrites each HostIp to the
// project's address, so that nothing a container publishes lands on the
// host's 127.0.0.1, or any other address but its project's.
func (w *walker) portBindings(n *node, v any, at string) error {
	if v == nil {
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return w.refuse(n, at, "not an object")
	}
	addr := w.route.Address.String()
	for _, port := range sortedKeys(obj) {
		pat := join(at, logKey(port))
		if !portKey(port) {
			r := w.refuse(n, at, "has a key that is not a port")
			r.Log = "field=" + pat + " not a port"
			return r
		}
		arr, ok := obj[port].([]any)
		// An empty or null list publishes nothing Compose would ask for;
		// refusing it costs nothing and leaves no reading of it to the daemon.
		if !ok || len(arr) == 0 {
			return w.refuse(n, at, "holds a port with no list of bindings")
		}
		var kept []any
		seen := map[string]bool{}
		for i, e := range arr {
			b, ok := e.(map[string]any)
			if !ok {
				return w.refuse(n, at, "holds a binding that is not an object")
			}
			bat := fmt.Sprintf("%s[%d]", pat, i)
			for _, k := range sortedKeys(b) {
				if k != "HostIp" && k != "HostPort" {
					r := w.refuse(n, at, "holds a binding with a field other than HostIp and HostPort")
					r.Log = "field=" + join(bat, quote(k)) + " unknown"
					return r
				}
			}
			hp, ok := b["HostPort"].(string)
			if !ok || !hostPort.MatchString(hp) || !w.listed(hp) {
				r := w.refuse(n, at, "holds a host port this project does not list")
				if ok {
					r.Log = fmt.Sprintf("hostport %s=%s not listed", logKey(port), quote(hp))
				} else {
					r.Log = fmt.Sprintf("hostport %s not a string", logKey(port))
				}
				return r
			}
			switch ip, has := b["HostIp"]; {
			case !has || ip == "" || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == addr:
				b["HostIp"] = addr
			default:
				r := &Refusal{Reason: ReasonHostIP, Detail: fmt.Sprintf("%s's %s", w.table.name, n.path)}
				if s, ok := ip.(string); ok {
					r.Log = fmt.Sprintf("hostip %s=%s not allowed", logKey(port), quote(s))
				} else {
					r.Log = fmt.Sprintf("hostip %s not a string", logKey(port))
				}
				return r
			}
			if seen[hp] {
				// "" and 127.0.0.1 are both the project's address now: one
				// binding, twice, which the daemon would fail to bind again.
				w.account = append(w.account, fmt.Sprintf("hostip %s->%s:%s collapsed", logKey(port), addr, hp))
				continue
			}
			seen[hp] = true
			kept = append(kept, b)
			w.account = append(w.account, fmt.Sprintf("hostip %s->%s:%s", logKey(port), addr, hp))
		}
		obj[port] = kept
	}
	return nil
}

func (w *walker) listed(hp string) bool {
	p, err := strconv.ParseUint(hp, 10, 16)
	return err == nil && slices.Contains(w.route.Ports, uint16(p))
}

// zero is whether v is unset to the daemon: null, "", 0, false, [] or {}.
func zero(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case json.Number:
		return zeroNumber(string(x))
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// zeroNumber is whether a JSON number is 0, read from its digits rather than
// as a float, which would take 1e-400 for 0.
func zeroNumber(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(s, "0.") == ""
}

// sameScalar compares an enum's value with a body's, as JSON: numbers by
// their text.
func sameScalar(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && x == y
	}
	return false
}

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	allHex = regexp.MustCompile(`^[0-9a-f]+$`)
	// anonVol is the whole name the daemon gives an anonymous volume, never
	// a prefix of one; F5 admits it only when it carries
	// com.docker.volume.anonymous and an owned container mounts it.
	anonVol = regexp.MustCompile(`^[0-9a-f]{64}$`)
	portRE  = regexp.MustCompile(`^([1-9][0-9]{0,4})(/(tcp|udp|sctp))?$`)
	maxPath = 4096
)

// objectName is a volume's or network's name, as the daemon's own grammar
// has it, and never all hex, so that it cannot be taken for an ID's prefix.
func objectName(s string) bool { return nameRE.MatchString(s) && !allHex.MatchString(s) }

func absPath(s string) bool {
	return strings.HasPrefix(s, "/") && len(s) <= maxPath && !strings.ContainsAny(s, ":\x00")
}

func portKey(s string) bool {
	m := portRE.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	p, err := strconv.Atoi(m[1])
	return err == nil && p <= 65535
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
