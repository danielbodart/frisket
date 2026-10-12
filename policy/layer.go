package policy

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/hostpattern"
	"github.com/danielbodart/frisket/projpolicy"
)

// CheckProjectLayer holds a project's layer -- the frisket section of its
// signed policy file, a merge patch -- to what a project may say, and
// merges it over base, the whole version 2 document of the layers under
// it. It refuses a key the document has no field for, one only the host
// may set (scope:"host", whether set or deleted with null), a route or SSH
// machine the base does not define, and the deletion of one, and returns
// the merged document's bytes for the caller to build. A pattern the layer
// writes that can never match is refused too (Unreachable).
func CheckProjectLayer(layer, base []byte) ([]byte, error) {
	lv, err := projpolicy.Decode(layer)
	if err != nil {
		return nil, fmt.Errorf("layer: %w", err)
	}
	lm, ok := lv.(map[string]any)
	if !ok {
		return nil, errors.New("layer: not a JSON object")
	}
	bv, err := projpolicy.Decode(base)
	if err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	bm, ok := bv.(map[string]any)
	if !ok {
		return nil, errors.New("base: not a JSON object")
	}
	var problems []error
	if v, ok := lm["version"]; ok && fmt.Sprint(v) != "2" {
		problems = append(problems, fmt.Errorf("version %v: a layer is version 2's", v))
	}
	if fmt.Sprint(bm["version"]) != "2" {
		return nil, errors.New("base: not a version 2 document")
	}
	problems = append(problems, scoped(lm, reflect.TypeFor[DocumentV2](), "")...)
	for _, coll := range []string{"routes", "ssh"} {
		lc, _ := lm[coll].(map[string]any)
		bc, _ := bm[coll].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(lc)) {
			if coll == "ssh" {
				if p, err := hostpattern.Compile(k); err == nil && !p.Literal() {
					continue // answers for the machines it matches
				}
			}
			_, inBase := bc[k]
			switch {
			case lc[k] == nil:
				problems = append(problems, fmt.Errorf("%s.%s: deleting a route is the host's: it takes its host fields with it", coll, k))
			case !inBase:
				problems = append(problems, fmt.Errorf("%s.%s: the base defines no such route, and a project layer only answers for the base's", coll, k))
			}
		}
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	merged, err := projpolicy.Encode(projpolicy.MergePatch(bm, lm))
	if err != nil {
		return nil, err
	}
	d, err := DecodeV2(merged)
	if err != nil {
		return nil, fmt.Errorf("merged: %w", err)
	}
	if _, err := Lower(d); err != nil {
		return nil, fmt.Errorf("merged: %w", err)
	}
	var never []error
	for _, u := range Unreachable(d) {
		if layerSets(lm, u.Path) {
			never = append(never, errors.New(u.String()))
		}
	}
	if len(never) > 0 {
		return nil, errors.Join(never...)
	}
	return merged, nil
}

// scoped is every key of v, read as t, that t has no field for or that is
// the host's alone.
func scoped(v any, t reflect.Type, at string) []error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	join := func(k string) string {
		if at == "" {
			return k
		}
		return at + "." + k
	}
	var out []error
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return nil // the merged document's decode says what is wrong
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			f, ok := fieldNamed(t, k)
			switch {
			case !ok:
				out = append(out, fmt.Errorf("%s: no such field", join(k)))
			case f.host:
				out = append(out, fmt.Errorf("%s: the host's alone (x-scope host), which a project layer may not set or delete", join(k)))
			case m[k] != nil:
				out = append(out, scoped(m[k], f.Type, join(k))...)
			}
		}
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if m[k] != nil {
				out = append(out, scoped(m[k], t.Elem(), join(k))...)
			}
		}
	case reflect.Slice:
		if s, ok := v.([]any); ok {
			for i, x := range s {
				out = append(out, scoped(x, t.Elem(), fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	return out
}

// layerSets is whether the layer sets the key at path, a list of keys.
func layerSets(v any, path []string) bool {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if v, ok = m[k]; !ok {
			return false
		}
	}
	return true
}

// Never is a key that can never match, or never decide anything.
type Never struct {
	// Path is the key's, a key at a time: ["routes", "api", "operations",
	// "GET /x"].
	Path []string
	Why  string
}

func (n Never) String() string { return fmt.Sprintf("%s: %s", strings.Join(n.Path, "."), n.Why) }

// Unreachable is every pattern in d that can never match a request, a name
// or a machine, or never decides one: what `frisket check` reports.
func Unreachable(d DocumentV2) []Never {
	var out []Never
	host := func(coll, k string) {
		if why := neverAName(k); why != "" {
			out = append(out, Never{[]string{coll, k}, why})
		}
	}
	for _, k := range slices.Sorted(maps.Keys(d.Allow)) {
		host("allow", k)
	}
	for _, k := range slices.Sorted(maps.Keys(d.LAN)) {
		host("lan", k)
	}
	for _, name := range slices.Sorted(maps.Keys(d.Routes)) {
		r := d.Routes[name]
		for _, k := range slices.Sorted(maps.Keys(r.Operations)) {
			if !IsEndpoint(k) {
				continue
			}
			at := []string{"routes", name, "operations", k}
			methods, path, prefix, err := ParseEndpoint(k)
			if err != nil {
				out = append(out, Never{at, err.Error()})
				continue
			}
			if why := neverAPath(path + prefix); why != "" {
				out = append(out, Never{at, why})
				continue
			}
			if path != "" {
				if _, ok := r.GraphQL[path]; ok {
					out = append(out, Never{at, "a GraphQL endpoint's path, which its body decides at every method"})
					continue
				}
				for pk, e := range r.Paths {
					pm, pp, pprefix, err := ParseEndpoint(pk)
					if err != nil || pp != path || pprefix != "" || e.Operation == nil {
						continue
					}
					if !slices.ContainsFunc(methods, func(m string) bool { return !slices.Contains(pm, m) }) && namedAnswer(r, e.Operation) {
						out = append(out, Never{at, fmt.Sprintf("operation %s is answered by name there, which no pattern overrules", e.Operation.ID)})
					}
				}
			}
		}
	}
	var machines []string
	for k := range d.SSH {
		if p, err := hostpattern.Compile(k); err == nil && p.Literal() {
			machines = append(machines, k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(d.SSH)) {
		p, err := hostpattern.Compile(k)
		if err != nil || p.Literal() {
			continue
		}
		if !slices.ContainsFunc(machines, p.Match) {
			out = append(out, Never{[]string{"ssh", k}, "matches no SSH route's name"})
		}
	}
	return out
}

func namedAnswer(r RouteV2, op *Operation) bool {
	if _, ok := r.Operations[op.ID]; ok {
		return true
	}
	_, ok := r.Operations["category:"+op.Category]
	return ok && op.Category != ""
}

// neverAName is why a host key can match no name a session's DNS
// considers, or "".
func neverAName(k string) string {
	p, err := hostpattern.Compile(k)
	if err != nil {
		return err.Error()
	}
	if _, below := p.Below(); p.Literal() || below {
		return "" // a name, or every name below one: matched in any case
	}
	for _, l := range strings.Split(k, ".") {
		if len(l) > 63 {
			return "a label longer than 63 bytes, which no name has"
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'A' && c <= 'Z':
				return "a capital, and names are matched in lower case"
			case c == '*', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return fmt.Sprintf("%q, which no name holds", c)
			}
		}
	}
	return ""
}

// neverAPath is why an endpoint pattern's path can match no request
// frisket would decide -- it refuses a path with an empty, "." or ".."
// segment before any rule -- or "".
func neverAPath(p string) string {
	if p == "/" {
		return ""
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		switch {
		case s == "" && i != len(segs)-1:
			return "an empty segment, and frisket refuses a path with one"
		case s == "." || s == "..":
			return "a dot segment, and frisket refuses a path with one"
		}
	}
	return ""
}
