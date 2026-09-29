package dockerapi

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// objects are the objects in a body whose keys a table fixes: those under a
// struct spec, and each binding and mount, which have fixed keys of their own.
func objects(n *node, v any) []map[string]any {
	var out []map[string]any
	switch n.kind {
	case kStruct:
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		out = append(out, obj)
		for name, c := range n.children {
			out = append(out, objects(c, obj[name])...)
		}
	case kMap:
		obj, _ := v.(map[string]any)
		for _, x := range obj {
			out = append(out, objects(n.elem, x)...)
		}
	case kPortBindings:
		obj, _ := v.(map[string]any)
		for _, x := range obj {
			arr, _ := x.([]any)
			for _, b := range arr {
				out = append(out, b.(map[string]any))
			}
		}
	}
	return out
}

func anyValue(t *rapid.T, label string) any {
	return rapid.OneOf(
		rapid.Just[any](nil),
		rapid.Just[any](false),
		rapid.Just[any](""),
		rapid.Just[any](json.Number("0")),
		rapid.Just[any]([]any{}),
		rapid.Just[any](map[string]any{}),
		rapid.Map(rapid.String(), func(s string) any { return s }),
		rapid.Just[any](true),
	).Draw(t, label)
}

// A key the table does not list refuses wherever it is, whatever its value,
// zero included: moby would read a key it knows in another case, and one it
// does not know is one frisket cannot judge.
func TestAnExtraKeyAtAnyDepthRefuses(t *testing.T) {
	tb := tables(t)["ContainerCreate"]
	rapid.Check(t, func(rt *rapid.T) {
		body := captured(t, rapid.SampledFrom([]int{17, 18}).Draw(rt, "seq"))
		objs := objects(tb.root, body)
		obj := rapid.SampledFrom(objs).Draw(rt, "object")
		key := rapid.StringMatching(`[A-Za-z][A-Za-z0-9_.-]{0,12}`).Filter(func(k string) bool {
			for existing := range obj {
				if strings.EqualFold(existing, k) {
					return false
				}
			}
			// A key a table lists for this object but the body left out
			// would be judged, not refused.
			for _, n := range structsFor(tb.root) {
				if _, ok := n.children[k]; ok {
					return false
				}
			}
			return k != "HostIp" && k != "HostPort"
		}).Draw(rt, "key")
		obj[key] = anyValue(rt, "value")
		_, err := tb.Check(encode(t, body), route)
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != ReasonBody {
			rt.Fatalf("%q admitted: %v", key, err)
		}
	})
}

func structsFor(n *node) []*node {
	var out []*node
	switch n.kind {
	case kStruct:
		out = append(out, n)
		for _, c := range n.children {
			out = append(out, structsFor(c)...)
		}
	case kMap:
		out = append(out, structsFor(n.elem)...)
	}
	return out
}

// A key the table lists, spelt in another case beside it or instead of it,
// refuses: to moby it is the same field, and it would read one or the other.
func TestAKeyDifferingOnlyInCaseRefuses(t *testing.T) {
	tb := tables(t)["ContainerCreate"]
	rapid.Check(t, func(rt *rapid.T) {
		body := captured(t, rapid.SampledFrom([]int{17, 18}).Draw(rt, "seq"))
		objs := objects(tb.root, body)
		obj := rapid.SampledFrom(objs).Draw(rt, "object")
		keys := sortedKeys(obj)
		if len(keys) == 0 {
			rt.Skip("an empty object")
		}
		key := rapid.SampledFrom(keys).Draw(rt, "key")
		flips := rapid.SliceOfN(rapid.Bool(), len(key), len(key)).Draw(rt, "flips")
		twin := []byte(key)
		for i, c := range twin {
			if flips[i] && ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
				twin[i] ^= 0x20
			}
		}
		if string(twin) == key {
			rt.Skip("no letter flipped")
		}
		if rapid.Bool().Draw(rt, "instead") {
			obj[string(twin)] = obj[key]
			delete(obj, key)
		} else {
			obj[string(twin)] = obj[key]
		}
		if _, err := tb.Check(encode(t, body), route); err == nil {
			rt.Fatalf("%q for %q admitted", twin, key)
		}
	})
}

func jsonTree(depth int) *rapid.Generator[any] {
	scalars := []*rapid.Generator[any]{
		rapid.Just[any](nil),
		rapid.Map(rapid.Bool(), func(b bool) any { return b }),
		rapid.Map(rapid.String(), func(s string) any { return s }),
		rapid.Map(rapid.StringMatching(`-?(0|[1-9][0-9]{0,20})(\.[0-9]{1,5})?([eE][+-]?[0-9]{1,3})?`), func(s string) any { return json.Number(s) }),
	}
	if depth == 0 {
		return rapid.OneOf(scalars...)
	}
	return rapid.OneOf(append(scalars,
		rapid.Map(rapid.SliceOfN(jsonTree(depth-1), 0, 4), func(a []any) any { return a }),
		rapid.Map(rapid.MapOfN(rapid.String(), jsonTree(depth-1), 0, 4), func(m map[string]any) any { return m }),
	)...)
}

// What frisket sends is what it judged: encoding a tree and reading it back
// gives the same tree.
func TestTheOutputReadsBackToTheSameTree(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		tree := rapid.MapOfN(rapid.String(), jsonTree(4), 0, 6).Draw(rt, "tree")
		b, err := Encode(tree)
		if err != nil {
			rt.Fatal(err)
		}
		back, err := Read(b)
		if err != nil {
			rt.Fatalf("%s: %v", b, err)
		}
		if !reflect.DeepEqual(back, tree) {
			rt.Fatalf("%s read back as %v", b, back)
		}
	})
}

// A merged filter holds the project's label and every term the client sent,
// under every key it sent.
func TestAMergedFilterHoldsTheLabelAndKeepsTheClientsTerms(t *testing.T) {
	allowed := []string{"label", "name", "id", "status", "health", "exited"}
	rapid.Check(t, func(rt *rapid.T) {
		in := rapid.MapOfN(rapid.SampledFrom(allowed), rapid.SliceOfN(rapid.String(), 0, 4), 0, len(allowed)).Draw(rt, "filters")
		raw := map[string]any{}
		for k, terms := range in {
			if rapid.Bool().Draw(rt, "array "+k) {
				arr := []any{}
				for _, s := range terms {
					arr = append(arr, s)
				}
				raw[k] = arr
			} else {
				obj := map[string]any{}
				for _, s := range terms {
					obj[s] = rapid.Bool().Draw(rt, "bool")
				}
				raw[k] = obj
			}
		}
		got, err := MergeFilter(string(encode(t, raw)), allowed, project)
		if err != nil {
			rt.Fatal(err)
		}
		var out map[string]map[string]bool
		if err := json.Unmarshal([]byte(got), &out); err != nil {
			rt.Fatal(err)
		}
		if !out["label"][LabelKey+"="+project] {
			rt.Fatalf("no label in %s", got)
		}
		for k, terms := range in {
			if _, ok := out[k]; !ok {
				rt.Fatalf("%q lost from %s", k, got)
			}
			for _, s := range terms {
				if !out[k][s] {
					rt.Fatalf("%q=%q lost from %s", k, s, got)
				}
			}
		}
	})
}
