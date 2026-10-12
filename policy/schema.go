package policy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// answerFields are the string fields, and the maps whose values, are
// answers: allow, ask or refuse.
var answerFields = map[string]bool{
	"Answers.Writes": true, "Answers.Guarded": true, "Answers.Unmatched": true, "Answers.Interactive": true,
	"RouteV2.Operations": true, "SSHRouteV2.Exec": true, "GraphQLV2.Unmatched": true,
}

// descriptions are a few keys' words, by Go type and field.
var descriptions = map[string]string{
	"DocumentV2.Version":     "2. A document without one is version 1's, which chase still writes.",
	"DocumentV2.Allow":       "The name allowlist: a name or a hostpattern key to true.",
	"DocumentV2.LAN":         "Names on the local network a session may reach, by name or hostpattern, with their ports.",
	"DocumentV2.Routes":      "The intercepted hosts, by route name.",
	"DocumentV2.SSH":         "The machines a session may run commands on, by route name; a hostpattern key's answers apply to every route it matches.",
	"Answers.Writes":         "An operation of class write: allow, ask or refuse. Unset, the next layer out's; at the last, ask.",
	"Answers.Guarded":        "An operation of class guarded. Unset, the next layer out's; at the last, refuse.",
	"Answers.Unmatched":      "A request no operation describes, or one of no class. Unset, the next layer out's; at the last, refuse (an SSH route's ask).",
	"Answers.Interactive":    "An SSH machine's interactive shell, with or without a terminal, relayed as it is with nothing typed into it decided: allow, ask or refuse. The host's alone, and never a route's. Unset, the next layer out's; at the last, refuse.",
	"DocumentV2.Ceiling":     "The most lenient answer any route may give each class, writes, guarded and unmatched, and any SSH machine its interactive shell: allow < ask < refuse, the stricter of an answer and its ceiling winning. Unset is no ceiling.",
	"RouteV2.Ceiling":        "The most lenient answer this route may give each class, beside the document's.",
	"RouteV2.Paths":          "What the route's requests are: \"METHOD[,METHOD] /path\" to the operation each is.",
	"RouteV2.Operations":     "Answers by operation id, \"category:<name>\", or endpoint pattern \"METHOD[,METHOD] /path\" (* one segment, a last ** the rest): id, then category, then the most specific pattern, then the class's answer.",
	"RouteV2.Git":            "git's smart HTTP for these repositories; a push is the operation git-receive-pack, of class write.",
	"RouteV2.GraphQL":        "GraphQL endpoints by path, each field answered as an operation by its id (its name where it has no operation).",
	"SSHRouteV2.Exec":        "Answers by exec rule: a command pattern, \"PATTERN [arg GLOB]\", or \"[arg GLOB]\"; an arg rule only tightens.",
	"SSHRouteV2.Commands":    "What each exec rule is, by the same key: one Exec does not answer is answered by its class.",
	"RouteV2.EncodedSlashes": "Path templates whose * takes a segment holding an encoded slash.",
}

// SchemaV2 is a version 2 policy document's JSON Schema, read off the
// types Decode reads it into, so it names every key Decode does and no
// other. A field only the host may set has "x-scope": "host".
func SchemaV2() []byte {
	s := schemaOf(reflect.TypeFor[DocumentV2]())
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["title"] = "frisket policy document, version 2"
	props := s["properties"].(map[string]any)
	props["version"] = map[string]any{"const": 2, "description": descriptions["DocumentV2.Version"]}
	// interactive is an SSH machine's, and the document's for every one:
	// a route has no shell, and Lower refuses it there, its ceiling's too.
	route := props["routes"].(map[string]any)["additionalProperties"].(map[string]any)["properties"].(map[string]any)
	delete(route["ceiling"].(map[string]any)["properties"].(map[string]any), "interactive")
	s["required"] = []string{"version"}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return buf.Bytes()
}

var answerSchema = map[string]any{"enum": []string{"allow", "ask", "refuse"}}

func schemaOf(t reflect.Type) map[string]any {
	switch {
	case t == reflect.TypeFor[json.RawMessage]():
		return map[string]any{}
	case t == reflect.TypeFor[QueryCheck]():
		return map[string]any{"description": "A check's name, or {\"filters\": [...]} or {\"enum\": [...]}."}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return schemaOf(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		for f := range fields(t) {
			var p map[string]any
			key := t.Name() + "." + f.Name
			if f.owner != "" {
				key = f.owner + "." + f.Name
			}
			if key == "Answers.Interactive" && t == reflect.TypeFor[RouteV2]() {
				continue // an SSH machine's, and the document's for every one
			}
			switch {
			case answerFields[key] && f.Type.Kind() == reflect.Map:
				p = map[string]any{"type": "object", "additionalProperties": answerSchema}
			case answerFields[key]:
				p = map[string]any{"enum": []string{"allow", "ask", "refuse"}}
			default:
				p = schemaOf(f.Type)
			}
			if d := descriptions[key]; d != "" {
				p["description"] = d
			}
			if f.host {
				p["x-scope"] = "host"
			}
			props[f.json] = p
		}
		return map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	}
	return map[string]any{}
}

// field is a struct field as its JSON reads it.
type field struct {
	reflect.StructField
	json string
	host bool
	// owner is the embedded struct's name, for one of its fields.
	owner string
}

// fields are t's JSON fields, an embedded struct's among them.
func fields(t reflect.Type) func(yield func(field) bool) {
	return func(yield func(field) bool) {
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				for g := range fields(f.Type) {
					if g.owner == "" {
						g.owner = f.Type.Name()
					}
					if !yield(g) {
						return
					}
				}
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" || !f.IsExported() {
				continue
			}
			if !yield(field{StructField: f, json: name, host: f.Tag.Get("scope") == "host"}) {
				return
			}
		}
	}
}

// fieldNamed is t's JSON field of that name.
func fieldNamed(t reflect.Type, name string) (field, bool) {
	for f := range fields(t) {
		if f.json == name {
			return f, true
		}
	}
	return field{}, false
}
