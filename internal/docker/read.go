// Package docker judges what a client asks of a Docker Engine: the JSON body
// of a create, against a table of the fields a route allows and a floor of
// fields frisket itself pins; the label filter of a list; and the loopback
// address and names a project's published ports are reached by. It does no
// I/O. What it finds a body names -- the volumes and networks the daemon must
// be asked about -- it hands back as data, for the route to look up.
//
// It is strict where the daemon is lax. moby decodes a body with Go's
// encoding/json, which matches a key to a field in any case, keeps the last of
// two equal keys, and skips a key it does not know. So a body is read here
// with every key exact-case, none twice and none unknown, and what goes
// upstream is re-encoded from the tree that was judged, never the bytes the
// client sent.
package docker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// MaxDepth bounds how deeply objects and arrays nest in a body, the outermost
// object being 1. The deepest a captured body goes is 4.
const MaxDepth = 32

// Read reads a body that must be exactly one JSON object: valid UTF-8 with no
// BOM, only whitespace after the object, nested at most MaxDepth deep, and no
// key twice in any object. The tree it gives holds map[string]any, []any,
// string, json.Number, bool and nil. A body it refuses is a *Refusal whose
// message says only what was wrong, never with what: the decoder's own error
// quotes the offending byte, so that goes to the log alone.
func Read(body []byte) (map[string]any, error) {
	if bytes.HasPrefix(body, []byte("\xef\xbb\xbf")) {
		return nil, unreadable("a byte-order mark", "bom")
	}
	if !utf8.Valid(body) {
		return nil, unreadable("not UTF-8", "not utf-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return nil, unreadable("not a JSON object", "not an object")
	}
	obj, err := readObject(dec, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, unreadable("more after the object", "trailing value")
	}
	return obj, nil
}

// readObject reads the members of an object whose '{' has been read, and its
// '}'.
func readObject(dec *json.Decoder, depth int) (map[string]any, error) {
	obj := map[string]any{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, syntax(err)
		}
		key, ok := t.(string)
		if !ok {
			return nil, unreadable("not JSON", "not a key")
		}
		if _, twice := obj[key]; twice {
			return nil, unreadable("a key twice in one object", "key "+quote(key)+" twice")
		}
		v, err := readValue(dec, depth)
		if err != nil {
			return nil, err
		}
		obj[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, syntax(err)
	}
	return obj, nil
}

// readValue reads one value inside something at depth.
func readValue(dec *json.Decoder, depth int) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, syntax(err)
	}
	switch t {
	case json.Delim('{'), json.Delim('['):
		if depth+1 > MaxDepth {
			return nil, unreadable("nested too deeply", "depth over 32")
		}
	}
	switch t {
	case json.Delim('{'):
		return readObject(dec, depth+1)
	case json.Delim('['):
		arr := []any{}
		for dec.More() {
			v, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, syntax(err)
		}
		return arr, nil
	}
	switch v := t.(type) {
	case string, json.Number, bool, nil:
		return v, nil
	}
	return nil, unreadable("not JSON", "unexpected token")
}

func syntax(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return unreadable("not JSON", "truncated")
	}
	return unreadable("not JSON", clip(err.Error()))
}

// Encode writes a tree Read gave, or one built from the same types, as the
// bytes that go upstream: keys in sorted order, numbers as they were read,
// and no HTML escaping, which moby would only undo.
func Encode(tree any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tree); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
