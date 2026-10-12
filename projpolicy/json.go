package projpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

// Decode reads b as one JSON value, strictly: valid UTF-8, no key twice in
// an object, integers only, and nothing after the value. Objects come back
// as map[string]any, arrays as []any and numbers as json.Number.
func Decode(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec, "")
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func decodeValue(dec *json.Decoder, at string) (any, error) {
	t, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, errors.New("no JSON value")
		}
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("%s: key %q twice", where(at), k)
				}
				if m[k], err = decodeValue(dec, at+"."+k); err != nil {
					return nil, err
				}
			}
			_, err := dec.Token()
			return m, err
		case '[':
			a := []any{}
			for i := 0; dec.More(); i++ {
				v, err := decodeValue(dec, fmt.Sprintf("%s[%d]", at, i))
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
		return nil, fmt.Errorf("%s: unexpected %v", where(at), t)
	case json.Number:
		if !integer.MatchString(string(t)) {
			return nil, fmt.Errorf("%s: %s is not an integer", where(at), t)
		}
		return t, nil
	default:
		return t, nil
	}
}

func where(at string) string {
	if at == "" {
		return "the top"
	}
	return at[1:]
}

// Encode writes v in the canonical form: keys sorted, two-space indent, no
// HTML escaping, and a newline at the end.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Format is b in the canonical form, the bytes a policy is signed over.
func Format(b []byte) ([]byte, error) {
	v, err := Decode(b)
	if err != nil {
		return nil, err
	}
	return Encode(v)
}

// Canonical is whether b is already in the canonical form.
func Canonical(b []byte) bool {
	f, err := Format(b)
	return err == nil && bytes.Equal(f, b)
}

// MergePatch applies patch to target as RFC 7396 says: an object patches
// an object key by key, null deleting a key, and anything else replaces
// the target whole. Neither argument is changed.
func MergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	out := map[string]any{}
	if t, ok := target.(map[string]any); ok {
		for k, v := range t {
			out[k] = v
		}
	}
	for k, v := range p {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = MergePatch(out[k], v)
	}
	return out
}

// Digest names a policy file's bytes: sha256: and the hex of their
// SHA-256. An absent file is "".
func Digest(b []byte) string {
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
