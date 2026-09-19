package intercept

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// detail is a request as it looked on the wire, kept only when the log is at
// debug level: what the client sent, before frisket touched it, and what came
// back. It exists to answer "what is this client doing" without a packet
// capture -- which, through interception, would show nothing anyway.
//
// A credential never goes in it, whole or in part. A header that can carry
// one is described instead -- its kind, its length and a short hash -- which
// says whether two requests sent the same thing, and whether that thing was
// frisket's own credential, without being usable by whoever reads the log.
type detail struct {
	reqHeader  []string
	query      []string
	respHeader []string
	respBody   string
	// responded logs a response's arrival, before its body: for a stream,
	// the request's own line comes only when the stream ends.
	responded func(status int, contentType string)
}

// maxLoggedBody is how much of an error response is kept: enough for an API's
// error object, not enough to be a transcript.
const maxLoggedBody = 1024

// sensitive reports whether a header's value may be a credential, by name.
// Deliberately broad: a header wrongly described costs a debugging session a
// value; one wrongly logged costs the credential.
func sensitive(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"auth", "token", "key", "cookie", "secret", "session", "signature", "password", "credential", "jwt"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// describeHeaders renders headers one "Name: value" per entry, sorted, with
// every sensitive value described rather than shown. ours is the credential
// frisket would inject, so a client that already holds it is visible as such.
func describeHeaders(h http.Header, ours string) []string {
	out := make([]string, 0, len(h))
	for name, vals := range h {
		for _, v := range vals {
			if sensitive(name) {
				v = describeSecret(v, ours)
			} else {
				v = printable(v)
			}
			out = append(out, name+": "+v)
		}
	}
	sort.Strings(out)
	return out
}

// describeSecret keeps an auth scheme, which is not secret, and describes
// what follows it.
func describeSecret(v, ours string) string {
	if scheme, rest, ok := strings.Cut(v, " "); ok && !strings.ContainsAny(scheme, "=,") {
		return scheme + " " + describeToken(rest, ours)
	}
	return describeToken(v, ours)
}

func describeToken(tok, ours string) string {
	if ours != "" && tok == ours {
		return "<frisket's credential>"
	}
	sum := sha256.Sum256([]byte(tok))
	return fmt.Sprintf("%s len=%d sha256=%x", kind(tok), len(tok), sum[:4])
}

// kind names what a token is without saying what it is: a JWT by its header
// and claim names, an Anthropic key by the prefix that names its type, and
// anything else as opaque.
func kind(tok string) string {
	if parts := strings.Split(tok, "."); len(parts) == 3 && strings.HasPrefix(tok, "eyJ") {
		return "jwt" + jwtShape(parts[0], parts[1])
	}
	if strings.HasPrefix(tok, "sk-") {
		if p := strings.SplitN(tok, "-", 4); len(p) == 4 {
			return strings.Join(p[:3], "-")
		}
	}
	return "opaque"
}

// jwtShape is a JWT's algorithm, its claim names and its expiry: what it is
// for and until when, which a debugging session needs, and none of its
// values, which it does not. The signature is never looked at.
func jwtShape(header, payload string) string {
	var h struct {
		Alg string `json:"alg"`
	}
	var claims map[string]json.RawMessage
	hb, err1 := base64.RawURLEncoding.DecodeString(header)
	pb, err2 := base64.RawURLEncoding.DecodeString(payload)
	if err1 != nil || err2 != nil || json.Unmarshal(hb, &h) != nil || json.Unmarshal(pb, &claims) != nil {
		return "(undecodable)"
	}
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	slices.Sort(names)
	s := fmt.Sprintf("(alg=%s claims=%s", printable(h.Alg), strings.Join(names, ","))
	if exp, ok := claims["exp"]; ok {
		s += " exp=" + printable(string(exp))
	}
	return s + ")"
}

// queryNames is a query string's parameter names. Never their values: a query
// is where tokens end up when someone puts them in a URL.
func queryNames(q url.Values) []string {
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// peekBody keeps the start of an error response's body for the log and puts
// it back in front of the rest, so the client receives it all.
func peekBody(res *http.Response) string {
	if res.Body == nil || res.Body == http.NoBody {
		return ""
	}
	buf := make([]byte, maxLoggedBody)
	n, _ := io.ReadFull(res.Body, buf)
	res.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf[:n]), res.Body), res.Body}
	return printable(string(buf[:n]))
}

// printable drops what would not survive a log line as text.
func printable(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' && r != '\t' }) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || (r < ' ' && r != '\t') {
			return '?'
		}
		return r
	}, s)
}
