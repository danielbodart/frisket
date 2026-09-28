package intercept

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Refusal reasons for a method override frisket cannot apply.
const (
	ReasonOverrideConflict = "method overrides disagree"
	ReasonOverrideInvalid  = "method override is not a method"
	ReasonFormUnread       = "form body too long to read for a method override"
)

// maxForm bounds a form body read for an override: an upstream reads the
// whole of it, so one frisket cannot read whole is refused.
const maxForm = 1 << 20

// overrideHeaders are the headers upstreams read as the request's real
// method: X-HTTP-Method-Override by Google's front end (measured), Rack,
// Symfony, Laravel, Express's method-override and ASP.NET Core;
// X-HTTP-Method by OData and SharePoint; X-Method-Override by ASP.NET
// Web API's override handlers. A name is compared with '_' read as '-', as
// CGI does, which is how PHP's frameworks see headers.
var overrideHeaders = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

// overrideParams are the query parameters, and a POST's form fields, read
// the same way, compared decoded and case-folded: $httpMethod by Google's
// front end (measured, and as %24httpMethod), _method by Rack, Laravel and
// Symfony, which read it from the form first.
var overrideParams = []string{"$httpmethod", "_method"}

// override applies the method a request's overrides name, and strips them,
// so that what is decided, logged and sent upstream is the method an
// upstream would run. A form a POST names GET or HEAD for, declared as one,
// is its query, as Google's clients send a long GET, and goes upstream so. It returns the
// method the request line said, and why it is refused if it is.
func override(r *http.Request) (sent, reason string) {
	form, ok := readForm(r)
	if !ok {
		return "", ReasonFormUnread
	}
	var named []string
	for k, vs := range r.Header {
		if !isOverrideHeader(k) {
			continue
		}
		for _, v := range vs {
			named = append(named, strings.Trim(v, " \t"))
		}
		delete(r.Header, k)
	}
	query, params, ok := stripOverrideParams(r.URL.RawQuery)
	if !ok {
		return "", ReasonOverrideInvalid
	}
	named = append(named, params...)
	if form != nil {
		stripped, fields, ok := stripOverrideParams(string(form))
		if !ok {
			return "", ReasonOverrideInvalid
		}
		named = append(named, fields...)
		form = []byte(stripped)
	}
	if len(named) == 0 {
		return "", ""
	}
	method := strings.ToUpper(named[0])
	for _, m := range named {
		if !validMethod(m) {
			return "", ReasonOverrideInvalid
		}
		if strings.ToUpper(m) != method {
			return "", ReasonOverrideConflict
		}
	}
	sent, r.Method = r.Method, method
	r.URL.RawQuery = query
	switch {
	case form == nil:
	case (method == http.MethodGet || method == http.MethodHead) && r.Header.Get("Content-Type") != "":
		if query != "" && len(form) > 0 {
			query += "&"
		}
		r.URL.RawQuery = query + string(form)
		r.Header.Del("Content-Type")
		setBody(r, nil)
	default:
		setBody(r, form)
	}
	return sent, ""
}

// readForm is a POST's form body, read whole and put back, or nil for any
// other request: Rack reads a POST with no Content-Type as a form too.
func readForm(r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost || r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	mt, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if mt = strings.TrimSpace(mt); mt != "" && !strings.EqualFold(mt, "application/x-www-form-urlencoded") {
		return nil, true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxForm+1))
	if err != nil || len(b) > maxForm {
		return nil, false
	}
	setBody(r, b)
	return b, true
}

func setBody(r *http.Request, b []byte) {
	r.ContentLength = int64(len(b))
	r.Body = http.NoBody
	if len(b) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
}

func isOverrideHeader(name string) bool {
	name = strings.ReplaceAll(name, "_", "-")
	for _, h := range overrideHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// stripOverrideParams is a raw query without its override parameters, and
// their values. Pairs are split at ';' as well as '&', as some servers do.
func stripOverrideParams(raw string) (query string, values []string, ok bool) {
	if raw == "" {
		return "", nil, true
	}
	var kept strings.Builder
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '&' && raw[i] != ';' {
			continue
		}
		pair := raw[start:i]
		sep := ""
		if start > 0 {
			sep = raw[start-1 : start]
		}
		start = i + 1
		key, value, _ := strings.Cut(pair, "=")
		if !isOverrideParam(key) {
			if kept.Len() > 0 {
				kept.WriteString(sep)
			}
			kept.WriteString(pair)
			continue
		}
		v, err := url.QueryUnescape(value)
		if err != nil {
			return "", nil, false
		}
		values = append(values, v)
	}
	if len(values) == 0 {
		return raw, nil, true
	}
	return kept.String(), values, true
}

// isOverrideParam reads a key as leniently as any server might: decoded as
// often as it decodes, and case-folded.
func isOverrideParam(key string) bool {
	for range maxDecodes {
		for _, p := range overrideParams {
			if strings.EqualFold(key, p) {
				return true
			}
		}
		next, err := url.QueryUnescape(key)
		if err != nil || next == key {
			return false
		}
		key = next
	}
	return false
}

// validMethod is an RFC 9110 token, and not CONNECT, which asks for a tunnel
// rather than naming what to do to a resource.
func validMethod(m string) bool {
	if m == "" || strings.EqualFold(m, http.MethodConnect) {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}
