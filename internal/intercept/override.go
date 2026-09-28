package intercept

import (
	"net/http"
	"net/url"
	"strings"
)

// Refusal reasons for a method override frisket cannot apply.
const (
	ReasonOverrideConflict = "method overrides disagree"
	ReasonOverrideInvalid  = "method override is not a method"
)

// overrideHeaders are the headers upstreams read as the request's real
// method: X-HTTP-Method-Override by Google's front end (measured), Rack,
// Symfony, Laravel, Express's method-override and ASP.NET Core;
// X-HTTP-Method by OData and SharePoint; X-Method-Override by ASP.NET
// Web API's override handlers.
var overrideHeaders = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

// overrideParams are the query parameters read the same way, compared
// decoded and case-folded: $httpMethod by Google's front end (measured, and
// as %24httpMethod), _method by Laravel and Symfony.
var overrideParams = []string{"$httpmethod", "_method"}

// override applies the method a request's overrides name, and strips them,
// so that what is decided, logged and sent upstream is the method an
// upstream would run. It returns the method the request line said, and why
// it is refused if it is.
func override(r *http.Request) (sent, reason string) {
	var named []string
	for _, h := range overrideHeaders {
		for _, v := range r.Header.Values(h) {
			named = append(named, strings.Trim(v, " \t"))
		}
		r.Header.Del(h)
	}
	query, params, ok := stripOverrideParams(r.URL.RawQuery)
	if !ok {
		return "", ReasonOverrideInvalid
	}
	named = append(named, params...)
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
	return sent, ""
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
