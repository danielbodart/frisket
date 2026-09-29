package docker

import (
	"strconv"
	"unicode/utf8"
)

// The reasons a refusal gives, as section 2.4 of the contract names them.
const (
	ReasonUnreadable = "body unreadable"
	ReasonBody       = "body not allowed"
	ReasonHostIP     = "hostip not allowed"
	ReasonQuery      = "query not allowed"
)

// Refusal is why a body or a query was refused, in two tellings. Error is
// what the client may read: a reason and, for a field, the table's own path,
// built from nothing but the table and frisket's words, so that a refusal
// body never echoes a request back (the invariant of refusal.go). Log is for
// frisket's log line, and may name the request's own key or value, quoted
// and clipped.
type Refusal struct {
	Reason string
	// Detail is where or what, in the table's terms: "ContainerCreate's
	// HostConfig.Privileged is not zero".
	Detail string
	Log    string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return r.Reason
	}
	return r.Reason + ": " + r.Detail
}

func unreadable(detail, log string) *Refusal {
	return &Refusal{Reason: ReasonUnreadable, Detail: detail, Log: "body " + log}
}

// maxQuoted is the most of a request's key or value that goes into a log line.
const maxQuoted = 128

// clip cuts s to maxQuoted bytes at a rune boundary.
func clip(s string) string {
	if len(s) <= maxQuoted {
		return s
	}
	n := maxQuoted
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// quote is a request's key or value as a log line holds it: Go-quoted, from at
// most maxQuoted bytes of it.
func quote(s string) string { return strconv.Quote(clip(s)) }

// logKey is a request's key in a path in the log: bare when it is plainly a
// name, and quoted otherwise, so that no key can pass for punctuation.
func logKey(s string) string {
	if s == "" || len(s) > maxQuoted {
		return quote(s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-' || c == '/') {
			return quote(s)
		}
	}
	return s
}
