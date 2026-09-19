// Package credential is where a route's credential comes from: a file on the
// host, read by frisket and never by the sandbox.
//
// frisket never refreshes a credential (PLAN.md, decision 10). The host's own
// sessions rotate the agent logins, and a second refresher would race them --
// codex's refresh tokens are single-use. So a source here only ever reads, and
// says when what it read has expired; what to answer then is the caller's
// decision, not this package's.
package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrUnavailable is every way a source can fail to produce a credential: the
// file is missing, unreadable, not the shape expected, or holds nothing. It is
// one error on purpose. The caller has exactly one thing to do with any of
// them -- refuse the request, loudly -- and a route that proceeds without its
// credential is the failure ottergate has, where a header that failed to
// decrypt is silently left off and the request goes out anyway.
var ErrUnavailable = errors.New("credential unavailable")

// Secret is a credential as read, and when it stops being any use.
type Secret struct {
	// Value is what is injected. It never appears in a log line or an error.
	Value string
	// Expires is when the credential stops working, where the source knows.
	// The zero value means the source does not say, not that it never expires.
	Expires time.Time
}

// Expired reports whether the secret is past its expiry at now. A secret with
// no known expiry is never reported expired: the upstream is the only judge
// of that, and guessing would turn a working token into a refusal.
func (s Secret) Expired(now time.Time) bool {
	return !s.Expires.IsZero() && !now.Before(s.Expires)
}

// String keeps the value out of anything that formats a Secret with %v.
func (s Secret) String() string {
	if s.Expires.IsZero() {
		return "credential.Secret{redacted}"
	}
	return fmt.Sprintf("credential.Secret{redacted, expires %s}", s.Expires.UTC().Format(time.RFC3339))
}

// GoString is String for %#v, which would otherwise print the struct's fields.
func (s Secret) GoString() string { return s.String() }

// Source produces the current credential. Get is called once per request, so
// it must be cheap; it must also be safe for concurrent use.
type Source interface {
	Get() (Secret, error)
}

// Extractor turns a credential file's bytes into a Secret. Errors it returns
// must not quote the file: they end up in a log line, and the file is the
// credential.
type Extractor func(raw []byte) (Secret, error)

// Trimmed is the whole file, less surrounding whitespace -- a token on its own
// in a file, as sops-nix and most `*_TOKEN_FILE` conventions write it.
func Trimmed() Extractor {
	return func(raw []byte) (Secret, error) {
		v := string(bytes.TrimSpace(raw))
		if err := validValue(v); err != nil {
			return Secret{}, err
		}
		return Secret{Value: v}, nil
	}
}

// JSON extracts the token at a dotted path through nested objects, and
// optionally an expiry at another.
//
// ExpiresMillis names a number of milliseconds since the epoch, which is how
// Claude Code writes `claudeAiOauth.expiresAt`. The unit is in the field's name
// rather than inferred from the number's size, because a guess that is wrong by
// a factor of a thousand is a credential that is either always stale or never.
//
// A route selects it with credentialJSON; without one it reads a bare token
// with Trimmed.
type JSON struct {
	Token         string
	ExpiresMillis string
}

// Extract is JSON as an Extractor.
func (j JSON) Extract(raw []byte) (Secret, error) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		// Deliberately not wrapping err: a syntax error from encoding/json
		// quotes the offending character, and the offending character is
		// part of a credential file.
		return Secret{}, fmt.Errorf("%w: file is not JSON", ErrUnavailable)
	}
	tok, ok := lookup(doc, j.Token).(string)
	if !ok {
		return Secret{}, fmt.Errorf("%w: no string at %q", ErrUnavailable, j.Token)
	}
	if err := validValue(tok); err != nil {
		return Secret{}, fmt.Errorf("%w (at %q)", err, j.Token)
	}
	s := Secret{Value: tok}
	if j.ExpiresMillis != "" {
		n, ok := lookup(doc, j.ExpiresMillis).(json.Number)
		if !ok {
			// A route configured with an expiry that the file does not carry
			// is refused rather than treated as never expiring: the expiry is
			// what turns a stale token into a 503 instead of a 401, and the
			// 401 is the one that fails the agent's turn.
			return Secret{}, fmt.Errorf("%w: no number at %q", ErrUnavailable, j.ExpiresMillis)
		}
		ms, err := n.Int64()
		if err != nil {
			return Secret{}, fmt.Errorf("%w: %q is not a whole number of milliseconds", ErrUnavailable, j.ExpiresMillis)
		}
		s.Expires = time.UnixMilli(ms)
	}
	return s, nil
}

func lookup(doc any, path string) any {
	if path == "" {
		return nil
	}
	for key := range strings.SplitSeq(path, ".") {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[key]
	}
	return doc
}

// validValue refuses what would be refused later, or worse, not refused: an
// empty token would send `Authorization: Bearer ` and let the upstream's 401
// fail the agent's turn, and a CR or LF would be a header injection if any
// layer between here and the wire ever stopped checking.
func validValue(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty", ErrUnavailable)
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= ' ' || c == 0x7f {
			return fmt.Errorf("%w: contains whitespace or a control character", ErrUnavailable)
		}
	}
	return nil
}
