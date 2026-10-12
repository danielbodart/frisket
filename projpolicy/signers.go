package projpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AllowedSigners is an allowed_signers file, read with OpenSSH's meaning
// (ssh-keygen(1), ALLOWED SIGNERS): each line's principals are a pattern
// list, its key a plain public key, and its options namespaces=,
// valid-after= and valid-before=.
//
// It is stricter than OpenSSH in one way: a line that does not parse, an
// unknown option or a cert-authority line refuses the whole file, rather
// than being skipped, since the file is root's and written by Nix, and a
// line silently not applying is a signer silently not trusted.
type AllowedSigners struct {
	Lines []SignerLine
}

// SignerLine is one line of the file.
type SignerLine struct {
	Line       int    // its number in the file, from 1
	Principals string // a pattern list, matched against -I
	Key        ssh.PublicKey
	Namespaces string // a pattern list; "" lets the key sign in any namespace
	HasNS      bool
	After      time.Time // zero is no valid-after
	Before     time.Time // zero is no valid-before
}

// ReadAllowedSigners reads and parses the file at path.
func ReadAllowedSigners(path string) (*AllowedSigners, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ParseAllowedSigners(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ParseAllowedSigners parses the file's contents.
func ParseAllowedSigners(b []byte) (*AllowedSigners, error) {
	s := &AllowedSigners{}
	n := 0
	for raw := range bytes.Lines(b) {
		n++
		line := strings.TrimSpace(string(raw))
		if line == "" || line[0] == '#' {
			continue
		}
		l, err := parseSignerLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		l.Line = n
		s.Lines = append(s.Lines, *l)
	}
	return s, nil
}

func parseSignerLine(line string) (*SignerLine, error) {
	l := &SignerLine{}
	var rest string
	if line[0] == '"' {
		end := strings.IndexByte(line[1:], '"')
		if end < 0 {
			return nil, errors.New("the principals' quote is not closed")
		}
		l.Principals, rest = line[1:1+end], line[2+end:]
	} else {
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			return nil, errors.New("principals and no key")
		}
		l.Principals, rest = line[:i], line[i:]
	}
	if l.Principals == "" {
		return nil, errors.New("no principals")
	}
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return nil, errors.New("no space after the principals")
	}
	if rest = strings.TrimLeft(rest, " \t"); rest == "" {
		return nil, errors.New("principals and no key")
	}
	key, _, opts, tail, err := ssh.ParseAuthorizedKey([]byte(rest))
	if err != nil {
		return nil, fmt.Errorf("the key: %w", err)
	}
	if len(bytes.TrimSpace(tail)) != 0 {
		return nil, errors.New("more than one line")
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, errors.New("a certificate in place of a key")
	}
	l.Key = key
	for _, o := range opts {
		name, value, hasValue := strings.Cut(o, "=")
		switch strings.ToLower(name) {
		case "cert-authority":
			return nil, errors.New("cert-authority: a project policy is signed by a plain key, so a CA line is not supported here")
		case "namespaces", "valid-after", "valid-before":
		default:
			return nil, fmt.Errorf("unknown option %q", name)
		}
		if !hasValue {
			return nil, fmt.Errorf("%s needs a value", name)
		}
		v, err := dequote(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		switch strings.ToLower(name) {
		case "namespaces":
			if l.HasNS {
				return nil, errors.New("namespaces given twice")
			}
			l.Namespaces, l.HasNS = v, true
		case "valid-after":
			if !l.After.IsZero() {
				return nil, errors.New("valid-after given twice")
			}
			if l.After, err = parseTime(v); err != nil {
				return nil, fmt.Errorf("valid-after: %w", err)
			}
		case "valid-before":
			if !l.Before.IsZero() {
				return nil, errors.New("valid-before given twice")
			}
			if l.Before, err = parseTime(v); err != nil {
				return nil, fmt.Errorf("valid-before: %w", err)
			}
		}
	}
	if !l.After.IsZero() && !l.Before.IsZero() && !l.Before.After(l.After) {
		return nil, errors.New("valid-before is not after valid-after")
	}
	return l, nil
}

// dequote takes the double quotes off an option's value, as opt_dequote
// does: a backslash makes the next quote literal.
func dequote(v string) (string, error) {
	if !strings.HasPrefix(v, `"`) {
		return v, nil
	}
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\' && i+1 < len(v) && v[i+1] == '"':
			b.WriteByte('"')
			i++
		case c == '"':
			if i != len(v)-1 {
				return "", errors.New("text after the closing quote")
			}
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
	return "", errors.New("the quote is not closed")
}

// parseTime reads OpenSSH's YYYYMMDD[HHMM[SS]], in UTC with a Z after it,
// else in local time, as parse_absolute_time does.
func parseTime(v string) (time.Time, error) {
	loc := time.Local
	if s, ok := strings.CutSuffix(v, "Z"); ok {
		v, loc = s, time.UTC
	} else if s, ok := strings.CutSuffix(v, "z"); ok {
		v, loc = s, time.UTC
	}
	var layout string
	switch len(v) {
	case 8:
		layout = "20060102"
	case 12:
		layout = "200601021504"
	case 14:
		layout = "20060102150405"
	default:
		return time.Time{}, fmt.Errorf("%q is not YYYYMMDD[HHMM[SS]][Z]", v)
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not YYYYMMDD[HHMM[SS]][Z]", v)
	}
	return t, nil
}

// Allowed is the principals of every line that lets key sign in namespace
// at now, as check_allowed_keys_line decides each: its principals match
// principal (any, when principal is ""), its key is key, its namespaces
// match namespace, and now is within its validity.
func (s *AllowedSigners) Allowed(key ssh.PublicKey, principal, namespace string, now time.Time) ([]string, error) {
	if s == nil {
		return nil, errors.New("no allowed signers")
	}
	want := key.Marshal()
	var who []string
	var why []string
	for _, l := range s.Lines {
		if !bytes.Equal(l.Key.Marshal(), want) {
			continue
		}
		if principal != "" && MatchPatternList(principal, l.Principals) != 1 {
			continue
		}
		switch {
		case l.HasNS && MatchPatternList(namespace, l.Namespaces) != 1:
			why = append(why, fmt.Sprintf("line %d's namespaces %q do not take %q", l.Line, l.Namespaces, namespace))
		case !l.After.IsZero() && now.Before(l.After):
			why = append(why, fmt.Sprintf("line %d's key is not valid until %s", l.Line, l.After.Format(time.RFC3339)))
		case !l.Before.IsZero() && now.After(l.Before):
			why = append(why, fmt.Sprintf("line %d's key expired at %s", l.Line, l.Before.Format(time.RFC3339)))
		default:
			who = append(who, l.Principals)
		}
	}
	if len(who) > 0 {
		return who, nil
	}
	if len(why) > 0 {
		return nil, errors.New(strings.Join(why, "; "))
	}
	if principal != "" {
		return nil, fmt.Errorf("%s is not an allowed signer for %s", ssh.FingerprintSHA256(key), principal)
	}
	return nil, fmt.Errorf("%s is not an allowed signer", ssh.FingerprintSHA256(key))
}

// MatchPatternList is OpenSSH's match_pattern_list, case-sensitive: 1 when
// s matches a pattern of the comma-separated list and no negated one, -1
// when it matches a negated (!) one, 0 when it matches none.
func MatchPatternList(s, list string) int {
	got := 0
	for sub := range strings.SplitSeq(list, ",") {
		neg := false
		if p, ok := strings.CutPrefix(sub, "!"); ok {
			sub, neg = p, true
		}
		if len(sub) >= 1023 {
			return 0
		}
		if MatchPattern(s, sub) {
			if neg {
				return -1
			}
			got = 1
		}
	}
	return got
}

// MatchPattern is OpenSSH's match_pattern: * any run of bytes, ? any one
// byte, anything else itself.
func MatchPattern(s, p string) bool {
	si, pi := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			si++
			pi++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
