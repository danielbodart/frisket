package dns

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// THE ADVERSARIAL TABLE, from the review's list: every way a name has been
// made to match a pattern it should not, or a pattern made to mean something
// other than what it says.
func TestMatcherAdversarial(t *testing.T) {
	m := MustMatcher("*.google.com", "api.github.com", "xn--bcher-kva.example")
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"www.google.com", true},
		{"a.b.c.google.com", true},
		{"WWW.GOOGLE.COM", true},
		{"www.google.com.", true},
		{"google.com", false},                             // the wildcard is strictly below
		{"evil-google.com", false},                        // suffix, but not after a dot
		{"evilgoogle.com", false},                         //
		{"www.evil-google.com", false},                    //
		{"a.google.com.evil.net", false},                  // prefix, not suffix
		{"google.com.evil.net", false},                    //
		{".google.com", false},                            // nothing in the wildcard's place
		{"a..google.com", false},                          // an empty label
		{"www.google.com..", false},                       // double trailing dot
		{"api.github.com", true},                          //
		{"API.GitHub.Com.", true},                         //
		{"api.github.com..", false},                       //
		{"x.api.github.com", false},                       // exact means exact
		{"api.github.co", false},                          //
		{"api-github.com", false},                         //
		{"xn--bcher-kva.example", true},                   // punycode is just ASCII
		{"XN--BCHER-KVA.EXAMPLE", true},                   //
		{"bücher.example", false},                         // the Unicode form is not the pattern
		{"xn--ggle-0nda.google.com", true},                // a homograph BELOW the wildcard is still below it
		{"xn--ggle-0nda.com", false},                      // and one beside it is not
		{"Key.google.com", false},                         // KELVIN SIGN: ToLower would make it 'k'
		{"api.github.com\x00", false},                     //
		{"api github.com", false},                         //
		{"", false},                                       //
		{".", false},                                      //
		{strings.Repeat("a.", 150) + "google.com", false}, // 310 bytes: longer than any name
	} {
		if got := m.Match(tc.name); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParsePatternRefusesWhatIsNotAName(t *testing.T) {
	for _, bad := range []string{
		"",
		"*",
		"*.",
		"**.google.com",
		"*google.com",
		"api.*.com",
		"google.*",
		"*.*.google.com",
		"*.",
		".google.com",
		"google..com",
		"google.com..",
		" google.com",
		"google.com/",
		"bücher.example",
		"-google.com",
		"google-.com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com", // 257 bytes
	} {
		if p, err := ParsePattern(bad); err == nil {
			t.Errorf("ParsePattern(%q) accepted it as %+v", bad, p)
		}
	}
	for in, want := range map[string]Pattern{
		"Google.COM":             {Name: "google.com"},
		"google.com.":            {Name: "google.com"},
		"*.GitHub.com.":          {Wildcard: true, Name: "github.com"},
		"_acme-challenge.x.test": {Name: "_acme-challenge.x.test"},
		"*.com":                  {Wildcard: true, Name: "com"},
		"xn--bcher-kva.example":  {Name: "xn--bcher-kva.example"},
	} {
		got, err := ParsePattern(in)
		if err != nil || got != want {
			t.Errorf("ParsePattern(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	if _, err := NewMatcher("ok.example", "*"); err == nil {
		t.Error("NewMatcher loaded a policy containing a bare *")
	}
}

func TestANilMatcherMatchesNothing(t *testing.T) {
	var m *Matcher
	if m.Match("anything.example") {
		t.Error("a nil matcher matched")
	}
}

// genLabel is a valid label, sometimes with upper case in it.
func genLabel(t *rapid.T, label string) string {
	return rapid.StringMatching(`[a-zA-Z0-9]([a-zA-Z0-9_-]{0,10}[a-zA-Z0-9])?`).Draw(t, label)
}

func genName(t *rapid.T, label string) string {
	n := rapid.IntRange(1, 4).Draw(t, label+"-labels")
	parts := make([]string, n)
	for i := range parts {
		parts[i] = genLabel(t, label)
	}
	return strings.Join(parts, ".")
}

// EVIL-GOOGLE.COM NEVER MATCHES *.GOOGLE.COM, generalised: for any suffix S,
// anything glued to the front of S without a dot does not match "*.S"; S
// itself does not; and any label, dot, S does -- in any case, with or without
// the trailing dot.
func TestAWildcardMatchesOnlyAfterADot(t *testing.T) {
	rapid.Check(t, propWildcardBoundary)
}

func FuzzAWildcardMatchesOnlyAfterADot(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(propWildcardBoundary))
}

func propWildcardBoundary(t *rapid.T) {
	suffix := genName(t, "suffix")
	m := MustMatcher("*." + suffix)
	glued := rapid.StringMatching(`[a-zA-Z0-9_-]{1,12}`).Draw(t, "glued") + suffix
	if m.Match(glued) {
		t.Fatalf("%q matched *.%s", glued, suffix)
	}
	if m.Match(suffix) {
		t.Fatalf("*.%s matched %s itself", suffix, suffix)
	}
	below := genName(t, "below") + "." + suffix
	if rapid.Bool().Draw(t, "shout") {
		below = strings.ToUpper(below)
	}
	if rapid.Bool().Draw(t, "fqdn") {
		below += "."
	}
	if !m.Match(below) {
		t.Fatalf("%q did not match *.%s", below, suffix)
	}
}

// NORMALISATION IS IDEMPOTENT, for any string at all, and ParsePattern round
// trips through its own String.
func TestNormalizeIsIdempotent(t *testing.T) {
	rapid.Check(t, propNormalizeIdempotent)
}

func FuzzNormalizeIsIdempotent(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(propNormalizeIdempotent))
}

func propNormalizeIdempotent(t *rapid.T) {
	s := rapid.OneOf(rapid.String(), rapid.StringMatching(`[a-zA-Z.*_-]{0,40}`)).Draw(t, "s")
	once := Normalize(s)
	if twice := Normalize(once); twice != once {
		t.Fatalf("Normalize(%q) = %q, and again = %q", s, once, twice)
	}
	if p, err := ParsePattern(s); err == nil {
		again, err := ParsePattern(p.String())
		if err != nil || again != p {
			t.Fatalf("ParsePattern(%q) = %+v, whose String %q parses to %+v, %v", s, p, p.String(), again, err)
		}
		if strings.ContainsAny(p.Name, "*ABCDEFGHIJKLMNOPQRSTUVWXYZ") || strings.HasSuffix(p.Name, ".") {
			t.Fatalf("ParsePattern(%q) left %q un-normalised", s, p.Name)
		}
	}
}

// Patterns come from configuration rather than the sandbox, but the grammar is
// the whole guarantee that "*" and "api.*.com" never load, so it is fuzzed too.
func FuzzParsePattern(f *testing.F) {
	for _, s := range []string{"*.google.com", "*", "api.*.com", "google.com.", "..", "*..x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePattern(s)
		if err != nil {
			return
		}
		if strings.Contains(p.Name, "*") || p.Name == "" {
			t.Fatalf("ParsePattern(%q) = %+v", s, p)
		}
		m := MustMatcher(s)
		if p.Wildcard && len(p.Name) <= maxName-2 {
			if m.Match(p.Name) || !m.Match("x."+p.Name) {
				t.Fatalf("wildcard %q: matches itself %v, matches x.%s %v", s, m.Match(p.Name), p.Name, m.Match("x."+p.Name))
			}
		} else if !p.Wildcard && !m.Match(p.Name) {
			t.Fatalf("exact %q does not match its own name %q", s, p.Name)
		}
	})
}
