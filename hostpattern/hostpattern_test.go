package hostpattern

import "testing"

func TestAPatternMatchesALabelOrMore(t *testing.T) {
	for _, c := range []struct {
		key, name string
		want      bool
	}{
		{"gateway", "gateway", true},
		{"gateway", "gateway.lan", false},
		{"*-ap", "kitchen-ap", true},
		{"*.bodar.com", "nas.bodar.com", true},
		{"*.bodar.com", "a.nas.bodar.com", false},
		{"**.bodar.com", "a.nas.bodar.com", true},
		{"**.bodar.com", "bodar.com", false},
		{"nas.*.com", "nas.bodar.com", true},
		{"*", "gateway", true},
		{"*", "github.com", false},
		{"**", "github.com", true},
	} {
		p, err := Compile(c.key)
		if err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		if got := p.Match(c.name); got != c.want {
			t.Errorf("%s matching %s: %v", c.key, c.name, got)
		}
	}
	for _, bad := range []string{"", "a**b", "**-ap.lan", "a.**", "a..b", "a,b", "|1|x", "a?b", "!a", "a b"} {
		if Check(bad) == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// Below is what a version 1 wildcard says, and CoversBelow whether a key
// matches every name a version 1 wildcard does.
func TestBelowAndCoversBelow(t *testing.T) {
	for key, want := range map[string]string{"**.example.com": "example.com", "**": ""} {
		p, _ := Compile(key)
		if got, ok := p.Below(); !ok || got != want {
			t.Errorf("%s below %q %v", key, got, ok)
		}
	}
	for _, key := range []string{"*.example.com", "**.*.com", "a.example.com", "**.ex*.com"} {
		p, _ := Compile(key)
		if _, ok := p.Below(); ok {
			t.Errorf("%s has a literal name below it", key)
		}
	}
	for _, c := range []struct {
		key, suffix string
		want        bool
	}{
		{"**", "googleapis.com", true},
		{"**.com", "googleapis.com", true},
		{"**.googleapis.com", "googleapis.com", true},
		{"**.*.com", "googleapis.com", true},
		{"**.mtls.googleapis.com", "googleapis.com", false},
		{"*.googleapis.com", "googleapis.com", false},
		{"**.googleapis.com", "mtls.googleapis.com", true},
	} {
		p, _ := Compile(c.key)
		if got := p.CoversBelow(c.suffix); got != c.want {
			t.Errorf("%s covers below %s: %v", c.key, c.suffix, got)
		}
	}
}

func TestBestIsTheLiteralThenTheNarrowest(t *testing.T) {
	keys := []string{"**.example", "*.example", "a.b.example", "*.b.example", "**.b.example"}
	for name, want := range map[string]string{
		"z.example":     "*.example",
		"q.z.example":   "**.example",
		"a.b.example":   "a.b.example",
		"c.b.example":   "*.b.example",
		"d.c.b.example": "**.b.example",
		"example":       "",
	} {
		if got := Best(keys, name, nil); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
