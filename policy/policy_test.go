package policy

import (
	"encoding/json"
	"slices"
	"testing"
)

// A misspelt key is a rule that silently does not apply, so Decode refuses
// it at any depth, and refuses a second value after the first.
func TestDecodeRefusesAnUnknownFieldAndATrailingValue(t *testing.T) {
	for _, b := range []string{
		`{"name":"p","alow":["a.test"]}`,
		`{"name":"p","routes":[{"name":"r","host":"a.test","pathz":[]}]}`,
		`{"name":"p"} {"name":"q"}`,
	} {
		var d Document
		if err := Decode([]byte(b), &d); err == nil {
			t.Errorf("%s decoded", b)
		}
	}
}

// What a writer marshals from these types is what Decode reads back.
func TestADocumentRoundTrips(t *testing.T) {
	want := Document{Name: "p", Policy: Policy{
		Allow: []string{"api.test"},
		Routes: []Route{{Name: "api", Host: "api.test", Paths: []PathRule{
			{Methods: []string{"GET"}, Prefix: "/"},
		}}},
	}}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Document
	if err := Decode(b, &got); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if got.Name != want.Name || !slices.Equal(got.Allow, want.Allow) || len(got.Routes) != 1 || got.Routes[0].Paths[0].Prefix != "/" {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
