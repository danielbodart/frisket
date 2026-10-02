package policy

import (
	"encoding/json"
	"net/netip"
	"reflect"
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
		`{"name":"p","record":{"default":"allow","always":true}}`,
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
		Allow:  []string{"api.test"},
		Record: &Record{Default: "allow", Sink: "/var/lib/frisket/records/s.jsonl"},
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

// An SSH route is strict at its own depth too: a misspelt key in a host or
// a rule is refused, not dropped.
func TestDecodeRefusesAnUnknownFieldInAnSSHRoute(t *testing.T) {
	for _, b := range []string{
		`{"name":"p","allow":[],"ssh":[{"name":"s","address":"10.0.0.5","user":"u","hostKeys":[],"agnet":"/a"}]}`,
		`{"name":"p","allow":[],"ssh":[{"name":"s","address":"10.0.0.5","user":"u","hostKeys":[],"exec":[{"command":"ls","allow":true}]}]}`,
		`{"name":"p","allow":[],"ssh":{"name":"s"}}`,
		`{"name":"p","allow":[],"ssh":[{"name":"s","address":"10.0.0.5","user":"u","hostKeys":[],"password":"/p"}]}`,
		`{"name":"p","allow":[],"ssh":[{"name":"s","address":"10.0.0.5","user":"u","hostKeys":[],"passwordFile":"/p","shell":"yes"}]}`,
	} {
		var d Document
		if err := Decode([]byte(b), &d); err == nil {
			t.Errorf("%s decoded", b)
		}
	}
}

// What chase marshals from SSHRoute is what Decode reads back, field for
// field.
func TestAnSSHRouteRoundTrips(t *testing.T) {
	want := Document{Name: "p", Policy: Policy{
		Allow: []string{},
		SSH: []SSHRoute{{
			Name:     "server",
			Address:  "[fd00::5]:2222",
			User:     "dan",
			HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKk7kU0dW1lSbm8W7xQ2uZVXvVq2zDQm0V6Zg7I4pYQb host"},
			Agent:    "/run/user/1000/gcr/ssh",
			Identity: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
			Exec: []ExecRule{
				{Command: "systemctl status *", Operation: &Operation{ID: "systemctl-status", Summary: "Show a unit's status", Class: "read", Category: "services"}},
				{Command: "sudo **", Ask: true},
				{Command: "rm **", Refuse: true},
				{Arg: ".ssh", Refuse: true},
				{Command: "less **", Arg: "+*", Ask: true},
			},
			Unmatched: "refuse",
		}, {
			Name:         "modem",
			Address:      "192.168.1.1",
			User:         "admin",
			HostKeys:     []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKk7kU0dW1lSbm8W7xQ2uZVXvVq2zDQm0V6Zg7I4pYQb modem"},
			PasswordFile: "/run/secrets/modem-password",
			Shell:        true,
			Exec:         []ExecRule{{Command: "xdslctl info **"}},
		}},
	}}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Document
	if err := Decode(b, &got); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// A route's destination is its address as written, at 22 when it names no
// port; one that is not a literal address is never a destination.
func TestSSHDestinationsAreEachRoutesAddressAndPort(t *testing.T) {
	p := Policy{SSH: []SSHRoute{
		{Address: "10.0.0.5"},
		{Address: "10.0.0.6:2222"},
		{Address: "fd00::5"},
		{Address: "[fd00::6]:2200"},
		{Address: "server.lan"},
		{Address: "10.0.0.7:0"},
	}}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.5:22"),
		netip.MustParseAddrPort("10.0.0.6:2222"),
		netip.MustParseAddrPort("[fd00::5]:22"),
		netip.MustParseAddrPort("[fd00::6]:2200"),
	}
	if got := p.SSHDestinations(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
