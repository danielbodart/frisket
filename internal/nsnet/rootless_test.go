package nsnet

import (
	"net/netip"
	"slices"
	"testing"
)

// Rootless, the helper is nsenter first: the user namespace, then the network
// namespace, and only then this program -- which, already inside, is not told
// to enter anything itself.
func TestARootlessHelperIsEnteredByNsenter(t *testing.T) {
	h := Helper{Exe: "/frisket", Userns: "/proc/7/fd/3", Nsenter: "/bin/nsenter"}
	argv, err := h.argv(HelperArgs{Netns: "/proc/7/fd/4", Specs: []Spec{{Net: "udp4", Addr: netip.MustParseAddrPort("127.0.0.1:53")}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/bin/nsenter", "--user=/proc/7/fd/3", "--net=/proc/7/fd/4", "--", "/frisket", "helper"}
	if !slices.Equal(argv[:len(want)], want) {
		t.Fatalf("argv = %q, want it to start %q", argv, want)
	}
	if slices.Contains(argv, "-net") {
		t.Errorf("argv = %q: the helper is told to enter a namespace nsenter already entered", argv)
	}
}
