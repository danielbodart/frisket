package nsmount

import (
	"strings"
	"testing"
)

// What it refuses, it refuses before anything is made. The attach itself
// needs root and a sandbox, and is tested in one (tests/flong.nix).
func TestAttachRefusesWhatIsNotASandboxsMountNamespace(t *testing.T) {
	files := []File{{Name: "ca.crt", Data: []byte("x")}}
	for name, c := range map[string]struct {
		mntns, dir string
		files      []File
		want       string
	}{
		// The mount would land on the host.
		"our own mount namespace": {"/proc/self/ns/mnt", "/etc/frisket", files, "own mount namespace"},
		"a network namespace":     {"/proc/self/ns/net", "/etc/frisket", files, "not a mount namespace"},
		"no namespace at all":     {"/nonexistent", "/etc/frisket", files, "opening mount namespace"},
		"a relative directory":    {"/proc/self/ns/mnt", "etc/frisket", files, "not an absolute directory"},
		"an unclean directory":    {"/proc/self/ns/mnt", "/etc/../etc/frisket", files, "not an absolute directory"},
		"the root":                {"/proc/self/ns/mnt", "/", files, "not an absolute directory"},
		"a file name with a /":    {"/proc/self/ns/mnt", "/etc/frisket", []File{{Name: "../x"}}, "not a file name"},
		"a file name of ..":       {"/proc/self/ns/mnt", "/etc/frisket", []File{{Name: ".."}}, "not a file name"},
	} {
		err := Attach(c.mntns, c.dir, c.files)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
}
