package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAPolicyNameIsOnePathComponent(t *testing.T) {
	for _, s := range []string{"strict", "trusted", "chase-a_b.1"} {
		if err := checkPolicyName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", ".", "..", "a/b", "-x", ".hidden", "a b"} {
		if err := checkPolicyName(s); err == nil {
			t.Errorf("%q was taken", s)
		}
	}
}

func TestTheGitSigningSocketIsMadeAgainInTheSameDirectory(t *testing.T) {
	root := t.TempDir()
	ln, err := listenGitSigning(root, "strict")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "strict")
	before, _ := os.Stat(dir)
	ln.SetUnlinkOnClose(false)
	ln.Close()

	ln, err = listenGitSigning(root, "strict")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	after, _ := os.Stat(dir)
	if !os.SameFile(before, after) || after.Mode().Perm() != 0o700 {
		t.Errorf("the directory changed: %v, %v", before, after)
	}
	fi, err := os.Stat(filepath.Join(dir, "agent"))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket: %v, %v", fi, err)
	}
	c, err := net.Dial("unix", filepath.Join(dir, "agent"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
