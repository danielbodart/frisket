package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAPolicyNameIsOnePathComponent(t *testing.T) {
	for _, s := range []string{"strict", "trusted", "chase-a_b.1"} {
		var p policyNames
		if err := p.Set(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", ".", "..", "a/b", "-x", ".hidden", "a b"} {
		var p policyNames
		if err := p.Set(s); err == nil {
			t.Errorf("%q was taken", s)
		}
	}
	var p policyNames
	_ = p.Set("strict")
	if err := p.Set("strict"); err == nil {
		t.Error("a policy given twice was taken")
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
