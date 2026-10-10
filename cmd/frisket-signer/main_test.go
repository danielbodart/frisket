package main

import (
	"os"
	"os/user"
	"strings"
	"testing"
)

func TestServeRefusesToStartWithoutTheAgentFd(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	err = runServe([]string{"-user", me.Username, "-terminal", "allow"})
	if err == nil || !strings.Contains(err.Error(), "no socket named agent") {
		t.Errorf("got %v", err)
	}
}

func TestSSHSIGRulesAreAllowOrAsk(t *testing.T) {
	r := rules{}
	if err := r.Set("git=allow"); err != nil || r["git"] != "allow" {
		t.Errorf("git=allow: %v, %v", r, err)
	}
	for _, bad := range []string{"git", "=allow", "git=refuse"} {
		if err := r.Set(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
