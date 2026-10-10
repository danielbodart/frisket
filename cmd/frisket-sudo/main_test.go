package main

import (
	"os"
	"strings"
	"testing"
)

func TestServeRefusesToStartWithoutTheGateFd(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	err := runServe([]string{"-user", "dan"})
	if err == nil || !strings.Contains(err.Error(), "no socket named gate") {
		t.Errorf("got %v", err)
	}
}
