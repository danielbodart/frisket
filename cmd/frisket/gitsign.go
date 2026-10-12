package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
)

const gitSigningDir = "/run/frisket-sign"

var policyName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// checkPolicyName is whether name is a policy name, a single path
// component.
func checkPolicyName(name string) error {
	if !policyName.MatchString(name) {
		return fmt.Errorf("%q is not a policy name: letters, digits, _, . and -, not starting with . or -", name)
	}
	return nil
}

// listenGitSigning makes root/policy/agent: the directory, which a sandbox
// binds, is kept across a restart, and the socket in it made again.
func listenGitSigning(root, policy string) (*net.UnixListener, error) {
	dir := filepath.Join(root, policy)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if fi, err := os.Lstat(dir); err != nil {
		return nil, err
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "agent")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("git signing socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
