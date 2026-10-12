package projpolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// NamespacePrefix starts every project policy's SSHSIG namespace. The
// signer refuses a raw sign in any namespace that starts with it.
const NamespacePrefix = "frisket-policy"

// SigSuffix names a policy file's signature beside it: chase.json.sig.
const SigSuffix = ".sig"

// maxFile bounds what is read of a policy file or its signature.
const maxFile = 1 << 20

// Namespace is the SSHSIG namespace a policy at root is signed in:
// frisket-policy:~/Projects/foo for a root under home, frisket-policy:~ for
// home itself, else frisket-policy: and the cleaned absolute path.
func Namespace(root, home string) (string, error) {
	r, err := RootName(root, home)
	if err != nil {
		return "", err
	}
	return NamespacePrefix + ":" + r, nil
}

// RootName is root as a namespace names it: ~/rel under home, else the
// cleaned absolute path.
func RootName(root, home string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("root %q is not absolute", root)
	}
	root = filepath.Clean(root)
	if home != "" {
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("home %q is not absolute", home)
		}
		if rel, ok := under(root, filepath.Clean(home)); ok {
			if rel == "." {
				return "~", nil
			}
			return "~/" + rel, nil
		}
	}
	return root, nil
}

// under is path relative to dir, when path is dir or beneath it.
func under(path, dir string) (string, bool) {
	if path == dir {
		return ".", true
	}
	prefix := dir
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	rel, ok := strings.CutPrefix(path, prefix)
	return rel, ok
}

// ErrNotFound is Find's answer when no directory from dir up to home holds
// the policy file.
var ErrNotFound = errors.New("no project policy file")

// Find is the nearest directory from dir up to home, both included, that
// holds a file named name. A dir outside home finds nothing, so neither /
// nor another user's tree is ever a project. A name there that is not a
// regular file (a symlink, a directory) is an error rather than passed
// over, so a parent's policy never applies in its place.
func Find(dir, home, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a file name", name)
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(home) {
		return "", fmt.Errorf("%q and %q must both be absolute", dir, home)
	}
	dir, home = filepath.Clean(dir), filepath.Clean(home)
	if _, ok := under(dir, home); !ok {
		return "", fmt.Errorf("%w: %s is not under %s", ErrNotFound, dir, home)
	}
	for d := dir; ; d = filepath.Dir(d) {
		st, err := os.Lstat(filepath.Join(d, name))
		switch {
		case err == nil && st.Mode().IsRegular():
			return d, nil
		case err == nil:
			return d, fmt.Errorf("%s is a %s, not a regular file", filepath.Join(d, name), st.Mode().Type())
		case !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR):
			return d, err
		}
		if d == home {
			return "", fmt.Errorf("%w from %s up to %s", ErrNotFound, dir, home)
		}
	}
}

// Policy is a project's policy file as read, and whether its signature
// verifies.
type Policy struct {
	Root      string // the directory holding the file
	Namespace string
	Bytes     []byte
	Sig       []byte // nil when there is no signature file
	Digest    string // Digest(Bytes)

	Verified   bool
	Principals []string // the allowed signers' lines that verified it
	Why        string   // why it does not verify, when it does not
}

// Load reads root/name and root/name.sig and verifies the signature over
// the file's exact bytes, in root's namespace (home decides its name),
// against signers. An unreadable policy file is the error; a missing,
// malformed or wrong signature is Verified false, with Why saying which.
func Load(root, home, name string, signers *AllowedSigners) (*Policy, error) {
	ns, err := Namespace(root, home)
	if err != nil {
		return nil, err
	}
	p := &Policy{Root: filepath.Clean(root), Namespace: ns}
	path := filepath.Join(p.Root, name)
	if p.Bytes, err = ReadFile(path); err != nil {
		return nil, err
	}
	p.Digest = Digest(p.Bytes)
	p.Sig, err = ReadFile(path + SigSuffix)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			p.Sig = nil
			p.Why = "no " + filepath.Base(path) + SigSuffix
		} else {
			p.Sig = nil
			p.Why = err.Error()
		}
		return p, nil
	}
	p.Principals, err = Verify(p.Bytes, p.Sig, ns, signers, "", time.Now())
	if err != nil {
		p.Why = err.Error()
		return p, nil
	}
	p.Verified = true
	return p, nil
}

// ReadFile reads a policy file or signature: a regular file, never through
// a symlink at the last component, and at most a MiB.
func ReadFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is over %d bytes", path, maxFile)
	}
	return b, nil
}
