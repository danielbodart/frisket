package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielbodart/frisket/projpolicy"
)

const defaultAllowedSigners = "/etc/frisket/allowed_signers"

// runPolicy is frisket policy: a project's policy file, checked or formatted
// by hand. Signing is the signer's, through galley.
func runPolicy(argv []string, stdout io.Writer) error {
	if len(argv) == 0 {
		return errors.New("name verify, fmt or signers")
	}
	switch argv[0] {
	case "verify":
		return runPolicyVerify(argv[1:], stdout)
	case "fmt":
		return runPolicyFmt(argv[1:], stdout)
	case "signers":
		return runPolicySigners(argv[1:], stdout)
	}
	return fmt.Errorf("unknown policy command %q: verify, fmt or signers", argv[0])
}

func runPolicyVerify(argv []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
	signers := fs.String("allowed-signers", defaultAllowedSigners, "the allowed signers file")
	home := fs.String("home", "", "the home a root's namespace is named from (default $HOME)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("name one policy file")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if *home == "" {
		if *home, err = os.UserHomeDir(); err != nil {
			return err
		}
	}
	all, err := projpolicy.ReadAllowedSigners(*signers)
	if err != nil {
		return err
	}
	p, err := projpolicy.Load(filepath.Dir(path), *home, filepath.Base(path), all)
	if err != nil {
		return err
	}
	if !p.Verified {
		return fmt.Errorf("%s does not verify in %s: %s", path, p.Namespace, p.Why)
	}
	fmt.Fprintf(stdout, "%s: signed by %s in %s\n", path, strings.Join(p.Principals, ", "), p.Namespace)
	return nil
}

func runPolicyFmt(argv []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("policy fmt", flag.ContinueOnError)
	check := fs.Bool("check", false, "only say whether FILE is canonical")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("name one policy file")
	}
	path := fs.Arg(0)
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := projpolicy.Format(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(f, b) {
		return nil
	}
	if *check {
		return fmt.Errorf("%s is not canonical: run frisket policy fmt on it, then sign it again", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(f); err == nil {
		err = tmp.Chmod(st.Mode().Perm())
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: formatted; its signature, if any, no longer matches\n", path)
	return nil
}

func runPolicySigners(argv []string, stdout io.Writer) error {
	if len(argv) != 1 {
		return errors.New("name one allowed signers file")
	}
	all, err := projpolicy.ReadAllowedSigners(argv[0])
	if err != nil {
		return err
	}
	for _, l := range all.Lines {
		ns := "any namespace"
		if l.HasNS {
			ns = "namespaces " + l.Namespaces
		}
		fmt.Fprintf(stdout, "line %d: %s %s, %s\n", l.Line, l.Principals, l.Key.Type(), ns)
	}
	return nil
}
