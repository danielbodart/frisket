package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh/agent"
)

const defaultAllowedSigners = "/etc/frisket/allowed_signers"

// runPolicy is frisket policy: a project's policy file, checked, formatted
// or signed by hand. Signing is the signer's, through galley.
func runPolicy(argv []string, stdout io.Writer) error {
	if len(argv) == 0 {
		return errors.New("name verify, fmt, signers or sign")
	}
	switch argv[0] {
	case "verify":
		return runPolicyVerify(argv[1:], stdout)
	case "fmt":
		return runPolicyFmt(argv[1:], stdout)
	case "signers":
		return runPolicySigners(argv[1:], stdout)
	case "sign":
		return runPolicySign(argv[1:], stdout)
	}
	return fmt.Errorf("unknown policy command %q: verify, fmt, signers or sign", argv[0])
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

func runPolicySign(argv []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	sock := flags.String("agent", os.Getenv("SSH_AUTH_SOCK"), "the signer's agent socket")
	oldPath := flags.String("old", "", "the bytes POLICY.sig was made over (default: git's HEAD of POLICY)")
	if err := flags.Parse(argv); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("name one policy file")
	}
	if *sock == "" {
		return errors.New("no agent: set SSH_AUTH_SOCK or -agent")
	}
	abs, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}
	// The directory as the kernel names it, as a process's working
	// directory is read, so the namespace is the one the signer and the
	// courier name it by.
	root, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	name := filepath.Base(abs)
	path := filepath.Join(root, name)
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return err
	}
	if !projpolicy.Canonical(b) {
		return fmt.Errorf("%s is not canonical: run frisket policy fmt %s first, and look at what it changed", path, path)
	}
	req := agentsrv.PolicySignRequest{Root: root, Name: name, New: b}
	req.OldSig, err = projpolicy.ReadFile(path + projpolicy.SigSuffix)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		req.OldSig = nil
	case err != nil:
		return err
	case *oldPath != "":
		if req.Old, err = projpolicy.ReadFile(*oldPath); err != nil {
			return err
		}
	default:
		req.Old = gitHead(root, name)
	}
	sig, err := policySign(*sock, req)
	if err != nil {
		return err
	}
	if err := writeBeside(path+projpolicy.SigSuffix, sig); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: signed, %s written\n", path, filepath.Base(path)+projpolicy.SigSuffix)
	return nil
}

// gitHead is name as git's HEAD has it in root, or nil.
func gitHead(root, name string) []byte {
	cmd := exec.Command("git", "-C", root, "show", "HEAD:./"+name)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return out
}

func policySign(sock string, req agentsrv.PolicySignRequest) ([]byte, error) {
	contents, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	out, err := agent.NewClient(c).Extension(agentsrv.PolicySignExtension, contents)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		return nil, fmt.Errorf("the agent at %s does not sign policies: it is not frisket-signer", sock)
	}
	if err != nil {
		return nil, err
	}
	var resp agentsrv.PolicySignResponse
	if len(out) < 1 || json.Unmarshal(out[1:], &resp) != nil {
		return nil, fmt.Errorf("the agent's answer %q is not policy-sign's", out)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("the signer: %s", resp.Error)
	}
	if resp.Sig == nil {
		return nil, errors.New("the signer sent no signature")
	}
	return resp.Sig, nil
}

// writeBeside replaces path with b through a temporary file beside it.
func writeBeside(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
