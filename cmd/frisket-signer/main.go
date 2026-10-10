// Command frisket-signer holds the SSH keys that live in the TPM, signs
// silently for frisket, for a terminal tab ssh-ing to a known host and for
// listed SSHSIG namespaces, and asks through galley for everything else.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/internal/grant"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/internal/tpmkey"
)

const (
	keyDir     = "/var/lib/frisket-signer"
	knownHosts = "/etc/ssh/ssh_known_hosts"
	tpmDevice  = "/dev/tpmrm0"
)

const usage = `frisket-signer -- SSH keys in the TPM, asked for through galley

  frisket-signer serve -user NAME -terminal allow|ask [-sshsig NAMESPACE=allow|ask]...
        Serve the agent socket systemd passes as the fd named agent, to
        NAME's uid only, with the keys in ` + keyDir + `.

  frisket-signer keygen -out DIR [-comment C] [--no-da]
        Make a key in the TPM and write DIR/id_ecdsa.tpm and DIR/id_ecdsa.pub
        in stock ssh-tpm-agent's format.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		err = runServe(args)
	case "keygen":
		err = runKeygen(args)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "frisket-signer: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "frisket-signer %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

type rules map[string]agentsrv.Rule

func (r rules) String() string { return fmt.Sprint(map[string]agentsrv.Rule(r)) }
func (r rules) Set(s string) error {
	ns, v, ok := strings.Cut(s, "=")
	if !ok || ns == "" {
		return fmt.Errorf("%q: want namespace=allow|ask", s)
	}
	rule, err := parseRule(v)
	if err != nil {
		return err
	}
	r[ns] = rule
	return nil
}

func parseRule(s string) (agentsrv.Rule, error) {
	switch r := agentsrv.Rule(s); r {
	case agentsrv.Allow, agentsrv.Ask:
		return r, nil
	}
	return "", fmt.Errorf("%q is not allow or ask", s)
}

func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	name := fs.String("user", "", "the only user served, and the galley user asked")
	terminal := fs.String("terminal", "", "a real tab's bound, direct sign to a host in "+knownHosts+": allow or ask")
	sshsig := rules{}
	fs.Var(sshsig, "sshsig", "a direct SSHSIG sign in a namespace: namespace=allow|ask; repeatable")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-user is required")
	}
	term, err := parseRule(*terminal)
	if err != nil {
		return fmt.Errorf("-terminal: %w", err)
	}
	u, err := user.Lookup(*name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	stdlog.SetOutput(io.Discard)

	ln, err := agentListener()
	if err != nil {
		return err
	}
	loaded, err := tpmkey.Load(keyDir, log)
	if err != nil {
		return err
	}
	tpm := tpmkey.Device(tpmDevice)
	s := &agentsrv.Server{
		User: *name, UID: uid, Terminal: term, SSHSIG: sshsig,
		KnownHosts: knownHosts, Grants: grant.New(), Log: log,
	}
	for _, k := range loaded {
		s.Keys = append(s.Keys, agentsrv.Key{Signer: k.Signer(tpm), Comment: k.Comment})
	}
	if n := sdnotify.FromEnv(); n != nil {
		if err := n.Ready(fmt.Sprintf("%d keys", len(s.Keys))); err != nil {
			return err
		}
	}
	log.Info("frisket-signer serve", "user", *name, "keys", len(s.Keys), "terminal", term, "sshsig", sshsig)
	return s.Serve(ln)
}

func agentListener() (*net.UnixListener, error) {
	fds, err := sdnotify.Listen()
	if err != nil {
		return nil, err
	}
	for _, fd := range fds {
		if fd.Name != "agent" {
			continue
		}
		ln, err := net.FileListener(fd.File)
		_ = fd.File.Close()
		if err != nil {
			return nil, fmt.Errorf("the agent socket systemd passed: %w", err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			return nil, fmt.Errorf("the agent socket systemd passed is a %T", ln)
		}
		return ul, nil
	}
	return nil, errors.New("systemd passed no socket named agent")
}

func runKeygen(argv []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "the directory to write id_ecdsa.tpm and id_ecdsa.pub to")
	comment := fs.String("comment", "", "the public key's comment")
	noDA := fs.Bool("no-da", false, "turn off the key's dictionary-attack protection")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	_, err := tpmkey.Generate(tpmkey.Device(tpmDevice), *out, *comment, *noDA)
	return err
}
