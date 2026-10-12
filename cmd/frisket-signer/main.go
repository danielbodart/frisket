// Command frisket-signer holds the SSH keys that live in the TPM, signs
// silently for frisket, for a terminal tab ssh-ing to a known host, for any
// process's direct login to a host allowed by name and for listed SSHSIG
// namespaces, and asks through galley for everything else.
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

  frisket-signer serve [-config FILE]
        Serve the agent socket systemd passes as the fd named agent, to
        forUser's uid only, with the keys in ` + keyDir + `, under the
        settings in FILE (default ` + defaultConfig + `).

  frisket-signer check FILE
        Read FILE as serve would, and say what is wrong with it.

  frisket-signer schema
        Print the config file's JSON Schema.

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
	case "check":
		err = runCheck(args)
	case "schema":
		fmt.Fprint(os.Stdout, schema)
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

func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", defaultConfig, "the settings file")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	u, err := user.Lookup(cfg.ForUser)
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
		User: cfg.ForUser, UID: uid, Terminal: cfg.Terminal, SSHSIG: cfg.SSHSIG, Hosts: cfg.SSH.Hosts,
		KnownHosts: knownHosts, Grants: grant.New(), Log: log,
	}
	if p := cfg.Policy; p != nil {
		s.Policy = &agentsrv.Policy{Courier: p.Courier, AllowedSigners: p.AllowedSigners, FileName: p.FileName, Home: u.HomeDir}
	}
	for _, k := range loaded {
		s.Keys = append(s.Keys, agentsrv.Key{Signer: k.Signer(tpm), Comment: k.Comment})
	}
	if n := sdnotify.FromEnv(); n != nil {
		if err := n.Ready(fmt.Sprintf("%d keys", len(s.Keys))); err != nil {
			return err
		}
	}
	log.Info("frisket-signer serve", "config", *path, "user", cfg.ForUser, "keys", len(s.Keys),
		"terminal", cfg.Terminal, "sshsig", cfg.SSHSIG, "hosts", cfg.SSH.Hosts, "policy", cfg.Policy)
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

func runCheck(argv []string) error {
	if len(argv) != 1 {
		return errors.New("name one config file")
	}
	_, err := loadConfig(argv[0])
	return err
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
