// Command frisket-policy is the policy courier: it runs as the user, with no
// network, and carries a project's signed policy file between the user's
// home and the system units that verify it, the signer and the sudo gate,
// which cannot read the home themselves.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/projpolicy"
)

const defaultSocket = "/run/frisket-policy/sock"

const usage = `frisket-policy -- a project's signed policy file, carried from the user's home

  frisket-policy serve [-config FILE]
        Serve the socket systemd passes as the fd named courier, as the user
        whose projects they are, to the units FILE's peers name, each as its
        user, under the settings in FILE (default ` + defaultConfig + `).

  frisket-policy check FILE
        Read FILE as serve would, and say what is wrong with it.

  frisket-policy schema
        Print the config file's JSON Schema.

  frisket-policy read [-socket PATH] PID [START]
        Ask the courier for the policy file above PID's working directory,
        START being PID's start time (default: read from /proc now), and
        print its answer as JSON.

  frisket-policy write [-socket PATH] -root DIR -old DIGEST -file POLICY -sig SIG
        Ask the courier to replace DIR's policy file with POLICY and SIG,
        if it is still the one DIGEST names ("" for none).
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
	case "check":
		err = runCheck(args)
	case "schema":
		fmt.Fprint(os.Stdout, schema)
	case "read":
		err = runRead(args, os.Stdout)
	case "write":
		err = runWrite(args, os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "frisket-policy: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "frisket-policy %s: %v\n", os.Args[1], err)
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
	me, err := user.Current()
	if err != nil {
		return err
	}
	if os.Getuid() == 0 {
		return errors.New("the courier runs as the user whose projects it reads, never as root")
	}
	peers := map[string]int{}
	for unit, name := range cfg.Peers {
		u, err := user.Lookup(name)
		if err != nil {
			return fmt.Errorf("peers.%s: %w", unit, err)
		}
		if peers[unit], err = strconv.Atoi(u.Uid); err != nil {
			return err
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	stdlog.SetOutput(io.Discard)

	ln, err := listener()
	if err != nil {
		return err
	}
	s := &courier.Server{
		Name: cfg.FileName, Home: me.HomeDir, UID: os.Getuid(), Peers: peers, Log: log,
		Signers: func() (*projpolicy.AllowedSigners, error) { return projpolicy.ReadAllowedSigners(cfg.AllowedSigners) },
	}
	if n := sdnotify.FromEnv(); n != nil {
		if err := n.Ready(fmt.Sprintf("%d peers", len(peers))); err != nil {
			return err
		}
	}
	log.Info("frisket-policy serve", "config", *path, "user", me.Username, "home", me.HomeDir,
		"fileName", cfg.FileName, "allowedSigners", cfg.AllowedSigners, "peers", cfg.Peers)
	return s.Serve(ln)
}

func listener() (*net.UnixListener, error) {
	fds, err := sdnotify.Listen()
	if err != nil {
		return nil, err
	}
	for _, fd := range fds {
		if fd.Name != "courier" {
			continue
		}
		ln, err := net.FileListener(fd.File)
		_ = fd.File.Close()
		if err != nil {
			return nil, fmt.Errorf("the courier socket systemd passed: %w", err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			return nil, fmt.Errorf("the courier socket systemd passed is a %T", ln)
		}
		return ul, nil
	}
	return nil, errors.New("systemd passed no socket named courier")
}

func runCheck(argv []string) error {
	if len(argv) != 1 {
		return errors.New("name one config file")
	}
	_, err := loadConfig(argv[0])
	return err
}

func runRead(argv []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket, "the courier's socket")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("name a pid, and optionally its start time")
	}
	pid, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		return err
	}
	var start uint64
	if fs.NArg() == 2 {
		start, err = strconv.ParseUint(fs.Arg(1), 10, 64)
	} else {
		start, err = startOf(pid)
	}
	if err != nil {
		return err
	}
	resp, err := courier.Read(context.Background(), *socket, pid, start)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(resp)
}

func runWrite(argv []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket, "the courier's socket")
	root := fs.String("root", "", "the project's directory")
	old := fs.String("old", "", "the digest of the file replaced, empty for none")
	file := fs.String("file", "", "the new policy file")
	sigFile := fs.String("sig", "", "its signature")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *root == "" || *file == "" || *sigFile == "" || fs.NArg() > 0 {
		return errors.New("-root, -file and -sig are required, and nothing else")
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*sigFile)
	if err != nil {
		return err
	}
	resp, err := courier.Write(context.Background(), *socket, *root, *old, b, sig)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(resp)
}

// startOf is pid's start time, field 22 of /proc/<pid>/stat.
func startOf(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat: %d fields", pid, len(f))
	}
	return strconv.ParseUint(f[19], 10, 64)
}
