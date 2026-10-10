// Command frisket-sudo is the gate frisket-sudo's plugin asks about each
// no-tty sudo: one galley item per command, and each claude's password
// window.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/internal/sudogate"
)

const usage = `frisket-sudo -- the gate for sudo with no terminal, asked through galley

  frisket-sudo serve -user NAME
        Serve the gate socket systemd passes as the fd named gate, asking
        NAME through galley.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "frisket-sudo: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "frisket-sudo %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	name := fs.String("user", "", "the gated user, and the galley user asked")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-user is required")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)

	ln, err := gateListener()
	if err != nil {
		return err
	}
	if n := sdnotify.FromEnv(); n != nil {
		if err := n.Ready("serving"); err != nil {
			return err
		}
	}
	log.Info("frisket-sudo serve", "user", *name)
	return (&sudogate.Gate{User: *name, Log: log}).Serve(ln)
}

func gateListener() (*net.UnixListener, error) {
	fds, err := sdnotify.Listen()
	if err != nil {
		return nil, err
	}
	for _, fd := range fds {
		if fd.Name != "gate" {
			continue
		}
		ln, err := net.FileListener(fd.File)
		_ = fd.File.Close()
		if err != nil {
			return nil, fmt.Errorf("the gate socket systemd passed: %w", err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			return nil, fmt.Errorf("the gate socket systemd passed is a %T", ln)
		}
		return ul, nil
	}
	return nil, errors.New("systemd passed no socket named gate")
}
