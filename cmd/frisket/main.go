// Command frisket keeps credentials out of sandboxes.
//
// This is build step 0: the privileged helper that creates a session's
// listeners inside a sandbox's network namespace, and the holder that accepts
// on them from the host and logs one line per connection. There is no egress,
// no DNS, no interception and no credential here yet -- see PLAN.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/nsnet"
	"github.com/danielbodart/frisket/internal/steer"
)

// version is stamped at build time. scripts/version.sh derives the real one
// from the repository; a build without it says so rather than claiming a number.
var version = "dev"

const usage = `frisket -- credentials on the wire, never in the sandbox

  frisket hold  -net <path> -spec <specs> [-session <id>]
        Create the listeners inside the network namespace at <path>, hold them
        from here, and log one line per connection. The walking skeleton's
        stand-in for "frisket serve" until the control socket exists.

  frisket helper -net <path> -spec <specs>
        The privileged half. Not run by hand: "hold" re-runs this binary as the
        helper, which enters the namespace, creates the listeners and passes
        them back over fd 3.

  frisket version

A spec is net:addr:port -- tcp4:127.0.0.1:15001, udp6:[::1]:15353 -- and
several are separated by commas.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "helper":
		err = nsnet.RunHelper(os.Args[2:], os.Stderr)
	case "hold":
		err = hold(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "frisket: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "frisket: %v\n", err)
		os.Exit(1)
	}
}

func hold(argv []string) error {
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	netns := fs.String("net", "", "path to the sandbox's network namespace; empty holds listeners in this one")
	specs := fs.String("spec", "", "comma-separated listeners to create in it")
	session := fs.String("session", "", "session id for the log; defaults to the namespace inode")
	loTimeout := fs.Duration("lo-timeout", nsnet.DefaultLoopbackTimeout, "how long to wait for lo to come up in there")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	parsed, err := nsnet.ParseSpecs(*specs)
	if err != nil {
		return err
	}

	// SIGINT/SIGTERM cancels, and cancelling closes every descriptor. That is
	// not tidiness: a held listener pins the sandbox's network namespace and
	// the user namespace that owns it, and nothing else has a handle on them.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	set, err := nsnet.Open(ctx, nsnet.Helper{}, nsnet.HelperArgs{
		Netns:     *netns,
		Specs:     parsed,
		LoTimeout: *loTimeout,
	})
	if err != nil {
		return err
	}
	defer set.Close()

	id := *session
	if id == "" {
		id = set.Netns
	}
	s := steer.New(id, os.Stderr)
	s.Log.Info("session",
		"session", id,
		"netns", set.Netns,
		"helper_pid", set.HelperPID,
		"listeners", len(set.Socks),
		"version", version,
	)

	var wg sync.WaitGroup
	for _, sock := range set.Socks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if sock.Listener != nil {
				err = s.Serve(ctx, sock.Listener, steer.HandlerFunc(announce))
			} else {
				err = s.ServePacket(ctx, sock.Packet, nil)
			}
			if err != nil {
				s.Log.Error("listener stopped", "session", id, "listener", sock.Spec.String(), "error", err.Error())
			}
		}()
	}
	wg.Wait()
	return nil
}

// announce is the placeholder for everything steps 1 to 3 add. It says where
// the connection was going and closes: there is no egress yet, and a connection
// that hung instead of closing would look like a working proxy.
func announce(_ context.Context, c *steer.Conn) {
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "frisket %s: steered to %s, and no egress until build step 1\n", version, c.Orig)
}
