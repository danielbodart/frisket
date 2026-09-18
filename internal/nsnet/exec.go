package nsnet

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

// RunExec is `frisket nsexec -net PATH -- PROGRAM ARGS...`: enter a network
// namespace and become PROGRAM there. It is how `frisket steer` runs nft and ip
// inside a sandbox without depending on util-linux's nsenter being on the PATH
// of whatever launched it.
//
// A process of its own, for the reason RunHelper is one: setns moves a single
// thread, and the Go runtime schedules goroutines onto whichever thread it
// likes. Measured, an in-process setns followed by an unlock sent 13 of 200 of
// frisket's own connections out through the sandbox. Here the thread that did
// the setns is the thread that execs, and execve discards every other thread,
// so the program starts wholly inside the namespace and nothing of ours is left
// behind in it.
func RunExec(argv []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("nsexec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	netns := fs.String("net", "", "path to the network namespace to enter")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	rest := fs.Args()
	if *netns == "" {
		// Running the program here instead would load a sandbox's ruleset into
		// the host. Refused rather than defaulted.
		return errors.New("nsexec: no namespace given")
	}
	if len(rest) == 0 {
		return errors.New("nsexec: no program given")
	}
	// Resolved by the caller, on the host, BEFORE the namespace changes -- a
	// PATH search is a filesystem walk, and a relative name here would be a
	// question about the caller's PATH answered in another process.
	if !filepath.IsAbs(rest[0]) {
		return fmt.Errorf("nsexec: %q is not an absolute path", rest[0])
	}

	// LOCKED AND NEVER UNLOCKED: exec is the only way out of this thread.
	runtime.LockOSThread()
	if err := enterNetns(*netns); err != nil {
		return err
	}
	return syscall.Exec(rest[0], rest, os.Environ())
}

// Command builds a command that runs program inside the namespace at netns, by
// re-running this executable as the nsexec verb. program is resolved against
// this process's PATH first, so the answer is the host's.
func Command(ctx context.Context, h Helper, netns, program string, args ...string) (*exec.Cmd, error) {
	if netns == "" {
		return nil, errors.New("no namespace to run in")
	}
	path, err := exec.LookPath(program)
	if err != nil {
		return nil, fmt.Errorf("finding %s: %w", program, err)
	}
	if path, err = filepath.Abs(path); err != nil {
		return nil, err
	}
	exe := h.Exe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("finding this executable to re-run as nsexec: %w", err)
		}
	}
	verb := h.ExecVerb
	if verb == "" {
		verb = "nsexec"
	}
	argv := append([]string{verb, "-net", netns, "--", path}, args...)
	return exec.CommandContext(ctx, exe, argv...), nil
}
