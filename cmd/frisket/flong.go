package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danielbodart/frisket/internal/control"
)

// FLONG'S HOOKS ARE ARGUMENT LISTS, NEVER SHELL. flong never parses a hook
// as shell: each is a list of words, which a hook program flong builds in the
// store execs as they are, having set what flong knows about the session in
// its environment -- $machine, $netns, $userns, $leader and $workspace in
// postStart, and $machine alone in postStop. So there is no shell to turn
// "$netns" into a flag's value, and -flong is how steer, connect and close
// are told to read those variables themselves. It is one explicit flag
// rather than a fallback for a flag left out: a hook that asks for flong's
// environment and does not get all of it fails the launch naming what is
// missing, and one that does not ask never reads it, so an unset -netns is
// never quietly a variable somebody happened to export.
//
// flong appends the launcher's own arguments after a postStart hook's words,
// which a hook must ignore; a postStop hook gets none. The adapter ends every
// argv with "--", so they are never read as flags whatever they look like,
// and -flong discards what follows it -- and only what follows it: a stray
// word before the "--" is a mistake in the hook, which would otherwise end
// the flags there and quietly drop the rest, so it is refused, as any
// argument is without -flong.

// The variables of flong's environment each step reads with -flong, in the
// order a missing one is reported: close runs in postStop, which has only
// $machine.
var (
	flongSteer   = []string{"machine", "netns", "userns", "leader", "workspace"}
	flongConnect = []string{"machine", "netns", "userns"}
	flongClose   = []string{"machine"}
)

// flongEnv reads the named variables from flong's environment, every one of
// which must be set and non-empty.
func flongEnv(getenv func(string) string, names []string) (map[string]string, error) {
	env := make(map[string]string, len(names))
	var missing []string
	for _, n := range names {
		v := getenv(n)
		if v == "" {
			missing = append(missing, "$"+n)
			continue
		}
		env[n] = v
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("-flong: flong's environment has no %s: is this a flong hook?", strings.Join(missing, ", "))
	}
	return env, nil
}

// refuseWithFlong refuses a flag that -flong supplies from the environment,
// so the two never disagree about which session a step is for.
func refuseWithFlong(fs *flag.FlagSet, names ...string) error {
	var given []string
	fs.Visit(func(f *flag.Flag) {
		for _, n := range names {
			if f.Name == n {
				given = append(given, "-"+n)
			}
		}
	})
	if len(given) > 0 {
		return fmt.Errorf("-flong reads %s from flong's environment; do not give %s as well", strings.Join(names, ", "), strings.Join(given, ", "))
	}
	return nil
}

// refuseArgs refuses arguments left after the flags, unless -flong says
// they are the launcher's and a "--" ended the flags before them. The flag
// package stops at the first word that is not a flag, so without that "--"
// what is left is a stray word and every flag after it, never the
// launcher's.
func refuseArgs(fs *flag.FlagSet, argv []string, flong bool) error {
	n := fs.NArg()
	if n == 0 || flong && argv[len(argv)-n-1] == "--" {
		return nil
	}
	return fmt.Errorf("unexpected argument %q", fs.Arg(0))
}

// leaderMntns is the mount namespace of flong's $leader, the session's
// first process, where steer puts the session's CA. $leader must be a pid,
// in the one form the kernel writes it, so it is never a way to name
// another /proc entry: /proc/self, the hook's own host namespace, say.
func leaderMntns(leader string) (string, error) {
	pid, err := strconv.Atoi(leader)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != leader {
		return "", fmt.Errorf("-flong: $leader %q is not a pid", leader)
	}
	return "/proc/" + leader + "/ns/mnt", nil
}

// machineToken is the one thing special in a policy path: the session's name.
const machineToken = "{machine}"

// expandPolicy makes a session's policy path from a template, where
// {machine} stands for the session's name and nothing else is special: a
// launcher that writes a document per session names where it will be, and
// frisket, which has the name, says which one. A template may hold at most
// one {machine}, and no other brace, so a path is never half a template; one
// with none is the path itself. The name is a session name, which is never
// a path separator nor "..", and the result must still be the absolute,
// clean path the daemon asks for.
func expandPolicy(template, name string) (string, error) {
	if !filepath.IsAbs(template) {
		return "", fmt.Errorf("-policy %q: want an absolute path", template)
	}
	if strings.Count(template, machineToken) > 1 {
		return "", fmt.Errorf("-policy %q: %s at most once", template, machineToken)
	}
	if strings.ContainsAny(strings.Replace(template, machineToken, "", 1), "{}") {
		return "", fmt.Errorf("-policy %q: a brace that is not %s", template, machineToken)
	}
	if strings.Contains(template, machineToken) {
		if err := control.ValidName(name); err != nil {
			return "", fmt.Errorf("-policy %q: session %w", template, err)
		}
	}
	path := strings.Replace(template, machineToken, name, 1)
	if err := control.ValidPolicyPath(path); err != nil {
		return "", fmt.Errorf("-policy %q: %w", template, err)
	}
	return path, nil
}
