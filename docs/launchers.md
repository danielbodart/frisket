# Other launchers

frisket ships a NixOS module for [flong](https://github.com/danielbodart/flong).
Any launcher that gives a sandbox its own network namespace and a hook before
it has egress can use it the same way.

Run as the daemon's user, in this order, from a hook that has the sandbox's
network namespace before anything gives it egress. `$userns` is the user
namespace that owns the sandbox's; each step enters it once, under that
`nsenter`, since a Go program cannot join a user namespace itself. Root, with
no user namespace to join, leaves out `-userns` and `-nsenter` -- but the
control socket answers only the daemon's user.

```console
$ frisket steer   -userns $userns -nsenter /path/to/nsenter \
                  -netns $netns -mntns /proc/$leader/ns/mnt \
                  -roots /etc/ssl/certs/ca-certificates.crt \
                  -steering $file -name $session -policy /etc/frisket/policies/research.json
$ frisket connect -userns $userns -nsenter /path/to/nsenter \
                  -netns $netns -steering $file -name $session
$ frisket close   -name $session
```

`-policy` takes the same `{machine}` a `policyFile` does. A launcher whose
hooks are argument lists never parsed as shell, as flong's are, gives each
step `-flong` instead of the flags its environment answers -- `$machine`,
`$netns`, `$userns`, `$leader` and `$workspace` -- and ends it with `--`,
after which the launcher's own arguments are ignored. A variable that is
missing fails the step, naming it, and so does a word before the `--`.

The adapter names frisket, nsenter and nft by store path and puts nothing on
its hooks' PATH, so a rules hook of your own names its tools the same way.

`$file` is `(frisket.lib.steering { set = "all"; }).json`: the ruleset and the
listener specification from one attrset. `frisket steering $file` prints what
it will do. `steer` creates the listeners inside the namespace, installs the
routing and the ruleset, and mounts the session's CA at `/etc/frisket`;
`connect` gives the namespace its egress. Each refuses to run out of turn.
Point the sandbox's runtimes at `/etc/frisket/ca-bundle.crt`.
