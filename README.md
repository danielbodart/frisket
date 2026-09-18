# frisket

> A *frisket* is the mask on a printing press that covers the parts of the sheet
> which must not take ink. [flong](https://github.com/danielbodart/flong) casts
> the plate; frisket decides what the sheet is allowed to take.

frisket keeps credentials out of sandboxes. It runs on the host, holds the
tokens, and is where a sandbox's credentials come from — added to requests on
the wire, where the sandbox cannot reach them. For a sandbox with no network of
its own it is also the only way out, and every connection it sees is logged.

Nothing in a sandbox is configured to use it. The kernel steers connections to
it: no proxy variables, no hosts file, no per-tool settings for egress. The one
thing a sandbox is told is which certificate authority to trust.

**[PLAN.md](PLAN.md) is the design**, including what was measured, what was
rejected and why, and the build order. Read it first.

## Status

Build step 0 of that order, and only the half that needs nothing from flong:
the namespace-socket core. There is no egress, no DNS, no interception, no
credential and no NixOS module yet.

What works today:

- **`frisket helper`** — the privileged half. It enters a network namespace,
  waits for `lo`, creates the session's listeners *in there*, and passes the
  descriptors back over `SCM_RIGHTS` with a manifest. It is a forked process
  rather than a goroutine on purpose: measured, doing the `setns` in-process and
  then unlocking the thread let the Go runtime schedule ordinary goroutines onto
  a thread still inside the sandbox, and 13 of 200 of frisket's own upstream
  connections left through the sandbox's network.
- **`frisket hold`** — the holder. It runs the helper, adopts the descriptors,
  accepts on them from the host, reads each connection's original destination
  from the kernel's conntrack entry, and logs one line per connection. A
  connection the kernel did not steer — the lookup failed, or the destination is
  the listener's own address — is refused. This is the stand-in for
  `frisket serve` until the control socket exists.

```console
$ sudo frisket hold -net /proc/1234/ns/net -spec tcp4:127.0.0.1:15001,tcp6:[::1]:15001,udp4:127.0.0.1:15353
{"time":"...","level":"INFO","msg":"session","session":"net:[4026533500]","netns":"net:[4026533500]","helper_pid":9123,"listeners":3}
{"time":"...","level":"INFO","msg":"connection","session":"net:[4026533500]","conn":1,"listener":"127.0.0.1:15001","peer":"127.0.0.1:41234","dst":"140.82.121.3:443","decision":"steered","action":"accepted"}
```

## Working on it

```console
$ nix develop          # go, gopls, golangci-lint
$ nix flake check      # the build, the tests, gofmt, go vet, shellcheck
$ nix run . -- version
```

The tests create user and network namespaces with clone flags rather than the
`unshare` binary, and skip where the kernel refuses, so `nix flake check` passes
inside the Nix sandbox. They assert on log output through an injected writer: a
logger that silences itself under test cannot be tested, and then "exactly one
line per connection" is a hope.

## Licence

MIT.
