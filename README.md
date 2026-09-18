<p align="center"><img src="logo.png" alt="flong" width="600"></p>

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

## Usage

With [flong](https://github.com/danielbodart/flong), steering a launcher's
sessions is one line beside it:

```nix
{
  imports = [
    inputs.flong.nixosModules.default
    inputs.frisket.nixosModules.flong   # the daemon comes with it
  ];

  services.frisket.user = "alice";      # whose credentials it holds

  containers.agent.privateNetwork = true;
  flong.agent = { user = "alice"; command = ''set -- "$@"''; };

  services.frisket.flong.agent = {
    policy = "standin";
    set = "all";                        # or "service", with flong's `network`
  };
}
```

Every session `flong.agent` starts is steered before it has any egress: root's
hook creates frisket's listeners inside the session's namespace and hands them
to the daemon, installs the policy routing and the ruleset that steer to them
(TPROXY), and only then gives the namespace connectivity. The session is closed when it ends, by its own
trap or by the next launch's sweep.

Any other launcher uses the same three commands, run as root, in this order:

```console
# frisket steer   -netns /proc/$leader/ns/net -steering $file -name $session -policy standin
# frisket connect -netns /proc/$leader/ns/net -steering $file -name $session
# frisket close   -name $session
```

`$file` is `(frisket.lib.steering { set = "all"; }).json`, written to the
store: the ruleset and the listener specification from one attrset, so their
ports cannot drift apart. `frisket steering $file` says what it will do. Each
step refuses to run out of turn.

### Options

| option | default | |
|---|---|---|
| `services.frisket.user` / `group` | `frisket` | who the daemon runs as: the owner of the credentials, never a DynamicUser |
| `services.frisket.controlSocket` | `/run/frisket/control.sock` | root-only; never bound into a sandbox |
| `services.frisket.maxSessions` | `256` | sizes the fd store that keeps sessions across a restart |
| `services.frisket.flong.<launcher>.policy` | *required* | what the daemon does with the session's connections |
| `services.frisket.flong.<launcher>.set` | `all` | `all`: everything steered, no network of its own; `service`: DNS and frisket's service address, with flong's `network` |
| `services.frisket.flong.<launcher>.params` | `{ }` | the policy's parameters; `workspace` is always passed |

## Status

Build step 0 of [PLAN.md](PLAN.md), with the integration it needs: steering,
the daemon, sessions that survive a restart, and the flong adapter, tested end
to end in a VM. There is no egress policy, no DNS, no interception and no
credential yet. The one policy, `standin`, splices every connection to where it
was going and logs it, and refuses interception and DNS.

## Working on it

```console
$ nix develop                       # go, gopls, golangci-lint
$ go test ./...
$ CGO_ENABLED=1 go test -race ./... # the shell builds static, as the flake does
$ nix flake check                   # the build, the tests with and without -race,
                                    # gofmt, go vet, shellcheck, both rulesets
                                    # through nft, and the flong VM test
$ nix run . -- version
```

The tests create user and network namespaces with clone flags rather than the
`unshare` binary, and skip where the kernel refuses, so `nix flake check` passes
inside the Nix sandbox. They assert on log output through an injected writer: a
logger that silences itself under test cannot be tested, and then "exactly one
line per connection" is a hope.

## Licence

MIT.
