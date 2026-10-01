<p align="center"><img src="logo.png" alt="frisket" width="600"></p>

# frisket

An egress proxy that keeps credentials out of sandboxes. The sandbox holds a
placeholder; frisket swaps in the real token on the wire, checks each request
against your rules, and logs everything. Nothing in the sandbox is configured
to use it.

> A *frisket* is the mask on a printing press that covers the parts of the sheet
> which must not take ink. [flong](https://github.com/danielbodart/flong) casts
> the plate; frisket decides what the sheet is allowed to take.

frisket runs on the host, as the user whose credentials it holds. The kernel steers the sandbox's DNS and
connections to it (TPROXY, inside the sandbox's own network namespace), so
there are no proxy variables for a tool to ignore: a tool that skips frisket
has nowhere else to go. Names off the allowlist don't resolve. For the hosts
you route, frisket terminates TLS with a CA made for that sandbox, replaces
the placeholder with the real credential, and forwards the request only if
its method and path are allowed.

## Why frisket

| | frisket | [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) | [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) | [httpjail](https://github.com/coder/httpjail) | [tokenizer](https://github.com/superfly/tokenizer) | [smokescreen](https://github.com/stripe/smokescreen) |
|---|---|---|---|---|---|---|
| **Traffic reaches it** | Kernel steering, no proxy variables | Host proxy for a microVM | Proxy variables, enforced by the sandbox | Kernel steering on Linux, proxy variables on macOS | Proxy setting, plain HTTP | Proxy setting (CONNECT) |
| **Name allowlist** | ✓, others NXDOMAIN | ✓ | ✓ | Through its rules | Per secret | ✓ |
| **Credentials stay outside** | ✓ placeholder | ✓ sentinel | Claude Code's mask mode, Linux only | — | ✓ sent encrypted by the client | — |
| **Method and path rules** | ✓, plus git and GraphQL | — | — | ✓ scripted | — | — |
| **Ask a person per request** | ✓ | — | — | — | — | — |
| **Works with** | Any network namespace; flong module | Its own microVM | Its own sandbox | Its own jail | Anything | Anything |
| **Open source** | ✓ Go | — | ✓ TypeScript | ✓ Rust | ✓ Go | ✓ Go |
| **Platforms** | Linux | macOS, Windows, Linux | Linux, macOS | Linux, macOS | Any | Any |

— is not offered, or not documented as of 2026. GitHub Copilot's agent
firewall and Codex cloud's internet access have name allowlists, and
Codex's can limit methods; both are hosted only.

The difference that matters most is steering. Behind a proxy variable, a tool
that ignores it (a database driver, gRPC, a static Go binary) either gets out
around the proxy or doesn't work. frisket needs no setting in the tool, so
it works and is still filtered; the one thing a tool must trust is the CA, and
a missing CA fails loudly.

## Terms

- **sandbox**: a network namespace frisket serves, such as a flong container.
- **session**: one sandbox's time with frisket: its policy, its CA and its
  listeners, from launch to exit.
- **policy**: the names a sandbox may resolve, and its routes.
- **route**: a host frisket intercepts: where to send it, which credential to
  add, and which requests to allow, ask about or refuse.
- **placeholder**: what the sandbox sends where a credential goes, such as
  `proxy-injected`. Only an exact placeholder is replaced.

## Example

With [flong](https://github.com/danielbodart/flong):

```nix
{
  imports = [
    inputs.flong.nixosModules.default
    inputs.frisket.nixosModules.flong   # the daemon comes with it
  ];

  services.frisket = {
    user = "alice";                     # whose credentials it holds
    policies.research = {
      allow = [ "api.example.com" "*.pkg.example.org" ];
      routes.example = {
        host = "api.example.com";
        upstream = "https://api.example.com";
        credentialFile = "/run/secrets/example-token";
        placeholder = "proxy-injected";
        paths = [ { methods = [ "GET" "POST" ]; prefix = "/v1"; } ];
      };
    };
  };

  containers.agent = {
    privateNetwork = true;
    config = {
      system.stateVersion = "24.05";
      users.users.alice = { isNormalUser = true; uid = 1000; };
      environment.variables.SSL_CERT_FILE = "/etc/frisket/ca-bundle.crt";
    };
  };
  flong.agent = { user = "alice"; command = [ "codex" ]; };

  services.frisket.flong.agent.policy = "research";
}
```

In the `agent` container:

- `api.example.com` resolves to frisket. A `GET` or `POST` under `/v1`
  carrying `Bearer proxy-injected` goes upstream with `Bearer <token>` from
  the file. Anything else on that host is refused.
- `*.pkg.example.org` resolves normally and passes through untouched.
- Every other name is NXDOMAIN, and every address frisket didn't resolve is
  refused.

## How it works

- **DNS.** frisket answers every query. A route's host resolves to frisket; an
  allowed name resolves upstream; anything else is NXDOMAIN, never looked up.
- **Egress.** A connection is allowed only to an address frisket resolved for
  that sandbox. Loopback, private ranges, link-local, CGNAT, ULA and the
  host's own addresses are always refused, checked at connect time so DNS
  rebinding can't get round it.
- **Interception.** Each session gets its own CA, name-constrained to its
  routes' hosts, mounted read-only at `/etc/frisket` (`ca.crt`, and
  `ca-bundle.crt`, the system bundle plus the CA). The key never leaves the
  daemon. Point the sandbox's tools at the bundle with whichever of
  `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`… they read.
- **Logging.** One JSON line per connection, request and DNS query, refusals
  included.
- **Restarts.** Sessions survive a daemon restart. A changed policy restarts
  the daemon, so tightening a policy tightens running sandboxes.

### Modes

`services.frisket.flong.<launcher>.set`:

- **`all`** (default): the sandbox has no network of its own. All TCP and DNS
  go to frisket, other UDP is refused, and frisket is the only way out.
- **`service`**: the sandbox has its own network (flong's `network`). Only DNS
  and route hosts go through frisket; everything else goes direct. A policy
  that should resolve everything allows `*`.

## Routes

A route can do more than add a bearer token. Each is in
[docs/routes.md](docs/routes.md):

- **Credential files** as a bare token or a JSON field, with an expiry; re-read
  when replaced. Claude Code's and codex's own logins work as they are.
- **Rules** by method and path, with `allow`, `ask` or `refuse` for each.
- **Asking**: hold a request while a program you choose asks a person.
- **git**: fetch the repositories you list; push refused, asked or allowed.
- **GraphQL**: rules per mutation field, read from the request body.
- **Wildcard hosts**, such as `*.googleapis.com`.
- **Session keys**: a signing key made per session, for clients such as
  Google's that sign their own tokens.
- **Docker**: hold a sandbox to its own project's containers on your daemon. See
  [docs/docker.md](docs/docker.md).

## Options

| option | default | |
|---|---|---|
| `services.frisket.user` / `group` | `frisket` | Who the daemon runs as: the owner of the credential files. |
| `services.frisket.policies.<name>.allow` | `[ ]` | Names a sandbox may resolve: `name`, `*.name` (any depth below) or `*`. |
| `services.frisket.policies.<name>.routes.<route>` | `{ }` | An intercepted host: `host`, `upstream`, `credentialFile`, `placeholder`, `paths`, … See [docs/routes.md](docs/routes.md). |
| `services.frisket.asker` | `null` | The program a question goes to; `null` refuses every question. |
| `services.frisket.dns` | host's `resolv.conf` | Where frisket resolves allowed names. |
| `services.frisket.controlSocket` | `/run/frisket/control.sock` | The daemon's control socket; never bound into a sandbox. |
| `services.frisket.logLevel` | `info` | `debug` adds request headers and error bodies; credentials are described, never shown. |
| `services.frisket.maxSessions` | `256` | Sessions kept across a restart. |
| `services.frisket.maxConnections` | built in | Concurrent connections per session. |
| `services.frisket.flong.<launcher>.policy` | *required* | The launcher's policy. |
| `services.frisket.flong.<launcher>.policyFile` | `null` | A policy file of the launcher's own instead; `{machine}` in the path is the session's name. |
| `services.frisket.flong.<launcher>.set` | `all` | `all` or `service`. See [Modes](#modes). |
| `services.frisket.flong.<launcher>.params` | `{ }` | Recorded with each session, for a policy that reads them. |

Each policy is written to `/etc/frisket/policies/<name>.json` and checked with
`frisket check` when the system builds. Not using flong? See
[docs/launchers.md](docs/launchers.md). The design, and what was measured and
rejected, is in [PLAN.md](PLAN.md).

## Development

```console
$ nix develop          # go, gopls, golangci-lint
$ go test ./...
$ nix flake check      # build, tests with and without -race, lint, both
                       # rulesets through nft, and the flong VM test
```

## Licence

MIT.
