# frisket — plan

> A *frisket* is the mask on a printing press that covers the parts of the sheet
> which must not take ink. flong casts the plate; frisket decides what the sheet
> is allowed to take.

frisket keeps credentials out of sandboxes. It runs on the host, holds the
tokens, and is where a sandbox's credentials come from — injected into requests
it can read, or minted short-lived where it cannot. For a sandbox with no
network of its own it is also the only way out, and every connection it sees is
logged.

Nothing in a sandbox is configured to use it. The kernel steers connections to
it: no proxy variables, no hosts file, no per-tool settings for egress.

Its first consumer is the agent containers in
[nix-config](https://github.com/danielbodart/nix-config), which run Claude Code
and codex inside [flong](https://github.com/danielbodart/flong). frisket itself
knows nothing about nspawn, flong or agents.

Status: planning. Nothing is built.

---

## Locked decisions

**1. Go for everything, including the spike.** Standard library only, so
`vendorHash = null` and there is no dependency to bump; `CGO_ENABLED = 0`, so
the binary is static. What it needs is all in stdlib: `httputil.ReverseProxy`
for credential routes (`Rewrite` to inject, `FlushInterval` for SSE), `net` and
`io.Copy` for egress (splice on Linux), a TLS client with HTTP/2, and
`crypto/rsa` for RS256 JWTs. The deciding factor over Zig and Bun was not speed
— the upstream round trip dominates in all three — but that this process parses
hostile input while holding every token, so memory safety and a hardened
parser matter most.

**2. One unix socket per session is how every sandbox reaches frisket.**
Whatever network the sandbox has, frisket traffic never crosses it. The socket
is bound into that sandbox alone, and it is the capability: nothing inside the
sandbox — relay, rules, configuration — needs to be trusted.

**3. Steering, not proxy configuration.** Root installs nftables rules inside
the sandbox's own network namespace before the workload starts, and the
workload's user has no `CAP_NET_ADMIN` to change them. Matching connections are
redirected to an in-sandbox relay, which prefixes each one with where it was
going (PROXY protocol v2, from `SO_ORIGINAL_DST`) and hands it to the socket.
frisket routes by that original destination. Nothing guesses a protocol.

A tool that ignores proxy settings is not a special case: it is steered like
everything else, and appears in the log whether it is allowed or refused.

**4. Three layers, each ignorant of the next.**

- **flong** gives a sandbox a network — `host`, `pasta` or `none` — and three
  generic hooks. It knows nothing about frisket.
- **frisket** is the daemon, the relay, and steering expressed as data. It
  knows nothing about launchers: anything offering the same hooks can use it.
- **The adapter** maps frisket's steering data onto flong's hooks. About a dozen
  lines of Nix; it lives in nix-config until it settles, then ships as
  `frisket.nixosModules.flong`, an optional integration.

Agent policy — tiers, trusted checkouts, workspace groups, the agent wrappers —
is a fourth thing and stays in nix-config. If it is ever extracted, it is the
natural home for the adapter, and the printing name for it is **chase**: the
frame that locks the type together so the page can be printed.

**5. Authorise by socket, never by peer uid.** Without a uid namespace every
process on both sides is the same uid, so `SO_PEERCRED` says nothing. A
session's identity and policy are fixed when its socket is created.

**6. Separate repository from day one.** nix-config declares
`github:danielbodart/frisket` and builds locally with
`--override-input frisket path:/home/dan/Projects/frisket` (explicitly `path:`,
so untracked files are included). The override is never written to
`flake.lock`, so no local path can be committed. Push frisket first, then
`nix flake update frisket` in nix-config.

---

## Considered and rejected

Recorded so they are not re-proposed without new information.

- **Proxy environment variables, `/etc/hosts` and low ports.** The earlier
  design. Every tool needed configuring, with quirks (curl honours only
  lowercase `http_proxy`; `no_proxy` had to exclude the relay or frisket
  refused its own base URLs; Node's `fetch` ignores the variables by default),
  and a tool that ignored them failed silently with no log line. Steering
  removes all of it.
- **One port, protocol sniffing.** Routing by the first byte of a connection.
  Rejected as dishonest; routing is by original destination.
- **A veth pair.** On the first host it would have exposed sshd on every
  address (including three global IPv6 ones), met `ip_forward = 1` from docker,
  and needed the sandbox side configured with no init to do it.
- **`host` network mode for a frisket sandbox.** A shared namespace cannot carry
  per-sandbox nftables rules, so steering is impossible. It also shares the
  host's loopback, port space, and abstract unix sockets — on the first host
  that includes Xwayland's X11 sockets.
- **SOCKS.** Database drivers and gRPC do not speak it, and LD_PRELOAD shims
  miss Go binaries, which make their own syscalls.
- **TLS interception.** Not needed: credentials go to plain-HTTP routes, and
  `gh`, the one tool without a base-URL hook, is minted a token instead.
- **Zig and Bun.** See decision 1. Zig's std has, to our knowledge, no RSA
  signing and no use-after-free protection; Bun's HTTP servers cannot do
  CONNECT and it parses hostile input in younger native code.

---

## What it is protecting

nix-config's two tiers are one mechanism with three settings:

| | trusted | strict (research on someone else's code) |
|---|---|---|
| Goal | credentials never leak | the same, and nothing local is reachable |
| flong network mode | `pasta` — internet, LAN, listed host ports | `none` — loopback only |
| Redirect set | `service` — only frisket's address | `all` — every connection, and DNS |
| frisket policy | allow all; full credentials | public hosts only; model-API credentials only |
| Workspace | read-write | read-only overlay, writes discarded |
| Agent state | shared | vanilla agents; only this project's transcripts persist |

Keeping credentials out does not depend on the network. Long-lived secrets never
enter; minted ones are short-lived whatever the network. So trusted gets a real
network stack — databases, gRPC and emulators just work — and the private
namespace is there to close the host's loopback and abstract sockets and to
make steering possible, not to filter.

For strict, nothing in the sandbox is worth stealing. What `all` still keeps
out is the host's loopback, the LAN, and the host's own addresses.

---

## Architecture

```
flong      gives the sandbox a network:       host | pasta | none
             (generic; knows nothing about frisket)

steering   installed by root at launch, inside the sandbox's namespace:
             nftables redirects the chosen set → relay → frisket socket
             each connection prefixed with its original destination (PROXY v2)

frisket    on the host, one socket per session; routes by original destination:
             • frisket's service address → its own services
                 HTTP: credential routes, GCP metadata, minting
                 DNS:  resolved on the host, logged
             • anything else               → egress
                 policy by address, named where possible, logged,
                 then an opaque splice to the original destination
```

```
host                                         sandbox network namespace
────                                         ─────────────────────────
frisket serve                                nftables (root, before the workload)
  control.sock ◄── adapter: new session        redirect set ──► relay
  sessions/<id>/
    frisket.sock ◄───── bind-mounted ──────► frisket relay -- <workload>
    tokens/                                    TCP listener ─┐
                                               DNS listener ─┴─► frisket.sock
```

### Components

**`frisket serve`** — the host daemon. A control socket creates a session with a
named policy and returns its directory, which is what gets bound into the
sandbox. Sessions whose sandbox has gone are collected.

**`frisket relay -- <command>`** — starts its listeners, then the workload. For
each connection it reads `SO_ORIGINAL_DST`, writes a PROXY v2 header, and
copies bytes; DNS is forwarded in its TCP form (RFC 7766). It parses nothing
else, and its integrity does not matter — killing it and listening instead
reaches the same socket.

**`frisket mint <service>`** — a client for minting that talks to the socket
directly, so the sandbox needs no curl.

**Steering data** — for a redirect set, frisket produces what a launcher needs:
an nftables ruleset, a `resolv.conf` (for `all`), and the relay wrapper. Pure
data, no launcher knowledge.

### Redirect sets

- **`all`** — for a sandbox with no network. Every non-loopback TCP connection
  and all DNS go to the relay; other UDP is dropped, so QUIC falls back to TCP.
  The namespace also gets a dummy interface with a default route: without a
  route, `connect()` fails before nftables ever sees the packet.
- **`service`** — for a sandbox with its own network. Only frisket's service
  address is redirected; everything else goes direct.

### frisket's service address

One address inside the sandbox where frisket's own services live: HTTP on 80
(credential routes, metadata, minting) and DNS on 53. The relay listens on high
ports and nftables sends traffic to it, so nothing binds a privileged port. See
open question 3 for the choice of address.

### Egress policy

- **Public:** refuse loopback, RFC 1918, link-local, CGNAT, ULA — and every
  address the host itself owns, not just private ranges. Checked in
  `net.Dialer.Control` against the address actually being dialled, so DNS
  rebinding cannot slip past.
- **Allowlist:** enforced at frisket's DNS. A name that is not allowed is
  refused without an upstream lookup, so it cannot leak through DNS; a
  connection is accepted only to an address frisket resolved for an allowed
  name in that session.
- **Names** come from frisket's own DNS answers to that session, with SNI or
  `Host` as a label where present, and the bare address otherwise. Policy never
  depends on guessing a protocol. frisket never terminates TLS.
- **Log:** one JSON line per connection and per DNS query — session, policy,
  destination, name, bytes, decision.

### Credentials

- **Routes** — long-lived secrets never enter the sandbox. The tool's base URL
  points at frisket's service address; frisket strips the placeholder and
  injects the real credential, upstream over HTTPS.
- **GCP metadata server** — the GCE metadata endpoints
  (`/computeMetadata/v1/instance/service-accounts/default/token`, project ID,
  account email) on the service address, answering with
  `Metadata-Flavor: Google`. Google's auth libraries for Go, Python, Node and
  Java find it through `GCE_METADATA_HOST`, so Spanner, BigQuery and Pub/Sub work
  unchanged with 1h tokens and no key file in the sandbox.
- **Minting** — where neither works, a short-lived, narrowly scoped token is
  handed over on demand. It does enter the sandbox; its lifetime and scope are
  the protection.

Credentialed routes are also write channels *as you*: a GitHub credential on
`api.github.com` lets a session create gists. So policy decides which routes
carry credentials, not just which destinations are reachable. Research on
public code needs none for GitHub or Hugging Face.

---

## Per-tool routes

`<frisket>` is the service address.

| Tool | Ideal: never sees a token | Fallback: short-lived, minted |
|---|---|---|
| git push | `url."http://<frisket>/github/".insteadOf = "git@github.com:"`, path-scoped to the session's repo | `credential.helper` → 1h GitHub App installation token |
| gh | — (no plain-HTTP base URL) | **wrapper runs `frisket mint github` at exec → `GH_TOKEN`**, 1h, repo-scoped |
| Claude Code | `ANTHROPIC_BASE_URL` → frisket, placeholder `ANTHROPIC_AUTH_TOKEN` | `apiKeyHelper` → current access token; refresh token stays on the host |
| codex | `model_providers` `base_url` + placeholder `env_key` | none clean — the ChatGPT access token lives ~6 days |
| hf | `HF_ENDPOINT` → frisket; CDN/Xet downloads are ordinary egress | not needed |
| Cloudflare | `CLOUDFLARE_API_BASE_URL` → frisket, placeholder `CLOUDFLARE_API_TOKEN` | child API token with `expires_on` |
| Spanner, BigQuery, Pub/Sub (client libraries) | **GCP metadata server** — the token is minted, but fetched the way GCP workloads always fetch it | — |
| gcloud CLI | — | `auth/access_token_file` → `tokens/gcloud`, unless it honours the metadata server (open question 4) |
| Postgres, Redis, MongoDB (local, in Docker) | no frisket involvement — trusted reaches them through pasta's forwarded host ports; strict cannot | — |
| npm, PyPI, crates, Go proxy | no credential — egress policy only | — |

Notes:

- The agent rows depend on phase 0. Both are simple with API keys; subscription
  auth through a base URL is unverified, and codex custom providers may be
  API-key shaped, which would mean API billing.
- gh installation tokens cover repos, PRs, issues and Actions, not user-scoped
  endpoints (gists, notifications, `gh auth status`).
- Metadata tokens come from impersonating a dedicated, narrowly-roled service
  account, or from your own login for trusted. Credential Access Boundaries
  only downscope Cloud Storage, so scope comes from the account's roles.

---

## Build order

**0. Spike (Go).** A minimal header-swapping reverse proxy on a plain local
listener — no socket, no steering. Does Claude Code with subscription auth work
through `ANTHROPIC_BASE_URL` with a placeholder `ANTHROPIC_AUTH_TOKEN` (OAuth
needs `Authorization: Bearer` plus `anthropic-beta: oauth-2025-04-20`)? Does
codex with ChatGPT login work through a custom provider? The answers settle the
two agent rows before anything is designed around them.

**1. Credential routes for git and hf** — the two static-header rows with no
unknowns, served on the session socket. The NixOS test suite starts here, with
the test talking to the socket directly.

**2. Agents**, per the spike.

**3. Steering.** The relay with PROXY v2, steering data for `service`, then
`all` with DNS, egress policy and logging. Tested in a bare network namespace,
without flong.

**4. Metadata server and minting** — Spanner/BigQuery/Pub/Sub, gh, Cloudflare,
gcloud.

**5. Integration** — the adapter in nix-config, against flong's network modes
and hooks. The flong work is independent and can happen in parallel from the
start.

---

## Flake

Same shape as flong, plus a package:

- `packages.default` — `buildGoModule`, `vendorHash = null`,
  `env.CGO_ENABLED = 0`.
- `nixosModules.default` — the daemon: `import ./module.nix { inherit self; }`,
  with a `package` option defaulting to this flake's build, so importing the
  module is enough.
- Steering data as a function of the redirect set, for any launcher.
- `nixosModules.flong` — the adapter, once it has settled in nix-config.
- `devShells.default` — go, gopls, golangci-lint.
- `checks` — the NixOS tests, the package itself (`buildGoModule` runs
  `go test`), gofmt.
- `formatter` — nixpkgs-fmt. `scripts/version.sh`, `VERSION` and the
  shellcheck gate copied from flong.

Consumers should `follows` nixpkgs — but note the reason differs from flong's:
frisket ships a package, so it then builds against the consumer's nixpkgs
rather than its own lock.

The service: `DynamicUser`, secrets via `LoadCredential`,
`ProtectSystem=strict`, nothing else reachable. It holds every credential on the
machine and deserves more isolation than the sandboxes it serves.

---

## Test plan

NixOS tests with a fake upstream standing in for the real services. Nothing
needs a real credential or real network.

**Steering, `all`:**

- `ip link` shows only `lo` and the dummy interface.
- A plain `curl https://example.com`, with no proxy settings anywhere, is
  steered, allowed under the public policy, and logged.
- A raw TCP connection to a private address is refused and logged.
- Loopback, link-local and host-owned addresses are refused — including the
  host's global IPv6 address.
- UDP 443 is dropped; DNS reaches frisket and is logged.
- Under an allowlist, a refused name triggers no upstream lookup, and a
  connection to an address frisket did not resolve for an allowed name is
  refused.
- The workload cannot list or change the nftables rules.
- The PROXY header's destination matches what the client dialled.

**Steering, `service`:**

- Only the service address reaches frisket; other traffic is untouched.

**Credentials:**

- The placeholder never reaches the upstream; the real credential does.
- A credentialed route used under a policy without it gets no credential.
- A Google client library fetches a token from the metadata server.
- An SSE response arrives incrementally, not buffered.
- A git push of a large packfile streams.

**Everywhere:** every connection and query produces exactly one log line.

---

## Required changes elsewhere

**flong** — generic, agent-agnostic:

- **Network modes:** `host` (today's behaviour, the default), `pasta`, `none`.
  flong creates the namespace itself and passes it with
  `--network-namespace-path`; pasta attaches to the same namespace. For `pasta`,
  explicit port forwards — host loopback into the sandbox (`-T`) and inbound to
  it (`-t`) — never `auto`, which forwards every loopback port on the host.
  Note that `containers.<name>.privateNetwork` is inert today (flong reads only
  `.path`, `.bindMounts` and `.allowedDevices`); the mode belongs to flong,
  since pasta is not expressible there.
- **Hook: setup as root inside the namespace**, before the workload. This is
  where steering's rules and dummy route go.
- **Hook: a bind the workload is not told about**, for the session directory.
  `extraBinds` does not fit: everything in it reaches the agents as `--add-dir`
  via `FLONG_EXTRA_BINDS`.
- **Hook: a file bound over a file** — `resolv.conf`, and the same option masks
  credential files.

**nix-config** — policy and, for now, the adapter:

- Define the policies and which sandbox gets which.
- The adapter: create a session at launch, feed frisket's steering data to
  flong's hooks, wrap `command` in `frisket relay --`, set base URLs and
  `GCE_METADATA_HOST`.
- Mask the credential files mounted into strict today. Until that is done,
  "no secrets exposed" is not true whatever frisket does.

Strict-tier hardening that is not frisket's concern, recorded so it is not lost:
the read-only workspace overlay (upper on disk, not `/run`), vanilla agents with
only `projects/<slug>` persisted, an io_uring syscall filter, and revisiting
`privateUsers` now that the credential bind that broke it is going away.

---

## Open questions

1. **Subscription auth through a base URL** — phase 0.
2. **Which adapter step creates the session.** It must run before the sandbox
   starts and produce a directory to bind; the control socket's permissions
   follow from who calls it.
3. **The service address.** `169.254.169.254` would let Google's libraries find
   the metadata server with no `GCE_METADATA_HOST` at all — but AWS and Azure
   SDKs probe that address too, and would get a 404 from frisket before moving
   on. The alternative is a dedicated address plus the variable.
4. **gcloud CLI and the metadata server** — does the CLI honour an override, or
   does it keep the token file?
5. **Hugging Face gated repos** — confirm presigned CDN and Xet downloads work
   as ordinary egress with no rewriting.
6. **pasta's forwarded ports for trusted** — one static list, or per project?
7. **Xwayland's X11 authorisation** — does it admit clients by local uid
   (`xhost` lists such rules)? It decides how exposed trusted is *today*, in
   host mode, until it moves to `pasta`.
