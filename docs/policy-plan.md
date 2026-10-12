# Plan: uniform settings, signed project policy, and "Always"

Across flong, frisket, chase, galley and nix-config. Like [signer-and-sudo-plan.md](signer-and-sudo-plan.md), a plan: each part moves into the component's own docs as it is built.

Status: design, 2026-10-12. §6 lists what is built.

## Threat model

Outside `strict`, this guards against an agent's *accidental* damage, not a determined attacker: it makes security better, not bulletproof. Prompts fire on surprises, things outside what the project normally does. Adversarial hardening is for `strict` alone, where it stays hard-coded.

## Decisions taken

- Strict JSON everywhere, `chase.jsonc` → `chase.json`, hujson dropped; ZON only in `build.zig.zon`.
- Every binary: `-config FILE` (default `/etc/<binary>/config.json`; galley `$XDG_CONFIG_HOME/galley/config.json`), `check FILE`, `schema`. Nix runs `check` at build time. JSON keys = Nix option names (camelCase).
- One project file, `chase.json`, one section per component. Signed with a standard sidecar `chase.json.sig` (SSHSIG). No invented lock format.
- Signature covers exact bytes: any edit, comments included, needs re-signing. Fine, since JSON has no comments.
- frisket does not hard-code `chase.json`: the courier's config says `fileName` (`services.frisket.policy.fileName`), which nix-config sets to `chase.json`.
- Sudo keeps prompting for the password the first time, as today; no "Always" for sudo for now.
- Timed grants ("Allow for 15 min") stay keyed to the claude process; "Always" is the explicit project-scoped answer.
- Always writes the specific rule asked about, but the file takes patterns: I, or an agent, widen a rule by editing it, and signing it again is the check. One general rule beats five hundred near-identical ones.
- nix-config-in-an-ops-container is parked (direction of travel).

## 0. Today: chase translates between vocabularies

| # | Where | What it translates |
|---|---|---|
| T1 | chase `lib/operations.nix` | a tier's `writes/guarded/unmatched` → per-path `ask`/`refuse` booleans on frisket path rules |
| T2 | `internal/policydoc/lists.go` `Apply` | project `apps.<app>.allow/ask/refuse` → path-rule booleans, GraphQL fields, `git.push` |
| T3 | `internal/policydoc/merge.go` | routes / ssh routes replaced by name; `allow` unioned |
| T4 | `internal/grant/launch.go:265-294` | `network.allow/lan` → document `allow`/`lan` |
| T5 | `internal/grant/approve.go:403` | `seccomp.allow/deny` → flong `seccompPolicy` hook lines |
| T6 | chase `module.nix:467-560` | tier seccomp/forwardPorts/egress → flong declaration; `tier.allow` → frisket policies |
| T7 | app generators (docker, gcloud, ssh, credentialFile) | generate routes: stays as sugar |

T1–T5 become a plain merge once frisket and flong understand the vocabulary themselves (§1.3). T6 becomes a rename.

## 1. One shape

### 1.1 `chase.json`

```json
{
  "version": 2,
  "frisket": { "allow": {"pypi.org": true},
               "routes": {"github": {"operations": {"pulls/create": "allow", "category:issues": "ask"},
                                     "guarded": "ask"}},
               "ssh": {"server": {"exec": {"systemctl restart foo.service": "allow"}}},
               "lan": {"nas.home.arpa": {"ports": [445]}} },
  "flong":   { "seccomp": {"syscalls": {"io_uring_setup": "allow", "ptrace": "deny"}},
               "limits": {"MemoryMax": {"size": "8G"}} },
  "signer":  { "ssh": {"hosts": {"gateway": "allow"}},
               "sshsig": {"git": "allow"} },
  "sudo":    { "exec": {"/run/current-system/sw/bin/systemctl restart foo.service": {"runAs": "root", "answer": "allow"}} },
  "chase":   { "secrets": "secrets.yaml", "secretsSHA256": "…",
               "apps": {"docker": {"project": "owner/repo", "images": {"postgres:18": true}},
                        "nix": {"devShell": true}} }
}
```

- Each section is that component's own schema (every field optional), from `<bin> schema`.
- `chase` holds only what no component owns: secrets binding, app bindings, the docker project.
- Galley has no project section.
- Who reads it:
  - **container project:** chase reads it all, merges each section over the tier, and passes it on.
  - **host-level project:** only `signer` and `sudo` mean anything; each daemon reads its own section.

### 1.2 Merge: RFC 7396 JSON Merge Patch

- Objects merge deeply. `null` deletes an inherited key. Arrays are replaced whole.
- So every collection becomes a map keyed by identity: hosts, syscalls, commands, operation ids, images, APIs. A layer can then add or remove one entry.
- Layers: component defaults (Nix) → nix-config tier (Nix, same shape) → host config `/etc/<bin>/config.json` → signed project file → sugar expanded per layer → ceiling clamp.
- ~40 lines of Go, ~10 of Nix. No strategic-merge dialect.

### 1.3 What components learn

- frisket routes and policy gain `writes`/`guarded`/`unmatched` (by operation class), `operations` (id / `category:x` / `METHOD /path` → answer) and `ceiling`.
- Evaluation is at request time: most specific first, then clamped to the ceiling. `frisket check` validates unknown ids.
- Then `policydoc.Apply`/`Merge`/`json.go` are deleted, and chase only merges.

### 1.4 Tiers

`chase.tiers.<t>` keeps chase-only selector fields (`match`, `bare`, `egress`, `caches`, `grants`) and app enables, and gains `frisket`/`flong`/`signer`/`sudo` sub-options typed from each schema. Strict's "anonymous github lists ignored" becomes data: `frisket.routes.github.ceiling = {writes = "refuse"; guarded = "refuse";}`.

### 1.5 Ceilings

1. **Field scope.** `x-scope: "host"` in the schema marks fields a project may never set; `check --layer project` refuses them.
   - flong: user, closure, hooks, mounts, overlays, network forwarding, nested sandbox, environment.
   - frisket: route host/upstream/credential, ssh agent/key, record, ceiling.
   - signer: user, terminal, key dir, known_hosts, max grant.
   - sudo: user, remote keys, danger catalogue (add only), trusted dirs, env allowlist.
   - chase: tiers, match, approver, app enable/scope/trust, egress, caches.
2. **Value ceilings.** A `ceiling` object (allow < ask < refuse, stricter wins), set by tier or host only.
   - Strict's ceilings refuse what a project may widen there, whatever its file says: strict is the one tier hard-coded against an adversary.
   - Fixed in code: sudo danger always asks; forwarded signs never silent; raw `frisket-policy*` SSHSIG refused; flong's fixed seccomp filters; private-address refusals; fallback never bare.

### 1.6 Patterns

Every rule key may be a pattern, in one grammar for every component, frisket's `execrule`'s: `*` matches one word (a command), label (a host) or segment (a path), and `**` matches the rest. A literal key beats a pattern, and a narrower pattern beats a wider one.

| Rule | Exact | Widened |
|---|---|---|
| host (signer, frisket `allow`/`ssh`) | `gateway` | `*-ap`, `*.bodar.com` |
| HTTP operation | `pulls/create`, `POST /repos/o/r/dispatches` | `category:pulls`, `POST /repos/o/*/dispatches`, `GET /**` |
| command (gateway ssh, later sudo) | `uci show wireless` | `uci show **`, `logread **` |
| SSHSIG namespace | `git` | `file` (no patterns: namespaces are few) |

`check` reports a pattern that can never match, and `frisket policy propose` (from the logs) can suggest the pattern a set of exact rules share.

## 2. Host-level project policy

- The same file, read by the signer and sudo gate. An unsigned or invalid file is ignored (one journal line), and behaviour is as today.
- **Courier:** `frisket-policy.service`, running as dan with no network, socket `/run/frisket-policy/sock`, peers checked by uid and cgroup.
  - Given an anchor (pid, start), it resolves cwd → nearest ancestor with the policy file (bounded at `$HOME`) → returns `{root, bytes, sig}`.
  - It can't forge (verifiers check the signature); it is trusted only for anchor → root.
- **Weakness, accepted:** the project is cwd-derived, so any process of dan's that `cd`s into X gets X's rules. Accepted under the threat model.
- **Trust root:** root-owned `/etc/frisket/allowed_signers`, from nix-config's TPM public keys: `dan namespaces="frisket-policy:*" ecdsa-sha2-nistp256 …`. Separate from git's.

## 3. Sidecar `chase.json.sig`

- Plain armoured SSHSIG over the exact bytes, namespace `frisket-policy:<root>` (home-relative, e.g. `~/Projects/foo`).
- Stock verify:
  `ssh-keygen -Y verify -f /etc/frisket/allowed_signers -I dan -n 'frisket-policy:~/Projects/foo' -s chase.json.sig < chase.json`
- Checked in OpenSSH 10.5p1 `sshsig.c`: the pattern list matches the namespace (:949), and verify strcmp's the exact `-n` (:355). So the project binding is exact.
- The signer refuses raw SSHSIG in any `frisket-policy*` namespace; it signs policy only through `policy-sign@frisket` (§4), which sees the bytes.
- **No rollback protection** (decided): restoring an older signed file from git history is not guarded against, per the threat model.
- `secretsSHA256` and `docker.project` live inside the signed bytes, so no multi-subject statement is needed.
- `chase fmt` gives the canonical form (sorted keys, 2-space indent, trailing newline); `chase sign` canonicalises first.

## 4. "Always"

- **Galley:**
  - An item may carry `sign: {namespace, path, old, new}`. Galley renders the diff itself.
  - The button reads "Always", with the project root in the question's text; it is never the Enter default.
  - It returns `{answer: "always", receipt}`; the receipt is single-use and lasts 60 s.
- **Signer `policy-sign@frisket`:**
  1. redeems the receipt with galley;
  2. checks the digests;
  3. signs;
  4. hands `{root, oldDigest, new, sig}` to the courier.
- **Courier write:** `flock`, compare-and-swap on the old digest, then write temp files and rename json then sig.
  - On a conflict (you were editing): allowed once, rule not saved, notice shown.
- **Offered only when** the current file verifies (or is absent) and is canonical, so it can't bless an agent's unsigned edits.
- **The rule Always writes is the specific one asked about** (the glove's default fit):
  - signer: host plus key (forwarded needs its own answer);
  - gateway HTTP: the operation id, else `METHOD /exact/path`;
  - gateway ssh: the literal command.
  - Sudo: none for now (decided).
- **Widening is by editing, then signing.** Any rule may use the patterns in §1.6; the signing dialog's diff is where a widening is seen and approved.
- **Inside containers:** the root is the session's workspace, from flong's `$workspace`.
  - frisket applies the rule to the live session at once; the file applies from the next launch.
- **Git:** the working tree is modified; you commit `chase.json` and `chase.json.sig`.

## 5. Phases

| Phase | What | Key files |
|---|---|---|
| **P0** | `-config`/`check`/`schema` for the sudo gate (signer done); fold `frisket serve` flags into `/etc/frisket/config.json`; galley config file; flong JSON declarations, drop `nix/to-zon.nix` | `cmd/frisket-sudo/main.go`, `nix/sudo-gate.nix`, `nix/module.nix:927-952`, flong `src/decl.zig`, `module.nix:960` |
| **P1** | Nix-rendered host rules in the final shape: `signer.ssh` (done for github.com), `sudo.exec` | `internal/agentsrv/agentsrv.go`, `internal/sudogate/gate.go` |
| **P2** | Signing core: `projpolicy`, public for chase (SSHSIG verify, allowed_signers parser, namespace, canonical JSON, mergePatch), courier unit, signer `policy-sign@` + raw refusal, galley `sign` block/diff/receipt/`redeem`, `frisket policy sign\|verify` | frisket, galley `wire/wire.go`, `daemon/` |
| **P3** | Always on the host: signer and gate read the project policy via the courier and offer Always | `agentsrv.go:409-445`, galleyask, `gate.go` |
| **P4a** (done) | frisket policy v2 (operations, class answers, ceiling, maps, `x-scope`, `check --layer project`), evaluated by frisket at request time | `policy/`, `internal/intercept/scope_v2.go`, `hostpattern/` |
| **P4b** (done) | live always-overlay in containers, asker `always`; flong `seccomp.syscalls` map, `x-scope` | `internal/ask`, `internal/intercept`, `internal/always`, flong `decl-options.json` |
| **P5** (done) | chase: `chase.json` v2 sections, mergePatch replaces policydoc, signature replaces the approver state, `chase check\|schema\|fmt\|sign\|migrate`, `chase record apply` writes then signs | `internal/grant/{file,approve,launch}.go`, `internal/policydoc/*`, `lib/operations.nix` |
| **P6** ✅ | nix-config: tiers as layers, `/etc/frisket/allowed_signers`, courier on, asker/approver to the sign flow | `features/chase/{tiers,asker,approver}.nix` |

**Migration:**
- One release reads both formats; a checkout with only `chase.jsonc` takes the legacy path and prints "run chase migrate".
- `chase migrate`:
  1. converts the file and prints the dropped comments;
  2. writes canonical `chase.json`;
  3. removes the `.jsonc`;
  4. signs it, in one dialog.
- hujson is deleted the release after.

## 6. Done today (2026-10-12)

- galley `81836d5`: over-long titles are cut with "…" in galley itself.
- galley `4ffa704` + frisket `0ef612c`: process chain as a scrolling table, wrappers folded, scripts split at operators.
- frisket `76c0d08`: signer `-config /etc/frisket-signer/config.json`, `check`, `schema`, `ssh.hosts.<name> = allow|ask`.
- frisket `019e92a`: signer questions show the claude/tab above git (display only).
- frisket: sudo gate `-config /etc/frisket-sudo/config.json`, `check`, `schema`; `remoteKeys` in the file, `danger.<pattern>` adds rules beside the built-in catalogue.
- frisket: `serve -config /etc/frisket/config.json` holds the settings the module passed as flags; `check -config`, `schema -config` (frisket's bare `check` is the policy document's). Policies stay documents in `/etc/frisket/policies`.
- nix-config: `work` tier (Triptease, push asks); trusted and ops push unasked; forks by owner alone; `github.com` signs unasked from the host.
- frisket P2, its part ([policy.md](policy.md)):
  - `projpolicy`, public rather than internal so chase imports it: SSHSIG parse, verify and sign; allowed_signers with OpenSSH's meaning (a bad or `cert-authority` line refuses the file); `Namespace`, `Find`, `Load` (which takes `home` too, to name the namespace); canonical JSON and `MergePatch`. Tests held to stock `ssh-keygen -Y sign`/`-Y verify`.
  - `frisket policy verify|fmt|signers`.
  - The signer refuses raw SSHSIG in any `frisket-policy*` namespace, and `check` refuses such an `sshsig` key.
  - The courier, `frisket-policy` (`internal/courier`, `cmd/frisket-policy`, `nixosModules.policy`): `read {pid, start}` and `write {root, oldDigest, bytes, sig}`; peers by uid and unit cgroup from its config, which the signer and gate modules fill in. It also refuses an anchor with another root (a sandbox), and a write whose bytes are not canonical or whose signature does not already verify.
  - `services.frisket.policy.allowedSigners` → root's `/etc/frisket/allowed_signers`.
  - The rest of P2, `policy-sign@frisket`, galley's diff and `frisket policy sign`, came with P3 below; galley's receipt and `redeem` were dropped.
- galley `e62b65f` (wire v5): `Item.Diff{path, old, new}`, rendered by galley as a unified diff, and `Item.Always`, galley's own button, answered `{"answer": "always"}`.
- frisket P3, the signer's part ([signer.md](signer.md#what-is-asked), [policy.md](policy.md#the-signer)), with what differs from §2–§4:
  - No receipt or `redeem`: the signer posts its own question with the diff and Always, and on "always" signs the file itself (`projpolicy.Sign`, in `frisket-policy:<root>`), has the courier write it with the old digest, and signs the login. A failed write still signs once, with an `always` `not saved` journal line and a galley notification.
  - The signer reads the anchor's project through the courier for a direct, bound login or SSHSIG from a chain not cut short; a verified file's `signer` section (only `ssh.hosts` and `sshsig`) is merged over the host's with `MergePatch`, decided as source `project`. Unsigned, invalid, or setting a host-only key: ignored, one journal line per file. Courier down: as before.
  - `ssh.hosts` keys, host and project, take §1.6's patterns: `*` one label, `*` within a label a run of it (`*-ap`), `**` as the first label one or more.
  - Always is offered when the root is known: the courier's read now returns the nearest `.git` directory up to home as `root`, with no `digest`, when there is no file yet.
  - `frisket policy sign FILE`, over `policy-sign@frisket`: FILE must be canonical; the old bytes are `-old` or git's `HEAD`; Refuse and Allow once only. Refused to frisket's main process and to a peer whose `/proc/<pid>/uid_map` is not the host's (the signer cannot open another user's namespace).
  - Sudo: no Always, and the gate does not read the project yet.

- frisket P4a, the gateway's policy document version 2 ([routes.md](routes.md#version-2), [policy.md](policy.md#frisket-the-policy-document-version-2)):
  - `"version": 2` selects it; version 1, which chase still writes, is read beside it for one release.
  - Maps keyed by identity throughout: `allow` name→true, `lan` and `routes` and `ssh` by name, a route's `paths` (what each `"METHOD[,METHOD] /path"` is: operation, class, category) and `operations` (answers by id, `category:x` or endpoint pattern), an SSH route's `exec` and `commands` by execrule's rule name (`"cmd **"`, `"cmd ** [arg GLOB]"`, `"[arg GLOB]"`).
  - At each request: id, then category, then the most specific endpoint pattern (§1.6: `*` one segment, a last `**` the rest; literal over pattern, narrower over wider), then the route's class answer (`writes`, `guarded`, `unmatched`), the document's, the built-in (writes ask, guarded refuse, unmatched refuse; SSH unmatched ask); then clamped to the route's and the document's `ceiling`, stricter winning. git's push is the operation `git-receive-pack`; a GraphQL field is answered by its id (its name where it has no operation). `unmatched` may allow.
  - `allow`, `lan` and `ssh` keys take the signer's host grammar, now the public `hostpattern` package; a route's host is a name or `**.suffix`. An `ssh` pattern key is answers for every machine it matches.
  - `scope:"host"` on the host's fields; `frisket schema` prints the schema with `x-scope: "host"`; `frisket check -layer project -base BASE [-section frisket] LAYER` refuses host fields, new or deleted routes and patterns that can never match, then merges and checks. `frisket check -http ROUTE DOC` answers request lines.
  - Golden equivalence: `tests/fixtures` has each of the repository's version 1 documents with its version 2 equivalent, decided the same request for request; and every scope every intercept test builds is decided again as version 2 says it, 16574 requests, with no difference.
  - What differs from §1.3–§1.6: a route's operation catalogue (`paths`, `graphql`, `git`) and `encodedSlashes` are host-scoped, since an operation's class picks its answer and ceiling; an operation with no class is answered and clamped as unmatched; frisket refuses (rather than ignores) an `operations` id or category no operation of the route has; SSH routes answer by rule, with no id or category answers of their own.
  - So chase can drop T1 (emit the tier's `writes`/`guarded`/`unmatched` and `ceiling` as answers, the catalogue as `paths`), T2 (a project's lists become `operations` entries, push `git-receive-pack`), T3 (MergePatch) and T4 (`allow`/`lan` are maps a layer merges); T5 is flong's.

- chase P5 (`c6f0d44`, `80209c8`, `fe9ef66`, `119ad23`; chase's README and PLAN.md decisions 10, 17, 18 and 20), on frisket `cf4bfc4` and flong `5061921`:
  - A checkout's grant is `chase.json`, version 2, §1.1's sections, strict JSON. Signed beside it as `chase.json.sig`, it launches with nothing asked when the signature verifies against `/etc/frisket/allowed_signers`; otherwise the launch puts it, canonical, to the signer's `policy-sign@frisket` against what git's `HEAD` signed, writes the signature beside it, and ends if refused. No approver state is kept for it.
  - `secretsSHA256` and `chase.apps.docker.project` are in the signed bytes, and a file saying other than the checkout is refused; `chase sign` writes both, canonicalises and signs. `chase check|fmt|schema` read, format and describe a project's file, the schema made of frisket's own; the module's configuration moved to `chase check -config` and `chase schema -config`.
  - Tiers' frisket documents are version 2, rendered by `lib/operations.nix` (T1 gone) and checked by `frisket check` at build time; a project's `frisket` section is merged by `policy.CheckProjectLayer` (T2, T3, T4 gone, `internal/policydoc` deleted). chase first refuses a document-wide answer, `**`, a public suffix's names and a `lan` pattern. Its `flong` section, `seccomp.syscalls` plus `@group` lists, is checked by `flong check --layer project` and printed as `seccompPolicy` lines (T5 kept as output, not translation).
  - `chase record` writes `proposal.json` in `chase.json`'s shape; `chase record apply` merges it and has it signed.
  - Migration as planned: a checkout with only `chase.jsonc` is approved as before, applied as the `chase.json` it migrates to, and told to run `chase migrate`, which writes, prints dropped comments, removes the `.jsonc` and signs. Every `chase.jsonc` in chase's tests and docs is migrated in a test against a golden `chase.json`.
  - What differs from §1:
    - Only the cloudflare, gcloud, git, github and huggingface routes take a project's answers (chase's `answerable`); an answer for Claude Code's, Codex's or Docker's route, a route the tier lacks, or an anonymous one is said and left out.
    - Strict's ceiling (§1.4, §1.5) applies to unauthenticated apps only: a route with no credential gets a `ceiling` refusing `writes`, `guarded` and `unmatched`. An authenticated app in strict is held by its tier's answers, and strict takes no grant.
    - SSH catalogue ids and `category:` names stay as `chase.apps.ssh.hosts.<name>` sugar, turned into `exec` answers by frisket's rule names with the catalogue operation under `commands`; `frisket.ssh.<machine>.exec` answers a tier's own machines directly.
    - The `sudo` section is shaped and checked (`exec` → `{runAs, answer}`) but not yet read by the gate.

- frisket P4b, Always on the gateway's questions in containers ([routes.md](routes.md#always), [policy.md](policy.md#frisket-always-in-a-session)), on galley `fb4307b` and `a79ebab` (`--diff-path`, `--diff-old`, `--diff-new`, or `--diff=FILE|-` with the question's `diff` as JSON, and `--always`, on a `--question`, answered `always`):
  - A question about an HTTP request, or an SSH command, on a version 2 route or machine marked `"always": true` offers Always: `always` and `diff`, the workspace's `chase.json` as it is and with the specific rule added -- the operation id, else `METHOD /exact/path`, under `frisket.routes.<route>.operations`; the SSH command's literal words under `frisket.ssh.<machine>.exec`, for one simple command of plain words. The workspace is flong's `$workspace`, which frisket holds for the session.
  - Offered only where it would stand: the file absent (and no `chase.jsonc` beside it) or verifying and canonical; the rule merged over the session's document by `policy.CheckProjectLayer` admitting the same request (so a ceiling at ask, a Docker route, a request of several operations, a path a rule would read as a pattern and a recording's question get none).
  - The asker contract gains `diff`, `always` and the answer `always`, taken only where offered, and a notice, `kind` "notice" with `text`, whose answer is nobody's.
  - Answered always: the rule admits for the rest of the session at once (logged rule `always`); frisket's main process has the signer's `policy-sign@frisket` sign the new bytes with `approved`, checks the signature, and has the courier write the file and `.sig` with the digest it read. A failed sign or write leaves the request admitted for the session, logs `always` `not saved`, and puts a notice to the asker.
  - The next launch is chase's: it merges the signed file's frisket section over the tier's document, so the rule admits unasked.
  - What differs from §4:
    - No receipt and no `redeem`: frisket's main process is trusted, under the threat model, as the signer already trusts it for a session's ssh logins, so the person's answer in its own question is the approval. The signer signs `approved` from frisket.service's main process unasked, refuses `approved` from anyone else, and still refuses frisket's main process anything else.
    - Which sessions offer Always is the host's mark on each route and machine, `always` (scope `host`), rather than read off the tier: chase marks the routes a project answers in a tier that takes grants, and strict's never, so strict offers no Always whatever asks there.
    - The courier, not frisket, writes the file, since frisket.service's home is read-only: `frisket.service` is one of its peers, as its user, when `services.frisket.always.enable` (on when the signer and the courier are).

- Interactive shells through the SSH route ([ssh.md](ssh.md#interactive-shells)): a version 2 machine's `interactive`, `refuse` (built-in), `ask` or `allow`, answered as a class of its own -- machine, `ssh` pattern, document, built-in -- and clamped by `ceiling.interactive`; scope `host` at every level, so no project's layer sets it, and a route has none. Admitted, frisket opens a pty (the sandbox's term, size and modes) and a shell on its own login and relays them as they are, resizes, signals, EOF and exit status included; asked, it is one question of `kind` `interactive` with `pty`, never offered Always. A command may have a terminal on a machine whose `interactive` is not refuse, the command decided by its words as ever. Two log lines, `phase` `start` and `end`, and no transcript; a recording writes a refused shell down as `hard`. Subsystems, forwarding and env stay refused. Named `interactive`, not `shell`, which is a machine's already (a device CLI's [shell route](ssh.md#shell-routes)). chase passes it through `chase.apps.ssh.hosts.<name>.interactive`; nix-config's ops tier asks for the server and the gateway, its strict tier sets `ceiling.interactive` refuse, and its asker shows the question.

## Appendix: why JSON, not ZON

Zig's own ZON parser was spiked as a C-ABI library called from Go through cgo. It works: static with `zig cc` against musl, about 215 KB larger. But every Go build here is `CGO_ENABLED=0` on purpose: static binaries with no glibc NSS (frisket, chase), and galley's client starting in 1–2 ms. cgo would also put an unsafe C boundary inside the gateway and the sudo gate, need zig as every Go build's C compiler, Mac included, and leave Nix, which has no ZON reader, and chase, which writes these files at runtime, needing their own. JSON is native to Nix (`builtins.toJSON`, keys sorted), to Go and to Zig's std.json.
- chase P6 (`e99912e`; nix-config `1e94c53`): `chase.tiers.<t>` takes `frisket`, `flong`, `signer` and `sudo` sections in `chase.json`'s shape, merged by RFC 7396 over what the tier's other options generate; every tier's rendered frisket document and flong declaration came out unchanged. The `signer` and `sudo` sections are checked and installed at `/etc/chase/layers/<tier>.json` but read by nothing yet. nix-config's approver is gone, with no `chase.jsonc` left (data-lab and pokeranker migrated); `/etc/frisket/allowed_signers` and the courier came in with P3 (nix-config `3d0bc2f`).
- Always made live (chase `d86f21d`; nix-config `212a0f5`): `chase.tiers.<t>.always`, by default a tier that takes grants and asks someone, so never strict, marks its answerable routes and SSH machines; nix-config's asker passes galley the diff and Always, and shows frisket's notices.
