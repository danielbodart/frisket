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
- frisket does not hard-code `chase.json`: its config says `projectPolicy.file`, which nix-config sets to `chase.json`.
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
| **P2** | Signing core: `internal/projpolicy` (SSHSIG verify, allowed_signers parser, namespace, canonical JSON, mergePatch), courier unit, signer `policy-sign@` + raw refusal, galley `sign` block/diff/receipt/`redeem`, `frisket policy sign\|verify` | frisket, galley `wire/wire.go`, `daemon/` |
| **P3** | Always on the host: signer and gate read the project policy via the courier and offer Always | `agentsrv.go:409-445`, galleyask, `gate.go` |
| **P4** | frisket policy v2 (operations, class answers, ceiling, maps, `x-scope`, `check --layer project`), live always-overlay, asker `always`; flong `seccomp.syscalls` map, `x-scope` | `policy/policy.go`, `internal/ask`, `internal/intercept`, flong `decl-options.json` |
| **P5** | chase: `chase.json` v2 sections, mergePatch replaces policydoc, signature replaces the approver state, `chase check\|schema\|fmt\|sign\|migrate`, `chase record apply` writes then signs | `internal/grant/{file,approve,launch}.go`, `internal/policydoc/*`, `lib/operations.nix` |
| **P6** | nix-config: tiers as layers, `/etc/frisket/allowed_signers`, courier on, asker/approver to the sign flow | `features/chase/{tiers,asker,approver}.nix` |

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
- nix-config: `work` tier (Triptease, push asks); trusted and ops push unasked; forks by owner alone; `github.com` signs unasked from the host.

## Appendix: why JSON, not ZON

Zig's own ZON parser was spiked as a C-ABI library called from Go through cgo. It works: static with `zig cc` against musl, about 215 KB larger. But every Go build here is `CGO_ENABLED=0` on purpose: static binaries with no glibc NSS (frisket, chase), and galley's client starting in 1–2 ms. cgo would also put an unsafe C boundary inside the gateway and the sudo gate, need zig as every Go build's C compiler, Mac included, and leave Nix, which has no ZON reader, and chase, which writes these files at runtime, needing their own. JSON is native to Nix (`builtins.toJSON`, keys sorted), to Go and to Zig's std.json.
