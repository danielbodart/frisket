# frisket-signer and frisket-sudo: plan (revision 4)

> Two small gatekeepers sit next to frisket. One holds the SSH keys that live in the TPM. The other decides about sudo when no terminal is asking. Both ask the person through galley. Both are built so that one Allow covers the common case and an odd request stands out.

The plan covers five pieces of work, done together:

- **frisket-signer** replaces gcr-ssh-agent and the ed25519 file key as the session's agent.
- **frisket-sudo** gates sudo when it runs without a terminal.
- **Shared packages** in frisket, used by both.
- **A service socket in galley.**
- **The NixOS wiring.** frisket owns the modules. nix-config only sets them.

The goal is fewer prompts, so that an unusual requester gets noticed. It is not a perfect boundary.

How claims are marked:

- `[spike: name]`: a spike measured it. Where the sceptic pass differs from the first report, the sceptic pass wins.
- `[checked 2026-10-08]`: re-checked on the host while this revision was written.
- **ASSUMPTION-UNTESTED**: nothing has tested it yet. Each one names the test or pre-build spike that will.
- **PENDING <spike>**: a design choice made now, frozen or replaced when that spike reports.

The appendix summarises the spike evidence.

Status: designed, not built. Nothing has been measured on the real Intel PTT; that is gate G0. Revision 2 applied all 38 confirmed adversarial review findings. Revision 3 applies the 22 completeness gaps (CG-1 to CG-22), listed in the review log. Revision 4 adds two things dan asked for after revision 3: grant times the person chooses (presets, a typed time, a hard cap, clock times), and one dialog for sudo that carries the password and the time (decisions 24–29, review log "Revision 4").

---

## Host facts checked for this revision (2026-10-08)

| # | Fact | How it was checked | Used by |
|---|---|---|---|
| H1 | dan-blade's systemd SRK is **RSA-2048** | `/run/systemd/tpm2-srk-public-key.pem` decodes as a 2048-bit RSA key | G0, EA9 |
| H2 | A gnome-console tab looks like this: `.kgx-wrapped --gapplication-service` (pid 4968, parent `systemd --user`) → `bash` (cmdline exactly `/run/current-system/sw/bin/bash`, exe `bash-interactive-5.3p9`, pid = pgrp = sid, tty_nr 34816) → `.claude-unwrapped` (claude-code-2.1.291, pgrp 5113, which is the tty's tpgid) | `/proc/<pid>/stat`, `cmdline` and `exe` | Terminal rule |
| H3 | Each command from Claude Code's Bash tool runs in **its own session with no controlling tty**: sid is its own, tty_nr 0, `/dev/tty` gives ENXIO, stdin is `/dev/null` | `/proc/self/stat` from inside the tool | Terminal rule, sudo gating |
| H4 | claude has **1 anonymous executable mapping** (JIT). kgx and the tab bash have none, and none of the three maps an executable file outside `/nix/store` | `/proc/<pid>/maps` | Maps check scope |
| H5 | Every store path that kgx, the tab bash and claude exec or map is in the closure of the current system **toplevel** (2,888 paths). claude-code links glibc-2.44 and the system glibc is 2.42; both are in that closure | `nix-store -qR $(readlink -f /run/current-system)` | Known set |
| H6 | Claude Code runs with `permissions.defaultMode = "auto"` and `permissions.allow = [ "Bash(sudo:*)" ]` | `home/dan.nix:612`, `:636` | Threat model, actor B |
| H7 | gcr exports `SSH_AUTH_SOCK` with `systemctl --user set-environment` (ExecStartPost of `gcr-ssh-agent.socket`). That puts it in the user manager's environment only, so ssh logins into the host get no agent today | `systemctl --user cat gcr-ssh-agent.socket`, `show-environment`; the NixOS module sets no variable | OPS-2 |
| H8 | frisket dials the agent from its own main process | frisket `internal/sshroute/upstream.go:174` | Decision 5 |
| H9 | nix-config has no `scripts/switch.sh` and no flake `checks` output. frisket reaches nix-config only through chase (`flake.nix:153-155`). `system.checks` exists in the pinned nixpkgs (`nixos/modules/system/activation/top-level.nix:225`). No `configurationLimit` is set | ls, grep | CF2, CF8, SK8 |
| H10 | **swtpm DA lockout**: with the lockout counter at 3/3, keys made from keyfile's default template (`ec.tpm`, `rsa.tpm`, and a fresh `new.tpm`) fail with `TPM_RC_LOCKOUT`. A key made with the same attributes plus `noDA` signs | re-run in `spikes/tpm-da-rerun/dalock.log`, from `spikes/tpm-da-lockout/code` | OPS-8 |
| H11 | `programs.ssh.settings` has four hosts: `modem` (admin@192.168.1.1, `HostkeyAlgorithms`/`PubkeyAcceptedAlgorithms = "+ssh-rsa"`), `gateway`, `server` and `mac` (dan-mac). chase's `modem` host logs in with a sops password and "takes no key". dan-mac's `authorized_keys` is not managed by Nix | `home/dan.nix:845-878`, `modules/chase/tiers.nix:280-295` [checked 2026-10-08] | M2, CG-8 |
| H12 | dan runs mise and direnv with nix-direnv. A project's devShell is a nix-direnv GC root and is inherited by anything started from that directory, including `claude` | `home/dan.nix:744-795` [checked 2026-10-08] | CG-3 |
| H13 | `nix.settings.trusted-users` is not set, so dan is not a trusted Nix user (the NixOS default is root only) | grep of `modules/` and `hosts/` [checked 2026-10-08] | Spike D1 |
| H14 | galley's wire protocol: one JSON object per line. `Hello{galley, item}`, `Item{kind, title, text, markup, icon, buttons[], default}`, `Button{answer: ok/cancel/extra/close, index, label, key, underline}`, `Answer{answer, index, error}`. Closing the connection withdraws the item. It currently lives at `internal/wire`. **Version 2** adds `kind=forms` with `Forms{fields[]}`, `Field{kind: entry/password/multiline/calendar/list/combo, label, values}` and `Answer.fields[]` (`FieldValue{text}`). Field values are filled only for an `ok` (or `timeout`) answer. An `extra` button answers its index and **no field values** (`window.js` `_finish`). A forms combo is a non-editable `Gtk.DropDown`. An `--entry` with values is an editable combo with no password field. Enter presses the item's `default` button, also in a form | `galley/internal/wire/wire.go`, `daemon/window.js`, `daemon/bodies.js` [checked 2026-10-08] | CG-16, decisions 25, 27 |
| H15 | galley's **real** parser and validator take the exact command lines this plan uses: `--forms --add-combo … --combo-values 'once\|5 minutes\|…' --add-entry … --ok-label Allow --cancel-label Refuse`, and the same with `--add-password` first. The parser makes a `kind=forms` item needing wire version 2. `validate.js` accepts both at version 2 and refuses them at version 1. The CLI prints a forms answer as fields joined by `\|` (`hunter2\|1 hour\|`), so a password containing `\|` would be misread by anything parsing that output. An `--extra-button` on a form answers only its label | `internal/zenity` parsed in a scratch copy of galley with `go test`; `daemon/validate.js` run under node on the resulting items (`scratchpad/galley-check/`) [checked 2026-10-08] | Decisions 25, 28 |
| H16 | sudo forks the askpass **from the sudo process itself**: `dup3` of a pipe onto stdout, `closefrom(3)`, `setgid`/`setgroups`/`setuid` to the user, `execl(askpass, askpass, prompt)`. It reads one line, then `waitpid`s for the askpass to exit. The sudoers auth loop calls `pam_authenticate` once per try, up to `passwd_tries`, so the PAM stack (and the grant helper) runs on every try | sudo source in `spikes/sudo-vm-sceptic/src`: `src/tgetpass.c:295-375`, `plugins/sudoers/auth/sudo_auth.c:323`, `auth/pam.c:322` [checked 2026-10-08, source reading only] | Decisions 27, 28 |
| H17 | gid 953 is free. logind keeps `/run/systemd/users/<uid>` root 0644, with `STATE=active`, `DISPLAY=<session>` and a "private data, do not parse" header | `getent group 953`; `ls -l`, `cat` [checked 2026-10-08] | Decisions 26, 28 |

**dan-desktop.** H1–H5 were measured on dan-blade only. G0 re-runs H1–H5 on dan-desktop: the SRK type, a tab's chain and stat fields, the Bash-tool shape, the maps, and closure membership. The results fill the second column of this table before M2 (CG-21):

| Fact | dan-blade | dan-desktop |
|---|---|---|
| SRK type (H1) | RSA-2048 | PENDING G0 |
| Terminal and tab shell paths (H2) | `.kgx-wrapped` → `bash-interactive-5.3p9` | PENDING G0 |
| Bash-tool session shape (H3) | own sid, tty 0 | PENDING G0 |
| claude anon exec maps (H4) | 1 | PENDING G0 |
| Session binaries in toplevel closure (H5) | yes | PENDING G0 |

---

## Earlier merge decisions still in force

These carry over from revision 1, updated where review changed them.

| # | Decision | Status |
|---|---|---|
| C1 | `serve` self-tests each key in-process before `READY=1`. A key that fails is dropped and logged. There is no ExecStartPost | Kept. Zero keys now means degraded serving plus a failing health check (OPS-1, OPS-4) |
| C2 | Module arguments include `utils` | Kept |
| C3 | `system.preSwitchChecks` exists | Kept, but demoted to a backstop. It runs for switch, boot and test, and `NIXOS_NO_CHECK=1` skips it (CF2, EA6). Build-time checks are the guard |
| C4 | The host terminal is gnome-console (`.kgx-wrapped`) | Kept. Rules now use exact store paths (F2, SK1, EA1) |
| C5 | A late Allow becomes a 2-minute grant | **Replaced.** A late Allow once is single-use and exact. A late Allow with a time is a normal grant for that time (F5, SK9, decision 24) |
| C6 | `TERMINFO` and `TERMINFO_DIRS` are allowed. `NIXOS_NO_CHECK` raises the outcome to ask | Kept |
| C7 | sudoedit is decided on its files, and the editor's env is skipped | Kept |
| C8 | Session-root anchors | **Revised.** `systemd --user` roots are never allowed or granted. Terminal=true is now a strict structural test, and a `kgx -- cmd` chain fails it (SK2, EA4) |
| C9 | Children of frisket inherit trust | **Reversed.** Only frisket's main process is trusted (F7) |
| C10 | frisket is a system unit (`User=dan`) | Kept |
| C11 | PAM_USER == PAM_RUSER and PAM_SERVICE == sudo | Kept |
| C12 | The host agent runs in the initial user namespace | Kept |
| C13 | uids 951 and 952 are free | Kept |

---

## What a day looks like

The targets are design targets. The **observe phase** (M3a) measures the signer's real numbers before enforcement starts (SK7). The **shadow phase** (M4a) does the same for the sudo gate (CG-19). The "today" column comes from the current configuration and the spikes.

| Moment | Today | Target | Measured (M3a/M4a) |
|---|---|---|---|
| `ssh`/`git` typed in a gnome-console tab to a host in `/etc/ssh/ssh_known_hosts` | 0 | 0 (terminal rule) | — |
| Same, to an unknown host key | 0 | 1 question per tab and host. A grant is keyed on the tab's shell (EA7) | — |
| Same, but `git` comes from a project devShell or mise (CG-3) | 0 | ssh is pinned to the system ssh, so it is silent when only `ssh` is involved. A devShell `git` between the tab and ssh makes the chain unusual: 1 question, no time picker (once only), until spike D1 decides | — |
| `kgx -- ssh host`, `kgx -- bash -c '…'`, `systemd-run --user ssh …` | 0 | 1 question, badged "launched through terminal/session", no time picker | — |
| An app started from the GNOME overview or by D-Bus (IDE, git GUI) runs `git push` (CG-2) | 0 | Anchors on the app's own process. Store-built app: 1 question, then 0 until the time chosen. App outside the store: unusual, 1 question each time. Flatpak: refused (foreign user namespace). PENDING K2 | — |
| A backgrounded `ssh -f`, or a ControlMaster mux re-parented to `systemd --user` or pid 1 (CG-9) | 0 | The chain is Cut or SessionRoot: asked, never grantable. ControlMaster is not configured. Adding it means one question per master | — |
| `sudo ssh …`, `sudo -E ssh …`, or `nixos-rebuild --target-host` under sudo, reaching the signer socket (CG-7) | 0 (gcr refuses other uids) | Refused at once, logged ("peer uid 0 is not dan") | — |
| frisket logging in for a chase session | 0 | 0 (trusted main process), even with galley closed | — |
| Host Claude Code, first `git push` of a session | 0 | 1 question with a time picker (once, 5 min, 15 min, 1 hour, until logout, or a typed time such as `45m`; at most `grant.cap`, 8 h), then 0 until that time, shown as a clock time, for that claude process, host and key (decision 24) | — |
| A Claude Code process started before a switch that upgraded claude-code (CG-22) | 0 | Its old exe is still known. It no longer matches a version-pinned rule, so it falls to `unmatched` (ask). Grants it already holds keep working | — |
| A renamed, deleted, `nix-store --add`-ed or LD_PRELOADed binary asks for a signature | 0, silent | 1 question flagged unusual, no time picker | — |
| ssh into the host, then `git pull` there | no agent (H7) | unchanged: the signer is not offered to remote sessions | — |
| `ssh modem` | password (wrapper askpass) | unchanged. `PubkeyAuthentication no` for the modem, so the signer is never asked (CG-8) | — |
| `ssh mac` | ed25519 via gcr | TPM key once dan-mac authorizes it (M2). Until then, the ed25519 file, with its passphrase asked by ssh in the terminal (CG-8) | — |
| `printf pw \| ssh host "sudo -S …"` (make-usb.sh) | password | unchanged: remote sudo is never gated (OPS-2) | — |
| Host Claude Code, first sudo of a session | 1 password dialog (typed argv) | **1 dialog**: password plus "Allow for", showing the requester chain and sudo's argv. No second question when what sudo resolved is what the dialog showed (decision 27). A second question only when it is not: an untrusted program path, an environment variable to ask about, `-s`/`-i`, a cut argv | — |
| The password typed wrong | sudo asks again, up to 3 | The dialog again, up to 3 (sudo's `passwd_tries`), saying the password was not accepted and listing the previous choice first | — |
| Further sudo, exact same command, inside the grant | 1 password per Bash call | 0 | — |
| Further sudo, a command an op-level grant covers (e.g. `systemctl daemon-reload`) | 1 password per Bash call | 0 | — |
| Further sudo, a different command, inside the anchor's grant | 1 password per Bash call | 1 question with the time picker, no password | — |
| Further sudo after the time chosen with the password has ended, while a grant still lives (decision 29) | 1 password per Bash call | 1 dialog (password and time). No question if the grant covers the command | — |
| sudo let through by its own ticket (a second sudo in one `bash -c`), a different command | 0 | 1 question with the time picker; no askpass ran, so no dialog | — |
| A question while the screen is locked (CG-18) | — | Refused at once with "screen locked; nobody to ask". Not held for 90/110 s | — |
| The laptop suspends for longer than a grant's cap (CG-4) | — | Every grant and the password window are expired on resume. The next request asks | — |
| sudo in a terminal | — | unchanged | — |
| A `nixos-rebuild switch` that changes frisket | — | at most 1 extra prompt per active anchor (grants live in memory) | — |
| Gate down or crash-looping | — | no-tty sudo refused with "use a terminal". Terminal sudo unchanged | — |

Honest trade-offs:

- Prompts **rise** for agent-originated SSH, which is silent today.
- Prompts **fall** for repeated agent sudo.
- With today's PATH, every rule-level "allow" for sudo becomes an ask (SK5). The sudo savings come from grants, not from silent allows.
- Projects whose devShell ships `git` lose the silent terminal path until D1 lands (CG-3).
- A grant now takes two clicks (pick a time, then Allow) where revision 3's "Allow 15 min" took one. Allow alone means once.
- A long grant chosen with the password (up to 8 h) skips the password for that long. Revision 3 capped this at 1 hour (decision 29).

---

## Goals and non-goals

Goals:

1. **SSH keys live in the TPM.**
   - ECDSA P-256 for everything. RSA-2048 only if the gateway's dropbear refuses ECDSA.
   - A key works only on its own chip.
   - Only `ssh-signer` can open the TPM.
2. **Every signature is attributed** to a requester and a destination.
   - The requester is a process chain with real exe paths. Rules match **exact store paths** that nix-config renders. A path counts as known only if it is in a root-built system closure.
   - The destination is a verified host key, plus the names known for it.
3. **One question**: Allow, for a time the person picks (once, a preset, until logout, or a typed time, never above a hard cap, each shown as a clock time), or Refuse. A grant keeps the next matching request quiet until that time, and use never extends it.
4. **sudo with no terminal gets the same treatment, in one dialog.** The askpass dialog carries the password and the time and shows the requester and the command. The gate asks a second question only when what sudo resolved differs from what the dialog showed. A grant can stand in for the password for that requester, but only until the time the person chose together with a typed password (1 hour when the password came some other way).
5. **Terminal sudo behaves as today at runtime.** A plugin that cannot load fails the system build on every rebuild path. If one still gets through, the recovery is the previous generation at the console (SK8).
6. **No Python.** Neither service runs as root or as dan. Each has its own user and only the access it needs.

Non-goals:

- Defending against root. Root's own ssh never uses the signer: any peer whose uid is not `forUser` is refused (CG-7).
- A boundary against code running as dan (see the threat model).
- Replacing sudo's password on the terminal path or for remote `sudo -S`.
- Host keys in the TPM, hierarchy keys, or a PIN cache.
- Fixing sudo for agent runners that give commands a pty. Those take the terminal path (S4).
- **Daemonised ssh.** `ssh -f`, `-N` masters and ControlMaster muxes are re-parented to `systemd --user` or pid 1, so their chain is Cut or SessionRoot. They are always asked and never grantable. ControlMaster is not configured today. Turning it on means one question per master connection, and later multiplexed sessions need no signature (CG-9).
- RSA SHA-1 (`ssh-rsa` with flags 0). The modem needs it and keeps its password (CG-8).

---

## Threat model

| Actor | Runs as | Can reach | In scope |
|---|---|---|---|
| A. Sandboxed agent (chase/flong container) | dan's uid in a user namespace, or a mapped uid | Only what frisket hands it. No `/run/galley-ask`, `/run/frisket-signer`, `XDG_RUNTIME_DIR` or user bus. Inside, wheel is empty and the store's sudo is not setuid | **Yes, hard boundary** |
| B. Host agent that a prompt injection can steer (host Claude Code in `defaultMode = "auto"`, `Bash(sudo:*)` pre-approved, `SUDO_ASKPASS` set) [H6] | dan, no tty, init user namespace | Everything dan can reach, subject to Claude Code's auto classifier | **Partly.** An attention boundary only while B acts through ssh, git and sudo without first persisting code. A B that writes user units or drop-ins, rc files, its own askpass, a devShell, or rebinds the galley socket has become C (F3) |
| C. Malware running as dan | dan | Everything dan can reach, including `~/.config/systemd/user` and `/run/galley-ask` (dan owns it) | **Not stopped, and not necessarily visible.** It cannot reach the TPM, root's cgroups or sudo internals. Galley questions may be answered by C with nothing on screen. The service journal is the after-the-fact record (EA5) |
| D. Root, kernel, firmware, physical access | root | Everything | No. Root peers are refused, not defended against (CG-7) |
| E. Remote host or network position (spoofed server, forwarded agent) | — | The agent protocol through a forwarded socket | **Yes** |

What follows from the table.

**Actor A is kept out by paths and namespaces, not by prompts.**

- The signer socket and `/run/galley-ask` are not bind-mounted into sandboxes. The VM test checks this end to end.
- The signer refuses any peer whose user namespace is not the initial one. That check needs `CAP_SYS_PTRACE` [spike: identity-vm, userns].

**Actors B and C can drive galley.** Each of the following was measured or follows from ownership:

- **Impersonate the window** with a user drop-in on `galley.service` [spike: galley-socket, "authenticate the real window" refuted].
- **Unlink `/run/galley-ask/dan.sock`** (the directory is dan's) and bind a listener that answers every service question, with no restart. The services check the cgroup of the process that bound the socket (decision 13). That raises the bar to the drop-in route, but it is **not** a boundary.
- **Post a decoy password row first** and receive the typed password [spike: galley-socket, sceptic Spike3].
- **Read frisket's environ and kill frisket** [spike: identity-vm].

So "answers only from the window" holds against socket clients, not against dan-uid code (G1).

**Whether B can become C** is decided by Claude Code's auto classifier, not by this design [H6].

- T5 adds deny rules for writes under `~/.config/systemd/user`, for `systemctl --user edit|daemon-reload|set-environment`, and for `/run/galley-ask`.
- That is a speed bump: other shell forms get around pattern rules. **ASSUMPTION-UNTESTED** that the auto classifier refuses such writes. It is checked by hand at M3.
- The only structural fix is galley under its own uid. It is out of scope and listed as G1.

**sudo's password against C.** The password is weak against C: C can capture it later with a decoy askpass row or a `SUDO_ASKPASS` it chose. It is still the only factor that needs a human. A galley Allow can be forged with no human at all, by impersonating the window. Hence:

- Grants are created only behind a typed password for that requester.
- The PAM helper skips the password only for a live grant whose requester's password window is still open, in **boot time** (decisions 14, 29). The window is the time chosen in the same dialog as the typed password, or 1 hour when the password came some other way. A grant made by a plain question never widens it.
- It never skips the password just because the gate is reachable (SK3).

**The one sudo dialog (decision 27) keeps the password as the human factor.** The dialog's time and its approval count only when pam_unix accepted the password typed into that same dialog, for that same sudo. Against each actor:

- **B** cannot answer a genuine dialog without the person, because answers come only from galley's window and the askpass checks galley's binder cgroup. B can make sudo run its own `SUDO_ASKPASS`, but that program lacks the `frisket-askpass` group, so the gate never takes a time from it. Even with a password it harvested, B then gets the plain question about the resolved command, exactly as in revision 3.
- **B** can wrap the genuine askpass and redirect its stdout to steal the password typed into a genuine dialog (residual risk S9). That is no worse than the decoy row it can already post. With the password, B still meets the plain question, because a stolen password brings no dialog record.
- **C** can impersonate the window, answer the genuine dialog itself, and pick any time. It needs the password for pam_unix, which it can capture. That is the revision-3 position: C with the password is root. Nothing is lost against C.
- The dialog's content comes from the gate, which built it from root-collected data ('G' links and sudo's own argv). Neither the askpass's argv nor its environment can change what it shows.

SK3's double prompt is therefore **removed** whenever the dialog showed what runs, and **kept** (password dialog, then the plain question) in exactly the cases where the dialog could not show it. The list is in "The gate's decision on 'A'", step 10.

**Re-rooting.** `systemd-run --user …` puts the requester under `systemd --user`. `kgx -- …` puts it under the terminal server.

- A `systemd --user` root is never allowed or granted.
- A chain under the terminal server gets Terminal=true only when it passes the strict structural test (see "Requester identification"). `kgx -- ssh`, `kgx -- bash -c` and `kgx -- git push` fail that test and are asked.
- **Residual risk:** `kgx -- bash -i` driven through rc files (`~/.bashrc`, `PROMPT_COMMAND`), or keystrokes injected into a real tab, can still pass. That needs dan-writable files (actor C) or a visible window held open for the minimum shell age. The person seeing the window is the only defence (R1).
- **ASSUMPTION-UNTESTED:** the exact process shape of `kgx -- cmd`. Pre-build spike K1 records it before T2/T3 freeze the Requester fields.

**What C cannot do**, grounded in measurements:

- Open `/dev/tpmrm0`. That covers every member route, enforced by the assertion in decision 2 [spike: identity-vm, tss].
- Move into the root-owned cgroup `/system.slice/frisket.service` [spike: identity-vm, MOVE-DENIED].
- Become frisket's main process. That would need ppid 1 and frisket's exact exe (F7).
- Create a process under a root-owned `sshd-session` without a real ssh login.
- Write to `/run/frisket`, `/run/frisket-signer`, `/run/frisket-sudo` or `/etc`.
- ptrace setuid sudo [spike: sudo-plugin].
- Run its own code with egid `frisket-askpass`, or ptrace or preload into the genuine askpass. A setgid exec is non-dumpable and `AT_SECURE` (decision 28; **ASSUMPTION-UNTESTED** for the NixOS wrapper, AP1).
- Stop or reset a system unit.
- Make a store path known. The known set is written by root from system closures only. A devShell or `nix-store --add` path is never in it (decision 12, CG-3).

**Actor E** is handled by session-bind verification and by refusing forwarded requests.

### Minimum trusted computing base

| Component | Runs as | Privilege | Why it is trusted |
|---|---|---|---|
| frisket-signer | `ssh-signer` | `/dev/tpmrm0` via tss. Ambient `CAP_SYS_PTRACE`, with ptrace-family syscalls blocked by seccomp | Holds the only TPM access. Reads exe paths and maps across uids |
| frisket-sudo gate | `sudo-gate` | None | Holds the sudo policy and grants. Only root can reach its gate socket. Only processes with egid `frisket-askpass` can reach its askpass socket, and nothing there carries a chain or a pid |
| `frisket-sudo-askpass` | dan, egid `frisket-askpass` (setgid wrapper) | Its group: the askpass socket, and galley's askpass class | Its group is the only proof that a time came from the genuine dialog. It handles the password and hands it only to sudo (decisions 27, 28) |
| `frisket_approval.so` + `frisket-sudo-pam` (C) | root, inside setuid sudo or pam_exec with seteuid | Whatever sudo has | Collects the chain as root, so the gate needs no capability. Detects remote sessions |
| `frisket-known-paths` activation script | root | — | Writes the known store-path set that both services read |
| galley window | dan | — | The only source of answers, against socket clients only. It enforces the time grammar and the askpass class's form shape (galley items 5, 5b) |
| frisket main process | dan, in system unit `frisket.service` | — | Trusted by the signer through cgroup, ppid 1 and exact exe, for its listed keys only. Its children are not trusted |

---

## Locked decisions

**1. Separate users, binaries and store paths. The tests run once, in one derivation.**

- `ssh-signer` (uid/gid 951) and `sudo-gate` (952) are fixed system users.
- `mkFrisket` stays the one derivation that runs `go test ./...` and `checks.race` over every package.
  - Add `pkgs.swtpm` to `nativeCheckInputs`, and set `FRISKET_REQUIRE_SWTPM=1` so the TPM tests fail rather than skip.
  - Set `excludedPackages = [ "cmd/frisket-signer" "cmd/frisket-sudo" ]` so the `frisket` output installs only frisket.
- The daemon packages are `(mkFrisket pkgs).overrideAttrs` with `subPackages = [ "cmd/<daemon>" ]`, `excludedPackages = [ ]`, `doCheck = false` and `meta.mainProgram` set. They share `vendorHash` and ldflags (CF4). The `frisket-sudo` package builds both `cmd/frisket-sudo` and `cmd/frisket-sudo-askpass`, and `mkFrisket`'s `excludedPackages` lists `cmd/frisket-sudo-askpass` too.
- The C pieces are exported as a function, `lib.sudoRoot`, so nix-config builds them against the host's own sudo and glibc (CF3).
- "CI" means named frisket flake `checks` outputs, run by `nix flake check` (CG-20):
  - `checks.no-replace`: fails if `go.mod` has any `replace` directive;
  - `checks.named-tests-ran`: runs the test suite with `-v` and fails unless every named security test printed its `--- PASS:` line (the list lives in `nix/security-tests.txt`);
  - `checks.fuzz-gate`: runs `FuzzNoRequestCrashesTheGate`, `FuzzNoAskpassMessageCrashesTheGate` and `FuzzNoAgentMessageCrashesTheParser` for 5 minutes each (`-fuzztime=5m`), 15 minutes in total.

**2. TPM access is the security boundary, not the key file.**

- Keys are `emptyAuth` and `userWithAuth` with no policy. Anyone who can read the blob and open `/dev/tpmrm0` can sign with it, and for the RSA key that includes raw `RSA_Decrypt` [spike: tpm-keys, sceptic].
- `security.tpm2.enable = true` puts `/dev/tpmrm0` at root:tss 0660 [spike: identity-vm].
- An assertion over **effective** membership enforces that no login user is in tss. It covers `users.groups.tss.members`, `extraGroups`, and tss as a primary group (EA10).
- Blobs are committed and may sit in the world-readable store. They are useless off this chip [spike: tpm-keys, TPM_RC_INTEGRITY].

**3. The signer reads real exe paths and maps with `CAP_SYS_PTRACE`, and seccomp stops it from ptracing.**

- `@system-service ~process_vm_readv ~process_vm_writev ~kcmp` blocks `ptrace` and `pidfd_getfd` (they live only in `@debug`) and keeps exe readable [spike: identity-vm, hardptrace].
- The capability is worth having only together with decision 12. Exact paths and closure membership are what make exe identity hard to forge (SK1).
- Leak accepted: the signer can read `maps`, `exe`, `cwd` and the `fd` links of any process. `environ` and `mem` stay closed.

**4. frisket-sudo gets the chain from root, and the gate daemon has no capability.**

- The approval plugin runs at euid 0 inside sudo. The pam_exec helper runs at uid 0 with `seteuid` [spike: sudo-vm].
- The gate trusts a chain only from peer uid 0.
- Because the gate cannot read `/proc` for dan's processes, all liveness is decided from root-collected starttimes (decision 15).
- Revision 4 keeps this. The askpass is identified without `/proc`, through `SO_PEERCRED` and `PIDFD_GET_INFO`, which need no capability [spike: identity-vm, hard] (decision 28).

**5. Only frisket's main process is trusted, and only for the keys its routes use.**

frisket's requests are unbound userauth: x/crypto never sends session-bind [spike: session-bind]. Its 10s `upstreamTimeout` means it can never wait on a prompt. All of these must hold:

- `SO_PEERPIDFD` is taken at accept.
- `PIDFD_GET_INFO` has the CREDS bit set, with `ruid ==` the frisket user.
- `cgroupid ==` the inode of `/sys/fs/cgroup/system.slice/frisket.service`, re-statted every time [spike: identity-vm].
- `ppid == 1` (from `PIDFD_GET_INFO`), and `/proc/<pid>/exe` equals the exact frisket binary path rendered from the package that `frisket.service` runs. frisket dials the agent from its main process [H8].
- The request is class-1 or class-2 userauth with a key listed in `trusted[].keys`. An SSHSIG request from frisket takes the normal path.
- The PID bit is still set after the decision.

Every other process in that cgroup (frisket-asker, nsnet helpers, `ssh-add` run by a hook) falls through to the normal rules, with the badge "inside frisket.service, not frisket" (F7).

**ASSUMPTION-UNTESTED:** that the cgroup move is denied from dan's delegated `user@1000.service`. The signer VM test tries it from a real `user@` session with linger.

**6. Dead peers and pid reuse fail closed.**

The recipe [spike: identity-vm]:

1. `SO_PEERPIDFD`.
2. `PIDFD_GET_INFO`.
3. Walk `/proc`.
4. `PIDFD_GET_INFO` again, requiring `mask & PIDFD_INFO_PID` with the same pid.

**Check the mask bits before using uid or cgroupid.** A dead pidfd reads ruid/euid as 0 and keeps the old cgroupid.

**7. Nobody signs late. A late Allow is honoured exactly as it was given.**

- The signer refuses at its own deadline (90s, under `LoginGraceTime` 120s) [spike: session-bind, PerSourcePenalties].
- The sudo gate refuses at 110s, under Claude Code's 120s Bash default, or when the requester hangs up, whichever comes first.
  - Hang-up detection is the main signal.
  - The 110s backstop stops a root command from running unseen after the agent has given up (SK9).
- The row then reads "requester gone".
  - A late **Allow once** becomes a single-use grant for the exact target: the sudo argv hash, or the host fingerprint plus key fingerprint for the signer. It is valid for 15 minutes and consumed on first use.
  - A late **Allow with a time** becomes a normal grant for that time, counted from when the late row was posted (decision 24).
  - Neither applies to Cut, unusual or SessionRoot chains.
  - The sudo dialog (decision 27) has no late form. Its row goes when sudo exits, because no password is ever kept to verify later.
  - Both are keyed on the anchor's `(pid, starttime, exe)`. A retry matches only if its freshly collected chain names that same triple. A dead anchor's pid cannot come back with the same starttime, so its grant can never match and simply expires (decision 15, CG-5).

**8. Terminal sudo and remote sudo are untouched.**

- With `tty=` present, `open()` returns 0: the plugin is removed and sudo carries on [spike: sudo-vm R6].
- With a **verified remote chain**, `open()` also returns 0 (OPS-2). A verified remote chain is an ancestor `sshd-session` running as the user, at the exact path the module passes, whose parent is a uid-0 `sshd-session`. That is today's `ssh host "sudo -S …"`, with a typed password.
- The PAM helper exits 1 in both cases.
- `open()` **never** returns -1 [spike: sudo-vm R4/X3].

**9. galley gets a service socket, with narrowly stated guarantees.**

- A root-made `0750 dan:galley-ask` directory holds the socket.
- The window allows only listed service uids. The caller is attached after `validate()`.
- Services may ask `kind=question`, or the time-picker form of decision 25 and nothing else. Password items never join.
- One more caller class, **askpass** (decision 28): a peer with the user's uid and egid `frisket-askpass`. It may post only the sudo dialog's form (password, combo, entry) or a password-only form.
- Claimed:
  - services cannot collect secrets: their only typed field is the time entry, which galley answers only in the time grammar;
  - services cannot impersonate another caller;
  - services cannot read another client's answer;
  - the askpass class's password goes only to the askpass, which hands it only to sudo.
- **Not** claimed:
  - "cannot phish";
  - "answers only from the window" against dan-uid code.

**10. Three new module dependencies**, amending frisket PLAN.md decision 1 (CF13):

- `github.com/google/go-tpm` `v0.9.9-0.20260124013517-8f8f42cba0de`.
- `github.com/foxboron/go-tpm-keyfiles` `v0.0.0-20260427185012-515ba073c4c1`. The legacy tpm2 and tpmutil packages are packages inside go-tpm, not separate modules.
- `github.com/danielbodart/galley`, at a pseudo-version at or after the commit that makes `wire/` public. galley's go.mod has no requires.
- `go list -deps` tests:
  - `./cmd/frisket` imports neither go-tpm nor galley;
  - `./cmd/frisket-sudo` imports no go-tpm and no `internal/dns`.
- No vendored copy of `wire`. A temporary `replace` to a local checkout is allowed during development, and `checks.no-replace` rejects it at merge (CG-20).

**11. No-tty sudo fails closed whenever the gate cannot answer.** (OPS-1, OPS-5, SK4, EA2)

In `enforce` mode, the no-tty request is denied with "frisket-sudo: gate not running (systemctl status frisket-sudo.socket); sudo in a terminal is not gated" when any of these happen:

- the directory is missing;
- the socket is missing;
- ECONNREFUSED;
- any other connect error;
- a timeout.

This cannot lock anyone out, because terminal and remote sudo never reach `check()`. "Gate intentionally off" is an explicit state: `services.frisket.sudoGate.enable = false`, which leaves the plugin line out of sudo.conf. It is never inferred from errno. In `shadow` mode the plugin approves on every error and logs it (decision 21).

**12. Program identity is exact, and "known" means "in a root-built system closure".** (F2, SK1, EA1, CG-3, CG-12)

- nix-config renders exact store paths into the signer policy: the terminal server, shells, leaf programs, anchors and the trusted frisket exe. `signpolicy` rejects any `*` inside a `/nix/store/` path.
- A root activation script writes `/run/frisket/known-store-paths`: `nix-store -qR` of the activating system, `/run/current-system`, `/run/booted-system` (if present) and every `/nix/var/nix/profiles/system-*-link`.
  - The toplevel closure covers everything the session's terminal and claude map [H5].
  - Including every present generation keeps processes started before a switch known.
- **File format** (fixed interface): UTF-8, one absolute top-level store path per line, `/nix/store/<32-char hash>-<name>`, no trailing slash, sorted bytewise (`LC_ALL=C sort -u`), terminated by a newline. Nothing else.
- **Fail-safe writing:** the script runs under `set -o pipefail`. It replaces the file only if `nix-store` succeeded, the new set is non-empty, and it contains `$systemConfig` itself. Otherwise it keeps the previous file and prints a warning. The activation still succeeds, because a missing known set only makes things ask more.
- **Fail-safe loading:** `peer.LoadKnown` rejects an empty file, any line that does not match the format, or a file without a trailing newline. On a reload error it keeps the previous set and logs at error level. With no set ever loaded, every exe is unusual.
- An exe, or an executable mapping, whose `/nix/store/<hash>-<name>` root is not in that set is **unusual**. That covers `nix-store --add`, `nix shell`, devShell and mise binaries.
- **devShells and nix-direnv roots are not added** to the known set. `/nix/var/nix/gcroots/auto` roots are made by the daemon from dan's own flakes, so including them would let dan-uid code make any path known (see the rejected options). The common devShell case is handled by pinning ssh (decision 18).

**13. galley binds the services socket itself; no socket activation for it.** (CG-1) PENDING G-P1.

- Under socket activation, `SO_PEERCRED` and `SO_PEERPIDFD` on the client side name the process that created the listener, which is `systemd --user` in `init.scope`. With the revision-2 design every answer would have been `ErrNobody`.
- Chosen: **option (a)**. galley.service creates `/run/galley-ask/dan.sock` itself at start (unlink a stale file, `bind`, `chmod 0666`, `listen`), with the path from `GALLEY_SERVICES_SOCKET`. The user socket `%t/galley/sock` stays socket-activated and unchanged.
- The services' peer check (decision 9, `internal/galleyask`) then sees galley's main process and its cgroup `…/app.slice/galley.service`.
- Cost: services can no longer start galley on demand. If galley is not running, a connect gets ENOENT or ECONNREFUSED, which is `ErrNobody`. galley is started by the graphical session.
- If G-P1 shows that the client already sees `galley.service` under activation, keep socket activation and the check unchanged. If option (a) cannot work, fall back to **option (b)**: the check accepts the `systemd --user` `init.scope` cgroup and is documented as proving only "the listener was bound by systemd from galley's unit", which C's drop-in can still produce. **Option (c), dropping the check, is rejected**: the socket-rebind route would then be free.

**14. All grant and password times use CLOCK_BOOTTIME.** (CG-4)

- Go's monotonic clock reads CLOCK_MONOTONIC, which stops during suspend. A grant made before a 12-hour suspend would count as fresh after resume.
- `internal/grant` takes `clock func() time.Duration`. In production that is `unix.ClockGettime(unix.CLOCK_BOOTTIME)`. Grants store boottime durations, never `time.Time`.
- Every grant's end (`posted + chosen`, decision 24), the cap, the late once-grant's 15 minutes, the pending-sudo and dialog records, and `PasswordUntil` (decision 29) are all measured in boottime. A suspend longer than a grant's time therefore expires it.
- No suspend hook is needed. Wall time is used only in log records and in the clock times shown to the person, which are computed from the boottime that remains each time they are shown.

**15. Anchor liveness is checked lazily, by starttime match.** (CG-5)

- Neither service holds pidfds for anchors. The gate could not: it has no capability, `ProtectProc=invisible` and `ProcSubset=pid`.
- A grant's key includes the anchor's `(pid, starttime, exe)`, collected fresh on every request: by root (sudo) or with `CAP_SYS_PTRACE` (signer). A grant matches only if the current chain's anchor has the same triple. A dead anchor's grant can never match again, because a reused pid has a different starttime.
- `Sweep()` drops entries whose boottime expiry has passed. It runs every minute and on every `Use`. It never needs `/proc`.
- The wire protocol needs no pidfd tag. The `'S'` tag (decision 16) carries sudo's own identity.

**16. The sudo wire names sudo itself.** (CG-6)

- 'A' and 'G' both carry a required tag `'S' u32be sudo_pid | u64be sudo_starttime`.
  - Plugin: `sudo_pid` from `user_info` `pid=`, and its starttime from field 22 of `/proc/self/stat` (the plugin runs inside sudo).
  - PAM helper: `getppid()` and field 22 of `/proc/<ppid>/stat`.
- A request without 'S' gets 'N'.
- On 'G' → 'Y', the gate records `(sudo_pid, sudo_starttime) → grant-authenticated` for 5 minutes of boottime. On 'A', if 'S' matches such a record, the request is grant-authenticated and does **not** move the anchor's `PasswordUntil`. Otherwise it is dialog-authenticated (decision 27) or password-authenticated another way (decision 29).
- Every 'G' also leaves a **pending sudo** record keyed on 'S', with the 'G' links and sudo's own argv (tag 'v'), for 10 minutes of boottime or until an 'A' with the same 'S' consumes it. The askpass socket looks sudos up only there (decision 28).
- **ASSUMPTION-UNTESTED:** that the pam_exec helper's parent is the same sudo process that later calls the approval plugin, so that both send the same 'S'. The sudo-gate VM test asserts that the pids and starttimes are equal.

**17. Every signer peer must be the configured user.** (CG-7)

- Decision step 0 on every connection: the peer's `SO_PEERCRED` uid must equal `forUser`'s uid. Anything else (root through `sudo ssh`, `sudo -E ssh`, `nixos-rebuild --target-host` under sudo, nix-daemon remote builds, another login user) is refused with an error log line, "peer uid N is not <forUser>". Nobody is asked.
- The socket is dan 0600, so in practice only root can be such a peer.

**18. ssh is pinned to the system ssh for git, and desktop apps anchor on themselves.** (CG-2, CG-3)

- home-manager sets `programs.git.extraConfig.core.sshCommand = "${config.programs.ssh.package}/bin/ssh"`, the same path the policy renders. A devShell or mise `git` then still runs the system ssh. A project that sets `GIT_SSH_COMMAND` overrides this, and its ssh is unusual.
- A devShell or mise `git` itself is a between link that is not known. The chain is therefore unusual: asked, with no time picker. This is accepted for v1 and counted in M3a (badge reason `devshell`). Spike D1 tests a second, signature-based tier of the known set that would lift it.
- **Desktop-launched apps.** The anchor is the nearest non-transient ancestor (see "Requester identification"), so an IDE or git GUI started from the GNOME overview or by D-Bus anchors on **its own process**, not on `systemd --user`.
  - Store-built app (known exe): treated like claude. It is asked, and the time picker is offered for that app process, host and key.
  - App outside the store (Toolbox download, AppImage, a mise binary): unusual, asked each time, no grant.
  - Flatpak: a foreign user namespace, so refused.
  - The ssh **directly** under `systemd --user` (no app in between) stays SessionRoot.
  - PENDING K2. If K2 shows the app's launcher is a transient name or that git is spawned through a helper that re-parents, add the helper to the transient set or record the shape as accepted prompts. Either way, record the decision here before T2 freezes.

**19. Rules match a known path with the same store name.** (CG-22)

- An exe field in a rule matches the exact rendered path, **or** any path in the known set whose store name (`<name>` after the hash) and relative path inside the store path are identical. That covers the same version rebuilt with a different hash (a dependency bump).
- A different version does not match. A claude or bash started before a version bump falls to `unmatched` (ask) until it is restarted. Grants it already holds still work, because grants key on the running exe, not on the rule.
- The terminal shells and terminal server follow the same rule. Old tabs survive a rebuild that only changes dependencies, and ask after a version bump.

**20. A question while the screen is locked is refused at once.** (CG-18)

- galley reads logind's `LockedHint` for its session over the system bus. While it is true, a service question gets `{"error":"locked"}` immediately and is not queued. **ASSUMPTION-UNTESTED** that `LockedHint` is set by GNOME 50's lock screen; the galley VM test sets it with `loginctl lock-session`.
- `galleyask` maps `locked` to `ErrLocked`, which the services treat as nobody to ask. The log and the reply say "screen locked; nobody to ask".
- A retry loop by actor B against a locked screen produces refusals, which feed PerSourcePenalties on the remote sshd (N2). That is accepted.
- User (non-service) items are unaffected.

**21. The sudo gate has a shadow mode before enforce.** (CG-19)

- `services.frisket.sudoGate.mode = "shadow" | "enforce"`, default `"shadow"`. The plugin line in sudo.conf carries `mode=shadow`.
- In shadow mode:
  - `check()` sends 'A' as usual, but always returns 1, whatever the reply or error. A connect error is logged to syslog.
  - The gate decides fully, never asks galley, and logs the would-be decision with `shadow:true` (outcome, rule, grant, PATH and env flags).
  - The PAM helper sends 'G' and logs what it would have done, but always exits 1, so the password is always asked.
- Shadow exercises every lockout guard (the plugin is loaded), so M4a also proves the load path.

**22. "Most specific rule wins" is a lexicographic tuple.** (CG-11)

Each signer rule gets a specificity tuple, compared from left to right:

1. The number of program constraints: one each for `leaf`, `anchor` and `terminal: true` (0–3).
2. The destination: a named host (a `hosts` name or a `known_hosts` name) = 2, `"known"` = 1, absent or `"any"` = 0.
3. The key: a rule restricted to named keys = 1, otherwise 0.

The highest tuple wins. On a tie, the stricter outcome wins (refuse > ask > allow). Two rules with the same tuple and the same outcome but different `grant` overrides (decision 23) use the smaller `cap`. `signpolicy` rejects a policy where an `allow` rule and a `refuse` rule have equal tuples and can both match the same chain shape.

**23. Rules may lower the grant cap.** (CG-10, revised by decision 24)

- Each signer rule may carry an optional `"grant": { "cap": "…" }`, which lowers the global `grant.cap` for grants offered from that rule's question. It must be ≤ the global cap. Presets above it are not offered, and a typed time above it is clamped to it. `lateOnce` and `untilLogout` stay global.
- Strict decode: unknown fields are an error, and so is a value above the global cap. Revision 3's `for` and `max` are gone, because grants no longer slide (decision 24). A policy that still has them fails `check`.

**24. Grant times are chosen by the person, are absolute, and have a hard cap.** (R4-1)

- **Choices**, in this order: `once`, `5 minutes`, `15 minutes`, `1 hour`, `until logout` (decision 26), plus a typed time. The presets are fixed in `internal/grant`. A preset above the cap is not offered, and `until logout` is offered only when `untilLogout` is true.
- **Typed time.** Lowercase it and remove spaces. It must match `^([0-9]{1,2}h)?([0-9]{1,3}m)?$`, with at least one part and a total above zero: `45m`, `2h`, `1h30m`. galley refuses to answer a form whose time entry does not match (galley item 5), and frisket parses it again with the same function. A typed time overrides the combo.
  - Unreadable or zero (only reachable with an old galley): **once**. That is logged, and the reply says "time not understood; allowed once".
  - Above the cap: clamped to the cap, and the reply says "8h is the most".
- **Absolute, not sliding.** A grant ends at a fixed boottime instant, `posted + chosen`. `posted` is when the question or the sudo dialog was posted. Use never extends it. This replaces revision 3's `Grant(k, slide, max)`, for two reasons:
  - a sliding end cannot be shown as a clock time;
  - a busy agent would keep a sliding grant alive until its cap.
- Counting from `posted` makes the clock times on the choices exact. A live row is answered within its deadline (90 s for the signer, 110 s for sudo), so at most that much of the chosen time is lost. A typed time shorter than the row's wait still allows the request that was asked about. Its grant is simply already over.
- **Cap.** `grant.cap` defaults to `8h` and may not exceed `24h`, so that a clock time plus "tomorrow" is never ambiguous. It is set in the signer policy and in `services.frisket.sudoGate.grant.cap`. Per-rule caps (decision 23) may only lower it.
- **Clock times.** Each preset's label carries its end, computed when the row is posted: `15 minutes (until 16:40)`, `until logout (at most until 00:25)`. The typed-time label names the cap's end: `… at most 8h, until 00:25`. When a grant is made, the reply states its end the same way: sudo prints "frisket-sudo: allowed `systemctl restart foo` for this claude until 16:40" (decision 27), and the journal record carries both the boottime end and the wall-clock end. ssh has no channel for such a reply, so for the signer the person sees the end on the label they picked, and a typed time's end only in the journal. The clock time is `time.Now()` plus the boottime that remains, so a clock change moves only the label, never the expiry (decision 14).
- Unusual, Cut and non-terminal SessionRoot chains stay ungrantable. Their question has no picker: `Allow once` / `Refuse`, as in revision 3.

**25. A grantable question carries the time picker as a galley form.** (R4-1)

- A grantable question is a `kind=forms` item (wire version 2) with exactly two fields:
  - a `combo` labelled "Allow for", holding the offered choices with `once` first;
  - an `entry` labelled "Or type a time (overrides the choice above): 45m, 2h, at most 8h, until 00:25".
- Its buttons are `Refuse` (cancel) and `Allow` (ok), and `default` is -1. The exact item is in "Service question wire format".
- Why a form, checked against galley's real code [H14, H15]:
  - `kind=question` has only buttons, and cannot carry a typed time;
  - an `extra` button answers no field values, so "Allow once" cannot be a button beside a picker. It is the combo's first value instead;
  - a forms combo is a non-editable dropdown, so the typed time needs its own entry;
  - `--entry` with values (an editable combo) would take presets and free text in one widget, but has no password field, so the sudo dialog could not use it. One shape for both is simpler;
  - `--list --radiolist` takes no typed value.
- An untouched combo is `once`, and a combo answer with no text counts as `once`. **ASSUMPTION-UNTESTED** that galley's `Gtk.DropDown` answers its first value when untouched; a galley e2e test pins it.

**26. "Until logout" ends with the graphical session, and at the cap at the latest.** (R4-1)

- When it makes such a grant, a service reads logind's `/run/systemd/users/<uid>` (`STATE=`, `DISPLAY=`) [H17] and records the display session id with the grant.
- The grant ends at the cap, or at the first `Use` or `Sweep` (every minute) where the file is unreadable or unparseable, `STATE` is neither `active` nor `online`, or `DISPLAY` names a different session. Every failure ends the grant, which only means more asking.
- The file's header says "private data, do not parse". sd-login's `sd_uid_get_display` reads the same file, and parsing it needs no new dependency. If systemd changes it, the VM test fails, and the fallback is logind over D-Bus (`github.com/godbus/dbus/v5`, a fourth dependency amending decision 10). **ASSUMPTION-UNTESTED** that both services can read it under their hardening and that a GNOME logout ends `DISPLAY`. Spike AP1 and the VM tests check this.

**27. sudo asks once: the askpass dialog carries the password and the time.** (R4-2)

- **Wiring.** `~/.claude/sudo-askpass.sh` (graphical-sudo, managed by T5) runs `exec /run/wrappers/bin/frisket-sudo-askpass "$@"` when that file exists and galley's services socket is present. It must `exec`, so that the askpass stays sudo's direct child [H16]. Otherwise it runs today's `galley --entry --hide-text` box unchanged.
- **The askpass** (`cmd/frisket-sudo-askpass`, a separate small binary rather than a `frisket-sudo askpass` subcommand, so that the setgid image holds no gate code) does this:
  1. Sends 'P' to the gate's askpass socket. The gate authenticates it (decision 28) and returns the dialog content, which it built from root-collected data: the requester chain and badges from the pending 'G' links, sudo's own argv from tag 'v' (sanitised: control and bidi characters escaped, cut at 1000 characters with "(cut)"), whether a time may be offered, the cap, the try count and the previous choice. A 'N' means "show the plain password box" (fallback below).
  2. Posts one form to galley's services socket as the askpass class (galley item 5b). The form has three fields, a password "Password for dan", the combo "Allow for" and the time entry, and two buttons, `Cancel` and `Allow`. `default` is `Allow`, so Enter after the password allows with the selected time, which is `once` unless changed. When no time may be offered (an unusual chain), the form has the password field only.
  3. On `Allow` with a non-empty password, it sends 'D' with the choice and waits up to 2 s for the gate's 'Y'. It then writes the password and a newline to stdout, the pipe sudo reads, and exits 0. Sending 'D' first means the dialog record exists before sudo can reach `check()`. If 'D' fails, the password is still written, and the 'A' simply has no dialog record (second question). An empty password sends no 'D'. It is written as an empty line, which pam_unix refuses.
  4. On `Cancel`, Escape or a withdrawn row, it writes nothing and exits 1, which sudo treats as ^C. galley's `locked` or `busy` also exits 1, saying "screen locked" or "galley busy" on stderr.
- **The password goes only to sudo's stdin.** It is never sent to the gate, logged, written to a file or put in the environment. The askpass zeroes its buffer after writing, and galley clears the field when it answers (as `bodies.js` does for hidden entries).
- **Approval with no second question.** When pam_unix accepted that password and the 'A' for the same `(pid, starttime)` arrives, the gate treats the dialog as the person's answer, under the conditions in "The gate's decision on 'A'", step 10. If they hold, it approves, records the grant for the chosen time and replies with its clock end. If not, it asks the plain question, whose text starts with the reason, for example "sudo resolved `/home/dan/bin/systemctl`, not what the password dialog showed".
- **Wrong password.** sudo runs the PAM stack once per try and forks a fresh askpass each time, up to `passwd_tries` (3) [H16]. Each try's 'G' refreshes the pending record. Each try's 'P' **clears** that sudo's dialog record, and only that try's own 'D' can set it again. So the 'A' can only use the dialog of the last try, whose password pam_unix accepted. If that try's 'D' was lost, there is no record and the question follows. The previous choice is kept in the pending record, not the dialog record. A retry's form says "That password was not accepted" and lists the previous choice first, so an untouched combo on a retry keeps what the person chose before.
- **No askpass ran** (sudo's own ticket, a grant let PAM through, `sudo -S`, or `-n`): there is no dialog record. A command that needs asking gets the plain question with the picker.
- **No late answers.** The askpass holds a pidfd for its parent (`pidfd_open(getppid())`, which needs no permission) and withdraws its row when sudo exits. It also gives up after 110 s, the gate's deadline (decision 7). The next sudo asks again.
- **stdout check.** The askpass refuses to start a dialog unless fd 1 is a pipe (`S_ISFIFO`) and it has no child processes at start. That catches the naive ways of stealing the password from a genuine dialog, but not a pipe whose reader has been double-forked away (residual risk S9).
- **Fallback, never trusted.** On 'N', or with the askpass socket absent, it posts today's plain password box to galley's user socket, as a plain client, and sends nothing to the gate. That covers terminal `sudo -A` (the PAM helper never sends 'G' with a tty), the gate disabled, and bob. If galley cannot be reached at all, it prints "frisket-sudo-askpass: galley is not running" to stderr and exits 1.
- **Shadow mode** (decision 21): the dialog is shown, with the line "shadow mode: this time is only recorded". The gate records the choice as a would-be grant for its log. The PAM helper still always exits 1.

**28. The askpass is identified by its group and its parent, never by its exe.** (R4-2)

- The gate cannot read `/proc/<pid>/exe`: it has no capability and `ProtectProc=invisible`. Reading exe needs `CAP_SYS_PTRACE` [spike: identity-vm, hardptrace vs dacread]. Giving the gate that capability would undo decision 4. What the uncapped gate under exactly this hardening does get, from `SO_PEERPIDFD` and `PIDFD_GET_INFO`, is mask 0x7: pid, ppid, the uids and gids, and the cgroup id. `/proc/<pid>` itself is invisible to it [spike: identity-vm, `hard` baseline: `mask=0x7 pid=1139 ppid=1138 ruid=1000 euid=1000 cgroupid=3222`, chain unreadable].
- So the askpass carries a **group** instead of an exe:
  - `frisket-sudo-askpass` is a NixOS setgid wrapper, `root:frisket-askpass`. Group `frisket-askpass` has gid 953 [H17] and no members, ever: an assertion over members, `extraGroups` and primary groups, like decision 2's for tss.
  - The askpass socket `/run/frisket-sudo-askpass/askpass.sock` is `0660 sudo-gate:frisket-askpass` in a root `0755` directory, so only a process whose egid is `frisket-askpass` can connect.
- The gate accepts a 'P' only when all of these hold:
  1. `SO_PEERCRED` names uid `forUser` and gid `frisket-askpass`;
  2. `PIDFD_GET_INFO` has the PID and CREDS bits, with ruid = euid = `forUser` and egid = `frisket-askpass` (decision 6: check the mask first);
  3. its `ppid` is the pid of a **pending sudo** (decision 16): a 'G' from root for this user, at most 10 minutes old, not yet consumed by an 'A'. With several pending records for that pid (pid reuse), only the newest counts;
  4. the parent is a setuid-root process of this user: `pidfd_open(ppid)` (no permission needed) and `PIDFD_GET_INFO` give euid 0 and ruid `forUser`. A process of dan's that took over a dead sudo's pid and forked the genuine askpass fails this, so it cannot get a genuine-looking dialog for that dead sudo's command;
  5. at most 4 dialogs are pending for that sudo's anchor (the asking cap). A fifth gets 'N' with "busy", and the askpass exits 1 with "too many sudo prompts waiting";
  6. a second `PIDFD_GET_INFO` on both pidfds after the lookup still has the PID bit, and the same ppid for the askpass.
- At 'D' it re-checks items 2, 4 and 6. A re-parented askpass (its sudo died) therefore records nothing.
- **No message on this socket names a pid.** The sudo is the kernel's `ppid`, so a time cannot be aimed at another sudo. A 'P' or 'D' carrying an 'S' tag, or any tag but the listed ones, gets 'N'.
- **Why the ppid is enough without the sudo's starttime.** The 'G' and the 'A' for `(pid, starttime)` both come from root. The dialog record is used only by an 'A' with the same 'S'. So that sudo was alive from 'G' to 'A', and since a pid cannot belong to two processes at once, the askpass's parent between them was that sudo. The ppid check also needs the askpass to be sudo's direct child, which H16 shows it is, and which the `exec` in `sudo-askpass.sh` keeps.
- **The genuine binary cannot be borrowed.** Running the wrapper from a shell gives a ppid that is not a pending sudo, so the gate refuses it and it falls back to the plain box on the user socket, with no reserved look. A setgid exec is non-dumpable and `AT_SECURE`, so dan-uid code cannot ptrace it or preload into it. **ASSUMPTION-UNTESTED** for the NixOS wrapper's exec of a static Go binary, including that Go's runtime keeps secure mode. Spike AP1 checks this.
- **Its inputs are fixed.** It reads no path from its environment. Its gate socket, galley socket, user and galley unit come from root-owned `/etc/frisket-sudo/askpass.json`. It ignores its argv (sudo's prompt, which `-p` lets the caller choose). It dials galley's services socket and applies the services' binder-cgroup check (`internal/galleyask`). So a `SUDO_ASKPASS` wrapper that sets `XDG_RUNTIME_DIR` or `GALLEY_SOCKET` cannot redirect it to a fake window.
- **It talks the galley wire itself, never the galley CLI.** The CLI prints a form's answer as fields joined by `|`, so a password containing `|` would be misread [H15]. The wire's `fields[]` array has no such problem.
- `go list -deps ./cmd/frisket-sudo-askpass` contains no `internal/sudogate`, `execrule`, `policy` or go-tpm.

**29. The password skip lasts as long as the time chosen with the password.** (R4-2; revises SK3's "within 1 h")

- Per anchor, the gate keeps `PasswordUntil`, a boottime instant. The PAM helper's 'G' gets 'Y' only when the anchor has a live grant (`AnyFor`) **and** now < `PasswordUntil`.
- How each kind of 'A' moves it:
  - **dialog-authenticated and approved** (decision 27): `max(PasswordUntil, posted + chosen)`. `once` adds nothing. `until logout` counts as the cap;
  - **password-authenticated another way** (`sudo -S`, the fallback box, a sudo ticket, or a dialog whose conditions failed): `max(PasswordUntil, now + 1h)` on receipt, which is revision 3's rule unchanged;
  - **grant-authenticated**: unchanged.
- So only a password typed together with a time in the genuine dialog can open the window for longer than an hour. A grant made by a plain question, whose Allow dan-uid code could forge, never widens it (SK3).
- A dialog record is discarded when its sudo is grant-authenticated. That can happen when a later try's 'G' gets 'Y' because another sudo opened the window meanwhile. A dialog whose password did not let its sudo in counts for nothing.

### Considered and rejected

| Option | Why it was rejected |
|---|---|
| Keeping ssh-tpm-agent | No session-bind. A global mutex held across askpass. Identifies peers by comm. Its `--swtpm` flag is an in-process cgo simulator [spike: tpm-keys]. It stays only as the escape hatch |
| Depending on `0x81000001` | The signer derives the H-2 ECC primary itself, which is deterministic [spike: tpm-keys (2)]. Using it is a G0 fallback only (EA9) |
| Caching key handles | A stale handle comes back with the same number. `/dev/tpmrm0` has 3 object slots per fd [spike: tpm-keys, sceptic] |
| keyfile's default template (no `noDA`) | Default keys fail with `TPM_RC_LOCKOUT` in DA lockout, and noDA keys still sign [H10]. Keys are emptyAuth, so DA protection buys nothing |
| Store-path globs in signer rules, and "outside `/nix/store` = unusual" | `nix-store --add` makes `/nix/store/<h>-openssh-10.5p1/bin/ssh` as dan [spike: evidence-audit, store-name-attack, sceptic-complexity] |
| Adding `/nix/var/nix/gcroots/auto` (nix-direnv roots) to the known set | The daemon builds whatever dan's flake says, so dan-uid code could build a fake `openssh-10.5p1/bin/ssh` and root it. That reopens F2 (CG-3) |
| Socket activation for the galley services socket, with a cgroup check | The client sees `systemd --user` as the peer, so the check fails for every answer (CG-1). PENDING G-P1 confirms |
| Dropping the galley peer check | The socket-rebind route becomes free (CG-1) |
| Holding anchor pidfds in the gate | The gate has no capability and cannot see dan's `/proc`. Passing pidfds over SCM_RIGHTS adds a tag and fd lifetime for no gain over a starttime match (CG-5) |
| CLOCK_MONOTONIC (Go's default) for grants | It stops in suspend, so grants would survive a 12-hour suspend (CG-4) |
| Question-as-authentication for sudo (no password on first use) | A galley Allow can be forged with zero human interaction (G1). The password needs a human at least once (SK3, verifier note 1). Revision 4's one dialog is not this: its approval counts only together with a password that pam_unix accepted (decision 27) |
| Sliding grants (revision 3's `slide` up to `max`) | A sliding end cannot be shown as a clock time, and a busy agent keeps it alive until the cap. Absolute ends instead (decision 24) |
| Grant time counted from the answer rather than from posting | The clock times on the choices would be wrong by up to the deadline. Counting from posting makes them exact, at a cost of at most 110 s (decision 24) |
| An "Allow once" extra button beside the time picker | galley answers an extra button with no field values [H14]. In the sudo dialog that would drop the password. `once` is the combo's first value instead (decision 25) |
| `--entry` with values (editable combo) as the picker | It has no password field, so the sudo dialog could not use it, and two shapes would be harder to test. Free text without the entry's own grammar check (decision 25) |
| `--list --radiolist` as the picker | It takes no typed time, and has no password field (decision 25) |
| The gate checking the askpass's exe | Needs `CAP_SYS_PTRACE` [spike: identity-vm], which decision 4 keeps off the gate. The setgid group plus the kernel's ppid identify it instead (decision 28) |
| The askpass naming its sudo's pid in its message | Anyone could name any pid. The gate takes the kernel's ppid from `PIDFD_GET_INFO` (decision 28) |
| The askpass parsing the galley CLI's output | Form fields are joined with `\|`, so a password containing `\|` is ambiguous [H15]. It speaks the wire (decision 28) |
| The askpass reaching the gate's root socket | Only root may reach it (decision 4). A second socket, reachable only with egid `frisket-askpass`, carries no chain and no pid (decision 28) |
| A sudo dialog answered late, after sudo exited | No password is ever kept, so nothing could verify a late answer. The row goes with sudo (decision 27) |
| Taking the dialog's time for an op-level grant | The dialog names "this command". An op scope would be wider than what the person saw (F6). Dialog grants are argv grants; op grants come only from a question that names the op |
| Fail-open on ECONNREFUSED or ENOENT | A crash loop trips the start limit, the socket fails and every connect is refused [spike: ops-socket-limit, evidence-audit startlimit]. With a fresh ticket that meant silent root [spike: sudo-vm Y4] |
| op-level grants by default | Coarse ops widen the person's consent (F6). argv grants are the default |
| Keeping gcr running as the gateway fallback | Keeps a silent ed25519 path to every host. A gateway-only key file is narrower (SK6, CF7) |
| Signer holding the ed25519 recovery key | It would turn the recovery key into a normal key (OPS-4) |
| Signer signing `ssh-rsa` (SHA-1) for the modem | SHA-1 signatures. The modem keeps its password (CG-8) |
| Separate-uid galley, or a window peer check as a boundary | A redesign. Listed as G1 |
| Root-owned `/run/galley-ask` with an fd hand-off | The drop-in route gets around it anyway (EA5) |
| A direct `frisket` flake input in nix-config | A second frisket would drift from chase's go.mod pin (CF8) |
| `scripts/switch.sh` as a guard | It does not exist, and a bare `nixos-rebuild` would bypass it (CF2) |
| Re-quoting argv into `execrule.Decide` | Wrongly allowed `time ls` and `LANG=C ls` [spike: policy-fit] |
| Trusting a path by prefix in sudo, or a non-clean path | `nix-store --add` fake `cat`, and `/run/current-system/sw/bin/../../../home/…/cat` both ran as root [spike: policy-fit, evidence-audit dotdot] |
| An env denylist | `LESSOPEN` ran code as root, and others slipped past [spike: policy-fit] |
| chase's Linux catalogue as the root catalogue | As root it allows `cat /etc/sudoers` and `less` [spike: policy-fit] |
| A Python sudo plugin | Not built into nixpkgs sudo, and there is a no-Python rule |
| Gating on `SUDO_ASKPASS` or `DISPLAY` | The caller chooses both. Gating is on the absence of `tty=` |
| Enforcing the sudo gate with no shadow phase | No data on the extra questions per day (CG-19) |

---

## Architecture

### Components and users

```
                      dan's desktop session (uid dan)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ galley window (galley.service, user)                                 │
  │   %t/galley/sock            0600  (dan's clients, socket-activated)  │
  │   /run/galley-ask/dan.sock  0666 in 0750 dan:galley-ask  (services,  │
  │                             bound by galley itself; decision 13)     │
  └──────────────▲──────────────────────────────────────▲────────────────┘
                 │ question/answer (galley wire)         │  binder's cgroup checked
   ssh-signer ───┘                                       └─── sudo-gate
  ┌─────────────────────────────┐            ┌─────────────────────────────┐
  │ frisket-signer              │            │ frisket-sudo (gate)         │
  │ user ssh-signer (951)       │            │ user sudo-gate (952), no caps│
  │ groups tss, galley-ask      │            │ group galley-ask            │
  │ CAP_SYS_PTRACE, seccomp     │            │ /run/frisket-sudo/gate.sock │
  │ /dev/tpmrm0 rw              │            │   (root 0700 dir)           │
  └──▲──────────────────────────┘            │ /run/frisket-sudo-askpass/  │
     │                                       │   askpass.sock 0660         │
     │                                       │   :frisket-askpass          │
     │                                       └──────────▲───────▲──────────┘
     │ ssh-agent protocol (peer uid == dan)  framed     │       │ 'P'/'D' (peer egid
     │ /run/frisket-signer/agent (dan 0600)  (uid 0)    │       │  frisket-askpass)
  ┌──┴───────────────┐   ┌──────────────────┐   ┌───────┴───────┴───────────┐
  │ ssh, git, scp    │   │ frisket.service  │   │ setuid sudo:              │
  │ (graphical       │   │ main process     │   │  pam_exec frisket-sudo-pam│
  │  session only)   │   │ (system, User=dan)│  │  frisket_approval.so      │
  └──────────────────┘   └──────────────────┘   │  └▶ frisket-sudo-askpass  │
                                                │     (setgid, sudo's child;│
                                                │      galley askpass class)│
                                                └───────────────────────────┘
        both services read /run/frisket/known-store-paths (root, activation)
```

### Data flow: an SSH login

```
ssh (dan) ──connect──▶ /run/frisket-signer/agent
   signer: SO_PEERCRED uid == forUser? (else refuse, log)          [decision 17]
           SO_PEERPIDFD → PIDFD_GET_INFO → /proc chain (exe, maps via CAP_SYS_PTRACE)
           → known-set membership, Terminal test, Remote test
ssh ──EXTENSION session-bind@openssh.com(hostkey,sid,sig,fwd)──▶ signer
   signer: verify sig over sid; push {hostkey,sid,fwd} on this connection
ssh ──REQUEST_IDENTITIES──▶ signer: list keys (no prompt)
ssh ──SIGN_REQUEST(key,data,flags)──▶ signer
   parse: userauth? sid == last bound sid? embedded hostkey == bound key?  (else refuse)
   decide: trusted? userns? remote? forwarded? grant/once? rule? → allow | refuse | ask
   ask: galley (binder cgroup checked), deadline 90s, POLLRDHUP, no global lock;
        "locked" → refuse at once
   observe mode: ask → allow + log observed:true
   allow: open tpmrm0 → CreatePrimary(H-2) → Load → Sign → Flush → close → verify → reply
   log: one structured journal record per decision (EA5)
```

### Data flow: an agent's `sudo systemctl restart foo` with no tty

```
claude ─▶ bash -c (own session, no ctty [H3]) ─▶ sudo (setuid; SUDO_ASKPASS=~/.claude/sudo-askpass.sh, DISPLAY set)
 sudoers check_policy (resolves the command, then authenticates; up to passwd_tries tries [H16])
   each try, PAM auth: [frisket-grant] pam_exec seteuid frisket-sudo-pam
      PAM_TTY set or remote chain? exit 1.  PAM_USER==PAM_RUSER==dan, SERVICE==sudo? else exit 1.
      chain (root) + 'S'(sudo pid, starttime) + 'v'(sudo's argv) → gate "G"
         (gate keeps a pending-sudo record for 'S'):
         live grant for anchor (peek, incl. once-grants) and now < PasswordUntil(anchor)?
                                          Y: exit 0 (no password; gate records 'S' as grant-auth)
                                          N: exit 1 → pam_unix → askpass
      (shadow mode: always exit 1)
   pam_unix → askpass: sudo-askpass.sh ─exec▶ /run/wrappers/bin/frisket-sudo-askpass
      (setgid frisket-askpass; sudo's direct child)
      → askpass.sock "P" (no pid in it). gate: peer gid/egid frisket-askpass, ppid (PIDFD_GET_INFO)
        is a pending sudo → ← 'Y' title, chain, sudo argv, offer, cap   ('N' → plain box, no time)
      → galley services socket, askpass class (binder cgroup checked):
        [Password ____] [Allow for: once ▾] [Or type a time ____]   Cancel / Allow
      → "D" choice ← 'Y'   then the password → stdout pipe → sudo, and nowhere else
      pam_unix checks it; a wrong one → next try, fresh askpass, dialog record replaced
   timestamp written (even if approval later refuses) [sudo-vm Y4]
 approval open(): tty= present or remote chain? return 0.  else return 1
 approval check(): dir check → connect (any failure: deny "gate not running"; shadow: approve)
      chain + 'S' + command_info + run_argv + run_envp → gate "A"
      gate: 'S' grant-auth? / dialog record for 'S'? / else password another way (hold 1 h);
            clean trusted path, env allowlist, PATH, DecideWords(root catalogue), grant
      → dialog record and what runs is what it showed? allow; grant until posted+chosen;
            PasswordUntil = posted+chosen                            (no second question)
      → else ask? galley form "Allow for ▾ / or type a time", Refuse / Allow (110s, hang-up aware)
      ← 'Y'+"allowed … until 16:40" (SUDO_CONV_INFO_MSG) | 'N'+message (SUDO_CONV_ERROR_MSG)
                                                     (shadow: logged, always approve)
```

---

## frisket-signer

### Layout

`cmd/frisket-signer/main.go` follows `cmd/frisket/main.go`: a FlagSet per subcommand, `frisket-signer <sub>: <err>` with exit 1, slog JSON, and `var version`. Subcommands:

- `serve`: the daemon. It takes its listener from `internal/sdnotify.Listen()`, using the fd named `agent`.
  - Without that fd it exits non-zero ("must be started by frisket-signer.socket") and never binds the path itself.
  - It calls `sdnotify.FromEnv().Ready(status)` after the per-key self-test (CF12).
- `keygen -type ecdsa|rsa -comment C -out DIR`: writes `ssh-tpm-<type>.tpm`, `.pub` and `.fp`. The `.fp` holds `ssh.FingerprintSHA256(pub)`, which is `SHA256:` plus 43 characters, matching chase's `fingerprint` type (CF6, EA11).
- `pub [-fp] FILE.tpm`: prints the public key, or its fingerprint. It reads the TPM2B_PUBLIC from the blob and needs no TPM.
- `check -policy FILE [-known FILE]`: strict decode. It also decides `requester-json destination` lines from stdin, offline. It runs in `system.checks`.
- `selftest`: loads every configured key and signs once. Run by the health timer.
- `alert -text T`: posts a one-button galley question ("Understood") and logs at error level. Used by `OnFailure=` units. A one-button question stays within decision 9.

Packages:

- `internal/tpmkey`: the only importer of go-tpm. Surface: `Generate(open, alg, comment)`, `Load(file) (*Key, error)` and `(*Key).Signer(open) ssh.Signer`.
- `internal/agentsrv`: a per-connection `ExtendedAgent`, the session-bind state, and the userauth and SSHSIG parsers.
- `internal/signpolicy`: the signer's own matcher. Chain rules cannot be encoded as execrule words [spike: policy-fit].

### Keys

**Creation.** keygen creates the key with **noDA** set [H10] (OPS-8):

```go
ph, _ := keyfile.GetParentHandle(sess, tpm2.TPMRHOwner, nil)   // H-2 ECC primary, flushed after
tpm2.Create{ParentHandle: *ph, InPublic: tpm2.New2B(tmpl)}      // keyfile default attrs + NoDA
k := keyfile.NewTPMKey(keyfile.OIDLoadableKey, pub, priv)        // emptyAuth, no policy
```

- The attributes are keyfile's defaults (fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, sign, decrypt) plus NoDA. RSA uses the same template with an RSA-2048 public area.
- Sign and decrypt are kept, because rsa-sha2-512 uses `RSA_Decrypt` [spike: tpm-keys (1)].
- **ASSUMPTION-UNTESTED:**
  - a noDA RSA key, since H10 covered ECC only;
  - stock ssh-tpm-agent 0.9.0 loading noDA key files. Spike N1 (pre-T3) and the signer VM test cover this.
  - If the interop fails, fall back to the default template and accept the lockout risk. The escape hatch matters more.

**Keygen runs as `ssh-signer` with `tss`** through the `frisket-signer-keygen@` oneshot. `sudo -u ssh-signer` would fail, because tss comes only from the unit [spike: identity-vm]. Output goes to `/var/lib/frisket-signer/new/`. The person copies the `.tpm`, `.pub` and `.fp` files into `nix-config/admins/<host>/`.

**Loading** (CF6):

- `serve -key FILE…` takes per-file store paths. There is no sibling `.pub`.
- The public key comes from the blob, and its fingerprint must appear in the policy's `keys` map, which nix-config builds from the same committed `.fp` files.
- Each key signs once and is verified before `READY=1`. A key that fails is dropped and logged.
- `TPM_RC_INTEGRITY` is reported as "TPM cleared or a different chip".
- **Zero keys loaded:** `serve` stays up. It sends `READY=1` with `STATUS=degraded: 0 keys (TPM cleared or different chip? see docs/signer.md)`, logs at error level, and serves only `REQUEST_IDENTITIES` (empty). The health timer's `selftest` fails, and `OnFailure=` raises an alert (OPS-1, OPS-4).

**Signing contract** (CF5):

```go
func (s *signer) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
    sig, err := s.once(r, d, o)
    if err != nil && !isIntegrity(err) && !isLockout(err) { sig, err = s.once(r, d, o) } // retry on a fresh fd
    return sig, err
}
func (s *signer) once(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
    t, err := s.open()              // linuxtpm.Open("/dev/tpmrm0") in prod, linuxudstpm in tests
    if err != nil { return nil, err }
    defer t.Close()                 // the kernel flushes anything left on this fd
    ks := keyfile.NewTPMKeySigner(s.k, noAuth, func() transport.TPMCloser { return t }, nil)
    return ks.Sign(r, d, o)         // the closure returns the SAME fd for both calls inside keyfile.Sign
}
```

- Never pass an open-per-call closure to `NewTPMKeySigner`. It calls the closure twice and closes neither result.
- keyfile's package-global `signerMutex` serialises TPM I/O on this path. No lock is ever held across a prompt.
- Use go-tpm's `linuxtpm`, which polls. Never hand-write device I/O: with a non-blocking fd and no poll, 279 of 300 reads returned 0 bytes [spike: identity-vm sceptic].
- RSA flags map 2 → rsa-sha2-256 and 4 → rsa-sha2-512. Flags 0 (`ssh-rsa`, SHA-1) are refused.
- Every signature is verified against the key's public key before it is returned.

**Error mapping:**

- `TPM_RC_INTEGRITY` → "TPM cleared or a different chip".
- `TPM_RC_LOCKOUT` → "TPM is in dictionary-attack lockout (TPM auth failed too many times); signing resumes when it clears". No retry (OPS-8). Keys made by stock `ssh-tpm-keygen` lack noDA, so they can still hit this.
- Anything else → retry once on a fresh fd. Whether hibernate is a TPM Reset is **ASSUMPTION-UNTESTED**, and moot on this stateless path.

**Latency** is unknown on PTT. swtpm p50 is 1.6–1.8 ms, and the qemu TPM 68–81 ms [spike: tpm-keys (5)]. If PTT is above about 150 ms, add caching as a separate contract:

- one long-lived fd per key, in a struct;
- flush the parent right after Load;
- reload on any error;
- never use `keyfile.LoadKey`, which leaks the parent on failure.

### Agent protocol

`agent.ServeAgent` runs once per connection, with a fresh `connAgent{peer, binds []bind}`. A connection from a peer whose uid is not `forUser` is closed after one error log line, before any message is read (decision 17). Each connection handler runs under `recover()`: a panic refuses that request and never exits the process (OPS-1).

| Message | Behaviour |
|---|---|
| `REQUEST_IDENTITIES` | List the loaded keys. No prompt. Logged with the requester |
| `SIGN_REQUEST` | Decide (below) |
| `EXTENSION session-bind@openssh.com` | Parse and verify `hostkey.Verify(sid, sig)`. Failure is returned [spike: session-bind T1]. Append to binds (max 16) |
| Other extensions | `ErrExtensionUnsupported` |
| `ADD_IDENTITY`, `REMOVE_*`, `LOCK`, `UNLOCK` | Refused |

Request classes [spike: session-bind]:

1. **Bound userauth.**
   - Require `sid == binds[last].sid`. For a hostbound request, also require the embedded hostkey to equal `binds[last].hostkey`.
   - A mismatch **returns an error**, in every mode including observe. Test T3 must get "agent refused operation".
   - Any `fwd=1` bind on the connection marks it forwarded.
2. **Unbound userauth.**
   - The destination is unknown, and an embedded hostkey is shown only as "claims <fp>".
   - A peer exe from an `openssh-<8.9` store path is treated as possibly forwarded.
3. **SSHSIG.** Parse the magic, namespace and hash, and show the namespace. **ASSUMPTION-UNTESTED**; the unit test uses real `ssh-keygen -Y sign` output.

Anything else is refused.

### Requester identification (`internal/peer`, shared)

**Collection.**

- `SO_PEERCRED` and `SO_PEERPIDFD` at accept, then `PIDFD_GET_INFO` (`0xC040FF0B`).
- Walk `/proc/<pid>/{stat,status,cmdline,exe,cgroup,ns/user}` up the ppids, to depth 16, pid 1, or the first unreadable link.
- Re-check the pidfd after the walk. A short or orphaned chain is `Cut` and never matches a grant or an allow rule [spike: identity-vm].

**Known set.**

- The set is loaded from `/run/frisket/known-store-paths` (format in decision 12) and re-read when its mtime changes. A bad reload keeps the previous set.
- `Known(path)` takes the realpath's `/nix/store/<hash>-<name>` root and checks it against the set.
- `SameName(rendered, exe)` implements decision 19: true if the exe's store root is known and has the same `<name>` and relative path as the rendered path.

**Unusual** (flagged; no time picker; never matches an allow rule or a grant). Applied to every link from the leaf up to and including the anchor:

- an exe that is not `Known`, including anything outside the store (badge reason `devshell` when its store root is not known but is the target of a `/nix/var/nix/gcroots/auto` root, else `not-known`);
- an exe ending in `(deleted)`;
- a `Cut` chain;
- a `systemd --user` root;
- **maps check** (signer only), on the leaf and on every link of a Terminal shape:
  - any executable file mapping whose store root is not `Known`;
  - any executable mapping outside the store;
  - any anonymous executable mapping other than `[vdso]` and `[vsyscall]`.

  This catches the real kgx or ssh run with `LD_PRELOAD` or from a memfd. The anonymous-mapping test is **not** applied to anchors such as claude, which JITs [H4].

**Anchor.**

- The anchor is the nearest ancestor whose exe basename is not in the transient set (`bash sh zsh fish dash env timeout nice nohup setsid script sudo ssh git`). It is identified by `(pid, starttime, exe)`.
- Host Claude Code resolves as `ssh ← git ← bash -c ← .claude-unwrapped`, so the anchor is the claude process [H2].
- A desktop-launched app resolves as `ssh ← git ← <app>`, so the anchor is the app (decision 18). PENDING K2 for the real shapes.

**Terminal=true** (SK2, EA4), for the terminal rule and tab grants. All of these must hold:

1. The link directly below the configured terminal server (exact path, e.g. `…-gnome-console-50.0/bin/.kgx-wrapped`) is a configured interactive shell (exact path, e.g. `…-bash-interactive-5.3p9/bin/bash`). Both match under decision 19.
2. That shell's cmdline is exactly its argv0, or `-bash`: no `-c`, `-s`, `-i`, `--rcfile`, `--init-file` or script argument. It is a session leader (`session == pid`) with a pts `tty_nr` [H2].
3. The terminal server's own parent is `systemd --user`.
4. The leaf shares the shell's `tty_nr`. It is in the foreground job (`pgrp == tpgid`) and does job control (`pgrp != sid`).
5. Every link between the shell and the leaf has an exe that is `Known` and a basename in `between` (`ssh git scp sftp rsync`).
6. The shell is at least `minShellAge` (5 s of boottime) old. This rules out a window opened just for this request.
7. The maps check passes.

What this means for real shapes:

- An agent's commands never pass: they have their own session and no tty [H3], and claude and `bash -c` sit in between.
- `kgx -- ssh`, `kgx -- bash -c …` and `kgx -- git push` fail test 1 or 2. They become SessionRoot with Terminal=false.
- A devShell `git` fails test 5, so the chain is unusual (decision 18).

For a Terminal chain, the **anchor is the tab's shell**. A grant is then per tab, and a `kgx -- cmd` window can never inherit it (EA7).

**SessionRoot** (no Terminal): the anchor is pid 1, `systemd --user`, or the terminal server. It never matches allow rules or grants and is badged "launched through <unit/terminal>". A re-parented `ssh -f` or ControlMaster lands here or in Cut (CG-9).

**Remote:** a link that is an `sshd-session` at the exact openssh path, running as the user, whose parent is a uid-0 `sshd-session` at the same path. **ASSUMPTION-UNTESTED** that this is the exact privsep shape of OpenSSH 10.5. Spike R1 (VM) records it.

**Foreign user namespace:** refused outright.

### Destination

- Names come from `/etc/ssh/ssh_known_hosts` (NixOS, unhashed) plus the policy's `hosts` map [spike: session-bind].
- A host key maps to a set of names. Grants key on the host-key SHA256 fingerprint, and names are for display only. An unknown key shows as "unknown host SHA256:…".
- nix-config adds `server` (10.0.0.4) to `programs.ssh.knownHosts`.

### Policy (`/etc/frisket-signer/policy.json`, strict decode, rendered by nix-config)

```json
{
  "mode": "observe",
  "forUser": "dan",
  "keys": { "ecdsa": "SHA256:<from admins/<h>/ssh-tpm-ecdsa.fp>", "gateway": "SHA256:<…>" },
  "known": "/run/frisket/known-store-paths",
  "trusted": [ { "name": "frisket", "unit": "frisket.service", "user": "dan",
                 "exe": "/nix/store/<hash>-frisket-<ver>/bin/frisket", "keys": ["ecdsa", "gateway"] } ],
  "terminal": { "server": "/nix/store/<hash>-gnome-console-50.0/bin/.kgx-wrapped",
                "shells": ["/nix/store/<hash>-bash-interactive-5.3p9/bin/bash"],
                "between": ["ssh", "git", "scp", "sftp", "rsync"], "minShellAge": "5s" },
  "sshdSession": "/nix/store/<hash>-openssh-10.5p1/libexec/sshd-session",
  "hosts": [ { "name": "server", "keys": ["SHA256:…"] } ],
  "rules": [
    { "name": "terminal ssh to a known host",
      "leaf": ["/nix/store/<hash>-openssh-10.5p1/bin/ssh"], "terminal": true,
      "destination": ["known"], "outcome": "allow" },
    { "name": "claude to github",
      "leaf": ["/nix/store/<hash>-openssh-10.5p1/bin/ssh"],
      "anchor": ["/nix/store/<hash>-claude-code-2.1.291/bin/.claude-unwrapped"],
      "destination": ["github.com"], "outcome": "ask",
      "grant": { "cap": "1h" } }
  ],
  "unmatched": "ask", "unbound": "ask", "forwarded": "refuse", "remote": "refuse", "sshsig": "ask",
  "grant": { "cap": "8h", "untilLogout": true, "lateOnce": "15m" }, "deadline": "90s"
}
```

Matching:

- Exe fields are exact paths, matched under decision 19, and `*` inside `/nix/store/` is a compile error.
- `"known"` means the host key is in `ssh_known_hosts` or `hosts`. A named destination matches by any of the host key's names.
- The most specific rule wins, by the tuple in decision 22. On a tie, the stricter outcome wins.
- An unusual chain can never get `allow` from a rule.
- A rule's `grant.cap` lowers the global cap for grants offered from its question (decision 23).
- `grant.cap` must be ≤ `24h`. `check` rejects a larger one, and any `for` or `max` left over from revision 3 (decision 24).

Decision order:

0. Peer uid ≠ `forUser` → refuse, logged (decision 17).
1. Bind mismatch, or a dead peer → refuse.
2. Trusted (decision 5) → allow, logged with frisket's route identity.
3. Foreign userns → refuse.
4. Remote → `remote` (default refuse, **immediately**, with the log line "remote sessions are not served"; never asked of a distant window) (OPS-2).
5. Forwarded → `forwarded`.
6. Once-grant or live grant (not unusual, not a non-terminal SessionRoot, same anchor triple) → allow. A once-grant is consumed. A normal grant is left as it is: it ends at its fixed time (decision 24).
7. Rule → its outcome.
8. `unmatched` / `unbound` / `sshsig`.

**Observe mode** (SK7):

- Every `ask` outcome is answered allow and logged with `observed:true`, plus the anchor, destination, key, class, unusual reasons, and whether a grant would have covered it.
- Steps 0, 1, 3, 4 and 5 are enforced in every mode.

### Grants (`internal/grant`, shared)

- `Key{Service, Anchor{Pid, Start, Exe}, Target}`.
  - Signer target: host fingerprint plus key fingerprint.
  - sudo target: `argv:<sha256 of resolved program + run_argv[1:]>` by default, or `op:<id>` for ops marked op-grantable (F6).
- All times are boottime durations (decision 14).
- `Grant(k, until, session)` ends at the boottime instant `until` = `posted + chosen`, where the chosen time is at most the cap (decision 24). Use never extends it. Revision 3's sliding `Grant(k, slide, max)` is gone. A new grant for a key that already has one keeps the later end.
  - `session` is nil, or the display session for an "until logout" grant, which also ends when that session does (decision 26).
  - The person's choice arrives as a `grant.Choice`, from `internal/galleyask` or from the askpass's 'D'. `grant.ParseTyped` is the one parser for typed times. galley's window applies the same grammar, pinned by shared vectors in galley's `wire/testdata/times.txt`.
  - `Expiry(k)` returns the boottime end and the wall-clock end, for the reply and the journal.
- `GrantOnce(k, ttl)`: consumed by the first `Use(k)` that matches. It expires after `ttl` (15 min).
- `AnyFor(service, anchor)` peeks at normal and once grants without consuming them. The PAM password skip uses it, together with `PasswordUntil` (decision 29).
- The sudo gate's pending-sudo and dialog records live in `internal/sudogate`, not here. They are keyed on 'S' and expire in boottime.
- Liveness is the anchor-triple match plus expiry (decision 15). `Sweep()` drops expired entries and "until logout" grants whose session has ended. It never reads `/proc`.
- Grants are in memory only. A restart costs at most one prompt per active anchor and never loosens anything. The default restart-on-switch is kept, because a stale signer after a switch is worse (SK7).

### Asking (`internal/galleyask`, shared)

- `Ask(ctx, Question)` dials the configured services socket and sends a `kind=question`, or the time-picker `kind=forms` for a grantable question (decision 25; wire format below).
- **Before trusting any answer**, the peer must have uid == the configured user and a `PIDFD_GET_INFO` cgroupid equal to the inode of `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/app.slice/galley.service`. Under decision 13 the peer is galley's own process, because galley bound the socket.
  - Anything else gives `ErrNobody` and an error log naming the peer's cgroup and pid.
  - This is a bar-raiser against socket rebinding, not a boundary (EA5).
  - PENDING G-P1 for the exact peer seen on the host.
- Closing the connection withdraws the row.
- EOF, `ENOENT`, `ECONNREFUSED`, a wrong peer, `busy` and `locked` all mean nobody to ask (`ErrNobody`, or `ErrLocked` for the message). ENOENT without linger is **ASSUMPTION-UNTESTED** and is covered by the VM test.
- The question includes:
  - the chain (exe and argv, cut to 1000 characters and sanitised like `modules/chase/asker.nix`);
  - the badges (unusual + reason, session root, launched through terminal, unbound, forwarded, inside frisket.service);
  - the destination names and fingerprint;
  - the key and class;
  - "waiting until HH:MM:SS";
  - the scope a grant would have, named: "this host from this tab", "this exact command from this claude", or "any '<op title>' from this claude".
- **A grantable question is the time-picker form** (decision 25): the combo "Allow for" (`once`, then the presets up to the cap, each with its clock end, then `until logout` if enabled), an entry for a typed time, and the buttons `Refuse` and `Allow`.
- **An ungrantable question** (unusual, Cut, non-terminal SessionRoot) is `kind=question` with `Allow once` and `Refuse`.
- The scope does not travel through galley. galley returns the field texts or the button index, and the caller maps them back to what it offered. A combo text it did not offer counts as `once` and is logged as a protocol error. The scope and the chosen time go into the log record and, for sudo, the reply message.
- While waiting, poll the requester connection for `POLLRDHUP`. The deadline still applies [spike: session-bind].
- **Late rows:** "Requester gone. Allow once lets this exact request through once if retried within 15 min." A late row is a new row, so its clock times are computed afresh. A late Allow with a time is a normal grant (decision 7).
- **Concurrency.**
  - No global lock.
  - The same `(anchor, target)` shares one pending decision.
  - At most 4 pending per anchor; the excess is refused at once.
  - Each refusal costs 5s of PerSourcePenalties (N2).
- **Nobody to ask:** trusted requesters and allow rules pass, and everything else is refused.
- **Audit:** every decision emits one structured journal record under the service uid. It names the requester chain, anchor, destination or command, outcome, source (rule, grant, once, trusted, observed, shadow, or galley answer), and the galley peer's pid and cgroup. A unit test asserts a record for every outcome path (EA5).

#### Service question wire format (fixed interface, T1 item 1 deliverable) (CG-16)

The service sends one `wire.Hello` line, with `Galley` set to `wire.Needs(item)`: 1 for the ungrantable question, 2 for the form [H15].

An **ungrantable** question (unusual, Cut, non-terminal SessionRoot):

```json
{"galley":1,"item":{
  "kind":"question",
  "title":"ssh to github.com",
  "text":"<plain text body, no markup>",
  "buttons":[
    {"answer":"extra","index":0,"label":"Allow once","underline":-1},
    {"answer":"cancel","label":"Refuse","underline":-1}
  ],
  "default":-1}}
```

A **grantable** question, the time-picker form (decision 25). The clock times are filled in when it is posted. Presets above the cap are left out, and `until logout` only when `untilLogout` is false:

```json
{"galley":2,"item":{
  "kind":"forms",
  "title":"ssh to github.com",
  "text":"<plain text body, no markup; ends with the scope, e.g. 'A grant covers this host from this claude.'>",
  "buttons":[
    {"answer":"cancel","label":"Refuse","underline":-1},
    {"answer":"ok","label":"Allow","underline":-1}
  ],
  "default":-1,
  "forms":{"fields":[
    {"kind":"combo","label":"Allow for",
     "values":["once","5 minutes (until 16:30)","15 minutes (until 16:40)","1 hour (until 17:25)",
               "until logout (at most until 00:25)"]},
    {"kind":"entry","label":"Or type a time (overrides the choice above): 45m, 2h, at most 8h, until 00:25"}
  ],"dateFormat":"%x"}}}
```

The form is the item galley's own parser makes from `galley --forms --add-combo 'Allow for' --combo-values 'once|5 minutes (until 16:30)|…' --add-entry 'Or type a time …' --ok-label Allow --cancel-label Refuse`, with `key`, `icon`, `markup` and `default` then set as the service rules below require. Both that and the hand-written service shape pass `validate.js` at version 2 [H15].

- `markup` is never set, `icon` is never set (the window forces the service icon), `key` is never set (no single-key press), and `default` is always -1 (Enter presses nothing).
- Ungrantable: `Question.Buttons[0]` is `Allow once` (`{"answer":"extra","index":0}`), and the last button is always Refuse (`{"answer":"cancel"}`).
- Grantable: always exactly these two buttons and two fields. The combo's first value is always `once`.
- The client never sends `caller`. The window sets `item.caller` after `validate()`, and a `caller` field from a client is a validation error.

The window answers with one `wire.Answer` line:

| Answer line | `galleyask` result |
|---|---|
| `{"answer":"extra","index":0}` (ungrantable) | Allow once |
| any other `extra` index | Refuse, logged as a protocol error |
| `{"answer":"ok","fields":[{"text":C},{"text":T}]}` (grantable) | Allow. `T` non-empty: the typed time (`grant.ParseTyped`, clamped to the cap; unreadable is once). Otherwise `C` mapped back to the offered choice. `C` absent or not offered: once |
| `{"answer":"cancel"}`, `{"answer":"close"}` (Escape), `{"answer":"timeout"}` | Refuse |
| `{"answer":"ok"}` on the ungrantable question, or an `ok` with the wrong number of fields | Refuse, logged as a protocol error |
| `{"error":"busy"}` | `ErrNobody`, reason `busy` |
| `{"error":"locked"}` | `ErrLocked` (decision 20) |
| any other `error` | `ErrNobody`, reason logged |
| EOF or a malformed line | `ErrNobody` |

- The window never withdraws a service row on its own. A row ends with an answer, or with the client closing the connection.
- Golden tests: `wire/testdata/service-question.json`, `service-question-times.json`, `askpass-form.json`, `service-answers.jsonl` and `times.txt` (typed-time vectors, each with its value or "invalid") live in galley. frisket's `internal/galleyask` test encodes the same Questions and compares them byte for byte with copies pinned at the same pseudo-version, decodes every answer line, and runs `grant.ParseTyped` over every vector. The goldens use a fixed clock for the labels.

**The sudo dialog** (decision 27) is posted by `frisket-sudo-askpass` as the askpass class (galley item 5b), not by a service:

```json
{"galley":2,"item":{
  "kind":"forms",
  "title":"sudo systemctl restart foo",
  "text":"<chain and badges from the gate, then sudo's argv, folded like today's askpass; plain text>",
  "buttons":[
    {"answer":"cancel","label":"Cancel","underline":-1},
    {"answer":"ok","label":"Allow","underline":-1}
  ],
  "default":1,
  "forms":{"fields":[
    {"kind":"password","label":"Password for dan"},
    {"kind":"combo","label":"Allow this command from this claude for",
     "values":["once","5 minutes (until 16:30)","15 minutes (until 16:40)","1 hour (until 17:25)",
               "until logout (at most until 00:25)"]},
    {"kind":"entry","label":"Or type a time (overrides the choice above): 45m, 2h, at most 8h, until 00:25"}
  ],"dateFormat":"%x"}}}
```

- `default` is `Allow`, so Enter after typing the password allows, with `once` unless the combo was changed. galley presses the default on Enter in forms too [H14].
- The answer is `{"answer":"ok","fields":[{"text":PASSWORD},{"text":C},{"text":T}]}`. The askpass reads it from the wire and never from the CLI's `|`-joined output [H15].
- When no time may be offered, the form has only the password field. When the gate said 'N', the askpass posts today's `kind=entry`, `hidden` box to the user socket instead, as a plain client.

### The gateway key

Order of preference, decided at M2 (SK6, CF7):

1. **ECDSA** if the gateway's dropbear accepts `ecdsa-sha2-nistp256`. Then there is no RSA key, and no raw `RSA_Decrypt` exposure.
2. **RSA-2048** with rsa-sha2-256 (`admins/<host>/ssh-tpm-rsa.*`). Dropbear acceptance is **ASSUMPTION-UNTESTED**. Legacy `ssh-rsa` cannot be signed.
3. Neither works: a **gateway-only** unencrypted ed25519 key file for chase's `hosts.gateway.keyFile`, authorized only on the gateway. gcr still goes off. This leaves a silent path for dan-uid code to the gateway alone, not to every host, and it is documented.

`sshSigner.gatewayOnTpm` stays false until M2 proves option 1 or 2 through the signer.

### Hosts that do not use the signer (CG-8)

- **modem** (192.168.1.1, Zyxel): it takes no key [H11], and it would need `ssh-rsa` (SHA-1) anyway. It keeps its password, through the `modem` wrapper's askpass and through chase's `passwordFile`. T5 sets `PubkeyAuthentication no` and `IdentityAgent none` on its block, so the signer is never even asked for identities.
- **mac** (dan-mac): its `authorized_keys` is managed by hand. M2 adds the TPM pubs there by hand. Until that cell passes, T5 renders `IdentityFile ~/.ssh/id_ed25519`, `IdentitiesOnly yes` and `IdentityAgent none` for it, so ssh asks for the passphrase in the terminal. With gcr off there is no cache.
- Every host that uses the signer gets `IdentityFile <store path of admins/<this host>/ssh-tpm-ecdsa.pub>` and `IdentitiesOnly yes`. So ssh offers only the TPM key and never silently falls back to `id_ed25519` (CG-8). Those hosts are `gateway` (when `gatewayOnTpm`, with the gateway key's pub), `server`, `github.com`, and every other host in the `hosts` list.

---

## frisket-sudo

### Pieces

- `sudo/frisket_approval.c` (~240 lines), `sudo/frisket-sudo-pam.c` (~140), and the shared `sudo/chain.c` (including the remote-chain test and the 'S' tag) and `sudo/wire.c`.
  - Exported as `lib.sudoRoot`, a callPackage function taking `{ stdenv, sudo }`. It builds against `sudo.src`'s `sudo_plugin.h` with `-Wall -Wextra -Werror -fvisibility=hidden` (CF3).
  - `passthru.symbol = "frisket_approval"` and `passthru.sudoVersion = sudo.version`.
  - The C only collects and frames. **All parsing and policy is in Go.**
- `sudo/frisket-sudo-check-plugin.c` (~40 lines): `dlopen(RTLD_NOW)`, `dlsym(symbol)`, then checks type 4, the API major version, and the sudo version recorded at build time against its argument. It runs in the package's `installCheckPhase` and in the sudo.conf derivation (SK8).
- `show_version` prints `frisket approval <version> (sudo <sudoVersion>) mode=<mode>`.
- `cmd/frisket-sudo` (Go):
  - `serve` takes the fds named `gate` and `askpass` via `sdnotify.Listen()`, refuses to start without `gate`, and is Ready after the rules load (CF12). Without `askpass` it serves the gate alone and logs that the one dialog is off. Flags `-grant-cap 8h -until-logout` (decision 24);
  - `check -rules FILE… [-grant-cap D]` decides argv lines offline and runs in `system.checks`. It rejects a cap above `24h`;
  - `alert`.
- `cmd/frisket-sudo-askpass` (Go, CGO off, about 300 lines): the askpass of decision 27, installed only through the setgid wrapper (decision 28). It imports `internal/galleyask`, `internal/grant` (presets and `ParseTyped`) and `internal/sudowire`, and nothing of the gate.
- The root catalogue ships as `${frisket-sudo}/share/frisket-sudo/operations.json`. nix-config may add a second `-rules` file (CF10).

### When it is involved

| Situation | Plugin | PAM helper | Result |
|---|---|---|---|
| tty present (including `-A` from a terminal) | `open()` returns 0 | exits 1 | Exactly today [spike: sudo-vm T2] |
| Verified remote chain, no tty (`ssh host "sudo -S …"`, make-usb.sh) | `open()` returns 0 | exits 1 | **Exactly today**: password over `-S` (OPS-2) |
| Local, no tty, askpass or auto-askpass | gates | may skip the password | This design. The askpass is the one dialog (decision 27) |
| Local, no tty, `SUDO_ASKPASS` pointing at something other than the wrapper | gates | may skip the password | The other program gets no time to the gate (decision 28). Approval needs the plain question |
| Local, no tty, `echo pw \| sudo -S` from a pipe or cron | gates | may skip the password | Gated. No dialog, so the plain question when asking is needed |
| tty present with `-A` | `open()` returns 0 | exits 1 (no 'G') | The askpass finds no pending sudo and shows today's plain box. Not gated |
| `-v`, `-l`, `-k` | never opened | runs | Unchanged [spike: sudo-vm M1/M2] |
| `-s`, `-i`, sudoedit | gates | runs | Decided on run_argv or `sudoedit=true` [spike: policy-fit] |
| `-n` | gates | only with `noninteractive_auth` | Open question S1 |
| Any of the gated rows in `mode=shadow` | logs, always approves | logs, always exits 1 | Today's behaviour, plus would-be decisions in the journal (decision 21) |

### Wire protocol, version 1

The socket is `/run/frisket-sudo/gate.sock`: `SOCK_STREAM`, one request and one reply per connection.

```
request  := "FSUD" | u8 version=1 | u8 kind ('A' approval | 'G' grant query) | u32be length | body
body     := record*      record := u8 tag | u32be len | bytes[len]
tags     : 'S' sudo itself: u32be sudo_pid | u64be sudo_starttime         (required, exactly once)
           'u' user_info "k=v" | 's' settings | 'c' command_info | 'a' run_argv (ordered)
           'e' run_envp | 'p' PAM item ("PAM_USER=…", "PAM_RUSER=…", "PAM_SERVICE=…")
           'k' chain link: u32be pid | u32be ppid | u64be starttime | u32be uid | u32be tty_nr
                           | u16be len exe | u16be len cmdline(NUL-sep, ≤4096)
                           | u8 flags (1 exe unreadable, 2 starttime changed during read)
           'm' mode: "enforce" | "shadow"                                  (required on 'A')
           'v' sudo's own argv, read as root from /proc/<sudo_pid>/cmdline
                (NUL-separated, ≤ 4096; 't' if cut)                         (required on 'G')
           't' truncated marker
limits   : ≤ 1 MiB total (truncate run_envp, then cmdline); ≤ 64 links; each record length is
           checked against the remaining body before allocating
reply    := u8 'Y'|'N' | u16be len | message (≤ 512 printable ASCII)
```

- 'A' carries `S m u s c a e k`. 'G' carries `S p v k`. A missing 'S', a missing 'm' on 'A', or a missing 'v' on 'G' gets 'N' (CG-6).
- A 'Y' to 'A' may carry a message, the grant's end ("allowed … until 16:40"). The plugin prints it with `sudo_plugin_printf(SUDO_CONV_INFO_MSG)`, so the agent sees it on stderr.
- The first 'k' link is sudo's parent (`ppid=` for the plugin, `getppid()`'s parent for the helper). 'S' names sudo itself.
- Each link reads `stat` before and after `exe` and `cmdline`.
- The gate parses each request under `recover()`. A panic replies 'N' and never exits the process. `MemoryMax` and `GOMEMLIMIT` are set.
- `FuzzNoRequestCrashesTheGate` runs in `checks.fuzz-gate` (CG-20).

**The askpass socket** (decision 28). `/run/frisket-sudo-askpass/askpass.sock`, `SOCK_STREAM`, `0660 sudo-gate:frisket-askpass` in a root `0755` directory. One connection carries one 'P' and at most one 'D', in that order. The framing is shared with the gate socket (`internal/sudowire`):

```
request  := "FSUD" | u8 version=1 | u8 kind ('P' prepare | 'D' decided) | u32be length | body
'P' body : empty. Any record gets 'N'. The sudo is the peer's kernel ppid, never a field.
'D' body : 'u' u8 choice (1 once | 2 for | 3 until logout) | u32be seconds (2 only; ≤ cap)  (required)
           'y' u8 typed (1 when the time came from the entry; for the log)
reply to 'P' := u8 'Y' | u32be len | records    |    u8 'N' | u16be len | message (≤ 512 ASCII)
   records : 'T' title (UTF-8, ≤ 1024)          'X' body text (UTF-8, ≤ 8192, plain, sanitised)
             'O' u8 offer (0 once only, password-only form | 1 the picker)
             'C' u32be cap seconds              'L' u8 until-logout offered
             'R' u8 tries so far for this sudo  'Q' u8 previous choice | u32be seconds (on a retry)
             'M' mode: "enforce" | "shadow"
reply to 'D' := u8 'Y'|'N' | u16be len | message
limits   : 'P' within 2 s of accept; 'D' within 115 s of the 'P' reply; ≤ 64 KiB per request;
           ≤ 16 askpass connections at once. Anything else closes the connection
```

- No record on this socket names a pid, a chain or a command. An 'S', 'k' or any unlisted tag gets 'N'.
- On 'P' the gate runs the six checks of decision 28, clears any dialog record for that sudo (a new try), and replies with the dialog content. It builds that content from the pending 'G' (links, badges, anchor, and 'v' sanitised and folded like today's askpass) and from its own configuration (cap, until logout, mode). 'O' is 0 when the 'G' chain is Cut, unusual or a non-terminal SessionRoot.
- On 'D' it re-checks the peer (decision 28), then stores the **dialog record** under the pending sudo's 'S': the choice, `posted` (the boottime of its 'P' reply), the shown argv, the shown anchor triple, and whether 'v' was cut. Each 'P' clears the record first, so only the last try's 'D' can be used. The choice is also copied into the pending record, which supplies 'Q' on the next try.
- `FuzzNoAskpassMessageCrashesTheGate` runs in `checks.fuzz-gate` for 5 minutes beside the other two.

### Plugin

**`open()`:**

- `tty=` present → return 0.
- Walk the chain from `ppid=`. A verified remote chain (`sshd=` option) → return 0.
- `sock=`, `gate_uid=`, `sshd=` or `mode=` bad or absent → set `misconfigured` and return 1, so `check()` denies with "frisket-sudo: plugin misconfigured in /etc/sudo.conf; use a terminal". A missing `mode=` counts as misconfigured, never as shadow.
- Otherwise return 1.
- **Never -1 or -2.**

**`check()`:**

1. `lstat` the socket's directory.
   - ENOENT → the "gate not running" deny (decision 11).
   - Exists but not uid 0 / mode 0700 / a real directory → deny with "gate directory is not root's", which means tampering (OPS-5).
2. `connect`. Any error → the "gate not running" deny.
3. The peer uid must be 0 or `gate_uid`. Under socket activation the listener is root's, so the directory check is the real guard. **ASSUMPTION-UNTESTED**; the VM test asserts it.
4. Send, then read with `SO_RCVTIMEO` = 125s (gate deadline plus 15). Timeout, EOF or garbage → deny ("no answer from gate").
5. 'N' → print the message with `sudo_plugin_printf(SUDO_CONV_ERROR_MSG)`, because errstr is never shown [spike: sudo-vm R1/R3], and return 0. 'Y' → print a non-empty message with `SUDO_CONV_INFO_MSG` (the grant's end, decision 24) and return 1.

In `mode=shadow`, steps 1–5 run the same, but every deny and every 'N' becomes "return 1" and is logged to syslog with the reason (decision 21).

### PAM grant helper

The rule is `auth sufficient pam_exec.so seteuid quiet <helper> <sock> <user> <sshd-session path> <mode>` at `unix.order - 10` [spike: sudo-vm]. `quiet_log` is dropped, because it was never tested on Linux-PAM 1.7.2. Steps:

1. `PAM_TTY` set → exit 1.
2. `PAM_SERVICE != sudo`, or `PAM_USER != PAM_RUSER`, or `PAM_USER` is not the configured user → exit 1 [spike: sudo-vm M13; C11].
3. Collect the chain from `getppid()`'s parent, 'S' from `getppid()`, and 'v' from `/proc/<getppid()>/cmdline`. A verified remote chain → exit 1.
4. Send 'G' with a 2s total timeout. Exit 0 **only** on 'Y' and only in `enforce` mode. Anything else falls through to pam_unix and askpass.

The helper never asks, because pam_exec waits forever. sudo runs it once per password try [H16], so every try sends a 'G'.

Every 'G' creates or refreshes the pending-sudo record for its 'S' (decision 16), whatever the answer. The gate answers 'G' with Y only when all of these hold:

- the chain is not Cut, unusual or SessionRoot;
- `AnyFor("sudo", anchor)` is true (peek);
- **now < `PasswordUntil(anchor)`** (decision 29): the time chosen together with a password in the dialog, or 1 h after a password typed another way.

On Y the gate records `(sudo_pid, sudo_starttime) → grant-authenticated` (decision 16) and discards any dialog record for that 'S' (decision 29). An 'A' whose 'S' is not grant-authenticated and has no dialog record counts as password-authenticated another way, and moves `PasswordUntil` to at least now + 1 h. A sudoers ticket reused inside one `bash -c` also counts this way. That is minor, because no-tty tickets are keyed by a short-lived parent (S7).

### The gate's decision on 'A'

1. **Peer.** The peer uid must be 0.
2. **Authentication.** Look up 'S' and consume its pending-sudo record.
   - Grant-authenticated → leave `PasswordUntil` alone, and discard any dialog record for 'S'.
   - Else, a dialog record for 'S' → **dialog-authenticated**: pam_unix accepted the password typed into that dialog. `PasswordUntil` moves only if step 10 approves.
   - Otherwise → password-authenticated another way: `PasswordUntil = max(PasswordUntil, now + 1h)` (decision 29).
3. **Requester.** `peer.FromLinks` with the known set: Cut, unusual (exe only; no maps for sudo) and SessionRoot.
4. **Program** (EA3).
   - The program is trusted only if `command_info["command"]` is absolute, `filepath.Clean(cmd) == cmd`, and `filepath.Dir(cmd)` **equals** one of `/run/current-system/sw/bin`, `/run/wrappers/bin` or `/etc/profiles/per-user/<user>/bin`. The program is then its basename.
   - Anything else (`..`, `.`, `//`, nested, other prefixes, store paths) is an **untrusted program**: the full path is shown, at least ask, and never allowed by a rule or grant [spike: policy-fit, evidence-audit dotdot].
5. **Words.**
   - Normally `[program] + run_argv[1:]`.
   - `-s` / `-i`: undo sudo's backslash escaping, then lex. Unreadable → ask.
   - sudoedit: `sudoedit <files…>`, with the editor shown but not matched.
6. **Environment allowlist** (skipped for sudoedit, C7).
   - Allowed: `HOME LOGNAME USER SHELL MAIL TERM TERMINFO TERMINFO_DIRS LANG LC_* PATH DISPLAY XAUTHORITY COLORTERM SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND SUDO_HOME`.
   - `NIXOS_NO_CHECK` → ask, because it also bypasses `preSwitchChecks` (C6, CF2).
   - Refused: `LD_*`, `BASH_ENV`, `ENV`, `LESSOPEN`, `LESSCLOSE`, `*PAGER`, `EDITOR`, `VISUAL`, `NIX_*` and `PYTHON*` [spike: policy-fit, LESSOPEN].
   - Any other name → ask, with the variable shown.
   - **ASSUMPTION-UNTESTED:** the exact set left after env_reset. The VM test pins it.
7. **PATH** (SK5).
   - A PATH entry is **trusted** only if it is absolute, exists, is a directory, and it and every ancestor are root-owned and neither group- nor world-writable.
   - A missing entry whose nearest existing ancestor is root-owned and not writable is ignored, because dan cannot create it.
   - Every other entry is untrusted: relative, empty, missing under a dan-owned ancestor, or dan-owned.
   - Any untrusted entry turns allow into ask, with the badge "PATH has user-writable directories". **With today's PATH this means every allow becomes ask** (mise shims, `~/.nix-profile/bin`, `~/.local/state/nix/profile/bin`, and any direnv devShell `bin` is root-owned in the store but is still checked).
8. **Rules.** `execrule.DecideWords(words)` against the root catalogue.
   - In v1 the catalogue's job is refuse and guarded rules, plus op ids for grant keys.
   - Its read → allow entries are kept but are inert under step 7 until S3 is settled.
   - Pagers and editors (`less more most vi vim nano`, and `systemctl`/`journalctl` without `--no-pager`) are at least ask.
9. **Grant.**
   - A once-grant for `(anchor, argv:<hash>)` is consumed. Otherwise a live grant for `(anchor, argv:<hash>)`, or for `(anchor, op:<id>)` when the op is marked `"grant": "op"`, turns ask into allow.
   - Never for an untrusted program, an unusual chain or a SessionRoot chain.
   - Units on the catalogue's `denyUnits` list (`debug-shell*`, `sshd*`, `frisket-*`, `nftables*`, `galley*`) stay ask even inside a grant.
10. **The dialog** (decision 27). Only for a dialog-authenticated request whose outcome so far is not refuse. The dialog counts as the person's answer when **all** of these hold:
    - a. the chain is not Cut, and its anchor triple equals the one the dialog showed;
    - b. the shown argv was not cut, and it ends with exactly `run_argv`, word for word, and `basename(command_info["command"]) == basename(run_argv[0])`;
    - c. it is not `-s`, `-i` or sudoedit, whose words are not what the dialog showed;
    - d. the program is trusted (step 4);
    - e. step 6 found no variable to ask about (an unlisted name, or `NIXOS_NO_CHECK`).

    Step 7 (PATH) is not a condition. It only turns rule allows into asks, and a person's Allow was never blocked by it. The dialog cannot show the PATH badge, because the gate does not see the run environment at 'P'. With today's PATH the badge was on every question, so its loss is accepted and listed in the review log (R4-14).

    If all hold, approve. The person's time then applies as follows:
    - the grant is `(anchor, argv:<hash>)`, until `posted + chosen` (with the display session for until logout). It is never an op grant, because the dialog named "this command";
    - `PasswordUntil = max(PasswordUntil, posted + chosen)`;
    - none of that for `once`, an unusual or SessionRoot chain, or a `denyUnits` unit. Those are allowed once, and a denied unit's reply says "allowed once; <unit> is never granted";
    - the reply 'Y' carries "frisket-sudo: allowed `<command>` for this claude until 16:40 (1 hour)", or "… once".

    The same applies when step 8 or 9 already allowed: the time extends or adds the grant.

    If any condition fails, the dialog does not count. The request becomes password-authenticated another way (`PasswordUntil = max(…, now + 1h)`) and goes on to step 12. That question's text starts with the reason ("sudo resolved `/home/dan/bin/systemctl`, not what the password dialog showed"; "the environment has FOO=…"; "the command was too long to show in full").
11. **Mode.** In `shadow`, log the outcome so far with `shadow:true` and reply 'Y'. Do not ask. The log includes what the dialog would have done and its would-be grant end.
12. **Ask** (110s, hang-up aware). The question shows the resolved command, the argv, the chain, the flags and the operation summary, then the scope. It is the time-picker form (decision 25), or `Allow once` / `Refuse` for an untrusted program, an unusual chain or a SessionRoot chain.
    - The scope is "`<exact command>` from this claude", or "any '<op title>' from this claude" for op-grantable ops.
    - A grant from this question does **not** move `PasswordUntil` (decision 29).
    - A `denyUnits` unit gets `Allow once` / `Refuse` only.

    The scope and the time are recorded in the reply message and the log.
13. **Nobody to ask** (including a locked screen). Refuse rules refuse. Allow rules allow only with a trusted PATH. A request the dialog approved in step 10 is already answered and needs nobody. Everything else is refused with "no one to ask; use a terminal" or "screen locked; use a terminal".

The askpass's dialog (decision 27) replaces revision 3's askpass row text "a confirmation of the resolved command follows". The second question it announced now comes only in step 10's failure cases, and its text says why (S5).

### Root catalogue (`sudo/operations.json`, chase's format plus two fields)

- A ~30-line loader in `internal/sudogate` maps read → allow, write → ask, guarded → refuse and unmatched → ask [spike: policy-fit].
- New per-op field `"grant": "op" | "argv"` (default `"argv"`).
  - Only reviewer-marked ops whose effect does not depend on their arguments may be `op`, e.g. `systemctl daemon-reload` and `systemctl reset-failed`.
  - Never write-file, copy, move, or any op whose `**` covers paths or unit names.
- New top-level `denyUnits`.
- v1 content: the guarded and refuse entries, plus op ids. Curation of read operations is deferred to S3.

### Failure behaviour (no lockout)

| Failure | Effect | Why safe |
|---|---|---|
| `.so` missing, wrong symbol, or wrong sudo version | **The system build fails** (sudo.conf is a checked derivation). If it somehow got through: all sudo fatal [spike: sudo-vm L2b/L3b/L4b] | Recovery is the previous generation at the console. Keep `boot.lanzaboote.configurationLimit` ≥ 5 (not set today, H9) |
| `sudo.conf` group-writable or not root's | Ignored; the gate is silently off [spike: sudo-vm L5/L6] | The store symlink is root 0444. The health timer checks (below) |
| Gate socket stopped, failed, or directory missing | Enforce: no-tty local sudo is refused with a clear message. Shadow: approved and logged. Terminal and remote sudo are unaffected | Decision 11 |
| Gate crash-loops | `StartLimitIntervalSec=0`, `RestartSec=1s`: the socket stays up. If it fails anyway: refused, as above, with `OnFailure=` raising an alert | [spike: ops-socket-limit] |
| A bad rules file after a bump | Fails `system.checks` at build. At runtime, `serve` loads a built-in refuse-all policy and logs why | No exit means no start-limit |
| Gate hangs | The plugin denies at 125s. The helper gives up at 2s and askpass follows | — |
| Approval refused after the password | The ticket is still written [spike: sudo-vm Y4]. The plugin runs on every command, and a dead gate refuses | The Y4 hazard is closed by decision 11 |
| galley quit, screen locked, or dan logged out | Nobody-to-ask rules. The askpass cannot show its dialog and exits 1 ("galley is not running"), so sudo fails authentication | — |
| Askpass socket missing, or the gate answers 'P' with 'N' | The askpass shows today's plain password box and sends no time. The 'A' then has no dialog record, so asking needs the plain question | Revision 3's double prompt, never a skipped one |
| The 'D' is lost, times out, or the gate restarts between 'D' and 'A' | The password is still written. With no dialog record the 'A' is password-authenticated another way, and the plain question follows | Dialog records are in memory only, like grants |
| sudo killed while its dialog is up | The askpass sees its parent's pidfd close, withdraws the row and exits. The pending record expires after 10 min | No late dialog (decision 27) |
| The wrapper is missing or not setgid (a broken build) | The askpass cannot connect (EACCES) and falls back to the plain box | The `sudo-gate` VM test asserts the mode bits, and so does the health unit |
| galley without item 5b (old galley) | The askpass-class form is refused (`invalid`) and the askpass falls back to the plain box on the user socket | T5 depends on T1 merged (CG-14) |

**Health check.** The health unit also checks that `/run/wrappers/bin/frisket-sudo-askpass` is `root:frisket-askpass` with the setgid bit and no setuid bit, and that the askpass socket is active. A failure raises the alert but locks nothing out: without the wrapper, sudo falls back to the plain box and the question. The health unit greps `sudo -V` (run as root) for `frisket approval`. **ASSUMPTION-UNTESTED** that sudo calls `show_version` on approval plugins when root runs `sudo -V` (CG-17). Spike SV1 checks it before T4. The sudo-gate VM test asserts that the health unit passes with the plugin loaded and fails with the plugin line removed. If SV1 fails, the health unit instead checks that `readlink -f /etc/sudo.conf` equals the store path of the checked derivation, then runs `frisket-sudo-check-plugin` against the `.so` named in it.

---

## Shared packages (frisket repo)

```go
// internal/peer — moved from internal/serve/peer.go and extended.
type Link struct {
    Pid, PPid, Pgrp, Sid, TPgid int; TTY uint32; Start uint64; UID int
    Exe string; Cmdline []string; Cgroup string; UserNS string; Unreadable bool
    ExecMaps []string // store roots of executable file mappings; "anon" / "outside" markers (signer only)
}
type Requester struct {
    Chain []Link; Anchor *Link
    Cut, SessionRoot, Terminal, Remote, ForeignNS bool
    Unusual []string // reasons: not-known, devshell, deleted, cut, session-root, maps:<detail>
    PeerUID int; CgroupID uint64; PPid int
}
type Known struct{ /* store-root set, reloaded on mtime change; keeps the last good set */ }
func LoadKnown(path string) (*Known, error)           // rejects empty, malformed, no trailing newline
func (k *Known) Contains(exe string) bool
func (k *Known) SameName(rendered, exe string) bool   // decision 19
type Options struct {
    Known *Known; Transient []string; Terminal TerminalShape; SSHDSession string; MaxDepth int
    Maps bool // signer: read /proc/<pid>/maps for leaf and terminal links
    Clock func() time.Duration // boottime; minShellAge
}
func FromConn(c *net.UnixConn, opts Options) (*Requester, error) // SO_PEERPIDFD path
func FromLinks(links []Link, opts Options) *Requester           // root-collected chain (sudo)
func (r *Requester) IsMainOf(unit string, uid int, exe string) bool // decision 5: inode, uid, ppid==1, exe; mask-checked
func (r *Requester) StillAlive() bool                              // PIDFD_INFO_PID recheck (signer only)

// internal/grant — all times are boottime durations (decision 14).
type Anchor struct{ Pid int; Start uint64; Exe string }
type Key struct{ Service string; Anchor Anchor; Target string }
func Boottime() time.Duration                          // unix.ClockGettime(CLOCK_BOOTTIME)
func New(clock func() time.Duration, sessions SessionReader) *Store // production: New(grant.Boottime, grant.Logind)
// Decision 24: what the person chose. For == 0 && !UntilLogout is once.
type Choice struct{ Label string; For time.Duration; UntilLogout bool; Typed, Clamped, Unreadable bool }
func Presets(cap time.Duration, untilLogout bool, now time.Time) []Choice // once first; labels carry clock ends
func ParseTyped(s string, cap time.Duration) (Choice, error) // ^([0-9]{1,2}h)?([0-9]{1,3}m)?$ after trimming; clamps
type Session struct{ UID int; Display string }               // decision 26
type SessionReader func(uid int) (Session, bool)             // Logind reads /run/systemd/users/<uid>
func (s *Store) Grant(k Key, until time.Duration, session *Session) // until = posted + chosen; never extended by use
func (s *Store) GrantOnce(k Key, ttl time.Duration)
func (s *Store) Use(k Key) bool                       // consumes a once-grant; never extends a normal grant
func (s *Store) Expiry(k Key) (boot time.Duration, wall time.Time, ok bool)
func (s *Store) AnyFor(service string, a Anchor) bool // peek, never consumes
func (s *Store) PasswordUntil(a Anchor) time.Duration; func (s *Store) HoldPassword(a Anchor, until time.Duration) // max(); decision 29
func (s *Store) MarkGrantAuth(sudoPid int, sudoStart uint64); func (s *Store) WasGrantAuth(sudoPid int, sudoStart uint64) bool
func (s *Store) Sweep()                               // expiry and ended sessions; never reads /proc (decision 15)

// internal/galleyask
type Question struct {
    Title, Text string
    Buttons []string       // ungrantable kind=question: "Allow once", then Refuse last
    Times   []grant.Choice // grantable: the time-picker form (decision 25); Times[0] is once
    Cap     time.Duration  // typed times are clamped to it
}
type Answer struct{ Allowed bool; Button int; Choice grant.Choice } // Choice set for the form
type Asker interface{ Ask(ctx context.Context, q Question) (Answer, error) }
var ErrNobody = errors.New("no one to ask")
var ErrLocked = errors.New("screen locked")
type PeerCheck struct{ UID int; Cgroup string } // inode re-statted per answer
func Dial(path string, window PeerCheck) Asker // github.com/danielbodart/galley/wire
// The askpass's own form (decision 27): the password comes back to the caller only, as a []byte it zeroes.
func AskPassword(ctx context.Context, path string, window PeerCheck, title, text string,
    times []grant.Choice, cap time.Duration) (password []byte, choice grant.Choice, err error)

// internal/sudowire: the framing shared by the gate socket, the askpass socket, the gate and the askpass.
// Records for 'A', 'G' ('S','v',…), 'P' and 'D'; replies with the 'Y'/'N' message or the 'P' records.

// execspec — new leaf package, stdlib only. Holds ExecRule AND Operation (incl. Class, Category).
// policy: type ExecRule = execspec.ExecRule; type Operation = execspec.Operation (aliases).
// execrule core uses *execspec.Operation everywhere and never imports policy.
func CompileRules(exec []execspec.ExecRule, env []string, unmatched string, shell bool) (*Rules, error)
func (r *Rules) DecideWords(words []string) Decision // decideSimple(Simple{Words: words}); same Decision builder as Decide
// execrule/route (or policy): func Compile(r policy.SSHRoute) (*execrule.Rules, error) — the only policy importer.
```

- The Decision construction in `Decide` (execrule.go ~192-215) is factored into one helper that both entry points use (CF9).
- T2 is done when all of these hold:
  - `go list -deps ./cmd/frisket-sudo` contains no `internal/dns`;
  - `go list -deps ./execrule` contains no `frisket/policy` or `frisket/project`;
  - chase compiles against the aliases.
- The split cuts the gate's closure from about 2.68 MB to about 1.98 MB [spike: policy-fit, deps].
- `internal/ask` stays as it is (F1).

### `tests/fakegalley` contract (fixed interface) (CG-15)

A Go program built from the pinned `galley/wire`. It speaks the service side of the window, and is used by the `internal/galleyask` unit tests and by both VM tests.

```
fakegalley -socket PATH [-answer N] [-delay D] [-never] [-busy] [-locked]
           [-close-after D] [-script FILE] [-log FILE] [-mode 0666] [-askpass-gid GID]
```

- `-socket PATH`: binds PATH itself (unlinks a stale file first), as galley does under decision 13. If `LISTEN_FDS` is set and `-socket` is absent, it uses the inherited fd instead, which is how the G-P1 negative test is run.
- `-answer N`: answers every question with button N (`{"answer":"extra","index":N}`), or `cancel` for the last button. Default: the last button (Refuse).
- `-delay D`: waits D before answering.
- `-never`: reads the Hello and never answers. It keeps the connection open until the client closes it.
- `-busy`: answers `{"error":"busy"}` at once.
- `-locked`: answers `{"error":"locked"}` at once.
- `-close-after D`: closes the connection after D with no answer.
- `-script FILE`: one action per line, used in order for successive questions: `answer N`, `delay D answer N`, `never`, `busy`, `locked`, `close D`, or `title <regexp> answer N`, which matches on the title. The last line repeats. Revision 4 adds:
  - `allow <combo text> [typed <time>]`: answers a time-picker form `ok` with those fields. `allow` alone takes the combo's first value;
  - `askpass <password> <combo text> [typed <time>]`: answers the askpass-class form `ok` with the password field first. `askpass-cancel` answers `cancel`;
  - `refuse`: answers `cancel`;
  - `raw <json>`: sends that answer line as it is, for malformed and old-galley answers.
- `-log FILE`: appends one JSON line per question received (`{"title","text","kind","buttons","fields","caller","peer":{"uid","gid","pid"}}`) and one per answer sent, so VM tests can assert what was asked. A password field's answer is logged as `{"password":"<n bytes>"}`, never its text.
- It validates the askpass class as galley item 5b does: the peer's gid must be the configured `-askpass-gid`, and the shape must be one of the two allowed forms.
- In VM tests it runs as the user unit **named `galley.service`**, so the services' peer check passes for the right reason. A positive subtest checks that a scripted `answer 0` gets through, alongside the negative "rebound socket is nobody" subtest (CG-1).
- It validates the Hello the way galley does for services (`kind=question` or the time-picker form, no markup, no icon, no caller) and answers `{"error":"invalid"}` otherwise, so client bugs fail in tests. On an `ok` it applies galley's time grammar to the entry (shared `times.txt`), and answers `{"error":"invalid-time"}` for an entry galley would not have accepted, so a test can feed frisket an unreadable time only by using `-script` with `raw <json>`.

---

## galley changes

All of these were shown working in the patched spike unless marked otherwise [spike: galley-socket]:

1. Move `internal/wire` to a public `wire/` package. Add the service question and answer golden files (see "Service question wire format"). **This merges first.** frisket T2 pins the pseudo-version at or after it.
2. `server.js` keeps taking the user listener from `LISTEN_FDNAMES` (`galley.socket`). It **binds the services socket itself** from `GALLEY_SERVICES_SOCKET` (unlink stale, bind, chmod 0666, listen), and removes the file on clean exit (decision 13, PENDING G-P1). Not demonstrated in the spike, which used socket activation.
3. Per-listener peer policy. The user listener allows self. The services listener allows only `GALLEY_SERVICES` uids, with names resolved from `/etc/passwd` at start. Other uids are reset.
4. `item.caller = {uid, name, label, pid}` is set after `validate()`. A client-sent `caller` fails validation.
5. Service items must be `kind=question`, or the **time-picker form** (decision 25): `kind=forms` with exactly a `combo` (at most 8 values, each at most 64 characters) followed by an `entry`, and exactly the buttons cancel and ok. Show, entry, password, other forms, file, notification and progress are refused. Markup is off, the icon is forced, `key` is dropped and `default` is forced to -1.
   - **Time grammar, enforced by the window.** When `ok` is pressed on a service form, the entry's text, lowercased with spaces removed, must be empty or match `^([0-9]{1,2}h)?([0-9]{1,3}m)?$` with a total above zero. Otherwise the row shows "Write a time like 45m, 2h or 1h30m" under the entry and does not answer. That keeps decision 9's "services cannot collect secrets": a service's only typed field cannot carry a password-like string. Vectors are in `wire/testdata/times.txt`, shared with frisket's `grant.ParseTyped`. Not in the spike; new code in `window.js` `_press`.
5b. **Askpass caller class** (decision 28). Not in the spike. On the services listener, a peer whose `SO_PEERCRED` uid is galley's own and whose gid is `GALLEY_ASKPASS_GID` (resolved from `GALLEY_ASKPASS_GROUP` in `/etc/group` at start) is the askpass. It may post only:
   - `kind=forms` with fields `[password]`, or `[password, combo, entry]` with the item-5 limits and the time grammar on the entry;
   - the buttons cancel and ok, with `default` -1 or the ok button.

   Its rows get the reserved service look with the caller label "sudo password", markup off, the icon forced and `key` dropped. They never join (item 6). Its answer goes only to that connection, and the password field is cleared from the widget when answered or withdrawn, as `bodies.js` already does for hidden entries. Any other item from it, or the same form from a uid-dan peer without that gid, gets `{"error":"invalid"}`. **ASSUMPTION-UNTESTED** that gjs gives galley the peer's gid: `Gio.Credentials` carries the `ucred` gid on Linux, and the fallback is `/proc/<pid>/status` `Gid:`. A galley test checks it.
6. Sameness includes the caller. Hidden entries, passwords, and forms with a password field never join. Group by `(caller, title)`, showing only the title.
7. **Reserve the service look.**
   - Service rows get a distinct accent and a header strip.
   - User items may not use `security-high*` icons.
   - A user title that starts with a service label gets the prefix "(from your session)".
   - A **rendered** screenshot test is required, because the spike checked only state JSON (G2).
8. Per-caller cap of 8 queued questions. The excess gets `{"error":"busy"}`.
9. **Locked screen** (decision 20): galley watches logind's `LockedHint` for its session. While it is true, service questions get `{"error":"locked"}` at once. Not demonstrated in the spike.
10. Regression tests:
    - the password-join tests become "the thief does not join";
    - a decoy-first test asserts only what is claimed;
    - a forms-with-password test;
    - a locked-screen test (`loginctl lock-session` in the VM);
    - the time-picker form: accepted from a service; with a third field, a password field, or 9 combo values, refused; `ok` with `45m`, `2h`, `1h30m` and an empty entry answers; `ok` with `hunter2`, `0m`, `100h` or `1d` does not answer and shows the hint;
    - an untouched combo answers its first value (pins decision 25's assumption about `Gtk.DropDown`);
    - the askpass class: both allowed forms accepted from a peer with the askpass gid; any other kind from it refused; the same form from a uid-dan peer without the gid refused; its rows never join; Enter after typing the password presses Allow.
11. **Drop-in warning** (visibility only, F3): at start, galley compares `systemctl --user show galley.service -p DropInPaths -p ExecStart` with its expected values. If they differ, it shows a notification. A replaced ExecStart defeats this, and the docs say so.
12. Home-manager options:
    - `services.galley.serviceSocket.{enable, path}` and `services.galley.services` (an attrset from uid name to label);
    - `services.galley.askpassGroup` (null by default), which sets `GALLEY_ASKPASS_GROUP` (item 5b);
    - they set `GALLEY_SERVICES_SOCKET` and `GALLEY_SERVICES` in `galley.service`'s environment. There is no socket unit for services under option (a). Under option (b) they render `systemd.user.sockets.galley-services` with `SocketMode=0666`, `FileDescriptorName=services` and `Service=galley.service` instead.

---

## NixOS wiring

### Ownership (CF11)

frisket owns the units. It provides keyed modules:

- `nixosModules.signer` (`nix/signer.nix`);
- `nixosModules.sudoGate` (`nix/sudo-gate.nix`);
- `nixosModules.knownPaths`, which both of the others import.

Each is keyed like `nixosModules.default` and added to frisket's double-import eval check. frisket's VM tests import **exactly** these modules.

nix-config only:

- sets options;
- holds the key files and the policy content;
- provides the session and chase wiring, the galley-ask group, known hosts, authorized keys and ssh host blocks;
- defines its own checks.

### Flake (CF8, CF3)

- There is **no direct frisket input.** nix-config takes `inputs.chase.inputs.frisket`, the single frisket in the lock, which follows nix-config's nixpkgs through chase [H9].
- A new frisket arrives through track **T2b** in chase. In one commit: `go get github.com/danielbodart/frisket@<rev>`, refresh `vendorHash`, run `nix flake update frisket`, and keep `frisket-pin` and `nix flake check` green. nix-config then runs `nix flake update chase`.
- galley reaches nix-config through its own input. T5 runs `nix flake update galley` after T1 merges (CG-14).
- nix-config adds an eval assertion that the frisket lock node's nixpkgs is the root nixpkgs.
- nix-config gains a `checks.x86_64-linux` output (new) with `sudo-lockout` and `signer-wiring`.

### frisket `nix/known-paths.nix`

```nix
self: { config, lib, pkgs, ... }:
let
  # A standalone script so tests/known-paths.nix can run it with a failing nix-store (CG-12).
  writeKnown = pkgs.writeShellScript "frisket-write-known-paths" ''
    set -u -o pipefail
    shopt -s nullglob
    nixStore=$1 system=$2 out=/run/frisket/known-store-paths
    roots=("$system")
    for p in /run/current-system /run/booted-system /nix/var/nix/profiles/system-*-link; do
      [ -e "$p" ] && roots+=("$p")
    done
    install -d -m 0755 /run/frisket
    if "$nixStore" -qR "''${roots[@]}" | LC_ALL=C sort -u > "$out.new" \
       && [ -s "$out.new" ] \
       && grep -qxF "$(readlink -f "$system")" "$out.new"; then
      chmod 0644 "$out.new" && mv -f "$out.new" "$out"
    else
      rm -f "$out.new"
      echo "frisket-known-paths: nix-store failed or set incomplete; kept the previous set" >&2
    fi
  '';
in {
  # Root writes the set of store paths that root-built systems contain (decision 12).
  system.activationScripts.frisket-known-paths = {
    deps = [ "specialfs" ];
    text = ''${writeKnown} ${config.nix.package}/bin/nix-store "$systemConfig" || true'';
  };
}
```

- The activation never fails because of this script. A stale or missing set only makes things ask more.
- `tests/known-paths.nix` (a `runCommand` check in frisket) runs `writeKnown` against a temp `/run` stand-in with a fake `nix-store` that (1) exits 1 after printing half the set, (2) prints nothing, (3) omits `$systemConfig`, and (4) succeeds. In 1–3 the previous file must be unchanged; in 4 it must be replaced. The script takes an output-directory override for the test.
- **ASSUMPTION-UNTESTED:** `nix-store -qR` as root during boot activation, and its cost with 11 generations. Both signer and gate VM tests assert that the file exists and lists the session's binaries.

### frisket `nix/signer.nix` (excerpt)

```nix
self: { config, lib, pkgs, utils, ... }:
let
  cfg = config.services.frisket.signer;
  fpkgs = self.packages.${pkgs.stdenv.hostPlatform.system};
  bin = lib.getExe' fpkgs.frisket-signer "frisket-signer";
  policy = pkgs.writeText "frisket-signer-policy.json"
    (builtins.toJSON (cfg.policy // { forUser = cfg.forUser; }));
  tpmUnit = { User = cfg.user; Group = cfg.user; SupplementaryGroups = [ "tss" ];
              DevicePolicy = "closed"; DeviceAllow = [ "/dev/tpmrm0 rw" ]; };
in {
  imports = [ self.nixosModules.knownPaths ];
  options.services.frisket.signer = {
    enable = lib.mkEnableOption "TPM-held SSH keys behind frisket-signer";
    user = lib.mkOption { type = lib.types.str; default = "ssh-signer"; };
    uid = lib.mkOption { type = lib.types.int; default = 951; };
    forUser = lib.mkOption { type = lib.types.str; default = "dan"; };
    keys = lib.mkOption { type = lib.types.listOf lib.types.path; default = [ ]; };
    policy = lib.mkOption { type = lib.types.attrs; };
    socket = lib.mkOption { type = lib.types.str; default = "/run/frisket-signer/agent"; readOnly = true; };
    galleySocket = lib.mkOption { type = lib.types.str; default = "/run/galley-ask/dan.sock"; };
  };
  config = lib.mkIf cfg.enable {
    security.tpm2.enable = true;
    users.groups.${cfg.user}.gid = cfg.uid;
    users.users.${cfg.user} = { isSystemUser = true; uid = cfg.uid; group = cfg.user; };
    assertions = [{
      assertion =
        let normal = lib.attrNames (lib.filterAttrs (_: u: u.isNormalUser) config.users.users);
            inTss = (config.users.groups.tss.members or [ ])
              ++ lib.attrNames (lib.filterAttrs (_: u: lib.elem "tss" (u.extraGroups or [ ])
                                                      || (u.group or "") == "tss") config.users.users);
        in lib.intersectLists normal inTss == [ ];
      message = "a login user in tss (members, extraGroups or primary group) could sign with any committed key blob";
    }];
    system.checks = [ (pkgs.runCommand "frisket-signer-policy-ok" { } ''
      ${bin} check -policy ${policy} && touch $out'') ];

    systemd.sockets.frisket-signer = {
      wantedBy = [ "sockets.target" ];
      socketConfig = { ListenStream = cfg.socket; SocketUser = cfg.forUser; SocketMode = "0600";
                       DirectoryMode = "0755"; FileDescriptorName = "agent"; };
      unitConfig.OnFailure = [ "frisket-signer-alert.service" ];
    };
    systemd.services.frisket-signer = {
      after = [ "tpm2.target" ]; wants = [ "tpm2.target" ];
      unitConfig = { StartLimitIntervalSec = 0; OnFailure = [ "frisket-signer-alert.service" ]; };
      serviceConfig = tpmUnit // {
        Type = "notify";
        SupplementaryGroups = [ "tss" "galley-ask" ];
        ExecStart = utils.escapeSystemdExecArgs ([ bin "serve" "-policy" policy "-galley" cfg.galleySocket ]
          ++ lib.concatMap (k: [ "-key" k ]) cfg.keys);
        AmbientCapabilities = [ "CAP_SYS_PTRACE" ]; CapabilityBoundingSet = [ "CAP_SYS_PTRACE" ];
        NoNewPrivileges = true;
        SystemCallFilter = [ "@system-service" "~@privileged" "~process_vm_readv" "~process_vm_writev" "~kcmp" ];
        SystemCallErrorNumber = "EPERM"; SystemCallArchitectures = "native";
        ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; ProtectProc = "invisible";
        RestrictAddressFamilies = [ "AF_UNIX" ]; IPAddressDeny = "any";
        RestrictNamespaces = true; LockPersonality = true; MemoryDenyWriteExecute = true;
        ProtectKernelTunables = true; ProtectKernelModules = true; ProtectControlGroups = true;
        ProtectClock = true; ProtectHostname = true; RestrictRealtime = true; RestrictSUIDSGID = true;
        KeyringMode = "private"; UMask = "0077"; Restart = "always"; RestartSec = "1s";
        MemoryMax = "256M"; Environment = [ "GOMEMLIMIT=200MiB" ];
      };
    };
    systemd.services."frisket-signer-keygen@".serviceConfig = tpmUnit // {
      Type = "oneshot"; StateDirectory = "frisket-signer";
      ExecStart = "${bin} keygen -type %i -comment ${cfg.forUser}@${config.networking.hostName} -out /var/lib/frisket-signer/new";
    };
    systemd.services.frisket-signer-health = {
      unitConfig.OnFailure = [ "frisket-signer-alert.service" ];
      serviceConfig = tpmUnit // { Type = "oneshot";
        ExecStart = utils.escapeSystemdExecArgs ([ bin "selftest" ] ++ lib.concatMap (k: [ "-key" k ]) cfg.keys); };
    };
    systemd.timers.frisket-signer-health = { wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "2m"; OnUnitActiveSec = "15m"; }; };
    systemd.services.frisket-signer-alert.serviceConfig = { Type = "oneshot"; User = cfg.user;
      SupplementaryGroups = [ "galley-ask" ];
      ExecStart = "${bin} alert -galley ${cfg.galleySocket} -text 'frisket-signer is failing or has no keys: see docs/signer.md'"; };
  };
}
```

- The full hardening set is **ASSUMPTION-UNTESTED** as a whole; subsets were tested [spike: nix-wiring3, identity-vm hardptrace]. The signer VM test runs this exact module.
- frisket.service has `ProtectSystem=strict` and `ProtectHome=read-only`. Connecting to a socket on a read-only mount should work. **ASSUMPTION-UNTESTED**; the VM stand-in uses frisket's real hardening.

### frisket `nix/sudo-gate.nix` (excerpt)

```nix
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.frisket.sudoGate;
  gate = self.packages.${pkgs.stdenv.hostPlatform.system}.frisket-sudo;
  root = pkgs.callPackage self.lib.sudoRoot { sudo = config.security.sudo.package; };
  sshd = "${config.services.openssh.package}/libexec/sshd-session";   # ASSUMPTION-UNTESTED path; VM asserts
  rules = [ "${gate}/share/frisket-sudo/operations.json" ]
    ++ lib.optional (cfg.extraOperations != [ ])
         (pkgs.writeText "frisket-sudo-extra.json" (builtins.toJSON cfg.extraOperations));
  sudoConf = pkgs.runCommand "sudo.conf" { } ''
    ${root}/bin/frisket-sudo-check-plugin ${root}/lib/frisket_approval.so ${root.passthru.symbol} \
      ${config.security.sudo.package.version}
    echo "Plugin ${root.passthru.symbol} ${root}/lib/frisket_approval.so sock=/run/frisket-sudo/gate.sock gate_uid=${toString cfg.uid} sshd=${sshd} mode=${cfg.mode}" > $out
  '';
in {
  imports = [ self.nixosModules.knownPaths ];
  options.services.frisket.sudoGate = {
    enable = lib.mkEnableOption "the no-terminal sudo gate";
    mode = lib.mkOption { type = lib.types.enum [ "shadow" "enforce" ]; default = "shadow"; };
    user = lib.mkOption { type = lib.types.str; default = "sudo-gate"; };
    uid = lib.mkOption { type = lib.types.int; default = 952; };
    forUser = lib.mkOption { type = lib.types.str; default = "dan"; };
    extraOperations = lib.mkOption { type = lib.types.listOf lib.types.attrs; default = [ ]; };
    lockoutCheck = lib.mkOption { type = lib.types.nullOr lib.types.package; default = null; };
    galleySocket = lib.mkOption { type = lib.types.str; default = "/run/galley-ask/dan.sock"; };
    grant = {                                                    # decision 24
      cap = lib.mkOption { type = lib.types.str; default = "8h"; };          # ≤ 24h; `check` rejects more
      untilLogout = lib.mkOption { type = lib.types.bool; default = true; }; # decision 26
    };
    askpass = {                                                  # decisions 27, 28
      enable = lib.mkOption { type = lib.types.bool; default = true; };
      group = lib.mkOption { type = lib.types.str; default = "frisket-askpass"; };
      gid = lib.mkOption { type = lib.types.int; default = 953; };           # free [H17]
    };
  };
  config = lib.mkIf cfg.enable {
    users.groups.${cfg.user}.gid = cfg.uid;
    users.users.${cfg.user} = { isSystemUser = true; uid = cfg.uid; group = cfg.user; };
    users.groups.${cfg.askpass.group}.gid = lib.mkIf cfg.askpass.enable cfg.askpass.gid;
    assertions = [{
      assertion = !cfg.askpass.enable ||
        (config.users.groups.${cfg.askpass.group}.members or [ ]) == [ ]
        && lib.all (u: !(lib.elem cfg.askpass.group (u.extraGroups or [ ])) && (u.group or "") != cfg.askpass.group)
                   (lib.attrValues config.users.users);
      message = "nobody may be in ${cfg.askpass.group}: its egid is the askpass's only identity (decision 28)";
    }];
    security.wrappers.frisket-sudo-askpass = lib.mkIf cfg.askpass.enable {
      source = lib.getExe' gate "frisket-sudo-askpass";
      owner = "root"; group = cfg.askpass.group; setuid = false; setgid = true;
      permissions = "u+rx,g+x,o+x";
    };
    environment.etc."frisket-sudo/askpass.json".text = builtins.toJSON {   # root-owned; the askpass reads no env
      gate = "/run/frisket-sudo-askpass/askpass.sock"; galley = cfg.galleySocket;
      galleyUnit = "galley.service"; user = cfg.forUser; };
    systemd.sockets.frisket-sudo-askpass = lib.mkIf cfg.askpass.enable {
      wantedBy = [ "sockets.target" ];
      socketConfig = { ListenStream = "/run/frisket-sudo-askpass/askpass.sock"; Service = "frisket-sudo.service";
                       SocketUser = cfg.user; SocketGroup = cfg.askpass.group; SocketMode = "0660";
                       DirectoryMode = "0755"; FileDescriptorName = "askpass"; };
    };
    environment.etc."sudo.conf".source = sudoConf;              # guard 1: build-time, every path (SK8)
    system.checks = [ (pkgs.runCommand "frisket-sudo-rules-ok" { } ''
      ${lib.getExe' gate "frisket-sudo"} check ${lib.concatMapStringsSep " " (r: "-rules ${r}") rules} -grant-cap ${cfg.grant.cap} && touch $out'') ];
    system.extraDependencies = lib.optional (cfg.lockoutCheck != null) cfg.lockoutCheck; # guard 2 (CF2)
    system.preSwitchChecks.frisket-sudo-plugin =                # backstop only; NIXOS_NO_CHECK=1 skips it
      "${root}/bin/frisket-sudo-check-plugin ${root}/lib/frisket_approval.so ${root.passthru.symbol} ${config.security.sudo.package.version}";

    security.pam.services.sudo.rules.auth.frisket-grant = {
      order = config.security.pam.services.sudo.rules.auth.unix.order - 10;
      control = "sufficient";
      modulePath = "${config.security.pam.package}/lib/security/pam_exec.so";
      args = [ "seteuid" "quiet" "${root}/bin/frisket-sudo-pam" "/run/frisket-sudo/gate.sock" cfg.forUser sshd cfg.mode ];
    };
    systemd.sockets.frisket-sudo = {
      wantedBy = [ "sockets.target" ];
      socketConfig = { ListenStream = "/run/frisket-sudo/gate.sock"; SocketUser = cfg.user;
                       SocketMode = "0600"; DirectoryMode = "0700"; FileDescriptorName = "gate"; };
      unitConfig.OnFailure = [ "frisket-sudo-alert.service" ];
    };
    systemd.services.frisket-sudo = {
      unitConfig = { StartLimitIntervalSec = 0; OnFailure = [ "frisket-sudo-alert.service" ]; };
      serviceConfig = {
        Type = "notify"; User = cfg.user; Group = cfg.user; SupplementaryGroups = [ "galley-ask" ];
        Sockets = [ "frisket-sudo.socket" ] ++ lib.optional cfg.askpass.enable "frisket-sudo-askpass.socket";
        ExecStart = "${lib.getExe' gate "frisket-sudo"} serve ${lib.concatMapStringsSep " " (r: "-rules ${r}") rules} -known /run/frisket/known-store-paths -galley ${cfg.galleySocket} -user ${cfg.forUser} -grant-cap ${cfg.grant.cap}${lib.optionalString cfg.grant.untilLogout " -until-logout"} -askpass-group ${cfg.askpass.group}";
        # Reads /run/systemd/users/<uid> for until-logout grants (decision 26): /run stays readable under ProtectSystem.
        CapabilityBoundingSet = ""; NoNewPrivileges = true; PrivateDevices = true; DevicePolicy = "closed";
        ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; ProtectProc = "invisible"; ProcSubset = "pid";
        RestrictAddressFamilies = [ "AF_UNIX" ]; IPAddressDeny = "any";
        SystemCallFilter = [ "@system-service" "~@privileged" ]; SystemCallErrorNumber = "EPERM";
        MemoryDenyWriteExecute = true; RestrictNamespaces = true; LockPersonality = true;
        UMask = "0077"; Restart = "always"; RestartSec = "1s";
        MemoryMax = "128M"; Environment = [ "GOMEMLIMIT=100MiB" ];
      };
    };
    systemd.services.frisket-sudo-health = {                     # timer, not boot-only (OPS-1)
      unitConfig.OnFailure = [ "frisket-sudo-alert.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        # ASSUMPTION-UNTESTED (SV1): sudo -V as root shows approval plugins. Fallback in the plan.
        /run/wrappers/bin/sudo -V 2>&1 | grep -q 'frisket approval' || { echo "plugin not loaded"; exit 1; }
        systemctl is-active --quiet frisket-sudo.socket || { echo "gate socket not active"; exit 1; }
        ${lib.optionalString cfg.askpass.enable ''
        [ "$(stat -c '%U:%G %A' /run/wrappers/bin/frisket-sudo-askpass)" = "root:${cfg.askpass.group} -r-x--s--x" ] \
          || { echo "askpass wrapper is not setgid ${cfg.askpass.group}"; exit 1; }
        systemctl is-active --quiet frisket-sudo-askpass.socket || { echo "askpass socket not active"; exit 1; }
        ''}
      '';
    };
    systemd.timers.frisket-sudo-health = { wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "1m"; OnUnitActiveSec = "15m"; }; };
    systemd.services.frisket-sudo-alert.serviceConfig = { Type = "oneshot"; User = cfg.user;
      SupplementaryGroups = [ "galley-ask" ];
      ExecStart = "${lib.getExe' gate "frisket-sudo"} alert -galley ${cfg.galleySocket} -text 'frisket-sudo is failing: no-terminal sudo is refused. sudo reset-failed frisket-sudo.socket from a terminal'"; };
  };
}
```

How the lockout guards fit together:

- **Guard 1:** sudo.conf is a derivation that only exists if the plugin loads with this host's glibc and sudo. It applies to every rebuild path (switch, boot, test, build), and `NIXOS_NO_CHECK` cannot skip it (SK8, EA6).
- **Guard 2:** the nix-config VM check `sudo-lockout` is a build dependency of the toplevel, so a bare `nixos-rebuild` runs it whenever the plugin, sudo or PAM changes. It is cached otherwise.
  - **ASSUMPTION-UNTESTED** that this evaluates without infinite recursion. Pre-build spike X1 checks it.
  - If X1 fails, guard 2 becomes a documented `nix build .#checks.x86_64-linux.sudo-lockout` before M4 and on every chase, nixpkgs or sudo bump. The plan then says plainly that a bare `nixos-rebuild` does not run it (CF2).
- `preSwitchChecks` runs for switch, boot, test and dry-activate, and only `NIXOS_NO_CHECK=1` skips it [switch-to-configuration-ng main.rs:1833]. It is a backstop.
- Do not trust the exit code of `sudo -V`: as root it still prints the version after the fatal lines [spike: sudo-vm L3c].

### nix-config `modules/ssh-signer.nix`

```nix
{ config, lib, pkgs, inputs, ... }:
let
  cfg = config.sshSigner;
  frisket = inputs.chase.inputs.frisket;
  host = config.networking.hostName;
  dir = ../admins + "/${host}";
  fp = n: let f = dir + "/${n}.fp"; in
    assert lib.assertMsg (builtins.pathExists f)
      "missing ${toString f}: run `systemctl start frisket-signer-keygen@…` and commit .tpm/.pub/.fp";
    lib.fileContents f;
  gwName = "ssh-tpm-${cfg.gatewayKey}";
in {
  imports = [ frisket.nixosModules.signer ];
  options.sshSigner = {
    enable = lib.mkEnableOption "TPM-held SSH keys";
    default = lib.mkOption { type = lib.types.bool; default = false;
      description = "Point the graphical session and chase at the signer; false keeps gcr (rollback)."; };
    gatewayOnTpm = lib.mkOption { type = lib.types.bool; default = false;
      description = "Set only after M2 proved a gateway login through the signer."; };
    gatewayKey = lib.mkOption { type = lib.types.enum [ "ecdsa" "rsa" ]; default = "ecdsa"; };
    macOnTpm = lib.mkOption { type = lib.types.bool; default = false;
      description = "Set only after M2 proved a dan-mac login through the signer (its authorized_keys is hand-managed)."; };
  };
  config = lib.mkIf cfg.enable {
    services.frisket.signer = {
      enable = true;
      keys = [ (dir + "/ssh-tpm-ecdsa.tpm") ]
        ++ lib.optional (cfg.gatewayKey == "rsa") (dir + "/ssh-tpm-rsa.tpm");
      policy = import ./ssh-signer-policy.nix { inherit config lib pkgs fp gwName; };
    };
    services.gnome.gcr-ssh-agent.enable = lib.mkIf cfg.default false;
    # User-manager environment only, as gcr does today (H7); ssh logins into this host get no agent (OPS-2).
    home-manager.users.dan.systemd.user.sessionVariables.SSH_AUTH_SOCK =
      lib.mkIf cfg.default config.services.frisket.signer.socket;
    # Decision 18: git always runs the system ssh, whatever a devShell puts on PATH.
    home-manager.users.dan.programs.git.extraConfig.core.sshCommand =
      lib.mkIf cfg.default "${config.programs.ssh.package}/bin/ssh";
    # CG-8: per-host identities, so ssh never silently falls back to id_ed25519.
    home-manager.users.dan.programs.ssh.settings = lib.mkIf cfg.default (import ./ssh-signer-hosts.nix {
      inherit lib cfg dir;
      hosts = adminHosts;   # the `hosts` list modules/common.nix already builds; T5 exposes it to this module
    });
  };
}
```

`ssh-signer-hosts.nix` renders, merged with the existing blocks in `home/dan.nix`:

- `server`, `"github.com"` and every name in `hosts` other than this host: `IdentityFile = "${dir}/ssh-tpm-ecdsa.pub"`, `IdentitiesOnly = "yes"`;
- `gateway`: the gateway key's `.pub` with `IdentitiesOnly = "yes"` when `gatewayOnTpm`; otherwise `IdentityFile = "~/.ssh/gateway_ed25519"`, `IdentitiesOnly = "yes"`, `IdentityAgent = "none"`;
- `modem`: `PubkeyAuthentication = "no"`, `IdentityAgent = "none"`;
- `mac`: the TPM `.pub` with `IdentitiesOnly = "yes"` when `macOnTpm`; otherwise `IdentityFile = "~/.ssh/id_ed25519"`, `IdentitiesOnly = "yes"`, `IdentityAgent = "none"`.

`ssh-signer-policy.nix` renders exact paths from Nix:

- `"${config.programs.ssh.package}/bin/ssh"`;
- `"${pkgs.gnome-console}/bin/.kgx-wrapped"` (the overridden package from `modules/gnome.nix`);
- `"${pkgs.bashInteractive}/bin/bash"`;
- the claude-code package that home-manager installs (`…/bin/.claude-unwrapped`);
- `trusted.exe`, from the package `frisket.service` runs;
- `keys = { ecdsa = fp "ssh-tpm-ecdsa"; gateway = fp gwName; }`;
- `trusted[].keys`: `ecdsa`, plus `gateway` when `gatewayOnTpm` is set.

**ASSUMPTION-UNTESTED:** that environment.d reaches new gnome-console tabs once gcr is off. Checked by hand at M3 with `echo $SSH_AUTH_SOCK` in a new tab.

### nix-config `modules/sudo-gate.nix`

```nix
{ config, lib, inputs, ... }: {
  imports = [ inputs.chase.inputs.frisket.nixosModules.sudoGate ];
  options.sudoGate = {
    enable = lib.mkEnableOption "the no-terminal sudo gate";
    mode = lib.mkOption { type = lib.types.enum [ "shadow" "enforce" ]; default = "shadow"; };
  };
  config = lib.mkIf config.sudoGate.enable {
    services.frisket.sudoGate = {
      enable = true;
      inherit (config.sudoGate) mode;
      lockoutCheck = inputs.self.checks.${config.nixpkgs.hostPlatform.system}.sudo-lockout;  # spike X1
    };
  };
}
```

### galley service socket

```nix
# modules/common.nix (NixOS): home-manager cannot create system groups.
users.groups.galley-ask = { };
systemd.tmpfiles.rules = [ "d /run/galley-ask 0750 dan galley-ask -" ];

# home/dan.nix
services.galley = { enable = true;
                    serviceSocket = { enable = true; path = "/run/galley-ask/dan.sock"; };
                    services = { ssh-signer = "SSH signer"; sudo-gate = "sudo gate"; };
                    askpassGroup = "frisket-askpass"; };                # galley item 5b, decision 28
```

**`~/.claude/sudo-askpass.sh` (graphical-sudo, T5).** Its first lines become:

```bash
# frisket-sudo's one dialog (decision 27). exec, so the askpass stays sudo's direct child.
if [ -x /run/wrappers/bin/frisket-sudo-askpass ] && [ -S /run/galley-ask/"$(id -un)".sock ]; then
    exec /run/wrappers/bin/frisket-sudo-askpass "$@"
fi
```

The rest of the script, today's `galley --entry --hide-text` or zenity box, stays as the fallback. The askpass's own fallback (gate 'N') shows the same plain box.

This was shown working in a VM with socket activation [spike: galley-socket, vm.log]. Self-binding (decision 13) is new and is covered by G-P1 and the VM tests. ENOENT without linger is **ASSUMPTION-UNTESTED** and covered by the VM test.

### chase, known hosts, authorized keys

```nix
# modules/chase/default.nix
let s = config.sshSigner; uid = toString config.chase.uid; in {
  chase.apps.ssh.agentSocket =
    if s.default then config.services.frisket.signer.socket else "/run/user/${uid}/gcr/ssh";
  chase.apps.ssh.identity = lib.mkIf s.default (fp "ssh-tpm-ecdsa");
  # A host-level identity needs a host-level agent: chase apps/ssh.nix:289 (CF1).
  chase.tiers.ops.apps.ssh.hosts.gateway = lib.mkIf s.default (
    if s.gatewayOnTpm
    then { agent = config.chase.apps.ssh.agentSocket; identity = fp "ssh-tpm-${s.gatewayKey}"; }
    else { keyFile = "/home/dan/.ssh/gateway_ed25519"; });     # gateway-only, preference 3
  # modem keeps passwordFile; it never reaches the signer (CG-8).
}

# modules/common.nix
let tpmAdmins = builtins.filter (h: builtins.pathExists ../admins/${h}/ssh-tpm-ecdsa.pub) admins; in {
  programs.ssh.knownHosts.server = { hostNames = [ "server" "10.0.0.4" ]; publicKey = "…"; };
  users.users.dan.openssh.authorizedKeys.keyFiles =
    map (h: ../admins/${h}/ssh.pub) admins                 # ed25519 stays: sops/age lineage + recovery
    ++ map (h: ../admins/${h}/ssh-tpm-ecdsa.pub) tpmAdmins;
}
```

- `admins/<host>/ssh.pub` stays: `age.pub` derives from it, and `install.sh` copies it.
- **Router plan requirement (OPS-3)**: every router image's `authorized_keys` is generated from the same `admins` list. It must include every `admins/*/ssh.pub` (ed25519 recovery) and every host's gateway TPM pub. An eval check is added once `routers/` exists.
- **Claude Code settings (F3)**: T5 adds `permissions.deny` entries for writes under `~/.config/systemd/user/**`, for `Bash(systemctl --user edit:*)`, `daemon-reload` and `set-environment`, and for `/run/galley-ask`. This is a speed bump, not a boundary. The one dialog does not depend on these: a rewritten `sudo-askpass.sh` can only lose the dialog (decision 28), never forge one.

---

## Testing strategy

Conventions:

- Whole-sentence test names, with a property comment above each test.
- stdlib `testing` plus `rapid`.
- swtpm is required in the Nix build (`FRISKET_REQUIRE_SWTPM=1`) and may skip locally.
- VM tests are shaped like `tests/host-dns.nix`.
- Every VM `machine.execute` has a timeout.
- Every test that involves time uses a fake boottime clock passed to `grant.New` and `peer.Options.Clock`.

### Unit tests (`go test ./...`, CGO off, in `mkFrisket`'s `doCheck`)

**`internal/tpmkey`** (swtpm via `linuxudstpm` on a relative socket, one swtpm per test):

- `TestAKeyFileSurvivesATPMRestart`
- `TestEverySignatureVerifiesWithTheKeyPublicKey`
- `TestRSAWithNoFlagsIsRefusedBecauseSHA1CannotBeSigned`
- `TestAClearedTPMSaysClearedNotCorrupt`
- `TestSigningLeavesNoTransientObjectsBehind`
- `TestSigningDoesNotLeakFileDescriptors`: 100 signs, `/proc/self/fd` unchanged, including with swtpm killed mid-run (CF5).
- `TestASignerKeySignsWhileTheTPMIsInDALockout`, which also asserts that a default-template key gets `TPM_RC_LOCKOUT` (OPS-8, H10).
- `TestLockoutIsNamedAndNotRetried`
- `TestKeygenWritesAFingerprintChaseAccepts`: `^SHA256:[A-Za-z0-9+/]{43}$` (CF6).
- `TestAKeyLoadsFromAStorePathWithNoPubBesideIt`

**`internal/agentsrv`:**

- `TestAForgedBindIsRefused`
- `TestASignForAnotherSessionThanTheLastBindIsRefused` (T3), which also runs in observe mode.
- `TestAHostboundRequestWhoseHostKeyIsNotTheBoundKeyIsRefused`
- `TestAnyForwardingBindMarksTheConnectionForwarded`
- `TestSSHSIGShowsItsNamespace` (real fixtures)
- `TestAPanicInOneRequestDoesNotStopTheNext`
- `TestAPeerThatIsNotTheConfiguredUserIsRefusedBeforeAnyMessage` (uid 0 and another uid; observe mode too) (CG-7)
- `FuzzNoAgentMessageCrashesTheParser`

**`internal/peer`:**

- `TestADeadPidfdIsNeverRoot`
- `TestATrustedUnitIsMatchedByInodeNotByPath`
- `TestOnlyFrisketsMainProcessIsTrusted` (ppid and exe) (F7)
- `TestTheClaudeChainAnchorsOnClaude` (H2 shape)
- `TestASystemdUserRootIsNeverGrantable`
- `TestATabShellRunningSshIsATerminal` (H2 fields)
- `TestACommandLaunchedThroughTheTerminalServerIsNotATerminalShell`, covering `kgx -- ssh`, `kgx -- bash -c`, `kgx -- git push`, a background job, and a fresh shell under `minShellAge` (SK2, EA4)
- `TestAnAgentCommandIsNeverATerminal` (H3: own session, tty 0)
- `TestAStorePathOutsideTheKnownSetIsUnusualAndNeverAllowed` (F2, SK1, EA1)
- `TestAPreloadedLibraryOutsideTheKnownSetMakesTheTerminalUnusual`
- `TestAnonymousExecutableMappingsAreIgnoredForTheClaudeAnchor` (H4)
- `TestARemoteChainNeedsARootSshdSessionParent`
- `TestADesktopLaunchedAppAnchorsOnTheApp`, from the K2 fixture: a known app is grantable; the same shape with the app outside the store is unusual; ssh directly under `systemd --user` is SessionRoot (CG-2)
- `TestADevShellGitBetweenTheTabAndSshIsUnusual`, from the K1 direnv fixture, with reason `devshell` (CG-3)
- `TestClaudeStartedInADevShellIsStillTheAnchorButItsDevShellGitIsUnusual` (CG-3)
- `TestAReparentedSshIsNeverGrantable`: `ssh -f` under `systemd --user` and under pid 1 (CG-9)
- `TestAnOldClaudeAfterASwitchIsKnownButMatchesOnlySameNameRules`: same name with a new hash matches, a new version does not (CG-22)
- `TestLoadKnownRejectsEmptyAndMalformedFilesAndKeepsThePreviousSet` (CG-12)

**`internal/signpolicy`:**

- `TestAStoreGlobInAnExeFieldIsACompileError`
- `TestATerminalShellToAnUnknownHostIsOfferedATabScopedGrant` (EA7)
- `TestATerminalGrantCoversOnlyItsOwnTab`
- `TestAKgxLaunchedWindowDoesNotInheritATabGrant`
- `TestObserveModeStillRefusesHardRefusals` (SK7)
- `TestRemoteIsRefusedWithoutAsking` (OPS-2)
- `TestTheMostSpecificRuleWins`: table-driven over the decision-22 tuple, including leaf+anchor against leaf+terminal, named destination against `known`, a tie that resolves to the stricter outcome, and an equal-tuple allow/refuse pair that fails to compile (CG-11)
- `TestARuleGrantOverrideIsDecodedStrictlyAndCappedByTheGlobal` (CG-10), including a revision-3 `for`/`max` rejected and a global `cap` above 24 h rejected (decision 24)

**`internal/grant`:**

- `TestAGrantEndsAtThePostedTimePlusTheChoiceAndUseNeverExtendsIt` (decision 24), plus a rapid property: for any sequence of `Use` calls, the end never moves.
- `TestATypedTimeAboveTheCapIsClampedAndSaysSo`
- `TestAnUnreadableOrZeroTypedTimeIsOnce`
- `TestATypedTimeOverridesTheCombo`
- `TestParseTypedAgreesWithGalleysVectors`: every line of the pinned `times.txt` (R4-1).
- `FuzzNoTypedTimeExceedsTheCap`: for any string, `ParseTyped` returns once, an error, or a time in (0, cap].
- `TestPresetsAboveTheCapAreNotOfferedAndOnceIsFirst`, including a per-rule cap of 1 h (decision 23).
- `TestTheClockLabelIsTheEndTheGrantGets`: with a fixed wall clock and fake boottime, the label's `HH:MM` equals `Expiry`'s wall time; a wall-clock jump after posting moves the label in later replies but not the boottime end.
- `TestUntilLogoutEndsWhenTheDisplaySessionChanges`, `…WhenTheStateFileIsUnreadable` and `…AtTheCapEvenWhileLoggedIn` (decision 26), with a fake `SessionReader`, plus a parser test against a copy of the real `/run/systemd/users/1000` [H17].
- `TestALateAllowOnceLetsExactlyOneMatchingRetryThroughWithinFifteenMinutes`: passes at 14m, a second retry asks, a different target asks, and 16m asks (F5, SK9).
- `TestALateAllowIsNotExtendedByUse`
- `TestAnyForPeeksWithoutConsuming`
- `TestPasswordSkipNeedsAnOpenPasswordWindow` (decision 29): a dialog choice of 2 h keeps the skip open at 1 h 59 m and shut at 2 h 01 m; a password typed another way keeps it open for 1 h; `once` opens nothing; `HoldPassword` never moves it backwards.
- `TestAGrantDoesNotSurviveASuspendLongerThanItsCap`: the fake boottime clock jumps 12 h while a wall-clock stand-in and a monotonic stand-in do not; the grant and the password window are both expired (CG-4)
- `TestAGrantForADeadAnchorNeverMatchesAReusedPid`: same pid, different starttime (CG-5)
- `TestSweepDropsOnlyExpiredEntries` (CG-5)

**`internal/galleyask`:**

- `TestAnAnswerFromAPeerOutsideGalleysCgroupIsNobody` (EA5)
- `TestAnAnswerFromGalleysOwnBoundSocketGetsThrough` (CG-1)
- `TestEveryOutcomeEmitsOneJournalRecord`
- `TestTheServiceQuestionEncodesToTheGoldenBytes` and `TestEveryGoldenAnswerLineDecodesToItsResult` (CG-16)
- `TestBusyIsNobodyAndLockedIsLocked` (CG-18)
- `TestAGrantableQuestionIsTheTimePickerFormAndAnUnusualOneIsNot` (decision 25), against the goldens.
- `TestAnOkWithNoComboTextOrAnUnofferedTextIsOnce`
- `TestAnOkOnTheUngrantableQuestionIsRefuse`
- `TestAskPasswordReturnsThePasswordOnlyToItsCaller`: the password never reaches a log record (the test captures slog output and searches it for the password).
- Runs against `tests/fakegalley`, built from the pinned `wire`, in every mode of its contract.

**`internal/sudogate`:**

- `FuzzNoRequestCrashesTheGate`
- `TestARequestThatPanicsTheParserIsDeniedAndTheNextAnswered`
- `TestARequestWithoutTheSudoTagIsDenied` (CG-6)
- `TestAGrantAuthenticatedSudoDoesNotMoveThePasswordWindow`: a 'G' → Y followed by an 'A' with the same 'S' leaves `PasswordUntil` unchanged, and an 'A' with a different 'S' and no dialog record moves it to now + 1 h (CG-6, decision 29)
- `TestShadowModeNeverDenies`: refuse rules, untrusted programs, unusual chains, nobody to ask, and a panicking parse all reply 'Y' with a `shadow:true` record (CG-19)
- `TestADotDotPathUnderATrustedDirIsNotTrusted`, covering `..`, `/./`, `//` and a nested subdirectory, plus a rapid property that no non-clean path is trusted (EA3)
- `TestAStorePathOutsideTheProfilesIsNeverAllowed`
- `TestLESSOPENIsRefused`
- `TestAnUnlistedVariableTurnsAllowIntoAsk`
- `TestTERMINFOIsAllowedBecauseSudoersKeepsIt`
- `TestAMissingPathDirectoryUnderHomeIsUntrusted`, using the host's real PATH shape (SK5)
- `TestAMissingPathDirectoryUnderARootOnlyParentIsIgnored`
- `TestSudoShellStringsAreUnescapedBeforeDeciding`
- `TestSudoeditIsDecidedOnTheFilesAndIgnoresEditorEnv`
- `TestAnArgvGrantDoesNotCoverADifferentUnit`
- `TestAGrantNeverCoversADifferentOperation`
- `TestAnOpGrantOnlyAppliesToOpsMarkedGrantable`
- `TestUnmatchedCommandsAreGrantedByArgvOnly`
- `TestTheQuestionNamesTheScopeAGrantWouldHave` (F6): "this exact command from this claude" or "any '<op title>' from this claude"
- `TestADenylistedUnitStaysAskInsideAGrant`
- `TestALateSudoAllowCoversOnlyTheSameResolvedArgv`
- `TestABadRulesFileServesRefuseAll` (OPS-1)
- `TestServeRefusesToStartWithoutTheNamedFd` (CF12)
- `TestALockedScreenRefusesAtOnceWithItsOwnMessage` (CG-18)

`internal/sudogate`, the one dialog (decisions 27–29). The peer checks use an injected `PeerInfo` (what `SO_PEERCRED` and `PIDFD_GET_INFO` would return):

- `FuzzNoAskpassMessageCrashesTheGate`
- `TestAnAskpassWhoseGidOrEgidIsNotTheAskpassGroupIsRefused`
- `TestAnAskpassWhoseParentIsNotAPendingSudoIsRefused`: no 'G' at all; a 'G' for another user; a 'G' older than 10 min; a 'G' already consumed by its 'A'.
- `TestAnAskpassWhoseParentIsNotSetuidRootIsRefused`: a dan process at a dead sudo's pid (euid dan) is refused, so it cannot get that sudo's dialog (R4-15).
- `TestTheNewestPendingRecordForAPidIsTheOneUsed`
- `TestAPrepareClearsTheDialogRecordSoALostDecidedMeansAQuestion` (R4-17)
- `TestAnEmptyPasswordSendsNoDecided` (askpass side) and `TestADecidedWithNoChoiceIsRefused` (gate side)
- `TestAnAskpassWhoseParentChangesBetweenPrepareAndDecidedRecordsNothing`
- `TestAnAskpassMessageThatNamesAPidOrCarriesAChainIsRefused` ('S', 'k' and unknown tags on 'P' and 'D').
- `TestADialogRecordIsUsedOnlyByTheSudoItWasMadeFor`: a record for `(P, t1)` is not used by an 'A' with `(P, t2)` (pid reuse) or `(Q, t1)`.
- `TestADialogRecordIsUsedOnceAndThenGone` (replay).
- `TestADialogRecordIsIgnoredWhenTheSudoWasLetThroughByAGrant` (decision 29).
- `TestTheLastTrysDialogIsTheOneThatCounts`: three 'D's for one 'S'; the 'A' uses the third.
- `TestADialogApprovesOnlyWhenTheShownArgvEndsWithTheRunArgv`: table over a matching argv, a different `run_argv[0]` basename, an extra word, `-s`, `-i`, sudoedit, and a cut 'v'.
- `TestAnUntrustedProgramAfterTheDialogStillAsks` (EA3), with the reason in the question text.
- `TestAVariableToAskAboutAfterTheDialogStillAsks`, including `NIXOS_NO_CHECK`.
- `TestAnUntrustedPathEntryDoesNotForceASecondQuestionAfterTheDialog` (R4-14, pinned on purpose).
- `TestARefuseRuleStillRefusesAfterTheDialog`
- `TestADialogGrantIsArgvScopedEvenForAnOpGrantableOp` (F6)
- `TestADenylistedUnitIsAllowedOnceFromTheDialogButNeverGranted`
- `TestAnUnusualChainIsOfferedOnceOnlyAndGetsNoGrant`
- `TestADialogSetsThePasswordWindowToTheChosenTimeAndAQuestionNeverDoes` (decision 29): dialog `2h` → `PasswordUntil = posted + 2h`; a later grant-authenticated question choosing `8h` leaves it.
- `TestNoAskpassMeansThePlainQuestion`: 'A' with no dialog record and a command needing asking goes to step 12.
- `TestTheApprovalReplyNamesTheEndAsAClockTime`
- `TestShadowModeRecordsTheDialogAsAWouldBeGrantAndStillApproves` (decision 21).
- `TestAFifthPendingDialogForOneAnchorIsBusy`

**`cmd/frisket-sudo-askpass`** (gate and galley faked over socketpairs; the binary built normally, not setgid):

- `TestThePasswordGoesOnlyToStdout`: it is not in the 'P' or 'D' bytes, stderr, the environment of anything started (nothing is), or any file under a temp `HOME`.
- `TestTheTimeIsSentAndAcknowledgedBeforeThePasswordIsWritten`
- `TestALostAcknowledgementStillWritesThePassword`
- `TestTheAskpassIgnoresGalleyAndRuntimePathsInItsEnvironment`: with `GALLEY_SOCKET`, `XDG_RUNTIME_DIR` and `HOME` pointing at a fake listener, it still dials the configured path, and the fake sees nothing.
- `TestTheAskpassIgnoresItsPromptArgument`: a `-p` prompt with markup and newlines never reaches the form.
- `TestARedirectedStdoutOrAChildAtStartStopsTheDialog`: stdout a regular file, a FIFO path, `/dev/null`; a child process present at start (S9).
- `TestCancelWritesNothingAndExitsOne`
- `TestTheRowIsWithdrawnWhenTheParentExits`
- `TestAGateNoFallsBackToThePlainBoxAndSendsNoTime`
- `TestARetryListsThePreviousChoiceFirst`
- `go list -deps ./cmd/frisket-sudo-askpass` contains no `internal/sudogate`, `execrule`, `policy` or go-tpm (decision 28).

**`execrule.DecideWords`:**

- `TestWrappersAreProgramsNotPrecommands`
- A property test that `DecideWords(Parse(s)) == Decide(s)` for readable strings.

**Dependencies:** the `go list -deps` assertions in decision 10 and the T2 done-condition.

**Flake checks** (CG-20): `checks.no-replace`, `checks.named-tests-ran` (every name in `nix/security-tests.txt`, which lists every test above that cites a finding id), `checks.fuzz-gate`, and `checks.known-paths` (`tests/known-paths.nix`, CG-12).

### VM tests in frisket (`runNixOSTest`, importing exactly `self.nixosModules.*`)

`tests/signer.nix` uses:

- `virtualisation.tpm.enable`;
- two sshds with **distinct host keys**;
- `tests/fakegalley` running as a real `galley.service` user unit that binds `/run/galley-ask/dan.sock` itself;
- a stand-in `frisket.service` with frisket's real hardening;
- dan with linger.

Subtests:

- Keygen through the template unit, then the keys load after a reboot.
- `/run/frisket/known-store-paths` exists, has the fixed format, and lists the session's ssh.
- dan cannot open `/dev/tpmrm0`.
- ecdsa, rsa-sha2-256 and rsa-sha2-512 logins work.
- The frisket main process signs without a question, also with galley absent.
- A child exec'd inside `frisket.service` (`ssh-add -L`, then a sign) is **asked** (F7).
- A `systemd-run --user --unit=frisket-x` impostor is asked with no time picker. It also tries a cgroup move from dan's real `user@` session.
- Tamper T3 is refused, in enforce and in observe mode.
- `-A` to the second sshd is refused.
- An OpenSSH 8.8 client is asked as unbound.
- Renamed and deleted binaries are flagged unusual.
- A `nix-store --add` fake `openssh-10.5p1/bin/ssh`, a fake `claude-code-x/bin/.claude-unwrapped` anchor, and a fake `gnome-console-*/bin/.kgx-wrapped` parent are each flagged unusual. Each is **asked, not allowed**, with no time picker (F2, SK1, EA1).
- The real `.kgx-wrapped` started with `LD_PRELOAD=fake.so`, spawning ssh, is flagged unusual. Use a fake terminal server with a pty if kgx cannot run in the VM.
- A terminal-shaped chain from a real interactive shell is allowed silently, which proves the known set covers it. `kgx -- ssh` and `kgx -- bash -c 'ssh …'` shapes are asked.
- **A real answer gets through (positive galley test):** fakegalley scripted `answer 0` lets an asked sign through, and its log shows the question. The journal names `…/app.slice/galley.service` as the galley peer (CG-1).
- A rebound `/run/galley-ask/dan.sock` (socat outside `galley.service`) is treated as nobody, and the journal records it (EA5).
- **G-P1 negative:** fakegalley started through a `systemd --user` socket unit (inherited fd) is reported with the `init.scope` peer, and its answers are nobody. This pins why decision 13 binds directly (CG-1).
- `sudo SSH_AUTH_SOCK=/run/frisket-signer/agent ssh …` and `sudo -E ssh …` are refused at once with the "peer uid 0" log line, and fakegalley's log shows no question (CG-7).
- With fakegalley in `-locked`, an asked sign is refused in under 1 s with "screen locked" (CG-18).
- **Suspend:** grant a destination for a typed `1m`, then `rtcwake -m mem -s 70`. After resume the next sign asks. If the VM cannot suspend, the subtest is replaced by the fake-clock unit test and the plan records that (CG-4).
- **Time picker** (decision 24): fakegalley `allow '15 minutes …'` makes a grant, and its log shows the combo values with clock times and `once` first. A second sign within the time is silent, and fakegalley's log shows no question. `allow once` grants nothing: the next sign asks. `allow once typed 2m` grants 2 minutes, and a sign at 2 min 10 s asks. A typed `99h` (sent with `raw`) is clamped to the policy cap, and the journal says so.
- **Absolute end:** a grant typed as `2m` and used every 20 s still asks at 2 min 10 s.
- **Until logout** (decision 26): `allow 'until logout …'`, then `loginctl terminate-user dan` and a fresh login. The next sign from a new anchor asks. The journal records the grant ended with the session within a minute (the `Sweep`). Also asserts that the signer could read `/run/systemd/users/1000` under its hardening.
- An unusual chain's question is `kind=question` with `Allow once` and `Refuse` only, in fakegalley's log.
- Pid reuse via `ns_last_pid` is refused.
- A peer in a user namespace is refused.
- `PTRACE_SEIZE` and `pidfd_getfd` from the signer's unit fail with EPERM.
- The deadline: `LoginGraceTime` 30s and signer 20s refuses. A late Allow once lets exactly one retry through.
- With ENOENT on the galley socket, frisket is allowed and the rest refused.
- A remote ssh session that sets `SSH_AUTH_SOCK` to the signer is refused at once (OPS-2).
- The socket is invisible inside a flong-style namespace.
- **TPM cleared** (swtpm state reset): `serve` stays up with `STATUS=degraded`, the health timer fails, and the alert posts a question. After re-keygen, logins work (OPS-4).
- **Crash loop**: a policy that makes the stand-in exit at start keeps the socket active, given `StartLimitIntervalSec=0`.
- **Known set fail-safe:** with a broken `nix-store` substituted through the script's argument, a re-run of the activation script leaves the old file in place (CG-12).
- Stock `pkgs.ssh-tpm-agent` 0.9.0, the deployed version, logs in with these **noDA** key files (N1).

`tests/sudo-gate.nix` is based on sudo-vm test3: no tty via `setsid -w runuser`, a tty via `script -qec` **with captured output**. It runs the gate in `enforce` unless a subtest says otherwise. Subtests:

The node has the real setgid wrapper, `SUDO_ASKPASS=/run/wrappers/bin/frisket-sudo-askpass` (and, in one subtest, the T5 `sudo-askpass.sh`), and fakegalley as `galley.service` with `-askpass-gid 953`. Short times are typed (`2m`), so no subtest waits an hour.

- With a tty, the gate is never contacted, also with `-A`. With `-A`, the askpass shows the plain box (no pending sudo), and fakegalley's log shows `kind=entry`.
- **One dialog** (decision 27): no tty, no grant, `sudo systemctl restart foo`. fakegalley `askpass <pw> '15 minutes …'`. The command runs, and fakegalley's log shows **exactly one** item: the askpass-class form, whose text has the chain and `sudo systemctl restart foo`. sudo's stderr has "allowed … until HH:MM". The journal has the grant's end and no password.
- The same through `sudo-askpass.sh` (T5's `exec`), which proves the `exec` keeps the askpass sudo's direct child.
- **Cancel**: `askpass-cancel` → sudo fails authentication, nothing is granted, and no 'A' arrives.
- **Wrong password**: `askpass wrong '1 hour…'`, then `askpass <pw> 'once'`. Two forms are logged, the second says "not accepted" and lists `1 hour…` first. The command runs once and no grant is made (the last try's choice counts).
- **A rule-allowed command with no grant still needs the password** (SK3): the dialog is asked.
- A dialog grant of `2m` lets the identical sudo from a new `bash -c` under the same anchor skip both prompts. A different unit gets one plain question (the time-picker form, from the `sudo-gate` caller) and no password.
- An op-grantable op (`daemon-reload`) approved **in a question** naming the op passes within the grant, and a different op asks. The same op approved **in the dialog** is granted by argv only.
- **Password window** (decision 29): dialog `2m` for command X; at 1 min a different command Y gets a question, chosen `typed 10m`; at 2 min 10 s, Y asks for the dialog again (the window shut, though Y's grant lives), with no second question, because Y's grant covers it.
- A grant-authenticated sudo does not widen the window: a dialog at t=0 with `2m`, grant skips at 30 s and 1 min 50 s, and the skip ends at 2 min 10 s (CG-6).
- **Resolved differently** (step 10): a dan-owned `~/bin/systemctl` early in PATH, then `sudo systemctl status`. The dialog shows `sudo systemctl status`, the gate resolves `~/bin/systemctl`, and a second question follows whose text names the path and the reason. The same for an unlisted environment variable kept by `sudo --preserve-env=FOO`.
- **Forged `SUDO_ASKPASS`**: a script that prints the right password (dan-owned, not setgid). The command does not run silently: fakegalley's log shows the plain question, and the gate journal shows "no dialog record".
- **Borrowed askpass, environment**: a `SUDO_ASKPASS` wrapper script that sets `GALLEY_SOCKET` and `XDG_RUNTIME_DIR` to a socat listener, then `exec`s the genuine askpass. The listener receives nothing, and fakegalley shows the genuine dialog.
- **Borrowed askpass, parent**: the genuine wrapper run directly from a shell under the anchor. The gate refuses its 'P' ("parent is not a pending sudo"), and it shows the plain box on the user socket.
- **Race for another sudo**: two sudos from one anchor, A and B, with A's dialog answered `8h` and B's `once`. Each 'A' uses its own record. B gets no grant, and A's grant names A's command only.
- **stdout redirected**: a wrapper that `exec`s the askpass with stdout to a file. The askpass shows no dialog, and sudo fails authentication (S9's naive case).
- **No askpass, ticket**: two sudos in one `bash -c`, the second a different command. The second gets the plain question and no dialog.
- **No askpass, `-S`**: `echo pw | sudo -S cmd` gets the plain question, never a silent allow.
- **Ptrace**: as dan, `strace -p` on a running askpass fails with EPERM, and `/proc/<askpass>/status` shows the setgid egid (decision 28; AP1).
- **Until logout**: a dialog `until logout`, then `loginctl terminate-user dan` and a fresh login. The next sudo from a new anchor asks, and the gate journal shows the grant ended with the session.
- **Shadow** (second node): the dialog is shown with the shadow line. The gate journal records a would-be grant with its end, and the next sudo still asks for the password.
- **'S' agreement:** the gate logs the 'S' from 'G' and from 'A' for one sudo, and they are equal (decision 16 assumption).
- A different anchor asks.
- Requester killed mid-question: the row reads "requester gone". A late Allow once lets the identical retry through after 5 min (fake clock), and a second retry asks.
- Y4: the ticket is written on refusal, the plugin refuses the cached retry, and with the gate stopped that retry is **still refused**.
- An impostor socket in a dan-owned directory is refused ("not root's").
- The socket-activated peer uid is asserted (F2 risk).
- **Gate stopped** (ECONNREFUSED), and separately **`/run/frisket-sudo` removed** (ENOENT): no-tty sudo is refused with the same message. Terminal and root `sudo id -u` still work (decision 11, OPS-5).
- **Crash loop past the old burst**: the socket stays active. If it is forced to fail, no-tty sudo is refused and tty sudo works (OPS-1, EA2).
- Gate hang → timeout deny.
- bob never gets a PAM grant.
- A `nix-store --add` fake `cat` is asked and flagged.
- `sudo /run/current-system/sw/bin/../../../home/dan/bin/cat` is asked and flagged untrusted, and the raw `command=` is logged (EA3).
- `LESSOPEN` is refused, and no marker file appears.
- `-s`, `-i` and sudoedit are decided. `-v` and `-l` are untouched.
- **Locked screen:** fakegalley `-locked`; a no-tty sudo needing a question is refused in under 2 s with "screen locked" (CG-18).
- **Shadow mode** (a second node, `mode = "shadow"`): a refuse-rule command, an untrusted path and a no-grant command all run after the password; the gate journal has `shadow:true` records for each; with the gate stopped no-tty sudo still works after the password; the PAM helper never skips the password (CG-19).
- **Health check:** with the plugin loaded the health unit passes; with a test-only sudo.conf lacking the plugin line it fails (CG-17, spike SV1).
- **Remote**, with fakegalley up and never answering:
  - make-usb.sh's exact `printf pw | ssh vm "sudo -S -p '' tar -C /var/lib -c …"` and `sudo -S cat /var/lib/sbctl/…` both succeed in under 5s;
  - with the gate stopped they still succeed (OPS-2).
- The remote-chain shape (sshd-session paths, uids, parents) is dumped and pinned (spike R1).
- The actual run_envp after env_reset is dumped and pinned.
- A broken `.so` or a wrong symbol fails the **sudo.conf derivation build**.
- A group-writable sudo.conf fails the health timer.
- `/etc/pam.d/sudo` renders the grant line before `pam_unix`.

### galley tests

- The item-10 regressions.
- Caller forgery, including a client-sent `caller` field.
- The services-kind restriction (no markup, no icon, no key, default -1).
- The service-question golden files round-trip (CG-16).
- Self-bound services socket: stale file replaced at start; removed on clean exit (CG-1).
- Locked screen answers `locked` and leaves user items alone (CG-18).
- A **rendered screenshot** of a service row next to a user row that copies its badge, and of the sudo dialog (askpass class) next to a user-posted copy of its form, which must not get the reserved look.
- The time-picker and askpass-class cases in item 10.
- The drop-in warning.
- The adapted VM test.

### nix-config checks (new `checks.x86_64-linux` output, on the pinned nixpkgs)

**`sudo-lockout`:**

- Imports `nixosModules.sudoGate`, the host's real `security.sudo` settings and its PAM config.
- Runs `sudo id -u` with a tty, as root, and with no tty against a real gate, in both `shadow` and `enforce`.
- Runs no-tty sudo with the gate stopped and expects a refusal with a message (enforce) or success after the password (shadow).
- Runs no-tty sudo with the askpass socket stopped and expects the plain box and then the question, never a lockout.
- Runs a remote `sudo -S`.

**`signer-wiring`:**

- Evaluates `config.system.build.toplevel.drvPath` for each host with `sshSigner.default = true`, for both values of `gatewayOnTpm`, so the assertions run (CF1).
- Asserts:
  - `hosts.gateway.agent == agentSocket` whenever `identity` is set;
  - gcr is off exactly when `default` is set;
  - the rendered policy's exact paths equal what the system uses;
  - `core.sshCommand` equals the policy's ssh leaf path (decision 18);
  - every committed `.fp` equals `ssh-keygen -lf` of its `.pub` (non-IFD derivation) (EA11);
  - the frisket lock node's nixpkgs is the root nixpkgs (CF3, CF8);
  - no normal user is in tss;
  - **socket and names agree** (CG-13): `home-manager.users.<forUser>.services.galley.serviceSocket.path == services.frisket.signer.galleySocket == services.frisket.sudoGate.galleySocket`; `serviceSocket.enable` is true whenever either service is enabled; and `services.galley.services` has an attribute named `services.frisket.signer.user` and one named `services.frisket.sudoGate.user` for each enabled service. Both modules' `forUser` equal the home-manager user that runs galley;
  - **ssh host blocks** (CG-8): every signer host has `IdentitiesOnly yes` with a TPM `.pub`, modem has `PubkeyAuthentication no`, and no block names `id_ed25519` except `mac` while `macOnTpm` is false;
  - **askpass** (decision 28): `services.galley.askpassGroup == services.frisket.sudoGate.askpass.group` whenever the dialog is enabled; no user is in that group; the rendered `sudo-askpass.sh` contains the `exec /run/wrappers/bin/frisket-sudo-askpass` line; `grant.cap` ≤ 24 h in both the signer policy and the gate.

---

## Pre-build spikes (before T2 and T3 freeze interfaces)

| Id | Question | How | Blocks |
|---|---|---|---|
| **G-P1** | For a socket-activated **user** socket, what pid and cgroup does the client get from `SO_PEERCRED`/`SO_PEERPIDFD` + `PIDFD_GET_INFO`? And for a socket galley binds itself? | A `systemd.user.sockets` unit with `Service=` a tiny listener, and the same listener binding the path directly. Client prints pid, `/proc/<pid>/cgroup` and cgroupid. VM with dan lingering, plus once on the host | Decision 13; T1 items 2 and 12; T2 `galleyask` (CG-1) |
| K1 | The exact process shape and `/proc/<pid>/stat` fields (session, tty_nr, tpgid, pgrp) of `kgx -- sleep 60`, `kgx -- bash -c 'sleep 60'`, `kgx -- bash -i` and a real tab. **Also:** a tab inside a direnv'd project whose devShell ships `git`, running `git fetch` over ssh; and `claude` started in that project, running `git push` through its Bash tool | By hand at the machine as dan, no root (it opens windows). Record the fixtures, including `readlink /proc/<pid>/exe` for each link | T2 `internal/peer` Terminal fields (SK2, EA4); decision 18 (CG-3) |
| **K2** | The chain of an app started from the GNOME overview and of one started by D-Bus activation, and how each runs `git` and `ssh` (direct child, helper process, re-parented?). Candidates: GNOME Text Editor's or Builder's git, a git GUI, any IDE dan uses | By hand at the machine; record fixtures as in K1 | Decision 18; the transient set (CG-2) |
| **D1** | Can the known set gain a second tier: paths whose narinfo carries a valid `cache.nixos.org-1` signature over the daemon-recorded narHash? Can the signer read that from the Nix DB as `ssh-signer`, and how fast? Can dan, as a non-trusted user [H13], get an unsigned or forged-signature path recorded with such a signature? | Spike: read `/nix/var/nix/db/db.sqlite` read-only (ValidPaths.sigs, narHash), verify ed25519 sigs in Go, time it for 2,888 + devShell paths; attack with `nix-store --add`, `nix store add-sig` (expected to need trusted-user), and a local derivation named like openssh | v2 only. Until D1 passes, devShell binaries stay unusual (CG-3) |
| N1 | Does stock ssh-tpm-agent 0.9.0 load noDA ECC **and RSA** key files and log in? | Extend `spikes/tpm-keys/vm/test.nix` with noDA keys made like `spikes/tpm-da-lockout/code` | Key template (OPS-8) |
| P1 | Does the persistent-parent fallback work? A key under an RSA SRK persisted at `0x81000001` with the systemd template, a salted session, and interop with stock agent 0.9.0, before and after reboot | swtpm plus a VM, now rather than after G0 | G0 fallback (EA9) |
| R1 | The sshd-session privsep shape on OpenSSH 10.5 for `ssh host cmd` and `ssh -t host`. Also: is the pam_exec helper's parent the same sudo process that calls the approval plugin (decision 16)? | VM dump of the chain as root; log `getppid()` and `user_info pid=` in a debug build | Remote test (OPS-2); 'S' tag (CG-6) |
| **SV1** | Does `sudo -V` run as root call `show_version` on an **approval** plugin, so the health unit can grep for it? | sudo-vm test3 with a stub approval plugin whose `show_version` prints a marker | T4 health unit (CG-17) |
| X1 | Does `system.extraDependencies = [ self.checks.….sudo-lockout ]` evaluate without recursion when the check imports the host's `security.sudo`? | `nix eval …toplevel.drvPath` in a branch | Guard 2 (CF2) |
| **AP1** | The askpass identity (decision 28), in a VM with sudo 1.9 and Linux-PAM as on the host. (1) A NixOS setgid wrapper exec'ing a static Go binary: is the process non-dumpable, `AT_SECURE`, with egid set, and does Go keep secure mode? (2) A service with no capability, `ProtectProc=invisible` and `ProcSubset=pid` (the gate's hardening): does `PIDFD_GET_INFO` on the askpass's `SO_PEERPIDFD` give the egid and the ppid? identity-vm printed only ruid and euid. Does `SO_PEERCRED` give the egid? Does `PIDFD_GET_INFO` on `pidfd_open(ppid)` give the setuid sudo's euid 0 and ruid to the same gate? (3) Is the askpass's ppid the same sudo pid as the pam_exec helper's `getppid()` and the plugin's `pid=`, on every try? (4) Does `passwd_tries` re-run the PAM stack (helper, then askpass) per try (H16 is from source only)? (5) Can both services read `/run/systemd/users/<uid>` under their hardening, and does `loginctl terminate-user` clear `DISPLAY`? (6) Does `sudo -A` from a tty skip the helper's 'G'? | Extend `spikes/sudo-vm-sceptic` test3 with a stub askpass and a stub gate printing what they see | T4 askpass and gate (R4-2), decision 26 |

---

## Migration and rollback

Gates that need a person at the machine.

**G0 / M0, PTT.** On each host:

```
sudo env TPM=dev:/dev/tpmrm0 tk srk
tk keygen /tmp/k/ec ecdsa
tk keygen /tmp/k/rsa rsa
tk bench /tmp/k/*.tpm
```

Also record on each host:

- the SRK type from `/run/systemd/tpm2-srk-public-key.pem`. dan-blade's is RSA-2048 [H1], which may mean ECC primaries fail on this PTT or that the handle predates systemd;
- `tpm2_getcap properties-variable`: `TPM_PT_LOCKOUT_COUNTER`, `MAX_AUTH_FAIL`, `LOCKOUT_INTERVAL`, `LOCKOUT_RECOVERY`, and whether `lockoutAuthSet` is set;
- `bootctl status` on dan-desktop;
- **on dan-desktop, the H2–H5 checks** (a tab's chain and stat fields, the Bash-tool session shape, claude's maps, closure membership), filling the dan-desktop column of the host-facts table (CG-21). Any difference (another terminal, another shell path) becomes a per-host policy value before M2.

Unknowns this settles:

- ECC SRK `CreatePrimary` on PTT;
- `RSA_Decrypt` with the Null scheme;
- noDA creation;
- per-sign latency.

Decisions:

- If `CreatePrimary` fails, use parent `0x81000001` (whatever its type), but only if P1 passed. Keys then depend on systemd keeping that handle, which is one more thing the recovery key covers. **ASSUMPTION-UNTESTED** until P1.
- If latency is above about 150 ms, build caching.

**M1, deploy alongside.**

- `sshSigner.enable = true`, `default = false`, and the galley service socket on.
- Run `systemctl start frisket-signer-keygen@ecdsa` (and `@rsa` only if needed).
- Copy `new/*.{tpm,pub,fp}` into `admins/<host>/`, commit, and switch. Do this on **both** hosts.

**M2, prove the keys on both hosts before either flips (OPS-3, CG-8).**

1. Both hosts are switched with `tpmAdmins` containing both hosts' pubs. Push the pubs to GitHub and `server`. Add them by hand to dan-mac's `~/.ssh/authorized_keys`.
2. Run this from **each** host against the other host, `server`, GitHub and `mac`. `BatchMode` proves it works with no tty and no passphrase fallback:

   ```
   SSH_AUTH_SOCK=/run/frisket-signer/agent ssh -o IdentitiesOnly=yes -o BatchMode=yes \
     -i admins/<h>/ssh-tpm-ecdsa.pub <target> true
   ```

   Set `sshSigner.macOnTpm = true` only when the `mac` cell passes.
3. **Gateway.**
   - Record `dropbear -V`.
   - Try `-o PubkeyAcceptedAlgorithms=ecdsa-sha2-nistp256` first, then `rsa-sha2-256` with the RSA key, against `root@10.0.0.1 true`.
   - Record the result in `docs/signer.md`.
   - Set `gatewayKey` and `gatewayOnTpm = true` only on success. Otherwise create the gateway-only key file (preference 3).
4. **Modem.** `ssh modem` still logs in with its password, and the signer journal shows no connection from it (`IdentityAgent none`).
5. Every cell must pass before any `default = true`. The `mac` cell may stay on ed25519 (`macOnTpm = false`) without blocking.

| From \ to | other host | server | GitHub | gateway | mac | modem |
|---|---|---|---|---|---|---|
| dan-blade | TPM | TPM | TPM | TPM or gateway file | TPM or ed25519 file | password |
| dan-desktop | TPM | TPM | TPM | TPM or gateway file | TPM or ed25519 file | password |

**M3a, observe (SK7).**

- `default = true` with policy `mode = "observe"` on one host. Switch, then **log out and log back in immediately**: gcr goes away and new sessions get the signer.
- Run it for 3–5 days with the real 3–4 concurrent Claude sessions.
- Count would-be prompts per day, anchor, destination and unusual reason (especially `devshell` and desktop apps):

  ```
  journalctl -u frisket-signer -o json | jq 'select(.observed)'
  ```

- Observe mode answers every ask itself, so it records no chosen times. Tune `grant.cap`, globally or per rule (decision 23), from the would-be prompt counts. Do not widen the anchor.
- Fill in the "Measured" column of the day table.
- Go to enforce only if the median would-be prompts per day is at most 10. If `devshell` prompts dominate, bring D1 forward before enforcing.

**M3b, enforce.**

- `mode = "enforce"`, then the other host after a day.
- Hand checks:
  - a new tab shows `SSH_AUTH_SOCK=/run/frisket-signer/agent`;
  - `kgx -- ssh <host>`, `kgx -- bash -c 'ssh <host>'` and `systemd-run --user ssh <host>` are asked and badged;
  - a typed ssh in a tab to a known host is silent;
  - `git fetch` in a direnv'd project with a devShell `git` is asked as unusual (reason `devshell`);
  - a desktop app's push is asked, and offers the time picker if the app is store-built;
  - lock the screen, trigger an asked sign from a timer, and see an immediate refusal;
  - a question shows the time picker with clock times; typing `45m` grants until the time shown in the journal; typing `hunter2` is refused by the window with the hint; "until logout" ends at the next logout;
  - `kgx -- bash -i` behaviour is recorded (R1);
  - Claude Code in auto mode is asked before writing `~/.config/systemd/user/x.service` (F3);
  - `systemctl --user cat galley.service` shows no unexpected drop-ins.
- A fallback to `id_ed25519` at this point means M2 was skipped. With no tty it fails, so roll back.

**M4a, sudo gate shadow (CG-19).**

- Enable `sudoGate.enable` with `mode = "shadow"`, only after X1, SV1 and AP1 are settled and `sudo-lockout` passes.
- Watch the health timer.
- Run it for 3–5 days. Count would-be questions, refusals and password skips per day:

  ```
  journalctl -u frisket-sudo -o json | jq 'select(.shadow)'
  ```

- The one dialog is live in shadow (decision 27). T5's `sudo-askpass.sh` change ships with M4a, so dan sees the dialog with its shadow line from day one. Count, per day:
  - dialogs, and the times chosen in them;
  - would-be second questions after a dialog, by step-10 reason. If `resolved differently` is common, look at PATH before enforcing;
  - fallbacks to the plain box, by reason (`no pending sudo`, `socket missing`, `galley refused`). Any `galley refused` means T1 item 5b is not deployed.

  ```
  journalctl -u frisket-sudo -o json | jq 'select(.shadow) | {dialog, choice, would, reason}'
  ```

- Fill in the sudo rows of the "Measured" column. Go to enforce only if the would-be questions are at most 10 per day, no would-be refusal hit a command dan actually needed, and no dialog was followed by an unexplained second question.

**M4b, sudo gate enforce.**

- `sudoGate.mode = "enforce"`.
- Break-glass: a `sudo-gate.nix` VM subtest shows `run0 id -u` with a polkit text agent (`pkttyagent`) working with the `.so` broken. If it does not, the plan states that **the only break-glass is the boot menu at the console**, and that SSH-only access cannot recover a sudo lockout (SK8).
- Set `boot.lanzaboote.configurationLimit` explicitly to at least 5.
- Hand checks:
  - a first agent sudo shows one dialog and no second question; sudo's output says "allowed … until HH:MM";
  - a wrong password gives the dialog again with the previous choice first;
  - `ls -l /run/wrappers/bin/frisket-sudo-askpass` shows `-r-x--s--x root frisket-askpass`;
  - `galley --forms --add-password P --add-combo 'Allow for' --combo-values once` posted by hand from a terminal does **not** get the "sudo password" look.

**M5, recovery.**

- ed25519 stays in `authorizedKeys`, on GitHub, in `admins/<host>/ssh.pub`, in every router image, on dan-mac, and on disk with its passphrase.
- Write `docs/signer.md` "TPM cleared, firmware update or new board":
  1. Set `sshSigner.default = false` and switch with terminal sudo. gcr, `SSH_AUTH_SOCK`, the ssh host blocks and chase's ed25519 path come back.
  2. Run `systemctl start frisket-signer-keygen@ecdsa` (and `@rsa`), then copy and commit `.tpm/.pub/.fp`.
  3. Push the new pubs to GitHub, `server`, the gateway or router image, dan-mac, and the other host's `authorizedKeys`, using the ed25519 key.
  4. Set `default = true` and switch.
  5. Separately, re-enrol the Blade's TPM disk unlock (`scripts/tpm-enroll.sh`).
- Before ME/BIOS firmware updates, run `ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o IdentityAgent=none server true`.
- DA lockout: if `lockoutAuth` is empty, `sudo tpm2_dictionarylockout --clear-lockout` ends it at once.
- The runbook is exercised once in `tests/signer.nix`.
- Update `installer/install.sh`'s closing text: TPM keys need keygen after a reinstall.

Rollback, cheapest first:

1. `sshSigner.default = false`: gcr, `SSH_AUTH_SOCK`, the ssh host blocks, `core.sshCommand` and chase revert.
2. `sshSigner.enable = false`.
3. `services.frisket.sudoGate.askpass.enable = false`: the wrapper and askpass socket go away. `sudo-askpass.sh` then runs today's box, and every first sudo gets revision 3's password-then-question.
4. `sudoGate.mode = "shadow"`: the gate can no longer deny anything.
5. `sudoGate.enable = false`: the plugin line and PAM rule go away.
6. If sudo is broken anyway: boot the previous generation from the systemd-boot/lanzaboote menu at the console. run0 or pkexec only if M4b's subtest proved it.
7. Last resort: stock `ssh-tpm-agent` loads the same key files [spike: tpm-keys (4)], subject to N1 for noDA keys.

---

## Work breakdown

**Fixed interfaces:**

- Go APIs above, including `grant.New(clock, sessions)`, `grant.Choice`, `grant.Presets`, `grant.ParseTyped`, `galleyask.Answer`, `galleyask.AskPassword` and `galleyask.ErrLocked`.
- Wire protocol v1, including the `'S'`, `'m'` and `'v'` tags, and the askpass socket's 'P' and 'D' messages and replies (decision 28).
- The service question and answer wire format, both shapes (decision 25), the askpass-class form, the time grammar, and the golden files including `times.txt` (CG-16).
- The preset list, its order (`once` first), and its labels (decision 24).
- `tests/fakegalley` flags and behaviour (CG-15), including `-askpass-gid` and the `allow`, `askpass`, `refuse` and `raw` script actions.
- Socket paths: `/run/frisket-signer/agent`, `/run/frisket-sudo/gate.sock`, `/run/frisket-sudo-askpass/askpass.sock`, `/run/galley-ask/dan.sock`, `/run/frisket/known-store-paths`.
- `/run/wrappers/bin/frisket-sudo-askpass` and `/etc/frisket-sudo/askpass.json`.
- The known-store-paths file format (decision 12).
- uids 951/952, and gid 953 (`frisket-askpass`).
- The policy JSON, including `forUser`, `grant.{cap,untilLogout,lateOnce}` and the optional per-rule `grant.cap` (CG-10, decision 24), and the specificity tuple (decision 22).
- Catalogue fields `grant` and `denyUnits`.
- galley `wire/`, `GALLEY_SERVICES_SOCKET`, `GALLEY_SERVICES`, `GALLEY_ASKPASS_GROUP`, the `busy`, `locked` and `invalid` errors, and the home-manager options `services.galley.serviceSocket.{enable,path}`, `services.galley.services` and `services.galley.askpassGroup`.
- Module options:
  - `services.frisket.signer.{enable,user,uid,forUser,keys,policy,socket,galleySocket}`;
  - `services.frisket.sudoGate.{enable,mode,user,uid,forUser,extraOperations,lockoutCheck,galleySocket,grant.{cap,untilLogout},askpass.{enable,group,gid}}`;
  - nix-config `sshSigner.{enable,default,gatewayOnTpm,gatewayKey,macOnTpm}` and `sudoGate.{enable,mode}`.
- frisket flake checks `no-replace`, `named-tests-ran`, `fuzz-gate`, `known-paths`.

| Track | Repo | Deliverables | Depends on | Done when |
|---|---|---|---|---|
| **T0 spikes** | scratch | G-P1, K1 (with direnv), K2, N1, P1, R1 (with 'S'), SV1, X1, **AP1** (askpass identity, per-try PAM, logind file). D1 may run later | — | Fixtures and decisions recorded here; decision 13 frozen as (a) or (b); decision 18's K2 note filled; decisions 26 and 28 confirmed or replaced |
| **G0 PTT** (human) | — | M0 numbers in frisket `docs/signer.md`; dan-desktop host facts | — | Parent, template and caching decided; host-facts table complete |
| **T1 galley** | galley | Item 1 first (public `wire/` + golden files, now including the time-picker form, the askpass form and `times.txt`), then items 2–12, with 5 (time-picker form, time grammar) and 5b (askpass class) | T0 G-P1 for items 2 and 12; AP1 for 5b's gid reading | e2e, VM, locked-screen and screenshot tests green, including the time-picker and askpass-class cases |
| **T2 shared** | frisket | `internal/peer` (known set, `SameName`, Terminal, Remote, maps, desktop-app anchors), `internal/grant` (boottime, absolute ends, presets and clock labels, `ParseTyped`, until-logout sessions, once, `PasswordUntil`, grant-auth record), `internal/galleyask` (peer check, both question shapes, `AskPassword`, wire mapping, audit), `internal/sudowire` (framing for both gate sockets), `tests/fakegalley`, `execspec` + `DecideWords` + `execrule/route`, `nixosModules.knownPaths` + `tests/known-paths.nix`, flake checks, PLAN decision 1 amended | T0 G-P1, K1, K2; T1 item 1 pseudo-version | Units green in `mkFrisket` doCheck; `go list -deps` assertions; chase still compiles against aliases; `checks.no-replace`, `checks.known-paths` green |
| **T2b chase** | chase | Bump frisket in go.mod, vendorHash and flake.lock; `frisket-pin`, policy checks and compile test green | T2 (then again after T3/T4) | `nix flake check` green in chase |
| **T3 signer** | frisket | `internal/tpmkey` (noDA, fd contract), `internal/agentsrv` (step 0), `internal/signpolicy` (specificity, per-rule cap, `grant.cap`/`untilLogout` decode), the signer's use of the time picker, `cmd/frisket-signer`, `nixosModules.signer`, `tests/signer.nix`, `docs/signer.md` (runbooks) | T2; T0 N1/P1 | `checks.named-tests-ran`, `checks.fuzz-gate`, `checks.race` and the VM test green; the daemon derivation builds |
| **T4 sudo** | frisket | `sudo/*.c` ('S', 'm', 'v', shadow, the 'Y' message), `lib.sudoRoot`, check-plugin, `internal/sudogate` (pending-sudo and dialog records, askpass socket, step 10, `PasswordUntil`), `cmd/frisket-sudo`, **`cmd/frisket-sudo-askpass`**, `sudo/operations.json` (refuse, guarded, op ids, grant flags, denyUnits), `nixosModules.sudoGate` (mode, grant, askpass wrapper, group, socket, assertion, health), `tests/sudo-gate.nix`, `docs/sudo.md` | T2; T0 R1, SV1, AP1; T1 item 5b for the VM's real-galley run (fakegalley otherwise) | As T3, with `checks.fuzz-gate` covering both gate fuzzers |
| **T5 nix-config** | nix-config | `modules/ssh-signer.nix`, `ssh-signer-policy.nix`, `ssh-signer-hosts.nix` (IdentityFile/IdentitiesOnly per host, modem, mac), `core.sshCommand`, `modules/sudo-gate.nix` (mode), galley-ask group and tmpfiles, galley serviceSocket path, `knownHosts.server`, `tpmAdmins`, chase wiring (agent and identity together), environment.d `SSH_AUTH_SOCK`, Claude Code deny rules, `sudo-askpass.sh` `exec`ing the wrapper (decision 27), `services.galley.askpassGroup`, new `checks` output (`sudo-lockout`, `signer-wiring` with the socket/name, host-block and askpass assertions), `configurationLimit`, router-plan cross-reference, delete `blockB.out`/`blockC.out` | **T1 merged and `nix flake update galley`**; T2b with T3/T4; T0 X1 (CG-14) | `nix flake check` green; every host toplevel evaluates with `default = true` |
| **T6 rollout** | nix-config | M1–M5 (M3a/M3b, M4a/M4b) | all | Both hosts enforcing; recovery runbook exercised once |

**Parallel work.** Once T0 and T1 item 1 are done:

- T1 (galley items 2–12) runs alongside T2.
- After T2 merges, T3 and T4 run in parallel. They share only `internal/peer`, `internal/grant`, `internal/galleyask`, `internal/sudowire` and `fakegalley`, which are frozen. The time picker is T2's (`grant` and `galleyask`). T3 and T4 only call it. The one sudo dialog is entirely T4's, plus T1 item 5b and T5's script line.
- T5 can be written against T2's module options while T3 and T4 are in flight. It merges only after T2b picks up T3 and T4, and after the galley bump.
- G0 is a human task and can happen at any point before M1. D1 can run in parallel with T3/T4 and lands as v2.

Conventions:

- frisket's comment voice, lowercase `%w` errors, `go vet`, gofmt and the race check.
- One-sentence behaviour commit subjects.
- No Python.
- `-Werror`-clean C.

---

## Open risks and questions

- **P1, PTT (G0).** Everything about keys rests on swtpm and qemu. H1 hints that ECC primaries may be a problem on PTT.
- **P2, hibernate.** Whether it is a TPM Reset or a Resume is unknown. The stateless signer does not care. Grants expire across it by boottime (decision 14).
- **P3, noDA interop.** Until N1 passes, the escape hatch is unproven for noDA keys.
- **S1, `-n`.** Grants help `sudo -n` only with `Defaults noninteractive_auth` [spike: sudo-vm M4–M7]. It is not set.
- **S2, DISPLAY.** Auto-askpass needs `DISPLAY`; `WAYLAND_DISPLAY` alone fails [spike: sudo-vm W1]. Fallbacks: `Path askpass` in sudo.conf, or `-A`.
- **S3, PATH. Decided for v1: grants only.** Any sudo allow rule asks under today's PATH. Later options:
  - a vetted list of programs that never exec through PATH with no tty, with a VM test planting a fake pager in a dan-owned PATH directory;
  - an agent-side clean PATH for sudo.

  `secure_path` stays rejected, because it changes terminal sudo.
- **S4, ptys.** Agent runners that give commands a pty bypass approval. Sandboxed agents cannot reach host sudo.
- **S5, double prompt on first use.** Revision 3 kept it on purpose (SK3). **Revision 4 removes it** in the common case: the askpass dialog carries the password and the time, and the gate approves with no second question when what runs is what the dialog showed (decision 27). The password stays the human factor, because the dialog counts only with a password pam_unix accepted. The double prompt remains, with its reason in the question's first line, when:
  - the program resolved to an untrusted path;
  - an environment variable needs asking about;
  - the command is `-s`, `-i` or sudoedit;
  - sudo's argv was too long to show in full;
  - the anchor in 'A' differs from the one shown;
  - the askpass fell back to the plain box (gate 'N', no askpass socket, old galley, or a `SUDO_ASKPASS` that is not the wrapper).
- **S6, agent tool timeout.** The gate deadline is 110s, below 120s. Hang-up detection is primary. **ASSUMPTION-UNTESTED** that the Bash tool's kill reaches setuid sudo. sudo's ruid is dan, so the signal is permitted, and the VM test simulates the kill.
- **S7, ticket attribution.** A sudoers ticket reused inside one `bash -c` counts as "password typed" for the anchor's hour. That is minor, because no-tty tickets are keyed by a short-lived parent.
- **S8, 'S' agreement.** Decision 16 assumes PAM and the approval plugin run in the same sudo process. R1 and the VM test check it. If they differ, the gate matches on the PAM helper's sudo pid plus the plugin's `ppid=`. Decision 28 adds the askpass's ppid to the same assumption (AP1). If the askpass turns out not to be sudo's direct child, the one dialog cannot be authenticated. sudo then keeps revision 3's double prompt, and the askpass falls back to the plain box.
- **S9, password harvesting through the genuine dialog.** A `SUDO_ASKPASS` wrapper can `exec` the genuine askpass with stdout on a pipe whose reader it double-forked away. The person then types the password into a dialog with the reserved look, and the wrapper gets it. The askpass's stdout and child checks stop only the naive forms of this. What B gains is the password, which a decoy row already gives it. With it, B still meets the plain question about the resolved command, because a stolen password brings no dialog record. If the wrapper also passes the password on to sudo, the command that runs is the one the genuine dialog showed. Accepted, and listed in G1.
- **S10, the logind state file** (decision 26). It is documented as private. A format change ends every "until logout" grant at once (fail closed) and fails the VM test. The fallback is D-Bus.
- **S11, PATH badge in the dialog** (R4-14). The dialog cannot show "PATH has user-writable directories", because the gate does not see the run environment at 'P'. A person's Allow was never blocked by it, and with today's PATH it was on every question. Accepted.
- **N1, forwarding.** Refused by default. `forwarded: ask` names the local `ssh -A`, never the hop's asker.
- **N2, penalties.** Looping refused tools can trigger PerSourcePenalties for 15–20s, including against a locked screen (decision 20).
- **R1, re-rooting.**
  - `kgx -- bash -i` held open past `minShellAge` and driven through rc files, or keystrokes into a real tab, can still reach the terminal allow.
  - A dan-uid process that ptraces a genuine child terminal binary can forge a terminal-anchored allow.
  - People who want no silent allow at all can set the terminal rule's outcome to `ask`.
  - The person seeing the window is the defence.
- **R2, desktop apps (K2).** Until K2, the shape of app-launched git is assumed. A helper that re-parents would make every app push SessionRoot (asked, no grant).
- **R3, devShells (D1).** Projects with `git` in their devShell lose silent terminal pushes. A project that sets `GIT_SSH_COMMAND` gets an unusual ssh leaf. D1 is the planned fix.
- **R4, version bumps (decision 19).** Old tabs and old claude processes ask after a version bump of bash, gnome-console or claude-code until restarted.
- **G1, galley trust.** "Answers only from the window" does not hold against dan-uid code: drop-ins, socket rebinding, decoy rows. The binder-cgroup check and the drop-in warning are bar-raisers. The only structural fix is galley under its own uid, which is out of scope. In revision 4 the reserved look of the sudo dialog (item 5b) makes a decoy password row easier to tell apart, but S9 lets dan-uid code borrow the genuine dialog, so the look is a hint, not a guarantee.
- **G2, badge.** Unproven until the screenshot test passes.
- **G3, galley not running.** With self-binding (decision 13), services can no longer start galley. A session where galley crashed refuses everything that needs a question until it restarts. `Restart=on-failure` on galley.service covers crashes.
- **B1, auto mode.** With `defaultMode = "auto"`, whether a steered host agent can persist code is Claude Code's classifier's call [H6]. Deny rules are a speed bump.
- **F1, `internal/ask`.** The split is deferred.
- **F2, gate identity.** The socket-activated listener's peer uid is root's. The guard is the root 0700 directory. **ASSUMPTION-UNTESTED**; asserted in the VM test.
- **F3, trusting frisket.** A compromised frisket main process can sign with its listed keys. Accepted, and logged with the route.
- **F4, C toolchain.** frisket's first C, and its first `stdenv.mkDerivation`-style package.
- **K1, known-set freshness.** Processes from garbage-collected generations show as unusual until restarted. The activation script's runtime at boot is **ASSUMPTION-UNTESTED**.
- **H1, housekeeping.** Delete `~/Projects/nix-config/blockB.out` and `blockC.out`, left by the session-bind spike, before the T5 commits.

### ASSUMPTION-UNTESTED register

| Assumption | Covered by |
|---|---|
| The client sees `systemd --user` as peer under user socket activation, and galley's own process when galley binds | G-P1 |
| The process shape of `kgx -- cmd`, devShell tabs and claude in a devShell | K1 |
| The chain of desktop-launched apps | K2 |
| A signature-verified second tier of the known set is sound and fast | D1 |
| noDA RSA keys; stock ssh-tpm-agent 0.9.0 loads noDA keys | N1, signer VM |
| Persistent-parent fallback | P1 |
| OpenSSH 10.5 privsep shape; PAM and approval share one sudo process | R1, sudo VM |
| `sudo -V` as root shows approval plugins | SV1, sudo VM health subtest |
| `extraDependencies` on the lockout check evaluates | X1 |
| Cgroup move denied from dan's delegated `user@` | signer VM |
| SSHSIG parsing on real output | unit test with real fixtures |
| Dropbear accepts ECDSA or rsa-sha2-256 | M2 |
| Hibernate is a TPM Reset or not (moot) | — |
| Exact env set after env_reset | sudo VM pin |
| Gate socket peer uid under activation | sudo VM |
| galley ENOENT behaviour without linger | VM tests |
| logind `LockedHint` set by GNOME 50's lock screen | galley VM test |
| `nix-store -qR` at boot activation, and its cost | both VM tests |
| Full signer hardening set as a whole | signer VM |
| Connecting to a socket from frisket's read-only mounts | signer VM stand-in |
| environment.d reaches new tabs once gcr is off | M3 hand check |
| The auto classifier refuses unit and drop-in writes | M3 hand check |
| The Bash tool's kill reaches setuid sudo | sudo VM simulation |
| VM suspend with `rtcwake` | signer VM (fallback: fake clock only) |
| The NixOS setgid wrapper's exec of the static Go askpass is non-dumpable and `AT_SECURE`, with egid set, and Go keeps secure mode | AP1, sudo VM ptrace subtest |
| `PIDFD_GET_INFO` and `SO_PEERCRED` give the uncapped gate the askpass's egid (identity-vm printed only ruid and euid; ppid and mask 0x7 were measured) | AP1, `internal/sudogate` peer tests on a real socket |
| The askpass's ppid is the same sudo that sends 'G' and 'A', on every password try | AP1, sudo VM 'S' agreement subtest |
| sudo re-runs the PAM stack, and so the grant helper and the askpass, once per try (H16 is from source reading only) | AP1, sudo VM wrong-password subtest |
| `sudo -A` with a tty never reaches the helper's 'G' | AP1, sudo VM tty subtest |
| Both services can read `/run/systemd/users/<uid>`, its format holds, and a logout clears `DISPLAY` | AP1, both VM until-logout subtests |
| galley's `Gtk.DropDown` answers its first value when untouched | galley e2e test (item 10) |
| gjs gives galley the peer's gid on the services socket | galley test (item 10) |
| The window can refuse an `ok` whose time entry fails the grammar, and keep the row | galley e2e test (item 10) |
| `pidfd_open` on the askpass's setuid parent works for the askpass | `cmd/frisket-sudo-askpass` test, sudo VM kill subtest |
| The uncapped gate can `pidfd_open` the askpass's setuid-root parent and read its euid and ruid with `PIDFD_GET_INFO` (decision 28, check 4) | AP1 |
| `/proc/<sudo>/cmdline` read by the PAM helper is sudo's argv as given (sudo does not rewrite it) | sudo VM "one dialog" subtest |

---

## Review log

### Revision 2: adversarial review (38 findings)

| Finding | Lens | How it was addressed |
|---|---|---|
| F2-crafted-store-path-defeats-unusual-flag | red-team | Decision 12: exact store paths rendered by nix-config, `*` in store paths is a compile error, a root-written known set defines "unusual", the maps check covers terminal and leaf links, and the strict Terminal test. Unit and VM tests with `nix-store --add` fakes |
| F3-actorB-becomes-window-auto-answers | red-team | Actor B demoted to "partly": persisting code makes B into C. Window impersonation listed for B and C. The auto-mode dependency is stated [H6]. Claude Code deny rules (speed bump), galley drop-in warning and M3 hand check added. Separate-uid galley recorded as the only structural fix (G1), not adopted |
| F5-late-allow-once-silently-becomes-timed-grant | red-team | A late Allow once is a single-use, exact-target `GrantOnce` (sudo argv hash), not 2 minutes of the anchor. Excluded for Cut, unusual and SessionRoot chains. Honest row label. PAM peeks and does not consume. Tests added |
| F6-coarse-op-grant-widens-scope | red-team | argv grants by default. `"grant":"op"` only for reviewer-marked ops whose effect does not depend on arguments. `denyUnits` stay ask inside grants. The button names the scope. Tests added |
| F7-frisket-cgroup-trust-too-broad-incl-asker-and-rsa | red-team | Trust requires ppid 1 and frisket's exact exe as well as cgroup and uid, limited to `trusted[].keys` and userauth. SSHSIG goes the normal way. Children ask. C9 reversed. VM subtest added. A per-boot secret and a gateway-destination rule were dropped (dan reads frisket's environ; frisket's requests are unbound) |
| SK1 | sceptic | Same fix as F2 and EA1. CAP_SYS_PTRACE kept, because exact paths and maps need it. The ptrace-a-genuine-child residual is listed in R1. The maps check uses the accepted maps leak |
| SK2 | sceptic | The "never silently allowed" claim is removed. Terminal=true is narrowed (interactive shell directly under kgx, session leader with a pts, foreground job with job control, allowed links in between, minimum shell age). `kgx -- bash -i` is documented. Unit tests added. M3 expects the real behaviour |
| SK3 | sceptic | Password on first use kept (verifier note 1), with the reason stated: an Allow can be forged with no human. Password skip needs a live grant and a password within 1 h. The askpass text announces the question. VM test "rule-allowed command still needs the password". Question-as-auth listed as rejected. **Revised in revision 4** (R4-2, R4-7): the password is still required on first use and still the human factor, but it is typed into the same dialog as the time. The second prompt remains only where the dialog could not show what runs. The 1 h window becomes "the time chosen with the password, else 1 h" (decision 29) |
| SK4 | sceptic | Decision 11: no-tty fails closed on every connect error. Remote sudo is untouched through `open()`. Residual-hazard row removed. VM tests for gate stopped (with a Y4 ticket), tty and remote |
| SK5 | sceptic | Trusted PATH entry defined, including missing directories. States that today every allow becomes ask. S3 decided as "grants only" for v1. Catalogue narrowed to refuse, guarded and op ids. Day table updated |
| SK6 | sceptic | The gateway proof through the signer is a hard M2 gate. `gatewayOnTpm` added. Agent and identity set together. ECDSA tried first. Fallback is a gateway-only key file, not gcr |
| SK7 | sceptic | Observe mode (M3a) with hard refusals still enforced. Counting with journalctl and jq. Enforce only at 10 or fewer would-be prompts a day. Measured column added. Restart-on-switch kept, with its cost stated. The anchor is not widened |
| SK8 | sceptic | Goal 5 reworded. sudo.conf is a checked derivation (dlopen, symbol, sudo version). check-plugin runs in `installCheckPhase`. Break-glass proven in a VM subtest, or the plan says the boot menu is the only one. `configurationLimit` ≥ 5 |
| SK9 | sceptic | The late once-grant lasts 15 min (single use). A late "Allow 15 min" is the normal grant. sudo deadline 110s, with hang-up detection primary. Tests at 14 and 16 minutes |
| OPS-1 | ops-lockout | `StartLimitIntervalSec=0` and `RestartSec=1s` on both services. `recover()` per connection. `serve` never exits on bad config (refuse-all, or degraded signer). `check` runs in `system.checks`. Health timers and `OnFailure` alerts. Crash-loop VM subtests. Plugin fails closed |
| OPS-2 | ops-lockout | Remote chains verified from a root sshd-session parent. sudo: `open()` returns 0 (today's behaviour), and the helper exits 1. Signer: `SSH_AUTH_SOCK` only in the user manager's environment [H7], and remote chains refused immediately. make-usb.sh VM subtests. Claim corrected |
| OPS-3 | ops-lockout | M2 is a two-host matrix with `BatchMode`. Switch then log out. Router-plan requirement that images authorize every `admins/*/ssh.pub` plus gateway TPM pubs, generated from `admins` |
| OPS-4 | ops-lockout | Zero keys → degraded `STATUS`, a failing health timer and an alert question. TPM-cleared runbook in `docs/signer.md`, exercised in the VM. Pre-firmware recovery check. The signer does not hold ed25519 |
| OPS-5 | ops-lockout | One rule: a missing directory, a missing socket or ECONNREFUSED gives the same "gate not running" deny. A wrong-owner directory gives a tamper deny. Two VM subtests |
| OPS-8 | ops-lockout | **Tested** [H10]: default keys fail in lockout and noDA keys sign. Keys are now created with noDA. LOCKOUT is named and not retried. G0 records DA parameters. Clear-lockout documented. N1 checks the escape hatch |
| CF1 | codebase-fit | Gateway `agent` and `identity` are set together under one `mkIf`. `signer-wiring` evaluates the toplevel `drvPath` with `default = true` |
| CF2 | codebase-fit | New `checks` output. Guard 2 is a build dependency of the toplevel (pending X1; otherwise documented). preSwitchChecks text corrected (runs for boot; `NIXOS_NO_CHECK` skips it). No switch.sh |
| CF3 | codebase-fit | The C is built through `lib.sudoRoot` with callPackage against `config.security.sudo.package`. The checker compares sudo versions. frisket follows nix-config's nixpkgs through chase, with an eval assertion |
| CF4 | codebase-fit | `mkFrisket` runs all tests with swtpm required. `excludedPackages` for the daemons. Daemons built with `overrideAttrs` and `doCheck = false`. Done-criteria and a check for PASS lines |
| CF5 | codebase-fit | `internal/tpmkey` signing contract: one fd per call, the closure returns the same fd, closed with defer, retry on a fresh fd. fd-leak test |
| CF6 | codebase-fit | The public key comes from the blob, checked against the policy's `keys` fingerprints. keygen writes `.fp`. `pub -fp` added. Per-file store paths work |
| CF7 | codebase-fit | `gatewayOnTpm` and `gatewayKey`. The gateway fallback is wired with a gateway-only key file, which keeps the silent path narrow. Both values checked |
| CF8 | codebase-fit | No direct frisket input; packages come from `inputs.chase.inputs.frisket`. T2b chase track. T5 depends on it |
| CF9 | codebase-fit | `execspec` holds ExecRule and Operation, with aliases in policy. `Compile` moves out of execrule's core. Corrected `CompileRules` signature. `DecideWords` uses a shared Decision builder. dep tests in T2's done-condition |
| CF10 | codebase-fit | `pkgs.stdenv.hostPlatform.system`. nix-config-style `sshSigner` and `sudoGate`. `tpmAdmins` defined with `pathExists`. Catalogue shipped in the gate package with `extraOperations` |
| CF11 | codebase-fit | frisket owns the keyed modules under `services.frisket.{signer,sudoGate}`. VM tests import them. nix-config only sets them. Option names added to the fixed interfaces |
| CF12 | codebase-fit | Both daemons use `internal/sdnotify.Listen()` and take the named fd, refuse to start without it, and are Ready after the self-test or rules load |
| CF13 | codebase-fit | Three dependencies, galley included. No vendored `wire`; T1 item 1 merges first. `replace` banned at merge. Tests against fakegalley built from the pinned `wire` |
| EA1 | evidence-audit | Same fix as F2 and SK1. Blocker for T2/T3 |
| EA2 | evidence-audit | Same as OPS-1 and SK4. "Socket activation means no ECONNREFUSED" removed. Crash-loop VM subtest |
| EA3 | evidence-audit | Clean absolute path whose `Dir` exactly equals a trusted directory. Unit and property tests, and a VM subtest with a `..` path |
| EA4 | evidence-audit | Pre-build spike K1 before T2/T3. Strict Terminal test with stat fields [H2, H3]. The C8 claim corrected |
| EA5 | evidence-audit | Actor C restated as "not stopped, not necessarily visible". Socket-rebind route documented. Journal audit record for every decision. Galley peer-cgroup check as a bar-raiser. VM subtest. The directory stays dan-owned |
| EA6 | evidence-audit | preSwitchChecks note corrected. Build-time `system.checks` and the sudo.conf derivation are the guards. switch.sh dropped. `NIXOS_NO_CHECK` → ask kept, with the reason |
| EA7 | evidence-audit | Terminal chains anchor on the tab's shell. "Allow 15 min" is offered per tab and host, and a `kgx -- cmd` window cannot inherit it. Day table and tests updated |
| EA9 | evidence-audit | SRK type checked [H1]. Fallback marked ASSUMPTION-UNTESTED and tested early (P1). Persistent-handle dependency noted |
| EA10 | evidence-audit | Assertion over effective tss membership (members, extraGroups, primary group). Also checked in `signer-wiring` on the real host config |
| EA11 | evidence-audit | keygen writes `.fp`. `pathExists` guard with a plain message. `signer-wiring` compares `.fp` with `ssh-keygen -lf` of the `.pub`. One source for chase and the policy |

### Revision 3: completeness review (22 gaps)

| Gap | How it was addressed |
|---|---|
| CG-1 galley peer check always fails under socket activation | Decision 13: galley binds the services socket itself (option a), with (b) as the fallback and (c) rejected. Pre-T2 spike G-P1. galley items 2 and 12 changed. fakegalley runs as `galley.service` and binds directly. Positive "a real answer gets through" VM subtest, plus a G-P1 negative subtest |
| CG-2 desktop-launched apps undefined | Decision 18: apps anchor on themselves; store-built apps grantable, others unusual, Flatpak refused. Spike K2. Day-table row, unit fixture, M3b hand check, risk R2 |
| CG-3 devShell, nix-direnv and mise binaries always unusual | Decision 18: `core.sshCommand` pinned to the system ssh. devShell `git` stays unusual in v1, with badge reason `devshell`, counted in M3a. gcroots/auto rejected (would reopen F2). Spike D1 for a signature-verified tier. K1 extended. Unit tests. Risk R3 |
| CG-4 suspend and the monotonic clock | Decision 14: CLOCK_BOOTTIME everywhere; `grant.New(clock func() time.Duration)`. `TestAGrantDoesNotSurviveASuspendLongerThanItsCap` and an `rtcwake` VM subtest |
| CG-5 gate cannot check anchor liveness | Decision 15: lazy liveness by `(pid, starttime, exe)` match on each request; `Sweep()` expires only. Decision 7 restated. Unit tests |
| CG-6 'A' lacks sudo's own pid and starttime | Decision 16: required `'S'` tag on 'A' and 'G'. Grant-auth record keyed on it. Unit and VM tests. Same-process assumption added to R1 and S8 |
| CG-7 root peers on the signer socket | Decision 17 and decision step 0: peer uid ≠ `forUser` → refuse, logged. Unit test and `sudo SSH_AUTH_SOCK=… ssh` VM subtest. Non-goal and day-table row |
| CG-8 modem and dan-mac missing from M2 | H11. Modem keeps its password with `PubkeyAuthentication no` and `IdentityAgent none`. `mac` added to M2 with `macOnTpm`. T5 renders `IdentityFile <tpm .pub>` + `IdentitiesOnly yes` per signer host. `signer-wiring` asserts the blocks |
| CG-9 daemonised ssh and ControlMaster | Non-goal sentence. Day-table row. `TestAReparentedSshIsNeverGrantable` |
| CG-10 no per-rule grant fields | Decision 23. Optional `grant` per rule, capped by the global. Strict-decode test. Listed in the fixed interfaces |
| CG-11 "most specific rule wins" undefined | Decision 22: lexicographic tuple (program constraints, destination, key), stricter outcome on a tie, equal-tuple allow/refuse rejected. Table-driven test |
| CG-12 known-paths script not fail-safe; format unspecified | Decision 12: file format fixed; script under `pipefail`, replaces only a non-empty set containing `$systemConfig`; `LoadKnown` rejects bad files and keeps the previous set. `tests/known-paths.nix` and a unit test |
| CG-13 no check that socket paths and names agree | `signer-wiring` asserts equal paths, `serviceSocket.enable`, and service names matching `cfg.user` on both modules |
| CG-14 T5 missing T1 dependency | T5 depends on T1 merged and `nix flake update galley` |
| CG-15 fakegalley unspecified | Its flag contract is a fixed interface: answer, delay, never, busy, locked, close-after, script, log, socket or inherited fd |
| CG-16 question and answer wire format unspecified | Exact `wire.Hello`/`wire.Answer` mapping, button index rules, error codes, scope stays with the caller. Golden files in both repos; T1 item 1 deliverable |
| CG-17 `sudo -V` health check untested | Marked ASSUMPTION-UNTESTED; spike SV1; VM assertion that health passes with and fails without the plugin line; a fallback check named |
| CG-18 questions while locked | Decision 20: galley answers `locked` at once; services refuse with "screen locked". fakegalley `-locked`. Unit, VM and galley tests |
| CG-19 no sudo shadow phase | Decision 21: `sudoGate.mode = "shadow"` (default), plugin approves, helper always exits 1, gate logs. M4a before M4b. `TestShadowModeNeverDenies` and a shadow VM node |
| CG-20 "CI" undefined | Named flake checks `no-replace`, `named-tests-ran`, `fuzz-gate` (and `known-paths`), in T2/T3/T4 done-when |
| CG-21 dan-desktop host facts unchecked | G0 re-runs H2–H5 on dan-desktop; host-facts table has a dan-desktop column |
| CG-22 long-running processes across upgrades | Decision 19: a rule matches the exact path or a known path with the same store name; a new version falls to `unmatched`. Unit test for "old claude after switch". Risk R4 |

### Revision 4: user additions

dan asked for two things after revision 3: grant times he chooses in the question, and one sudo dialog instead of a password box followed by a question. R4-1 to R4-14, R4-26 and R4-27 are the design and the attacks and cases dan named. R4-15 to R4-25 came from a self-adversarial pass over the revision-4 text, read once as an attacker and once as a sceptic.

| Item | How it was addressed |
|---|---|
| R4-1 custom grant times (signer and sudo) | Decision 24: `once`, 5 min, 15 min, 1 hour, until logout, or a typed `45m`/`2h`/`1h30m`; hard cap `grant.cap` (8 h default, ≤ 24 h) in the signer policy and the gate module; per-rule caps only lower it (decision 23); clock ends on every label and in every reply and journal record. Decision 26 defines until logout. Tests in `internal/grant`, `galleyask` and both VMs |
| R4-2 one dialog for sudo | Decisions 27–29: `frisket-sudo-askpass` (setgid wrapper, `exec`'d by `sudo-askpass.sh`) shows password, time, chain and sudo's argv in one galley form, sends the time to the gate ('P'/'D' on a second socket), and writes the password only to sudo's stdin. The gate approves on 'A' with no second question when step 10's conditions hold |
| R4-3 what galley can carry, checked against its real code | H14, H15: the parser and `validate.js` were run on the exact command lines. Form with combo + entry chosen (decision 25). Rejected: extra button beside a picker (answers no fields), `--entry` with values (no password field), radiolist (no typed value). galley items 5 and 5b added |
| R4-4 absolute or sliding | Absolute, from posting time (decision 24). Sliding is in the rejected table. Decision 14 restated for the new times |
| R4-5 "exe == the askpass path" is not checkable by the gate | The gate has no `CAP_SYS_PTRACE` and `ProtectProc=invisible`, so exe is unreadable [spike: identity-vm], and decision 4 is kept. Identity is the setgid group (egid via `SO_PEERCRED` and `PIDFD_GET_INFO`, measured to work uncapped for uids and ppid) plus the kernel's ppid matching a root-reported pending sudo (decision 28). Spike AP1 for the egid and the wrapper |
| R4-6 the galley CLI's `\|`-joined form output | The askpass speaks the wire (decision 28) [H15] |
| R4-7 SK3 against the one dialog | The dialog counts only with a password pam_unix accepted, for the same 'S'. Each actor is walked through in the threat model. The double prompt is removed except in step 10's failure cases and on fallback (S5) |
| R4-8 attack: forged `SUDO_ASKPASS` | It lacks the group, so it cannot reach the askpass socket, and no time is recorded. The plain question follows, even with a harvested password. VM subtest |
| R4-9 attack: wrapper redirecting the genuine askpass (env, argv) | No env-derived paths, argv ignored, root-owned config, galley binder-cgroup check (decision 28). VM subtest |
| R4-10 attack: racing a time for someone else's sudo | No pid in any askpass message; the kernel's ppid must be a pending sudo; one record per 'S'; used only by the 'A' with the same 'S'. Unit and VM tests |
| R4-11 attack: a time with no password | 'D' only with a non-empty password; the record counts only if pam_unix let that sudo in; discarded on grant-auth (decision 29). Unit tests |
| R4-12 attack: replay | One 'P' and one 'D' per connection; the record is consumed by its 'A' and expires in boottime. Unit test |
| R4-13 attack: forged 'S' | 'S' still only from root on the 0700 gate socket. The askpass socket refuses any 'S' tag. Unit test |
| R4-14 PATH badge not in the dialog | Accepted (S11): the gate does not see the run environment at 'P'; the badge never blocked a person's Allow; today it is on every question. Pinned by a unit test so it is a choice, not an accident |
| R4-15 (pass) a dan process takes over a dead sudo's pid and forks the genuine askpass, getting a genuine-looking dialog for the dead sudo's command | Check 4: the parent must be setuid-root (euid 0, ruid dan) via `pidfd_open` + `PIDFD_GET_INFO`; and the newest pending record for a pid wins. Unit tests; AP1 |
| R4-16 (pass) Enter with an empty password sent a time | No 'D' for an empty password (decision 27). Unit test |
| R4-17 (pass) on a retry, a lost 'D' would let the 'A' use the previous try's record, whose password was wrong | Each 'P' clears the sudo's dialog record. The previous choice moves to the pending record (decision 27, protocol). Unit test |
| R4-18 (pass) decoy rows and harvesting | The askpass class gets the reserved look (galley 5b), so decoys are easier to tell apart. Harvesting through the genuine dialog by stdout redirection is only partly stopped (pipe and child checks) and is listed as S9. A harvested password still meets the plain question |
| R4-19 (pass) a late answer to the sudo dialog | Not possible: no password is kept to verify later. The askpass withdraws with sudo and gives up at 110 s (decision 27). Rejected table |
| R4-20 (pass) the dialog's time on an op-grantable op would widen the scope beyond "this command" | Dialog grants are argv-scoped only (step 10). Unit test |
| R4-21 (pass) a plain-question grant could stretch the password skip to 8 h | Decision 29: only a time chosen with a typed password opens the window beyond 1 h. Unit and VM tests |
| R4-22 (pass) a service form's free-text entry breaks "services cannot collect secrets" | galley enforces the time grammar on service and askpass-class entries before answering (item 5). Decision 9 restated. galley tests |
| R4-23 (pass) a typed time shorter than the row's wait | The asked request is still allowed; the grant is already over (decision 24) |
| R4-24 (pass) an untested claim that `--question --extra-button` reproduces the ungrantable item | Removed. Only the forms command line was run through the parser |
| R4-25 (pass) the signer has no reply channel for the clock end | Stated in decision 24: the label shows it, and the journal has a typed time's end |
| R4-26 sudo asked no password (its own ticket, a grant, `-S`) | No dialog record, so a command needing asking gets the plain question with the picker (decision 27; day table; VM subtests) |
| R4-27 wrong-password retries | One askpass per try [H16]; per-try record handling (R4-17); the previous choice listed first; VM subtest |

---

## Appendix: spike evidence

All paths are under `/tmp/claude-1000/-home-dan-Projects-nix-config/0b66dc1f-0ef9-4530-951c-324010908cca/scratchpad/spikes/`. A sceptic directory's verdict overrides the original. Revision 3's new spikes (G-P1, K2, D1, SV1, and the K1/R1 extensions) and revision 4's AP1 have not run yet. Revision 4's parser, validator and source checks are under `galley-check/` and in "Revision 4 checks" below.

### tpm-keys (`tpm-keys/`, `tpm-keys-sceptic/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| Pure-Go (CGO off) ECDSA P-256 and RSA-2048 TPM key files with no PIN | confirmed | `tpm-keys/code/main.go`; `tk keygen` / `tk info` (emptyAuth, 430/820 bytes) |
| The H-2 parent is deterministic across restarts, and keys reload | confirmed | `tk srk` before and after restart; `vm-interop.log` SRK equal after reboot |
| A cleared or different TPM fails loudly | confirmed | `TPM_RC_INTEGRITY` after `tk clear` (`tpm-keys-sceptic/`) |
| TPM signatures are valid for nistp256, rsa-sha2-256 and rsa-sha2-512 (x/crypto, ssh-keygen, sshd) | confirmed | `tk sshsig`; `vm-interop.log` LOGIN-OK lines |
| Interop with stock ssh-tpm-agent both ways | confirmed (checkout v0.9.0-12, not the deployed 0.9.0) | `vm/test.nix`, `vm-interop.log` |
| Sign latency is small | partly (swtpm and qemu only, no PTT) | `bench-swtpm.txt` |
| Cached handles survive a TPM reset | refuted | `tk stale`: TPM_RC_REFERENCE_H0 |
| swtpm tests run in the Nix sandbox with CGO off | confirmed | `sandbox.nix`, `nix log` |
| Transient-object count is not a practical limit | refuted | TPM_RC_OBJECT_MEMORY after leaks; `tpm_space` has 3 slots per fd |

### tpm-da-lockout (`tpm-da-lockout/`, re-run in `tpm-da-rerun/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| Default-template emptyAuth keys keep signing in DA lockout | refuted | `tpm-da-rerun/dalock.log`: ec, rsa and new → `TPM_RC_LOCKOUT` at counter 3/3 |
| A noDA key signs in lockout | confirmed (ECC only) | same log: "sign noDA under lockout: <nil>"; template in `tpm-da-lockout/code/main.go` `makeNoDA` |

### session-bind (`session-bind/`, `session-bind/sceptic/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| OpenSSH 10.5 sends session-bind before the sign | confirmed | `agent.log`, `sceptic/ag.log` (distinct host keys) |
| The bind can be parsed and verified; mismatches detected | confirmed (detection only; the spike signed anyway) | `agent/tamper.go`, `sceptic/ag.log` T1–T5 |
| known_hosts maps a host key to a name | partly (a set of names; hashed entries cannot be reversed) | `hashed-agent.log`, `sceptic/ag.log` c6 |
| Forwarding is visible | partly (8.8 sends no fwd bind) | `sceptic/ag.log` c9, c12 |
| git over ssh looks like a normal login | confirmed | `agent.log` c6–c8 |
| x/crypto and old clients send no bind | confirmed | `agent.log` c9, c13 |
| A blocked sign fails through LoginGraceTime; penalties | confirmed (lockout real) | `blockA.out`, `sshd/sshd.log`, `sceptic/sc1.log` |
| Requester hang-up is visible while asking | partly (server-side drops are invisible) | `hup-agent.log` |
| What a refusal looks like; penalties | confirmed | `refuse-agent.log`, `sshd.log` |

### identity-vm (`identity-vm/`, `identity-vm-sceptic/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| An uncapped other uid reads status and cmdline, not exe | confirmed | `identity-vm/reports.jsonl` plain |
| ProtectProc=invisible works without a capability | refuted | hard/* chain length 1 |
| CAP_SYS_PTRACE is the minimum for exe; DAC_READ_SEARCH is not enough | confirmed | hardptrace vs dacread |
| seccomp `@system-service` removes the ptrace risk | confirmed | ptraceopen vs hardptrace; systemd-analyze 260.4 |
| Disguises are detectable only through exe | confirmed | renamed, spoofed, symlink, deleted |
| The chain identifies who asked | refuted (orphans and hand-offs cut it) | orphan, handoff reports |
| Pidfd recipe defeats pid reuse; check the mask | confirmed | `build.log` REUSE lines; dead pidfd mask 0xc |
| frisket is recognisable by its root cgroup | confirmed (move denial tested from a root cgroup only) | frisket-system-unit reports, MOVE-DENIED |
| A same-uid user-namespace peer can be told apart | partly (needs the capability) | hardptrace/userns |
| tss and udev permissions | confirmed | `build.log` 1071-1092, 1161 |
| The TPM EOFs were contention | partly → cause established (non-blocking fd with no poll) | `identity-vm-sceptic/src/cmd/tpmeof/main.go`, `build.log` |

### sudo-vm (`sudo-vm/`, `sudo-vm-sceptic/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| sudo.conf with only the plugin keeps sudoers | confirmed | `results.txt`, nix eval |
| tty= only with a ctty; the askpass path is no-tty | partly (`-A` from a terminal has tty=; auto-askpass needs DISPLAY) | T1–T6, `sudo-vm-sceptic/results3.txt` W1/W2/K1, `src/src/tgetpass.c:139` |
| PAM auth runs before approval check() | confirmed | every no-grant run |
| check() runs on every command | confirmed | Y1, TS5–TS8 |
| No ticket is written on approval refusal | refuted | Y4; `src/plugins/sudoers/check.c:214-223` |
| Refusal messages and return codes | confirmed | R1, R3, R4/X3, R6 |
| Fail-open without lockout | partly (load failure is fatal for all) | S1–S3, Z1, L2b/L3b/L4b/L4c, L5/L6, L3c |
| All modes reach the plugin | partly | M1–M14 |
| pam_exec codes express grant, fallthrough and refuse | confirmed | P1, P3, P4, X5, P6, M13 |
| The helper reads the chain as root | confirmed | helper logs |

### galley-socket (`galley-socket/`, `galley-socket-sceptic/`; map: `galley-join-leak/`, `galley-service-socket/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| A second client cannot list or answer another client's question | confirmed | `e2e-baseline.log` |
| A joiner cannot answer or cancel | confirmed | TestSpikeJoinerCannotAnswerOrCancel |
| A joiner learns the answer (question kind) | confirmed (fixed by caller sameness) | `vm.log` 1138-1140 |
| Password prompts leak to joiners | confirmed; the no-join patch is needed but a decoy-first row still wins | `galley-socket-sceptic/galley/tests/spike3_test.go` |
| A client can forge the caller | partly (state-level only, never rendered) | TestSpikeForgedCaller, `vm.log` |
| Services reach the window outside `/run/user` | confirmed (linger only; socket-activated) | `vm.log` 1050-1278 |
| Labelling by uid without NSS | confirmed | `vm.log` 1096, 1239 |
| The kind restriction prevents phishing | partly (no secrets, but free text) | `e2e-patched-full.log` 104-107 |
| The answer goes only to the asking service | confirmed | `vm.log` 1167-1205 |
| Services can authenticate the window | refuted ("peer credentials name systemd under socket activation"; this is what CG-1 turns into decision 13) | `vm.log` 1298-1353 |
| The patch keeps existing behaviour | partly (5 intended failures) | `e2e-patched-full.log` |

### policy-fit (`policy-fit/`, `policy-fit-sceptic/`)

| Assumption | Verdict | Evidence |
|---|---|---|
| chase's catalogue gives sensible root answers | partly (allows `less` and `cat /etc/sudoers`; LESSOPEN ran as root) | `sceptic.log`, `policy-fit-sceptic/vm/build2.log` |
| execrule decides the resolved command | refuted | `fit_test.go` |
| basename or argv[0] can be trusted | refuted (`~/bin/systemctl`; `nix-store --add` cat ran as root) | `vm/build.log`, `policy-fit-sceptic/vm/build.log` |
| Re-quoting argv into Decide is safe | refuted | `fit_test.go:113`, `argv_test.go` |
| `-s`/`-i` classifiable | partly (needs unescaping) | `escaped_test.go`, `vm/build.log` |
| argv alone is enough | refuted (env matters; a denylist is insufficient) | `vm/build.log`, `sceptic.log` |
| sudoedit classifiable | partly | `vm/build.log` |
| execrule/policy too heavy | partly (2.68 → 1.98 MB with a split) | `deps.log` |
| chase's loader reusable | refuted (internal) | `catalogue.go` |
| Chain rules as execrule words | refuted | `fit_test.go:184-192` |
| Sudo-like sliding grants | confirmed (no longer used: revision 4 grants are absolute, decision 24) | `grant_test.go`; check.c timestamp_update |

### Revision 4 checks (`galley-check/`, beside `spikes/` in the same scratchpad)

| Assumption | Verdict | Evidence |
|---|---|---|
| galley's parser takes the time-picker form, the sudo dialog form, an editable combo, a radiolist and a form with an extra button | confirmed | `galley-check/galley/internal/zenity/probe_test.go` (a scratch copy of galley at `b47b52a`), `go test -run TestProbe -v` |
| `validate.js` accepts both service shapes at wire version 2 and refuses them at 1 | confirmed | `galley-check/js/run.mjs` under node, on `galley-check/items/*.json` and the hand-written shapes |
| An extra button on a form answers only its label | confirmed (parser output; window code `_finish` fills values only for ok/timeout) | probe output; `daemon/window.js` |
| A form's CLI output joins fields with `\|` | confirmed (`hunter2\|1 hour\|`) | probe output |
| sudo forks the askpass itself, waits for it, and runs PAM per try | source reading only | `spikes/sudo-vm-sceptic/src/src/tgetpass.c:295-375`, `plugins/sudoers/auth/sudo_auth.c:323`, `auth/pam.c:322`. AP1 runs it |
| The uncapped, `ProtectProc=invisible` gate gets ppid and uids from `PIDFD_GET_INFO` | confirmed (egid not printed) | `spikes/identity-vm/reports.jsonl`, server `hard`, label `baseline` |

### Review-lens spikes

| Spike | Assumption tested | Verdict | Evidence |
|---|---|---|---|
| `ops-socket-limit/` | Socket activation means no ECONNREFUSED after crashes | refuted: start-limit-hit fails the socket, and connects are refused with the socket file still present | VM log there (systemd 260.4) |
| `evidence-audit/` (`startlimit.nix`) | Same | refuted | `startlimit.nix` run |
| `evidence-audit/` (`dotdot.nix`) | A prefix check on `command=` is safe | refuted: `/run/current-system/sw/bin/../../../../../home/alice/bin/cat` ran as uid 0 | `dotdot.nix` run (SUDO_COMMAND observed) |
| `evidence-audit/`, `ea1-refute/`, `store-name-attack/`, `sceptic-complexity/` | Store-path globs identify programs | refuted: `nix-store --add` gives `<h>-openssh-10.5p1/bin/ssh`, `<h>-claude-code-9.9/bin/.claude-unwrapped` and `<h>-gnome-console-49.0` as dan | the added trees in each directory |

### Codebase-map spikes (cited by the map, not re-verified here)

- `frisket-map/`
- `nix-wiring/`, `nix-wiring2/`, `nix-wiring3/`: unit hardening subsets and root-owned `/run` directories.
- `sudo-plugin/`: ptrace of setuid sudo, and `[success=die]`.
- `galley-join-leak/`
- `galley-service-socket/`
- `tpm-agent-ref/`: ssh-tpm-agent internals.
- `pidinfo`: no directory exists under `spikes/`. Its claims (the `PIDFD_GET_INFO` ioctl number and fields) are covered by `identity-vm/`.
