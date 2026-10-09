# frisket-signer and frisket-sudo: plan

Two small gatekeepers beside frisket, both asking the person through galley:

- **frisket-signer** holds the SSH keys that live in the TPM. It signs silently for frisket and for a terminal tab ssh-ing to a known host, and asks for everything else.
- **frisket-sudo** gates sudo when no terminal is asking. The first sudo of a Claude session shows one dialog with the password. That password is then remembered for a time the person picks, for that claude only, and every command is still shown and asked.

```
$ git push                          # typed in a gnome-console tab, github.com in ssh_known_hosts
                                    # signed, nothing asked

claude> git push                    # galley: "ssh to github.com from claude (pid 5113)"
                                    #   [Refuse] [Allow once] [Allow for 15 minutes ▾]

claude> sudo systemctl restart foo  # galley: "sudo systemctl restart foo"
                                    #   Password [••••]  Remember for [15] [minutes ▾]  [Cancel] [Allow]
frisket-sudo: password remembered for this claude until 16:40

claude> sudo journalctl -u foo      # galley: "sudo journalctl -u foo"   [Refuse] [Allow]   (no password)

claude> sudo systemctl stop sshd    # galley, danger icon and banner: "touches a unit that guards this machine"
                                    #   [Refuse] [Allow]   (never opens a window)
```

The work, done together:

- **frisket-signer**, replacing the stock `ssh-tpm-agent` that ships first (M0.5).
- **frisket-sudo**: a C approval plugin, a C PAM helper, a Go gate daemon and a Go askpass.
- **Shared packages** in frisket.
- **A services socket in galley**, with a `level` field.
- **NixOS wiring**: frisket owns the modules, nix-config sets them.

## 0. Goals and the floor

Goals:

1. SSH keys live in the TPM (ECDSA P-256 only). A key works only on its own chip, and only `ssh-signer` can open the TPM.
2. Every signature is journaled with its requester and destination, verified wherever ssh binds the session.
3. One question per new situation: Allow once, Allow for a time the person picks, or Refuse.
4. No-tty sudo: the person types the password once per claude per window, and still sees every command.
5. Terminal sudo and remote `sudo -S` behave as today.
6. No Python. Neither daemon runs as root or as dan.

**The floor.** Nothing here is ever looser than stock `ssh-tpm-agent` or default sudo. Where flong already stops an attack, these programs do not repeat the defence. Defending against code that already runs as dan on the host is a non-goal (see §2).

**Rules for the code.** No timeouts or deadlines anywhere in our code (signer, gate, plugin, PAM helper, askpass, galley). A request is open until it is answered or its requester goes away; the caller owns the timer (sshd's `LoginGraceTime`, Claude Code's Bash timeout, a person's Ctrl-C). A duration the person picks (Allow for 15 minutes) is not a timeout.

**Approach.** Build it, use it, read the journal, tune. New silent or refuse cases are a code change made after reading the journal.

## 1. Host facts

Measured on both hosts (dan-blade, dan-desktop) unless marked; a file source is a code read.

| # | Fact | Source |
|---|---|---|
| H1 | Both TPMs are Intel PTT (ADL, fw 0x2580012). A transient H-2 ECC primary works. Sign takes ~225 ms with a fresh parent and ~43 ms with parent and key kept loaded. `MAX_AUTH_FAIL` 32, `LOCKOUT_INTERVAL` 7200 s, `lockoutAuthSet` 1. Persistent handles 0x81000001/2/9 and 0x81010001 exist; dan-blade's LUKS tokens are sealed under 0x81000001 | [spike: g0] |
| H2 | dan-desktop. A gnome-console tab: `.kgx-wrapped --gapplication-service` (parent `systemd --user`) → `bash` (cmdline exactly `/run/current-system/sw/bin/bash`, pid = pgrp = sid, pts `tty_nr`) → `.claude-unwrapp` (comm, 15 chars) | [spike: host-facts-desktop] |
| H3 | dan-desktop. Each command from Claude Code's Bash tool runs in its own session with no tty (`tty_nr` 0; `/dev/tty` gives ENXIO) | [spike: host-facts-desktop] |
| H4 | Claude Code: `permissions.defaultMode = "auto"`, `permissions.allow = [ "Bash(sudo:*)" ]`, `SUDO_ASKPASS` set in its env only. Its commands inherit `DISPLAY=:0`, without which sudo with no tty and no `-A` says "a terminal is required" and never runs the askpass | `home/dan.nix:612`, `:636`, `:646`; sudo `tgetpass.c:139` |
| H5 | ssh hosts: `modem` (password, needs `ssh-rsa`), `gateway` (OpenWrt dropbear; cannot take a P-256 key), `server`, `mac` (hand-managed `authorized_keys`), GitHub | `home/dan.nix:845-878` |
| H6 | galley wire: one JSON object per line, `Hello{galley,item}`, `Item{kind,title,text,markup,icon,buttons,default,forms}`, `Answer{answer,index,fields,error}`. An `extra` button answers its index and no field values. Enter presses the item's `default`, in forms too | `galley/internal/wire`, `daemon/window.js` |
| H7 | sudo forks the askpass itself (`execl` after dropping to the user) and waits for it. The PAM stack, so the PAM helper and the askpass, runs once per password try | sudo `tgetpass.c:295-375`; [spike: AP1] |
| H8 | `kernel.yama.ptrace_scope` is 1 on both hosts | [spike: g0] |
| H9 | nix-config has no flake `checks` output yet. dan-blade boots lanzaboote, dan-desktop plain systemd-boot; neither sets `configurationLimit` (null, unlimited) | `hosts/dan-blade/secure-boot.nix`, `modules/common.nix:19` |

## 2. Threat model

| Actor | Runs as | Reaches | In scope |
|---|---|---|---|
| A. Agent in a chase/flong container | dan's uid in a user namespace | No signer, galley or sudo sockets (flong `protect` list), no user bus, no setuid sudo (NNP set, `/run/wrappers` absent). Can write the checkout, and in the trusted tier the host's `~/.claude`, `~/.codex` and cc-socks | **Yes.** Kept out by flong, not by prompts |
| B. Host agent a prompt injection can steer (host Claude Code, auto mode, `Bash(sudo:*)`, `SUDO_ASKPASS`) | dan, no tty | Everything dan reaches | **Partly.** An attention boundary while B acts through ssh, git and sudo. A B that persists code (user units, rc files, a devShell, its own askpass) has become C |
| C. Code running as dan on the host | dan | Everything dan reaches, including joining `galley.service`'s cgroup | **No.** It cannot reach the TPM, root's cgroups or sudo internals; the journals record what it asked for |
| D. Root, kernel, firmware | root | Everything | No. Root peers are refused, not defended against |
| E. Remote host or network position | — | The agent protocol through a forwarded socket | **Yes**: session-bind is verified, forwarding is shown |

**Accepted limits.** Each is at the stock floor or is stopped by flong.

- C can answer galley. Any dan process inside `user@1000.service` can write its pid into `app.slice/galley.service/cgroup.procs`, rebind `/run/galley-ask/dan.sock` and pass the services' binder check [spike: G-P1]. The check is a bar-raiser against a plain socket rebind. Stock agent: signs silently; stock sudo: any program can draw a password box.
- Forged terminal chains. Links are identified by comm and kernel structure, so a host process can build a chain shaped like a tab (bash copied as `.kgx-wrapped` under `systemd-run --user --pty`) and get a silent sign to a known host. Stock signs silently. A preloaded or memfd-loaded program is shown by its name.
- `SUDO_ASKPASS=./steal sudo -A …` makes `./steal` sudo's child; it passes the ppid and euid-0 checks and receives the password typed into the genuine form. Stock: any program can draw a password box.
- A checkout's devShell is code from whoever wrote the checkout; entering it in a host tab runs it as dan.
- A trusted-tier session can write the host's `~/.claude`, `~/.codex` and cc-socks and so reach host sessions. Accepted: the end state is that nothing runs with host access.
- Detached remote sudo (`ssh host 'setsid -f sh -c "sudo -S …"'`) loses its ssh ancestry and is gated locally: asked on the desktop, or refused with nobody to ask [spike: R1].
- An ssh blocked on the agent after the server's `LoginGraceTime` keeps its row until its launcher kills it.
- A process that frisket.service starts (the asker, a hook) can double-fork to ppid 1 and name itself `frisket`, and then signs silently as frisket's main process. Stock signs for any dan process.
- After a window ends, a sudo whose parent still holds a sudoers ticket gets a question without the password, as stock sudo skips the password.
- During M0.5, dan is in `tss`: dan-uid code can sign with the key and drive DA lockout. That is stock `ssh-tpm-agent`.

**What makes the sudo window hold.** The window is pinned to the galley process that took the password. An Allow is counted only from that process, so C's rebound socket does not count inside a window. The pin assumes C cannot steal galley's listener fd: `pidfd_getfd` works at `ptrace_scope` 0 and is EPERM at 1 [spike: G-P1]. An assertion keeps `ptrace_scope >= 1`. It also assumes no dan process can press Allow inside galley: galley answers only from its own buttons (no answer GAction) and runs with `GTK_A11Y=none` (its default); turning on galley's accessibility option opens the window to any dan process.

**What C cannot do:**

- Open `/dev/tpmrm0`: only `ssh-signer` is in `tss` once the signer is enabled (assertion) [spike: identity-vm].
- Move into `system.slice/frisket.service`: `cgroup.procs` is root 0644. UNTESTED from inside `user@1000.service`; the signer VM test tries it.
- Be frisket's main process: that needs ppid 1 in frisket's cgroup. A process frisket starts could get there by double-forking (an accepted limit above).
- Write `/run/frisket-signer`, `/run/frisket-sudo`, `/run/frisket-sudo-askpass` or `/etc`.
- ptrace setuid sudo [spike: sudo-plugin], or galley at `ptrace_scope` 1 [spike: G-P1].

### Trusted computing base

| Component | Runs as | Privilege | Trusted for |
|---|---|---|---|
| frisket-signer | `ssh-signer` (951) | `/dev/tpmrm0` via `tss`; no capabilities | The only TPM access; verifying session-bind |
| frisket-sudo gate | `sudo-gate` (952) | none | Deciding sudo; holding each claude's password window and its galley pin; relaying the password to the askpass |
| `frisket_approval.so`, `frisket-sudo-pam` | root inside setuid sudo / pam_exec | sudo's | Collecting the chain as root, so the gate needs no capability |
| `frisket-sudo askpass` | dan, plain program | none | Handing the password to sudo's stdin |
| galley window | dan | none | The only source of answers; the pinned process for a window |
| frisket main process | dan, system unit `frisket.service` | none | Signing silently for chase sessions |

## 3. What a day looks like

| Moment | Today | Target |
|---|---|---|
| `ssh`/`git` typed in a tab to a host in `/etc/ssh/ssh_known_hosts` | 0 | 0 |
| Same, to a host key not in `ssh_known_hosts` | 0 | 1 question; a grant covers that tab's shell |
| `kgx -- ssh host`, `systemd-run --user ssh …`, a re-parented `ssh -f` | 0 | 1 question, warning icon, Allow once only |
| frisket logging in for a chase session | 0 | 0, even with galley closed |
| Host Claude Code, first `git push` of a session | 0 | 1 question; Allow for 15 minutes (prefilled) makes it 0 for that claude, host and key until the grant ends |
| `ssh -A` and a sign on the far side | 0 | 1 question with the line "forwarded" |
| `sudo ssh …` reaching the signer as root | refused by gcr | refused, logged |
| `ssh gateway` | ed25519 via gcr | ed25519 file, authorized on the gateway only |
| `ssh modem` | password | unchanged |
| `printf pw \| ssh host "sudo -S …"` | password | unchanged |
| Host Claude Code, first sudo | 1 password dialog | 1 dialog: password and "remember for 15 minutes"; it approves this command |
| Further sudo inside the window | 1 password per Bash call | 1 question, no password |
| A danger command (§4.6) | 1 password | a question with the danger icon and banner (outside a window, after the dialog); never opens a window |
| Window ended, or galley restarted | — | the dialog again |
| A question while the screen is locked | — | it waits until unlock or until the requester gives up |
| sudo in a terminal | — | unchanged |
| Gate socket stopped | — | no-tty sudo refused with "gate not running"; terminal sudo unchanged |

Prompts rise for agent SSH, which is silent today. Typing falls for agent sudo; reviewing does not.

## 4. Decisions

### 4.1 Keys and the TPM

- **ECDSA P-256 only.** No RSA key and no gateway key on the TPM. The gateway keeps the old ed25519 file key, authorized there only, until it runs a current OpenSSH; no further gateway work is in this plan.
- **Keys come from stock `ssh-tpm-keygen`** at M0.5, with its defaults: DA protection on, `emptyAuth` (an empty passphrase at its prompt), `userWithAuth`, no policy, parent the transient H-2 ECC primary. The signer loads those same files later. `frisket-signer keygen` (~100 lines) makes new keys the same way for recovery and new hosts; `--no-da` exists and is unused.
- **TPM access is the boundary.** Anyone who can read a blob and open `/dev/tpmrm0` can sign with it. `security.tpm2.enable` puts `/dev/tpmrm0` at `root:tss 0660`. When the signer is enabled, an assertion over effective membership (members, `extraGroups`, primary group) keeps every login user out of `tss`. Blobs are useless off their chip (`TPM_RC_INTEGRITY`) [spike: tpm-keys].
- **The parent is transient and cached.** The signer creates the H-2 ECC primary on a long-lived `/dev/tpmrm0` fd and keeps it (and loaded keys) there [spike: g0]. On any TPM error other than integrity or lockout, it closes the fd (the kernel flushes everything on it), rebuilds, and retries that sign once.
- **Never touch a persistent handle.** Nothing of ours creates, evicts or replaces one. dan-blade's disk unlock depends on 0x81000001.
- **Loading.** At start the signer parses every `*.tpm` in `/var/lib/frisket-signer` and lists its public key, without touching the TPM; a file it cannot parse is skipped with one journal line. No keys is normal: `REQUEST_IDENTITIES` answers an empty list. The key is loaded into the TPM on its first sign and kept. A failed sign returns the error to ssh and writes one journal error line with the cause:
  - `TPM_RC_INTEGRITY`: "TPM cleared or a different chip";
  - `TPM_RC_LOCKOUT`: "TPM is in dictionary-attack lockout; signing resumes when it decays", not retried;
  - anything else: the TPM's error text.

### 4.2 Who is asking

Collected by `internal/peer` for the signer (from the socket) and for the gate (from root-collected links):

- **Peer uid.** The signer's peer must have `SO_PEERCRED` uid == `forUser`. Anything else (root through `sudo ssh`, nix-daemon, another user) is refused with "peer uid N is not dan", and nobody is asked.
- **Chain.** `SO_PEERPIDFD`, then `PIDFD_GET_INFO` (check the mask bits first: a dead pidfd reads uid 0 [spike: identity-vm]), then walk `/proc/<pid>/{stat,status,cmdline,cgroup}` up the ppids to depth 16, pid 1, or the first unreadable link. Links are named by **comm** (stat field 2) and kernel structure (ppid, sid, `tty_nr`, uid, cgroup).
- **Cut**: the walk stopped early, or the chain is orphaned. **SessionRoot**: the anchor is pid 1, `systemd --user` or the terminal server. Both are never grantable and never open a window, and both get the warning icon.
- **Anchor**: the nearest ancestor whose comm is not transient (`bash sh zsh fish dash env timeout nice nohup setsid script sudo ssh git`), keyed on `(pid, starttime)`. Host Claude Code resolves as `ssh ← git ← bash ← .claude-unwrapp`, so the anchor is the claude process [H2]. A desktop app anchors on itself, or falls to SessionRoot and is asked.
- **Terminal**, all of:
  1. the link below the terminal server (comm `.kgx-wrapped`) is a shell (comm `bash`) whose cmdline is exactly its argv0 or `-bash`, which is a session leader with a pts `tty_nr`;
  2. the terminal server's parent is `systemd --user`;
  3. every link between the shell and the leaf has comm `ssh`, `git`, `scp`, `sftp` or `rsync`.

  For a Terminal chain the anchor is the tab's shell, so a grant is per tab. Agent commands fail rule 3: claude and its `bash` sit between the tab's shell and the leaf. `kgx -- ssh`, `kgx -- bash -c …` and `kgx -- git push` fail rule 1 and become SessionRoot.
- **Remote** (sudo only): a link with comm `sshd-session` running as the user whose parent is a uid-0 `sshd-session` [spike: R1].
- **frisket's main process**: uid `forUser`, `cgroupid` == the inode of `/sys/fs/cgroup/system.slice/frisket.service` (stat'ed at every check), ppid 1, comm `frisket`. Any other process in that cgroup (frisket-asker, an `ssh-add` from a hook) is a normal requester.

### 4.3 galley

- **A services socket** at `/run/galley-ask/<user>.sock`, 0666, in a `0755 dan` directory. galley binds it itself (unlink a stale file, bind, chmod, listen): under socket activation every client sees `systemd --user` as its peer [spike: G-P1].
- **Who may post**: only uids listed in `GALLEY_SERVICES`; others are reset. The window sets `item.caller` from `SO_PEERCRED` after validation (a client-sent `caller` fails validation) and shows the caller's label.
- **What galley owns**: markup is off for services; the icon comes from `level` (`normal`, `warning`, `danger`), drawn by galley, with a banner for `danger`; recording keeps its red. Service rows never join. Any form shape is allowed.
- **Who answered.** Before trusting an answer, a service checks its galley peer: uid `forUser`, and `cgroupid` == the inode of `…/user@<uid>.service/app.slice/galley.service`, stat'ed at every check (it changes on every galley start) [spike: G-P1, identity-vm]. Anything else is nobody to ask.
- **Time control**: a number entry prefilled `15` and a `minutes|hours` dropdown; capped at 24 h (a constant). An absent or empty unit is minutes. An unreadable number or 0 means once, logged as "time not understood" without the text. Above 24 h is clamped.
- **No deadlines.** A row lives as long as the requester's connection to the service. The service closes its galley connection when the requester hangs up, which withdraws the row. A locked screen does nothing special: the row waits.

### 4.4 The signer decides in a fixed order

1. Peer uid is not `forUser` → refuse, logged.
2. Userauth on a connection with binds, whose session id is not the last bind's, or a hostbound request whose embedded host key is not the bound key → refuse. A connection with no binds goes on as unbound.
3. frisket's main process, userauth → sign.
4. Terminal chain, bound userauth, not forwarded, host key in `/etc/ssh/ssh_known_hosts` → sign.
5. A live grant for `(anchor, host key, key)`, chain not Cut or SessionRoot → sign.
6. Otherwise ask.

Forwarded, unknown host key, unbound and SSHSIG appear as text lines in the question; whether any becomes silent or refused is decided from the journal.

### 4.5 sudo: one dialog, then a per-claude password window

- **The first no-tty sudo** of a claude reaches the askpass. The gate posts one form to galley: the command and requester, a password field, and "remember the password for this claude for [15] [minutes]". On Allow, the gate relays the password to the askpass, which writes it to sudo. If pam_unix accepts it, that dialog is also the approval of this command, and the window opens for the chosen time.
- **Inside the window** the PAM helper lets sudo skip pam_unix, and every command is still asked as a plain question (Allow / Refuse).
- **The window** is keyed on the claude anchor `(pid, starttime)` and pinned to the galley process that served the dialog (its pid from `SO_PEERPIDFD` on the gate's galley connection, and its starttime from `/proc/<pid>/stat`). It ends at the chosen time, when that galley process exits, or when the anchor exits. An Allow from any other galley process does not count.
- **Only a password typed in the dialog opens a window.** Never a sudoers ticket, `-S`, NOPASSWD, intercept, or an approval with no dialog. A danger command never opens a window. A Cut or SessionRoot chain never gets one.
- **The askpass is a plain program**, `frisket-sudo askpass`, run as dan. The gate accepts it only when its kernel ppid is a sudo waiting on a pending 'G', and that parent (opened with `pidfd_open`) has euid 0 and ruid `forUser` [spike: AP1]. `SUDO_ASKPASS` must reach it by `exec`, so it stays sudo's direct child [spike: AP1].
- **The askpass has no fallback box.** On a refusal or a down gate it prints the reason and exits 1. `SUDO_ASKPASS` points at it only when the gate is enabled.
- **Who runs what**: the plugin and the PAM helper run as root inside sudo; the gate as `sudo-gate`; the askpass as dan.

### 4.6 Danger and warning

The gate classifies every command on 'A'. The dialog on 'P' is not classified: a danger command's dialog is a normal one, and its 'A' then asks the danger question and opens no window. A danger command gets the danger icon and banner and a reason line, is always asked, never forces a password, and never opens a window.

- **Danger:**
  - a command matching the embedded catalogue: `systemctl` touching a guard unit `frisket*`, `galley*`, `sshd*`, `nftables*`, `debug-shell*` (`status` included);
  - a program outside the root-owned directories: `command_info["command"]` is not absolute and clean, or `filepath.Dir` of it is not exactly `/run/current-system/sw/bin`, `/run/wrappers/bin` or `/etc/profiles/per-user/<user>/bin` (for example nix-config's `make-usb` script, or `~/bin/systemctl` found first in PATH);
  - `sh`/`bash -c`, `-s`/`-i` and `env`: the gate unwraps them and passes the inner string to execrule's `Parse`; every simple command in it is classified, and anything execrule cannot read is danger.
- **Warning** (requester only): a Cut or SessionRoot chain.
- **Text lines**, no icon change: environment variables outside the allowlist (`HOME LOGNAME USER SHELL MAIL TERM TERMINFO TERMINFO_DIRS LANG LC_* PATH DISPLAY XAUTHORITY COLORTERM SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND SUDO_HOME`), shown with their values cut; for the signer, forwarded, unknown host key, unbound and SSHSIG namespace.

The plugin is uninvolved when the invoking user is not `forUser`.

### 4.7 Failure

- **No-tty sudo fails closed** when the gate cannot be reached: "frisket-sudo: gate not running (systemctl status frisket-sudo.socket); sudo in a terminal is not gated". Terminal and remote sudo never reach the gate, so this cannot lock anyone out. "Gate off" is `sudoGate.enable = false`, which leaves the plugin line out of `sudo.conf`.
- `open()` never returns -1 or -2 [spike: sudo-vm].
- **Nobody to ask** (galley not running, wrong galley peer): the signer signs at steps 3-5 as usual and refuses at step 6; the gate refuses with "no one to ask; use a terminal".
- A panic in one request refuses that request and never exits the process.

## 5. Architecture

### Components

```
                         dan's session (uid dan)
  ┌───────────────────────────────────────────────────────────────────────┐
  │ galley window (galley.service, user)                                  │
  │   %t/galley/sock               0600  dan's clients (socket-activated) │
  │   /run/galley-ask/dan.sock     0666  services; bound by galley itself │
  └───────────▲─────────────────────────────────────────▲─────────────────┘
              │ question / answer, level                 │ password form, questions
              │ (peer: uid dan + galley.service cgroup)  │ (window pinned to galley's pid)
  ┌───────────┴───────────────┐            ┌─────────────┴─────────────────────┐
  │ frisket-signer            │            │ frisket-sudo gate                 │
  │ ssh-signer (951), tss     │            │ sudo-gate (952), no capabilities  │
  │ /dev/tpmrm0               │            │ /run/frisket-sudo/gate.sock       │
  │ /var/lib/frisket-signer/  │            │   0600, root 0700 dir: 'G' 'A'    │
  │   *.tpm                   │            │ /run/frisket-sudo-askpass/        │
  └───────────▲───────────────┘            │   askpass.sock 0666: 'P'          │
              │ agent protocol             └──────▲─────────────────▲──────────┘
              │ /run/frisket-signer/agent         │ 'G' 'A' (uid 0) │ 'P' → password
              │ (dan 0600)                        │                 │ (ppid = waiting sudo)
  ┌───────────┴──────┐  ┌──────────────────┐  ┌───┴─────────────────┴─────────────┐
  │ ssh, git, scp    │  │ frisket.service  │  │ setuid sudo                       │
  │                  │  │ main process     │  │  pam_exec frisket-sudo-pam ('G')  │
  └──────────────────┘  └──────────────────┘  │  frisket_approval.so ('A')        │
                                              │  └▶ frisket-sudo askpass (child)  │
                                              └───────────────────────────────────┘
```

### An SSH login

```
ssh ──connect──▶ /run/frisket-signer/agent
   signer: SO_PEERCRED uid == dan?            (else refuse, log)
           SO_PEERPIDFD → PIDFD_GET_INFO → /proc chain by comm: Cut, SessionRoot, Terminal, anchor
ssh ──session-bind@openssh.com(hostkey, sid, sig, fwd)──▶ verify sig over sid; push bind
ssh ──REQUEST_IDENTITIES──▶ loaded keys
ssh ──SIGN_REQUEST──▶ parse: userauth? sid == last bind? embedded hostkey == bound key? (else refuse)
   decide (§4.4): frisket? terminal to known host? grant? → sign | ask
   ask: galley question; poll ssh's connection for POLLRDHUP; hang-up withdraws the row
   sign: cached parent + key on the long-lived fd → TPM2_Sign → reply
   journal: one record per decision
```

### An agent's sudo

```
first:  'G' → gate: no window → 'N'  ─▶ pam_unix → askpass 'P' → gate posts the dialog
        Allow → 'Y' password → sudo's stdin; pam_unix accepts
        'A' → gate: the dialog is the approval → 'Y', window opens (§7)
next:   'G' → gate: window live → 'Y' (pam_unix skipped)
        'A' → gate: question → Allow from the pinned galley → 'Y'
```

## 6. frisket-signer

### Commands

`cmd/frisket-signer` follows `cmd/frisket/main.go`: a FlagSet per subcommand, `frisket-signer <sub>: <err>` and exit 1, slog JSON.

- `serve`: takes its listener from `internal/sdnotify.Listen()` (fd named `agent`) and exits non-zero without it. Loads the keys, then `READY=1`.
- `keygen -out DIR [-comment C] [--no-da]`: writes `id_ecdsa.tpm` and `id_ecdsa.pub` in stock's format. Runs as `ssh-signer` through the `frisket-signer-keygen` oneshot, because `tss` comes only from the unit.

Packages:

- `internal/tpmkey`: the only go-tpm importer. `Generate`, `Load(file)`, `(*Key).Signer`, and the cached-parent session. Uses go-tpm's `linuxtpm` (it polls; a hand-written non-blocking read returned 0 bytes 279 times in 300 [spike: identity-vm]). Never `keyfile.LoadKey`, which leaks the parent on failure.
- `internal/agentsrv`: a per-connection `ExtendedAgent`, the session-bind state, and the userauth and SSHSIG parsers.

### Agent protocol

| Message | Behaviour |
|---|---|
| `REQUEST_IDENTITIES` | The loaded keys. Logged with the requester |
| `SIGN_REQUEST` | Decide (§4.4) |
| `EXTENSION session-bind@openssh.com` | Verify `hostkey.Verify(sid, sig)`; a failure is returned. Append to the connection's binds (at most 16) [spike: session-bind] |
| Other extensions | `ErrExtensionUnsupported` |
| `ADD_IDENTITY`, `REMOVE_*`, `LOCK`, `UNLOCK` | Refused |

Request classes [spike: session-bind]:

1. **Bound userauth**: `sid == binds[last].sid`; a hostbound request's embedded host key must equal `binds[last].hostkey`. Any `fwd=1` bind on the connection marks it forwarded.
2. **Unbound userauth** (x/crypto, OpenSSH < 8.9): no verified destination; an embedded host key is shown as "claims SHA256:…".
3. **SSHSIG**: magic, namespace and hash parsed; the namespace is shown. UNTESTED on real output: the unit test uses `ssh-keygen -Y sign` fixtures.

Anything else is refused.

### Destination

Names come from `/etc/ssh/ssh_known_hosts` (NixOS writes it unhashed). A host key maps to a set of names. Grants key on the host key's SHA256 fingerprint; names are for display. An unknown key shows as "unknown host SHA256:…". nix-config adds `server` and `mac` to `programs.ssh.knownHosts`.

### Questions

A grantable question (not Cut, not SessionRoot) is a form with the time control; an ungrantable one is a plain question with the warning level.

```json
{"galley":3,"item":{"kind":"forms","level":"normal","title":"ssh to github.com",
  "text":"claude (pid 5113) ← bash ← git push ← ssh\nkey SHA256:… (dan@dan-blade)\nA grant covers github.com from this claude.",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow once","underline":-1},
             {"answer":"ok","label":"Allow for","underline":-1}],
  "default":-1,
  "forms":{"fields":[{"kind":"entry","label":"Allow for","values":["15"]},
                     {"kind":"combo","label":"","values":["minutes","hours"]}]}}}
```

```json
{"galley":3,"item":{"kind":"question","level":"warning","title":"ssh to server",
  "text":"launched through systemd --user\nsystemd --user ← ssh",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow once","underline":-1}],
  "default":-1}}
```

| Answer line | Result |
|---|---|
| `{"answer":"extra","index":0}` | Allow once |
| `{"answer":"ok","fields":[{"text":N},{"text":U}]}` | Allow for N U (§4.3) |
| anything else, `cancel`, `close` | Refuse |
| an error, EOF | nobody to ask |

- Text is plain: control and bidi characters escaped, each argv cut at 1000 characters.
- While asking, the signer polls the ssh connection for `POLLRDHUP` and closes the galley connection on hang-up.

### Grants (`internal/grant`, signer only)

- `Key{Anchor{Pid, Start}, Host, KeyFP}`; `Grant(k, until)`; `Use(k) bool`.
- `until` = answer time + chosen, in `CLOCK_BOOTTIME`, so suspend counts against it. Use never extends it. A second grant for the same key keeps the later end.
- A dead anchor's grant never matches again: a reused pid has another starttime. `Grant` drops expired entries; nothing reads `/proc`.
- In memory only. A restart costs at most one question per active anchor.

### Journal

One structured record per decision: requester chain, anchor, destination, key, class, text lines, outcome, its source (frisket, terminal, grant, galley answer, nobody), the chosen time, and the galley peer's pid and cgroup.

## 7. frisket-sudo

### Pieces

- `sudo/frisket_approval.c`, `sudo/frisket-sudo-pam.c`, shared `sudo/chain.c` (chain walk, remote test, 'S') and `sudo/wire.c`. Built against `sudo.src`'s `sudo_plugin.h` with `-Wall -Wextra -Werror -fvisibility=hidden`. The C collects, frames and makes the three stock-sudo exits (other user, tty, remote); everything else is in Go.
- `sudo/frisket-sudo-check-plugin.c` (~40 lines): `dlopen(RTLD_NOW)`, `dlsym`, then checks plugin type 4 (approval), the API major and the sudo version. A wrong type makes every sudo segfault [spike: SV1], so this check is mandatory.
- `cmd/frisket-sudo`: `serve` (fds `gate` and `askpass` from `sdnotify.Listen()`; refuses to start without `gate`) and `askpass`.
- `sudo/danger.json`, embedded with `go:embed`, checked by a unit test.

### When it is involved

| Situation | Plugin | PAM helper | Result |
|---|---|---|---|
| Invoking user is not `forUser` | `open()` 0 | exits 1 | Stock sudo |
| tty present | `open()` 0 | exits 1 | Stock sudo |
| tty present, `-A` with frisket's askpass | `open()` 0 | exits 1 | The askpass gets 'N' "not started by a waiting sudo" and sudo fails; `SUDO_ASKPASS` is set only in Claude Code's env [spike: AP1] |
| Remote chain, no tty (`ssh host "sudo -S …"`) | `open()` 0 | exits 1 | Stock sudo |
| Local, no tty, askpass | gates | may skip pam_unix | §4.5 |
| Local, no tty, `-S`, a ticket, another `SUDO_ASKPASS` | gates | may skip pam_unix | No dialog: a question, no window |
| `-v`, `-l`, `-k` | not opened | runs | Unchanged |
| `-n` | gates | not run | Fails without a ticket, as stock (`noninteractive_auth` is unset) |
| No tty, no `DISPLAY`, no `-A` | gates | runs | sudo's own "a terminal is required"; the pending record goes when sudo exits [spike: sudo-vm] |

### Wire, version 1

One request and one reply per connection.

```
request := "FSUD" | u8 version=1 | u8 kind | u32be length | body
kind     : 'G' grant query (PAM helper)  'A' approval (plugin)  'P' password (askpass)
body     := record*        record := u8 tag | u32be len | bytes[len]
'S'  u32be sudo_pid | u64be sudo_starttime                    G, A: required, once
'k'  chain link: u32be pid | u32be ppid | u64be starttime | u32be uid | u32be tty_nr
                 | u16be len comm | u16be len cmdline (NUL-separated, ≤ 4096)   G, A
'v'  sudo's own argv from /proc/<sudo_pid>/cmdline (NUL-separated, ≤ 4096)      G: required
'u' user_info  's' settings  'c' command_info  'a' run_argv  'e' run_envp       A
't'  truncated marker
'P'  body empty; the sudo is the peer's kernel ppid, never a field
limits   : ≤ 1 MiB (truncate run_envp, then cmdline); ≤ 16 links;
           every record length checked against the remaining body before allocating
reply    := u8 'Y' | u16be len | message      'Y' to 'P': the password, raw bytes, ≤ 1023
          | u8 'N' | u16be len | message      messages: ≤ 512 printable ASCII
```

- `gate.sock` takes 'G' and 'A' from peer uid 0 only. `askpass.sock` takes 'P' only; any other kind or a non-empty body gets 'N'.
- A 'G' or 'A' missing 'S' (or a 'G' missing 'v') gets 'N'.
- The first 'k' link is sudo's parent. Each link reads `stat` before and after `cmdline`; a starttime change cuts the chain there.
- 'S' starttime is field 22 of `/proc/<pid>/stat`: the plugin reads its own, the helper its parent's. Both name the same sudo on every try [spike: R1, AP1].

### Plugin

`open()`:

- `user_info` user is not the `user=` option → 0.
- `tty=` present → 0 [spike: sudo-vm].
- Remote chain → 0.
- `user=` missing → set misconfigured and return 1; `check()` then denies with "frisket-sudo: plugin misconfigured in /etc/sudo.conf; use a terminal".
- Otherwise 1. Never -1 or -2.

`check()`:

1. Connect `/run/frisket-sudo/gate.sock` (compiled in). Any error → the "gate not running" denial.
2. Send 'A' and read the reply, with no timeout of its own.
3. EOF or garbage → deny "no answer from gate". 'N' → print the message with `sudo_plugin_printf(SUDO_CONV_ERROR_MSG)` (errstr is never shown [spike: sudo-vm]) and return 0. 'Y' → print a non-empty message with `SUDO_CONV_INFO_MSG` and return 1.

sudo writes its ticket even when approval refuses, but the plugin runs on every command and a dead gate refuses, so the ticket never runs a command unseen [spike: sudo-vm].

### PAM helper

`auth sufficient pam_exec.so seteuid quiet <helper> <user>`, ordered before `pam_unix` [spike: sudo-vm].

1. `PAM_TTY` set → exit 1. (`sudo -A` from a terminal reaches the helper and stops here [spike: AP1].)
2. `PAM_SERVICE != sudo`, `PAM_USER != PAM_RUSER`, or `PAM_USER != <user>` → exit 1.
3. Collect the chain from `getppid()`'s parent, 'S' from `getppid()`, 'v' from `/proc/<getppid()>/cmdline`. Remote chain → exit 1.
4. Send 'G' and wait. 'Y' → exit 0. Anything else → exit 1, and pam_unix runs.

The helper never asks: pam_exec waits for it.

### Askpass

`frisket-sudo askpass` connects `/run/frisket-sudo-askpass/askpass.sock` (compiled in), sends 'P', and waits. 'Y' → write the password and a newline to stdout, zero the buffer, exit 0. 'N' or a connect error → print "frisket-sudo: <reason>" on stderr, exit 1, which sudo treats as a cancelled prompt. It is installed as `bin/frisket-sudo-askpass`, a script that runs `exec frisket-sudo askpass`, so it stays sudo's direct child.

### The gate on 'G'

1. Peer uid 0.
2. Store or refresh the pending record for 'S': links, 'v', the classified anchor, and `pidfd_open(S.pid)` (sudo is blocked in PAM, so the pid is its). The record goes when that pidfd reports exit.
3. Reply 'Y' only when the chain is not Cut or SessionRoot, the anchor has a window, now < its end, and its pinned galley process has not exited. Mark the record `skipped`. Otherwise 'N', and clear `skipped`.

### The gate on 'P'

1. Peer: `SO_PEERCRED` uid `forUser`; `PIDFD_GET_INFO` on `SO_PEERPIDFD` gives the ppid (mask checked); `pidfd_open(ppid)` and `PIDFD_GET_INFO` give euid 0 and ruid `forUser` [spike: AP1]. The ppid must be the pid of a pending record that is not `skipped` and whose sudo pidfd has not reported exit. Otherwise 'N' "not started by a waiting sudo".
2. Post the dialog (below). Poll the galley connection, the askpass connection and the sudo pidfd. If sudo exits or the askpass hangs up, close the galley connection.
3. Cancel or close → 'N' "cancelled". A password with a NUL or newline → 'N' "password contains a newline". Allow with a non-empty password → replace the record's dialog record (shown argv, shown anchor, level, chosen time, the galley peer's pid and starttime), then reply 'Y' and the password. Each try's 'P' replaces the dialog record, so only the last try counts.

```json
{"galley":3,"item":{"kind":"forms","level":"normal","title":"sudo systemctl restart foo",
  "text":"claude (pid 5113) ← bash\n\nsudo systemctl restart foo",
  "buttons":[{"answer":"cancel","label":"Cancel","underline":-1},
             {"answer":"ok","label":"Allow","underline":-1}],
  "default":1,
  "forms":{"fields":[{"kind":"password","label":"Password for dan"},
                     {"kind":"entry","label":"Remember the password for this claude for","values":["15"]},
                     {"kind":"combo","label":"","values":["minutes","hours"]}]}}}
```

- `default` is Allow, so Enter after the password allows with the prefilled time.
- A Cut or SessionRoot dialog has the warning level and the password field only.
- The password is never logged; the journal records "<n> bytes".

### The gate on 'A'

1. Peer uid 0. Take and remove the pending record for 'S'.
2. Classify (§4.6). Words are `[basename(program)] + run_argv[1:]`; for `-s`/`-i` sudo's backslash escaping is undone first.
3. **Window path** (the record is `skipped`): if the window has ended or its galley process has exited, reply 'N' "password window ended; run it again to be asked for the password". Otherwise ask the question (below). An answer counts only if the galley peer is the pinned process; any other answer is a refusal.
4. **Dialog path** (a dialog record exists): the dialog is the answer when the chain's anchor is the one the dialog showed. Then approve. If the chosen time is above 0 and the chain is not Cut or SessionRoot, open the window: until = answer time + chosen (boottime, at most 24 h), pinned to the dialog's galley process. Reply 'Y' "frisket-sudo: password remembered for this claude until 16:40". If 'A' finds danger or an environment line the dialog did not show, ask the question instead, whose text starts with the reason ("sudo resolved /home/dan/bin/systemctl, outside the root-owned directories"), and open no window.
5. **No 'G' or no dialog** (a ticket, `-S`, another askpass): ask the question.
6. Nobody to ask → 'N' "no one to ask; use a terminal".

The question:

```json
{"galley":3,"item":{"kind":"question","level":"danger","title":"sudo systemctl stop sshd.service",
  "text":"touches a unit that guards this machine\n\nclaude (pid 5113) ← bash\n/run/current-system/sw/bin/systemctl stop sshd.service",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow","underline":-1}],
  "default":-1}}
```

While asking, the gate polls the plugin's connection for `POLLRDHUP` and withdraws the row on hang-up.

### Danger catalogue

frisket's `policy.ExecRule` list, compiled by execrule and matched with `execrule.DecideWords`. An Ask match is danger and its summary is the reason line; no match is normal. `ask` and `operation.id` are there because the format requires them with `arg`.

```json
[
  {"command":"systemctl **","arg":"frisket*","ask":true,"operation":{"id":"guard-unit","summary":"touches a unit that guards this machine"}},
  {"command":"systemctl **","arg":"galley*","ask":true,"operation":{"id":"guard-unit","summary":"touches a unit that guards this machine"}},
  {"command":"systemctl **","arg":"sshd*","ask":true,"operation":{"id":"guard-unit","summary":"touches a unit that guards this machine"}},
  {"command":"systemctl **","arg":"nftables*","ask":true,"operation":{"id":"guard-unit","summary":"touches a unit that guards this machine"}},
  {"command":"systemctl **","arg":"debug-shell*","ask":true,"operation":{"id":"guard-unit","summary":"touches a unit that guards this machine"}}
]
```

New patterns are added after reading the journal.

### Failure (no lockout)

| Failure | Effect | Why it is safe |
|---|---|---|
| `.so` missing, wrong symbol, type or sudo version | The `sudo.conf` derivation fails to build (guard 1) | If it got through anyway, the previous generation at the console; `configurationLimit >= 5` |
| `sudo.conf` group-writable or not root's | Every sudo prints "/etc/sudo.conf is group writable"; the gate is off | The store symlink is root 0444 [spike: SV1] |
| Gate socket stopped or absent | No-tty sudo refused with the message; terminal and remote sudo unaffected | Terminal sudo never reaches the gate |
| Gate service crash-looping | The socket stays up and connects succeed with no answer, so no-tty sudo waits until its caller gives up; terminal and remote sudo unaffected | `StartLimitIntervalSec=0` keeps the socket up [spike: crosscheck]; no lockout |
| Gate hangs | sudo waits until its caller gives up | The caller owns the timer |
| galley not running | The askpass prints "no one to ask; use a terminal" and exits 1; questions refuse with the same | Terminal sudo unaffected |
| sudo killed while its dialog or question is up | The gate sees the pidfd or the connection close and withdraws the row | No late rows |
| Gate restarts | Windows and records are lost; the next sudo asks for the password | In memory only |

## 8. Shared packages (frisket repo)

```go
// internal/peer: moved from internal/serve/peer.go and extended.
type Link struct {
    Pid, PPid, Sid int; TTY uint32; Start uint64; UID int
    Comm string; Cmdline []string; Cgroup string
}
type Requester struct {
    Chain []Link; Anchor *Link
    Cut, SessionRoot, Terminal, Remote bool
    PeerUID int; CgroupID uint64; PPid int
}
func FromConn(c *net.UnixConn) (*Requester, error) // SO_PEERPIDFD path (signer)
func FromLinks(links []Link) *Requester            // root-collected chain (gate)
func (r *Requester) IsMainOf(unit string, uid int) bool

// internal/galleyask
type Question struct{ Title, Text, Level string; Grantable bool; Password bool }
type Answer struct {
    Allowed bool; For time.Duration      // 0 is once
    Password []byte                      // the dialog only; the caller zeroes it
    Galley struct{ Pid int; Start uint64 }
}
var ErrNobody = errors.New("no one to ask")
func Ask(ctx context.Context, user string, q Question) (Answer, error)
```

- `internal/peer`'s transient set and depth are constants.
- `galleyask.Ask` dials `/run/galley-ask/<user>.sock`, checks the peer (§4.3), posts the item, and closes the connection when `ctx` is cancelled; the caller cancels it on `POLLRDHUP` or the sudo pidfd's exit. It speaks `github.com/danielbodart/galley/wire`.
- `internal/grant` belongs to the signer (§6). The sudo window is one record in `internal/sudogate`.
- `execrule` gains `DecideWords(words []string) Decision` beside `Decide`, sharing its Decision builder, so the gate never re-quotes argv into a shell string [spike: policy-fit].
- New module dependencies: `github.com/google/go-tpm`, `github.com/foxboron/go-tpm-keyfiles`, and `github.com/danielbodart/galley` at a pseudo-version with a public `wire/`.

### `tests/fakegalley`

A Go program built from the pinned `galley/wire`, run in the VM tests as the user unit `galley.service`, so the binder check passes for the right reason.

```
fakegalley -socket PATH -script FILE [-log FILE]
```

Script actions, one per question, the last line repeating: `ok <field>…` (answers the fields in order), `cancel`, `answer N` (extra N), `never`. `-log` writes one JSON line per question received (title, text, kind, level, buttons, fields, peer uid and pid) and per answer sent; a password is logged as its length.

## 9. galley changes

1. Move `internal/wire` to a public `wire/` package with golden files: the signer form, the plain question, the sudo dialog, every `level`, and the answer lines. Wire version 3 adds `level` (and the window-set `caller`). **This merges first.**
2. `server.js` keeps the user listener from `LISTEN_FDNAMES` and binds `GALLEY_SERVICES_SOCKET` itself (unlink, bind, chmod 0666, listen). Shown with real gjs [spike: galley-socket].
3. The services listener admits only `GALLEY_SERVICES` uids (names from `/etc/passwd` at start); others are reset. gjs reads the peer uid and pid from `Gio.Credentials` [spike: crosscheck/galley].
4. `item.caller = {uid, name, label, pid}` is set after `validate()`; a client-sent `caller` fails validation.
5. Service items: markup forced off; `level` (`normal`, `warning`, `danger`; absent is `normal`) chooses galley's icon, and `danger` adds galley's banner. No shape allowlist.
6. Service rows never join.
7. An `entry` field shows `values[0]` as its initial text.
8. Home-manager: `services.galley.services` (uid name → label); the socket is on when it is non-empty.

## 10. NixOS wiring

frisket owns `nixosModules.signer` and `nixosModules.sudoGate`, each added to frisket's double-import eval check and imported by its VM test. nix-config sets options and owns host wiring. nix-config reaches frisket through `inputs.chase.inputs.frisket`; a new frisket arrives by a go.mod bump in chase.

### frisket `services.frisket.signer`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | false | Run the signer |
| `forUser` | str | `"dan"` | The only peer uid served; galley user |

Fixed: user and group `ssh-signer` (951); socket `/run/frisket-signer/agent`; keys `/var/lib/frisket-signer/*.tpm`.

Load-bearing lines:

```nix
assertions = [{
  assertion = lib.intersectLists normalUsers usersInTss == [ ];   # members, extraGroups, primary group
  message = "a login user in tss could sign with any key blob";
}];
socketConfig = { ListenStream = "/run/frisket-signer/agent"; SocketUser = cfg.forUser;
                 SocketMode = "0600"; DirectoryMode = "0755"; FileDescriptorName = "agent"; };
serviceConfig = { User = "ssh-signer"; SupplementaryGroups = [ "tss" ];
                  DevicePolicy = "closed"; DeviceAllow = [ "/dev/tpmrm0 rw" ];
                  StateDirectory = "frisket-signer"; StateDirectoryMode = "0700"; };
```

Hardening: `NoNewPrivileges`, `CapabilityBoundingSet = ""`, `ProtectSystem = "strict"`, `ProtectHome`, `PrivateTmp`, `ProtectControlGroups`, `RestrictAddressFamilies = [ "AF_UNIX" ]`, `SystemCallFilter = [ "@system-service" "~@privileged" ]`, `MemoryDenyWriteExecute`, `Restart = "always"`, `StartLimitIntervalSec = 0`. UNTESTED as a set with the real binary and TPM; the signer VM test runs this module.

`frisket-signer-keygen` is a oneshot with the same `User`, `tss` and `DeviceAllow`, writing to `/var/lib/frisket-signer/new/`.

### frisket `services.frisket.sudoGate`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | false | Plugin line in `sudo.conf`, PAM rule, gate |
| `forUser` | str | `"dan"` | The gated user |

Fixed: user and group `sudo-gate` (952); `/run/frisket-sudo/gate.sock`; `/run/frisket-sudo-askpass/askpass.sock`.

Load-bearing lines:

```nix
sudoConf = pkgs.runCommand "sudo.conf" { } ''        # guard 1: build-time, every rebuild path
  ${root}/bin/frisket-sudo-check-plugin ${so} frisket_approval ${sudo.version}
  echo "Plugin frisket_approval ${so} user=${cfg.forUser}" > $out
'';
environment.etc."sudo.conf".source = sudoConf;
security.pam.services.sudo.rules.auth.frisket-grant = {
  order = config.security.pam.services.sudo.rules.auth.unix.order - 10;
  control = "sufficient";
  modulePath = "${config.security.pam.package}/lib/security/pam_exec.so";
  args = [ "seteuid" "quiet" "${root}/bin/frisket-sudo-pam" cfg.forUser ];
};
systemd.sockets.frisket-sudo.socketConfig = { ListenStream = "/run/frisket-sudo/gate.sock";
  SocketUser = "sudo-gate"; SocketMode = "0600"; DirectoryMode = "0700"; FileDescriptorName = "gate"; };
systemd.sockets.frisket-sudo-askpass.socketConfig = { ListenStream = "/run/frisket-sudo-askpass/askpass.sock";
  Service = "frisket-sudo.service"; SocketUser = "sudo-gate"; SocketMode = "0666";
  DirectoryMode = "0755"; FileDescriptorName = "askpass"; };
assertions = [{ assertion = (config.boot.kernel.sysctl."kernel.yama.ptrace_scope" or 1) >= 1;
                message = "the sudo window's galley pin needs ptrace_scope >= 1"; }];
```

The gate unit: `User = "sudo-gate"`, `CapabilityBoundingSet = ""`, `ProcSubset = "pid"`, `PrivateDevices`, `ProtectSystem = "strict"`, `ProtectHome`, `RestrictAddressFamilies = [ "AF_UNIX" ]`, `Restart = "always"`, `RestartSec = "1s"`, `StartLimitIntervalSec = 0`.

`/run` is root 0755, so only root can create the gate's directories; the plugin needs no check of who made them.

### frisket `nix/flong.nix`

When the signer or the gate is enabled, every flong session's `protect` list gains `/run/frisket-signer`, `/run/galley-ask`, `/run/frisket-sudo` and `/run/frisket-sudo-askpass`, beside frisket's control socket, so "no socket in a container" is checked by flong.

### nix-config

| Option | Type | Default | Meaning |
|---|---|---|---|
| `sshSigner.enable` | bool | false | false: M0.5's stock agent; true: frisket-signer |

| Setting | M0.5 (`sshSigner.enable = false`) | Signer (`true`) |
|---|---|---|
| Agent | home-manager `services.ssh-tpm-agent.enable` (keys in `~/.ssh`) | `services.frisket.signer.enable` |
| `tss` | dan in `extraGroups`; `security.tpm2.enable` | only `ssh-signer` (assertion) |
| `SSH_AUTH_SOCK` | the module's `$XDG_RUNTIME_DIR/ssh-tpm-agent.sock` | `/run/frisket-signer/agent` (home `sessionVariables`) |
| chase `ssh.agentSocket` | `/run/user/<uid>/ssh-tpm-agent.sock` | `/run/frisket-signer/agent` |
| gcr ssh agent | off | off |

Both states:

- ssh host blocks: `server`, `github.com`, `mac` and the other host get `IdentityFile = admins/<this host>/ssh-tpm.pub` and `IdentitiesOnly = yes`; `gateway` gets `IdentityFile = ~/.ssh/id_ed25519`, `IdentitiesOnly = yes`, `IdentityAgent = none`, and chase's gateway host uses `keyFile = /home/dan/.ssh/id_ed25519`; `modem` gets `PubkeyAuthentication = no`, `IdentityAgent = none`.
- `users.users.dan.openssh.authorizedKeys.keyFiles` holds both hosts' `admins/*/ssh-tpm.pub`. `admins/<host>/ssh.pub` stays in the repo (`age.pub` derives from it) and is authorized only on the gateway.
- `programs.ssh.knownHosts.server` and `.mac`.
- Before the gate is enabled, the boot menu keeps at least 5 generations: `boot.lanzaboote.configurationLimit` on dan-blade and `boot.loader.systemd-boot.configurationLimit` on dan-desktop are null (unlimited, today's value) or `>= 5`.
- galley: `services.galley.services = { ssh-signer = "SSH signer"; sudo-gate = "sudo"; }`; `systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 dan dan -" ]`.
- Claude Code: `permissions.allow = [ "Bash(sudo:*)" ]` stays, and no deny rules are added. `env.SUDO_ASKPASS` is `${frisket-sudo}/bin/frisket-sudo-askpass` when `services.frisket.sudoGate.enable`, else today's `~/.claude/sudo-askpass.sh`.
- Hosts set `services.frisket.sudoGate.enable` directly.

### nix-config `checks.x86_64-linux.sudo-lockout` (guard 2)

A NixOS VM test, run by `nix flake check` on chase, nixpkgs or sudo bumps and before M3. It imports only frisket's `nixosModules.sudoGate` and copies the host's sudo and PAM values by name. Importing nix-config's host modules recurses, and at the host's `eval-cores = 0` that is a silent hang [spike: X1]. It runs:

- `sudo id -u` with a tty, as root, and with no tty against a real gate;
- no-tty sudo with the gate's socket stopped: refused with the message, while tty sudo works;
- a remote `sudo -S` over ssh.

## 11. Tests

Whole-sentence test names, stdlib `testing` plus `rapid`. `mkFrisket` runs `go test ./...` with `pkgs.swtpm` in `nativeCheckInputs` and `FRISKET_REQUIRE_SWTPM=1`, so the TPM tests fail rather than skip. Fuzz targets run on their seed corpus there. Time is a fake boottime clock. Daemon packages are `mkFrisket` overrides with `doCheck = false`.

### Unit tests

`internal/tpmkey` (one swtpm per test):

- `TestAStockKeygenFileLoadsAndSigns`
- `TestASignatureVerifiesWithTheKeysPublicKey`
- `TestAFileThatDoesNotParseIsSkippedAndTheRestLoad`
- `TestAClearedTPMSaysClearedNotCorrupt`
- `TestLockoutIsNamedAndNotRetried` (a DA-on key at counter = max)
- `TestNoDAFlagSetsTheAttribute`
- `TestTheCachedParentIsRebuiltAfterATPMRestart`
- `TestSigningDoesNotLeakFileDescriptorsOrTransientObjects` (100 signs, swtpm killed mid-run)

`internal/agentsrv`:

- `TestAForgedBindIsRefused`
- `TestASignForAnotherSessionThanTheLastBindIsRefused`
- `TestAHostboundRequestWhoseHostKeyIsNotTheBoundKeyIsRefused`
- `TestAnyForwardingBindMarksTheConnectionForwarded`
- `TestSSHSIGShowsItsNamespace` (real fixtures)
- `TestAPeerThatIsNotTheConfiguredUserIsRefusedBeforeAnyMessage`
- `TestAPanicInOneRequestDoesNotStopTheNext`
- `TestNoKeysAnswersAnEmptyList`
- `FuzzNoAgentMessageCrashesTheParser`

`internal/peer`:

- `TestADeadPidfdIsNeverRoot`
- `TestOnlyFrisketsMainProcessIsTrusted` (ppid, cgroup by inode)
- `TestTheClaudeChainAnchorsOnClaude` (H2 fixture)
- `TestATabShellRunningSshIsATerminal` (H2 fixture)
- `TestACommandLaunchedThroughTheTerminalServerIsNotATerminal`: `kgx -- ssh`, `kgx -- bash -c`, `kgx -- git push`
- `TestAnAgentCommandIsNeverATerminal` (claude and its `bash` between the tab's shell and the leaf)
- `TestASystemdUserRootAndAReparentedSshAreNeverGrantable`
- `TestARemoteChainNeedsARootSshdSessionParent`

`internal/grant`:

- `TestAGrantEndsAtTheAnswerPlusTheChoiceAndUseNeverExtendsIt`, plus a rapid property
- `TestAGrantDoesNotSurviveASuspendLongerThanItsTime` (boottime jumps, monotonic does not)
- `TestAGrantForADeadAnchorNeverMatchesAReusedPid`

`internal/galleyask`:

- `TestAnAnswerFromAPeerOutsideGalleysCgroupIsNobody`
- `TestTheQuestionsEncodeToTheGoldenBytes` and `TestEveryGoldenAnswerLineDecodesToItsResult`
- `TestTheTimeFieldParsesClampsAndLogsNoRawText`: `15 minutes`, `2 hours`, `15` with no unit (15 minutes), `0`, `hunter2` (once, logged as "time not understood"), `100 hours` (24 h)
- `TestHangUpWithdrawsTheRow`
- `TestThePasswordIsNeverLogged` (captures slog output and searches it)

`internal/sudogate` (peer facts injected as `PeerInfo`):

- `FuzzNoRequestCrashesTheGate` (all three kinds, both sockets)
- `TestARequestWithoutTheSudoTagIsDenied`
- `TestAPasswordRequestWhoseParentIsNotAWaitingSudoIsRefused`: no 'G'; a 'G' already consumed; a 'G' whose sudo has exited; a parent with euid dan; another user
- `TestAGWhoseSudoExitsWithoutAnALeavesNoRecord`
- `TestTheLastTrysDialogIsTheOneThatCounts`
- `TestADialogRecordIsUsedOnlyByTheSudoItWasMadeFor` (`(P, t1)` vs `(P, t2)` and `(Q, t1)`)
- `TestADialogDoesNotCountWhenAFindsDangerOrAnUnshownVariable`
- `TestAProgramOutsideTheRootOwnedDirsIsDanger`: `..`, `/./`, `//`, a nested dir, a store path, plus a rapid property that no non-clean path passes
- `TestShellAndEnvWrappersAreClassifiedByEveryInnerCommand`, and unreadable is danger
- `TestTheGuardUnitsAreDanger` (the embedded catalogue)
- `TestEnvironmentVariablesAreTextLines`: allowlisted names pass; `LESSOPEN`, `LD_PRELOAD`, `FOO` are shown and stop the dialog counting
- `TestOnlyADialogPasswordOpensAWindow`: a ticket ('A' with no 'G'), `-S`, intercept, a question's Allow, a dialog whose 'A' is danger and a Cut chain open none
- `TestTheWindowCountsOnlyAnswersFromThePinnedGalley`
- `TestTheWindowEndsWithItsGalleyProcessItsAnchorOrItsTime`
- `TestAWindowThatEndsBetweenGAndAIsRefused`
- `TestServeRefusesToStartWithoutTheGateFd`

`cmd/frisket-sudo askpass` (gate faked on a socketpair): `TestThePasswordGoesOnlyToStdout`, `TestAGateNoPrintsTheReasonAndExitsOne`.

`execrule`: `TestDecideWordsAgreesWithDecideOnReadableStrings` (rapid).

### VM tests (frisket, `runNixOSTest`, importing exactly the module under test)

`tests/signer.nix`: `virtualisation.tpm.enable`; two sshds with distinct host keys; fakegalley as `galley.service`; a stand-in `frisket.service` with frisket's real hardening; dan with linger.

- A key made by stock `ssh-tpm-keygen` and copied into the state dir loads, and an ECDSA login works; with no key files, identities are empty and `serve` is up.
- dan cannot open `/dev/tpmrm0`.
- The frisket main process signs without a question, also with galley absent; a live grant still signs; everything else is then refused.
- A child exec'd inside `frisket.service` is asked.
- A cgroup move from dan's real `user@` session into `frisket.service` is refused.
- A sign for another session than the last bind (tamper) is refused.
- `ssh -A` through the second sshd: the far-side sign is asked with the "forwarded" line.
- A terminal-shaped chain (a pty holder with comm `.kgx-wrapped`, then bash, then ssh) to a known host signs silently; `kgx -- ssh` shapes and `systemd-run --user ssh` are asked with the warning level and no time field.
- fakegalley `ok 15 minutes` makes a grant: the next sign from the same anchor is silent and fakegalley logs no question; `answer 0` (Allow once) grants nothing.
- A rebound `/run/galley-ask/dan.sock` (socat outside `galley.service`) is nobody, and the journal names its cgroup.
- An ssh killed while its question is up: fakegalley logs the close.
- The sockets are absent inside a flong-style namespace.
- TPM cleared (swtpm state reset): the key is still listed, a sign fails with "TPM cleared or a different chip" in ssh's error and the journal, and `serve` stays up.

`tests/sudo-gate.nix`: no tty via `setsid -w runuser` with `DISPLAY=:0`, a tty via `script -qec`; `SUDO_ASKPASS` set to the package's `bin/frisket-sudo-askpass`; fakegalley as `galley.service`.

- With a tty and no `-A`, the gate is never contacted. With a tty and `-A`, no 'G' or 'A' arrives and the askpass's 'N' "not started by a waiting sudo" fails the sudo.
- **One dialog**: `sudo systemctl restart foo` with fakegalley `ok <pw> 15 minutes`. It runs; fakegalley logged exactly one item, from the `sudo-gate` caller, showing the chain and the command; stderr says "password remembered … until"; the journal has no password.
- **Window**: the next sudo from a new `bash -c` under the same claude gets one question and no password; a different claude gets the dialog.
- **Pin**: fakegalley restarted → the next sudo gets the dialog. A thief that joins `galley.service`'s cgroup and rebinds the socket inside a window → its Allow is a refusal, the journal names the pin, and the window is unchanged. A socat outside the cgroup → nobody to ask.
- **Danger**: `sudo systemctl stop frisket.service` outside a window → the normal dialog, then a danger question, and no window afterwards; inside a window → a danger question with no password.
- **Resolved differently**: a dan-owned `~/bin/systemctl` first in PATH → the dialog shows `sudo systemctl status`, and a danger question follows naming the path.
- **sh -c**: `sudo sh -c 'systemctl stop sshd'` is danger; `sudo sh -c "$(printf x)"` is danger as unreadable.
- **Environment**: `sudo --preserve-env=FOO …` → the dialog does not count; a question shows `FOO`.
- **Cancel**: sudo fails authentication and no 'A' arrives.
- **Wrong password**, then right: two forms; the second's time is the one used.
- **Forged askpass**: a `SUDO_ASKPASS` script that prints the password → a question, no window.
- **Askpass from a shell**: `frisket-sudo askpass` run directly → refused, exit 1.
- **Ticket**: `sudo -v; sudo id` → the second gets a question and no window.
- **`-S`**: `echo pw | sudo -S id` → a question.
- **'S' agreement**: 'G', the askpass's ppid and 'A' name the same sudo.
- **Ticket on refusal**: the ticket is written on refusal; the plugin refuses the cached retry, also with the gate stopped.
- **Gate socket stopped**: no-tty sudo refused with the message; tty and root sudo work.
- **Crash loop**: a gate that exits at start keeps the socket active; no-tty sudo blocks until the test's timeout kills it, and tty sudo works.
- **Hang-up**: sudo killed while its dialog is up → fakegalley logs the close; the same for a question.
- **Never answered**: fakegalley `never` keeps sudo waiting; killing it withdraws the row.
- **Another user** (bob): the plugin is uninvolved, no 'G' is sent.
- **Remote**: make-usb's `printf pw | ssh vm "sudo -S -p '' tar …"` succeeds with fakegalley never answering and with the gate stopped. Detached `ssh vm 'setsid -f sh -c "sudo -S id"'` is gated.
- A broken `.so`, a wrong symbol or a wrong plugin type fails the `sudo.conf` derivation build.
- `/etc/pam.d/sudo` has the grant line before `pam_unix`.

### galley tests

- An unlisted uid on the services socket is reset; a client-sent `caller` is refused.
- Markup is off for services; each `level` renders its icon, and `danger` its banner.
- Service rows never join any other row; a thief with the same title does not join.
- A stale services socket file is replaced at start.
- The golden files round-trip.
- An entry shows `values[0]`; Enter in the sudo form presses Allow.
- A service row on a locked screen stays until answered or withdrawn.

## 12. Rollout

### M0.5: stock agent and TPM keys

nix-config only, before any frisket work ships.

1. On each host, with `sshSigner.enable = false`: dan in `tss`, home-manager `services.ssh-tpm-agent.enable`, gcr's ssh agent off. Switch, log out and in.
2. On each host: `ssh-tpm-keygen` (ECDSA P-256, defaults; press Enter at both passphrase prompts, since the signer has no PIN support). Commit `~/.ssh/id_ecdsa.pub` as `admins/<host>/ssh-tpm.pub`.
3. Authorize both pubs: nix-config's `authorizedKeys`, `server`, GitHub, and `mac` by hand. Remove the ed25519 key everywhere but the gateway.
4. Ship the host blocks and chase wiring (§10).
5. From each host, with no tty: `ssh -o BatchMode=yes <target> true` to the other host, `server`, GitHub and `mac`; `ssh gateway true` with ed25519; `ssh modem` with its password.

### M1: galley

galley items 1-8 merged and deployed; `services.galley.services` and the tmpfiles directory set.

### M2: signer

1. `sshSigner.enable = true` on one host and switch; dan leaves `tss`, and the signer starts with no keys. Then `sudo install -o ssh-signer -g ssh-signer -m 0600 ~/.ssh/id_ecdsa.tpm /var/lib/frisket-signer/` and `sudo systemctl restart frisket-signer`. Log out and in; `id` in a new tab shows no `tss`.
2. Check by hand: a tab's `ssh server true` is silent; Claude Code's `git push` is asked and a 15-minute grant holds; `systemd-run --user ssh server true` is asked with the warning; a chase session's push is silent.
3. Read the journal for a few days and tune in code. Then the other host.

### M3: sudo gate

Preconditions: `sudo-lockout` passes; `configurationLimit` is null or `>= 5` (§10).

1. `services.frisket.sudoGate.enable = true` on one host; `SUDO_ASKPASS` switches with it.
2. Check by hand: a first agent sudo shows one dialog and runs; the next asks without a password; a wrong password shows the dialog again; `sudo systemctl stop galley.service` shows danger.
3. Read the journal (dialogs, windows, questions per window) and tune. Then the other host.

### M4: stock agent removed

After M2 has settled on both hosts, delete the M0.5 branch from nix-config. The key files in `~/.ssh` stay; they are useless to dan outside `tss`.

### M5: recovery

- **TPM cleared, firmware update or new board**: `sudo systemctl start frisket-signer-keygen`, move the new key from `/var/lib/frisket-signer/new/` into place, commit the `.pub` and authorize it on GitHub, `server`, `mac` and the other host, using the other host's TPM key. If both hosts lost their keys, add the pubs at each remote's console. Re-enrol the Blade's disk unlock separately (`scripts/tpm-enroll.sh`).
- **DA lockout**: signing resumes when the counter decays (`LOCKOUT_INTERVAL` 7200 s). Lockout auth is set on both hosts, so `tpm2_dictionarylockout --clear-lockout` needs it.
- `installer/install.sh`'s closing text: TPM keys need keygen after a reinstall.

### Rollback

1. `sshSigner.enable = false`: back to the stock agent on the same key file (until M4; after M4, put the M0.5 branch back).
2. `services.frisket.sudoGate.enable = false`: the plugin line and PAM rule go; `SUDO_ASKPASS` goes back to `sudo-askpass.sh`.
3. sudo broken anyway: boot the previous generation from the boot menu at the console.

### Later tracks, not designed here

- **Remote sudo** through the forwarded agent and `pam_rssh`, asked in galley: after the signer's rollout (never with the stock agent, which signs forwarded requests silently), with the normal key; the question needn't show the remote command; starts with a small spike.
- **Allow-with-notice sudo class** (e.g. `nixos-rebuild switch`, run without a question but posted as a galley notice): parked; it would need a root-owned-PATH check.
- **A TPM-held age identity.**

## 13. Work breakdown

| Track | Repo | Deliverables | Depends on |
|---|---|---|---|
| T0 M0.5 | nix-config | §12 M0.5 | — |
| T1 galley | galley | Items 1-8 and their tests; item 1 first | — |
| T2 shared | frisket | `internal/peer`, `internal/galleyask`, `internal/grant`, `execrule.DecideWords`, `tests/fakegalley`, swtpm in `mkFrisket` | T1 item 1's pseudo-version |
| T3 signer | frisket | `internal/tpmkey`, `internal/agentsrv`, `cmd/frisket-signer`, `nixosModules.signer`, flong protect entries, `tests/signer.nix`, `docs/signer.md` (recovery) | T2 |
| T4 sudo | frisket | `sudo/*.c`, check-plugin, `internal/sudogate`, `cmd/frisket-sudo`, `sudo/danger.json`, `nixosModules.sudoGate`, `tests/sudo-gate.nix`, `docs/sudo.md` | T2 |
| T2b chase | chase | go.mod, `vendorHash` and flake.lock bump after T3 and T4 | T3, T4 |
| T5 nix-config | nix-config | `sshSigner`, gate enable, `SUDO_ASKPASS` switch, galley services, `configurationLimit`, `checks.sudo-lockout` | T1 merged, T2b |

T3 and T4 run in parallel once T2 merges. Cross-repo contracts, frozen when their track merges:

- galley `wire/` and its golden files, including `level`, the entry initial value and the three item shapes;
- `GALLEY_SERVICES_SOCKET`, `GALLEY_SERVICES`, `services.galley.services`;
- socket paths: `/run/frisket-signer/agent`, `/run/frisket-sudo/gate.sock`, `/run/frisket-sudo-askpass/askpass.sock`, `/run/galley-ask/<user>.sock`;
- the sudo wire (kinds, tags, replies) between the C and the gate;
- uids 951 and 952;
- module options in §10.

## 14. Not doing

- **Exe paths or a known store-path set**: they need `CAP_SYS_PTRACE` and were forgeable with `nix-store --add` [spike: store-name-attack]; comm plus structure is at the stock floor.
- **Question-as-authentication for sudo outside a window**: a galley Allow can come from dan-uid code with nobody there; the dialog's password needs a person.
- **A prefix check on `command=`**: `/run/current-system/sw/bin/../../../home/…/cat` ran as root [spike: evidence-audit].
- **An env denylist**: `LESSOPEN` ran code as root [spike: policy-fit]; variables are shown instead.
- **Fail-open when the gate is unreachable**: a crash loop with a fresh ticket was silent root [spike: sudo-vm, ops-socket-limit].
- **A Python sudo plugin**: not built into nixpkgs sudo, and there is a no-Python rule.

## 15. Open, untested, try later

UNTESTED, each with the test that settles it:

- **Claude Code's Bash timeout kills the whole process tree**, so sudo and ssh hang up and their rows are withdrawn. A quick check before building: a Bash call running `sudo -A sleep 600` with a short timeout, then `pgrep sudo`. If sudo survives, a timed-out command keeps its row until answered.
- **The comm of frisket's main process** is `frisket`: record it in the signer VM stand-in.
- **The tab shape on dan-blade** (H2 was recorded on dan-desktop): record one chain before M2 there.
- **comm of `sshd-session`** links is `sshd-session` on OpenSSH 10.5 (only exe and cmdline were recorded): the sudo VM remote subtest.
- **The cgroup move from `user@` into `frisket.service`** is refused: signer VM.
- **SSHSIG parsing** on real `ssh-keygen -Y sign` output: unit test.
- **The signer's hardening set as a whole**, with the real binary and the TPM: signer VM.
- **Connecting to the signer socket from frisket.service's read-only mounts**: signer VM stand-in.
- **galley `entry` initial text**: galley e2e.
- **The environment sudo passes after `env_reset`**: record it once in the sudo VM and write it into `docs/sudo.md`.
- **galley's peer check under the signer's and gate's hardening** (cgroup inode stat worked under the same flags for `frisket.service` [spike: identity-vm]): both VM tests.

Try later, after reading the journal:

- Make forwarded, unbound or SSHSIG requests silent or refused.
- A terminal grant offer on unknown host keys versus a silent sign.
- Retry niceties in the sudo dialog (keep the previous time; "that password was not accepted").
- More danger patterns.
- Splitting `execrule` so the gate binary drops `policy` and `internal/dns` (~0.7 MB).
- A cap on queued service rows, if flooding shows up.

## 16. Evidence index

Spike directories are under `~/spike-tools/`. Where a spike has a `-sceptic` twin, the sceptic's verdict wins.

| Spike | Showed | Path |
|---|---|---|
| g0 | PTT on both hosts; transient H-2 parent works; ~225 ms per sign fresh, ~43 ms cached; DA settings; persistent handles; `ptrace_scope` 1 | `g0/out-dan-*.txt` |
| tpm-keys | Pure-Go P-256 TPM keys; H-2 parent deterministic; cleared TPM → `TPM_RC_INTEGRITY`; interop with stock agent | `rev2-spikes/spikes/tpm-keys{,-sceptic}/` |
| tpm-da-lockout | DA-on keys fail with `TPM_RC_LOCKOUT` in lockout | `rev2-spikes/spikes/tpm-da-{lockout,rerun}/` |
| session-bind | OpenSSH binds before signing; binds verify; forwarding visible; `LoginGraceTime` | `rev2-spikes/spikes/session-bind/` |
| identity-vm | uncapped readers get stat, status, cmdline, cgroup but not exe; pidfd mask recipe; cgroup inode stat under hardening; `linuxtpm` polling | `rev2-spikes/spikes/identity-vm{,-sceptic}/` |
| sudo-vm | `tty=` and `open()` returns; messages; ticket written on refusal; no-tty askpass needs `DISPLAY`; pam_exec codes | `rev2-spikes/spikes/sudo-vm{,-sceptic}/` |
| ops-socket-limit | the default start limit stops the socket after 5 failed starts, and connects are then refused | `rev2-spikes/spikes/ops-socket-limit/` |
| sudo-plugin | setuid sudo cannot be ptraced | `rev2-spikes/spikes/sudo-plugin/` |
| policy-fit, evidence-audit | resolved-command trust, dotdot path, `LESSOPEN`, no re-quoting | `rev2-spikes/spikes/{policy-fit,policy-fit-sceptic,evidence-audit}/` |
| store-name-attack | `nix-store --add` forges store names | `rev2-spikes/spikes/store-name-attack/` |
| galley-socket | answers go only to the asker; password rows leak to joiners without no-join; real gjs self-binding | `rev2-spikes/spikes/galley-socket{,-sceptic}/` |
| G-P1 | activation hides the peer; self-bound peer is galley's MainPID; cgroup migration passes the binder check; `pidfd_getfd` needs `ptrace_scope` 0 | `t0-2026-10-08/spikes/G-P1{,-sceptic}/` |
| AP1 | askpass ppid is the 'S' sudo when `SUDO_ASKPASS` execs; parent euid 0 via `pidfd_open`; PAM per try; tty `-A` stops at `PAM_TTY` | `t0-2026-10-08/spikes/AP1{,-sceptic}/` |
| R1 | OpenSSH 10.5 privsep chain; 'S' agrees; detached remote sudo loses ancestry | `t0-2026-10-08/spikes/R1{,-sceptic}/` |
| SV1 | wrong plugin type segfaults sudo; ignored `sudo.conf` warns | `t0-2026-10-08/spikes/SV1{,-sceptic}/` |
| X1 | the lockout check recurses if it imports host modules | `t0-2026-10-08/spikes/X1{,-sceptic}/` |
| host-facts-desktop | H2, H3 on dan-desktop | `t0-2026-10-08/spikes/host-facts-desktop{,-sceptic}/` |
| crosscheck | gjs peer credentials; `StartLimitIntervalSec=0` keeps the socket up, and connects then get no answer | `crosscheck/galley/`, `crosscheck/verify-startlimit0/`, `crosscheck.md` |
| flong probe | containers see none of these sockets, no setuid sudo, NNP; trusted tier writes host `~/.claude` | `simplify-synthesis.md` §4 |
