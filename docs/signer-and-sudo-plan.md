# frisket-signer and frisket-sudo: plan

Two small gatekeepers beside frisket, both asking the person through galley:

- **frisket-signer** holds the SSH keys that live in the TPM. It signs silently for frisket, for a terminal tab ssh-ing to a known host and for git's commit signatures, and asks for everything else.
- **frisket-sudo** gates sudo when no terminal is asking. Each such sudo is one galley dialog showing the resolved command. Outside a window the dialog takes the password, which then opens a window, for a time the person picks and for that claude only, in which every command is still shown and asked, without the password.

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
                                    #   [Refuse] [Allow]   (inside the window; never opens one)
```

The work, done together:

- **frisket-signer**, replacing the stock `ssh-tpm-agent` that ships first (M0.5).
- **frisket-sudo**: a Zig audit plugin, a Zig PAM helper and a Go gate daemon.
- **Shared packages** in frisket.
- **A services socket in galley**, with a `level` field and prefilled field text.
- **NixOS wiring**: frisket owns the modules, nix-config sets them.

## 0. Goals and the floor

Goals:

1. SSH keys live in the TPM (ECDSA P-256 only). A key works only on its own chip, and only `ssh-signer` can open the TPM.
2. Every signature is journaled with its requester and destination, verified wherever ssh binds the session.
3. One question per new situation: Allow once, Allow for a time the person picks, or Refuse.
4. No-tty sudo: the person types the password once per claude per window, and still sees every command.
5. Terminal sudo and attached remote `sudo -S` behave as today.
6. No Python. Neither daemon runs as root or as dan.

**The floor.** Nothing here is ever looser than stock `ssh-tpm-agent` or default sudo. Where flong already stops an attack, these programs do not repeat the defence. Defending against code that already runs as dan on the host is a non-goal (see §2).

**Rules for the code.** No timeouts or deadlines anywhere in our code (signer, gate, plugin, PAM helper, galley). A request is open until it is answered or its requester goes away; the caller owns the timer (sshd's `LoginGraceTime`, Claude Code's Bash timeout, a person's Ctrl-C). A duration the person picks (Allow for 15 minutes) is not a timeout.

**Approach.** Build it, use it, read the journal, tune. New silent or refuse cases are a code change made after reading the journal.

## 1. Host facts

Measured on both hosts (dan-blade, dan-desktop) unless marked; a file source is a code read.

| # | Fact | Source |
|---|---|---|
| H1 | Both TPMs are Intel PTT (ADL, fw 0x2580012). A transient H-2 ECC primary works. Sign takes ~225 ms with a fresh parent and ~43 ms with parent and key kept loaded. `MAX_AUTH_FAIL` 32, `LOCKOUT_INTERVAL` 7200 s, `lockoutAuthSet` 1. Persistent handles 0x81000001/2/9 and 0x81010001 exist; dan-blade's LUKS tokens are sealed under 0x81000001 | [spike: g0] |
| H2 | dan-desktop. A gnome-console tab: `.kgx-wrapped --gapplication-service` (parent `systemd --user`) → `bash` (cmdline exactly `/run/current-system/sw/bin/bash`, pid = pgrp = sid, pts `tty_nr`) → `.claude-unwrapp` (comm, 15 chars) | [spike: host-facts-desktop] |
| H3 | dan-desktop. Each command from Claude Code's Bash tool runs in its own session with no tty (`tty_nr` 0; `/dev/tty` gives ENXIO), stdin `/dev/null` | [spike: host-facts-desktop, one-hop-sudo] |
| H4 | Claude Code: `permissions.defaultMode = "auto"`, `permissions.allow = [ "Bash(sudo:*)" ]`, `SUDO_ASKPASS` (`sudo-askpass.sh`) set in its env, and its commands inherit `DISPLAY=:0`. With both set, sudo runs the askpass itself whenever pam_unix needs a password and there is no tty. No-tty sudo through the gate needs neither | `home/dan.nix:612`, `:636`, `:646`; sudo `src/tgetpass.c:136-145`; [spike: one-hop-sudo Q1a] |
| H5 | ssh hosts: `modem` (password, needs `ssh-rsa`), `gateway` (OpenWrt dropbear; cannot take a P-256 key), `server`, `mac` (hand-managed `authorized_keys`), GitHub | `home/dan.nix:845-878` |
| H6 | galley wire: one JSON object per line, `Hello{galley,item}`, `Item{kind,title,text,markup,icon,buttons,default,forms}`, `Answer{answer,index,fields,error}`. An `extra` button answers its index and no field values. Enter presses the item's `default`, in forms too. A form `Field` has no initial text | `galley/internal/wire`, `daemon/window.js` |
| H7 | sudo calls an audit plugin's `open()` before PAM, PAM before the policy's accept, and the audit plugin's `accept()` on that accept; an `accept()` returning other than 1 refuses the command. PAM's `PAM_TTY` and sudo's `tty_nr` always agree and follow the controlling tty, not stdin | sudo `src/sudo.c:233`, `:1782-1792`; [spike: one-hop-sudo Q1, Q2, V1-V3] |
| H8 | `kernel.yama.ptrace_scope` is 1 on both hosts | [spike: g0] |
| H9 | nix-config has no flake `checks` output yet. dan-blade boots lanzaboote, dan-desktop plain systemd-boot; neither sets `configurationLimit` (null, unlimited) | `hosts/dan-blade/secure-boot.nix`, `modules/common.nix:19` |
| H10 | The host's sudo auth stack is `pam_unix` then `pam_deny` | `/etc/pam.d/sudo`; [spike: one-hop-sudo noninteractive] |

## 2. Threat model

| Actor | Runs as | Reaches | In scope |
|---|---|---|---|
| A. Agent in a chase/flong container | dan's uid in a user namespace | No signer, galley or sudo sockets (flong `protect` list), no user bus, no setuid sudo (NNP set, `/run/wrappers` absent). Can write the checkout, and in the trusted tier the host's `~/.claude`, `~/.codex` and cc-socks | **Yes.** Kept out by flong, not by prompts |
| B. Host agent a prompt injection can steer (host Claude Code, auto mode, `Bash(sudo:*)`) | dan, no tty | Everything dan reaches | **Partly.** An attention boundary while B acts through ssh, git and sudo. A B that persists code (user units, rc files, a devShell) has become C |
| C. Code running as dan on the host | dan | Everything dan reaches, including joining `galley.service`'s cgroup | **No.** It cannot reach the TPM, root's cgroups or sudo internals; the journals record what it asked for |
| D. Root, kernel, firmware | root | Everything | No. Root peers are refused, not defended against |
| E. Remote host or network position | — | The agent protocol through a forwarded socket | **Yes**: session-bind is verified, forwarding is shown and always asked |

**Accepted limits.** Each is at the stock floor or is stopped by flong.

- C can answer galley. Any dan process inside `user@1000.service` can write its pid into `app.slice/galley.service/cgroup.procs`, rebind `/run/galley-ask/dan.sock` and pass the services' binder check [spike: G-P1]. The check is a bar-raiser against a plain socket rebind. Stock agent: signs silently; stock sudo: any program can draw a password box.
- Forged terminal chains. Links are identified by comm and kernel structure, so a host process can build a chain shaped like a tab (bash copied as `.kgx-wrapped` under `systemd-run --user --pty`) and get a silent sign to a known host. Stock signs silently. A preloaded or memfd-loaded program is shown by its name.
- A process that opens its own pty (`script -qec 'sudo …'`) is a terminal to sudo, so it gets stock sudo prompting on that pty [spike: one-hop-sudo A8].
- A checkout's devShell is code from whoever wrote the checkout; entering it in a host tab runs it as dan.
- A trusted-tier session can write the host's `~/.claude`, `~/.codex` and cc-socks and so reach host sessions. Accepted: the end state is that nothing runs with host access.
- Remote sudo (`ssh host 'sudo -S …'`) takes the stock exit before PAM [spike: one-hop-sudo S3 (approval variant), N4b]. Detached remote sudo (`ssh host 'setsid -f sh -c "sudo -S …"'`) loses its ssh ancestry [spike: R1], so it is gated locally: asked on the desktop, its `-S` password ignored, or refused with nobody to ask.
- A git signature through a forwarder that sends no session-bind (OpenSSH before 8.9, an x/crypto tool) looks like a local `ssh-keygen -Y sign` and is silent. Only an unsandboxed dan process can run one; flong hides the socket. Stock signs silently.
- An ssh blocked on the agent after the server's `LoginGraceTime` keeps its row until its launcher kills it.
- A process that frisket.service starts (the asker, a hook) can double-fork to ppid 1 and name itself `frisket`, and then signs silently as frisket's main process. Stock signs for any dan process.
- During M0.5, dan is in `tss`: dan-uid code can sign with the key and drive DA lockout. That is stock `ssh-tpm-agent`.

**What makes the sudo window hold.** The window is pinned to the galley process that took the password. An Allow is counted only from that process, so C's rebound socket does not count inside a window. The pin assumes C cannot steal galley's listener fd: `pidfd_getfd` works at `ptrace_scope` 0 and is EPERM at 1 [spike: G-P1]. An assertion keeps `ptrace_scope >= 1`. It also assumes no dan process can press Allow inside galley: galley answers only from its own buttons (no answer GAction) and runs with `GTK_A11Y=none` (its default); turning on galley's accessibility option opens the window to any dan process.

**What C cannot do:**

- Open `/dev/tpmrm0`: only `ssh-signer` is in `tss` once the signer is enabled (assertion) [spike: identity-vm].
- Move into `system.slice/frisket.service`: `cgroup.procs` is root 0644. UNTESTED from inside `user@1000.service`; the signer VM test tries it.
- Be frisket's main process: that needs ppid 1 in frisket's cgroup. A process frisket starts could get there by double-forking (an accepted limit above).
- Write `/run/frisket-signer`, `/run/frisket-sudo` or `/etc`.
- Reach the dialog's password: it goes from galley to the gate and over a root-only socket into setuid sudo, which cannot be ptraced [spike: sudo-plugin]; galley cannot be ptraced at `ptrace_scope` 1 [spike: G-P1].

### Trusted computing base

| Component | Runs as | Privilege | Trusted for |
|---|---|---|---|
| frisket-signer | `ssh-signer` (951) | `/dev/tpmrm0` via `tss`; no capabilities | The only TPM access; verifying session-bind |
| frisket-sudo gate | `sudo-gate` (952) | none | Deciding sudo; holding check-ins, each claude's password window and its galley pin; passing the dialog's password to the plugin |
| `frisket_sudo.so`, `frisket-sudo-pam` | root inside setuid sudo / pam_exec | sudo's | Deciding before PAM whether to gate; collecting the chain as root; verifying the password |
| galley window | dan | none | The only source of answers; the pinned process for a window |
| frisket main process | dan, system unit `frisket.service` | none | Signing silently for chase sessions |

## 3. What a day looks like

| Moment | Today | Target |
|---|---|---|
| `ssh`/`git` typed in a tab to a host in `/etc/ssh/ssh_known_hosts` | 0 | 0 (`terminal = "allow"`) |
| Same, to a host key not in `ssh_known_hosts` | 0 | 1 question; a grant covers that tab's shell |
| `bash deploy.sh` in a tab, ssh-ing inside | 0 | 1 question; a grant covers that tab's shell |
| `kgx -- ssh host`, `systemd-run --user ssh …`, a re-parented `ssh -f` | 0 | 1 question, warning icon, Allow once only |
| frisket logging in for a chase session | 0 | 0, even with galley closed |
| Host Claude Code, first `git push` of a session | 0 | 1 question; Allow for 15 minutes (prefilled) makes it 0 for that claude, host and key until the grant ends |
| `git commit -S` with an SSH signing key | — | 0 (`sshsig.git = "allow"`) |
| `ssh -A` and a sign on the far side | 0 | 1 question with the line "forwarded", also from a tab to a known host; its grant covers forwarded signs only |
| `sudo ssh …` reaching the signer as root | refused by gcr | refused, logged |
| `ssh gateway` | ed25519 via gcr | ed25519 file, authorized on the gateway only |
| `ssh modem` | password | unchanged |
| `printf pw \| ssh host "sudo -S …"` | password | unchanged |
| Host Claude Code, first sudo (`-n` too) | 1 password dialog (`-n`: fails) | 1 dialog: the command, the password and "remember for 15 minutes" |
| A wrong password in it | — | the dialog again |
| Further sudo inside the window | 1 password per Bash call | 1 question, no password |
| A danger command (§4.6) | 1 password | danger icon and banner; outside a window the dialog with the password and no time; inside, a question; never opens a window |
| Window ended, or galley restarted | — | the dialog again |
| A question while the screen is locked | — | it waits until unlock or until the requester gives up |
| sudo in a terminal | — | unchanged |
| Gate socket stopped | — | no-tty sudo says "gate not running" and fails as stock with no terminal; terminal sudo unchanged |

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
- **Anchor**: the nearest ancestor whose comm is not transient (`bash sh zsh fish dash env timeout nice nohup setsid script sudo ssh git`), keyed on `(pid, starttime)`. The walk stops at a tab's shell (rule 1 below), which is then the anchor: `bash deploy.sh` from a tab anchors on the tab's shell, not the terminal server. Host Claude Code resolves as `ssh ← git ← bash ← .claude-unwrapp`, so the anchor is the claude process, found before the tab's shell [H2]. A desktop app anchors on itself, or falls to SessionRoot and is asked.
- **Terminal**, all of:
  1. the link below the terminal server (comm `.kgx-wrapped`) is a shell (comm `bash`) whose cmdline is exactly its argv0 or `-bash`, which is a session leader with a pts `tty_nr`;
  2. the terminal server's parent is `systemd --user`;
  3. every link between the shell and the leaf has comm `ssh`, `git`, `scp`, `sftp` or `rsync`.

  For a Terminal chain the anchor is the tab's shell, so a grant is per tab. Agent commands fail rule 3: claude and its `bash` sit between the tab's shell and the leaf. `kgx -- ssh`, `kgx -- bash -c …` and `kgx -- git push` fail rule 1 and become SessionRoot.
- **Remote** (sudo only, tested in C): a link with comm `sshd-session` running as the user whose parent is a uid-0 `sshd-session` [spike: R1].
- **frisket's main process**: uid `forUser`, `cgroupid` == the inode of `/sys/fs/cgroup/system.slice/frisket.service` (stat'ed at every check), ppid 1, comm `frisket`. No exe check. Any other process in that cgroup (frisket-asker, an `ssh-add` from a hook) is a normal requester.

### 4.3 galley

- **A services socket** at `/run/galley-ask/<user>.sock`, 0666, in a `0755 dan` directory. galley binds it itself (unlink a stale file, bind, chmod, listen): under socket activation every client sees `systemd --user` as its peer [spike: G-P1]. So that the socket exists before a service asks, galley starts at login when `services.galley.services` is set. A services set-up failure is logged and the user's own socket keeps working.
- **Who may post**: only uids listed in `GALLEY_SERVICES`; others are reset. The window sets `item.caller` from `SO_PEERCRED` after validation (a client-sent `caller` fails validation) and shows the caller's label.
- **What galley owns**: markup is off for services; the icon comes from `level` (`normal`, `warning`, `danger`), drawn by galley, with galley's banner for `danger` (the service sends only a reason line); recording keeps its red. Service rows never join. Any form shape is allowed.
- **Who answered.** Before trusting an answer, a service checks its galley peer: uid `forUser`, and `cgroupid` == the inode of `…/user@<uid>.service/app.slice/galley.service`, stat'ed at every check (it changes on every galley start) [spike: G-P1, identity-vm]. Anything else is nobody to ask.
- **Time control**: an entry prefilled `15` (wire `Field.text`) and a `minutes|hours` combo; capped at 24 h (a constant). An absent or empty unit is minutes. 0 means once; an unreadable number is once, logged as "time not understood" without the text. Above 24 h is clamped. Grants and windows count from the answer.
- **Waiting rows follow a new grant or window.** When an answer makes a grant or opens a window, the service rechecks the rows it is still waiting on, so a request that arrived before the answer is treated as one arriving after it. Signer: a waiting row the new grant covers is signed and withdrawn. Sudo: a waiting non-danger dialog from the same claude is withdrawn and posted again as a plain question, still asked. Service rows never join: a typed password would reach every joiner, and one answer would approve a requester the row does not show.
- **No deadlines.** A row lives as long as the requester's connection to the service. The service closes its galley connection when the requester hangs up, which withdraws the row. A locked screen does nothing special: the row waits.

### 4.4 The signer decides in a fixed order

1. Peer uid is not `forUser` → refuse, logged.
2. Userauth on a connection with binds, whose session id is not the last bind's, or a hostbound request whose embedded host key is not the bound key → refuse. A connection with no binds goes on as unbound.
3. frisket's main process, userauth → sign.
4. Terminal chain, bound userauth, not forwarded, host key in `/etc/ssh/ssh_known_hosts` → `terminal`: `allow` signs, `ask` goes to step 6.
5. SSHSIG, not forwarded, namespace listed in `sshsig` → its value: `allow` signs, `ask` goes to step 6.
6. Userauth only: a live grant for `(anchor, host key, key, forwarded)`, chain not Cut or SessionRoot → sign.
7. Otherwise ask.

- **Forwarded** signs are never silent at steps 4 and 5. A grant made from a forwarded question has `Fwd` set and covers only forwarded signs; a direct grant never covers one. The hop host is not part of the key.
- **Allow once only**: unbound userauth, SSHSIG (an unlisted namespace, or one set to `ask`), Cut and SessionRoot.
- Forwarded, unknown host key, unbound and SSHSIG are text lines in the question.

### 4.5 sudo: one hop, one dialog

Stock sudoers stays the policy. frisket-sudo adds one audit plugin (`frisket_sudo.so`, one `sudo.conf` line), one PAM rule and the gate [spike: one-hop-sudo].

- **Before PAM**, the plugin's `open()` decides whether this sudo is gated: the invoking user is `forUser`, there is no tty, the chain is not remote (a detached remote sudo is local [spike: R1]), and the mode is not `-v` or `-l`. Only then does it check in with the gate, which records the sudo's `(pid, starttime)` for as long as that connection is open. Any other sudo is stock.
- **In PAM**, the helper (`auth sufficient`, before `pam_unix`) lets sudo skip the password only when its own sudo checked in.
- **On the policy's accept**, the plugin sends the resolved command to the gate, and the gate posts the one galley item for it:
  - **outside a window**: the dialog with the command, the requester, a password field and "remember the password for this claude for [15] [minutes]". The gate passes the password to the plugin, which verifies it itself with `pam_authenticate` on a `frisket-sudo` PAM service. A wrong password brings the dialog back, each try costing pam_unix's fail delay (~1.6 s) [spike: one-hop-sudo Q3a]. A verified password approves this command and opens the window for the chosen time (0 is once);
  - **inside a window**: a plain question, Allow or Refuse, no password.

  A refusal makes `accept()` return 0, and sudo refuses the command.
- **The window** is keyed on the claude anchor `(pid, starttime)` and pinned to the galley process that served the dialog (its pid from `SO_PEERPIDFD` on the gate's galley connection, and its starttime from `/proc/<pid>/stat`). It ends at the chosen time, when that galley process exits, or when the anchor exits. An Allow from any other galley process does not count.
- **The password is never kept.** The gate zeroes its copy once it has sent it in 'W', and the plugin zeroes its copy after `pam_authenticate`. A window is a time and a galley pin, and holds no password.
- **Only a verified dialog password opens a window.** A danger command never opens one, nor does a Cut or SessionRoot chain: their dialog has no time field.
- **Rules the module sets**, from the one `enable` option: `Defaults noninteractive_auth`, so an agent's no-tty `sudo -n` reaches the dialog [spike: one-hop-sudo N1a]; `Defaults timestamp_type=tty`, with any other `timestamp_type` refused, since under `global` a no-tty skip leaves the next terminal sudo passwordless [spike: one-hop-sudo Q4f, T8b]; `rootpw`, `targetpw` and `runaspw` refused [spike: one-hop-sudo A7]; `intercept` and `log_subcmds` refused, since each intercepted subcommand calls `accept()` again (sudo `src/exec_intercept.c:508`) and nix-config sets neither; and a build assertion that sudo's auth stack is exactly the helper, `pam_unix`, `pam_deny`, since under `noninteractive_auth` any other module would run on every terminal `sudo -n` [spike: one-hop-sudo noninteractive].
- **Accepted consequences**: with no tty, `-S` and any askpass are ignored, as the dialog's password is the one checked [spike: one-hop-sudo Q2d, Q2e, Q2g]; NOPASSWD commands still get the dialog [spike: one-hop-sudo T10]; a no-tty `sudo -v` or `-l` fails as stock (`-n`: "a password is required") [spike: one-hop-sudo N5]; a refusal adds sudo's line `sudo: frisket_audit: unable to log accept event: <reason>`; a terminal `sudo -n` without a ticket logs two extra `pam_unix` journal lines.
- **Who runs what**: the plugin and the PAM helper run as root inside sudo; the gate as `sudo-gate`.

### 4.6 Danger and warning

The gate classifies every command it is sent. A danger command gets the danger level (galley's icon and banner) and a reason line, is always asked, never opens a window, and needs the password only where any command would (outside a window).

- **Danger:**
  - a command matching the embedded catalogue: `systemctl` touching a guard unit `frisket*`, `galley*`, `sshd*`, `nftables*`, `debug-shell*` (`status` included);
  - a program outside the root-owned directories: `command_info["command"]` is not absolute and clean, or `filepath.Dir` of it is not exactly `/run/current-system/sw/bin`, `/run/wrappers/bin` or `/etc/profiles/per-user/<user>/bin` (for example nix-config's `make-usb` script, or `~/bin/systemctl` found first in PATH);
  - `sh`/`bash -c`, `-s`/`-i` and `env`: the gate unwraps them and passes the inner string to execrule's `Parse`; every simple command in it is classified, and anything execrule cannot read is danger.
- **Warning** (requester only): a Cut or SessionRoot chain.
- **Text lines**, no icon change: environment variables outside the allowlist (`HOME LOGNAME USER SHELL MAIL TERM TERMINFO TERMINFO_DIRS LANG LC_* PATH DISPLAY XAUTHORITY COLORTERM SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND SUDO_HOME`), shown with their values cut; for the signer, forwarded, unknown host key, unbound and SSHSIG namespace.

### 4.7 Failure

- **No-tty sudo fails closed** when the gate cannot be reached: the plugin prints "frisket-sudo: gate not running (systemctl status frisket-sudo.socket); sudo in a terminal is not gated", the helper finds no check-in, and `pam_unix` fails with no terminal [spike: one-hop-sudo Q5f, N3c]. A no-tty, local `forUser` sudo with no check-in is refused at `accept()`, whether `open()` gated it or a wrong mode parse left it ungated, so a same-parent sudoers ticket cannot carry it past PAM (decided, not measured; the sudo VM's Ticket case). Terminal and remote sudo never reach the gate, so this cannot lock anyone out. "Gate off" is `sudoGate.enable = false`, which leaves the plugin line out of `sudo.conf`.
- `open()` returns 1 on every path, its allocation and socket errors included: 0 would make sudo unlink the plugin, so nothing vetoes, and -1 is `sudo_fatalx` on every sudo, terminal sudo included (sudo `src/sudo.c:1658-1670`).
- **Nobody to ask** (galley not running, wrong galley peer): the signer signs at steps 3-6 as usual and refuses at step 7; the gate refuses with "no one to ask; use a terminal".
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
              │ question / answer, level                 │ dialog, questions
              │ (peer: uid dan + galley.service cgroup)  │ (window pinned to galley's pid)
  ┌───────────┴───────────────┐            ┌─────────────┴─────────────────────┐
  │ frisket-signer            │            │ frisket-sudo gate                 │
  │ ssh-signer (951), tss     │            │ sudo-gate (952), no capabilities  │
  │ /dev/tpmrm0               │            │ /run/frisket-sudo/gate.sock       │
  │ /var/lib/frisket-signer/  │            │   0600, root 0700 dir             │
  │   *.tpm                   │            └──────▲─────────────────▲──────────┘
  └───────────▲───────────────┘                   │ 'C' 'A' 'V'     │ 'G'
              │ agent protocol                    │ (uid 0)         │ (uid 0)
              │ /run/frisket-signer/agent  ┌──────┴─────────────────┴──────────┐
              │ (dan 0600)                 │ setuid sudo                       │
  ┌───────────┴──────┐  ┌───────────────┐  │  frisket_sudo.so (audit plugin)   │
  │ ssh, git, scp    │  │ frisket.svc   │  │  pam_exec frisket-sudo-pam        │
  └──────────────────┘  │ main process  │  │  pam_authenticate("frisket-sudo") │
                        └───────────────┘  └───────────────────────────────────┘
```

### An SSH login

```
ssh ──connect──▶ /run/frisket-signer/agent
   signer: SO_PEERCRED uid == dan?            (else refuse, log)
           SO_PEERPIDFD → PIDFD_GET_INFO → /proc chain by comm: Cut, SessionRoot, Terminal, anchor
ssh ──session-bind@openssh.com(hostkey, sid, sig, fwd)──▶ verify sig over sid; push bind
ssh ──REQUEST_IDENTITIES──▶ loaded keys
ssh ──SIGN_REQUEST──▶ parse: userauth? sid == last bind? embedded hostkey == bound key? (else refuse)
   decide (§4.4): frisket? terminal? sshsig? grant? → sign | ask
   ask: galley question; poll ssh's connection for POLLRDHUP; hang-up withdraws the row
   sign: cached parent + key on the long-lived fd → TPM2_Sign → reply
   journal: one record per decision
```

### An agent's sudo

```
open():    forUser, no tty, local, not -v/-l → connect gate.sock, 'C'      (else stock sudo)
PAM:       helper 'G' → gate: its parent sudo checked in → 'Y' (pam_unix skipped)
accept():  'A' resolved command →
  outside a window: dialog → 'W' password → pam_authenticate(frisket-sudo) → 'V'
                    ok → window opens → 'Y'     bad → dialog again
  inside a window:  question → Allow from the pinned galley → 'Y'
  refused:          'N' → accept() returns 0, sudo refuses
exit:      connection closes → check-in gone, any row withdrawn
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

A grantable question is a form with the time control; an Allow-once question (§4.4) is a plain question, with the warning level for Cut and SessionRoot.

```json
{"galley":3,"item":{"kind":"forms","level":"normal","title":"ssh to github.com",
  "text":"claude (pid 5113) ← bash ← git push ← ssh\nkey SHA256:… (dan@dan-blade)\nA grant covers github.com from this claude.",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow once","underline":-1},
             {"answer":"ok","label":"Allow for","underline":-1}],
  "default":2,
  "forms":{"fields":[{"kind":"entry","label":"Allow for","text":"15"},
                     {"kind":"combo","label":"","values":["minutes","hours"]}]}}}
```

```json
{"galley":3,"item":{"kind":"question","level":"warning","title":"ssh to server",
  "text":"launched through systemd --user\nsystemd --user ← ssh",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow once","underline":-1}],
  "default":1}}
```

| Answer line | Result |
|---|---|
| `{"answer":"extra","index":0}` | Allow once |
| `{"answer":"ok","fields":[{"text":N},{"text":U}]}` | Allow for N U (§4.3) |
| anything else, `cancel`, `close` | Refuse |
| an error, EOF | nobody to ask |

- Every question's default is its last button, an Allow, so Enter allows, danger included; galley never takes the focus by itself, so only a question dan has opened takes an Enter.
- Text is plain: control and bidi characters escaped, each argv cut at 1000 characters.
- While asking, the signer polls the ssh connection for `POLLRDHUP` and closes the galley connection on hang-up.

### Grants (`internal/grant`, signer only)

- `Key{Anchor{Pid, Start}, Host, KeyFP, Fwd}`; `Grant(k, until)`; `Use(k) bool`.
- `until` = answer time + chosen, in `CLOCK_BOOTTIME`, so suspend counts against it. Use never extends it. A second grant for the same key keeps the later end.
- A dead anchor's grant never matches again: a reused pid has another starttime. `Grant` drops expired entries; nothing reads `/proc`.
- In memory only. A restart costs at most one question per active anchor.
- A new grant is checked against every waiting row; each it covers is signed and its row withdrawn.

### Journal

One structured record per decision: requester chain, anchor, destination, key, class, forwarded, text lines, outcome, its source (frisket, terminal, sshsig, grant, galley answer, nobody), the chosen time, and the galley peer's pid and cgroup.

## 7. frisket-sudo

### Pieces

- `sudo/frisket_sudo.zig` (the audit plugin, exported symbol `frisket_audit`), `sudo/frisket-sudo-pam.zig`, shared `sudo/chain.zig` (chain walk, remote test) and `sudo/wire.zig`. The Zig decides whether to gate, collects, frames and verifies the password; everything else is in Go. sudo loads a plugin into a setuid process, which rules out Go's runtime; Zig has none.
- **Zig as flong uses it**: 0.15.2 from nixpkgs' `zig_0_15`, built ReleaseSafe, with flong's toolkit: descriptors only through generation-checked handles (flong `src/fd.zig`, whether imported or copied decided when built), zwanzig's open models for a double close or use after close, minish property tests, and fdlint's rules (`extern`/`@cImport` of `sudo_plugin.h` and `pam_appl.h` in one ABI file, no `catch unreachable` without `// proven:`, no general-purpose allocator). Unlike flong it runs inside sudo, a libc process with libpam, so it uses libc, and the leak property is that every descriptor it opens is closed by `close()` or exit.
- **No panic on the ungated path**: a ReleaseSafe panic in `open()` aborts every sudo, terminal sudo included. `open()` touches no handle until it has decided to gate, and returns errors rather than panicking.
- `sudo/frisket-sudo-check-plugin.zig` (build time only): `dlopen(RTLD_NOW)`, `dlsym`, then checks plugin type 3 (audit), the API major and the sudo version. A wrong type makes every sudo segfault [spike: SV1], so this check is mandatory.
- `cmd/frisket-sudo serve`: fd `gate` from `sdnotify.Listen()`; refuses to start without it.
- `sudo/danger.json`, embedded with `go:embed`, checked by a unit test.

### When it is involved

| Situation | `open()` | PAM helper | `accept()` | Result |
|---|---|---|---|---|
| Invoking user is not `forUser` | not gated | exits 1 | passes | Stock sudo [spike: one-hop-sudo S2, approval variant] |
| tty present | not gated | exits 1 | passes | Stock sudo |
| Remote chain (`ssh host "sudo -S …"`) | not gated | exits 1 | passes | Stock sudo [spike: one-hop-sudo S3, approval variant; N4b] |
| Detached remote (`setsid -f`) | checks in | exits 0 | asks the gate | Gated locally (§2) [spike: R1] |
| `-v`, `-l` (any spelling) | not gated | exits 1 | — | Stock; fails with no tty [spike: one-hop-sudo S4, N5] |
| Local, no tty (`-n`, `-S`, `-A`, `-k cmd` alike) | checks in | exits 0 | asks the gate | §4.5 |
| Same, a sudoers ticket from the same parent | checks in | not run | asks the gate | The ticket gives nothing [spike: one-hop-sudo Q4a, Q4d] |
| Same, NOPASSWD | checks in | not run | asks the gate | The dialog [spike: one-hop-sudo T10] |
| Same, gate unreachable | prints "gate not running" | exits 1 | refuses | pam_unix fails with no terminal |

### Wire, version 1

```
request := "FSUD" | u8 version=1 | u8 kind | u32be length | body
kind     : 'C' check-in (plugin open())       'G' did my sudo check in (PAM helper)
           'A' approval (plugin accept())     'V' verify result (plugin, after a 'W' reply)
body     := record*        record := u8 tag | u32be len | bytes[len]
'k'  chain link: u32be pid | u32be ppid | u64be starttime | u32be uid | u32be tty_nr
                 | u16be len comm | u16be len cmdline (NUL-separated, ≤ 4096)   A
'u' user_info  's' settings  'c' command_info  'a' run_argv  'e' run_envp       A
'r'  u8: 1 the password verified, 0 not                                          V
't'  truncated marker
'C', 'G': body empty; the sudo is the peer ('C') or the peer's kernel ppid ('G'), never a field
limits   : ≤ 1 MiB (truncate run_envp, then cmdline); ≤ 16 links;
           every record length checked against the remaining body before allocating
reply    := u8 'Y' | u16be len | message      messages: ≤ 512 printable ASCII
          | u8 'N' | u16be len | message
          | u8 'W' | u16be len | password     to 'A' or 'V' only; raw bytes, ≤ 1023
```

- `gate.sock` takes requests from peer uid 0 only.
- A 'G' is one request and one reply on its own connection.
- 'C' opens the plugin's connection, which stays open until `close()` or sudo's exit; the check-in lasts as long. 'C' → 'Y'; then 'A' → 'Y', 'N' or 'W'; after 'W', 'V' → 'Y', 'N' or 'W'. An 'A' or 'V' anywhere else gets 'N'.
- The first 'k' link is sudo's parent. Each link reads `stat` before and after `cmdline`; a starttime change cuts the chain there.

### Plugin

`open()`, always returning 1:

- Gated when all hold: `user_info` user is the `user=` option, no `tty=` [spike: sudo-vm], the chain is not remote, and the mode is not `-v` or `-l` [spike: one-hop-sudo S4]. The mode is read from the arguments before `submit_optind` as sudo's `getopt_long` reads them: sudo's short-option string (`src/parse_args.c:115`) so an option's argument (`-gwheel`, `-u lp`) is skipped, a stop at `--`, and any unambiguous prefix of `--validate` or `--list` (`--li`). A missing `user=` leaves every sudo ungated. The mode test is the only part read from arguments, so `accept()` repeats the rest (below): a wrong parse can then only refuse, never run a command unasked.
- Gated: connect `/run/frisket-sudo/gate.sock` (compiled in, `SOCK_CLOEXEC`), check the peer is `sudo-gate`'s uid, send 'C', read 'Y'. Any failure prints the "gate not running" line with `sudo_plugin_printf(SUDO_CONV_ERROR_MSG)`.

`accept()`, for the policy plugin's accept:

1. The gating test without the mode: `user_info` user is the `user=` option, no `tty=`, the chain is not remote. Not all hold → return 1. All hold and no check-in → errstr "gate not running", return 0. `-v` and `-l` never reach `accept()`, so this refuses only a sudo the gate is down for, or one a wrong mode parse left ungated, which a same-parent ticket or NOPASSWD rule would otherwise run unasked.
2. Collect the chain and send 'A' with the run info. Wait, with no timeout of its own.
3. 'Y' → print a non-empty message with `SUDO_CONV_INFO_MSG`, return 1. 'N' → print the message with `SUDO_CONV_ERROR_MSG`, return 0. EOF or garbage → "no answer from gate", return 0.
4. 'W' → `pam_start("frisket-sudo", user)`, `pam_authenticate(PAM_SILENT)` and `pam_acct_mgmt`, with a conversation that answers every prompt with the password; zero the buffer; send 'V' with the result and go to 3 [spike: one-hop-sudo Q3, V1, V2].

`close()` closes the connection.

### PAM helper

`auth sufficient pam_exec.so seteuid quiet <helper> <user>`, ordered before `pam_unix` [spike: sudo-vm].

1. `PAM_TTY` set → exit 1.
2. `PAM_SERVICE != sudo` or `PAM_USER != <user>` → exit 1.
3. Connect `gate.sock`, check the peer is `sudo-gate`'s uid, send 'G'. 'Y' → exit 0. Anything else → exit 1, and pam_unix runs.

### The gate on 'C' and 'G'

- **'C'**: `SO_PEERCRED` uid 0. Record the peer's `(pid, starttime)` from `SO_PEERPIDFD` (mask checked) and `/proc/<pid>/stat`. Reply 'Y'. The check-in lasts until the connection closes; then any row it posted is withdrawn.
- **'G'**: `SO_PEERCRED` uid 0, and the peer's parent, its kernel ppid from `PIDFD_GET_INFO` and that pid's starttime, is a live check-in's `(pid, starttime)` → 'Y'. Otherwise 'N'. A child of sudo running as another user is refused here [spike: one-hop-sudo Q6k].

### The gate on 'A'

1. Classify (§4.6). Words are `[basename(program)] + run_argv[1:]`; for `-s`/`-i` sudo's backslash escaping is undone first.
2. **Inside a window** (the anchor has one, now < its end, its pinned galley process is alive, and the chain is not Cut or SessionRoot): ask the question (below). An Allow counts only if the galley peer is the pinned process; any other answer is a refusal → 'N'. Allow → 'Y'.
3. **Otherwise** post the dialog (below). Cancel or close → 'N' "cancelled". An empty password, or one with a NUL or newline → the dialog again. Allow with a non-empty password → 'W' and the password; keep the answer's time and galley peer `(pid, starttime)`.
4. Nobody to ask → 'N' "no one to ask; use a terminal".

While asking, the gate polls the plugin's connection for `POLLRDHUP` and withdraws the row on hang-up.

### The gate on 'V'

- **1**: if the chosen time is above 0, the command is not danger and the chain is not Cut or SessionRoot, open the window: until = answer time + chosen (boottime, at most 24 h), pinned to the dialog's galley process. Reply 'Y' "frisket-sudo: password remembered for this claude until 16:40", or 'Y' with no message when no window opened. A new window turns the claude's other waiting non-danger dialogs into plain questions (withdraw, post again).
- **0**: post the dialog again with the line "wrong password", as on 'A' step 3.

The dialog:

```json
{"galley":3,"item":{"kind":"forms","level":"normal","title":"sudo systemctl restart foo",
  "text":"claude (pid 5113) ← bash\n\n/run/current-system/sw/bin/systemctl restart foo",
  "buttons":[{"answer":"cancel","label":"Cancel","underline":-1},
             {"answer":"ok","label":"Allow","underline":-1}],
  "default":1,
  "forms":{"fields":[{"kind":"password","label":"Password for dan"},
                     {"kind":"entry","label":"Remember the password for this claude for","text":"15"},
                     {"kind":"combo","label":"","values":["minutes","hours"]}]}}}
```

- `default` is Allow, so Enter after the password allows with the prefilled time.
- A danger dialog has the danger level, its reason first in the text, and the password field only. A Cut or SessionRoot dialog has the warning level and the password field only.
- The password is never logged; the journal records "<n> bytes".

The question:

```json
{"galley":3,"item":{"kind":"question","level":"danger","title":"sudo systemctl stop sshd.service",
  "text":"touches a unit that guards this machine\n\nclaude (pid 5113) ← bash\n/run/current-system/sw/bin/systemctl stop sshd.service",
  "buttons":[{"answer":"cancel","label":"Refuse","underline":-1},
             {"answer":"extra","index":0,"label":"Allow","underline":-1}],
  "default":1}}
```

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
| `sudo.conf` group-writable or not root's | Every sudo prints "/etc/sudo.conf is group writable"; no check-in, so no-tty sudo fails as stock | The store symlink is root 0444 [spike: SV1, one-hop-sudo Q5d, Q5e] |
| `sudo.conf` empty or ignored | Stock sudo | No check-in, the helper exits 1 [spike: one-hop-sudo Q5b, N3a] |
| Gate socket stopped or absent | No-tty sudo says "gate not running" and fails as stock; terminal and remote sudo unaffected | Terminal sudo never reaches the gate [spike: one-hop-sudo Q5f, N3c] |
| Gate service crash-looping | The socket stays up and connects succeed with no answer, so no-tty sudo waits until its caller gives up; terminal and remote sudo unaffected | `StartLimitIntervalSec=0` keeps the socket up [spike: crosscheck]; no lockout |
| Gate hangs | sudo waits until its caller gives up | The caller owns the timer |
| galley not running | 'N' "no one to ask; use a terminal" | Terminal sudo unaffected |
| sudo killed while its dialog or question is up | The gate sees the connection close and withdraws the row | No late rows |
| Gate restarts | Check-ins and windows are lost; open sudos get no answer and fail; the next sudo gets the dialog | In memory only |

## 8. Shared packages (frisket repo)

```go
// internal/peer: moved from internal/serve/peer.go and extended.
type Link struct {
    Pid, PPid, Sid int; TTY uint32; Start uint64; UID int
    Comm string; Cmdline []string; Cgroup string
}
type Requester struct {
    Chain []Link; Anchor *Link
    Cut, SessionRoot, Terminal bool
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
    Galley struct{ Pid int; Start uint64; Cgroup string }
}
var ErrNobody = errors.New("no one to ask")
func Ask(ctx context.Context, user string, q Question) (Answer, error)
```

- `internal/peer`'s transient set and depth are constants.
- `galleyask.Ask` dials `/run/galley-ask/<user>.sock`, checks the peer (§4.3), posts the item, and closes the connection when `ctx` is cancelled; the caller cancels it on `POLLRDHUP`. It speaks `github.com/danielbodart/galley/wire`.
- `internal/grant` belongs to the signer (§6). Check-ins and the sudo window are records in `internal/sudogate`.
- `execrule` gains `DecideWords(words []string) Decision` beside `Decide`, sharing its Decision builder, so the gate never re-quotes argv into a shell string [spike: policy-fit].
- New module dependencies: `github.com/google/go-tpm`, `github.com/foxboron/go-tpm-keyfiles`, and `github.com/danielbodart/galley` at a pseudo-version with a public `wire/`.

### `tests/fakegalley`

A Go program built from the pinned `galley/wire`, run in the VM tests as the user unit `galley.service`, so the binder check passes for the right reason.

```
fakegalley -socket PATH -script FILE [-log FILE]
```

Script actions, one per question, the last line repeating: `ok <field>…` (answers the fields in order), `cancel`, `answer N` (extra N), `never`. `-log` writes one JSON line per question received (title, text, kind, level, buttons, fields, peer uid and pid) and per answer sent; a password is logged as its length.

## 9. galley changes

1. Move `internal/wire` to a public `wire/` package with golden files: the signer form, the plain question, the sudo dialog, every `level`, and the answer lines. Wire version 3 adds `level`, `Field.text` and the window-set `caller`. **This merges first.**
2. `server.js` keeps the user listener from systemd and binds `GALLEY_SERVICES_SOCKET` itself (unlink, bind, chmod 0666, listen), so a client's peer is galley's own process. Shown with real gjs [spike: galley-socket]. A services set-up failure is logged and the user's socket keeps working.
3. The services listener admits only `GALLEY_SERVICES` uids (names from `/etc/passwd` at start); others are reset. gjs reads the peer uid and pid from `Gio.Credentials` [spike: crosscheck/galley].
4. `item.caller = {uid, name, label, pid}` is set after `validate()`; a client-sent `caller` fails validation.
5. Service items: markup forced off; `level` (`normal`, `warning`, `danger`; absent is `normal`) chooses galley's icon, and `danger` adds galley's banner. No shape allowlist.
6. Service rows never join, and a service's notification row goes when its connection closes.
7. Prefilled text: wire `Field.text` is an entry or multiline field's initial text, and fails validation on a password field. The CLI gains `--value TEXT` in the forms option group, setting it on the preceding `--add-entry` or `--add-multiline-entry`; `--scale`'s integer `--value` is unchanged: both mean the starting value, typed by the dialog.
8. Home-manager: `services.galley.services` (user name → label, as `GALLEY_SERVICES` JSON); when it is non-empty, the unit sets `GALLEY_SERVICES` and `GALLEY_SERVICES_SOCKET` and galley starts with the graphical session.

## 10. NixOS wiring

frisket owns `nixosModules.signer` and `nixosModules.sudoGate`, each added to frisket's double-import eval check and imported by its VM test. nix-config sets options and owns host wiring. nix-config reaches frisket through `inputs.chase.inputs.frisket`; a new frisket arrives by a go.mod bump in chase.

### frisket `services.frisket.signer`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | false | Run the signer |
| `forUser` | str | `"dan"` | The only peer uid served; galley user |
| `terminal` | `allow` \| `ask` | `allow` | A real tab's bound, direct sign to a host in `ssh_known_hosts` |
| `sshsig.<namespace>` | `allow` \| `ask` | `{ git = "allow"; }` | A direct SSHSIG sign in that namespace; an unlisted namespace is asked, Allow once |

Not options: frisket's main process is always trusted, a forwarded sign is never silent, and there is no refuse value.

Fixed: user and group `ssh-signer` (951); socket `/run/frisket-signer/agent`; keys `/var/lib/frisket-signer/*.tpm`.

Load-bearing lines:

| What | Line |
|---|---|
| tss assertion, when enabled | no login user in `tss` by members, `extraGroups` or primary group: "a login user in tss could sign with any key blob" |
| Socket | `/run/frisket-signer/agent`, `SocketUser = forUser`, `SocketMode = 0600`, `DirectoryMode = 0755`, fd name `agent` |
| Service | `User = ssh-signer`, `SupplementaryGroups = tss`, `DevicePolicy = closed`, `DeviceAllow = /dev/tpmrm0 rw`, `StateDirectory = frisket-signer` mode 0700 |

Hardening: `NoNewPrivileges`, `CapabilityBoundingSet = ""`, `ProtectSystem = "strict"`, `ProtectHome`, `PrivateTmp`, `ProtectControlGroups`, `RestrictAddressFamilies = [ "AF_UNIX" ]`, `SystemCallFilter = [ "@system-service" "~@privileged" ]`, `MemoryDenyWriteExecute`, `Restart = "always"`, `StartLimitIntervalSec = 0`. UNTESTED as a set with the real binary and TPM; the signer VM test runs this module.

`frisket-signer-keygen` is a oneshot with the same `User`, `tss` and `DeviceAllow`, writing to `/var/lib/frisket-signer/new/`.

### frisket `services.frisket.sudoGate`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enable` | bool | false | Plugin line in `sudo.conf`, PAM rule, `frisket-sudo` PAM service, sudoers defaults, gate |
| `forUser` | str | `"dan"` | The gated user |

Fixed: user and group `sudo-gate` (952); `/run/frisket-sudo/gate.sock`.

Load-bearing lines:

| What | Line |
|---|---|
| `sudo.conf` (guard 1, build-time on every rebuild path) | a derivation that runs `frisket-sudo-check-plugin <so> frisket_audit <sudo version>` and writes `Plugin frisket_audit <so> user=<forUser>` |
| PAM rule | `sudo` auth `frisket-sudo-pam`: `sufficient pam_exec.so seteuid quiet <helper> <forUser>`, order `unix.order - 10` |
| Auth stack assertion | sudo's enabled auth rules are exactly `frisket-sudo-pam`, `unix`, `deny`: "a conversation-free auth module would run on every terminal sudo -n" |
| PAM service | `security.pam.services.frisket-sudo = { }` |
| sudoers | `Defaults noninteractive_auth`, `Defaults timestamp_type=tty` |
| sudoers assertion | no other `timestamp_type`, and no `rootpw`, `targetpw`, `runaspw`, `intercept` or `log_subcmds` |
| Socket | `/run/frisket-sudo/gate.sock`, `SocketUser = sudo-gate`, `SocketMode = 0600`, `DirectoryMode = 0700`, fd name `gate` |
| ptrace assertion | `kernel.yama.ptrace_scope >= 1`: "the sudo window's galley pin needs ptrace_scope >= 1" |

The gate unit: `User = "sudo-gate"`, `CapabilityBoundingSet = ""`, `ProcSubset = "pid"`, `PrivateDevices`, `ProtectSystem = "strict"`, `ProtectHome`, `RestrictAddressFamilies = [ "AF_UNIX" ]`, `Restart = "always"`, `RestartSec = "1s"`, `StartLimitIntervalSec = 0`.

`/run` is root 0755, so only root can create the gate's directory; the plugin needs no check of who made it.

### frisket `nix/flong.nix`

When the signer or the gate is enabled, every flong session's `protect` list gains `/run/frisket-signer`, `/run/galley-ask` and `/run/frisket-sudo`, beside frisket's control socket, so "no socket in a container" is checked by flong.

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
- galley: `services.galley.services = { ssh-signer = "SSH signer"; sudo-gate = "sudo"; }`; `systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 dan users -" ]`.
- Claude Code: `permissions.allow = [ "Bash(sudo:*)" ]` stays, and no deny rules are added. `env.SUDO_ASKPASS` is unset when `sudoGate.enable` and stays `sudo-askpass.sh` when it is off; left set, a no-tty sudo the gate does not take (gate stopped, `-v`) would run the askpass [H4].
- Hosts set `services.frisket.sudoGate.enable` directly.

### nix-config `checks.x86_64-linux.sudo-lockout` (guard 2)

A NixOS VM test, run by `nix flake check` on chase, nixpkgs or sudo bumps and before M3. It imports only frisket's `nixosModules.sudoGate` and copies the host's sudo and PAM values by name. Importing nix-config's host modules recurses, and at the host's `eval-cores = 0` that is a silent hang [spike: X1]. It runs:

- `sudo id -u` with a tty, as root, and with no tty against a real gate;
- `sudo -n id -u` with a tty and no ticket: stock "a password is required";
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
- `TestTerminalAskAsksATabToAKnownHost`
- `TestAGitSignatureIsSilentByDefaultAndAnUnlistedNamespaceIsAllowOnce`
- `TestAForwardedSignIsAskedEvenFromATabToAKnownHost`
- `TestADirectGrantNeverCoversAForwardedSignNorTheReverse`
- `FuzzNoAgentMessageCrashesTheParser`

`internal/peer`:

- `TestADeadPidfdIsNeverRoot`
- `TestOnlyFrisketsMainProcessIsTrusted` (comm, ppid, cgroup by inode)
- `TestTheClaudeChainAnchorsOnClaude` (H2 fixture)
- `TestAScriptRunFromATabAnchorsOnTheTabsShell`
- `TestATabShellRunningSshIsATerminal` (H2 fixture)
- `TestACommandLaunchedThroughTheTerminalServerIsNotATerminal`: `kgx -- ssh`, `kgx -- bash -c`, `kgx -- git push`
- `TestAnAgentCommandIsNeverATerminal` (claude and its `bash` between the tab's shell and the leaf)
- `TestASystemdUserRootAndAReparentedSshAreNeverGrantable`

`internal/grant`:

- `TestAGrantEndsAtTheAnswerPlusTheChoiceAndUseNeverExtendsIt`, plus a rapid property
- `TestAGrantDoesNotSurviveASuspendLongerThanItsTime` (boottime jumps, monotonic does not)
- `TestAGrantForADeadAnchorNeverMatchesAReusedPid`

`internal/galleyask`:

- `TestAnAnswerFromAPeerOutsideGalleysCgroupIsNobody`
- `TestTheQuestionsEncodeToTheGoldenBytes` and `TestEveryGoldenAnswerLineDecodesToItsResult`
- `TestTheTimeFieldParsesClampsAndLogsNoRawText`: `15 minutes`, `2 hours`, `15` with no unit (15 minutes), `0`, `hunter2` (once, logged as "time not understood"), `100 hours` (24 h)
- `TestHangUpWithdrawsTheRow`
- `TestANewGrantSignsTheWaitingRowsItCovers`: a covered row is signed and withdrawn; another host, key, anchor or a forwarded row stays
- `TestThePasswordIsNeverLogged` (captures slog output and searches it)

`internal/sudogate` (peer facts injected as `PeerInfo`):

- `FuzzNoRequestCrashesTheGate` (every kind, in and out of order)
- `TestOnlyARootPeerChecksIn`
- `TestGIsYesOnlyWhenThePeersParentIsALiveCheckIn`: a non-root peer, a root peer whose parent never checked in, a check-in whose connection closed
- `TestAnAOrVOffACheckInConnectionIsRefused`
- `TestAWrongPasswordBringsTheDialogBack`
- `TestANewWindowTurnsTheClaudesWaitingDialogsIntoQuestions`: another claude's dialog and a danger dialog stay
- `TestOnlyAVerifiedDialogPasswordOpensAWindow`: a failed verify, a question's Allow, a danger dialog, a Cut chain and a time of 0 open none
- `TestADangerOrCutDialogHasNoTimeField`
- `TestTheWindowCountsOnlyAnswersFromThePinnedGalley`
- `TestTheWindowEndsWithItsGalleyProcessItsAnchorOrItsTime`
- `TestAProgramOutsideTheRootOwnedDirsIsDanger`: `..`, `/./`, `//`, a nested dir, a store path, plus a rapid property that no non-clean path passes
- `TestShellAndEnvWrappersAreClassifiedByEveryInnerCommand`, and unreadable is danger
- `TestTheGuardUnitsAreDanger` (the embedded catalogue)
- `TestEnvironmentVariablesAreTextLines`: allowlisted names pass; `LESSOPEN`, `LD_PRELOAD`, `FOO` are shown
- `TestServeRefusesToStartWithoutTheGateFd`

`sudo/` (Zig, minish):

- The gating test and the mode parse: a property over generated arguments (every byte, every option and prefix, `--`, attached and separate option arguments) that the parse agrees with sudo's own `parse_args` built as a test oracle; and that `open()`'s ungated path never panics.
- `accept()` refuses a no-tty, local `forUser` sudo with no check-in whatever `open()` decided: a mode test forced to say `-v`.
- zwanzig's planted bugs for the plugin's handle kinds; every descriptor closed after `close()`.

`execrule`: `TestDecideWordsAgreesWithDecideOnReadableStrings` (rapid).

### VM tests (frisket, `runNixOSTest`, importing exactly the module under test)

`tests/signer.nix`: `virtualisation.tpm.enable`; two sshds with distinct host keys; fakegalley as `galley.service`; a stand-in `frisket.service` with frisket's real hardening; dan with linger.

- A key made by stock `ssh-tpm-keygen` and copied into the state dir loads, and an ECDSA login works; with no key files, identities are empty and `serve` is up.
- dan cannot open `/dev/tpmrm0`.
- The frisket main process signs without a question, also with galley absent; a live grant still signs; everything else is then refused.
- A child exec'd inside `frisket.service` is asked.
- A cgroup move from dan's real `user@` session into `frisket.service` is refused.
- A sign for another session than the last bind (tamper) is refused.
- `ssh -A` through the second sshd: the far-side sign is asked with the "forwarded" line, also from a terminal-shaped chain.
- A terminal-shaped chain (a pty holder with comm `.kgx-wrapped`, then bash, then ssh) to a known host signs silently, and is asked with `terminal = "ask"`; `kgx -- ssh` shapes and `systemd-run --user ssh` are asked with the warning level and no time field.
- `ssh-keygen -Y sign -n git` signs silently; `-n file` is asked, Allow once.
- fakegalley `ok 15 minutes` makes a grant: the next sign from the same anchor is silent and fakegalley logs no question; `answer 0` (Allow once) grants nothing.
- A rebound `/run/galley-ask/dan.sock` (socat outside `galley.service`) is nobody, and the journal names its cgroup.
- An ssh killed while its question is up: fakegalley logs the close.
- TPM cleared (swtpm state reset): the key is still listed, a sign fails (the agent protocol carries no text, so ssh only says the agent refused) with "TPM cleared or a different chip" in the journal, and `serve` stays up.

`tests/sudo-gate.nix`: no tty via `setsid -w runuser … </dev/null`, a tty via `script -qec`; fakegalley as `galley.service`.

- With a tty, the gate is never contacted and sudo prompts as stock; tty `sudo -n` says "a password is required".
- **One dialog**: `sudo systemctl restart foo` with fakegalley `ok <pw> 15 minutes`. It runs; fakegalley logged exactly one item, from the `sudo-gate` caller, showing the chain and the resolved command; stderr says "password remembered … until"; the journal has no password.
- **`-n`**: `sudo -n id -u` with no tty gets the dialog and runs.
- **Window**: the next sudo from a new `bash -c` under the same claude gets one question and no password; a different claude gets the dialog.
- **Pin**: fakegalley restarted → the next sudo gets the dialog. A thief that joins `galley.service`'s cgroup and rebinds the socket inside a window → its Allow is a refusal, the journal names the pin, and the window is unchanged. A socat outside the cgroup → nobody to ask.
- **Wrong password**, then right: two dialogs; the second's time is the one used.
- **Danger**: `sudo systemctl stop frisket.service` outside a window → one dialog with the danger level, a password and no time field, and no window afterwards; inside a window → a danger question with no password.
- **Resolved path**: a dan-owned `~/bin/systemctl` first in PATH → danger, the line naming the path.
- **sh -c**: `sudo sh -c 'systemctl stop sshd'` is danger; `sudo sh -c "$(printf x)"` is danger as unreadable.
- **Environment**: `sudo --preserve-env=FOO …` → the item shows `FOO`.
- **Cancel**: sudo refuses and prints sudo's "unable to log accept event" line.
- **Ignored input**: `echo wrong | sudo -S id` and `sudo -A id` with a script askpass → the askpass never runs, and the dialog's password is the one checked.
- **Ticket**: two no-tty sudos from the same parent → the second is asked again; with the gate stopped in between, refused; with a NOPASSWD rule and a plugin built to misread the mode, refused.
- **`-v` and `-l`**: `sudo -v`, `-nv`, `-l`, `--validate`, `--vali`, `--li` with no tty → fail as stock, no check-in, and the next sudo is asked. `-gwheel id` and `-u lp id` check in and get the dialog, with and without a same-parent ticket.
- **NOPASSWD**: a NOPASSWD rule's command still gets the dialog.
- **timestamp_type**: a no-tty `sudo id` allowed through fakegalley (`ok <pw> 0`), then a tty `sudo id` in the same VM → prompted.
- **Gate socket stopped**: no-tty sudo refused with the message; tty and root sudo work.
- **Crash loop**: a gate that exits at start keeps the socket active; no-tty sudo blocks until the test's timeout kills it, and tty sudo works.
- **Hang-up**: sudo killed while its dialog is up → fakegalley logs the close; the same for a question.
- **Never answered**: fakegalley `never` keeps sudo waiting; killing it withdraws the row.
- **Another user** (bob): no check-in; stock.
- **Child of sudo**: a process run by `sudo -u bob` sending 'G' gets 'N'.
- **Remote**: make-usb's `printf pw | ssh vm "sudo -S -p '' tar …"` succeeds with fakegalley never answering and with the gate stopped; a wrong password fails as stock. Detached `ssh vm 'setsid -f sh -c "sudo -S id"'` is gated: fakegalley logs a dialog, and with `never` sudo waits.
- A broken `.so`, a wrong symbol or a wrong plugin type fails the `sudo.conf` derivation build.
- `/etc/pam.d/sudo` auth is the helper, `pam_unix`, `pam_deny`; an extra auth rule, `timestamp_type=global`, `rootpw` or `intercept` fails evaluation.

### galley tests

- An unlisted uid on the services socket is reset; a client-sent `caller` is refused.
- Markup is off for services; each `level` renders its icon, and `danger` its banner.
- Service rows never join any other row; a thief with the same title does not join.
- A stale services socket file is replaced at start.
- The golden files round-trip.
- An entry shows `Field.text`; `text` on a password field fails validation; `--value` fills the preceding `--add-entry` or `--add-multiline-entry`, and `--scale --value 5` still parses; Enter in the sudo form presses Allow.
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

1. `sshSigner.enable = true` on one host and switch; dan leaves `tss`, and the signer starts with no keys. Then `sudo systemctl start frisket-signer` (its first start makes the key directory), `sudo install -o ssh-signer -g ssh-signer -m 0600 ~/.ssh/id_ecdsa.tpm /var/lib/frisket-signer/` and `sudo systemctl restart frisket-signer`. Log out and in; `id` in a new tab shows no `tss`.
2. Check by hand: a tab's `ssh server true` is silent; Claude Code's `git push` is asked and a 15-minute grant holds; `systemd-run --user ssh server true` is asked with the warning; a chase session's push is silent; a signed commit is silent.
3. Read the journal for a few days and tune in code. Then the other host.

Done: dan-desktop checked as in step 2, then dan-blade switched without the wait, so both hosts are in daily use and tuning comes from that.

### M3: sudo gate

Preconditions: `sudo-lockout` passes; `configurationLimit` is null or `>= 5` (§10).

1. `services.frisket.sudoGate.enable = true` on one host; Claude Code's `SUDO_ASKPASS` goes with it (§10).
2. Check by hand: a first agent sudo (`-n` too) shows one dialog and runs; the next asks without a password; a wrong password shows the dialog again; `sudo systemctl stop galley.service` shows danger; terminal sudo prompts as before.
3. Read the journal (dialogs, windows, questions per window) and tune. Then the other host.

### M4: stock agent removed

After M2 has settled on both hosts, delete the M0.5 branch from nix-config. The key files in `~/.ssh` stay; they are useless to dan outside `tss`.

### M5: recovery

- **TPM cleared, firmware update or new board**: `sudo systemctl start frisket-signer-keygen`, move the new key from `/var/lib/frisket-signer/new/` into place, commit the `.pub` and authorize it on GitHub, `server`, `mac` and the other host, using the other host's TPM key. If both hosts lost their keys, add the pubs at each remote's console. Re-enrol the Blade's disk unlock separately (`scripts/tpm-enroll.sh`).
- **DA lockout**: signing resumes when the counter decays (`LOCKOUT_INTERVAL` 7200 s). Lockout auth is set on both hosts, so `tpm2_dictionarylockout --clear-lockout` needs it.
- `installer/install.sh`'s closing text: TPM keys need keygen after a reinstall.

### Rollback

1. `sshSigner.enable = false`: back to the stock agent on the same key file (until M4; after M4, put the M0.5 branch back).
2. `services.frisket.sudoGate.enable = false`: the plugin line, the PAM rule and service, and the sudoers defaults go, and Claude Code's `SUDO_ASKPASS` is back.
3. sudo broken anyway: boot the previous generation from the boot menu at the console.

### Later tracks, not designed here

- **Remote sudo** through the forwarded agent and `pam_rssh`, asked in galley: after the signer's rollout (never with the stock agent, which signs forwarded requests silently), with the normal key; the question needn't show the remote command; starts with a small spike. It must revisit the sudo auth stack assertion.
- **Commit signing from inside containers**, built: a policy with `gitSigning` gets `/run/frisket-sign/<policy>/agent` from frisket, which lists the signer's keys, passes on SSHSIG signs in the `git` namespace, refuses everything else (session-bind included), and answers only frisket's user; the signer sees frisket asking and signs under `sshsig.git`. chase binds the directory into the tier's container. The signer is not told which session asked; frisket's journal says which policy and pid.
- **Allow-with-notice sudo class** (e.g. `nixos-rebuild switch`, run without a question but posted as a galley notice): parked; it would need a root-owned-PATH check.
- **A TPM-held age identity.**

## 13. Work breakdown

| Track | Repo | Deliverables | Depends on |
|---|---|---|---|
| T0 M0.5 | nix-config | §12 M0.5 | — |
| T1 galley | galley | Items 1-8 and their tests; item 1 first | — |
| T2 shared | frisket | `internal/peer`, `internal/galleyask`, `internal/grant`, `execrule.DecideWords`, `tests/fakegalley`, swtpm in `mkFrisket` | T1 item 1's pseudo-version |
| T3 signer | frisket | `internal/tpmkey`, `internal/agentsrv`, `cmd/frisket-signer`, `nixosModules.signer`, flong protect entries, `tests/signer.nix`, `docs/signer.md` (recovery) | T2 |
| T4 sudo | frisket | `sudo/*.zig`, check-plugin, `internal/sudogate`, `cmd/frisket-sudo`, `sudo/danger.json`, `nixosModules.sudoGate`, `tests/sudo-gate.nix`, `docs/sudo.md` | T2 |
| T2b chase | chase | go.mod, `vendorHash` and flake.lock bump after T3 and T4 | T3, T4 |
| T5 nix-config | nix-config | `sshSigner`, gate enable with Claude Code's `SUDO_ASKPASS` switch, galley services, `configurationLimit`, `checks.sudo-lockout` | T1 merged, T2b |

T3 and T4 run in parallel once T2 merges. Cross-repo contracts, frozen when their track merges:

- galley `wire/` and its golden files, including `level`, `Field.text` and the three item shapes;
- `GALLEY_SERVICES_SOCKET`, `GALLEY_SERVICES`, `services.galley.services`;
- socket paths: `/run/frisket-signer/agent`, `/run/frisket-sudo/gate.sock`, `/run/galley-ask/<user>.sock`;
- the sudo wire (kinds, tags, replies) between the Zig and the gate;
- uids 951 and 952;
- module options in §10.

## 14. Not doing

- **Exe paths or a known store-path set**: they need `CAP_SYS_PTRACE` and were forgeable with `nix-store --add` [spike: store-name-attack]; comm plus structure is at the stock floor.
- **Question-as-authentication for sudo outside a window**: a galley Allow can come from dan-uid code with nobody there; the dialog's password needs a person.
- **An approval plugin**: its `open()` returning 0 skips `check()` after the helper has skipped the password, and a `sudo.conf` that loses its line does the same [spike: one-hop-sudo A1, A2, A4].
- **A check-in read from `/proc/<sudo>/maps`**: it shows the `.so` is loaded, not that this sudo is gated [spike: one-hop-sudo A1, A2, A4].
- **An askpass**: with no tty sudo never runs one once the helper skips the password [spike: one-hop-sudo Q2g].
- **A prefix check on `command=`**: `/run/current-system/sw/bin/../../../home/…/cat` ran as root [spike: evidence-audit].
- **An env denylist**: `LESSOPEN` ran code as root [spike: policy-fit]; variables are shown instead.
- **Fail-open when the gate is unreachable**: a crash loop with a fresh ticket was silent root [spike: sudo-vm, ops-socket-limit].
- **A Python sudo plugin**: not built into nixpkgs sudo, and there is a no-Python rule.

## 15. Open, untested, try later

UNTESTED, each with the test that settles it:

- **Claude Code's Bash timeout kills the whole process tree**, so sudo and ssh hang up and their rows are withdrawn. A quick check before building: a Bash call running `sudo -n sleep 600` with a short timeout, then `pgrep sudo`. If sudo survives, a timed-out command keeps its row until answered.
- **The plugin's one connection** lives from `open()` through PAM and pam_exec's fork to `accept()`, the gate sees its hang-up while `accept()` waits, and its close ends the check-in: the sudo VM (Hang-up, Ticket cases).
- **Ungated sudo passes the audit-only veto**: S2 and S3 ran with the approval plugin, and the veto runs failed in PAM first, so no run shows an ungated no-tty sudo reaching `accept()` and passing (remote `printf pw | ssh host 'sudo -S id'`): the sudo VM's Remote case.
- **The "gate not running" line printed from the audit `open()`** reaches stderr: the sudo VM.
- **The sudo lecture** on a terminal `sudo -n` from a user never lectured [spike: one-hop-sudo noninteractive]: the sudo VM.
- **The comm of frisket's main process** is `frisket`: record it in the signer VM stand-in.
- **The tab shape on dan-blade** (H2 was recorded on dan-desktop): record one chain before M2 there.
- **comm of `sshd-session`** links is `sshd-session` on OpenSSH 10.5 (only exe and cmdline were recorded): the sudo VM remote subtest.
- **The cgroup move from `user@` into `frisket.service`** is refused: signer VM.
- **SSHSIG parsing** on real `ssh-keygen -Y sign` output: unit test.
- **The signer's hardening set as a whole**, with the real binary and the TPM: signer VM.
- **Connecting to the signer socket from frisket.service's read-only mounts**: signer VM stand-in.
- **galley `Field.text` and `--value`**: galley e2e.
- **sudo's `parse_args` as a test oracle**: whether it builds alone from `sudo.src` for the mode-parse property: a first build in the `sudo/` tests.
- **A Zig audit plugin loaded by sudo**: the exported `frisket_audit` passes the check-plugin and sudo's loader: the sudo VM.
- **The environment sudo passes after `env_reset`**: record it once in the sudo VM and write it into `docs/sudo.md`.
- **galley's peer check under the signer's and gate's hardening** (cgroup inode stat worked under the same flags for `frisket.service` [spike: identity-vm]): both VM tests.

Try later, after reading the journal:

- Make forwarded, unbound or SSHSIG requests silent or refused.
- A terminal grant offer on unknown host keys versus a silent sign.
- Keep the previous time when the dialog comes back after a wrong password.
- A cap on wrong passwords in one dialog.
- More danger patterns.
- Splitting `execrule` so the gate binary drops `policy` and `internal/dns` (~0.7 MB).
- A cap on queued service rows, if flooding shows up.

## 16. Evidence index

Spike directories are under `~/spike-tools/`. Where a spike has a sceptic twin, the sceptic's verdict wins.

| Spike | Showed | Path |
|---|---|---|
| g0 | PTT on both hosts; transient H-2 parent works; ~225 ms per sign fresh, ~43 ms cached; DA settings; persistent handles; `ptrace_scope` 1 | `g0/out-dan-*.txt` |
| tpm-keys | Pure-Go P-256 TPM keys; H-2 parent deterministic; cleared TPM → `TPM_RC_INTEGRITY`; interop with stock agent | `rev2-spikes/spikes/tpm-keys{,-sceptic}/` |
| tpm-da-lockout | DA-on keys fail with `TPM_RC_LOCKOUT` in lockout | `rev2-spikes/spikes/tpm-da-{lockout,rerun}/` |
| session-bind | OpenSSH binds before signing; binds verify; forwarding visible; `LoginGraceTime` | `rev2-spikes/spikes/session-bind/` |
| identity-vm | uncapped readers get stat, status, cmdline, cgroup but not exe; pidfd mask recipe; cgroup inode stat under hardening; `linuxtpm` polling | `rev2-spikes/spikes/identity-vm{,-sceptic}/` |
| sudo-vm | `tty=` and `open()` returns; messages; pam_exec codes | `rev2-spikes/spikes/sudo-vm{,-sceptic}/` |
| one-hop-sudo | audit `open()` → PAM → accept order; `PAM_TTY` and `tty_nr` agree; `pam_authenticate` inside sudo (~1.6 s on a wrong password); tickets under each `timestamp_type`, `global` a bypass; fail-closed cases; `-S`/`-A` ignored with no tty; NOPASSWD still asked; approval-plugin and maps holes; check-in only when gating; the audit-only veto; `rootpw` replaced; `noninteractive_auth` and `-n` | `one-hop-sudo/{summary.md,sceptic.md,sceptic/,noninteractive/}` |
| ops-socket-limit | the default start limit stops the socket after 5 failed starts, and connects are then refused | `rev2-spikes/spikes/ops-socket-limit/` |
| sudo-plugin | setuid sudo cannot be ptraced | `rev2-spikes/spikes/sudo-plugin/` |
| policy-fit, evidence-audit | resolved-command trust, dotdot path, `LESSOPEN`, no re-quoting | `rev2-spikes/spikes/{policy-fit,policy-fit-sceptic,evidence-audit}/` |
| store-name-attack | `nix-store --add` forges store names | `rev2-spikes/spikes/store-name-attack/` |
| galley-socket | answers go only to the asker; password rows leak to joiners without no-join; real gjs self-binding | `rev2-spikes/spikes/galley-socket{,-sceptic}/` |
| G-P1 | activation hides the peer; self-bound peer is galley's MainPID; cgroup migration passes the binder check; `pidfd_getfd` needs `ptrace_scope` 0 | `t0-2026-10-08/spikes/G-P1{,-sceptic}/` |
| R1 | OpenSSH 10.5 privsep chain; detached remote sudo loses ancestry | `t0-2026-10-08/spikes/R1{,-sceptic}/` |
| SV1 | wrong plugin type segfaults sudo; ignored `sudo.conf` warns | `t0-2026-10-08/spikes/SV1{,-sceptic}/` |
| X1 | the lockout check recurses if it imports host modules | `t0-2026-10-08/spikes/X1{,-sceptic}/` |
| host-facts-desktop | H2, H3 on dan-desktop | `t0-2026-10-08/spikes/host-facts-desktop{,-sceptic}/` |
| crosscheck | gjs peer credentials; `StartLimitIntervalSec=0` keeps the socket up, and connects then get no answer | `crosscheck/galley/`, `crosscheck/verify-startlimit0/`, `crosscheck.md` |
| flong probe | containers see none of these sockets, no setuid sudo, NNP; trusted tier writes host `~/.claude` | `simplify-synthesis.md` §4 |
