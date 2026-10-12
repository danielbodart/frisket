# frisket-sudo

Gates sudo when no terminal is asking. Each such sudo is one galley item
showing the resolved command. Outside a window it is a dialog that takes
your password, which opens a window for that claude for a time you pick.
Inside the window every command is still shown and asked, with no
password.

```
claude> sudo systemctl restart foo  # galley: "sudo systemctl restart foo"
                                    #   Password [••••]  Remember for [15] [minutes ▾]  [Cancel] [Allow]
frisket-sudo: password remembered for this claude until 16:40

claude> sudo journalctl -u foo      # galley: "sudo journalctl -u foo"   [Refuse] [Allow]

claude> sudo systemctl stop sshd    # galley, danger: "touches a unit that guards this machine"
                                    #   [Refuse] [Allow]   (never opens a window)

$ sudo id                           # in a terminal: stock sudo, the gate never sees it
```

## Setup

```nix
{
  imports = [ inputs.frisket.nixosModules.sudoGate ];

  services.frisket.sudoGate = {
    enable = true;
    forUser = "alice";
  };
}
```

Let galley take questions from the gate:

```nix
services.galley.services = { sudo-gate = "sudo"; };   # home-manager
systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 alice alice -" ];
```

Unset `SUDO_ASKPASS` for anything that runs sudo with no terminal: a sudo
the gate does not take (the gate stopped, `-v`) would run it.

Keep at least five generations in the boot menu before the first switch
(`configurationLimit` null or `>= 5`): a broken sudo is fixed from the
previous generation.

## Options

| Option | Default | Meaning |
|---|---|---|
| `enable` | `false` | The plugin line in `/etc/sudo.conf`, the PAM rule, the `frisket-sudo` PAM service, the sudoers defaults and the gate. |
| `forUser` | `"dan"` | The gated user, and whose galley is asked. |
| `remoteKeys` | `[ ]` | SSH public key lines whose signature approves a remote sudo (below); empty is remote mode off. |
| `danger.<pattern>` | `{ }` | Danger rules beside the built-in catalogue (below): `reason` for any command the pattern matches, `args.<glob>` for one with an argument the glob matches. |
| `exec.<pattern>.answer` | | The host's exec rules ([Rules](#rules)): `allow`, `ask` or `refuse` for a resolved command the pattern matches. |
| `exec.<pattern>.runAs` | `"root"` | The user the rule's commands run as; a sudo as anyone else is not the rule's. |

With `services.frisket.policy.courier.enable`, the file also gets
`policy`: the courier's socket, `/etc/frisket/allowed_signers` and the
policy file's name, and the gate reads the project a sudo is run in.

The options are written to `/etc/frisket-sudo/config.json`, which
`frisket-sudo serve -config` reads, keys named as the options are:

```json
{ "forUser": "alice", "remoteKeys": [ "ecdsa-sha2-nistp256 AAAA… alice@laptop" ],
  "danger": { "reboot **": { "reason": "reboots this machine" },
              "systemctl **": { "args": { "postgresql*": "touches the database" } } },
  "exec": { "/run/current-system/sw/bin/journalctl **": { "runAs": "root", "answer": "allow" } },
  "policy": { "courier": "/run/frisket-policy/sock",
              "allowedSigners": "/etc/frisket/allowed_signers", "fileName": "chase.json" } }
```

A key it does not know (a rule's spelt in another case included), a
remote key that does not parse, or a danger or exec rule that does not
compile stops it starting; the build runs `frisket-sudo
check` on the file first, and a change restarts the gate. `frisket-sudo
schema` prints its JSON Schema.

The module sets `Defaults noninteractive_auth` and `Defaults
timestamp_type=tty`, and evaluation fails when:

- sudo's auth stack is anything but the helper, `pam_unix`, `pam_deny`,
  or the `frisket-sudo` PAM service's anything but `pam_unix`, `pam_deny`;
- sudoers sets another `timestamp_type` (`!tty_tickets` included), or
  `rootpw`, `targetpw`, `runaspw`, `intercept` or `log_subcmds` (as
  options or as `INTERCEPT:` and `LOG_SUBCMDS:` tags);
- `kernel.yama.ptrace_scope` is 0.

The plugin is built against `security.sudo.package`, and `/etc/sudo.conf`
is built only once `frisket-sudo-check-plugin` has loaded the plugin as sudo
would and found an audit plugin for this sudo's version.

## What is gated

A sudo of `forUser`'s with no tty, not under an ssh login, and not `-v` or
`-l`. Everything else is stock sudo: a terminal, another user, root,
`ssh host 'sudo -S …'`, unless remote mode takes it.

A gated sudo skips `pam_unix` and asks the gate. With no tty, `-S`, `-A`,
a sudoers ticket and NOPASSWD are all ignored: the dialog's password is
the one checked. `sudo -n` gets the dialog too.

- **A rule matching** (the host's or the project's, [Rules](#rules)):
  allowed with no password, asked with none, or refused, but never for
  a danger or a warning.
- **Outside a window**: the dialog. A wrong password brings it back. A
  verified one runs the command and, with a time above 0, opens a window.
- **Inside a window**: a question, Allow or Refuse. The window is
  keyed on the claude and pinned to the galley process that took the
  password; it ends at its time, or when either exits. An Allow from any
  other galley process is a refusal.
- **Danger**: a `systemctl` on `frisket*`, `galley*`, `sshd*`,
  `nftables*` or `debug-shell*`, a command matching a `danger` rule, a
  program outside `/run/current-system/sw/bin`, `/run/wrappers/bin` and
  `/etc/profiles/per-user/<user>/bin`, or a `<shell> -c STRING` (`sh`,
  `bash`, `dash`, `zsh`, `ksh`, `mksh`, `fish`, …), `sudo -s`, `sudo -i`
  or `env` whose inner command is either or cannot be read. A shell run
  any other way (`bash -lc`, `sh -c -- …`, `bash script.sh`, a bare
  `sudo -s`) cannot be read. Shown with galley's danger banner, always
  asked, never opens a window; its dialog has no time field.
- **Warning**: a process chain cut short, or launched straight from
  `systemd --user`. No time field.
- Variables outside the allowlist (`HOME`, `PATH`, `TERM`, `LANG`,
  `LC_*`, `DISPLAY`, `SUDO_*`, …) are shown as lines.

A refusal is sudo's own line:

```
sudo: frisket_audit: unable to log accept event: cancelled
```

A sudo that is killed withdraws its item; until it runs the command, sudo
holds SIGTERM, SIGINT, SIGHUP and SIGQUIT, so only SIGKILL does. Nothing
that waits on you times out: a sudo waits until it is answered or killed.
The check-in alone is bounded: a gate that does not answer it within
250 ms is not running.

## Rules

Exec rules answer a sudo before any dialog: the host's, from
`services.frisket.sudoGate.exec`, and the project's, from the `sudo`
section of the signed `chase.json` the sudo is run in.

```nix
services.frisket.sudoGate.exec = {
  "/run/current-system/sw/bin/journalctl **".answer = "allow";
  "/run/current-system/sw/bin/journalctl ** [arg --vacuum*]".answer = "ask";
  "/run/current-system/sw/bin/reboot **".answer = "refuse";
};
```

```json
{ "version": 2,
  "sudo": { "exec": { "/run/current-system/sw/bin/systemctl restart foo.service": { "runAs": "root", "answer": "ask" },
                      "/run/current-system/sw/bin/reboot **": null } } }
```

```
claude> sudo journalctl -u foo      # runs: no dialog, no password
claude> sudo systemctl restart foo  # galley: "asked, with no password, by the project rule …"  [Refuse] [Allow]
claude> sudo shutdown now           # no rule: the password dialog, as ever
claude> sudo systemctl stop sshd    # danger: the dialog, whatever a rule says
```

- **Patterns** are execrule's, over the resolved command: the program's
  absolute path, as the dialog shows it, then its arguments. `*` is one
  word, a last `**` any number; ` [arg GLOB]` after a pattern makes an
  arg rule, which only asks or refuses, for a command with an argument
  the glob matches (`*` any run of characters but `/`). A literal pattern
  beats a pattern, a narrower one a wider one, and an arg rule only makes
  the answer stricter. A pattern whose first word is not an absolute,
  clean path could never match, and is refused.
- **Answers**: `allow` runs the command with no question and no password;
  `ask` is a plain Allow/Refuse question with no password, inside a
  window or not, which opens no window; `refuse` is sudo's own refusal
  line, naming the rule
  (`unable to log accept event: refused by the host rule /run/current-system/sw/bin/reboot **`).
  No rule matching is the dialog, or the window's question, as without
  rules. An arg rule asking about a command no command rule matches
  leaves it the dialog: the password is the stricter.
- **runAs**: a rule is for the user it names, root by default; a
  `sudo -u lp` is decided by `lp`'s rules alone.
- **Never a rule's**, fixed in the gate whatever any rule says: a danger
  (the catalogue, a `danger` rule, a program outside the root-owned
  directories, an unreadable shell command), a warning (a chain cut short
  or launched from `systemd --user`), a command the gate did not see
  whole, one with a variable outside the allowlist, and a shell,
  `sudo -s`, `sudo -i` or `env`, whose command is another's. Each is
  asked as it is with no rules. Remote mode reads no rules.
- **The project** is the one the courier finds above the working
  directory of the process that ran sudo ([policy.md](policy.md)). Its
  `sudo.exec` is merged over the host's with RFC 7396's merge patch: a
  pattern the host has is replaced, `null` takes it away, a new one is
  added. A project may set `exec` alone. The file counts only when
  `chase.json.sig` verifies against `/etc/frisket/allowed_signers` in
  the project's namespace; unsigned, not verifying, or with a `sudo`
  section a project may not set, it is ignored with one
  `project policy ignored` journal line, and the host's rules decide. No
  project, or the courier down, is the host's rules.
- The journal's `decision` has `source` `host rule` or `project rule`,
  with `rule` (the pattern), `answer` and the project's `root`; an
  answered `ask` has `source` `galley` and `rule_source`.

There is no Always for sudo: a project's rule is written into
`chase.json` by hand, or by an agent, and signed (`chase sign`).

## Remote mode

```
claude@laptop> ssh -A desktop sudo systemctl restart foo
                                    # laptop's galley: "sudo on desktop"
                                    #   /run/current-system/sw/bin/systemctl restart foo
                                    #   [Refuse] [Allow]
```

On a host whose gate has `remoteKeys`, a sudo of `forUser`'s with no tty
under an ssh login with a forwarded agent is approved by a signature from
one of those keys:

```nix
services.frisket.sudoGate.remoteKeys = [ "ecdsa-sha2-nistp256 AAAA… alice@laptop" ];
```

The keys are written to `/etc/frisket-sudo/config.json` and `remote` is
added to the plugin line; there are no new PAM lines. The client needs
only `ForwardAgent` for the host.

The gate classifies the command as for a local sudo and hands the plugin a
message to sign: a nonce, the host's keys, the user, the runas user, the
cwd, the resolved command, the level and the reasons. The plugin connects
to the forwarded agent as the invoking user and asks for a plain signature
with the first listed key the agent holds. frisket-signer on the client
asks every time, naming the host from `/etc/ssh/ssh_known_hosts`, and
refuses unless its forwarded session is bound to one of the message's host
keys; no grant or window skips it. A stock agent holding a listed key
signs without asking.

A sudo with a tty (`ssh -t`) asks the host's own password, as stock. No
forwarded agent, no `remoteKeys`, or the gate down is stock too: "a
terminal is required". The agent refusing, failing or holding no listed
key refuses the sudo:

```
frisket-sudo: the forwarded agent refused
sudo: frisket_audit: unable to log accept event
```

## Journal

```
journalctl -u frisket-sudo -o cat | jq 'select(.msg == "decision")'
```

One `decision` record per answer: the chain, the anchor, the program and
argv, danger reasons, environment lines, the outcome, and its `source`
(`galley`, `window`, `verified`, `wrong password`, `cancelled`, `nobody`,
`not the pinned galley`, `hung up`, `host rule`, `project rule`). A password appears only as its length.
A remote sudo's records have `remote` set, the message's fields, the host
key fingerprints, the nonce, and the key that signed.

## Environment

With NixOS's sudoers, `env_reset` leaves the command, and the gate, this
from a caller with `TERM`, `DISPLAY`, `LANG`, `COLORTERM`, `XAUTHORITY`
and `FOO` set (recorded in the sudo VM test):

```
COLORTERM=truecolor
XAUTHORITY=/home/dan/.Xauthority
LANG=C.UTF-8
TERM=dumb
DISPLAY=:0
PATH=/run/wrappers/bin:/run/current-system/sw/bin
MAIL=/var/mail/root
LOGNAME=root
USER=root
HOME=/root
SHELL=/run/current-system/sw/bin/bash
SUDO_COMMAND=/run/current-system/sw/bin/env
SUDO_USER=dan
SUDO_UID=1000
SUDO_GID=100
SUDO_HOME=/home/dan
```

All of it is on the allowlist, so a plain sudo shows no variable lines;
`FOO` arrives only with `--preserve-env=FOO`, and is shown. PAM's session
then adds root's NixOS environment (`GTK_PATH`, `INFOPATH`,
`LIBEXEC_PATH`, `LOCALE_ARCHIVE`, `NIX_PATH`, `TERMINFO_DIRS`, …) after
the gate has answered, so the gate never sees it.

## Recovery

**No-tty sudo says `frisket-sudo: gate not running`.** The gate socket is
down, or the gate is not answering (crash-looping or stuck); sudo in a
terminal works as before.

```
systemctl status frisket-sudo.socket frisket-sudo.service
sudo systemctl restart frisket-sudo.socket
```

**No-tty sudo hangs.** galley is not answering. Kill the sudo
(`kill -KILL`), then check `journalctl -u frisket-sudo`.

**`no one to ask; use a terminal`.** galley is not running, or the socket
at `/run/galley-ask/<user>.sock` is not galley's.

**Rollback.** `services.frisket.sudoGate.enable = false` removes the
plugin line, the PAM rule and service and the sudoers defaults; set
`SUDO_ASKPASS` back if you use one.

**sudo broken everywhere.** Boot the previous generation from the boot
menu at the console.
