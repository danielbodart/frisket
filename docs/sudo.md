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

claude> sudo journalctl -u foo      # galley: "sudo journalctl -u foo"   [Refuse] [Allow once]

claude> sudo systemctl stop sshd    # galley, danger: "touches a unit that guards this machine"
                                    #   [Refuse] [Allow once]   (never opens a window)

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
`ssh host 'sudo -S …'`.

A gated sudo skips `pam_unix` and asks the gate. With no tty, `-S`, `-A`,
a sudoers ticket and NOPASSWD are all ignored: the dialog's password is
the one checked. `sudo -n` gets the dialog too.

- **Outside a window**: the dialog. A wrong password brings it back. A
  verified one runs the command and, with a time above 0, opens a window.
- **Inside a window**: a question, Allow once or Refuse. The window is
  keyed on the claude and pinned to the galley process that took the
  password; it ends at its time, or when either exits. An Allow from any
  other galley process is a refusal.
- **Danger**: a `systemctl` on `frisket*`, `galley*`, `sshd*`,
  `nftables*` or `debug-shell*`, a program outside
  `/run/current-system/sw/bin`, `/run/wrappers/bin` and
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

## Journal

```
journalctl -u frisket-sudo -o cat | jq 'select(.msg == "decision")'
```

One `decision` record per answer: the chain, the anchor, the program and
argv, danger reasons, environment lines, the outcome, and its `source`
(`galley`, `window`, `verified`, `wrong password`, `cancelled`, `nobody`,
`not the pinned galley`, `hung up`). A password appears only as its length.

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
