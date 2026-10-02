# SSH

An SSH route lets a session run commands on one of your machines -- `ssh
gateway systemctl status nginx` -- with no key in the sandbox. frisket
terminates the sandbox's SSH itself, decides each command it asks to run,
and runs the ones it admits over its own login to the machine, with your key
or your password. No shell is ever opened for the sandbox: a route runs
commands, one to a channel, and nothing else -- on a [shell
route](#shell-routes), to a device whose CLI ignores a command sent as one,
by typing each into a shell frisket opens itself.

A route is reached at its own address, which no name resolves to: the
session's ruleset steers exactly that address and port to frisket. In the
`all` set every other port on it is refused like any other private address;
a `service`-set sandbox has its own network, which steers nothing else to
frisket, so it reaches that address's other ports -- and every other private
address -- directly, whatever its SSH routes say. frisket dials
the machine at exactly that address -- not through egress, whose structural
refusal of private addresses still holds for everything else, and never by
a name a resolver could answer differently.

## The document

SSH routes are a policy document's `ssh` list, beside `allow` and `routes`
-- in a session's own document (`policyFile`), as chase writes one, rather
than the module's `policies`:

```json
{
  "allow": [],
  "ssh": [
    {
      "name": "gateway",
      "address": "192.168.1.1",
      "user": "admin",
      "hostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... root@gateway"],
      "agent": "/run/user/1000/gcr/ssh",
      "identity": "SHA256:7Yb9...",
      "exec": [
        { "command": "systemctl status *",
          "operation": { "id": "systemctl-status", "summary": "Show a unit's status",
                         "class": "read", "category": "services" } },
        { "command": "journalctl **" },
        { "command": "cat **" },
        { "command": "systemctl restart *", "ask": true },
        { "command": "systemctl restart sshd", "refuse": true },
        { "arg": ".ssh", "refuse": true },
        { "arg": "*.pem", "refuse": true }
      ],
      "env": ["LANG", "LC_*", "TZ"],
      "unmatched": "ask"
    }
  ]
}
```

- **`name`**: what the sandbox calls the machine -- `ssh gateway ...` -- and
  the name its host certificate is for. Lower-case letters, digits, dots and
  hyphens, starting with a letter or digit; never an address, and never an
  intercepted host or a Docker name, or one under a wildcard route, since
  the session answers those with an address of its own. Unique.
- **`address`**: a literal IP, `v4:port` or `[v6]:port`, port 22 when
  absent. Never a name: what the session reaches is fixed here. A private
  address is what a route is for; unspecified, loopback, link-local
  (`169.254.169.254` and `fe80::/10` with it), multicast and broadcast
  addresses are refused, as are port 0, port 53, frisket's own service
  addresses, its dummy addresses as lib.steering makes them by default
  (`192.0.2.1`, `2001:db8::1`), and the Docker project's. A deployment that
  moves the dummy elsewhere keeps routes off it itself. Unique, address and
  port together.
- **`user`**: who the commands run as on the machine: a login name of at
  most 255 bytes, of letters, digits and `. _ @ -`, since it is written into
  the sandbox's ssh_config as it is.
- **`hostKeys`**: the machine's own keys, one or more, as authorized_keys
  and known_hosts write them: `ssh-ed25519 AAAA... [comment]`, with no host
  or marker before it. ed25519, ECDSA or RSA; never a certificate.
- **`agent`**, **`keyFile`** or **`passwordFile`**, exactly one: an
  ssh-agent's socket, an unencrypted private key, or a file holding a
  password, for a machine that takes no key, by absolute path. See [Logging
  in](#logging-in).
- **`identity`**: optional, a key's `SHA256:...` fingerprint as `ssh-keygen
  -l` prints it: the one key offered, where an agent holds several and a
  server counts each one offered against its `MaxAuthTries`. With `keyFile`,
  the file must be that key; with `passwordFile` it is an error.
- **`shell`**: optional, `true` for a device whose login shell ignores the
  command an exec carries -- a router's or a modem's own CLI. Its commands
  are typed into a shell frisket opens, and read far more narrowly: see
  [Shell routes](#shell-routes). A shell route lists no `env`.
- **`exec`**: rules, each a `command` pattern, an `arg` glob, or both, and
  `ask` or `refuse`, or neither to admit; an `arg` rule must ask or refuse.
  Both is an error, and so is a rule listed twice. Each may have an
  `operation`, as a path rule's: an `id` and `summary`, and optionally a
  `description`, a `class` (`read`, `write` or `guarded`) and a `category`,
  shown to the person asked and logged, never matched on.
- **`env`**: optional, the variables a command may set for itself and
  still be decided as the command it runs -- `LANG=C ls`, `env TZ=UTC
  date` -- see [What runs](#what-runs-precommands-time-assignments-and-env). Each a
  name of letters, digits and `_`, not starting with a digit, or the start
  of one and a trailing `*`, `LC_*`; at most 64, none twice. A name that
  changes what any command runs, and a `*` that covers one, is refused:
  `PATH`, `LD_*`, `DYLD_*`, `GCONV_PATH`, `BASH_ENV`, `ENV`, `IFS`,
  `SHELLOPTS` and `BASHOPTS`, and glibc's `LOCPATH`, `NLSPATH` and
  `GLIBC_TUNABLES`, which every program reads as where to load data it
  trusts or how to run -- so `L*`, `N*`, `G*` and `P*` are refused too.
- **`unmatched`**: `ask`, the default -- unlike an HTTP route's -- or
  `refuse`: for a simple command no command rule matches, and every command
  that is not readable (below). A route whose command rules neither admit
  nor ask anything, under `refuse`, refuses every command, and does not
  load.

A document has at most 32 routes: each is a Host block and a destination in
what frisket answers a session with when it opens, which is one message.

Every field is checked when the document loads, and `frisket check` checks
it offline: the agent and the key file are read only when frisket logs in,
so a document is checked where neither exists. `frisket check -exec <name>
<document>` checks it, then answers each line of its input, a command, as
that route decides it -- `allow`, `ask` or `refuse`, a tab, and the rule --
so a route's rules are tested as commands, by frisket's own reading of them.
A Go program that writes rules can do the same in process: the public
package `github.com/danielbodart/frisket/execrule` is the reading itself --
`execrule.Compile(route)` checks a route's `exec`, `env` and `unmatched` as
frisket does, and `Decide(command)` answers as the route would -- which is
how chase tests its catalogue, with no copy of the grammar to drift.

## Commands

sshd hands a command to the login shell as one string, so a command is only
what its words say if a shell reads it as exactly those words -- and frisket
does not know which shell the machine has. So it reads a small grammar that
sh, bash, zsh, ksh, fish and csh all read alike, and a command outside it is
**unreadable**.

**An SSH route assumes its machine's login shell is one of those**: of the
POSIX family, fish or csh. Windows' cmd.exe, the login shell of a stock
Windows OpenSSH server, reads no such grammar the same way -- `'` is no
quote to it, `;` no separator, `%VAR%` expands quoted or not, and `"`, its
only quote, does not stop `&` -- so `echo 'a & shutdown /r & echo b'`, one
word after `echo` here, is three commands there. PowerShell is not
verified either. Rules on a route to such a machine decide words it does
not run, so do not route to one.

**A command is read as its words alone, not as the machine's startup files
would have it.** sshd's shell reads some before the command: zsh always its
`.zshenv`, fish its `config.fish`, tcsh its `.tcshrc`, and bash, which
knows sshd started it, `/etc/bashrc` and `~/.bashrc`. A function one of
them defines is what a non-interactive shell runs for its name, so on a
machine whose startup files define `git`, a rule for `git **` decides a
command that runs that function and not the program. The agreement between
shells claimed here was checked by running `sh -c` and its kin from a clean
environment, with no startup file read. Rules are only as good as the
machine's startup files, which are its owner's to keep plain.

A **readable** command is one or more simple commands joined by `&&`, `||`,
`;` or `|`, with or without spaces around them, and at most 8 KiB long. A
simple command is words separated by spaces, and a word is one of:

- **plain**: letters, digits and `_@%+=:,./-`, which none of those shells
  gives a meaning of its own -- but not beginning `%`, which fish reads
  there (`%self` is its PID), nor `=` (below);
- **single-quoted**: `'...'` holding printable ASCII but `'`, `\` and `!` --
  fish reads a backslash there and csh a `!` -- whose content is the word,
  `$`, `*`, `;` and all;
- **double-quoted**: `"..."` holding what a single-quoted word may, but
  `$`, a backtick and `"` -- every shell expands the first two there --
  whose content is the word: `grep "a b; c" log` is `grep`, `a b; c` and
  `log`. Each of the 89 bytes left is itself inside double quotes to all
  six shells frisket was checked against (bash, dash, zsh, mksh, fish and
  tcsh).

After its words, a simple command may end `>/dev/null`, `</dev/null` or
both, each once and a word of its own, exactly so: its output thrown away,
its input empty. They are no words of the command, so `ls -l >/dev/null` is
decided as `ls -l`. No other redirection is readable -- not `2>/dev/null`,
which csh reads as an argument `2`, nor `> /dev/null` with a space, nor
`>>`, `&>` or `>&`, nor one before a word, which fish refuses -- and nor
is output to `/dev/null` from a simple command piped into another, or
input from it to one a pipe feeds, both of which csh calls ambiguous and
refuses to run, and zsh reads as both.

Anything else makes the whole command unreadable: `$`, a backtick, a
backslash outside quotes, any other `<` or `>`, a single `&`, `()`, `{}`,
`*?[]` unquoted, `~`, `!`, `#`, a tab, a newline, anything not ASCII; a word
that is two of those run together, `a'b'` or `"a"'b'` -- zsh can read
`'a''b'` as one string -- a plain word beginning `=`, which zsh reads as the
path of the command of that name, so that `cat =deploy` prints whatever
`deploy` on `PATH` is, or `%` (a pattern word beginning either is refused);
an operator first or last, two together, an empty simple command, and a
command longer than 8 KiB, which bounds the work of deciding one -- nothing
worth a rule is that long, and a question shows a person far less of one.
So is a simple command whose first word, once [what
runs](#what-runs-precommands-time-assignments-and-env) is found:

- **holds `=`**: to a shell `PATH=/tmp/x ls` is an assignment and then a
  command, `ls` run some other way, and neither a rule for `ls` nor one for
  `PATH=/tmp/x` may say what it is. An assignment of a name `env` lists is
  taken off instead (below); any other is unreadable. Quoted, `'X=1'` is a
  command's name to bash, but nothing is worth a rule for one. A pattern
  whose first word holds `=` is refused as a document error, since it could
  never match.
- **is a reserved word** of bash, zsh or fish -- `if then else elif fi case
  esac for select while until do done in function coproc repeat foreach end
  nocorrect noglob - begin not and or switch` -- which a shell reads as its
  syntax, not a command: fish's `not rm x` and zsh's `ls; - rm x` run `rm`.
  A pattern starting with one is refused too. `time` is one, and is taken
  off (below); a pattern starting with it is refused all the same.
- **is a precommand**, `exec`, `command` or `builtin`, anywhere but first
  (below), where it is the program of that name to some shells and the
  builtin to others. A pattern starting with one is refused.

A pattern is words separated by single spaces, each one of:

- a literal word, in the plain alphabet, matching that word exactly, quoted
  or not: `sudo` matches `'sudo'` and `"sudo"`;
- `*`, matching exactly one word, whatever a quoted one holds;
- `**`, last only, matching any number of words, none included.

So `systemctl status *` matches `systemctl status nginx` and not `systemctl
status`, and `journalctl **` matches `journalctl` and `journalctl -u nginx
-n 50`.

### What runs: precommands, time, assignments and env

Some words before a command only say how it runs, and the command after
them is what runs: frisket takes them off and decides the command -- `LANG=C
ls -l` by the rules for `ls -l`. The question and the log still show the
command exactly as it was sent. In a simple command's first places:

- **`exec`, `command` or `builtin`**, plain and first: each runs the
  command after it -- `exec` in place of the shell, `command` by `PATH`,
  `builtin` as the shell's own -- so `command sudo reboot` is decided as
  `sudo reboot`. Where a shell has no such builtin (csh's `command` and
  `builtin`, dash's `builtin`) it runs the program of that name -- POSIX's
  wrapper of the builtin where the system has one, which runs the command,
  or nothing. Quoted, `'exec'` is that program to csh too, so it is
  unreadable, and so is any option -- `command -v`, `command -p`, `exec -a`,
  `--` -- and a precommand with no command after it. After one, `env` and
  `time` are the programs, as after `env` (below); an assignment is a
  command's name to every shell, and another precommand a program to some
  and the builtin to others, so both are unreadable. Anywhere else a
  precommand is unreadable: after an assignment it is no builtin to csh,
  and after `env` or `time` the program of that name.
- **`NAME=value`**, a plain word, before the command or another such word:
  an assignment, for that command alone. The name must be one `env` lists,
  and the value may not begin `=` or hold `:=`, where zsh may expand the
  path of a command. Nor may it begin `/`, `.` or `:`, or hold `..` or `%`:
  every program the command runs reads it, and `LANG`, `LC_*` and `TZ` name
  files too -- glibc loads a locale named `/dir` from that directory, musl
  a zone named `/f` or `./f` from that file, `TZ=:f` is `f`, `..` leaves the
  zone directory, and `%` is expanded in `NLSPATH`. That data is trusted by
  the library that parses it, so a file the session wrote would be parsed
  inside the program a rule admitted. What is left names the system's own
  data: `C.UTF-8`, `en_GB.UTF-8`, `UTC`, `Europe/London`. `PATH=/tmp ls`, `LD_PRELOAD=x ls`, a name not listed, a
  quoted `'LANG=C' ls`, and an assignment with no command after it --
  `LANG=C`, which sets the shell's own variable for whatever comes next --
  are unreadable.
- **`env`**, then `NAME=value` words of listed names: env runs the word
  after them as the command. With no command after it, `env` is the command,
  decided by a rule for `env` -- a pattern of `env` and anything more is
  refused, since it could never match. So is `env` with only options that
  run nothing, before any assignment -- `-0`, `--null`, `-i`, `-`, `-v`,
  `--debug`, and `-u NAME` in its spellings -- which prints the environment
  as `env` does. Any other option -- `-S`, `-C`, `--` -- and any option with
  a command after it -- `env -i ls`, `env -u LANG ls` -- is unreadable.
- **`time`**: the shell's keyword in bash, zsh and ksh, and `/usr/bin/time`
  in dash or after `env` or a precommand; either way, the command after it
  runs. After `env` or a precommand it is only ever the program, and takes
  `-p`, POSIX's one option.
  Anywhere else `time -p` is unreadable, since the shells disagree what
  `-p` is: bash's option only unquoted, and to zsh, whose `time` has none,
  the command to run -- `time -p ls` there runs whatever `-p` is on `PATH`.
  Any other option, and `time` with no command, are unreadable.

They combine, but where `time` and an assignment meet, the shells disagree
and the command is unreadable: `time LANG=C ls` runs `ls` in bash, but in
dash, whose `time` is `/usr/bin/time`, `LANG=C` is the command to run, and
whether `LANG=C time ls` reaches the keyword is the shell's own grammar.
`time env LANG=C ls` and `env LANG=C time -p ls` mean one thing everywhere,
and are read.

Every arg rule sees the assignments taken off, as it sees arguments, so
`KUBECONFIG=/root/.kube/config ls` is refused by an arg rule for `.kube`.
Taking them off never decides a command more loosely than the command
without them: it is decided as that command, or more strictly by an arg
rule, or it is unreadable.

**List only names that change nothing that matters.** frisket refuses the
names that change what any command runs, but cannot refuse every name some
program reads as code: `LESSOPEN`, `PAGER` and `SYSTEMD_PAGER`,
`GIT_SSH_COMMAND`, `PYTHONPATH`, `NODE_OPTIONS` each make a rule for one
command admit another program, and a route that lists one decides words
that are no longer what runs. A locale, a timezone and a terminal's width
are what `env` is for. csh has no assignment before a command: `LANG=C ls`
runs a command named `LANG=C` there, which fails, so a route to a machine
whose login shell is csh has no use for `env`.

**Each simple command is decided on its own**, and the strictest decides
the whole: refusing, then asking, then admitting. Every part of a command
may run, whatever joins it to the rest, so `cd /etc && ls` is admitted only
if both `cd /etc` and `ls` are, and `cat log | sh` is whatever `sh` is. For
one simple command, where several command rules match, the one with the
most literal words decides -- `systemctl restart sshd` over `systemctl
restart *` over `systemctl **` -- and between rules as literal as each
other, the stricter. A simple command no command rule matches is
`unmatched`.

### Arg rules

A rule with an **`arg`** glob only ever tightens. Its `*` matches any run of
characters but `/`, and every other character itself; the glob is matched
against each word after a simple command's first -- the word whole, what
follows its first `=` (`--key=id_rsa`), and each `/`-separated part of
either -- and each assignment taken off it (see [What
runs](#what-runs-precommands-time-assignments-and-env)) as well. Once a simple
command's command rules have decided it, every arg rule that matches one of
its words -- and whose `command`, if it has one, matches it too -- makes the decision stricter if it is stricter, and never
less strict. One only as strict as the decision is credited with it all
the same -- the first such, if there are several -- so `cp
/root/.ssh/id_rsa /tmp`, where `cp **` and an `id_*` arg rule both ask, is
asked about as the arg rule's operation, and `xxd /etc/shadow` under `"unmatched": "refuse"` is
logged as `[arg shadow]`, not out of scope. An arg rule that would admit is an error.

```json
{ "arg": ".ssh", "refuse": true },
{ "arg": "id_*", "refuse": true },
{ "command": "less **", "arg": "+*", "ask": true }
```

Under those, `cat /root/.ssh/config`, `cat id_ed25519` and `cd /home/u/.ssh
&& cat config` are refused however `cat` and `cd` are ruled, and `less +F
log` is asked about where `less **` admits it.

**Arg rules catch the obvious, not a determined workload.** They see a
path a command is given, spelt out. They do not see one a command finds for
itself -- `grep -r key /root`, `find / -name '*.pem'` -- nor one spelt
another way, through a symlink, a `~` (`cat ~/.ssh/id_rsa` is unreadable,
so unmatched, not refused), a relative path after a `cd` to the directory
above, or a file a script names. What keeps a secret is the
remote user's own permissions; arg rules keep an agent off the paths
nobody wants it on by accident.

### What a rule can and cannot refuse

**An unreadable command is never matched by any rule**, admitting or
refusing, command or arg: it is unmatched, asked about by default and
refused under `unmatched: "refuse"` -- and on a [shell route](#shell-routes)
refused either way. So no rule ever admits a command a
shell would read differently from its words, and `ls; rm -rf $HOME` is
never `ls **` and `rm **`. The converse is the caveat: a refuse rule decides
readable commands only. `sudo **` refused does not refuse `sudo reboot`
spelt `sudo $(echo reboot)`, or `sudo reboot #`, or a script that runs it, and
`rm x; echo $HOME` is unmatched, not refused -- under `unmatched: "ask"`
those are asked about, and a person sees them as sent. Refuse rules, arg
rules among them, are a convenience, carving a hole in a broader rule;
**only `unmatched: "refuse"` is a boundary**, and with it only what the
rules admit or ask about runs at all.

A command that is not UTF-8 is refused outright: it cannot be shown to a
person as it is.

## What the sandbox gets

A session with SSH routes has two more files in `/etc/frisket`, beside
`ca.crt` and `ca-bundle.crt`:

- **`ssh_known_hosts`**: the session's SSH CA, trusted for host
  certificates, `@cert-authority * ssh-ed25519 AAAA... frisket`.
- **`ssh_config`**: a `Host` block per route, with its `HostName`, `Port`
  and `User`.

Nothing points ssh at them; the sandbox's own ssh configuration does, as
chase's does:

```
# the sandbox's /etc/ssh/ssh_config, before any Host or Match block
Include /etc/frisket/ssh_config
GlobalKnownHostsFile /etc/frisket/ssh_known_hosts /etc/ssh/ssh_known_hosts
```

The SSH CA is ed25519, derived from the session's TLS CA key, so a session
restored after a restart keeps the CA its sandbox already trusts. Each
route's host certificate names the route and its address, and is valid
until the TLS CA expires; it is the only host key frisket offers, so the
sandbox trusts it through the CA or not at all. The sandbox needs no key,
and is asked for none: any user name is accepted, and logged as
`client_user`, never as who the command runs as.

## Host keys

The keys a route pins are the whole of the trust in the machine. The key the
machine presents must be one of them, byte for byte, as a known_hosts entry
would be: nothing is learnt on first use, a certificate is refused, and
nobody is ever asked about a key. frisket asks the machine for the pinned
keys' types only, so a machine that also has a key of a type it prefers
still presents the one pinned; an RSA key is asked for by its SHA-2
signatures first, and `ssh-rsa` last, for a machine too old for them. A
key that does not match fails the command, as below, with `reason=host key
not pinned` and the key's fingerprint in the log.

`ssh-keyscan -t ed25519 <address>` prints a key with the address before it,
which goes; check it against the machine's own
`/etc/ssh/ssh_host_ed25519_key.pub`.

## Logging in

frisket logs in on the first command a connection runs, and shares that
login between the connection's commands; one login lasts no longer than
the connection.

- **`agent`** is an ssh-agent's socket, dialled for each login and closed
  once it is over. The daemon is a system service: it has no
  `SSH_AUTH_SOCK`, so the path is written out -- gcr's is
  `/run/user/<uid>/gcr/ssh`, OpenSSH's own agent whatever `-a` gives it.
  Not under `/tmp`, which the daemon's PrivateTmp hides, and so not
  `ssh-agent`'s default. The daemon runs as `services.frisket.user`, which
  must be able to open it, and `/run/user/<uid>` is there only while that
  user is logged in.
- **`keyFile`** is an unencrypted private key, read at each login. An
  encrypted one fails, saying so: frisket has no passphrase, and an agent
  is the way to use one.
- **`passwordFile`** is a file holding a password, for a machine that takes
  no key -- sops-nix's `/run/secrets/<name>`, which the daemon's user must
  be able to read. It is read at each login, never when the document is
  checked, and never logged: the file's bytes, less one trailing newline
  (`\n` or `\r\n`), at most 4 KiB and not empty. frisket logs in with it by
  `password`, or by `keyboard-interactive` where that is all the machine
  offers, answering each prompt that hides what is typed with the password,
  in one round; a prompt that echoes, a second round that hides one --
  the password wrong, or a second factor -- and more than three rounds in
  all end the login rather than send the password somewhere it was not
  asked for. The password is tried once: one `password` refused is not
  offered again by `keyboard-interactive`, since a device that locks an
  account counts each. No error quotes it. A password the machine refused
  is not tried again for five minutes while the file still holds it -- a
  workload running a command in a loop would otherwise try a stale password
  once a connection, and lock a device that counts tries -- and one the file
  holds instead is tried at once.

A login that fails -- no agent, no key the server takes, a password file
missing or a password refused, a host key not pinned, a machine that does
not answer within ten seconds -- fails the
command, with exit status 255 and the reason on its stderr; where the
credential could not be read, the reason says what was wrong with it but
not where it is -- the file's or the agent's path is in the journal's line,
never the sandbox's stderr. So does a
machine that goes while a command runs -- rebooted, reset, or silent for
the 45 seconds frisket's keepalives give it -- since the command never said
how it ended.

## Shell routes

Some devices' SSH servers run their own CLI as the login shell, and that
CLI ignores the command an exec carries: `ssh modem xdslctl info` on a
Zyxel's ZySH opens the CLI and waits. A route with `"shell": true` is for
one. The sandbox's side is unchanged -- it runs `ssh modem xdslctl info
--show` as an exec like any other, and the command is decided as on any
route -- but upstream frisket opens a session with a terminal, `dumb` and of
no size, and a shell, and:

1. waits for the device to finish greeting: its banner and prompt, until it
   has printed nothing for 1.5 seconds. The last line it printed is taken as
   its prompt, if it is a short one.
2. types the command and a carriage return, as a terminal's Enter does.
3. waits for the command's output to finish: when it ends with the prompt
   and has printed nothing more for a quarter of a second, or, whatever it
   ends with, when it has printed nothing for 3 seconds -- so a device whose
   prompt frisket did not find takes that long for every command.
4. types `exit`, gives the device 2 seconds to close, and closes it -- but
   only where the prompt came back. Output that went quiet without it may
   be a command waiting on a question, a pager or a value, which `exit`
   would answer, so the shell is closed with nothing more typed into it.

What the command printed is the exec's stdout, once it has finished --
not streamed -- with the device's echo of the command taken off its start,
the prompt off its end, and its lines ended `\n`, not the terminal's `\r\n`.
That is **best effort**: the device draws its own echo and prompt, and one
that draws them otherwise has them left in. The exit status is 0, since a
CLI says nothing of how a command went but in what it prints. A device
that greeted with a prompt that did not come back after the command has
not been seen to finish it, and its output may be cut short: what it
printed is given, with exit status 255 and that said on stderr. The whole
conversation has 60 seconds; one that does not finish, a device that
prints more than 1 MiB, its greeting with it -- nothing past that is kept --
a device that closes before it is given the
command, and one that refuses the terminal or the shell fail the command
with exit status 255, what it had printed on stdout, and the reason on
stderr. A device that closes after the command -- the command may have been
what closed it -- has given its output, with status 0.

**Only one simple command of plain words is readable on a shell route.**
The device's shell is no shell of the POSIX family, and frisket knows
nothing of its grammar: what it can say is that a line of letters, digits
and `_@%+=:,./-`, words separated by spaces, is words to any shell, and
holds no byte a line editor reads as more than itself -- nothing to end the
line early, no tab or `?` to complete or ask for help. So `;`, `&&`, `||`,
`|`, a redirection -- `>/dev/null` included -- and a quote are unreadable on
a shell route, whatever they would be on another, since whether a device's
CLI reads them as operators is the device's business; so is a word
beginning `%` or `=`, as on any route, and a command longer than 255 bytes,
since a line editor that cut a longer line short would run the start of
it, a command nobody decided. Nothing is taken off a command: `env`,
`time`, `exec` and an assignment are words like any other, and a shell
route lists no `env` names. **An unreadable command is refused on a shell
route, whatever `unmatched` says**, and never asked about: it would be typed
into the device byte for byte, where a carriage return in it ends the line
and types a second command, a `^U` erases what came before it, and a line
too long is cut short -- none of which a person shown it could see or would
have decided. Its stderr says it is not one line of plain words. A readable
command no rule names is unmatched, as on any route.

**The sandbox's stdin is never sent** to a shell route's device: whatever it
sent would be typed into the device's shell as commands nobody decided. It
is not read at all, and a question about a command on a shell route has an
empty `body`.

A device old enough to need this is often old enough to offer only
`ssh-rsa` host keys, SHA-1 signatures: pinned, such a key is asked for by
`ssh-rsa` last, after its SHA-2 signatures (see [Host keys](#host-keys)),
and nothing else is widened for it. A Zyxel VMG4005-B50A on firmware V5.17
ABQA, which offers `curve25519-sha256`, `aes128-ctr` and `hmac-sha2-256`
and an RSA host key alone, takes no key and only a password, was checked
end to end so: `passwordFile` from sops-nix, `"shell": true`, and `xdslctl
info --show` given back as the device printed it, less the echo and the
`ZySH> ` prompt.

```json
{
  "name": "modem",
  "address": "192.168.1.1",
  "user": "admin",
  "hostKeys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAwCGFmQQ..."],
  "passwordFile": "/run/secrets/modem-password",
  "shell": true,
  "exec": [{ "command": "xdslctl info **" }],
  "unmatched": "refuse"
}
```

## What is refused

Each command is decided before anything reaches the machine. One refused,
by a rule, by `unmatched`, or by a person, is answered as a command that ran
and failed: `frisket: <route>: <reason>` on its stderr and exit status 126,
so the agent sees why.

Everything but a command is refused, on the connection, whatever the rules
say:

- **pty, shell and subsystem** requests from the sandbox, sftp included,
  on a shell route too. A pty refused is a
  warning to ssh, which goes on to run the command; a bare `ssh gateway`
  is refused its shell, and exits.
- **Forwarding**: `-L`, `-R`, `-D`, `-W`, agent forwarding and X11, each
  refused where it is asked for, and logged.
- **env** requests -- ssh's `SendEnv` and `SetEnv` -- and a second command
  on one channel. A route's `env` names are about what a command sets for
  itself in its own words, which are decided; a variable sent beside the
  command is not.

**sudo** has no support of its own yet. A command run with `sudo` is a
command like any other -- decided by its words, `sudo apt update` matched by
`sudo apt update` -- and it works where the machine's sudoers lets the user
run it without a password; there is no terminal for sudo to ask on.

## Asking

A command asked about goes to `services.frisket.asker` like a request (see
[docs/routes.md](routes.md#asking)), as a question with `"kind": "ssh"`:

```json
{"session": "...", "workspace": "/home/alice/Projects/site", "policy": "...",
 "kind": "ssh", "route": "gateway", "host": "gateway",
 "address": "192.168.1.1:22", "user": "admin",
 "command": "systemctl restart nginx", "body": "", "bodyMore": true,
 "operation": {"id": "systemctl-restart", "summary": "Restart a unit", "class": "write"}}
```

`operation` is the operation of the rule that decided, if it has one, and
`operations` every operation the command's simple commands were decided by,
where there are more than one -- `cd /srv && systemctl restart app` -- as
for a GraphQL request with several fields. `command` is exactly as the
sandbox sent it; `shell` is `true` on a [shell route](#shell-routes), where
it is typed into the device's own CLI, and absent elsewhere; and `body` the
start of its
stdin -- empty on a [shell route](#shell-routes), which sends none: its first 4 KiB, or what arrived before stdin was silent for half a
second, from the start -- `ssh host command` without `-n` holds stdin open
and sends nothing, and a question that waited for a first byte would wait
for ever. On an allow, `body` goes to the machine first and the rest streams
after it. A client that disconnects takes its question with it. As for a
request, a session has one question at a time, and with no asker every
command asked about is refused.

## Logging

One `ssh` line per command: `session`, `conn`, `channel`, `dst`, `route`,
`user` and `client_user`, `command` (its first 1024 bytes, control bytes
escaped), `decision`, `rule` (the rule that decided: its pattern, an arg rule's glob
after it as `[arg .ssh]`, or `unmatched`), `operation` (its operation's id,
or every part's, joined by commas, where there are several),
`asked` when a person was, `reason`, `exit_status` or `exit_signal`, the
bytes of stdin, stdout and stderr, `duration_ms` and `error`. A channel that
is not a session gets a line of its own with its `channel_type`, and a
connection that ran no command -- a handshake that failed, a shell refused,
a client that only looked at the host key -- gets one with `channels`.
