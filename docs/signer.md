# frisket-signer

An SSH agent whose keys live in the TPM. It signs without asking for
frisket's main process, for a terminal tab ssh-ing to a host in
`/etc/ssh/ssh_known_hosts`, for any program's login to a host you allow by
name, here or in the project's signed policy file, and for git's commit
signatures. Everything else is asked in galley: Allow once, Allow for a time
you pick, Refuse, or, from a project, Always.

```
$ git push                          # typed in a tab, github.com in ssh_known_hosts
                                    # signed, nothing asked

claude> git push                    # galley: "ssh to github.com"
                                    #   [Refuse] [Allow once] [Allow for 15 minutes ▾]

claude> git push                    # with ssh.hosts."github.com" = "allow"
                                    # signed, nothing asked

claude> git push                    # in ~/Projects/foo, courier on
                                    # galley: "ssh to github.com", with the diff
                                    #   [Refuse] [Allow once] [Allow for …] [Always]
                                    # Always: ~/Projects/foo/chase.json and its
                                    # .sig written, and the next push is silent
```

## Setup

```nix
{
  imports = [ inputs.frisket.nixosModules.signer ];

  services.frisket.signer = {
    enable = true;
    forUser = "alice";
  };
}
```

Then point the user's `SSH_AUTH_SOCK` at `/run/frisket-signer/agent`, and
let galley take questions from the signer:

```nix
services.galley.services = { ssh-signer = "SSH signer"; };   # home-manager
systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 alice alice -" ];
```

The signer starts with no keys, and on its first connection, which makes
its key directory. Start it, then move a key made by stock `ssh-tpm-keygen`
into place:

```
sudo systemctl start frisket-signer
sudo install -o ssh-signer -g ssh-signer -m 0600 ~/.ssh/id_ecdsa.tpm /var/lib/frisket-signer/
sudo systemctl restart frisket-signer
ssh-add -l
```

Only `ssh-signer` may open the TPM: evaluation fails if any normal user is
in `tss`. Log out and in after leaving it.

## Options

| Option | Default | Meaning |
|---|---|---|
| `enable` | `false` | Run the signer. |
| `forUser` | `"dan"` | The only user served, and whose galley is asked. |
| `terminal` | `"allow"` | A tab's direct sign to a host in `ssh_known_hosts`: `allow` or `ask`. |
| `sshsig.<namespace>` | `{ git = "allow"; }` | A direct SSHSIG sign in that namespace: `allow` or `ask`. Any other namespace is asked, Allow once. |
| `ssh.hosts.<name>` | `{ }` | A direct login from any program to the host key listed under `name` in `ssh_known_hosts`, or under a name the pattern `name` matches: `allow` or `ask`. |

`ssh.hosts` keys may be patterns: `*` alone is one label, `*` within a
label any run of it (`*-ap`), and `**` as the first label one or more
labels (`**.bodar.com`). A literal key beats a pattern; between patterns,
more whole literal labels win, then more literal bytes in the labels with
a `*`, then one without `**`; at a tie `ask` wins.

With `services.frisket.policy.courier.enable` (see [policy.md](policy.md)),
the signer also reads the asking program's project policy file, offers
Always, and serves `frisket policy sign`. It needs no option of its own:
the module writes the `policy` section below from `services.frisket.policy`.

The options are written to `/etc/frisket-signer/config.json`, which
`frisket-signer serve -config` reads, keys named as the options are:

```json
{ "forUser": "alice", "terminal": "allow", "sshsig": { "git": "allow" },
  "ssh": { "hosts": { "github.com": "allow" } },
  "policy": { "courier": "/run/frisket-policy/sock",
              "allowedSigners": "/etc/frisket/allowed_signers", "fileName": "chase.json" } }
```

A key it does not know, a value other than `allow` or `ask`, a host key
that is not a name or a pattern of one, or a `policy` path that is not
absolute stops it starting; the build runs `frisket-signer check` on the file first.
`frisket-signer schema` prints its JSON Schema.

frisket's main process is always trusted, a forwarded sign (`ssh -A`) is
always asked, and nothing is refused unasked but an SSHSIG in a
`frisket-policy` namespace, which `check` also refuses as an `sshsig` key,
and a `policy-sign` from frisket's main process or another user namespace.

## What is asked

In order, the first that applies:

1. A peer other than `forUser`: refused.
2. A login whose session or host key is not the one ssh bound: refused.
   So is an SSHSIG in any namespace starting `frisket-policy`, from
   anyone, frisket included, with the journal reason "a frisket-policy
   namespace is never signed raw": a project's policy is signed only where
   the signer sees its bytes (see [policy.md](policy.md)).
3. frisket's main process: signed.
4. A tab's shell running ssh, git, scp, sftp or rsync, to a known host,
   not forwarded: `terminal`.
5. Any program's login, not forwarded and its process chain not cut
   short, to a host key `ssh_known_hosts` lists under a name whose most
   specific `ssh.hosts` rule is `allow`: signed, as source `host`, or
   `project` when the rule is the project's. The rules are the host's with
   the project's `signer` section merged over them (RFC 7396: a project may
   add a rule, set one to `ask`, or delete one with `null`). A hashed
   entry, a pattern in `ssh_known_hosts` itself, or the same name with
   another key never matches.
6. An SSHSIG, not forwarded: its namespace's value, the project's merged
   over the host's (`sshsig`, or `project`).
7. A live grant for this process, host key, key and forwarding: signed.
8. Otherwise: asked. With no galley to ask, refused.

The project is the asking program's (the anchor's): the courier reads its
working directory up to the nearest policy file, as
[policy.md](policy.md) says. Its file applies only when its signature
verifies against `/etc/frisket/allowed_signers` in the project's namespace
and its `signer` section sets only `ssh.hosts` and `sshsig`; otherwise it is
ignored, with one `project policy ignored` line per file, and the decision
is as if there were none. So is a cut chain, a chain with no anchor, and a
courier that is down or not configured. A forwarded sign is never covered
by a project, as by the host's rules.

A grant covers the asking program (a claude, a tab's shell) until the time
you picked; a forwarded question's grant covers forwarded signs only.

**Always** is offered on a grantable, direct question to a known host when
the project is known (the courier found its policy file, or the program is
in a git repository under the home, where the file would be), its file is
absent or verifies and is canonical, and a key here may sign in its
namespace. The question carries the diff of the file it would write, the
current one with `signer.ssh.hosts."<name>": "allow"` merged in, canonical
(`{"version": 2}` when there is none), `<name>` the host key's first name in
`ssh_known_hosts`, and says "Always allows `<name>` from `~/Projects/foo`,
signed into its chase.json." On Always the signer signs the new file in
`frisket-policy:<root>`, has the courier write it and its `.sig` if the file
is still the one read, and signs the login. If the write fails, a change
made meanwhile say, the login is still signed, once, and the journal's
`always` line and a galley notification say the rule was not saved. Always
grants nothing beyond the file: a later login is decided by it.

`frisket policy sign FILE` signs a file you edited, a rule widened to a
pattern say, through the agent extension `policy-sign@frisket`: galley shows
the diff against the bytes the old `.sig` verifies over (`-old FILE`, else
git's `HEAD`), or against nothing, saying why, with Refuse and Allow once
only, and on Allow `FILE.sig` is written. FILE must already be canonical
(`frisket policy fmt`). It is refused unasked to frisket's main process,
which serves sandboxes, and to a process in another user namespace; a
sandbox's git signing socket refuses every extension in any case.
Allow once is the only choice for a sign ssh did not bind to a host, for an
SSHSIG, for a program launched straight from `systemd --user` or the
terminal server, and for a process chain cut short; galley shows the last
two with a warning. A question goes when
the ssh that asked exits.

A question shows the process chain from the asking program down. For a
commit's signature that is the claude or tab above `git commit`, since
git's `ssh-keygen -Y sign` is shown through; the decision, and the
journal's anchor, are still ssh-keygen's.

## Journal

```
journalctl -u frisket-signer -o cat | jq 'select(.msg == "decision")'
```

One `decision` record per sign: the chain, the anchor, the destination, the
key, the outcome, and its `source` (`frisket`, `terminal`, `host`,
`project`, `sshsig`, `grant`, `galley`, `always`, `nobody`, `hung up`),
with `project`, `project_digest` and `project_applies` when a project was
read. An `always` line says whether Always's file was `written` or `not
saved`, and why; a `project policy ignored` line why a file did not apply. A failed sign is one `sign failed`
line with the TPM's cause; ssh itself only says `agent refused operation`.

## Commit signing from a sandbox

frisket serves a policy's sandboxes an agent socket that only signs git
commits:

```nix
services.frisket = {
  gitSigning.agent = "/run/frisket-signer/agent";
  policies.strict.gitSigning = true;
};
```

```
$ ls -l /run/frisket-sign/strict
srw------- 1 alice users 0 ... agent
```

Bind `/run/frisket-sign/<policy>` into the sandbox at the same path and set
`SSH_AUTH_SOCK=/run/frisket-sign/<policy>/agent`. The socket lists the
signer's keys and passes on a sign whose data is an SSHSIG in the `git`
namespace, which the signer makes under `sshsig.git`. Every other sign,
key management, lock and every extension, `session-bind` among them, is
refused. Only `services.frisket.user` may connect, from any user namespace.
The directory is kept across a restart of frisket, so a bind of it stays
good. Each request is one `decision` line in frisket's journal, with the
policy, the peer's pid, the namespace and the outcome.

## Recovery

**TPM cleared, firmware update or new board.** Every sign fails with `TPM
cleared or a different chip`. Make a new key and swap it in:

```
sudo systemctl start frisket-signer-keygen
sudo cat /var/lib/frisket-signer/new/id_ecdsa.pub
sudo mv /var/lib/frisket-signer/new/id_ecdsa.tpm /var/lib/frisket-signer/
sudo systemctl restart frisket-signer
```

Authorize the new public key wherever the old one was (GitHub, your
servers, the other host), logging in with another machine's key; if every
machine lost its key, add it at each server's console. keygen refuses to
overwrite, so empty `new/` before it runs again.

**Dictionary-attack lockout.** Signs fail with `TPM is in
dictionary-attack lockout; signing resumes when it decays`. Wait for the
counter to decay, or clear it with the TPM's lockout auth:
`tpm2_dictionarylockout --clear-lockout`.

**Reinstall.** A key file from before is listed but never signs on another
chip or a cleared one; run keygen as above.

**Rollback.** `services.frisket.signer.enable = false`, and point
`SSH_AUTH_SOCK` back at your previous agent.
