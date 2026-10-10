# frisket-signer

An SSH agent whose keys live in the TPM. It signs without asking for
frisket's main process, for a terminal tab ssh-ing to a host in
`/etc/ssh/ssh_known_hosts`, and for git's commit signatures. Everything
else is asked in galley: Allow once, Allow for a time you pick, or Refuse.

```
$ git push                          # typed in a tab, github.com in ssh_known_hosts
                                    # signed, nothing asked

claude> git push                    # galley: "ssh to github.com"
                                    #   [Refuse] [Allow once] [Allow for 15 minutes ▾]
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

The signer starts with no keys. Move a key made by stock
`ssh-tpm-keygen` into place:

```
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

frisket's main process is always trusted, a forwarded sign (`ssh -A`) is
always asked, and nothing is refused unasked.

## What is asked

In order, the first that applies:

1. A peer other than `forUser`: refused.
2. A login whose session or host key is not the one ssh bound: refused.
3. frisket's main process: signed.
4. A tab's shell running ssh, git, scp, sftp or rsync, to a known host,
   not forwarded: `terminal`.
5. An SSHSIG, not forwarded: its namespace's value.
6. A live grant for this process, host key, key and forwarding: signed.
7. Otherwise: asked. With no galley to ask, refused.

A grant covers the asking program (a claude, a tab's shell) until the time
you picked; a forwarded question's grant covers forwarded signs only.
Allow once is the only choice for a sign ssh did not bind to a host, for an
SSHSIG, for a program launched straight from `systemd --user` or the
terminal server, and for a process chain cut short; galley shows the last
two with a warning. A question goes when
the ssh that asked exits.

## Journal

```
journalctl -u frisket-signer -o cat | jq 'select(.msg == "decision")'
```

One `decision` record per sign: the chain, the anchor, the destination, the
key, the outcome, and its `source` (`frisket`, `terminal`, `sshsig`,
`grant`, `galley`, `nobody`, `hung up`). A failed sign is one `sign failed`
line with the TPM's cause; ssh itself only says `agent refused operation`.

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
