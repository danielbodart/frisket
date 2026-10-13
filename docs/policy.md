# A project's signed policy

A project may hold its own policy file, beside its code: `chase.json`, say,
with a section per component. It counts only when a stock SSHSIG beside it,
`chase.json.sig`, verifies over its exact bytes, by a key in root's allowed
signers, in a namespace that names the project's directory
(`quoin-policy:~/Projects/foo`). [policy-plan.md](policy-plan.md) is the
plan, and says what reads the file and how "Always" writes it.

The file itself -- its signature and namespace, the canonical form, the
allowed signers (`/etc/quoin/allowed_signers`, from
`services.quoin.policy.allowedSigners`), finding it, the courier that
carries it between the home and the programs that cannot read it, the
signer's and the sudo gate's reading of it, `quoin policy verify`, `fmt`,
`signers` and `sign`, and package `projpolicy` -- is
[quoin](https://github.com/danielbodart/quoin)'s, which these were moved to
from frisket; see quoin's
[docs/policy.md](https://github.com/danielbodart/quoin/blob/trunk/docs/policy.md).
frisket imports quoin's packages to read and write it, so the two read it
the same way. This page is what frisket does with the file: Always, and its
`frisket` section, a layer of a session's policy document.

frisket does not name the file, nor where the allowed signers are: its
module's `services.frisket.always.fileName` and `allowedSigners` do, which
the host sets to what it gave quoin.

## frisket: Always in a session

A session's question about an HTTP request or an SSH command, on a version 2
route or machine its document marks `always`, offers Always with the diff of
its workspace's file -- the workspace frisket was given by flong's hook,
`$workspace`, which the session cannot choose -- adding the specific rule:
the operation id or `METHOD /exact/path` under `frisket.routes.<route>.operations`,
or the command's literal words under `frisket.ssh.<machine>.exec`. It is
offered when the file is absent or verifies, against the allowed signers in
the workspace's namespace, and is canonical, and when the rule, merged over
the session's document as `check -layer project` merges, admits the request.
See [routes.md](routes.md#always) for the question and the answer.

Answered always, the rule admits for the rest of the session at once, and
frisket's main process asks quoin-signer's `policy-sign@quoin` (quoin's
package `policysign`) to sign the new bytes with `approved` set: the signer
trusts a unit for that only when its `services.quoin.signer.policySigners`
names it, which a host running both makes `frisket.service`, so the person's
answer in that question is the approval and nothing more is asked. The
signer refuses `approved` from anyone else. frisket checks the signature
against the allowed signers and has quoin-courier (quoin's package
`courier`) write the file and its `.sig` with the digest it read:
`frisket.service` is one of the courier's peers, as its user,
`services.quoin.policy.courier.peers."frisket.service"`, since its own home
is read-only to it.
A failed sign or write is logged as `always` `not saved` and said in a notice
through the asker; the request stays admitted for the session.

`services.frisket.always.enable` is off unless the host turns it on, with
`always.signer`, `always.courier`, `always.allowedSigners` and
`always.fileName`, which the module asserts are set: frisket's module reads
no option of quoin's. It writes `always` into `/etc/frisket/config.json`:
those four and the home a namespace is named from. For quoin's modules'
defaults that is:

```nix
services.frisket.always = {
  enable = true;
  signer = "/run/quoin-signer/agent";
  courier = "/run/quoin-courier/sock";
  allowedSigners = "/etc/quoin/allowed_signers";
  fileName = "chase.json";
};
services.quoin.signer.policySigners = [ "frisket.service" ];
services.quoin.policy.courier.peers."frisket.service" = config.services.frisket.user;
```

## frisket: the policy document, version 2

A project's `frisket` section is a layer of the session's policy document,
merged with quoin's `projpolicy.MergePatch` over the layers under it -- frisket's
defaults, a tier, the host's -- into a version 2 document, `"version": 2`,
which frisket reads beside version 1 (still what chase generates) for one
release. Its shape and how a request is answered are in
[routes.md](routes.md#version-2); `frisket schema` prints its JSON Schema.

Every collection a layer adds to or takes from is an object keyed by what
each entry is -- `allow` and `lan` by name or host pattern, `routes` and
`ssh` by name, a route's `paths` and `operations` by operation id,
`category:<name>` or `"METHOD /path"`, an SSH route's `exec` and `commands`
by rule -- so a layer adds an entry by naming it and deletes one with `null`:

```json
{"frisket": {
  "allow": {"pypi.org": true, "old.example": null},
  "routes": {"github": {"operations": {"pulls/create": "allow", "category:issues": "ask", "repos/delete": null}}},
  "ssh": {"*-ap": {"exec": {"uci show **": "allow"}}}
}}
```

Arrays are replaced whole, and are kept for what only the host sets (a
machine's `hostKeys`, a lan name's `ports`). A whole document has no `null`:
a null is a layer's, to delete with, and a key twice in one object is refused,
where JSON's decoders would keep the last.

### Field scope

A field only the host may set has `"x-scope": "host"` in the schema: the
document's `name`, `record`, `interactive` and `ceiling`; a route's `host`, `upstream`,
`upstreamCA`, `credentialFile`, `credentialJSON`, `header`, `basicUser`,
`placeholder`, `refusal`, `sessionKey` and `docker`, which say where a request
goes and what it carries, `always`, and its `paths`, `graphql`, `git`, `encodedSlashes`
and `ceiling`, which say what a request is and so which class answers it and
which ceiling holds it -- a project that could reclassify a guarded operation
could lift it past its ceiling; an SSH machine's `address`, `user`, `hostKeys`,
`agent`, `keyFile`, `passwordFile`, `identity`, `shell`, `commands`,
`always`, `interactive` -- whether an interactive shell, nothing typed into
which is decided, may be opened on it ([ssh.md](ssh.md#interactive-shells))
-- and `ceiling`. A project answers: `allow`, `lan`, `operations`, `exec`, `env`,
`writes`, `guarded`, `unmatched`.

```
frisket check -layer project -base BASE [-section frisket] LAYER
```

refuses a layer that sets or deletes a host field, has a key the schema does
not, defines a route or SSH machine `BASE` does not (a key that is a host
pattern, under `ssh`, is answers for the machines it matches, not a machine),
or deletes one, which takes its host fields with it; it refuses a pattern
the layer writes that can never match -- a path with a dot or empty segment,
which frisket refuses before any rule, a GraphQL endpoint's own path, an
endpoint whose operation is answered by name and so never by a pattern, a
host pattern in capitals or with a byte no name holds, an SSH pattern that
matches no machine; and then it merges the layer over `BASE` and checks the
result as `frisket check` checks a document, an operation id or category no
operation of the route has included. `-section` reads the layer from one key
of the file, as `chase.json` keeps frisket's under `frisket`.

## For chase

The file's own reading -- `Verify`, `Sign`, the allowed signers, `Find`,
`Load`, the canonical form, `MergePatch` -- is quoin's package
`github.com/danielbodart/quoin/projpolicy`, which chase and frisket both
import.

For the gateway's document, `github.com/danielbodart/frisket/policy` has
`DocumentV2` and its parts, `Load` (either version, as `version` says),
`DecodeV2`, `Lower` (a version 2 document as the gateway builds it),
`CheckProjectLayer(layer, base)` (what `check -layer project` does, short of
building the result), `Unreachable` and `SchemaV2`; and
`github.com/danielbodart/quoin/hostpattern` is the host-key grammar quoin's
signer and frisket's `allow`, `lan` and `ssh` share.
