# Recording

A recording session finds out what a sandbox needs by letting it do the one
thing that was refused, and writing down every rule that would have stopped
it. Something is refused; you run `chase record --default allow claude`, do
the action, and exit; what is left is one line for each request, command,
connection and name the policy would have refused or asked about -- precise
enough for chase to turn into the grant entries the action needed.

A session records when its policy document has a `record` block. chase
writes one into the document it launches `chase record` with, and never
otherwise; nothing in a project's own files can ask for it.

```json
{
  "name": "chase-trusted",
  "allow": ["api.github.com"],
  "routes": [ ... ],
  "record": {
    "default": "allow",
    "sink": "/var/lib/frisket/records/chase-trusted-4127.jsonl"
  }
}
```

- `default` is `allow`, `ask` or `refuse`: the answer to every subject, with
  nobody asked. `allow` and `ask` both let it through now and differ only in
  what is recorded -- a grant entry that allows, or one that asks. `refuse`
  refuses it, as the policy would have, and records that. Absent or empty,
  each subject is put to the asker (below), and the person's answer does the
  same. A document with no default needs a daemon with an asker, or it is
  refused when the session opens.
- `sink` is a file the lines are appended to as well as the journal, which
  rate-limits: by its absolute path, directly in the daemon's
  `-record-dir` -- `/var/lib/frisket/records` under the NixOS module. It is
  created 0600, not followed if it is a link, and bounded at 64 MiB, after
  which one `{"truncated": true}` line ends it. Absent, the journal alone.

## What a recording decides

Everything a policy decides by its rules:

- **a route's request** the scope refuses or asks about: a path rule's
  refusal or question, a request no rule matches, a git push, a GraphQL
  field, and what a GraphQL request does that frisket cannot see. Guarded
  operations included: recording is manual mode.
- **an SSH route's command** the rules refuse or ask about.
- **a connection to a name off the allowlist.** The session's DNS resolves
  every name while recording -- the answer kept apart from the allowlist's,
  in a set of its own -- so that a connection to one can be decided by the
  name and port it was for.
- **a connection to the local network, by name**: a private (RFC 1918),
  unique-local or link-local address that the session's DNS gave for any
  name, allowed or not. Not the host's own addresses, not a router the host's
  routing tables name, not a cloud's metadata service, and never loopback,
  CGNAT, multicast or an address written inside a v6 one: those stay
  structural refusals. A v6 link-local address resolved by name has no zone,
  and so cannot be dialled.

What the policy allows is served as ever, silently, and logged as ever.

A connection is matched to its name by its address, as egress always has: an
address the session's DNS gave for a name is that name's while the answer
lives, so a literal dial to it is decided as that name, and an address an
allowed name shares -- a CDN's -- is admitted as the allowed name's, and
leaves no line. Reading the name a connection is for from the connection
itself is the next phase's.

A subject admitted while recording is served as an admitted one is: a
request carrying the placeholder goes upstream with the real credential,
since the person recording is driving; a command runs over frisket's own
login. Its ordinary log line says `rule` `recorded`.

Each subject is decided once a session. Its first answer is written down and
stands for the rest of the session, a refusal as much as an admission: a
second request for the same operation, the same command, or the same name and
port is answered the same, with nothing asked and nothing written. Two at
once wait for one answer. The want of an answer -- the asker failing, the
client gone -- is not remembered, and the next time asks again. Answers are
kept in the daemon's memory alone: a session restored after a restart starts
with none, and its sink goes on.

## What a recording never overrides

Each is refused as in any session, and written down with `source` `hard`
where there is a subject to name:

- every structural refusal but the local network's above, and every address
  dialled by itself: a literal IP, or an answer held past its life, has no
  name to grant;
- a credential or placeholder that does not hold, a stale credential, a
  `Host` that is not the SNI, a method override that disagrees or is no
  method, a path that is not canonical;
- anything on a Docker route: its refusals keep a session to its own
  project, and its questions go to the asker as in any session;
- a command a shell route cannot read -- a line break, an operator, a quote
  -- which would be typed into a device's CLI byte for byte;
- the CA: still constrained to the routes' hosts, so a name that is not a
  route's is spliced, never intercepted, and never carries a credential.

## The lines

One JSON object per line, in the sink and as a `record` line in the journal.
Every line has `time`, `session`, `policy`, `kind`, `would` (what the policy
would have done: `refuse` or `ask`), `answer` (`allow`, `ask` or `refuse`)
and `source`:

- `default`: the record block's default answered;
- `human`: a person answered, through the asker;
- `unanswered`: put to the asker and refused for want of an answer, with
  `reason` saying why; never remembered;
- `hard`: refused as in any session, with `reason`;
- `telemetry`: a name resolved off the allowlist; nothing was decided at DNS.

`rule` is what decided for the policy: a path rule's reason (`path`,
`refused by rule`, `out of scope`, `unmatched`, `git`, `graphql`, `push not
allowed`), an SSH rule's pattern or `unmatched`, `not allowed` for a name off
the allowlist, or `structural: private` (`unique-local`, `link-local`) for
the local network. The rest depends on `kind`:

```json
{"time":"2026-10-02T21:14:03.5Z","session":"chase-trusted-4127","policy":"chase-trusted","kind":"http",
 "route":"github","method":"DELETE","host":"api.github.com","path":"/repos/o/r/git/refs/heads/x",
 "operation":"git/delete-ref","would":"ask","rule":"path","answer":"allow","source":"default"}
{"time":"...","session":"...","policy":"...","kind":"ssh","route":"server","user":"ops",
 "address":"192.168.1.20:22","command":"systemctl restart nginx","operation":"restart",
 "would":"ask","rule":"systemctl restart *","answer":"ask","source":"human"}
{"time":"...","session":"...","policy":"...","kind":"egress","name":"registry.npmjs.org","port":443,
 "address":"104.16.1.34:443","would":"refuse","rule":"not allowed","answer":"allow","source":"default"}
{"time":"...","session":"...","policy":"...","kind":"egress","name":"nas.lan","port":445,
 "address":"192.168.1.20:445","lan":true,"would":"refuse","rule":"structural: private",
 "answer":"allow","source":"default"}
{"time":"...","session":"...","policy":"...","kind":"egress","address":"203.0.113.9:443",
 "would":"refuse","rule":"not resolved by this session","answer":"refuse","source":"hard",
 "reason":"not resolved by this session"}
{"time":"...","session":"...","policy":"...","kind":"dns","name":"registry.npmjs.org",
 "would":"refuse","rule":"not allowed","answer":"allow","source":"telemetry"}
```

- `http`: `route`, `method`, `host`, `path` (escaped, as sent, without its
  query; 2 KiB at most), `operation` -- the matched rule's id, every one
  comma-joined for a request holding several -- and `graphql`, what a GraphQL
  request was read as. The subject is the operation where a rule named one,
  and the exact path where none did.
- `ssh`: `route`, `user`, `address`, `command` (exactly as sent; 4 KiB at
  most), `operation` as for `http`, and `shell` on a shell route. The
  subject is the command.
- `egress`: `name` and `port`, `address` the ip:port dialled, and `lan` for
  the local network. The subject is the name and port.
- `dns`: `name`. Once a session per name.

Only metadata: never a body, a header, a query string or a command's stdin.

## The sink's place

The daemon runs as the user whose credentials it holds, under
`ProtectSystem=strict`, so the one place it writes is a directory systemd
makes for it: `StateDirectory=frisket/records`, which is
`/var/lib/frisket/records`, the user's own and 0700, kept across a restart.
The user's `chase record` reads a session's file there after the session
ends, and, being its owner, can remove it; no sandbox binds `/var/lib`, so
none can read another session's lines, or its own. A daemon without
`-record-dir` keeps no records, and refuses a document with a sink.

## Asking

With no default, each subject is put to `services.frisket.asker` as any
question is, with `record` set, and an `id` naming the subject within its
session -- the same for a second asking, different for any other. A
connection is asked about with `kind` `egress`, `host` the name and `address`
the ip:port. The asker's answer is one of three: see
[routes.md](routes.md#asking) for how it says which. A recording session's
questions are never refused for being busy: each waits its turn.
