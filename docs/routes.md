# Routes

What a route can do beyond adding a token. The basics are in the
[README](../README.md). The examples are version 1 documents, which chase
writes; [Version 2](#version-2) is the shape layers are merged in.

## Credential files

A credential file is read by the daemon, as `user`, and re-read when replaced,
by rename too. The option is a string, so the file is never copied into the
store. Keep it out of `/tmp`, which the daemon cannot see.

A file that is not a bare token is read as JSON, at dotted paths. Claude Code's
own login, which the host's sessions keep refreshed:

```nix
credentialFile = "/home/alice/.claude/.credentials.json";
credentialJSON = {
  token = "claudeAiOauth.accessToken";
  expiresMillis = "claudeAiOauth.expiresAt";  # past it, 503 rather than a stale token
};
```

Where the expiry is inside the token rather than beside it, as codex's login
keeps it, `expiresJWT` names the JWT to read `exp` from -- usually the token
itself. The claim is read, not verified:

```nix
credentialFile = "/home/alice/.codex/auth.json";
credentialJSON = {
  token = "tokens.access_token";
  expiresJWT = "tokens.access_token";
};
```

Clients retry a 503 quietly, so a credential that stays expired is logged once,
at error, when requests first find it so, and once more when it is fresh again.

## git

GitHub takes a token for git only as Basic auth's password. With the
sandbox's git sending the placeholder there:

```nix
routes.github = {
  host = "github.com";
  upstream = "https://github.com";
  credentialFile = "/run/secrets/gh-token";
  placeholder = "proxy-injected";
  basicUser = "x-access-token";
  git = { repos = [ "*" ]; push = "ask"; };   # or [ "owner/repo" ... ]
  paths = [ { methods = [ "GET" "HEAD" ]; prefix = "/"; } ];  # releases, archives
};
```

```ini
# the sandbox's /etc/gitconfig
[url "https://github.com/"]
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[credential "https://github.com"]
	helper = !gh auth git-credential   # GH_TOKEN=proxy-injected
```

`git` admits `info/refs` and `git-upload-pack` for the listed repositories,
matched by segment, and decides `git-receive-pack` as `push` says: `refuse`,
the default, `ask` or `allow`. It decides every git-shaped request, so a
refused push is refused at its ref advertisement even where `paths` admits
`GET`. One asked about admits the advertisement, which says no more than a
fetch's, and asks once, at the push, as the operation `git-receive-pack`: the
body the asker is shown opens with the refs it would update, and the pack
streams after it. Without `credentialFile`, the same route is
read-only GitHub with nothing of yours on it: what the sandbox sends goes on as
it came, for what the scope admits.

## Wildcard routes

```nix
allow = [ "*.googleapis.com" ];
routes.google = {
  host = "*.googleapis.com";
  upstream = "https://*.googleapis.com";      # the name each request was made to
  credentialFile = "/run/secrets/gcp-token.json";
  credentialJSON = { token = "access_token"; expiresMillis = "expiry"; };
  placeholder = "proxy-injected";
  unmatched = "ask";
};
routes.google-mtls = {
  host = "*.mtls.googleapis.com";
  upstream = "https://*.mtls.googleapis.com";
  paths = [ { methods = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ]; prefix = "/"; refuse = true; } ];
};
```

`*.googleapis.com` is every name below it, at any depth, and not
`googleapis.com` itself. A name's exact route serves it, and failing that the
nearest wildcard above it, so `iam.mtls.googleapis.com` is refused. Each
request goes to the name the client asked for, on the upstream's port if it
names one, verified as that name; a request for another name on the same
connection is 421. The allowlist must cover the wildcard whole, and the
session's CA is constrained to `googleapis.com`.

## Session keys

A client that signs its own tokens -- Google's, with a service-account key
file -- is given a key made for the session, and its route the public half:

```json
"sessionKey": {
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "issuer": "agent@project.iam.gserviceaccount.com",
  "grants": ["oauth2.googleapis.com/token", "www.googleapis.com/oauth2/v4/token"]
}
```

- A JWT-bearer grant posted to one of `grants`, whose assertion the key signed
  as `issuer`, for one of those URLs, at most an hour long, is answered by
  frisket: `{"access_token": <placeholder>, "expires_in": 3599, "token_type":
  "Bearer"}`, or an ID token signed by nobody when it asks for
  `target_audience`. The log says `credential: answered`. Anything else sent
  there is 400, and nothing sent to a grant URL, however it is spelt, ever
  leaves.
- A bearer JWT the key signed, RS256, as `issuer`, in date and at most an hour
  long, whose audience is `https://<host>/` for a host the route serves or
  which has a `scope` and no audience, is the placeholder, and replaced. One the key signed that fails
  any of that is 403. Any other bearer goes upstream as it was sent.

The key is made per session, so a document with one is a launcher's
(`policyFile`), not the module's.

## GraphQL

A GraphQL endpoint is one path whose body says what each request does, so a
route's `graphql` rules decide it by the body: a query by `query`, and a
mutation or subscription by the rule for each field at its root, named as the
schema names it. A request is decided by the strictest of everything its
document holds -- every field of every operation -- so nothing sent beside a
field loosens its rule. A field no rule names is the endpoint's `unmatched`
-- `refuse`, the default, `ask` or `allow`. frisket knows GraphQL and no API's schema: the fields come from the
configuration, and chase generates them from the provider's published one.

```nix
graphql = [{
  path = "/graphql";
  query.operation = { id = "graphql-query"; summary = "A GraphQL query"; class = "read"; };
  mutations = [
    { field = "closePullRequest"; ask = true; operation = { id = "closePullRequest"; summary = "Close a pull request."; class = "write"; category = "pulls"; }; }
    { field = "deleteRepository"; refuse = true; }
  ];
  unmatched = "ask";
}];
```

The body is read (1 MiB at most) before anything is decided, and what goes
upstream is exactly what was read. A field is found through fragment spreads
and inline fragments at the root, by its name and never its alias, and a
skipped one counts as run; a fragment is followed once however often it is
spread. The rule decides at its path and at any spelling that may reach the
same handler -- `/graphql/`, `/GraphQL`, `/graphql/v4`, `/graphql.json`.

What frisket cannot see is never admitted: it is asked about, or refused
where `unmatched` refuses. That is a request that may run something its
document does not show -- a key other than `query`, `operationName` and
`variables`, a persisted query's hash among them -- and one frisket cannot
read at all: anything but a POST of `application/json` with no query string
and no `Content-Encoding`, a batch, a key twice, a body over 1 MiB, a
document it refuses, or one with more than 16384 selections to follow at its
roots. Beside what the document does show, the strictest decides. The rule decides every request at its path, whatever the method,
before any path rule.

Documents are read strictly, to the October 2021 grammar, and anything two
readers could disagree about is refused rather than resolved: outside a
string, only printable ASCII, tab, LF and CRLF -- a CR alone ends a comment to
the spec and not to graphql-ruby, GitHub's reader, which reads on past it into
what the spec calls code; a comment is printable ASCII; a string holds no
escaped surrogate. `internal/graphql`'s tests hold frisket to graphql-ruby on
documents made to find where readers disagree (`scripts/graphql-oracle`):
whatever frisket reads, graphql-ruby reads the same way.

## Asking

A route can put a request to a person instead of deciding it. A path rule
names one operation exactly with `path`, a `*` segment matching any one
segment and `*:verb` one ending in `:verb` (Google's custom methods, the
colon unencoded and the verb in its case), and `ask = true` holds a matching
request while the asker decides; `unmatched = "ask"` does the same for
anything no rule matches, and `refuse = true` refuses what it matches
outright -- a hole in a broader rule. Where several rules match, the most
specific decides, segment by segment from the left -- a literal beats
`*:verb`, that beats `*`, and each beats the end of a prefix -- and between
equals, the stricter: refusing, then asking, then admitting. Neither a
question nor a refusal can be spelt around: a request is also read as
leniently as an upstream might -- decoded, case-folded, a `;parameter` or
trailing dot dropped, an encoded slash taken either way, `%3A` as a colon --
and a stricter rule that matches that reading decides.

A `*` never matches a segment holding an encoded slash, which an upstream
might read as two, unless its rule has `encodedSlashes = true`: Cloud
Storage's `/storage/v1/b/*/o/*`, whose object names are one segment.

```nix
routes.cloudflare = {
  host = "api.cloudflare.com";
  upstream = "https://api.cloudflare.com";
  credentialFile = "/run/secrets/cloudflare-token";
  placeholder = "proxy-injected";
  unmatched = "ask";
  paths = [
    { methods = [ "GET" "HEAD" ]; path = "/client/v4/zones/*/dns_records/*"; }
    {
      methods = [ "DELETE" ];
      path = "/client/v4/zones/*/dns_records/*";
      ask = true;
      operation = {
        id = "dns-records-for-a-zone-delete-dns-record";
        summary = "Delete DNS Record";
        description = "Permanently removes a DNS record from the zone.";
        class = "guarded";   # read, write or guarded: shown, never matched on
        category = "DNS Records for a Zone";
      };
    }
  ];
};
```

frisket ships no dialog. `services.frisket.asker` names a program, run as the
daemon's user inside its sandbox, once per question and one at a time. The
question is one JSON document on stdin:

```json
{"session": "...", "workspace": "/home/alice/Projects/site", "policy": "...",
 "route": "cloudflare", "method": "PATCH", "host": "api.cloudflare.com",
 "path": "/client/v4/zones/023e/dns_records/372e", "query": "...",
 "body": "{\"content\":\"203.0.113.9\"}", "bodyMore": false, "bodyLength": 26,
 "operation": {"id": "...", "summary": "...", "description": "...",
               "class": "write", "category": "..."}}
```

A GraphQL request holding several fields has every one's in `operations`, and
`operation` is the one that decided.

A request with a body is asked about by its start: `body` is its first 4 KiB,
or what arrived before it paused for half a second -- a streaming RPC sends
one message and waits -- `bodyMore` whether it went on past that, and
`bodyLength` the length it declared, if it did. A body is waited for until
its first byte, so a question never shows an empty start of a body still to
come; one without a body is asked about at once. On an allow, `body` goes
upstream first and the rest streams after it, however long it is: what a
person admits is the start of a body.

Exit 0 admits the request, 1 declines it, and anything else refuses it and is
logged as the asker failing. On 0 or 1, and only then, the asker may answer on
stdout instead: one line, `allow`, `ask` or `refuse`, in any case, 64 bytes at
most, which stands in place of the status. `ask` admits the request as `allow`
does; a [recording session](record.md) records it as one to keep asking
about. Nothing on stdout leaves the status to answer, and anything else there
is the asker failing -- never a yes. zenity answers so already:

```sh
zenity --question --ok-label=Allow --cancel-label=Refuse --extra-button=Ask ...
```

prints nothing and exits 0 for Allow, 1 for Refuse, and prints `Ask` and exits
1 for Ask. Offer the third button when the question has `record` set: one
from a recording session. Every question has an `id`, the same for a second
asking of the same subject in a session -- the operation, where a rule named
one, or the exact path -- and different for any other.

`operation` is absent when nothing matched, and it
is the only prose in the question: it comes from the configuration, and
everything else is the workload's, to be shown as the request. A client that
stops waiting takes its question with it: queued, it is never asked; open, the
asker's process group is sent SIGTERM. With no asker, every ask is refused.

One question is open at a time, daemon-wide, and each session has one
question at most: another while one waits is refused at once, so no sandbox
can queue ahead of another's or bury a question among many. An asker that
stacks its questions in one window can take more of both:
`services.frisket.askerConcurrent` and `askerPerSession` (the same keys in
`/etc/frisket/config.json`), one each by default. A recording session's
questions are never refused for being busy: each waits its turn.

Where several rules match, an admission never depends on how literally the
upstream reads its paths: a rule that asks, and matches the request read
leniently -- another case, a trailing slash, a `;parameter`, a trailing dot --
asks, unless the rule that admits is more specific. An operation named with
`path` always outranks a `prefix`.

A method override is the method: `X-HTTP-Method-Override`, `X-HTTP-Method`,
`X-Method-Override`, and `$httpMethod` or `_method` in the query or a POST's
form body (up to 1 MiB), are taken, upper-cased, stripped, and everything
after -- a session key's grant, every rule, the question, the log line and
the request upstream -- is that method. A form a POST names `GET` for goes
upstream as the GET's query. Overrides that disagree, or name no method, are
400.

A gRPC call's log line carries its `grpc_status`, from its trailers: its HTTP
status is 200 whatever happened.

A refusal is plain text unless the route gives it the API's own error shape,
which a client then reads and reports:

```nix
refusal = {
  contentType = "application/json";
  body = builtins.toJSON {
    success = false;
    errors = [{ code = 403; message = "{{message}}"; }];
    messages = [ ];
    result = null;
  };
};
```

`{{message}}` is frisket's reason and the matched operation's summary --
`frisket: refused: declined (Create a Namespace)` -- never the request's.

### Always

A version 2 route or SSH machine marked `"always": true` -- a field only the
host sets, for a route whose answers a project's file is merged into, which
chase marks and strict's tiers never are -- offers Always on its questions,
when frisket's settings name the signer and the courier (`always` in
`/etc/frisket/config.json`, which the module fills in when both are on). The
question then also has:

```json
{"always": true,
 "diff": {"path": "~/Projects/site/chase.json",
          "old": "<the file as it is, or empty for none>",
          "new": "<the file with the one rule added>"}}
```

The rule is the specific one asked about: the request's operation id, or
failing one its `METHOD /exact/path`, under `frisket.routes.<route>.operations`;
an SSH command's literal words, under `frisket.ssh.<machine>.exec`, for a
command that is one simple command of plain words. It is offered only where
it would stand: the session's workspace's file (`services.frisket.policy.fileName`)
is absent or verifies and is canonical, with no `chase.jsonc`-style commented
form beside an absent one; the rule merged over the session's document by
`frisket check -layer project`'s own check admits the request, so no ceiling
holds it at ask; and the question is not a recording's. A request holding
several operations, a Docker route's, or a path a rule would read as a
pattern is offered none.

`always` on stdout, with exit 0 or 1, answers it, and only such a question may
be answered so. galley shows both and prints it: `jq -c .diff | galley
--question ... --diff=- --always`, the diff as JSON on stdin, which
`systemd-run --user --pipe` passes on where a file in frisket's private
`/tmp` would not reach. The request is admitted, and the rule admits what it
names for the rest of the session at once, logged with rule `always`.
Meanwhile frisket's main process has frisket-signer's `policy-sign@frisket`
sign the new file, approved -- the answer was the approval, so the signer asks
nothing more, and takes approved from no one else -- and the courier writes it
and its `.sig` over the file as read; the next launch merges it. A sign or
write that fails (the file changed meanwhile, say) leaves the request
admitted for the session, logs `always` with `outcome` `not saved`, and puts a
notice to the asker: `{"kind": "notice", "text": "…"}`, said rather than
asked, its exit and stdout answering nothing.

## Version 2

A document with `"version": 2` says all of the above in the shape every layer
of a policy is written in ([policy.md](policy.md#frisket-the-policy-document-version-2)):
each collection an object keyed by what each entry is, so that a layer
merged over another by JSON Merge Patch adds or deletes one entry. A route
says what its requests *are*, in `paths`, and how each is *answered*, in
`operations` and its class answers; frisket answers each request when it is
made.

```json
{
  "version": 2,
  "name": "work",
  "allow": {"api.github.com": true, "github.com": true, "**.googleapis.com": true},
  "writes": "ask", "guarded": "refuse", "unmatched": "ask",
  "ceiling": {"guarded": "ask"},
  "routes": {
    "api": {
      "host": "api.github.com",
      "upstream": "https://api.github.com",
      "credentialFile": "/run/secrets/gh-token",
      "placeholder": "proxy-injected",
      "paths": {
        "POST /repos/*/*/pulls":   {"operation": {"id": "pulls/create", "summary": "Create a pull request", "class": "write", "category": "pulls"}},
        "POST /repos/*/*/issues":  {"operation": {"id": "issues/create", "summary": "Create an issue", "class": "write", "category": "issues"}},
        "DELETE /repos/*/*":       {"operation": {"id": "repos/delete", "summary": "Delete a repository", "class": "guarded", "category": "repos"}},
        "GET /repos/*/*":          {"operation": {"id": "repos/get", "summary": "Get a repository", "class": "read", "category": "repos"}}
      },
      "graphql": {"/graphql": {
        "query": {"operation": {"id": "graphql-query", "summary": "A GraphQL query", "class": "read"}},
        "mutations": {"closePullRequest": {"operation": {"id": "closePullRequest", "summary": "Close a pull request.", "class": "write", "category": "pulls"}}}
      }},
      "operations": {
        "pulls/create": "allow",
        "category:issues": "ask",
        "GET,HEAD /**": "allow",
        "POST /repos/me/*/dispatches": "allow"
      }
    },
    "github": {
      "host": "github.com", "upstream": "https://github.com",
      "credentialFile": "/run/secrets/gh-token", "placeholder": "proxy-injected", "basicUser": "x-access-token",
      "git": {"repos": {"*": true}},
      "operations": {"git-receive-pack": "ask", "GET,HEAD /**": "allow"}
    }
  }
}
```

A request is answered by the first of these that says:

1. `operations` by the **id** of the operation the request is -- the most
   specific `paths` entry that matches it (ranked as path rules are), a
   GraphQL field, or git's push, `git-receive-pack` -- then by
   **`category:<its category>`**;
2. `operations` by the most specific **endpoint pattern** that matches it,
   `"METHOD[,METHOD] /path"`: `*` is one segment (`*:verb` one ending so), a
   last `**` any number of them, none included (`/a/**` is version 1's
   prefix `/a`), a literal beats a pattern and an exact path any `**`;
3. the route's answer for the operation's **class**: `writes` for `write`,
   `guarded` for `guarded`, and `unmatched` for a request no operation
   describes, or one whose operation has no class; a `read` is allowed;
4. the document's;
5. the built-in: writes ask, guarded refuse, unmatched refuse (an SSH
   route's, ask).

Then it is **clamped**: an answer more lenient than the route's `ceiling` or
the document's for its class is the ceiling's, `allow` < `ask` < `refuse`, the
stricter winning. A read has no ceiling. So an id answer decides even where a
narrower pattern says otherwise, but never past a ceiling, and an operation
answered by its class is overruled by any pattern that matches the request,
however wide. `unmatched` may now be `allow`, and what it admits is still
held to any stricter operation or pattern a lenient reading of the request
matches, as every admission is.

git and GraphQL decide every request at their paths first, as in version 1:
a push is `git-receive-pack`, of class `write`, and a GraphQL field is
answered by its operation's id (its name where it has none), then category,
then class; a field no entry names is the endpoint's `unmatched`, else the
route's, else the document's. `encodedSlashes` names the path templates --
or single endpoints, `"GET /storage/v1/b/*/o/*"` -- whose `*` takes a segment
holding an encoded slash.

An SSH route answers in `exec`, keyed by the rule as execrule names one:
`"systemctl status *"`, `"less ** [arg +*]"`, `"[arg .ssh]"` for every
command; an arg rule answered `allow` is no rule, since one only tightens.
`commands`, by the same key, is what each rule is, and a rule there that
`exec` does not answer is answered by its class. An SSH key that is a host
pattern, `"*-ap"`, is no machine: its `exec`, `env` and answers apply to
every machine whose name it matches, the machine's own winning and a
narrower pattern's over a wider one's. `unmatched: "allow"` admits every
readable command no rule matches and refuses what cannot be read.

Hosts: `allow` and `lan` keys are names or host patterns, the signer's grammar
(hostpattern): `*` one label, `*` within a label a run of it (`*-ap.lan`),
and `**` as the first label one or more -- so version 1's `*.example.com` is
`**.example.com` here, and `*` is `**`. A route's `host` is a name or
`**.suffix`, its `upstream` `https://**.suffix` to match. A lan pattern needs
a literal label, and reaches only names the allowlist allows too.

Version 1 says nothing version 2 cannot:

| Version 1 | Version 2 |
|---|---|
| `{methods: [GET, HEAD], prefix: "/v1"}` | `operations: {"GET,HEAD /v1/**": "allow"}` |
| `{methods: [DELETE], path: "/x/*", ask: true, operation: {id: d, ...}}` | `paths: {"DELETE /x/*": {operation: {id: d, ...}}}`, `operations: {d: "ask"}` |
| `{..., refuse: true}` with no operation | `operations: {"DELETE /x/**": "refuse"}` |
| `encodedSlashes: true` on a rule | `encodedSlashes: {"GET /b/*/o/*": true}` |
| route `unmatched: "ask"` | route `unmatched: "ask"` |
| `git: {repos: [o/r], push: ask}` | `git: {repos: {"o/r": true}}`, `operations: {"git-receive-pack": "ask"}` |
| GraphQL `mutations: [{field: f, refuse: true}]` | `mutations: {f: {}}`, `operations: {f: "refuse"}` |
| SSH `exec: [{command: c, arg: g, ask: true}]` | `exec: {"c [arg g]": "ask"}` |
| `allow: ["*.example.com", "*"]` | `allow: {"**.example.com": true, "**": true}` |

`tests/fixtures` holds the repository's version 1 documents each with its
version 2 equivalent, decided the same by a test, request for request.
`frisket check -http ROUTE DOCUMENT` answers lines of `METHOD /path` on stdin
as the route's scope would before reading a body -- answer, reason and
operation -- for either version, and `frisket check` says on stderr of a
version 2 document each pattern in it that can never match.
