# Docker

A route whose upstream is a Docker Engine (`docker`) holds a session to its
own project's objects. It carries no credential (no placeholder, header or
credential file), and it is the one place frisket changes a request, only to
narrow it: it forwards the query and a JSON body
as it re-encoded them from what it checked; replaces a container's or
network's name or ID prefix in the path with the full ID it verified; adds
`frisket.project=<project>` to the labels of what it lets be created and
merges it into the label filter of what it lets be listed; and binds a
published address that is empty, absent, `0.0.0.0` or `127.0.0.1` to the
project's own loopback address, refusing any other; and, for a request with
a body, sets `Content-Type: application/json` and removes `Content-Encoding`,
so the daemon reads the body frisket wrote. In the response it caps
`Api-Version` at the route's highest version. Each change is logged in
`docker`.

A session reaches its project's containers at `127.0.0.1:P`, `[::1]:P` and
the project's address `:P`, for each port P the project names. Its ruleset
steers those to frisket's existing listener on 15001, and frisket relays each
connection only to the project's address on that port, and only while one of
the project's own running containers publishes it there. The project's
name, `<repo>.<owner>.internal` -- lower-cased and otherwise as the slug
spells it, so `bodar/bodar.ts` is `bodar.ts.bodar.internal` -- resolves to
that address in the session's DNS, before the allowlist; the rest of
`.internal`, such as `metadata.google.internal` and
`docker.frisket.internal`, resolves as before. It is logged
`decision=local`, never asked upstream and never recorded for egress. Under
`allow = ["*"]`, another project's name may be answered by the host's
resolver, but its address is not steered and egress refuses loopback, so the
session cannot reach it. An owner whose name would be or fall under
`frisket.internal` or `google.internal` gets no name, nor does a repo
glibc could not resolve (an empty label, as `.github`'s, or a `-` first),
and a document whose name equals or falls under one of its own route hosts
does not load. The name says `internal`, not `docker`, because the address
carries the session's own dev servers too.

Two projects whose slugs hash to one address both run: each session's relay
reaches only what a container with its own project's label publishes there.

## On the host

`frisket dns` (`services.frisket.hostDNS.enable`) answers the same names on
the host, so a browser reaches a project's containers by name. The name is
the whole lookup: `<repo>.<owner>.internal` reads back as `owner/repo`,
since an owner has no dots, and its address is the hash -- so there is no
registry, nothing to keep in step with the projects a machine has, and a
project cloned a minute ago resolves. It forwards nothing: anything else
under `.internal` is NXDOMAIN and anything outside it REFUSED. systemd binds
its socket, 127.0.0.153:53 by default, and it runs as a DynamicUser that can
open no socket of its own. Point the host's resolver at it for `.internal`
alone -- with systemd-resolved, a drop-in of `DNS=127.0.0.153` and
`Domains=~internal`.
