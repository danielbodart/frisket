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
the project's own running containers publishes it there. The session's
names, `<label>.internal` and `<label>.<owner>.internal`, resolve to that
address in its DNS, before the allowlist; the rest of `.internal`, such as
`metadata.google.internal` and `docker.frisket.internal`, resolves as before.
Its own names are logged `decision=local`, never asked upstream and never
recorded for egress. Under `allow = ["*"]`, another project's name may be
answered by the host's resolver from `/etc/hosts`, but its address is not
steered and egress refuses loopback, so the session cannot reach it.
A name equal to or under `frisket.internal` or `google.internal` is never
generated, and a document whose names equal or fall under one of its own
route hosts does not load. The names say `internal`, not `docker`, because
the address will later carry the session's own dev servers too.
