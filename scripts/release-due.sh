#!/usr/bin/env bash
# Whether the commit checked out is due a release: prints true and exits 0
# if anything a release is built from changed since the last release, else
# prints false and exits 1. With no release yet, it is due. CI's release
# job and the weekly update ask it (mise run release-due).
#
# What a release is built from is RELEASE_PATHS, which mise.toml sets (and
# says why), plus mise.toml's Go pin: a release's binaries are compiled by
# scripts/build.sh with the Go mise.toml pins, not by the flake's, so a Go
# patch, often a security fix to crypto/* or net, is a new release. A bump
# of shellcheck changes no binary and is not.
set -euo pipefail
unset CDPATH
shopt -s inherit_errexit

cd "$(git rev-parse --show-toplevel)"

if [ -z "${RELEASE_PATHS:-}" ]; then
    echo "release-due: RELEASE_PATHS is not set; run it as mise run release-due" >&2
    exit 2
fi
read -ra paths <<<"$RELEASE_PATHS"

due() { echo true; exit 0; }

# The trunk commit the last release was made from, which is the parent of
# its tag's commit, not the tag's own commit (scripts/last-release.sh):
# that adds nix/release.json, which is the release's output, not its input.
read -r _ last < <(scripts/last-release.sh) || due

[ -z "$(git diff --name-only "$last" HEAD -- "${paths[@]}")" ] || due

# The `go = "..."` line of mise.toml's [tools] at a revision, empty if
# there is none.
gopin() {
    git show "$1:mise.toml" 2>/dev/null |
        sed -n -E '/^\[tools\]/,/^\[/s/^"?go"? *= *"([^"]*)".*$/\1/p'
}
[ "$(gopin "$last")" = "$(gopin HEAD)" ] || due

echo false
exit 1
