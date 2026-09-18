#!/usr/bin/env bash
# The version, DERIVED from the repository rather than stored in it.
#
# Only the MAJOR is committed (in ./VERSION) -- it is the one part that is a
# deliberate decision, and 0 says the option interface is still moving. MINOR
# is the commit count, so it only ever rises and names exactly one commit.
# PATCH is the CI run number, or a local timestamp, separating two builds of
# the same commit -- a re-run or a manual build -- and making a developer
# build sort after CI's and obviously not one of CI's.
#
# (Scheme from mogwai-db and dragoman, which lifted it from tidewaiter. Shell
# rather than TypeScript because nothing else here needs a runtime.)
set -euo pipefail

major=$(tr -d '[:space:]' < "$(git rev-parse --show-toplevel)/VERSION")

# Counted from HEAD, not a branch name: on Actions the checkout is detached,
# and a pull request ref is not a rev at all.
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
    echo "version: shallow clone, so the commit count and the version are wrong." >&2
    echo "         In Actions, check out with \`fetch-depth: 0\`." >&2
    exit 1
fi

minor=$(git rev-list --count HEAD)
patch=${GITHUB_RUN_NUMBER:-$(date -u +%Y%m%d%H%M%S)}

printf '%s.%s.%s\n' "$major" "$minor" "$patch"
