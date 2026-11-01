#!/usr/bin/env bash
# Pins one of Dan's repositories to a release tag in every place this repo
# takes it from: the flake input's url in flake.nix, so flake.lock records
# the tag beside its commit, and go.mod's require, which the binary is
# compiled from. Where it is both, the NAME-pin check holds the two to the
# same tag. A tag is cut by that repo's CI only once its checks pass, and
# never moves, so this never pins a commit CI has not passed. With no tag,
# the latest release. The weekly update runs it for every such repo.
#
#   scripts/pin.sh quoin v0.81.13
#   scripts/pin.sh quoin
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	echo "usage: scripts/pin.sh NAME [vMAJOR.MINOR.PATCH]" >&2
	exit 2
fi
name=$1
cd "$(git rev-parse --show-toplevel)"
repo="https://github.com/danielbodart/$name"
if [ $# -eq 2 ]; then
	tag=$2
else
	tag=$(git ls-remote --tags --refs "$repo" 'v*' | sed 's|.*refs/tags/||' |
		grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1)
fi
if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "pin: '$tag' is not a release tag" >&2
	exit 2
fi
if ! git ls-remote --exit-code --tags "$repo" "refs/tags/$tag" >/dev/null; then
	echo "pin: $name has no tag $tag" >&2
	exit 1
fi

in_flake=false in_gomod=false
if grep -q "url = \"github:danielbodart/${name}[/\"]" flake.nix; then in_flake=true; fi
if go mod edit -json | jq -e --arg m "github.com/danielbodart/$name" '.Require[]? | select(.Path == $m)' >/dev/null; then in_gomod=true; fi
if ! $in_flake && ! $in_gomod; then
	echo "pin: neither flake.nix nor go.mod takes $name" >&2
	exit 2
fi

if $in_flake; then
	sed -i -E "s|url = \"github:danielbodart/$name(/[^\"]*)?\";|url = \"github:danielbodart/$name/$tag\";|" flake.nix
	nix flake lock
fi
if $in_gomod; then
	# Straight to GitHub: the module proxy can be minutes behind a new tag.
	GOPROXY=direct GOFLAGS=-mod=mod go get "github.com/danielbodart/$name@$tag"
	go mod tidy
	scripts/vendor-hash.sh
fi
echo "pinned $name $tag"
