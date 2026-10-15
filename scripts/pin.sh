#!/usr/bin/env bash
# Pins one of Dan's modules to a release tag in both places this flake takes
# it from: the input's url in flake.nix, so flake.lock records the tag beside
# its commit, and go.mod's require, which the binary is compiled from. The
# NAME-pin check holds the two to the same tag. A tag is cut by the module's
# CI only once its checks pass, and never moves, so this never pins a commit
# CI has not passed. vendorHash is then worked out again from go.sum.
#
#   scripts/pin.sh quoin v0.81.13
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: scripts/pin.sh NAME vMAJOR.MINOR.PATCH" >&2
	exit 2
fi
name=$1 tag=$2
if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "pin: $tag is not a release tag" >&2
	exit 2
fi
cd "$(git rev-parse --show-toplevel)"
if ! grep -q "url = \"github:danielbodart/${name}[/\"]" flake.nix; then
	echo "pin: flake.nix has no $name input" >&2
	exit 2
fi
if ! git ls-remote --exit-code --tags "https://github.com/danielbodart/$name" "refs/tags/$tag" >/dev/null; then
	echo "pin: $name has no tag $tag" >&2
	exit 1
fi

sed -i -E "s|url = \"github:danielbodart/$name(/[^\"]*)?\";|url = \"github:danielbodart/$name/$tag\";|" flake.nix
nix flake lock

# go straight to GitHub: the module proxy can be minutes behind a new tag.
go() { GOPROXY=direct GOFLAGS=-mod=mod nix shell --inputs-from . nixpkgs#go -c go "$@"; }
go get "github.com/danielbodart/$name@$tag"
go mod tidy

fake=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
old=$(sed -n 's/.*vendorHash = "\(sha256-[^"]*\)";.*/\1/p' flake.nix)
sed -i "s|$old|$fake|" flake.nix
got=$(nix build --no-link .#default 2>&1 | sed -n 's/.*got: *//p' || true)
if [ -z "$got" ]; then
	sed -i "s|$fake|$old|" flake.nix
	echo "pin: no vendorHash came out of the build; vendorHash is left as it was" >&2
	exit 1
fi
sed -i "s|$fake|$got|" flake.nix
echo "pinned $name $tag (vendorHash $got)"
