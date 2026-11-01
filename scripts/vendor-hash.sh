#!/usr/bin/env bash
# Works flake.nix's vendorHash out again from go.mod and go.sum: builds the
# package with lib.fakeHash and writes back the hash Nix reports. Run after
# anything moves a Go dependency (scripts/pin.sh, the weekly update).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fake=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
old=$(sed -n 's/.*vendorHash = "\(sha256-[^"]*\)";.*/\1/p' flake.nix)
if [ "$(wc -l <<<"$old")" -ne 1 ] || [ -z "$old" ]; then
	echo "vendor-hash: flake.nix must have exactly one vendorHash" >&2
	exit 1
fi
sed -i "s|$old|$fake|" flake.nix
got=$(nix build --no-link .#default 2>&1 | sed -n 's/.*got: *//p' || true)
if [ -z "$got" ]; then
	sed -i "s|$fake|$old|" flake.nix
	echo "vendor-hash: no hash came out of the build; vendorHash is left as it was" >&2
	exit 1
fi
sed -i "s|$fake|$got|" flake.nix
echo "vendorHash $got"
