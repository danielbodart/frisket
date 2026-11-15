#!/usr/bin/env bash
# The static frisket binary for every platform a release ships for, into
# dist/<os>-<arch>/frisket, with the version stamped in. CI's build job runs
# it with the Go mise.toml pins; a release carries what it makes, and the
# flake's package is that release binary (flake.nix says why).
#
# usage: scripts/build.sh [os/arch ...]     (default: linux/amd64 linux/arm64)
#
# Linux only: frisket holds listeners in a sandbox's network namespace and
# steers with nftables (PLAN.md decision 2), none of which exists elsewhere.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version=$(scripts/version.sh)
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(linux/amd64 linux/arm64)

for target in "${targets[@]}"; do
    os=${target%/*}
    arch=${target#*/}
    out="dist/$os-$arch"
    mkdir -p "$out"
    # A STATIC BINARY, with no cgo: frisket runs as a systemd unit with
    # ProtectSystem=strict, and cgo would drag in glibc's NSS, which resolves
    # names through whatever the host's nsswitch.conf says. -trimpath so the
    # binary names no path on the machine that built it.
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=$version" \
        -o "$out/frisket" ./cmd/frisket
    echo "$out: $version"
done
