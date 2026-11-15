#!/usr/bin/env bash
# The files a release carries: one bare static binary per platform,
# frisket-<V>-<os>-<arch>, and SHA256SUMS over them. nix/release.json
# (scripts/release-json.sh) names each by URL and hash, and the flake's
# package is the one for its system.
#
# usage: scripts/release-assets.sh VERSION OUT [DIR ...]     (default DIR: dist)
#
# Each DIR is searched for <os>-<arch>/frisket, as scripts/build.sh lays
# dist/ out, or as actions/download-artifact unpacks the build job's
# artifact. Every platform must be found exactly once, and the one this
# machine can run must say it is VERSION, so a release can never carry a
# binary stamped with another version than its tag. The other cannot be run
# here, so it must at least contain VERSION's bytes, which -X main.version
# put there.
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: scripts/release-assets.sh VERSION OUT [DIR ...]" >&2
    exit 2
fi
version=$1
out=$2
shift 2
dirs=("$@")
[ ${#dirs[@]} -gt 0 ] || dirs=(dist)

if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release-assets: '$version' is not MAJOR.MINOR.PATCH" >&2
    exit 2
fi

# The platforms every release ships for, in Go's GOOS-GOARCH names.
platforms=(linux-amd64 linux-arm64)

case $(uname -m) in
x86_64) host=linux-amd64 ;;
aarch64 | arm64) host=linux-arm64 ;;
*) host=none ;;
esac
[ "$(uname -s)" = Linux ] || host=none

mkdir -p "$out"
checked=false
for platform in "${platforms[@]}"; do
    found=()
    while IFS= read -r -d '' f; do found+=("$f"); done \
        < <(find "${dirs[@]}" -type f -path "*/$platform/frisket" -print0)
    if [ ${#found[@]} -ne 1 ]; then
        echo "release-assets: want exactly one $platform/frisket under ${dirs[*]}, found ${#found[@]}" >&2
        exit 1
    fi
    asset="$out/frisket-$version-$platform"
    # 0755 because actions/upload-artifact does not keep the mode.
    install -m 0755 "${found[0]}" "$asset"
    if [ "$platform" = "$host" ]; then
        said=$("$asset" version)
        if [ "$said" != "$version" ]; then
            echo "release-assets: $platform's binary says it is $said, not $version" >&2
            exit 1
        fi
        checked=true
    elif ! grep -qaF -- "$version" "$asset"; then
        echo "release-assets: $platform's binary does not contain $version, so it was not stamped with it" >&2
        exit 1
    fi
done
if ! $checked; then
    echo "release-assets: no binary for this machine, so none was asked its version" >&2
    exit 1
fi

# sha256sum's own format, sorted by name.
(cd "$out" && sha256sum "${platforms[@]/#/frisket-$version-}" | LC_ALL=C sort -k2 >SHA256SUMS)
ls -l "$out"
