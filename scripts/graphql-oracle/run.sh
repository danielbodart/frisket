#!/usr/bin/env bash
# Regenerates ../../internal/graphql/testdata/ruby.json: documents made to
# find where two GraphQL readers disagree, each with what graphql-ruby --
# GitHub's reader -- makes of it, or null where it refuses one. internal/graphql's tests hold frisket to it:
# a document frisket accepts, graphql-ruby must read the same way.
#
#   scripts/graphql-oracle/run.sh [N [SEED]]
#
# What it found first is why frisket refuses a CR without an LF: graphql-ruby
# runs a comment on past one, where the spec, and every other reader tried,
# ends it.
set -o errexit
set -o nounset
set -o pipefail

version=2.6.11
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../internal/graphql/testdata/ruby.json"
n=${1:-30000}
seed=${2:-1}
gems=$(mktemp -d)
trap 'rm -rf "$gems"' EXIT

nix shell nixpkgs#ruby nixpkgs#python3 --command bash -c "
    set -o errexit -o pipefail
    gem install --silent --no-document --install-dir '$gems' graphql -v $version >/dev/null
    python3 '$here/generate.py' $n $seed > '$gems/docs.json'
    GEM_PATH='$gems' ruby '$here/ruby.rb' < '$gems/docs.json' > '$gems/ruby.json'
    python3 - '$gems/docs.json' '$gems/ruby.json' '$out' '$version' <<'PY'
import json, sys
docs, ruby = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
# Every document graphql-ruby reads, and a thousand it refuses: those frisket
# must refuse too, or read the same way if it ever stops refusing them.
read = [{'doc': d, 'ruby': r} for d, r in zip(docs, ruby) if r is not None]
cases = read + [{'doc': d, 'ruby': None} for d, r in zip(docs, ruby) if r is None][:1000]
json.dump({'graphql-ruby': sys.argv[4], 'cases': cases}, open(sys.argv[3], 'w'), ensure_ascii=True, indent=0)
print(f'{len(docs)} documents, {len(read)} read by graphql-ruby', file=sys.stderr)
PY
"
