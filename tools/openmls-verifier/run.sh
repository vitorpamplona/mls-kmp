#!/usr/bin/env bash
# Replays passive-client vectors through OpenMLS (the engine under MDK).
#
#   tools/openmls-verifier/run.sh <vectors.json>
#
# Clones OpenMLS at $OPENMLS_TAG into $OPENMLS_DIR (default: a build dir next
# to this script), appends a test that feeds the vectors to OpenMLS's own
# passive-client KAT runner, and runs it. Exits non-zero if any vector fails.
set -euo pipefail

vectors="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "$0")" && pwd)"
tag="${OPENMLS_TAG:-v0.9.2}"
dir="${OPENMLS_DIR:-$here/build/openmls-$tag}"

if [ ! -d "$dir" ]; then
  git clone --quiet --depth 1 --branch "$tag" https://github.com/openmls/openmls.git "$dir"
fi

kat="$dir/openmls/src/group/mls_group/tests_and_kats/kats/passive_client.rs"
grep -q "test_mlskmp_authored_vectors" "$kat" || cat "$here/mlskmp_passive_client.rs" >> "$kat"

cd "$dir"
MLSKMP_PASSIVE_VECTORS="$vectors" cargo test -p openmls --lib test_mlskmp_authored_vectors -- --nocapture 2>&1 | tee test-output.log
grep -q "test result: ok. 1 passed" test-output.log
