#!/usr/bin/env bash
# Replays passive-client vectors through mls-rs (AWS Labs).
#
#   tools/mlsrs-verifier/run.sh <vectors.json>
#
# Clones mls-rs at $MLSRS_TAG into $MLSRS_DIR (default: a build dir next to
# this script), appends a test that replays the vectors the way mls-rs's own
# passive-client KAT does, and runs it. Exits non-zero if any vector fails.
set -euo pipefail

vectors="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "$0")" && pwd)"
tag="${MLSRS_TAG:-0.56.0}"
dir="${MLSRS_DIR:-$here/build/mls-rs-$tag}"

if [ ! -d "$dir" ]; then
  git clone --quiet --depth 1 --branch "$tag" https://github.com/awslabs/mls-rs.git "$dir"
fi

kat="$dir/mls-rs/src/group/interop_test_vectors/passive_client.rs"
grep -q "mlskmp_authored_vectors" "$kat" || cat "$here/mlskmp_passive_client.rs" >> "$kat"

cd "$dir"
MLSKMP_PASSIVE_VECTORS="$vectors" cargo test -p mls-rs --lib --features test_util mlskmp_authored_vectors -- --nocapture 2>&1 | tee test-output.log
grep -q "test result: ok. 1 passed" test-output.log
