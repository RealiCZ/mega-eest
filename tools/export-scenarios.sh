#!/usr/bin/env bash
# Exports the evm2-based implementation's differential scenarios into the candidate namespace:
# candidates/exported/ holds one authoring document per converted scenario and summary.json, which
# accounts for every scenario. Nothing here is a fixture yet: `mega-fixture fill` completes a
# candidate with an implementation's observations into candidates/filled/<adapter>/, and only a
# review against the rule text promotes one.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
bash "$root/tools/fetch-implementations.sh" >&2
(cd "$root/exporter" && CARGO_TARGET_DIR="$target/exporter" cargo build -q --locked)
out="$root/candidates/exported"
rm -rf "$out"
mkdir -p "$out"
"$target/exporter/debug/scenario-dump" > "$out/scenarios.jsonl"
EXPORT_SOURCE_COMMIT=$(git -C "$root/vendor/mega-evm" rev-parse HEAD) \
  python3 -I "$root/tools/export_scenarios.py" "$out/scenarios.jsonl" "$out"
