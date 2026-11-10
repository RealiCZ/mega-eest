#!/usr/bin/env bash
# Verifies a downloaded differential-corpus release archive against its pinned digest and prints
# its member inventory (docs/corpus-archive.md). It only reads the archive; it neither mirrors nor
# converts anything. Needs shasum, zstd, tar and python3.
#
#   tools/verify_corpus.sh <mega-evm2-corpus.tar.zst> [<scratch-dir>]
set -euo pipefail
archive=$1
scratch=${2:-$(cd "$(dirname "$0")/.." && pwd)/target/verify-corpus}
pinned=7a6e3dd2512e5631d18ac8367a8b6a8ea1ad5a255d456b13321fb50268da62fa  # release corpus-2026-11-10
got=$(shasum -a 256 "$archive" | cut -d' ' -f1)
if [ "$got" != "$pinned" ]; then
  echo "verify_corpus: digest $got, pinned $pinned" >&2
  exit 1
fi
echo "verify_corpus: archive sha256 $got, $(wc -c < "$archive" | tr -d ' ') bytes: matches the pin"
mkdir -p "$scratch/outer" "$scratch/reference"
zstd -dc "$archive" | tar -xf - -C "$scratch/outer"
zstd -dc "$scratch/outer/mega-evm2-corpus/reference/reference-outputs.tar.zst" | tar -xf - -C "$scratch/reference"
python3 -I - "$scratch" <<'PY'
import glob, json, os, sys
s = sys.argv[1]
outer = os.path.join(s, "outer", "mega-evm2-corpus")
members = [os.path.relpath(os.path.join(d, f), outer) for d, _, fs in os.walk(outer) for f in fs]
print(f"verify_corpus: {len(members)} files in the archive")
for set_ in ("d4", "p9", "rot"):
    m = json.load(open(os.path.join(outer, "real-blocks", set_, "manifest.json")))
    print(f"  real-blocks/{set_}: {len(m)} recorded blocks in its manifest")
ref = os.path.join(s, "reference")
main = json.load(open(os.path.join(ref, "satin-oracle.json")))
print(f"  reference satin-oracle.json: {len(main)} scenario records")
fuzz = {os.path.basename(f)[:-5]: len(json.load(open(f))) for f in sorted(glob.glob(os.path.join(ref, "oracles", "*.json")))}
print(f"  reference oracles/: {len(fuzz)} fuzz batches, {sum(fuzz.values())} records")
for d in ("satin", "satin-block"):
    for set_ in sorted(os.listdir(os.path.join(ref, "raw", d))):
        print(f"  reference raw/{d}/{set_}: {len(os.listdir(os.path.join(ref, 'raw', d, set_)))} block outputs")
PY
