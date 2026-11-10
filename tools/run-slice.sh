#!/usr/bin/env bash
# Runs the vertical slice on both Satin implementations and prints, on standard output, exactly:
#
#   SLICE cases=<n> adapters=2 pass=<p> fail=<f> unsupported=<u> error=<e> digests=identical|differ
#   PARITY adapters=2 cases=<n> mismatches=<m>
#   NEGATIVE wrong-expected verdict=<pass|fail|...> rewritten=<no|yes>
#
# Everything else goes to standard error. It builds what it needs (the format CLI, the scenario
# checkouts under vendor/, both adapters), checks that slice/ is what tools/make_slice.py writes,
# consumes slice/cases with each adapter plain and instrumented (read-only), checks that the
# quarantined cases still fail exactly as recorded on the implementation they are recorded
# against and pass on the other, runs the deliberately wrong expectation, and fills candidates
# from both implementations into candidates/ to compare them with the spec-derived expectations.
# It exits nonzero when any of that does not hold.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
work="$target/run-slice"
rm -rf "$work"
mkdir -p "$work"
log() { echo "run-slice: $*" >&2; }

log "building"
bash "$root/tools/fetch-implementations.sh" >&2
(cd "$root" && CARGO_TARGET_DIR="$target" cargo build -q --locked -p mega-fixture-format --bin mega-fixture) >&2
for a in revm evm2; do
  (cd "$root/adapters/$a" && CARGO_TARGET_DIR="$target/adapter-$a" cargo build -q --locked) >&2
done
cli="$target/debug/mega-fixture"
adapter() { echo "$target/adapter-$1/debug/adapter-$1"; }
python3 -I "$root/tools/make_slice.py" --check >&2

# The slice's bytes before anything runs: consuming must rewrite nothing.
digest_tree() { (cd "$root/slice" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | cut -d' ' -f1); }
before=$(digest_tree)

status=0
for a in revm evm2; do
  for mode in plain instrumented; do
    flag=()
    [ "$mode" = instrumented ] && flag=(--instrumented)
    if ! "$cli" consume --adapter "$(adapter $a)" ${flag[@]+"${flag[@]}"} --specs "$root/specs" \
        --report "$work/$a-$mode.json" "$root/slice/cases" > "$work/$a-$mode.log"; then
      status=1
    fi
    tail -1 "$work/$a-$mode.log" >&2
    grep -v '^pass ' "$work/$a-$mode.log" | grep -v '^CONSUME ' >&2 || true
  done
  "$cli" consume --adapter "$(adapter $a)" --specs "$root/specs" --report "$work/$a-quarantine.json" \
    "$root/slice/quarantine" > "$work/$a-quarantine.log" || true
  "$cli" consume --adapter "$(adapter $a)" --specs "$root/specs" --report "$work/$a-negative.json" \
    "$root/slice/negative" > "$work/$a-negative.log" || true
done

# Fill candidates from the slice's own inputs (expectations and requirements removed) with each
# implementation, into the candidate namespace; they are compared with the derivation, never
# copied into it.
mkdir -p "$work/authoring"
python3 -I - "$root/slice/cases" "$work/authoring" <<'EOF'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
for name in sorted(os.listdir(src)):
    with open(os.path.join(src, name), encoding="utf-8") as f:
        case = json.load(f)
    for key in ("requires", "expected"):
        case.pop(key)
    case["provenance"] = {"authoring": case["provenance"].get("authoring"), "generator": "tools/run-slice.sh"}
    with open(os.path.join(dst, name), "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, sort_keys=True)
EOF
for a in revm evm2; do
  rm -rf "$root/candidates/filled-slice/$a"
  "$cli" fill --adapter "$(adapter $a)" --specs "$root/specs" --out "$root/candidates/filled-slice/$a" \
    "$work"/authoring/*.json > "$work/$a-fill.log" || true
  tail -1 "$work/$a-fill.log" >&2
done

after=$(digest_tree)
if ! python3 -I - "$work" "$root" "$before" "$after" <<'EOF'
import json, os, sys
work, root, before, after = sys.argv[1:5]
adapters, modes = ("revm", "evm2"), ("plain", "instrumented")
load = lambda name: json.load(open(os.path.join(work, name), encoding="utf-8"))
runs = {(a, m): {c["file"]: c for c in load(f"{a}-{m}.json")["cases"]} for a in adapters for m in modes}
files = sorted(runs["revm", "plain"])
ok = all(sorted(r) == files for r in runs.values())
n = len(files)
counts = {s: 0 for s in ("pass", "fail", "unsupported", "error")}
for a in adapters:
    for f in files:
        counts[runs[a, "plain"][f]["status"]] += 1
identical = ok
for f in files:
    seen = set()
    for r in runs.values():
        c = r[f]
        seen |= {c["inputDigest"], c["adapterInputDigest"]}
    identical = identical and len(seen) == 1 and None not in seen
mismatches = 0
for a in adapters:
    for f in files:
        p, i = runs[a, "plain"][f], runs[a, "instrumented"][f]
        if p["status"] != i["status"] or p["observationsDigest"] != i["observationsDigest"] or p["observationsDigest"] is None:
            mismatches += 1

# Quarantine: each case fails exactly as recorded on its recorded implementation, passes on the other.
index = json.load(open(os.path.join(root, "slice", "index.json"), encoding="utf-8"))
names = {"mega-eest-adapter-revm": "revm", "mega-eest-adapter-evm2": "evm2"}
held = {a: {c["caseId"]: c for c in load(f"{a}-quarantine.json")["cases"]} for a in adapters}
recorded = 0
for q in index["quarantine"]:
    k = q["knownFail"]
    bad = names[k["adapter"]]
    other = "evm2" if bad == "revm" else "revm"
    got, good = held[bad].get(q["caseId"]), held[other].get(q["caseId"])
    if (got and got["status"] == "fail" and got["path"] == k["path"] and got["expected"] == k["expected"]
            and got["actual"] == k["actual"] and good and good["status"] == "pass"):
        recorded += 1
print(f"run-slice: quarantine: {recorded} of {len(index['quarantine'])} fail exactly as recorded on their implementation "
      f"and pass on the other", file=sys.stderr)

# The wrong expectation: every adapter fails it at the recorded path.
verdicts = set()
for a in adapters:
    for c in load(f"{a}-negative.json")["cases"]:
        wrong_at = {x["caseId"]: x["wrongAt"] for x in index["negative"]}.get(c["caseId"])
        verdicts.add(c["status"] if c["status"] != "fail" or c.get("path") == wrong_at else "fail-elsewhere")
verdict = verdicts.pop() if len(verdicts) == 1 else "mixed"

# The candidates the filler wrote, against the spec-derived expectations.
for a in adapters:
    d = os.path.join(root, "candidates", "filled-slice", a)
    equal = total = 0
    for f in files:
        case = json.load(open(f, encoding="utf-8"))
        cand = os.path.join(d, case["caseId"] + ".json")
        if os.path.exists(cand):
            total += 1
            cj = json.load(open(cand, encoding="utf-8"))
            equal += cj["expected"] == case["expected"] and cj["provenance"]["status"] == "candidate"
    print(f"run-slice: filler {a}: {total} candidates in candidates/filled-slice/{a}, {equal} equal to the derivation",
          file=sys.stderr)

rewritten = "no" if before == after else "yes"
print(f"SLICE cases={n} adapters=2 pass={counts['pass']} fail={counts['fail']} unsupported={counts['unsupported']} "
      f"error={counts['error']} digests={'identical' if identical else 'differ'}")
print(f"PARITY adapters=2 cases={n} mismatches={mismatches}")
print(f"NEGATIVE wrong-expected verdict={verdict} rewritten={rewritten}")
good = (counts["pass"] == 2 * n and identical and mismatches == 0 and verdict == "fail" and rewritten == "no"
        and recorded == len(index["quarantine"]))
sys.exit(0 if good else 1)
EOF
then
  status=1
fi
exit $status
