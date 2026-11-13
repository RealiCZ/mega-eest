#!/usr/bin/env python3
"""Convert the differential gates' scenarios into candidate `state-transition` authoring documents.

Input: the JSON lines `exporter/` (scenario-dump) writes, one hand-written scenario of
`mega-evm2-scenarios` per line. Output, into a candidate namespace (never `examples/` or a
release): one authoring document per converted scenario — a fixture without `requires` and
`expected`, which `mega-fixture fill` completes with an implementation's observations — and
`summary.json`, which counts every scenario by disposition and gives each exclusion its reason.

The conversion follows docs/corpus-inventory.md §1:

- integer conveniences become full-width keys and quantities;
- per-transaction limit and detention-cap overrides (`Limits`) and the simulation switches
  `skip_nonce_check` and `skip_eip3607` are not chain inputs: such scenarios are excluded to the
  parameterized-model lane (decision D-11);
- the scenario senders have no keys, so every transaction is a `synthetic` message, pre-recovered
  EIP-7702 authorities included; deposits become deposit envelope bytes;
- SALT `(address, slot or account, multiplier or capacity)` entries become bucket capacities under
  `salt-v1`, the unlisted buckets minimal (`complete`), as both gates have them;
- a scenario with earlier transactions of its block needs a block profile, one with oracle answers
  needs their request order for a transcript, and one with an L1 fee needs signed bytes: each is
  excluded with that reason, to be converted when its profile or input exists.

The scenario's own rule ids are kept as the candidate's rules where the pinned registry has them
as active rules, unreviewed until a reviewer names the rules the case pins (D-76); the name and
group stay as aliases. Each authoring document is written at `<out-dir>/<caseId>.json`, the slice's
layout. A candidate is evidence for review, never an expectation by itself.

Usage:
    tools/export_scenarios.py <scenarios.jsonl> <out-dir>

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_examples as ex  # noqa: E402
import salt_mapping  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SPEC_DIR = os.path.join(ROOT, "specs", "satin-d34e626")
SOURCE = {
    "crate": "mega-evm2-scenarios",
    "repository": "https://github.com/RealiCZ/mega-evm",
    "path": "next/diff/shared",
}
BLOCK = {
    # The block both gates run every scenario in.
    "number": "0x1", "timestamp": hex(1_000), "gasLimit": hex(10_000_000_000), "baseFee": "0x0",
    "prevRandao": "0x" + "00" * 32, "parentHash": "0x" + "00" * 32, "parentTimestamp": hex(999),
    "parentBeaconBlockRoot": "0x" + "00" * 32, "extraData": "0x", "slotNumber": hex(42), "blobBaseFee": "0x1",
    "depositOnly": False, "activation": False,
}
DEPOSIT_SOURCE_HASH = bytes(31) + b"\x42"  # the gates' deposit source hash


def q(n: int) -> str:
    return hex(n)


def h32(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def case_id(s: dict) -> str:
    segment = lambda t: re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", t.lower())).strip("-") or "x"
    return f"satin/exported/{segment(s['group'])}/{segment(s['name'])}"


def exclusion(s: dict) -> str | None:
    lim = s["limits"]
    if any(v is not None for v in lim.values()):
        return "limit or detention-cap override: parameterized-model lane (D-11)"
    if s["skipNonceCheck"] or s["skipEip3607"]:
        return "simulation switch (skip_nonce_check or skip_eip3607): not a chain input"
    if s["prior"]:
        return "earlier transactions of its block: needs a block profile"
    if s["oracle"]:
        return "oracle answers without their request order: a transcript needs a recorded run"
    if s["l1Fee"] is not None:
        return "an L1 fee: needs signed bytes, which the scenario's keyless sender cannot give"
    return None


def pre_state(s: dict) -> dict:
    accounts = {}
    for a in s["accounts"]:
        nonce, balance, storage = int(a["nonce"]), int(a["balance"]), a["storage"]
        if nonce == 0 and balance == 0 and a["code"] == "0x" and not storage:
            continue  # the gates' databases hold no such account: absent
        slots = {h32(int(k)): q(int(v)) for k, v in storage if int(v) != 0}
        accounts[a["address"]] = {"nonce": q(nonce), "balance": q(balance), "code": a["code"], "storage": dict(sorted(slots.items()))}
    return {"completeness": "complete", "accounts": dict(sorted(accounts.items()))}


def salt(s: dict) -> dict:
    buckets = {}
    for address, slot, m in s["salt"]:
        b = salt_mapping.slot_bucket(address, int(slot)) if slot is not None else salt_mapping.account_bucket(address)
        buckets[b] = 256 * int(m)
    for address, slot, cap in s["saltCapacity"]:
        b = salt_mapping.slot_bucket(address, int(slot)) if slot is not None else salt_mapping.account_bucket(address)
        buckets[b] = int(cap)
    return {"mapping": "salt-v1", "complete": True, "buckets": {q(b): q(c) for b, c in sorted(buckets.items())}}


def transaction(s: dict) -> dict:
    to = None if s["create"] else s["to"]
    if s["deposit"] is not None:
        recipient = b"" if to is None else bytes.fromhex(to[2:])  # an empty `to` is a creation
        raw = ex.deposit(DEPOSIT_SOURCE_HASH, bytes.fromhex(s["sender"][2:]), recipient, int(s["deposit"]),
                         int(s["value"]), int(s["gasLimit"]), bytes.fromhex(s["data"][2:]))
        return {"kind": "deposit", "raw": "0x" + raw.hex()}
    price = int(s["gasPrice"])
    ty = 4 if s["auths"] else int(s["txType"])
    chain = q(int(s["chainId"])) if s["chainId"] is not None else None
    if ty:
        chain = "0x1"
    return {
        "kind": "synthetic",
        "type": q(ty),
        "chainId": chain,
        "nonce": q(int(s["nonce"])),
        "sender": s["sender"],
        "to": to,
        "value": q(int(s["value"])),
        "data": s["data"],
        "gasLimit": q(int(s["gasLimit"])),
        "gasPrice": q(price) if ty in (0, 1) else None,
        "maxFeePerGas": q(price) if ty in (2, 4) else None,
        "maxPriorityFeePerGas": q(price) if ty in (2, 4) else None,
        "accessList": [],
        "authorizationList": [
            {"chainId": q(int(a["chainId"])), "address": a["address"], "nonce": q(int(a["nonce"])), "authority": a["authority"]}
            for a in s["auths"]
        ],
    }


def convert(s: dict, descriptor: str, active: set[str], commit: str) -> dict:
    rules = sorted({r for r in s["rules"] if r in active})
    dropped = sorted(set(s["rules"]) - set(rules))
    inp = {"chain": {"chainId": "0x1"}, "block": {**BLOCK, "coinbase": s["beneficiary"]}, "blockHashes": {},
           "pre": pre_state(s), "transaction": transaction(s), "salt": salt(s)}
    notes = ["the scenario's sender has no key: a synthetic message, which counts toward no signature or envelope coverage"]
    if s["deposit"] is not None:
        notes = ["a deposit envelope with the gates' source hash 0x..42, no system flag"]
    if dropped:
        notes.append(f"rule ids not active in the pinned registry, kept as aliases only: {dropped}")
    return {
        "format": "mega-execution-fixture",
        "schemaVersion": "2.0",
        "caseId": case_id(s),
        "specRef": {"name": "megaeth/Satin", "descriptor": descriptor},
        "profile": "state-transition",
        "rules": rules,
        "input": inp,
        "provenance": {
            "status": "candidate",
            "source": {**SOURCE, "commit": commit, "name": s["name"], "group": s["group"]},
            "aliases": [s["name"], s["group"]],
            "originalRules": s["rules"],
            "conversion": notes,
            "review": "unreviewed: the scenario's own rule ids, until a reviewer names the rules the case pins",
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    source, out = argv[1], argv[2]
    parts = os.path.normpath(os.path.abspath(out)).split(os.sep)
    if "examples" in parts or any(p.startswith("release") for p in parts):
        print("export_scenarios: candidates never go to examples/ or a release", file=sys.stderr)
        return 2
    with open(os.path.join(SPEC_DIR, "descriptor.json"), encoding="utf-8") as f:
        descriptor = "sha256:" + hashlib.sha256(canonical(json.load(f))).hexdigest()
    with open(os.path.join(SPEC_DIR, "rules.json"), encoding="utf-8") as f:
        active = {k for k, v in json.load(f)["rules"].items() if v["status"] == "active"}
    commit = os.environ.get("EXPORT_SOURCE_COMMIT", "unknown")
    counts: dict[str, int] = {}
    excluded: dict[str, list[str]] = {}
    seen: dict[str, str] = {}
    converted = 0
    os.makedirs(out, exist_ok=True)
    with open(source, encoding="utf-8") as f:
        scenarios = [json.loads(line) for line in f if line.strip()]
    for s in scenarios:
        reason = exclusion(s)
        cid = case_id(s)
        if reason is None and not [r for r in s["rules"] if r in active]:
            reason = "cites no active rule of the pinned registry: needs authored rules"
        if reason is None and cid in seen:
            reason = f"duplicate case id of {seen[cid]}"
        if reason:
            counts[reason] = counts.get(reason, 0) + 1
            excluded.setdefault(reason, []).append(s["name"])
            continue
        seen[cid] = s["name"]
        doc = convert(s, descriptor, active, commit)
        path = os.path.join(out, cid + ".json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as g:
            g.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        converted += 1
    summary = {
        "format": "mega-fixture-export-summary",
        "source": {**SOURCE, "commit": commit},
        "scenarios": len(scenarios),
        "converted": converted,
        "excluded": {reason: {"count": counts[reason], "names": sorted(names)} for reason, names in sorted(excluded.items())},
    }
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as g:
        g.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"export_scenarios: {len(scenarios)} scenarios: {converted} converted, "
          f"{len(scenarios) - converted} excluded -> {out}")
    for reason in sorted(counts):
        print(f"  {counts[reason]:5d}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
