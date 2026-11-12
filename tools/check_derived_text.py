#!/usr/bin/env python3
"""Check that every figure in the slice's text follows the model's constants.

The slice's human-readable text — each case's intent and boundary, its derivation steps, the
quarantine verdicts, the negative case's note, and `slice/README.md` — must write every figure that
depends on a constant of the specification from that constant (`tools/satin_model/constants.py`), never as a
typed number. This check changes one constant at a time, regenerates the slice from a copy of the
tools into a temporary directory, and fails if any text there still shows a figure computed from
the constant's old value.

The old figures of a constant are:

- the figures it feeds directly, from the table `MUTATIONS` below: the constant itself and its
  products with the byte counts and counts the slice uses;
- every figure of a case's expected gas ledgers, receipt gas and resources that changes when the
  constant changes: the sums and products the derivations reach.

A figure equal to one of the case's own inputs — its transaction's gas limit or value, or a number
its contract code pushes (the system contracts' code aside) — is that input, which no constant
sets, and is not taken for a stale figure: a call requesting 100,000 gas, or a gas limit of
100,000, does not follow `KEYLESS_DEPLOY_OVERHEAD_GAS`.

Usage:
    tools/check_derived_text.py

Standard library only. Exits 0 when every figure follows its constant.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOOLS = ("make_slice.py", "make_examples.py", "salt_mapping.py")
MODEL = "satin_model"  # the model's package, copied whole; its constants are in constants.py


def fmt(n: int) -> str:
    return f"{n:,}"


def kept_threshold(m, history: int) -> list[int]:
    """The least regular gas a caller forwarding all it may keeps `history` from, and one below it."""
    at = -(-history * m.GAS_RETAINED_DENOMINATOR // m.GAS_RETAINED_NUMERATOR)
    return [at, at - 1]


# constant -> (the value it is changed to, the figures it feeds at its old value). A figure
# function takes the model's old constants. A constant is moved by more than one where a case sits one
# below a threshold it sets, so that the figure one below the new value is not the old value itself.
MUTATIONS = {
    "COST_PER_HISTORY_BYTE": (
        89,
        lambda m: [m.COST_PER_HISTORY_BYTE * k for k in (
            1, m.TX_BODY_SIZE, m.WRITE_RECORD_SIZE, 2 * m.WRITE_RECORD_SIZE, m.TX_BODY_SIZE + m.WRITE_RECORD_SIZE,
            m.LOG_BASE_SIZE, m.AUTHORIZATION_SIZE, m.TX_BODY_SIZE + m.AUTHORIZATION_SIZE + m.WRITE_RECORD_SIZE)]
        + kept_threshold(m, 2 * m.WRITE_RECORD_SIZE * m.COST_PER_HISTORY_BYTE),
    ),
    "COST_PER_STATE_BYTE": (
        1_531,
        lambda m: [m.COST_PER_STATE_BYTE * k for k in (
            1, m.SLOT_STATE_BYTES, m.ACCOUNT_STATE_BYTES, m.DELEGATION_STATE_BYTES,
            m.ACCOUNT_STATE_BYTES + m.DELEGATION_STATE_BYTES)],
    ),
    "KEYLESS_DEPLOY_OVERHEAD_GAS": (
        100_007,
        lambda m: [m.KEYLESS_DEPLOY_OVERHEAD_GAS, m.KEYLESS_DEPLOY_OVERHEAD_GAS - 1],
    ),
}

NUMBER = re.compile(r"(?<![\w.\-])(\d{1,3}(?:,\d{3})+|\d+)(?![\w])")


def generate(out: str, constant: str | None = None, value: int | None = None) -> dict[str, str]:
    """The slice `tools/make_slice.py` writes, from a copy of the tools with `constant` set to `value`."""
    tools = os.path.join(out, "tools")
    os.makedirs(tools)
    for name in TOOLS:
        shutil.copy(os.path.join(ROOT, "tools", name), tools)
    shutil.copytree(os.path.join(ROOT, "tools", MODEL), os.path.join(tools, MODEL),
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(os.path.join(ROOT, "tools", "system-contracts.json"), tools)
    os.symlink(os.path.join(ROOT, "specs"), os.path.join(out, "specs"))  # read only
    if constant is not None:
        path = os.path.join(tools, MODEL, "constants.py")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        text, n = re.subn(rf"^{constant} = [\d_]+", f"{constant} = {value}", text, flags=re.M)
        if n != 1:
            raise SystemExit(f"check_derived_text: {constant} is not assigned once by a plain number in the model")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    slice_dir = os.path.join(out, "slice")
    program = (
        "import os, sys\n"
        f"sys.path.insert(0, {tools!r})\n"
        "import make_slice\n"
        "for rel, text in make_slice.outputs().items():\n"
        f"    path = os.path.join({slice_dir!r}, rel)\n"
        "    os.makedirs(os.path.dirname(path), exist_ok=True)\n"
        "    with open(path, 'w', encoding='utf-8') as f:\n"
        "        f.write(text)\n"
    )
    subprocess.run([sys.executable, "-I", "-B", "-c", program], check=True)
    files = {}
    for base, _, names in os.walk(slice_dir):
        for name in names:
            path = os.path.join(base, name)
            with open(path, encoding="utf-8") as f:
                files[os.path.relpath(path, slice_dir)] = f.read()
    return files


def pushes(code: bytes) -> set[int]:
    out, pc = set(), 0
    while pc < len(code):
        op = code[pc]
        n = op - 0x5F if 0x60 <= op <= 0x7F else 0
        if n:
            out.add(int.from_bytes(code[pc + 1:pc + 1 + n], "big"))
        pc += 1 + n
    return out


def inputs(doc: dict) -> set[int]:
    """The figures a case takes as inputs: its gas limit and value, and what its own code pushes."""
    out = set()
    tx = doc.get("provenance", {}).get("transaction", {})
    for key in ("gasLimit", "value"):
        if key in tx:
            out.add(int(tx[key], 16))
    for address, account in doc.get("input", {}).get("pre", {}).get("accounts", {}).items():
        if account and not address.startswith("0x634200000000000000000000000000000000000"):
            out |= pushes(bytes.fromhex(account["code"][2:]))
    return out


def texts(files: dict[str, str]):
    """(where, text, the case's input figures) for every human-readable string of the slice."""
    for rel, raw in sorted(files.items()):
        doc = json.loads(raw)
        if rel == "index.json":
            for q in doc.get("quarantine", []):
                yield f"{rel} {q['caseId']} knownFail.verdict", q["knownFail"]["verdict"], set()
            continue
        own = inputs(doc)
        prov = doc.get("provenance", {})
        for key, value in sorted(prov.get("authoring", {}).items()):
            yield f"{rel} authoring.{key}", value, own
        for d in prov.get("derivation", []):
            for i, step in enumerate(d["steps"]):
                yield f"{rel} derivation {d['path']} step {i}", step, own
        if "quarantine" in prov:
            yield f"{rel} quarantine.verdict", prov["quarantine"]["verdict"], own
        if "note" in prov:
            yield f"{rel} note", prov["note"], own
    with open(os.path.join(ROOT, "slice", "README.md"), encoding="utf-8") as f:
        yield "slice/README.md", f.read(), set()


def figures(files: dict[str, str]) -> dict[tuple, int]:
    """Every gas, receipt-gas and resource figure of every case's expectation, by (file, path)."""
    out = {}
    for rel, raw in files.items():
        if rel == "index.json":
            continue
        expected = json.loads(raw).get("expected") or {}
        for key, value in (expected.get("gasLedgers") or {}).items():
            out[(rel, "gasLedgers", key)] = int(value, 16)
        receipt = expected.get("receipt") or {}
        if "gasUsed" in receipt:
            out[(rel, "receipt", "gasUsed")] = int(receipt["gasUsed"], 16)
        for dim, v in (expected.get("resources") or {}).items():
            out[(rel, "resources", dim)] = int(v["net"])
    return out


def main() -> int:
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import satin_model as model  # the old values

    failures = 0
    with tempfile.TemporaryDirectory(prefix="check-derived-text-") as tmp:
        baseline = generate(os.path.join(tmp, "baseline"))
        base_figures = figures(baseline)
        for constant, (value, fed) in MUTATIONS.items():
            old = getattr(model, constant)
            mutated = generate(os.path.join(tmp, constant.lower()), constant, value)
            now = figures(mutated)
            moved = {v for k, v in base_figures.items() if k in now and now[k] != v}
            stale = set(fed(model)) | moved
            found = []
            scanned = 0
            for where, text, own in texts(mutated):
                scanned += 1
                for m in NUMBER.finditer(text):
                    figure = int(m.group(1).replace(",", ""))
                    if figure not in stale or figure in own:
                        continue
                    context = text[max(0, m.start() - 40):m.end() + 40]
                    found.append((where, m.group(1), context.replace("\n", " ")))
            changed = sum(1 for k in now if k in base_figures and now[k] != base_figures[k])
            print(f"check_derived_text: {constant} {fmt(old)} -> {fmt(value)}: {len(mutated)} files regenerated, "
                  f"{scanned} texts scanned, {len(stale)} old figures sought ({changed} expected figures moved): "
                  f"{'ok' if not found else f'{len(found)} stale'}")
            for where, figure, context in found:
                print(f"  stale {figure} in {where}: ...{context}...")
            failures += len(found)
    if failures:
        print(f"check_derived_text: FAILED: {failures} figure(s) in the slice text do not follow their constant")
        return 1
    print("check_derived_text: ok: every figure in the slice text follows its constant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
