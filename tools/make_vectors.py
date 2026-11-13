#!/usr/bin/env python3
"""Write the canonicalization and digest vectors under vectors/.

Each vector is an exact input byte string and either the canonical bytes and digests it must
produce, or the error code (and, below the JSON layer, the JSON Pointer) it must be rejected with.
The inputs and the intended rejection codes are authored here. The expected canonical bytes and
digests are computed by the Rust format crate's command-line tool, whose path is the argument, and
this script fails if the tool rejects an input for any other reason than the intended one.
tools/check_vectors.py then reproduces every vector independently, without the Rust crate.

Usage:
    tools/make_vectors.py <path-to-mega-fixture-binary>

Standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
VECTORS = os.path.join(ROOT, "vectors")

JSON_ACCEPT = {
    "json-key-order-and-whitespace": b' { "b" : [true , null] ,\n\t"a":"x", "B": {} }\r\n',
    "json-code-point-key-order": '{"z":"","é":"","\U0001F600":"","\\ufffd":"","Z":""}'.encode(),
    "json-string-escapes": b'["\\u0041\\/\\b\\f\\n\\r\\t\\u0001\\u001F\\u007f\\u00e9\\ud83d\\ude00\\"\\\\"]',
    "json-raw-non-ascii-kept": '{"s":"  café 漢"}'.encode(),
    "json-array-order-kept": b'{"a":["b","a",["c",{"y":null,"x":false}]]}',
    "json-empty-object": b"{}",
    "json-top-level-string": b'"0x0"',
    "json-nested-objects-sorted": b'{"outer":{"z":{"b":"1","a":"2"},"a":[{"d":"","c":""}]}}',
    "json-nesting-256-levels": b"[" * 255 + b'{"a":"b"}' + b"]" * 255,
}

JSON_REJECT = {
    "json-duplicate-key": (b'{"a":"1","a":"2"}', "duplicate-key"),
    "json-duplicate-key-after-unescaping": (b'{"a":"1","\\u0061":"2"}', "duplicate-key"),
    "json-integer": (b'{"gas":21000}', "number-not-allowed"),
    "json-float": (b'{"gas":"0x1","ratio":0.5}', "number-not-allowed"),
    "json-negative-number": (b'["-1",-1]', "number-not-allowed"),
    "json-exponent": (b'{"x":1e3}', "number-not-allowed"),
    "json-nan": (b'{"x":NaN}', "invalid-json"),
    "json-byte-order-mark": (b'\xef\xbb\xbf{}', "byte-order-mark"),
    "json-invalid-utf8": (b'{"a":"\xc3\x28"}', "invalid-utf8"),
    "json-lone-high-surrogate": (b'["\\ud800"]', "invalid-unicode-escape"),
    "json-lone-low-surrogate": (b'["\\udc00"]', "invalid-unicode-escape"),
    "json-trailing-comma": (b'{"a":"1",}', "invalid-json"),
    "json-raw-control-character": (b'{"a":"tab\there"}', "invalid-json"),
    "json-trailing-content": (b'{} {}', "invalid-json"),
    "json-empty-input": (b"", "invalid-json"),
    "json-single-quotes": (b"{'a':'1'}", "invalid-json"),
    "json-nesting-257-levels": (b"[" * 256 + b'{"a":"b"}' + b"]" * 256, "invalid-json"),
}


def load_example(name: str) -> dict:
    with open(os.path.join(ROOT, "examples", name), encoding="utf-8") as f:
        return json.load(f)


def dump(value) -> bytes:
    """A deliberately non-canonical rendering: indented, keys in authoring order."""
    return (json.dumps(value, indent=1, ensure_ascii=True) + "\n").encode()


def case_rejects() -> dict[str, tuple[bytes, str, str]]:
    base = load_example("state-transition-sstore-fresh-slot.json")
    sender = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
    contract = "0x00000000000000000000000000000000000c0de0"
    out: dict[str, tuple[bytes, str, str]] = {}

    def mutate(name: str, code: str, path: str, edit):
        c = copy.deepcopy(base)
        edit(c)
        out[name] = (dump(c), code, path)

    text = dump(base).decode()
    out["case-duplicate-key"] = (
        text.replace('"caseId":', '"caseId": "satin/duplicate/key",\n "caseId":', 1).encode(), "duplicate-key", "")
    out["case-float"] = (text.replace('"gasLimit": "0x6fc23ac00"', '"gasLimit": 30000000000.0', 1).encode(), "number-not-allowed", "")

    mutate("case-non-minimal-quantity", "non-minimal-quantity", f"/input/pre/accounts/{sender}/balance",
           lambda c: c["input"]["pre"]["accounts"][sender].__setitem__("balance", "0x0de0b6b3a7640000"))
    mutate("case-zero-as-empty-quantity", "non-minimal-quantity", "/expected/gasLedgers/refund",
           lambda c: c["expected"]["gasLedgers"].__setitem__("refund", "0x"))
    mutate("case-uppercase-hex-hash", "uppercase-hex", "/expected/reads/codes/0",
           lambda c: c["expected"]["reads"]["codes"].__setitem__(0, "0x" + c["expected"]["reads"]["codes"][0][2:].upper()))
    mutate("case-uppercase-hex-quantity", "uppercase-hex", "/expected/receipt/gasUsed",
           lambda c: c["expected"]["receipt"].__setitem__("gasUsed", "0x249F0"))
    for vid, extra in [("case-unknown-required-feature", "feature:blob-sidecar"), ("case-unknown-group", "group:inspector-frames")]:
        position = sorted(base["requires"] + [extra]).index(extra)
        mutate(vid, "unknown-requirement", f"/requires/{position}",
               lambda c, extra=extra: c.__setitem__("requires", sorted(c["requires"] + [extra])))
    mutate("case-schema-major-1", "unsupported-schema-version", "/schemaVersion",
           lambda c: c.__setitem__("schemaVersion", "1.1"))
    mutate("case-unknown-format", "unsupported-format", "/format",
           lambda c: c.__setitem__("format", "eest-state-test"))
    mutate("case-unknown-field", "unknown-field", "/expected/inspected",
           lambda c: c["expected"].__setitem__("inspected", True))
    mutate("case-unknown-profile", "unknown-profile", "/profile",
           lambda c: c.__setitem__("profile", "rpc-call"))
    mutate("case-odd-length-bytes", "odd-length-bytes", f"/input/pre/accounts/{contract}/code",
           lambda c: c["input"]["pre"]["accounts"][contract].__setitem__("code", "0x600"))
    mutate("case-short-address", "wrong-width", "/input/block/coinbase",
           lambda c: c["input"]["block"].__setitem__("coinbase", "0x42000000000000000000000000000000000011"))
    mutate("case-quantity-overflow", "quantity-overflow", "/input/block/gasLimit",
           lambda c: c["input"]["block"].__setitem__("gasLimit", "0x10000000000000000"))
    mutate("case-missing-hex-prefix", "missing-hex-prefix", "/input/block/number",
           lambda c: c["input"]["block"].__setitem__("number", "2"))
    mutate("case-invalid-digest", "invalid-digest", "/specRef/descriptor",
           lambda c: c["specRef"].__setitem__("descriptor", "sha1:" + "00" * 20))
    mutate("case-negative-zero", "invalid-signed-integer", "/expected/resources/kvUpdates/net",
           lambda c: c["expected"]["resources"]["kvUpdates"].__setitem__("net", "-0"))
    mutate("case-null-for-required-object", "wrong-type", "/expected/state",
           lambda c: c["expected"].__setitem__("state", None))
    mutate("case-unknown-spec", "unknown-spec", "/specRef/descriptor",
           lambda c: c["specRef"].__setitem__("descriptor", "sha256:" + "00" * 32))
    mutate("case-unsorted-rules", "unsorted-set", "/rules",
           lambda c: c.__setitem__("rules", list(reversed(c["rules"]))))
    mutate("case-unsorted-requires", "unsorted-set", "/requires",
           lambda c: c.__setitem__("requires", list(reversed(c["requires"]))))
    def synthetic(c):
        c["input"]["transaction"] = {
            "kind": "synthetic", "type": "0x2", "chainId": "0x1", "nonce": "0x0", "sender": sender, "to": contract,
            "value": "0x0", "data": "0x", "gasLimit": "0xf4240", "gasPrice": "0xf4240", "maxFeePerGas": "0xf4240",
            "maxPriorityFeePerGas": "0x0", "accessList": [], "authorizationList": [],
        }
        c["requires"] = sorted(c["requires"] + ["feature:synthetic-transaction"])
    mutate("case-synthetic-fee-fields-of-another-type", "inconsistent-transaction", "/input/transaction/gasPrice", synthetic)
    mutate("case-deposit-kind-with-signed-bytes", "inconsistent-transaction", "/input/transaction/raw",
           lambda c: c["input"]["transaction"].__setitem__("kind", "deposit"))
    mutate("case-assertions-member", "unknown-field", "/assertions",
           lambda c: c.__setitem__("assertions", [{"path": "/expected/gasLedgers", "rules": c["rules"][:1]}]))
    build = load_example("block-build-policy-skip.json")
    c = copy.deepcopy(build)
    c["input"]["actions"].insert(2, {"op": "commit", "candidate": "0x0"})
    out["case-build-commit-twice"] = (dump(c), "invalid-reference", "/input/actions/2")
    c = copy.deepcopy(build)
    c["input"]["actions"] = [{"op": "abandon", "candidate": "0x1"}] + c["input"]["actions"]
    out["case-build-abandon-before-execute"] = (dump(c), "invalid-reference", "/input/actions/0")
    mutate("case-witness-state-in-state-transition", "invalid-value", "/input/pre/completeness",
           lambda c: c["input"]["pre"].__setitem__("completeness", "witness")
           or [a.__setitem__("storageComplete", True) for a in c["input"]["pre"]["accounts"].values()])
    return out


MANIFEST_EXAMPLES = [
    "block-build-policy-skip.json",
    "deposit-state-transition-new-caller.json",
    "invalid-block-foreign-registry-code.json",
    "state-transition-sstore-fresh-slot.json",
    "stateless-block-witness-wrong-parent-anchor.json",
    "transaction-validation-gas-below-intrinsic.json",
]


def run(cli: str, *args: str) -> str:
    return subprocess.run([cli, *args], capture_output=True, text=True, cwd=ROOT).stdout


def parse_reject(line: str) -> tuple[str, str]:
    # "reject <file> <code> at <path>: detail" or "reject <file> <code>: detail" (check)
    # "reject <code> at <path>: detail" or "reject <code>: detail" (canon)
    words = line.split(" ")
    rest = words[2:] if words[1].endswith(".json") else words[1:]
    code = rest[0].rstrip(":")
    path = rest[2].rstrip(":") if len(rest) > 2 and rest[1] == "at" else ""
    return code, path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    cli = os.path.abspath(argv[1])
    for sub in ("accept", "reject"):
        os.makedirs(os.path.join(VECTORS, sub), exist_ok=True)
        for name in os.listdir(os.path.join(VECTORS, sub)):
            os.remove(os.path.join(VECTORS, sub, name))
    vectors = []
    problems = []

    def write(rel: str, data: bytes):
        with open(os.path.join(VECTORS, rel), "wb") as f:
            f.write(data)

    def accept(vid: str, kind: str, data: bytes):
        rel_in = f"accept/{vid}.in.json"
        write(rel_in, data)
        path_in = os.path.join("vectors", rel_in)
        canon = subprocess.run([cli, "canon", path_in], capture_output=True, cwd=ROOT).stdout
        if canon.startswith(b"reject"):
            problems.append(f"{vid}: {canon.decode().strip()}")
            return
        rel_out = f"accept/{vid}.canonical.json"
        write(rel_out, canon)
        entry = {"id": vid, "kind": kind, "input": rel_in, "canonical": rel_out}
        if kind == "json":
            entry["digest"] = run(cli, "digest", path_in).strip()
        elif kind == "case":
            line = run(cli, "check", "--specs", "specs", path_in).strip()
            if not line.startswith("ok "):
                problems.append(f"{vid}: {line}")
                return
            fields = dict(w.split("=", 1) for w in line.split(" ")[2:])
            entry["fileDigest"] = fields["file"]
            entry["semanticDigest"] = fields["semantic"]
        else:
            line = run(cli, "manifest", path_in).strip()
            if line.startswith("reject"):
                problems.append(f"{vid}: {line}")
                return
            entry["digest"] = line
        vectors.append(entry)

    def reject(vid: str, kind: str, data: bytes, code: str, path: str):
        rel_in = f"reject/{vid}.json"
        write(rel_in, data)
        path_in = os.path.join("vectors", rel_in)
        command = {"json": ["canon", path_in], "case": ["check", "--specs", "specs", path_in], "manifest": ["manifest", path_in]}[kind]
        line = run(cli, *command).strip()
        if not line.startswith("reject"):
            problems.append(f"{vid}: accepted")
            return
        got_code, got_path = parse_reject(line)
        if got_code != code or (path and got_path != path):
            problems.append(f"{vid}: expected {code} at {path!r}, got {got_code} at {got_path!r}")
        vectors.append({"id": vid, "kind": kind, "input": rel_in, "error": {"code": code, "path": path}})

    for vid, data in JSON_ACCEPT.items():
        accept(vid, "json", data)
    for name in MANIFEST_EXAMPLES:
        with open(os.path.join(ROOT, "examples", name), "rb") as f:
            accept("case-" + name[:-5], "case", f.read())
    renamed = load_example("state-transition-sstore-fresh-slot.json")
    renamed["caseId"] = "satin/state-gas/sstore-fresh-slot/renamed-alias"
    renamed["provenance"] = {"status": "candidate", "note": "Same semantics as the example under another logical name."}
    accept("case-same-semantics-other-name", "case", dump(renamed))
    for vid, (data, code) in JSON_REJECT.items():
        reject(vid, "json", data, code, "")
    for vid, (data, code, path) in case_rejects().items():
        reject(vid, "case", data, code, path)

    # A manifest of the examples.
    entries = []
    for name in MANIFEST_EXAMPLES:
        path = os.path.join("examples", name)
        case = load_example(name)
        line = run(cli, "check", "--specs", "specs", path).strip()
        fields = dict(w.split("=", 1) for w in line.split(" ")[2:])
        entries.append({"caseId": case["caseId"], "profile": case["profile"], "requires": case["requires"],
                        "path": path, "file": fields["file"], "semantic": fields["semantic"]})
    entries.sort(key=lambda e: e["caseId"])
    schemas = {}
    for name in sorted(os.listdir(os.path.join(ROOT, "schema"))):
        with open(os.path.join(ROOT, "schema", name), "rb") as f:
            schemas["schema/" + name] = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    with open(os.path.join(ROOT, "specs", "satin-cac999a", "descriptor.json"), encoding="utf-8") as f:
        descriptor = json.load(f)
    descriptor_digest = run(cli, "digest", "specs/satin-cac999a/descriptor.json").strip()
    manifest = {
        "format": "mega-execution-manifest",
        "schemaVersion": "1.0",
        "suite": {"name": "satin-examples", "version": "0.0.0-example"},
        "schemas": schemas,
        "specs": {descriptor_digest: {"name": descriptor["name"], "registry": descriptor["registry"]}},
        "cases": entries,
        "shards": {"required": sorted(e["caseId"] for e in entries if e["profile"] != "stateless-block")},
        "blobs": {},
        "files": {},
        "counts": {"cases": hex(len(entries)), "blobs": "0x0"},
    }
    accept("manifest-examples", "manifest", dump(manifest))
    m = copy.deepcopy(manifest)
    m["cases"] = list(reversed(m["cases"]))
    reject("manifest-unsorted-cases", "manifest", dump(m), "unsorted-set", "/cases")
    m = copy.deepcopy(manifest)
    m["counts"]["cases"] = hex(len(entries) + 1)
    reject("manifest-count-mismatch", "manifest", dump(m), "invalid-reference", "/counts/cases")
    m = copy.deepcopy(manifest)
    m["shards"]["required"] = sorted(m["shards"]["required"] + ["satin/not/in-manifest"])
    position = m["shards"]["required"].index("satin/not/in-manifest")
    reject("manifest-shard-member-missing", "manifest", dump(m), "invalid-reference", f"/shards/required/{position}")
    m = copy.deepcopy(manifest)
    m["cases"][0]["path"] = "../outside.json"
    reject("manifest-unsafe-path", "manifest", dump(m), "invalid-value", "/cases/0/path")

    index = {"format": "mega-fixture-vectors", "schemaVersion": "1.0", "specs": "specs", "vectors": vectors}
    with open(os.path.join(VECTORS, "index.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(index, indent=2) + "\n")
    if problems:
        for p in problems:
            print("make_vectors: " + p, file=sys.stderr)
        return 1
    print(f"make_vectors: {len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
