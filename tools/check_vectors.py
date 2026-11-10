#!/usr/bin/env python3
"""Independent second reader of the fixture format: reproduce every vector and check the examples.

This checker shares no code with the Rust format crate. It reads the published contract only:
the JSON Schemas under schema/ (interpreted by the small validator below, including the x-hex,
x-error and x-signed annotations), the canonical JSON rules and the semantic checks of
docs/canonical-json.md and docs/format.md, and the rule registries under specs/.

For every vector of <vectors-dir>/index.json it parses the exact input bytes and either
reproduces the canonical bytes and digests or rejects the input with the vector's error code (and,
below the JSON layer, its JSON Pointer). It then validates every example under examples/ and
rejects every negative example with the code its file name starts with.

Usage:
    python3 -I tools/check_vectors.py vectors

The last line says "ok" when everything agrees. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

JSON_LAYER = {"invalid-utf8", "byte-order-mark", "invalid-json", "duplicate-key", "number-not-allowed", "invalid-unicode-escape"}
NON_SEMANTIC = ("caseId", "provenance")


class Reject(Exception):
    def __init__(self, code: str, path: str = "", detail: str = ""):
        super().__init__(f"{code} at {path!r}: {detail}")
        self.code, self.path, self.detail = code, path, detail


# ------------------------------------------------------------------------------------------------
# Strict JSON and canonical bytes (docs/canonical-json.md)

def parse_strict(data: bytes):
    if data.startswith(b"\xef\xbb\xbf"):
        raise Reject("byte-order-mark")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise Reject("invalid-utf8", "", str(e)) from None

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise Reject("duplicate-key", "", f"member {key!r} twice")
            obj[key] = value
        return obj

    def number(text):
        raise Reject("number-not-allowed", "", text)

    def constant(text):
        raise Reject("invalid-json", "", text)

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=number, parse_float=number, parse_constant=constant)
    except json.JSONDecodeError as e:
        raise Reject("invalid-json", "", str(e)) from None
    except RecursionError:
        raise Reject("invalid-json", "", "nesting too deep") from None
    _no_surrogates(value)
    if _depth(value) > MAX_DEPTH:
        raise Reject("invalid-json", "", "more than 256 nested arrays and objects")
    return value


MAX_DEPTH = 256


def _depth(value) -> int:
    """The number of nested arrays and objects at the deepest point."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, dict):
            deepest = max(deepest, d)
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            deepest = max(deepest, d)
            stack.extend((x, d + 1) for x in v)
    return deepest


def _no_surrogates(value):
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            items = [v]
        elif isinstance(v, dict):
            items = list(v.keys())
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
            items = []
        else:
            items = []
        for s in items:
            if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
                raise Reject("invalid-unicode-escape", "", "unpaired surrogate")


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(s: str) -> str:
    out = ['"']
    for c in s:
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif ord(c) < 0x20:
            out.append("\\u%04x" % ord(c))
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _canon(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        # Code point order of the keys equals the byte order of their UTF-8 encodings.
        keys = sorted(value, key=lambda k: k.encode("utf-8"))
        return "{" + ",".join(_string(k) + ":" + _canon(value[k]) for k in keys) + "}"
    raise TypeError(type(value))


def canonical(value) -> bytes:
    return _canon(value).encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def child(path: str, token: str) -> str:
    return path + "/" + token.replace("~", "~0").replace("/", "~1")


def pointer(value, ptr: str):
    """Resolve a JSON Pointer; returns (found, value)."""
    if ptr == "":
        return True, value
    if not ptr.startswith("/"):
        return False, None
    current = value
    for raw in ptr[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token) or int(token) >= len(current):
                return False, None
            current = current[int(token)]
        else:
            return False, None
    return True, current


# ------------------------------------------------------------------------------------------------
# A JSON Schema interpreter for the keywords schema/*.json uses

def classify_hex(s: str, kind: str, schema: dict) -> str | None:
    """The error code of a malformed hex string (docs/canonical-json.md, "Hex strings")."""
    if kind == "digest":
        if not s.startswith("sha256:"):
            return "invalid-digest"
        digits = s[len("sha256:"):]
    else:
        if not s.startswith("0x"):
            return "missing-hex-prefix"
        digits = s[2:]
    if any(c not in "0123456789abcdefABCDEF" for c in digits):
        return "invalid-hex"
    if any(c in "ABCDEF" for c in digits):
        return "uppercase-hex"
    if kind == "quantity":
        if digits == "" or (len(digits) > 1 and digits[0] == "0"):
            return "non-minimal-quantity"
        if len(digits) > int(schema["x-bits"]) // 4:
            return "quantity-overflow"
    elif kind == "bytes":
        if len(digits) % 2:
            return "odd-length-bytes"
    elif kind == "fixed":
        if len(digits) != 2 * int(schema["x-bytes"]):
            return "wrong-width"
    elif kind == "digest":
        if len(digits) != 64:
            return "wrong-width"
    return None


def _matches(pattern: str, s: str) -> bool:
    # ECMA-262 '$' matches only at the end; Python's also before a final newline.
    if pattern.endswith("$"):
        pattern = pattern[:-1] + r"\Z"
    return re.search(pattern, s) is not None


TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


class Schemas:
    def __init__(self, directory: str):
        self.docs = {}
        for name in os.listdir(directory):
            if name.endswith(".json"):
                with open(os.path.join(directory, name), encoding="utf-8") as f:
                    self.docs[name] = json.load(f)

    def resolve(self, ref: str, base: str):
        file, _, frag = ref.partition("#")
        file = file or base
        node = self.docs[file]
        for token in frag.split("/")[1:]:
            node = node[token]
        return node, file

    def ok(self, inst, schema, base) -> bool:
        try:
            self.check(inst, schema, "", base)
            return True
        except Reject:
            return False

    def check(self, inst, s: dict, path: str, base: str):
        if "$ref" in s:
            target, file = self.resolve(s["$ref"], base)
            self.check(inst, target, path, file)
        code = s.get("x-error", "invalid-value")
        if "type" in s and not isinstance(inst, TYPES[s["type"]]):
            raise Reject("wrong-type", path, f"expected {s['type']}")
        for keyword in ("const", "enum"):
            if keyword in s:
                allowed = [s["const"]] if keyword == "const" else s["enum"]
                if all(isinstance(a, str) for a in allowed) and not isinstance(inst, str):
                    raise Reject("wrong-type", path, "expected string")
                if inst not in allowed:
                    raise Reject(code, path, f"{inst!r} not allowed")
        if isinstance(inst, str):
            if "pattern" in s and not _matches(s["pattern"], inst):
                hexcode = classify_hex(inst, s["x-hex"], s) if "x-hex" in s else None
                raise Reject(hexcode or code, path, f"{inst!r} does not match")
            if "maxLength" in s and len(inst) > s["maxLength"]:
                raise Reject(code, path, "too long")
            if "x-signed" in s:
                bound = 1 << (int(s["x-signed"]) - 1)
                if not -bound <= int(inst) < bound:
                    raise Reject(code, path, "out of range")
        if isinstance(inst, dict):
            for name in s.get("required", []):
                if name not in inst:
                    raise Reject("missing-field", child(path, name), "missing")
            props = s.get("properties", {})
            for key in sorted(inst, key=lambda k: k.encode("utf-8")):
                at = child(path, key)
                if key in props:
                    self.check(inst[key], props[key], at, base)
                    continue
                if "propertyNames" in s:
                    self.check(key, s["propertyNames"], at, base)
                extra = s.get("additionalProperties", True)
                if extra is False:
                    raise Reject("unknown-field", at, "unknown member")
                if isinstance(extra, dict):
                    self.check(inst[key], extra, at, base)
        if isinstance(inst, list):
            if len(inst) < s.get("minItems", 0):
                raise Reject("too-few-items", path, "too few items")
            if "maxItems" in s and len(inst) > s["maxItems"]:
                raise Reject("too-many-items", path, "too many items")
            if "items" in s:
                for i, item in enumerate(inst):
                    self.check(item, s["items"], f"{path}/{i}", base)
        for sub in s.get("allOf", []):
            self.check(inst, sub, path, base)
        if "oneOf" in s:
            branches = s["oneOf"]
            passing = [b for b in branches if self.ok(inst, b, base)]
            if len(passing) != 1:
                if len(passing) > 1:
                    raise Reject("invalid-value", path, "matches several branches")
                non_null = [b for b in branches if b != {"type": "null"}]
                if inst is None:
                    raise Reject("wrong-type", path, "null not allowed")
                self.check(inst, non_null[0], path, base)
        if "if" in s:
            branch = s.get("then") if self.ok(inst, s["if"], base) else s.get("else")
            if branch is not None:
                self.check(inst, branch, path, base)


# ------------------------------------------------------------------------------------------------
# Specs and rule registries

class Specs:
    def __init__(self, directory: str):
        self.by_digest = {}
        for name in sorted(os.listdir(directory)):
            d_path = os.path.join(directory, name, "descriptor.json")
            if not os.path.isfile(d_path):
                continue
            with open(d_path, "rb") as f:
                descriptor = parse_strict(f.read())
            with open(os.path.join(directory, name, "rules.json"), "rb") as f:
                registry = parse_strict(f.read())
            with open(os.path.join(directory, name, "sources.json"), "rb") as f:
                sources = parse_strict(f.read())
            if descriptor["registry"] != sha256(canonical(registry)):
                raise SystemExit(f"{name}: the descriptor does not bind its registry")
            if descriptor["sources"] != sha256(canonical(sources)):
                raise SystemExit(f"{name}: the descriptor does not bind its sources")
            rules = {}
            for rid, e in registry["rules"].items():
                if e["status"] not in ("active", "retired"):
                    raise SystemExit(f"{name}: {rid}: unknown status {e['status']!r}")
                if not all(isinstance(r, str) for r in e["rows"]):
                    raise SystemExit(f"{name}: {rid}: a row is not a string")
                if sha256(e["text"].encode("utf-8")) != e["textDigest"]:
                    raise SystemExit(f"{name}: {rid}: textDigest is not the digest of its text")
                rules[rid] = (e["status"] == "active", set(e["rows"]))
            self.by_digest[sha256(canonical(descriptor))] = (descriptor["name"], rules)


# ------------------------------------------------------------------------------------------------
# Semantic checks (docs/format.md, "Semantic checks"), in their documented order

def _sorted_set(items, path):
    for a, b in zip(items, items[1:]):
        if not a.encode("utf-8") < b.encode("utf-8"):
            raise Reject("unsorted-set", path, "not sorted, or holds a duplicate")


def _qty(s) -> int:
    return int(s[2:], 16)


def _rule_parts(ref: str):
    rid, _, row = ref.partition("/")
    return rid, (row if "/" in ref else None)


def _deposit(raw: str) -> bool:
    return raw.startswith("0x7e")


def _synthetic(tx, path):
    t = tx["type"]
    legacy_fee = t in ("0x0", "0x1")
    checks = [
        ("chainId", t == "0x0" or tx["chainId"] is not None),
        ("to", t != "0x4" or tx["to"] is not None),
        ("gasPrice", (tx["gasPrice"] is not None) == legacy_fee),
        ("maxFeePerGas", (tx["maxFeePerGas"] is not None) != legacy_fee),
        ("maxPriorityFeePerGas", (tx["maxPriorityFeePerGas"] is not None) != legacy_fee),
        ("accessList", t != "0x0" or not tx["accessList"]),
        ("authorizationList", (not tx["authorizationList"]) != (t == "0x4")),
    ]
    for field, ok in checks:
        if not ok:
            raise Reject("inconsistent-transaction", path + "/" + field, f"does not fit type {t}")


def derive_requirements(profile, inp, exp) -> set:
    out = set()
    if profile == "state-transition":
        out |= {"group:outcome", "group:state", "group:receipts", "group:gas-ledgers", "group:resources", "group:limit"}
        for key, group in (("gasPools", "group:gas-pools"), ("detention", "group:detention"), ("reads", "group:reads"), ("checkpoints", "group:checkpoints")):
            if key in exp:
                out.add(group)
        tx = inp["transaction"]
        if tx["kind"] == "synthetic":
            out.add("feature:synthetic-transaction")
        elif _deposit(tx["raw"]):
            out.add("feature:deposit")
    elif profile == "transaction-validation":
        out.add("group:validation")
        if _deposit(inp["raw"]):
            out.add("feature:deposit")
    else:
        out |= {"group:blocks", "group:state", "group:outcome", "group:receipts"}
        if profile == "block-build":
            out.add("group:decisions")
            txs = list(exp["transactions"])
            if any(_deposit(c["raw"]) for c in inp["candidates"]):
                out.add("feature:deposit")
        else:
            txs = [t for b in (exp["blocks"] or []) for t in b.get("transactions", [])]
        if any(_deposit(t) for b in inp.get("blocks", []) for t in b.get("transactions", [])):
            out.add("feature:deposit")
        if profile == "stateless-block":
            out.add("group:witness")
            if inp["witness"]["proof"] is not None:
                out.add("feature:proof-attachment")
        if len(inp["chain"]["schedule"]) > 1:
            out.add("feature:schedule")
        if inp["chain"]["rawConfig"] is not None:
            out.add("feature:raw-chain-config")
        for key, group in (("gasPools", "group:gas-pools"), ("gasLedgers", "group:gas-ledgers"), ("resources", "group:resources"),
                           ("limit", "group:limit"), ("detention", "group:detention"), ("reads", "group:reads")):
            carried = sum(1 for t in txs if key in t)
            if 0 < carried < len(txs):
                raise Reject("requirement-mismatch", "/requires", f"{group} carried by some transactions only")
            if carried:
                out.add(group)
    for key, feature in (("salt", "feature:salt"), ("oracle", "feature:oracle-transcript"), ("faults", "feature:injected-faults")):
        if key in inp:
            out.add(feature)
    pre = inp.get("pre")
    if isinstance(pre, dict) and pre.get("completeness") == "sparse":
        out.add("feature:sparse-state")
    return out


def _outcome(o, path) -> bool:
    admission, execution, commit = o["admission"]["status"], o["execution"], o["commit"]["status"]
    if admission == "refused":
        if execution is None and commit == "not-committed":
            return False
        raise Reject("inconsistent-outcome", path, "refused")
    if commit == "fault":
        if execution is None:
            return False
        raise Reject("inconsistent-outcome", path, "fault")
    if admission == "admitted":
        if commit == "committed" and execution is not None:
            return True
        raise Reject("inconsistent-outcome", path, "admitted")
    if commit == "committed" and (execution is None or execution["status"] == "halt"):
        return True
    raise Reject("inconsistent-outcome", path, "failed deposit")


def _receipt_status(o, receipt, path):
    success = (o["execution"] or {}).get("status") == "success"
    if (receipt["status"] == "0x1") != success:
        raise Reject("inconsistent-outcome", path, "receipt status")


def _block_tx(tx, path):
    if not _outcome(tx["outcome"], path + "/outcome"):
        raise Reject("inconsistent-outcome", path + "/outcome", "not executed")
    _receipt_status(tx["outcome"], tx["receipt"], path + "/receipt/status")


def _valid_blocks(blocks):
    return [(i, b) for i, b in enumerate(blocks or []) if b["status"] == "valid"]


def semantic_checks(case, specs: Specs):
    profile, inp, exp = case["profile"], case["input"], case["expected"]
    # 1. Specs.
    if case["specRef"]["descriptor"] not in specs.by_digest:
        raise Reject("unknown-spec", "/specRef/descriptor", "unknown descriptor")
    name, registry = specs.by_digest[case["specRef"]["descriptor"]]
    if name != case["specRef"]["name"]:
        raise Reject("spec-name-mismatch", "/specRef/name", name)
    if profile in ("block-import", "block-build", "stateless-block"):
        schedule = inp["chain"]["schedule"]
        for i, entry in enumerate(schedule):
            base = f"/input/chain/schedule/{i}/spec"
            if entry["spec"]["descriptor"] not in specs.by_digest:
                raise Reject("unknown-spec", base + "/descriptor", "unknown descriptor")
            if specs.by_digest[entry["spec"]["descriptor"]][0] != entry["spec"]["name"]:
                raise Reject("spec-name-mismatch", base + "/name", "name")
        for a, b in zip(schedule, schedule[1:]):
            if _qty(a["timestamp"]) >= _qty(b["timestamp"]):
                raise Reject("unsorted-set", "/input/chain/schedule", "timestamps")
        names = [e["spec"]["name"] for e in schedule]
        if len(set(names)) != len(names):
            raise Reject("invalid-reference", "/input/chain/schedule", "a spec named twice")
        for i, block in enumerate(exp.get("blocks") or []):
            if block["activeSpec"] is not None and block["activeSpec"] not in names:
                raise Reject("spec-name-mismatch", f"/expected/blocks/{i}/activeSpec", "not in the schedule")
    # 2. Sorted sets of the envelope.
    _sorted_set(case["requires"], "/requires")
    _sorted_set(case["rules"], "/rules")
    _sorted_set([a["path"] for a in case["assertions"]], "/assertions")
    for i, a in enumerate(case["assertions"]):
        _sorted_set(a["rules"], f"/assertions/{i}/rules")
    # 3. Rules resolve.
    for i, ref in enumerate(case["rules"]):
        rid, row = _rule_parts(ref)
        if rid not in registry:
            raise Reject("unknown-rule", f"/rules/{i}", rid)
        active, rows = registry[rid]
        if row is not None and row not in rows:
            raise Reject("unknown-rule-row", f"/rules/{i}", ref)
        if not active:
            raise Reject("retired-rule", f"/rules/{i}", rid)
    # 4. Assertions.
    cited, covered = set(case["rules"]), set()
    for i, a in enumerate(case["assertions"]):
        if not pointer(case, a["path"])[0]:
            raise Reject("unbound-assertion", f"/assertions/{i}/path", a["path"])
        for j, r in enumerate(a["rules"]):
            if r not in cited:
                raise Reject("assertion-rule-not-cited", f"/assertions/{i}/rules/{j}", r)
            covered.add(r)
    for i, r in enumerate(case["rules"]):
        if r not in covered:
            raise Reject("uncovered-rule", f"/rules/{i}", r)
    # 5. Transaction sources.
    sources = []
    if profile == "state-transition":
        sources = [("/input/transaction", inp["transaction"])]
    elif profile == "block-build":
        sources = [(f"/input/candidates/{i}", c) for i, c in enumerate(inp["candidates"])]
    for path, tx in sources:
        if tx["kind"] == "synthetic":
            _synthetic(tx, path)
        elif (tx["kind"] == "deposit") != _deposit(tx["raw"]):
            raise Reject("inconsistent-transaction", path + "/raw", "kind and bytes disagree")
    # 6. Requirements.
    if derive_requirements(profile, inp, exp) != set(case["requires"]):
        raise Reject("requirement-mismatch", "/requires", "requires differs from the content")
    # 7. Consistency.
    if profile == "state-transition":
        executed = _outcome(exp["outcome"], "/expected/outcome")
        groups = ["receipt", "gasLedgers", "resources"]
        if not executed:
            groups.append("limit")
            groups += [g for g in ("gasPools", "detention") if g in exp]
            for g in groups:
                if exp[g] is not None:
                    raise Reject("inconsistent-outcome", "/expected/" + g, "no outcome, no group")
        else:
            for g in groups:
                if exp[g] is None:
                    raise Reject("inconsistent-outcome", "/expected/" + g, "executed, group required")
            _receipt_status(exp["outcome"], exp["receipt"], "/expected/receipt/status")
    elif profile in ("block-import", "stateless-block"):
        for i, block in _valid_blocks(exp["blocks"]):
            for j, tx in enumerate(block["transactions"]):
                _block_tx(tx, f"/expected/blocks/{i}/transactions/{j}")
        for i, block in enumerate(exp["blocks"] or []):
            underived = any(block[k] is None for k in ("activeSpec", "depositOnly", "activation"))
            if underived and block["failure"]["phase"] != "decode":
                raise Reject("inconsistent-outcome", f"/expected/blocks/{i}", "flags are derived for every block that decodes")
        if profile == "stateless-block":
            verified = exp["witness"]["status"] == "verified"
            for key in ("blocks", "head", "state"):
                if (exp[key] is None) == verified:
                    raise Reject("inconsistent-outcome", "/expected/" + key, "witness")
            attached = inp["witness"]["proof"] is not None
            if verified and (exp["witness"].get("proof") == "valid") != attached:
                raise Reject("inconsistent-outcome", "/expected/witness/proof", "proof")
    elif profile == "block-build":
        for j, tx in enumerate(exp["transactions"]):
            _block_tx(tx, f"/expected/transactions/{j}")
    # 8. State.
    pre = inp.get("pre")
    completeness = pre.get("completeness") if isinstance(pre, dict) else None
    if completeness == "complete":
        for address in sorted(pre["accounts"]):
            storage = pre["accounts"][address]["storage"]
            for key in sorted(storage):
                if storage[key] == "0x0":
                    raise Reject("zero-slot-in-complete-state", child(child(child("/input/pre/accounts", address), "storage"), key), "zero")
    if completeness != "complete":
        roots = []
        if profile in ("block-import", "stateless-block"):
            roots = [(f"/expected/blocks/{i}/commitments", b["commitments"]) for i, b in _valid_blocks(exp["blocks"])]
        elif profile == "block-build":
            roots = [("/expected/commitments", exp["commitments"])]
        for path, commitments in roots:
            if "mpt-state-root" in commitments:
                raise Reject("root-over-sparse-state", path + "/mpt-state-root", "sparse")
    # 9. Observation sets.
    def tx_sets(tx, path):
        reasons = tx["outcome"]["admission"].get("reasons")
        if reasons is not None:
            _sorted_set(reasons, path + "/outcome/admission/reasons")
        if "reads" in tx:
            _sorted_set(tx["reads"]["codes"], path + "/reads/codes")
    if profile == "state-transition":
        tx_sets(exp, "/expected")
    elif profile == "transaction-validation":
        if "reasons" in exp["validation"]:
            _sorted_set(exp["validation"]["reasons"], "/expected/validation/reasons")
    elif profile in ("block-import", "stateless-block"):
        for i, block in _valid_blocks(exp["blocks"]):
            for j, tx in enumerate(block["transactions"]):
                tx_sets(tx, f"/expected/blocks/{i}/transactions/{j}")
    else:
        for i, d in enumerate(exp["decisions"]):
            _sorted_set(d["reasons"], f"/expected/decisions/{i}/reasons")
        for j, tx in enumerate(exp["transactions"]):
            tx_sets(tx, f"/expected/transactions/{j}")
    # 10. References.
    if profile in ("block-import", "stateless-block"):
        inputs, results = inp["blocks"], exp["blocks"] or []
        if results:
            for i, block in enumerate(results[:-1]):
                if block["status"] != "valid":
                    raise Reject("inconsistent-outcome", f"/expected/blocks/{i}", "import stops")
            last_valid = results[-1]["status"] == "valid"
            if (last_valid and len(results) != len(inputs)) or len(results) > len(inputs):
                raise Reject("invalid-reference", "/expected/blocks", "count")
            accepted = sum(1 for b in results if b["status"] == "valid")
            if accepted == 0:
                header = inp["anchor"]["header"]
            elif inputs[accepted - 1]["encoding"] == "fields":
                header = inputs[accepted - 1]["header"]
            else:
                header = None
            if header is not None and _qty(header["number"]) != _qty(exp["head"]["number"]):
                raise Reject("inconsistent-outcome", "/expected/head/number", "head")
            if accepted == 0 and exp["state"]["accounts"]:
                raise Reject("inconsistent-outcome", "/expected/state", "failed import changes nothing")
            for i, block in enumerate(results):
                if inputs[i]["encoding"] != "fields":
                    continue
                n_in = len(inputs[i]["transactions"])
                if block["status"] == "valid":
                    if len(block["transactions"]) != n_in:
                        raise Reject("invalid-reference", f"/expected/blocks/{i}/transactions", "count")
                else:
                    ti = block["failure"]["transactionIndex"]
                    if ti is not None and _qty(ti) >= n_in:
                        raise Reject("invalid-reference", f"/expected/blocks/{i}/failure/transactionIndex", "index")
    elif profile == "block-build":
        n = len(inp["candidates"])
        executed, commits = set(), []
        for i, action in enumerate(inp["actions"]):
            c = _qty(action["candidate"])
            if c >= n:
                raise Reject("invalid-reference", f"/input/actions/{i}/candidate", "index")
            if action["op"] == "execute":
                executed.add(c)
                continue
            if c not in executed:
                raise Reject("invalid-reference", f"/input/actions/{i}", "no pending execution")
            executed.discard(c)
            if action["op"] == "commit":
                commits.append(c)
        if len(exp["decisions"]) != n:
            raise Reject("invalid-reference", "/expected/decisions", "count")
        committed = set()
        for i, c in enumerate(exp["committed"]):
            if _qty(c) >= n or _qty(c) in committed:
                raise Reject("invalid-reference", f"/expected/committed/{i}", "index")
            committed.add(_qty(c))
        for i, d in enumerate(exp["decisions"]):
            included = d["decision"] == "included"
            if included != (i in committed) or included == bool(d["reasons"]):
                raise Reject("inconsistent-outcome", f"/expected/decisions/{i}", "decision")
        attempts = iter(commits)
        for c in exp["committed"]:
            if not any(a == _qty(c) for a in attempts):
                raise Reject("inconsistent-outcome", "/expected/committed", "not in the order of the commit actions")
        if len(exp["transactions"]) != len(committed):
            raise Reject("invalid-reference", "/expected/transactions", "count")


def check_case(data: bytes, schemas: Schemas, specs: Specs):
    value = parse_strict(data)
    schemas.check(value, schemas.docs["fixture.json"], "", "fixture.json")
    semantic_checks(value, specs)
    projection = {k: v for k, v in value.items() if k not in NON_SEMANTIC}
    return value, sha256(canonical(value)), sha256(canonical(projection))


def check_manifest(data: bytes, schemas: Schemas):
    value = parse_strict(data)
    schemas.check(value, schemas.docs["manifest.json"], "", "manifest.json")
    ids = [c["caseId"] for c in value["cases"]]
    _sorted_set(ids, "/cases")
    for name in sorted(value["shards"], key=lambda k: k.encode("utf-8")):
        members = value["shards"][name]
        base = child("/shards", name)
        _sorted_set(members, base)
        for i, member in enumerate(members):
            if member not in ids:
                raise Reject("invalid-reference", f"{base}/{i}", member)
    if _qty(value["counts"]["cases"]) != len(ids):
        raise Reject("invalid-reference", "/counts/cases", "count")
    if _qty(value["counts"]["blobs"]) != len(value["blobs"]):
        raise Reject("invalid-reference", "/counts/blobs", "count")
    return value


# ------------------------------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    vectors_dir = os.path.abspath(argv[1])
    root = os.path.dirname(vectors_dir)
    schemas = Schemas(os.path.join(root, "schema"))
    with open(os.path.join(vectors_dir, "index.json"), "rb") as f:
        index = parse_strict(f.read())
    specs = Specs(os.path.join(root, index["specs"]))
    failures: list[str] = []
    passed = 0
    for v in index["vectors"]:
        with open(os.path.join(vectors_dir, v["input"]), "rb") as f:
            data = f.read()
        try:
            if v["kind"] == "json":
                value = parse_strict(data)
                digests = {"digest": sha256(canonical(value))}
            elif v["kind"] == "case":
                value, file_digest, semantic = check_case(data, schemas, specs)
                digests = {"fileDigest": file_digest, "semanticDigest": semantic}
            else:
                value = check_manifest(data, schemas)
                digests = {"digest": sha256(canonical(value))}
        except Reject as r:
            want = v.get("error")
            if want is None:
                failures.append(f"{v['id']}: rejected: {r}")
            elif r.code != want["code"] or (r.code not in JSON_LAYER and r.path != want["path"]):
                failures.append(f"{v['id']}: expected {want['code']} at {want['path']!r}, got {r.code} at {r.path!r}")
            else:
                passed += 1
            continue
        if "error" in v:
            failures.append(f"{v['id']}: accepted, expected {v['error']['code']}")
            continue
        with open(os.path.join(vectors_dir, v["canonical"]), "rb") as f:
            want_bytes = f.read()
        if canonical(value) != want_bytes:
            failures.append(f"{v['id']}: canonical bytes differ")
            continue
        wrong = [k for k, d in digests.items() if v[k] != d]
        if wrong:
            failures.append(f"{v['id']}: {', '.join(wrong)} differ")
            continue
        passed += 1
    examples = 0
    examples_dir = os.path.join(root, "examples")
    if os.path.isdir(examples_dir):
        for name in sorted(os.listdir(examples_dir)):
            if name.endswith(".json"):
                with open(os.path.join(examples_dir, name), "rb") as f:
                    try:
                        check_case(f.read(), schemas, specs)
                        examples += 1
                    except Reject as r:
                        failures.append(f"examples/{name}: rejected: {r}")
        negative_dir = os.path.join(examples_dir, "negative")
        for name in sorted(os.listdir(negative_dir)) if os.path.isdir(negative_dir) else []:
            if not name.endswith(".json"):
                continue
            want = name[:-5].split("--")[0]
            with open(os.path.join(negative_dir, name), "rb") as f:
                try:
                    check_case(f.read(), schemas, specs)
                    failures.append(f"examples/negative/{name}: accepted")
                except Reject as r:
                    if r.code != want:
                        failures.append(f"examples/negative/{name}: expected {want}, got {r}")
                    else:
                        examples += 1
    for failure in failures:
        print("FAIL " + failure)
    total = len(index["vectors"])
    if failures:
        print(f"check_vectors: FAILED: {len(failures)} problem(s); {passed}/{total} vectors agree")
        return 1
    print(f"check_vectors: ok: {passed}/{total} vectors reproduced, {examples} examples checked")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
