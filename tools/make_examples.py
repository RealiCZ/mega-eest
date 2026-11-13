#!/usr/bin/env python3
"""Write the example fixtures under examples/ from the definitions in this file.

The examples show the shape of every profile with real encodings: signed transactions are signed
with a well-known test key, deposits and headers are RLP-encoded, and the parent anchor of a block
is the Keccak-256 of the anchor header's encoding. Their expected values are ILLUSTRATIVE: they
have not been executed by an implementation or reviewed against the specification, and every
example says so in its provenance (`status: example`). Only the shape and the encodings are
meant to be read from them.

Usage:
    tools/make_examples.py            write examples/*.json and examples/negative/*.json
    tools/make_examples.py --check    fail when a written file differs

Standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# ------------------------------------------------------------------------------------------------
# Keccak-256 (the original Keccak padding, not SHA-3's).

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 2) % rate) + b"\x80"
    if len(msg) % rate:
        raise AssertionError("padding")
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# ------------------------------------------------------------------------------------------------
# RLP

def rlp(item) -> bytes:
    if isinstance(item, int):
        item = b"" if item == 0 else item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, (bytes, bytearray)):
        if len(item) == 1 and item[0] < 0x80:
            return bytes(item)
        return _length(len(item), 0x80) + bytes(item)
    payload = b"".join(rlp(x) for x in item)
    return _length(len(payload), 0xC0) + payload


def _length(n: int, offset: int) -> bytes:
    if n < 56:
        return bytes([offset + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(b)]) + b


# ------------------------------------------------------------------------------------------------
# secp256k1 signing with RFC 6979 nonces.

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def _mul(k: int, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _rfc6979(key: int, h: bytes) -> int:
    import hmac
    x = key.to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(key: int, h: bytes) -> tuple[int, int, int]:
    k = _rfc6979(key, h)
    r_point = _mul(k, G)
    r = r_point[0] % N
    s = pow(k, -1, N) * (int.from_bytes(h, "big") + r * key) % N
    recid = r_point[1] & 1
    if s > N // 2:
        s, recid = N - s, recid ^ 1
    return recid, r, s


def address_of(key: int) -> bytes:
    x, y = _mul(key, G)
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


# The secret key of Ethereum's own test fixtures; its address is 0xa94f...6ebf0b.
TEST_KEY = 0x45A915E4D060149EB4365960E6A7A45F334393093061116B197E3240065FF2D8


def signed_legacy(chain_id: int, nonce: int, gas_price: int, gas: int, to: bytes, value: int, data: bytes) -> bytes:
    fields = [nonce, gas_price, gas, to, value, data]
    recid, r, s = sign(TEST_KEY, keccak256(rlp(fields + [chain_id, 0, 0])))
    return rlp(fields + [recid + 35 + 2 * chain_id, r, s])


def deposit(source_hash: bytes, sender: bytes, to: bytes, mint: int, value: int, gas: int, data: bytes) -> bytes:
    return b"\x7e" + rlp([source_hash, sender, to, mint, value, gas, 0, data])


# ------------------------------------------------------------------------------------------------
# Helpers for the JSON

def hx(b: bytes) -> str:
    return "0x" + b.hex()


def q(n: int) -> str:
    return hex(n)


def h32(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


with open(os.path.join(ROOT, "specs", "satin-cac999a", "descriptor.json"), encoding="utf-8") as f:
    SATIN = {"name": "megaeth/Satin", "descriptor": sha256(canonical(json.load(f)))}

SENDER = address_of(TEST_KEY)
assert hx(SENDER) == "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b", hx(SENDER)
CONTRACT = bytes.fromhex("00000000000000000000000000000000000c0de0")
COINBASE = bytes.fromhex("4200000000000000000000000000000000000011")
REGISTRY = bytes.fromhex("6342000000000000000000000000000000000006")
CHAIN_ID = 1
EMPTY_TRIE = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
EMPTY_OMMERS = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
EMPTY_REQUESTS = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ZERO32 = "0x" + "00" * 32
BLOOM0 = "0x" + "00" * 256
EXAMPLE_NOTE = (
    "Expected values are illustrative: they show the shape of the format and have not been "
    "executed by an implementation or reviewed against the specification."
)

PROVENANCE = {
    "status": "example",
    "note": EXAMPLE_NOTE,
    "generator": "tools/make_examples.py",
}


def block_env(number: int, timestamp: int):
    return {
        "number": q(number),
        "timestamp": q(timestamp),
        "coinbase": hx(COINBASE),
        "gasLimit": q(30_000_000_000),
        "baseFee": q(1_000_000),
        "prevRandao": ZERO32,
        "parentHash": h32(0xA11CE),
        "parentTimestamp": q(timestamp - 1),
        "parentBeaconBlockRoot": ZERO32,
        "extraData": "0x",
        "slotNumber": "0x0",
        "blobBaseFee": "0x1",
        "depositOnly": False,
        "activation": False,
    }


def dims(data: int, kv: int, growth: int):
    return {
        "dataSize": {"limit": q(13_107_200), "net": str(data), "reported": q(max(data, 0))},
        "kvUpdates": {"limit": q(500_000), "net": str(kv), "reported": q(max(kv, 0))},
        "stateGrowth": {"limit": q(1_000), "net": str(growth), "reported": q(max(growth, 0))},
    }


def header(number: int, parent_hash: str, timestamp: int, state_root: str):
    return {
        "parentHash": parent_hash,
        "ommersHash": EMPTY_OMMERS,
        "beneficiary": hx(COINBASE),
        "stateRoot": state_root,
        "transactionsRoot": EMPTY_TRIE,
        "receiptsRoot": EMPTY_TRIE,
        "logsBloom": BLOOM0,
        "difficulty": "0x0",
        "number": q(number),
        "gasLimit": q(30_000_000_000),
        "gasUsed": "0x0",
        "timestamp": q(timestamp),
        "extraData": "0x",
        "mixHash": ZERO32,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": q(1_000_000),
        "withdrawalsRoot": EMPTY_TRIE,
        "blobGasUsed": "0x0",
        "excessBlobGas": "0x0",
        "parentBeaconBlockRoot": ZERO32,
        "requestsHash": EMPTY_REQUESTS,
    }


HEADER_ORDER = [
    "parentHash", "ommersHash", "beneficiary", "stateRoot", "transactionsRoot", "receiptsRoot",
    "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash",
    "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas",
    "parentBeaconBlockRoot", "requestsHash",
]
QUANTITIES = {"difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed", "excessBlobGas"}


def header_hash(h) -> str:
    items = [int(h[k], 16) if k in QUANTITIES else bytes.fromhex(h[k][2:]) for k in HEADER_ORDER]
    return hx(keccak256(rlp(items)))


def chain():
    return {"chainId": q(CHAIN_ID), "schedule": [{"spec": SATIN, "timestamp": "0x0"}], "rawConfig": None}


def envelope(case_id, profile, requires, rules, inp, expected, provenance_extra=None):
    prov = dict(PROVENANCE)
    prov.update(provenance_extra or {})
    return {
        "format": "mega-execution-fixture",
        "schemaVersion": "2.0",
        "caseId": case_id,
        "specRef": SATIN,
        "profile": profile,
        "requires": sorted(requires),
        "rules": sorted(rules),
        "input": inp,
        "expected": expected,
        "provenance": prov,
    }


# ------------------------------------------------------------------------------------------------
# The examples

def state_transition():
    # PUSH1 1, PUSH1 0, SSTORE, STOP: write 1 into the contract's empty slot 0.
    code = bytes.fromhex("6001600055") + b"\x00"
    raw = signed_legacy(CHAIN_ID, 0, 1_000_000, 1_000_000, CONTRACT, 0, b"")
    slot0 = ZERO32
    st_requires = ["group:outcome", "group:state", "group:receipts", "group:gas-ledgers", "group:resources",
                   "group:limit", "group:reads", "feature:salt"]
    return envelope(
        "satin/state-gas/sstore-fresh-slot/minimum-bucket",
        "state-transition",
        st_requires,
        ["SATIN-POOL-019", "SATIN-STATE-008", "SATIN-WIT-009"],
        {
            "chain": {"chainId": q(CHAIN_ID)},
            "block": block_env(2, 1_700_000_002),
            "blockHashes": {},
            "pre": {
                "completeness": "complete",
                "accounts": {
                    hx(SENDER): {"nonce": "0x0", "balance": q(10**18), "code": "0x", "storage": {}},
                    hx(CONTRACT): {"nonce": "0x1", "balance": "0x0", "code": hx(code), "storage": {}},
                },
            },
            "transaction": {"kind": "signed", "raw": hx(raw)},
            "salt": {"mapping": "salt-v1", "complete": True, "buckets": {}},
        },
        {
            "outcome": {
                "admission": {"status": "admitted"},
                "execution": {"status": "success", "output": "0x", "createdAddress": None},
                "commit": {"status": "committed"},
            },
            "state": {
                "accounts": {
                    hx(SENDER): {"nonce": "0x1", "balance": q(10**18 - 150_000 * 1_000_000), "code": "0x", "storage": {}},
                    hx(CONTRACT): {"nonce": "0x1", "balance": "0x0", "code": hx(code), "storage": {slot0: "0x1"}},
                }
            },
            "receipt": {"type": "0x0", "status": "0x1", "gasUsed": q(150_000), "logs": [],
                        "depositNonce": None, "depositReceiptVersion": None},
            "gasLedgers": {"total": q(150_000), "regular": q(40_000), "state": q(97_920), "history": q(12_080),
                           "historyBytes": q(151), "refund": "0x0", "floor": q(21_000), "gasUsed": q(150_000),
                           "blockGas": q(150_000)},
            "resources": dims(151, 3, 1),
            "limit": None,
            "reads": {
                "accounts": {
                    hx(COINBASE): None,
                    hx(SENDER): {"nonce": "0x0", "balance": q(10**18), "codeHash": hx(keccak256(b""))},
                    hx(CONTRACT): {"nonce": "0x1", "balance": "0x0", "codeHash": hx(keccak256(code))},
                },
                "storage": {hx(CONTRACT): {slot0: "0x0"}},
                "codes": [hx(keccak256(code))],
                "blockHashes": {},
                "buckets": {"0x2a": q(256)},
                "oracle": [],
                "hints": [],
            },
        },
    )


def deposit_case():
    depositor = bytes.fromhex("00000000000000000000000000000000000de905")
    recipient = bytes.fromhex("00000000000000000000000000000000000ba5e0")
    raw = deposit(bytes.fromhex("5e" * 32), depositor, recipient, 10**15, 10**15, 100_000, b"")
    return envelope(
        "satin/deposits/empty-caller/new-account-charged-once",
        "state-transition",
        ["group:outcome", "group:state", "group:receipts", "group:gas-ledgers", "group:resources", "group:limit",
         "feature:deposit"],
        ["SATIN-DEP-003", "SATIN-DEP-009"],
        {
            "chain": {"chainId": q(CHAIN_ID)},
            "block": block_env(3, 1_700_000_003),
            "blockHashes": {},
            "pre": {"completeness": "complete", "accounts": {}},
            "transaction": {"kind": "deposit", "raw": hx(raw)},
        },
        {
            "outcome": {
                "admission": {"status": "admitted"},
                "execution": {"status": "success", "output": "0x", "createdAddress": None},
                "commit": {"status": "committed"},
            },
            "state": {
                "accounts": {
                    hx(depositor): {"nonce": "0x1", "balance": "0x0", "code": "0x", "storage": {}},
                    hx(recipient): {"nonce": "0x0", "balance": q(10**15), "code": "0x", "storage": {}},
                }
            },
            "receipt": {"type": "0x7e", "status": "0x1", "gasUsed": q(100_000), "logs": [],
                        "depositNonce": "0x0", "depositReceiptVersion": "0x1"},
            "gasLedgers": {"total": q(100_000), "regular": q(12_000), "state": q(81_600), "history": q(6_400),
                           "historyBytes": q(80), "refund": "0x0", "floor": q(21_000), "gasUsed": q(100_000),
                           "blockGas": q(100_000)},
            "resources": dims(80, 2, 2),
            "limit": None,
        },
        {"input": "A user deposit from an address the state holds no account for, minting and sending value to another empty address."},
    )


def validation_case():
    raw = signed_legacy(CHAIN_ID, 0, 1_000_000, 10_000, CONTRACT, 0, b"")
    return envelope(
        "satin/transaction-validation/gas-limit-below-intrinsic-regular",
        "transaction-validation",
        ["group:validation"],
        ["SATIN-VAL-002", "SATIN-VAL-003"],
        {"chain": {"chainId": q(CHAIN_ID)}, "block": None, "pre": None, "raw": hx(raw)},
        {"validation": {"status": "rejected", "phase": "validation", "reasons": ["intrinsic-gas-too-low"]}},
        {"input": "A gas limit of 10,000 is below TX_BASE_COST (12,000) alone, so step 2 of SATIN-VAL-003 refuses it whatever else the transaction carries."},
    )


def invalid_block_case():
    genesis = header(0, ZERO32, 1_700_000_000, h32(0x5A17))
    block1 = header(1, header_hash(genesis), 1_700_000_001, h32(0x5A18))
    return envelope(
        "satin/sequencer-registry/foreign-code/block-invalid",
        "block-import",
        ["group:blocks", "group:state", "group:outcome", "group:receipts", "feature:sparse-state"],
        ["SATIN-REG-004"],
        {
            "chain": chain(),
            "anchor": {"header": genesis},
            "pre": {
                "completeness": "sparse",
                "accounts": {
                    hx(REGISTRY): {"nonce": "0x1", "balance": "0x0", "code": "0x00", "storage": {}, "storageComplete": True},
                },
            },
            "ancestors": {},
            "blocks": [{"encoding": "fields", "header": block1, "transactions": []}],
        },
        {
            "blocks": [{
                "status": "invalid",
                "activeSpec": "megaeth/Satin",
                "depositOnly": False,
                "activation": False,
                "failure": {"phase": "pre-block", "reason": "invalid-registry", "transactionIndex": None},
            }],
            "head": {"number": "0x0", "hash": header_hash(genesis)},
            "state": {"accounts": {}},
        },
        {"input": "The SequencerRegistry's address holds one byte of foreign code when block 1 resolves the live system address."},
    )


def witness_case():
    genesis = header(0, ZERO32, 1_700_000_000, h32(0x5A17))
    block1 = header(1, header_hash(genesis), 1_700_000_001, h32(0x5A18))
    wrong_parent = hx(keccak256(b"another parent"))
    return envelope(
        "satin/stateless-witness/parent-anchor/wrong-parent-hash",
        "stateless-block",
        ["group:blocks", "group:state", "group:outcome", "group:receipts", "group:witness"],
        ["SATIN-WIT-010"],
        {
            "chain": chain(),
            "anchor": {"header": genesis},
            "pre": {"completeness": "witness", "accounts": {}},
            "ancestors": {},
            "blocks": [{"encoding": "fields", "header": block1, "transactions": []}],
            "witness": {"parentHash": wrong_parent, "parentStateRoot": h32(0x5A17), "proof": None},
        },
        {
            "witness": {"status": "failed", "stage": "anchor", "reason": "wrong-parent-anchor", "read": None},
            "blocks": None,
            "head": None,
            "state": None,
        },
        {"input": "The witness names a parent hash other than the block header's parentHash, the Keccak-256 of the anchor header."},
    )


def block_build_case():
    genesis = header(0, ZERO32, 1_700_000_000, h32(0x5A17))
    to = bytes.fromhex("00000000000000000000000000000000000ba5e0")
    small = signed_legacy(CHAIN_ID, 0, 1_000_000, 100_000, to, 10**15, b"")
    large = signed_legacy(CHAIN_ID, 1, 1_000_000, 2_000_000, to, 0, b"\x01" * 4096)
    return envelope(
        "satin/block-building/policy-data-size/skip-and-continue",
        "block-build",
        ["group:blocks", "group:decisions", "group:state", "group:outcome", "group:receipts"],
        ["SATIN-BLK-011"],
        {
            "chain": chain(),
            "anchor": {"header": genesis},
            "pre": {
                "completeness": "complete",
                "accounts": {hx(SENDER): {"nonce": "0x0", "balance": q(10**18), "code": "0x", "storage": {}}},
            },
            "ancestors": {},
            "block": {
                "number": "0x1",
                "timestamp": q(1_700_000_001),
                "beneficiary": hx(COINBASE),
                "gasLimit": q(30_000_000_000),
                "baseFeePerGas": q(1_000_000),
                "prevRandao": ZERO32,
                "parentBeaconBlockRoot": ZERO32,
                "extraData": "0x",
            },
            "policy": {"gas": None, "dataSize": q(2_048), "kvUpdates": None, "stateGrowth": None},
            "candidates": [{"kind": "signed", "raw": hx(small)}, {"kind": "signed", "raw": hx(large)}],
            "actions": [
                {"op": "execute", "candidate": "0x0"},
                {"op": "commit", "candidate": "0x0"},
                {"op": "execute", "candidate": "0x1"},
                {"op": "abandon", "candidate": "0x1"},
            ],
        },
        {
            "decisions": [
                {"decision": "included", "reasons": []},
                {"decision": "skipped", "reasons": ["policy-limit"]},
            ],
            "committed": ["0x0"],
            "transactions": [{
                "outcome": {
                    "admission": {"status": "admitted"},
                    "execution": {"status": "success", "output": "0x", "createdAddress": None},
                    "commit": {"status": "committed"},
                },
                "receipt": {"type": "0x0", "status": "0x1", "gasUsed": q(52_000), "cumulativeGasUsed": q(52_000),
                            "logs": [], "logsBloom": BLOOM0, "depositNonce": None, "depositReceiptVersion": None},
            }],
            "counters": {"gasUsed": q(52_000), "dataSize": q(150), "kvUpdates": "0x3", "stateGrowth": "0x1"},
            "commitments": {"salt-state-root": h32(0x5A18), "mpt-receipts-root": h32(0x7EC1)},
            "state": {
                "accounts": {
                    hx(SENDER): {"nonce": "0x1", "balance": q(10**18 - 10**15 - 52_000 * 1_000_000), "code": "0x", "storage": {}},
                    hx(to): {"nonce": "0x0", "balance": q(10**15), "code": "0x", "storage": {}},
                }
            },
        },
        {"input": "The builder's policy holds the block to 2,048 bytes of data size; the second candidate's 4 KiB of calldata does not fit, so it is skipped and building continues. A skip leaves no receipt and is not an invalid transaction."},
    )


EXAMPLES = {
    "state-transition-sstore-fresh-slot.json": state_transition,
    "deposit-state-transition-new-caller.json": deposit_case,
    "transaction-validation-gas-below-intrinsic.json": validation_case,
    "invalid-block-foreign-registry-code.json": invalid_block_case,
    "stateless-block-witness-wrong-parent-anchor.json": witness_case,
    "block-build-policy-skip.json": block_build_case,
}


# ------------------------------------------------------------------------------------------------
# Negative examples: one defect each; the file name before "--" is the error code both readers
# must report.

def negatives(base: dict, deposit_base: dict, block_base: dict, build_base: dict) -> dict[str, str]:
    out: dict[str, str] = {}

    def add(name: str, case, raw: str | None = None):
        out[name] = raw if raw is not None else json.dumps(case, indent=2, ensure_ascii=False) + "\n"

    c = copy.deepcopy(base)
    c["input"]["gasSchedule"] = {}
    add("unknown-field--input-member.json", c)

    c = copy.deepcopy(base)
    del c["expected"]["receipt"]
    add("missing-field--receipt-group.json", c)

    c = copy.deepcopy(base)
    c["requires"] = sorted(c["requires"] + ["feature:parallel-execution"])
    add("unknown-requirement--future-feature.json", c)

    c = copy.deepcopy(base)
    c["requires"].remove("group:reads")
    add("requirement-mismatch--reads-carried-not-required.json", c)

    c = copy.deepcopy(base)
    c["input"]["pre"]["accounts"][hx(SENDER)]["nonce"] = "0x00"
    add("non-minimal-quantity--nonce.json", c)

    c = copy.deepcopy(base)
    c["input"]["pre"]["accounts"][hx(CONTRACT)]["code"] = "0x6001600055" + "0A"
    add("uppercase-hex--code.json", c)

    c = copy.deepcopy(base)
    c["rules"] = sorted(c["rules"] + ["SATIN-POOL-999"])
    add("unknown-rule--pool-999.json", c)

    c = copy.deepcopy(base)
    c["rules"] = sorted(c["rules"] + ["SATIN-POOL-013"])
    add("retired-rule--pool-013.json", c)

    # Schema 1's per-path rule lists: schema 2 has no `assertions` member (D-76).
    c = copy.deepcopy(base)
    c["assertions"] = [{"path": "/expected/gasLedgers", "rules": ["SATIN-POOL-019", "SATIN-STATE-008"]}]
    add("unknown-field--assertions-member.json", c)

    c = copy.deepcopy(base)
    c["input"]["pre"]["accounts"][hx(CONTRACT)]["storage"] = {ZERO32: "0x0"}
    add("zero-slot-in-complete-state--explicit-zero.json", c)

    c = copy.deepcopy(base)
    c["expected"]["outcome"]["admission"] = {"status": "refused", "phase": "validation", "reasons": ["nonce-too-low"]}
    c["expected"]["outcome"]["execution"] = None
    c["expected"]["outcome"]["commit"] = {"status": "not-committed"}
    add("inconsistent-outcome--refused-with-receipt.json", c)

    c = copy.deepcopy(deposit_base)
    c["input"]["transaction"]["kind"] = "signed"
    add("inconsistent-transaction--deposit-bytes-as-signed.json", c)

    c = copy.deepcopy(deposit_base)
    c["expected"]["outcome"]["admission"] = {"status": "failed-deposit"}
    add("inconsistent-outcome--failed-deposit-that-succeeded.json", c)

    c = copy.deepcopy(block_base)
    c["expected"]["blocks"][0]["activeSpec"] = "megaeth/Rex6"
    add("spec-name-mismatch--active-spec-not-scheduled.json", c)

    c = copy.deepcopy(block_base)
    c["expected"]["head"]["number"] = "0x1"
    add("inconsistent-outcome--head-moved-after-failed-import.json", c)

    c = copy.deepcopy(build_base)
    c["input"]["actions"] = [{"op": "commit", "candidate": "0x0"}, {"op": "execute", "candidate": "0x1"}, {"op": "abandon", "candidate": "0x1"}]
    add("invalid-reference--commit-without-execute.json", c)

    c = copy.deepcopy(build_base)
    c["input"]["actions"] = [a for a in c["input"]["actions"] if a["op"] != "commit"]
    add("inconsistent-outcome--committed-without-commit-action.json", c)

    c = copy.deepcopy(deposit_base)
    c["requires"].remove("feature:deposit")
    add("requirement-mismatch--deposit-feature-missing.json", c)

    c = copy.deepcopy(block_base)
    c["expected"]["blocks"][0] = {
        "status": "valid", "activeSpec": "megaeth/Satin", "depositOnly": False, "activation": False,
        "preBlock": [], "transactions": [],
        "counters": {"gasUsed": "0x0", "dataSize": "0x0", "kvUpdates": "0x0", "stateGrowth": "0x0"},
        "commitments": {"mpt-state-root": h32(0x5A18)},
        "state": {"accounts": {}},
    }
    add("root-over-sparse-state--mpt-root.json", c)

    c = copy.deepcopy(block_base)
    c["expected"]["blocks"][0]["failure"]["reason"] = "invalid-sequencer"
    add("invalid-value--block-failure-reason.json", c)

    text = json.dumps(base, indent=2, ensure_ascii=False)
    add("duplicate-key--profile-twice.json", None,
        text.replace('"profile": "state-transition",', '"profile": "state-transition",\n  "profile": "state-transition",', 1) + "\n")
    add("number-not-allowed--float-gas-limit.json", None,
        text.replace('"gasLimit": "0x6fc23ac00"', '"gasLimit": 3.0e10', 1) + "\n")
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    files: dict[str, str] = {}
    built = {name: make() for name, make in EXAMPLES.items()}
    for name, case in built.items():
        files[os.path.join("examples", name)] = json.dumps(case, indent=2, ensure_ascii=False) + "\n"
    for name, text in negatives(
        built["state-transition-sstore-fresh-slot.json"],
        built["deposit-state-transition-new-caller.json"],
        built["invalid-block-foreign-registry-code.json"],
        built["block-build-policy-skip.json"],
    ).items():
        files[os.path.join("examples", "negative", name)] = text
    stale = []
    for sub in ("examples", os.path.join("examples", "negative")):  # a file the generator no longer writes
        for name in sorted(os.listdir(os.path.join(ROOT, sub))):
            rel = os.path.join(sub, name)
            if name.endswith(".json") and rel not in files:
                if check:
                    stale.append(rel)
                else:
                    os.remove(os.path.join(ROOT, rel))
    for rel, text in sorted(files.items()):
        path = os.path.join(ROOT, rel)
        if check:
            try:
                with open(path, encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(rel)
            except FileNotFoundError:
                stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    if stale:
        print("make_examples: out of date: " + ", ".join(stale), file=sys.stderr)
        return 1
    print(f"make_examples: {len(files)} files {'checked' if check else 'written'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
