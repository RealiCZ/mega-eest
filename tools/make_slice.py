#!/usr/bin/env python3
"""Write the vertical slice: reviewed `state-transition` cases with spec-derived expectations.

Each case is authored here — its setup, the transaction (real signed bytes, or a deposit
envelope), the SALT capacities its state lands in — and its expected observations come from
`tools/satin_model.py`, an executable restatement of the cited rules of the pinned specification
(`specs/satin-22a5f4b`). No implementation is run: the filler's output is a candidate to compare
with, never the source of these values (`tools/run-slice.sh` runs both implementations against
them).

Each case's provenance carries the derivation of every assertion — the steps, their arithmetic and
the rules each applies — and the text digest of every cited rule, so a reviewer can hold each
number to the exact rule text it was derived from.

Output: `slice/cases/<case-id>.json`, `slice/quarantine/<case-id>.json` (cases an implementation
fails against a clear rule: the expectation stands, the case stays out of the gating slice, and
`QUARANTINE` records the implementation, the exact difference and the specification's verdict),
`slice/negative/*.json` (deliberately wrong expectations that a consumer must fail without any
fixture being rewritten) and `slice/index.json`.

Usage:
    tools/make_slice.py            write the slice
    tools/make_slice.py --check    fail when a committed file differs from what this writes

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_examples as ex  # noqa: E402
import salt_mapping  # noqa: E402
import satin_model as model  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SPEC_DIR = os.path.join(ROOT, "specs", "satin-22a5f4b")
OUT = os.path.join(ROOT, "slice")

KEY = ex.TEST_KEY
SENDER = ex.address_of(KEY)
OTHER_KEY = 0x8A1F9A8F95BE41CD7CCB6168179AFB4504AEFE388D1E14474D32C45C72CE7B7A
OTHER = ex.address_of(OTHER_KEY)
CONTRACT = bytes.fromhex("00000000000000000000000000000000000c0de1")
EOA = bytes.fromhex("000000000000000000000000000000000000beef")
ABSENT = bytes.fromhex("000000000000000000000000000000000000dead")
L1_BLOCK = bytes.fromhex("4200000000000000000000000000000000000015")
REGISTRY = bytes.fromhex("6342000000000000000000000000000000000006")
COINBASE = bytes.fromhex("4200000000000000000000000000000000000011")
CHAIN_ID = 1
BLOCK_GAS_LIMIT = 10_000_000_000
ETH = 10**18
ZERO32 = "0x" + "00" * 32


def h(b: bytes) -> str:
    return "0x" + b.hex()


def q(n: int) -> str:
    return hex(n)


# --- Bytecode ----------------------------------------------------------------------------------


def push(n: int) -> bytes:
    if n == 0:
        return b"\x5f"
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x5F + len(b)]) + b


def sstore(key: int, value: int) -> bytes:
    return push(value) + push(key) + b"\x55"


def sstore_p1(key: int, value: int) -> bytes:
    """SSTORE with both operands pushed by PUSH1, as the specification's worked example has it."""
    return bytes([0x60, value, 0x60, key, 0x55])


def mstore(offset: int, value: int) -> bytes:
    return push(value) + push(offset) + b"\x52"


def log(n: int, offset: int, size: int, topics: list[int]) -> bytes:
    return b"".join(push(t) for t in reversed(topics)) + push(size) + push(offset) + bytes([0xA0 + n])


def ret(offset: int, size: int) -> bytes:
    return push(size) + push(offset) + b"\xf3"


def revert(offset: int, size: int) -> bytes:
    return push(size) + push(offset) + b"\xfd"


STOP = b"\x00"
INVALID = b"\xfe"


def init_returning(code: bytes) -> bytes:
    """Initcode that writes `code` to memory and returns it (at most 32 bytes)."""
    assert 0 < len(code) <= 32
    word = int.from_bytes(code.ljust(32, b"\x00"), "big")
    return mstore(0, word) + ret(0, len(code))


# --- Transactions -------------------------------------------------------------------------------


def _signed(ty: int, fields: list, key: int) -> bytes:
    payload = bytes([ty]) + ex.rlp(fields) if ty else ex.rlp(fields)
    recid, r, s = ex.sign(key, ex.keccak256(payload))
    return bytes([ty]) + ex.rlp(fields + [recid, r, s])


def legacy(nonce, gas_price, gas, to, value, data, chain_id=CHAIN_ID, key=KEY) -> bytes:
    fields = [nonce, gas_price, gas, to if to is not None else b"", value, data]
    recid, r, s = ex.sign(key, ex.keccak256(ex.rlp(fields + [chain_id, 0, 0])))
    return ex.rlp(fields + [recid + 35 + 2 * chain_id, r, s])


def eip2930(nonce, gas_price, gas, to, value, data, access_list) -> bytes:
    al = [[a, [k.to_bytes(32, "big") for k in keys]] for a, keys in access_list]
    return _signed(1, [CHAIN_ID, nonce, gas_price, gas, to, value, data, al], KEY)


def eip1559(nonce, max_priority, max_fee, gas, to, value, data) -> bytes:
    return _signed(2, [CHAIN_ID, nonce, max_priority, max_fee, gas, to, value, data, []], KEY)


SOURCE_HASH = bytes.fromhex("00" * 31 + "5d")


# --- Cases --------------------------------------------------------------------------------------


class Case:
    def __init__(self, case_id: str, intent: str, *, code: bytes = STOP, to=CONTRACT, value=0, data=b"", gas=1_000_000,
                 gas_price=0, base_fee=0, ty=0, max_priority=0, max_fee=0, nonce=0, sender_nonce=0, sender_balance=ETH,
                 sender_code=b"", storage=None, extra=None, salt=None, access_list=None, chain_id=CHAIN_ID,
                 deposit=None, absent_sender=False, boundary=""):
        self.case_id, self.intent, self.boundary = case_id, intent, boundary
        self.code, self.to, self.value, self.data, self.gas = code, to, value, data, gas
        self.gas_price, self.base_fee, self.ty = gas_price, base_fee, ty
        self.max_priority, self.max_fee, self.nonce = max_priority, max_fee, nonce
        self.sender_nonce, self.sender_balance, self.sender_code = sender_nonce, sender_balance, sender_code
        self.storage = storage or {}
        self.extra = extra or {}
        self.salt = salt or {}  # (address, slot or None) -> multiplier
        self.access_list = access_list or []
        self.chain_id = chain_id
        self.deposit = deposit  # (mint, gas)
        self.absent_sender = absent_sender


def cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    # Intrinsic gas, the body's history and the floor.
    add(Case("satin/intrinsic/call/eoa-no-value", "a call to an account without code, no value: the intrinsic cost and "
             "the body's history alone", to=EOA, code=b""))
    add(Case("satin/intrinsic/call/contract-stop", "a call to a contract that stops at once", code=STOP))
    add(Case("satin/intrinsic/call/self-no-value", "a transaction to its own sender pays TX_BASE_COST alone", to=SENDER, code=b""))
    add(Case("satin/intrinsic/call/self-with-value", "value to the sender itself: TX_BASE_COST alone, no record and no "
             "transfer log", to=SENDER, code=b"", value=1_000))
    add(Case("satin/intrinsic/calldata/zero-bytes", "32 zero calldata bytes: 4 gas each, 88 of history each, the floor "
             "64 each", data=bytes(32)))
    add(Case("satin/intrinsic/calldata/non-zero-bytes", "64 non-zero calldata bytes: the block counts the floor over the "
             "regular ledger", data=b"\x01" * 64, boundary="floor above the regular ledger"))
    add(Case("satin/intrinsic/calldata/mixed-bytes", "calldata of 10 zero and 10 non-zero bytes",
             data=bytes(10) + b"\xff" * 10))
    add(Case("satin/intrinsic/access-list/one-address-two-keys", "an EIP-2930 access list: 4,180 per address, 4,048 per key, "
             "20 and 32 history bytes", ty=1, access_list=[(CONTRACT, [1, 2])]))
    add(Case("satin/intrinsic/access-list/warm-slot-write", "a fresh slot the access list made warm: the SSTORE pays the warm "
             "access", ty=1, access_list=[(CONTRACT, [1])], code=sstore(1, 1) + STOP))
    # Value transfers.
    add(Case("satin/value-transfer/existing-eoa", "value to an existing account: its record before the frame, a transfer "
             "log, one KV update", to=EOA, code=b"", value=1))
    add(Case("satin/value-transfer/absent-recipient/minimum-bucket", "value to an absent account: new-account state gas at "
             "step 4, no legacy share, one unit of state growth", to=ABSENT, code=None, value=10**9))
    add(Case("satin/value-transfer/absent-recipient/bucket-x4", "value to an absent account whose bucket has four times "
             "the minimum capacity", to=ABSENT, code=None, value=10**9, salt={(ABSENT, None): 4}))
    add(Case("satin/value-transfer/contract-stop", "value to a contract that stops", value=5))
    add(Case("satin/value-transfer/contract-revert", "value to a contract that reverts: the value, its record and its "
             "transfer log are taken back", value=5, code=revert(0, 0)))
    add(Case("satin/value-transfer/with-fees", "value with a gas price above the base fee: the base fee vault and the "
             "beneficiary are credited", to=EOA, code=b"", value=7, gas_price=3_000_000, base_fee=1_000_000))
    # SSTORE.
    add(Case("satin/sstore/fresh-slot/minimum-bucket", "a cold fresh slot at m = 1: 2,100 access, 10,000 write, "
             "97,920 state gas with its 10,000 legacy share", code=sstore(1, 1) + STOP))
    add(Case("satin/sstore/fresh-slot/bucket-x2", "a fresh slot whose bucket has twice the minimum capacity",
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 2}))
    add(Case("satin/sstore/fresh-slot/bucket-x16", "a fresh slot whose bucket has sixteen times the minimum capacity",
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 16}))
    add(Case("satin/sstore/fresh-slot/capacity-between-multiples", "a bucket of 3.5 minimum buckets: m is the floor, 3",
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 3.5}, boundary="capacity between two multiples"))
    add(Case("satin/sstore/fresh-slot/with-reservoir", "a gas limit 10,000,000 above the execution cap: the body's history "
             "and the slot's state gas draw the reservoir first", code=sstore(1, 1) + STOP, gas=210_000_000))
    add(Case("satin/sstore/reset/non-zero-to-non-zero", "a slot whose original value is not zero, reset to another value",
             code=sstore(1, 7) + STOP, storage={1: 5}))
    add(Case("satin/sstore/clear/specification-example", "the worked example of SATIN-POOL-019: clearing one cold slot spends "
             "27,106 regular and 30,800 history gas, refunds 11,581 and uses 46,325", code=sstore_p1(0, 0) + STOP,
             storage={0: 1}))
    add(Case("satin/sstore/no-op/same-non-zero", "writing the present non-zero value: the access alone, no record",
             code=sstore(1, 5) + STOP, storage={1: 5}))
    add(Case("satin/sstore/no-op/zero-to-zero", "writing zero to a zero slot: the access alone", code=sstore(1, 0) + STOP))
    add(Case("satin/sstore/fresh-then-restored", "0 -> 1 -> 0 in one transaction: the state gas and the record's history "
             "come back, the restore refund applies", code=sstore(1, 1) + sstore(1, 0) + STOP))
    add(Case("satin/sstore/fresh-then-overwritten", "0 -> 1 -> 2: one rise of state growth, one record",
             code=sstore(1, 1) + sstore(1, 2) + STOP))
    add(Case("satin/sstore/reset-then-restored", "5 -> 7 -> 5: the record is taken back, the restored-reset refund applies",
             code=sstore(1, 7) + sstore(1, 5) + STOP, storage={1: 5}))
    add(Case("satin/sstore/clear-then-reset", "5 -> 0 -> 5: the cleared-slot refund is withdrawn and the restore refund "
             "applies", code=sstore(1, 0) + sstore(1, 5) + STOP, storage={1: 5}))
    add(Case("satin/sstore/two-fresh-slots/two-buckets", "two fresh slots in buckets of m = 1 and m = 4",
             code=sstore(1, 1) + sstore(2, 1) + STOP, salt={(CONTRACT, 2): 4}))
    add(Case("satin/sstore/sload-then-fresh-write", "an SLOAD makes the slot warm: the SSTORE after it pays 100 for its access",
             code=push(1) + b"\x54\x50" + sstore(1, 1) + STOP))
    add(Case("satin/sstore/fresh-slot/eip1559-fees", "a fresh slot paid by an EIP-1559 transaction: the effective price is "
             "the base fee plus the priority fee", code=sstore(1, 1) + STOP, ty=2, max_priority=2_000_000,
             max_fee=5_000_000, base_fee=1_000_000))
    # Logs.
    add(Case("satin/logs/log0-empty", "an empty LOG0: 375 regular gas, 32 history bytes", code=log(0, 0, 0, []) + STOP))
    add(Case("satin/logs/log0-one-word", "a LOG0 of one word: memory, 8 per byte, 64 history bytes",
             code=mstore(0, 0xC0FFEE) + log(0, 0, 32, []) + STOP))
    add(Case("satin/logs/log2-two-topics", "a LOG2 with two topics and no data", code=log(2, 0, 0, [0xAA, 0xBB]) + STOP))
    add(Case("satin/logs/log4-four-topics-two-words", "a LOG4 with four topics and 64 data bytes",
             code=mstore(0, 1) + mstore(32, 2) + log(4, 0, 64, [1, 2, 3, 4]) + STOP))
    add(Case("satin/logs/two-logs-in-order", "two logs keep their order", code=log(1, 0, 0, [1]) + log(1, 0, 0, [2]) + STOP))
    add(Case("satin/logs/log-after-value-transfer", "the transfer log comes before the contract's own log", value=3,
             code=log(0, 0, 0, []) + STOP))
    # Outcomes.
    add(Case("satin/outcomes/revert/empty", "an empty REVERT: the frame's regular charges stay spent", code=revert(0, 0)))
    add(Case("satin/outcomes/revert/with-data", "a REVERT with one word of data", code=mstore(0, 0xBAD) + revert(0, 32)))
    add(Case("satin/outcomes/revert/after-fresh-slot", "a REVERT after a fresh slot: the slot's state and history gas come "
             "back and return to the sender", code=sstore(1, 1) + revert(0, 0)))
    add(Case("satin/outcomes/revert/after-log", "a REVERT after a LOG: the log and its history are taken back",
             code=log(0, 0, 0, []) + revert(0, 0)))
    add(Case("satin/outcomes/return/one-word", "a RETURN of one word", code=mstore(0, 0x1234) + ret(0, 32)))
    add(Case("satin/outcomes/halt/invalid-opcode", "INVALID halts: the gas limit is used", code=INVALID, gas=100_000))
    add(Case("satin/outcomes/halt/after-fresh-slot", "a halt after a fresh slot: nothing of the slot is kept, the gas limit is "
             "used", code=sstore(1, 1) + INVALID, gas=300_000))
    add(Case("satin/outcomes/halt/out-of-gas-at-sstore", "too little gas for a fresh slot's state gas: out of gas",
             code=sstore(1, 1) + STOP, gas=60_000, boundary="below the slot's state gas"))
    add(Case("satin/outcomes/halt/with-reservoir", "a halt with a reservoir: the regular budget is used, the reservoir is "
             "returned", code=INVALID, gas=210_000_000))
    # Creation transactions.
    add(Case("satin/creation/empty-code", "a creation that deploys no code: the created account's state gas and record "
             "before the frame", to=None, data=ret(0, 0)))
    add(Case("satin/creation/one-byte-code", "a creation that deploys one byte", to=None, data=init_returning(b"\x00")))
    add(Case("satin/creation/thirty-two-byte-code", "a creation that deploys 32 bytes", to=None,
             data=init_returning(bytes(range(1, 33)))))
    add(Case("satin/creation/code-bucket-x2", "a creation whose account bucket has twice the minimum capacity", to=None,
             data=init_returning(b"\x60\x00"), salt={("created", None): 2}))
    add(Case("satin/creation/initcode-reverts", "initcode that reverts: nothing is created, the sender's nonce stays bumped",
             to=None, data=revert(0, 0)))
    add(Case("satin/creation/initcode-writes-slot", "initcode that writes a fresh slot of the created account", to=None,
             data=sstore(0, 42) + ret(0, 0)))
    # Validation refusals.
    add(Case("satin/validation/nonce-too-high", "a nonce above the account's", nonce=1))
    add(Case("satin/validation/nonce-too-low", "a nonce below the account's", nonce=2, sender_nonce=3))
    add(Case("satin/validation/insufficient-funds", "a balance below the gas limit times the price", gas_price=10**9,
             sender_balance=10**14))
    add(Case("satin/validation/below-intrinsic-regular", "a gas limit below the intrinsic regular gas", gas=14_999,
             boundary="one below the intrinsic regular gas"))
    add(Case("satin/validation/floor-above-gas-limit", "a gas limit that covers the intrinsic regular gas but not the floor",
             data=b"\x01" * 100, gas=20_000))
    add(Case("satin/validation/body-history-uncovered", "a gas limit that covers the intrinsic regular gas and the floor, "
             "not the body's history", gas=42_279, boundary="one below intrinsic plus body history"))
    add(Case("satin/validation/gas-limit-above-block", "a gas limit above the block's", gas=BLOCK_GAS_LIMIT + 1))
    add(Case("satin/validation/chain-id-mismatch", "a transaction signed for chain 2", chain_id=2))
    add(Case("satin/validation/sender-has-code", "a sender with code (EIP-3607)", sender_code=b"\x00"))
    add(Case("satin/validation/fee-cap-below-base-fee", "a gas price below the base fee", gas_price=999_999, base_fee=1_000_000))
    add(Case("satin/validation/priority-above-max-fee", "an EIP-1559 priority fee above its fee cap", ty=2,
             max_priority=3_000_000, max_fee=2_000_000))
    # Deposits.
    add(Case("satin/deposits/new-caller/minimum-bucket", "a deposit from an absent caller: its new-account state gas once, "
             "before the frame; the deposit pays history gas", deposit=(ETH, 1_000_000), absent_sender=True))
    add(Case("satin/deposits/new-caller/bucket-x2", "a deposit from an absent caller whose bucket has twice the minimum "
             "capacity", deposit=(ETH, 1_000_000), absent_sender=True, salt={("sender", None): 2}))
    add(Case("satin/deposits/existing-caller/fresh-slot", "a deposit from an existing account that writes a fresh slot",
             deposit=(0, 1_000_000), sender_nonce=3, code=sstore(1, 1) + STOP))
    return out


# --- Assembling a case --------------------------------------------------------------------------


def account(nonce=0, balance=0, code=b"", storage=None) -> dict:
    return {"nonce": q(nonce), "balance": q(balance), "code": h(code),
            "storage": {"0x" + k.to_bytes(32, "big").hex(): q(v) for k, v in sorted((storage or {}).items())}}


def salt_bucket(address: bytes, slot):
    return salt_mapping.slot_bucket(h(address), slot) if slot is not None else salt_mapping.account_bucket(h(address))


def build(c: Case):
    sender = OTHER if c.deposit and c.absent_sender else SENDER
    pre = {
        L1_BLOCK: model.Account(code=b"\xfe"),
        REGISTRY: model.Account(code=b"\xfe"),
    }
    if not (c.deposit and c.absent_sender):
        pre[sender] = model.Account(nonce=c.sender_nonce, balance=c.sender_balance, code=c.sender_code)
    if c.to == CONTRACT:
        pre[CONTRACT] = model.Account(nonce=1, code=c.code, storage=dict(c.storage))
    elif c.to == EOA:
        pre[EOA] = model.Account(balance=1)
    created = model.created_address(sender, c.sender_nonce) if c.to is None else None
    # SALT: every bucket the case names, by the salt-v1 mapping; unnamed buckets are minimal.
    buckets = {}
    for (who, slot), m in c.salt.items():
        address = {"created": created, "sender": sender}.get(who, who)
        capacity = int(m * salt_mapping.MIN_BUCKET_SIZE)
        buckets[salt_bucket(address, slot)] = capacity
    env = model.Env(CHAIN_ID, COINBASE, c.base_fee, BLOCK_GAS_LIMIT, buckets)

    if c.deposit:
        mint, gas = c.deposit
        raw = ex.deposit(SOURCE_HASH, sender, c.to, mint, c.value, gas, c.data)
        tx = model.Tx("deposit", 0x7E, sender, c.to, 0, gas, c.value, c.data, None, mint=mint)
        source = {"kind": "deposit", "raw": h(raw)}
    else:
        if c.ty == 0:
            raw = legacy(c.nonce, c.gas_price, c.gas, c.to, c.value, c.data, chain_id=c.chain_id)
        elif c.ty == 1:
            raw = eip2930(c.nonce, c.gas_price, c.gas, c.to, c.value, c.data, c.access_list)
        else:
            raw = eip1559(c.nonce, c.max_priority, c.max_fee, c.gas, c.to, c.value, c.data)
        tx = model.Tx("signed", c.ty, sender, c.to, c.nonce, c.gas, c.value, c.data, c.chain_id, gas_price=c.gas_price,
                      max_fee=c.max_fee, max_priority=c.max_priority, access_list=c.access_list)
        source = {"kind": "signed", "raw": h(raw)}
    result = model.Run(env, pre, tx, salt_bucket).run()

    inp = {
        "chain": {"chainId": q(CHAIN_ID)},
        "block": {
            "number": q(2), "timestamp": q(0x6553F102), "coinbase": h(COINBASE), "gasLimit": q(BLOCK_GAS_LIMIT),
            "baseFee": q(c.base_fee), "prevRandao": ZERO32, "parentHash": "0x" + (0xA11CE).to_bytes(32, "big").hex(),
            "parentTimestamp": q(0x6553F101), "parentBeaconBlockRoot": ZERO32, "extraData": "0x", "slotNumber": "0x0",
            "blobBaseFee": "0x1", "depositOnly": False, "activation": False,
        },
        "blockHashes": {},
        "pre": {"completeness": "complete",
                "accounts": {h(a): account(x.nonce, x.balance, x.code, x.storage) for a, x in sorted(pre.items())}},
        "transaction": source,
        "salt": {"mapping": "salt-v1", "complete": True, "buckets": {q(b): q(cap) for b, cap in sorted(buckets.items())}},
    }
    decoded = {"type": q(tx.ty), "sender": h(sender), "to": h(c.to) if c.to else None, "nonce": q(tx.nonce),
               "gasLimit": q(tx.gas_limit), "value": q(tx.value), "data": h(tx.data)}
    if c.deposit:
        decoded["mint"] = q(c.deposit[0])
        decoded["sourceHash"] = h(SOURCE_HASH)
    return inp, result, decoded


# Disagreements resolved by the specification's verdict: the expectation is the rule's, and the
# implementation that differs fails the case. These cases stay out of the gating slice until the
# implementation is fixed; tools/run-slice.sh checks that each still fails exactly as recorded and
# that the other implementation passes it.
DEPOSIT_HISTORY = (
    "SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas for its body as any transaction does, and "
    "SATIN-HIST-022 has a deposit report its body's 310 bytes; the revm-based implementation at 5e3f30ad charges a "
    "deposit no history gas, so its gas used is 27,280 (the body's 310 bytes at 88 gas) below the rule's"
)
QUARANTINE = {
    "satin/deposits/new-caller/minimum-bucket": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x37258",
        "actual": "0x307c8", "verdict": DEPOSIT_HISTORY},
    "satin/deposits/new-caller/bucket-x2": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x63f88",
        "actual": "0x5d4f8", "verdict": DEPOSIT_HISTORY},
    "satin/deposits/existing-caller/fresh-slot": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x260b2",
        "actual": "0x1e862", "verdict": DEPOSIT_HISTORY},
}

GROUP_PATHS = {"outcome": "/expected/outcome", "state": "/expected/state", "receipt": "/expected/receipt",
               "gasLedgers": "/expected/gasLedgers", "resources": "/expected/resources"}


def fixture(c: Case, descriptor_digest: str, rule_texts: dict) -> dict:
    inp, result, decoded = build(c)
    d = result.derivation
    assertions, derivation = [], []
    for group, path in sorted(GROUP_PATHS.items(), key=lambda x: x[1]):
        rules = d.rules(group)
        if not rules:
            continue
        assertions.append({"path": path, "rules": rules})
        derivation.append({"path": path, "rules": rules, "steps": d.texts(group)})
    rules = sorted({r for a in assertions for r in a["rules"]})
    unknown = [r for r in rules if r not in rule_texts]
    if unknown:
        raise SystemExit(f"{c.case_id}: cites rules the registry does not have: {unknown}")
    requires = ["group:gas-ledgers", "group:limit", "group:outcome", "group:receipts", "group:resources", "group:state",
                "feature:salt"] + (["feature:deposit"] if c.deposit else [])
    return {
        "format": "mega-execution-fixture",
        "schemaVersion": "1.0",
        "caseId": c.case_id,
        "specRef": {"name": "megaeth/Satin", "descriptor": descriptor_digest},
        "profile": "state-transition",
        "requires": sorted(requires),
        "rules": rules,
        "assertions": assertions,
        "input": inp,
        "expected": result.observations,
        "provenance": {
            "status": "candidate",
            "generator": "tools/make_slice.py",
            "authoring": {"intent": c.intent, **({"boundary": c.boundary} if c.boundary else {})},
            "evidence": "derived from the specification by tools/satin_model.py, an executable restatement of the cited "
                        "rules that shares no code with either implementation; implementation runs are cross-checks only",
            "review": {
                "spec": {"commit": "22a5f4bc95dd2abbcc9e75146e24be781e08aadd", "descriptor": descriptor_digest},
                "ruleTexts": {r: rule_texts[r] for r in rules},
                "decision": "pending: approval is the owner's",
            },
            "derivation": derivation,
            "transaction": decoded,
        },
    }


def negative(base: dict) -> dict:
    """A deliberately wrong expectation: the fresh slot's state gas off by one."""
    bad = json.loads(json.dumps(base))
    bad["caseId"] = "satin/negative/wrong-expected/state-gas-off-by-one"
    state = int(bad["expected"]["gasLedgers"]["state"], 16)
    bad["expected"]["gasLedgers"]["state"] = q(state + 1)
    bad["provenance"] = {
        "status": "example",
        "generator": "tools/make_slice.py",
        "note": "A deliberately wrong expectation: satin/sstore/fresh-slot/minimum-bucket with its state ledger one above "
                "the derived value. Every consumer must report fail at /expected/gasLedgers/state, and no fixture is "
                "rewritten by consuming it.",
    }
    return bad


def pretty(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def outputs() -> dict[str, str]:
    with open(os.path.join(SPEC_DIR, "descriptor.json"), encoding="utf-8") as f:
        descriptor_digest = "sha256:" + hashlib.sha256(canonical(json.load(f))).hexdigest()
    with open(os.path.join(SPEC_DIR, "rules.json"), encoding="utf-8") as f:
        rule_texts = {k: v["textDigest"] for k, v in json.load(f)["rules"].items()}
    files: dict[str, str] = {}
    index = []
    by_id = {}
    quarantine = []
    for c in cases():
        fx = fixture(c, descriptor_digest, rule_texts)
        q_entry = QUARANTINE.get(c.case_id)
        rel = f"{'quarantine' if q_entry else 'cases'}/{c.case_id.replace('/', '--')}.json"
        if q_entry:
            fx["provenance"]["quarantine"] = q_entry
        files[rel] = pretty(fx)
        by_id[c.case_id] = fx
        entry = {"caseId": c.case_id, "file": rel, "area": c.case_id.split("/")[1], "rules": fx["rules"],
                 "fileDigest": "sha256:" + hashlib.sha256(canonical(fx)).hexdigest()}
        if q_entry:
            quarantine.append({**entry, "knownFail": q_entry})
        else:
            index.append(entry)
    neg = negative(by_id["satin/sstore/fresh-slot/minimum-bucket"])
    files["negative/wrong-expected--state-gas-off-by-one.json"] = pretty(neg)
    files["index.json"] = pretty({
        "format": "mega-fixture-slice-index",
        "spec": {"name": "megaeth/Satin", "descriptor": descriptor_digest},
        "profile": "state-transition",
        "cases": index,
        "quarantine": quarantine,
        "negative": [{"caseId": neg["caseId"], "file": "negative/wrong-expected--state-gas-off-by-one.json",
                      "wrongAt": "/expected/gasLedgers/state"}],
    })
    return files


def main(argv: list[str]) -> int:
    files = outputs()
    if "--check" in argv[1:]:
        stale = []
        for rel, text in files.items():
            try:
                with open(os.path.join(OUT, rel), encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(rel)
            except FileNotFoundError:
                stale.append(rel)
        present = set()
        for sub in ("cases", "quarantine", "negative"):
            d = os.path.join(OUT, sub)
            if os.path.isdir(d):
                present |= {f"{sub}/{n}" for n in os.listdir(d)}
        extra = sorted(present - set(files))
        if stale or extra:
            print(f"make_slice: out of date: {stale + extra}", file=sys.stderr)
            return 1
        print(f"make_slice: {len(files)} files up to date")
        return 0
    for sub in ("cases", "quarantine", "negative"):
        d = os.path.join(OUT, sub)
        if os.path.isdir(d):
            for n in os.listdir(d):
                os.remove(os.path.join(d, n))
    for rel, text in files.items():
        path = os.path.join(OUT, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    cases_n = sum(1 for rel in files if rel.startswith("cases/"))
    held = sum(1 for rel in files if rel.startswith("quarantine/"))
    print(f"make_slice: wrote {len(files)} files to slice/: {cases_n} cases, {held} quarantined, 1 negative")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
