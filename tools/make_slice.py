#!/usr/bin/env python3
"""Write the vertical slice: reviewed `state-transition` cases with spec-derived expectations.

Each case is authored here — its setup, the transaction (real signed bytes, or a deposit
envelope), the SALT capacities its state lands in — and its expected observations come from
`tools/satin_model.py`, an executable restatement of the cited rules of the pinned specification
(`specs/satin-d34e626`; the cases added for interception, the keyless decoder and EIP-7702
existence cite `specs/satin-d334ef8`, decision D-54, and those for the edges of the charge-order
principles `specs/satin-5fb2688`, D-59). No implementation is run: the filler's output is a candidate to compare
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
SPEC_DIR = os.path.join(ROOT, "specs", "satin-d34e626")
SPEC_COMMITS = {"satin-d34e626": "d34e6266e6d7b69963701baa5ae25ccb8a548260",
                "satin-d334ef8": "d334ef8748a6fb09dfcf1162704539fe22373aef",
                "satin-5fb2688": "5fb26884b5ed1d02bb622073dfdf1d7ea814f1be"}
DEFAULT_SPEC = "satin-d34e626"
INTERCEPTION_SPEC = "satin-d334ef8"  # interception before the frame start, SATIN-ICPT-007
ORDERING_SPEC = "satin-5fb2688"  # the charge-order principles, SATIN-HIST-023
PRINCIPLES_SPECS = {ORDERING_SPEC}  # the snapshots that state the principles the model cites
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
AUTH_KEY = 0x3C2AD3B4B9F1E7A6D5C4B3A29180F7E6D5C4B3A29180F7E6D5C4B3A29180F7E6
AUTHORITY = ex.address_of(AUTH_KEY)
EMPTY_LEAF = bytes.fromhex("000000000000000000000000000000000000e3e7")
PLAIN = bytes.fromhex("00000000000000000000000000000000000c0de2")  # a contract with code, no system contract
DELEGATED = bytes.fromhex("0000000000000000000000000000000000de1e9a")  # an account holding a delegation
DELEGATE = bytes.fromhex("00000000000000000000000000000000000de1e9")  # the account it delegates to
CHAIN_ID = 1
BLOCK_GAS_LIMIT = 10_000_000_000
ETH = 10**18
ZERO32 = "0x" + "00" * 32


def h(b: bytes) -> str:
    return "0x" + b.hex()


fmt = model.fmt
NUMBERS = {12: "twelve"}


def pool_019_example() -> dict:
    """The worked example of SATIN-POOL-019, by its own arithmetic: one cold slot cleared by two PUSH1s and
    an SSTORE, in a call without value or calldata. The model's ledgers for the case must reproduce it."""
    regular = (model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + 2 * model.G_VERYLOW + model.COLD_SSTORE_ACCESS
               + model.SSTORE_RESET)
    history = (model.TX_BODY_SIZE + model.WRITE_RECORD_SIZE) * model.COST_PER_HISTORY_BYTE
    refund = min(model.REFUND_CLEARED, (regular + history) // model.REFUND_QUOTIENT)
    return {"regular": regular, "history": history, "refund": refund, "gasUsed": regular + history - refund}


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


def authorization(key: int, chain_id: int, target: bytes, nonce: int) -> list:
    """A signed EIP-7702 authorization tuple: the signature is over 0x05 || rlp([chain_id, address, nonce])."""
    recid, r, s = ex.sign(key, ex.keccak256(b"\x05" + ex.rlp([chain_id, target, nonce])))
    return [chain_id, target, nonce, recid, r, s]


def eip7702(nonce, max_priority, max_fee, gas, to, value, data, auths) -> bytes:
    return _signed(4, [CHAIN_ID, nonce, max_priority, max_fee, gas, to, value, data, [], auths], KEY)


def system_contracts() -> dict:
    """The system contracts a call can reach, with the code the specification names by hash."""
    with open(os.path.join(ROOT, "tools", "system-contracts.json"), encoding="utf-8") as f:
        listing = json.load(f)
    out = {}
    for c in listing["contracts"]:
        code = bytes.fromhex(c["code"][2:])
        if h(ex.keccak256(code)) != c["codeHash"]:
            raise SystemExit(f"tools/system-contracts.json: {c['name']}'s code is not {c['codeHashConstant']}")
        out[bytes.fromhex(c["address"][2:])] = code
    return out


SOURCE_HASH = bytes.fromhex("00" * 31 + "5d")


# --- Cases --------------------------------------------------------------------------------------


class Case:
    def __init__(self, case_id: str, intent: str, *, code: bytes = STOP, to=CONTRACT, value=0, data=b"", gas=1_000_000,
                 gas_price=0, base_fee=0, ty=0, max_priority=0, max_fee=0, nonce=0, sender_nonce=0, sender_balance=ETH,
                 sender_code=b"", storage=None, extra=None, salt=None, access_list=None, chain_id=CHAIN_ID,
                 deposit=None, absent_sender=False, boundary="", salt_complete=True, spec=DEFAULT_SPEC, accounts=None,
                 contract_balance=0, authorizations=None, system=False, check=None, tune=None):
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
        self.salt_complete = salt_complete  # False: every bucket the case reads must be listed
        self.spec = spec  # the registry snapshot the case cites
        self.accounts = accounts or {}  # more pre-state accounts: address -> model.Account
        self.contract_balance = contract_balance
        self.authorizations = authorizations or []  # (key, chain id, delegation target, nonce)
        self.system = system  # the system contracts' code in the pre-state
        self.check = check or {}  # gasLedgers figures the derivation must reproduce
        # (probe, regular gas): the gas limit is set so the model's probe point (satin_model.Run.probe)
        # holds exactly that regular gas; `gas` is the limit the model is first run with to find it.
        self.tune = tune


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
    zeros = 32
    add(Case("satin/intrinsic/calldata/zero-bytes", f"{zeros} zero calldata bytes: {model.CALLDATA_ZERO} gas each, "
             f"{model.COST_PER_HISTORY_BYTE} of history each, the floor {model.FLOOR_PER_BYTE} each", data=bytes(zeros)))
    add(Case("satin/intrinsic/calldata/non-zero-bytes", "64 non-zero calldata bytes: the block counts the floor over the "
             "regular ledger", data=b"\x01" * 64, boundary="floor above the regular ledger"))
    add(Case("satin/intrinsic/calldata/mixed-bytes", "calldata of 10 zero and 10 non-zero bytes",
             data=bytes(10) + b"\xff" * 10))
    add(Case("satin/intrinsic/access-list/one-address-two-keys", f"an EIP-2930 access list: {fmt(model.ACCESS_LIST_ADDRESS)} "
             f"per address, {fmt(model.ACCESS_LIST_KEY)} per key, {model.ACCESS_LIST_ADDRESS_SIZE} and "
             f"{model.ACCESS_LIST_SLOT_SIZE} history bytes", ty=1, access_list=[(CONTRACT, [1, 2])]))
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
    add(Case("satin/sstore/fresh-slot/minimum-bucket", f"a cold fresh slot at m = 1: {fmt(model.COLD_SSTORE_ACCESS)} access, "
             f"{fmt(model.SSTORE_SET)} write, {fmt(model.SLOT_STATE)} state gas with its {fmt(model.LEGACY_SSTORE_SHARE)} "
             "legacy share", code=sstore(1, 1) + STOP))
    add(Case("satin/sstore/fresh-slot/bucket-x2", "a fresh slot whose bucket has twice the minimum capacity",
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 2}))
    add(Case("satin/sstore/fresh-slot/bucket-x16", "a fresh slot whose bucket has sixteen times the minimum capacity; "
             "the SALT input lists that bucket alone and is incomplete, so a node mapping the slot to any other bucket "
             "meets a missing input", code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 16}, salt_complete=False,
             gas=3_000_000))
    add(Case("satin/sstore/fresh-slot/capacity-between-multiples", "a bucket of 3.5 minimum buckets: m is the floor, 3",
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 3.5}, boundary="capacity between two multiples"))
    above_cap = 10_000_000
    add(Case("satin/sstore/fresh-slot/with-reservoir", f"a gas limit {fmt(above_cap)} above the execution cap: the body's "
             "history and the slot's state gas draw the reservoir first", code=sstore(1, 1) + STOP,
             gas=model.EXECUTION_CAP + above_cap))
    add(Case("satin/sstore/reset/non-zero-to-non-zero", "a slot whose original value is not zero, reset to another value",
             code=sstore(1, 7) + STOP, storage={1: 5}))
    example = pool_019_example()
    add(Case("satin/sstore/clear/specification-example", "the worked example of SATIN-POOL-019: clearing one cold slot spends "
             f"{fmt(example['regular'])} regular and {fmt(example['history'])} history gas, refunds {fmt(example['refund'])} "
             f"and uses {fmt(example['gasUsed'])}", code=sstore_p1(0, 0) + STOP, storage={0: 1}, check=example))
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
    add(Case("satin/sstore/sload-then-fresh-write", f"an SLOAD makes the slot warm: the SSTORE after it pays {model.WARM_READ} "
             "for its access",
             code=push(1) + b"\x54\x50" + sstore(1, 1) + STOP))
    add(Case("satin/sstore/fresh-slot/eip1559-fees", "a fresh slot paid by an EIP-1559 transaction: the effective price is "
             "the base fee plus the priority fee", code=sstore(1, 1) + STOP, ty=2, max_priority=2_000_000,
             max_fee=5_000_000, base_fee=1_000_000))
    # Logs.
    add(Case("satin/logs/log0-empty", f"an empty LOG0: {model.LOG_COST} regular gas, {model.LOG_BASE_SIZE} history bytes",
             code=log(0, 0, 0, []) + STOP))
    add(Case("satin/logs/log0-one-word", f"a LOG0 of one word: memory, {model.LOG_DATA_COST} per byte, "
             f"{model.LOG_BASE_SIZE + 32} history bytes",
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
             "used; the charges regular gas paid for it are on the regular ledger (D-51)", code=sstore(1, 1) + INVALID, gas=300_000))
    add(Case("satin/outcomes/halt/out-of-gas-at-sstore", "too little gas for a fresh slot's state gas: out of gas; what regular gas "
             "paid of the charge is on the regular ledger (D-51)",
             code=sstore(1, 1) + STOP, gas=60_000, boundary="below the slot's state gas"))
    add(Case("satin/outcomes/halt/with-reservoir", "a halt with a reservoir: the regular budget is used, the reservoir is "
             "returned", code=INVALID, gas=model.EXECUTION_CAP + above_cap))
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
    add(Case("satin/validation/below-intrinsic-regular", "a gas limit below the intrinsic regular gas",
             gas=model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS - 1,
             boundary="one below the intrinsic regular gas"))
    add(Case("satin/validation/floor-above-gas-limit", "a gas limit that covers the intrinsic regular gas but not the floor",
             data=b"\x01" * 100, gas=20_000))
    add(Case("satin/validation/body-history-uncovered", "a gas limit that covers the intrinsic regular gas and the floor, "
             "not the body's history", boundary="one below intrinsic plus body history",
             gas=model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE - 1))
    add(Case("satin/validation/gas-limit-above-block", "a gas limit above what the block's gas limit has left: skipped for the block, "
             "reported in engine isolation as a refusal at inclusion (D-50)", gas=BLOCK_GAS_LIMIT + 1))
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
    out += interception_cases()
    out += ordering_cases()
    return out


# --- Interception before the frame start, the keyless decoder, EIP-7702 existence ------------------


def bytes_to_memory(b: bytes) -> bytes:
    """MSTOREs that lay `b` out in memory from offset 0, one word at a time."""
    return b"".join(mstore(i, int.from_bytes(b[i:i + 32].ljust(32, b"\x00"), "big")) for i in range(0, len(b), 32))


def call(gas: int, target: bytes, value: int, in_size: int) -> bytes:
    """CALL(gas, target, value, 0, in_size, 0, 0)."""
    return push(0) + push(0) + push(in_size) + push(0) + push(value) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf1"


def record_result() -> bytes:
    """Stores what the call left: its success flag in slot 0, its return data's length in slot 1 and the
    keccak256 of the return data in slot 2."""
    return (push(0) + b"\x55"  # SSTORE(0, success)
            + b"\x3d" + push(1) + b"\x55"  # SSTORE(1, RETURNDATASIZE)
            + b"\x3d" + push(0) + push(0) + b"\x3e"  # RETURNDATACOPY(0, 0, RETURNDATASIZE)
            + b"\x3d" + push(0) + b"\x20" + push(2) + b"\x55")  # SSTORE(2, keccak256(0, RETURNDATASIZE))


def word(n: int) -> bytes:
    return n.to_bytes(32, "big")


def send_hint(topic: int, data: bytes) -> bytes:
    return model.SEND_HINT + word(topic) + word(0x40) + word(len(data)) + data.ljust((len(data) + 31) // 32 * 32, b"\x00")


def interception_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = INTERCEPTION_SPEC
    hint = send_hint(7, b"\xaa")

    def interceptor_call(target: bytes, value: int, data: bytes) -> bytes:
        return bytes_to_memory(data) + call(100_000, target, value, len(data)) + record_result() + STOP

    # A contract calls each interceptor with a value it can or cannot fund (SATIN-ICPT-007).
    add(Case("satin/interception/send-hint/value-funded", "a sendHint carrying a value its caller can fund: admitted and "
             "counted before the frame start, then the Oracle's non-payable bytecode reverts", system=True, spec=spec,
             code=interceptor_call(model.ORACLE, 1, hint), contract_balance=10))
    add(Case("satin/interception/send-hint/value-unfunded", "a sendHint carrying a value its caller cannot fund: admitted and "
             "counted, then its frame start refuses the call, which fails with empty return data and returns its gas",
             system=True, spec=spec, code=interceptor_call(model.ORACLE, 1, hint)))
    # Twelve hints of 1 MiB each, forwarded 1 gas, are admitted and counted; the thirteenth, which carries a
    # value its caller cannot fund, would cross the data-size limit and is answered with the stop.
    big = 1 << 20
    count = (model.TX_DATA_LIMIT - model.TX_BODY_SIZE) // big  # as many 1 MiB hints as fit under the limit
    helpers = b"".join(push(0) + push(0) + push(big) + push(0) + push(0) + push(int.from_bytes(model.ORACLE, "big"))
                       + push(1) + b"\xf1\x50" for _ in range(count))
    add(Case("satin/interception/send-hint/over-data-size-limit", "a sendHint whose input would take the transaction over "
             "its data-size limit, carrying a value its caller cannot fund: answered MegaLimitExceeded(0, limit) at "
             f"admission, nothing counted; {NUMBERS.get(count, str(count))} admitted 1 MiB hints bring the data size near "
             "the limit", system=True,
             spec=spec, gas=4_000_000,
             code=mstore(0, int.from_bytes(model.SEND_HINT, "big") << 224) + helpers + call(100_000, model.ORACLE, 1, big)
             + record_result() + STOP))
    for name, target, method in (("access-control", model.MEGA_ACCESS_CONTROL, "disableVolatileDataAccess()"),
                                 ("limit-control", model.MEGA_LIMIT_CONTROL, "remainingComputeGas()")):
        for funded in (True, False):
            add(Case(f"satin/interception/{name}/value-{'funded' if funded else 'unfunded'}",
                     f"{method} called with a value its caller {'can' if funded else 'cannot'} fund: answered "
                     "NonZeroTransfer() before the frame start", system=True, spec=spec,
                     code=interceptor_call(target, 1, model.selector(method)), contract_balance=10 if funded else 0))
    unpadded = model.KEYLESS_DEPLOY_CALL + word(0x40) + word(1_000_000) + word(5) + bytes.fromhex("0102030405")
    add(Case("satin/interception/keyless/transaction-value", "the transaction's own keylessDeploy call carrying value, "
             "which validity funds: the overhead is charged, then NoEtherTransfer() before any value moves", system=True,
             spec=spec, to=model.KEYLESS_DEPLOY, code=None, value=1, data=unpadded, gas=300_000))
    # The keylessDeploy decoder set: the informative table under SATIN-ICPT-006.
    for name, data, intent in (
            ("unpadded-bytes", unpadded, "word(0x40), word(gas), word(5), 5 bytes, the tail padding cut: recognized, the "
             "overhead charged, step 3 refuses the 5 bytes"),
            ("offset-into-head", model.KEYLESS_DEPLOY_CALL + word(0x20) + word(3) + bytes.fromhex("010203"),
             "word(0x20), word(3), 3 bytes, the offset pointing at the second head word: recognized, step 3 refuses the 3 "
             "bytes"),
            ("offset-zero", model.KEYLESS_DEPLOY_CALL + word(0) + word(1_000_000), "word(0), word(gas): the first head word "
             "read as the length, the bytes empty: recognized, step 3 refuses them"),
            ("one-byte-short", unpadded[:-1], "the first input one byte short of its declared length: not recognized, the "
             "bytecode reverts with empty data and no overhead is charged")):
        add(Case(f"satin/keyless/recognition/{name}", intent, system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
                 data=data, gas=300_000))
    # EIP-7702 existence: an authority whose leaf the state holds, empty under EIP-161, exists.
    add(Case("satin/authorizations/empty-leaf-authority", "an authority present as an empty leaf exists: the indicator's "
             "state gas alone, no new-account charge, no state growth, one write record", system=True, spec=spec, ty=4,
             to=EOA, code=b"", gas=300_000, authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)],
             accounts={AUTHORITY: model.Account()}))
    add(Case("satin/authorizations/absent-authority", "an authority the state holds no account for is new: the new-account "
             "state gas and one unit of state growth, besides the indicator", system=True, spec=spec, ty=4, to=EOA, code=b"",
             gas=500_000, authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)]))
    add(Case("satin/value-transfer/empty-leaf-recipient", "value to an account present as an empty leaf: as a recipient it "
             "is new under EIP-161, with the new-account charge and one unit of state growth", system=True, spec=spec,
             to=EMPTY_LEAF, code=None, value=10**9, accounts={EMPTY_LEAF: model.Account()}))
    return out


# --- The edges of the charge-order principles (SATIN-HIST-023) ------------------------------------

MAX_GAS = 2**256 - 1  # a CALL's gas operand at its maximum: the forward is the cap


def store_gas(slot: int) -> bytes:
    """SSTORE(slot, GAS): the regular gas the frame has left, its reservoir not included (SATIN-POOL-009)."""
    return b"\x5a" + push(slot) + b"\x55"


def kept_threshold(history: int) -> int:
    """The least regular gas a caller can hold once a CALL's regular charges are made and still pay `history` from
    what it keeps after forwarding all it may: remaining x GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR >=
    history (SATIN-FWD-001)."""
    return -(-history * model.GAS_RETAINED_DENOMINATOR // model.GAS_RETAINED_NUMERATOR)


def big_hints(count: int, size: int) -> bytes:
    """`count` sendHint calls of `size` input bytes each, forwarded 1 gas, with no value, from memory whose first
    word holds sendHint's selector; each is admitted and counted, and the Oracle halts at its first opcode."""
    return (mstore(0, int.from_bytes(model.SEND_HINT, "big") << 224)
            + b"".join(push(0) + push(0) + push(size) + push(0) + push(0) + push(int.from_bytes(model.ORACLE, "big"))
                       + push(1) + b"\xf1\x50" for _ in range(count)))


def ordering_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = ORDERING_SPEC
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    two = 2 * record
    at = kept_threshold(two)  # a caller that forwards all it may pays two records from what it keeps
    access_control = model.selector("disableVolatileDataAccess()")
    limit_control = model.selector("remainingComputeGas()")
    hint = send_hint(7, b"\xaa")

    def value_call(target: bytes, data: bytes, gas: int, *after: bytes) -> bytes:
        return bytes_to_memory(data) + call(gas, target, 1, len(data)) + b"".join(after) + STOP

    # The pool split after an answered value call: the records' history is charged in the opcode and given back
    # into the caller's reservoir, which GAS does not read (SATIN-HIST-023, SATIN-HIST-012, SATIN-POOL-009).
    add(Case("satin/call-order/answered/access-control-two-records", "a value call its caller can fund, answered "
             f"NonZeroTransfer() by MegaAccessControl, then GAS stored: the two records' {fmt(two)} history, charged in "
             "the opcode and given back into the caller's reservoir, is not in GAS", system=True, spec=spec,
             code=value_call(model.MEGA_ACCESS_CONTROL, access_control, 100_000, store_gas(3), record_result()),
             contract_balance=10))
    add(Case("satin/call-order/answered/access-control-one-record", "as the two-record case, the caller's account "
             f"already changed by the transaction's value: one record, {fmt(record)}, is charged and given back",
             system=True, spec=spec, value=1,
             code=value_call(model.MEGA_ACCESS_CONTROL, access_control, 100_000, store_gas(3), record_result()),
             contract_balance=10))
    add(Case("satin/call-order/answered/limit-control-two-records", "a value call its caller can fund, answered "
             f"NonZeroTransfer() by MegaLimitControl, then GAS stored: {fmt(two)} given back into the reservoir",
             system=True, spec=spec,
             code=value_call(model.MEGA_LIMIT_CONTROL, limit_control, 100_000, store_gas(3), record_result()),
             contract_balance=10))
    big = 1 << 20
    count = (model.TX_DATA_LIMIT - model.TX_BODY_SIZE) // big
    add(Case("satin/call-order/answered/hint-over-data-size-limit", "a sendHint its caller can fund whose input would "
             "take the transaction over its data-size limit, then GAS stored: answered MegaLimitExceeded(0, limit), and "
             f"the two records' {fmt(two)} history given back into the reservoir; "
             f"{NUMBERS.get(count, str(count))} admitted 1 MiB hints bring the data size near the limit", system=True,
             spec=spec, gas=4_000_000, contract_balance=10,
             code=big_hints(count, big) + call(100_000, model.ORACLE, 1, big) + store_gas(3) + record_result() + STOP))
    # The caller cannot pay the records: it halts in the opcode, before any decision (SATIN-HIST-023, -009).
    for name, target, data, gas, want, what in (
            ("access-control", model.MEGA_ACCESS_CONTROL, access_control, MAX_GAS, at,
             "MegaAccessControl, the gas operand at its maximum"),
            ("send-hint", model.ORACLE, hint, MAX_GAS, at, "the Oracle's sendHint, the gas operand at its maximum"),
            ("zero-gas", model.MEGA_ACCESS_CONTROL, access_control, 0, two,
             "MegaAccessControl with the gas operand zero, so that it forwards nothing")):
        after = (record_result(),) if gas else ()
        for short in (True, False):
            held = want - 1 if short else want
            kept = held * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR if gas else held
            if short:
                result = (f"it keeps {fmt(kept)} after the forward, one short of the two records' {fmt(two)}, and halts out "
                          "of gas in the opcode: " + ("no hint is admitted or counted" if target == model.ORACLE
                                                      else "no interceptor answers"))
            else:
                result = (f"it keeps the two records' {fmt(kept)} after the forward and pays them: " +
                          ("the hint is admitted and counted, and the Oracle's bytecode refuses the value"
                           if target == model.ORACLE else "answered NonZeroTransfer()"))
            add(Case(f"satin/call-order/records-unpaid/{name}-{'one-short' if short else 'exact'}",
                     f"a value call its caller can fund to {what}, the caller holding {fmt(held)} of regular gas once the "
                     f"opcode's regular charges are made: {result}",
                     boundary=f"the caller's regular gas {'one below' if short else 'at'} {fmt(want)}", system=True,
                     spec=spec, contract_balance=10, code=value_call(target, data, gas, *after),
                     tune=("forward", held)))
    # A value the caller cannot fund makes no record: nothing is charged or given back (SATIN-HIST-015).
    short = at - 1
    add(Case("satin/call-order/unfunded/contract", f"a value call its caller cannot fund to a contract, the gas operand at "
             f"its maximum, the caller holding {fmt(short)} of regular gas at the forward: no record is charged, so it does "
             "not halt; the start is refused and the child's whole regular gas, the stipend included, returns to GAS",
             spec=spec, accounts={PLAIN: model.Account(nonce=1, code=INVALID)},
             code=value_call(PLAIN, b"", MAX_GAS, store_gas(3), record_result()), tune=("forward", short)))
    add(Case("satin/call-order/unfunded/limit-control", f"a value call its caller cannot fund to MegaLimitControl, the gas "
             f"operand at its maximum, the caller holding {fmt(short)} at the forward: no record is charged, the call is "
             "answered NonZeroTransfer() and the child's whole regular gas returns to GAS", system=True, spec=spec,
             code=value_call(model.MEGA_LIMIT_CONTROL, limit_control, MAX_GAS, store_gas(3), record_result()),
             tune=("forward", short)))
    new_account = model.ACCOUNT_STATE
    add(Case("satin/call-order/unfunded/empty-account", "a value call its caller cannot fund to an account empty under "
             f"EIP-161: the new account's {fmt(new_account)} state gas, its legacy share first, is charged before the "
             f"forward and given back into the caller's reservoir when the start is refused; no record is charged, the "
             f"caller holding {fmt(short)} at the forward", spec=spec,
             code=value_call(ABSENT, b"", MAX_GAS, store_gas(3), record_result()), tune=("forward", short)))
    add(Case("satin/call-order/unfunded/contract-refused", "a value call its caller cannot fund to a contract, with the "
             "sendHint input of the interception case: no interception, the start refused, the child's whole regular gas "
             "returned, the stipend included", spec=spec, accounts={PLAIN: model.Account(nonce=1, code=INVALID)},
             code=value_call(PLAIN, hint, 100_000, record_result())))
    # A delegated recipient's delegate access before the first frame (SATIN-SCHED-008 step 5).
    delegation = model.DELEGATION_PREFIX + DELEGATE
    held = {DELEGATED: model.Account(nonce=1, code=delegation), DELEGATE: model.Account(nonce=1, code=STOP)}
    plain = {DELEGATED: model.Account(nonce=1), DELEGATE: model.Account(nonce=1, code=STOP)}
    warm, cold = model.WARM_READ, model.WARM_READ + model.COLD_ACCOUNT_SURCHARGE
    add(Case("satin/delegated-recipient/warm-delegate", f"a transaction to an account delegating to an account in its "
             f"access list: the delegate's warm access, {fmt(warm)}, before the first frame", spec=spec, ty=1, to=DELEGATED,
             code=None, access_list=[(DELEGATE, [])], accounts=held))
    add(Case("satin/delegated-recipient/no-delegation", "the warm-delegate transaction to the same account without its "
             "delegation: no delegate access", spec=spec, ty=1, to=DELEGATED, code=None, access_list=[(DELEGATE, [])],
             accounts=plain))
    add(Case("satin/delegated-recipient/cold-delegate", f"a transaction to an account delegating to an account that is not "
             f"warm: the warm read, then the cold surcharge, {fmt(cold)} in all, before the first frame", spec=spec,
             to=DELEGATED, code=None, accounts=held))
    for short in (True, False):
        left = cold - 1 if short else cold
        add(Case(f"satin/delegated-recipient/cold-delegate-{'one-short' if short else 'exact'}",
                 f"the cold-delegate transaction with {fmt(left)} of regular gas left for the delegate's access: " +
                 ("the warm read is paid and the cold surcharge is not, so the delegate is not loaded and the transaction "
                  "runs out of gas before its first frame" if short else "the access is paid and the first frame starts "
                  "with no regular gas, running the delegate's STOP"),
                 boundary=f"the regular gas left for the delegate's access {'one below' if short else 'at'} {fmt(cold)}",
                 spec=spec, to=DELEGATED, code=None, accounts=held, gas=100_000, tune=("delegate", left)))
    add(Case("satin/delegated-recipient/own-sender", f"a transaction to its own sender, which delegates to an account that "
             f"is not warm: TX_BASE_COST alone, then the delegate's access, {fmt(cold)}, before the first frame",
             spec=spec, to=SENDER, code=None, sender_code=delegation, accounts={DELEGATE: model.Account(nonce=1, code=STOP)}))
    # The reservoir pays the authorities' records first (SATIN-HIST-005).
    body = (model.TX_BODY_SIZE + model.AUTHORIZATION_SIZE) * model.COST_PER_HISTORY_BYTE
    indicator = model.DELEGATION_STATE_BYTES * model.COST_PER_STATE_BYTE
    reservoir = body + indicator + record
    add(Case("satin/pre-frame/authorities-first-halt", f"a reservoir of {fmt(reservoir)}: the body's history and the "
             f"authority's delegation indicator leave {fmt(record)} when step 3 begins, which pays the authority's record; "
             "the first frame's start record is paid by regular gas, and the halt of the first frame returns none of it",
             spec=spec, ty=4, value=1, code=INVALID, gas=model.EXECUTION_CAP + reservoir,
             authorizations=[(AUTH_KEY, CHAIN_ID, DELEGATE, 0)], accounts={AUTHORITY: model.Account(balance=1)}))
    # The transaction's own start record before interception answers its keylessDeploy call (SATIN-HIST-005).
    unpadded = model.KEYLESS_DEPLOY_CALL + word(0x40) + word(1_000_000) + word(5) + bytes.fromhex("0102030405")
    overhead = model.KEYLESS_DEPLOY_OVERHEAD_GAS
    for short in (True, False):
        left = overhead - 1 if short else overhead
        add(Case(f"satin/pre-frame/keyless-start-record-{'one-short' if short else 'exact'}",
                 f"the transaction's own value keylessDeploy call, its start record's {fmt(record)} charged before the "
                 f"first frame, leaving {fmt(left)} for the frame: " +
                 (f"one short of step 1's {fmt(overhead)}, so the frame halts out of gas and no NoEtherTransfer() is "
                  "answered" if short else f"step 1's {fmt(overhead)} is paid and the call is answered NoEtherTransfer(), "
                  "the record's history given back"),
                 boundary=f"the frame's regular gas {'one below' if short else 'at'} {fmt(overhead)}", system=True,
                 spec=spec, to=model.KEYLESS_DEPLOY, code=None, value=1, data=unpadded, gas=300_000,
                 tune=("frame", left)))
    # The data-size check of a hint: over the limit, not at it (SATIN-ORCL-010).
    room = model.TX_DATA_LIMIT - model.TX_BODY_SIZE - count * big
    for over in (False, True):
        size = room + 1 if over else room
        add(Case(f"satin/interception/send-hint/{'one-byte-over' if over else 'at'}-data-size-limit",
                 f"after {NUMBERS.get(count, str(count))} admitted 1 MiB hints, a sendHint of {fmt(size)} input bytes " +
                 ("takes the data size one byte over the limit: answered MegaLimitExceeded(0, limit), nothing counted"
                  if over else "takes the data size exactly to the limit: admitted and counted"),
                 boundary=f"the data size {'one byte over' if over else 'at'} TX_DATA_LIMIT", system=True, spec=spec,
                 gas=4_000_000, code=big_hints(count, big) + push(0) + push(0) + push(size) + push(0) + push(0)
                 + push(int.from_bytes(model.ORACLE, "big")) + push(1) + b"\xf1" + STOP))
    # Give-backs credit the reservoir, deposits pay history (SATIN-HIST-012, SATIN-HIST-016).
    add(Case("satin/sstore/fresh-then-restored-gas", "0 -> 1 -> 0, then GAS stored: the slot's state and history gas "
             "come back into the reservoir, which GAS does not read", spec=spec,
             code=sstore(1, 1) + sstore(1, 0) + store_gas(2) + STOP))
    add(Case("satin/deposits/existing-caller/one-log", "a deposit from an existing account that emits one empty LOG0: "
             "the deposit pays the log's history", spec=spec, deposit=(0, 1_000_000), sender_nonce=3,
             code=log(0, 0, 0, []) + STOP))
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
        pre[CONTRACT] = model.Account(nonce=1, balance=c.contract_balance, code=c.code, storage=dict(c.storage))
    elif c.to == EOA:
        pre[EOA] = model.Account(balance=1)
    if c.system:
        for address, code in system_contracts().items():
            pre[address] = model.Account(code=code)
    for address, acct in c.accounts.items():
        pre[address] = model.Account(acct.nonce, acct.balance, acct.code, dict(acct.storage))
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
        elif c.ty == 4:
            auths = [authorization(k, cid, target, n) for k, cid, target, n in c.authorizations]
            raw = eip7702(c.nonce, c.max_priority, c.max_fee, c.gas, c.to, c.value, c.data, auths)
        else:
            raw = eip1559(c.nonce, c.max_priority, c.max_fee, c.gas, c.to, c.value, c.data)
        tx = model.Tx("signed", c.ty, sender, c.to, c.nonce, c.gas, c.value, c.data, c.chain_id, gas_price=c.gas_price,
                      max_fee=c.max_fee, max_priority=c.max_priority, access_list=c.access_list,
                      authorizations=[(cid, target, n, ex.address_of(k)) for k, cid, target, n in c.authorizations])
        source = {"kind": "signed", "raw": h(raw)}
    run = model.Run(env, pre, tx, salt_bucket, principles=c.spec in PRINCIPLES_SPECS)
    result = run.run()
    result.probe = run.probe

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
        "salt": {"mapping": "salt-v1", "complete": c.salt_complete, "buckets": {q(b): q(cap) for b, cap in sorted(buckets.items())}},
    }
    decoded = {"type": q(tx.ty), "sender": h(sender), "to": h(c.to) if c.to else None, "nonce": q(tx.nonce),
               "gasLimit": q(tx.gas_limit), "value": q(tx.value), "data": h(tx.data)}
    if c.deposit:
        decoded["mint"] = q(c.deposit[0])
        decoded["sourceHash"] = h(SOURCE_HASH)
    if c.authorizations:
        decoded["authorizationList"] = [{"chainId": q(cid), "address": h(target), "nonce": q(n),
                                         "authority": h(ex.address_of(k))} for k, cid, target, n in c.authorizations]
    return inp, result, decoded


# Disagreements resolved by the specification's verdict: the expectation is the rule's, and the
# implementation that differs fails the case. These cases stay out of the gating slice until the
# implementation is fixed; tools/run-slice.sh checks that each still fails exactly as recorded and
# that the other implementation passes it.
def deposit_history_verdict(ledgers: dict, records: str) -> str:
    """The specification's verdict on a deposit the revm-based implementation charges no history gas:
    its gas used falls short by the history the deposit keeps, its body and its write records."""
    price, body, size = model.COST_PER_HISTORY_BYTE, model.TX_BODY_SIZE, model.WRITE_RECORD_SIZE
    history, history_bytes = int(ledgers["history"], 16), int(ledgers["historyBytes"], 16)
    kept = history_bytes - body
    if kept % size or history != history_bytes * price:
        raise SystemExit(f"a deposit verdict: {history_bytes} history bytes and {history} history gas are not the body's "
                         "and whole write records at the history price")
    if kept:
        what = (f"the body's {body} bytes and {records} of {kept} bytes at {price} gas, ({body} + {kept}) x {price} = "
                f"{fmt(history)}")
    else:
        what = f"the body's {body} bytes at {price} gas, {body} x {price} = {fmt(history)}, the deposit keeping no write record"
    return ("SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas as any transaction does, for its body among "
            "the rest, and SATIN-HIST-022 counts the body among the history bytes every transaction reports; the revm-based "
            f"implementation at 5e3f30ad charges a deposit no history gas, so its gas used is {fmt(history)} below the "
            f"rule's: {what}")


QUARANTINE = {
    "satin/deposits/new-caller/minimum-bucket": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x37258",
        "actual": "0x307c8"},
    "satin/deposits/new-caller/bucket-x2": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x63f88",
        "actual": "0x5d4f8"},
    "satin/deposits/existing-caller/fresh-slot": {
        "adapter": "mega-eest-adapter-revm", "path": "/expected/gasLedgers/gasUsed", "expected": "0x260b2",
        "actual": "0x1e862"},
}
# What each quarantined deposit keeps besides its body, for its verdict.
QUARANTINE_RECORDS = {"satin/deposits/existing-caller/fresh-slot": "the fresh slot's write record"}

# The cases of the charge-order edges that the revm-based implementation at its pin fails, for one of two
# decided rules it has not made yet: every give-back credits the reservoir, never regular gas (SATIN-HIST-012),
# and a deposit pays history gas (SATIN-HIST-016). Each records what that implementation's difference makes of
# the derived figure: GAS above the rule's by the give-back the frame's reservoir holds when GAS reads, or a
# deposit's gas used below the rule's by its whole history. tools/run-slice.sh checks the figure on every run.
REVM_PIN = "4e39cfd6"
GIVE_BACKS = {  # case -> (the slot its GAS is stored in, what the reservoir holds when GAS reads)
    "satin/call-order/answered/access-control-two-records": (
        3, "the history of the two records the opcode charged for the start that MegaAccessControl's answer replaced"),
    "satin/call-order/answered/access-control-one-record": (
        3, "the history of the record the opcode charged for the start that MegaAccessControl's answer replaced"),
    "satin/call-order/answered/limit-control-two-records": (
        3, "the history of the two records the opcode charged for the start that MegaLimitControl's answer replaced"),
    "satin/call-order/answered/hint-over-data-size-limit": (
        3, "the history of the two records the opcode charged for the start that the hint's data-size stop replaced"),
    "satin/call-order/unfunded/empty-account": (
        3, "the new account's state gas, its legacy share included, that the refused start gives back (SATIN-POOL-015)"),
    "satin/sstore/fresh-then-restored-gas": (
        2, "the fresh slot's state gas and its record's history, given back when the slot returns to zero "
           "(SATIN-STATE-008, SATIN-HIST-006)"),
}
DEPOSIT_HISTORY = {"satin/deposits/existing-caller/one-log": "the log's"}


def storage_path(address: bytes, slot: int) -> str:
    return f"/expected/state/accounts/{h(address)}/storage/0x{slot:064x}"


def edge_quarantine(c: Case, fx: dict) -> dict | None:
    """The quarantine record of an edge case the revm-based implementation fails, or None."""
    adapter = "mega-eest-adapter-revm"
    if c.case_id in GIVE_BACKS:
        slot, what = GIVE_BACKS[c.case_id]
        held, gas = c.probe["gas-reservoir"], c.probe["gas"]
        if fx["expected"]["state"]["accounts"][h(CONTRACT)]["storage"].get(f"0x{slot:064x}") != q(gas):
            raise SystemExit(f"{c.case_id}: slot {slot} does not hold the GAS the derivation read")
        path = storage_path(CONTRACT, slot)
        verdict = ("SATIN-HIST-012 makes every give-back of state or history gas credit the reservoir of the frame that "
                   "receives it, never its regular gas, whichever pool paid the charge, and SATIN-POOL-009 makes GAS push "
                   f"the regular gas alone; the revm-based implementation at {REVM_PIN} credits {what}, "
                   f"{fmt(held)}, to the frame's regular gas, so the GAS it stores is {fmt(held)} above the rule's")
        return {"adapter": adapter, "path": path, "expected": q(gas), "actual": q(gas + held), "verdict": verdict}
    if c.case_id in DEPOSIT_HISTORY:
        ledgers = fx["expected"]["gasLedgers"]
        history, history_bytes = int(ledgers["history"], 16), int(ledgers["historyBytes"], 16)
        used = int(ledgers["gasUsed"], 16)
        price, body = model.COST_PER_HISTORY_BYTE, model.TX_BODY_SIZE
        verdict = ("SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas as any transaction does, for its body "
                   f"and its logs among the rest; the revm-based implementation at {REVM_PIN} charges a deposit no history "
                   f"gas, so its gas used is {fmt(history)} below the rule's: the body's {body} bytes and "
                   f"{DEPOSIT_HISTORY[c.case_id]} {history_bytes - body} at {price} gas, ({body} + {history_bytes - body}) x "
                   f"{price} = {fmt(history)}")
        return {"adapter": adapter, "path": "/expected/gasLedgers/gasUsed", "expected": q(used), "actual": q(used - history),
                "verdict": verdict}
    return None

GROUP_PATHS = {"outcome": "/expected/outcome", "state": "/expected/state", "receipt": "/expected/receipt",
               "gasLedgers": "/expected/gasLedgers", "resources": "/expected/resources"}


def tuned(c: Case) -> None:
    """Sets a tuned case's gas limit so its probe point holds the regular gas it names: below the execution
    cap every charge before that point is fixed, so the probe moves with the gas limit one for one."""
    point, want = c.tune
    if c.gas > model.EXECUTION_CAP:
        raise SystemExit(f"{c.case_id}: a tuned gas limit must be below the execution cap")
    _, result, _ = build(c)
    c.gas += want - result.probe[point]
    _, result, _ = build(c)
    if result.probe.get(point) != want:
        raise SystemExit(f"{c.case_id}: the gas limit {c.gas} gives {point} {result.probe.get(point)}, not {want}")
    c.tune = None


def fixture(c: Case, descriptor_digest: str, rule_texts: dict, spec_commit: str = SPEC_COMMITS[DEFAULT_SPEC]) -> dict:
    if c.tune:
        tuned(c)
    inp, result, decoded = build(c)
    c.probe = result.probe
    for key, want in c.check.items():
        got = int(result.observations["gasLedgers"][key], 16)
        if got != want:
            raise SystemExit(f"{c.case_id}: the derivation gives {key} {got}, the worked example {want}")
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
                "spec": {"commit": spec_commit, "descriptor": descriptor_digest},
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


def spec_of(name: str) -> tuple[str, dict]:
    d = os.path.join(ROOT, "specs", name)
    with open(os.path.join(d, "descriptor.json"), encoding="utf-8") as f:
        digest = "sha256:" + hashlib.sha256(canonical(json.load(f))).hexdigest()
    with open(os.path.join(d, "rules.json"), encoding="utf-8") as f:
        texts = {k: v["textDigest"] for k, v in json.load(f)["rules"].items()}
    return digest, texts


def outputs() -> dict[str, str]:
    specs = {name: spec_of(name) for name in SPEC_COMMITS}
    descriptor_digest, rule_texts = specs[DEFAULT_SPEC]
    files: dict[str, str] = {}
    index = []
    by_id = {}
    quarantine = []
    for c in cases():
        fx = fixture(c, *specs[c.spec], SPEC_COMMITS[c.spec])
        q_entry = QUARANTINE.get(c.case_id)
        if q_entry:
            q_entry = {**q_entry, "verdict": deposit_history_verdict(fx["expected"]["gasLedgers"],
                                                                     QUARANTINE_RECORDS.get(c.case_id, ""))}
        else:
            q_entry = edge_quarantine(c, fx)
        rel = f"{'quarantine' if q_entry else 'cases'}/{c.case_id.replace('/', '--')}.json"
        if q_entry:
            fx["provenance"]["quarantine"] = q_entry
        files[rel] = pretty(fx)
        by_id[c.case_id] = fx
        entry = {"caseId": c.case_id, "file": rel, "area": c.case_id.split("/")[1], "rules": fx["rules"],
                 "fileDigest": "sha256:" + hashlib.sha256(canonical(fx)).hexdigest()}
        if c.spec != DEFAULT_SPEC:  # the index's spec is the default; a case citing another names its own
            entry["spec"] = {"name": "megaeth/Satin", "descriptor": fx["specRef"]["descriptor"]}
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
