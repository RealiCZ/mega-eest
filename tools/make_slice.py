#!/usr/bin/env python3
"""Write the vertical slice: reviewed `state-transition` cases with spec-derived expectations.

Each case is authored here — its setup, the transaction (real signed bytes, or a deposit
envelope), the SALT capacities its state lands in — and its expected observations come from
`tools/satin_model/`, an executable restatement of the cited rules of the pinned specification
(`specs/satin-d34e626`; the cases added for interception, the keyless decoder and EIP-7702
existence cite `specs/satin-d334ef8`, decision D-54, and those for the edges of the charge-order
principles, gas detention, the Oracle's reads, the refused volatile read, the reads group, the
stops of the transaction's own frame and the gas pools `specs/satin-5fb2688`, D-59 to D-64, and
those for the take-back page's worked examples, the destruction page's own rules and gas detention's
rules `specs/satin-cdded1e`, D-65, D-70 and D-67). No implementation is
run: the filler's output is a candidate to compare with, never the source of these values
(`tools/run-slice.sh` runs both implementations against them).

A case file holds what a consumer compares and a pointer to where it came from (D-76): its `rules`
are the rules it pins (`AREA_SCOPE`, `pinned`), and its provenance names the generator, the function
that defines the case and the specification commit. The derivation of every observation group — the
steps, their arithmetic and the rules each applies — the text digest of every rule applied, and the
decoded transaction are not stored; `--explain` derives them again for any case, so a reviewer can
hold each number to the exact rule text it was derived from.

Output: `slice/cases/<case-id>.json`, `slice/quarantine/<case-id>.json` (cases an implementation
fails against a clear rule: the expectation stands, the case stays out of the gating slice, and
`QUARANTINE` records the implementation, the exact difference and the specification's verdict),
`slice/negative/<case-id>.json` (deliberately wrong expectations that a consumer must fail without
any fixture being rewritten) and `slice/index.json`.

Usage:
    tools/make_slice.py                       write the slice
    tools/make_slice.py --check               fail when a committed file differs from what this writes
    tools/make_slice.py --explain CASE-ID...  print each case's derivation, as JSON

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
import satin_model as model  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SPEC_DIR = os.path.join(ROOT, "specs", "satin-d34e626")
SPEC_COMMITS = {"satin-d34e626": "d34e6266e6d7b69963701baa5ae25ccb8a548260",
                "satin-d334ef8": "d334ef8748a6fb09dfcf1162704539fe22373aef",
                "satin-5fb2688": "5fb26884b5ed1d02bb622073dfdf1d7ea814f1be",
                "satin-cdded1e": "cdded1e1d131a1d16a2c4b1cd873557f16a6a558"}
DEFAULT_SPEC = "satin-d34e626"
INTERCEPTION_SPEC = "satin-d334ef8"  # interception before the frame start, SATIN-ICPT-007
ORDERING_SPEC = "satin-5fb2688"  # the charge-order principles, SATIN-HIST-023
TAKE_BACK_SPEC = "satin-cdded1e"  # one home for each rule, and the take-back page's worked examples as cases
PRINCIPLES_SPECS = {ORDERING_SPEC, TAKE_BACK_SPEC}  # the snapshots that state the principles the model cites
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
SECOND_AUTH_KEY = 0x5D4C3B2A19F8E7D6C5B4A39281706F5E4D3C2B1A09F8E7D6C5B4A39281706F5E
SECOND_AUTHORITY = ex.address_of(SECOND_AUTH_KEY)
EMPTY_LEAF = bytes.fromhex("000000000000000000000000000000000000e3e7")
PLAIN = bytes.fromhex("00000000000000000000000000000000000c0de2")  # a contract with code, no system contract
DELEGATED = bytes.fromhex("0000000000000000000000000000000000de1e9a")  # an account holding a delegation
DELEGATE = bytes.fromhex("00000000000000000000000000000000000de1e9")  # the account it delegates to
DETAINED = bytes.fromhex("00000000000000000000000000000000000c0de3")  # a contract that runs detained
BURNER = bytes.fromhex("00000000000000000000000000000000000c0de4")  # a contract whose one charge passes the cap
UNTOUCHED = bytes.fromhex("000000000000000000000000000000000000ba1a")  # an account no case's state holds
# The take-back examples' contracts (SATIN-TAKE-005 to -012).
WRITER = bytes.fromhex("00000000000000000000000000000000000c0de5")  # P of the descendant example
DESCENDANT = bytes.fromhex("00000000000000000000000000000000000c0de6")  # C, whose code P runs by DELEGATECALL
RETURNER = bytes.fromhex("00000000000000000000000000000000000c0de7")  # Q of the sent-back example
SENDER_BACK = bytes.fromhex("00000000000000000000000000000000000c0de8")  # P of the sent-back example's last variant
LOGGER = bytes.fromhex("00000000000000000000000000000000000c0de9")  # the log-reverted example's child
WRITER_CHILD = bytes.fromhex("00000000000000000000000000000000000c0dea")  # the reverted and halted examples' child
STOPPED_CHILD = bytes.fromhex("00000000000000000000000000000000000c0e01")  # a child a limit stops
STARTED = bytes.fromhex("00000000000000000000000000000000000c0e02")  # a value call's target whose start is held
TAKER = bytes.fromhex("00000000000000000000000000000000000c0e03")  # code that takes a record back and sends a hint
RELAY_B = bytes.fromhex("00000000000000000000000000000000000c0e04")  # the relays of a chain three calls deep
RELAY_C = bytes.fromhex("00000000000000000000000000000000000c0e05")
DEEP = bytes.fromhex("00000000000000000000000000000000000c0e06")  # the frame three calls below the first
LIST_KEY = 0x5EED_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0001  # the first of a list's keys
CHAIN_ID = 1
BLOCK_GAS_LIMIT = 10_000_000_000
BLOCK_TIMESTAMP = 0x6553F102
BLOCK_NUMBER = 2
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
                 contract_balance=0, authorizations=None, system=False, check=None, tune=None, make=None,
                 params=None, retune=None, reads=False, pools=False, destruction=False, coinbase=COINBASE,
                 detention=False, block_hashes=None, stops=False):
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
        # (probe, regular gas): the gas limit is set so the model's probe point (satin_model's Run.probe)
        # holds exactly that regular gas; `gas` is the limit the model is first run with to find it.
        self.tune = tune
        # A case whose code is written from parameters: `make(**params)` is its code, and each of `retune`,
        # (probe, regular gas, parameter, slope), sets a parameter so the probe holds that gas, the probe
        # moving by `slope` per unit of the parameter. A parameter "words" is the memory a burn expands to,
        # and "pad" a run of JUMPDESTs, one compute each: what the pad would hold beyond a word's cost moves
        # into the burn (`settle_burn`).
        self.make, self.params, self.retune = make, dict(params or {}), list(retune or [])
        self.reads = reads  # the case carries the reads group (D-61)
        self.pools = pools  # the case carries the gasPools group (D-64)
        self.destruction = destruction  # the case cites the destruction page's own rules (D-70)
        self.coinbase = coinbase  # the block beneficiary
        self.detention = detention  # a case of gas detention's rules at cdded1e (D-67)
        self.block_hashes = block_hashes or {}  # number -> the hash BLOCKHASH answers
        self.stops = stops  # the case pins the limit-stop page: its derivation cites which endings are stops (D-73)
        self.definition = ""  # the function of this file that defines the case, set by cases()
        if make:
            self.code = make(**self.params)


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
    for c in out:
        c.definition = "cases"
    for group in (interception_cases, ordering_cases, detention_cases, detention_rule_cases, reads_cases, limit_cases,
                  gas_pools_cases, take_back_cases, selfdestruct_cases, limit_stop_cases):
        made = group()
        for c in made:
            c.definition = group.__name__
        out += made
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


# --- Gas detention, the Oracle's reads, the refused volatile read ---------------------------------

RETURN_RETURNDATA = b"\x3d\x5f\x5f\x3e\x3d\x5f\xf3"  # RETURNDATACOPY(0, 0, RETURNDATASIZE), RETURN(0, RETURNDATASIZE)
REVERT_RETURNDATA = b"\x3d\x5f\x5f\x3e\x3d\x5f\xfd"  # RETURNDATACOPY(0, 0, RETURNDATASIZE), REVERT(0, RETURNDATASIZE)


def burn(words: int) -> bytes:
    """MLOAD of the last of `words` words of memory, and POP: its memory expansion is one regular charge."""
    return push(words * 32 - 32) + b"\x51\x50"


def words_within(budget: int) -> int:
    """The most memory words whose expansion from none costs at most `budget`."""
    words = int((budget * 512) ** 0.5)
    while model.memory_cost(words + 1) <= budget:
        words += 1
    while model.memory_cost(words) > budget:
        words -= 1
    return words


def detained(words: int, pad: int) -> bytes:
    """TIMESTAMP, a read of the block environment that detains the transaction, then a burn of compute and a
    pad of JUMPDESTs that leave the limit a set distance away."""
    return b"\x42\x50" + burn(words) + b"\x5b" * pad


def detention_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = ORDERING_SPEC
    cap, oracle_cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS, model.ORACLE_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 6_000), "pad": 0}
    push_cost = model.G_VERYLOW  # the PUSH20 before each child's BALANCE
    balance = push(int.from_bytes(UNTOUCHED, "big")) + b"\x31\x50" + STOP
    cold = model.WARM_READ + model.COLD_ACCOUNT_SURCHARGE

    def via_child(child_gas: int, tail: bytes = RETURN_RETURNDATA):
        return lambda words, pad: detained(words, pad) + call(child_gas, DETAINED, 0, 0) + tail

    # One charge under detention: each part an opcode deducts is a charge of its own (SATIN-DET-018, -020).
    for name, spendable, whole, what in (
            ("balance-static-crossing", 50, 1_000, f"is stopped at BALANCE's static cost, {model.WARM_READ}, which the "
             f"whole {fmt(1_000)} can pay, not run out of gas on the {fmt(cold)} the access costs in all; the transaction "
             "returns the frame's return data"),
            ("balance-static-out-of-gas", 50, 80, f"runs out of gas at BALANCE's static cost, {model.WARM_READ}, which its "
             "whole regular gas cannot pay either; the transaction returns the frame's empty return data"),
            ("balance-static-one-short", model.WARM_READ - 1, 5_000, "is stopped at BALANCE's static cost, nothing of the "
             "opcode spent, and its caller stops"),
            ("balance-static-paid", model.WARM_READ, 5_000, f"pays BALANCE's static cost and is stopped at its cold access, "
             f"{fmt(model.COLD_ACCOUNT_SURCHARGE)}, the static cost staying spent, and its caller stops")):
        pair = whole == 5_000  # the caller of the pair stops at once: at the static cost the limit leaves it nothing
        add(Case(f"satin/detention/{name}", f"a detained frame with {fmt(spendable)} of spendable gas and {fmt(whole)} of "
                 f"regular gas in all does BALANCE of an account that is not warm: it {what}", spec=spec, gas=21_000_000,
                 accounts={DETAINED: model.Account(nonce=1, code=balance)},
                 boundary=(f"the spendable part {'one below' if spendable < model.WARM_READ else 'at'} BALANCE's static cost"
                           if pair else ""),
                 make=via_child(whole + push_cost, STOP if pair else RETURN_RETURNDATA), params=start,
                 retune=[("child-room", spendable + push_cost, "pad", -1)]))
    value_call = call(0, UNTOUCHED, 1, 0) + STOP
    add(Case("satin/detention/call-value-crossing", "a detained frame with 200 of spendable gas does a value CALL: the "
             f"static cost {model.WARM_READ} is paid, and the frame is stopped at the value transfer, "
             f"{fmt(model.CALL_VALUE_COST)}, the static cost staying spent; the transaction returns the frame's return data",
             spec=spec, gas=21_000_000, accounts={DETAINED: model.Account(nonce=1, code=value_call)},
             make=via_child(20_000), params=start, retune=[("child-room", 200, "pad", -1)]))
    # The Oracle's SLOAD: the read, its mark, then one charge (SATIN-ORCL-004). A deposit's read asks no service
    # (SATIN-ORCL-005), so the cases are deposits; the mark shows in a later call whose one charge passes the cap.
    get_slot = mstore(0, int.from_bytes(model.selector("getSlot(uint256)"), "big") << 224)
    burner = burn(words_within(oracle_cap) + 1) + STOP
    for name, left, what in (
            ("read-short-of-warm-base", 50, f"under the warm base {model.WARM_READ}"),
            ("read-short-of-cold-access", 1_000, f"from the warm base to under COLD_SLOAD_COST {fmt(model.COLD_SLOAD)}")):
        add(Case(f"satin/oracle/{name}", f"a deposit's call to the Oracle's getSlot holds {fmt(left)} of regular gas at the "
                 f"SLOAD, {what}: the slot is read and the read marked, then the frame runs out of gas; a later call whose "
                 "one charge passes the Oracle's cap is stopped by the mark, and the deposit returns its return data",
                 spec=spec, system=True, deposit=(0, 22_000_000), sender_nonce=3,
                 accounts={BURNER: model.Account(nonce=1, code=burner)},
                 make=lambda gas: get_slot + call(gas, model.ORACLE, 0, 36) + b"\x50" + call(MAX_GAS, BURNER, 0, 0)
                 + RETURN_RETURNDATA,
                 params={"gas": 1_000}, retune=[("oracle-sload", left, "gas", 1)]))
    add(Case("satin/oracle/read-at-crossing", "a deposit's detained call to the Oracle's getSlot holds 50 of spendable gas "
             f"and {fmt(1_000)} in all at the SLOAD: the read is marked, and its one charge of {fmt(model.COLD_SLOAD)} is "
             "beyond the whole regular gas, so the frame runs out of gas rather than being stopped", spec=spec, system=True,
             deposit=(0, 21_000_000), sender_nonce=3,
             make=lambda words, pad, gas: get_slot + detained(words, pad) + call(gas, model.ORACLE, 0, 36) + RETURN_RETURNDATA,
             params={**start, "gas": 2_000},
             retune=[("oracle-sload", 1_000, "gas", 1), ("oracle-sload-room", 50, "pad", -1)]))
    # A refused volatile read costs nothing and comes before any charge (SATIN-MAC-003, -004).
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
    refused = disable + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50" + push(int.from_bytes(COINBASE, "big")) \
        + b"\x31" + STOP
    add(Case("satin/access-control/refused-read", "a frame switches its volatile-data access off, then does BALANCE of the "
             "block beneficiary: refused before any charge, the frame reverts with VolatileDataAccessDisabled(10) on the "
             "gas it held at the opcode", spec=spec, system=True, code=refused))
    add(Case("satin/access-control/refused-read-under-static-gas", "as the refused read, the frame holding 50 of regular "
             f"gas at the BALANCE, under its static cost {model.WARM_READ}: refused all the same, not out of gas", spec=spec,
             system=True, code=refused, gas=100_000, tune=("refused", 50)))
    return out


# --- Gas detention's rules at cdded1e: what is volatile, compute, the withheld part, precompiles ------

SPINNER = bytes.fromhex("00000000000000000000000000000000000c0df1")  # a value call's callee that runs on its stipend
REPORTER = bytes.fromhex("00000000000000000000000000000000000c0df2")  # a callee that returns the GAS it starts with
# EIP-2935's history contract, its runtime code as the EIP deploys it: the system address's path stores the parent
# hash; every other caller's input is checked to be one word, then NUMBER is read before the requested block is
# checked against the window and its slot loaded.
HISTORY_CODE = bytes.fromhex(
    "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257"
    "611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500")
SPIN_STEPS = 1_000  # the JUMPDESTs the stipend's callee runs before it stops


def over_cap(cap: int) -> bytes:
    """One memory expansion whose cost is past `cap`: past what any read's limit leaves the transaction."""
    return burn(words_within(cap) + 1)


def detention_rule_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = TAKE_BACK_SPEC
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    big = over_cap(cap)
    start = {"words": words_within(cap - 30_000), "pad": 0}

    def at_and_past(name: str, at_intent: str, past_intent: str, make, params, retune, past, **kw):
        """A case tuned to land exactly on its edge, and its twin one step past it: `past` turns the tuned
        parameters into the twin's."""
        at = Case(f"satin/detention/{name}-at-limit", at_intent, spec=spec, detention=True, make=make, params=params,
                  retune=retune, boundary="the transaction's compute reaches its limit exactly", **kw)
        remade(at)
        add(at)
        add(Case(f"satin/detention/{name}-one-past-limit", past_intent, spec=spec, detention=True, make=make,
                 params=past(dict(at.params)), boundary="the transaction's compute one past its limit", **kw))

    # What is volatile: BLOBHASH is not (SATIN-DET-002); every BLOCKHASH is (SATIN-DET-004). The read shows in one
    # memory expansion past the cap, which a read stops and nothing else does.
    add(Case("satin/detention/not-volatile/blobhash", "BLOBHASH reads the transaction's own blob hashes, no volatile "
             f"data: nothing is marked, and one memory expansion of {fmt(model.memory_cost(words_within(cap) + 1))}, past "
             "the cap, completes", spec=spec, detention=True, gas=21_000_000,
             code=push(0) + b"\x49\x50" + big + STOP))
    for name, n, what in (("current-block", BLOCK_NUMBER, "of the current block, which BLOCKHASH answers with zero"),
                          ("future-block", BLOCK_NUMBER + 1, "of a future block, which BLOCKHASH answers with zero"),
                          ("in-range", BLOCK_NUMBER - 1, "of the previous block, whose hash BLOCKHASH answers")):
        add(Case(f"satin/detention/blockhash/{name}", f"BLOCKHASH {what}, is a read of the block environment whatever "
                 "its operand: the memory expansion after it, past the cap, is stopped with MegaLimitExceeded(2, limit)",
                 spec=spec, detention=True, gas=21_000_000, code=push(n) + b"\x40\x50" + big + STOP,
                 block_hashes={BLOCK_NUMBER - 1: bytes.fromhex("a1" * 32)}))
    # The block environment's other reads, and the beneficiary's account read by EXTCODESIZE and EXTCODEHASH
    # (SATIN-DET-001); reads of other accounts and of a contract's own storage are none.
    for op, name in ((0x41, "COINBASE"), (0x44, "PREVRANDAO"), (0x45, "GASLIMIT"), (0x48, "BASEFEE"),
                     (0x4A, "BLOBBASEFEE"), (0x4B, "SLOTNUM")):
        add(Case(f"satin/detention/block-environment/{name.lower()}", f"{name} is a read of the block environment: the "
                 "memory expansion after it, past the cap, is stopped with MegaLimitExceeded(2, limit)", spec=spec,
                 detention=True, gas=21_000_000, code=bytes([op]) + b"\x50" + big + STOP))
    for op, name in ((0x3B, "EXTCODESIZE"), (0x3F, "EXTCODEHASH")):
        add(Case(f"satin/detention/beneficiary/{name.lower()}", f"{name} of the block beneficiary is a read of its "
                 "account: the memory expansion after it, past the cap, is stopped", spec=spec, detention=True,
                 gas=21_000_000, code=push(int.from_bytes(COINBASE, "big")) + bytes([op]) + b"\x50" + big + STOP))
    add(Case("satin/detention/not-volatile/other-accounts", "BALANCE of an account that is not the block beneficiary, "
             "the contract's own SELFBALANCE and an SLOAD of its own storage read nothing volatile: the memory expansion "
             "after them, past the cap, completes", spec=spec, detention=True, gas=21_000_000, storage={1: 7},
             code=push(int.from_bytes(UNTOUCHED, "big")) + b"\x31\x50" + b"\x47\x50" + push(1) + b"\x54\x50" + big + STOP))
    # A call to the EIP-2935 history contract is a read where, and only when, its code completes a NUMBER
    # (SATIN-DET-005): the call itself is not marked.
    history = {model.HISTORY_STORAGE_ADDRESS: model.Account(code=HISTORY_CODE)}
    future = mstore(0, BLOCK_NUMBER + 3)  # a requested block in the future: the contract reverts after its NUMBER
    for name, gas, size, intent, edge in (
            ("at-number", 52, 32, "forwarded exactly the gas its code spends up to and including NUMBER: NUMBER "
             "completes, so the call is a read, and the contract then runs out of gas; the memory expansion after the "
             "call, past the cap, is stopped", "the forward at the gas the history contract spends through its NUMBER"),
            ("short-of-number", 51, 32, "forwarded one gas less: the contract runs out of gas at NUMBER, which does not "
             "complete, so nothing is marked and the memory expansion after the call, past the cap, completes",
             "the forward one below the gas the history contract spends through its NUMBER"),
            ("input-refused", 10_000, 0, "with an empty input: the contract's input check, which comes before its "
             "NUMBER, refuses it with a revert, so nothing is marked and the memory expansion after the call, past the "
             "cap, completes", "")):
        add(Case(f"satin/detention/history-contract/{name}", f"a call to the EIP-2935 history contract {intent}",
                 spec=spec, detention=True, gas=21_000_000, accounts=history, boundary=edge,
                 code=future + call(gas, model.HISTORY_STORAGE_ADDRESS, 0, size) + b"\x50" + big + STOP))
    # A creation is never a read (SATIN-DET-006), and the beneficiary's own frame reads by its own SELFBALANCE
    # (SATIN-DET-007): the created address made the block beneficiary.
    created = model.created_address(SENDER, 0)
    add(Case("satin/detention/creation/created-at-beneficiary", "a creation transaction whose created address is the "
             "block beneficiary is not detained from its start: its initcode's memory expansion past the cap completes, "
             "and the account is created", spec=spec, detention=True, to=None, coinbase=created, gas=21_500_000,
             data=big + ret(0, 0)))
    add(Case("satin/detention/creation/beneficiary-selfbalance", "the same creation's initcode, running as the block "
             "beneficiary, reads its own balance by SELFBALANCE: a read of the beneficiary's account, so the memory "
             "expansion after it, past the cap, stops the transaction's own frame", spec=spec, detention=True, to=None,
             coinbase=created, gas=21_500_000, data=b"\x47\x50" + big + ret(0, 0)))
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224) \
        + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50"
    add(Case("satin/detention/creation/create-at-beneficiary-access-off", "a contract switches its volatile-data access "
             "off, then CREATEs an account at the block beneficiary's address: the creation is neither refused nor "
             "marked, and the memory expansion after it, past the cap, completes", spec=spec, detention=True, system=True,
             coinbase=model.created_address(CONTRACT, 1), gas=21_500_000, code=disable + create(0, ret(0, 0)) + big + STOP))
    # Detained from the start (SATIN-DET-008): the sender, the recipient or an applied authority is the beneficiary.
    pad_end = lambda words, pad: burn(words) + b"\x5b" * pad + STOP
    at_and_past("beneficiary/recipient", "a transaction to the block beneficiary, a contract, is detained from its "
                "start at compute zero: its frame's compute reaches the cap exactly and it completes",
                "the same transaction one compute past the cap: its last JUMPDEST is stopped with MegaLimitExceeded(2, "
                "limit)", pad_end, {"words": words_within(cap - 6_000), "pad": 0}, [("end-spendable", 0, "pad", -1)],
                lambda p: {**p, "pad": p["pad"] + 1}, coinbase=CONTRACT, gas=21_000_000)
    add(Case("satin/detention/beneficiary/sender", "a transaction whose sender is the block beneficiary is detained from "
             "its start: one memory expansion past the cap stops its frame", spec=spec, detention=True, coinbase=SENDER,
             gas=21_000_000, code=big + STOP))
    add(Case("satin/detention/beneficiary/authority", "an EIP-7702 transaction whose applied authority is the block "
             "beneficiary is detained from its start, though neither its sender nor its recipient is: one memory "
             "expansion past the cap stops its frame", spec=spec, detention=True, ty=4, coinbase=AUTHORITY,
             authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)], accounts={AUTHORITY: model.Account(balance=1)},
             gas=21_500_000, code=big + STOP))
    # The cap (SATIN-DET-012, -013): the limit is the compute at the read plus the protocol's cap, exactly.
    at_and_past("cap/timestamp", "TIMESTAMP detains the transaction, and its frame then computes exactly to the limit, "
                "the compute at the read plus the cap: it completes", "one compute more: the last JUMPDEST is stopped",
                lambda words, pad: detained(words, pad) + STOP, {"words": words_within(cap - 6_000), "pad": 0},
                [("end-spendable", 0, "pad", -1)], lambda p: {**p, "pad": p["pad"] + 1}, gas=21_000_000)
    # The limit only goes down (SATIN-DET-012): a later read whose own limit is higher binds nothing.
    mid = words_within(cap // 2)
    at_and_past("cap/second-read", "TIMESTAMP, then half the cap of compute, then NUMBER, whose own limit is higher: "
                "the first read's limit binds, and the frame computes exactly to it and completes",
                "one compute more: stopped at the first read's limit",
                lambda words, pad: b"\x42\x50" + burn(mid) + b"\x43\x50" + burn(words) + b"\x5b" * pad + STOP,
                {"words": words_within(cap - 6_000), "pad": 0}, [("end-spendable", 0, "pad", -1)],
                lambda p: {**p, "pad": p["pad"] + 1}, gas=21_000_000)
    # The cap counts from the compute at the read, which may be larger than the cap itself (SATIN-DET-012).
    before = words_within(cap + cap // 4)
    at_and_past("cap/after-larger-spend", "a transaction computes more than the cap, then reads TIMESTAMP: it may still "
                "compute the cap after the read, exactly, and completes", "one compute more: stopped",
                lambda words, pad: burn(before) + b"\x42\x50" + burn(words) + b"\x5b" * pad + STOP,
                {"words": words_within(model.memory_cost(before) + cap - 6_000), "pad": 0},
                [("end-spendable", 0, "pad", -1)], lambda p: {**p, "pad": p["pad"] + 1}, gas=46_000_000)
    # State and history gas regular gas paid before the read is not compute (SATIN-DET-009).
    at_and_past("cap/spill-before-read", "a fresh slot written before TIMESTAMP, its state gas and its record's history "
                "paid from regular gas with no reservoir: that is not compute, so the frame computes the cap after the "
                "read exactly and completes", "one compute more: stopped",
                lambda words, pad: sstore(1, 1) + b"\x42\x50" + burn(words) + b"\x5b" * pad + STOP,
                {"words": words_within(cap - 6_000), "pad": 0}, [("end-spendable", 0, "pad", -1)],
                lambda p: {**p, "pad": p["pad"] + 1}, gas=21_000_000)
    # A give-back after the read lands in the reservoir and lifts nothing (SATIN-DET-009, SATIN-HIST-012).
    for name, storage, first, back, what in (
            ("state-refill", {}, 1, 0, "a fresh slot written before TIMESTAMP and written back to zero after it: its "
             "state gas and its record's history are given back into the reservoir"),
            ("history-refill", {1: 1}, 2, 1, "a slot written away from its non-zero original before TIMESTAMP and back "
             "after it: its record and the record's history are given back into the reservoir")):
        at_and_past(f"cap/{name}-after-read", f"{what}, which gives the frame no compute: it computes the cap after the "
                    "read exactly and completes", "one compute more: stopped",
                    lambda words, pad, first=first, back=back: sstore(1, first) + b"\x42\x50" + sstore(1, back)
                    + burn(words) + b"\x5b" * pad + STOP, {"words": words_within(cap - 6_000), "pad": 0},
                    [("end-spendable", 0, "pad", -1)], lambda p: {**p, "pad": p["pad"] + 1}, gas=21_000_000,
                    storage=storage)
    # The stipend (SATIN-DET-010): what a value call's callee runs on it is compute, and what it leaves of it
    # lowers nothing when it comes back.
    spinner = {SPINNER: model.Account(nonce=1, code=b"\x5b" * SPIN_STEPS + STOP)}
    at_and_past("stipend/spun", f"after TIMESTAMP, a value call forwarding no gas runs a callee that spends "
                f"{fmt(SPIN_STEPS)} of its {fmt(model.CALL_STIPEND)} stipend: that is compute, and the stipend's rest "
                "comes back without lowering it, so the caller's JUMPDESTs reach the limit exactly and it completes",
                "one JUMPDEST more: stopped, as it would not be if the callee's work were not compute or the stipend's "
                "rest lowered it",
                lambda words, pad: b"\x42\x50" + burn(words) + call(0, SPINNER, 1, 0) + b"\x50" + b"\x5b" * pad + STOP,
                dict(start), [("end-spendable", 0, "pad", -1)], lambda p: {**p, "pad": p["pad"] + 1},
                gas=21_000_000, contract_balance=10, accounts=spinner)
    # The withheld part: GAS, the SSTORE check and the forward see it (SATIN-DET-015); the settlement returns it and
    # the refund cap leaves it out (SATIN-DET-016); state and history gas draw it first (SATIN-DET-017).
    add(Case("satin/detention/withheld/gas-sees-whole", "TIMESTAMP detains a transaction of 25,000,000 gas, which "
             "withholds what is past the cap: GAS, stored in slot 0, reads the whole regular gas, the withheld part "
             "included", spec=spec, detention=True, gas=25_000_000, code=b"\x42\x50" + b"\x5a" + push(0) + b"\x55" + STOP))
    add(Case("satin/detention/withheld/sstore-check-sees-whole", f"a detained frame with {fmt(2_000)} of spendable gas, "
             f"under the {fmt(model.CALL_STIPEND)} of SSTORE's minimum-gas check, and much more withheld writes a fresh "
             "slot: the check reads the whole regular gas and passes, and the write's charge is the crossing, a stop "
             "and not an out-of-gas", spec=spec, detention=True, gas=21_000_000,
             make=lambda words, pad: detained(words, pad) + sstore(1, 1) + STOP, params=dict(start),
             retune=[("sstore-room", 2_000, "pad", -1)], boundary="the spendable part under the minimum-gas check"))
    add(Case("satin/detention/withheld/sstore-check-sees-whole-write-paid", f"a slot written before TIMESTAMP is "
             f"written again in a detained frame with {fmt(2_000)} of spendable gas, under the "
             f"{fmt(model.CALL_STIPEND)} of SSTORE's minimum-gas check: the check reads the whole regular gas and passes, "
             "the warm rewrite costs its static cost alone, and the transaction completes as without the read",
             spec=spec, detention=True, gas=21_000_000,
             make=lambda words, pad: sstore(1, 1) + detained(words, pad) + sstore(1, 2) + STOP, params=dict(start),
             retune=[("sstore-room", 2_000, "pad", -1)], boundary="the spendable part under the minimum-gas check"))
    reporter = {REPORTER: model.Account(nonce=1, code=b"\x5a" + push(0) + b"\x52" + push(32) + push(0) + b"\xf3")}
    add(Case("satin/detention/withheld/forward-sees-whole", "a detained frame with little spendable gas and much "
             "withheld calls a contract with all the gas it may forward: the forward is computed from the whole regular "
             "gas, as the callee's GAS, which the transaction returns, shows", spec=spec, detention=True, gas=21_000_000,
             accounts=reporter, make=lambda words, pad: detained(words, pad) + call(MAX_GAS, REPORTER, 0, 0)
             + RETURN_RETURNDATA, params=dict(start), retune=[("child-room", 100, "pad", -1)]))
    add(Case("satin/detention/withheld/refund-cap", "TIMESTAMP detains a transaction of 25,000,000 gas that clears two "
             "slots: the withheld gas returns to the sender and is not in the total whose fifth caps the refund, so the "
             "refund is capped", spec=spec, detention=True, gas=25_000_000, storage={1: 5, 2: 5},
             code=b"\x42\x50" + sstore(1, 0) + sstore(2, 0) + STOP))
    sstore_regular = model.COLD_SSTORE_ACCESS + model.SSTORE_SET
    tail = 50
    at_and_past("withheld/state-gas", f"a detained frame writes a fresh slot with {fmt(sstore_regular + tail)} of "
                "spendable gas: the slot's regular charge leaves it the "
                f"{tail} its JUMPDESTs then spend, because the slot's state gas and its record's history draw the "
                "withheld part first; it completes at its limit", "one JUMPDEST more: stopped",
                lambda words, pad, tail: detained(words, pad) + sstore(1, 1) + b"\x5b" * tail + STOP,
                {**start, "tail": tail}, [("sstore-room", sstore_regular + tail, "pad", -1)],
                lambda p: {**p, "tail": p["tail"] + 1}, gas=21_000_000)
    # Precompiles (SATIN-DET-021 to -024): decided from the price, read before the precompile runs.
    words32 = 32 * 32
    identity_price = model.IDENTITY_BASE + model.IDENTITY_WORD * 32
    for name, room, gas, tail, intent, edge in (
            ("identity/priced-at-allowance", identity_price, MAX_GAS, STOP, f"priced {fmt(identity_price)}, the allowance "
             "exactly: it runs on its whole forward, and the transaction completes at its limit",
             "the price at the allowance"),
            ("identity/priced-past-allowance", identity_price - 1, MAX_GAS, RETURN_RETURNDATA, "priced one past the "
             "allowance and within its forward: it does not run and is the crossing, whose stop its caller catches and "
             "returns", "the price one past the allowance"),
            ("identity/priced-at-forward", 60, identity_price, RETURN_RETURNDATA, "forwarded its price, past an allowance "
             "of 60: the price is within the forward, so it is the crossing", "the price at the forward"),
            ("identity/priced-past-forward", 60, identity_price - 1, RETURN_RETURNDATA, "forwarded one gas less than its "
             "price, past an allowance of 60: it runs on its forward and fails out of gas, as without the read, and what "
             "it burns is no compute, so its caller completes", "the price one past the forward")):
        add(Case(f"satin/detention/precompile/{name}", "after TIMESTAMP, a call to the identity precompile with "
                 f"{fmt(words32)} bytes of input, " + intent, spec=spec, detention=True, gas=21_000_000, boundary=edge,
                 make=lambda words, pad, gas=gas, tail=tail: detained(words, pad) + call(gas, model.IDENTITY, 0, words32)
                 + tail, params=dict(start), retune=[("precompile-room", room, "pad", -1)]))
    held = {model.IDENTITY: model.Account(balance=1)}
    add(Case("satin/detention/precompile/identity/value-within-allowance", "after TIMESTAMP, a value call to the identity "
             f"precompile with {fmt(words32)} bytes of input, priced within the allowance: it runs on its whole forward, "
             "the value moves, and the start keeps its records and its transfer log, as without the read", spec=spec,
             detention=True, gas=21_000_000, accounts=held, contract_balance=10,
             code=detained(start["words"], 0) + call(MAX_GAS, model.IDENTITY, 1, words32) + RETURN_RETURNDATA))
    for name, balance, intent in (
            ("identity/value-crossing", 10, "carrying one wei its caller can fund, priced past the allowance: the "
             "crossing, held to the price alone, so the value does not move and no record or transfer log is kept"),
            ("identity/value-unfunded", 0, "carrying one wei its caller cannot fund, priced past the allowance: refused "
             "on its caller's account, it runs no precompile and fails as without the read, not the crossing")):
        add(Case(f"satin/detention/precompile/{name}", "after TIMESTAMP, a value call to the identity precompile with "
                 f"{fmt(words32)} bytes of input, " + intent, spec=spec, detention=True, gas=21_000_000, accounts=held,
                 contract_balance=balance, make=lambda words, pad: detained(words, pad)
                 + call(MAX_GAS, model.IDENTITY, 1, words32) + RETURN_RETURNDATA, params=dict(start),
                 retune=[("precompile-room", identity_price - 1, "pad", -1)]))
    over_bound = model.MODEXP_MAX_INPUT_SIZE + 1
    modexp_input = word(over_bound) + word(0) + word(0)
    modexp_price = model.modexp_price(modexp_input)[0]
    for name, room, tail, intent, edge in (
            ("modexp/over-bound-at-allowance", modexp_price, STOP, "the allowance exactly: it runs, charges its price, "
             "fails EIP-7823's bound and consumes its forward, as without the read", "the price at the allowance"),
            ("modexp/over-bound-past-allowance", modexp_price - 1, RETURN_RETURNDATA, "one past the allowance and within "
             "its forward: an input that would fail a check made after the gas charge is the crossing too",
             "the price one past the allowance")):
        add(Case(f"satin/detention/precompile/{name}", f"after TIMESTAMP, a ModExp call whose base length, "
                 f"{fmt(over_bound)}, is over EIP-7823's bound, priced by its formula all the same, {fmt(modexp_price)}: "
                 + intent, spec=spec, detention=True, gas=21_000_000, boundary=edge,
                 make=lambda words, pad, tail=tail: detained(words, pad) + bytes_to_memory(modexp_input)
                 + call(MAX_GAS, model.MODEXP, 0, len(modexp_input)) + tail,
                 params={"words": words_within(cap - 2 * modexp_price - 30_000), "pad": 0},
                 retune=[("precompile-room", room, "pad", -1)]))
    pairing = model.BN254_PAIRING_MAX_INPUT_SIZE + 1
    add(Case("satin/detention/precompile/bn254-pairing-over-size-limit", f"after TIMESTAMP, a BN254 pairing call of "
             f"{fmt(pairing)} bytes, one over its size limit, with an allowance of 100 and a forward past the pairing "
             "formula's price for that many bytes: priced at zero, it runs on its forward, fails before any gas check and "
             "consumes the forward, as without the read", spec=spec, detention=True, gas=31_000_000,
             make=lambda words, pad: detained(words, pad) + call(MAX_GAS, model.BN254_PAIRING, 0, pairing) + STOP,
             params=dict(start), retune=[("precompile-room", 100, "pad", -1)]))
    # A user's deposit is detained as any transaction (SATIN-DET-026).
    burner = {BURNER: model.Account(nonce=1, code=big + STOP)}
    add(Case("satin/detention/deposit/user-deposit", "a user's deposit reads TIMESTAMP and calls a contract whose one "
             "memory expansion is past the cap: the callee is stopped with MegaLimitExceeded(2, limit), which the deposit "
             "returns", spec=spec, detention=True, deposit=(0, 21_000_000), sender_nonce=3, accounts=burner,
             code=b"\x42\x50" + call(MAX_GAS, BURNER, 0, 0) + RETURN_RETURNDATA))
    return out


# --- Reads: what a transaction loads (the stateless witness) ----------------------------------------


def reads_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = ORDERING_SPEC
    entries = [(AUTH_KEY, CHAIN_ID, DELEGATE, 0), (SECOND_AUTH_KEY, CHAIN_ID, DELEGATE, 0)]
    both = {AUTHORITY: model.Account(balance=1), SECOND_AUTHORITY: model.Account(balance=1)}
    # Every authorization list is simulated, the whole list walked: each authority it consults is loaded
    # whether or not the list is then applied (SATIN-AUTH-005, SATIN-WIT-004).
    add(Case("satin/reads/list-simulated-out-of-gas", "a two-entry EIP-7702 list whose first entry's ACCOUNT_WRITE, "
             f"{fmt(model.ACCOUNT_WRITE)}, is one gas beyond the regular gas left: the transaction runs out of gas before "
             "its first frame with nothing of the list applied, and both authorities are in the reads, the list's "
             "simulation having loaded them; the recipient, whose load is at step 4, is not", spec=spec, ty=4, to=EOA,
             code=b"", gas=500_000, authorizations=entries, accounts=both, reads=True,
             tune=("list", model.ACCOUNT_WRITE - 1)))
    add(Case("satin/reads/list-simulated-applied", "the same two-entry list with the gas to apply it: both authorities and "
             "the recipient are in the reads", spec=spec, ty=4, to=EOA, code=b"", gas=500_000, authorizations=entries,
             accounts=both, reads=True))
    # The delegate is loaded at step 5 only once its access is paid (SATIN-SCHED-008).
    delegation = model.DELEGATION_PREFIX + DELEGATE
    held = {DELEGATED: model.Account(nonce=1, code=delegation), DELEGATE: model.Account(nonce=1, code=STOP)}
    cold = model.WARM_READ + model.COLD_ACCOUNT_SURCHARGE
    for short in (True, False):
        left = cold - 1 if short else cold
        add(Case(f"satin/reads/delegate-{'not-loaded' if short else 'loaded'}", f"a transaction to an account delegating to "
                 f"an account that is not warm, with {fmt(left)} of regular gas left for the delegate's access: " +
                 ("the cold surcharge cannot be paid, so the delegate is not loaded and is not in the reads" if short else
                  "the access is paid, so the delegate is loaded and is in the reads"),
                 boundary=f"the regular gas left for the delegate's access {'one below' if short else 'at'} {fmt(cold)}",
                 spec=spec, to=DELEGATED, code=None, accounts=held, gas=100_000, reads=True, tune=("delegate", left)))
    # The Oracle's SLOAD loads its slot before its charge (SATIN-ORCL-004).
    get_slot = mstore(0, int.from_bytes(model.selector("getSlot(uint256)"), "big") << 224)
    add(Case("satin/reads/oracle-slot-before-charge", "a deposit's call to the Oracle's getSlot holds 50 of regular gas at "
             f"the SLOAD, under the warm base {model.WARM_READ}: the slot is loaded before the charge runs the frame out of "
             "gas, and is in the reads", spec=spec, system=True, deposit=(0, 1_000_000), sender_nonce=3, reads=True,
             make=lambda gas: get_slot + call(gas, model.ORACLE, 0, 36) + STOP, params={"gas": 1_000},
             retune=[("oracle-sload", 50, "gas", 1)]))
    # A cold account load the gas cannot pay is not made (SATIN-WIT-012).
    for short in (True, False):
        left = cold - 1 if short else cold
        add(Case(f"satin/reads/balance-cold-{'unpaid' if short else 'paid'}", f"a BALANCE of an account that is not warm "
                 f"with {fmt(left)} of regular gas: " +
                 ("the static cost is paid and the cold access is not, so the frame runs out of gas without loading the "
                  "account, which is not in the reads" if short else "the access is paid and the account, absent, is in "
                  "the reads as read and absent"),
                 boundary=f"the regular gas at BALANCE {'one below' if short else 'at'} {fmt(cold)}", spec=spec,
                 code=push(int.from_bytes(UNTOUCHED, "big")) + b"\x31" + STOP, gas=100_000, reads=True,
                 tune=("balance", left)))
    return out


# --- Limit stops of the transaction's own frame ------------------------------------------------------


def limit_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = ORDERING_SPEC
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    # Compute: gas detention's crossing in the transaction's own frame (SATIN-DET-018), the transaction's result.
    over = words_within(cap) + 1
    add(Case("satin/limit-stops/compute-at-one-charge", "TIMESTAMP detains the transaction, then one memory expansion of "
             f"{fmt(model.memory_cost(over))} passes what the limit leaves it: the transaction's own frame is stopped with "
             "MegaLimitExceeded(2, limit) and the expansion is not charged", spec=spec, gas=21_000_000,
             code=b"\x42\x50" + burn(over) + STOP))
    add(Case("satin/limit-stops/compute-at-static-cost", "TIMESTAMP and a burn leave the transaction's own frame 50 of "
             f"spendable gas: a BALANCE of an account that is not warm is stopped at its static cost, {model.WARM_READ}",
             spec=spec, gas=21_000_000, make=lambda words, pad: detained(words, pad) + push(int.from_bytes(UNTOUCHED, "big"))
             + b"\x31" + STOP, params={"words": words_within(cap - 6_000), "pad": 0},
             retune=[("balance-room", 50 + model.G_VERYLOW, "pad", -1)]))
    # State growth: fresh slots past the frame's budget, which is the transaction's whole limit (SATIN-LIM-002).
    # Its first slots reach the budget without a stop; the case's own figures show them kept until the last.
    limit = model.TX_STATE_GROWTH_LIMIT
    add(Case("satin/limit-stops/state-growth-one-over", f"{fmt(limit + 1)} fresh slots: the first {fmt(limit)} reach the "
             f"frame's state-growth budget, {fmt(limit)}, and the last takes it past, so the frame is stopped with "
             "MegaLimitExceeded(3, limit) after that SSTORE's regular and state charges and before its record is charged, "
             "and the transaction settles as a revert", spec=spec, gas=150_000_000,
             code=b"".join(sstore(k, 1) for k in range(1, limit + 2)) + STOP))
    # Data size: hints use what the transaction has left, and a log of the frame's crosses the transaction's limit
    # while the frame's budget holds it (SATIN-LIM-012).
    big = 1 << 20
    count = (model.TX_DATA_LIMIT - model.TX_BODY_SIZE) // big
    tail = 100  # what one more hint leaves the transaction, for a small log to land on or cross
    last = model.TX_DATA_LIMIT - model.TX_BODY_SIZE - count * big - tail
    hints = big_hints(count, big) + push(0) + push(0) + push(last) + push(0) + push(0) \
        + push(int.from_bytes(model.ORACLE, "big")) + push(1) + b"\xf1\x50"
    for over_limit in (False, True):
        size = tail - model.LOG_BASE_SIZE + (1 if over_limit else 0)
        add(Case(f"satin/limit-stops/data-size-{'one-byte-over' if over_limit else 'at-limit'}",
                 f"admitted hints, {NUMBERS.get(count, str(count))} of 1 MiB and one of {fmt(last)} bytes, leave the "
                 f"transaction {tail} bytes of data size, and a LOG0 of {size} data bytes " +
                 ("takes it one byte past its limit while the frame's budget holds the log: the frame is stopped with "
                  "MegaLimitExceeded(0, limit) naming the transaction limit, the log is not kept, and the hints stay "
                  "counted" if over_limit else "takes it exactly to its limit: the log is kept"),
                 boundary=f"the data size {'one byte over' if over_limit else 'at'} TX_DATA_LIMIT", system=True, spec=spec,
                 gas=8_000_000, code=hints + log(0, 0, size, []) + STOP))
    return out


# --- The gas pools, observed at the first frame's start and end -------------------------------------


def gas_pools_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = ORDERING_SPEC
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE
    slot = model.SLOT_STATE
    add(Case("satin/gas-pools/value-transfer-control", "a plain value transfer to an account without code: the first "
             "frame runs nothing, so its pools end as they start, regular gas pays no state or history charge, and the "
             "gas returned is what it was given", spec=spec, to=EOA, code=b"", value=1, pools=True))
    # A reservoir smaller than the slot's state gas past its legacy share: regular gas pays the share and the spill.
    part = slot // 4
    add(Case("satin/gas-pools/fresh-slot-partly-from-regular", f"a fresh slot with {fmt(part)} of reservoir at the first "
             f"frame's start: of its {fmt(slot)} of state gas the reservoir pays {fmt(part)} and regular gas the legacy "
             f"share and the rest, and regular gas pays its record's {fmt(record)}", spec=spec,
             gas=model.EXECUTION_CAP + body + part, code=sstore(1, 1) + STOP, pools=True))
    # A reservoir larger than the slot's state gas: the legacy share is still regular gas's (SATIN-STATE-012).
    add(Case("satin/gas-pools/legacy-share-from-regular", f"a fresh slot with {fmt(slot * 4)} of reservoir at the first "
             f"frame's start: regular gas still pays the legacy share, {fmt(model.LEGACY_SSTORE_SHARE)}, and the reservoir "
             "the rest and the record", spec=spec, gas=model.EXECUTION_CAP + body + slot * 4, code=sstore(1, 1) + STOP,
             pools=True))
    # Give-backs land in the reservoir, never regular gas (SATIN-HIST-012).
    add(Case("satin/gas-pools/fresh-slot-restored", "0 -> 1 -> 0 with no reservoir: regular gas pays the slot's state gas "
             f"and record, {fmt(slot + record)}, and the give-back lands in the reservoir, which the first frame ends "
             "with and which returns to the sender", spec=spec, code=sstore(1, 1) + sstore(1, 0) + STOP, pools=True))
    access_control = model.selector("disableVolatileDataAccess()")
    add(Case("satin/gas-pools/answered-call-history-returns", "a value call its caller can fund, answered NonZeroTransfer() "
             f"by MegaAccessControl: the two records' {fmt(2 * record)} of history, charged in the opcode from regular "
             "gas, is given back into the reservoir, which the first frame ends with and which returns to the sender at "
             "the settlement", system=True, spec=spec, contract_balance=10, pools=True,
             code=bytes_to_memory(access_control) + call(100_000, model.MEGA_ACCESS_CONTROL, 1, 4) + STOP))
    return out


# --- The take-back page's worked examples (SATIN-TAKE-005 to -012), one case each ----------------


def delegatecall(gas: int, target: bytes) -> bytes:
    """DELEGATECALL(gas, target, 0, 0, 0, 0)."""
    return push(0) + push(0) + push(0) + push(0) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf4"


def create(value: int, init: bytes) -> bytes:
    """CREATE of `init`, laid out in memory from offset 0, with `value` wei; the created address is popped."""
    return bytes_to_memory(init) + push(len(init)) + push(0) + push(value) + b"\xf0\x50"


def jump_if(cond: bytes, then: bytes, otherwise: bytes) -> bytes:
    """`cond`, then `otherwise` when it is zero, or a jump to `then` when it is not."""
    dest = len(cond) + 3 + len(otherwise)
    assert dest < 256
    return cond + bytes([0x60, dest]) + b"\x57" + otherwise + b"\x5b" + then


def share_source(share: int) -> int:
    """The least reservoir a caller keeps after a start's charges whose child's share is `share` (SATIN-POOL-011)."""
    remaining = share
    while remaining - remaining * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR < share:
        remaining += 1
    return remaining


def take_back_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = TAKE_BACK_SPEC
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    log0 = model.LOG_BASE_SIZE * model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE

    # SATIN-TAKE-005, descendant: P writes its slot, and C, run by P's DELEGATECALL on P's storage, writes it back.
    # The first frame calls P, so that P's own end shows in the first frame's reservoir.
    gas_back = b"\x5a" + push(0) + b"\x52" + ret(0, 32)  # GAS, MSTORE(0, GAS), RETURN(0, 32)
    head = (f"in a transaction without a reservoir, P's slot 0, whose original is 7, is written to 8, its record's "
            f"{fmt(record)} of history paid from P's regular gas; C, run by P's DELEGATECALL on P's storage with no "
            f"reservoir, emits an empty LOG0, {fmt(log0)} of history from its regular gas, and writes the slot back to 7, "
            f"giving the {fmt(record)} into its own reservoir")
    for name, c_tail, p_tail, b_tail, tail in (
        ("kept", gas_back, RETURN_RETURNDATA, RETURN_RETURNDATA,
         f"; C's next GAS, returned as the transaction's output, reads its regular gas, which the give-back did not "
         f"raise; C and P succeed, so the {fmt(record)} join P's reservoir and the first frame's, and return to the sender"),
        ("descendant-reverted", revert(0, 0), STOP, STOP,
         f"; C then reverts: the slot is 8 again and P's record stands, and C's rollback makes its reservoir "
         f"{fmt(record)} + ({fmt(log0)} - {fmt(record)}) = {fmt(log0)}, which joins P's reservoir and, P succeeding, the "
         "first frame's"),
        ("both-reverted", revert(0, 0), revert(0, 0), STOP,
         f"; C reverts, then P reverts: P's reservoir becomes {fmt(log0)} + {fmt(record)} = {fmt(log0 + record)}, what "
         "C's rollback returned and P's own record, which join the first frame's reservoir"),
        ("writer-halted", revert(0, 0), INVALID, STOP,
         f"; C reverts, then P halts: P's reservoir becomes the zero it received, the {fmt(log0)} C's rollback returned "
         "to it consumed with its regular gas"),
    ):
        c_code = log(0, 0, 0, []) + sstore(0, 7) + c_tail
        p_code = sstore(0, 8) + delegatecall(MAX_GAS, DESCENDANT) + b"\x50" + p_tail
        add(Case(f"satin/take-backs/descendant/{name}", head + tail, spec=spec, pools=True,
                 code=call(MAX_GAS, WRITER, 0, 0) + b"\x50" + b_tail,
                 accounts={WRITER: model.Account(nonce=1, code=p_code, storage={0: 7}),
                           DESCENDANT: model.Account(nonce=1, code=c_code)}))

    # SATIN-TAKE-006, sent-back: P (the first frame) calls Q with 1 wei, and Q calls P back with 1 wei.
    back = call(MAX_GAS, CONTRACT, 1, 0) + b"\x50" + STOP
    for name, first, tail in (
        ("round-trip", b"",
         f"the first start makes both accounts' records, {fmt(2 * record)} of history charged to P after its forward, "
         f"and the second, Q's, takes both back; once P's re-entered frame returned, Q is given the {fmt(2 * record)} into "
         "its reservoir, which joins P's when Q returns"),
        ("nonce-bumped", create(0, b""),
         f"P first bumps its nonce by a CREATE, so P's account differs already: the first start makes Q's record alone, "
         f"{fmt(record)}, and the second takes Q's alone back, P's nonce keeping P's record"),
    ):
        p_code = jump_if(b"\x34", STOP, first + call(MAX_GAS, RETURNER, 1, 0) + b"\x50" + STOP)
        add(Case(f"satin/take-backs/sent-back/{name}", "P, a contract the transaction has not changed, calls Q, unchanged "
                 f"too, with 1 wei, and Q calls P back with 1 wei: {tail}", spec=spec, pools=True, contract_balance=10,
                 code=p_code, accounts={RETURNER: model.Account(nonce=1, balance=10, code=back)}))
    # The signs turned: Q first sends P 1 wei, then P's call to Q takes both records back, and Q's call back would make
    # them again, which Q, left 5,000 of regular gas after its forward and no reservoir, cannot pay.
    left = 5_000
    keep = 3 * model.G_VERYLOW + model.WARM_READ + model.CALL_VALUE_COST + left  # PUSH2, SWAP1, SUB, the CALL, what is left
    q_back = (push(0) + push(0) + push(0) + push(0) + push(1) + push(int.from_bytes(SENDER_BACK, "big")) + b"\x5a"
              + bytes([0x61]) + keep.to_bytes(2, "big") + b"\x90\x03\xf1\x50" + STOP)
    q_code = jump_if(b"\x36", call(0, SENDER_BACK, 1, 0) + b"\x50" + STOP, q_back)
    p_code = jump_if(b"\x34", STOP, call(200_000, RETURNER, 1, 0) + b"\x50" + STOP)
    q_paid = jump_if(b"\x36", call(0, SENDER_BACK, 1, 0) + b"\x50" + STOP, call(100_000, SENDER_BACK, 1, 0) + b"\x50" + STOP)
    add(Case("satin/take-backs/sent-back/signs-turned-paid", "Q first sends P 1 wei, making both accounts' records and "
             f"paying their {fmt(2 * record)}; then P calls Q with 1 wei, returning both balances to what was loaded, so "
             f"that start takes both records back, and Q's call back with 1 wei, which Q can pay, makes them again, "
             f"charging Q {fmt(2 * record)} before its start; once Q returns, P's start kept, P is given the "
             f"{fmt(2 * record)} of the records its start took back into its reservoir", spec=spec, pools=True,
             code=call(MAX_GAS, RETURNER, 0, 1) + b"\x50" + call(MAX_GAS, SENDER_BACK, 0, 0) + b"\x50" + STOP,
             accounts={RETURNER: model.Account(nonce=1, balance=10, code=q_paid),
                       SENDER_BACK: model.Account(nonce=1, balance=10, code=p_code)}))
    add(Case("satin/take-backs/sent-back/signs-turned", "Q first sends P 1 wei, making both accounts' records and paying "
             f"their {fmt(2 * record)}; then P calls Q with 1 wei, returning both balances to what was loaded, so that start "
             f"takes both records back, and Q's call back with 1 wei would make them again: it charges Q {fmt(2 * record)} "
             f"after the forward, which Q, left {fmt(left)} of regular gas and no reservoir, cannot pay, so Q runs out of "
             "gas, and P's start, failing, keeps both records standing", spec=spec,
             code=call(MAX_GAS, RETURNER, 0, 1) + b"\x50" + call(MAX_GAS, SENDER_BACK, 0, 0) + b"\x50" + STOP,
             accounts={RETURNER: model.Account(nonce=1, balance=10, code=q_code),
                       SENDER_BACK: model.Account(nonce=1, balance=10, code=p_code)}))

    # SATIN-TAKE-007: P creates C, whose constructor writes two fresh slots and which deploys 100 bytes of code; P
    # then calls C, which destroys itself to ABSENT, warmed first, with no balance or with the 1 wei P endowed it.
    runtime = (push(int.from_bytes(ABSENT, "big")) + b"\x31\x50" + push(int.from_bytes(ABSENT, "big")) + b"\xff").ljust(100, STOP)
    init = sstore(1, 1) + sstore(2, 1) + bytes_to_memory(runtime) + ret(0, len(runtime))
    created = model.created_address(CONTRACT, 1)
    state = model.ACCOUNT_STATE + 2 * model.SLOT_STATE + len(runtime) * model.CODE_STATE_PER_BYTE
    history = 3 * record + len(runtime) * model.COST_PER_HISTORY_BYTE
    shares = model.LEGACY_CREATE_SHARE + 2 * model.LEGACY_SSTORE_SHARE
    made = (f"P creates C at an address the state holds no account for, every bucket at m = 1: the creation and C's "
            f"constructor, which writes two fresh slots, and C's {len(runtime)} bytes of code charge {fmt(state)} of state "
            f"gas and {fmt(history)} of history, and count state growth +3, KV +3 and data size "
            f"+{3 * model.WRITE_RECORD_SIZE + len(runtime)}, their legacy shares, {fmt(shares)}, from regular gas, as all "
            "else is in a transaction without a reservoir; P's nonce record stays; later, called by P, C destroys itself ")
    add(Case("satin/take-backs/destroyed-creation/no-balance", made + "holding no balance: the destruction gives the "
             f"{fmt(state + history)} back into C's reservoir and counts -3, -3 and -{3 * model.WRITE_RECORD_SIZE + len(runtime)} "
             "on C's net, so the transaction keeps P's nonce record alone, and the reservoir returns to the sender",
             spec=spec, pools=True, code=create(0, init) + call(MAX_GAS, created, 0, 0) + b"\x50" + STOP))
    bens = model.ACCOUNT_STATE
    add(Case("satin/take-backs/destroyed-creation/new-beneficiary", made + "holding the 1 wei P endowed it with, to a warm "
             "beneficiary empty under EIP-161: first its regular charges, "
             f"{fmt(model.SELFDESTRUCT_COST + model.SELFDESTRUCT_NEW_ACCOUNT_COST)}, and the beneficiary's {fmt(bens)} of state "
             f"gas, its {fmt(model.LEGACY_SELFDESTRUCT_SHARE)} legacy share from regular gas, then the give-back of "
             f"{fmt(state + history)} into C's reservoir, then the beneficiary's rise, record and transfer log, and last its "
             f"record's {fmt(record)}, which the reservoir pays", spec=spec, pools=True, contract_balance=1,
             code=create(1, init) + call(MAX_GAS, created, 0, 0) + b"\x50" + STOP))

    # SATIN-TAKE-008, set-then-clear: two accepted entries of one absent authority, a delegation then a clear.
    indicator = model.DELEGATION_STATE_BYTES * model.COST_PER_STATE_BYTE
    add(Case("satin/take-backs/set-then-clear", "a list whose two entries are signed by an authority the state holds no "
             "account for, neither the sender nor a value recipient, the first delegating at nonce 0 and the second "
             f"clearing at nonce 1: the first charges the new account's {fmt(model.ACCOUNT_STATE)}, ACCOUNT_WRITE and the "
             f"indicator's {fmt(indicator)}; the second charges nothing and gives the {fmt(indicator)} back to no one; the "
             "list keeps one record and one unit of state growth, and leaves the authority with nonce 2 and no code",
             spec=spec, ty=4, to=EOA, code=b"", gas=500_000,
             authorizations=[(AUTH_KEY, CHAIN_ID, DELEGATE, 0), (AUTH_KEY, CHAIN_ID, bytes(20), 1)]))

    # SATIN-TAKE-009, log-reverted: a child emits LOG2 with 64 data bytes and reverts.
    data = 64
    log2 = (model.LOG_BASE_SIZE + 2 * model.LOG_TOPIC_SIZE + data) * model.COST_PER_HISTORY_BYTE
    child = log(2, 0, data, [1, 2]) + revert(0, 0)
    for name, value, tail in (
        ("reverted", 0, f"the {fmt(log2)} come back into the child's reservoir by its rollback, though its regular gas "
                        "paid them, and join the first frame's"),
        ("allowance", 1, f"as a value call's child, its history allowance pays the {fmt(log2)} and nothing of them comes "
                         f"back; the failed start's records give the first frame their {fmt(2 * record)}"),
    ):
        add(Case(f"satin/take-backs/log-reverted/{name}", f"a child emits LOG2 with {data} data bytes, "
                 f"{model.LOG_BASE_SIZE + 2 * model.LOG_TOPIC_SIZE + data} bytes and {fmt(log2)} of history gas, and "
                 f"reverts: {tail}", spec=spec, pools=True, contract_balance=value,
                 code=call(100_000, LOGGER, value, 0) + b"\x50" + STOP,
                 accounts={LOGGER: model.Account(nonce=1, code=child)}))

    # SATIN-TAKE-010, answer-stopped. The text's KV budget of 3 cannot be reached under the protocol's KV limit; the
    # same start crosses the state-growth budget instead. P is the first frame, whose state-growth budget is the
    # transaction's whole limit (SATIN-LIM-002); its fresh slots bring its net to one below it, and its value call to
    # an empty account would add the account's leaf. In a transaction without a reservoir, the first frame's final
    # reservoir is exactly what the stop gives back.
    limit = model.TX_STATE_GROWTH_LIMIT
    growth = limit - 1
    add(Case("satin/take-backs/answer-stopped", f"in a transaction without a reservoir, P, the first frame, whose "
             f"state-growth budget is {fmt(limit)}, writes {fmt(growth)} fresh slots, one short of it, then calls an "
             "account empty under EIP-161, without code, with 1 wei and no gas: the start would keep two records, a "
             "transfer log and the new account's leaf, and the started frame's state-growth budget is the share of P's "
             f"remaining 1, 0, which the leaf crosses; P was charged the new account's {fmt(model.ACCOUNT_STATE)}, its "
             f"{fmt(model.LEGACY_NEW_ACCOUNT_SHARE)} legacy share first, before the forward and {fmt(2 * record)} after "
             "it, the answer is replaced by MegaLimitExceeded(3, 0) on the stipend, and both charges are given back into "
             "P's reservoir, which ends with them; P returns the stop as its output", spec=spec, pools=True,
             gas=150_000_000, contract_balance=1,
             code=b"".join(sstore(k, 1) for k in range(1, growth + 1)) + call(0, ABSENT, 1, 0) + b"\x50"
             + RETURN_RETURNDATA))

    # SATIN-TAKE-011, reverted and halted: a child with a reservoir share of 100,000 writes a cold fresh slot. The
    # forward covers the operands pushed before the write, so that the child holds 50,000 at its SSTORE.
    share = 100_000
    keeps = share_source(share)
    # PUSH0, PUSH0 (REVERT's operands), PUSH3 of the slot's value, PUSH0. The value written is the share itself, an
    # input of the case, so that its figure is the case's own and not a constant's (tools/check_derived_text.py).
    pushes = 3 * model.G_BASE + model.G_VERYLOW
    regular = 50_000
    paid = model.SLOT_STATE - model.LEGACY_SSTORE_SHARE
    for name, end, tail in (
        ("reverted", b"\xfd", f"it reverts: its rollback makes its reservoir {fmt(share - paid - record)} + "
                              f"{fmt(model.SLOT_STATE + record)} = {fmt(share + model.LEGACY_SSTORE_SHARE)}, which returns "
                              "to the caller's reservoir, and its regular gas returns to the caller's"),
        ("halted", INVALID, f"it halts: its reservoir becomes the {fmt(share)} it received, which returns, and its regular "
                            "gas is consumed"),
    ):
        add(Case(f"satin/take-backs/failed-child/{name}", f"the first frame, with {fmt(keeps)} of reservoir, calls a child "
                 f"that receives a reservoir share of {fmt(share)} and holds {fmt(regular)} of regular gas at its write of "
                 f"a cold fresh slot at m = 1: the write's {fmt(model.COLD_SSTORE_ACCESS + model.SSTORE_SET)} of regular "
                 f"gas, the {fmt(model.LEGACY_SSTORE_SHARE)} legacy share from regular gas and {fmt(paid)} from the "
                 f"reservoir, then the record's {fmt(record)} from the reservoir, which is left with "
                 f"{fmt(share - paid - record)}; " + tail, spec=spec, pools=True,
                 gas=model.EXECUTION_CAP + body + keeps, code=call(regular + pushes, WRITER_CHILD, 0, 0) + b"\x50" + STOP,
                 accounts={WRITER_CHILD: model.Account(nonce=1, code=push(0) + push(0) + sstore(0, share) + end)}))

    # SATIN-TAKE-012, failed-deposit: a deposit from an absent sender whose own frame halts.
    add(Case("satin/take-backs/failed-deposit", "a deposit with a gas limit of 1,000,000 from a sender empty under "
             f"EIP-161, whose own frame halts after the caller's {fmt(model.ACCOUNT_STATE)} of state gas was paid: it reports "
             "its whole gas limit as regular gas, no state and no history gas, one unit of state growth, zero KV updates "
             "and its body's data size, the same bytes as its history bytes; the sender keeps its nonce bump and the mint",
             spec=spec, deposit=(ETH, 1_000_000), absent_sender=True, code=INVALID))
    return out


# --- SELFDESTRUCT and the destruction table (SATIN-SD-001 to -020), the page's own rules ------------

HEIR = bytes.fromhex("00000000000000000000000000000000000000e1")  # an existing beneficiary, holding 1 wei
WRAPPER = bytes.fromhex("00000000000000000000000000000000000c0deb")  # a frame that calls the created account and fails
LIBRARY = bytes.fromhex("00000000000000000000000000000000000c0dec")  # code a constructor runs by DELEGATECALL
HALTER = bytes.fromhex("00000000000000000000000000000000000c0ded")  # a child that halts at once


def selfdestruct_to(beneficiary: bytes) -> bytes:
    """SELFDESTRUCT(beneficiary)."""
    return push(int.from_bytes(beneficiary, "big")) + b"\xff"


def returning(runtime: bytes, prefix: bytes = b"") -> bytes:
    """Initcode that runs `prefix`, then lays `runtime` out in memory and returns it."""
    return prefix + bytes_to_memory(runtime) + ret(0, len(runtime))


def selfdestruct_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = TAKE_BACK_SPEC
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    created = model.created_address(CONTRACT, 1)  # what CONTRACT, at nonce 1, creates first
    heir = {HEIR: model.Account(balance=1)}

    def case(name: str, intent: str, **kw) -> None:
        add(Case(f"satin/selfdestruct/{name}", intent, spec=spec, destruction=True, **kw))

    # An account the transaction did not create (SATIN-SD-012, -001): the balance moves, nothing of the table.
    case("not-created/moves-balance", "the transaction's own frame, a contract the transaction did not create holding 10 "
         "wei, destroys itself to a cold existing account: EIP-6780 moves the balance and does not delete the account; "
         "no table applies, nothing is refilled or taken back, and the move writes both accounts, two records and a "
         "transfer log", contract_balance=10, code=selfdestruct_to(HEIR), accounts=heir)
    case("not-created/no-balance", "the same destruction of a contract holding no balance: nothing moves, so no account "
         "is written and no transfer log is emitted, and the account stays", code=selfdestruct_to(HEIR), accounts=heir)
    case("not-created/new-beneficiary", "a child frame, a contract the transaction did not create holding 10 wei, "
         "destroys itself to an address the state holds no account for: the beneficiary is created and charged as a new "
         "account, one unit of state growth, and the contract keeps its code with no balance",
         code=call(MAX_GAS, PLAIN, 0, 0) + b"\x50" + STOP,
         accounts={PLAIN: model.Account(nonce=1, balance=10, code=selfdestruct_to(ABSENT))})
    case("not-created/new-beneficiary-bucket-x2", "the same, the beneficiary's bucket holding twice the minimum "
         "capacity: its new-account state gas is priced at m = 2, its legacy share the same",
         code=call(MAX_GAS, PLAIN, 0, 0) + b"\x50" + STOP, salt={(ABSENT, None): 2},
         accounts={PLAIN: model.Account(nonce=1, balance=10, code=selfdestruct_to(ABSENT))})
    case("not-created/new-beneficiary-caller-reverts", "the same destruction, and the transaction's own frame then "
         "reverts: the beneficiary is never created, its state gas, legacy share included, comes back with the revert, "
         "and nothing of the move is kept", code=call(MAX_GAS, PLAIN, 0, 0) + b"\x50" + revert(0, 0),
         accounts={PLAIN: model.Account(nonce=1, balance=10, code=selfdestruct_to(ABSENT))})
    case("not-created/to-itself", "the transaction's own frame, a contract the transaction did not create holding 10 "
         "wei, destroys itself to itself: EIP-6780 moves nothing and deletes nothing, so no account is written, no "
         "transfer log is emitted and nothing rises", contract_balance=10, code=selfdestruct_to(CONTRACT))
    case("not-created/to-sender", "the same contract destroys itself to the transaction's sender: the balance moves with "
         "its transfer log, and the cleared account's record is the only one it makes, the sender's account being "
         "written by validation already", contract_balance=10, code=selfdestruct_to(SENDER))
    case("not-created/changed-beneficiary", "the transaction's own frame, a contract holding 10 wei, first sends 1 wei to "
         "an address the state holds no account for, which creates it and writes both accounts, then destroys itself to "
         "it: the beneficiary exists, so it is no new account and no rise, and both records stand, so the destruction "
         "makes none", contract_balance=10, code=call(0, ABSENT, 1, 0) + b"\x50" + selfdestruct_to(ABSENT))

    # The first effective destruction (SATIN-SD-002, -003, -016, -017): P creates C at an address the state holds no
    # account for, or holds a leaf for with nonce 0, no balance, no code and two slots; C's constructor writes slot 1
    # to 5, the value the state holds there, and C is then called and destroys itself to a warm existing account.
    init = sstore(1, 5) + returning(selfdestruct_to(HEIR))
    destroy = create(0, init) + push(int.from_bytes(HEIR, "big")) + b"\x31\x50" + call(MAX_GAS, created, 0, 0) + b"\x50"
    case("first-effective/absent-leaf", "P creates C at an address the state holds no account for; C's constructor writes "
         "a fresh slot and deploys code that destroys C; P then calls C, which destroys itself to a warm existing "
         "account: the first effective destruction gives back the leaf, the code and the slot, their state gas, the "
         "records of the leaf and the slot and the code's data size and history, so the transaction keeps P's nonce "
         "record alone", code=destroy + STOP, accounts=heir, gas=3_000_000)
    case("first-effective/empty-leaf-with-storage", "the same, at an address whose leaf the state holds with nonce 0, no "
         "balance, no code and two slots: the creation does not collide on storage alone, and charges and counts the "
         "address, empty under EIP-161, as a new account; the slot the constructor writes, first accessed after the "
         "creation, reads zero, so its write is a fresh slot that the destruction gives back; the slot never accessed "
         "makes no record; the leaf, present at the transaction's start, keeps its charge, its rise and its record; "
         "and the account is deleted", code=destroy + STOP, gas=3_000_000,
         accounts={**heir, created: model.Account(storage={1: 5, 2: 9})})
    case("first-effective/absent-leaf-bucket-x2", "the same as at an absent address, the created account's and the "
         "slot's buckets holding twice the minimum capacity: each part comes back at the price it was charged, the leaf, "
         "the code and the slot at m = 2", code=destroy + STOP, accounts=heir, gas=3_000_000,
         salt={(created, None): 2, (created, 1): 2})
    case("first-effective/in-constructor", "P creates C, whose constructor destroys C at once, before any code or slot: "
         "the destruction gives back the leaf's state gas and its record, and the creation deploys no code",
         code=create(0, selfdestruct_to(HEIR)) + STOP, accounts=heir, gas=3_000_000)
    case("first-effective/slot-restored-before", "P creates C, whose constructor writes two fresh slots and writes the "
         "first back to zero, then deploys code that destroys C; P calls C: the restored slot, zero at the start and "
         "zero before the destruction, is already clear and is not given back twice, and the other slot is",
         code=create(0, sstore(1, 1) + sstore(2, 1) + sstore(1, 0) + returning(selfdestruct_to(HEIR)))
         + push(int.from_bytes(HEIR, "big")) + b"\x31\x50" + call(MAX_GAS, created, 0, 0) + b"\x50" + STOP,
         accounts=heir, gas=3_000_000)

    # The marked account (SATIN-SD-011, -013, -015): C's runtime stores its calldata word in slot 1, accepts value, or
    # destroys C to a beneficiary.
    def runtime(beneficiary: bytes) -> bytes:
        """With calldata, SSTORE(1, CALLDATALOAD(0)); with value, STOP; else SELFDESTRUCT(beneficiary)."""
        destroy = selfdestruct_to(beneficiary)
        accept = 8 + len(destroy)  # CALLDATASIZE, PUSH1, JUMPI, CALLVALUE, PUSH1, JUMPI, then `destroy`
        store = accept + 2  # JUMPDEST, STOP
        return (b"\x36" + bytes([0x60, store]) + b"\x57" + b"\x34" + bytes([0x60, accept]) + b"\x57" + destroy
                + b"\x5b" + STOP + b"\x5b" + push(0) + b"\x35" + push(1) + b"\x55" + STOP)

    made = create(0, returning(runtime(HEIR)))
    again = call(MAX_GAS, created, 0, 0) + b"\x50"
    case("repeated/no-balance", "P creates C and calls it twice, and C destroys itself to an existing account each time, "
         "holding no balance: the first destruction gives back the leaf and the code and their records; the second, "
         "while the mark stands, applies the table for nothing, refilling and taking back nothing, and its regular gas "
         "is its only charge", code=made + again + again + STOP, accounts=heir, gas=3_000_000)
    made_absent = create(0, returning(runtime(ABSENT)))
    case("repeated/funded-to-new-beneficiary", "P creates C, which destroys itself to an address the state holds no "
         "account for while holding nothing, so no beneficiary is created; P then sends C 1 wei, which is no rise and "
         "makes no record for the marked C, and calls C again: the second destruction applies the table for nothing, "
         "but moves the 1 wei to the absent beneficiary, which it creates and is charged for, its record and its rise",
         contract_balance=1, gas=3_000_000,
         code=made_absent + again + call(MAX_GAS, created, 1, 0) + b"\x50" + again + STOP)
    case("marked/value-burned", "P creates C, which destroys itself holding nothing; P then sends C 1 wei and stops: the "
         "value is no rise and makes no record for C, its transfer log stays, and C is removed at the transaction's end "
         "with the 1 wei, which no account receives and no log records", contract_balance=1, gas=3_000_000,
         accounts=heir, code=made + again + call(MAX_GAS, created, 1, 0) + b"\x50" + STOP)
    store = mstore(0, 7) + call(MAX_GAS, created, 0, 32) + b"\x50"
    case("marked/fresh-slot", "P creates C, which destroys itself; P then calls C with a word of calldata, and C writes "
         "it to a slot that was never written: while the mark stands the write pays its regular gas as any fresh "
         "slot's, and charges no state gas, adds no state growth and makes no record", accounts=heir, gas=3_000_000,
         code=made + again + store + STOP)
    case("created/fresh-slot", "the control: P creates C and calls it with a word of calldata, and C writes it to a slot "
         "that was never written, C not destroyed: the write is charged a fresh slot's state gas, its legacy share "
         "first, and adds a unit of state growth and a record", accounts=heir, gas=3_000_000, code=made + store + STOP)
    little = 60_000  # pays a fresh slot's regular gas and not its state gas, in a transaction without a reservoir
    small_store = mstore(0, 7) + call(little, created, 0, 32) + b"\x50"
    case("marked/fresh-slot-on-little-gas", f"P creates C, which destroys itself; P then calls C with {fmt(little)} of "
         "regular gas and a word of calldata, which C writes to a slot that was never written: the write, charged no "
         "state gas while the mark stands, completes on what pays its regular gas", accounts=heir, gas=3_000_000,
         code=made + again + small_store + STOP)
    case("created/fresh-slot-on-little-gas", f"the control: the same call of C with {fmt(little)} of regular gas, C not "
         "destroyed: the write needs the fresh slot's state gas, which a transaction without a reservoir pays from "
         "regular gas, and C runs out of gas in it", accounts=heir, gas=3_000_000, code=made + small_store + STOP)
    case("marked/logs-stay", "P creates C with 1 wei; called without value, C's code emits a LOG0 and destroys C to an "
         "existing account, moving the 1 wei; P then sends C 1 wei more, which C accepts: the LOG0 and the three "
         "transfer logs stay counted, and the LOG0's history stays charged, while the leaf's and the code's charges and "
         "records are given back, and C is removed with the 1 wei it holds at the end",
         contract_balance=2, accounts=heir, gas=3_000_000,
         code=create(1, returning(jump_if(b"\x34", STOP, log(0, 0, 0, []) + selfdestruct_to(HEIR)))) + again
         + call(MAX_GAS, created, 1, 0)
         + b"\x50" + STOP)

    # Code deposited after its constructor destroyed its own account (SATIN-SD-014): the constructor runs, by
    # DELEGATECALL, code that destroys the account, then returns C's runtime.
    library = {LIBRARY: model.Account(nonce=1, code=selfdestruct_to(HEIR))}
    deposited = create(0, returning(selfdestruct_to(HEIR), delegatecall(MAX_GAS, LIBRARY) + b"\x50"))
    case("marked/code-deposited", "P creates C, whose constructor destroys C through a DELEGATECALL and then returns its "
         "code: the destruction gives back the leaf and its record; the code, deposited after the mark, on the "
         "absent-then-absent row, is charged no state gas, and its data size and history gas are charged as any "
         "deposited code's", accounts={**heir, **library}, gas=3_000_000, code=deposited + STOP)
    case("marked/code-deposited-destroyed-again", "the same, and P then calls C, whose code destroys it again: the "
         "repeated destruction takes nothing back, the code's data size and history gas included",
         accounts={**heir, **library}, gas=3_000_000, code=deposited + again + STOP)

    # A destruction in a frame that fails (SATIN-SD-010): P creates C, whose constructor writes a fresh slot, and calls
    # W, which calls C, which destroys itself, and then W reverts or halts.
    init = sstore(1, 1) + returning(selfdestruct_to(HEIR))
    for name, end, tail, what in (
            ("reverted", revert(0, 0), b"", "reverts"),
            ("halted", INVALID, b"", "halts"),
            ("reverted-then-kept", revert(0, 0), again, "reverts, and P then calls C itself")):
        wrapper = {WRAPPER: model.Account(nonce=1, code=call(MAX_GAS, created, 0, 0) + b"\x50" + end)}
        kept = ("the later destruction, in a frame that is kept, is the first effective one: it gives back the leaf, "
                "the code and the slot once" if tail else "C survives with its code and its slot: the leaf's, the "
                "code's and the slot's charges stand, and the records the table took back stand again")
        case(f"discarded/{name}", f"P creates C, whose constructor writes a fresh slot, and calls W, which calls C, which "
             f"destroys itself; then W {what}: the mark and every effect of the table are discarded with W, and {kept}",
             accounts={**heir, **wrapper}, gas=3_000_000,
             code=create(0, init) + call(2_000_000, WRAPPER, 0, 0) + b"\x50" + tail + STOP)

    # The give-back is reservoir of the destroying frame and returns up the chain as reservoir (SATIN-SD-010, -005):
    # after the destruction, P calls a child that halts, which burns the regular gas it was forwarded and returns
    # the reservoir share it received; the give-back, in P's reservoir, is not forwarded and not burned.
    case("first-effective/give-back-as-reservoir", "P creates C, which destroys itself, and the table's give-back "
         "returns to P as reservoir; P then calls a child, forwarding all the regular gas it may, and the child halts: "
         "it burns the regular gas it was forwarded and returns the reservoir share it received, so the give-back "
         "returns to the sender, none of it burned", gas=3_000_000,
         accounts={**heir, HALTER: model.Account(nonce=1, code=INVALID)},
         code=destroy + call(MAX_GAS, HALTER, 0, 0) + b"\x50" + STOP)

    # The volatile read of a destruction's beneficiary, the block beneficiary (SATIN-SD-020, SATIN-DET-001, -003): a
    # contract holding 10 wei destroys itself to the block beneficiary, which the state holds no account for, and its
    # caller then expands memory by more than the cap a read of the beneficiary sets. The read is marked once the
    # destruction completed, at the compute its charges reached, and the expansion is stopped; a destruction whose
    # child cannot pay the beneficiary's new-account state gas halts in its charges and marks nothing, and the same
    # expansion is paid.
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    over = burn(words_within(cap) + 1)
    to_coinbase = {PLAIN: model.Account(nonce=1, balance=10, code=selfdestruct_to(COINBASE))}
    child = 100_000
    case("beneficiary-read/marked-after-charges", "a child frame, a contract the transaction did not create holding 10 "
         "wei, destroys itself to the block beneficiary, which it creates: the read of the beneficiary is marked once the "
         "destruction completed, at the compute its regular charges reached, and the limit it sets stops its caller's "
         "later memory expansion, which costs more than the cap", accounts=to_coinbase, gas=21_000_000,
         code=call(MAX_GAS, PLAIN, 0, 0) + b"\x50" + over + STOP)
    case("beneficiary-read/halted-unmarked", f"the same destruction in a child forwarded {fmt(child)} of regular gas, "
         "which pays its regular charges and the beneficiary's legacy share and not the rest of the beneficiary's state "
         "gas: the child halts in the destruction's charges, so the read is not marked, and its caller's same memory "
         "expansion is paid", accounts=to_coinbase, gas=21_000_000,
         code=call(child, PLAIN, 0, 0) + b"\x50" + over + STOP)
    return out


# --- The limit-stop page's rules: stops below the first frame, at a start, and which endings are stops --


def hints_leaving(room: int, kept: int = 0) -> bytes:
    """Admitted hints, 1 MiB each and one smaller, forwarded 1 gas, that leave the transaction `room` bytes of data
    size below TX_DATA_LIMIT, after its body and `kept` more bytes its frames counted before them."""
    big = 1 << 20
    total = model.TX_DATA_LIMIT - model.TX_BODY_SIZE - kept - room
    count, last = divmod(total, big)
    code = big_hints(count, big)
    if last:
        code += push(0) + push(0) + push(last) + push(0) + push(0) + push(int.from_bytes(model.ORACLE, "big")) + push(1) \
            + b"\xf1\x50"
    return code


def limit_stop_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = TAKE_BACK_SPEC
    limit = fmt(model.TX_DATA_LIMIT)
    log0 = model.LOG_BASE_SIZE
    record = model.WRITE_RECORD_SIZE
    transfer_log = model.TRANSFER_LOG_SIZE

    # A child stopped by the transaction's data-size limit; its caller catches the stop and carries on, held to what
    # the transaction has left once the child's counts are discarded (SATIN-STOP-005 to -008).
    room = 100
    child_data = room - log0 + 1 - log0  # the child's second LOG0, one byte past what its first left
    child = log(0, 0, 0, []) + log(0, 0, child_data, []) + STOP
    for crosses in (False, True):
        data = room - log0 + (1 if crosses else 0)
        add(Case(f"satin/limit-stops/child-stopped/caller-log-{'crosses' if crosses else 'fits'}",
                 f"hints leave the transaction {room} bytes of data size; a child emits an empty LOG0, kept, then a LOG0 "
                 f"of {child_data} data bytes one byte past what is left, and is stopped with MegaLimitExceeded(0, "
                 f"{limit}); its caller catches the stop, the child's kept log discarded with it, and emits a LOG0 of "
                 f"{data} data bytes, " + ("one byte past the room the discard gave back: the caller is stopped in turn "
                                           "and the stop is the transaction's result" if crosses else
                                           "exactly the room the discard gave back: kept, and the transaction succeeds "
                                           "with the child's stop as its output, keeping the caller's log and nothing of "
                                           "the child"),
                 boundary=f"the caller's log {'one byte over' if crosses else 'at'} the room the child's discard left",
                 system=True, spec=spec, stops=True, gas=8_000_000,
                 code=hints_leaving(room) + call(MAX_GAS, STOPPED_CHILD, 0, 0) + b"\x50" + log(0, 0, data, [])
                 + RETURN_RETURNDATA, accounts={STOPPED_CHILD: model.Account(nonce=1, code=child)}))

    # A value call's start held to what it kept, two records and a transfer log, before its frame runs (SATIN-STOP-013).
    start = 2 * record + transfer_log
    ran = revert(0, 32)  # the target, when it runs, reverts with a word of memory, zero
    for crosses in (False, True):
        left = start - (1 if crosses else 0)
        add(Case(f"satin/limit-stops/start-crossing/value-call-{'one-byte-over' if crosses else 'at-limit'}",
                 f"hints leave the transaction {left} bytes of data size, and a contract calls another with 1 wei, whose "
                 f"start keeps two records and a transfer log, {start} bytes: " +
                 ("one byte more than is left, so the started frame is stopped before it runs an instruction, the value "
                  "and the transfer log reverted with it, and the caller returns the stop" if crosses else
                  "exactly what is left, so the frame runs, reverts with its word, and the caller returns that word"),
                 boundary=f"the start's {start} bytes {'one byte over' if crosses else 'at'} what the transaction has left",
                 system=True, spec=spec, stops=True, gas=8_000_000, contract_balance=1,
                 code=hints_leaving(left) + call(MAX_GAS, STARTED, 1, 0) + b"\x50" + RETURN_RETURNDATA,
                 accounts={STARTED: model.Account(nonce=1, code=mstore(0, 0) + ran)}))

    # A creation stopped at its start: the creator keeps its nonce bump, whose record is counted on the creator once
    # the creation returned and held to the creator's limits (SATIN-STOP-013, -015, SATIN-LIM-008).
    created = start - record  # the created account's record and the endowment's transfer log
    for crosses in (False, True):
        left = record - (1 if crosses else 0)
        add(Case(f"satin/limit-stops/creation-stopped/creator-record-{'crosses' if crosses else 'fits'}",
                 f"hints leave the transaction {left} bytes of data size, and a contract creates with 1 wei and empty init "
                 f"code: the creation's start keeps the created account's record and the endowment's transfer log, "
                 f"{created} bytes, and is stopped before its init code runs, the created account and the endowment "
                 f"reverted with it; the creator keeps its nonce bump, whose {record}-byte record is counted on the creator "
                 "once the creation returned, " + ("one byte past what is left: the creator is stopped in turn, and the "
                                                   "stop is the transaction's result" if crosses else
                                                   "exactly what is left: the creator runs on and returns the creation's "
                                                   "stop"),
                 boundary=f"the creator's nonce record {'one byte over' if crosses else 'at'} what the transaction has left",
                 system=True, spec=spec, stops=True, gas=8_000_000, contract_balance=1,
                 code=hints_leaving(left) + create(1, b"") + RETURN_RETURNDATA))

    # A hint sent into room a take-back freed, by a frame that then fails (SATIN-STOP-006): the record stands again,
    # the hint stays counted, and the frame it returns into returns the stop of the transaction's data-size limit.
    oracle = int.from_bytes(model.ORACLE, "big")
    hint = mstore(0, int.from_bytes(model.SEND_HINT, "big") << 224) + push(0) + push(0) + push(record) + push(0) \
        + push(0) + push(oracle) + push(1) + b"\xf1\x50"
    for name, tail, what in (
            ("kept", STOP, "succeeds: the take-back and the hint merge, the transaction exactly at its limit, and the "
                           "caller runs on"),
            ("reverted", revert(0, 0), "reverts"),
            ("halted", INVALID, "halts"),
            ("stopped", log(0, 0, 0, []) + STOP, f"emits an empty LOG0, {log0} bytes past the limit, and is itself stopped"),
    ):
        failed = name != "kept"
        add(Case(f"satin/limit-stops/hint-into-freed-room/{name}",
                 f"a contract writes its slot 1, whose original is 7, to 8, a record of {record} bytes, then sends hints "
                 "that take the transaction exactly to its data-size limit; a DELEGATECALL frame on its storage writes the "
                 f"slot back to 7, taking the record back, sends a hint of {record} bytes into the room that freed, and "
                 f"{what}" + ("; the failure puts the record back while the hint stays counted, over the limit, and the "
                              "caller returns the stop of the transaction's data-size limit before it runs another "
                              "instruction, the transaction's result" if failed else ""),
                 system=True, spec=spec, stops=True, gas=8_000_000, storage={1: 7},
                 code=sstore(1, 8) + hints_leaving(0, record) + delegatecall(MAX_GAS, TAKER) + b"\x50" + STOP,
                 accounts={TAKER: model.Account(nonce=1, code=sstore(1, 7) + hint + tail)}))

    # State growth: a child stopped by its frame budget, its share of what its caller has left; the caller resumes
    # with the child's slots discarded and is held to its own budget (SATIN-STOP-005 to -007, SATIN-LIM-003).
    growth = model.TX_STATE_GROWTH_LIMIT
    own = growth - 10
    budget = (growth - own) * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    grower = b"".join(sstore(k, 1) for k in range(1, growth - own + 1)) + STOP
    for crosses in (False, True):
        more = growth - own + (1 if crosses else 0)
        add(Case(f"satin/limit-stops/child-budget/caller-{'crosses' if crosses else 'fills'}-its-budget",
                 f"the transaction's own frame, whose state-growth budget is {fmt(growth)}, writes {fmt(own)} fresh slots, "
                 f"then calls a child whose budget is the share of the {growth - own} it has left, {budget}: the child's "
                 f"{budget + 1}th fresh slot crosses it, and the child is stopped with MegaLimitExceeded(3, {budget}), its "
                 f"slots discarded; the caller writes {more} more fresh slots, " +
                 (f"the last taking it past its budget {fmt(growth)}: it is stopped in turn, the transaction's result"
                  if crosses else f"exactly its budget {fmt(growth)}: kept, and it returns the child's stop"),
                 boundary=f"the caller's state growth {'one over' if crosses else 'at'} its budget after the child's discard",
                 spec=spec, stops=True, gas=150_000_000,
                 code=b"".join(sstore(k, 1) for k in range(1, own + 1)) + call(MAX_GAS, STOPPED_CHILD, 0, 0) + b"\x50"
                 + b"".join(sstore(k, 1) for k in range(own + 1, own + more + 1)) + RETURN_RETURNDATA,
                 accounts={STOPPED_CHILD: model.Account(nonce=1, code=grower)}))

    # Which endings are stops: a log one byte past the data-size limit is the stop once its regular charge is paid,
    # and an out-of-gas, a halt and no stop, one gas short of it (SATIN-STOP-002, SATIN-HIST-013).
    room, data = 100, 100 - log0 + 1
    charge = model.LOG_COST + model.LOG_DATA_COST * data
    for paid in (True, False):
        add(Case(f"satin/limit-stops/log-over-limit/regular-charge-{'paid' if paid else 'short'}",
                 f"hints leave the transaction {room} bytes of data size, and the frame holds "
                 f"{fmt(charge if paid else charge - 1)} of regular gas at a LOG0 of {data} data bytes, one byte past it, "
                 f"whose regular charge is {fmt(charge)}: " +
                 ("it pays the charge, the log's bytes cross the limit, and the frame is stopped with "
                  f"MegaLimitExceeded(0, {limit})" if paid else
                  "it cannot pay the charge and runs out of gas before the log's bytes are counted: a halt, which is no "
                  "limit stop, and the transaction reports none"),
                 boundary=f"the regular gas at the LOG0 {'at' if paid else 'one below'} its regular charge",
                 system=True, spec=spec, stops=True, gas=8_000_000, tune=("log", charge if paid else charge - 1),
                 code=hints_leaving(room) + log(0, 0, data, []) + STOP))

    # The stop applies only to a transaction that pays every charge before its first frame (SATIN-STOP-003).
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    over = words_within(cap) + 1
    crossing = b"\x42\x50" + burn(over) + STOP
    start_record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    short = (model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + model.TX_VALUE_COST
             + model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE + start_record - 1)
    add(Case("satin/limit-stops/pre-frame/start-record-unpaid", "a value call to a contract whose frame would read "
             "TIMESTAMP and cross gas detention's limit, with a gas limit one gas short of the history of its start "
             f"record, {fmt(start_record)}, the last charge before its first frame: it runs out of gas before that frame "
             "and reports no stop", boundary="the gas limit one below the charges before the first frame", spec=spec,
             stops=True, value=1, gas=short, code=crossing))
    add(Case("satin/limit-stops/pre-frame/start-record-paid", "the same value call with the gas to run its frame: the "
             "frame reads TIMESTAMP and one memory expansion crosses gas detention's limit, so it is stopped with "
             "MegaLimitExceeded(2, limit), the value and its records reverted with it", spec=spec, stops=True, value=1,
             gas=21_000_000, code=crossing))

    # A stop's bytes do not make a stop: a contract reverting with them, of every kind, and a caller re-raising the stop
    # it caught, are ordinary reverts, and the transaction reports no stop (SATIN-STOP-020, -021).
    for kind in range(4):
        data = model.limit_exceeded(kind, 10)
        add(Case(f"satin/limit-stops/revert-with-stop-bytes/kind-{kind}", f"a contract reverts with the bytes of "
                 f"MegaLimitExceeded({kind}, 10), which no limit produced: an ordinary revert, and the transaction "
                 "reports no stop", spec=spec, stops=True, code=bytes_to_memory(data) + revert(0, len(data))))
    room = 100
    add(Case("satin/limit-stops/child-stopped/caller-re-raises", f"hints leave the transaction {room} bytes of data size; "
             f"a child emits an empty LOG0 and then a LOG0 of {child_data} data bytes past what is left, and is stopped with "
             f"MegaLimitExceeded(0, {limit}); its caller reverts with the stop's bytes as its own data: the transaction "
             "reverts with them and reports no stop, its own frame having crossed nothing", system=True, spec=spec,
             stops=True, gas=8_000_000, code=hints_leaving(room) + call(MAX_GAS, STOPPED_CHILD, 0, 0) + b"\x50"
             + REVERT_RETURNDATA, accounts={STOPPED_CHILD: model.Account(nonce=1, code=child)}))
    # A stop above the execution cap returns the reservoir with the unspent regular gas (SATIN-STOP-009).
    body = model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE
    add(Case("satin/limit-stops/reservoir/compute-stop-above-cap", "a gas limit above the execution cap gives the first "
             "frame a reservoir, which pays the body's history first; the frame reads TIMESTAMP and one memory expansion "
             "crosses gas detention's limit: the frame is stopped with MegaLimitExceeded(2, limit), and the reservoir it "
             "kept returns to the sender with its unspent regular gas", spec=spec, stops=True,
             gas=model.EXECUTION_CAP + body + 1_000_000, code=b"\x42\x50" + burn(words_within(model.BLOCK_ENV_ACCESS_COMPUTE_GAS) + 1)
             + STOP))
    # Budgets three calls deep: the first frame's 1,000, then 98% of each caller's remaining (SATIN-LIM-003).
    deep = growth
    for _ in range(3):
        deep = deep * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    relay = lambda to: call(MAX_GAS, to, 0, 0) + b"\x50" + RETURN_RETURNDATA
    add(Case("satin/limit-stops/child-budget/depth-three", f"the first frame relays to a frame three calls below it, "
             f"each relay writing nothing: that frame's state-growth budget is {fmt(deep)}, the share of the share of the "
             f"share of {fmt(growth)}, and its {fmt(deep + 1)}th fresh slot crosses it: it is stopped with "
             f"MegaLimitExceeded(3, {fmt(deep)}), its slots discarded, and every relay returns the stop's bytes, the "
             "transaction succeeding with them", spec=spec, stops=True, gas=150_000_000, code=relay(RELAY_B),
             accounts={RELAY_B: model.Account(nonce=1, code=relay(RELAY_C)), RELAY_C: model.Account(nonce=1, code=relay(DEEP)),
                       DEEP: model.Account(nonce=1, code=b"".join(sstore(k, 1) for k in range(1, deep + 2)) + STOP)}))

    # State growth can cross before the first frame only on an authorization list, which is then skipped and the own
    # frame stopped before it runs, naming the transaction limit (SATIN-STOP-017, SATIN-AUTH-010): one absent authority
    # more than the state-growth limit.
    entries = [(LIST_KEY + i, CHAIN_ID, DELEGATE, 0) for i in range(growth + 1)]
    add(Case("satin/limit-stops/authorization-list/one-authority-over", f"an EIP-7702 list of {fmt(growth + 1)} entries, each "
             "signed by an authority the state holds no account for: its state-growth total, one unit for each new "
             f"authority, crosses the transaction's limit of {fmt(growth)}, so the list is skipped, none of it applied or "
             "charged beyond the intrinsic gas and the body's history, and the transaction's own frame is stopped before "
             f"it runs with MegaLimitExceeded(3, {fmt(growth)})", spec=spec, stops=True, ty=4, to=EOA, code=b"",
             gas=20_000_000, authorizations=entries))

    # A deposit whose own frame is stopped settles as a revert, not a failed deposit (SATIN-STOP-010); the same
    # deposit one gas short of the crossing charge runs out of gas and is a failed deposit.
    cost = model.memory_cost(over)
    for stopped in (True, False):
        add(Case(f"satin/limit-stops/deposit/{'stopped' if stopped else 'out-of-gas'}",
                 "a deposit from a sender empty under EIP-161, whose caller account it creates, reads TIMESTAMP and "
                 f"holds {'exactly' if stopped else 'one gas less than'} the {fmt(cost)} of one memory expansion past "
                 "what gas detention's limit leaves it: " +
                 ("the expansion is the crossing, the frame is stopped with MegaLimitExceeded(2, limit), and the deposit "
                  "settles as a revert, keeping its mint, its nonce bump and its created caller" if stopped else
                  "the expansion is beyond its whole regular gas, an out-of-gas, so its frame halts and it is a failed "
                  "deposit"),
                 boundary=f"the regular gas at the expansion {'at' if stopped else 'one below'} its charge",
                 spec=spec, stops=True, deposit=(ETH, 21_000_000), absent_sender=True, code=crossing,
                 tune=("expand", cost if stopped else cost - 1)))
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
    env = model.Env(CHAIN_ID, c.coinbase, c.base_fee, BLOCK_GAS_LIMIT, buckets, timestamp=BLOCK_TIMESTAMP,
                    number=BLOCK_NUMBER, block_hashes=dict(c.block_hashes))

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
    run = model.Run(env, pre, tx, salt_bucket, principles=c.spec in PRINCIPLES_SPECS, reads=c.reads, pools=c.pools,
                    destruction=c.destruction, detention=c.detention, stops=c.stops)
    result = run.run()
    result.probe = run.probe

    inp = {
        "chain": {"chainId": q(CHAIN_ID)},
        "block": {
            "number": q(BLOCK_NUMBER), "timestamp": q(BLOCK_TIMESTAMP), "coinbase": h(c.coinbase), "gasLimit": q(BLOCK_GAS_LIMIT),
            "baseFee": q(c.base_fee), "prevRandao": ZERO32, "parentHash": "0x" + (0xA11CE).to_bytes(32, "big").hex(),
            "parentTimestamp": q(0x6553F101), "parentBeaconBlockRoot": ZERO32, "extraData": "0x", "slotNumber": "0x0",
            "blobBaseFee": "0x1", "depositOnly": False, "activation": False,
        },
        "blockHashes": {q(n): h(v) for n, v in sorted(c.block_hashes.items())},
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


# The detention cases the revm-based implementation fails, for two more decided rules it has not made yet: a
# refused volatile read charges nothing (SATIN-MAC-004), and the Oracle's SLOAD reads and marks before its one
# charge (SATIN-ORCL-004). The first difference of each is the regular ledger the block counts. A refusal's figure
# is derived, the rule's plus the static cost that implementation charges first, or plus the gas the frame held and
# burns when it cannot pay it. An Oracle read's figure is that implementation's run, recorded: it follows from what
# it does once the read is skipped or the crossing comes early, which the model does not restate (D-60).
REFUSALS = {"satin/access-control/refused-read": "static", "satin/access-control/refused-read-under-static-gas": "held"}
ORACLE_RUNS = {  # case -> the regular ledger the revm-based implementation reports
    "satin/oracle/read-short-of-warm-base": 0x13180AC,
    "satin/oracle/read-short-of-cold-access": 0x1318462,
    "satin/oracle/read-at-crossing": 0x1316789,
}


# The reads cases the revm-based implementation fails. It reads the SequencerRegistry's account and slot 0 in
# every transaction's validation, to classify it, where SATIN-REG-002 has the block resolve the live system
# address once and no transaction read the registry: the registry's account is the first difference of each
# non-deposit case, derived from the case's pre-state (D-61). Where the case's own edge differs too, the verdict
# says so. The deposit's first difference is its history, which that implementation does not charge.
READS_QUARANTINE = {
    "satin/reads/list-simulated-out-of-gas": "; it also skips the simulation of a list too short to cross a limit "
        "(SATIN-AUTH-005, SATIN-WIT-004), so the list that runs out of gas at its first entry leaves the second "
        "authority unloaded and out of its reads",
    "satin/reads/list-simulated-applied": "",
    "satin/reads/delegate-not-loaded": "",
    "satin/reads/delegate-loaded": "",
    "satin/reads/balance-cold-unpaid": "",
    "satin/reads/balance-cold-paid": "",
    "satin/reads/oracle-slot-before-charge": None,
}


# The gas-pools cases the revm-based implementation fails: it credits a give-back to the frame's regular gas,
# and draws a fresh slot's state gas from the reservoir first with no legacy share. The first difference is the
# first frame's final regular gas, the rule's plus what that implementation credits or did not charge to it: the
# give-back the reservoir ends with, or the legacy share (D-64).
POOLS_QUARANTINE = {
    "satin/gas-pools/answered-call-history-returns": "the history of the two records the opcode charged for the start "
        "that MegaAccessControl's answer replaced",
    "satin/gas-pools/fresh-slot-restored": "the fresh slot's state gas and its record's history, given back when the "
        "slot returns to zero",
    "satin/gas-pools/legacy-share-from-regular": None,
}


# The take-back examples the revm-based implementation fails: what it credits to regular gas, or None where a frame
# halts and its spill leaves that implementation's counter.
TAKE_BACKS_QUARANTINE = {
    "satin/take-backs/descendant/kept": "the record's history C's write back to 7 gives back",
    "satin/take-backs/descendant/descendant-reverted": "the LOG0's history C's rollback returns, net of the record it took "
        "back",
    "satin/take-backs/descendant/both-reverted": "what C's rollback returns and P's own record, which P's rollback returns",
    "satin/take-backs/descendant/writer-halted": None,
    "satin/take-backs/sent-back/round-trip": "the history of the two records Q's start took back",
    "satin/take-backs/sent-back/nonce-bumped": "the history of Q's record, which Q's start took back",
    "satin/take-backs/sent-back/signs-turned-paid": "the history of the two records P's start took back",
    "satin/take-backs/destroyed-creation/no-balance": "the state and history gas the destruction table gives back",
    "satin/take-backs/destroyed-creation/new-beneficiary": "what is left of the destruction table's give-back once the "
        "beneficiary's record is paid",
    "satin/take-backs/log-reverted/reverted": "the LOG2's history, which the child's rollback returns",
    "satin/take-backs/log-reverted/allowance": "the history of the two records the failed start made",
    "satin/take-backs/answer-stopped": "the stopped start's two charges given back to P",
    "satin/take-backs/failed-child/reverted": "the fresh slot's legacy share, which the child's regular gas paid and its "
        "rollback returns",
    "satin/take-backs/failed-child/halted": None,
}
# The failed-deposit example: the history bytes it keeps, which the revm-based implementation does not report.
TAKE_BACKS_DEPOSITS = {"satin/take-backs/failed-deposit"}
# The destruction cases the revm-based implementation fails: it credits the table's give-back to the regular gas of
# the frames that paid the charges, where SATIN-SD-005 and SATIN-SD-010 make it reservoir of the destroying frame,
# which returns up the chain as reservoir. The difference shows without the pools when the caller then forwards all
# it may to a child that halts: that implementation forwards the give-back too, and the child burns it (D-70). Each
# records the child whose CALL forwards it.
SELFDESTRUCT_QUARANTINE = {"satin/selfdestruct/first-effective/give-back-as-reservoir": HALTER}


def forward_cap(remaining: int) -> int:
    """What a CALL forwards of `remaining` regular gas at most (SATIN-FWD-001)."""
    return remaining - remaining * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR


# The cases of gas detention's rules the revm-based implementation fails (D-68): a user's deposit, which it charges no
# history gas (SATIN-HIST-016), and a ModExp input over EIP-7823's bound priced between the allowance and the
# forward, which it runs instead of answering with the crossing (SATIN-DET-023, -024). The first difference of each is
# derived: the deposit's gas used short by its body's history; the regular ledger above the rule's by the forward the
# failed call consumes, less the copy of the stop's return data the rule's caller makes.
DETENTION_QUARANTINE = {"satin/detention/deposit/user-deposit": "deposit",
                        "satin/detention/precompile/modexp/over-bound-past-allowance": "modexp"}


def detention_quarantine(c: Case, fx: dict) -> dict:
    adapter, ledgers = "mega-eest-adapter-revm", fx["expected"]["gasLedgers"]
    if DETENTION_QUARANTINE[c.case_id] == "deposit":
        used, history = int(ledgers["gasUsed"], 16), int(ledgers["history"], 16)
        body, price = model.TX_BODY_SIZE, model.COST_PER_HISTORY_BYTE
        if history != body * price:
            raise SystemExit(f"{c.case_id}: the deposit keeps more history than its body")
        verdict = ("SATIN-DET-026 and SATIN-MST-010 detain a user's deposit as any transaction, which the revm-based "
                   f"implementation at {REVM_PIN} does: its callee is stopped at the crossing as the rule has it; but "
                   "SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas for its body, and that implementation "
                   f"charges a deposit none, so its gas used is the body's {body} x {price} = {fmt(history)} below the rule's")
        return {"adapter": adapter, "path": "/expected/gasLedgers/gasUsed", "expected": q(used),
                "actual": q(used - history), "verdict": verdict}
    block = int(ledgers["blockGas"], 16)
    if int(ledgers["regular"], 16) != block:
        raise SystemExit(f"{c.case_id}: the block's figure is not the regular ledger")
    remaining = c.probe["forward"]
    forward = remaining - remaining * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR
    stop_words = (len(model.limit_exceeded(model.DETENTION_STOP, 0)) + 31) // 32
    copy = model.COPY_WORD * stop_words
    verdict = ("SATIN-DET-023 prices a ModExp input by its Osaka formula whatever its lengths, an input over EIP-7823's "
               "bound included, since SATIN-PCMP-007 charges that price before the bound check, and SATIN-DET-024 makes "
               "an input priced past the allowance and within the forward that would fail a check after its gas charge "
               f"the crossing, which moves nothing and returns the forward; the revm-based implementation at {REVM_PIN} "
               f"runs the call instead, which fails the bound and consumes its forward of {fmt(forward)}, and its caller "
               "copies empty return data where the rule's copies the stop's "
               f"{stop_words} words at {model.COPY_WORD} each: its regular ledger, which the block counts, is "
               f"{fmt(forward)} - {copy} = {fmt(forward - copy)} above the rule's")
    return {"adapter": adapter, "path": "/expected/gasLedgers/blockGas", "expected": q(block),
            "actual": q(block + forward - copy), "verdict": verdict}


# The limit-stop deposits the revm-based implementation fails: it charges a deposit no history gas (SATIN-HIST-016), so
# a stopped deposit's gas used is below the rule's by its body's history, and the deposit one gas short of the crossing
# charge holds that history more regular gas, which pays the charge: it stops where the rule runs out of gas (D-74).
STOP_DEPOSITS = {"satin/limit-stops/deposit/stopped", "satin/limit-stops/deposit/out-of-gas"}


def storage_path(address: bytes, slot: int) -> str:
    return f"/expected/state/accounts/{h(address)}/storage/0x{slot:064x}"


def edge_quarantine(c: Case, fx: dict) -> dict | None:
    """The quarantine record of an edge case the revm-based implementation fails, or None."""
    adapter = "mega-eest-adapter-revm"
    if c.case_id in DETENTION_QUARANTINE:
        return detention_quarantine(c, fx)
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
    if c.case_id in SELFDESTRUCT_QUARANTINE:
        child = SELFDESTRUCT_QUARANTINE[c.case_id].hex()
        regular, given = c.probe["forward:" + child], c.probe["reservoir:" + child]
        more = forward_cap(regular + given) - forward_cap(regular)
        block = int(fx["expected"]["gasLedgers"]["blockGas"], 16)
        verdict = ("SATIN-SD-005 and SATIN-SD-010 make the destruction table's give-back reservoir of the destroying "
                   "frame, which returns up the chain as reservoir (SATIN-POOL-012), and SATIN-HIST-012 never credits it "
                   f"to regular gas; the revm-based implementation at {REVM_PIN} credits the give-back, {fmt(given)}, to "
                   "the regular gas of the frames that paid the charges, so the caller's next CALL forwards "
                   f"{fmt(more)} more regular gas to a child that halts and burns it, where SATIN-POOL-014 returns a "
                   "halted child's reservoir share: the regular ledger, which the block counts, is that much above the "
                   "rule's")
        return {"adapter": adapter, "path": "/expected/gasLedgers/blockGas", "expected": q(block),
                "actual": q(block + more), "verdict": verdict}
    if c.case_id in STOP_DEPOSITS:
        ledgers = fx["expected"]["gasLedgers"]
        price, body = model.COST_PER_HISTORY_BYTE, model.TX_BODY_SIZE
        history = body * price
        if c.case_id.endswith("/stopped"):
            used = int(ledgers["gasUsed"], 16)
            verdict = ("SATIN-STOP-010 settles a deposit whose own frame is stopped as the revert of SATIN-STOP-009, which "
                       "keeps the body's history, and SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas as any "
                       f"transaction does; the revm-based implementation at {REVM_PIN} settles the stop as a revert but "
                       f"charges the deposit no history gas, so its gas used is {fmt(history)} below the rule's: the body's "
                       f"{body} bytes at {price} gas")
            return {"adapter": adapter, "path": "/expected/gasLedgers/gasUsed", "expected": q(used),
                    "actual": q(used - history), "verdict": verdict}
        block = int(ledgers["blockGas"], 16)
        ran = (model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + 2 * model.G_BASE + 2 * model.G_VERYLOW)
        verdict = ("SATIN-DET-020 makes a regular charge beyond the frame's whole regular gas an out-of-gas, as without the "
                   "read, and SATIN-DEP-004 and SATIN-STOP-010 make a deposit whose own frame halts a failed deposit, which "
                   "reports its whole gas limit as regular gas (SATIN-DEP-005); the revm-based implementation at "
                   f"{REVM_PIN} charges a deposit no history gas (SATIN-HIST-016), so the frame holds the body's "
                   f"{fmt(history)} more regular gas, which pays the expansion: it stops the frame at the crossing "
                   "(SATIN-DET-018) and settles the deposit as a revert, its regular ledger, which the block counts, the "
                   f"intrinsic gas and the {2 * model.G_BASE + 2 * model.G_VERYLOW} of compute that ran, {fmt(ran)}")
        return {"adapter": adapter, "path": "/expected/gasLedgers/blockGas", "expected": q(block), "actual": q(ran),
                "verdict": verdict}
    if c.case_id in TAKE_BACKS_DEPOSITS:
        kept = int(fx["expected"]["gasLedgers"]["historyBytes"], 16)
        verdict = ("SATIN-HIST-022 makes a deposit report the history bytes it keeps, and SATIN-DEP-006 and SATIN-TAKE-012 "
                   f"have a failed deposit keep its body and calldata, {kept} bytes, which it reports as its history "
                   "bytes though it pays no history gas; the revm-based implementation at "
                   f"{REVM_PIN} charges a deposit no history gas and reports a failed deposit's history bytes as 0")
        return {"adapter": adapter, "path": "/expected/gasLedgers/historyBytes", "expected": q(kept), "actual": q(0),
                "verdict": verdict}
    if c.case_id in TAKE_BACKS_QUARANTINE:
        pools = fx["expected"]["gasPools"]
        what = TAKE_BACKS_QUARANTINE[c.case_id]
        if what is None:
            spilled = int(pools["spilled"], 16)
            dropped = c.probe["halted-drawn"]
            verdict = ("SATIN-POOL-014 consumes a halting frame's regular gas with the part of its state and history "
                       "charges regular gas paid, and SATIN-HIST-012 never credits that part back, so it stays in what "
                       f"regular gas paid for state and history, {fmt(spilled)}; the revm-based implementation at {REVM_PIN} "
                       "counts in its spill only what a later refill may still credit to regular gas, its departure from "
                       f"SATIN-HIST-012, and drops the halted frames' {fmt(dropped)}, so it reports {fmt(spilled - dropped)}")
            return {"adapter": adapter, "path": "/expected/gasPools/spilled", "expected": q(spilled),
                    "actual": q(spilled - dropped), "verdict": verdict}
        regular_end = int(pools["regular"]["final"], 16)
        more = int(pools["reservoir"]["final"], 16) - int(pools["reservoir"]["initial"], 16)
        legacy = ("; SATIN-STATE-012 draws the legacy share from regular gas, which the revm-based implementation does "
                  "not, and its revert returns the frame's spill to regular gas" if "legacy" in what else "")
        verdict = ("SATIN-HIST-012 makes every give-back of state or history gas, a failed frame's rollback "
                   "(SATIN-POOL-014) and the destruction table's (SATIN-SD-005) among them, credit the reservoir of the "
                   "frame that receives it, never its regular gas, whichever pool paid the charge; the revm-based "
                   f"implementation at {REVM_PIN} credits {what}, {fmt(more)}, to regular gas{legacy}, so the first frame "
                   f"ends with {fmt(more)} more regular gas and as much less reservoir than the rule's")
        return {"adapter": adapter, "path": "/expected/gasPools/regular/final", "expected": q(regular_end),
                "actual": q(regular_end + more), "verdict": verdict}
    if c.case_id in POOLS_QUARANTINE:
        pools = fx["expected"]["gasPools"]
        regular_end = int(pools["regular"]["final"], 16)
        what = POOLS_QUARANTINE[c.case_id]
        if what is None:
            more = model.LEGACY_SSTORE_SHARE
            verdict = ("SATIN-STATE-012 and SATIN-POOL-008 make a fresh slot's legacy share a charge on regular gas before "
                       f"the reservoir pays any of the slot's state gas; the revm-based implementation at {REVM_PIN} draws "
                       f"the whole state charge from the reservoir first, with no legacy share, so the first frame ends with "
                       f"{fmt(more)} more regular gas and as much less reservoir than the rule's, and regular gas paid "
                       f"{fmt(more)} less of the frame's state charges")
        else:
            more = int(pools["reservoir"]["final"], 16) - int(pools["reservoir"]["initial"], 16)
            verdict = ("SATIN-HIST-012 makes every give-back of state or history gas credit the reservoir of the frame that "
                       "receives it, never its regular gas, whichever pool paid the charge; the revm-based implementation "
                       f"at {REVM_PIN} credits {what}, {fmt(more)}, to the first frame's regular gas, so the frame ends "
                       f"with {fmt(more)} more regular gas and as much less reservoir than the rule's")
        return {"adapter": adapter, "path": "/expected/gasPools/regular/final", "expected": q(regular_end),
                "actual": q(regular_end + more), "verdict": verdict}
    if c.case_id in READS_QUARANTINE:
        registry = fx["input"]["pre"]["accounts"][h(REGISTRY)]
        read = {"balance": registry["balance"], "codeHash": h(ex.keccak256(bytes.fromhex(registry["code"][2:]))),
                "nonce": registry["nonce"]}
        reg = ("SATIN-REG-002 has the block resolve the live system address once, before its transactions, and no "
               "transaction read the registry for its classification, so a transaction's reads hold neither the "
               f"registry's account nor its slot 0; the revm-based implementation at {REVM_PIN} reads both in every "
               "transaction's validation")
        extra = READS_QUARANTINE[c.case_id]
        if extra is None:
            ledgers = fx["expected"]["gasLedgers"]
            used, history = int(ledgers["gasUsed"], 16), int(ledgers["history"], 16)
            verdict = ("SATIN-HIST-016 and SATIN-DEP-001 make a deposit pay history gas, and the revm-based implementation "
                       f"at {REVM_PIN} charges it none, so its gas used is {fmt(history)} below the rule's, the first "
                       f"difference; its reads differ too: {reg}, and it skips the Oracle read it cannot pay the cold "
                       "access of (SATIN-ORCL-004), so its reads lack the Oracle's slot")
            return {"adapter": adapter, "path": "/expected/gasLedgers/gasUsed", "expected": q(used),
                    "actual": q(used - history), "verdict": verdict}
        verdict = f"{reg}, so its reads hold the registry's account, the first difference{extra}"
        return {"adapter": adapter, "path": f"/expected/reads/accounts/{h(REGISTRY)}", "expected": None, "actual": read,
                "verdict": verdict}
    if c.case_id in REFUSALS or c.case_id in ORACLE_RUNS:
        block = int(fx["expected"]["gasLedgers"]["blockGas"], 16)
        if int(fx["expected"]["gasLedgers"]["regular"], 16) != block:
            raise SystemExit(f"{c.case_id}: the block's figure is not the regular ledger")
        path = "/expected/gasLedgers/blockGas"
    if c.case_id in REFUSALS:
        static = model.WARM_READ
        if REFUSALS[c.case_id] == "static":
            more = static
            how = (f"charges BALANCE's static cost, {static}, before it refuses the read at the load, so the frame reverts "
                   f"on {static} less")
        else:
            more = c.probe["refused"]
            how = (f"charges BALANCE's static cost, {static}, first, which the {more} of regular gas the frame holds cannot "
                   "pay: the frame runs out of gas instead of being refused, and burns them")
        verdict = ("SATIN-MAC-003 and SATIN-MAC-004 refuse a volatile read in a frame whose access is off before the opcode "
                   "charges anything, the frame reverting on the gas it held at the opcode; the revm-based implementation "
                   f"at {REVM_PIN} {how}: the regular ledger, which the block counts, is {fmt(more)} above the rule's")
        return {"adapter": adapter, "path": path, "expected": q(block), "actual": q(block + more), "verdict": verdict}
    if c.case_id in ORACLE_RUNS:
        actual = ORACLE_RUNS[c.case_id]
        if c.case_id.endswith("at-crossing"):
            how = (f"charges the read's warm base, {model.WARM_READ}, first, which the spendable part cannot pay and the "
                   "whole regular gas can: the crossing, which stops the Oracle's frame and returns its regular gas to its "
                   f"caller, where the rule's one charge of {fmt(model.COLD_SLOAD)}, beyond the whole, is an out-of-gas "
                   "(SATIN-DET-018, SATIN-DET-020) that burns it")
        else:
            how = (f"charges the read's warm base, {model.WARM_READ}, first and skips the read when the cold access "
                   "cannot be paid, marking nothing, so the later call's charge past the Oracle's cap is paid instead of "
                   "stopped (SATIN-DET-003, SATIN-DET-012)")
        verdict = ("SATIN-ORCL-004 makes the Oracle's SLOAD load the slot and mark the read before its cold access, which "
                   f"is then one charge; the revm-based implementation at {REVM_PIN} {how}. Its regular ledger, which the "
                   f"block counts, is {fmt(abs(actual - block))} {'above' if actual > block else 'below'} the rule's; the "
                   "deposit's history, which it does not charge either (SATIN-HIST-016), is not in that figure")
        return {"adapter": adapter, "path": path, "expected": q(block), "actual": q(actual), "verdict": verdict}
    return None

GROUP_PATHS = {"outcome": "/expected/outcome", "state": "/expected/state", "receipt": "/expected/receipt",
               "gasLedgers": "/expected/gasLedgers", "resources": "/expected/resources", "reads": "/expected/reads",
               "limit": "/expected/limit", "gasPools": "/expected/gasPools"}


def settle_burn(params: dict) -> None:
    """Moves what a JUMPDEST pad holds into the burn's memory words while a whole word's cost fits in it."""
    while "words" in params and params["pad"] >= model.memory_cost(params["words"] + 1) - model.memory_cost(params["words"]):
        params["pad"] -= model.memory_cost(params["words"] + 1) - model.memory_cost(params["words"])
        params["words"] += 1


def remade(c: Case) -> None:
    """Sets a case's code parameters from its probes (Case.retune)."""
    _, result, _ = build(c)
    for point, want, param, slope in c.retune:
        moved, rest = divmod(want - result.probe[point], slope)
        if rest:
            raise SystemExit(f"{c.case_id}: {point} moves by {slope} per {param}")
        c.params[param] += moved
    if any(v < 0 for v in c.params.values()):
        raise SystemExit(f"{c.case_id}: the parameters {c.params} are not reachable")
    settle_burn(c.params)
    c.code = c.make(**c.params)
    _, result, _ = build(c)
    for point, want, _, _ in c.retune:
        if result.probe.get(point) != want:
            raise SystemExit(f"{c.case_id}: the code parameters {c.params} give {point} {result.probe.get(point)}, not {want}")
    c.retune = []


def tuned(c: Case) -> None:
    """Sets a tuned case's gas limit so its probe point holds the regular gas it names: below the execution
    cap every charge before that point is fixed, so the probe moves with the gas limit one for one."""
    point, want = c.tune
    if (c.deposit[1] if c.deposit else c.gas) > model.EXECUTION_CAP:
        raise SystemExit(f"{c.case_id}: a tuned gas limit must be below the execution cap")
    _, result, _ = build(c)
    if c.deposit:  # a deposit's gas limit is its envelope's
        c.deposit = (c.deposit[0], c.deposit[1] + want - result.probe[point])
    else:
        c.gas += want - result.probe[point]
    _, result, _ = build(c)
    if result.probe.get(point) != want:
        raise SystemExit(f"{c.case_id}: the gas limit {c.gas} gives {point} {result.probe.get(point)}, not {want}")
    c.tune = None


# --- What a case pins (D-76) --------------------------------------------------------------------
#
# A case pins the rules its derivation applied that are in its area's scope or that its definition names.
# The area is the second segment of the case id. Its scope names whole pages of the specification, by rule
# family, where the area tests that page, and single rules of the pages every transaction passes through
# (the gas schedule, history gas, the gas model, resource accounting, resource limits, outcomes), whose other
# rules every derivation applies and no case of the area tests. The definition names a rule by its full id
# in the case's intent or boundary, or, for a quarantined case, in its known failure's verdict. A rule the
# derivation did not apply is never pinned, and a case pins at least one rule.
AREA_SCOPE = {
    "intrinsic": ("SATIN-SCHED-005", "SATIN-SCHED-006", "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004",
                  "SATIN-POOL-020", "SATIN-LOG-003"),
    "value-transfer": ("SATIN-LOG", "SATIN-STATE", "SATIN-HIST-005", "SATIN-SCHED-008", "SATIN-POOL-024",
                       "SATIN-ACCT-005", "SATIN-ACCT-014", "SATIN-ACCT-015"),
    "sstore": ("SATIN-STATE", "SATIN-SCHED-003", "SATIN-SCHED-004", "SATIN-POOL-008", "SATIN-POOL-019",
               "SATIN-ACCT-004", "SATIN-ACCT-006", "SATIN-ACCT-016", "SATIN-HIST-006", "SATIN-HIST-012"),
    "logs": ("SATIN-LOG", "SATIN-HIST-002", "SATIN-HIST-006", "SATIN-ACCT-001"),
    "outcomes": ("SATIN-OUT", "SATIN-POOL-014", "SATIN-POOL-017", "SATIN-HIST-012"),
    "creation": ("SATIN-STATE", "SATIN-SCHED-011", "SATIN-HIST-005", "SATIN-POOL-024", "SATIN-ACCT-005",
                 "SATIN-ACCT-013", "SATIN-ACCT-014"),
    "validation": ("SATIN-VAL", "SATIN-BLK"),
    "interception": ("SATIN-ICPT", "SATIN-ORCL", "SATIN-KEY", "SATIN-OUT-010", "SATIN-LIM-015"),
    "keyless": ("SATIN-KEY", "SATIN-ICPT"),
    "authorizations": ("SATIN-AUTH", "SATIN-STATE-011", "SATIN-ACCT-015", "SATIN-SCHED-007"),
    "call-order": ("SATIN-HIST-009", "SATIN-HIST-015", "SATIN-HIST-023", "SATIN-ICPT-007", "SATIN-POOL-009",
                   "SATIN-POOL-012"),
    "delegated-recipient": ("SATIN-SCHED-006", "SATIN-SCHED-008", "SATIN-SCHED-009", "SATIN-SCHED-010"),
    "pre-frame": ("SATIN-HIST-005", "SATIN-POOL-024", "SATIN-ICPT-007"),
    "detention": ("SATIN-DET",),
    "limit-stops": ("SATIN-STOP", "SATIN-LIM"),
    "gas-pools": ("SATIN-POOL",),
    "take-backs": ("SATIN-TAKE", "SATIN-AUTH-009", "SATIN-HIST-009"),
    "selfdestruct": ("SATIN-SD", "SATIN-STATE"),
    "deposits": ("SATIN-DEP", "SATIN-HIST-016", "SATIN-ACCT-003", "SATIN-LOG-004"),
    "oracle": ("SATIN-ORCL",),
    "access-control": ("SATIN-MAC",),
    "reads": ("SATIN-WIT",),
}
RULE_ID = re.compile(r"SATIN-[A-Z]+-[0-9]{3}")


def area_of(case_id: str) -> str:
    return case_id.split("/")[1]


def in_scope(rule: str, area: str) -> bool:
    family = rule.rsplit("-", 1)[0]
    return any(entry in (rule, family) for entry in AREA_SCOPE[area])


def pinned(c: Case, applied: list[str], quarantine: dict | None) -> list[str]:
    """The rules a case pins: those its derivation applied that its area's scope holds or its definition names."""
    if area_of(c.case_id) not in AREA_SCOPE:
        raise SystemExit(f"{c.case_id}: the area {area_of(c.case_id)} has no scope in AREA_SCOPE")
    named = set(RULE_ID.findall(" ".join([c.intent, c.boundary, (quarantine or {}).get("verdict", "")])))
    pins = [r for r in applied if in_scope(r, area_of(c.case_id)) or r in named]
    if not pins:
        raise SystemExit(f"{c.case_id}: pins no rule: none of {applied} is in its area's scope or named by its definition")
    return pins


# --- The case files -----------------------------------------------------------------------------

EVIDENCE = ("derived from the specification by tools/satin_model/, an executable restatement of the cited rules that "
            "shares no code with either implementation; implementation runs are cross-checks only")


def fixture(c: Case, descriptor_digest: str, rule_texts: dict, spec_commit: str) -> tuple[dict, dict]:
    """The case's fixture, without its rules (`derive` adds the pins), and its explanation: the derivation of every
    observation group, the rules it applied with their text digests, and the decoded transaction."""
    if c.retune:
        remade(c)
    if c.tune:
        tuned(c)
    inp, result, decoded = build(c)
    c.probe = result.probe
    for key, want in c.check.items():
        got = int(result.observations["gasLedgers"][key], 16)
        if got != want:
            raise SystemExit(f"{c.case_id}: the derivation gives {key} {got}, the worked example {want}")
    d = result.derivation
    derivation = []
    for group, path in sorted(GROUP_PATHS.items(), key=lambda x: x[1]):
        rules = d.rules(group)
        if rules:
            derivation.append({"path": path, "rules": rules, "steps": d.texts(group)})
    applied = sorted({r for step in derivation for r in step["rules"]})
    unknown = [r for r in applied if r not in rule_texts]
    if unknown:
        raise SystemExit(f"{c.case_id}: cites rules the registry does not have: {unknown}")
    requires = ["group:gas-ledgers", "group:limit", "group:outcome", "group:receipts", "group:resources", "group:state",
                "feature:salt"] + (["feature:deposit"] if c.deposit else []) + (["group:reads"] if c.reads else []) \
        + (["group:limit-stop"] if result.observations["limit"] else []) + (["group:gas-pools"] if c.pools else [])
    authoring = {"intent": c.intent, **({"boundary": c.boundary} if c.boundary else {})}
    fx = {
        "format": "mega-execution-fixture",
        "schemaVersion": "2.0",
        "caseId": c.case_id,
        "specRef": {"name": "megaeth/Satin", "descriptor": descriptor_digest},
        "profile": "state-transition",
        "requires": sorted(requires),
        "input": inp,
        "expected": result.observations,
        "provenance": {
            "status": "candidate",
            "generator": "tools/make_slice.py",
            "definition": f"tools/make_slice.py::{c.definition}",
            "specCommit": spec_commit,
            "authoring": authoring,
        },
    }
    explanation = {
        "caseId": c.case_id,
        "definition": f"tools/make_slice.py::{c.definition}",
        "authoring": authoring,
        "spec": {"commit": spec_commit, "descriptor": descriptor_digest},
        "evidence": EVIDENCE,
        "transaction": decoded,
        "applied": applied,
        "ruleTexts": {r: rule_texts[r] for r in applied},
        "derivation": derivation,
    }
    return fx, explanation


def derive(c: Case, specs: dict) -> tuple[str, dict, dict | None, dict]:
    """One case: its file under slice/, its fixture, its quarantine record (None when it gates) and its explanation."""
    fx, explanation = fixture(c, *specs[c.spec], SPEC_COMMITS[c.spec])
    q_entry = QUARANTINE.get(c.case_id)
    if q_entry:
        q_entry = {**q_entry, "verdict": deposit_history_verdict(fx["expected"]["gasLedgers"],
                                                                 QUARANTINE_RECORDS.get(c.case_id, ""))}
    else:
        q_entry = edge_quarantine(c, fx)
    fx["rules"] = pinned(c, explanation["applied"], q_entry)
    if q_entry:
        fx["provenance"]["quarantine"] = q_entry
    rel = f"{'quarantine' if q_entry else 'cases'}/{c.case_id}.json"
    explanation = {"caseId": c.case_id, "file": rel, "fileDigest": "sha256:" + hashlib.sha256(canonical(fx)).hexdigest(),
                   "pins": fx["rules"], "scope": list(AREA_SCOPE[area_of(c.case_id)]),
                   **{k: v for k, v in explanation.items() if k != "caseId"}}
    return rel, fx, q_entry, explanation


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


def outputs(explained: dict | None = None) -> dict[str, str]:
    """Every file of slice/, by its path there. `explained`, when given, receives each case's explanation."""
    specs = {name: spec_of(name) for name in SPEC_COMMITS}
    descriptor_digest, _ = specs[DEFAULT_SPEC]
    files: dict[str, str] = {}
    index = []
    by_id = {}
    quarantine = []
    for c in cases():
        rel, fx, q_entry, explanation = derive(c, specs)
        if explained is not None:
            explained[c.case_id] = explanation
        files[rel] = pretty(fx)
        by_id[c.case_id] = fx
        entry = {"caseId": c.case_id, "file": rel, "area": area_of(c.case_id), "rules": fx["rules"],
                 "fileDigest": explanation["fileDigest"]}
        if c.spec != DEFAULT_SPEC:  # the index's spec is the default; a case citing another names its own
            entry["spec"] = {"name": "megaeth/Satin", "descriptor": fx["specRef"]["descriptor"]}
        if q_entry:
            quarantine.append({**entry, "knownFail": q_entry})
        else:
            index.append(entry)
    neg = negative(by_id["satin/sstore/fresh-slot/minimum-bucket"])
    neg_rel = f"negative/{neg['caseId']}.json"
    files[neg_rel] = pretty(neg)
    files["index.json"] = pretty({
        "format": "mega-fixture-slice-index",
        "spec": {"name": "megaeth/Satin", "descriptor": descriptor_digest},
        "profile": "state-transition",
        "cases": index,
        "quarantine": quarantine,
        "negative": [{"caseId": neg["caseId"], "file": neg_rel, "wrongAt": "/expected/gasLedgers/state"}],
    })
    return files


def explain(case_ids: list[str]) -> int:
    """Prints the explanation of each named case, derived again: what a case file no longer stores."""
    specs = {name: spec_of(name) for name in SPEC_COMMITS}
    wanted = set(case_ids)
    found = {}
    for c in cases():
        if c.case_id in wanted:
            _, _, _, found[c.case_id] = derive(c, specs)
    missing = sorted(wanted - set(found))
    if missing:
        print(f"make_slice: no case {', '.join(missing)}", file=sys.stderr)
        return 1
    for case_id in case_ids:
        sys.stdout.write(pretty(found[case_id]))
    return 0


SUBDIRS = ("cases", "quarantine", "negative")


def present() -> list[str]:
    """Every file under the slice's case directories, by its path under slice/."""
    out = []
    for sub in SUBDIRS:
        for base, _, names in os.walk(os.path.join(OUT, sub)):
            out += [os.path.relpath(os.path.join(base, n), OUT).replace(os.sep, "/") for n in names]
    return sorted(out)


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--explain"]:
        if len(argv) < 3:
            print("usage: tools/make_slice.py --explain CASE-ID...", file=sys.stderr)
            return 2
        return explain(argv[2:])
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
        extra = sorted(set(present()) - set(files))
        if stale or extra:
            print(f"make_slice: out of date: {stale + extra}", file=sys.stderr)
            return 1
        print(f"make_slice: {len(files)} files up to date")
        return 0
    for rel in present():
        os.remove(os.path.join(OUT, rel))
    for sub in SUBDIRS:  # the directories the removed files leave empty
        top = os.path.join(OUT, sub)
        for base, _, _ in os.walk(top, topdown=False):
            if base != top and not os.listdir(base):
                os.rmdir(base)
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
