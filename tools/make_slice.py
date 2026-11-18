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
rules `specs/satin-cdded1e`, D-65, D-70 and D-67, those for the outcomes page, the authorization
page's own rules and KeylessDeploy's page `specs/satin-c130558`, D-79, D-80, D-85 and D-88, and the
four whose derivation takes a reading the specification states from `bcf260d` on, a precompile's
halt, a failed deposit's step-4 load and a promoted system transaction's receipt,
`specs/satin-bcf260d`, D-96, as do those for the rules of the two gas pools, state gas and the gas
schedule that no case pinned, D-106, and the two cases held out of the precompile and size batch, a
deposit whose top-level creation's initcode is over its limit and a call refused at a precompile
address's beneficiary delegate, `specs/satin-83c0d26`, D-112 and D-114, as do those for a call refused
at its target's EIP-7702 delegate, D-115). No implementation is run: the
filler's output is a candidate to compare with, never the source of these values
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

import functools
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
                "satin-cdded1e": "cdded1e1d131a1d16a2c4b1cd873557f16a6a558",
                "satin-c130558": "c130558e2f38a913982dc17f0cd8eb8834967262",
                "satin-bcf260d": "bcf260d3de62c50cd1700e4f82f91560c4f8df48",
                "satin-83c0d26": "83c0d269a92aaa580bb1805e3168d3cbd4b290aa"}
DEFAULT_SPEC = "satin-d34e626"
INTERCEPTION_SPEC = "satin-d334ef8"  # interception before the frame start, SATIN-ICPT-007
ORDERING_SPEC = "satin-5fb2688"  # the charge-order principles, SATIN-HIST-023
TAKE_BACK_SPEC = "satin-cdded1e"  # one home for each rule, and the take-back page's worked examples as cases
FILL_SPEC = "satin-c130558"  # the first fill batch's clarifications (D-78), and the cases of D-79, D-80, D-85, D-88
SECOND_FILL_SPEC = "satin-bcf260d"  # QI-36 and QI-37's wordings (D-96), and the cases of D-82, D-91, D-100, D-103, D-104, D-106, D-109
CURRENT_SPEC = "satin-83c0d26"  # the snapshot new cases cite (D-112)
# The snapshots that state the principles the model cites.
PRINCIPLES_SPECS = {ORDERING_SPEC, TAKE_BACK_SPEC, FILL_SPEC, SECOND_FILL_SPEC, CURRENT_SPEC}
# The snapshots whose cases the model derives with `Run.current`: `83c0d26` moves none of the readings it gates (D-112).
CURRENT_SPECS = {SECOND_FILL_SPEC, CURRENT_SPEC}
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


def signing_hash(payload: bytes) -> bytes:
    """The Keccak-256 a signature covers. `make_examples.keccak256` pads an input of 135 bytes modulo its 136-byte
    rate as two blocks where Keccak's padding is the one byte 0x81, so its hash of such an input is not Keccak-256:
    a case whose signed bytes have that length is refused, and its author changes a field of it."""
    if len(payload) % 136 == 135:
        raise SystemExit(f"a signed pre-image of {len(payload)} bytes, 135 modulo Keccak's rate: change a field")
    return ex.keccak256(payload)


def _signed(ty: int, fields: list, key: int) -> bytes:
    payload = bytes([ty]) + ex.rlp(fields) if ty else ex.rlp(fields)
    recid, r, s = ex.sign(key, signing_hash(payload))
    return bytes([ty]) + ex.rlp(fields + [recid, r, s])


def legacy(nonce, gas_price, gas, to, value, data, chain_id=CHAIN_ID, key=KEY) -> bytes:
    fields = [nonce, gas_price, gas, to if to is not None else b"", value, data]
    if chain_id is None:  # pre-EIP-155: no chain id, v is 27 or 28
        recid, r, s = ex.sign(key, signing_hash(ex.rlp(fields)))
        return ex.rlp(fields + [recid + 27, r, s])
    recid, r, s = ex.sign(key, signing_hash(ex.rlp(fields + [chain_id, 0, 0])))
    return ex.rlp(fields + [recid + 35 + 2 * chain_id, r, s])


def eip2930(nonce, gas_price, gas, to, value, data, access_list, chain_id=CHAIN_ID) -> bytes:
    al = [[a, [k.to_bytes(32, "big") for k in keys]] for a, keys in access_list]
    return _signed(1, [chain_id, nonce, gas_price, gas, to, value, data, al], KEY)


def eip1559(nonce, max_priority, max_fee, gas, to, value, data, chain_id=CHAIN_ID) -> bytes:
    return _signed(2, [chain_id, nonce, max_priority, max_fee, gas, to, value, data, []], KEY)


UNRECOVERABLE = "unrecoverable"  # an entry whose signature recovers no authority: y_parity, r and s all zero
Y_PARITY_TWO = "y-parity-2"  # a valid signature whose y_parity is 2, outside {0, 1}: it recovers no authority
R_AT_ORDER = "r-at-order"  # a valid signature whose r is secp256k1's order, the excluded bound: it recovers no authority


@functools.lru_cache(maxsize=None)
def authorization(key: int, chain_id: int, target: bytes, nonce: int, signature: str = "") -> tuple:
    """A signed EIP-7702 authorization tuple: the signature is over 0x05 || rlp([chain_id, address, nonce]), or,
    for an UNRECOVERABLE entry, the zero signature, which recovers no authority. Cached: a list of a thousand
    entries is signed once."""
    if signature == UNRECOVERABLE:
        return (chain_id, target, nonce, 0, 0, 0)
    recid, r, s = ex.sign(key, signing_hash(b"\x05" + ex.rlp([chain_id, target, nonce])))
    if signature == Y_PARITY_TWO:
        recid = 2
    elif signature == R_AT_ORDER:
        r = ex.N
    elif signature:
        raise SystemExit(f"an authorization signature {signature!r}")
    return (chain_id, target, nonce, recid, r, s)


@functools.lru_cache(maxsize=None)
def key_address(key: int) -> bytes:
    """A key's address, cached: a list of a thousand entries recovers a thousand of them."""
    return ex.address_of(key)


def authority_of(entry: tuple) -> bytes | None:
    """The authority an entry's signature recovers: its key's address, or None for an entry whose signature is made
    to recover none (UNRECOVERABLE, Y_PARITY_TWO, R_AT_ORDER)."""
    return None if entry[4:] else key_address(entry[0])


def eip7702(nonce, max_priority, max_fee, gas, to, value, data, auths, chain_id=CHAIN_ID) -> bytes:
    return _signed(4, [chain_id, nonce, max_priority, max_fee, gas, to, value, data, [], auths], KEY)


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
                 detention=False, block_hashes=None, stops=False, lists=False, outcomes=False, chain=CHAIN_ID,
                 system_flag=False, gas_used_check=None, system_tx=False, source_hash=None, synthetic=False,
                 sender=None, block_number=BLOCK_NUMBER, system_pages=False, precompile_page=False,
                 size_page=False, pricing=False):
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
        self.gas_used_check = gas_used_check  # a keyless answer's gasUsed the derivation must reproduce (a worked example)
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
        self.lists = lists  # a case of the authorization page's own rules: its derivation cites them (D-88)
        self.outcomes = outcomes  # the case pins the outcomes page or validation's order (D-85)
        self.chain = chain  # the chain's id, which CHAINID reads (D-85)
        self.system_flag = system_flag  # a deposit's base-layer isSystemTransaction flag (D-85)
        self.system_tx = system_tx  # a case of the system-transaction page or of gas forwarding (D-82)
        self.source_hash = source_hash or SOURCE_HASH  # a deposit's source hash
        self.synthetic = synthetic  # the transaction is a synthetic message, its sender given, not recovered (D-83)
        self.sender = sender  # the sender of a synthetic message
        self.block_number = block_number  # the block's number, which NUMBER and BLOCKHASH read
        self.system_pages = system_pages  # a case of the deposits page or of a system contract's page (D-109)
        self.precompile_page = precompile_page  # a case of the precompile page's own rules (D-103)
        self.size_page = size_page  # a case of the contract-limits page's own rules (D-104)
        self.pricing = pricing  # a case of the gas pools', state gas's and gas schedule's own rules (D-106)
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
    for group in (interception_cases, ordering_cases, detention_cases, detention_rule_cases, detention_gap_cases,
                  reads_cases, limit_cases,
                  gas_pools_cases, take_back_cases, selfdestruct_cases, selfdestruct_gap_cases, limit_stop_cases,
                  limit_stop_gap_cases,
                  authorization_cases,
                  outcome_cases, outcome_edge_cases, keyless_cases,
                  keyless_gap_cases, forwarding_cases, system_tx_cases, deposit_page_cases, oracle_page_cases,
                  system_contract_cases, system_pages_gap_cases, history_cases, accounting_cases, precompile_cases,
                  size_cases, precompile_gap_cases, size_gap_cases, pricing_cases, delegate_refusal_cases):
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
    # A precompile that halts burns its whole forward and counts none of it as compute, its charged price included:
    # `SATIN-DET-011` states it from `c130558` on (D-78, superseding D-69's first reading). From `bcf260d` on it names
    # the halt on an input over a size limit, which charges no price, and `SATIN-DET-019` excepts a halting
    # precompile's charged price from the paid work that still counts, so the two cases whose precompile runs and
    # halts cite that snapshot (D-96).
    for name, room, tail, intent, edge, snapshot in (
            ("modexp/over-bound-at-allowance", modexp_price, STOP, "the allowance exactly: it runs, charges its price, "
             "fails EIP-7823's bound and consumes its forward, as without the read", "the price at the allowance",
             SECOND_FILL_SPEC),
            ("modexp/over-bound-past-allowance", modexp_price - 1, RETURN_RETURNDATA, "one past the allowance and within "
             "its forward: an input that would fail a check made after the gas charge is the crossing too",
             "the price one past the allowance", spec)):
        add(Case(f"satin/detention/precompile/{name}", f"after TIMESTAMP, a ModExp call whose base length, "
                 f"{fmt(over_bound)}, is over EIP-7823's bound, priced by its formula all the same, {fmt(modexp_price)}: "
                 + intent, spec=snapshot, detention=True, gas=21_000_000, boundary=edge,
                 make=lambda words, pad, tail=tail: detained(words, pad) + bytes_to_memory(modexp_input)
                 + call(MAX_GAS, model.MODEXP, 0, len(modexp_input)) + tail,
                 params={"words": words_within(cap - 2 * modexp_price - 30_000), "pad": 0},
                 retune=[("precompile-room", room, "pad", -1)]))
    pairing = model.BN254_PAIRING_MAX_INPUT_SIZE + 1
    add(Case("satin/detention/precompile/bn254-pairing-over-size-limit", f"after TIMESTAMP, a BN254 pairing call of "
             f"{fmt(pairing)} bytes, one over its size limit, with an allowance of 100 and a forward past the pairing "
             "formula's price for that many bytes: priced at zero, it runs on its forward, fails before any gas check and "
             "consumes the forward, as without the read", spec=SECOND_FILL_SPEC, detention=True, gas=31_000_000,
             make=lambda words, pad: detained(words, pad) + call(MAX_GAS, model.BN254_PAIRING, 0, pairing) + STOP,
             params=dict(start), retune=[("precompile-room", 100, "pad", -1)]))
    # A user's deposit is detained as any transaction (SATIN-DET-026).
    burner = {BURNER: model.Account(nonce=1, code=big + STOP)}
    add(Case("satin/detention/deposit/user-deposit", "a user's deposit reads TIMESTAMP and calls a contract whose one "
             "memory expansion is past the cap: the callee is stopped with MegaLimitExceeded(2, limit), which the deposit "
             "returns", spec=spec, detention=True, deposit=(0, 21_000_000), sender_nonce=3, accounts=burner,
             code=b"\x42\x50" + call(MAX_GAS, BURNER, 0, 0) + RETURN_RETURNDATA))
    return out


# --- Gas detention's edges a review of the first batch found unpinned ----------------------------------


PAYER = bytes.fromhex("00000000000000000000000000000000000c0e10")  # a child whose value call's start record it cannot pay
PAYEE = bytes.fromhex("00000000000000000000000000000000000c0e11")  # the contract that value call is to


def delegatecall_with(gas: int, target: bytes, in_size: int) -> bytes:
    """DELEGATECALL(gas, target, 0, in_size, 0, 0)."""
    return push(0) + push(0) + push(in_size) + push(0) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf4"


def detention_gap_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    big = over_cap(cap)
    start = {"words": words_within(cap - 30_000), "pad": 0}

    def at_and_past(name: str, at_intent: str, past_intent: str, make, params, retune, **kw):
        """A case whose compute reaches its limit exactly at its STOP, and its twin one JUMPDEST past it."""
        at = Case(f"satin/detention/{name}-at-limit", at_intent, spec=spec, detention=True, make=make, params=params,
                  retune=retune, boundary="the transaction's compute reaches its limit exactly", **kw)
        remade(at)
        add(at)
        add(Case(f"satin/detention/{name}-one-past-limit", past_intent, spec=spec, detention=True, make=make,
                 params={**at.params, "pad": at.params["pad"] + 1}, boundary="the transaction's compute one past its limit",
                 **kw))

    # A precompile that halts on a check made after its gas charge burns its whole forward, its charged price
    # included, and counts none of it as compute (SATIN-DET-011 at c130558): the caller's later charges show it.
    over_bound = model.MODEXP_MAX_INPUT_SIZE + 1
    modexp_input = word(over_bound) + word(0) + word(0)
    modexp_price = model.modexp_price(modexp_input)[0]
    add(Case("satin/detention/precompile/modexp/over-bound-at-allowance-then-jumpdest", "after TIMESTAMP, a ModExp call "
             f"whose base length, {fmt(over_bound)}, is over EIP-7823's bound, priced {fmt(modexp_price)}, the allowance "
             "exactly: it runs, charges its price, fails the bound and burns its whole forward, and none of it is compute "
             "(SATIN-DET-011), so the caller's JUMPDEST after the call is within the limit and the transaction completes",
             spec=spec, detention=True, gas=21_000_000, boundary="the price at the allowance, then one more charge",
             make=lambda words, pad: detained(words, pad) + bytes_to_memory(modexp_input)
             + call(MAX_GAS, model.MODEXP, 0, len(modexp_input)) + b"\x5b" + STOP,
             params={"words": words_within(cap - 2 * modexp_price - 30_000), "pad": 0},
             retune=[("precompile-room", modexp_price, "pad", -1)]))
    forward = 100_000
    after_halt = lambda words, pad: b"\x42\x50" + bytes_to_memory(modexp_input) \
        + call(forward, model.MODEXP, 0, len(modexp_input)) + b"\x50" + burn(words) + b"\x5b" * pad + STOP
    at_and_past("precompile/modexp/over-bound-then-compute",
                f"after TIMESTAMP, a ModExp call forwarded {fmt(forward)}, within the allowance, with a base over "
                f"EIP-7823's bound: it charges its price {fmt(modexp_price)}, fails the bound and burns the forward, none of "
                "it compute (SATIN-DET-011); the caller then computes exactly to the limit, the compute at the read plus "
                "the cap, and completes", "one compute more: the caller's last JUMPDEST is stopped with "
                "MegaLimitExceeded(2, limit), the halted precompile's price not lowering what the limit leaves",
                after_halt, {"words": words_within(cap - 6_000), "pad": 0}, [("end-spendable", 0, "pad", -1)],
                gas=21_500_000)
    # RIPEMD-160's price, read before it runs, decides the call (SATIN-DET-021, -023): at the allowance it runs.
    ripemd_price = model.RIPEMD160_BASE + model.RIPEMD160_WORD
    for name, room, tail, intent, edge in (
            ("ripemd160/priced-at-allowance", ripemd_price, STOP, f"priced {fmt(ripemd_price)}, the allowance exactly: "
             "it runs on its whole forward, and the transaction completes at its limit", "the price at the allowance"),
            ("ripemd160/priced-past-allowance", ripemd_price - 1, RETURN_RETURNDATA, "priced one past the allowance and "
             "within its forward: it does not run and is the crossing, whose stop its caller catches and returns",
             "the price one past the allowance")):
        add(Case(f"satin/detention/precompile/{name}", f"after TIMESTAMP, a call to the RIPEMD-160 precompile forwarded "
                 f"{fmt(forward)} with one word of input, " + intent, spec=spec, detention=True, gas=21_000_000,
                 boundary=edge, make=lambda words, pad, tail=tail: detained(words, pad) + mstore(0, 0xABC)
                 + call(forward, model.RIPEMD160, 0, 32) + tail, params=dict(start),
                 retune=[("precompile-room", room, "pad", -1)]))
    # The transaction's own call of a precompile, detained from its start as a call to the block beneficiary, which
    # ModExp's address is (SATIN-DET-008, -021, -023): decided from its price at compute zero.
    bound = model.MODEXP_MAX_INPUT_SIZE
    for name, exp_len, gas, what in (
            ("priced-past-allowance", 72, 30_000_000, "past the allowance, the cap, and within its regular gas: it does "
             "not run and is the crossing, the transaction's own stop MegaLimitExceeded(2, limit), its first frame's gas "
             "untouched"),
            ("priced-within-allowance", 70, 30_000_000, "within the allowance, the cap: it runs, charges its price and "
             "returns its zero result"),
            ("priced-past-gas", 72, 20_500_000, "past its whole regular gas: it runs on it and fails out of gas, as "
             "without the read")):
        header = word(bound) + word(exp_len) + word(bound)
        price = model.modexp_price(header)[0]
        add(Case(f"satin/detention/own-precompile/modexp-{name}", "the block beneficiary is ModExp's address, and a "
                 "transaction calls it, detained from its start at compute zero; its input's header gives a base and a "
                 f"modulus of {fmt(bound)} bytes and an exponent of {exp_len} bytes, which the transaction does not carry "
                 f"and ModExp reads as zeros, priced {fmt(price)}: " + what, spec=spec, detention=True, gas=gas,
                 to=model.MODEXP, coinbase=model.MODEXP, code=b"", data=header))
    # A finite forward between the spendable part and what the whole regular gas lets a call forward is the
    # forward: the forward reads the whole regular gas (SATIN-DET-015).
    asked = 1_000_000
    reporter = {REPORTER: model.Account(nonce=1, code=b"\x5a" + push(0) + b"\x52" + push(32) + push(0) + b"\xf3")}
    add(Case("satin/detention/withheld/finite-forward-sees-whole", f"a detained frame with 100 of spendable gas and "
             f"much more withheld calls a contract asking for {fmt(asked)}, past the spendable part and within what its "
             "whole regular gas lets it forward: the forward is the gas asked for, as the callee's GAS, which the "
             "transaction returns, shows", spec=spec, detention=True, gas=21_000_000, accounts=reporter,
             make=lambda words, pad: detained(words, pad) + call(asked, REPORTER, 0, 0) + RETURN_RETURNDATA,
             params=dict(start), retune=[("child-room", 100, "pad", -1)]))
    # SHA-256's and ecrecover's prices decide the call the same way (SATIN-DET-021, -023): one word of input to SHA-256,
    # and to ecrecover an input of zeros, whose v recovers nothing, so a call that runs returns empty output.
    sha_price = model.SHA256_BASE + model.SHA256_WORD
    for target, label, price, what in ((model.SHA256, "sha256", sha_price, "one word of input"),
                                       (model.ECRECOVER, "ecrecover", model.ECRECOVER_GAS, "128 zero bytes of input")):
        for name, room, tail, intent, edge in (
                ("priced-at-allowance", price, STOP, f"priced {fmt(price)}, the allowance exactly: it runs on its whole "
                 "forward, and the transaction completes at its limit", "the price at the allowance"),
                ("priced-past-allowance", price - 1, RETURN_RETURNDATA, "priced one past the allowance and within its "
                 "forward: it does not run and is the crossing, whose stop its caller catches and returns",
                 "the price one past the allowance")):
            add(Case(f"satin/detention/precompile/{label}/{name}", f"after TIMESTAMP, a call to the {label} precompile "
                     f"forwarded {fmt(forward)} with {what}, " + intent, spec=spec, detention=True, gas=21_000_000,
                     boundary=edge, make=lambda words, pad, target=target, tail=tail, size=32 if target == model.SHA256
                     else 128: detained(words, pad) + call(forward, target, 0, size) + tail, params=dict(start),
                     retune=[("precompile-room", room, "pad", -1)]))
    # A DELEGATECALL of a precompile moves no value: its inherited value is no transfer to check (SATIN-DET-024).
    words32 = 32 * 32
    identity_price = model.IDENTITY_BASE + model.IDENTITY_WORD * 32
    add(Case("satin/detention/precompile/identity/delegatecall-inherited-value", "a transaction sends its sender's whole "
             "balance, 10 wei, to a contract that reads TIMESTAMP and DELEGATECALLs the identity precompile with "
             f"{fmt(words32)} bytes of input, priced {fmt(identity_price)}, one past the allowance and within the forward: "
             "the call inherits the 10 wei and the sender, whose balance is now zero, but moves no value and checks no "
             "account, so it is the crossing, whose stop the contract returns", spec=spec, detention=True,
             gas=21_000_000, value=10, sender_balance=10, boundary="the price one past the allowance",
             make=lambda words, pad: detained(words, pad) + delegatecall_with(MAX_GAS, model.IDENTITY, words32)
             + RETURN_RETURNDATA, params=dict(start), retune=[("precompile-room", identity_price - 1, "pad", -1)]))
    # A child that halts on its value call's start record (SATIN-HIST-010 step 4) burns what it had, the forward its
    # opcode reserved handed back first and the stipend never its own: none of it is compute (SATIN-DET-009, -011),
    # and its opcode's regular charges, paid before the halt, are (SATIN-DET-019).
    record_history = 2 * model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    held = kept_threshold(record_history) - 1
    payer = {PAYER: model.Account(nonce=1, balance=1, code=call(MAX_GAS, PAYEE, 1, 0) + STOP),
             PAYEE: model.Account(nonce=1, code=STOP)}
    at_and_past("unpaid-start/caller-computes",
                f"after TIMESTAMP, a child makes a value call it can fund to a contract with all the gas it may forward, "
                f"holding {fmt(held)} of regular gas once the opcode's regular charges are made, so that it keeps one gas "
                f"less than the {fmt(record_history)} of history the start's two records cost: it halts in the opcode, "
                "and what it burns, the forward and the rest, is no compute while the opcode's regular charges are; its "
                "caller then computes exactly to the limit and completes", "one compute more: the caller's last JUMPDEST "
                "is stopped with MegaLimitExceeded(2, limit)",
                lambda gas, words, pad: b"\x42\x50" + call(gas, PAYER, 0, 0) + b"\x50" + burn(words) + b"\x5b" * pad
                + STOP, {"gas": 500_000, "words": words_within(cap - 30_000), "pad": 0},
                [("forward:" + PAYEE.hex(), held, "gas", 1), ("end-spendable", 0, "pad", -1)], gas=21_500_000,
                accounts=payer)
    # A value call's callee that runs on its stipend alone and halts (SATIN-DET-010, -011): what it ran counts as compute,
    # and what it burns, the stipend's rest among it, does not.
    halter = {SPINNER: model.Account(nonce=1, code=b"\x5b" * SPIN_STEPS + INVALID)}
    at_and_past("stipend/spun-then-halted", f"after TIMESTAMP, a value call forwarding no gas runs a callee that spends "
                f"{fmt(SPIN_STEPS)} of its {fmt(model.CALL_STIPEND)} stipend and halts: what it ran is compute, and what it "
                "burns, the rest of the stipend, is not, so the caller's JUMPDESTs reach the limit exactly and it "
                "completes", "one JUMPDEST more: stopped",
                lambda words, pad: b"\x42\x50" + burn(words) + call(0, SPINNER, 1, 0) + b"\x50" + b"\x5b" * pad + STOP,
                dict(start), [("end-spendable", 0, "pad", -1)], gas=21_000_000, contract_balance=10, accounts=halter)
    # Every BLOCKHASH is a read (SATIN-DET-004): the last block in range and the first one too old, at block 300.
    number = 300
    oldest = number - model.BLOCKHASH_WINDOW
    for name, n, what in (("last-in-range", oldest, f"of block {fmt(oldest)}, the oldest of the last "
                           f"{model.BLOCKHASH_WINDOW}, whose hash it answers"),
                          ("first-too-old", oldest - 1, f"of block {fmt(oldest - 1)}, one older than the last "
                           f"{model.BLOCKHASH_WINDOW}, which it answers with zero")):
        add(Case(f"satin/detention/blockhash/{name}", f"in block {fmt(number)}, BLOCKHASH {what}, is a read of the block "
                 "environment: the memory expansion after it, past the cap, is stopped with MegaLimitExceeded(2, limit)",
                 spec=spec, detention=True, gas=21_000_000, block_number=number,
                 boundary="the oldest block in range" if n == oldest else "one block older than the range",
                 code=push(n) + b"\x40\x50" + big + STOP, block_hashes={oldest: bytes.fromhex("b2" * 32)}))
    # A creation is no read and is not refused with access off, also when its creator is the beneficiary
    # (SATIN-DET-006): a creation transaction's created address made the beneficiary, which then CREATEs.
    created = model.created_address(SENDER, 0)
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224) \
        + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50"
    add(Case("satin/detention/creation/creator-at-beneficiary-access-off", "a creation transaction whose created address "
             "is the block beneficiary switches its volatile-data access off, then CREATEs another account: the creation "
             "loads its creator, the beneficiary, as its own check, so it is neither refused nor marked, and the memory "
             "expansion after it, past the cap, completes", spec=spec, detention=True, system=True, to=None,
             coinbase=created, gas=22_000_000, data=disable + create(0, ret(0, 0)) + big + ret(0, 0)))
    # BLOBHASH is no volatile read (SATIN-DET-002): with access off it is not refused.
    add(Case("satin/detention/not-volatile/blobhash-access-off", "a contract switches its volatile-data access off, then "
             "reads BLOBHASH, no volatile read: it is not refused, nothing is marked, and the memory expansion after it, "
             "past the cap, completes", spec=spec, detention=True, system=True, gas=21_000_000,
             code=disable + push(0) + b"\x49\x50" + big + STOP))
    # A read whose opcode completed stays marked when its frame then fails (SATIN-DET-003, -012): a child's NUMBER,
    # then the child reverts or halts, and its caller's memory expansion past the cap is stopped.
    for name, end in (("reverts", revert(0, 0)), ("halts", INVALID)):
        add(Case(f"satin/detention/completed-read/child-{name}", f"a child completes NUMBER, a read of the block "
                 f"environment, and then {name}: the read stays marked though its frame fails, and the limit it set "
                 "stops its caller's later memory expansion, past the cap, with MegaLimitExceeded(2, limit)", spec=spec,
                 detention=True, gas=21_000_000, accounts={DETAINED: model.Account(nonce=1, code=b"\x43\x50" + end)},
                 code=call(10_000, DETAINED, 0, 0) + b"\x50" + big + STOP))
    # The Oracle's read is marked before its one charge of COLD_SLOAD_COST, which is the crossing when the whole regular
    # gas pays it and an out-of-gas one gas short (SATIN-ORCL-004, SATIN-DET-018, -020). A deposit's read asks no
    # service, so the cases are deposits.
    get_slot = mstore(0, int.from_bytes(model.selector("getSlot(uint256)"), "big") << 224)
    for name, whole, what in (
            ("read-charge-at-whole-gas", model.COLD_SLOAD, "exactly the read's one charge: the whole regular gas pays it "
             "and the spendable part does not, so the charge is not made and the Oracle's frame is stopped with "
             "MegaLimitExceeded(2, limit), its gas returned, which the deposit returns"),
            ("read-charge-one-short", model.COLD_SLOAD - 1, "one gas less than the read's one charge: the whole regular "
             "gas cannot pay it, so the Oracle's frame runs out of gas, as without the read, and burns its forward")):
        add(Case(f"satin/detention/oracle/{name}", "a deposit's detained call to the Oracle's getSlot holds 50 of "
                 f"spendable gas and {fmt(whole)} in all at the SLOAD, {what}; the read is marked before the charge "
                 "(SATIN-ORCL-004)", spec=spec, detention=True, system=True, deposit=(0, 21_000_000), sender_nonce=3,
                 boundary=f"the whole regular gas {'at' if whole == model.COLD_SLOAD else 'one below'} the read's charge",
                 make=lambda words, pad, gas: get_slot + detained(words, pad) + call(gas, model.ORACLE, 0, 36)
                 + RETURN_RETURNDATA, params={**start, "gas": 3_000},
                 retune=[("oracle-sload", whole, "gas", 1), ("oracle-sload-room", 50, "pad", -1)]))
    # A call short of an operand fails on its operands as with access on, though its target delegates to the
    # beneficiary (SATIN-MAC-003, SATIN-DET-001): six operands, the target's the second from the top.
    to_beneficiary = {DELEGATED: model.Account(code=model.DELEGATION_PREFIX + COINBASE)}
    six = push(0) + push(0) + push(0) + push(0) + push(int.from_bytes(DELEGATED, "big")) + push(100_000)
    for name, op in (("call", b"\xf1"), ("callcode", b"\xf2")):
        add(Case(f"satin/detention/access-off/{name}-short-of-an-operand", f"a contract switches its volatile-data "
                 f"access off, then does a {name.upper()} with six of its seven operands, its target an account whose "
                 "EIP-7702 delegate is the block beneficiary: the opcode fails on its operands as it would with access "
                 "on, a stack underflow that halts the frame, and is not refused (SATIN-MAC-003)", spec=spec,
                 detention=True, system=True, gas=1_000_000, accounts=to_beneficiary,
                 boundary="one operand short of the call", code=disable + six + op + STOP))
    # More of the beneficiary's account (SATIN-DET-001, -003, -008): EXTCODECOPY of it in a child that completes and in
    # one that runs out of gas at its copy, which marks nothing; a DELEGATECALL of it; a recipient delegating to it.
    for name, size, child_gas, what in (
            ("extcodecopy-completes", 32, 100_000, "completes: the read is marked, and the caller's memory expansion past "
             "the cap is stopped with MegaLimitExceeded(2, limit)"),
            ("extcodecopy-fails", 4_000_000, 100_000, "cannot pay its copy of 4,000,000 bytes and runs out of gas: a read "
             "whose opcode fails marks nothing, so the caller's memory expansion past the cap completes")):
        copier = {DETAINED: model.Account(nonce=1, code=push(size) + push(0) + push(0)
                                          + push(int.from_bytes(COINBASE, "big")) + b"\x3c" + STOP)}
        add(Case(f"satin/detention/beneficiary/{name}", f"a child does EXTCODECOPY of the block beneficiary's code, {size:,} "
                 f"bytes, on {fmt(child_gas)} of regular gas: it " + what, spec=spec, detention=True, gas=21_000_000,
                 accounts={**copier, COINBASE: model.Account(nonce=1, code=STOP)},
                 code=call(child_gas, DETAINED, 0, 0) + b"\x50" + big + STOP,
                 boundary="the read's opcode completed" if size == 32 else "the read's opcode failed at its copy"))
    add(Case("satin/detention/beneficiary/delegatecall-target", "a contract DELEGATECALLs the block beneficiary, a contract "
             "whose one memory expansion is past the cap, with all the gas it may forward: the read of the beneficiary's "
             "account is marked when the start is decided, at a compute that leaves out the forward, so the child's "
             "expansion is stopped with MegaLimitExceeded(2, limit), which the contract returns", spec=spec,
             detention=True, gas=21_000_000, accounts={COINBASE: model.Account(nonce=1, code=big + STOP)},
             code=push(7) + b"\x50" + delegatecall(MAX_GAS, COINBASE) + RETURN_RETURNDATA))
    add(Case("satin/detention/beneficiary/recipient-delegates", "a transaction to an account whose EIP-7702 delegate is "
             "the block beneficiary, a contract whose one memory expansion is past the cap: the transaction is detained "
             "from its start at compute zero, its limit the cap exactly, though the delegate's access is charged before "
             "its first frame, and the frame running the delegate's code is stopped with MegaLimitExceeded(2, limit)",
             spec=spec, detention=True, gas=21_000_000, to=DELEGATED, code=None,
             accounts={DELEGATED: model.Account(code=model.DELEGATION_PREFIX + COINBASE),
                       COINBASE: model.Account(nonce=1, code=big + STOP)}))
    # The beneficiary's account through BALANCE and as a call's target (SATIN-DET-001, -003).
    add(Case("satin/detention/beneficiary/balance", "BALANCE of the block beneficiary is a read of its account: the memory "
             "expansion after it, past the cap, is stopped with MegaLimitExceeded(2, limit)", spec=spec, detention=True,
             gas=21_000_000, code=push(int.from_bytes(COINBASE, "big")) + b"\x31\x50" + big + STOP))
    add(Case("satin/detention/beneficiary/call-target", "a contract calls the block beneficiary, a contract whose one "
             "memory expansion is past the cap, with all the gas it may forward: the read of the beneficiary's account is "
             "marked when the start is decided, before the child runs, at a compute that leaves out the forward, so the "
             "child's expansion is stopped with MegaLimitExceeded(2, limit) at that compute plus the cap, which the "
             "contract returns", spec=spec, detention=True, gas=21_000_000,
             accounts={COINBASE: model.Account(nonce=1, code=big + STOP)},
             code=push(7) + b"\x50" + call(MAX_GAS, COINBASE, 0, 0) + RETURN_RETURNDATA))
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


# --- The gas pools', state gas's and gas schedule's own rules (D-106) ---------------------------------

RESTORER = bytes.fromhex("00000000000000000000000000000000000c0e21")  # a child that fills a fresh slot and restores it
SAME_BUCKET_SLOTS = (4677, 6750)  # two slots of CONTRACT that salt-v1 puts in one bucket
RELAY = bytes.fromhex("00000000000000000000000000000000000c0e22")  # a child that calls a writer and stops
CROWDED_WRITER = bytes.fromhex("00000000000000000000000000000000000c0e23")  # a writer whose slot's bucket is crowded
SHARE_WRITER = bytes.fromhex("00000000000000000000000000000000000c0e24")  # a child that fills one fresh slot
DEPOSITOR = bytes.fromhex("00000000000000000000000000000000000c0e25")  # a creator that returns its CREATE's result
MERGE_RELAY = bytes.fromhex("00000000000000000000000000000000000c0e26")  # a child that calls a child and stops
MERGE_LEAF = bytes.fromhex("00000000000000000000000000000000000c0e27")  # a child that stops at once
HOLLOW = bytes.fromhex("000000000000000000000000000000000000e3e8")  # a destruction's beneficiary, present as a leaf


def least_passing(make, lo: int, hi: int, holds) -> int:
    """The least value in [lo, hi] whose case, `make(value)`, gives a result that `holds`, which is monotone in it."""
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            passing = holds(build(make(mid))[1])
        except model.Unmodelled:  # too little for the run to reach the edge at all
            passing = False
        if passing:
            hi = mid
        else:
            lo = mid + 1
    return lo


def pricing_cases() -> list[Case]:
    """The rules of the two-pool gas model, of state gas and SALT pricing, and of the gas schedule that no case pinned
    (D-106): the execution cap and the absent total-gas cap at their edges, a charge made before the first frame that
    regular gas partly paid and a first frame that then fails, a returned reservoir after its caller spilled, a
    first frame's failure after a list's charges, a creation and a value call whose start fails after their state
    charge, computation to the last regular gas; where each state charge is made, what its multiplier scales, the
    bucket SALT maps it to and the one read of a bucket's capacity, a give-back at the charge's price, and the pricing of
    a deposit and of a system-originated transaction; the forward's 98/100 cap, the doubled static gas of EXTCODESIZE,
    and the accounts warm from the transaction's start."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    kw = dict(spec=spec, pricing=True)
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE
    slot, account = model.SLOT_STATE, model.ACCOUNT_STATE
    cap = model.EXECUTION_CAP

    # SATIN-POOL-001, -005: the execution cap splits the gas limit, at the cap and one above it.
    add(Case("satin/gas-pools/execution-cap/gas-limit-at-cap", f"a gas limit of exactly the execution cap, {fmt(cap)}: "
             "the reservoir is zero, so the body's history and a fresh slot's state gas and record are paid from the regular "
             "budget, the cap less the intrinsic gas (SATIN-POOL-001)", boundary="the gas limit at the execution cap",
             gas=cap, code=sstore(1, 1) + STOP, pools=True, **kw))
    add(Case("satin/gas-pools/execution-cap/gas-limit-one-above-cap", f"a gas limit one above the execution cap, "
             f"{fmt(cap + 1)}: the reservoir is 1, which pays the first of the body's {fmt(body)} of history, the regular "
             "budget the rest (SATIN-POOL-001)", boundary="the gas limit one above the execution cap", gas=cap + 1,
             code=sstore(1, 1) + STOP, pools=True, **kw))

    # SATIN-POOL-003: no cap on a transaction's total gas; the block's gas limit bounds it (one above refuses: the case
    # satin/validation/gas-limit-above-block).
    total_cap = model.TX_MAX_TOTAL_GAS_LIMIT
    add(Case("satin/gas-pools/total-gas/one-above-eip-8037-cap", f"a gas limit of {fmt(total_cap + 1)}, one above "
             f"EIP-8037's TX_MAX_TOTAL_GAS_LIMIT {fmt(total_cap)}, which Satin does not apply: admitted, the reservoir is "
             "the gas limit past the execution cap, and a fresh slot at m = 3 takes its state gas past the legacy share "
             "from it (SATIN-POOL-003)", boundary="one above TX_MAX_TOTAL_GAS_LIMIT", gas=total_cap + 1,
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 3}, pools=True, **kw))
    add(Case("satin/gas-pools/total-gas/at-block-gas-limit", f"a gas limit equal to the block's gas limit, "
             f"{fmt(BLOCK_GAS_LIMIT)}, which alone bounds it: admitted, with a reservoir of {fmt(BLOCK_GAS_LIMIT - cap)} "
             "(SATIN-POOL-003)", boundary="the gas limit at the block's gas limit", gas=BLOCK_GAS_LIMIT,
             code=sstore(1, 1) + STOP, pools=True, **kw))

    # SATIN-POOL-003's second paragraph, SATIN-POOL-015, -024: a creation's charges before its frame, partly paid by the
    # regular budget, and its frame halting or reverting.
    paid = 90_000
    for name, init, tail in (("halts", INVALID, "the reservoir's part returns to the reservoir and the regular budget's "
                              "part is consumed with the frame's regular gas"),
                             ("reverts", revert(0, 0), "the whole charge, the regular budget's part included, is given "
                              "back into the transaction's reservoir")):
        own_body = (model.TX_BODY_SIZE + len(init)) * model.COST_PER_HISTORY_BYTE
        add(Case(f"satin/gas-pools/pre-frame-spill/creation-{name}", f"a creation transaction whose reservoir, after the "
                 f"body's history, is {fmt(record + paid)}: it pays the start record's {fmt(record)} and {fmt(paid)} of the "
                 f"created account's {fmt(account)}, the regular budget the other {fmt(account - paid)}; the initcode "
                 f"{name}: {tail} (SATIN-POOL-015, SATIN-POOL-003)", to=None, data=init,
                 gas=cap + own_body + record + paid, outcomes=True, **kw))

    # SATIN-POOL-002, -012: the reservoir a child returns joins its caller's after the caller spilled, crediting no
    # regular gas.
    left = 50_000
    add(Case("satin/gas-pools/child-merge/returned-reservoir-after-spill", f"the first frame, with {fmt(left)} of "
             f"reservoir, fills a fresh slot: the legacy share and {fmt(slot - model.LEGACY_SSTORE_SHARE - left)} of spill "
             "from regular gas; its child, given no reservoir, fills and restores a fresh slot, and returns the give-back, "
             f"{fmt(slot + record)}, as reservoir: it joins the caller's, and none of it unwinds the caller's spill into "
             "regular gas (SATIN-POOL-002)", gas=cap + body + left, pools=True,
             code=sstore(1, 1) + call(MAX_GAS, RESTORER, 0, 0) + b"\x50" + STOP,
             accounts={RESTORER: model.Account(nonce=1, code=sstore(1, 1) + sstore(1, 0) + STOP)}, **kw))

    # SATIN-POOL-002, -024: a first frame's revert returns nothing of the reservoir the list's charges drew.
    auth_body = (model.TX_BODY_SIZE + model.AUTHORIZATION_SIZE) * model.COST_PER_HISTORY_BYTE
    add(Case("satin/gas-pools/first-frame-revert/authorization-charges-kept", "an EIP-7702 list whose one entry, for an "
             "authority the state holds no account for, is applied from the reservoir, then a first frame that reverts: "
             "the list's state and history charges are kept, and the frame's failure returns none of the reservoir they "
             "drew (SATIN-POOL-002)", ty=4, code=revert(0, 0), lists=True,
             gas=cap + auth_body + 1_000_000, authorizations=[(AUTH_KEY, CHAIN_ID, DELEGATE, 0)], **kw))

    # SATIN-POOL-015: a creation from a frame whose initcode fails, and a value call its caller cannot fund to an
    # account empty under EIP-161, each given its account's state gas back, its legacy share included, into the reservoir.
    funds = 400_000
    for name, init in (("reverts", revert(0, 0)), ("halts", INVALID)):
        add(Case(f"satin/gas-pools/created-account-give-back/initcode-{name}", f"the first frame, with {fmt(funds)} of "
                 f"reservoir, creates an account: its {fmt(account)} of state gas, the legacy share "
                 f"{fmt(model.LEGACY_CREATE_SHARE)} from regular gas and the rest from the reservoir; the initcode {name}, "
                 "and the whole charge, its legacy share included, is given back into the creator's reservoir after the "
                 "child's reservoir joined it (SATIN-POOL-015)", gas=cap + body + funds, pools=True,
                 code=create(0, init) + STOP, **kw))
    add(Case("satin/gas-pools/new-account-give-back/unfunded-value-call", f"the first frame, with {fmt(funds)} of "
             "reservoir and no balance, makes a value call to an account the state does not hold: the new account's "
             f"{fmt(account)} of state gas, the legacy share {fmt(model.LEGACY_NEW_ACCOUNT_SHARE)} from regular gas and the "
             "rest from the reservoir, is given back whole into the reservoir when the start does not happen, and the "
             "legacy share is not credited to regular gas (SATIN-POOL-015)", gas=cap + body + funds, pools=True,
             code=call(MAX_GAS, ABSENT, 1, 0) + b"\x50" + STOP, **kw))

    # SATIN-POOL-021: computation is paid in regular gas, held by no compute limit: the whole regular budget spent, and
    # one gas more.
    budget = cap - model.TX_BASE_COST - model.COLD_ACCOUNT_ACCESS
    fixed = model.G_VERYLOW + model.G_VERYLOW + model.G_BASE  # PUSH, MLOAD, POP
    words = words_within(budget - fixed)
    pad = budget - fixed - model.memory_cost(words)
    for name, extra in (("regular-budget-spent", 0), ("one-past-regular-budget", 1)):
        add(Case(f"satin/gas-pools/no-compute-limit/{name}", "a first frame whose computation, a memory expansion and a run "
                 f"of JUMPDESTs, {'is' if not extra else 'is one gas past'} its whole regular budget, {fmt(budget)}, with a "
                 f"reservoir of {fmt(1_000_000)}: " + ("it completes with no regular gas left, the reservoir untouched"
                                                       if not extra else "it runs out of gas, a halt, and no limit stops "
                                                       "it; the reservoir returns to the sender")
                 + " (SATIN-POOL-021)", boundary=f"computation {'at' if not extra else 'one past'} the regular budget",
                 gas=cap + body + 1_000_000, pools=not extra, code=burn(words) + b"\x5b" * (pad + extra) + STOP, **kw))

    # SATIN-POOL-008, SATIN-STATE-012: a fresh slot's legacy share from regular gas whatever the reservoir holds: a child
    # forwarded one gas short of its pushes, its write and the share, and forwarded exactly that.
    need = 2 * model.G_VERYLOW + model.COLD_SSTORE_ACCESS + model.SSTORE_SET + model.LEGACY_SSTORE_SHARE
    for name, forward, ending in (("one-short", need - 1, "it runs out of gas paying the share though its reservoir share "
                                   "could pay the whole charge, so its slot is not written and the transaction keeps no "
                                   "state gas"),
                                  ("exact", need, "it pays the share and completes, the reservoir paying the rest")):
        add(Case(f"satin/gas-pools/legacy-share/child-{name}", f"a child forwarded {fmt(forward)} of regular gas, with a "
                 "large reservoir share, fills a cold fresh slot: its pushes, the access and the write, "
                 f"{fmt(need - model.LEGACY_SSTORE_SHARE)}, then the legacy share {fmt(model.LEGACY_SSTORE_SHARE)} from "
                 f"regular gas: {ending} (SATIN-POOL-008, SATIN-STATE-012)", boundary=f"the child's regular gas "
                 f"{'one below' if forward < need else 'at'} its charges with the share", gas=cap + body + 1_000_000,
                 pools=True, code=call(forward, SHARE_WRITER, 0, 0) + b"\x50" + STOP,
                 accounts={SHARE_WRITER: model.Account(nonce=1, code=sstore(1, 1) + STOP)}, **kw))

    # SATIN-POOL-011, -012, -002: a reservoir share returned unspent through two merges, against one merge.
    for name, relay, tail in (("two-merges", call(MAX_GAS, MERGE_LEAF, 0, 0) + b"\x50" + STOP, "Q keeps 1 and R receives "
                               "97; R returns 97 into Q's 1, and Q returns 98 into P's 1"),
                              ("one-merge", STOP, "Q stops at once and returns 98 into P's 1")):
        add(Case(f"satin/gas-pools/child-merge/unspent-share-{name}", "the first frame P, with 99 of reservoir, calls Q "
                 f"without value: P keeps 1 and Q receives 98; {tail}: P ends with 99, and no merge credits regular gas "
                 "(SATIN-POOL-011, SATIN-POOL-012)", gas=cap + body + 99, pools=True,
                 code=b"\x5b" + call(MAX_GAS, MERGE_RELAY, 0, 0) + b"\x50" + STOP,
                 accounts={MERGE_RELAY: model.Account(nonce=1, code=relay), MERGE_LEAF: model.Account(nonce=1, code=STOP)},
                 **kw))

    # SATIN-POOL-003, -024: a value start's record, paid by the regular budget below the cap, and a first frame that halts.
    add(Case("satin/gas-pools/pre-frame-spill/value-start-record-halts", "a value transfer to a contract whose code halts, "
             f"below the execution cap: the start record's {fmt(record)} is paid by the regular budget before the frame, and "
             "with the halt the value, its log and the record are taken back and that regular gas stays spent, none of it "
             "returning (SATIN-POOL-003, SATIN-POOL-024)", value=1, code=INVALID, gas=1_000_000, **kw))

    # The keyless creation destroying the deploy address after a fresh slot: the table gives back the leaf and the
    # slot, and the call's gasUsed adds back the leaf and its own record alone.
    keyless_raw = carried(sstore(1, 1) + b"\x32\xff", gas=500_000)
    add(Case("satin/gas-pools/keyless/destroyed-after-fresh-slot", "the transaction's own keylessDeploy call, its constructor "
             "filling a fresh slot and then destroying the deploy address: the destruction table gives back the slot and "
             "the created account with their records into the creation's reservoir, and the call's gasUsed adds back what "
             "step 14 charged for the account and its one record, not the slot's record (SATIN-KEY-015, SATIN-SD-004)",
             system=True,
             to=model.KEYLESS_DEPLOY, code=None, data=keyless_data(keyless_raw, 500_000, padded=False), gas=1_500_000, **kw))

    # SATIN-STATE-004, -005: where a charge is made, and what m scales.
    made = model.created_address(CONTRACT, 1)
    code10 = bytes(range(0x60, 0x6a))
    add(Case("satin/state-gas/multiplier/creation-at-m3", "a CREATE from the first frame onto an address in a bucket at "
             f"three times the minimum capacity, which deploys {len(code10)} bytes: the created account's state gas and the "
             f"code's are scaled by m = 3, {fmt(account * 3)} and {fmt(model.CODE_STATE_PER_BYTE * 3 * len(code10))}; the "
             f"legacy share {fmt(model.LEGACY_CREATE_SHARE)}, CREATE_ACCESS, the hashing and the history are not "
             "(SATIN-STATE-004, SATIN-STATE-005)", gas=2_000_000, code=create(0, init_returning(code10)) + STOP,
             salt={(made, None): 3}, **kw))
    add(Case("satin/state-gas/multiplier/value-call-new-account-at-m5", "a value call to an account the state does not "
             f"hold, in a bucket at five times the minimum capacity: the call makes the new account's {fmt(account * 5)} "
             f"of state gas; its legacy share {fmt(model.LEGACY_NEW_ACCOUNT_SHARE)}, the value transfer and the records' "
             "history are not scaled (SATIN-STATE-004, SATIN-STATE-005)", gas=2_000_000, contract_balance=10,
             code=call(0, ABSENT, 1, 0) + b"\x50" + STOP, salt={(ABSENT, None): 5}, **kw))
    add(Case("satin/state-gas/sites/zero-value-call-to-absent", "a call without value to an account the state does not "
             "hold: it adds no account and makes no state charge, so no bucket's capacity is read, the SALT input "
             "holding none and being incomplete (SATIN-STATE-004)", gas=1_000_000, salt_complete=False,
             code=call(0, ABSENT, 0, 0) + b"\x50" + STOP, **kw))

    # SATIN-STATE-006, -010: two fresh slots that SALT maps to one bucket, one restored: one read of the capacity, one m
    # for both charges and the give-back.
    k1, k2 = SAME_BUCKET_SLOTS
    add(Case("satin/state-gas/same-bucket/two-slots-one-restored", f"slots {k1} and {k2} of one contract, which SALT's "
             "mapping puts in one bucket, at five times the minimum capacity, are filled, and the second is restored: both "
             f"charges and the give-back are priced at the one m = 5, {fmt(slot * 5)} each, the capacity the incomplete "
             "SALT input lists for that bucket alone (SATIN-STATE-006, SATIN-STATE-010)", gas=3_000_000,
             code=sstore(k1, 1) + sstore(k2, 1) + sstore(k2, 0) + STOP, salt={(CONTRACT, k1): 5}, salt_complete=False,
             reads=True, **kw))

    # SATIN-STATE-006: the destruction table gives a created account's code back at that account's own price, though an
    # account created after it deposited code at another.
    first, second = model.created_address(CONTRACT, 1), model.created_address(CONTRACT, 2)
    runtime = push(int.from_bytes(ABSENT, "big")) + b"\x31\x50" + push(int.from_bytes(ABSENT, "big")) + b"\xff"
    add(Case("satin/state-gas/give-back-price/destroyed-after-another-creation", "the first frame creates A in a bucket at "
             f"four times the minimum capacity, deploying {len(runtime)} bytes, then B at m = 1, deploying one byte, and "
             f"calls A, which destroys itself: the table gives back A's leaf and its code at A's m = 4, "
             f"{fmt(model.CODE_STATE_PER_BYTE * 4 * len(runtime))} for the code, the price each was charged, not B's "
             "(SATIN-STATE-006)", gas=3_000_000,
             code=create(0, returning(runtime)) + create(0, init_returning(b"\x00")) + call(MAX_GAS, first, 0, 0) + b"\x50"
             + STOP, salt={(first, None): 4}, **kw))

    # SATIN-STATE-006: a charge given back at the price it was made, at m = 3 and m = 4: a creation whose initcode
    # reverts, and a write two frames deep that reverts, beside its control that keeps it.
    made3 = model.created_address(CONTRACT, 1)
    add(Case("satin/state-gas/give-back-price/created-account-reverted-at-m3", "a CREATE onto an address in a bucket at "
             f"three times the minimum capacity whose initcode reverts: the created account's {fmt(account * 3)}, charged "
             "before the forward, is given back at the same m = 3, its legacy share included, and the transaction keeps "
             "no state gas (SATIN-STATE-006)", gas=2_000_000, code=create(0, revert(0, 0)) + STOP,
             salt={(made3, None): 3}, **kw))
    for name, tail, ending in (("reverts", revert(0, 0), "its frame reverts, and the charge comes back whole at the same "
                                "m, so the transaction keeps no state gas"),
                               ("keeps", STOP, "its frame succeeds, and the transaction keeps the charge at that m")):
        add(Case(f"satin/state-gas/give-back-price/inner-frame-{name}-at-m4", "the first frame calls a relay, which calls "
                 "a writer that fills a fresh slot in a bucket at four times the minimum capacity, "
                 f"{fmt(slot * 4)}: {ending} (SATIN-STATE-006)", gas=3_000_000,
                 code=call(MAX_GAS, RELAY, 0, 0) + b"\x50" + STOP, salt={(CROWDED_WRITER, 1): 4},
                 accounts={RELAY: model.Account(nonce=1, code=call(MAX_GAS, CROWDED_WRITER, 0, 0) + b"\x50" + STOP),
                           CROWDED_WRITER: model.Account(nonce=1, code=sstore(1, 1) + tail)}, **kw))

    # SATIN-STATE-006, SATIN-POOL-015, SATIN-SCHED-011: a creation whose constructor wrote a crowded slot, one gas short of
    # its code deposit's last charge, its history, and exactly paid.
    held = model.created_address(DEPOSITOR, 1)
    depositor = (bytes_to_memory(returning(b"\x00", sstore(1, 1))) + push(len(returning(b"\x00", sstore(1, 1)))) + push(0)
                 + push(0) + b"\xf0" + push(0) + b"\x52" + ret(0, 32))

    def deposit_case(request: int, name: str, ending: str) -> Case:
        return Case(f"satin/state-gas/give-back-price/code-deposit-{name}-after-crowded-write", "a contract creates an "
                    "account in a bucket at three times the minimum capacity, whose constructor fills slot 1 in a bucket at "
                    "four times it and returns one byte, its regular gas set " + ending + " (SATIN-STATE-006, "
                    "SATIN-POOL-015, SATIN-SCHED-011)", boundary=f"the creation {name} its deposit's last charge",
                    gas=3_000_000, code=call(request, DEPOSITOR, 0, 0) + b"\x50" + RETURN_RETURNDATA,
                    accounts={DEPOSITOR: model.Account(nonce=1, code=depositor)},
                    salt={(held, None): 3, (held, 1): 4}, **kw)
    deployed = lambda result: (result.observations.get("state") or {}).get("accounts", {}).get(h(held), {}).get("code") == "0x00"
    least = least_passing(lambda r: deposit_case(r, "paid", ""), 100_000, 2_900_000, deployed)
    add(deposit_case(least - 1, "one-short", f"one gas short of the deposit's history, {model.COST_PER_HISTORY_BYTE}: the "
                     "creation halts, nothing of it is kept, the slot's state gas goes with its rollback at m = 4 and the "
                     "account's comes back to the creator at m = 3, its legacy share included, and the CREATE answers zero"))
    add(deposit_case(least, "paid", "to pay the deposit's last charge exactly: the account, its slot and its byte are kept"))

    # SATIN-STATE-004, -011: a SELFDESTRUCT's beneficiary present as an empty leaf, with and without storage, is a new
    # account; one with a nonce is not.
    for name, leaf, ending in (("empty-leaf-at-m3", model.Account(), "empty under EIP-161: the destruction adds it and "
                                f"charges {fmt(account * 3)} of state gas at its m = 3, its legacy share "
                                f"{fmt(model.LEGACY_SELFDESTRUCT_SHARE)} first, and one unit of state growth"),
                               ("empty-leaf-with-storage-at-m3", model.Account(storage={7: 9}), "empty under EIP-161 though "
                                "it holds a slot: the same new-account charge and growth, and its slot stays"),
                               ("nonce-one-leaf", model.Account(nonce=1), "not empty, its nonce being 1: no new-account "
                                "charge and no growth")):
        add(Case(f"satin/state-gas/sites/selfdestruct-to-{name}", "the transaction's own frame, a contract it did not "
                 "create holding 1 wei, SELFDESTRUCTs to an account whose leaf the state holds with no balance and no code, "
                 f"{ending} (SATIN-STATE-004, SATIN-STATE-011)", contract_balance=1, destruction=True, reads=True,
                 code=selfdestruct_to(HOLLOW), accounts={HOLLOW: leaf}, salt={(HOLLOW, None): 3}, gas=2_000_000, **kw))

    # SATIN-STATE-002, SATIN-STATE-007's valid side: a capacity listed at the minimum, and one below twice it and at it.
    for name, m, label in (("listed-at-minimum", 1, f"exactly {model.MIN_BUCKET_SIZE}, the minimum, a bucket: m = 1"),
                           ("one-below-twice-minimum", (2 * model.MIN_BUCKET_SIZE - 1) / model.MIN_BUCKET_SIZE,
                            f"{2 * model.MIN_BUCKET_SIZE - 1}, one below twice the minimum: m = 1"),
                           ("twice-minimum", 2, f"{2 * model.MIN_BUCKET_SIZE}, twice the minimum: m = 2")):
        add(Case(f"satin/state-gas/capacity/{name}", f"a fresh slot whose bucket the incomplete SALT input lists alone at "
                 f"{label} (SATIN-STATE-002)", boundary=f"a capacity of {int(m * model.MIN_BUCKET_SIZE)}",
                 code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): m}, salt_complete=False, reads=True, **kw))

    # SATIN-STATE-010: an account's bucket and its slot's are SALT's, each its own.
    rt = b"\x60\x00\x60\x00"
    add(Case("satin/state-gas/mapping/account-and-slot-buckets", "a CREATE whose constructor fills slot 1 of the created "
             "account and deploys 4 bytes, the account's bucket at twice the minimum capacity and the slot's at six "
             f"times: the account's {fmt(account * 2)} and the code's state gas at m = 2, the slot's {fmt(slot * 6)} at "
             "m = 6 (SATIN-STATE-010)", gas=3_000_000, code=create(0, returning(rt, sstore(1, 1))) + STOP,
             salt={(made, None): 2, (made, 1): 6}, **kw))

    # SATIN-STATE-009: a system-originated deposit priced at m = 1, its give-back too, and a creation in it; a user's
    # deposit priced by its bucket.
    deposit = dict(deposit=(0, 2_000_000), sender_nonce=3)
    add(Case("satin/state-gas/system-originated/fresh-slots-and-give-back", "a deposit carrying "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH fills two fresh slots and restores one: the charges and the give-back "
             "are at m = 1 and read no bucket's capacity, the SALT input incomplete and holding none (SATIN-STATE-009)",
             source_hash=SYSTEM_TX_SOURCE, code=sstore(1, 1) + sstore(2, 1) + sstore(2, 0) + STOP, salt_complete=False,
             **deposit, **kw))
    add(Case("satin/state-gas/system-originated/creation", "a deposit carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH "
             "creates an account that deploys one byte: the created account's and the code's state gas at m = 1, no "
             "bucket's capacity read, the SALT input incomplete and holding none (SATIN-STATE-009)",
             source_hash=SYSTEM_TX_SOURCE, code=create(0, init_returning(b"\x00")) + STOP, salt_complete=False,
             **deposit, **kw))
    add(Case("satin/state-gas/deposit/user-deposit-new-account", "a deposit with another source hash, not "
             "system-originated, whose frame makes a value call to an account the state does not hold, in a bucket at four "
             f"times the minimum capacity: priced by that bucket, {fmt(account * 4)} (SATIN-STATE-009)", contract_balance=10,
             code=call(0, ABSENT, 1, 0) + b"\x50" + STOP, salt={(ABSENT, None): 4}, **deposit, **kw))

    # SATIN-SCHED-001: 1,000 of regular gas forwards 980, not 985.
    add(Case("satin/schedule/forward/one-thousand-forwards-980", "a CALL requesting all it may from a caller holding "
             "1,000 of regular gas after the opcode's charges: the 98/100 cap forwards 980, where Amsterdam's 63/64 "
             f"would forward 985; the child's GAS, after its own {model.G_BASE}, shows {980 - model.G_BASE} "
             "(SATIN-SCHED-001)", boundary="a remaining of 1,000",
             accounts={REPORTER: model.Account(nonce=1, code=REPORT_GAS)},
             code=call(MAX_GAS, REPORTER, 0, 0) + b"\x50" + RETURN_RETURNDATA, tune=("forward", 1_000), **kw))

    # SATIN-SCHED-002, -012, -014: EXTCODESIZE's two warm reads, EXTCODEHASH's one, and the warm accounts.
    target = {PLAIN: model.Account(nonce=1, code=b"\x60\x00\x00")}
    extcodesize = lambda who: push(int.from_bytes(who, "big")) + b"\x3b\x50"
    extcodehash = lambda who: push(int.from_bytes(who, "big")) + b"\x3f\x50"
    balance = lambda who: push(int.from_bytes(who, "big")) + b"\x31\x50"
    add(Case("satin/schedule/static-gas/extcodesize-cold", "EXTCODESIZE of a contract that is not warm: its static gas, "
             f"two warm reads, {2 * model.WARM_READ}, then the cold access {fmt(model.COLD_ACCOUNT_SURCHARGE)} "
             "(SATIN-SCHED-002)", accounts=dict(target), code=extcodesize(PLAIN) + STOP, **kw))
    add(Case("satin/schedule/static-gas/extcodesize-warm-recipient", "EXTCODESIZE of the transaction's own recipient, "
             f"warm from its start: its static gas alone, {2 * model.WARM_READ} (SATIN-SCHED-002, SATIN-SCHED-014)",
             code=extcodesize(CONTRACT) + STOP, **kw))
    add(Case("satin/schedule/static-gas/extcodehash-warm-sender", "EXTCODEHASH of the sender, warm from the "
             f"transaction's start: one warm read, {model.WARM_READ}, as Osaka's, where EXTCODESIZE pays two "
             "(SATIN-SCHED-002, SATIN-SCHED-014)", code=extcodehash(SENDER) + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/extcodesize-precompile", "EXTCODESIZE of the identity precompile, warm from "
             f"the transaction's start: {2 * model.WARM_READ}, no cold access (SATIN-SCHED-012)",
             code=extcodesize(model.IDENTITY) + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/sender-recipient-and-cold", "BALANCE of the sender and of the recipient, "
             f"each warm from the transaction's start, {model.WARM_READ}, then of an account the transaction has not "
             f"accessed, {fmt(model.WARM_READ + model.COLD_ACCOUNT_SURCHARGE)} (SATIN-SCHED-014)",
             code=balance(SENDER) + balance(CONTRACT) + balance(UNTOUCHED) + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/access-list-address-without-keys", "an access list naming a contract with no "
             f"storage keys: BALANCE, its first access, costs {model.WARM_READ}, the list having warmed it; the CALL after it "
             "is warm too (SATIN-SCHED-012)", ty=1, access_list=[(PLAIN, [])], accounts=dict(target),
             code=balance(PLAIN) + call(0, PLAIN, 0, 0) + b"\x50" + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/access-list-address-with-keys", "an access list naming a contract with a "
             f"storage key: the first CALL to it, without value, makes no cold access, its warm read {model.WARM_READ} "
             "alone (SATIN-SCHED-012)", ty=1, access_list=[(PLAIN, [1])], accounts=dict(target),
             code=call(0, PLAIN, 0, 0) + b"\x50" + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/callcode-access-listed", "an access list naming a contract with no storage "
             f"keys: the first CALLCODE of it, without value, makes no cold access, its warm read {model.WARM_READ} alone "
             "(SATIN-SCHED-012)", ty=1, access_list=[(PLAIN, [])], accounts=dict(target),
             code=callcode(0, PLAIN, 0) + b"\x50" + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/selfdestruct-beneficiary-access-listed", "an access list naming an existing "
             "account with no storage keys, to which the transaction's own frame, a contract it did not create, "
             f"SELFDESTRUCTs its balance: its first access as a beneficiary is warm, the static cost "
             f"{fmt(model.SELFDESTRUCT_COST)} without the cold {fmt(model.COLD_ACCOUNT_ACCESS)} (SATIN-SCHED-012)",
             ty=1, access_list=[(HEIR, [])], accounts={HEIR: model.Account(balance=1)}, contract_balance=5,
             destruction=True, code=push(int.from_bytes(HEIR, "big")) + b"\xff", **kw))
    add(Case("satin/schedule/warm-from-start/call-beneficiary", "a CALL without value to the block beneficiary, warm from "
             f"the transaction's start: its access is the warm read {model.WARM_READ} (SATIN-SCHED-012)",
             code=call(0, COINBASE, 0, 0) + b"\x50" + STOP, accounts={COINBASE: model.Account(nonce=1, code=STOP)},
             detention=True, **kw))
    add(Case("satin/schedule/warm-from-start/first-call-access-listed", "an access list naming a contract with no storage "
             f"keys, whose first access is a CALL without value: its warm read {model.WARM_READ} alone, no cold access, "
             "nothing having touched it before (SATIN-SCHED-012)", ty=1, access_list=[(PLAIN, [])], accounts=dict(target),
             code=call(0, PLAIN, 0, 0) + b"\x50" + STOP, **kw))
    add(Case("satin/schedule/warm-from-start/first-staticcall-access-listed", "the same first access by a STATICCALL: its "
             f"warm read {model.WARM_READ} alone (SATIN-SCHED-012)", ty=1, access_list=[(PLAIN, [])],
             accounts=dict(target), code=staticcall(0, PLAIN) + b"\x50" + STOP, **kw))
    extcodecopy = lambda who, dest, offset, size: (push(size) + push(offset) + push(dest) + push(int.from_bytes(who, "big"))
                                                   + b"\x3c")
    add(Case("satin/schedule/static-gas/extcodecopy-cold-zero-length-twice", "EXTCODECOPY of zero bytes of a contract "
             f"that is not warm, twice: the first pays its static gas, two warm reads, {2 * model.WARM_READ}, and the cold "
             f"access {fmt(model.COLD_ACCOUNT_SURCHARGE)}, the second its static gas alone, though neither copies a byte "
             "(SATIN-SCHED-002)", accounts=dict(target),
             code=extcodecopy(PLAIN, 0, 0, 0) + extcodecopy(PLAIN, 0, 0, 0) + STOP, **kw))
    add(Case("satin/schedule/static-gas/extcodecopy-cold-copies-code", "EXTCODECOPY of a cold contract's 3 bytes of code "
             f"into memory, returned: {2 * model.WARM_READ} of static gas, the cold access, the copy of one word and the "
             "memory's word (SATIN-SCHED-002)", accounts=dict(target), code=extcodecopy(PLAIN, 0, 0, 3) + ret(0, 32), **kw))
    for size in (96, 97):
        add(Case(f"satin/schedule/intrinsic/initcode-{size}-bytes", f"a creation transaction whose initcode is STOP and "
                 f"{size - 1} zero bytes, {size} bytes in {(size + 31) // 32} words: EIP-3860's word cost and the calldata "
                 "tokens are in its intrinsic regular gas, and every byte is in its body's history and its floor "
                 "(SATIN-SCHED-006)", boundary=f"initcode of {size} bytes", to=None, data=STOP + bytes(size - 1), **kw))
    code33 = bytes(range(1, 34))
    add(Case("satin/schedule/code-deposit/history-per-byte", f"a CREATE that deploys {len(code33)} bytes: the regular "
             f"code-deposit cost is zero a byte, the hashing {model.KECCAK_WORD} a word, the code's state gas "
             f"{fmt(model.CODE_STATE_PER_BYTE)} a byte and its history {model.COST_PER_HISTORY_BYTE} a byte, where Amsterdam "
             "prices it at zero (SATIN-SCHED-001)", gas=2_000_000, code=create(0, returning(code33)) + STOP, **kw))
    return out


# --- The take-back page's worked examples (SATIN-TAKE-005 to -012), one case each ----------------


def delegatecall(gas: int, target: bytes) -> bytes:
    """DELEGATECALL(gas, target, 0, 0, 0, 0)."""
    return push(0) + push(0) + push(0) + push(0) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf4"


def create(value: int, init: bytes) -> bytes:
    """CREATE of `init`, laid out in memory from offset 0, with `value` wei; the created address is popped."""
    return bytes_to_memory(init) + push(len(init)) + push(0) + push(value) + b"\xf0\x50"


def create2(value: int, init: bytes, salt: int) -> bytes:
    """CREATE2 of `init`, laid out in memory from offset 0, with `value` wei and `salt`; the created address is popped."""
    return bytes_to_memory(init) + push(salt) + push(len(init)) + push(0) + push(value) + b"\xf5\x50"


def callcode(gas: int, target: bytes, value: int) -> bytes:
    """CALLCODE(gas, target, value, 0, 0, 0, 0)."""
    return push(0) + push(0) + push(0) + push(0) + push(value) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf2"


def staticcall(gas: int, target: bytes) -> bytes:
    """STATICCALL(gas, target, 0, 0, 0, 0)."""
    return push(0) + push(0) + push(0) + push(0) + push(int.from_bytes(target, "big")) + push(gas) + b"\xfa"


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


def selfdestruct_gap_cases() -> list[Case]:
    """The destruction page's edges a review of the first batch found unpinned."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    heir = {HEIR: model.Account(balance=1)}
    first, second = model.created_address(CONTRACT, 1), model.created_address(CONTRACT, 2)
    warm_heir = push(int.from_bytes(HEIR, "big")) + b"\x31\x50"

    def case(name: str, intent: str, **kw) -> None:
        add(Case(f"satin/selfdestruct/{name}", intent, spec=spec, destruction=True, **kw))

    # Two accounts created in one transaction, each destroyed by its own table (SATIN-SD-002, -004, -005, -008): C at
    # a bucket of the minimum capacity, D at twice it, with a fresh slot of its constructor; C is destroyed first.
    make_both = create(0, returning(selfdestruct_to(HEIR))) + create(0, returning(selfdestruct_to(HEIR), sstore(1, 1)))
    both = warm_heir + call(MAX_GAS, first, 0, 0) + b"\x50" + call(MAX_GAS, second, 0, 0) + b"\x50"
    case("first-effective/two-accounts", "P creates C, whose account's bucket holds the minimum capacity, and then D, "
         "whose account's bucket holds twice it and whose constructor writes a fresh slot; P then calls C and D, each of "
         "which destroys itself to a warm existing account: each first effective destruction gives back its own leaf, "
         "code and slots at the prices they were charged, C's code at m = 1 and D's at m = 2, and D's slot with D, so the "
         "transaction keeps P's nonce record alone", code=make_both + both + STOP, accounts=heir, gas=4_000_000,
         salt={(second, None): 2})
    # A created account's destruction to itself burns its balance at once and silently (SATIN-LOG-005, SATIN-SD-001).
    case("first-effective/to-itself", "P creates C with 1 wei, and C's code destroys C to C itself: the first effective "
         "destruction gives back C's leaf and code, and the 1 wei is burned at once, with no transfer log, no record and "
         "no rise for a beneficiary (SATIN-LOG-005); P's BALANCE of C after it, stored in P's slot 1, reads zero",
         code=create(1, returning(selfdestruct_to(first))) + call(MAX_GAS, first, 0, 0) + b"\x50"
         + push(int.from_bytes(first, "big")) + b"\x31" + push(1) + b"\x55" + STOP, contract_balance=1, gas=4_000_000)
    # The table's falls come before the positive effects (SATIN-SD-019, -018): C's frame starts with a state-growth
    # budget of zero, P having counted C's creation and 998 fresh slots, and C destroys itself, holding 1 wei, to an
    # address the state holds no account for, whose rise needs room in that budget.
    filled = model.TX_STATE_GROWTH_LIMIT - 2
    fill = b"".join(sstore(k, 1) for k in range(1, filled + 1))
    for name, present, what in (
            ("absent-leaf-falls-first", False, "C's leaf, absent at the transaction's start, falls by one before the "
             "beneficiary rises by one: the frame's net growth is zero, within its budget, and the destruction completes "
             "with empty return data"),
            ("present-leaf-rise-crosses", True, "C's leaf, which the state holds with storage, gives back no rise, so the "
             "beneficiary's rise of one crosses the frame's budget of zero: C is stopped with MegaLimitExceeded(3, 0), "
             "the destruction and its table discarded, and P catches the stop")):
        case(f"budget/{name}", f"P creates C with 1 wei, writes {fmt(filled)} fresh slots, leaving the transaction one "
             "unit of state growth, and calls C, whose state-growth budget is its share of that one, zero; C destroys "
             f"itself to an address the state holds no account for: {what}; P then reverts with the call's return data",
             contract_balance=1, gas=400_000_000,
             accounts={**heir, **({first: model.Account(storage={1: 5})} if present else {})},
             boundary="a destruction's rise at a budget of zero, " + ("with" if not present else "without") + " a fall",
             code=create(1, returning(selfdestruct_to(ABSENT))) + fill + call(MAX_GAS, first, 0, 0)
             + REVERT_RETURNDATA)
    # SELFDESTRUCT's parts are charges of their own under gas detention (SATIN-DET-018, SATIN-SD-019 step 1): a detained
    # child with 4,999 of spendable gas destroys itself to a cold address the state holds no account for. Its static
    # cost alone crosses when the whole regular gas pays it, though its dynamic part would not fit; one gas below the
    # static cost is an out-of-gas (SATIN-DET-020).
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 30_000), "pad": 0}
    push_cost = model.G_VERYLOW
    spendable = model.SELFDESTRUCT_COST - 1
    destroyer = {DETAINED: model.Account(nonce=1, balance=10, code=selfdestruct_to(ABSENT))}
    for name, whole, what in (
            ("static-cost-crossing", 6_000, "the static cost is the crossing: the destruction is not made, the child is "
             "stopped with MegaLimitExceeded(2, limit), its gas returned, and the caller returns the stop (SATIN-DET-018)"),
            ("static-cost-out-of-gas", spendable, "the whole regular gas cannot pay the static cost either: the child "
             "runs out of gas, as without the read, nothing of the destruction made (SATIN-DET-020)")):
        add(Case(f"satin/selfdestruct/charges/{name}", f"after TIMESTAMP, a child holding 10 wei with {fmt(spendable)} of "
                 f"spendable gas and {fmt(whole)} of regular gas in all destroys itself to a cold address the state holds "
                 f"no account for, whose static cost {fmt(model.SELFDESTRUCT_COST)} is one charge and its cold access and new "
                 "account another: " + what, spec=spec, destruction=True, detention=True, gas=21_000_000,
                 accounts=destroyer, boundary=f"the static cost one past the spendable part, the whole regular gas "
                 f"{'past' if whole > spendable else 'one below'} it",
                 make=lambda words, pad, whole=whole: detained(words, pad) + call(whole + push_cost, DETAINED, 0, 0)
                 + RETURN_RETURNDATA, params=dict(start), retune=[("child-room", spendable + push_cost, "pad", -1)]))
    # The destruction's charges come before its table (SATIN-SD-009, -019): C, created with 1 wei and two fresh slots,
    # destroys itself to an absent address, a new account whose state gas the child pays from regular gas; the table's
    # large give-back would pay it, but comes after it.
    regular = model.SELFDESTRUCT_COST + model.COLD_ACCOUNT_ACCESS + model.SELFDESTRUCT_NEW_ACCOUNT_COST
    needs = push_cost + regular + model.ACCOUNT_STATE
    two_slots = create(1, returning(selfdestruct_to(ABSENT), sstore(1, 1) + sstore(2, 1)))
    for name, gas, what in (
            ("new-beneficiary-state-one-short", needs - 1, "one gas short of the new account's state gas: the child halts "
             "in the destruction's charges, before the table, whose give-back it never receives, and C survives with its "
             "slots"),
            ("new-beneficiary-state-paid", needs, "exactly its regular charges and the new account's state gas: the "
             "destruction completes, and the table then gives back C's leaf, code and slots, which pay the beneficiary's "
             "record history")):
        case(f"charges/{name}", f"P creates C with 1 wei and two fresh slots, and calls C with {fmt(gas)} of regular gas; "
             "C destroys itself to a cold address the state holds no account for, whose regular charges are "
             f"{fmt(regular)} and whose new account's state gas, {fmt(model.ACCOUNT_STATE)}, regular gas pays, the "
             f"transaction having no reservoir: " + what, code=two_slots + call(gas, first, 0, 0) + b"\x50" + STOP,
             contract_balance=1, gas=4_000_000, boundary=f"the child's gas {'one below' if gas < needs else 'at'} the "
             "destruction's charges")
    # A destruction's read of the block beneficiary is marked only once every step that can fail has passed (SATIN-SD-020,
    # SATIN-DET-003): after the table's take-backs, its beneficiary's record and the transfer log cross the transaction's
    # data-size limit, or fit exactly. C is created with 1 wei, hints then leave the room, and P calls C, which destroys
    # itself to the beneficiary; P then expands its memory past the cap.
    to_coinbase = create(1, returning(selfdestruct_to(COINBASE)))
    probe = Case("satin/selfdestruct/late-failure/probe", "the creation alone", spec=spec, destruction=True, system=True,
                 code=to_coinbase + STOP, contract_balance=1, gas=4_000_000)
    made = int(build(probe)[1].observations["resources"]["dataSize"]["net"]) - model.TX_BODY_SIZE
    freed = model.WRITE_RECORD_SIZE + len(selfdestruct_to(COINBASE))  # C's leaf record and its code, taken back
    effects = model.WRITE_RECORD_SIZE + model.TRANSFER_LOG_SIZE  # the beneficiary's record and the transfer log
    hinted = (1 << 20) // 32  # the memory words the hints expanded P's memory to
    over = burn(words_within(cap + model.memory_cost(hinted)) + 1)  # an expansion from there past the cap
    for name, room, what in (
            ("beneficiary-read-data-stopped", effects - 1 - freed, "one byte short of them: C is stopped with "
             f"MegaLimitExceeded(0, {fmt(model.TX_DATA_LIMIT)}), its destruction discarded and its read of the "
             "beneficiary not marked, so P's expansion past the cap completes"),
            ("beneficiary-read-data-fits", effects - freed, "exactly them: the destruction completes, its read of the "
             "beneficiary is marked last, and P's expansion past the cap is stopped with MegaLimitExceeded(2, limit)")):
        case(f"late-failure/{name}", f"P creates C with 1 wei, and hints then leave the transaction {room} bytes of data "
             f"size; C destroys itself to the block beneficiary, which the state holds no account for: the table gives "
             f"back C's record and code, {freed} bytes, and the beneficiary's record and the transfer log need {effects}, "
             + what, code=to_coinbase + hints_leaving(room, made) + call(MAX_GAS, first, 0, 0) + b"\x50" + over + STOP,
             system=True, contract_balance=1, gas=30_000_000, boundary="the destruction's positive effects "
             + ("one byte past" if "stopped" in name else "at") + " what the take-backs left")
    # The transaction's own creation frame destroys the account it creates (SATIN-SD-001, -007, SATIN-HIST-005): the
    # table gives back the charges made before the first frame for it, once, into that frame's reservoir.
    own = model.created_address(SENDER, 0)
    for name, init, what in (("destroyed", selfdestruct_to(HEIR), "destroys it at once"),
                             ("destroyed-with-slot", sstore(1, 1) + selfdestruct_to(HEIR), "writes a fresh slot and "
                              "destroys it")):
        case(f"own-creation/{name}", f"a creation transaction's initcode {what}, to an existing account: the first "
             "effective destruction's table gives back, into the first frame's reservoir and once, the created account's "
             "state gas and its record's history, charged before the first frame" + (", and the slot's state gas and "
             "record" if "slot" in name else "") + "; the account is removed at the transaction's end, and the "
             "settlement gives nothing back again", to=None, data=init, accounts=heir, gas=3_000_000, pools=True)
    # Its own end is a read when the created address is the block beneficiary (SATIN-SD-020, SATIN-DET-007): a
    # DELEGATECALL frame on it destroys it, and the constructor's memory expansion past the cap after that is stopped.
    library = {LIBRARY: model.Account(nonce=1, code=selfdestruct_to(HEIR))}
    case("own-creation/own-end-read-binds", "a creation transaction whose created address is the block beneficiary, not "
         "detained from its start, runs a library by DELEGATECALL that destroys the account it creates: that "
         "SELFDESTRUCT's own end is the beneficiary's account, a read marked once it completes (SATIN-DET-007), so the "
         "constructor's memory expansion past the cap after it is stopped with MegaLimitExceeded(2, limit)", to=None,
         coinbase=own, detention=True, gas=22_000_000, accounts={**heir, **library},
         data=delegatecall(MAX_GAS, LIBRARY) + b"\x50" + burn(words_within(cap) + 1) + ret(0, 0))
    # A creation resets its address's storage (SATIN-BASE-001, the base layer's create transition): C is created onto
    # a leaf the state holds with three slots and survives; its constructor writes slot 2 and writes slot 3 back to the
    # value the state held, and never accesses slot 1.
    over = {first: model.Account(storage={1: 5, 2: 9, 3: 5})}
    init = sstore(2, 7) + sstore(3, 5) + returning(STOP)
    case("creation-over-storage/survives", "P creates C at an address whose leaf the state holds with nonce 0, no "
         "balance, no code and three slots, and C survives: the creation resets the address's storage as the base "
         "layer's create transition does (SATIN-BASE-001), so slot 1, which the transaction never accesses, is zero "
         "afterwards, slot 2 holds what the constructor wrote, and slot 3, written back to the value the state held, is "
         "unchanged; each write is a fresh slot from an original of zero, and the reset itself makes no record",
         code=create(0, init) + STOP, accounts=over, gas=3_000_000, boundary="a slot the creation reset and no one wrote")
    held = model.created_address(WRAPPER, 1)
    wrapper_create = {WRAPPER: model.Account(nonce=1, code=create(0, init) + revert(0, 0)),
                      held: model.Account(storage={1: 5, 2: 9, 3: 5})}
    case("creation-over-storage/creator-reverts", "the control: W creates C at an address whose leaf the state holds "
         "with three slots, C's constructor writes two of them, and W then reverts: the creation is rolled back with "
         "it, so the reset is too, and the leaf keeps its three slots, unchanged (SATIN-BASE-001)",
         code=call(2_000_000, WRAPPER, 0, 0) + b"\x50" + STOP, accounts=wrapper_create, gas=3_000_000)
    # The same, C's destruction discarded by a wrapper that reverts: C survives with what it was charged, and D's table
    # still gives back D's slot.
    wrapper = {WRAPPER: model.Account(nonce=1, code=call(MAX_GAS, first, 0, 0) + b"\x50" + revert(0, 0))}
    case("discarded/one-of-two-accounts", "P creates C, at a bucket of the minimum capacity, and D, at twice it, whose "
         "constructor writes a fresh slot; P calls W, which calls C, which destroys itself, and then W reverts, "
         "discarding C's mark and its table; P then calls D, which destroys itself: D's table gives back D's leaf, code "
         "and slot at m = 2, and C survives, its leaf's and its code's charges and records standing",
         code=make_both + warm_heir + call(2_000_000, WRAPPER, 0, 0) + b"\x50" + call(MAX_GAS, second, 0, 0) + b"\x50"
         + STOP, accounts={**heir, **wrapper}, gas=4_000_000, salt={(second, None): 2})
    return out


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


# --- The authorization page's own rules (D-88) -----------------------------------------------------

def limit_stop_gap_cases() -> list[Case]:
    """The limit-stop page's edges a review of the first batch found unpinned."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    limit = fmt(model.TX_DATA_LIMIT)
    record, transfer_log, log0 = model.WRITE_RECORD_SIZE, model.TRANSFER_LOG_SIZE, model.LOG_BASE_SIZE
    start = 2 * record + transfer_log  # a value start's two records and its transfer log
    stipend = model.CALL_STIPEND
    identity = {model.IDENTITY: model.Account(nonce=1, balance=1)}

    # A precompile that answers is a frame answered without running (SATIN-STOP-014): a success whose start crosses is
    # replaced by the stop on the child's whole regular gas, its price not taken from it; a failure kept nothing.
    room, forward = start - 1, 10_000
    for name, words, what, edge in (
            ("identity-answer-stopped", 1, "its forward and stipend pay the price, so the precompile would answer with a "
             "success: its start is held to what it would keep and crosses the transaction's limit, the answer is "
             f"replaced by MegaLimitExceeded(0, {limit}) on the call's whole {fmt(forward + stipend)} of regular gas, "
             "the forward and the stipend, nothing of the price taken from it, and the contract returns the stop",
             "a start one byte past what is left, the precompile priced within its gas"),
            ("identity-failure-kept", (forward + stipend - model.IDENTITY_BASE) // model.IDENTITY_WORD + 1,
             "its price is past its forward and stipend, so the precompile fails: an answer that failed kept nothing "
             "and is not replaced by a stop, the call consumes the gas forwarded to it, the stipend included, and the "
             "contract returns the call's empty return data", "a start one byte past what is left, the precompile "
             "priced one word past its gas")):
        price = model.IDENTITY_BASE + model.IDENTITY_WORD * words
        add(Case(f"satin/limit-stops/precompile-start/{name}", f"hints leave the transaction {room} bytes of data size, "
                 f"and a contract sends 1 wei to the identity precompile with {fmt(words)} words of input, priced "
                 f"{fmt(price)}, forwarding {fmt(forward)} besides the {fmt(stipend)} stipend; the start would keep two "
                 f"records and a transfer log, {start} bytes, one byte past what is left: " + what, boundary=edge,
                 system=True, spec=spec, stops=True, gas=8_000_000, contract_balance=1, accounts=identity,
                 code=hints_leaving(room) + call(forward, model.IDENTITY, 1, 32 * words) + b"\x50" + RETURN_RETURNDATA))
    # The address holds code, and the call still runs the precompile (SATIN-PCMP-008): its failure is kept too.
    words = (forward + stipend - model.IDENTITY_BASE) // model.IDENTITY_WORD + 1
    price = model.IDENTITY_BASE + model.IDENTITY_WORD * words
    add(Case("satin/limit-stops/precompile-start/identity-failure-kept-code-at-address", f"the identity precompile's "
             "address holds code, which a call to it does not run (SATIN-PCMP-008); hints leave the transaction "
             f"{room} bytes of data size, and a contract sends it 1 wei with {fmt(words)} words of input, priced "
             f"{fmt(price)}, past its forward {fmt(forward)} and stipend {fmt(stipend)}; the start would keep {start} bytes, "
             "one byte past what is left: the precompile fails, its failure is not replaced by a stop, and the call "
             "consumes its gas", boundary="a start one byte past what is left, the precompile priced one word past its "
             "gas", system=True, spec=spec, stops=True, gas=8_000_000, contract_balance=1,
             accounts={model.IDENTITY: model.Account(nonce=1, balance=1, code=INVALID)},
             code=hints_leaving(room) + call(forward, model.IDENTITY, 1, 32 * words) + b"\x50" + RETURN_RETURNDATA))
    # A precompile priced past gas detention's allowance moves nothing and is held to the price alone (SATIN-STOP-014,
    # SATIN-DET-022): its start would cross the data-size limit as well, and the stop is the compute stop.
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    words32 = 32 * 32
    identity_price = model.IDENTITY_BASE + model.IDENTITY_WORD * 32
    add(Case("satin/limit-stops/precompile-start/identity-priced-past-allowance-start-crosses", f"hints leave the "
             f"transaction {room} bytes of data size; after TIMESTAMP, a contract sends 1 wei to the identity precompile "
             f"with {fmt(words32)} bytes of input, priced {fmt(identity_price)}, one past the allowance and within the "
             f"forward, whose start would keep two records and a transfer log, {start} bytes, one byte past what is "
             "left: the price is consulted before the value moves, so the call is the crossing, held to the price alone, "
             "and its stop is MegaLimitExceeded(2, limit), not the data-size stop its records would have made",
             boundary="the price one past the allowance, the start one byte past the data size left", system=True,
             spec=spec, stops=True, detention=True, gas=30_000_000, contract_balance=10, accounts=identity,
             make=lambda words, pad: hints_leaving(room) + detained(words, pad) + call(MAX_GAS, model.IDENTITY, 1, words32)
             + RETURN_RETURNDATA, params={"words": words_within(cap - 30_000), "pad": 0},
             retune=[("precompile-room", identity_price - 1, "pad", -1)]))

    # A frame's own data-size budget, reached through its logs, their history paid from a reservoir (SATIN-LIM-003,
    # -004, -011, SATIN-STOP-018): twelve LOG0s of 1 MiB from the same memory and a last one sized to the budget.
    mib = 1 << 20
    own = model.TX_DATA_LIMIT - model.TX_BODY_SIZE  # the transaction's own frame's budget: what the body left
    child_budget = own * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    logs = lambda budget, more: b"".join(log(0, 0, mib, []) for _ in range(12)) \
        + log(0, 0, budget - 12 * (mib + log0) - log0 + more, []) + STOP
    reservoir_gas = 2_000_000_000
    add(Case("satin/limit-stops/frame-budget/own-frame-log-one-byte-over", f"a transaction of {fmt(reservoir_gas)} gas, "
             "whose reservoir pays its logs' history, emits twelve LOG0s of 1 MiB and a last LOG0 that takes its frame's "
             f"data size one byte past its budget, {fmt(own)}, what the transaction's {limit} left after the body: the log "
             "crosses its frame's budget and the transaction's limit at once, and the stop names the frame's budget, "
             f"MegaLimitExceeded(0, {fmt(own)})", boundary="the frame's data size one byte past its budget",
             spec=spec, stops=True, gas=reservoir_gas, code=logs(own, 1)))
    for crosses in (False, True):
        add(Case(f"satin/limit-stops/frame-budget/child-logs-{'one-byte-over' if crosses else 'at-budget'}", "a "
                 f"transaction of {fmt(reservoir_gas)} gas calls a child, whose data-size budget is the share of its "
                 f"caller's {fmt(own)}, {fmt(child_budget)}; the child emits twelve LOG0s of 1 MiB and a last LOG0 that "
                 + ("takes it one byte past that budget: it is stopped with MegaLimitExceeded(0, "
                    f"{fmt(child_budget)}), the budget and not the transaction's limit, and its caller reverts with the stop"
                    if crosses else "fills that budget exactly: kept, and its caller reverts with the call's success "
                    "flag, so that no log is kept"),
                 boundary=f"the child's data size {'one byte past' if crosses else 'at'} its budget", spec=spec, stops=True,
                 gas=reservoir_gas, accounts={STOPPED_CHILD: model.Account(nonce=1, code=logs(child_budget, int(crosses)))},
                 code=call(MAX_GAS, STOPPED_CHILD, 0, 0) + (REVERT_RETURNDATA if crosses else push(0) + b"\x52"
                                                           + revert(0, 32))))

    # The hint exception on a creation's return (SATIN-STOP-006, -012, -015): P, holding its account's record from the
    # transaction's value, writes two slots away from their originals, two records, then hints leave the 40 bytes its
    # creation's start record takes. The initcode calls P back, which writes both slots back, taking the records back,
    # and sends an 80-byte hint into the room that freed; the creation then fails, which puts the records back and keeps
    # the hint, 40 bytes over the limit, or succeeds.
    oracle = int.from_bytes(model.ORACLE, "big")
    hint80 = mstore(0, int.from_bytes(model.SEND_HINT, "big") << 224) + push(0) + push(0) + push(2 * record) + push(0) \
        + push(0) + push(oracle) + push(1) + b"\xf1\x50"
    callback = sstore(1, 7) + sstore(2, 7) + hint80 + STOP
    dirty = sstore(1, 8) + sstore(2, 8)
    probe = Case("satin/limit-stops/hint-into-freed-room/probe", "the records before the hints", spec=spec, stops=True,
                 system=True, value=1, storage={1: 7, 2: 7}, code=dirty + STOP, gas=8_000_000)
    counted = int(build(probe)[1].observations["resources"]["dataSize"]["net"]) - model.TX_BODY_SIZE
    for name, tail, what in (
            ("creation-kept", ret(0, 0), "succeeds: the take-backs, the hint and the created account's record merge, the "
             "transaction exactly at its limit, and P runs on"),
            ("creation-reverted", revert(0, 0), "reverts"),
            ("creation-halted", INVALID, "halts"),
            ("creation-stopped", log(0, 0, 0, []) + STOP, f"emits an empty LOG0, {log0} bytes past the limit, and is "
             "itself stopped")):
        failed = name != "creation-kept"
        init = call(MAX_GAS, CONTRACT, 0, 1) + b"\x50" + tail
        add(Case(f"satin/limit-stops/hint-into-freed-room/{name}", "a transaction sends 1 wei to P, which therefore holds "
                 f"its account's record; P writes its slots 1 and 2 away from their originals, two records, and hints "
                 f"leave the transaction the {record} bytes its CREATE's start record takes; the initcode calls P back, "
                 f"which writes both slots back, taking the two records back, and sends a hint of {2 * record} bytes into "
                 f"the room that freed, and the creation {what}" + ("; its failure discards the created account's record "
                 "and puts the two records back while the hint stays counted, over the limit, so P, whose nonce bump "
                 "makes no record, returns the stop of the transaction's data-size limit before its next instruction"
                 if failed else ""), system=True, spec=spec, stops=True, gas=8_000_000, value=1, storage={1: 7, 2: 7},
                 boundary="the hint exception on the creator's resume" if failed else "",
                 code=jump_if(b"\x36\x15", dirty + hints_leaving(record, counted) + create(0, init) + STOP, callback)))

    # The first frame's start counts on the transaction (SATIN-LIM-013, SATIN-STOP-013): a transaction carrying 1 wei
    # to a contract, whose hints then leave room for an empty LOG0 or one byte less.
    kept = record + transfer_log  # the recipient's record and the value's transfer log; the sender's is the body's
    for crosses in (False, True):
        left = log0 - (1 if crosses else 0)
        add(Case(f"satin/limit-stops/first-frame-value/log-{'one-byte-over' if crosses else 'at-limit'}", "a transaction "
                 f"sends 1 wei to a contract, whose first frame's start keeps the contract's record and the transfer log, "
                 f"{kept} bytes, counted on the transaction; the contract's hints then leave {left} bytes of data size, and "
                 f"it emits an empty LOG0 of {log0} bytes: " + (f"one byte past what is left, so the frame is stopped with "
                                                                f"MegaLimitExceeded(0, {limit}), the transaction's result"
                                                                if crosses else "exactly what is left: kept, and the "
                                                                "transaction succeeds"),
                 boundary=f"the log {'one byte over' if crosses else 'at'} what the start and the hints left",
                 system=True, spec=spec, stops=True, gas=8_000_000, value=1,
                 code=hints_leaving(left, kept) + log(0, 0, 0, []) + STOP))

    # Applied authorities' state growth counts on the transaction, not on a frame (SATIN-LIM-002): two absent
    # authorities, 501 fresh slots of the first frame, then a call that starts a child, all within the limits.
    slots = 501
    add(Case("satin/limit-stops/pre-frame-growth/two-authorities-then-child", "an EIP-7702 transaction applies two "
             f"authorities the state holds no account for, two units of state growth before the first frame, which "
             f"writes {slots} fresh slots and then calls a contract that stops: the transaction's state growth is "
             f"{slots + 2}, within its limit {fmt(model.TX_STATE_GROWTH_LIMIT)}, and the child's start keeps nothing, "
             "so it is not stopped, and the transaction returns the call's empty return data", system=True, spec=spec,
             stops=True, ty=4,
             gas=100_000_000, authorizations=[(AUTH_KEY, CHAIN_ID, PLAIN, 0), (SECOND_AUTH_KEY, CHAIN_ID, PLAIN, 0)],
             accounts={PLAIN: model.Account(nonce=1, code=STOP)},
             code=b"".join(sstore(k, 1) for k in range(1, slots + 1)) + call(MAX_GAS, PLAIN, 0, 0) + RETURN_RETURNDATA))
    return out


THIRD_AUTH_KEY = 0x6E5D4C3B2A1908F7E6D5C4B3A29180706F5E4D3C2B1A0908F7E6D5C4B3A29181
THIRD_AUTHORITY = ex.address_of(THIRD_AUTH_KEY)


def balance_of(address: bytes) -> bytes:
    """BALANCE of `address`, its result dropped: the frame pays the account's access, warm or cold."""
    return push(int.from_bytes(address, "big")) + b"\x31\x50"


def authorization_cases() -> list[Case]:
    out: list[Case] = []
    spec = FILL_SPEC

    def add(name: str, intent: str, **kw) -> None:
        kw.setdefault("ty", 4)
        kw.setdefault("gas", 300_000)
        out.append(Case(f"satin/authorizations/{name}", intent, spec=spec, lists=True, **kw))

    funded = {AUTHORITY: model.Account(balance=1)}
    probe = balance_of(AUTHORITY) + STOP
    warm, cold = model.WARM_READ, model.COLD_ACCOUNT_ACCESS
    base = model.PER_AUTH_BASE_COST

    # The gates of SATIN-AUTH-002: an entry they skip reads nothing and warms nothing (SATIN-AUTH-014), and pays its
    # PER_AUTH_BASE_COST alone (SATIN-AUTH-007, SATIN-SCHED-007). The frame's BALANCE of the authority shows its warmth.
    for name, entry, why in (
            ("chain-id-other", (AUTH_KEY, 2, CONTRACT, 0), "signed for chain 2"),
            ("nonce-max", (AUTH_KEY, CHAIN_ID, CONTRACT, model.MAX_U64), "whose nonce is 2^64 - 1"),
            ("signature-recovers-nothing", (AUTH_KEY, CHAIN_ID, CONTRACT, 0, UNRECOVERABLE),
             "whose signature, all zero, recovers no authority")):
        add(f"gates/{name}", f"an entry {why} is skipped before any authority is read: it pays its PER_AUTH_BASE_COST "
            f"{fmt(base)} and nothing else, the authority its key signs for keeps its account as it was, and the frame's "
            f"BALANCE of that account pays the cold access, {fmt(cold)}", authorizations=[entry], accounts=funded,
            code=probe)
    add("gates/chain-id-zero", "the gates' control: an entry for chain id zero passes the chain-id gate and is applied, "
        f"its existing authority loaded and warm, so the frame's BALANCE of it pays the warm read, {fmt(warm)}",
        authorizations=[(AUTH_KEY, 0, CONTRACT, 0)], accounts=funded, code=probe)

    # SATIN-AUTH-003: an authority whose code is not a delegation indicator is loaded and skipped, and warm.
    add("code/contract-authority", "an entry at its authority's nonce whose authority holds code other than a delegation "
        "indicator: the authority is loaded with its code and the entry is skipped, its nonce not bumped and nothing "
        f"charged; the application loaded it, so the frame's BALANCE of it pays the warm read, {fmt(warm)}",
        authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 1)],
        accounts={AUTHORITY: model.Account(nonce=1, balance=1, code=STOP)}, code=probe)
    add("code/delegated-authority", "the control: an authority that holds a delegation indicator is no contract, and its "
        "entry is applied, delegating it again; holding an indicator at the start of the transaction, it is charged no "
        "indicator state gas, but its ACCOUNT_WRITE and its write record", authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 1)],
        accounts={AUTHORITY: model.Account(nonce=1, balance=1, code=model.DELEGATION_PREFIX + DELEGATE)}, code=probe)
    # SATIN-AUTH-004 and -014: a nonce that does not match skips the entry after the load, which warms the authority.
    add("nonce/mismatch", "an entry whose nonce, 1, is not its existing authority's, 0: skipped and nothing charged, the "
        f"authority's nonce unchanged; the application loaded it first, so the frame's BALANCE of it pays the warm read, "
        f"{fmt(warm)}", authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 1)], accounts=funded, code=probe)

    # The sender's own authorization (SATIN-AUTH-004, -008, -015).
    add("sender/own-entry", "the sender's own authorization at its nonce after validation's bump, 1: applied, the sender "
        "holding the delegation indicator at nonce 2; it is charged the indicator's state gas, but no ACCOUNT_WRITE, "
        "which validation paid, and it makes no write record, its account being a fixed record of the body",
        authorizations=[(KEY, CHAIN_ID, DELEGATE, 1)])
    add("sender/own-entry-before-bump", "the sender's own authorization signed for its nonce before the transaction, 0: "
        "its effective nonce is validation's bump, 1, so the entry is skipped; the sender keeps that bump alone and no "
        "code", authorizations=[(KEY, CHAIN_ID, DELEGATE, 0)])
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    add("sender/own-entry-not-detained", "the sender's own authorization applied, the block beneficiary another account: "
        "SATIN-DET-008 detains a transaction from its start for an applied authority that is the beneficiary, which the "
        f"sender is not, so the frame's one memory expansion past the {fmt(cap)} cap completes and the transaction "
        "succeeds", authorizations=[(KEY, CHAIN_ID, DELEGATE, 1)], code=over_cap(cap) + STOP, gas=21_500_000)

    # The first frame's start record when the list keeps no authority record: the reservoir pays it whole, and a halt
    # returns that part to the reservoir (SATIN-HIST-005).
    body = (model.TX_BODY_SIZE + model.AUTHORIZATION_SIZE) * model.COST_PER_HISTORY_BYTE
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    add("start-record/reservoir-pays-it-whole", "a value call to a contract that halts, whose one entry, for chain 2, is "
        "skipped by its gate and keeps no authority record: the reservoir, after the body's history, pays the first "
        f"frame's start record, {fmt(record)}, whole, before the authorities' records, of which there are none, and the "
        "halt returns that part to the reservoir and to the sender (SATIN-HIST-005)",
        authorizations=[(AUTH_KEY, 2, CONTRACT, 0)], accounts=funded, value=1, code=INVALID,
        gas=model.EXECUTION_CAP + body + record + 1_000)

    # The frame of an applied list's transaction: its sender as ORIGIN, its effective price as GASPRICE.
    env = b"\x32" + push(0) + b"\x52" + b"\x3a" + push(32) + b"\x52" + ret(0, 64)
    add("frame/origin-and-gas-price", "an applied list's transaction runs its frame with its sender as ORIGIN and its "
        "effective gas price, the base fee and the priority fee, as GASPRICE, which the frame returns, as the base "
        "layer has them (SATIN-BASE-001)",
        authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)], accounts=funded, code=env, max_priority=1_000,
        max_fee=5_000_000, base_fee=1_000_000)

    # The list's totals at the state-growth limit (SATIN-AUTH-008, -010): new authorities exactly at the limit fit, and
    # entries that keep nothing more leave the total there; one more new authority skips the whole list.
    growth = model.TX_STATE_GROWTH_LIMIT
    fresh = [(LIST_KEY + i, CHAIN_ID, bytes(20), 0) for i in range(growth)]
    held = model.EXECUTION_CAP * 2
    add("limit/at-growth-limit", f"an EIP-7702 list of {fmt(growth)} entries, each signed by an authority the state holds "
        f"no account for, with a zero delegation target: its state-growth total is the transaction's limit, {fmt(growth)}, "
        "which it does not exceed, so the list fits and is applied, each authority created at nonce 1 with no code and "
        "charged its new-account state gas, its ACCOUNT_WRITE and its write record, and no indicator",
        boundary=f"the list's state-growth total at the limit, {fmt(growth)}",
        authorizations=fresh, to=EOA, code=b"", gas=held)
    existing = {SECOND_AUTHORITY: model.Account(), AUTHORITY: model.Account(balance=1),
                THIRD_AUTHORITY: model.Account(nonce=1, code=model.DELEGATION_PREFIX + DELEGATE)}
    add("limit/at-limit-existing-authorities", f"the {fmt(growth)} new authorities at the limit, after three accepted "
        "entries whose authorities the state holds: an empty leaf, an account with a balance, and one holding a "
        "delegation, which the third entry clears: an authority whose account the state holds is no rise, empty under "
        "EIP-161 or not (SATIN-STATE-011, SATIN-ACCT-015), so the total stays at the limit and the whole list is applied",
        boundary=f"the list's state-growth total at the limit, {fmt(growth)}",
        authorizations=[(SECOND_AUTH_KEY, CHAIN_ID, bytes(20), 0), (AUTH_KEY, CHAIN_ID, bytes(20), 0),
                        (THIRD_AUTH_KEY, CHAIN_ID, bytes(20), 1)] + fresh,
        accounts=existing, to=EOA, code=b"", gas=held)
    spare = [LIST_KEY + growth + i for i in range(4)]  # authorities the state holds no account for, besides the list's
    add("limit/at-limit-entries-adding-nothing", f"the {fmt(growth)} new authorities at the limit, with five more entries "
        "for authorities the state holds no account for that keep nothing: one signed for chain 2, one at nonce 2^64 - "
        "1, one whose signature recovers nothing, one whose nonce, 1, does not match, and a second entry for one of the "
        "list's authorities, accepted at nonce 1 but counted once: the total stays at the limit and the list is applied",
        boundary=f"the list's state-growth total at the limit, {fmt(growth)}",
        authorizations=[(spare[0], 2, bytes(20), 0), (spare[1], CHAIN_ID, bytes(20), model.MAX_U64),
                        (spare[2], CHAIN_ID, bytes(20), 0, UNRECOVERABLE), (spare[3], CHAIN_ID, bytes(20), 1)]
        + fresh + [(LIST_KEY, CHAIN_ID, bytes(20), 1)], to=EOA, code=b"", gas=held)
    add("limit/one-over-all-or-nothing", f"an existing authority's entry and the sender's own, each of which would fit "
        f"by itself, before {fmt(growth + 1)} entries for new authorities: the list's state-growth total crosses the "
        f"transaction's limit of {fmt(growth)}, so none of it is applied, the existing authority and the sender among "
        "them: the sender keeps validation's bump alone, nothing is charged beyond the intrinsic gas and the body's "
        f"history, and the transaction, included, has its own frame stopped with MegaLimitExceeded(3, {fmt(growth)})",
        boundary=f"the list's state-growth total one past the limit, {fmt(growth + 1)}", stops=True,
        authorizations=[(AUTH_KEY, CHAIN_ID, DELEGATE, 0), (KEY, CHAIN_ID, DELEGATE, 1)]
        + [(LIST_KEY + i, CHAIN_ID, bytes(20), 0) for i in range(growth + 1)],
        accounts=funded, to=EOA, code=b"", gas=20_000_000)

    # The simulation of a short list, its loads in the reads (SATIN-AUTH-001, -002, -005).
    three = {AUTHORITY: model.Account(balance=1), SECOND_AUTHORITY: model.Account(balance=1),
             THIRD_AUTHORITY: model.Account(balance=1)}
    add("reads/short-list-out-of-gas", "a three-entry list, too short to cross a limit, whose first entry's ACCOUNT_WRITE, "
        f"{fmt(model.ACCOUNT_WRITE)}, is one gas beyond the regular gas left: the transaction runs out of gas before its "
        "first frame with nothing of the list applied, but the list was simulated all the same, so the first and the "
        "third authorities are in the reads; the second entry, signed for chain 2, is skipped before its authority is "
        "read, which is not in the reads, and neither is the recipient", reads=True, to=EOA, code=b"", gas=500_000,
        authorizations=[(AUTH_KEY, CHAIN_ID, DELEGATE, 0), (SECOND_AUTH_KEY, 2, DELEGATE, 0),
                        (THIRD_AUTH_KEY, CHAIN_ID, DELEGATE, 0)], accounts=three, tune=("list", model.ACCOUNT_WRITE - 1))

    # The caller a deposit creates is no authorization (SATIN-AUTH-017): it is new by EIP-161 emptiness, not existence.
    add("deposit-caller/empty-leaf", "a deposit whose caller's leaf the state holds, empty under EIP-161: the caller a "
        "deposit creates is no authorization, so it is decided by emptiness, not by an authority's existence, and is "
        "new: its new-account state gas and one unit of state growth, and no ACCOUNT_WRITE, write record or list rule",
        ty=0, deposit=(ETH, 1_000_000), absent_sender=True, accounts={OTHER: model.Account()})
    out += authorization_gap_cases()
    return out


# The edges an independent review of the cases above listed as unpinned (D-88), each numbered by the gap it closes.
REVERTER = bytes.fromhex("00000000000000000000000000000000000c0e07")  # a delegate whose code reverts at once
SECOND_TARGET = PLAIN  # a second delegation target, besides DELEGATE


def authorization_gap_cases() -> list[Case]:
    out: list[Case] = []
    spec = FILL_SPEC

    def add(name: str, intent: str, **kw) -> None:
        kw.setdefault("ty", 4)
        kw.setdefault("gas", 300_000)
        out.append(Case(f"satin/authorizations/{name}", intent, spec=spec, lists=True, **kw))

    D, E, zero = DELEGATE, SECOND_TARGET, bytes(20)
    funded = {AUTHORITY: model.Account(balance=1)}
    both = {AUTHORITY: model.Account(balance=1), SECOND_AUTHORITY: model.Account(balance=1)}
    cold, warm = model.COLD_ACCOUNT_ACCESS, model.WARM_READ
    indicator = model.DELEGATION_STATE_BYTES * model.COST_PER_STATE_BYTE
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    write = model.ACCOUNT_WRITE
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    growth = model.TX_STATE_GROWTH_LIMIT

    # 1. An out-of-gas before the first frame after an authorization was applied takes it back (SATIN-SCHED-009, -010).
    delegated = {EOA: model.Account(nonce=1, code=model.DELEGATION_PREFIX + D), D: model.Account(nonce=1, code=STOP)}
    for short in (True, False):
        left = cold - 1 if short else cold
        add(f"rollback/sender-entry-delegate-access-{'short' if short else 'paid'}", "the sender's own authorization is "
            "applied, with its indicator's state gas, and the transaction's recipient delegates to an account that is not "
            f"warm, whose access, {fmt(cold)}, the regular gas left " + (
                "cannot pay by one: the transaction runs out of gas before its first frame, and the sender's authorization "
                "is taken back with its state gas, the sender left at validation's nonce and with no code"
                if short else "pays exactly: the frame runs, and the sender keeps its authorization"),
            boundary=f"the regular gas at the delegate's access {'one below' if short else 'at'} {fmt(cold)}",
            to=EOA, code=b"", accounts=delegated, authorizations=[(KEY, CHAIN_ID, D, 1)], gas=200_000,
            tune=("delegate", left))
    add("rollback/second-write-short", f"two entries by existing authorities: the first is applied, its ACCOUNT_WRITE and "
        f"indicator paid, and the second's ACCOUNT_WRITE, {fmt(write)}, is one gas beyond the regular gas left: the "
        "transaction runs out of gas before its first frame, and the first authorization is taken back",
        boundary=f"the regular gas at the second ACCOUNT_WRITE one below {fmt(write)}", to=EOA, code=b"",
        accounts=both, authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (SECOND_AUTH_KEY, CHAIN_ID, D, 0)], gas=200_000,
        tune=("write:1", write - 1))
    add("rollback/indicator-short", f"an existing authority's ACCOUNT_WRITE is paid, and its indicator's state gas, "
        f"{fmt(indicator)}, is one gas beyond the regular gas left: the transaction runs out of gas before its first "
        "frame, and the authorization is taken back", boundary=f"the regular gas at the indicator one below {fmt(indicator)}",
        to=EOA, code=b"", accounts=funded, authorizations=[(AUTH_KEY, CHAIN_ID, D, 0)], gas=200_000,
        tune=("indicator:0", indicator - 1))
    add("rollback/records-history-short", "an existing authority's step-2 charges are paid, and the history of its write "
        f"record, {fmt(record)}, charged at step 3 after every entry's step-2 charges, is one gas beyond the regular gas "
        "left: the transaction runs out of gas before its first frame, and the authorization is taken back",
        boundary=f"the regular gas at the records' history one below {fmt(record)}", to=EOA, code=b"",
        accounts=funded, authorizations=[(AUTH_KEY, CHAIN_ID, D, 0)], gas=200_000, tune=("records", record - 1))

    # 2. The authority that is also the transaction's value recipient (SATIN-ACCT-009, SATIN-AUTH-015).
    add("overlap/value-to-existing-authority", "the example of SATIN-AUTH-015: 1 wei to an existing account B whose one "
        "authorization carries its nonce and a zero target: before its first frame the transaction pays its intrinsic "
        "gas, the entry and the history of the body, the entry and B's one write record, which the value to B does not "
        "make again, and no ACCOUNT_WRITE, indicator or new-account state gas; the transfer log stays",
        to=AUTHORITY, value=1, accounts=funded, authorizations=[(AUTH_KEY, CHAIN_ID, zero, 0)])
    add("overlap/value-to-absent-authority", "1 wei to an account the state holds no account for, whose one authorization "
        "creates it: its new-account state gas once, at its authorization, and the value's start finds it no longer "
        "empty, so no second new-account charge, no second record and no ACCOUNT_WRITE",
        to=AUTHORITY, value=1, authorizations=[(AUTH_KEY, CHAIN_ID, zero, 0)])
    add("overlap/value-to-authority-frame-reverts", "1 wei to an existing account whose authorization delegates it to a "
        "contract that reverts: the frame runs that code and reverts, taking back the value and its transfer log, and the "
        "authority keeps its nonce, its delegation, its indicator's state gas and its one write record, which the value "
        "did not make", to=AUTHORITY, value=1,
        accounts={AUTHORITY: model.Account(balance=1), REVERTER: model.Account(nonce=1, code=revert(0, 0))},
        authorizations=[(AUTH_KEY, CHAIN_ID, REVERTER, 0)])

    # 3. The indicator's charge across several accepted entries for one authority (SATIN-AUTH-009).
    held = model.Account(nonce=1, balance=1, code=model.DELEGATION_PREFIX + D)
    add("indicator/held-clear-then-set", "an authority holding an indicator at the start is cleared and then delegated "
        "again: no indicator state gas, the clear notwithstanding; one ACCOUNT_WRITE and one record; nonce 3, delegating "
        "to the second target", to=EOA, code=b"", accounts={AUTHORITY: held},
        authorizations=[(AUTH_KEY, CHAIN_ID, zero, 1), (AUTH_KEY, CHAIN_ID, E, 2)])
    add("indicator/absent-set-clear-set", f"an absent authority set, cleared and set again: one new-account charge, one "
        f"indicator charge of {fmt(indicator)}, the clear not erasing that the list paid for an indicator; one record, one "
        "unit of growth, nonce 3, delegating to the last target", to=EOA, code=b"", gas=1_000_000,
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (AUTH_KEY, CHAIN_ID, zero, 1), (AUTH_KEY, CHAIN_ID, E, 2)])
    add("indicator/absent-clear-then-set", f"an absent authority cleared and then set: the clear marks no indicator as "
        f"paid, so the set charges its {fmt(indicator)}", to=EOA, code=b"", gas=1_000_000,
        authorizations=[(AUTH_KEY, CHAIN_ID, zero, 0), (AUTH_KEY, CHAIN_ID, D, 1)])
    add("indicator/existing-set-then-set", "an existing authority without an indicator delegated twice: one indicator "
        "charge, the second entry applied, its target the last", to=EOA, code=b"", accounts=funded,
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (AUTH_KEY, CHAIN_ID, E, 1)])

    # 4. The simulation walks on past the entry that crosses the limit (SATIN-AUTH-005).
    third_code = {THIRD_AUTHORITY: model.Account(nonce=1, code=STOP)}
    add("reads/simulation-past-crossing", f"{fmt(growth + 1)} entries for new authorities, then an entry by an existing "
        "authority holding code other than a delegation: the list's state-growth total crosses at its last new authority, "
        "the list is skipped and the frame stopped, and the simulation, walking the whole list, still loads the last "
        "authority with its code, which the reads hold; the transaction is sent to its own sender, which validation loads, "
        "so the reads do not turn on whether a skipped list's transaction makes the recipient's load of step 4 (D-89)",
        reads=True, stops=True, to=SENDER, code=None, gas=20_000_000,
        accounts=third_code, authorizations=[(LIST_KEY + i, CHAIN_ID, zero, 0) for i in range(growth + 1)]
        + [(THIRD_AUTH_KEY, CHAIN_ID, zero, 1)])

    # 5. A first frame that reverts after the list applied (SATIN-AUTH-016).
    add("revert/sender-entry", "the sender's own authorization applied, and the first frame reverts: the sender keeps nonce "
        "2 and its delegation, and the indicator's state gas stays charged", authorizations=[(KEY, CHAIN_ID, D, 1)],
        code=revert(0, 0))
    add("revert/absent-authority-with-slot", "an absent authority applied, and the first frame writes a fresh slot and "
        "reverts: the slot is discarded, and the authority keeps nonce 1, its delegation, its new-account and indicator "
        "state gas, its write record and its history, and its unit of growth",
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0)], code=sstore(1, 1) + revert(0, 0), gas=1_000_000)

    # 6. The simulation's gates and code load, observed in the reads of a list that runs out of gas at its first entry.
    add("reads/short-list-gates-and-code", f"a four-entry list whose first entry's ACCOUNT_WRITE, {fmt(write)}, is one gas "
        "beyond the regular gas left; its other entries are an existing authority at nonce 2^64 - 1, an entry whose "
        "signature recovers nothing, and an authority holding code other than a delegation: the reads hold the first "
        "authority and the last, with its code, and not the second, nor any account for the third, nor the recipient",
        reads=True, to=EOA, code=b"", gas=500_000,
        accounts={AUTHORITY: model.Account(balance=1), SECOND_AUTHORITY: model.Account(balance=1),
                  THIRD_AUTHORITY: model.Account(nonce=1, code=STOP)},
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (SECOND_AUTH_KEY, CHAIN_ID, D, model.MAX_U64),
                        (LIST_KEY + 3 * growth, CHAIN_ID, D, 0, UNRECOVERABLE), (THIRD_AUTH_KEY, CHAIN_ID, D, 1)],
        tune=("list", write - 1))

    # 7. A rejected entry does not move the effective nonce; a stale one after an acceptance is rejected (SATIN-AUTH-004).
    add("nonce/early-and-stale-entries", "four entries for one existing authority at nonce 0, at nonces 1, 0, 0 and 1: "
        "rejected, accepted, rejected as stale, accepted; it ends at nonce 2 with no code, having paid one ACCOUNT_WRITE, "
        "one record and one indicator, the last entry clearing it", to=EOA, code=b"", accounts=funded, gas=20_000_000,
        authorizations=[(AUTH_KEY, CHAIN_ID, E, 1), (AUTH_KEY, CHAIN_ID, D, 0), (AUTH_KEY, CHAIN_ID, E, 0),
                        (AUTH_KEY, CHAIN_ID, zero, 1)])
    add("sender/own-entries-in-sequence", "the sender's own entries at nonces 0, 1 and 2 against a transaction at nonce 0: "
        "the first is skipped, its nonce before validation's bump, and the other two are applied: the sender ends at "
        "nonce 3 delegating to the last target, with one indicator charge and no ACCOUNT_WRITE or record",
        authorizations=[(KEY, CHAIN_ID, D, 0), (KEY, CHAIN_ID, D, 1), (KEY, CHAIN_ID, E, 2)])

    # 8. The last nonce an authorization can carry (SATIN-AUTH-002, -004).
    add("nonce/last-valid", "an existing authority at nonce 2^64 - 2 authorized at that nonce, then at 2^64 - 1: the first "
        "entry is applied, the authority ending at nonce 2^64 - 1, and the second is skipped by its gate, the first target "
        "staying", to=EOA, code=b"", accounts={AUTHORITY: model.Account(nonce=model.MAX_U64 - 1, balance=1)},
        authorizations=[(AUTH_KEY, CHAIN_ID, D, model.MAX_U64 - 1), (AUTH_KEY, CHAIN_ID, E, model.MAX_U64)])

    # 9. An authority that is the block beneficiary detains only when its entry is applied (SATIN-DET-008).
    for name, entry, why in (("skipped", (AUTH_KEY, CHAIN_ID, D, 1), "whose nonce does not match: loaded and warm, "
                              "not applied"),
                             ("gated", (AUTH_KEY, 2, D, 0), "for chain 2: skipped unread")):
        add(f"beneficiary/{name}-authority-not-detained", f"the block beneficiary's entry {why}: SATIN-DET-008 detains for "
            "an applied authority that is the beneficiary, so the frame's one memory expansion past the "
            f"{fmt(cap)} cap completes", coinbase=AUTHORITY, accounts=funded, authorizations=[entry],
            code=over_cap(cap) + STOP, gas=21_500_000)

    # 10. The authority's own bucket prices both of its state charges (SATIN-AUTH-008, -009, SATIN-STATE-003).
    add("salt/authority-bucket-prices", "an absent authority whose account bucket has twice the minimum capacity, "
        "delegating twice to an account whose bucket has three times it: the new account and the indicator are each "
        "priced at the authority's multiplier, 2, and charged once; ACCOUNT_WRITE and the record's history do not scale",
        to=EOA, code=b"", salt={(AUTHORITY, None): 2, (D, None): 3}, gas=1_000_000,
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (AUTH_KEY, CHAIN_ID, D, 1)])

    # 11. The reservoir pays the start record in part after the authority's record (SATIN-HIST-005).
    body = (model.TX_BODY_SIZE + model.AUTHORIZATION_SIZE) * model.COST_PER_HISTORY_BYTE
    add("start-record/reservoir-pays-one", f"a value call to a contract that halts, with a reservoir that pays the body's "
        f"history, the indicator and the authority's record, and 1 of the first frame's start record, whose other "
        f"{fmt(record - 1)} regular gas pays: the halt returns that 1 to the reservoir and keeps the authority's record "
        "(SATIN-HIST-005)", accounts=funded, authorizations=[(AUTH_KEY, CHAIN_ID, D, 0)], value=1, code=INVALID,
        gas=model.EXECUTION_CAP + body + indicator + record + 1)

    # 12. The application warms the authority it loads, not the target its entry names (SATIN-AUTH-014).
    add("warmth/target-not-warmed", f"an applied authority delegating to an account the transaction does not otherwise "
        f"touch: the frame's BALANCE of that target pays the cold access, {fmt(cold)}, and its BALANCE of the authority "
        f"the warm read, {fmt(warm)}", accounts=funded, authorizations=[(AUTH_KEY, CHAIN_ID, D, 0)],
        code=balance_of(D) + balance_of(AUTHORITY) + STOP)

    # 13. A skipped list's settlement at a non-zero price (SATIN-AUTH-011, -013, -018).
    add("limit/one-over-with-fees", f"the skipped list of one-over-all-or-nothing at a base fee of 1 and a priority fee of "
        "1: the sender pays the intrinsic gas and the body's history at 2 wei, the base fee vault and the beneficiary each "
        "receive 1 wei of it, and the rest of the gas limit returns", stops=True, base_fee=1, max_priority=1, max_fee=2,
        boundary=f"the list's state-growth total one past the limit, {fmt(growth + 1)}",
        authorizations=[(AUTH_KEY, CHAIN_ID, D, 0), (KEY, CHAIN_ID, D, 1)]
        + [(LIST_KEY + i, CHAIN_ID, zero, 0) for i in range(growth + 1)],
        accounts=funded, to=EOA, code=b"", gas=20_000_000)

    # 14. Signatures that recover no authority beyond the all-zero one (SATIN-AUTH-002).
    for name, mode, why in (("y-parity-two", Y_PARITY_TWO, "a y_parity of 2, outside 0 and 1"),
                            ("r-at-order", R_AT_ORDER, "an r equal to secp256k1's order, the excluded bound")):
        add(f"gates/{name}", f"an entry whose signature has {why}, its other fields those of a valid signature by an "
            "existing account, recovers no authority: it is skipped and that account is not loaded, so the frame's "
            f"BALANCE of it pays the cold access, {fmt(cold)}; the valid entry after it is applied",
            accounts=both, authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0, mode), (SECOND_AUTH_KEY, CHAIN_ID, CONTRACT, 0)],
            code=balance_of(AUTHORITY) + STOP)
    return out


# --- Assembling a case --------------------------------------------------------------------------


# --- The outcomes page and the order of validation's refusals (D-85) ----------------------------------

# The SequencerRegistry's runtime code at version 2.0.0, whose keccak256 is the specification's
# SEQUENCER_REGISTRY_CODE_HASH (docs/spec/satin/system-contracts/overview.md), read from the revm-based
# implementation's versioned artifacts at its pin (crates/system-contracts/artifacts/SequencerRegistry-2.0.0.json).
# A case that resolves a live system address holds it at the registry's address (D-87).
SEQUENCER_REGISTRY_CODE = bytes.fromhex(
    "608060405234801561000f575f5ffd5b50600436106100e5575f3560e01c806354fd4d5011610088578063de7a36af11610063578063de7a"
    "36af146101f7578063e3093f5014610214578063e812903014610227578063f851a44014610245575f5ffd5b806354fd4d501461019d5780"
    "6375829def146101dc578063c7455c42146101ef575f5ffd5b80632b659fd8116100c35780632b659fd81461014e5780633411f3c3146101"
    "6157806344d744591461017457806348a2cf6d1461017c575f5ffd5b80630e18b681146100e9578063129c8240146100f357806326782247"
    "14610130575b5f5ffd5b6100f1610263565b005b610106610101366004611274565b610336565b60405173ffffffffffffffffffffffffff"
    "ffffffffffffff90911681526020015b60405180910390f35b60035473ffffffffffffffffffffffffffffffffffffffff16610106565b61"
    "00f161015c3660046112b3565b61045c565b6100f161016f366004611336565b6107e1565b6100f1610a91565b61018f61018a3660046113"
    "36565b610aa3565b604051908152602001610127565b604080518082018252600581527f322e302e30000000000000000000000000000000"
    "00000000000000000000000060208201529051610127919061135e565b6100f16101ea3660046113b1565b610c5b565b600d5461018f565b"
    "5f5473ffffffffffffffffffffffffffffffffffffffff16610106565b610106610222366004611274565b610d0b565b60015473ffffffff"
    "ffffffffffffffffffffffffffffffff16610106565b60025473ffffffffffffffffffffffffffffffffffffffff16610106565b60035473"
    "ffffffffffffffffffffffffffffffffffffffff163381146102b5576040517f058d9a1b0000000000000000000000000000000000000000"
    "0000000000000000815260040160405180910390fd5b6002805473ffffffffffffffffffffffffffffffffffffffff8381167fffffffffff"
    "ffffffffffffff00000000000000000000000000000000000000008084168217909455600380549094169093556040519116919082907ff8"
    "ccb027dfcd135e000e9d45e6cc2d662578a8825d4c45b5e32e0adf67e79ec6905f90a35050565b5f43821115610371576040517fdbe289ad"
    "00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6006548210156103ad576040517f"
    "d2c461b000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600c54805b801561043b"
    "575f600c6103c66001846113fe565b815481106103d6576103d6611411565b5f91825260209091200180549091506bffffffffffffffffff"
    "ffffff16851061042857546c01000000000000000000000000900473ffffffffffffffffffffffffffffffffffffffff1694935050505056"
    "5b50806104338161143e565b9150506103b2565b505060055473ffffffffffffffffffffffffffffffffffffffff1692915050565b610464"
    "610e31565b43831161049d576040517fc2fdad04000000000000000000000000000000000000000000000000000000008152600401604051"
    "80910390fd5b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff83036105cd5773ffffffffffffffffffff"
    "ffffffffffffffffffff841615610512576040517fd92e233d00000000000000000000000000000000000000000000000000000000815260"
    "040160405180910390fd5b600980547fffffffffffffffffffffffff00000000000000000000000000000000000000001690555f600a8190"
    "5560015473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f7ac0520c61d87c"
    "77ffc308e23c801f5a351140175ec3f6356a3a890aa0cfdbf97fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffff6040516105c091815260200190565b60405180910390a36107db565b6bffffffffffffffffffffffff831115610613576040517f9d73"
    "78d300000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b73ffffffffffffffffffffff"
    "ffffffffffffffffff8416610660576040517fd92e233d000000000000000000000000000000000000000000000000000000008152600401"
    "60405180910390fd5b600d5461066d9043611472565b8310156106a6576040517f11ede46e00000000000000000000000000000000000000"
    "000000000000000000815260040160405180910390fd5b5f6106bb6106b48686610aa3565b8484610e82565b90508473ffffffffffffffff"
    "ffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610722576040517fe415bbae00000000000000"
    "000000000000000000000000000000000000000000815260040160405180910390fd5b6009805473ffffffffffffffffffffffffffffffff"
    "ffffffff87167fffffffffffffffffffffffff00000000000000000000000000000000000000009091168117909155600a85905561078a60"
    "015473ffffffffffffffffffffffffffffffffffffffff1690565b73ffffffffffffffffffffffffffffffffffffffff167f7ac0520c61d8"
    "7c77ffc308e23c801f5a351140175ec3f6356a3a890aa0cfdbf9866040516107d191815260200190565b60405180910390a3505b50505050"
    "565b6107e9610e31565b438111610822576040517fc2fdad0400000000000000000000000000000000000000000000000000000000815260"
    "040160405180910390fd5b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81036109505773ffffffffff"
    "ffffffffffffffffffffffffffffff821615610897576040517fd92e233d0000000000000000000000000000000000000000000000000000"
    "0000815260040160405180910390fd5b600780547fffffffffffffffffffffffff0000000000000000000000000000000000000000169055"
    "5f6008819055805473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167fd839b7"
    "efbcae2bd482a7aa1c098265fdb6b43c10e3e5138a8fa2b395a02eb9157fffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffff60405161094491815260200190565b60405180910390a35050565b6bffffffffffffffffffffffff81111561099657604051"
    "7f9d7378d300000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b73ffffffffffffffff"
    "ffffffffffffffffffffffff82166109e3576040517fd92e233d000000000000000000000000000000000000000000000000000000008152"
    "60040160405180910390fd5b6007805473ffffffffffffffffffffffffffffffffffffffff84167fffffffffffffffffffffffff00000000"
    "0000000000000000000000000000000090911681179091556008829055610a4a5f5473ffffffffffffffffffffffffffffffffffffffff16"
    "90565b73ffffffffffffffffffffffffffffffffffffffff167fd839b7efbcae2bd482a7aa1c098265fdb6b43c10e3e5138a8fa2b395a02e"
    "b9158360405161094491815260200190565b610a9961108c565b610aa1611181565b565b604080518082018252601981527f4d6567614554"
    "482053657175656e63657252656769737472790000000000000060209182015281518083018352600181527f310000000000000000000000"
    "00000000000000000000000000000000000000009082015281517f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b"
    "39400f818301527f85da835bd1cf371efdb3f9056e5a3a6245af1400fa0ce2e878a198765a4eb9c2818401527fc89efdaa54c0f20c7adf61"
    "2882df0950f5a951637e0307cdcb4c672f298b8bc660608201524660808201523060a0808301919091528351808303909101815260c08201"
    "84528051908301207faebf84f20bcc14afc14200ed16cfb9314ef205d4d1d8fbcc0a256c39a3e79aa960e083015273ffffffffffffffffff"
    "ffffffffffffffffffffff861661010083015261012080830186905284518084039091018152610140830185528051908401207f19010000"
    "0000000000000000000000000000000000000000000000000000000061016084015261016283019190915261018280830191909152835180"
    "830390910181526101a290910190925281519101205b92915050565b610c63610e31565b6003805473ffffffffffffffffffffffffffffff"
    "ffffffffff83167fffffffffffffffffffffffff00000000000000000000000000000000000000009091168117909155610cc660025473ff"
    "ffffffffffffffffffffffffffffffffffffff1690565b73ffffffffffffffffffffffffffffffffffffffff167fe5cd1c804f1c9cc6d700"
    "9e4c0fb532f0e2d8863524c3323a6b3790c3f80bf25c60405160405180910390a350565b5f43821115610d46576040517fdbe289ad000000"
    "00000000000000000000000000000000000000000000000000815260040160405180910390fd5b600654821015610d82576040517fd2c461"
    "b000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600b54805b8015610e10575f60"
    "0b610d9b6001846113fe565b81548110610dab57610dab611411565b5f91825260209091200180549091506bffffffffffffffffffffffff"
    "168510610dfd57546c01000000000000000000000000900473ffffffffffffffffffffffffffffffffffffffff16949350505050565b5080"
    "610e088161143e565b915050610d87565b505060045473ffffffffffffffffffffffffffffffffffffffff1692915050565b60025473ffff"
    "ffffffffffffffffffffffffffffffffffff163314610aa1576040517f7bfa4b9f0000000000000000000000000000000000000000000000"
    "0000000000815260040160405180910390fd5b5f60418214610ebd576040517fe415bbae0000000000000000000000000000000000000000"
    "0000000000000000815260040160405180910390fd5b5f610ecb6020828587611485565b610ed4916114ac565b90505f610ee56040602086"
    "88611485565b610eee916114ac565b90505f85856040818110610f0457610f04611411565b919091013560f81c9150507f7fffffffffffff"
    "ffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0821115610f69576040517fe415bbae00000000000000000000000000000000"
    "000000000000000000000000815260040160405180910390fd5b8060ff16601b14158015610f8157508060ff16601c14155b15610fb85760"
    "40517fe415bbae00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b604080515f8082"
    "52602082018084528a905260ff841692820192909252606081018590526080810184905260019060a0016020604051602081039080840390"
    "855afa158015611009573d5f5f3e3d5ffd5b50506040517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0"
    "015191505073ffffffffffffffffffffffffffffffffffffffff8116611081576040517fe415bbae00000000000000000000000000000000"
    "000000000000000000000000815260040160405180910390fd5b979650505050505050565b60075473ffffffffffffffffffffffffffffff"
    "ffffffffff16806110ad5750565b600854438111156110bc575050565b5f805473ffffffffffffffffffffffffffffffffffffffff938416"
    "7fffffffffffffffffffffffff000000000000000000000000000000000000000091821681178355604080518082019091526bffffffffff"
    "ffffffffffffff948516815260208101918252600b8054600181018255908552905191519095166c01000000000000000000000000029316"
    "929092177f0175b7a638427703f0dbe7bb9bbf987a2551717b34e79f33b5b1008d1fa01db990930192909255600780549091169055600855"
    "565b60095473ffffffffffffffffffffffffffffffffffffffff16806111a25750565b600a54438111156111b1575050565b6001805473ff"
    "ffffffffffffffffffffffffffffffffffffff9384167fffffffffffffffffffffffff000000000000000000000000000000000000000091"
    "821681178355604080518082019091526bffffffffffffffffffffffff948516815260208101918252600c805494850181555f9081529051"
    "91519095166c01000000000000000000000000029316929092177fdf6966c971051c3d54ec59162606531493a51404a002842f56009d7e5c"
    "f4a8c790910155600980549091169055600a55565b5f60208284031215611284575f5ffd5b5035919050565b803573ffffffffffffffffff"
    "ffffffffffffffffffffff811681146112ae575f5ffd5b919050565b5f5f5f5f606085870312156112c6575f5ffd5b6112cf8561128b565b"
    "935060208501359250604085013567ffffffffffffffff8111156112f1575f5ffd5b8501601f81018713611301575f5ffd5b803567ffffff"
    "ffffffffff811115611317575f5ffd5b876020828401011115611328575f5ffd5b949793965060200194505050565b5f5f60408385031215"
    "611347575f5ffd5b6113508361128b565b946020939093013593505050565b602081525f82518060208401528060208501604085015e5f60"
    "40828501015260407fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f83011684010191505092915050"
    "565b5f602082840312156113c1575f5ffd5b6113ca8261128b565b9392505050565b7f4e487b710000000000000000000000000000000000"
    "00000000000000000000005f52601160045260245ffd5b81810381811115610c5557610c556113d1565b7f4e487b71000000000000000000"
    "000000000000000000000000000000000000005f52603260045260245ffd5b5f8161144c5761144c6113d1565b507fffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffff0190565b80820180821115610c5557610c556113d1565b5f5f8585111561149357"
    "5f5ffd5b8386111561149f575f5ffd5b5050820193919092039150565b80356020831015610c55577fffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffff602084900360031b1b169291505056fea164736f6c634300081e000a")



# The High-Precision Timestamp's runtime code, the Oracle's address embedded, which SATIN-HPTS-001 names by
# HIGH_PRECISION_TIMESTAMP_CODE_HASH: read from the revm-based implementation (its system/timestamp.rs at the pin), and
# checked against the hash where a case's pre-state holds it (D-109).
HIGH_PRECISION_TIMESTAMP_CODE = bytes.fromhex(
    "608060405234801561000f575f5ffd5b5060043610610064575f3560e01c806382ab890a1161004d57806382ab890a146100f5578063"
    "8582b7bc1461010a578063b80777ea1461013f575f5ffd5b806328af7f3c146100685780633e6890fb146100a9575b5f5ffd5b61008f"
    "7f000000000000000000000000000000000000000000000000000000000000000881565b60405163ffffffff90911681526020015b60"
    "405180910390f35b6100d07f000000000000000000000000634200000000000000000000000000000000000181565b60405173ffffff"
    "ffffffffffffffffffffffffffffffffff90911681526020016100a0565b6101086101033660046103b6565b610147565b005b610131"
    "7f000000000000000000000000000000000000000000000000000000000000000081565b6040519081526020016100a0565b61013161"
    "0154565b6101515f82610165565b50565b5f5f61015f5f610245565b92915050565b8161016f8161031a565b73ffffffffffffffffff"
    "ffffffffffffffffffffff7f00000000000000000000000063420000000000000000000000000000000000011663fbc0d0356101d585"
    "7f00000000000000000000000000000000000000000000000000000000000000006103cd565b60405160e083901b7fffffffff000000"
    "000000000000000000000000000000000000000000000000001681526004810191909152602481018590526044015f60405180830381"
    "5f87803b15801561022a575f5ffd5b505af115801561023c573d5f5f3e3d5ffd5b50505050505050565b5f816102508161031a565b73"
    "ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000634200000000000000000000000000000000000116"
    "637eba7ba66102b6857f00000000000000000000000000000000000000000000000000000000000000006103cd565b6040518263ffff"
    "ffff1660e01b81526004016102d491815260200190565b602060405180830381865afa1580156102ef573d5f5f3e3d5ffd5b50505050"
    "6040513d601f19601f820116820180604052508101906103139190610405565b9392505050565b63ffffffff7f000000000000000000"
    "00000000000000000000000000000000000000000000081661034c8260016103cd565b10610151576040517fef94d842000000000000"
    "0000000000000000000000000000000000000000000081526004810182905263ffffffff7f0000000000000000000000000000000000"
    "00000000000000000000000000000816602482015260440160405180910390fd5b5f602082840312156103c6575f5ffd5b5035919050"
    "565b8082018082111561015f577f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260"
    "245ffd5b5f60208284031215610415575f5ffd5b505191905056fea2646970667358221220290614c973d24b9016b73a6b3fa98b2485"
    "a5c324199ceeb767818495dbe785e864736f6c634300081e0033")


CAUGHT = bytes.fromhex("00000000000000000000000000000000000c0e07")  # a child whose ending its caller catches
DUP1, CREATE = b"\x80", b"\xf0"
# ORIGIN and CHAINID laid out as two words of memory, then a REVERT of both.
ORIGIN_CHAIN_ID = b"\x32" + push(0) + b"\x52" + b"\x46" + push(32) + b"\x52"


def least_gas(c: Case) -> int:
    """The gas a case's transaction uses, derived on the gas limit it is given: the least gas limit that runs it as it ran,
    for a transaction with no reservoir, refund or binding floor."""
    _, result, _ = build(c)
    ledgers = result.observations["gasLedgers"]
    if int(ledgers["refund"], 16) or int(ledgers["floor"], 16) >= int(ledgers["total"], 16):
        raise SystemExit("least_gas: a refund or a binding floor")
    return int(ledgers["total"], 16)


def outcome_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = FILL_SPEC
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    history = model.COST_PER_HISTORY_BYTE
    record = model.WRITE_RECORD_SIZE * history
    body = model.TX_BODY_SIZE * history
    call_value = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + model.TX_VALUE_COST
    call_plain = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS

    # SATIN-OUT-002: gas detention's compute limit stops only the frame that crosses it, and its caller catches the
    # stop; the same charge beyond the child's whole regular gas is an out-of-gas, a halt (SATIN-OUT-007).
    child = log(0, 0, 0, []) + over_cap(cap) + STOP
    for stopped in (True, False):
        add(Case(f"satin/outcomes/stop/child-{'stopped-caught' if stopped else 'halted-control'}",
                 "the transaction's own frame writes a fresh slot, reads TIMESTAMP and calls a child that emits an empty "
                 f"LOG0 and then expands memory past the {fmt(cap)} the read's limit leaves the transaction; "
                 + ("forwarded all it may, the child's whole regular gas pays the expansion, so the charge is gas "
                    "detention's crossing: the child alone is stopped, its log discarded, and the caller catches the stop, "
                    "keeps its slot and returns the stop's bytes (SATIN-OUT-002)" if stopped else
                    f"forwarded {fmt(100_000)}, the child's whole regular gas cannot pay the expansion, so the charge is an "
                    "out-of-gas: the child halts and burns its forward, and the caller keeps its slot and returns empty "
                    "return data"),
                 boundary=f"the expansion {'within' if stopped else 'beyond'} the child's whole regular gas",
                 spec=spec, outcomes=True, gas=30_000_000,
                 code=sstore(1, 1) + b"\x42\x50" + call(MAX_GAS if stopped else 100_000, CAUGHT, 0, 0) + b"\x50"
                 + RETURN_RETURNDATA, accounts={CAUGHT: model.Account(nonce=1, code=child)}))

    # SATIN-OUT-008: a refused volatile read reverts the frame that made it; its caller catches the revert.
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
    add(Case("satin/outcomes/refused-read/child-reverts-caught", "the transaction's own frame switches its volatile-data "
             "access off and calls a child that writes a fresh slot and reads TIMESTAMP: the read is refused, and the child "
             "reverts with VolatileDataAccessDisabled(1), its slot taken back and its unspent gas returned; the caller "
             "catches the revert and returns its bytes (SATIN-OUT-008)", spec=spec, outcomes=True, system=True,
             code=disable + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50" + call(MAX_GAS, CAUGHT, 0, 0) + b"\x50"
             + RETURN_RETURNDATA, accounts={CAUGHT: model.Account(nonce=1, code=sstore(1, 1) + b"\x42" + STOP)}))

    # SATIN-OUT-009: a system contract's own refusal reverts with its own error.
    add(Case("satin/outcomes/system-refusal/not-intercepted", "a contract calls MegaLimitControl with a selector it has no "
             "method for: no interceptor answers it, the bytecode's fallback reverts with its own error NotIntercepted(), "
             "and the caller returns those bytes (SATIN-OUT-009)", spec=spec, outcomes=True, system=True,
             code=mstore(0, 0x12345678 << 224) + call(100_000, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-OUT-003, SATIN-SIZE-003: the size checks halt; neither is a limit stop.
    for over in (True, False):
        size = model.MAX_INITCODE_SIZE + (1 if over else 0)
        add(Case(f"satin/outcomes/size/create-initcode-{'over' if over else 'at'}-limit",
                 f"a CREATE of {fmt(size)} zero bytes of initcode, "
                 + (f"one over MAX_INITCODE_SIZE: the size check halts the frame at the opcode, before any charge, and the "
                    "transaction uses its whole gas limit (SATIN-OUT-003)" if over else
                    "MAX_INITCODE_SIZE exactly: the creation runs its initcode, which stops at once, and creates an account "
                    "with no code"),
                 boundary=f"the initcode {'one byte over' if over else 'at'} MAX_INITCODE_SIZE", spec=spec, outcomes=True,
                 gas=5_000_000, code=push(size) + push(0) + push(0) + CREATE + STOP))
    size = model.MAX_CONTRACT_SIZE + 1
    deposit_gas = model.CODE_STATE_PER_BYTE * size + model.COST_PER_HISTORY_BYTE * size + model.KECCAK_WORD * ((size + 31) // 32)
    add(Case("satin/outcomes/size/deployed-code-over-limit", f"a creation transaction whose initcode returns {fmt(size)} zero "
             f"bytes, one over MAX_CONTRACT_SIZE, with a gas limit of {fmt(1_000_000_000)}, which could pay that code's "
             f"deposit, {fmt(deposit_gas)}: the size check alone halts the creation, before its code-deposit charges; its "
             "regular gas is consumed and the reservoir, with what it paid of the start, returns (SATIN-OUT-003)",
             spec=spec, outcomes=True, to=None, gas=1_000_000_000, data=push(size) + push(0) + b"\xf3"))
    # The code deposit a creation cannot pay halts it (SATIN-OUT-007, SATIN-SCHED-011): one zero byte of code, its
    # deposit's last charge, the code's history, one gas short and paid.
    one_byte = mstore(0, 0) + ret(0, 1)
    least = least_gas(Case("probe", "", spec=spec, outcomes=True, to=None, data=one_byte, gas=10_000_000))
    for short in (True, False):
        add(Case(f"satin/outcomes/size/code-deposit-{'one-short' if short else 'paid'}",
                 f"a creation transaction whose initcode returns one zero byte, with a gas limit of "
                 f"{fmt(least - (1 if short else 0))}: " +
                 (f"one short of the code deposit's last charge, the byte's {model.COST_PER_HISTORY_BYTE} of history: the "
                  "creation halts, deploys nothing and the whole gas limit is used (SATIN-OUT-007)" if short else
                  "exactly the code deposit's charges: the creation deploys the byte"),
                 boundary=f"the gas limit {'one below' if short else 'at'} the code deposit's charges", spec=spec,
                 outcomes=True, to=None, data=one_byte, gas=least - (1 if short else 0)))

    # SATIN-OUT-004, SATIN-OUT-011: a precompile that fails consumes its whole forward; its caller resumes.
    # SATIN-OUT-004: the BN254 pairing's size limit decides, not its length's validity or its price: zero bytes are pairs
    # of points at infinity, valid at the limit and one pair over it, and the forward pays the price either way.
    forward = 11_000_000
    for over in (False, True):
        pairs = model.BN254_PAIRING_MAX_INPUT_SIZE // model.BN254_PAIR_SIZE + (1 if over else 0)
        size = pairs * model.BN254_PAIR_SIZE
        price = model.BN254_PAIRING_BASE + model.BN254_PAIRING_PER_PAIR * pairs
        add(Case(f"satin/outcomes/precompile/bn254-pairing-{'over' if over else 'at'}-size-limit",
                 f"a contract calls the BN254 pairing with {fmt(size)} zero bytes, {pairs} pairs of points at infinity, "
                 f"forwarding {fmt(forward)}, which pays their price, {fmt(price)}: " +
                 ("one pair over its size limit, so the call fails before any gas check and consumes the whole forward, "
                  "and the caller returns empty return data (SATIN-OUT-004, SATIN-OUT-011)" if over else
                  "at its size limit, so the pairing runs and the caller returns its word 1 (SATIN-OUT-004)"),
                 boundary=f"the input {'one pair over' if over else 'at'} the size limit", spec=spec, outcomes=True,
                 gas=13_000_000, code=call(forward, model.BN254_PAIRING, 0, size) + b"\x50" + RETURN_RETURNDATA))
    price = model.IDENTITY_BASE + model.IDENTITY_WORD
    for short in (True, False):
        forward = price - (1 if short else 0)
        add(Case(f"satin/outcomes/precompile/identity-{'one-short-of' if short else 'at'}-price",
                 f"a contract calls the identity precompile with one word, priced {price}, forwarding {forward}: "
                 + ("one short, so the call fails out of gas and consumes the forward, and the caller returns empty return "
                    "data (SATIN-OUT-011)" if short else "its price exactly, so the call succeeds and the caller returns "
                    "the word it echoes"),
                 boundary=f"the forward {'one below' if short else 'at'} the precompile's price", spec=spec, outcomes=True,
                 code=mstore(0, 0xC0FFEE) + call(forward, model.IDENTITY, 0, 32) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-OUT-012, SATIN-OUT-018: a CREATE short of its operands and a DUP1 of an empty stack halt their frame; the
    # halt has no reason the specification names.
    add(Case("satin/outcomes/halt/create-short-of-operands", "CREATE with two of its three operands on the stack halts the "
             "transaction's own frame before any charge, and the transaction uses its whole gas limit (SATIN-OUT-012)",
             spec=spec, outcomes=True, gas=100_000, code=push(0) + push(0) + CREATE + STOP))
    add(Case("satin/outcomes/halt/dup-of-empty-stack", "DUP1 on an empty stack halts the transaction's own frame: a halt "
             "alone, whatever label a node gives it (SATIN-OUT-018), with a failed receipt and the whole gas limit used "
             "(SATIN-OUT-013)", spec=spec, outcomes=True, gas=100_000, code=DUP1 + STOP))

    # SATIN-OUT-014: a revert of the transaction's own frame, a deposit's included, which is no failed deposit.
    reverting = sstore(1, 1) + ORIGIN_CHAIN_ID + revert(0, 64)
    chain = 7  # a chain other than 1, so that CHAINID shows the chain's id
    add(Case("satin/outcomes/revert/origin-and-chain-id", f"on chain {chain}, the transaction's own frame writes a fresh slot "
             "and reverts with ORIGIN and CHAINID: a failed receipt, the slot's charges given back (SATIN-OUT-014)",
             spec=spec, outcomes=True, code=reverting, chain=chain, chain_id=chain))
    add(Case("satin/outcomes/deposit/reverted", f"on chain {chain}, a deposit's own frame writes a fresh slot and reverts "
             "with ORIGIN and CHAINID, the deposit's sender and the chain's id: the deposit settles as a revert, not a "
             "failed deposit, keeping its mint and nonce bump (SATIN-OUT-014)", spec=spec, outcomes=True,
             deposit=(ETH, 1_000_000), sender_nonce=3, code=reverting, chain=chain))
    add(Case("satin/outcomes/deposit/halted", "a deposit's own frame writes a fresh slot, logs and halts on DUP1 of an empty "
             "stack: a failed deposit, which keeps its mint and nonce bump and nothing else, uses its whole gas limit and "
             "reports no stop (SATIN-OUT-005, SATIN-OUT-013)", spec=spec, outcomes=True, deposit=(ETH, 1_000_000),
             sender_nonce=3, code=sstore(1, 1) + log(0, 0, 0, []) + DUP1 + STOP))

    # SATIN-OUT-006: a charge before the first frame that the transaction cannot pay: out of gas, no frame; a deposit
    # becomes a failed deposit. The charge is the first frame's start record, of a value to an existing account.
    least = call_value + body + record
    # One gas short of the start record is satin/limit-stops/pre-frame/start-record-unpaid; this is its edge's other side.
    add(Case("satin/outcomes/pre-frame/start-record-paid", f"a value transfer to an existing account with a gas limit of "
             f"{fmt(least)}: the intrinsic gas {fmt(call_value)} and the body's history {fmt(body)} leave exactly the first "
             f"frame's start record, {fmt(record)} of history gas, so the charges before the first frame are paid and the "
             "frame starts with no regular gas and moves the value (SATIN-OUT-006)",
             boundary="the gas limit at what the start record needs", spec=spec, outcomes=True, to=EOA, code=b"", value=1,
             gas=least))
    # The second charge, a new recipient's state gas at step 4 (SATIN-SCHED-008), once the record is paid.
    for short in (True, False):
        gas = least + model.ACCOUNT_STATE - (1 if short else 0)
        add(Case(f"satin/outcomes/pre-frame/new-account-state-{'one-short' if short else 'paid'}",
                 f"a value transfer to an absent account with a gas limit of {fmt(gas)}: once the intrinsic gas, the "
                 f"body's history and the start record are paid, {fmt(gas - least)} is left for the new account's state "
                 f"gas, {fmt(model.ACCOUNT_STATE)} " +
                 ("one short: the transaction runs out of gas before its first frame and runs none (SATIN-OUT-006)" if short
                  else "exactly: the frame starts with no regular gas and the value creates the account"),
                 boundary=f"the gas limit {'one below' if short else 'at'} what the new account's state gas needs",
                 spec=spec, outcomes=True, to=ABSENT, code=None, value=1, gas=gas))
    for short in (True, False):
        gas = least - (1 if short else 0)
        add(Case(f"satin/outcomes/pre-frame/deposit-start-record-{'one-short' if short else 'paid'}",
                 f"a deposit of 1 wei to an existing account with a gas limit of {fmt(gas)}: the intrinsic gas and the "
                 f"body's history leave {fmt(gas - call_value - body)} for the first frame's start record, {fmt(record)} of "
                 "history gas " + ("one short: the deposit becomes a failed deposit (SATIN-OUT-006)" if short else
                                   "exactly: the value moves and the deposit succeeds"),
                 boundary=f"the gas limit {'one below' if short else 'at'} what the start record needs", spec=spec,
                 outcomes=True, deposit=(0, gas), sender_nonce=3, to=EOA, code=b"", value=1))
    add(Case("satin/outcomes/deposit/value-unfunded", "a deposit of 2 wei from a sender holding 1 wei, minting nothing: its "
             "first frame's start cannot fund the value and makes no record, so the deposit is a failed deposit "
             "(SATIN-OUT-013)", spec=spec, outcomes=True, deposit=(0, 1_000_000), sender_nonce=3, sender_balance=1, to=EOA,
             code=b"", value=2))

    # SATIN-VAL-003: the order of Satin's own checks, each failing one named by the first that fails.
    data = b"\x01" * 100
    intrinsic = call_plain + model.CALLDATA_NONZERO * len(data)
    floor = call_plain + model.FLOOR_PER_BYTE * len(data)
    add(Case("satin/validation/order/gas-limit-at-floor", f"{len(data)} non-zero calldata bytes and a gas limit of "
             f"{fmt(floor)}, the floor exactly, above the intrinsic regular gas {fmt(intrinsic)}: step 3 refuses a floor "
             "above the gas limit and passes this one, so step 5, the intrinsic gas with the body's history, names the "
             "refusal (SATIN-VAL-003)", boundary="the gas limit at the floor", spec=spec, outcomes=True, data=data,
             gas=floor))
    add(Case("satin/validation/order/below-intrinsic-and-floor", f"{len(data)} non-zero calldata bytes and a gas limit of "
             f"{fmt(intrinsic - 1)}, one below the intrinsic regular gas and below the floor {fmt(floor)}: step 2 names "
             "the refusal before step 3 (SATIN-VAL-003)", boundary="one below the intrinsic regular gas, below the floor",
             spec=spec, outcomes=True, data=data, gas=intrinsic - 1))

    # SATIN-VAL-008, SATIN-OUT-016: a deposit that fails validation is included as a failed deposit.
    least = call_plain + body
    for short in (True, False):
        gas = least - (1 if short else 0)
        add(Case(f"satin/validation/deposit/intrinsic-and-history-{'one-short' if short else 'paid'}",
                 f"a deposit with a gas limit of {fmt(gas)}, against its intrinsic regular gas {fmt(call_plain)} and its "
                 f"body's history gas {fmt(body)}: " + ("one short, it fails validation and is included as a failed "
                                                        "deposit, reporting no stop (SATIN-VAL-008, SATIN-OUT-016)" if short
                                                        else "exactly, it passes and its frame stops at once"),
                 boundary=f"the gas limit {'one below' if short else 'at'} the intrinsic gas with the body's history",
                 spec=spec, outcomes=True, deposit=(ETH, gas), sender_nonce=3))

    # SATIN-VAL-005, SATIN-VAL-008: a deposit from the live system address never has the system shape and is a failed
    # deposit; the registry holds version 2.0.0's code and names the deposit's sender in its slot 0.
    registry = model.Account(code=SEQUENCER_REGISTRY_CODE,
                             storage={model.CURRENT_SYSTEM_ADDRESS_SLOT: int.from_bytes(SENDER, "big")})
    if ex.keccak256(SEQUENCER_REGISTRY_CODE) != model.SEQUENCER_REGISTRY_CODE_HASH:
        raise SystemExit("SEQUENCER_REGISTRY_CODE is not SEQUENCER_REGISTRY_CODE_HASH's")
    add(Case("satin/validation/system-address/deposit-from-live-system-address", "a deposit whose sender the registry names "
             "as the live system address: a deposit never has the system shape, so it is invalid and, a deposit, included "
             "as a failed deposit that runs no call, keeping its mint and nonce bump (SATIN-VAL-005, SATIN-VAL-008)",
             spec=spec, outcomes=True, deposit=(ETH, 1_000_000), sender_nonce=3, code=sstore(1, 1) + STOP,
             accounts={REGISTRY: registry}))

    # SATIN-VAL-001, SATIN-VAL-004: the body counts a record for every authorization entry; the data size before the first
    # frame holds the records of the authorities applied, none for an entry skipped.
    for chain_id in (2, 0):
        skipped = chain_id != 0
        add(Case(f"satin/validation/authorization-records/entry-{'skipped' if skipped else 'applied'}",
                 f"one authorization entry for chain id {chain_id}: the body's {model.AUTHORIZATION_SIZE} bytes of it and "
                 f"its {model.WRITE_RECORD_SIZE}-byte record are counted against the data-size limit (SATIN-VAL-001); "
                 + ("skipped for its chain id, it applies no authority, so the data size before the first frame is the "
                    "body's alone (SATIN-VAL-004)" if skipped else "applied, its authority's record is counted before the "
                    "first frame with the body (SATIN-VAL-004)"),
                 boundary=f"an entry {'skipped' if skipped else 'applied'}", spec=spec, outcomes=True, ty=4, to=EOA,
                 code=b"", gas=500_000, authorizations=[(AUTH_KEY, chain_id, CONTRACT, 0)]))
    return out


def outcome_edge_cases() -> list[Case]:
    """The second round of the outcomes page's and validation's edges (D-85): what the first round's cases left
    unpinned."""
    out: list[Case] = []
    add = out.append
    spec = FILL_SPEC
    history = model.COST_PER_HISTORY_BYTE
    record = model.WRITE_RECORD_SIZE * history
    body = model.TX_BODY_SIZE * history
    call_plain = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS
    call_value = call_plain + model.TX_VALUE_COST
    word_revert = mstore(0, 0xBAD) + revert(0, 32)

    # SATIN-VAL-002, -003: the least gas limits validation admits, and step 3 at the intrinsic gas exactly.
    add(Case("satin/validation/order/call-at-least-gas-limit", f"a call without value to an existing account without code, "
             f"its gas limit {fmt(call_plain + body)}, the intrinsic regular gas {fmt(call_plain)} with the body's history "
             f"{fmt(body)} exactly: admitted, and the frame runs on no regular gas (SATIN-VAL-003)",
             boundary="the gas limit at the intrinsic gas with the body's history", spec=spec, outcomes=True, to=EOA,
             code=b"", gas=call_plain + body))
    add(Case("satin/validation/order/self-transfer-at-least-gas-limit", f"1 wei to the sender itself, its gas limit "
             f"{fmt(model.TX_BASE_COST + body)}, TX_BASE_COST with the body's history exactly: admitted, with no start record "
             "and no transfer log (SATIN-VAL-003)", boundary="the gas limit at the intrinsic gas with the body's history",
             spec=spec, outcomes=True, to=SENDER, code=b"", value=1, gas=model.TX_BASE_COST + body))
    data = b"\x01" * 100
    intrinsic = call_plain + model.CALLDATA_NONZERO * len(data)
    add(Case("satin/validation/order/gas-limit-at-intrinsic-below-floor", f"{len(data)} non-zero calldata bytes and a gas "
             f"limit of {fmt(intrinsic)}, the intrinsic regular gas exactly, below the floor "
             f"{fmt(call_plain + model.FLOOR_PER_BYTE * len(data))}: step 2 passes and step 3 names the refusal "
             "(SATIN-VAL-003)", boundary="the gas limit at the intrinsic regular gas", spec=spec, outcomes=True, data=data,
             gas=intrinsic))

    # SATIN-VAL-006, -007: a legacy transaction without a chain id is valid; a typed one carrying chain id 0 is not the
    # chain's; a nonce of 2^64 - 1 and an empty authorization list are the base layer's refusals.
    add(Case("satin/validation/chain-id/legacy-without-chain-id", "a legacy transaction signed before EIP-155, carrying no "
             "chain id: valid, and it runs (SATIN-VAL-006)", spec=spec, outcomes=True, chain_id=None))
    for ty, name in ((1, "access-list"), (2, "fee-market"), (4, "authorization")):
        add(Case(f"satin/validation/chain-id/{name}-chain-zero", f"a type-{ty} transaction carrying chain id 0 on chain "
                 f"{CHAIN_ID}: not the chain's id, so it is refused (SATIN-VAL-006)", spec=spec, outcomes=True, ty=ty,
                 chain_id=0, access_list=[(CONTRACT, [1])] if ty == 1 else None,
                 authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)] if ty == 4 else None, to=EOA if ty == 4 else CONTRACT,
                 code=b"" if ty == 4 else STOP))
    for at_max in (True, False):
        nonce = model.MAX_U64 - (0 if at_max else 1)
        add(Case(f"satin/validation/nonce/{'at-maximum' if at_max else 'below-maximum'}",
                 f"a sender whose nonce is 2^64 - {1 if at_max else 2} sends a transaction at that nonce: " +
                 ("EIP-2681 refuses a nonce of 2^64 - 1 (SATIN-VAL-007)" if at_max else
                  "valid, and the sender's nonce becomes 2^64 - 1"),
                 boundary=f"the nonce {'at' if at_max else 'one below'} 2^64 - 1", spec=spec, outcomes=True, nonce=nonce,
                 sender_nonce=nonce))
    add(Case("satin/validation/authorization-list/empty", "an EIP-7702 transaction whose authorization list is empty: "
             "refused (SATIN-VAL-007); satin/validation/authorization-records/entry-applied is its control", spec=spec,
             outcomes=True, ty=4, to=EOA, code=b"", gas=500_000))

    # SATIN-OUT-006: a deposit's empty caller and a creation's account, the charges before the first frame, paid or one
    # gas short.
    state = model.ACCOUNT_STATE
    for short in (True, False):
        gas = call_plain + body + state - (1 if short else 0)
        add(Case(f"satin/outcomes/pre-frame/deposit-new-caller-{'one-short' if short else 'paid'}",
                 f"a deposit from a sender empty under EIP-161, minting 1 ether, with a gas limit of {fmt(gas)}: the intrinsic "
                 f"gas and the body's history leave {fmt(gas - call_plain - body)} for the new caller's state gas, "
                 f"{fmt(state)}, " + ("one short: a failed deposit, which keeps the caller, counted and not charged "
                                      "(SATIN-OUT-006)" if short else "exactly: the caller is charged and the frame stops "
                                                                       "at once"),
                 boundary=f"the gas limit {'one below' if short else 'at'} the new caller's state gas", spec=spec,
                 outcomes=True, deposit=(ETH, gas), absent_sender=True))
    create_least = model.TX_BASE_COST + model.CREATE_ACCESS + body + record + state
    add(Case("satin/outcomes/pre-frame/created-account-one-short", f"a creation transaction with no initcode and a gas "
             f"limit of {fmt(create_least - 1)}: the intrinsic gas, the body's history and the start record leave one gas "
             f"short of the created account's state gas, {fmt(state)}: the transaction runs out of gas before its first "
             "frame and is included out of gas, its fee charged, and its sender keeps the nonce bump the creation would "
             "have made, with no account created (SATIN-OUT-006, SATIN-SCHED-010)", boundary="the gas limit one below the "
             "created account's state gas", spec=spec, outcomes=True, to=None, data=b"", gas=create_least - 1))
    add(Case("satin/outcomes/pre-frame/created-account-paid", f"a creation transaction with no initcode and a gas limit of "
             f"{fmt(create_least)}: the intrinsic gas, the body's history and the start record leave exactly the created "
             f"account's state gas, {fmt(state)}, so the charges before the first frame are paid; the frame runs nothing "
             "and creates an account without code (SATIN-OUT-006)", boundary="the gas limit at the created account's "
             "state gas", spec=spec, outcomes=True, to=None, data=b"", gas=create_least))

    # SATIN-OUT-005, -013: a failed deposit uses its whole gas limit, its reservoir included.
    add(Case("satin/outcomes/deposit/halted-with-reservoir", f"a deposit with a gas limit one above the execution cap, "
             f"{fmt(model.EXECUTION_CAP + 1)}, whose own frame halts: a failed deposit uses its whole gas limit, the "
             "reservoir included, where an ordinary halt returns it (satin/outcomes/halt/with-reservoir) (SATIN-OUT-005)",
             boundary="a reservoir of one", spec=spec, outcomes=True, deposit=(ETH, model.EXECUTION_CAP + 1), sender_nonce=3,
             code=INVALID))

    # SATIN-OUT-014: a deposit's revert takes back its value's start; a created caller and its state gas survive it.
    add(Case("satin/outcomes/deposit/reverted-with-value", "a deposit minting 1 ether sends 1 wei to a contract that reverts "
             "with a word: the value, its record and its transfer log are taken back with the start record's history, the "
             "mint and the nonce bump are kept, and unused gas is not consumed (SATIN-OUT-014)", spec=spec, outcomes=True,
             deposit=(ETH, 1_000_000), sender_nonce=3, value=1, code=word_revert))
    add(Case("satin/outcomes/deposit/reverted-new-caller", f"a deposit from a sender empty under EIP-161 whose own frame "
             f"reverts with a word: the caller it created keeps its {fmt(state)} of state gas and its unit of state growth, "
             "which a failed deposit would not charge (SATIN-OUT-014)", spec=spec, outcomes=True, deposit=(ETH, 1_000_000),
             absent_sender=True, code=word_revert))

    # SATIN-OUT-012, SATIN-SIZE-005, -006: a creation's checks and charges in order, under gas detention. A detained child
    # runs CREATE2 with its value, offset and size and no salt: its initcode cost is the crossing with 1 spendable, and
    # with 5 it pays that and the memory and halts on the missing salt. A detained CREATE of initcode over
    # MAX_INITCODE_SIZE halts at the size check, before any charge could be the crossing.
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 6_000), "pad": 0}
    salt_short = push(32) + push(0) + push(0) + b"\xf5" + STOP
    operands = model.G_VERYLOW + 2 * model.G_BASE  # the pushes before the opcode
    initcode, memory = model.INITCODE_WORD_COST, model.memory_cost(1)
    for spendable in (initcode - 1, initcode + memory):
        crossing = spendable < initcode
        add(Case(f"satin/outcomes/halt/create2-short-of-salt-{'at-crossing' if crossing else 'charges-paid'}",
                 f"a detained child with {spendable} of spendable gas at a CREATE2 holding its value, offset and size but "
                 f"no salt, its whole regular gas ample: " +
                 (f"its initcode cost, {initcode}, is the first charge and gas detention's crossing, so the child is "
                  "stopped, a revert whose regular gas returns, before the missing salt is read (SATIN-OUT-012)" if crossing
                  else f"it pays its initcode cost, {initcode}, and its memory, {memory}, and then halts on the missing "
                       "salt, burning its regular gas (SATIN-OUT-012)"),
                 boundary=f"the spendable part {'below' if crossing else 'at'} the charges before the salt", spec=spec,
                 outcomes=True, gas=21_000_000, accounts={DETAINED: model.Account(nonce=1, code=salt_short)},
                 make=lambda words, pad: detained(words, pad) + call(100_000, DETAINED, 0, 0) + STOP, params=start,
                 retune=[("child-room", spendable + operands, "pad", -1)]))
    oversize = push(model.MAX_INITCODE_SIZE + 1) + push(0) + push(0) + b"\xf0" + STOP
    add(Case("satin/outcomes/halt/create-initcode-over-limit-detained", f"a detained child with 1 of spendable gas at a "
             f"CREATE of {fmt(model.MAX_INITCODE_SIZE + 1)} bytes of initcode, one over MAX_INITCODE_SIZE: the size check "
             "comes before any charge, so the child halts there and burns its regular gas, where an initcode cost charged "
             "first would have been the crossing (SATIN-OUT-003)", spec=spec, outcomes=True, gas=21_000_000,
             accounts={DETAINED: model.Account(nonce=1, code=oversize)},
             make=lambda words, pad: detained(words, pad) + call(100_000, DETAINED, 0, 0) + STOP, params=start,
             retune=[("child-room", 1 + operands, "pad", -1)]))

    # SATIN-OUT-011, SATIN-LIM-014: a value call to the identity precompile whose start would cross the transaction's
    # data-size limit: failing on its stipend, it kept nothing and is no stop; priced within it, its start is stopped.
    room, stipend = 239, model.CALL_STIPEND
    for fails in (True, False):
        words = (stipend - model.IDENTITY_BASE) // model.IDENTITY_WORD + (1 if fails else 0)
        price = model.IDENTITY_BASE + model.IDENTITY_WORD * words
        add(Case(f"satin/outcomes/precompile/identity-value-start-{'fails' if fails else 'stopped'}",
                 f"hints leave the transaction {room} bytes of data size, and a contract sends 1 wei to the identity "
                 f"precompile with {words} words of input, priced {fmt(price)}, on the {fmt(stipend)} stipend alone; its "
                 f"start would keep two records and a transfer log, {2 * model.WRITE_RECORD_SIZE + model.TRANSFER_LOG_SIZE} "
                 "bytes: " + ("the precompile fails, so the start kept nothing and is no stop, and the call consumes the "
                              "stipend (SATIN-OUT-011)" if fails else
                              "the stipend pays the price, so the start is held to its limits and stopped, and the caller "
                              "returns the stop"),
                 boundary=f"the price {'one over' if fails else 'within'} the stipend", system=True, spec=spec,
                 outcomes=True, gas=8_000_000, contract_balance=1,
                 accounts={model.IDENTITY: model.Account(nonce=1, balance=1)},
                 code=hints_leaving(room) + call(0, model.IDENTITY, 1, 32 * words) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-VAL-006, -007, -008: a transaction from the live system address (D-87): a Mega System Transaction refused for
    # its own chain-id, EIP-3607 and nonce checks, and once it passes them a deposit, which a gas limit short of its
    # intrinsic gas with its body's history makes a failed deposit.
    registry = model.Account(code=SEQUENCER_REGISTRY_CODE,
                             storage={model.CURRENT_SYSTEM_ADDRESS_SLOT: int.from_bytes(SENDER, "big")})
    live = {REGISTRY: registry}
    # Without the system shape such a transaction is refused (SATIN-VAL-005); neither adapter maps that refusal to a
    # reason, so it has no case (D-87).
    for name, intent, kw in (
            ("chain-id-missing", "carrying no chain id, signed before EIP-155, which a Mega System Transaction must "
             "carry (SATIN-VAL-006)", {"chain_id": None}),
            ("sender-has-code", "from a system address holding code that is no EIP-7702 delegation (SATIN-VAL-007)",
             {"sender_code": b"\x00"}),
            ("nonce-too-high", "carrying a nonce one above the system address's (SATIN-VAL-007)", {"nonce": 1}),
            ("nonce-at-maximum", "from a system address whose nonce is 2^64 - 1, at that nonce, which EIP-2681 refuses "
             "(SATIN-VAL-007)", {"nonce": model.MAX_U64, "sender_nonce": model.MAX_U64})):
        add(Case(f"satin/validation/system-address/system-tx-{name}", f"a legacy call to the Oracle from the live system "
                 f"address, of the system shape, {intent}: the Mega System Transaction fails its own check before its "
                 "promotion and is refused", spec=spec, outcomes=True, system=True, to=model.ORACLE, code=None,
                 accounts=dict(live), **kw))
    # `SATIN-MST-005` states from `bcf260d` on that the promoted transaction's receipt is a legacy one, whose status and
    # gas used follow the promoted execution, D-87's reading: the case cites that snapshot (D-96).
    add(Case("satin/validation/system-address/system-tx-below-intrinsic-and-history", f"a Mega System Transaction with a gas "
             f"limit of {fmt(call_plain + body - 1)}, one below its intrinsic gas with its body's history: it passes its own "
             "checks and is promoted to a deposit, which that check makes a failed deposit, not a refusal (SATIN-VAL-008)",
             boundary="one below the intrinsic gas with the body's history", spec=SECOND_FILL_SPEC, outcomes=True, system=True,
             to=model.ORACLE, code=None, gas=call_plain + body - 1, accounts=dict(live)))
    add(Case("satin/validation/deposit/system-transaction-flag", "a deposit carrying the base layer's system-transaction "
             "flag, which the base layer refuses from Regolith on: a deposit is never rejected, so it is a failed deposit "
             "(SATIN-VAL-008)", spec=spec, outcomes=True, deposit=(ETH, 1_000_000), sender_nonce=3, system_flag=True))

    # SATIN-OUT-009: KeylessDeploy's step 1 overhead one short (a halt) and paid (step 3 refuses with its own error).
    unpadded = model.KEYLESS_DEPLOY_CALL + word(0x40) + word(1_000_000) + word(5) + bytes.fromhex("0102030405")
    overhead = model.KEYLESS_DEPLOY_OVERHEAD_GAS
    for short in (True, False):
        add(Case(f"satin/outcomes/keyless/overhead-{'one-short' if short else 'paid'}",
                 f"the transaction's own keylessDeploy call with arguments the decoder recognizes and 5 bytes that are no "
                 f"transaction, the first frame holding {fmt(overhead - (1 if short else 0))} of regular gas against step "
                 f"1's overhead of {fmt(overhead)}: " + ("one short, the step halts the frame (SATIN-OUT-009)" if short else
                                                        "paid, step 3 refuses with MalformedEncoding(), a revert"),
                 boundary=f"the frame's regular gas {'one below' if short else 'at'} step 1's overhead", spec=spec,
                 outcomes=True, system=True, to=model.KEYLESS_DEPLOY, code=None, data=unpadded, gas=300_000,
                 tune=("frame", overhead - (1 if short else 0))))

    # SATIN-OUT-005, -013, SATIN-WIT-002: a failed deposit keeps its reads; the unfunded value's recipient is loaded.
    # `SATIN-DEP-012` states from `bcf260d` on that a deposit that reaches step 4 keeps the load made there when its
    # first frame then fails, so the case cites that snapshot (D-96).
    add(Case("satin/outcomes/deposit/value-unfunded-reads", f"a deposit of 2 wei from a sender holding 1 wei, minting "
             f"nothing, with a gas limit of {fmt(call_value + body)}, its intrinsic gas with its body's history: no start "
             "record is charged for the value it cannot fund, its recipient is loaded before the frame's start fails, and "
             "the failed deposit's reads keep that load (SATIN-OUT-013)", spec=SECOND_FILL_SPEC, outcomes=True, reads=True,
             deposit=(0, call_value + body), sender_nonce=3, sender_balance=1, to=EOA, code=b"", value=2))
    return out


# --- The gas a call forwards: the cap, the request, the stipend and the reservoir share (D-82) --------------------

REPORT_GAS = b"\x5a" + push(0) + b"\x52" + push(32) + push(0) + b"\xf3"  # MSTORE(0, GAS), RETURN(0, 32)
STORE_REPORTER = bytes.fromhex("00000000000000000000000000000000000c0e08")  # writes a fresh slot, then returns GAS
STIPEND_LOGGER = bytes.fromhex("00000000000000000000000000000000000c0e09")  # logs past its history allowance
CREATE2_CREATOR = bytes.fromhex("00000000000000000000000000000000000c0e0a")  # creates by CREATE2 initcode that halts
SLOT_WRITER = bytes.fromhex("00000000000000000000000000000000000c0e0b")  # writes fresh slots
WRITE_LOG_REVERTER = bytes.fromhex("00000000000000000000000000000000000c0e0c")  # writes a fresh slot and logs, then reverts


def cap_of(remaining: int) -> int:
    """SATIN-FWD-001: the most regular gas a start forwards of `remaining`."""
    return remaining - remaining * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR


def forwarding_cases() -> list[Case]:
    """The gas a call or a creation forwards (SATIN-FWD-001 to -007, D-82): the cap computed by subtraction on the
    caller's regular gas after the opcode's charges, the request below and above it, the stipend added after it and to
    a value-transferring CALL alone, a CREATE's forward, the small remainders where the subtraction and the frame-budget
    multiplication differ, and the reservoir share, outside the request and the cap."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    num, den, stipend = model.GAS_RETAINED_NUMERATOR, model.GAS_RETAINED_DENOMINATOR, model.CALL_STIPEND
    reporter = {REPORTER: model.Account(nonce=1, code=REPORT_GAS)}
    report = lambda gas, value=0: call(gas, REPORTER, value, 0) + b"\x50" + RETURN_RETURNDATA

    # SATIN-FWD-001, -003: the cap against the request, one either side of it.
    remaining = 200_000
    cap = cap_of(remaining)
    for over in (False, True):
        request = cap + (1 if over else -1)
        child = min(request, cap)
        add(Case(f"satin/gas-forwarding/call/request-{'above' if over else 'below'}-cap",
                 f"a CALL requesting {fmt(request)} from a caller holding {fmt(remaining)} of regular gas after the "
                 f"opcode's charges: the cap is {fmt(remaining)} - {fmt(remaining)} x {num} / {den} = {fmt(cap)} "
                 f"(EIP-150's 63/64 would be {fmt(remaining - remaining // 64)}), and the child receives min(request, cap) = "
                 f"{fmt(child)}, " + ("the cap: a request one above it does not raise the forward (SATIN-FWD-003)" if over
                                      else "the request, one below the cap (SATIN-FWD-003)")
                 + f"; its GAS, after its own {model.G_BASE}, shows {fmt(child - model.G_BASE)} (SATIN-FWD-001)",
                 boundary=f"the request one {'above' if over else 'below'} the cap", spec=spec, accounts=dict(reporter),
                 code=report(request), tune=("forward", remaining)))

    # SATIN-FWD-006: the small remainders, where the subtraction gives what the multiplication of the frame budgets does
    # not; a remaining below 50 is forwarded whole.
    for remaining in (49, 50, 99):
        cap = cap_of(remaining)
        product = remaining * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
        add(Case(f"satin/gas-forwarding/small-remainder/remaining-{remaining}",
                 f"a CALL requesting all it may from a caller holding {remaining} of regular gas after the opcode's charges: "
                 f"the subtraction forwards {remaining} - {remaining} x {num} / {den} = {cap}"
                 + (", the whole remaining" if cap == remaining else "") +
                 f", where the frame-budget multiplication {remaining} x {model.FRAME_SHARE_NUMERATOR} / "
                 f"{model.FRAME_SHARE_DENOMINATOR} would give {product} (SATIN-FWD-006); the child's GAS shows "
                 f"{cap - model.G_BASE}", boundary=f"a remaining of {remaining}", spec=spec, accounts=dict(reporter),
                 code=report(MAX_GAS), tune=("forward", remaining)))
    add(Case("satin/gas-forwarding/small-remainder/remaining-1", f"a CALL requesting all it may from a caller holding 1 of "
             f"regular gas after the opcode's charges: the subtraction forwards 1 - 1 x {num} / {den} = 1 and the caller "
             f"keeps 0, where the multiplication would forward 0 (SATIN-FWD-006); the child halts and burns it, and the "
             "caller stops with nothing left, so the transaction uses its whole gas limit", boundary="a remaining of 1",
             spec=spec, accounts={HALTER: model.Account(nonce=1, code=INVALID)},
             code=call(MAX_GAS, HALTER, 0, 0) + STOP, tune=("forward", 1)))

    # SATIN-FWD-002, -003: the specification's own value call. The caller's account and the callee's are recorded by an
    # earlier transfer, so the measured call makes no record and charges no history after the forward.
    held = 10_000
    cap = cap_of(held)
    add(Case("satin/gas-forwarding/value-call/ten-thousand-left", f"a value-transferring CALL whose caller has {fmt(held)} "
             f"of regular gas left after the value-transfer charge, {fmt(model.CALL_VALUE_COST)}, which holds the stipend: "
             f"it forwards the cap {fmt(cap)}, the child receives {fmt(cap)} + CALL_STIPEND {fmt(stipend)} = "
             f"{fmt(cap + stipend)} and its GAS shows {fmt(cap + stipend - model.G_BASE)}, and the caller keeps "
             f"{fmt(held - cap)}: the stipend is added after the cap and not taken from the caller (SATIN-FWD-002, "
             "SATIN-FWD-003); an earlier transfer recorded both accounts, so the call makes no record", spec=spec,
             value=10, accounts=dict(reporter), code=call(0, REPORTER, 1, 0) + b"\x50" + report(MAX_GAS, 1),
             tune=("forward-last", held)))

    # SATIN-FWD-003: the stipend is a value-transferring CALL's alone: a DELEGATECALL in a frame entered with value adds
    # none.
    remaining = 50_000
    cap = cap_of(remaining)
    add(Case("satin/gas-forwarding/delegatecall/frame-with-value", f"a frame entered with 1 wei runs a DELEGATECALL of a "
             f"reporter's code requesting all it may, holding {fmt(remaining)} of regular gas after the opcode's charges: "
             f"the child receives the cap {fmt(cap)} and no stipend, which a value-transferring CALL alone adds, the frame's "
             f"value moving nothing; its GAS shows {fmt(cap - model.G_BASE)} (SATIN-FWD-001, SATIN-FWD-003)", spec=spec,
             value=1, accounts=dict(reporter), code=delegatecall(MAX_GAS, REPORTER) + b"\x50" + RETURN_RETURNDATA,
             tune=("delegate-forward", remaining)))

    # SATIN-FWD-004: CREATE has no gas operand: it forwards the cap and adds no stipend, an endowment moving with it.
    remaining = 1_000_000
    cap = cap_of(remaining)
    add(Case("satin/gas-forwarding/create/endowed", f"a CREATE endowing 1 wei, its creator holding {fmt(remaining)} of "
             f"regular gas after the opcode's charges and the created account's state gas, which come before the forward: "
             f"it forwards the cap {fmt(cap)} and no stipend, and the initcode stores its GAS, {fmt(cap - model.G_BASE)}, "
             "in a fresh slot of the created account (SATIN-FWD-002, SATIN-FWD-004)", spec=spec, contract_balance=1,
             code=create(1, b"\x5a" + push(0) + b"\x55" + STOP) + STOP, tune=("create-forward", remaining)))

    # SATIN-FWD-005, -006: the reservoir share, outside the request and the cap. The caller's reservoir after its start's
    # charges is set by the gas limit above the execution cap; the child writes a fresh slot, whose state gas the share
    # pays in part, and its GAS after the write shows what the share left its regular gas to pay.
    body = model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE
    store_report = {STORE_REPORTER: model.Account(nonce=1, code=sstore(1, 1) + REPORT_GAS)}
    for left in (99, 1):
        share = cap_of(left)
        add(Case(f"satin/gas-forwarding/reservoir/share-of-{left}", f"a transaction whose gas limit leaves its own frame a "
                 f"reservoir of {left} after the body's history: its CALL, which charges no state or history, gives the "
                 f"child the share {left} - {left} x {num} / {den} = {share} and keeps {left - share}, where the "
                 f"multiplication would give {left * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR} "
                 "(SATIN-FWD-006); the child writes a fresh slot, whose state gas the share pays first after its legacy "
                 "share, so its GAS after the write shows the rest paid from its regular gas (SATIN-FWD-005)",
                 boundary=f"a reservoir of {left}", spec=spec, gas=model.EXECUTION_CAP + body + left,
                 accounts=dict(store_report), code=call(MAX_GAS, STORE_REPORTER, 0, 0) + b"\x50" + RETURN_RETURNDATA))
    size = model.HISTORY_ALLOWANCE_BYTES - model.LOG_BASE_SIZE + 40
    logger = {STIPEND_LOGGER: model.Account(nonce=1, code=log(0, 0, size, []) + STOP)}
    add(Case("satin/gas-forwarding/reservoir/value-call-requesting-nothing", f"a value-transferring CALL requesting no gas, "
             f"with a reservoir: the child receives the {fmt(stipend)} stipend as its regular gas and the reservoir share "
             f"all the same (SATIN-FWD-005); it logs {size} bytes, {model.LOG_BASE_SIZE + size} bytes of history, 40 past "
             f"the {model.HISTORY_ALLOWANCE_BYTES} the value call's history allowance covers, which is no part of its gas "
             "(SATIN-FWD-003): the share pays the history past it, which the stipend left after the log's regular "
             "charges could not, and the log is kept", spec=spec, gas=model.EXECUTION_CAP + 1_000_000,
             contract_balance=1, accounts=dict(logger), code=call(0, STIPEND_LOGGER, 1, 0) + STOP))

    # SATIN-FWD-006: the reservoir share either side of 50, where the subtraction forwards the whole reservoir below it.
    for left in (49, 50):
        share = cap_of(left)
        add(Case(f"satin/gas-forwarding/reservoir/share-of-{left}", f"a transaction whose gas limit leaves its own frame a "
                 f"reservoir of {left} after the body's history: its CALL gives the child the share {left} - {left} x {num} "
                 f"/ {den} = {share} and keeps {left - share}" + (", the whole reservoir, a remaining below 50 being "
                                                                  "forwarded whole" if share == left else "") +
                 " (SATIN-FWD-006, SATIN-POOL-011); the child writes a fresh slot, whose state gas the share pays first "
                 "after its legacy share, so its GAS after the write shows the rest paid from its regular gas (SATIN-FWD-005)",
                 boundary=f"a reservoir of {left}", spec=spec, gas=model.EXECUTION_CAP + body + left,
                 accounts=dict(store_report), code=call(MAX_GAS, STORE_REPORTER, 0, 0) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-FWD-001 to -003, -006: CALLCODE's own path. It moves its value from the calling account to itself, so it makes
    # no record and charges no history after the forward (SATIN-ACCT-007); its value adds the stipend as CALL's does.
    report_code = lambda gas, value=0: callcode(gas, REPORTER, value) + b"\x50" + RETURN_RETURNDATA
    held = 10_000
    cap = cap_of(held)
    for value in (0, 1):
        for over in (False, True):
            request = cap + (1 if over else -1)
            child = min(request, cap) + (stipend if value else 0)
            add(Case(f"satin/gas-forwarding/callcode/{'value' if value else 'no-value'}-request-"
                     f"{'above' if over else 'below'}-cap",
                     f"a CALLCODE of a reporter's code " + (f"with {value} wei, which moves from the calling account to "
                                                            "itself, " if value else "without value, ") +
                     f"requesting {fmt(request)} from a caller holding {fmt(held)} of regular gas after the opcode's "
                     "charges" + (f", the value-transfer cost {fmt(model.CALL_VALUE_COST)} among them" if value else "") +
                     f": the cap is {fmt(held)} - {fmt(held)} x {num} / {den} = {fmt(cap)}, and the frame receives "
                     f"min(request, cap) = {fmt(min(request, cap))}" +
                     (f" + CALL_STIPEND {fmt(stipend)} = {fmt(child)}, the stipend added after the cap" if value else
                      ", with no stipend") + f"; its GAS shows {fmt(child - model.G_BASE)} (SATIN-FWD-001, "
                     "SATIN-FWD-002, SATIN-FWD-003)", boundary=f"the request one {'above' if over else 'below'} the cap",
                     spec=spec, contract_balance=value, accounts=dict(reporter), code=report_code(request, value),
                     tune=("callcode-forward", held)))
    for remaining in (49, 50, 99):
        cap = cap_of(remaining)
        add(Case(f"satin/gas-forwarding/callcode/remaining-{remaining}", f"a CALLCODE requesting all it may from a caller "
                 f"holding {remaining} of regular gas after the opcode's charges: it forwards {remaining} - {remaining} x "
                 f"{num} / {den} = {cap}" + (", the whole remaining" if cap == remaining else "") + ", where the "
                 f"multiplication would give {remaining * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR} "
                 f"(SATIN-FWD-001, SATIN-FWD-006); the frame's GAS shows {cap - model.G_BASE}",
                 boundary=f"a remaining of {remaining}", spec=spec, accounts=dict(reporter), code=report_code(MAX_GAS),
                 tune=("callcode-forward", remaining)))
    # The share of a CALLCODE that forwards no regular gas: the frame receives the stipend and its history allowance, and
    # logs two bytes of history past the allowance, which the share pays first and its regular gas the rest.
    left = 99
    share = cap_of(left)
    size = model.HISTORY_ALLOWANCE_BYTES - model.LOG_BASE_SIZE + 2
    past = 2 * model.COST_PER_HISTORY_BYTE
    allowance_logger = {STIPEND_LOGGER: model.Account(nonce=1, code=log(0, 0, size, []) + REPORT_GAS)}
    add(Case("satin/gas-forwarding/callcode/value-requesting-nothing", f"a CALLCODE with 1 wei requesting no gas, its "
             f"caller's reservoir {left} after the start's charges, which make no record: the frame receives the "
             f"{fmt(stipend)} stipend as its regular gas and the share {left} - {left} x {num} / {den} = {share} all the same, "
             "neither bounded by the request (SATIN-FWD-005, SATIN-FWD-006); it logs "
             f"{model.LOG_BASE_SIZE + size} bytes of history, 2 past the {model.HISTORY_ALLOWANCE_BYTES} a value "
             f"CALLCODE's allowance covers, {fmt(past)} of history gas that the share pays first and regular gas the rest, "
             "so its GAS shows the share", boundary=f"a reservoir of {left}", spec=spec,
             gas=model.EXECUTION_CAP + body + left, contract_balance=1, accounts=dict(allowance_logger),
             code=callcode(0, STIPEND_LOGGER, 1) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-FWD-001, -003, -006: STATICCALL's own path, with no value and no stipend, read by a reporter that changes no
    # state.
    report_static = lambda gas: staticcall(gas, REPORTER) + b"\x50" + RETURN_RETURNDATA
    remaining = 200_000
    cap = cap_of(remaining)
    for over in (False, True):
        request = cap + (1 if over else -1)
        add(Case(f"satin/gas-forwarding/staticcall/request-{'above' if over else 'below'}-cap", f"a STATICCALL requesting "
                 f"{fmt(request)} from a caller holding {fmt(remaining)} of regular gas after the opcode's charges: the cap is "
                 f"{fmt(remaining)} - {fmt(remaining)} x {num} / {den} = {fmt(cap)}, and the frame receives min(request, cap) "
                 f"= {fmt(min(request, cap))} and no stipend; its GAS shows {fmt(min(request, cap) - model.G_BASE)} "
                 "(SATIN-FWD-001, SATIN-FWD-003)", boundary=f"the request one {'above' if over else 'below'} the cap",
                 spec=spec, accounts=dict(reporter), code=report_static(request), tune=("static-forward", remaining)))
    for remaining in (49, 50, 99):
        cap = cap_of(remaining)
        add(Case(f"satin/gas-forwarding/staticcall/remaining-{remaining}", f"a STATICCALL requesting all it may from a "
                 f"caller holding {remaining} of regular gas after the opcode's charges: it forwards {remaining} - "
                 f"{remaining} x {num} / {den} = {cap}" + (", the whole remaining" if cap == remaining else "") + ", where "
                 f"the multiplication would give {remaining * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR} "
                 f"(SATIN-FWD-001, SATIN-FWD-006); the frame's GAS shows {cap - model.G_BASE}",
                 boundary=f"a remaining of {remaining}", spec=spec, accounts=dict(reporter), code=report_static(MAX_GAS),
                 tune=("static-forward", remaining)))

    # SATIN-FWD-004, -006: CREATE2's normal path. A small remainder: a creator called with a tuned gas operand, holding a
    # reservoir share that pays the created account's state gas past its legacy share and the start's records, creates
    # initcode that halts and burns its forward; the creator keeps the rest of its regular gas and stops.
    salt = 0x5A17
    creator2 = {CREATE2_CREATOR: model.Account(nonce=1, code=create2(0, INVALID, salt) + STOP)}
    for remaining in (50, 99):
        cap = cap_of(remaining)
        add(Case(f"satin/gas-forwarding/create2/remaining-{remaining}", f"a CREATE2 whose creator holds {remaining} of "
                 "regular gas after the opcode's charges and the created account's state gas, which come before the "
                 f"forward: it forwards {remaining} - {remaining} x {num} / {den} = {cap} and no stipend, and the creator "
                 f"keeps {remaining - cap}, where the multiplication would keep "
                 f"{remaining - remaining * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR} and EIP-150's "
                 f"63/64 {remaining // 64} (SATIN-FWD-001, SATIN-FWD-002, SATIN-FWD-004, SATIN-FWD-006); the initcode "
                 "halts and burns the forward, the creation fails, and the creator stops on what it kept; its reservoir "
                 "share pays the start's records after the forward", boundary=f"a remaining of {remaining}", spec=spec,
                 gas=model.EXECUTION_CAP + body + 200_000, accounts=dict(creator2),
                 make=lambda gas: call(gas, CREATE2_CREATOR, 0, 0) + STOP, params={"gas": 300_000},
                 retune=[("create-forward", remaining, "gas", 1)]))
    remaining = 1_000_000
    cap = cap_of(remaining)
    add(Case("satin/gas-forwarding/create2/endowed", f"a CREATE2 endowing 1 wei with salt {salt:#x}, its creator holding "
             f"{fmt(remaining)} of regular gas after the opcode's charges, the initcode's hashing among them, and the created "
             f"account's state gas, which come before the forward: it forwards the cap {fmt(cap)} and no stipend, and the "
             f"initcode stores its GAS, {fmt(cap - model.G_BASE)}, in a fresh slot of the account at the address the salt "
             "and the initcode decide, whatever the creator's nonce (SATIN-FWD-002, SATIN-FWD-004)", spec=spec,
             contract_balance=1, code=create2(1, b"\x5a" + push(0) + b"\x55" + STOP, salt) + STOP,
             tune=("create-forward", remaining)))
    left = 99
    records = 2 * model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE  # the created account's and the creator's nonce
    created = model.ACCOUNT_STATE - model.LEGACY_CREATE_SHARE  # what the reservoir pays of the created account's state gas
    add(Case(f"satin/gas-forwarding/create2/share-of-{left}", f"a CREATE2 whose creator's reservoir, after the created "
             f"account's state gas past its legacy share and the history of the start's two records, is {left}: the "
             f"creation receives the share {left} - {left} x {num} / {den} = {cap_of(left)}, outside its regular forward "
             "(SATIN-FWD-005, SATIN-FWD-006, SATIN-POOL-011); its initcode writes a fresh slot, whose state gas the share "
             "pays first after its legacy share, and stores its GAS after the write, which shows the rest paid from its "
             "regular gas", boundary=f"a reservoir of {left}", spec=spec, gas=model.EXECUTION_CAP + body + created + records + left,
             code=create2(0, sstore(1, 1) + store_gas(2) + STOP, salt) + STOP))
    return out


# --- Mega System Transactions and the protocol's own transactions (D-82, D-83) -----------------------------------

SYSTEM_TX_SOURCE = model.MEGA_SYSTEM_TRANSACTION_SOURCE_HASH


def registry_naming(address: bytes, code: bytes = SEQUENCER_REGISTRY_CODE) -> dict:
    """A SequencerRegistry whose slot 0 names `address`: the live system address when the code is version 2.0.0's
    (SATIN-REG-002, D-87)."""
    return {REGISTRY: model.Account(code=code, storage={model.CURRENT_SYSTEM_ADDRESS_SLOT: int.from_bytes(address, "big")})}


def system_tx_cases() -> list[Case]:
    """The system-transaction page's rules (SATIN-MST-001 to -009, D-82, D-83): the system shape and the refusal of every
    other transaction from the live system address (SATIN-VAL-005), a caller the registry does not name, a Mega System
    Transaction promoted and run, and the protocol's own transactions, priced at m = 1, not detained and not stopped."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    live = registry_naming(SENDER)
    history = model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * history
    call_plain = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS
    common = dict(spec=spec, system_tx=True, system=True, code=None)

    # SATIN-VAL-005, SATIN-MST-001, -003: from the live system address, a transaction without the system shape is
    # refused whatever its type, every other check of it passing: it carries the chain's id, its nonce is the address's
    # and the address holds no code and can pay its fee.
    for name, what, kw in (
            ("legacy-call-off-whitelist", "a legacy call to MegaLimitControl, a system contract that is not on "
             "MEGA_SYSTEM_TX_WHITELIST", {"to": model.MEGA_LIMIT_CONTROL}),
            ("legacy-creation", "a legacy creation, which is no call", {"to": None, "data": b""}),
            ("access-list-call-to-oracle", "a type-1 call to the Oracle", {"ty": 1, "to": model.ORACLE}),
            ("fee-market-call-to-oracle", "a type-2 call to the Oracle", {"ty": 2, "to": model.ORACLE}),
            ("authorization-call-to-oracle", "a type-4 call to the Oracle with one authorization entry",
             {"ty": 4, "to": model.ORACLE, "authorizations": [(AUTH_KEY, CHAIN_ID, CONTRACT, 0)]})):
        add(Case(f"satin/system-tx/shape/{name}", f"{what}, from the live system address the registry names, otherwise "
                 "valid: judged on its own fields it does not have the system shape, a legacy call to an address on the "
                 "whitelist (SATIN-MST-001), so it is invalid and, not a deposit, refused (SATIN-VAL-005, SATIN-MST-003)",
                 accounts=dict(live), **{**common, **kw}))

    # SATIN-MST-004: a caller the registry does not name is a user, the system shape and all.
    retired = registry_naming(OTHER)
    price = 10**9
    add(Case("satin/system-tx/other-caller/retired-address-charged", f"a legacy call to the Oracle, the system shape, at a "
             f"gas price of {fmt(price)} wei, from an address the registry no longer names, a rotation having made another "
             "the live system address: no Mega System Transaction, it is validated and charged as a user's, its fee paid "
             "and credited, and the Oracle's bytecode runs on its empty input and reverts (SATIN-MST-004)",
             to=model.ORACLE, gas=200_000, gas_price=price, accounts=dict(retired), **common))
    add(Case("satin/system-tx/other-caller/retired-address-below-intrinsic", f"the system shape from an address the "
             f"registry no longer names, with a gas limit of {fmt(call_plain + body - 1)}, one below its intrinsic gas "
             "with its body's history: a user's transaction, refused for it, where the live system address's would be "
             "promoted and a failed deposit (SATIN-MST-004)", boundary="one below the intrinsic gas with the body's history",
             to=model.ORACLE, gas=call_plain + body - 1, accounts=dict(retired), **common))
    add(Case("satin/system-tx/other-caller/untrusted-registry", "a type-2 call to the Oracle from the address slot 0 of a "
             "SequencerRegistry names whose code is not version 2.0.0's: the registry names no live system address "
             "(SATIN-REG-002), so the sender is a user and its transaction, which the live system address could not "
             "send, is admitted and runs the Oracle's bytecode, which reverts on its empty input (SATIN-MST-004)", ty=2,
             to=model.ORACLE, gas=200_000, accounts=registry_naming(SENDER, code=b"\x00"), **common))

    # SATIN-MST-002, -005: a Mega System Transaction that passes its own checks runs as a deposit: no fee, whatever its
    # gas price, and no balance for one; the system address's nonce bumped; the Oracle's read asks no service.
    slot, value = 7, 0xC0FFEE
    oracle = {model.ORACLE: model.Account(code=system_contracts()[model.ORACLE], storage={slot: value})}
    add(Case("satin/system-tx/promoted/oracle-read", f"a legacy call to the Oracle's getSlot({slot}) from the live system "
             f"address, which holds no balance and a nonce of 1, signed at a gas price of {fmt(price)} wei: a Mega System Transaction "
             "(SATIN-MST-002), promoted once its own checks pass and run as a deposit, with no fee charged or credited "
             "and no balance asked for one, the system address's nonce bumped and the Oracle answering the slot's value "
             "(SATIN-MST-005); system-originated, it pays history gas as any transaction (SATIN-MST-007, SATIN-MST-008)",
             to=model.ORACLE, gas=200_000, gas_price=price, sender_balance=0, nonce=1, sender_nonce=1,
             data=model.selector("getSlot(uint256)") + word(slot), accounts={**live, **oracle}, **common))

    # SATIN-MST-007, -008: a deposit carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH is the protocol's, whoever its caller.
    deposit = dict(deposit=(0, 1_000_000), sender_nonce=3, spec=spec, system_tx=True)
    for system in (True, False):
        add(Case(f"satin/system-tx/origin/{'source-hash' if system else 'user'}-deposit-crowded-bucket",
                 "a deposit from an ordinary sender " + ("carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH" if system else
                                                          "carrying another source hash") +
                 " writes a fresh slot in a bucket at twice the minimum capacity: " +
                 ("system-originated, it is priced at m = 1 and reads no bucket's capacity (SATIN-MST-007, SATIN-MST-008)"
                  if system else "a user's deposit, priced at the bucket's m = 2 (SATIN-MST-010)"),
                 source_hash=SYSTEM_TX_SOURCE if system else None, code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 2},
                 **deposit))
    # SATIN-MST-007: a transaction from SYSTEM_CALLER is the protocol's, whatever its type, a simulation's included: a
    # synthetic message, whose sender is given, since no key signs for SYSTEM_CALLER; the same message from a user is
    # priced by bucket.
    for system in (True, False):
        add(Case(f"satin/system-tx/origin/{'system-caller' if system else 'user'}-message-crowded-bucket",
                 "a type-2 execution message from " + ("SYSTEM_CALLER, the caller of the pre-block calls, for which no key "
                                                         "signs" if system else "an ordinary sender, the same message") +
                 ", writes a fresh slot in a bucket at twice the minimum capacity: " +
                 ("system-originated on its own fields, it is priced at m = 1 and reads no bucket's capacity, and it "
                  "pays history gas (SATIN-MST-007, SATIN-MST-008)" if system else
                  "a user's transaction, priced at the bucket's m = 2 (SATIN-MST-004)"),
                 synthetic=True, sender=model.SYSTEM_CALLER if system else None, ty=2, spec=spec, system_tx=True,
                 code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 2}))
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    add(Case("satin/system-tx/origin/source-hash-deposit-not-detained", "a deposit carrying "
             f"MEGA_SYSTEM_TRANSACTION_SOURCE_HASH reads TIMESTAMP and then expands memory past the {fmt(cap)} gas "
             "detention would leave it: system-originated, it is not detained whatever it reads, and its frame succeeds "
             "(SATIN-MST-008); satin/detention/deposit/user-deposit is the user's deposit that is stopped",
             source_hash=SYSTEM_TX_SOURCE, deposit=(0, 30_000_000), sender_nonce=3, spec=spec, system_tx=True,
             code=b"\x42\x50" + over_cap(cap) + STOP))
    size = 32
    add(Case("satin/system-tx/origin/source-hash-deposit-past-data-size-limit", "a deposit carrying "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH sends hints that fill the transaction's data size to TX_DATA_LIMIT "
             f"{fmt(model.TX_DATA_LIMIT)} and then logs {size} bytes past it: system-originated, it is stopped by no "
             "per-transaction limit or frame budget, so the log is kept, and its usage is counted and reported past the "
             "limit (SATIN-MST-008, SATIN-MST-009)", source_hash=SYSTEM_TX_SOURCE, deposit=(0, 20_000_000), sender_nonce=3,
             spec=spec, system_tx=True, system=True, code=hints_leaving(0) + log(0, 0, size, []) + STOP))
    add(Case("satin/system-tx/origin/source-hash-deposit-from-live-address", "a deposit carrying "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH, the promotion's, from the live system address: system-originated, "
             "and a deposit from that address, which never has the system shape, so it is a failed deposit that runs no "
             "call; no promotion is made for it (SATIN-MST-003, SATIN-MST-007)", source_hash=SYSTEM_TX_SOURCE,
             deposit=(ETH, 1_000_000), sender_nonce=3, spec=spec, system_tx=True, code=sstore(1, 1) + STOP,
             accounts=dict(live)))

    # SATIN-FWD-007: the protocol's own transaction splits the reservoir as any execution does.
    left = 99
    add(Case("satin/gas-forwarding/system-originated/reservoir-share-of-99", f"a deposit carrying "
             f"MEGA_SYSTEM_TRANSACTION_SOURCE_HASH whose gas limit leaves its own frame a reservoir of {left}: "
             f"system-originated, exempt from the per-transaction limits, its CALL still gives the child the share "
             f"{left} - {left} x {model.GAS_RETAINED_NUMERATOR} / {model.GAS_RETAINED_DENOMINATOR} = {cap_of(left)}, not "
             "the whole reservoir (SATIN-FWD-007); the child writes a fresh slot at m = 1 and its GAS shows what the share "
             "left its regular gas to pay", source_hash=SYSTEM_TX_SOURCE, deposit=(0, model.EXECUTION_CAP + body + left),
             sender_nonce=3, spec=spec, system_tx=True,
             accounts={STORE_REPORTER: model.Account(nonce=1, code=sstore(1, 1) + REPORT_GAS)},
             code=call(MAX_GAS, STORE_REPORTER, 0, 0) + b"\x50" + RETURN_RETURNDATA))

    # SATIN-MST-002, -005, SATIN-DEP-003: a Mega System Transaction from a system address empty under EIP-161 executes as
    # a deposit whose caller it creates, charged once at m = 1 though the caller's bucket is crowded, before the frame.
    get_slot = model.selector("getSlot(uint256)") + word(slot)
    promoted = dict(to=model.ORACLE, gas_price=price, data=get_slot, accounts={**live, **oracle}, **common)
    caller_state = model.ACCOUNT_STATE
    for gas, paid in ((200_000, False), (300_000, True)):
        add(Case(f"satin/system-tx/promoted/empty-address-{'paid' if paid else 'unpaid'}", "a Mega System Transaction to the "
                 f"Oracle's getSlot({slot}) with a gas limit of {fmt(gas)}, from the live system address, which is empty "
                 "under EIP-161 and whose account bucket is at twice the minimum capacity: promoted, it executes as a "
                 "deposit whose caller is empty, charged that account's new-account state gas once, before its first frame, "
                 f"at m = 1, {fmt(caller_state)} (SATIN-DEP-003, SATIN-MST-005, SATIN-MST-008); " +
                 ("its gas limit pays it, so the caller is created, its nonce 1, one unit of state growth and no write "
                  "record, no fee charged, and the bucket's capacity is not read" if paid else
                  "its gas limit cannot pay it, so it is a failed deposit, which uses its whole gas limit as regular gas "
                  "with no state or history gas, and keeps the created caller, its nonce bump and its unit of state growth"),
                 boundary="the caller's state gas " + ("paid" if paid else "unpaid"), gas=gas, sender_balance=0,
                 salt={("sender", None): 2}, reads=paid, **promoted))
    # SATIN-MST-005: the checks before the promotion, a failure a rejection, and the EIP-7702 exception to EIP-3607.
    add(Case("satin/system-tx/promoted/chain-id-off-by-one", f"the system shape from the live system address signed for "
             f"chain {CHAIN_ID + 1}, the chain's id plus one, every other field valid: a Mega System Transaction must carry "
             "the chain's id, so it is rejected before any promotion, and nothing runs or is charged (SATIN-MST-005)",
             gas=200_000, nonce=1, sender_nonce=1, sender_balance=0, chain_id=CHAIN_ID + 1, **promoted))
    add(Case("satin/system-tx/promoted/nonce-below-address", "the system shape from the live system address, whose nonce is "
             "1, carrying nonce 0: its nonce must equal the system address's, so it is rejected before any promotion and "
             "the address's nonce is not bumped (SATIN-MST-005)", gas=200_000, nonce=0, sender_nonce=1, sender_balance=0,
             **promoted))
    add(Case("satin/system-tx/promoted/delegated-address", "the system shape from the live system address, which holds an "
             "EIP-7702 delegation indicator, its nonce matched: the one code EIP-3607 lets a sender hold, so it is promoted "
             f"and runs as a deposit, the Oracle answering getSlot({slot}) with no fee charged (SATIN-MST-002, "
             "SATIN-MST-005)", gas=200_000, nonce=1, sender_nonce=1, sender_balance=0,
             sender_code=model.DELEGATION_PREFIX + DELEGATE, **promoted))
    # SATIN-MST-005: no mint; the value the promoted deposit carries is its sender's to fund.
    for balance in (1, 0):
        add(Case(f"satin/system-tx/promoted/value-{'funded' if balance else 'unfunded'}", "a Mega System Transaction to the "
                 f"Oracle's getSlot({slot}) carrying 1 wei from a system address holding {balance}: promoted with no mint, "
                 + ("the value moves at its frame's start and the Oracle's method, which takes no value, reverts: the "
                    "deposit's revert keeps the nonce bump and its body's history, takes the value back, and charges no fee"
                    if balance else "its frame's start cannot fund the value, so it is a failed deposit, using its whole gas "
                    "limit as regular gas, the nonce bumped and no value minted for it") + " (SATIN-MST-005)",
                 boundary=f"a value of 1 against a balance of {balance}", gas=200_000, value=1, nonce=1, sender_nonce=1,
                 sender_balance=balance, **promoted))

    # SATIN-MST-008: a system-originated transaction reads no bucket's capacity at all: the reads show none served, and a
    # SALT input that does not hold the bucket is never asked for it.
    add(Case("satin/system-tx/origin/source-hash-deposit-reads-no-capacity", "a deposit carrying "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH writes a fresh slot in a bucket at twice the minimum capacity: "
             "system-originated, its state charge is priced at m = 1 and no bucket's capacity is read, so its reads serve "
             "no SALT capacity (SATIN-MST-007, SATIN-MST-008)", source_hash=SYSTEM_TX_SOURCE, code=sstore(1, 1) + STOP,
             salt={(CONTRACT, 1): 2}, reads=True, **deposit))
    add(Case("satin/system-tx/origin/system-caller-message-reads-no-capacity", "a type-2 execution message from "
             "SYSTEM_CALLER writes a fresh slot in a bucket at twice the minimum capacity: system-originated, its state "
             "charge is priced at m = 1 and no bucket's capacity is read, so its reads serve no SALT capacity "
             "(SATIN-MST-007, SATIN-MST-008)", synthetic=True, sender=model.SYSTEM_CALLER, ty=2, spec=spec, system_tx=True,
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 2}, reads=True))
    add(Case("satin/system-tx/origin/source-hash-deposit-incomplete-salt", "a deposit carrying "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH writes a fresh slot, its SALT input incomplete and holding no bucket: "
             "system-originated, it reads no bucket's capacity, so the missing bucket is never asked for and the deposit "
             "succeeds at m = 1 (SATIN-MST-008), where a user's write would need the capacity the input does not hold",
             source_hash=SYSTEM_TX_SOURCE, code=sstore(1, 1) + STOP, salt_complete=False, **deposit))

    # SATIN-MST-007: SYSTEM_CALLER's transaction is the protocol's whatever its type, a deposit's among them; the address
    # one above it is a user's.
    caller_kw = dict(synthetic=True, sender=model.SYSTEM_CALLER, spec=spec, system_tx=True, code=sstore(1, 1) + STOP,
                     salt={(CONTRACT, 1): 2})
    for name, what, kw in (("legacy", "a legacy execution message", {"ty": 0}),
                           ("access-list", "a type-1 execution message with an access list", {
                               "ty": 1, "access_list": [(REPORTER, [])]}),
                           ("authorization", "a type-4 execution message with one valid authorization entry", {
                               "ty": 4, "authorizations": [(AUTH_KEY, CHAIN_ID, DELEGATE, 0)]})):
        add(Case(f"satin/system-tx/origin/system-caller-{name}-message", f"{what} from SYSTEM_CALLER writes a fresh slot in "
                 "a bucket at twice the minimum capacity: system-originated on its sender whatever its type, it is priced "
                 "at m = 1 (SATIN-MST-007, SATIN-MST-008)", **{**caller_kw, **kw}))
    add(Case("satin/system-tx/origin/system-caller-deposit", "a deposit from SYSTEM_CALLER carrying another source hash than "
             "MEGA_SYSTEM_TRANSACTION_SOURCE_HASH writes a fresh slot in a bucket at twice the minimum capacity: "
             "system-originated on its caller, it is priced at m = 1, and it settles as a deposit, with a deposit's receipt "
             "(SATIN-MST-007, SATIN-MST-008)", sender=model.SYSTEM_CALLER, code=sstore(1, 1) + STOP,
             salt={(CONTRACT, 1): 2}, **deposit))
    beside = (int.from_bytes(model.SYSTEM_CALLER, "big") + 1).to_bytes(20, "big")
    add(Case("satin/system-tx/origin/beside-system-caller-message", f"a type-2 execution message from {h(beside)}, the "
             "address one above SYSTEM_CALLER, writes a fresh slot in a bucket at twice the minimum capacity: only "
             "SYSTEM_CALLER itself is the protocol's caller, so this is a user's transaction, validated and charged as "
             "one and priced at the bucket's m = 2 (SATIN-MST-004)", **{**caller_kw, "sender": beside, "ty": 2}))

    # SATIN-MST-008, -009: no frame budget or transaction limit stops the protocol's own transaction, in a child as in its
    # own frame, and what it uses is reported; a user's deposit is stopped at the same edges (SATIN-MST-010).
    writes = lambda n: b"".join(sstore(k, 1) for k in range(1, n + 1)) + STOP
    budget = model.TX_STATE_GROWTH_LIMIT * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    many = dict(deposit=(0, 130_000_000), sender_nonce=3, spec=spec, system_tx=True)
    for system in (True, False):
        who = "source-hash" if system else "user"
        add(Case(f"satin/system-tx/origin/{who}-deposit-child-{budget + 1}-slots", "a deposit " +
                 ("carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH" if system else "carrying another source hash") +
                 f" calls a child that writes {budget + 1} fresh slots, one past the {budget} of state growth a child's "
                 "budget holds: " + ("system-originated, no frame budget stops it, every write is kept and the growth is "
                                     "reported (SATIN-MST-008, SATIN-MST-009)" if system else
                                     "a user's deposit, its child is stopped at the write past its budget, its writes "
                                     "discarded, and the deposit runs on (SATIN-MST-010)"),
                 boundary=f"{budget + 1} fresh slots in a child", source_hash=SYSTEM_TX_SOURCE if system else None,
                 accounts={SLOT_WRITER: model.Account(nonce=1, code=writes(budget + 1))},
                 code=call(MAX_GAS, SLOT_WRITER, 0, 0) + b"\x50" + STOP, **many))
        add(Case(f"satin/system-tx/origin/{who}-deposit-{model.TX_STATE_GROWTH_LIMIT + 1}-slots", "a deposit " +
                 ("carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH" if system else "carrying another source hash") +
                 f" writes {fmt(model.TX_STATE_GROWTH_LIMIT + 1)} fresh slots in its own frame, one past TX_STATE_GROWTH_LIMIT "
                 f"{fmt(model.TX_STATE_GROWTH_LIMIT)}: " +
                 ("system-originated, no transaction limit stops it, every write is kept and its growth is reported past "
                  "the limit, not clamped to it (SATIN-MST-008, SATIN-MST-009)" if system else
                  "a user's deposit, its frame is stopped at the last write and the deposit settles as a revert "
                  "(SATIN-MST-010)"), boundary=f"{fmt(model.TX_STATE_GROWTH_LIMIT + 1)} fresh slots",
                 source_hash=SYSTEM_TX_SOURCE if system else None, code=writes(model.TX_STATE_GROWTH_LIMIT + 1), **many))

    # SATIN-MST-008, -010: history is charged at every point it is for any transaction, the protocol's own included: a
    # created account's code, and a failed child's rollback, which gives back what the child charged.
    for system in (True, False):
        who = "source-hash" if system else "user"
        what = "carrying MEGA_SYSTEM_TRANSACTION_SOURCE_HASH" if system else "carrying another source hash"
        add(Case(f"satin/system-tx/origin/{who}-deposit-code-history", f"a deposit {what} creates an account whose initcode "
                 f"deploys 1 byte of code: the code's byte is history the deposit pays, {model.COST_PER_HISTORY_BYTE} gas, "
                 "with the created account's record and the creator's nonce record, " +
                 ("system-originated or not (SATIN-MST-008)" if system else "as any transaction (SATIN-MST-010)"),
                 source_hash=SYSTEM_TX_SOURCE if system else None, code=create(0, init_returning(STOP)) + STOP, **deposit))
        add(Case(f"satin/system-tx/origin/{who}-deposit-child-reverted", f"a deposit {what} calls a child that writes a "
                 "fresh slot and logs, then reverts: the rollback discards the write and the log and gives back the state "
                 "and history gas the child charged for them, so the deposit keeps only its body's history, " +
                 ("system-originated or not (SATIN-MST-008)" if system else "as any transaction (SATIN-MST-010)"),
                 source_hash=SYSTEM_TX_SOURCE if system else None,
                 accounts={WRITE_LOG_REVERTER: model.Account(nonce=1, code=sstore(1, 1) + log(0, 0, 0, []) + revert(0, 0))},
                 code=call(MAX_GAS, WRITE_LOG_REVERTER, 0, 0) + b"\x50" + STOP, **deposit))

    # SATIN-MST-003, SATIN-VAL-005: a deposit from the live system address fails whatever its destination.
    for name, what, to in (("creating", "a creation, its recipient empty", None),
                           ("self-addressed", "addressed to the live system address itself", SENDER)):
        add(Case(f"satin/system-tx/origin/live-address-{name}-deposit", f"a deposit from the live system address, {what}, "
                 "with a mint: a deposit never has the system shape, so it is a failed deposit, which keeps the mint and the "
                 "nonce bump, creates or calls nothing, and reports its body as its history bytes (SATIN-MST-003, "
                 "SATIN-VAL-005)", deposit=(ETH, 1_000_000), sender_nonce=3, spec=spec, system_tx=True, to=to, data=b"",
                 code=None, accounts=dict(live)))
    return out


# --- A keyless deployment past step 3: steps 3 to 15, the creation, the signer's nonce and the answer -----------

SIGNER_KEY = 0x4E1C4A7D2B9F3E8A6C5D0F1B2A3948576E8D9C0B1A2F3E4D5C6B7A8998A7B6C5  # the carried transactions' signer
SIGNER = ex.address_of(SIGNER_KEY)
DEPLOY = model.created_address(SIGNER, 0)  # the deploy address, keccak256(rlp([signer, 0]))[12:]
CARRIED_GAS_PRICE = 100 * 10**9  # what the carried transactions are signed at: no fee is paid at it
NO_POINT_R = 5  # an r that is the x of no secp256k1 point: 5^3 + 7 is no square modulo p


def carried(init: bytes, gas: int = 90_000, value: int = 0, nonce: int = 0, to: bytes | None = None,
            chain_id: int | None = None, key: int = SIGNER_KEY, high_s: bool = False, r: int | None = None,
            gas_price: int = CARRIED_GAS_PRICE) -> bytes:
    """A signed legacy creation for a keyless deployment: pre-EIP-155 (v 27 or 28) unless `chain_id` is given; with
    `high_s` its s is replaced by n - s and its parity flipped, a signature of the same key; with `r` the signature's r
    is replaced, leaving one that recovers no key."""
    fields = [nonce, gas_price, gas, to if to is not None else b"", value, init]
    recid, sig_r, sig_s = ex.sign(key, ex.keccak256(ex.rlp(fields + ([] if chain_id is None else [chain_id, 0, 0]))))
    if high_s:
        recid, sig_s = recid ^ 1, ex.N - sig_s
    v = 27 + recid if chain_id is None else 35 + 2 * chain_id + recid
    return ex.rlp(fields + [v, sig_r if r is None else r, sig_s])


def keyless_data(raw: bytes, override: int, padded: bool = True) -> bytes:
    """keylessDeploy(raw, override), canonically ABI-encoded, or with the bytes' tail padding cut (SATIN-ICPT-006)."""
    return model.KEYLESS_DEPLOY_CALL + word(0x40) + word(override) + word(len(raw)) + (
        raw.ljust((len(raw) + 31) // 32 * 32, b"\x00") if padded else raw)


def keyless_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = FILL_SPEC
    every = 2**256 - 1  # a gasLimitOverride above MAX_UINT64, which the deployment reads as MAX_UINT64
    code = init_returning(bytes(range(1, 33)))  # initcode that deploys 32 bytes of code
    pad = b"\x5b" * 16  # JUMPDESTs before a constructor whose own cost the case leaves free
    signer = lambda **kw: {SIGNER: model.Account(**kw)}

    def case(name: str, intent: str, raw: bytes, override: int = every, gas: int = 1_000_000, padded: bool = True,
             **kw) -> None:
        add(Case(f"satin/keyless/{name}", intent, system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
                 data=keyless_data(raw, override, padded), gas=gas, **kw))

    # Step 3's own order, and the table's order of steps 3 to 13 (SATIN-KEY-006).
    case("refusal/to-and-chain-id", "a carried transaction with to set and a chain id: step 3 refuses it for both, with "
         "the first error in its own order, NotContractCreation()", carried(code, to=EOA, chain_id=CHAIN_ID))
    case("refusal/chain-id", "a carried creation signed with a chain id: step 3 refuses it with NotPreEIP155()",
         carried(code, chain_id=CHAIN_ID))
    signed = 90_000
    case("refusal/nonce-and-override", "a carried nonce of 1 and a gasLimitOverride below the signed gas limit: step 4 "
         "answers before step 6", carried(code, nonce=1), override=signed - 1)
    case("refusal/override-and-signer-nonce", "a gasLimitOverride one below the signed gas limit and a signer at nonce "
         "2: step 6 answers before step 8", carried(code), override=signed - 1, accounts=signer(nonce=2))
    case("refusal/signer-nonce-two", "a signer at nonce 2: step 8 refuses it, the signer's account read and the "
         "deploy address not", carried(code), accounts=signer(nonce=2), reads=True)
    case("refusal/signer-nonce-and-code", "a signer at nonce 2 that holds code: step 8 answers before step 9",
         carried(code), accounts=signer(nonce=2, code=b"\x60\x00"))
    case("refusal/signer-has-code", "a signer that holds code other than a delegation indicator: SignerHasCode()",
         carried(code), accounts=signer(nonce=1, code=b"\x60\x00"))
    case("refusal/invalid-signature", "a carried signature whose r is the x of no curve point: no signer is recovered, "
         "InvalidSignature()", carried(pad + code, r=NO_POINT_R))
    case("refusal/taken-and-unfunded", "a deploy address that holds code and a carried value the signer cannot fund: "
         "step 12 answers before step 13, both accounts read", carried(code, value=1),
         accounts={**signer(nonce=1), DEPLOY: model.Account(nonce=1, code=b"\x00")}, reads=True)
    case("refusal/insufficient-balance", "a carried value the empty signer cannot fund: step 10 charges the signer's "
         "account, then step 13 refuses, and that state gas comes back", carried(code, value=1))
    # The forward's checks, steps 11 and 15, at their edges: the call's regular gas one short of the signed gas limit.
    case("refusal/step-11-one-short", "the call holds one gas less than the signed gas limit after step 10: step 11 "
         "refuses with GasLimitTooLow", carried(code, gas=signed), tune=("keyless-11", signed - 1))
    case("refusal/step-15-one-short", "the call holds one gas less than the signed gas limit after step 14's charges: "
         "step 15 refuses with GasLimitTooLow, and the state and history gas of steps 10 and 14 come back",
         carried(code, gas=signed), tune=("keyless-15", signed - 1))
    case("deploy/forward-at-signed-gas", "the call holds exactly the signed gas limit after step 14: the creation is "
         "forwarded all of it and deploys", carried(code, gas=signed), tune=("keyless-15", signed))
    # Deployments: the creation as a child of the call, the signer's nonce, the records, gasUsed and the answer.
    case("deploy/absent-signer", "a deployment from an absent signer: step 10 charges its account, the creation deploys "
         "32 bytes, the nonce bump is kept, and the signer's record and unit of state growth are counted on the call",
         carried(code))
    case("deploy/signer-nonce-one", "a deployment from signer nonce 1: the bump is taken back, and with it the signer's "
         "record, whose history comes back", carried(code), accounts=signer(nonce=1, balance=ETH))
    case("deploy/signer-nonce-one-reverts", "a deployment from signer nonce 1 whose initcode reverts: the bump is taken "
         "back all the same", carried(pad + revert(0, 0)), accounts=signer(nonce=1, balance=ETH))
    case("deploy/reverts-with-data", "initcode that reverts with one word: ExecutionReverted(gasUsed, the word)",
         carried(pad + mstore(0, 0xBAD) + revert(0, 32)))
    fresh = model.G_VERYLOW + model.G_BASE + model.COLD_SSTORE_ACCESS + model.SSTORE_SET + 2 * model.G_BASE
    case("deploy/fresh-slot-reverts", f"a constructor that writes a fresh slot at m = 1 from regular gas alone and "
         f"reverts: gasUsed is its regular charges, {fmt(fresh)}, the slot's state and history returning as reservoir",
         carried(bytes([0x60, 0x01]) + b"\x5f\x55\x5f\x5f\xfd", gas_price=2**128 - 1), gas_used_check=fresh)
    case("deploy/halts", "initcode that halts: ExecutionHalted with the creation's whole forward", carried(pad + INVALID),
         override=signed)
    case("deploy/empty-code", "a constructor that returns empty code: the deposit is refused, the creation reverts and "
         "the address stays deployable; EmptyCodeDeployed", carried(pad + STOP))
    destroyed = model.G_BASE + model.SELFDESTRUCT_COST
    case("deploy/destroyed-in-constructor", f"a constructor ORIGIN; SELFDESTRUCT at m = 1, given 500,000 of regular gas "
         f"and no reservoir: gasUsed {fmt(destroyed)}, step 14's created account and record coming back within the "
         "creation; EmptyCodeDeployed; the bytes argument unpadded", carried(b"\x32\xff", gas=500_000), override=500_000,
         gas=1_500_000, padded=False, gas_used_check=destroyed)
    case("deploy/inner-empty-creation", "a constructor whose own CREATE returns empty code, then deploys 32 bytes: the "
         "empty-code refusal concerns the deploy address alone (SATIN-KEY-009)", carried(create(0, b"") + code))
    case("deploy/origin-gasprice-caller-gas", "initcode that stores GAS, ORIGIN, GASPRICE and CALLER: the forward "
         "without the 98/100 cap, the transaction's own origin and gas price, and the signer as caller",
         carried(b"\x5a" + push(4) + b"\x55" + b"\x32" + push(5) + b"\x55" + b"\x3a" + push(6) + b"\x55" + b"\x33"
                 + push(7) + b"\x55" + code), gas_price=7, gas=2_000_000)
    case("deploy/balance-only-address", "a deploy address that holds one wei alone: step 12 passes, step 14 charges no "
         "created-account state gas, the creation counts no rise and keeps the wei", carried(code),
         accounts={DEPLOY: model.Account(balance=1)})
    case("deploy/with-reservoir", "a successful deployment above the execution cap: steps 10 and 14 draw from the "
         "reservoir, and the creation's unused regular gas and reservoir return to their respective pools "
         "(SATIN-POOL-012); the ABI gasUsed nets both pools across the creation (SATIN-KEY-015)", carried(code),
         gas=model.EXECUTION_CAP + 1_000_000, pools=True)
    case("deploy/high-s", "a carried signature with its s above half the curve order: the same signer is recovered and "
         "the deployment lands at the same address", carried(code, high_s=True))
    case("deploy/delegated-signer", "a signer the transaction's own EIP-7702 list delegated: step 9 admits the "
         "indicator, step 14 charges no nonce record, the bump from nonce 1 is taken back and the record the list made "
         "stands", carried(code), ty=4, authorizations=[(SIGNER_KEY, CHAIN_ID, PLAIN, 0)])
    case("deploy/carried-value", "a carried value the signer holds exactly: it moves to the created account at the "
         "creation's start, with its transfer log, and the signer, not empty, is charged no account",
         carried(code, value=5), accounts=signer(balance=5))
    case("deploy/signer-nonce-one-with-value", "a deployment from signer nonce 1 that moves a carried value out of the "
         "signer: the bump is taken back, and the record stays, the balance having changed", carried(code, value=5),
         accounts=signer(nonce=1, balance=ETH))
    case("deploy/constructor-log", "a constructor that emits an empty LOG0 before it deploys: the log is the "
         "transaction's, emitted by the deploy address", carried(log(0, 0, 0, []) + code))
    case("deploy/buckets", "the signer's account and the created account priced at their own buckets, of twice and "
         "four times the minimum capacity", carried(code), salt={(SIGNER, None): 2, (DEPLOY, None): 4}, gas=2_000_000)
    case("deploy/signer-is-sender", "a deployment the signer sends itself: validation bumped its nonce to 1, the "
         "creation's bump is taken back, and the sender's account makes no record of its own",
         carried(code, key=KEY))
    case("deploy/collision", "a deploy address that holds a nonce and no code: step 12 passes, and the creation "
         "collides there, ExecutionHalted with its whole forward", carried(code), override=signed,
         accounts={DEPLOY: model.Account(nonce=1)})
    case("halt/step-10-one-short", "the call cannot pay the signer's new account at step 10 by one gas: it halts out of "
         "gas, and nothing of the deployment happens", carried(code),
         tune=("keyless-10", model.ACCOUNT_STATE - 1))
    step14 = (model.CREATE_GAS + model.INITCODE_WORD_COST * ((len(code) + 31) // 32) + model.ACCOUNT_STATE
              + 2 * model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE)
    case("halt/step-14-one-short", "the call cannot pay step 14's charges by one gas, the last of them its records' "
         "history: it halts out of gas before the creation starts", carried(code), accounts=signer(balance=1),
         tune=("keyless-14", step14 - 1))
    # The signer as the block beneficiary (SATIN-KEY-010), and the stop of the creation it leads to (SATIN-KEY-016).
    words = words_within(model.BLOCK_ENV_ACCESS_COMPUTE_GAS + 500_000)
    case("detention/signer-is-beneficiary", "a signer that is the block beneficiary detains the deployment at its read, "
         "at step 1's compute: the constructor's burn past the cap is the crossing, which stops the creation, and the "
         "call answers ExecutionReverted with the stop", carried(burn(words) + code), coinbase=SIGNER, gas=25_000_000)
    case("detention/signer-not-beneficiary", "the same burn without the signer being the beneficiary: no read, the "
         "constructor pays it and deploys", carried(burn(words) + code), gas=25_000_000)
    # A keylessDeploy call a contract makes runs the bytecode (SATIN-KEY-003).
    raw = keyless_data(carried(code), every)
    for value in (0, 1):
        add(Case(f"satin/keyless/contract-call/{'with-value' if value else 'no-value'}",
                 "a contract's keylessDeploy call " + ("carrying value: the bytecode reverts with empty data, the method "
                                                       "not being payable" if value else
                                                       "without value: the bytecode reverts with NotIntercepted() "
                                                       "(SATIN-KEY-003); the call reads KeylessDeploy but neither the "
                                                       "carried signer nor the address its creation would deploy to "
                                                       "(SATIN-WIT-002)"),
                 system=True, spec=spec, code=bytes_to_memory(raw) + call(500_000, model.KEYLESS_DEPLOY, value, len(raw))
                 + record_result() + STOP, contract_balance=10, gas=2_000_000, reads=value == 0))
    # Recognition whatever code the state holds at the address (SATIN-ICPT-006).
    held = {model.KEYLESS_DEPLOY: model.Account(code=b"\x0c")}
    add(Case("satin/keyless/recognition/held-code-unrecognized", "recognition whatever code the state holds "
             "(SATIN-ICPT-006), in engine isolation and not a state a chain reaches: KeylessDeploy's address holding the "
             "undefined opcode 0x0c, called with arguments one byte short of their declared length: not recognized, the "
             "code the state holds runs and halts", system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None, accounts=held,
             data=model.KEYLESS_DEPLOY_CALL + word(0x40) + word(every) + word(5) + bytes.fromhex("01020304"),
             gas=300_000))
    other = b"\x00\x00\x00\x00" + keyless_data(carried(code), every)[4:]
    add(Case("satin/keyless/recognition/held-code-other-selector", "recognition whatever code the state holds "
             "(SATIN-ICPT-006), in engine isolation and not a state a chain reaches: KeylessDeploy's address holding the "
             "undefined opcode 0x0c, called with another selector before arguments that would decode: not recognized, the "
             "code the state holds runs and halts", system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None, accounts=held,
             data=other, gas=1_000_000))
    case("recognition/held-code-recognized", "recognition whatever code the state holds (SATIN-ICPT-006), in engine "
         "isolation and not a state a chain reaches: KeylessDeploy's address holding the undefined opcode 0x0c, called "
         "with arguments that decode: recognized, and the deployment runs", carried(code), accounts=held)
    return out


def keyless_input(raw: bytes, override: int) -> bytes:
    """keylessDeploy(raw, override), canonically encoded unless that makes 196 bytes of calldata, whose floor, 27,544, is
    a figure another case's history moves to under a changed history price, which tools/check_derived_text.py would take
    for stale: those pass the bytes unpadded, or, where the bytes fill their words exactly, add a byte after the encoding,
    both encodings SATIN-ICPT-006 accepts (D-80)."""
    data = keyless_data(raw, override)
    if len(data) != 196:
        return data
    data = keyless_data(raw, override, padded=False)
    return data if len(data) != 196 else data + b"\x00"


def keyless_gap_cases() -> list[Case]:
    """The edges a review of the first keyless cases found unpinned (D-80)."""
    out: list[Case] = []
    add = out.append
    spec = FILL_SPEC
    every = 2**256 - 1
    code = init_returning(bytes(range(1, 33)))
    one = init_returning(b"\x00")  # PUSH0 PUSH0 MSTORE PUSH1 1 PUSH0 RETURN: deploys one zero byte
    # What `one` spends: its opcodes and memory, then the deposit of its byte: hashing, state gas and history gas.
    one_ops = 2 * model.G_BASE + model.G_VERYLOW + model.memory_cost(1) + model.G_VERYLOW + model.G_BASE
    one_cost = one_ops + model.KECCAK_WORD + model.CODE_STATE_PER_BYTE + model.COST_PER_HISTORY_BYTE
    signed = 90_000
    signer = lambda **kw: {SIGNER: model.Account(**kw)}
    pad = b"\x5b" * 16

    def case(name: str, intent: str, raw: bytes, override: int = every, gas: int = 1_000_000, **kw) -> Case:
        c = Case(f"satin/keyless/{name}", intent, system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
                 data=keyless_input(raw, override), gas=gas, **kw)
        add(c)
        return c

    def at_reservoir(c: Case, want: int) -> None:
        """Sets a case's gas limit, above the execution cap, so the call holds `want` of reservoir after step 14: there
        the reservoir moves with the gas limit one for one."""
        _, result, _ = build(c)
        c.gas += want - result.probe["keyless-reservoir-15"]
        _, result, _ = build(c)
        if result.probe["keyless-reservoir-15"] != want:
            raise SystemExit(f"{c.case_id}: the reservoir after step 14 is not {want}")

    # Gap 1: the creation's reservoir share, R - floor(2R / 100), at 50 and 51 left after step 14; the share pays the
    # first of the deposited byte's state gas, and the forward is set so that one more unit of share deploys.
    for left, share, verdict in ((50, 49, "halts out of gas in its deposit"), (51, 50, "deploys")):
        c = case(f"reservoir/share-{share}", f"{left} of reservoir left after step 14: the creation's share is {share}, which "
                 "pays the first of its deposited byte's state gas, and a forward one short of the rest: it " + verdict,
                 carried(one, gas=0), override=one_cost - 50, gas=model.EXECUTION_CAP + 1_000_000)
        at_reservoir(c, left)
    # The legacy shares come from regular gas even with a reservoir: a signed gas limit one above what the call holds
    # at step 15, where taking them from the reservoir would leave the call enough.
    g = 199_000_000
    for _ in range(8):
        c = Case("satin/keyless/reservoir/legacy-shares-from-regular", "above the execution cap, steps 10 and 14 take their "
                 "legacy shares from regular gas before the reservoir: the call holds one gas less than the signed gas "
                 "limit at step 15 and is refused, which a reservoir paying the shares would not leave it", system=True,
                 spec=spec, to=model.KEYLESS_DEPLOY, code=None, data=keyless_input(carried(code, gas=g), every),
                 gas=model.EXECUTION_CAP + 1_000_000)
        _, result, _ = build(c)
        if result.probe["keyless-15"] + 1 == g:
            break
        g = result.probe["keyless-15"] + 1
    else:
        raise SystemExit("legacy-shares-from-regular: the signed gas limit does not settle")
    add(c)
    # Gap 2: the signer's record, counted on the call after the creation returned, against the transaction's data-size
    # limit that admitted hints left it: it fits with 40 bytes of room and stops the call with 39.
    for room, how in ((model.WRITE_RECORD_SIZE, "fits exactly"), (model.WRITE_RECORD_SIZE - 1, "crosses")):
        kept = 0
        for _ in range(6):
            init = hints_leaving(room, kept) + one
            data = keyless_input(carried(init), every)
            if kept == len(data) + model.WRITE_RECORD_SIZE + 1:
                break
            kept = len(data) + model.WRITE_RECORD_SIZE + 1
        add(Case(f"satin/keyless/settlement/signer-record-{'fits' if room == model.WRITE_RECORD_SIZE else 'crosses'}",
                 f"a constructor's hints leave the transaction {room} bytes of data size before the signer's record, "
                 f"counted on the call once the creation returned: it {how}"
                 + ("" if how == "fits exactly" else ", and the call itself is stopped, the deployment and the nonce "
                    "taken back and the hints kept"), system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
                 data=data, gas=8_000_000))
    # The creation's own write held to the transaction's data-size limit after its hints: a LOG0 that fits exactly and
    # one byte over, each followed by an empty revert, and the signer's record on the call after the discard.
    for size in (0, 1):
        kept = 0
        for _ in range(6):
            init = hints_leaving(model.LOG_BASE_SIZE, kept) + log(0, 0, size, []) + revert(0, 0)
            data = keyless_input(carried(init), every)
            if kept == len(data) + model.WRITE_RECORD_SIZE:
                break
            kept = len(data) + model.WRITE_RECORD_SIZE
        add(Case(f"satin/keyless/limits/log-after-hints-{'crosses' if size else 'fits'}", "a constructor's hints leave the "
                 f"transaction room for an empty LOG0; its LOG0 of {size} data byte{'s' if size != 1 else ''} "
                 + ("crosses the transaction's data-size limit, which stops the creation: ExecutionReverted with the stop"
                    if size else "fits, and the constructor reverts with empty data")
                 + "; the signer's record fits on the call once the creation's counts are discarded", system=True,
                 spec=spec, to=model.KEYLESS_DEPLOY, code=None, data=data, gas=8_000_000))
    # Gap 3: the creation's state-growth budget, 980 of the call's 1,000, the created account its first unit.
    budget = model.TX_STATE_GROWTH_LIMIT * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    for slots, nonce in ((budget - 1, 0), (budget, 0), (budget, 1)):
        init = b"".join(sstore(1_000_000 + k, 1) for k in range(1, slots + 1)) + one
        what = "fits" if slots < budget else "crosses the creation's budget, which stops it"
        case(f"budget/fresh-slots-{slots}" + ("-signer-nonce-one" if nonce else ""), f"a constructor that writes {slots} "
             f"fresh slots after the created account's unit: it {what}"
             + (", from signer nonce 1, whose bump is taken back" if nonce else ", the signer's unit counted on the call"),
             carried(init), gas=150_000_000, **({"accounts": signer(nonce=1, balance=ETH)} if nonce else {}))
    # Gap 5: the empty deposit refused with effects to undo, against a destruction whose effects stand.
    effects = sstore(1, 1) + log(0, 0, 0, []) + STOP
    case("empty-code/with-effects", "a constructor that writes a slot and logs, then returns empty code: the refusal "
         "reverts the creation, slot, log and created account taken back", carried(effects))
    case("empty-code/with-effects-and-value", "the same constructor carrying a value from signer nonce 1: the value comes "
         "back with the revert, the bump is taken back and the signer, as loaded, keeps no record",
         carried(effects, value=1), accounts=signer(nonce=1, balance=ETH))
    case("empty-code/balance-only-address", "the same constructor at a deploy address that held one wei: the refusal "
         "leaves the address as it was, with its wei, no nonce and no code", carried(effects),
         accounts={DEPLOY: model.Account(balance=1)})
    case("destroyed/log-and-value", "a constructor that logs and destroys the deploy address, sending its value to the "
         "transaction's sender: EmptyCodeDeployed, but the log and the value's moves stand, and the signer at nonce 1, "
         "its balance changed, keeps its record", carried(log(0, 0, 0, []) + b"\x32\xff", value=300),
         accounts=signer(nonce=1, balance=ETH))
    case("destroyed/balance-only-address", "a constructor that destroys a deploy address that held one wei: "
         "EmptyCodeDeployed; the table gives nothing back for a leaf the transaction did not create, so gasUsed adds "
         "nothing back", carried(b"\x32\xff"), accounts={DEPLOY: model.Account(balance=1)})
    # Gap 6: gasUsed before the EIP-3529 refund, a slot filled and cleared again.
    case("deploy/refund-not-in-gas-used", "a constructor that fills and clears a slot: its state and history come back "
         "within the creation, and the refund it earns is the transaction's, not taken from gasUsed",
         carried(sstore(1, 1) + sstore(1, 0) + one))
    # Gap 7: an earlier, lower detention limit stands; the forward draws the withheld part.
    words = words_within(model.BLOCK_ENV_ACCESS_COMPUTE_GAS + 500_000)
    case("detention/earlier-limit-stands", "the signer is the transaction's sender and the block beneficiary: detained "
         "from the transaction's start, whose limit the signer's later read does not raise; the constructor's burn is "
         "stopped at the earlier limit", carried(burn(words) + one, key=KEY), coinbase=SENDER, gas=25_000_000)
    big = 21_000_000
    case("detention/withheld-forward", "a detained call forwards the signed gas limit, above the spendable part: steps "
         "11 and 15 count the withheld part, the creation receives the whole forward, and its GAS shows it",
         carried(b"\x5a" + push(4) + b"\x55" + one, gas=big, key=KEY), override=big, coinbase=SENDER, gas=25_000_000)
    # Gap 8: no intrinsic gas of the carried transaction is required.
    case("signed-gas/zero", "a carried transaction signed with gas limit 0, below any transaction's intrinsic gas: the "
         "native creation admits it and deploys", carried(one, gas=0), override=500_000)
    case("signed-gas/zero-everything", "signed gas limit 0, gasLimitOverride 0 and empty initcode: steps 6, 11 and 15 "
         "pass at equality, the creation runs with no gas and the empty deposit is refused",
         carried(b"", gas=0, gas_price=1), override=0)
    # Gap 9: the charges paid exactly, and refusals the forward decides before later steps.
    case("refusal/step-10-paid-exactly", "the call holds exactly the signer's new account at step 10: it pays it, and step "
         "11 refuses with nothing left", carried(code), tune=("keyless-10", model.ACCOUNT_STATE))
    step14 = (model.CREATE_GAS + model.INITCODE_WORD_COST * ((len(code) + 31) // 32) + model.ACCOUNT_STATE
              + 2 * model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE)
    case("refusal/step-14-paid-exactly", "the call holds exactly step 14's charges: it pays them, and step 15 refuses "
         "with nothing left", carried(code), accounts=signer(balance=1), tune=("keyless-14", step14))
    case("refusal/step-11-before-taken", "the forward one short at step 11 with a deploy address that holds code: step "
         "11 answers, and the deploy address is never read", carried(code),
         accounts={DEPLOY: model.Account(nonce=1, code=b"\x00")}, tune=("keyless-11", signed - 1), reads=True)
    case("refusal/step-11-before-balance", "the forward one short at step 11 with a carried value the absent signer "
         "cannot fund: step 11 answers before step 13", carried(code, value=1), tune=("keyless-11", signed - 1))
    case("refusal/override-and-invalid-signature", "a gasLimitOverride one below the signed gas limit and a signature "
         "that recovers no signer: step 6 answers before step 7", carried(code, r=NO_POINT_R), override=signed - 1)
    # Gap 10: the uint64 clamp, the ABI's accepted shapes, the carried decoding and the signature's endpoints.
    case("abi/override-2-64", "gasLimitOverride 2^64, read as MAX_UINT64 and not truncated to 0: the deployment runs",
         carried(code), override=2**64)
    raw = carried(code)
    add(Case("satin/keyless/abi/trailing-byte", "one byte after the arguments' encoding: recognized all the same, and "
             "the deployment runs", system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
             data=keyless_input(raw, every) + b"\x01"))
    add(Case("satin/keyless/abi/unaligned-offset", "the bytes' offset at 0x41, one byte past the head and in bounds: "
             "recognized, and the deployment runs", system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None,
             data=model.KEYLESS_DEPLOY_CALL + word(0x41) + word(every) + b"\x00" + word(len(raw)) + raw))
    for name, data, intent in (
            ("head-63-bytes", model.KEYLESS_DEPLOY_CALL + bytes(63), "a head of 63 bytes"),
            ("offset-2-64", model.KEYLESS_DEPLOY_CALL + word(2**64) + word(every) + word(len(raw)) + raw,
             "an offset of 2^64"),
            ("offset-2-64-minus-1", model.KEYLESS_DEPLOY_CALL + word(2**64 - 1) + word(every) + word(len(raw)) + raw,
             "an offset of 2^64 - 1, past the input"),
            ("length-2-64", model.KEYLESS_DEPLOY_CALL + word(0x40) + word(every) + word(2**64) + raw, "a length of 2^64")):
        # The 63-byte head's body would hold 33,176 of history, a figure another case's text shows that a changed history
        # price leaves where it is: an access list naming KeylessDeploy's address, warm already, lengthens the body (D-80).
        short = name == "head-63-bytes"
        add(Case(f"satin/keyless/abi/{name}", f"{intent}: the decoder refuses the arguments, so the call is not recognized, "
                 "pays no overhead, and the bytecode reverts with empty data", system=True, spec=spec,
                 to=model.KEYLESS_DEPLOY, code=None, data=data, gas=300_000,
                 **({"ty": 1, "access_list": [(model.KEYLESS_DEPLOY, [])]} if short else {})))
    case("rlp/trailing-byte", "one byte after a carried list that has to set, a chain id and nonce 1: the bytes are no "
         "encoding, and MalformedEncoding() answers before the list's own refusals",
         carried(code, to=EOA, chain_id=CHAIN_ID, nonce=1) + b"\x00")
    fields = [0, CARRIED_GAS_PRICE, signed, b"", 0, code]
    recid, r, s_ = ex.sign(SIGNER_KEY, ex.keccak256(ex.rlp(fields)))
    case("rlp/eight-fields", "a carried list of eight fields, its s left out: MalformedEncoding()",
         ex.rlp(fields + [27 + recid, r]))
    case("rlp/nested-list", "a carried list whose data field is a list: MalformedEncoding()",
         ex.rlp([0, CARRIED_GAS_PRICE, signed, b"", 0, [code], 27 + recid, r, s_]))
    items = [ex.rlp(f) for f in fields + [27 + recid, r, s_]]
    items[1] = b"\x86\x00" + CARRIED_GAS_PRICE.to_bytes(5, "big")  # the gas price with a leading zero byte
    payload = b"".join(items)
    case("rlp/leading-zero", "a carried gas price encoded with a leading zero byte, no RLP integer: MalformedEncoding()",
         (bytes([0xF7 + 1, len(payload)]) if len(payload) < 256 else b"") + payload)
    case("signature/r-zero", "a carried signature with r = 0: no signer, InvalidSignature()", carried(code, r=0))
    case("signature/s-equal-n", "a carried signature with s equal to the curve order: no signer, InvalidSignature()",
         ex.rlp(fields + [27 + recid, r, ex.N]))
    # Gap 11: the outer transaction's warm set, and the reads of refusals before steps 7 and 12.
    for listed in (True, False):
        add(Case(f"satin/keyless/warm-set/{'listed' if listed else 'unlisted'}-account", "a constructor's BALANCE of an "
                 + ("account the transaction's access list makes warm: the warm read" if listed else
                    "account no access list names: the cold access"), system=True, spec=spec, to=model.KEYLESS_DEPLOY,
                 code=None, data=keyless_input(carried(push(int.from_bytes(EOA, "big")) + b"\x31\x50" + one), every),
                 ty=1 if listed else 0, access_list=[(EOA, [])] if listed else None,
                 accounts={EOA: model.Account(balance=1)}))
    add(Case("satin/keyless/reads/overhead-unpaid", "a recognized call one gas short of the overhead: it halts at step 1, "
             "and neither the signer nor the deploy address is read", system=True, spec=spec, to=model.KEYLESS_DEPLOY,
             code=None, data=keyless_input(raw, every), tune=("frame", model.KEYLESS_DEPLOY_OVERHEAD_GAS - 1), reads=True))
    add(Case("satin/keyless/reads/value-refused", "a recognized call carrying value: refused before any read",
             system=True, spec=spec, to=model.KEYLESS_DEPLOY, code=None, data=keyless_input(raw, every), value=1,
             reads=True))
    case("reads/override-refused", "a gasLimitOverride below the signed gas limit: step 6 refuses before step 7 "
         "recovers the signer, so neither account is read", raw, override=signed - 1, reads=True)
    # Gap 14: the selector anywhere else, and a keylessDeploy call made while a keyless creation runs.
    add(Case("satin/keyless/recognition/ordinary-contract", "an ordinary contract holding the undefined opcode 0x0c, "
             "called with a keylessDeploy call's whole input: only KeylessDeploy's address is recognized, so the code "
             "runs and halts", system=True, spec=spec, code=b"\x0c", data=keyless_input(raw, every)))
    add(Case("satin/keyless/recognition/unknown-selector", "KeylessDeploy's own bytecode called with a selector it does "
             "not declare: not recognized, no overhead, and the bytecode reverts with empty data", system=True, spec=spec,
             to=model.KEYLESS_DEPLOY, code=None, data=bytes.fromhex("deadbeef") + keyless_input(raw, 2**64)[4:],
             gas=300_000))
    inner = keyless_input(carried(code, key=OTHER_KEY), every)
    for value in (0, 1):
        case(f"contract-call/from-constructor{'-with-value' if value else ''}", "a keyless constructor's own keylessDeploy "
             "call, " + ("carrying value: an empty revert, the value kept" if value else "without value: NotIntercepted()")
             + ", nothing of the inner deployment made, and the outer one deploys",
             carried(bytes_to_memory(inner) + call(500_000, model.KEYLESS_DEPLOY, value, len(inner)) + record_result()
                     + code, value=value), gas=2_000_000, **({"accounts": signer(balance=1)} if value else {}))
    # Gap 13: an applied EIP-7702 list of new authorities leaves the call 2, 1 or 0 of state growth, and one more entry
    # does not fit: the creation's share of it, the created account's unit at its start, the signer's on the call.
    limit = model.TX_STATE_GROWTH_LIMIT
    for n, what in ((limit - 2, "the call has 2 of state growth left and the creation 1: the created account's unit "
                                "fits, and the signer's on the call brings the transaction to its limit"),
                    (limit - 1, "the call has 1 left and the creation 0: the created account's unit at its start "
                                "crosses, the creation is stopped before its initcode, and the signer's unit fits the call"),
                    (limit, "the call has 0 left: the creation's start is stopped, and the signer's unit then crosses "
                            "the call's own budget, which stops the call"),
                    (limit + 1, "the list does not fit: it is skipped and the call is stopped before it runs, before "
                                "the overhead")):
        add(Case(f"satin/keyless/authorizations/{n}-new-authorities", f"an EIP-7702 list of {fmt(n)} new authorities "
                 f"before a deployment from an absent signer: {what}", system=True, spec=spec, ty=4,
                 to=model.KEYLESS_DEPLOY, code=None, data=keyless_input(carried(one), every), gas=1_000_000_000,
                 authorizations=[(LIST_KEY + i, CHAIN_ID, DELEGATE, 0) for i in range(n)], stops=n > limit))
    # Gap 4: a delegated signer whose own code spends nonces while its creation runs: the constructor calls the signer,
    # whose delegate creates; bumps that survive the creation are all kept, ones its failure discards are not.
    lib = bytes.fromhex("00000000000000000000000000000000000c0e07")  # the signer's delegate
    delegated = lambda lib_code: {SIGNER: model.Account(nonce=1, balance=ETH, code=model.DELEGATION_PREFIX + lib),
                                  lib: model.Account(nonce=1, code=lib_code)}
    two = create(0, b"") + create(0, b"") + STOP
    call_signer = call(1_000_000, SIGNER, 0, 0) + b"\x50"
    case("nonce-rule/delegate-spends-two", "a constructor that calls its delegated signer, whose delegate makes two "
         "creations at the signer's next nonces: they survive the creation, so every bump is kept, the signer ending "
         "at nonce 4", carried(call_signer + code), accounts=delegated(two), gas=2_000_000)
    case("nonce-rule/delegate-spends-two-reverted", "the same constructor reverting after the call: the delegate's two "
         "creations go with the revert, the creation's bump is the last change and is taken back, nonce 1",
         carried(call_signer + revert(0, 0)), accounts=delegated(two), gas=2_000_000)
    case("nonce-rule/delegate-spends-one-failed", "the delegate's one creation runs reverting initcode: nothing stands "
         "at that address, but the nonce it spent does, and every bump is kept, nonce 3",
         carried(call_signer + code), accounts=delegated(create(0, revert(0, 0)) + STOP), gas=2_000_000)
    # Gap 12: the signer's record after the nonce rule, decided on the whole account.
    case("nonce-rule/value-sent-back", "from signer nonce 1 with a carried wei the constructor sends back to the signer: "
         "the nonce set back leaves the account as loaded, so no record stands and its history comes back",
         carried(call(0, SIGNER, 1, 0) + b"\x50" + code, value=1), accounts=signer(nonce=1, balance=ETH))
    case("nonce-rule/value-received", "from signer nonce 1, a constructor that sends the signer a wei the deploy address "
         "held: the nonce is set back, but the balance changed, so the record stands",
         carried(call(0, SIGNER, 1, 0) + b"\x50" + code), accounts={**signer(nonce=1, balance=ETH),
                                                                    DEPLOY: model.Account(balance=1)})
    # Gap 15: the creation's own deposit admission and charges, and the answer's lengths.
    case("deposit/ef-byte", "a constructor returning the one byte 0xef: EIP-3541 refuses it and the creation halts, "
         "ExecutionHalted with the whole forward", carried(init_returning(b"\xef")), override=signed)
    case("deposit/ee-byte", "a constructor returning the one byte 0xee: deposited", carried(init_returning(b"\xee")))
    case("deposit/history-one-short", "a forward one short of the deposited byte's history gas, no reservoir: the "
         "creation runs out of gas in its deposit, ExecutionHalted", carried(one, gas=0), override=one_cost - 1)
    case("deposit/history-paid", "a forward that pays the deposited byte's history gas exactly: deployed",
         carried(one, gas=0), override=one_cost)
    for length in (1, 31, 33):
        case(f"answer/revert-{length}-byte{'s' if length > 1 else ''}", f"a constructor that reverts with {length} "
             f"byte{'s' if length > 1 else ''}: ExecutionReverted carries them, padded to a word, and the answer's length "
             "follows", carried(pad + mstore(0, int.from_bytes(bytes(range(0xA0, 0xC0)), "big"))
                                + mstore(32, int.from_bytes(bytes(range(0xC0, 0xE0)), "big")) + revert(0, length)))
    return out


# --- The deposits page, the Oracle and the small system contracts (D-109) ---------------------------


def staticcall_with(gas: int, target: bytes, in_size: int) -> bytes:
    """STATICCALL(gas, target, 0, in_size, 0, 0)."""
    return push(0) + push(0) + push(in_size) + push(0) + push(int.from_bytes(target, "big")) + push(gas) + b"\xfa"


def abi_words(*values: int) -> bytes:
    return b"".join(word(v) for v in values)


def multi_call(*payloads: bytes) -> bytes:
    """The Oracle's multiCall(bytes[]) of `payloads`, ABI-encoded."""
    head, tail, offset = b"", b"", 32 * len(payloads)
    for p in payloads:
        head += word(offset)
        padded = p.ljust((len(p) + 31) // 32 * 32, b"\x00")
        tail += word(len(p)) + padded
        offset += 32 + len(padded)
    return model.selector("multiCall(bytes[])") + word(0x20) + word(len(payloads)) + head + tail


TIMESTAMP_CONTRACT = {model.HIGH_PRECISION_TIMESTAMP: model.Account(code=HIGH_PRECISION_TIMESTAMP_CODE)}
OTHER_SELECTOR = model.selector("estimateComputeGas()")  # a selector MegaLimitControl does not intercept


def deposit_page_cases() -> list[Case]:
    """The deposits page's rules (SATIN-DEP-002, -005, -006, -008, -010, -012, D-109): a deposit's load for its first
    frame's start, made at step 4 of SATIN-SCHED-008 and kept when the deposit then fails there or at step 5, and none
    made by one that fails earlier; a creation and a deposit to its own sender; a failed deposit's report, the hints it
    keeps and the gas it returns none of; the deposits that are failed deposits whatever they carry; a creation from a
    sender at MAX_NONCE; and a user's deposit priced by bucket and detained."""
    out: list[Case] = []
    add = out.append
    history = model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * history
    record = model.WRITE_RECORD_SIZE * history
    call_plain = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS
    call_value = call_plain + model.TX_VALUE_COST
    least = call_value + body + record  # a value deposit's charges up to its start record, paid exactly
    created = model.TX_BASE_COST + model.CREATE_ACCESS + body + record  # an empty creation's, up to its start record
    pages = dict(spec=SECOND_FILL_SPEC, system_pages=True, sender_nonce=3)
    seen = dict(pages, reads=True)
    account = model.ACCOUNT_STATE

    # SATIN-DEP-012: the load for the first frame's start is made at step 4, and kept when the deposit fails there.
    gas = least + account - 1
    add(Case("satin/deposits/start-load/empty-recipient-unpaid", f"a deposit of 1 wei to an absent account with a gas limit "
             f"of {fmt(gas)}: its intrinsic gas, its body's history and its start record leave {fmt(account - 1)}, one short "
             f"of the recipient's new-account state gas {fmt(account)} at step 4, so it is a failed deposit, which keeps "
             "the load step 4 made of its recipient (SATIN-DEP-012) and reports its whole gas limit as regular gas "
             "(SATIN-DEP-005)", boundary="one below the recipient's new-account state gas", deposit=(0, gas), to=ABSENT,
             code=None, value=1, **seen))
    add(Case("satin/deposits/start-load/empty-recipient-paid", f"the same deposit with a gas limit of {fmt(gas + 1)}, which "
             "pays the recipient's new-account state gas exactly: it succeeds and creates the recipient",
             boundary="at the recipient's new-account state gas", deposit=(0, gas + 1), to=ABSENT, code=None, value=1, **seen))
    add(Case("satin/deposits/start-load/funded-recipient", f"the deposit one short of the new account's state gas, with the "
             f"same gas limit of {fmt(gas)}, to an account holding a balance and no code: not empty under EIP-161, so step 4 "
             "charges nothing, the deposit succeeds, and only the recipient's state tells it from the failed one "
             "(SATIN-DEP-012)", deposit=(0, gas), to=EOA, code=b"", value=1, **seen))
    add(Case("satin/deposits/start-load/creation-unpaid", f"a deposit creating a contract from empty initcode with a gas "
             f"limit of {fmt(created + account - 1)}, one short of the created account's state gas at step 4: a failed "
             "deposit that keeps the load of its created address, absent (SATIN-DEP-012)",
             boundary="one below the created account's state gas", deposit=(0, created + account - 1), to=None, data=b"",
             **seen))
    add(Case("satin/deposits/start-load/creation-paid", f"the same creation with a gas limit of {fmt(created + account)}: "
             "the created account's state gas paid exactly, the account created with nonce 1 and no code",
             boundary="at the created account's state gas", deposit=(0, created + account), to=None, data=b"", **seen))
    least_self = model.TX_BASE_COST + body
    add(Case("satin/deposits/start-load/to-sender-below-intrinsic", f"a deposit of 5 wei to its own sender with a gas limit "
             f"of {fmt(least_self - 1)}, one below its intrinsic gas with its body's history: it fails validation and makes "
             "no load for its first frame's start, but its recipient, the sender, is loaded all the same (SATIN-DEP-012)",
             boundary="one below the intrinsic gas with the body's history", deposit=(0, least_self - 1), to=SENDER,
             code=None, value=5, **seen))
    add(Case("satin/deposits/start-load/to-sender", f"the same deposit to its own sender with a gas limit of "
             f"{fmt(least_self)}: its value moves nothing and its start makes no record, so step 3 charges none, and it "
             "succeeds having loaded only its sender (SATIN-DEP-012)", deposit=(0, least_self), to=SENDER, code=None,
             value=5, **seen))
    add(Case("satin/deposits/start-load/below-intrinsic", f"a deposit of 1 wei to an existing account with a gas limit of "
             f"{fmt(call_value + body - 1)}, one below its intrinsic gas with its body's history: it fails validation and "
             "makes no load of its recipient (SATIN-DEP-012)", boundary="one below the intrinsic gas with the body's history",
             deposit=(0, call_value + body - 1), to=EOA, code=b"", value=1, **seen))
    add(Case("satin/deposits/start-load/start-record-unpaid", f"a deposit of 1 wei to an existing account with a gas limit "
             f"of {fmt(least - 1)}, one short of its start record at step 3: a failed deposit that makes no load of its "
             "recipient (SATIN-DEP-012)", boundary="one below the start record", deposit=(0, least - 1), to=EOA, code=b"",
             value=1, **seen))
    delegated = {DELEGATED: model.Account(code=model.DELEGATION_PREFIX + DELEGATE), DELEGATE: model.Account(nonce=1, code=STOP)}
    cold = model.WARM_READ + model.COLD_ACCOUNT_SURCHARGE
    for name, left, what in (
            ("warm-read-unpaid", model.WARM_READ - 1, f"one short of WARM_STORAGE_READ_COST {model.WARM_READ}, the first "
             "charge of its delegate's access: a failed deposit that keeps its recipient's load and loads no delegate"),
            ("cold-access-unpaid", cold - 1, f"one short of the cold delegate's access, {model.WARM_READ} and "
             f"{fmt(model.COLD_ACCOUNT_SURCHARGE)}: a failed deposit that keeps its recipient's load and does not load the "
             "delegate, whose additional cold access the gas left cannot pay"),
            ("cold-access-paid", cold, f"the cold delegate's access, {fmt(cold)}, exactly: the delegate is loaded and its "
             "code runs in the recipient's frame")):
        add(Case(f"satin/deposits/start-load/delegated-{name}", f"a deposit to an account holding an EIP-7702 delegation to "
                 f"an account that is not warm, with {fmt(left)} of regular gas at step 5, {what} (SATIN-DEP-012)",
                 boundary=f"the regular gas at step 5 at {fmt(left)}", deposit=(0, 100_000), to=DELEGATED, code=None,
                 accounts=dict(delegated), tune=("delegate", left), **seen))
    to_sender = {DELEGATED: model.Account(code=model.DELEGATION_PREFIX + SENDER)}
    add(Case("satin/deposits/start-load/delegated-warm-delegate", f"a deposit to an account holding an EIP-7702 delegation "
             f"to the deposit's sender, warm from the transaction's start, with {model.WARM_READ} of regular gas at step 5: "
             "the warm read is paid, no cold access is owed, and the sender's empty code runs (SATIN-DEP-012)",
             boundary="the regular gas at step 5 at the warm read", deposit=(0, 100_000), to=DELEGATED, code=None,
             accounts=to_sender, tune=("delegate", model.WARM_READ), **seen))

    # SATIN-DEP-005, -006: a failed deposit's report and what it keeps.
    hint = send_hint(7, b"\xaa")
    hinting = bytes_to_memory(hint) + call(100_000, model.ORACLE, 0, len(hint)) + b"\x50"
    add(Case("satin/deposits/failed/hint-kept", f"a deposit whose contract sends a hint of {len(hint)} input bytes to the "
             "Oracle, admitted and handed to the service with the contract's address, and then halts: a failed deposit, "
             "which keeps the data size of its body and of the hint it admitted (SATIN-DEP-006), and reports its whole gas "
             "limit as regular gas with no state or history gas (SATIN-DEP-005)", system=True, deposit=(0, 1_000_000),
             code=hinting + INVALID, **seen))
    above = model.EXECUTION_CAP + 1_000_000
    add(Case("satin/deposits/failed/detained-above-cap", f"a deposit with a gas limit of {fmt(above)}, above the execution "
             "cap, whose contract reads TIMESTAMP, which detains it as any user's transaction, and then halts: a failed "
             "deposit, which returns no withheld gas, no unspent gas and no reservoir, its gas used its whole gas limit "
             "(SATIN-DEP-006, SATIN-DEP-002)", deposit=(0, above), code=b"\x42\x50" + INVALID, **pages))
    add(Case("satin/deposits/failed/new-caller-halts", "a deposit from an absent caller, which pays the created caller's "
             "state gas, whose own frame then halts: a failed deposit, the created caller carrying no state gas and still "
             "counted as one unit of state growth (SATIN-DEP-005)", deposit=(ETH, 1_000_000), absent_sender=True,
             code=INVALID, **pages))

    # SATIN-DEP-008: the deposits that are failed deposits, whatever they carry.
    live = registry_naming(SENDER)
    add(Case("satin/deposits/failed/live-system-address", "a deposit to a contract whose caller is the live system "
             "address the registry names: a failed deposit (SATIN-DEP-008)", deposit=(0, 1_000_000), code=sstore(1, 1) + STOP,
             accounts=dict(live), **pages))
    add(Case("satin/deposits/failed/promotion-source-hash", "a deposit handed to the node already carrying the promotion's "
             "source hash from the live system address: a failed deposit (SATIN-DEP-008)", deposit=(0, 1_000_000),
             code=sstore(1, 1) + STOP, source_hash=SYSTEM_TX_SOURCE, accounts=dict(live), **pages))
    add(Case("satin/deposits/failed/system-flag", "a deposit carrying the base layer's system-transaction flag, which the "
             "base layer refuses from Regolith on: a failed deposit (SATIN-DEP-008)", deposit=(0, 1_000_000),
             code=sstore(1, 1) + STOP, system_flag=True, **pages))

    # SATIN-DEP-010: a creation from a sender at MAX_NONCE creates nothing.
    add(Case("satin/deposits/max-nonce/creation-creates-nothing", f"a deposit creating a contract from a sender at "
             f"MAX_NONCE, {model.MAX_U64}, whose initcode would write a slot: the nonce cannot be bumped, so the deposit "
             "succeeds with nothing created, no account, state gas, record or state growth for the creation, the initcode "
             "not run and its sender's nonce as it was (SATIN-DEP-010)", deposit=(0, 1_000_000), to=None,
             data=sstore(0, 1) + sstore(1, 1) + STOP, **{**pages, "sender_nonce": model.MAX_U64}))

    # SATIN-DEP-002: a user's deposit is priced by its bucket.
    add(Case("satin/deposits/bucket/fresh-slot-x4", "a user's deposit writing a fresh slot whose bucket has four times the "
             "minimum capacity: priced by its bucket at m = 4, as any transaction (SATIN-DEP-002)", deposit=(0, 1_000_000),
             code=sstore(1, 1) + STOP, salt={(CONTRACT, 1): 4}, **pages))
    return out


def oracle_page_cases() -> list[Case]:
    """The Oracle's page (SATIN-ORCL-001, -007, -008, -011, D-109): its read and write methods run as its bytecode, a
    restricted write authorized by the bytecode's own check of its immediate caller, the hint handed to the service with
    the address of the frame that sent it, and a sendHint run by DELEGATECALL, which reaches no service."""
    out: list[Case] = []
    add = out.append
    pages = dict(spec=SECOND_FILL_SPEC, system_pages=True, system=True)
    sel = model.selector
    oracle = {model.ORACLE: model.Account(code=system_contracts()[model.ORACLE], storage={1: 0xAA, 2: 0xBB})}

    add(Case("satin/oracle/get-slots/in-order", "a deposit calls the Oracle's getSlots with slots 2 and 1: their values "
             "in the order asked, each read by SLOAD in the Oracle's own frame, charged as a cold access and asking no "
             "service (SATIN-ORCL-001)", deposit=(0, 1_000_000), sender_nonce=3, to=model.ORACLE, code=None,
             data=sel("getSlots(uint256[])") + abi_words(0x20, 2, 2, 1), accounts=dict(oracle), **pages))
    set_slot = sel("setSlot(uint256,bytes32)") + abi_words(3, 7)
    add(Case("satin/oracle/set-slot/user-not-system-address", "a user's transaction calls the Oracle's setSlot(3, 7), its "
             "sender not the address the registry names: the body writes the fresh slot and is charged for it, then the "
             "bytecode's check reverts the call with NotSystemAddress(), the write taken back (SATIN-ORCL-001, "
             "SATIN-ORCL-011)", to=model.ORACLE, code=None, data=set_slot, gas=300_000,
             accounts={**oracle, **registry_naming(OTHER)}, **pages))
    add(Case("satin/oracle/set-slot/live-system-address", "a Mega System Transaction from the live system address calls "
             "the Oracle's setSlot(3, 7): promoted and run as a deposit, and the bytecode's check finds its immediate "
             "caller is the address the registry names, so the write stands (SATIN-ORCL-011)", to=model.ORACLE, code=None,
             data=set_slot, gas=1_000_000, sender_balance=0, nonce=1, sender_nonce=1, system_tx=True,
             accounts={**oracle, **registry_naming(SENDER)}, **pages))
    add(Case("satin/oracle/set-slots/lengths-differ", "a user's transaction calls the Oracle's setSlots with two slots and "
             "one value: the call reverts with InvalidLength(2, 1) before any SSTORE and before the caller is checked "
             "(SATIN-ORCL-001)", to=model.ORACLE, code=None, gas=300_000,
             data=sel("setSlots(uint256[],bytes32[])") + abi_words(0x40, 0xA0, 2, 1, 2, 1, 7),
             accounts={**oracle, **registry_naming(OTHER)}, **pages))
    hint = send_hint(7, b"\xaa")
    add(Case("satin/oracle/send-hint/from-contract", f"a contract's CALL of the Oracle's sendHint with topic 7 and one byte "
             f"of data: admitted, its {len(hint)} input bytes counted, and handed to the service with the topic, the data "
             "and the contract's address, the frame that made the call (SATIN-ORCL-007)", reads=True,
             code=bytes_to_memory(hint) + call(100_000, model.ORACLE, 0, len(hint)) + b"\x50" + STOP, **pages))
    add(Case("satin/oracle/send-hint/own-call", f"the transaction's own call of the Oracle's sendHint with topic 7 and one "
             f"byte of data: admitted on its first frame's regular gas, its {len(hint)} input bytes counted twice, as "
             "calldata and as the hint, and handed to the service with the sender's address (SATIN-ORCL-007, "
             "SATIN-ORCL-009)", reads=True, to=model.ORACLE, code=None, data=hint, gas=300_000, **pages))
    add(Case("satin/oracle/send-hint/delegatecall", "a contract's DELEGATECALL of the Oracle with sendHint's input: the "
             "bytecode runs in the contract's own context, no hint reaches the service and nothing is counted "
             "(SATIN-ORCL-008)", reads=True,
             code=bytes_to_memory(hint) + delegatecall_with(100_000, model.ORACLE, len(hint)) + b"\x50" + STOP, **pages))
    batch = multi_call(hint)
    add(Case("satin/oracle/send-hint/multicall-payload", "a contract's CALL of the Oracle's multiCall with one sendHint "
             "payload: the call is no sendHint call, and the payload runs by DELEGATECALL into the Oracle, which reaches no "
             "service and counts nothing (SATIN-ORCL-008)", reads=True,
             code=bytes_to_memory(batch) + call(100_000, model.ORACLE, 0, len(batch)) + b"\x50" + STOP, **pages))
    return out


def system_contract_cases() -> list[Case]:
    """MegaLimitControl's and the High-Precision Timestamp's pages (SATIN-MLC-001 to -004, SATIN-HPTS-001, -002,
    D-109): remainingComputeGas() answered by the node to a CALL or STATICCALL and to the transaction's own call, its
    answer the lesser of the caller's own regular gas and what a compute limit leaves, regular gas only; its bytecode
    run by a DELEGATECALL or another selector; and the timestamp read through the Oracle's getSlot, as an Oracle read,
    its update a restricted write of the Oracle, and its accessors."""
    out: list[Case] = []
    add = out.append
    pages = dict(spec=SECOND_FILL_SPEC, system_pages=True, system=True)
    sel = model.selector
    remaining = sel("remainingComputeGas()")
    ask = mstore(0, int.from_bytes(remaining, "big") << 224)
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    # The transaction's own calls name MegaLimitControl in an access list, which prices them apart from the other cases.
    own_call = dict(pages, ty=1, access_list=[(model.MEGA_LIMIT_CONTROL, [])])

    add(Case("satin/system-contracts/limit-control/own-call", "the transaction's own call of remainingComputeGas(): a CALL "
             "at depth 0, intercepted, with no calling frame, so it hears the regular gas its own frame was given "
             "(SATIN-MLC-004)", to=model.MEGA_LIMIT_CONTROL, code=None, data=remaining, **own_call))
    above = model.EXECUTION_CAP + 1_000_000
    add(Case("satin/system-contracts/limit-control/own-call-above-cap", f"the transaction's own call of "
             f"remainingComputeGas() with a gas limit of {fmt(above)}, above the execution cap: it hears the regular gas the "
             "execution cap leaves it, the reservoir not counted (SATIN-MLC-003)", to=model.MEGA_LIMIT_CONTROL, code=None,
             data=remaining, gas=above, **own_call))
    add(Case("satin/system-contracts/limit-control/own-call-detained", f"the transaction's own call of "
             f"remainingComputeGas() from the block beneficiary with a gas limit of {fmt(30_000_000)}: detained from its "
             f"start, it hears what the compute limit leaves it, {fmt(cap)}, less than its frame's regular gas "
             "(SATIN-MLC-004)", to=model.MEGA_LIMIT_CONTROL, code=None, data=remaining, gas=30_000_000, coinbase=SENDER,
             **own_call))
    asking = ask + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA
    add(Case("satin/system-contracts/limit-control/contract-call", "a contract's CALL of remainingComputeGas() forwarding "
             "all it may: the answer is its own regular gas after the opcode's charges, the forward counted back, and it "
             "returns the answer (SATIN-MLC-002)", code=asking, **pages))
    add(Case("satin/system-contracts/limit-control/detained-allowance-less", f"a contract reads TIMESTAMP with a gas limit "
             f"of {fmt(30_000_000)} and then calls remainingComputeGas(): the compute limit the read set leaves less than "
             "the contract's own regular gas, and the answer is that allowance (SATIN-MLC-002)", gas=30_000_000,
             code=b"\x42\x50" + asking, **pages))
    add(Case("satin/system-contracts/limit-control/detained-own-less", "a contract reads TIMESTAMP and then calls "
             "remainingComputeGas() with less regular gas than the compute limit leaves: the answer is its own regular gas "
             "(SATIN-MLC-002)", code=b"\x42\x50" + asking, **pages))
    add(Case("satin/system-contracts/limit-control/staticcall", "a contract's STATICCALL of remainingComputeGas(): "
             "intercepted as a CALL is, and answered its own regular gas (SATIN-MLC-001, SATIN-MLC-002)",
             code=ask + staticcall_with(MAX_GAS, model.MEGA_LIMIT_CONTROL, 4) + b"\x50" + RETURN_RETURNDATA, **pages))
    add(Case("satin/system-contracts/limit-control/delegatecall", "a contract's DELEGATECALL of remainingComputeGas(): not "
             "intercepted, so MegaLimitControl's bytecode runs and reverts with NotIntercepted(), which the contract "
             "returns (SATIN-MLC-001)", code=ask + delegatecall_with(MAX_GAS, model.MEGA_LIMIT_CONTROL, 4) + b"\x50"
             + RETURN_RETURNDATA, **pages))
    other = mstore(0, int.from_bytes(OTHER_SELECTOR, "big") << 224)
    add(Case("satin/system-contracts/limit-control/other-selector", "a contract's CALL of MegaLimitControl with a selector "
             "it does not intercept: the bytecode runs and reverts with NotIntercepted(), which the contract returns "
             "(SATIN-MLC-001)", code=other + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA,
             **pages))

    # The High-Precision Timestamp (SATIN-HPTS-001, -002).
    micros = BLOCK_TIMESTAMP * 1_000_000
    oracle = {model.ORACLE: model.Account(code=system_contracts()[model.ORACLE],
                                          storage={model.TIMESTAMP_BASE_SLOT: micros})}
    timestamp = sel("timestamp()")
    add(Case("satin/system-contracts/timestamp/read", "a deposit calls the High-Precision Timestamp's timestamp(): it reads "
             "the Oracle's slot TIMESTAMP_BASE_SLOT through getSlot, an Oracle read charged as a cold access that asks no "
             "service for a deposit, and returns the slot's value (SATIN-HPTS-001, SATIN-HPTS-002)",
             deposit=(0, 1_000_000), sender_nonce=3, to=model.HIGH_PRECISION_TIMESTAMP, code=None, data=timestamp,
             accounts={**oracle, **TIMESTAMP_CONTRACT}, **pages))
    burner = burn(words_within(model.ORACLE_ACCESS_COMPUTE_GAS) + 1) + STOP
    reading = (mstore(0, int.from_bytes(timestamp, "big") << 224) + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, 4)
               + b"\x50" + call(MAX_GAS, BURNER, 0, 0) + RETURN_RETURNDATA)
    add(Case("satin/system-contracts/timestamp/read-detains", "a deposit's contract reads the timestamp and then calls a "
             "contract whose one charge passes the Oracle's cap: the wrapper's read is an Oracle read, marked for gas "
             "detention, and the later charge is stopped, the deposit returning the stop (SATIN-HPTS-002)",
             deposit=(0, 22_000_000), sender_nonce=3, code=reading,
             accounts={**oracle, **TIMESTAMP_CONTRACT, BURNER: model.Account(nonce=1, code=burner)}, **pages))
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
    refused = (disable + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50" + mstore(0, int.from_bytes(timestamp, "big")
                                                                                            << 224)
               + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, 4) + b"\x50" + RETURN_RETURNDATA)
    add(Case("satin/system-contracts/timestamp/read-refused", "a contract switches its volatile-data access off and then "
             "reads the timestamp: the Oracle's SLOAD in a frame below it is refused, the Oracle reverting with "
             "VolatileDataAccessDisabled(11), which the wrapper and the contract return (SATIN-HPTS-002)", code=refused,
             accounts={**oracle, **TIMESTAMP_CONTRACT}, **pages))
    update = sel("update(uint256)") + word(micros + 1)
    add(Case("satin/system-contracts/timestamp/update-not-live", "a user's transaction calls the timestamp's update: it "
             "forwards to the Oracle's setSlot, whose immediate caller, the timestamp contract, is not the live system "
             "address, so the Oracle reverts with NotSystemAddress() and the wrapper returns that revert "
             "(SATIN-HPTS-001)", to=model.HIGH_PRECISION_TIMESTAMP, code=None, data=update, gas=300_000,
             accounts={**oracle, **TIMESTAMP_CONTRACT, **registry_naming(OTHER)}, **pages))
    add(Case("satin/system-contracts/timestamp/update-live", "a user's transaction calls the timestamp's update while the "
             "registry names the timestamp contract as the live system address: the Oracle's setSlot authorizes its "
             "immediate caller, so the write of slot TIMESTAMP_BASE_SLOT stands (SATIN-HPTS-001, SATIN-ORCL-011)",
             to=model.HIGH_PRECISION_TIMESTAMP, code=None, data=update, gas=300_000,
             accounts={**oracle, **TIMESTAMP_CONTRACT, **registry_naming(model.HIGH_PRECISION_TIMESTAMP)}, **pages))
    for name, method in (("oracle-address", "ORACLE_CONTRACT_ADDRESS()"), ("allocation-start", "ALLOCATION_START()"),
                         ("allocation-size", "ALLOCATION_SIZE()")):
        add(Case(f"satin/system-contracts/timestamp/{name}", f"the transaction's own call of the timestamp's {method}: the "
                 "constant its interface states, from the contract's own code (SATIN-HPTS-001)",
                 to=model.HIGH_PRECISION_TIMESTAMP, code=None, data=sel(method), accounts=dict(TIMESTAMP_CONTRACT), **pages))
    return out


def callcode_with(gas: int, target: bytes, value: int, in_size: int) -> bytes:
    """CALLCODE(gas, target, value, 0, in_size, 0, 0)."""
    return push(0) + push(0) + push(in_size) + push(0) + push(value) + push(int.from_bytes(target, "big")) + push(gas) + b"\xf2"


def returndata_to(offset: int) -> bytes:
    """RETURNDATACOPY(offset, 0, RETURNDATASIZE)."""
    return b"\x3d" + push(0) + push(offset) + b"\x3e"


HINT_CHILD = bytes.fromhex("00000000000000000000000000000000000c0e20")  # a child that sends a hint, then reverts
STATIC_RELAY = bytes.fromhex("00000000000000000000000000000000000c0e21")  # a frame a STATICCALL started that sends a hint
ASKER = bytes.fromhex("00000000000000000000000000000000000c0e22")  # a child that asks remainingComputeGas()
LIVE_CODE = bytes.fromhex("00000000000000000000000000000000000c0e23")  # code the live system address delegates to


def system_pages_gap_cases() -> list[Case]:
    """The edges an independent review of the deposits and system-contract cases found unpinned (D-109): a user's deposit detained from its start and its own remainingComputeGas() call; hints
    dropped before any size check, at a child's gas of 0 and 1 and on a value call's stipend, malformed or unpadded,
    sent by STATICCALL and CALLCODE, and kept in order through a failed deposit; the Oracle's write from delegated
    live-system code, a read after a write, a repeated slot, and its code on another account's storage; a creation from
    MAX_NONCE carrying a funded value; a creating deposit's bucket, its reverting initcode and its code deposit; dispatch
    by address and four selector bytes; a transaction's own value call of an intercepted method; MegaLimitControl's
    answer on a restricted forward, above the execution cap, in a nested frame and detained by an authority; multiCall's
    failures, emitLog and setSlots of one slot twice; an existing sender empty under EIP-161; and the timestamp read
    twice."""
    out: list[Case] = []
    add = out.append
    sel = model.selector
    pages = dict(spec=SECOND_FILL_SPEC, system_pages=True)
    sys_pages = dict(pages, system=True)
    history = model.COST_PER_HISTORY_BYTE
    body = model.TX_BODY_SIZE * history
    record = model.WRITE_RECORD_SIZE * history
    call_plain = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    remaining = sel("remainingComputeGas()")
    ask = mstore(0, int.from_bytes(remaining, "big") << 224)
    hint = send_hint(7, b"\xaa")
    oracle_code = system_contracts()[model.ORACLE]

    # 1. A user's deposit detained from its start (SATIN-DET-008, SATIN-DEP-002), and its own remainingComputeGas().
    burner = burn(words_within(cap) + 1) + STOP
    for name, coinbase, what in (("sender", SENDER, "its sender is"), ("recipient", CONTRACT, "its recipient is")):
        add(Case(f"satin/deposits/detained-from-start/{name}-is-beneficiary", f"a user's deposit with a gas limit of "
                 f"{fmt(30_000_000)} whose {name} is the block beneficiary: detained from its start, as any transaction "
                 f"whose {what} the beneficiary, its compute limit {fmt(cap)}, so its contract's one memory expansion past "
                 "that limit is the crossing: the deposit is stopped, a revert and no failed deposit, its mint and nonce "
                 "kept (SATIN-DEP-002)", deposit=(0, 30_000_000), sender_nonce=3, code=burner, coinbase=coinbase,
                 **pages))
    add(Case("satin/deposits/detained-from-start/no-party-is-beneficiary", "the same deposit with neither its sender nor "
             "its recipient the block beneficiary: no limit is set, and the expansion is paid (SATIN-DEP-002)",
             deposit=(0, 30_000_000), sender_nonce=3, code=burner, **pages))
    for name, coinbase, what in (("own-call", COINBASE, "no limit set, so it hears its own frame's regular gas"),
                                 ("own-call-detained", OTHER, f"its sender the block beneficiary, so it is detained from "
                                  f"its start and hears {fmt(cap)}")):
        add(Case(f"satin/deposits/limit-control/{name}", f"a deposit from an absent caller whose own call is "
                 f"remainingComputeGas(), with a gas limit of {fmt(30_000_000)}: a CALL at depth 0, intercepted, {what} "
                 "(SATIN-MLC-004)", deposit=(0, 30_000_000), absent_sender=True, to=model.MEGA_LIMIT_CONTROL, code=None,
                 data=remaining, coinbase=coinbase, **sys_pages))

    # 2. A dropped hint is never size-checked (SATIN-ORCL-006, -010): twelve admitted hints of 1 MiB, then a hint that
    # would cross the data-size limit, from a frame whose access is off, or forwarded no gas.
    big = 1 << 20
    count = (model.TX_DATA_LIMIT - model.TX_BODY_SIZE) // big
    helpers = b"".join(push(0) + push(0) + push(big) + push(0) + push(0) + push(int.from_bytes(model.ORACLE, "big"))
                       + push(1) + b"\xf1\x50" for _ in range(count))
    past = model.TX_DATA_LIMIT - model.TX_BODY_SIZE - count * big + 1
    disable = (mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
               + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50")
    hint_selector = mstore(0, int.from_bytes(model.SEND_HINT, "big") << 224)
    for name, gas_op, prefix, what in (
            ("access-off-past-limit", 100_000, disable, "the frame switches its volatile-data access off and"),
            ("no-gas-past-limit", 0, b"", "the frame")):
        add(Case(f"satin/oracle/send-hint/{name}", f"{NUMBERS.get(count, str(count))} admitted 1 MiB hints, then {what} "
                 f"sends a hint of {fmt(past)} input bytes, one past what the data-size limit leaves, "
                 + ("forwarding 100,000 gas" if gas_op else "forwarding no gas with no value") + ": not admitted, so "
                 "dropped and never size-checked, no stop; the call runs the Oracle's bytecode (SATIN-ORCL-006)",
                 gas=4_000_000, code=hint_selector + helpers + prefix + hint_selector + call(gas_op, model.ORACLE, 0, past)
                 + record_result() + STOP, **sys_pages))

    # 3. A child's regular gas of 0 and 1, and a value call's stipend (SATIN-ORCL-006, -007).
    laid = bytes_to_memory(hint)
    for name, gas_op, value, balance, what in (
            ("gas-zero", 0, 0, 0, "forwarding no gas and no value: its frame would start with none, so the hint is "
             "dropped, nothing counted or handed, and the frame runs out of gas at once"),
            ("gas-one", 1, 0, 0, "forwarding one gas: admitted, counted and handed to the service, and then its frame runs "
             "out of gas"),
            ("stipend-funded", 0, 1, 10, "requesting no gas with 1 wei it can fund: its frame starts on the stipend, so "
             "the hint is admitted and handed, and the bytecode refuses the value"),
            ("stipend-unfunded", 0, 1, 0, "requesting no gas with 1 wei it cannot fund: admitted on the stipend and handed, "
             "and then its frame start refuses the call")):
        add(Case(f"satin/oracle/send-hint/{name}", f"a contract's CALL of sendHint {what} (SATIN-ORCL-006, "
                 "SATIN-ORCL-007)", reads=True, contract_balance=balance,
                 code=laid + call(gas_op, model.ORACLE, value, len(hint)) + record_result() + STOP, **sys_pages))

    # 4. Malformed and noncanonical input (SATIN-ORCL-009).
    unpadded = model.SEND_HINT + word(7) + word(0x40) + word(1) + b"\xaa"
    for name, data, what in (
            ("selector-only", model.SEND_HINT, "sendHint's selector alone, 4 bytes: admitted and counted, it decodes as no "
             "hint and reaches no service, and the bytecode's decoder reverts"),
            ("trailing-byte", hint + b"\xaa", f"a canonical input followed by one byte, {len(hint) + 1} bytes: all of them "
             "counted, and the same topic and data handed as without the byte"),
            ("unpadded", unpadded, f"a valid input whose data is not padded to a word, {len(unpadded)} bytes: counted and "
             "handed, the decoder needing no padding")):
        add(Case(f"satin/oracle/send-hint/{name}", f"a contract's CALL of the Oracle with {what} (SATIN-ORCL-009)",
                 reads=True, code=bytes_to_memory(data) + call(100_000, model.ORACLE, 0, len(data)) + record_result() + STOP,
                 **sys_pages))

    # 5. The Oracle's write from code the live system address delegates to, in a user's deposit (SATIN-ORCL-011).
    set_slot = sel("setSlot(uint256,bytes32)") + abi_words(3, 7)
    writer = bytes_to_memory(set_slot) + call(200_000, model.ORACLE, 0, len(set_slot)) + b"\x50" + RETURN_RETURNDATA
    live_delegated = {DELEGATED: model.Account(code=model.DELEGATION_PREFIX + LIVE_CODE),
                      LIVE_CODE: model.Account(nonce=1, code=writer), **registry_naming(DELEGATED),
                      model.ORACLE: model.Account(code=oracle_code)}
    add(Case("satin/oracle/set-slot/delegated-live-address", "a user's deposit calls the live system address, which holds "
             "an EIP-7702 delegation to code that calls the Oracle's setSlot(3, 7): the Oracle's immediate caller is the "
             "live system address, whatever sent the transaction and whatever its type, so the write stands "
             "(SATIN-ORCL-011)", deposit=(0, 1_000_000), sender_nonce=3, to=DELEGATED, code=None,
             accounts=dict(live_delegated), **sys_pages))
    add(Case("satin/oracle/set-slot/deposit-not-system-address", "the same deposit calling the Oracle's setSlot(3, 7) "
             "itself: its immediate caller, the deposit's sender, is not the live system address, so the call reverts "
             "with NotSystemAddress() (SATIN-ORCL-011)", deposit=(0, 1_000_000), sender_nonce=3, to=model.ORACLE, code=None,
             data=set_slot, accounts=dict(live_delegated), **sys_pages))

    # 6. A read after an authorized write, and a repeated slot (SATIN-ORCL-002, -003).
    micros = BLOCK_TIMESTAMP * 1_000_000
    stamped = {model.ORACLE: model.Account(code=oracle_code, storage={model.TIMESTAMP_BASE_SLOT: micros}),
               **TIMESTAMP_CONTRACT}
    update = sel("update(uint256)") + word(micros + 1)
    timestamp = sel("timestamp()")
    write_then_read = (bytes_to_memory(update) + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, len(update)) + b"\x50"
                       + mstore(0, int.from_bytes(timestamp, "big") << 224)
                       + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, 4) + b"\x50" + RETURN_RETURNDATA)
    add(Case("satin/system-contracts/timestamp/update-then-read", "a deposit's contract updates the timestamp while the "
             "registry names the timestamp contract, and then reads it: the Oracle's read pushes the slot's present "
             "value, the write made earlier in the deposit, charged as a cold access (SATIN-HPTS-001, SATIN-ORCL-002)",
             deposit=(0, 1_000_000), sender_nonce=3, code=write_then_read,
             accounts={**stamped, **registry_naming(model.HIGH_PRECISION_TIMESTAMP)}, **sys_pages))
    two_slots = {model.ORACLE: model.Account(code=oracle_code, storage={1: 0xAA, 2: 0xBB})}
    add(Case("satin/oracle/get-slots/repeated-slot", "a deposit calls the Oracle's getSlots with slots 2, 2 and 1: the "
             "values in that order, and the second read of slot 2 charged as a cold access again (SATIN-ORCL-003)",
             deposit=(0, 1_000_000), sender_nonce=3, to=model.ORACLE, code=None,
             data=sel("getSlots(uint256[])") + abi_words(0x20, 3, 2, 2, 1), accounts=dict(two_slots), **sys_pages))

    # 7. The Oracle's code on another account's storage (SATIN-ORCL-002).
    get_one = sel("getSlot(uint256)") + word(1)
    elsewhere = (bytes_to_memory(get_one) + delegatecall_with(100_000, model.ORACLE, len(get_one)) + b"\x50"
                 + delegatecall_with(100_000, model.ORACLE, len(get_one)) + b"\x50"
                 + burn(words_within(model.ORACLE_ACCESS_COMPUTE_GAS) + 1) + RETURN_RETURNDATA)
    add(Case("satin/oracle/get-slot/delegatecall-own-storage", "a deposit's contract, whose slot 1 holds 9, runs the "
             "Oracle's getSlot(1) twice by DELEGATECALL, the Oracle's own slot 1 holding 7, and then expands its memory "
             "past the Oracle's cap: the reads are its own slot's, 9, a cold and then a warm SLOAD, no Oracle read, so "
             "nothing is marked and the expansion is paid (SATIN-ORCL-002)", deposit=(0, 22_000_000), sender_nonce=3,
             code=elsewhere, storage={1: 9}, accounts={model.ORACLE: model.Account(code=oracle_code, storage={1: 7})},
             **sys_pages))

    # 8. A STATICCALL of sendHint is a sendHint call (SATIN-ORCL-008), and from a frame a STATICCALL started.
    add(Case("satin/oracle/send-hint/staticcall", "a contract's STATICCALL of sendHint: a sendHint call, admitted, counted "
             "and handed to the service with the contract's address, the hint being no write of state (SATIN-ORCL-008)",
             reads=True, code=laid + staticcall_with(100_000, model.ORACLE, len(hint)) + record_result() + STOP,
             **sys_pages))
    relay = laid + staticcall_with(100_000, model.ORACLE, len(hint)) + b"\x50" + STOP
    add(Case("satin/oracle/send-hint/staticcall-in-static-frame", "a contract's STATICCALL of a relay, which STATICCALLs "
             "sendHint from its static frame: admitted, and handed with the relay's address (SATIN-ORCL-008)", reads=True,
             code=staticcall_with(200_000, STATIC_RELAY, 0) + record_result() + STOP,
             accounts={STATIC_RELAY: model.Account(nonce=1, code=relay)}, **sys_pages))

    # 10. A creation from MAX_NONCE carrying a value its mint funds (SATIN-DEP-010).
    add(Case("satin/deposits/max-nonce/creation-with-value", f"a deposit creating a contract from a sender at MAX_NONCE "
             "holding no balance, minting 1 wei and carrying 1 wei: the value is checked first, against the balance with "
             "the mint credited, which funds it exactly; the creation then creates nothing, and the value moves nowhere, "
             "the sender keeping its minted wei (SATIN-DEP-010)", deposit=(1, 1_000_000), to=None,
             data=sstore(0, 1) + sstore(1, 1) + STOP, value=1, **{**pages, "sender_nonce": model.MAX_U64, "sender_balance": 0}))

    # 11. A creating deposit's bucket: the created address's, from the sender's nonce (SATIN-DEP-002, -012).
    nonce_zero = model.created_address(SENDER, 0)
    for name, salt, what in (
            ("crowded-created-address", {("created", None): 4}, "the created address's bucket at four times the minimum "
             "capacity"),
            ("crowded-other-address", {(nonce_zero, None): 4}, "the bucket of the address nonce 0 would derive at four "
             "times the minimum capacity, which is never read")):
        add(Case(f"satin/deposits/creation/reverts-{name}", f"a deposit from a sender of nonce 3 whose initcode reverts, "
                 f"{what}: the deposit reverts, not a failed deposit, its created account and its charges taken back; its "
                 "reads keep the created address and its bucket's capacity (SATIN-DEP-012)", deposit=(0, 1_000_000),
                 sender_nonce=3, to=None, data=revert(0, 0), salt=salt, reads=True, **pages))
    add(Case("satin/deposits/creation/crowded-created-address", "a deposit creating an empty contract in a bucket of four "
             "times the minimum capacity: its created account's state gas priced at m = 4 (SATIN-DEP-002)",
             deposit=(0, 1_000_000), sender_nonce=3, to=None, data=b"", salt={("created", None): 4}, **pages))

    # 12. Dispatch is the address and four selector bytes (SATIN-ICPT-001, SATIN-MLC-001).
    trailing = remaining + b"\xaa"
    add(Case("satin/system-contracts/limit-control/trailing-byte", "a contract's CALL of remainingComputeGas() followed by "
             "one more byte: matched on the four selector bytes alone, intercepted and answered (SATIN-MLC-001)",
             code=bytes_to_memory(trailing) + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, len(trailing)) + b"\x50"
             + RETURN_RETURNDATA, **sys_pages))
    add(Case("satin/system-contracts/limit-control/three-byte-input", "a contract's CALL of MegaLimitControl with the "
             "selector's first three bytes: no selector, so not intercepted, and the bytecode reverts with "
             "NotIntercepted() (SATIN-MLC-001)", code=ask + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 3) + b"\x50"
             + RETURN_RETURNDATA, **sys_pages))
    add(Case("satin/system-contracts/limit-control/selector-elsewhere", "a contract's CALL of another contract, which "
             "stops, with remainingComputeGas()'s selector: matching is on the address first, so nothing intercepts it "
             "and its code runs (SATIN-MLC-001)", code=ask + call(MAX_GAS, PLAIN, 0, 4) + b"\x50" + RETURN_RETURNDATA,
             accounts={PLAIN: model.Account(nonce=1, code=STOP)}, **sys_pages))
    add(Case("satin/system-contracts/limit-control/other-code-at-address", "a contract's CALL of remainingComputeGas() at "
             "MegaLimitControl's address, which holds a code that only stops: interception matches the address and the "
             "selector, never the code, so the call is answered (SATIN-MLC-001)",
             code=ask + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA,
             accounts={model.MEGA_LIMIT_CONTROL: model.Account(code=STOP)}, **sys_pages))

    # 13. The transaction's own value call of an intercepted method (SATIN-ICPT-003).
    add(Case("satin/system-contracts/limit-control/own-call-with-value", "the transaction's own call of "
             "remainingComputeGas() carrying 1 wei: answered NonZeroTransfer() at depth 0 before any value moves, the "
             "value staying with the sender and the start record's history given back (SATIN-MLC-001)",
             to=model.MEGA_LIMIT_CONTROL, code=None, data=remaining, value=1, **sys_pages))
    add(Case("satin/interception/access-control/own-call-with-value", "the transaction's own call of "
             "disableVolatileDataAccess() carrying 1 wei: answered NonZeroTransfer() at depth 0 before any value moves, "
             "the start record's history given back (SATIN-ICPT-003)", to=model.MEGA_ACCESS_CONTROL, code=None,
             data=model.DISABLE_VOLATILE_DATA_ACCESS, value=1, **sys_pages))

    # 14. A restricted forward and a reservoir (SATIN-MLC-002, -003).
    for name, gas_op, what in (("forward-zero", 0, "forwarding no gas"), ("forward-one", 1, "forwarding one gas")):
        add(Case(f"satin/system-contracts/limit-control/{name}", f"a contract's CALL of remainingComputeGas() {what}: the "
                 "answer is the caller's own regular gas, the forward counted back (SATIN-MLC-002)",
                 code=ask + call(gas_op, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA, **sys_pages))
    above = model.EXECUTION_CAP + 1_000_000
    add(Case("satin/system-contracts/limit-control/contract-call-above-cap", f"a contract's CALL of remainingComputeGas() "
             f"with a gas limit of {fmt(above)}: the caller holds a reservoir and gives the call its share, and the answer "
             "is its regular gas alone (SATIN-MLC-003)", gas=above,
             code=ask + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA, **sys_pages))

    # 15. The transaction's allowance across a nested frame, and an authority that is the beneficiary (SATIN-MLC-002, -004).
    asker = ask + call(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50" + RETURN_RETURNDATA
    nested = b"\x42\x50" + burn(words_within(5_000_000)) + call(MAX_GAS, ASKER, 0, 0) + b"\x50" + RETURN_RETURNDATA
    add(Case("satin/system-contracts/limit-control/nested-allowance", f"a contract reads TIMESTAMP with a gas limit of "
             f"{fmt(30_000_000)}, spends compute, and calls a child that asks remainingComputeGas(): the answer is the "
             "transaction's allowance, what the limit leaves its compute across both frames, below the child's own "
             "regular gas (SATIN-MLC-002)", gas=30_000_000, code=nested, accounts={ASKER: model.Account(nonce=1, code=asker)},
             **sys_pages))
    add(Case("satin/system-contracts/limit-control/own-call-detained-by-authority", f"the transaction's own call of "
             f"remainingComputeGas() with a gas limit of {fmt(30_000_000)} whose EIP-7702 list applies an authorization "
             f"of the block beneficiary: detained from its start, it hears {fmt(cap)} (SATIN-MLC-004)", ty=4,
             to=model.MEGA_LIMIT_CONTROL, code=None, data=remaining, gas=30_000_000,
             authorizations=[(AUTH_KEY, CHAIN_ID, CONTRACT, 0)], coinbase=AUTHORITY, **sys_pages))

    # 16. CALLCODE runs the bytecode (SATIN-ORCL-008, SATIN-MLC-001).
    add(Case("satin/oracle/send-hint/callcode", "a contract's CALLCODE of the Oracle with sendHint's input: no sendHint "
             "call, so the bytecode runs in the contract's context, nothing counted and nothing handed "
             "(SATIN-ORCL-008)", reads=True, code=laid + callcode_with(100_000, model.ORACLE, 0, len(hint)) + record_result()
             + STOP, **sys_pages))
    add(Case("satin/system-contracts/limit-control/callcode", "a contract's CALLCODE of remainingComputeGas(): not "
             "intercepted, so MegaLimitControl's bytecode runs and reverts with NotIntercepted(), which the contract returns "
             "(SATIN-MLC-001)", code=ask + callcode_with(MAX_GAS, model.MEGA_LIMIT_CONTROL, 0, 4) + b"\x50"
             + RETURN_RETURNDATA, **sys_pages))

    # 17. Hints in order across a reverted child and a failed deposit (SATIN-DEP-006, SATIN-ORCL-007).
    child_hint = send_hint(8, b"\xbb")
    third = send_hint(9, b"\xcc")
    child = bytes_to_memory(child_hint) + call(100_000, model.ORACLE, 0, len(child_hint)) + b"\x50" + revert(0, 0)
    parent = (laid + call(100_000, model.ORACLE, 0, len(hint)) + b"\x50" + call(200_000, HINT_CHILD, 0, 0) + b"\x50"
              + bytes_to_memory(third) + call(100_000, model.ORACLE, 0, len(third)) + b"\x50" + INVALID)
    add(Case("satin/deposits/failed/three-hints-kept", "a deposit's contract sends a hint, calls a child that sends another "
             "and reverts, sends a third and halts: a failed deposit, which keeps all three hints' bytes as data size, "
             "and the service was handed the three in order, the second from the child (SATIN-DEP-006)", reads=True,
             deposit=(0, 1_000_000), sender_nonce=3, code=parent, accounts={HINT_CHILD: model.Account(nonce=1, code=child)},
             **sys_pages))

    # 18. multiCall's failures, emitLog, and setSlots of one slot twice (SATIN-ORCL-001, -011).
    oracle_plain = {model.ORACLE: model.Account(code=oracle_code)}
    add(Case("satin/oracle/multicall/first-payload-fails", "a user's multiCall of setSlot(3, 7) and getSlot(3): the first "
             "payload writes, then reverts with NotSystemAddress(), and multiCall reverts with that data at once, the "
             "second payload never run (SATIN-ORCL-001)", to=model.ORACLE, code=None, gas=300_000,
             data=multi_call(set_slot, sel("getSlot(uint256)") + word(3)),
             accounts={**oracle_plain, **registry_naming(OTHER)}, **sys_pages))
    add(Case("satin/oracle/multicall/empty-revert", "a user's multiCall of a payload whose selector the Oracle does not "
             "declare, which reverts with empty data: multiCall reverts with Error(\"Multicall: call failed\") "
             "(SATIN-ORCL-001)", to=model.ORACLE, code=None, gas=300_000, data=multi_call(OTHER_SELECTOR),
             accounts={**oracle_plain, **registry_naming(OTHER)}, **sys_pages))
    emit = sel("emitLog(bytes32,bytes)") + abi_words(5, 0x40, 1) + b"\xee".ljust(32, b"\x00")
    add(Case("satin/oracle/emit-log/not-system-address", "a user's emitLog: the log is emitted and charged, then the call "
             "reverts with NotSystemAddress(), taking the log back (SATIN-ORCL-001, SATIN-ORCL-011)", to=model.ORACLE,
             code=None, gas=300_000, data=emit, accounts={**oracle_plain, **registry_naming(OTHER)}, **sys_pages))
    add(Case("satin/oracle/emit-log/live-system-address", "a Mega System Transaction's emitLog: the log stands, emitted by "
             "the Oracle (SATIN-ORCL-011)", to=model.ORACLE, code=None, data=emit, gas=1_000_000, sender_balance=0,
             nonce=1, sender_nonce=1, system_tx=True, accounts={**oracle_plain, **registry_naming(SENDER)}, **sys_pages))
    add(Case("satin/oracle/set-slots/same-slot-twice", "a Mega System Transaction's setSlots of slot 3 twice, to 7 and "
             "then 8: the writes run in order and the last stands (SATIN-ORCL-001)", to=model.ORACLE, code=None,
             data=sel("setSlots(uint256[],bytes32[])") + abi_words(0x40, 0xA0, 2, 3, 3, 2, 7, 8), gas=1_000_000,
             sender_balance=0, nonce=1, sender_nonce=1, system_tx=True,
             accounts={**oracle_plain, **registry_naming(SENDER)}, **sys_pages))

    # 19. An existing sender empty under EIP-161 (SATIN-DEP-003, -005, -012).
    least = call_plain + body + 2 * model.ACCOUNT_STATE
    for name, gas, nonce, what in (
            ("unpaid", least - 1, 0, f"one short of its new-account state gas at m = 2, {fmt(2 * model.ACCOUNT_STATE)}: a "
             "failed deposit at step 1, the account counted as one unit of state growth with no state gas, its bucket's "
             "capacity read and its recipient not loaded"),
            ("paid", least, 0, "paying its new-account state gas at m = 2 exactly: the account created and charged once"),
            ("nonce-one", least - 1, 1, "with a nonce of 1, so not empty: no new-account charge, and the deposit "
             "succeeds")):
        add(Case(f"satin/deposits/empty-caller/{name}", f"a deposit minting 1 wei from a sender the state holds with no "
                 f"balance and no code, {what} (SATIN-DEP-003, SATIN-DEP-012)", deposit=(1, gas), sender_nonce=nonce,
                 sender_balance=0, salt={("sender", None): 2}, reads=True, **pages))

    # 21. A creating deposit's code deposit, and its initcode's revert with data (SATIN-DEP-004, -007).
    one_byte = init_returning(b"\xee")
    paid = least_paying(Case("probe", "", deposit=(0, 1_000_000), sender_nonce=3, to=None, data=one_byte, **pages))
    for name, gas, what in (("code-deposit-one-short", paid - 1, "one gas short of its one byte's code deposit: the "
                             "creation halts, a failed deposit"),
                            ("code-deposit-paid", paid, "paying its one byte's code deposit exactly: deployed")):
        add(Case(f"satin/deposits/creation/{name}", f"a deposit creating a contract whose initcode returns one byte, "
                 f"with a gas limit of {fmt(gas)}, {what} (SATIN-DEP-004)", boundary=f"the gas limit {'one below' if gas < paid else 'at'} "
                 "the code deposit's last charge", deposit=(0, gas), sender_nonce=3, to=None, data=one_byte, **pages))
    add(Case("satin/deposits/creation/initcode-reverts-with-data", "a deposit creating a contract whose initcode reverts "
             "with one word: a revert, not a failed deposit, its mint and nonce kept and its REVERT data its output "
             "(SATIN-DEP-007)", deposit=(0, 1_000_000), sender_nonce=3, to=None, data=mstore(0, 0xBAD) + revert(0, 32),
             **pages))

    # 22. The timestamp read twice, its slot holding zero (SATIN-HPTS-001, -002).
    twice = (mstore(0, int.from_bytes(timestamp, "big") << 224) + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, 4)
             + b"\x50" + returndata_to(32) + call(MAX_GAS, model.HIGH_PRECISION_TIMESTAMP, 0, 4) + b"\x50"
             + returndata_to(64) + ret(32, 64))
    add(Case("satin/system-contracts/timestamp/read-twice", "a deposit's contract reads the timestamp twice, its slot "
             "holding zero, and returns both answers: the same word twice, each read an Oracle read charged as a cold "
             "access (SATIN-HPTS-001, SATIN-HPTS-002)", deposit=(0, 1_000_000), sender_nonce=3, code=twice,
             accounts={**oracle_plain, **TIMESTAMP_CONTRACT}, **sys_pages))

    # 3, its own-call variant: a deposit's own sendHint on a first frame of 0 and of 1 regular gas (SATIN-ORCL-006).
    zeros = hint.count(0)
    paid_before = (call_plain + model.CALLDATA_ZERO * zeros + model.CALLDATA_NONZERO * (len(hint) - zeros)
                   + (model.TX_BODY_SIZE + len(hint)) * history)
    for left, what in ((0, "with no regular gas, so the hint is dropped, counted once as calldata only"),
                       (1, "with one regular gas, so the hint is admitted, counted a second time and handed with the "
                        "sender's address")):
        add(Case(f"satin/deposits/own-hint/first-frame-gas-{'zero' if left == 0 else 'one'}", f"a deposit whose own call "
                 f"is sendHint, its gas limit of {fmt(paid_before + left)} leaving its first frame {what}; the Oracle's "
                 "bytecode then runs out of gas, so the deposit is a failed deposit, which keeps the data size of its "
                 "body and of a hint it admitted (SATIN-DEP-006)", boundary=f"the first frame's regular gas at {left}",
                 deposit=(0, paid_before + left), sender_nonce=3, to=model.ORACLE, code=None, data=hint, reads=True,
                 **sys_pages))

    # 23. A contract's DELEGATECALL or CALLCODE of KeylessDeploy with arguments that decode (SATIN-ICPT-006).
    keyless_input = model.KEYLESS_DEPLOY_CALL + word(0x40) + word(1_000_000) + word(5) + bytes.fromhex("0102030405")
    held = {model.KEYLESS_DEPLOY: model.Account(code=STOP)}
    for name, op in (("delegatecall", delegatecall_with(MAX_GAS, model.KEYLESS_DEPLOY, len(keyless_input))),
                     ("callcode", callcode_with(MAX_GAS, model.KEYLESS_DEPLOY, 0, len(keyless_input)))):
        add(Case(f"satin/interception/keyless/{name}-runs-held-code", f"a contract's {name.upper()} of KeylessDeploy's "
                 "address, which holds a code that only stops, with keylessDeploy's selector and arguments that decode: "
                 "recognition needs a CALL at depth 0, so the held code runs and succeeds (SATIN-ICPT-006)",
                 code=bytes_to_memory(keyless_input) + op + record_result() + STOP, accounts=dict(held), **sys_pages))
    return out


def least_paying(c: Case) -> int:
    """The least gas limit at which a deposit's frame succeeds, from the model's own derivation (D-59): a search over
    the gas limit, every charge before the frame fixed."""
    lo, hi = 1, c.deposit[1]
    while lo < hi:
        mid = (lo + hi) // 2
        c.deposit = (c.deposit[0], mid)
        _, result, _ = build(c)
        if result.observations["outcome"]["admission"]["status"] == "admitted":
            hi = mid
        else:
            lo = mid + 1
    return lo


# --- History gas and the history allowance, and resource accounting: the rules no case pinned (D-100) ---------

ALLOWANCE_CHILD = bytes.fromhex("00000000000000000000000000000000000c0f01")  # a value call's child that logs or writes
DELEGATED_LOGGER = bytes.fromhex("00000000000000000000000000000000000c0f02")  # code a frame runs by DELEGATECALL
FAILING = bytes.fromhex("00000000000000000000000000000000000c0f03")  # a contract that reverts at once
CALLCODE_TARGET = bytes.fromhex("00000000000000000000000000000000000c0f04")  # code a CALLCODE runs, which stops
PAYEE_Q = bytes.fromhex("00000000000000000000000000000000000c0f05")  # an existing contract a frame sends value to
PAYEE_R = bytes.fromhex("00000000000000000000000000000000000c0f06")  # a second one
RELAY_W = bytes.fromhex("00000000000000000000000000000000000c0f07")  # a frame that calls and then fails or succeeds
GROWER_D = bytes.fromhex("00000000000000000000000000000000000c0f08")  # a frame that writes fresh slots


def jumpdests(n: int) -> bytes:
    """`n` JUMPDESTs, one gas each: a pad that burns exactly `n` of a frame's regular gas."""
    return b"\x5b" * n


def history_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    record = model.WRITE_RECORD_SIZE * model.COST_PER_HISTORY_BYTE
    log0 = model.LOG_BASE_SIZE * model.COST_PER_HISTORY_BYTE
    allowance = model.HISTORY_ALLOWANCE_BYTES * model.COST_PER_HISTORY_BYTE
    log0_ops = 2 * model.G_BASE + model.LOG_COST  # PUSH0, PUSH0, LOG0

    def case(name: str, intent: str, **kw) -> None:
        add(Case(f"satin/history/{name}", intent, spec=spec, **kw))

    # SATIN-HIST-001: history is COST_PER_HISTORY_BYTE a byte, whatever bucket the state charges land in.
    init = sstore(0, 1) + log(0, 0, 0, []) + init_returning(b"\x01")
    case("unscaled/creation-in-crowded-buckets", "a creation transaction whose created account's bucket gives m = 2 and "
         "whose initcode writes a fresh slot in a bucket of m = 4, emits an empty LOG0 and deploys one byte: the "
         f"account's {fmt(model.ACCOUNT_STATE)}, the slot's {fmt(model.SLOT_STATE)} and the code byte's "
         f"{fmt(model.CODE_STATE_PER_BYTE)} of state gas are each scaled by their bucket's m, while the history of the two "
         f"records, the log and the byte, {fmt(2 * record + log0 + model.COST_PER_HISTORY_BYTE)}, is COST_PER_HISTORY_BYTE "
         "a byte, whatever the buckets", to=None, data=init, salt={("created", None): 2, ("created", 0): 4})

    # SATIN-HIST-008, -013: an SSTORE that observed its write fails after its load, at its regular charge or at its
    # record's history; slot 1 of the contract holds 5 and is reset to 7, which charges no state gas.
    reset = model.COLD_SSTORE_ACCESS + model.SSTORE_RESET
    pushes = 2 * model.G_VERYLOW
    for name, held, tail, boundary in (
            ("regular-one-short", reset - 1, f"which cannot pay the {fmt(reset)} the SSTORE charges after it loaded the "
             "slot: the SSTORE observed its write and halts out of gas, keeping nothing of it and charged no history",
             "the regular gas at the SSTORE one below its regular charge"),
            ("record-history-one-short", reset + record - 1, f"which pays its {fmt(reset)} of regular charges and is one "
             f"short of the record's {fmt(record)} of history, charged after the limits hold the record: it halts out of "
             "gas, keeping neither the record nor its bytes", "the regular gas one below the record's history"),
            ("record-history-paid", reset + record, f"which pays the {fmt(reset)} and the record's {fmt(record)} of history "
             "exactly: the write and its record are kept", "the regular gas at the record's history")):
        case(f"sstore-after-load/{name}", f"the transaction's own frame holds {fmt(held)} of regular gas at an SSTORE that "
             f"resets slot 1, whose original is 5, to 7, a cold access and a reset, {fmt(reset)} in all, " + tail
             + "; the slot is loaded in every case", boundary=boundary, storage={1: 5}, code=sstore(1, 7) + STOP,
             reads=True, tune=("frame", pushes + held))

    # SATIN-HIST-008, -013: a SELFDESTRUCT that fails after its load, at its regular charge or its records' history.
    sd_regular = model.SELFDESTRUCT_COST + model.COLD_ACCOUNT_ACCESS
    funded = {PAYEE_Q: model.Account(nonce=1, balance=1, code=selfdestruct_to(PAYEE_R)),
              PAYEE_R: model.Account(nonce=1, balance=1, code=STOP)}
    flag = push(0) + b"\x52" + ret(0, 32)  # MSTORE(0, the call's success), RETURN(0, 32)
    for name, held, tail in (
            ("destruction-after-load/cold-access-one-short", sd_regular - 1, f"its static cost paid and one short of the "
             f"beneficiary's cold access, {fmt(model.COLD_ACCOUNT_ACCESS)}: it halts before the load, so the beneficiary "
             "is not loaded, and nothing is kept"),
            ("destruction-after-load/records-history-one-short", sd_regular + 2 * record - 1, "its regular charges paid "
             f"and one short of the two records' {fmt(2 * record)} of history: it halts, keeping neither the records nor "
             "the move"),
            ("destruction-after-load/records-history-paid", sd_regular + 2 * record, "its regular charges and the two "
             f"records' {fmt(2 * record)} of history paid exactly: the move and both records are kept")):
        case(name, "a contract the transaction did not create, holding 1 wei, destroys itself to a cold existing "
             f"contract holding 1 wei, called with {fmt(held)} of regular gas left at the SELFDESTRUCT, " + tail
             + "; its caller returns the call's success", destruction=True, reads=True, accounts=funded,
             code=call(model.G_VERYLOW + held, PAYEE_Q, 0, 0) + flag)
    # The regular charge a SELFDESTRUCT makes after its load: a new beneficiary's account, which the load decides.
    sd_new = sd_regular + model.SELFDESTRUCT_NEW_ACCOUNT_COST
    case("destruction-after-load/new-account-one-short", "a contract the transaction did not create, holding 1 wei, "
         "destroys itself to a cold address the state holds no account for, called with "
         f"{fmt(sd_new - 1)} of regular gas left at the SELFDESTRUCT: it pays the static cost and holds the cold access, "
         "so the beneficiary is loaded and found empty, and the cold access with the new account's "
         f"{fmt(model.SELFDESTRUCT_NEW_ACCOUNT_COST)}, charged after the load, is one gas short: it halts, keeping nothing "
         "and charged no history; its caller returns the call's success",
         boundary="the regular gas one below the charge made after the load", destruction=True, reads=True,
         accounts={PAYEE_Q: model.Account(nonce=1, balance=1, code=selfdestruct_to(UNTOUCHED))},
         code=call(model.G_VERYLOW + sd_new - 1, PAYEE_Q, 0, 0) + flag)
    # SATIN-HIST-013: a log's bytes are held to the limits before its history is charged. Hints leave the transaction
    # room for less than an empty LOG0 or exactly one, and the frame cannot pay the log's history once its regular
    # charge is paid: the crossing is the stop, and the log that fits halts out of gas.
    for name, room, tail in (
            ("limit-before-history/crossing", model.LOG_BASE_SIZE - 1, "its bytes cross the data-size limit, which is "
             f"held first, so the frame is stopped with MegaLimitExceeded(0, {fmt(model.TX_DATA_LIMIT)}) and no history is "
             "charged"),
            ("limit-before-history/fitting", model.LOG_BASE_SIZE, "its bytes fit the data-size limit exactly, and the "
             "history charge that follows cannot be paid: a halt, keeping neither the log nor its bytes")):
        case(name, f"hints leave the transaction {room} bytes of data size, and the frame holds "
             f"{fmt(model.LOG_COST + log0 - 1)} of regular gas at an empty LOG0, which pays its {fmt(model.LOG_COST)} of "
             f"regular charge and is one short of its {fmt(log0)} of history: " + tail,
             boundary=f"the log's {model.LOG_BASE_SIZE} bytes {'one past' if room < model.LOG_BASE_SIZE else 'at'} the "
             "room the hints leave", system=True, gas=8_000_000, tune=("log", model.LOG_COST + log0 - 1),
             code=hints_leaving(room) + log(0, 0, 0, []) + STOP)

    # SATIN-HIST-014: a value call's start is paid for by its opcode before it is held to the limits. Hints leave less
    # room than the start's two records and transfer log; a caller one short of the records' history runs out of gas
    # first, and one that pays it sees its start stopped and the charge given back.
    start_bytes = 2 * model.WRITE_RECORD_SIZE + model.TRANSFER_LOG_SIZE
    eoa = {EOA: model.Account(balance=1)}
    for name, kept, tail, extra in (
            ("start-paid-before-hold/one-short", 2 * record - 1, "it cannot pay them and halts out of gas in the opcode: "
             "the start is never decided, so it is not held to the limits and nothing is stopped", {}),
            ("start-paid-before-hold/paid", 2 * record, "it pays them, the start is decided and held to the limits, its "
             f"{start_bytes} bytes cross the data-size limit, and the started frame is stopped with "
             f"MegaLimitExceeded(0, {fmt(model.TX_DATA_LIMIT)}), which the caller catches; the {fmt(2 * record)} come "
             "back into the caller's reservoir when the stopped frame returns, which the first frame ends with",
             {"pools": True})):
        case(name, f"hints leave the transaction {start_bytes - 1} bytes of data size, and the first frame sends 1 wei and "
             f"no gas to an existing account without code, a start that would keep two records and a transfer log, "
             f"{start_bytes} bytes; the caller keeps {fmt(kept)} of regular gas and no reservoir for the records' "
             f"{fmt(2 * record)} of history: " + tail,
             boundary=f"the caller's regular gas {'one below' if kept < 2 * record else 'at'} the records' history",
             system=True, gas=8_000_000, contract_balance=1, accounts=eoa, tune=("forward:" + EOA.hex(), kept),
             code=hints_leaving(start_bytes - 1) + call(0, EOA, 1, 0) + b"\x50" + STOP, **extra)

    # SATIN-HIST-010: a value CALL to an account empty under EIP-161 charges the new account's state gas before the
    # forward and the records' history after it, from what the caller keeps of a forward of all it may.
    at = kept_threshold(2 * record)
    for name, remaining, tail in (
            ("new-account-call/kept-one-short", at - 1, f"keeps {fmt((at - 1) * model.GAS_RETAINED_NUMERATOR // model.GAS_RETAINED_DENOMINATOR)}, "
             f"one short of the records' {fmt(2 * record)}, and halts out of gas in the opcode"),
            ("new-account-call/kept-at-history", at, f"keeps {fmt(2 * record)}, which pays the records' history exactly, "
             "and the account is created")):
        case(name, "the first frame, holding 1 wei, calls an address the state holds no account for with 1 wei, "
             f"forwarding all it may: the new account's {fmt(model.ACCOUNT_STATE)} of state gas, its "
             f"{fmt(model.LEGACY_NEW_ACCOUNT_SHARE)} legacy share first, is paid from regular gas before the forward, "
             f"leaving {fmt(remaining)}, of which the forward takes all but {model.GAS_RETAINED_NUMERATOR}/"
             f"{model.GAS_RETAINED_DENOMINATOR}; the records' history is charged after the forward, and the caller " + tail,
             boundary=f"the regular gas left for the forward {'one below' if remaining < at else 'at'} {fmt(at)}",
             contract_balance=1, gas=1_000_000, tune=("forward:" + ABSENT.hex(), remaining),
             code=call(MAX_GAS, ABSENT, 1, 0) + b"\x50" + STOP)

    # SATIN-HIST-011: a CREATE charges the created account's state gas before it computes the forward, which the
    # constructor's GAS shows, stored in its fresh slot 0.
    for name, extra, tail in (
            ("create-forward/state-from-regular", {}, "with no reservoir, the account's whole "
             f"{fmt(model.ACCOUNT_STATE)} of state gas, its {fmt(model.LEGACY_CREATE_SHARE)} legacy share first, comes "
             "from regular gas before the forward"),
            ("create-forward/state-from-reservoir", {"gas": model.EXECUTION_CAP + 1_000_000}, "with a reservoir that "
             f"pays the account's state gas past its {fmt(model.LEGACY_CREATE_SHARE)} legacy share, the legacy share alone "
             "comes from regular gas before the forward")):
        case(name, "the first frame creates an account whose constructor stores GAS, the regular gas the creation was "
             "forwarded less GAS's own, in its slot 0: " + tail + ", so the forward, all but "
             f"{model.GAS_RETAINED_NUMERATOR}/{model.GAS_RETAINED_DENOMINATOR} of what that leaves, is what the slot shows; "
             "the history of the start's records is charged after the forward", code=create(0, store_gas(0) + STOP) + STOP,
             **extra)

    case("create-forward/create2-state-from-regular", "the first frame creates by CREATE2 an account whose constructor "
         "stores GAS in its slot 0: the salt, the init code's hashing and CREATE_ACCESS are the opcode's regular charges, "
         f"then the created account's whole {fmt(model.ACCOUNT_STATE)} of state gas, its "
         f"{fmt(model.LEGACY_CREATE_SHARE)} legacy share first, comes from regular gas before the forward, which the "
         "slot shows; the history of the start's records is charged after it", code=create2(0, store_gas(0) + STOP, 7)
         + STOP)

    # SATIN-HIST-018 to -021: the history allowance of a value call's child.
    def child(code: bytes, storage=None) -> dict:
        return {ALLOWANCE_CHILD: model.Account(nonce=1, code=code, storage=storage or {})}

    value_call = call(0, ALLOWANCE_CHILD, 1, 0) + b"\x50" + STOP
    case("allowance/one-empty-log", "the specification's example: a value call whose child has the stipend alone and no "
         f"reservoir emits an empty LOG0, {fmt(log0)} of history, which the child's allowance of {fmt(allowance)} pays: the "
         "child succeeds, the log's history is on no gas ledger, and its bytes are among the transaction's history bytes",
         contract_balance=1, accounts=child(log(0, 0, 0, []) + STOP), code=value_call)
    fits = model.HISTORY_ALLOWANCE_BYTES // model.LOG_BASE_SIZE
    for n, tail in (
            (fits, f"their {model.HISTORY_ALLOWANCE_BYTES} bytes are the allowance's exactly, which pays all their history, "
                   "the transfer log of the value that granted it having drawn nothing on it: the child succeeds"),
            (fits + 1, "the allowance pays the first " + str(fits) + f" and is spent; the last log's {fmt(log0)} must come "
                       "from the stipend's remainder, which cannot pay it: the child halts and its start is discarded")):
        case(f"allowance/empty-logs-{n}", f"a value call whose child has the stipend alone and no reservoir emits {n} empty "
             f"LOG0s, {fmt(n * log0_ops)} of regular gas within the stipend: " + tail,
             boundary=f"{n * model.LOG_BASE_SIZE} log bytes {'at' if n == fits else 'past'} the allowance's "
                      f"{model.HISTORY_ALLOWANCE_BYTES}",
             contract_balance=1, accounts=child(log(0, 0, 0, []) * n + STOP), code=value_call)
    # A log two bytes past the allowance: the frame's gas pays the rest, one gas short of it and exactly. (One byte
    # past would leave the frame one byte's history short, a figure equal to COST_PER_HISTORY_BYTE less one.)
    data = model.HISTORY_ALLOWANCE_BYTES - model.LOG_BASE_SIZE + 2
    over = (model.LOG_BASE_SIZE + data) * model.COST_PER_HISTORY_BYTE - allowance
    log_cost = (model.G_VERYLOW + model.G_BASE + model.LOG_COST + model.LOG_DATA_COST * data
                + model.memory_cost((data + 31) // 32))
    for name, left in (("allowance/log-past-allowance/rest-one-short", over - 1),
                       ("allowance/log-past-allowance/rest-paid", over)):
        pad = model.CALL_STIPEND - log_cost - left
        case(name, f"a value call whose child has the stipend alone burns {fmt(pad)} of it and emits a LOG0 of {data} "
             f"data bytes, {fmt(log_cost)} of regular gas with its memory, leaving {fmt(left)}: its history draws "
             f"min(history, allowance) = {fmt(allowance)} from the allowance first and {fmt(over)} from the frame's gas, "
             + ("which is one short: the child halts" if left < over else "which it pays: the child succeeds"),
             boundary=f"the child's regular gas after the log's charge {'one below' if left < over else 'at'} what the "
                      "allowance leaves of its history",
             contract_balance=1, accounts=child(jumpdests(pad) + log(0, 0, data, []) + STOP), code=value_call)
    # A write record's history draws nothing on the allowance (SATIN-HIST-019).
    for name, short in (("allowance/record-not-drawn/one-short", 1), ("allowance/record-not-drawn/paid", 0)):
        need = pushes + reset + record - short
        case(name, f"a value call whose child resets its slot 1, which holds 5, to 7, and holds {fmt(need)} of regular gas, "
             f"the stipend included: {fmt(reset)} of regular charges and then the record's {fmt(record)} of history, which "
             f"the frame's gas must pay, the allowance of {fmt(allowance)} paying a log's history alone: "
             + ("one short, the child halts with its allowance untouched" if short else "paid, the child succeeds and its "
                "allowance is untouched"),
             boundary=f"the child's regular gas {'one below' if short else 'at'} its charges and the record's history",
             contract_balance=1, accounts=child(sstore(1, 7) + STOP, {1: 5}),
             code=call(need - model.CALL_STIPEND, ALLOWANCE_CHILD, 1, 0) + b"\x50" + STOP)
    # No other start grants an allowance (SATIN-HIST-018).
    short = log0_ops + log0 - 1
    case("allowance/none/call-without-value", f"a call without value forwards {fmt(short)} to a child that emits an empty "
         f"LOG0, one short of its {fmt(log0_ops)} of regular gas and {fmt(log0)} of history: the start grants no allowance, "
         "so the child halts", boundary="the child's gas one below the log's charges",
         accounts=child(log(0, 0, 0, []) + STOP), code=call(short, ALLOWANCE_CHILD, 0, 0) + b"\x50" + STOP)
    case("allowance/none/delegatecall-in-value-frame", f"a transaction carrying 1 wei to a contract that runs, by "
         f"DELEGATECALL forwarding {fmt(short)}, code that emits an empty LOG0: the delegated frame runs with the value "
         "its frame was entered with, and a DELEGATECALL grants no allowance, so it halts one short of the log's history",
         boundary="the delegated frame's gas one below the log's charges", value=1,
         accounts={DELEGATED_LOGGER: model.Account(nonce=1, code=log(0, 0, 0, []) + STOP)},
         code=delegatecall(short, DELEGATED_LOGGER) + b"\x50" + STOP)
    case("allowance/none/endowed-creation", f"a contract holding 1 wei creates, with that wei as endowment, an account "
         f"whose constructor emits {fits} empty LOG0s and deploys nothing: a creation grants no allowance, value or not, "
         f"so the logs' {fmt(fits * log0)} of history is charged to the constructor and is on the history ledger",
         contract_balance=1, code=create(1, log(0, 0, 0, []) * fits + STOP) + STOP)
    case("allowance/none/own-frame", "a transaction carrying 1 wei to a contract that emits an empty LOG0: the "
         f"transaction's own frame is granted no allowance, so the log's {fmt(log0)} of history is on its history ledger",
         value=1, code=log(0, 0, 0, []) + STOP)

    # Each value start grants its own allowance; a call without value from a frame holding one grants none
    # (SATIN-HIST-018, -019).
    fives = log(0, 0, 0, []) * fits + STOP
    case("allowance/two-siblings", f"a contract holding 10 wei makes two value calls to the same child, each with the "
         f"stipend alone, and the child emits {fits} empty LOG0s each time: each start grants its own allowance, so both "
         f"children succeed, the {2 * fits} logs on no gas ledger, the transaction's history the body's and the two "
         "records'", contract_balance=10, accounts=child(fives),
         code=call(0, ALLOWANCE_CHILD, 1, 0) + b"\x50" + call(0, ALLOWANCE_CHILD, 1, 0) + b"\x50" + STOP)
    inner = {DELEGATED_LOGGER: model.Account(nonce=1, code=log(0, 0, 0, []) + STOP)}
    case("allowance/none/call-without-value-from-allowance-frame", "a value call's child, holding its unspent allowance, "
         f"calls a contract without value forwarding {fmt(short)}, one short of an empty LOG0's {fmt(log0_ops)} of regular "
         f"gas and {fmt(log0)} of history: the call grants no allowance and inherits none of its caller's, so the callee "
         "halts and the child succeeds", boundary="the callee's gas one below the log's charges", contract_balance=1,
         accounts={**child(call(short, DELEGATED_LOGGER, 0, 0) + b"\x50" + STOP), **inner},
         code=call(10_000, ALLOWANCE_CHILD, 1, 0) + b"\x50" + STOP)
    # The allowance pays no computation and no state (SATIN-HIST-020).
    for n, tail in ((model.CALL_STIPEND, "the stipend pays them all: the child succeeds, its allowance unspent"),
                    (model.CALL_STIPEND + 1, "the last cannot be paid, the allowance being no gas: the child halts")):
        case(f"allowance/no-computation/jumpdests-{n}", f"a value call whose child has the stipend alone runs {fmt(n)} "
             "JUMPDESTs, one gas each, with its allowance of " + f"{fmt(allowance)} unspent: " + tail,
             boundary=f"the child's computation {'at' if n == model.CALL_STIPEND else 'one past'} the stipend",
             contract_balance=1, accounts=child(jumpdests(n) + STOP), code=value_call)
    fresh = model.COLD_SSTORE_ACCESS + model.SSTORE_SET + model.SLOT_STATE
    for name, held, tail in (
            ("allowance/no-state/one-short", pushes + fresh - 1, "one short of the slot's state gas: it halts in the "
             "state charge, the allowance paying none of it"),
            ("allowance/no-state/paid", pushes + fresh + record, "the state gas and the record's history paid: the "
             "write is kept, the allowance untouched")):
        case(name, f"a value call whose child holds {fmt(held)} of regular gas, the stipend included, and no reservoir, and "
             f"writes a cold fresh slot: {fmt(model.COLD_SSTORE_ACCESS + model.SSTORE_SET)} of regular charges and "
             f"{fmt(model.SLOT_STATE)} of state gas, its legacy share first, then the record's {fmt(record)} of history; "
             + tail, boundary=f"the child's regular gas {'one below' if 'short' in name else 'at'} its charges",
             contract_balance=1, accounts=child(sstore(1, 1) + STOP),
             code=call(held - model.CALL_STIPEND, ALLOWANCE_CHILD, 1, 0) + b"\x50" + STOP)

    # SATIN-HIST-022: the specification's example of a deposit's history bytes.
    case("bytes/deposit-empty-calldata", "the specification's example: a deposit with empty calldata that makes no write, "
         f"from an existing caller to a contract that stops, reports {model.TX_BODY_SIZE} bytes of data size and "
         f"{model.TX_BODY_SIZE} history bytes, its body", deposit=(0, 1_000_000), sender_nonce=3)

    # SATIN-HIST-007: a give-back lands in the reservoir of the frame that makes it, which can pay a later record with
    # it. P, the first frame, writes slot 0 from 7 to 8; C, run by DELEGATECALL on P's storage, writes it back and
    # resets slot 1 from 5 to 6, whose record the give-back pays.
    case("give-back/descendant-pays-record", f"the first frame P writes its slot 0, whose original is 7, to 8, paying the "
         f"record's {fmt(record)} of history from regular gas; C, run by P's DELEGATECALL on P's storage with no reservoir, "
         f"writes slot 0 back to 7, which gives the {fmt(record)} into C's own reservoir, and resets slot 1 from 5 to 6, "
         "whose record that reservoir pays: regular gas paid one record's history in all, and the first frame ends with "
         "no reservoir", storage={0: 7, 1: 5}, pools=True,
         accounts={DELEGATED_LOGGER: model.Account(nonce=1, code=sstore(0, 7) + sstore(1, 6) + STOP)},
         code=sstore(0, 8) + delegatecall(MAX_GAS, DELEGATED_LOGGER) + b"\x50" + STOP)

    # SATIN-HIST-017: the floor bounds the block's figure; at these constants it never reaches the gas used.
    n = 32
    gap = (model.FLOOR_PER_BYTE - model.CALLDATA_NONZERO) * n  # the floor less the intrinsic regular gas
    for name, burn_, tail in (
            ("floor/block-counts-floor", gap - 1, "one below the floor: the block counts the floor"),
            ("floor/block-counts-regular", gap + 1, "one above the floor: the block counts the regular ledger")):
        case(name, f"{n} non-zero calldata bytes to a contract that burns {fmt(burn_)} of regular gas, which puts the "
             f"regular ledger " + tail + "; the gas used is the transaction's spend, its history among it, which is above "
             "the floor", boundary=f"the regular ledger one {'below' if burn_ < gap else 'above'} the floor",
             data=b"\xff" * n, code=jumpdests(burn_) + STOP)
    case("floor/deposit-block-counts-floor", f"a deposit of {n} non-zero calldata bytes from an existing caller to a "
         "contract that stops: its regular ledger is below its floor, so the block counts the floor, its receipt's gas "
         "used is its spend, and the deposit pays nothing either way", deposit=(0, 1_000_000), sender_nonce=3,
         data=b"\xff" * n)
    return out


def accounting_cases() -> list[Case]:
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC

    def case(name: str, intent: str, **kw) -> None:
        add(Case(f"satin/accounting/{name}", intent, spec=spec, **kw))

    # SATIN-ACCT-007: a value that moves from an account to itself records nothing.
    target = {CALLCODE_TARGET: model.Account(nonce=1, code=STOP)}
    case("no-record/callcode-with-value", "a contract holding 10 wei sends 1 wei by CALLCODE to code that stops: the value "
         "moves from the calling account to itself, so no account changes, no record is made and no transfer log is "
         "emitted", contract_balance=10, accounts=target, code=callcode(MAX_GAS, CALLCODE_TARGET, 1) + b"\x50" + STOP)
    case("no-record/call-to-self-with-value", "a contract holding 10 wei calls itself with 1 wei, and the inner frame, "
         "seeing the value, stops: no account changes, no record is made and no transfer log is emitted",
         contract_balance=10, code=jump_if(b"\x34", STOP, call(MAX_GAS, CONTRACT, 1, 0) + b"\x50" + STOP))
    # SATIN-ACCT-008: the sender's account is a fixed record of the body.
    case("sender/value-call-to-sender", "a contract holding 10 wei sends 1 wei to the transaction's sender: the sender's "
         "account, a fixed record of the body, is not recorded again, so the transfer records the contract's account "
         "alone, one KV update, with a transfer log", contract_balance=10,
         code=call(0, SENDER, 1, 0) + b"\x50" + STOP)
    # SATIN-ACCT-009: an applied authority is changed by the list.
    authority = {AUTHORITY: model.Account(balance=1)}
    case("authority/value-call-after-list", "an EIP-7702 transaction whose one entry, signed by an existing account at its "
         "nonce with a zero target, is applied, and whose first frame, a contract holding 10 wei, sends that authority "
         "1 wei: the authority's record is the list's, and the value adds none, so the transaction keeps two records, "
         "the authority's and the contract's", ty=4, max_fee=0, max_priority=0, contract_balance=10, gas=500_000,
         accounts=authority, authorizations=[(AUTH_KEY, CHAIN_ID, bytes(20), 0)],
         code=call(0, AUTHORITY, 1, 0) + b"\x50" + STOP)
    # SATIN-ACCT-010, -017: the fee accounts.
    vault = {model.BASE_FEE_VAULT: model.Account(balance=1)}
    case("fee-account/value-call-to-base-fee-vault", "a contract holding 10 wei sends 1 wei to the base fee vault, which "
         "holds 1 wei, in a transaction that pays a base fee: execution's write to the vault is recorded like a write to "
         "any other account, two records with the contract's, and the settlement's fee credit to it adds none",
         contract_balance=10, accounts=vault, gas_price=2_000_000, base_fee=1_000_000,
         code=call(0, model.BASE_FEE_VAULT, 1, 0) + b"\x50" + STOP)
    case("fee-account/value-to-absent-base-fee-vault", "a transaction's 1 wei to the base fee vault, which the state holds "
         "no account for, with a gas price above the base fee: the value is the vault's rise, its write record and its "
         "state gas, as any recipient's; the settlement's credits to the vault and to the block beneficiary, absent too, "
         "are no rise and no record", to=model.BASE_FEE_VAULT, code=None, value=1, gas_price=3_000_000,
         base_fee=1_000_000)
    # SATIN-ACCT-011: a creator's nonce record survives its creation's failure; a sibling's failure discards only
    # its own counts, a destruction's mark kept by a frame that succeeded included.
    case("merge/creator-record-survives-failed-creation", "a contract creates an account whose initcode reverts: nothing "
         "is created, and the creator's nonce record, the creating frame's, survives the creation's failure, one KV "
         "update", code=create(0, revert(0, 0)) + STOP)
    created = model.created_address(CONTRACT, 1)
    heir = {HEIR: model.Account(balance=1), FAILING: model.Account(nonce=1, code=revert(0, 0))}

    def runtime(beneficiary: bytes) -> bytes:
        """With calldata, SSTORE(1, CALLDATALOAD(0)); with value, STOP; else SELFDESTRUCT(beneficiary)."""
        destroy = selfdestruct_to(beneficiary)
        accept = 8 + len(destroy)  # CALLDATASIZE, PUSH1, JUMPI, CALLVALUE, PUSH1, JUMPI, then `destroy`
        store = accept + 2  # JUMPDEST, STOP
        return (b"\x36" + bytes([0x60, store]) + b"\x57" + b"\x34" + bytes([0x60, accept]) + b"\x57" + destroy
                + b"\x5b" + STOP + b"\x5b" + push(0) + b"\x35" + push(1) + b"\x55" + STOP)

    case("merge/mark-survives-failed-sibling", "P creates C and calls it, and C, holding nothing, destroys itself to an "
         "existing account holding 1 wei; P then calls a contract that reverts, whose failure discards its own counts alone, and calls "
         "C with a word of calldata, which C writes to a slot never written: C's mark, made in a frame that succeeded, "
         "stands, so the write charges no state gas and adds no state growth and no record",
         accounts=heir, gas=3_000_000, destruction=True,
         code=create(0, returning(runtime(HEIR))) + call(MAX_GAS, created, 0, 0) + b"\x50"
         + call(MAX_GAS, FAILING, 0, 0) + b"\x50" + mstore(0, 7) + call(MAX_GAS, created, 0, 32) + b"\x50" + STOP)
    big = 42_400
    case("merge/large-log-then-child-log", f"the first frame emits a LOG0 of {fmt(big)} data bytes and then calls a "
         "child that emits an empty LOG0 and succeeds: the child's bytes merge into its caller's, no log is a write "
         "record, and the transaction keeps no KV update", gas=6_000_000,
         accounts={ALLOWANCE_CHILD: model.Account(nonce=1, code=log(0, 0, 0, []) + STOP)},
         code=log(0, 0, big, []) + call(MAX_GAS, ALLOWANCE_CHILD, 0, 0) + b"\x50" + STOP)
    # SATIN-ACCT-018, -019: the signed net of state growth, at the transaction's limit.
    limit = model.TX_STATE_GROWTH_LIMIT
    fill = b"".join(sstore(k, 1) for k in range(1, limit + 1))
    case("growth/fall-at-limit-then-rise", f"the first frame writes {fmt(limit)} fresh slots, its whole state-growth "
         "budget, writes the first back to zero, a fall that crosses nothing and frees one unit, and writes one more "
         "fresh slot, a rise the signed net holds: it fits, and the transaction keeps its whole limit",
         gas=140_000_000, code=fill + sstore(1, 0) + sstore(limit + 1, 1) + STOP)
    case("growth/fall-at-limit-then-two-rises", f"the same {fmt(limit)} fresh slots, fall and rise, and then one more "
         "fresh slot: that rise takes the signed net past the budget, which the fall freed by one unit alone, and is the "
         "crossing: it is not kept, and the frame is stopped",
         gas=140_000_000, code=fill + sstore(1, 0) + sstore(limit + 1, 1) + sstore(limit + 2, 1) + STOP)
    # SATIN-ACCT-016, -018, -019: a child's signed net below zero, then rises, against a budget of nothing; and the
    # remaining it passes on, clamped to its budget (SATIN-LIM-004).
    for name, rises, tail in (
            ("growth/child-net-below-zero-then-rise", 1, "a rise that brings its signed net back to zero, its budget: it "
             "fits, the child succeeds and the transaction keeps its whole limit"),
            ("growth/child-net-below-zero-then-two-rises", 2, "a rise that brings its net back to zero, which fits, and "
             "a second, past its budget: the child is stopped with MegaLimitExceeded(3, 0), its fall and rises "
             "discarded, and the first frame's slots stand")):
        grow = sstore(1, 0) + b"".join(sstore(limit + k, 1) for k in range(1, rises + 1)) + STOP
        case(name, f"the first frame writes {fmt(limit)} fresh slots, its whole state-growth budget, and runs, by "
             "DELEGATECALL on its storage, code whose budget is the share of nothing, 0: the code clears slot 1, a fall "
             "that takes its signed net to -1, then makes " + tail + "; the first frame returns the call's return data",
             gas=140_000_000, accounts={GROWER_D: model.Account(nonce=1, code=grow)},
             code=fill + delegatecall(MAX_GAS, GROWER_D) + b"\x50" + RETURN_RETURNDATA)
    share = (limit - 1) * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    clamp = share * model.FRAME_SHARE_NUMERATOR // model.FRAME_SHARE_DENOMINATOR
    for n in (clamp, clamp + 1):
        grandchild = {PAYEE_R: model.Account(nonce=1, code=b"".join(sstore(k, 1) for k in range(1, n + 1)) + STOP),
                      GROWER_D: model.Account(nonce=1, code=sstore(1, 0) + call(MAX_GAS, PAYEE_R, 0, 0) + b"\x50"
                                              + RETURN_RETURNDATA)}
        case(f"growth/clamped-share/{'at' if n == clamp else 'one-past'}", "the first frame writes one fresh slot and runs, "
             f"by DELEGATECALL, code whose budget is {fmt(share)}, which clears that slot, a signed net of -1, and calls a "
             f"contract writing {fmt(n)} fresh slots: the code's remaining is clamped to its budget, so the callee's "
             f"budget is {fmt(share)} x {model.FRAME_SHARE_NUMERATOR} / {model.FRAME_SHARE_DENOMINATOR} = {fmt(clamp)}, "
             "not the share of the budget and the slot taken back, and the "
             + (f"{fmt(n)} slots fit" if n == clamp else f"last of the {fmt(n)} slots crosses it: the callee is stopped "
                f"with MegaLimitExceeded(3, {fmt(clamp)})"),
             boundary=f"the callee's slots {'at' if n == clamp else 'one past'} its clamped budget",
             gas=140_000_000, accounts=grandchild,
             code=sstore(1, 1) + delegatecall(MAX_GAS, GROWER_D) + b"\x50" + RETURN_RETURNDATA)
    # SATIN-ACCT-004 to -006, -011: account records across repeated, failed and passed-on transfers.
    stop_q = {PAYEE_Q: model.Account(nonce=1, code=STOP)}
    stop_r = {PAYEE_R: model.Account(nonce=1, code=STOP)}
    send = lambda target, value=1, size=0: call(MAX_GAS, target, value, size) + b"\x50"
    case("records/failed-transfer-then-sibling", "a contract holding 10 wei sends 1 wei to a contract that reverts, which "
         "discards the start's two records, and then 1 wei to another that stops: the contract's account is recorded "
         "again by the second start, and the transaction keeps its record and the second recipient's",
         contract_balance=10, accounts={PAYEE_Q: model.Account(nonce=1, code=revert(0, 0)), **stop_r},
         code=send(PAYEE_Q) + send(PAYEE_R) + STOP)
    case("records/failed-transfer-then-same-recipient", "a contract holding 10 wei sends 1 wei to a contract that reverts "
         "when called without calldata, and then 1 wei with one byte of calldata, which it accepts: the second start "
         "records both accounts again", contract_balance=10,
         accounts={PAYEE_Q: model.Account(nonce=1, code=jump_if(b"\x36", STOP, revert(0, 0)))},
         code=send(PAYEE_Q) + send(PAYEE_Q, size=1) + STOP)
    case("records/two-transfers-one-recipient", "a contract holding 10 wei sends 1 wei twice to one contract that stops: "
         "the first start records both accounts, the second finds them changed already, and each logs",
         contract_balance=10, accounts=stop_q, code=send(PAYEE_Q) + send(PAYEE_Q) + STOP)
    case("records/two-recipients", "a contract holding 10 wei sends 1 wei to each of two contracts that stop: its own "
         "account recorded once, each recipient once", contract_balance=10, accounts={**stop_q, **stop_r},
         code=send(PAYEE_Q) + send(PAYEE_R) + STOP)
    back = lambda value: {PAYEE_Q: model.Account(nonce=1, code=call(0, CONTRACT, value, 0) + b"\x50" + STOP)}
    case("records/partial-return", "a contract holding 10 wei sends 2 wei to a contract, which sends 1 back: both "
         "balances differ from what the transaction loaded, so both records stand and nothing is taken back",
         contract_balance=10, accounts=back(1),
         # A JUMPDEST of one gas moves the regular ledger off 36,168, a figure another case's history has at
         # COST_PER_HISTORY_BYTE, which tools/check_derived_text.py would take for a stale one.
         code=jump_if(b"\x34", STOP, send(PAYEE_Q, 2) + jumpdests(1) + STOP))
    case("records/pass-on-exact", "a contract holding 10 wei sends 1 wei to a contract that passes exactly that wei on to "
         "a third that stops: the middle account returns to what the transaction loaded, so its record is taken back "
         "in the frame that made the second start, and the sender's and the last recipient's stand",
         contract_balance=10, accounts={PAYEE_Q: model.Account(nonce=1, code=call(0, PAYEE_R, 1, 0) + b"\x50" + STOP),
                                        **stop_r}, code=send(PAYEE_Q) + STOP)
    # SATIN-ACCT-004, -006, -011, SATIN-HIST-006, -007: a SELFDESTRUCT of an account the transaction did not create that
    # returns accounts to what the transaction loaded takes their records back.
    def refund_to(beneficiary: bytes) -> bytes:
        """With value, STOP; else SELFDESTRUCT(beneficiary)."""
        destroy = selfdestruct_to(beneficiary)
        return b"\x34" + bytes([0x60, 4 + len(destroy)]) + b"\x57" + destroy + b"\x5b" + STOP

    payee = lambda code: {PAYEE_Q: model.Account(nonce=1, code=code)}
    case("records/destruction-returns-both", "a contract holding 10 wei sends 1 wei to an existing contract that held "
         "none, whose code, run with the value, destroys it back to the sender of the wei: both balances return to what "
         "the transaction loaded, so the destruction takes back both records the transfer made, giving their history "
         "into the destroying frame's reservoir, and only the two transfer logs stay", contract_balance=10,
         destruction=True, pools=True, accounts=payee(selfdestruct_to(CONTRACT)), code=send(PAYEE_Q) + STOP)
    case("records/destruction-returns-one", "the same transfer to a contract whose code destroys it to a third, existing "
         "contract: the destroyed account returns to what the transaction loaded and its record is taken back, the "
         "sender's stands, and the beneficiary's is made", contract_balance=10, destruction=True,
         accounts={**payee(selfdestruct_to(PAYEE_R)), **stop_r}, code=send(PAYEE_Q) + STOP)
    for name, end, tail in (("records/destruction-takes-back-in-kept-frame", STOP, "the relay succeeds, so the take-backs "
                             "stand and the transaction keeps no record"),
                            ("records/destruction-takes-back-in-failed-frame", revert(0, 0), "the relay reverts, so the "
                             "destruction is discarded with it and the two records stand again")):
        case(name, "a contract holding 10 wei sends 1 wei to an existing contract that held none, which accepts it, and "
             "then calls a relay that calls that contract without value, whose code destroys it back to the sender of "
             "the wei, taking back both records: " + tail, contract_balance=10, destruction=True,
             accounts={**payee(refund_to(CONTRACT)),
                       RELAY_W: model.Account(nonce=1, code=call(MAX_GAS, PAYEE_Q, 0, 0) + b"\x50" + end)},
             code=send(PAYEE_Q) + call(MAX_GAS, RELAY_W, 0, 0) + b"\x50" + STOP)
    # SATIN-ACCT-004, -011, SATIN-HIST-015: creations and the creator's nonce record.
    case("merge/creator-record-two-failed-creations", "a contract creates twice from initcode that reverts: nothing is "
         "created, its nonce is bumped twice, and its account is recorded once, the second bump finding it changed",
         code=create(0, revert(0, 0)) + create(0, revert(0, 0)) + STOP)
    landing = model.created_address(CONTRACT, 1)
    case("records/creation-onto-funded-address", "a contract holding 10 wei sends 1 wei to the address its first CREATE "
         "will take, which the state holds no account for, paying the new account's state gas, and then creates there "
         "from initcode that stops: the address differs already by its balance and is not empty under EIP-161, so the "
         "creation charges no leaf and makes no record and no rise, and the creator, changed by the transfer, no nonce "
         "record: the transaction keeps the transfer's two records and its one rise", contract_balance=10,
         code=call(0, landing, 1, 0) + b"\x50" + create(0, STOP) + STOP)
    case("records/creation-unfunded-control", "the control: a contract holding 10 wei creates at that address, which the "
         "state holds no account for, from initcode that stops: the creation charges the leaf and makes its record, its "
         "rise and the creator's nonce record", contract_balance=10, code=create(0, STOP) + STOP)
    case("merge/creation-endowment-unfunded", "a contract holding nothing creates with an endowment of 1 wei: the opcode "
         "refuses the creation before it charges anything for the start and before it reads the created address, so "
         "nothing is created, the creator's nonce is not bumped and nothing is recorded", code=create(1, STOP) + STOP)
    # SATIN-ACCT-010: the fee accounts and the other roles an account can take.
    vault1 = {model.BASE_FEE_VAULT: model.Account(balance=1)}
    case("fee-account/destruction-to-base-fee-vault", "a contract the transaction did not create, holding 1 wei, destroys "
         "itself to the base fee vault, which holds 1 wei: both the cleared account and the vault are recorded, the "
         "vault's write being execution's and not the settlement's", destruction=True,
         accounts={**vault1, PAYEE_Q: model.Account(nonce=1, balance=1, code=selfdestruct_to(model.BASE_FEE_VAULT))},
         code=call(MAX_GAS, PAYEE_Q, 0, 0) + b"\x50" + STOP)
    case("fee-account/beneficiary-is-applied-authority", "the block beneficiary is an existing account whose one EIP-7702 "
         "entry, with a zero target, the transaction applies; the first frame, a contract holding 10 wei, sends it 1 wei: "
         "the authority's record is the list's and the value adds none, so the transaction keeps two records; detained "
         "from its start by the authority", ty=4, contract_balance=10, gas=500_000, coinbase=AUTHORITY,
         accounts=authority, authorizations=[(AUTH_KEY, CHAIN_ID, bytes(20), 0)],
         code=call(0, AUTHORITY, 1, 0) + b"\x50" + STOP)
    case("fee-account/beneficiary-is-sender", "the block beneficiary is the transaction's sender, and the first frame, a "
         "contract holding 10 wei, sends it 1 wei: the sender's account is the body's, fee account or not, so the "
         "transfer records the contract's account alone; detained from its start by the sender", contract_balance=10,
         coinbase=SENDER, code=call(0, SENDER, 1, 0) + b"\x50" + STOP)
    # SATIN-ACCT-001, -002, -012, -013: an access list's entries are body bytes, counted entry by entry, and no record.
    for name, entries in (("body/access-list-one-entry", 1), ("body/access-list-duplicate-entries", 2)):
        case(name, f"a type-1 transaction to a contract that stops, with {entries} access-list "
             + ("entry" if entries == 1 else "entries for the same address and the same key") + ": each entry is "
             f"{model.ACCESS_LIST_ADDRESS_SIZE} + {model.ACCESS_LIST_SLOT_SIZE} bytes of the body, counted whatever the "
             "warm set makes of it, and none is a write record or a rise", ty=1, access_list=[(CONTRACT, [1])] * entries)
    # SATIN-ACCT-008: the sender's account is the body's, whatever runs as the sender; its storage is not.
    delegation = model.DELEGATION_PREFIX + DELEGATE
    for name, store, tail in (("sender/delegated-sender-transfers", b"", "the recipient's account alone is recorded"),
                              ("sender/delegated-sender-transfers-and-writes", sstore(1, 7), "the recipient's account "
                               "and the sender's slot are recorded, the slot being no part of the account the body "
                               "covers")):
        case(name, "a transaction to its own sender, which delegates to code that sends 1 wei to an existing contract "
             + ("" if not store else "and resets the sender's slot 1 from 5 to 7 ") + "in the sender's own frame: the "
             "sender's account is the body's and is not recorded, and " + tail, to=SENDER, code=None,
             sender_code=delegation, accounts={**stop_r, DELEGATE: model.Account(nonce=1, code=store + send(PAYEE_R) + STOP),
                                               SENDER: model.Account(balance=ETH, code=delegation, storage={1: 5})})
    # SATIN-ACCT-020: a failed deposit's caller, empty under EIP-161, counts one unit of state growth, uncharged.
    intrinsic = model.TX_BASE_COST + model.COLD_ACCOUNT_ACCESS + model.TX_BODY_SIZE * model.COST_PER_HISTORY_BYTE
    for name, held, tail in (("failed-deposit/empty-leaf-caller", model.Account(), "an empty leaf, empty under EIP-161: "
                              "the failed deposit counts it as one unit of state growth, charged no state gas"),
                             ("failed-deposit/nonce-only-caller", model.Account(nonce=1), "an account of nonce 1 and no "
                              "balance, not empty under EIP-161: the failed deposit counts no state growth")):
        case(name, f"a deposit one gas short of its intrinsic gas and its body's history, {fmt(intrinsic)}, fails "
             f"validation and is a failed deposit; its caller is " + tail, deposit=(0, intrinsic - 1),
             absent_sender=True, accounts={OTHER: held})
    return out


# --- The precompile page's and the contract-limits page's own rules (D-103, D-104) ----------------------------

POP_RETURN = b"\x50" + RETURN_RETURNDATA  # POP the call's success flag, then return what the call returned


def precompile_call(forward: int, target: bytes, data: bytes, size: int | None = None) -> bytes:
    """`data` laid out in memory from offset 0 (zero bytes need no store), a CALL of `target` with `size` input bytes
    (all of `data` by default) forwarding `forward`, then a return of what it returned."""
    size = len(data) if size is None else size
    return (bytes_to_memory(data) if any(data) else b"") + call(forward, target, 0, size) + POP_RETURN


def generous(forward: int) -> int:
    """A gas limit whose first frame can forward `forward` and pay the memory of a large input."""
    return forward + forward // 40 + 1_000_000


def kzg_input(y: int = 0, z: int = 1) -> bytes:
    """An EIP-4844 point evaluation input whose commitment and proof are both G1's point at infinity, its versioned hash
    the commitment's, at the evaluation point `z` with the value `y`."""
    infinity = model.G1_INFINITY_COMPRESSED
    versioned = bytes([model.VERSIONED_HASH_VERSION_KZG]) + hashlib.sha256(infinity).digest()[1:]
    return versioned + word(z) + word(y) + infinity + infinity


P256_KEY, P256_NONCE = 0x5EED_C0FFEE, 0xBEEF_F00D  # the signer's key and the signature's nonce
P256_MESSAGE = int.from_bytes(hashlib.sha256(b"Satin P256VERIFY").digest(), "big")


def p256_input(valid: bool = True) -> bytes:
    """A P256VERIFY input: a message hash, a signature of it by P256_KEY with the nonce P256_NONCE (ECDSA over P-256), and
    the key's public point; with `valid` false, s is one more, so the signature no longer verifies."""
    n = model.P256_N
    qx, qy = model.p256_mul(P256_KEY, model.P256_G)
    r = model.p256_mul(P256_NONCE, model.P256_G)[0] % n
    s = pow(P256_NONCE, -1, n) * (P256_MESSAGE + r * P256_KEY) % n
    return word(P256_MESSAGE) + word(r) + word(s if valid else s + 1) + word(qx) + word(qy)


def modexp_input(base: bytes, exponent: bytes, modulus: bytes) -> bytes:
    return word(len(base)) + word(len(exponent)) + word(len(modulus)) + base + exponent + modulus


def precompile_cases() -> list[Case]:
    """The precompile page's own rules (D-103): KZG point evaluation at its fixed price, P256VERIFY at EIP-7951's,
    ModExp on the Osaka schedule, and the OP input size limits, each at its edge, where no limit is set."""
    out: list[Case] = []
    add = out.append
    spec = SECOND_FILL_SPEC
    page = {"spec": spec, "precompile_page": True}

    # SATIN-PCMP-001, -006: KZG point evaluation at KZG_POINT_EVALUATION_GAS, charged exactly; a forward one short fails
    # out of gas before any verification, and a forward that pays it, given an input that fails, is consumed whole.
    kzg = model.KZG_POINT_EVALUATION_GAS
    for name, forward, intent in (
            ("forward-one-short-of-price", kzg - 1, "one short of it: the call fails out of gas before any verification "
             "runs and consumes its forward, though the input verifies"),
            ("forward-at-price", kzg, "exactly: the input verifies, the call is charged that price and returns "
             "FIELD_ELEMENTS_PER_BLOB and the scalar field's modulus"),
            ("forward-above-price", 3 * kzg, "three times over: the input verifies and the call is charged exactly the "
             "price, returning the rest of its forward")):
        add(Case(f"satin/precompiles/kzg/{name}", f"a contract calls KZG point evaluation with a 192-byte input whose "
                 "commitment and proof are the point at infinity, the zero polynomial's proof at z = 1 with y = 0, which "
                 f"verifies, forwarding {fmt(forward)} against KZG_POINT_EVALUATION_GAS {fmt(kzg)}: {intent}",
                 boundary=f"the forward {'one below' if forward < kzg else 'at' if forward == kzg else 'above'} the price",
                 gas=generous(forward), code=precompile_call(forward, model.KZG_POINT_EVALUATION, kzg_input()), **page))
    mismatched = bytearray(kzg_input())
    mismatched[31] ^= 0x01
    for name, data, size, intent in (
            ("input-one-byte-short", kzg_input(), model.KZG_INPUT_SIZE - 1, "the verifying input less its last byte, "
             "an input of the wrong length"),
            ("versioned-hash-mismatch", bytes(mismatched), None, "the verifying input with the last byte of its versioned "
             "hash flipped, a versioned hash that does not match the commitment"),
            ("proof-does-not-verify", kzg_input(1), None, "the verifying input with y = 1, a proof that does not verify")):
        add(Case(f"satin/precompiles/kzg/{name}", f"a contract calls KZG point evaluation with {intent}, forwarding "
                 f"{fmt(3 * kzg)}, which pays KZG_POINT_EVALUATION_GAS: the call fails and consumes all the gas forwarded "
                 "to it, not only the price", gas=generous(3 * kzg),
                 code=precompile_call(3 * kzg, model.KZG_POINT_EVALUATION, data, size), **page))

    # SATIN-PCMP-003: P256VERIFY costs P256VERIFY_GAS, verified or not.
    p256 = model.P256VERIFY_GAS
    for name, forward, valid, intent in (
            ("valid-signature-one-short-of-price", p256 - 1, True, "one short of P256VERIFY_GAS: the call fails out of gas "
             "and consumes its forward"),
            ("valid-signature-at-price", p256, True, "P256VERIFY_GAS exactly: the signature verifies and the call returns "
             "the word 1"),
            ("invalid-signature-twice-price", 2 * p256, False, "twice P256VERIFY_GAS: the signature does not verify, so "
             "the call succeeds with empty output, charged P256VERIFY_GAS as a verified one is, and returns the rest")):
        add(Case(f"satin/precompiles/p256verify/{name}", "a contract calls P256VERIFY with a 160-byte input, an ECDSA "
                 "signature over P-256 of a message hash " + ("by its public key" if valid else "with its s one more, "
                                                                 "which does not verify")
                 + f", forwarding {fmt(forward)}, {intent}", gas=generous(forward),
                 boundary=f"the forward {'one below' if forward < p256 else 'at' if forward == p256 else 'above'} the "
                          "price", code=precompile_call(forward, model.P256VERIFY, p256_input(valid)), **page))

    # SATIN-PCMP-002, -007: ModExp's minimum, EIP-7883's formula past 32 bytes, EIP-7823's bound, and lengths too large
    # to price.
    small = modexp_input(b"\x03", b"\x05", b"\x07")
    floor = model.MODEXP_MIN_GAS
    for short in (True, False):
        forward = floor - (1 if short else 0)
        add(Case(f"satin/precompiles/modexp/minimum-price-{'one-short' if short else 'paid'}",
                 f"a contract calls ModExp for 3^5 mod 7, one-byte operands whose formula price is below the minimum "
                 f"MODEXP_MIN_GAS {fmt(floor)}, forwarding {fmt(forward)}: " +
                 ("one short of the minimum, so the call fails out of gas and consumes its forward" if short else
                  "the minimum exactly, so the call succeeds and returns 5"),
                 boundary=f"the forward {'one below' if short else 'at'} the minimum", gas=generous(forward),
                 code=precompile_call(forward, model.MODEXP, small), **page))
    width = 33  # one byte past the 32 at which EIP-7883's complexity and its exponent's multiplier change
    long = modexp_input((2).to_bytes(width, "big"), b"\x01" * width, (1000).to_bytes(width, "big"))
    price, complexity, iterations = model.modexp_price(long)
    for short in (True, False):
        forward = price - (1 if short else 0)
        add(Case(f"satin/precompiles/modexp/long-operands-{'one-short-of-price' if short else 'at-price'}",
                 f"a contract calls ModExp with a base, an exponent and a modulus of {width} bytes each, priced by "
                 f"EIP-7883 at its multiplication complexity {fmt(complexity)} times its iteration count "
                 f"{fmt(iterations)}, {fmt(price)}, forwarding {fmt(forward)}: " +
                 ("one short, so the call fails out of gas and consumes its forward" if short else
                  "its price exactly, so the call succeeds and returns the power modulo 1000"),
                 boundary=f"the forward {'one below' if short else 'at'} the formula price", gas=generous(forward),
                 code=precompile_call(forward, model.MODEXP, long), **page))
    bound = model.MODEXP_MAX_INPUT_SIZE
    forward = 50_000
    for over in (False, True):
        data = word(0) + word(0) + word(bound + (1 if over else 0))
        price = model.modexp_price(data)[0]
        add(Case(f"satin/precompiles/modexp/modulus-{'over' if over else 'at'}-bound",
                 f"a contract calls ModExp with no base and no exponent and a zero modulus of {fmt(bound + over)} bytes, "
                 f"priced {fmt(price)}, forwarding {fmt(forward)}: " +
                 ("one byte over EIP-7823's bound, so the call is charged its whole formula price and then fails the "
                  "bound, consuming its forward" if over else
                  "at EIP-7823's bound, so the call is charged its price and returns the zero modulus's bytes"),
                 boundary=f"the modulus length {'one over' if over else 'at'} EIP-7823's bound", gas=generous(forward),
                 code=precompile_call(forward, model.MODEXP, data), **page))
    forward = 1_000_000
    add(Case("satin/precompiles/modexp/lengths-too-large-to-price", f"a contract calls ModExp whose base length is "
             f"2^256 - 1, forwarding {fmt(forward)}: lengths too large to price are priced past any gas a call can hold, "
             "so the call fails out of gas and consumes its forward", gas=generous(forward),
             code=precompile_call(forward, model.MODEXP, word(2**256 - 1) + word(0) + word(0)), **page))

    # SATIN-PCMP-004, -005: the OP input size limits at their exact bytes, zero bytes being pairs of points at infinity:
    # at the limit the precompile runs on its price, one pair over it fails before any gas check and consumes its
    # forward, though the forward pays the price that input would have.
    bn = model.BN254_PAIRING_MAX_INPUT_SIZE
    pairs = bn // model.BN254_PAIR_SIZE
    price = model.BN254_PAIRING_BASE + model.BN254_PAIRING_PER_PAIR * pairs
    for short in (True, False):
        forward = price - (1 if short else 0)
        add(Case(f"satin/precompiles/bn254-pairing/at-size-limit-{'one-short-of-price' if short else 'at-price'}",
                 f"a contract calls the BN254 pairing with {fmt(bn)} zero bytes, its size limit, {pairs} pairs of points "
                 f"at infinity priced {fmt(price)}, forwarding {fmt(forward)}: " +
                 ("one short of the price the limit lets it reach, so the call fails out of gas and consumes its forward"
                  if short else "the price exactly: the pairing runs and returns the word 1"),
                 boundary=f"the input at the size limit, the forward {'one below' if short else 'at'} its price",
                 gas=generous(forward), code=precompile_call(forward, model.BN254_PAIRING, b"", bn), **page))
    for target, label, limit, size in (
            (model.BLS12_G1_MSM, "bls12-g1-msm", model.BLS12_G1_MSM_MAX_INPUT_SIZE, model.BLS12_G1_MSM_PAIR_SIZE),
            (model.BLS12_G2_MSM, "bls12-g2-msm", model.BLS12_G2_MSM_MAX_INPUT_SIZE, model.BLS12_G2_MSM_PAIR_SIZE),
            (model.BLS12_PAIRING, "bls12-pairing", model.BLS12_PAIRING_MAX_INPUT_SIZE, model.BLS12_PAIRING_PAIR_SIZE)):
        what = {"bls12-g1-msm": "BLS12-381 G1 MSM", "bls12-g2-msm": "BLS12-381 G2 MSM",
                "bls12-pairing": "BLS12-381 pairing"}[label]
        for over in (False, True):
            pairs = limit // size + (1 if over else 0)
            price = model.bls12_price(target, pairs)
            add(Case(f"satin/precompiles/{label}/{'over' if over else 'at'}-size-limit",
                     f"a contract calls the {what} with {fmt(pairs * size)} zero bytes, {pairs} pairs of points at infinity "
                     f"and " + ("zero scalars" if target != model.BLS12_PAIRING else "their pairs") +
                     f", forwarding {fmt(price)}, their price: " +
                     (f"one pair over its size limit of {fmt(limit)} bytes, so the call fails before any gas check and "
                      "consumes all the gas forwarded to it" if over else
                      f"its size limit exactly, so the precompile runs on its forward and answers "
                      + ("the point at infinity" if target != model.BLS12_PAIRING else "the word 1")),
                     boundary=f"the input {'one pair over' if over else 'at'} the size limit", gas=generous(price),
                     code=precompile_call(price, target, b"", pairs * size), **page))
    return out


PRECOMPILE_DELEGATE = bytes.fromhex("00000000000000000000000000000000000c0e22")  # a delegate a precompile's address names
FLAG_RETURN = (push(0) + b"\x52"  # MSTORE(0, the call's success flag)
               + b"\x3d" + push(0) + push(32) + b"\x3e"  # RETURNDATACOPY(32, 0, RETURNDATASIZE)
               + b"\x3d" + push(32) + b"\x01" + push(0) + b"\xf3")  # RETURN(0, 32 + RETURNDATASIZE)


def flagged_call(forward: int, target: bytes, data: bytes, size: int | None = None) -> bytes:
    """`precompile_call`, returning the call's success flag as a word before what it returned."""
    size = len(data) if size is None else size
    return (bytes_to_memory(data) if any(data) else b"") + call(forward, target, 0, size) + FLAG_RETURN


def p256_y(x: int) -> int:
    """A y with (x, y) on P-256: the square root of x^3 + ax + b, p being 3 modulo 4."""
    p = model.P256_P
    rhs = (x ** 3 + model.P256_A * x + model.P256_B) % p
    y = pow(rhs, (p + 1) // 4, p)
    if y * y % p != rhs:
        raise SystemExit(f"p256_y: {x:#x} is no x of the curve")
    return y


def p256_fields(data: bytes) -> list[int]:
    return [int.from_bytes(data[i:i + 32], "big") for i in range(0, model.P256VERIFY_INPUT_SIZE, 32)]


def p256_words(*fields: int) -> bytes:
    return b"".join(word(f) for f in fields)


def precompile_gap_cases() -> list[Case]:
    """The precompile page's edges an independent review found unpinned (D-103, second round), in its rank order."""
    out: list[Case] = []
    add = out.append
    page = {"spec": SECOND_FILL_SPEC, "precompile_page": True}
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 20_000), "pad": 0}
    indicator = lambda d: model.DELEGATION_PREFIX + d  # noqa: E731

    # SATIN-PCMP-008: a precompile's address holding a delegation indicator runs the precompile, priced by it, after
    # the opcode's charges, the delegate's access among them. With access off, a delegate that is the beneficiary is
    # refused at its load and the call never reaches dispatch (SATIN-MAC-007), charged the refusal's settlement
    # (SATIN-MAC-004): that case waited for the evm2-based pin to take it (D-105) and enters at `83c0d26` (D-114).
    other_word = mstore(0, 0xD15EA5E) + ret(0, 32)
    echoed = word(0xC0FFEE)
    price = model.IDENTITY_BASE + model.IDENTITY_WORD
    add(Case("satin/precompiles/delegated-address/identity-runs", "the identity precompile's address holds an EIP-7702 "
             "delegation to a contract whose code returns another word; a contract calls the address with one word, "
             f"forwarding {fmt(price)}, the identity's price: the call pays the delegate's access with its other charges, "
             "and dispatch runs the identity precompile, which returns the word, not the delegate's code",
             gas=200_000, accounts={model.IDENTITY: model.Account(code=indicator(PRECOMPILE_DELEGATE)),
                                    PRECOMPILE_DELEGATE: model.Account(nonce=1, code=other_word)},
             code=precompile_call(price, model.IDENTITY, echoed), **page))
    disable = mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
    add(Case("satin/precompiles/delegated-address/beneficiary-delegate-access-off", "the identity precompile's address "
             "holds an EIP-7702 delegation to the block beneficiary; a contract switches its volatile-data access off and "
             "calls the address with one word: the call pays its static cost, loads its warm target and passes the "
             "delegation guard, and its delegate's load is refused as the beneficiary's account, so it never reaches "
             "dispatch and the contract reverts with VolatileDataAccessDisabled(10)", gas=500_000, system=True,
             accounts={model.IDENTITY: model.Account(code=indicator(COINBASE))},
             code=disable + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50" + mstore(0, 0xC0FFEE)
             + call(1_000, model.IDENTITY, 0, 32) + POP_RETURN, **dict(page, spec=CURRENT_SPEC)))
    words32 = 32 * 32
    identity_price = model.IDENTITY_BASE + model.IDENTITY_WORD * 32
    add(Case("satin/precompiles/delegated-address/priced-past-allowance-detained", "the identity precompile's address "
             "holds an EIP-7702 delegation to a contract that stops at once; after TIMESTAMP, a call to the address with "
             f"{fmt(words32)} bytes of input, priced {fmt(identity_price)} by the identity, one past the allowance, and "
             "forwarded more: decided by the identity's price and not the delegate's code, it is gas detention's "
             "crossing, whose stop its caller returns", boundary="the identity's price one past the allowance",
             gas=21_000_000, accounts={model.IDENTITY: model.Account(code=indicator(PRECOMPILE_DELEGATE)),
                                       PRECOMPILE_DELEGATE: model.Account(nonce=1, code=STOP)},
             make=lambda words, pad: detained(words, pad) + call(MAX_GAS, model.IDENTITY, 0, words32) + RETURN_RETURNDATA,
             params=dict(start), retune=[("precompile-room", identity_price - 1, "pad", -1)], **page))

    # SATIN-PCMP-004, -005: a BLS12-381 input over its size limit fails before any gas check under gas detention too:
    # priced at zero, it is no crossing though the price its pairs would have is past the allowance and within the
    # forward; it runs on its forward, fails and consumes it.
    for target, label, limit, size in (
            (model.BLS12_G1_MSM, "bls12-g1-msm", model.BLS12_G1_MSM_MAX_INPUT_SIZE, model.BLS12_G1_MSM_PAIR_SIZE),
            (model.BLS12_G2_MSM, "bls12-g2-msm", model.BLS12_G2_MSM_MAX_INPUT_SIZE, model.BLS12_G2_MSM_PAIR_SIZE),
            (model.BLS12_PAIRING, "bls12-pairing", model.BLS12_PAIRING_MAX_INPUT_SIZE, model.BLS12_PAIRING_PAIR_SIZE)):
        pairs = limit // size + 1
        price = model.bls12_price(target, pairs)
        add(Case(f"satin/precompiles/{label}/over-size-limit-detained", f"after TIMESTAMP, a call with {fmt(pairs * size)} "
                 f"zero bytes, one pair over the size limit of {fmt(limit)}, whose {pairs} pairs would be priced "
                 f"{fmt(price)}, one past the allowance, and forwarded more: the size check comes before any gas check, so "
                 "the call is priced at zero, is no crossing, runs on its whole forward, fails and consumes it",
                 boundary="the price the pairs would have one past the allowance", gas=40_000_000,
                 make=lambda words, pad, target=target, n=pairs * size: detained(words, pad)
                 + call(MAX_GAS, target, 0, n) + STOP,
                 params={"words": words_within(cap - price - 400_000), "pad": 0},
                 retune=[("precompile-room", price - 1, "pad", -1)], **page))

    # SATIN-PCMP-003: EIP-7951 compares r with the x of R reduced modulo n: a key whose x is n + 3 and a signature with
    # h = 0 and r = s = 3, for which R is the key itself.
    n = model.P256_N
    x = n + 3
    reduced = p256_words(0, 3, 3, x, p256_y(x))
    p256 = model.P256VERIFY_GAS
    add(Case("satin/precompiles/p256verify/recovered-x-reduced-mod-n", "a contract calls P256VERIFY with h = 0, r = s = 3 "
             "and a public key whose x is the curve order plus 3, forwarding P256VERIFY_GAS: R is the key itself, whose x "
             "reduced modulo n is r, so the signature verifies and the call returns the word 1; comparing x with r "
             "unreduced would not", gas=200_000, code=flagged_call(p256, model.P256VERIFY, reduced), **page))
    # SATIN-PCMP-003: inputs EIP-7951 rejects before verification, each a success with empty output charged the price.
    valid = p256_input()
    h_, r_, s_, qx, qy = p256_fields(valid)
    pf = model.P256_P
    for name, data, size, what in (
            ("input-159-bytes", valid, 159, "the verifying input less its last byte"),
            ("input-161-bytes", valid + b"\x00", 161, "the verifying input and one zero byte more"),
            ("r-zero", p256_words(h_, 0, s_, qx, qy), None, "r = 0"),
            ("r-at-order", p256_words(h_, n, s_, qx, qy), None, "r = n, the curve's order"),
            ("s-zero", p256_words(h_, r_, 0, qx, qy), None, "s = 0"),
            ("s-at-order", p256_words(h_, r_, n, qx, qy), None, "s = n"),
            ("key-at-origin", p256_words(h_, r_, s_, 0, 0), None, "a public key of (0, 0), the encoding of infinity"),
            ("key-off-curve", p256_words(h_, r_, s_, qx, (qy + 1) % pf), None, "a public key in range and off the "
             "curve"),
            ("qx-at-field-modulus", p256_words(h_, r_, s_, pf, qy), None, "a public key whose x is p"),
            ("qy-at-field-modulus", p256_words(h_, r_, s_, qx, pf), None, "a public key whose y is p"),
            ("infinity-intermediate", p256_words(n - 1, 1, 1, *model.P256_G), None, "h = n - 1, r = s = 1 and the "
             "generator as the key, for which R is the point at infinity")):
        add(Case(f"satin/precompiles/p256verify/rejected/{name}", f"a contract calls P256VERIFY with {what}, forwarding "
                 f"twice P256VERIFY_GAS, and returns the call's success flag with its output: the input fails one of "
                 "EIP-7951's checks, so the call succeeds with empty output, charged P256VERIFY_GAS, and returns the "
                 "rest", gas=200_000, code=flagged_call(2 * p256, model.P256VERIFY, data, size), **page))

    # SATIN-PCMP-002: EIP-7823's bound on the exponent's length and the accepting side of the base's. The exponent's
    # bytes are all 0x01, so its first 32 bytes and its low 256 bits, which EIP-7883's text and its implementations
    # read for the iteration count, are the same.
    bound = model.MODEXP_MAX_INPUT_SIZE
    for over in (False, True):
        data = modexp_input(b"\x03", b"\x01" * (bound + over), b"\x07")
        price = model.modexp_price(data)[0]
        forward = 300_000
        add(Case(f"satin/precompiles/modexp/exponent-{'over' if over else 'at'}-bound", f"a contract calls ModExp with a "
                 f"one-byte base 3 and modulus 7 and an exponent of {fmt(bound + over)} bytes of 0x01, priced {fmt(price)}, "
                 f"forwarding {fmt(forward)}: " + ("one byte over EIP-7823's bound on the exponent, so the call is "
                                                   "charged its formula price and then fails the bound, consuming its "
                                                   "forward" if over else
                                                   "the exponent at EIP-7823's bound, so the call runs and returns the "
                                                   "power modulo 7"),
                 boundary=f"the exponent's length {'one over' if over else 'at'} EIP-7823's bound", gas=generous(forward),
                 code=precompile_call(forward, model.MODEXP, data), **page))
    data = modexp_input(bytes(bound), b"", b"\x07")
    price = model.modexp_price(data)[0]
    add(Case("satin/precompiles/modexp/base-at-bound", f"a contract calls ModExp with a zero base of {fmt(bound)} bytes, "
             f"EIP-7823's bound, no exponent and the modulus 7, priced {fmt(price)}, forwarding 50,000: the base at the "
             "bound runs, and 0 to the power 0 modulo 7 is 1", boundary="the base's length at EIP-7823's bound",
             gas=generous(50_000), code=precompile_call(50_000, model.MODEXP, data), **page))
    # SATIN-PCMP-002, -007: EIP-7883's thresholds one at a time, with an exponent of 32 bytes whose top bit alone is set.
    exponent = (1 << 255).to_bytes(32, "big")
    for name, base_width, mod_width, pair in (("widths-32", 32, 32, True), ("base-width-33", 33, 32, False),
                                              ("widths-40", 40, 40, False), ("widths-41", 41, 41, True)):
        data = modexp_input((3).to_bytes(base_width, "big"), exponent, (7).to_bytes(mod_width, "big"))
        price, complexity, iterations = model.modexp_price(data)
        for short in ((True, False) if pair else (False,)):
            forward = price - (1 if short else 0)
            add(Case(f"satin/precompiles/modexp/{name}-{'one-short-of-price' if short else 'at-price'}",
                     f"a contract calls ModExp with a base of {base_width} bytes, the exponent 2^255 in 32 bytes and a "
                     f"modulus of {mod_width} bytes, priced by EIP-7883 at its multiplication complexity {fmt(complexity)} "
                     f"times its iteration count {fmt(iterations)}, {fmt(price)}, forwarding {fmt(forward)}: " +
                     ("one short, so the call fails out of gas and consumes its forward" if short else
                      "its price exactly, so the call succeeds and returns 3 to that power modulo 7"),
                     boundary=f"the forward {'one below' if short else 'at'} the formula price", gas=generous(forward),
                     code=precompile_call(forward, model.MODEXP, data), **page))

    # SATIN-PCMP-006: KZG point evaluation's upper length, and an evaluation point or value that is no canonical field
    # element, against a point one below the modulus.
    kzg = model.KZG_POINT_EVALUATION_GAS
    modulus = model.BLS_MODULUS
    for name, data, size, forward, intent in (
            ("input-one-byte-long", kzg_input(), model.KZG_INPUT_SIZE + 1, 3 * kzg, "the verifying input and one zero "
             "byte more, an input of the wrong length: the call fails and consumes its forward"),
            ("z-at-modulus", kzg_input(z=modulus), None, 3 * kzg, "z equal to the scalar field's modulus, no canonical "
             "field element: the call fails and consumes its forward"),
            ("y-at-modulus", kzg_input(y=modulus), None, 3 * kzg, "y equal to the scalar field's modulus, no canonical "
             "field element: the call fails and consumes its forward"),
            ("z-below-modulus-at-price", kzg_input(z=modulus - 1), None, kzg, "z one below the modulus and y = 0, "
             "forwarded KZG_POINT_EVALUATION_GAS: the input verifies and the call is charged exactly the price")):
        add(Case(f"satin/precompiles/kzg/{name}", "a contract calls KZG point evaluation with a commitment and proof at "
                 f"infinity and " + intent, gas=generous(forward),
                 code=precompile_call(forward, model.KZG_POINT_EVALUATION, data, size), **page))

    # SATIN-PCMP-001: Karst's simplest arithmetic precompiles are installed at their prices.
    for target, label in ((model.BN254_ADD, "bn254-add"), (model.BN254_MUL, "bn254-mul"),
                          (model.BLS12_G1_ADD, "bls12-g1-add"), (model.BLS12_G2_ADD, "bls12-g2-add")):
        size, price, answer = model.INFINITY_ARITHMETIC[target]
        add(Case(f"satin/precompiles/{label}/infinity-at-price", f"a contract calls the precompile at {h(target)} with "
                 f"{size} zero bytes, points at infinity, forwarding its Karst price, {fmt(price)}: it is installed, runs, "
                 f"is charged exactly that price and answers the point at infinity, {answer} zero bytes",
                 gas=200_000, code=precompile_call(price, target, b"", size), **page))
    return out


CREATOR = bytes.fromhex("00000000000000000000000000000000000c0e20")  # a child whose CREATE is its creating frame's
STATIC_CREATOR = bytes.fromhex("00000000000000000000000000000000000c0e21")  # a child a STATICCALL starts, which creates
RETURN_TOP = push(0) + b"\x52" + ret(0, 32)  # MSTORE(0, the stack's top), RETURN(0, 32)


def creating(init: bytes, opcode: bytes = b"\xf0", salt: int = 0) -> bytes:
    """`init` laid out in memory from offset 0, a CREATE (or, with opcode 0xf5, a CREATE2 with `salt`) of it with no value,
    and a return of the created address, zero when the creation failed."""
    return (bytes_to_memory(init) + (push(salt) if opcode == b"\xf5" else b"") + push(len(init)) + push(0) + push(0)
            + opcode + RETURN_TOP)


def size_cases() -> list[Case]:
    """The contract-limits page's own rules (D-104): the code and initcode limits at their exact bytes, from a creation
    transaction and a creation opcode, and the order of a creation's checks and charges, under gas detention
    where a charge made out of order would be the crossing."""
    out: list[Case] = []
    add = out.append
    page = {"spec": SECOND_FILL_SPEC, "size_page": True}
    code_max, init_max = model.MAX_CONTRACT_SIZE, model.MAX_INITCODE_SIZE
    history = model.COST_PER_HISTORY_BYTE

    # SATIN-SIZE-002, -004: a creation transaction's initcode at MAX_INITCODE_SIZE runs; one byte over is rejected at
    # validation. Zero bytes of initcode stop at once. A deposit's top-level creation one byte over runs (below).
    gas = 150_000_000
    for over in (False, True):
        size = init_max + (1 if over else 0)
        add(Case(f"satin/contract-limits/creation-tx/initcode-{'over' if over else 'at'}-limit",
                 f"a creation transaction whose initcode is {fmt(size)} zero bytes, with a gas limit of {fmt(gas)}, which "
                 "pays its intrinsic gas and its body's history: " +
                 ("one byte over MAX_INITCODE_SIZE, so the transaction is rejected at validation" if over else
                  "MAX_INITCODE_SIZE exactly, so it passes validation, its initcode stops at once and it creates an "
                  "account without code"),
                 boundary=f"the initcode {'one byte over' if over else 'at'} MAX_INITCODE_SIZE", to=None, data=bytes(size),
                 gas=gas, **page))
    # From `83c0d26` on, a deposit's top-level creation is not checked against MAX_INITCODE_SIZE: its creation runs
    # subject to its other checks and charges, where at `bcf260d` it was a failed deposit (D-112, closing D-105's hold).
    # The model derives a creating deposit as the deposits page's cases do (`system_pages`, D-109).
    add(Case("satin/contract-limits/deposit/initcode-over-limit", f"a deposit minting 1 ether that creates with "
             f"{fmt(init_max + 1)} zero bytes of initcode, one over MAX_INITCODE_SIZE, with a gas limit of {fmt(gas)}: a "
             "deposit's top-level creation is not checked against MAX_INITCODE_SIZE, so the deposit is no failed deposit "
             "for it and its creation runs, paying for its initcode as any creation transaction does; the initcode stops "
             "at once and creates an account without code", boundary="the initcode one byte over MAX_INITCODE_SIZE",
             deposit=(ETH, gas), sender_nonce=3, to=None, data=bytes(init_max + 1),
             **dict(page, spec=CURRENT_SPEC, system_pages=True)))

    # SATIN-SIZE-001, -003: deployed code at MAX_CONTRACT_SIZE is deposited; one byte over halts the creation, a creation
    # transaction's (satin/outcomes/size/deployed-code-over-limit) or a CREATE's, consuming the creation's regular gas.
    gas = 1_000_000_000
    deposit_gas = model.CODE_STATE_PER_BYTE * code_max + history * code_max + model.KECCAK_WORD * (code_max // 32)
    add(Case("satin/contract-limits/creation-tx/deployed-code-at-limit", f"a creation transaction whose initcode returns "
             f"{fmt(code_max)} zero bytes, MAX_CONTRACT_SIZE exactly, with a gas limit of {fmt(gas)}, which pays that "
             f"code's deposit, {fmt(deposit_gas)}: the size check passes and the code is deposited",
             boundary="the deployed code at MAX_CONTRACT_SIZE", to=None, gas=gas, data=push(code_max) + push(0) + b"\xf3",
             **page))
    for over in (False, True):
        size = code_max + (1 if over else 0)
        add(Case(f"satin/contract-limits/create/deployed-code-{'over' if over else 'at'}-limit",
                 f"a contract CREATEs with initcode that returns {fmt(size)} zero bytes, with a gas limit of {fmt(gas)}, "
                 f"which could pay a deposit of MAX_CONTRACT_SIZE's code, {fmt(deposit_gas)}, and returns the created "
                 "address: " +
                 ("one byte over MAX_CONTRACT_SIZE, so the size check halts the creation before its deposit, consuming "
                  "its regular gas; the created account's charges are given back, and the creator, which is not halted, "
                  "returns zero" if over else "MAX_CONTRACT_SIZE exactly, so the code is deposited and the creator "
                  "returns the created address"),
                 boundary=f"the deployed code {'one byte over' if over else 'at'} MAX_CONTRACT_SIZE", gas=gas,
                 code=creating(push(size) + push(0) + b"\xf3"), **page))

    # SATIN-SIZE-002, -003: initcode over MAX_INITCODE_SIZE halts the creating frame at the opcode, here a child, which
    # consumes its regular gas; its caller resumes, with no stop's return data.
    forward = 5_000_000
    for over in (False, True):
        size = init_max + (1 if over else 0)
        add(Case(f"satin/contract-limits/create/initcode-{'over' if over else 'at'}-limit-in-child",
                 f"a contract calls a child, forwarding {fmt(forward)}, that CREATEs with {fmt(size)} zero bytes of "
                 "initcode and stops, and returns what the call returned: " +
                 ("one byte over MAX_INITCODE_SIZE, so the size check halts the child at the opcode, consuming its "
                  "regular gas; it is no limit stop, and the caller resumes with empty return data" if over else
                  "MAX_INITCODE_SIZE exactly, so the child creates an account without code and stops"),
                 boundary=f"the initcode {'one byte over' if over else 'at'} MAX_INITCODE_SIZE", gas=8_000_000,
                 accounts={CREATOR: model.Account(nonce=1, code=push(size) + push(0) + push(0) + b"\xf0" + STOP)},
                 code=call(forward, CREATOR, 0, 0) + POP_RETURN, **page))

    # SATIN-SIZE-005 step 5: the offset of empty initcode is not checked, a non-empty one's is.
    top = 2**256 - 1
    for opcode, name in ((b"\xf0", "create"), (b"\xf5", "create2")):
        add(Case(f"satin/contract-limits/{name}/empty-initcode-offset-out-of-range",
                 f"a contract runs {name.upper()} with no value, an offset of 2^256 - 1 and a size of zero"
                 + (" and a salt of zero" if name == "create2" else "") + ", and returns the created address: the offset "
                 "of empty initcode is not checked, so the creation runs and creates an account without code",
                 boundary="an out-of-range offset with empty initcode",
                 code=(push(0) if name == "create2" else b"") + push(0) + push(top) + push(0) + opcode + RETURN_TOP,
                 **page))
    add(Case("satin/contract-limits/create/one-byte-initcode-offset-out-of-range", "a contract runs CREATE with no value, "
             "an offset of 2^256 - 1 and a size of one: the initcode is not empty, so after its initcode cost its offset's "
             "range is checked, which fails, and the frame halts, using the whole gas limit",
             boundary="an out-of-range offset with one byte of initcode", gas=100_000,
             code=push(1) + push(top) + push(0) + b"\xf0" + RETURN_TOP, **page))

    # SATIN-SIZE-005, -006 under gas detention: a child left 1 of spendable gas at a creation, where any charge made
    # before the check that halts it would be the crossing and stop it instead; and CREATE2 short of its salt, whose
    # memory is the crossing once its initcode cost is paid.
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 6_000), "pad": 0}
    detained_call = lambda words, pad: detained(words, pad) + call(100_000, DETAINED, 0, 0) + STOP  # noqa: E731
    oversize = push(0) + push(init_max + 1) + push(0) + push(0) + b"\xf5" + STOP
    operands = model.G_VERYLOW + 3 * model.G_BASE
    add(Case("satin/contract-limits/create2/initcode-over-limit-detained", f"a detained child with 1 of spendable gas at a "
             f"CREATE2 of {fmt(init_max + 1)} bytes of initcode, one over MAX_INITCODE_SIZE, with its salt: the size check "
             "comes before the initcode cost, the memory and the salt's charges, so the child halts there and burns its "
             "regular gas, where an initcode cost charged first would have been the crossing",
             boundary="1 of spendable gas at the opcode", gas=21_000_000,
             accounts={DETAINED: model.Account(nonce=1, code=oversize)}, make=detained_call, params=dict(start),
             retune=[("child-room", 1 + operands, "pad", -1)], **page))
    salt_short = push(32) + push(0) + push(0) + b"\xf5" + STOP
    initcode, memory = model.INITCODE_WORD_COST, model.memory_cost(1)
    spendable = initcode + memory - 1
    add(Case("satin/contract-limits/create2/short-of-salt-memory-crossing", f"a detained child with {spendable} of "
             f"spendable gas at a CREATE2 holding its value, offset and size but no salt: it pays its initcode cost, "
             f"{initcode}, and then its memory, {memory}, is gas detention's crossing, so the child is stopped, a revert "
             "whose regular gas returns, before the missing salt is read, where reading the salt before the memory would "
             "have halted it", boundary="the spendable part one below the charges before the salt", gas=21_000_000,
             accounts={DETAINED: model.Account(nonce=1, code=salt_short)}, make=detained_call, params=dict(start),
             retune=[("child-room", spendable + model.G_VERYLOW + 2 * model.G_BASE, "pad", -1)], **page))
    static_create = push(32) + push(0) + push(0) + b"\xf0" + STOP
    add(Case("satin/contract-limits/static-frame/create-detained", "a detained child that a STATICCALL started, with 1 of "
             "spendable gas at a CREATE of 32 bytes of initcode: the static context is checked before the operands and "
             "every charge, so the child halts and burns its regular gas, where an initcode cost charged first would "
             "have been the crossing and stopped it", boundary="1 of spendable gas at the opcode", gas=21_000_000,
             accounts={STATIC_CREATOR: model.Account(nonce=1, code=static_create)},
             make=lambda words, pad: detained(words, pad) + staticcall(100_000, STATIC_CREATOR) + STOP, params=dict(start),
             retune=[("child-room", 1 + model.G_VERYLOW + 2 * model.G_BASE, "pad", -1)], **page))
    return out


def size_gap_cases() -> list[Case]:
    """The contract-limits page's edges an independent review found unpinned (D-104, second round)."""
    out: list[Case] = []
    add = out.append
    page = {"spec": SECOND_FILL_SPEC, "size_page": True}
    code_max, init_max = model.MAX_CONTRACT_SIZE, model.MAX_INITCODE_SIZE
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    start = {"words": words_within(cap - 20_000), "pad": 0}
    detained_call = lambda words, pad: detained(words, pad) + call(100_000, DETAINED, 0, 0) + STOP  # noqa: E731

    # SATIN-SIZE-001 to -003 through CREATE2, salt present: initcode at MAX_INITCODE_SIZE, and deployed code at
    # MAX_CONTRACT_SIZE and one byte over.
    add(Case("satin/contract-limits/create2/initcode-at-limit", f"a contract runs CREATE2 with a salt of zero over "
             f"{fmt(init_max)} zero bytes of initcode, MAX_INITCODE_SIZE exactly, and returns the created address: the size "
             "check passes, the initcode is hashed for the address, and it stops at once, creating an account without "
             "code", boundary="the initcode at MAX_INITCODE_SIZE", gas=5_000_000,
             code=push(0) + push(init_max) + push(0) + push(0) + b"\xf5" + RETURN_TOP, **page))
    gas = 1_000_000_000
    for over in (False, True):
        size = code_max + (1 if over else 0)
        add(Case(f"satin/contract-limits/create2/deployed-code-{'over' if over else 'at'}-limit",
                 f"a contract runs CREATE2 with a salt of zero over initcode that returns {fmt(size)} zero bytes, with a "
                 f"gas limit of {fmt(gas)}, and returns the created address: " +
                 ("one byte over MAX_CONTRACT_SIZE, so the size check halts the creation before its deposit, consuming "
                  "its regular gas, and the creator returns zero" if over else
                  "MAX_CONTRACT_SIZE exactly, so the code is deposited at the salted address"),
                 boundary=f"the deployed code {'one byte over' if over else 'at'} MAX_CONTRACT_SIZE", gas=gas,
                 code=creating(push(size) + push(0) + b"\xf3", b"\xf5"), **page))

    # SATIN-SIZE-003 under gas detention: the code-size check comes before the deposit's first compute charge, its
    # hashing, which the creation's spendable part cannot pay; the creation halts and is not stopped.
    oversize = push(code_max + 1) + push(0) + b"\xf3"
    hashing = model.KECCAK_WORD * ((code_max + 1 + 31) // 32)
    room = model.G_VERYLOW + model.G_BASE + model.memory_cost((code_max + 1 + 31) // 32) + 1
    add(Case("satin/contract-limits/create/deployed-code-over-limit-detained", f"after TIMESTAMP, a contract CREATEs with "
             f"initcode that returns {fmt(code_max + 1)} zero bytes, one over MAX_CONTRACT_SIZE, the creation left 1 of "
             f"spendable gas after its RETURN, below its deposit's hashing, {fmt(hashing)}: the size check comes before "
             "every charge of the deposit, so the creation halts, consuming its regular gas, where a hashing charged "
             "first would have been the crossing and stopped it", boundary="1 of spendable gas after the RETURN",
             gas=30_000_000, make=lambda words, pad: detained(words, pad) + bytes_to_memory(oversize)
             + push(len(oversize)) + push(0) + push(0) + b"\xf0" + STOP,
             params={"words": words_within(cap - room - 100_000), "pad": 0},
             retune=[("child-room", room, "pad", -1)], **page))

    # SATIN-SIZE-005 step 6, SATIN-DET-018 under gas detention: CREATE2's CREATE_ACCESS and the hashing of its initcode,
    # after its salt, are one charge, as the base layer deducts them; memory already expanded, a spendable part one short
    # of that charge and one that pays it.
    pre_expanded = mstore(0, 0)
    salted = pre_expanded + push(0) + push(32) + push(0) + push(0) + b"\xf5" + STOP
    before = model.G_BASE * 2 + model.G_VERYLOW + model.memory_cost(1) + model.G_BASE + model.G_VERYLOW + 2 * model.G_BASE
    initcode, access, hashing = model.INITCODE_WORD_COST, model.CREATE_ACCESS, model.KECCAK_WORD
    for paid in (False, True):
        spendable = initcode + access + hashing - (0 if paid else 1)
        add(Case(f"satin/contract-limits/create2/access-and-hashing-{'paid' if paid else 'one-short'}",
                 f"a detained child expands one word of memory and runs CREATE2 over 32 zero bytes with its salt, "
                 f"{fmt(spendable)} of spendable gas at the opcode: it pays its initcode cost, {initcode}, and no memory, "
                 f"and then CREATE_ACCESS, {fmt(access)}, and the hashing of the initcode, {hashing}, one charge as the "
                 "base layer deducts them, " + ("which the spendable part pays: the creation runs" if paid else
                                                "which the spendable part is one short of: that charge is gas "
                                                "detention's crossing, and none of the access stays spent"),
                 boundary=f"the spendable part {'at' if paid else 'one below'} the charges", gas=21_000_000,
                 accounts={DETAINED: model.Account(nonce=1, code=salted)}, make=detained_call, params=dict(start),
                 retune=[("child-room", spendable + before, "pad", -1)], **page))

    # SATIN-SIZE-005 step 5 under gas detention: the initcode cost comes before the offset's range is checked, so with 1
    # of spendable gas the cost is the crossing, a stop, where the out-of-range offset would have halted the child.
    top = 2**256 - 1
    for opcode, name, salt in ((b"\xf0", "create", b""), (b"\xf5", "create2", push(0))):
        body = salt + push(1) + push(top) + push(0) + opcode + STOP
        operands = (model.G_BASE if salt else 0) + model.G_VERYLOW + model.G_VERYLOW + model.G_BASE
        add(Case(f"satin/contract-limits/{name}/one-byte-initcode-offset-out-of-range-detained", f"a detained child with 1 "
                 f"of spendable gas at a {name.upper()} of one byte of initcode at the offset 2^256 - 1"
                 + (" with its salt" if salt else "") + ": its initcode cost, 2, comes before the offset's range is checked "
                 "and is gas detention's crossing, so the child is stopped, a revert whose regular gas returns, where "
                 "checking the offset first would have halted it", boundary="1 of spendable gas at the opcode",
                 gas=21_000_000, accounts={DETAINED: model.Account(nonce=1, code=body)}, make=detained_call,
                 params=dict(start), retune=[("child-room", 1 + operands, "pad", -1)], **page))

    # SATIN-SIZE-005 step 1, SATIN-SIZE-006: CREATE2 in a static frame, with its salt, halts on the static context.
    static_create2 = push(0) + push(32) + push(0) + push(0) + b"\xf5" + STOP
    add(Case("satin/contract-limits/static-frame/create2-detained", "a detained child that a STATICCALL started, with 1 of "
             "spendable gas at a CREATE2 of 32 bytes of initcode with its salt: the static context is checked before the "
             "operands and every charge, so the child halts and burns its regular gas, where an initcode cost charged "
             "first would have been the crossing and stopped it", boundary="1 of spendable gas at the opcode",
             gas=21_000_000, accounts={STATIC_CREATOR: model.Account(nonce=1, code=static_create2)},
             make=lambda words, pad: detained(words, pad) + staticcall(100_000, STATIC_CREATOR) + STOP, params=dict(start),
             retune=[("child-room", 1 + model.G_VERYLOW + 3 * model.G_BASE, "pad", -1)], **page))

    # SATIN-SIZE-004: a keyless deployment's initcode over MAX_INITCODE_SIZE is refused by its own rule, step 5; at the
    # limit step 5 passes and step 6, a gasLimitOverride one below the signed gas limit, answers.
    signed = 90_000
    for over in (False, True):
        size = init_max + (1 if over else 0)
        override = 2**256 - 1 if over else signed - 1
        add(Case(f"satin/contract-limits/keyless/initcode-{'over' if over else 'at'}-limit", f"the transaction's own "
                 f"keylessDeploy call carries a signed pre-EIP-155 creation with nonce 0 and {fmt(size)} zero bytes of "
                 "initcode: " + ("one byte over MAX_INITCODE_SIZE, so step 5 refuses it with "
                                 "InitCodeTooLarge(uint64,uint64), no creation made" if over else
                                 "MAX_INITCODE_SIZE exactly, so step 5 passes, and its gasLimitOverride, one below the "
                                 "signed gas limit, is refused at step 6 with GasLimitTooLow(uint64,uint64)"),
                 boundary=f"the carried initcode {'one byte over' if over else 'at'} MAX_INITCODE_SIZE", system=True,
                 to=model.KEYLESS_DEPLOY, code=None, data=keyless_data(carried(bytes(size), gas=signed), override),
                 gas=150_000_000, **page))
    return out


# --- A call refused at its target's EIP-7702 delegate, at `83c0d26` (D-115) ----------------------

REFUSING = bytes.fromhex("00000000000000000000000000000000000c0e40")  # the frame whose call is refused at the delegate
WARMER = bytes.fromhex("00000000000000000000000000000000000c0e41")  # reads the delegator's balance, then reverts
BENEFICIARY_DELEGATOR = bytes.fromhex("0000000000000000000000000000000000de1ea0")  # delegates to the block beneficiary
CALL_OPS = {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFA: "STATICCALL"}
STOP_DATA = len(model.limit_exceeded(model.DETENTION_STOP, 0))  # the bytes of MegaLimitExceeded(kind, limit)
AUTHORITY_TARGET = model.DELEGATION_PREFIX + COINBASE  # an authority's code once it delegates to the beneficiary
ONE_HOP = bytes.fromhex("0000000000000000000000000000000000de1ea1")  # delegates to an ordinary account
ONE_HOP_DELEGATE = bytes.fromhex("0000000000000000000000000000000000de1ea2")  # that ordinary account


def call_op(op: int, target: bytes, value: int = 0, inp: tuple = (0, 0), out: tuple = (0, 0), gas: int = 0) -> bytes:
    """A call opcode `op` of `target` with the gas operand `gas`, `value` for a CALL or a CALLCODE, and the input and
    output ranges `inp` and `out`, each (offset, size)."""
    code = push(out[1]) + push(out[0]) + push(inp[1]) + push(inp[0])
    if op in (0xF1, 0xF2):
        code += push(value)
    return code + push(int.from_bytes(target, "big")) + push(gas) + bytes([op])


def delegate_refusal_cases() -> list[Case]:
    """A call refused at its target's EIP-7702 delegate in a frame whose volatile-data access is off (D-115): the call
    makes its steps before the delegate's load as with access on, each of which can end it, and at the delegate's load
    it is refused and settled on its static cost, its memory expansion and its target's access (SATIN-MAC-004, -007).
    The transaction's own frame switches its access off and calls the frame under test, REFUSING, forwarding it what
    leaves the call the regular gas the case names; under gas detention it reads TIMESTAMP first and burns compute so
    that the limit leaves REFUSING the spendable part the case names at its call."""
    out: list[Case] = []
    add = out.append
    warm, surcharge, value_cost = model.WARM_READ, model.COLD_ACCOUNT_SURCHARGE, model.CALL_VALUE_COST
    cold = warm + surcharge
    target = int.from_bytes(BENEFICIARY_DELEGATOR, "big")
    disable = (mstore(0, int.from_bytes(model.DISABLE_VOLATILE_DATA_ACCESS, "big") << 224)
               + call(10_000, model.MEGA_ACCESS_CONTROL, 0, 4) + b"\x50")
    balance = push(target) + b"\x31\x50"  # BALANCE of the delegator, its result popped: what it costs shows its warmth
    delegator = {BENEFICIARY_DELEGATOR: model.Account(nonce=1, code=model.DELEGATION_PREFIX + COINBASE)}
    listed = {"ty": 1, "access_list": [(BENEFICIARY_DELEGATOR, [])]}
    page = {"spec": CURRENT_SPEC, "system": True}
    refusal = f"VolatileDataAccessDisabled({model.ACCESS_TYPE_BENEFICIARY})"
    stop = f"MegaLimitExceeded({model.DETENTION_STOP}, limit)"

    def refusing(code: bytes, left: int, name: str, intent: str, before: bytes = b"", after: bytes = b"",
                 accounts: dict | None = None, boundary: str = "", probe: str = "refusal-call", spare: int = 10_000,
                 via: int = 0xF1, switch: bool = True, **kw) -> None:
        """A case whose transaction's own frame switches its access off (unless `switch` is false), runs `before`,
        calls REFUSING by `via`, REFUSING's `code` holding `left` of regular gas at its call opcode, then runs `after`
        and returns REFUSING's return data."""
        add(Case(f"satin/access-control/delegate-refusal/{name}", intent, boundary=boundary,
                 accounts={**delegator, REFUSING: model.Account(nonce=1, code=code + STOP), **(accounts or {})},
                 make=lambda gas: (disable if switch else b"") + before + call_op(via, REFUSING, gas=gas) + after
                 + RETURN_RETURNDATA,
                 params={"gas": left + spare}, retune=[(probe, left, "gas", 1)], **page, **kw))

    static = call_op(0xFA, BENEFICIARY_DELEGATOR)
    # The control: a call whose target operand is the beneficiary itself is refused before it charges
    # anything, though the frame holds less than its static cost and could fund neither its value nor its memory.
    left = warm // 2
    refusing(call_op(0xF1, COINBASE, value=1, inp=(0, 2**20)), left, "direct-call-under-static-gas",
             f"REFUSING holds {fmt(left)} of regular gas, under the static cost {warm}, at a value CALL of the block "
             f"beneficiary itself with {fmt(2**20)} bytes of input, a value it cannot fund: the call is refused before it "
             f"charges or checks anything and the frame reverts with {refusal}, the call spending nothing "
             "(SATIN-MAC-003, SATIN-MAC-004)", probe="refused")
    left = warm // 10
    refusing(call_op(0xF4, COINBASE), left, "direct-delegatecall-under-static-gas", f"REFUSING holds {fmt(left)} of "
             f"regular gas, under the static cost {warm}, at a DELEGATECALL of the block beneficiary itself: refused before "
             f"it charges anything, the frame reverts with {refusal}, the call spending nothing (SATIN-MAC-003, "
             "SATIN-MAC-004)", probe="refused")
    # A cold delegator, at the edges of the target's load and of the delegation guard.
    for name, left, what, boundary in (
            ("cold-target-load-skipped", cold - 1, f"its static cost leaves {fmt(cold - 1 - warm)}, below the target's "
             f"cold surcharge {fmt(surcharge)}, so the target's load is skipped with an out-of-gas halt: the frame halts, "
             "and the delegator is not in the reads (SATIN-WIT-004, SATIN-WIT-012)",
             f"the regular gas at the call one below the static cost and the cold surcharge, {fmt(cold)}"),
            ("cold-target-loaded-at-the-load", cold, f"its static cost leaves {fmt(surcharge)}, which covers the target's "
             f"cold surcharge, so the target is loaded, and the delegation guard, the cold surcharge and {warm} for the "
             f"delegate's access, {fmt(cold)}, halts the call: the frame halts with the delegator in the reads "
             "(SATIN-WIT-002)", f"the regular gas at the call at the static cost and the cold surcharge, {fmt(cold)}"),
            ("cold-target-one-short-of-the-guard", cold + warm - 1, "the target is loaded and the delegation guard, "
             f"{fmt(cold)}, is one above the {fmt(cold - 1)} its static cost leaves, so the call halts before its "
             "delegate's load: the frame halts with the delegator in the reads (SATIN-WIT-002)",
             f"the regular gas at the call one below the static cost and the guard, {fmt(cold + warm)}")):
        refusing(static, left, name, f"REFUSING holds {fmt(left)} of regular gas at a STATICCALL of an account that is "
                 "not warm and holds an EIP-7702 delegation to the block beneficiary: " + what, boundary=boundary,
                 reads=True)
    left = cold + warm
    refusing(static, left, "cold-target-refused", f"REFUSING holds {fmt(left)} of regular gas at a STATICCALL of an "
             "account that is not warm and holds an EIP-7702 delegation to the block beneficiary: the target is loaded, "
             "the delegation guard holds, and the delegate's load is refused as the beneficiary's account; the call "
             f"pays its static cost and its target's cold surcharge, {fmt(cold)} in all (SATIN-SCHED-003), and the frame "
             "reverts with "
             f"{refusal} (SATIN-MAC-005), handing back {fmt(left - cold)}. The frame's revert leaves the delegator cold "
             "for the caller, whose BALANCE of it pays the cold access and reads the same account",
             boundary=f"the regular gas at the call at the static cost and the guard, {fmt(left)}", after=balance,
             reads=True)
    for op in (0xF1, 0xF2):
        refusing(call_op(op, BENEFICIARY_DELEGATOR), left, f"{CALL_OPS[op].lower()}-cold-target-refused", f"REFUSING "
                 f"holds {fmt(left)} of regular gas at a {CALL_OPS[op]} without value of an account that is not warm and "
                 "holds an EIP-7702 delegation to the block beneficiary: refused at the delegate's load, it pays its "
                 f"static cost and its target's cold surcharge, {fmt(cold)}, nothing given back that it was not charged, "
                 f"and the frame reverts with {refusal}; the revert leaves the delegator cold for the caller, whose "
                 "BALANCE of it pays the cold access", after=balance)
    cap = model.BLOCK_ENV_ACCESS_COMPUTE_GAS
    refusing(static, left, "refusal-marks-nothing", f"REFUSING holds {fmt(left)} of regular gas at a STATICCALL of an "
             "account that is not warm and holds an EIP-7702 delegation to the block beneficiary, refused at the "
             "delegate's load: a refused read marks nothing for gas detention, so the caller's memory expansion after it, "
             f"past the cap {fmt(cap)}, completes (SATIN-MAC-004)", after=b"\x50" + over_cap(cap),
             gas=21_500_000)
    # A delegator the access list warms, at the edge of the delegation guard.
    for refused, left in ((False, 2 * warm - 1), (True, 2 * warm)):
        refusing(static, left, f"warm-target-{'refused' if refused else 'one-short-of-the-guard'}", f"REFUSING holds "
                 f"{fmt(left)} of regular gas at a STATICCALL of an account the transaction's access list warms, which "
                 "holds an EIP-7702 delegation to the block beneficiary: the target is loaded with no cold surcharge, and "
                 + (f"the delegation guard, {warm} for the delegate's access, holds; the delegate's load is refused, the "
                    f"call pays its static cost {warm} alone (SATIN-SCHED-003), and the frame reverts with {refusal}, "
                    "handing back "
                    f"{fmt(left - warm)}; the access list's warmth stays, so the caller's BALANCE of the delegator pays "
                    "the warm access" if refused else
                    f"the delegation guard, {warm} for the delegate's access, is one above the {fmt(left - warm)} the "
                    "static cost leaves: the call halts before its delegate's load"),
                 boundary=f"the regular gas at the call {'at' if refused else 'one below'} the static cost and the guard, "
                 f"{fmt(2 * warm)}", after=balance if refused else b"", **listed)
    # A value call its frame cannot fund pays the value transfer before the target's load, and has it
    # back at the refusal, which comes before the start's funds check; a CALLCODE the same.
    left = warm + value_cost + cold
    refusing(call_op(0xF1, BENEFICIARY_DELEGATOR, value=1), left, "value-call-at-the-guard", f"REFUSING, which holds "
             f"no balance, holds {fmt(left)} of regular gas at a CALL with value 1 of an account that is not warm and "
             "holds an EIP-7702 delegation to the block beneficiary: the static cost and the value transfer, "
             f"{fmt(warm + value_cost)} (SATIN-SCHED-003), leave the delegation guard's {fmt(cold)} exactly; the "
             "delegate's load is "
             f"refused before the start checks the funds, the value transfer is given back, and the call pays its static "
             f"cost and its target's cold surcharge, {fmt(cold)}, the frame reverting with {refusal}. The target's "
             "completed read stays in the witness (SATIN-WIT-002, SATIN-WIT-012)",
             boundary=f"the regular gas at the call at the static cost, the value transfer and the guard, {fmt(left)}",
             reads=True)
    refusing(call_op(0xF1, BENEFICIARY_DELEGATOR, value=1), left - 1, "value-call-one-short-of-the-guard",
             f"REFUSING, which holds no balance, holds {fmt(left - 1)} of regular gas at a CALL with value 1 of an "
             "account that is not warm and holds an EIP-7702 delegation to the block beneficiary: the static cost and "
             f"the value transfer leave {fmt(cold - 1)}, which covers the target's cold surcharge, so the target is "
             f"loaded, and the delegation guard, {fmt(cold)}, halts the call: the frame halts with the delegator in the "
             "reads (SATIN-WIT-002)", boundary="the regular gas at the call one below the static cost, the value "
             f"transfer and the guard, {fmt(left)}", reads=True)
    left = 15_000
    for op, name in ((0xF1, "value-call-refused"), (0xF2, "value-callcode-refused")):
        refusing(call_op(op, BENEFICIARY_DELEGATOR, value=1), left, name, f"REFUSING, which holds no balance, holds "
                 f"{fmt(left)} of regular gas at a {CALL_OPS[op]} with value 1 to a cold account with an EIP-7702 "
                 f"delegation to the block beneficiary. It pays {fmt(value_cost)} for the value transfer before "
                 "loading the target and gets that charge back at the delegate's refusal (SATIN-SCHED-003). "
                 f"It pays {fmt(cold)} in static cost and cold surcharge and reverts with {refusal}, handing back "
                 f"{fmt(left - cold)}. "
                 "The target's completed read stays in the witness (SATIN-WIT-002, SATIN-WIT-012)", reads=True)
    left = cold + warm
    refusing(call_op(0xF4, BENEFICIARY_DELEGATOR), left, "delegatecall-cold-target-refused", f"REFUSING holds "
             f"{fmt(left)} of regular gas at a DELEGATECALL of an account that is not warm and holds an EIP-7702 "
             "delegation to the block beneficiary: refused at the delegate's load, it pays its static cost and its "
             f"target's cold surcharge, {fmt(cold)}, and the frame reverts with {refusal}; the revert leaves the delegator "
             "cold for the caller, whose BALANCE of it pays the cold access", after=balance)
    for op in (0xF1, 0xF2, 0xF4):
        opcode = CALL_OPS[op]
        refusing(call_op(op, BENEFICIARY_DELEGATOR), left, f"{opcode.lower()}-cold-target-refusal-reads",
                 f"REFUSING holds {fmt(left)} of regular gas at a {opcode} without value to a cold account with "
                 f"an EIP-7702 delegation to the block beneficiary: it reverts with {refusal} and hands back "
                 f"{fmt(left - cold)} after paying {fmt(cold)} in static cost and cold surcharge (SATIN-SCHED-003). "
                 "The target's completed read stays in the witness (SATIN-WIT-002, SATIN-WIT-012), with no later "
                 "access to the target",
                 reads=True)
    # The memory expansion stays charged: the opcode's own growth for its two ranges together, nothing for memory the
    # frame already holds.
    words = 32
    grown = model.memory_cost(words)
    left = 1_000
    refusing(call_op(0xFA, BENEFICIARY_DELEGATOR, out=(0, words * 32)), left, "memory-stays-charged", f"REFUSING holds "
             f"{fmt(left)} of regular gas at a STATICCALL with an output range of {fmt(words * 32)} bytes of an account "
             "the access list warms, which holds an EIP-7702 delegation to the block beneficiary: refused at the "
             f"delegate's load, the call pays its static cost {warm} and its memory expansion to {words} words, "
             f"{fmt(grown)}, which stays charged, and the frame reverts with {refusal}", **listed)
    refusing(mstore(words * 32 - 32, 1) + call_op(0xFA, BENEFICIARY_DELEGATOR, out=(0, words * 32)), left,
             "memory-already-held", f"REFUSING first stores a word that grows its memory to {words} words, then holds "
             f"{fmt(left)} of regular gas at a STATICCALL with an output range of {fmt(words * 32)} bytes, within that "
             "memory, of an account the access list warms, which holds an EIP-7702 delegation to the block beneficiary: "
             f"refused at the delegate's load, the call pays its static cost {warm} alone, its ranges growing no memory",
             **listed)
    held_words, past = 2 * words, (3 * words * 32, 64)
    past_words = (past[0] + past[1]) // 32
    refusing(mstore(held_words * 32 - 32, 1) + call_op(0xFA, BENEFICIARY_DELEGATOR, inp=(0, words * 32), out=past),
             left, "memory-grown-past-held", f"REFUSING first stores a word that grows its memory to {held_words} words, "
             f"then holds {fmt(left)} of regular gas at a STATICCALL of an account the access list warms, which holds an "
             f"EIP-7702 delegation to the block beneficiary, with an input range within that memory and an output range "
             f"past it, to {past_words} words: refused at the delegate's load, the call pays its static cost {warm} and "
             f"the growth from {held_words} to {past_words} words, "
             f"{fmt(model.memory_cost(past_words) - model.memory_cost(held_words))}, not the frame's whole memory cost",
             **listed)
    both = model.memory_cost(2 * words)
    left = 20_000
    refusing(call_op(0xF1, BENEFICIARY_DELEGATOR, value=1, inp=(0, words * 32), out=(0, 2 * words * 32)), left,
             "memory-of-both-ranges", f"REFUSING, which holds no balance, holds {fmt(left)} of regular gas at a CALL with "
             f"value 1, an input range of {fmt(words * 32)} bytes and an output range of {fmt(2 * words * 32)} bytes, of "
             "an account that is not warm and holds an EIP-7702 delegation to the block beneficiary: refused at the "
             f"delegate's load, the call pays its static cost {warm}, its memory expansion for its two ranges together, "
             f"to {2 * words} words, {fmt(both)}, and its target's cold surcharge {fmt(surcharge)}, the value transfer "
             "given back")
    left = 5_000
    refusing(call_op(0xF2, BENEFICIARY_DELEGATOR, inp=(0, 2**20)), left, "memory-halts-before-the-target",
             f"REFUSING holds {fmt(left)} of regular gas at a CALLCODE with {fmt(2**20)} bytes of input of an account that "
             "holds an EIP-7702 delegation to the block beneficiary: the memory expansion, a step before the target's "
             "load, halts the call out of gas, so the delegator is not in the reads (SATIN-WIT-004, SATIN-WIT-012)",
             reads=True)
    left = cold + warm
    refusing(sstore(1, 1) + sstore(1, 0) + static, left, "refusal-after-a-give-back", "REFUSING writes a fresh slot and "
             "writes it back to zero, a give-back into its reservoir, then holds "
             f"{fmt(left)} of regular gas at a STATICCALL of an account that is not warm and holds an EIP-7702 delegation "
             "to the block beneficiary: the refusal restores its regular gas and charges its static cost and its target's "
             f"cold surcharge, {fmt(cold)}, leaving the reservoir as the opcode found it, and the frame's revert rolls "
             "back its own state and history charges (SATIN-MAC-004, SATIN-POOL-014)", spare=200_000)
    # The warmth the refused call pays for: EIP-2929's accessed addresses as they stand when it reaches its target's
    # load, and the frame's end rolls back the warming the frame took.
    left = 1_000
    refusing(balance + static, left, "warmth-taken-in-the-frame-rolls-back", f"REFUSING reads the balance of an account "
             "that holds an EIP-7702 delegation to the block beneficiary, warming it, then holds "
             f"{fmt(left)} of regular gas at a STATICCALL of it: the call finds its target warm and pays its static cost "
             f"{warm} alone, and the frame's revert rolls back the warming it took, so the caller's BALANCE of the "
             f"delegator pays the cold access, {fmt(cold)}", after=balance)
    left = 2 * warm
    refusing(static, left, "warmth-from-before-the-frame-stays", "the transaction's own frame reads the balance of an "
             "account that holds an EIP-7702 delegation to the block beneficiary before it calls REFUSING, which holds "
             f"{fmt(left)} of regular gas at a STATICCALL of it: the call finds its target warm and pays its static cost "
             f"{warm} alone, and REFUSING's revert leaves the warmth from before it started, so the caller's BALANCE of "
             f"the delegator pays {warm}", before=balance, after=balance)
    left = cold + warm
    refusing(static, left, "warmth-a-revert-took-back", "the transaction's own frame calls a frame that reads the "
             "balance of an account holding an EIP-7702 delegation to the block beneficiary and reverts, then calls "
             f"REFUSING, which holds {fmt(left)} of regular gas at a STATICCALL of it: the warming the revert took back "
             f"does not count, so the call pays its static cost and its target's cold surcharge, {fmt(cold)}. The "
             f"caller's BALANCE after REFUSING reverts also pays the cold access, {fmt(cold)} (SATIN-SCHED-003)",
             before=call(50_000, WARMER, 0, 0) + b"\x50", after=balance,
             accounts={WARMER: model.Account(nonce=1, code=balance + revert(0, 0))})

    def buffered(gas: int) -> bytes:
        """Calls REFUSING forwarding `gas`, with an output range of 68 bytes, a limit stop's size, over memory already
        held and cleared, and returns that range at no cost: the size is pushed before the call and the call's own
        status, zero when REFUSING fails, is the RETURN's offset (D-117)."""
        return (mstore(0, 0) + mstore(64, 0) + push(STOP_DATA) + call_op(0xF1, REFUSING, out=(0, STOP_DATA), gas=gas)
                + b"\xf3")

    # Under gas detention: the static cost, the memory expansion and the value transfer are each a charge the spendable
    # part can cross before the target's load; at the refusal the call's gas is restored, and only the target's cold
    # surcharge, charged last, can cross (SATIN-DET-018, SATIN-MAC-004).
    start = {"words": words_within(cap - 30_000), "pad": 0}

    def detained_refusal(code: bytes, whole: int, spendable: int, name: str, intent: str, boundary: str = "",
                         tail: bytes | None = RETURN_RETURNDATA, reads: bool = True, gas: int = 21_000_000,
                         area: str = "delegate-refusal", probe: str = "refusal-call", accounts: dict | None = None,
                         **kw) -> None:
        """A case whose transaction's own frame reads TIMESTAMP, burns compute, switches its access off and calls
        REFUSING, whose `code` holds `whole` of regular gas at its call opcode, of which it may spend `spendable`. A
        `tail` of None returns REFUSING's return data at no cost (`buffered`), so a caller left no allowance shows it."""
        call_refusing = (lambda g: call(g, REFUSING, 0, 0) + tail) if tail is not None else buffered
        add(Case(f"satin/detention/{area}/{name}", intent, boundary=boundary, detention=True, reads=reads, gas=gas,
                 accounts={**delegator, REFUSING: model.Account(nonce=1, code=code + STOP), **(accounts or {})},
                 make=lambda words, pad, gas: detained(words, pad) + disable + call_refusing(gas),
                 params={**start, "gas": whole + 1_000},
                 retune=[(probe, whole, "gas", 1), (probe.replace("refusal-call", "refusal-call-room")
                                                    if probe == "refusal-call" else probe.replace("call-opcode:",
                                                                                                    "call-opcode-room:"),
                                                    spendable, "pad", -1)], **page, **kw))

    whole = 5_200
    held = f"after TIMESTAMP, REFUSING holds {fmt(whole)} of regular gas at a STATICCALL of an account that is not warm " \
           "and holds an EIP-7702 delegation to the block beneficiary, of which it may spend"
    spendable = warm - 1
    detained_refusal(static, whole, spendable, "static-cost-crossing", f"{held} {fmt(spendable)}: its static cost {warm} "
                     f"is gas detention's crossing, so the frame is stopped with {stop} before its target's load, handing "
                     f"back all {fmt(whole)}, and the delegator is not in the reads (SATIN-MAC-007, SATIN-WIT-004, "
                     "SATIN-WIT-012)",
                     boundary=f"the spendable part one below the static cost {warm}")
    for spendable, name, boundary in ((2 * warm, "surcharge-crossing", ""),
                                      (cold - 1, "surcharge-crossing-one-short",
                                       f"the spendable part one below the static cost and the cold surcharge, {fmt(cold)}")):
        detained_refusal(static, whole, spendable, name, f"{held} {fmt(spendable)}: the whole regular gas loads the "
                         "target and passes the delegation guard, and the delegate's load is refused; the call's gas is "
                         f"restored and its static cost {warm} charged again, and its target's cold surcharge "
                         f"{fmt(surcharge)}, charged last, is gas detention's crossing: the frame is stopped with {stop}, "
                         f"not reverted with {refusal}, handing back {fmt(whole - warm)}, the withheld part included, and "
                         "the delegator stays in the reads (SATIN-MAC-004, SATIN-MAC-007, SATIN-OUT-008, SATIN-STOP-020, "
                         "SATIN-WIT-002, SATIN-WIT-012)", boundary=boundary)
    spendable = cold
    detained_refusal(static, whole, spendable, "surcharge-paid", f"{held} {fmt(spendable)}: refused at the delegate's "
                     f"load, the call pays its static cost and its target's cold surcharge, {fmt(cold)}, from the "
                     f"spendable part, which can, and the frame reverts with {refusal}, not a limit stop, handing back "
                     f"{fmt(whole - cold)}; the caller, left no allowance, returns REFUSING's return data at no cost, "
                     f"so the refusal's error shows (SATIN-MAC-004, SATIN-MAC-005, SATIN-OUT-008, SATIN-STOP-020)",
                     boundary=f"the spendable part at the static cost and the cold surcharge, {fmt(cold)}", tail=None)
    spendable = warm
    detained_refusal(static, whole, spendable, "warm-target-refused", f"after TIMESTAMP, REFUSING holds {fmt(whole)} of "
                     "regular gas at a STATICCALL of an account the transaction's access list warms, which holds an "
                     f"EIP-7702 delegation to the block beneficiary, of which it may spend {fmt(spendable)}: its static "
                     f"cost uses up the spendable part; refused at the delegate's load, the call's gas is restored and its "
                     f"static cost {warm} charged again, with no cold surcharge that could cross, and the frame reverts "
                     f"with {refusal}, handing back {fmt(whole - warm)}; the caller, left no allowance, returns "
                     "REFUSING's return data at no cost, so the refusal's error shows (SATIN-MAC-004, SATIN-MAC-005, "
                     "SATIN-OUT-008, SATIN-STOP-020)", boundary=f"the spendable part at the static cost {warm}",
                     tail=None, **listed)
    ranged = call_op(0xFA, BENEFICIARY_DELEGATOR, out=(0, words * 32))
    held = f"after TIMESTAMP, REFUSING holds {fmt(whole)} of regular gas at a STATICCALL with an output range of " \
           f"{fmt(words * 32)} bytes, whose memory costs {fmt(grown)}, of an account that is not warm and holds an " \
           "EIP-7702 delegation to the block beneficiary, of which it may spend"
    spendable = warm + grown - 1
    detained_refusal(ranged, whole, spendable, "memory-crossing-before-the-load", f"{held} {fmt(spendable)}: the memory "
                     f"expansion, after the static cost, is gas detention's crossing, so the frame is stopped with {stop} "
                     f"before its target's load, handing back {fmt(whole - warm)}, and the delegator is not in the reads "
                     "(SATIN-MAC-007, SATIN-WIT-004, SATIN-WIT-012)", boundary=f"the spendable part one below the static "
                     f"cost and the memory, {fmt(warm + grown)}")
    spendable = 3 * warm
    detained_refusal(ranged, whole, spendable, "surcharge-crossing-keeps-the-memory", f"{held} {fmt(spendable)}: the call "
                     "reaches its delegate's load and is refused; its static cost and its memory expansion are charged "
                     f"again, and its target's cold surcharge, charged last, is gas detention's crossing: the frame is "
                     f"stopped with {stop}, the memory staying charged, handing back {fmt(whole - warm - grown)}, and the "
                     "delegator stays in the reads (SATIN-MAC-004, SATIN-MAC-007, SATIN-OUT-008, SATIN-STOP-020, "
                     "SATIN-WIT-002, SATIN-WIT-012)")
    whole = 20_000
    valued = call_op(0xF1, BENEFICIARY_DELEGATOR, value=1)
    held = f"after TIMESTAMP, REFUSING, which holds no balance, holds {fmt(whole)} of regular gas at a CALL with value " \
           "1 of an account that is not warm and holds an EIP-7702 delegation to the block beneficiary, of which it " \
           "may spend"
    spendable = warm + value_cost
    detained_refusal(valued, whole, spendable, "value-call-pays-its-surcharge", f"{held} {fmt(spendable)}: its static "
                     f"cost and its value transfer use up the spendable part, the whole regular gas loads the target and "
                     "passes the delegation guard, and at the refusal the restoration gives the value transfer back, so "
                     f"the spendable part pays the target's cold surcharge: the frame reverts with {refusal}, handing back "
                     f"{fmt(whole - cold)}, the value transfer not among what stays spent (SATIN-MAC-004, SATIN-MAC-005, "
                     "SATIN-OUT-008)",
                     boundary=f"the spendable part at the static cost and the value transfer, {fmt(warm + value_cost)}")
    spendable = warm + value_cost - 1
    detained_refusal(valued, whole, spendable, "value-transfer-crossing", f"{held} {fmt(spendable)}: its value "
                     f"transfer, after the static cost, is gas detention's crossing, so the frame is stopped with {stop} "
                     f"before its target's load, handing back {fmt(whole - warm)}, and the delegator is not in the reads "
                     "(SATIN-MAC-007, SATIN-WIT-004, SATIN-WIT-012)", boundary="the spendable part one below the static "
                     f"cost and the value transfer, {fmt(warm + value_cost)}")
    # A memory expansion past the allowance and within the whole gas, under the protocol's cap.
    forward, size = 40_000_000, 0x32_0000
    add(Case("satin/detention/delegate-refusal/memory-crossing-reads-nothing", f"after TIMESTAMP, the transaction's own "
             f"frame switches its access off and calls REFUSING forwarding {fmt(forward)}; REFUSING does a STATICCALL with "
             f"{fmt(size)} bytes of input, whose memory costs {fmt(model.memory_cost(size // 32))}, past what the limit "
             "leaves it and within its whole regular gas, of an account holding an EIP-7702 delegation to the block "
             f"beneficiary: the memory expansion is gas detention's crossing, so the frame is stopped with {stop} before "
             "its target's load, handing back its gas at the opcode less the static cost, and the delegator is not in the "
             "reads (SATIN-MAC-007, SATIN-WIT-004, SATIN-WIT-012)", detention=True, reads=True, gas=50_000_000,
             accounts={**delegator, REFUSING: model.Account(nonce=1, code=call_op(0xFA, BENEFICIARY_DELEGATOR,
                                                                                  inp=(0, size)) + STOP)},
             code=b"\x42\x50" + disable + call(forward, REFUSING, 0, 0) + RETURN_RETURNDATA, **page))

    # SATIN-PCMP-008: a precompile's address delegating to the beneficiary ends at or before the delegate's load, at the
    # edge of the delegation guard, and never reaches dispatch.
    for refused, left in ((False, 2 * warm - 1), (True, 2 * warm)):
        add(Case(f"satin/precompiles/delegated-address/beneficiary-delegate-{'at' if refused else 'one-short-of'}-the-guard",
                 f"the identity precompile's address holds an EIP-7702 delegation to the block beneficiary; with access "
                 f"off, REFUSING holds {fmt(left)} of regular gas at a STATICCALL of the address, warm from the "
                 "transaction's start: " + (f"the delegation guard, {warm} for the delegate's access, holds, and the "
                                            f"delegate's load is refused, the call paying its static cost {warm} alone, so "
                                            f"it never reaches dispatch and the frame reverts with {refusal}" if refused
                                            else f"the delegation guard, {warm} for the delegate's access, is one above the "
                                            f"{fmt(left - warm)} the static cost leaves, so the call halts before its "
                                            "delegate's load and never reaches dispatch"),
                 boundary=f"the regular gas at the call {'at' if refused else 'one below'} the static cost and the guard, "
                 f"{fmt(2 * warm)}", precompile_page=True,
                 accounts={model.IDENTITY: model.Account(code=model.DELEGATION_PREFIX + COINBASE),
                           REFUSING: model.Account(nonce=1, code=call_op(0xFA, model.IDENTITY) + STOP)},
                 make=lambda gas: disable + call(gas, REFUSING, 0, 0) + RETURN_RETURNDATA, params={"gas": left + 1_000},
                 retune=[("refusal-call", left, "gas", 1)], **page))

    # The edges an independent review found unpinned (D-117), in its order.
    huge = 2**20
    # 1. A value CALL in a frame a STATICCALL started: the static-context check, after the static cost and before the
    # memory, the value transfer and the target's load; a call of the beneficiary itself is refused before it.
    refusing(call_op(0xF1, BENEFICIARY_DELEGATOR, value=1, inp=(0, huge)), warm, "static-frame-value-call-halts",
             f"the transaction's own frame switches its access off and STATICCALLs REFUSING, which holds {warm} of regular "
             f"gas at a CALL with value 1 and {fmt(huge)} bytes of input of an account that is not warm and holds an "
             "EIP-7702 delegation to the block beneficiary: the static cost paid, the static-context check halts the "
             "frame before the memory, the value transfer and the target's load, so the delegator is not in the reads "
             "(SATIN-MAC-007, SATIN-WIT-004, SATIN-WIT-012)", boundary=f"the regular gas at the call at the static cost "
             f"{warm}", via=0xFA, reads=True)
    left = warm // 2
    refusing(call_op(0xF1, COINBASE, value=1, inp=(0, huge)), left, "static-frame-direct-value-call-refused",
             f"the transaction's own frame switches its access off and STATICCALLs REFUSING, which holds {fmt(left)} of "
             f"regular gas at a CALL with value 1 and {fmt(huge)} bytes of input of the block beneficiary itself: the "
             f"call is refused before its static cost and before the static-context check, and the frame reverts with "
             f"{refusal} (SATIN-MAC-003, SATIN-MAC-004)", probe="refused", via=0xFA)
    # 6. Zero-length ranges at the largest offset grow nothing; an unaligned range rounds up to whole words.
    top = 2**256 - 1
    left = 2 * warm
    refusing(call_op(0xFA, BENEFICIARY_DELEGATOR, inp=(top, 0), out=(top, 0)), left, "zero-length-ranges-at-the-top",
             f"REFUSING holds {fmt(left)} of regular gas at a STATICCALL with empty input and output ranges at the offset "
             "2^256 - 1, of an account the access list warms, which holds an EIP-7702 delegation to the block "
             f"beneficiary: empty ranges grow no memory and the offset is never checked, so the call is refused at the "
             f"delegate's load, paying its static cost {warm} alone", **listed)
    odd = (31, 2)
    odd_words = (odd[0] + odd[1] + 31) // 32
    odd_cost = model.memory_cost(odd_words)
    for refused, left in ((False, 2 * warm + odd_cost - 1), (True, 2 * warm + odd_cost)):
        refusing(call_op(0xFA, BENEFICIARY_DELEGATOR, out=odd), left,
                 f"unaligned-output-{'at' if refused else 'one-short-of'}-the-guard", f"REFUSING holds {fmt(left)} of "
                 f"regular gas at a STATICCALL with an output range of {odd[1]} bytes at offset {odd[0]}, ending in its "
                 f"{odd_words}nd word, whose memory costs {odd_cost}, of an account the access list warms, which holds an "
                 "EIP-7702 delegation to the block beneficiary: " +
                 (f"the guard holds and the call is refused, paying its static cost and the memory, {warm + odd_cost}"
                  if refused else f"the static cost and the memory leave {fmt(left - warm - odd_cost)}, one below the "
                  f"delegation guard's {warm}, so the call halts before its delegate's load"),
                 boundary=f"the regular gas at the call {'at' if refused else 'one below'} the static cost, the memory "
                 f"and the guard, {2 * warm + odd_cost}", **listed)
    # 7. The forward the call asks for has no part in the refusal.
    for name, code, left, observe_reads, kw in (
            ("max-forward-cold-target-refused", call_op(0xFA, BENEFICIARY_DELEGATOR, gas=top), cold + warm, True, {}),
            ("max-forward-warm-target-refused", call_op(0xFA, BENEFICIARY_DELEGATOR, gas=top), 2 * warm, True, listed),
            ("max-forward-value-call-at-the-guard", call_op(0xF1, BENEFICIARY_DELEGATOR, value=1, gas=top),
             warm + value_cost + cold, False, {})):
        read_note = (". The target's completed read stays in the witness (SATIN-WIT-002, SATIN-WIT-012), with no later "
                     "access to the target" if observe_reads else "")
        refusing(code, left, name, f"REFUSING holds {fmt(left)} of regular gas at a call asking to forward 2^256 - 1, "
                 "the most a gas operand holds, of an account holding an EIP-7702 delegation to the block beneficiary: "
                 "the refusal at the delegate's load comes before any forward is computed, so the call is settled as "
                 "the same call asking for nothing, handing back "
                 f"{fmt(left - (warm if kw else cold))}" + read_note, reads=observe_reads, **kw)
    # 4. Warmth an EIP-7702 authorization's application gives the target (SATIN-AUTH-014).
    to_authority = call_op(0xFA, AUTHORITY)
    left = 2 * warm
    refusing(to_authority, left, "authority-warm-from-application", "the transaction's EIP-7702 list makes an authority "
             "delegate to the block beneficiary, and the application warms it; REFUSING holds "
             f"{fmt(left)} of regular gas at a STATICCALL of the authority: the call finds its target warm, and is "
             f"refused at the delegate's load paying its static cost {warm} alone (SATIN-AUTH-014)", ty=4,
             authorizations=[(AUTH_KEY, CHAIN_ID, COINBASE, 0)], lists=True)
    refusing(to_authority, left, "authority-warmed-by-a-skipped-entry", "an authority whose code already delegates to "
             "the block beneficiary is named by an EIP-7702 entry whose nonce does not match: the application loads it "
             f"and warms it though it skips the entry; REFUSING holds {fmt(left)} of regular gas at a STATICCALL of the "
             f"authority, which it finds warm, and is refused paying its static cost {warm} alone (SATIN-AUTH-014)",
             ty=4, authorizations=[(AUTH_KEY, CHAIN_ID, COINBASE, 0)], lists=True, data=b"\x01",
             accounts={AUTHORITY: model.Account(nonce=1, code=AUTHORITY_TARGET)})
    refusing(to_authority, left, "authority-gated-entry-leaves-it-cold", "an authority whose code already delegates to "
             "the block beneficiary is named by an EIP-7702 entry for another chain, which its gate skips before "
             f"anything reads or warms the authority; REFUSING holds {fmt(left)} of regular gas at a STATICCALL of it: "
             f"the target is not warm and the {fmt(left - warm)} the static cost leaves is below its cold surcharge, so "
             "the call halts without loading it, and the authority is not in the reads (SATIN-AUTH-014, SATIN-WIT-004, "
             "SATIN-WIT-012)", ty=4, authorizations=[(AUTH_KEY, 2, COINBASE, 0)], reads=True,
             accounts={AUTHORITY: model.Account(code=AUTHORITY_TARGET)})
    # 9. The one hop: a delegator of an ordinary account is no refusal, also when that account's code is an indicator.
    one_hop = {ONE_HOP: model.Account(nonce=1, code=model.DELEGATION_PREFIX + ONE_HOP_DELEGATE)}
    flag = call_op(0xF1, ONE_HOP) + push(0) + b"\x52" + ret(0, 32)  # the call's success flag, returned
    left = 10_000
    for name, delegate_code, switch, what in (
            ("one-hop-delegate-runs", STOP, True, "its delegate's code, STOP, runs, and the call succeeds"),
            ("one-hop-delegate-runs-access-on", STOP, False, "with access on, the same call pays the same, the two "
             "accounts' access at the schedule's prices (SATIN-SCHED-003), and succeeds"),
            ("one-hop-delegate-holds-an-indicator", model.DELEGATION_PREFIX + COINBASE, True, "the delegate's own code is "
             "an EIP-7702 indicator naming the block beneficiary, which the call does not follow: that code runs as it "
             "is, its first byte 0xEF undefined, so the call's frame halts and the call fails")):
        refusing(flag, left, name, f"REFUSING holds {fmt(left)} of regular gas at a CALL of an account that is not warm "
                 "and delegates to another account that is not warm and is not the block beneficiary: the call is not "
                 "refused and pays the target's access and its delegate's, "
                 f"{fmt(2 * cold)}, resolving the one hop alone; " + what + ", and REFUSING returns the call's success "
                 "flag (SATIN-MAC-003, SATIN-MAC-007)", probe="call-opcode:" + ONE_HOP.hex(), switch=switch,
                 accounts={**one_hop, ONE_HOP_DELEGATE: model.Account(nonce=1, code=delegate_code)})
    # The caller's BALANCE after a call that halted: the frame's end rolls back the warming its load took.
    for name, left in (("cold-target-load-skipped-caller-probe", cold - 1),
                       ("cold-target-loaded-at-the-load-caller-probe", cold)):
        refusing(static, left, name, f"REFUSING holds {fmt(left)} of regular gas at a STATICCALL of an account that is "
                 "not warm and holds an EIP-7702 delegation to the block beneficiary, and halts " +
                 ("before the target's load" if left < cold else "at the delegation guard after it") + ": the caller's "
                 "BALANCE of the delegator then pays the cold access, the halted frame having left it cold", after=balance)
    # 3. Above the execution cap, where the frame holds a reservoir share: the settlement leaves the reservoir.
    above = model.EXECUTION_CAP + 10_000_000
    left = cold + warm
    refusing(sstore(1, 1) + sstore(1, 0) + static, left, "refusal-after-a-give-back-above-the-cap", "a transaction "
             f"whose gas limit is {fmt(above - model.EXECUTION_CAP)} above the execution cap calls REFUSING with a share "
             "of its reservoir; REFUSING writes a fresh slot, whose state gas the reservoir pays past its legacy share, "
             f"and writes it back, then holds {fmt(left)} of regular gas at a STATICCALL of an account that is not warm "
             "and holds an EIP-7702 delegation to the block beneficiary: the refusal restores its regular gas alone and "
             f"charges {fmt(cold)}, leaving the reservoir as the opcode found it, and the frame's revert rolls back its "
             "own state and history charges (SATIN-MAC-004, SATIN-POOL-014)", spare=200_000, gas=above, pools=True,
             pricing=True)

    # 2. The whole regular gas at the load and the guard, under gas detention: the spendable part held at the static
    # cost, the whole at the edges of the load and of the guard.
    spendable = warm
    for name, whole_at, what in (
            ("whole-gas-load-one-short", cold - 1, f"the static cost leaves {fmt(cold - 1 - warm)} in all, below the "
             f"target's cold surcharge, so the call halts without loading the target (SATIN-WIT-004, SATIN-WIT-012)"),
            ("whole-gas-at-the-load", cold, f"the static cost leaves {fmt(surcharge)} in all, which covers the cold "
             "surcharge though the spendable part cannot: the target is loaded, and the delegation guard halts the call "
             "(SATIN-WIT-002)"),
            ("whole-gas-one-short-of-the-guard", cold + warm - 1, "the target is loaded and the delegation guard, "
             f"{fmt(cold)}, halts the call (SATIN-WIT-002)"),
            ("whole-gas-at-the-guard", cold + warm, "the guard holds on the whole regular gas; refused, the call's gas is "
             f"restored and its static cost charged again, and its target's cold surcharge is the crossing: the frame is "
             f"stopped with {stop}, handing back {fmt(cold)}, the delegator read (SATIN-MAC-004, SATIN-OUT-008, "
             "SATIN-STOP-020, SATIN-WIT-002, SATIN-WIT-012)")):
        detained_refusal(static, whole_at, spendable, name, f"after TIMESTAMP, REFUSING holds {fmt(whole_at)} of regular "
                         "gas at a STATICCALL of an account that is not warm and holds an EIP-7702 delegation to the block "
                         f"beneficiary, of which it may spend {spendable}, its static cost: " + what + "; the caller, left "
                         "no allowance, returns REFUSING's return data at no cost (SATIN-MAC-007)",
                         boundary=f"the whole regular gas {'at' if whole_at in (cold, cold + warm) else 'one below'} "
                         + ("the static cost and the cold surcharge" if whole_at in (cold - 1, cold) else
                            "the static cost and the guard") + f", {fmt(cold if whole_at < cold + warm - 1 else cold + warm)}",
                         tail=None)
    for refused, whole_at in ((False, 2 * warm - 1), (True, 2 * warm)):
        detained_refusal(static, whole_at, spendable, f"warm-whole-gas-{'at' if refused else 'one-short-of'}-the-guard",
                         f"after TIMESTAMP, REFUSING holds {fmt(whole_at)} of regular gas at a STATICCALL of an account the "
                         "access list warms, which holds an EIP-7702 delegation to the block beneficiary, of which it may "
                         f"spend {spendable}, its static cost: " +
                         (f"the guard, {warm}, holds on the whole regular gas, and the call is refused paying its static "
                          f"cost alone, the frame reverting with {refusal} (SATIN-MAC-005, SATIN-OUT-008)" if refused else
                          f"the {fmt(whole_at - warm)} left in all is one below the delegation guard's {warm}, so the call "
                          "halts before its delegate's load") + "; the caller returns REFUSING's return data at no cost "
                         "(SATIN-MAC-007)", boundary=f"the whole regular gas {'at' if refused else 'one below'} the static "
                         f"cost and the guard, {2 * warm}", tail=None, **listed)
    # 3, detained: a stop at the cold surcharge above the execution cap returns the frame's reservoir share untouched.
    whole = 5_200
    detained_refusal(static, whole, 2 * warm, "surcharge-crossing-above-the-cap", "after TIMESTAMP, in a transaction "
                     f"whose gas limit is {fmt(above - model.EXECUTION_CAP)} above the execution cap, REFUSING holds "
                     f"{fmt(whole)} of regular gas and a share of the reservoir at a STATICCALL of an account that is not "
                     f"warm and holds an EIP-7702 delegation to the block beneficiary, of which it may spend {2 * warm}: "
                     f"its target's cold surcharge is the crossing, the frame is stopped with {stop}, handing back "
                     f"{fmt(whole - warm)} of regular gas, and its reservoir share returns untouched (SATIN-MAC-004, "
                     "SATIN-MAC-007, SATIN-OUT-008, SATIN-STOP-020)", gas=above, pools=True, pricing=True)
    # 5. The inherited path's cold load (D-117): an account loaded once the whole regular gas covers its cold surcharge,
    # and kept loaded when that charge is gas detention's crossing.
    probe_balance = push(int.from_bytes(UNTOUCHED, "big")) + b"\x31\x50" + STOP
    for name, whole_at, what in (
            ("balance-crossing-keeps-the-load", 5_000, "the whole regular gas covers the account's cold surcharge, so the "
             "account is loaded, and the surcharge is then gas detention's crossing: the frame is stopped with the "
             "account in the reads (SATIN-WIT-002, SATIN-WIT-012)"),
            ("balance-load-skipped", cold - 1, f"the {fmt(cold - 1 - warm)} left in all is below the cold surcharge, so the "
             "load is skipped and the frame runs out of gas, the account not in the reads (SATIN-WIT-012)"),
            ("balance-loaded-at-the-load", cold, f"the {fmt(surcharge)} left in all covers the cold surcharge, so the "
             "account is loaded, and the surcharge is the crossing (SATIN-WIT-002, SATIN-WIT-012)")):
        add(Case(f"satin/detention/cold-load-crossing/{name}", f"a detained frame holds {fmt(whole_at)} of regular gas "
                 f"at a BALANCE of an account that is not warm, of which it may spend {warm}, its static cost: " + what +
                 "; the caller, left no allowance, returns the frame's return data at no cost (SATIN-DET-018)",
                 boundary=("" if whole_at == 5_000 else f"the whole regular gas {'one below' if whole_at < cold else 'at'} "
                           f"the static cost and the cold surcharge, {fmt(cold)}"),
                 detention=True, reads=True, gas=21_000_000, accounts={REFUSING: model.Account(nonce=1, code=probe_balance)},
                 make=lambda words, pad, gas: detained(words, pad) + buffered(gas), params={**start, "gas": 6_000},
                 retune=[("balance", whole_at, "gas", 1), ("balance-room", warm, "pad", -1)], **page))
    detained_refusal(call_op(0xF1, PLAIN), whole, 2 * warm, "call-crossing-keeps-the-load", "after TIMESTAMP, with "
                     f"access off, REFUSING holds {fmt(whole)} of regular gas at a CALL of an account that is not warm and "
                     f"holds no delegation, of which it may spend {2 * warm}: as with access on, the whole regular gas "
                     "loads the target, and its cold surcharge is then gas detention's crossing, the frame stopped with "
                     f"{stop} and the target in the reads (SATIN-MAC-007, SATIN-WIT-002, SATIN-WIT-012)",
                     area="cold-load-crossing", probe="call-opcode:" + PLAIN.hex(),
                     accounts={PLAIN: model.Account(nonce=1, code=STOP)})

    # 8 and 7: a precompile's address delegating to the beneficiary, with memory and with the largest forward.
    words4 = model.memory_cost(4)
    for name, code, left, refused in (
            ("beneficiary-delegate-memory-one-short-of-the-guard", call_op(0xFA, model.IDENTITY, inp=(0, 64),
                                                                           out=(64, 64)), 2 * warm + words4 - 1, False),
            ("beneficiary-delegate-memory-at-the-guard", call_op(0xFA, model.IDENTITY, inp=(0, 64), out=(64, 64)),
             2 * warm + words4, True),
            ("beneficiary-delegate-max-forward-at-the-guard", call_op(0xFA, model.IDENTITY, gas=top), 2 * warm, True)):
        add(Case(f"satin/precompiles/delegated-address/{name}", "the identity precompile's address holds an EIP-7702 "
                 f"delegation to the block beneficiary; with access off, REFUSING holds {fmt(left)} of regular gas at a "
                 "STATICCALL of the address" + (" with 64 bytes of input and an output range after them, whose memory, "
                                                f"4 words, costs {words4}" if "memory" in name else
                                                ", asking to forward 2^256 - 1") + ": " +
                 (f"the guard holds and the call is refused paying {fmt(left - warm)}, its static cost" +
                  (" and its memory" if "memory" in name else "") + ", never reaching dispatch" if refused else
                  f"the static cost and the memory leave {fmt(left - warm - words4)}, one below the delegation guard's "
                  f"{warm}, so the call halts after its target's load and never reaches dispatch"),
                 boundary="" if "max-forward" in name else f"the regular gas at the call {'at' if refused else 'one below'} "
                 f"the static cost, the memory and the guard, {2 * warm + words4}", precompile_page=True,
                 accounts={model.IDENTITY: model.Account(code=model.DELEGATION_PREFIX + COINBASE),
                           REFUSING: model.Account(nonce=1, code=code + STOP)},
                 make=lambda gas: disable + call(gas, REFUSING, 0, 0) + RETURN_RETURNDATA, params={"gas": left + 1_000},
                 retune=[("refusal-call", left, "gas", 1)], **page))
    return out


def account(nonce=0, balance=0, code=b"", storage=None) -> dict:
    return {"nonce": q(nonce), "balance": q(balance), "code": h(code),
            "storage": {"0x" + k.to_bytes(32, "big").hex(): q(v) for k, v in sorted((storage or {}).items())}}


def salt_bucket(address: bytes, slot):
    return salt_mapping.slot_bucket(h(address), slot) if slot is not None else salt_mapping.account_bucket(h(address))


def synthetic_message(c: Case, sender: bytes) -> dict:
    """A synthetic execution message (docs/format.md, "Transactions"): the transaction's fields with its sender given."""
    legacy_fee = c.ty in (0, 1)
    return {"kind": "synthetic", "type": q(c.ty), "chainId": None if c.chain_id is None else q(c.chain_id),
            "nonce": q(c.nonce), "sender": h(sender), "to": h(c.to) if c.to else None, "value": q(c.value),
            "data": h(c.data), "gasLimit": q(c.gas), "gasPrice": q(c.gas_price) if legacy_fee else None,
            "maxFeePerGas": None if legacy_fee else q(c.max_fee),
            "maxPriorityFeePerGas": None if legacy_fee else q(c.max_priority),
            "accessList": [{"address": h(a), "storageKeys": ["0x" + k.to_bytes(32, "big").hex() for k in keys]}
                           for a, keys in c.access_list],
            "authorizationList": [{"chainId": q(e[1]), "address": h(e[2]), "nonce": q(e[3]),
                                   "authority": h(authority_of(e)) if authority_of(e) else None}
                                  for e in c.authorizations]}


def build(c: Case):
    sender = c.sender if c.sender else OTHER if c.deposit and c.absent_sender else SENDER
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
    env = model.Env(c.chain, c.coinbase, c.base_fee, BLOCK_GAS_LIMIT, buckets, timestamp=BLOCK_TIMESTAMP,
                    number=c.block_number, block_hashes=dict(c.block_hashes))

    if c.deposit:
        mint, gas = c.deposit
        to = c.to if c.to is not None else b""  # a creating deposit's recipient field is empty
        raw = (ex.deposit(c.source_hash, sender, to, mint, c.value, gas, c.data) if not c.system_flag else
               b"\x7e" + ex.rlp([c.source_hash, sender, to, mint, c.value, gas, 1, c.data]))
        tx = model.Tx("deposit", 0x7E, sender, c.to, 0, gas, c.value, c.data, None, mint=mint, system_flag=c.system_flag,
                      source_hash=c.source_hash)
        source = {"kind": "deposit", "raw": h(raw)}
    elif c.synthetic:
        tx = model.Tx("synthetic", c.ty, sender, c.to, c.nonce, c.gas, c.value, c.data, c.chain_id, gas_price=c.gas_price,
                      max_fee=c.max_fee, max_priority=c.max_priority, access_list=c.access_list,
                      authorizations=[(e[1], e[2], e[3], authority_of(e)) for e in c.authorizations])
        source = synthetic_message(c, sender)
    else:
        if c.ty == 0:
            raw = legacy(c.nonce, c.gas_price, c.gas, c.to, c.value, c.data, chain_id=c.chain_id)
        elif c.ty == 1:
            raw = eip2930(c.nonce, c.gas_price, c.gas, c.to, c.value, c.data, c.access_list, chain_id=c.chain_id)
        elif c.ty == 4:
            auths = [list(authorization(*e)) for e in c.authorizations]
            raw = eip7702(c.nonce, c.max_priority, c.max_fee, c.gas, c.to, c.value, c.data, auths, chain_id=c.chain_id)
        else:
            raw = eip1559(c.nonce, c.max_priority, c.max_fee, c.gas, c.to, c.value, c.data, chain_id=c.chain_id)
        tx = model.Tx("signed", c.ty, sender, c.to, c.nonce, c.gas, c.value, c.data, c.chain_id, gas_price=c.gas_price,
                      max_fee=c.max_fee, max_priority=c.max_priority, access_list=c.access_list,
                      authorizations=[(e[1], e[2], e[3], authority_of(e)) for e in c.authorizations])
        source = {"kind": "signed", "raw": h(raw)}
    run = model.Run(env, pre, tx, salt_bucket, principles=c.spec in PRINCIPLES_SPECS, reads=c.reads, pools=c.pools,
                    destruction=c.destruction, detention=c.detention, stops=c.stops, lists=c.lists,
                    outcomes=c.outcomes, system_tx=c.system_tx, current=c.spec in CURRENT_SPECS,
                    system_pages=c.system_pages, precompile_page=c.precompile_page, size_page=c.size_page,
                    pricing=c.pricing)
    result = run.run()
    result.probe = run.probe

    inp = {
        "chain": {"chainId": q(c.chain)},
        "block": {
            "number": q(c.block_number), "timestamp": q(BLOCK_TIMESTAMP), "coinbase": h(c.coinbase), "gasLimit": q(BLOCK_GAS_LIMIT),
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
        decoded["sourceHash"] = h(c.source_hash)
    if c.authorizations:
        decoded["authorizationList"] = [{"chainId": q(e[1]), "address": h(e[2]), "nonce": q(e[3]),
                                         "authority": h(authority_of(e)) if authority_of(e) else None}
                                        for e in c.authorizations]
    return inp, result, decoded


# Disagreements resolved by the specification's verdict: the expectation is the rule's, and the
# implementation that differs fails the case. Such a case stays out of the gating slice until the
# implementation is fixed; tools/run-slice.sh checks that it still fails exactly as recorded and
# that the other implementation passes it. A record names the case's adapter, its first differing
# path with both values, and a verdict that cites the rule and the revision it was recorded at.
#
# None is held: at the revm-based pin, 1a981f4b, every case passes on both implementations, among them
# the seventy-one held at the previous pin, 7110d87b (D-94).
QUARANTINE: dict[str, dict] = {}


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
    "gas-forwarding": ("SATIN-FWD", "SATIN-POOL-011"),
    "system-tx": ("SATIN-MST", "SATIN-VAL-005", "SATIN-REG-002"),
    "system-contracts": ("SATIN-MLC", "SATIN-HPTS", "SATIN-SYSC"),
    "history": ("SATIN-HIST",),
    "accounting": ("SATIN-ACCT",),
    "precompiles": ("SATIN-PCMP",),
    "contract-limits": ("SATIN-SIZE",),
    "state-gas": ("SATIN-STATE",),
    "schedule": ("SATIN-SCHED",),
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


def fixture(c: Case, descriptor_digest: str, rule_texts: dict, retired: set, spec_commit: str) -> tuple[dict, dict]:
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
    if c.gas_used_check is not None and result.probe.get("keyless-gas-used") != c.gas_used_check:
        raise SystemExit(f"{c.case_id}: the derivation gives gasUsed {result.probe.get('keyless-gas-used')}, the worked "
                         f"example {c.gas_used_check}")
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
    gone = [r for r in applied if r in retired]
    if gone:
        raise SystemExit(f"{c.case_id}: applies rules its snapshot {c.spec} retires: {gone}")
    requires = ["group:gas-ledgers", "group:limit", "group:outcome", "group:receipts", "group:resources", "group:state",
                "feature:salt"] + (["feature:deposit"] if c.deposit else []) + (["group:reads"] if c.reads else []) \
        + (["group:limit-stop"] if result.observations["limit"] else []) + (["group:gas-pools"] if c.pools else []) \
        + (["feature:synthetic-transaction"] if c.synthetic else [])
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


def spec_of(name: str) -> tuple[str, dict, set]:
    """A snapshot's descriptor digest, each rule's text digest, and the ids it retires."""
    d = os.path.join(ROOT, "specs", name)
    with open(os.path.join(d, "descriptor.json"), encoding="utf-8") as f:
        digest = "sha256:" + hashlib.sha256(canonical(json.load(f))).hexdigest()
    with open(os.path.join(d, "rules.json"), encoding="utf-8") as f:
        rules = json.load(f)["rules"]
    return digest, {k: v["textDigest"] for k, v in rules.items()}, {k for k, v in rules.items() if v["status"] != "active"}


def outputs(explained: dict | None = None) -> dict[str, str]:
    """Every file of slice/, by its path there. `explained`, when given, receives each case's explanation."""
    specs = {name: spec_of(name) for name in SPEC_COMMITS}
    descriptor_digest = specs[DEFAULT_SPEC][0]
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
