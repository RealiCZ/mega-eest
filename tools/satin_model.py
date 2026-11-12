#!/usr/bin/env python3
"""A small executable model of Satin's transaction rules, for deriving expected values.

This is the independent evidence behind the vertical slice's expectations: it restates, from the
specification at `d34e626` (`specs/satin-d34e626`), for calls, interception and EIP-7702 at
`d334ef8` (`specs/satin-d334ef8`), and for the charge-order principles at `5fb2688`
(`specs/satin-5fb2688`), the arithmetic a `state-transition` case's observations follow, for the
narrow class of transactions the slice uses:

- the transaction's own frame: the opcodes `STOP`, `ADD`, `POP`, `PUSH0`..`PUSH32`, `CALLER`,
  `CALLVALUE`, `GAS`, `TIMESTAMP`, `BALANCE`, `MSTORE`, `SLOAD`, `SSTORE`, `LOG0`..`LOG4`, `RETURN`,
  `REVERT` and `INVALID`, and the stack, arithmetic, calldata, jump, return-data and `KECCAK256`
  opcodes a system contract's dispatcher and decoder use; no creation opcode or self-destruct, and
  of the volatile reads only those below;
- a `CALL` from that frame to a system contract, decided in the order of `SATIN-ICPT-007`: an
  interceptor's `NonZeroTransfer()`, the `sendHint` admission and its data-size stop, the frame
  start that refuses a value the caller cannot fund, and a child frame that reverts or halts; the
  opcode charges the history of the records its start would make, as the state stands, before all
  of these, and a caller that cannot pay it halts in the opcode; a value `CALL` its caller cannot
  fund to any other account, a contract or one empty under EIP-161, refused at its frame start;
- a transaction's own `keylessDeploy` call, recognized or not (`SATIN-ICPT-006`), as far as the
  refusals of steps 2 and 3 or a halt at step 1;
- one-entry EIP-7702 lists whose entry is accepted, the authority present or absent, and a
  transaction to an account holding a delegation, its sender's own among them, which pays its
  delegate's access before the first frame;
- a transaction that runs out of gas before its first frame with nothing applied but validation's
  changes to its sender, an authorization list's first write among the charges it cannot pay;
- for the cases that ask, the `reads` group: what the transaction loads, as the stateless witness
  needs it;
- a stop of the transaction's own frame, its result: gas detention's crossing, and an `SSTORE`'s
  record or a log's bytes held to the frame's budget and the transaction's limit;
- gas detention: `TIMESTAMP`, a deposit's `SLOAD` in the Oracle's frame and `BALANCE` as reads, the
  limit they set, every frame's spendable and withheld parts, each part an opcode deducts as one
  charge, the crossing that stops a child frame and the out-of-gas beyond its whole gas; and
  `disableVolatileDataAccess()` with the refusal of a volatile read in a frame whose access is off;
- calls, value transfers, creation transactions and deposits, with or without a reservoir;
- the refusals of transaction validation.

Every charge is a step of a derivation that names the rule it applies, so a reviewer can check
each number against the pinned rule text, and the case's assertions cite exactly the rules its
steps applied. The model shares no code with either implementation or adapter. It is not an
implementation of Satin: anything outside the class above raises `Unmodelled`.

Standard library only.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_examples as ex  # noqa: E402  (Keccak-256, RLP)

# --- Constants, with the rules that state them -------------------------------------------------

EXECUTION_CAP = 200_000_000  # SATIN-POOL-005
TX_BASE_COST = 12_000  # SATIN-SCHED-006
COLD_ACCOUNT_ACCESS = 3_000  # SATIN-SCHED-006
TX_VALUE_COST = 6_000  # SATIN-SCHED-006
CREATE_ACCESS = 12_000  # SATIN-SCHED-006
INITCODE_WORD_COST = 2  # EIP-3860, kept by SATIN-SCHED-001
CALLDATA_ZERO = 4  # inherited calldata cost, kept by SATIN-SCHED-001
CALLDATA_NONZERO = 16
ACCESS_LIST_ADDRESS = 4_180  # SATIN-SCHED-003
ACCESS_LIST_KEY = 4_048  # SATIN-SCHED-003
FLOOR_PER_BYTE = 16 * 4  # SATIN-SCHED-005: TOTAL_COST_FLOOR_PER_TOKEN x FLOOR_TOKENS_PER_BYTE
WARM_READ = 100  # SATIN-SCHED-003
COLD_SLOAD = 2_100  # SATIN-SCHED-003 (2,000 additional) and SATIN-SCHED-004
COLD_SSTORE_ACCESS = 2_100  # SATIN-SCHED-004
SSTORE_SET = 10_000  # SATIN-SCHED-003, fresh slot before the load cost
SSTORE_RESET = 10_000  # SATIN-SCHED-003, reset before the cold load
REFUND_RESTORED_FRESH = 10_000  # SATIN-SCHED-003
REFUND_RESTORED_RESET = 10_000  # SATIN-SCHED-003
REFUND_CLEARED = 11_616  # SATIN-SCHED-003
CALL_STIPEND = 2_300  # inherited EIP-2200 sentry
KECCAK_WORD = 6  # SATIN-SCHED-011
COST_PER_STATE_BYTE = 1_530  # SATIN-STATE-003
SLOT_STATE_BYTES = 64  # SATIN-STATE-003: the EIP-8037 byte count of a storage slot
ACCOUNT_STATE_BYTES = 120  # SATIN-STATE-003: the EIP-8037 byte count of an account leaf
SLOT_STATE = SLOT_STATE_BYTES * COST_PER_STATE_BYTE  # SATIN-STATE-003
ACCOUNT_STATE = ACCOUNT_STATE_BYTES * COST_PER_STATE_BYTE  # SATIN-STATE-003
CODE_STATE_PER_BYTE = COST_PER_STATE_BYTE  # SATIN-STATE-003: deployed code, per byte
PRE_FORK_SSTORE_SET_COST = 20_000  # SATIN-STATE-012
LEGACY_SSTORE_SHARE = PRE_FORK_SSTORE_SET_COST - SSTORE_SET  # SATIN-STATE-012: PRE_FORK_SSTORE_SET_COST - SSTORE_WRITE_COST
COST_PER_HISTORY_BYTE = 88  # SATIN-HIST-001
TX_BODY_SIZE = 310  # SATIN-HIST-003
WRITE_RECORD_SIZE = 40  # SATIN-HIST-002
ACCESS_LIST_ADDRESS_SIZE = 20
ACCESS_LIST_SLOT_SIZE = 32
LOG_BASE_SIZE = 32
LOG_TOPIC_SIZE = 32
TRANSFER_LOG_SIZE = 160  # SATIN-ACCT-001, SATIN-LOG-006
LOG_COST = 375  # inherited
LOG_TOPIC_COST = 375
LOG_DATA_COST = 8
MEMORY_WORD = 3
# The inherited static gas tiers of the opcodes the model runs (Osaka's, kept by SATIN-SCHED-002).
G_ZERO, G_JUMPDEST, G_BASE, G_VERYLOW, G_LOW, G_MID, G_HIGH = 0, 1, 2, 3, 5, 8, 10
REFUND_QUOTIENT = 5  # EIP-3529, kept by SATIN-POOL-018
MIN_BUCKET_SIZE = 256  # SATIN-STATE-002
TX_DATA_LIMIT = 13_107_200  # SATIN-LIM-001
TX_KV_UPDATE_LIMIT = 500_000
TX_STATE_GROWTH_LIMIT = 1_000

TRANSFER_LOG_ADDRESS = bytes.fromhex("ff" * 19 + "fe")  # SATIN-LOG-001
TRANSFER_TOPIC = bytes.fromhex("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

BASE_FEE_VAULT = bytes.fromhex("4200000000000000000000000000000000000019")
# The reads of a transaction (the stateless witness, at `5fb2688`): the fee recipients besides the
# beneficiary, and the L1 block contract's slots every non-deposit transaction reads (SATIN-WIT-011).
L1_FEE_VAULT = bytes.fromhex("420000000000000000000000000000000000001a")
OPERATOR_FEE_VAULT = bytes.fromhex("420000000000000000000000000000000000001b")
L1_BLOCK_ADDRESS = bytes.fromhex("4200000000000000000000000000000000000015")
L1_BASE_FEE_SLOT, L1_ECOTONE_SCALARS_SLOT, L1_FEE_OVERHEAD_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_OPERATOR_SCALARS_SLOT = 1, 3, 5, 7, 8
KECCAK_EMPTY = ex.keccak256(b"")

# Calls, interception and EIP-7702 (the specification at `d334ef8`).
COLD_ACCOUNT_SURCHARGE = 2_900  # SATIN-SCHED-003: cold account access, additional to the warm read
CALL_VALUE_COST = 11_300  # SATIN-SCHED-003: value transfer of a call, with its 2,300 stipend
GAS_RETAINED_NUMERATOR, GAS_RETAINED_DENOMINATOR = 2, 100  # SATIN-FWD-001
KECCAK_BASE = 30  # inherited KECCAK256 static gas, kept by SATIN-SCHED-002
COPY_WORD = 3  # inherited per-word copy cost (RETURNDATACOPY), kept by SATIN-SCHED-001
PER_AUTH_BASE_COST = 7_816  # SATIN-SCHED-003: EIP-7702 authorization, intrinsic regular gas
ACCOUNT_WRITE = 9_000  # SATIN-SCHED-003: EIP-8038 account write of an authority
DELEGATION_STATE_BYTES = 23  # SATIN-STATE-003: the EIP-8037 byte count of a delegation indicator
AUTHORIZATION_SIZE = 101  # SATIN-HIST-002: bytes of an authorization entry
KEYLESS_DEPLOY_OVERHEAD_GAS = 100_000  # SATIN-KEY-005 step 1
MAX_U64 = 2**64 - 1
# The charge-order principles (the specification at `5fb2688`).
PRE_FORK_NEW_ACCOUNT_COST = 25_000  # SATIN-STATE-012: the pre-Satin price of a new account
LEGACY_NEW_ACCOUNT_SHARE = PRE_FORK_NEW_ACCOUNT_COST - 0  # SATIN-STATE-012: a value CALL's new account has no execution charge
DELEGATION_PREFIX = b"\xef\x01\x00"  # EIP-7702's delegation indicator, followed by the delegate's address
# Gas detention, the Oracle's reads and the access-control refusal (the specification at `5fb2688`).
BLOCK_ENV_ACCESS_COMPUTE_GAS = 20_000_000  # SATIN-DET-012: the cap after a read of the block environment
ORACLE_ACCESS_COMPUTE_GAS = 20_000_000  # SATIN-DET-012: the cap after a read of the Oracle's storage
DETENTION_STOP = 2  # SATIN-DET-018: the kind of MegaLimitExceeded a crossing stops a frame with
# SATIN-STOP-002, SATIN-STOP-018: the kind of each dimension's stop, and the dimension the format names it by.
DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP = 0, 1, 3
STOP_DIMENSIONS = {DATA_SIZE_STOP: "data-size", KV_UPDATE_STOP: "kv-updates", DETENTION_STOP: "compute",
                   STATE_GROWTH_STOP: "state-growth"}

ORACLE = bytes.fromhex("6342000000000000000000000000000000000001")
KEYLESS_DEPLOY = bytes.fromhex("6342000000000000000000000000000000000003")
MEGA_ACCESS_CONTROL = bytes.fromhex("6342000000000000000000000000000000000004")
MEGA_LIMIT_CONTROL = bytes.fromhex("6342000000000000000000000000000000000005")


def selector(signature: str) -> bytes:
    return ex.keccak256(signature.encode())[:4]


SEND_HINT = selector("sendHint(bytes32,bytes)")
KEYLESS_DEPLOY_CALL = selector("keylessDeploy(bytes,uint256)")
# SATIN-ICPT-001: the intercepted methods of the two contracts whose answer is the node's.
INTERCEPTED = {
    MEGA_ACCESS_CONTROL: {selector("disableVolatileDataAccess()"), selector("enableVolatileDataAccess()"),
                          selector("isVolatileDataAccessDisabled()")},
    MEGA_LIMIT_CONTROL: {selector("remainingComputeGas()")},
}
NON_ZERO_TRANSFER = selector("NonZeroTransfer()")  # SATIN-ICPT-003
NO_ETHER_TRANSFER = selector("NoEtherTransfer()")  # SATIN-KEY-005 step 2
MALFORMED_ENCODING = selector("MalformedEncoding()")  # SATIN-KEY-005 step 3
DISABLE_VOLATILE_DATA_ACCESS = selector("disableVolatileDataAccess()")  # SATIN-MAC-001
VOLATILE_DATA_ACCESS_DISABLED = selector("VolatileDataAccessDisabled(uint8)")  # SATIN-MAC-004
ACCESS_TYPE_TIMESTAMP, ACCESS_TYPE_BENEFICIARY, ACCESS_TYPE_ORACLE = 1, 10, 11  # SATIN-MAC-005


def delegate_of(code: bytes) -> bytes | None:
    """The delegate an EIP-7702 delegation indicator names, or None for any other code."""
    return code[3:] if len(code) == 23 and code[:3] == DELEGATION_PREFIX else None


def limit_exceeded(kind: int, limit: int) -> bytes:
    """`MegaLimitExceeded(uint8,uint64)` with its two arguments (SATIN-STOP-020)."""
    return selector("MegaLimitExceeded(uint8,uint64)") + kind.to_bytes(32, "big") + limit.to_bytes(32, "big")


def keyless_arguments(data: bytes):
    """SATIN-ICPT-006's five conditions on the input after the selector: the `bytes` argument, or
    None when KeylessDeploy's decoder refuses the arguments."""
    body = data[4:]
    if len(body) < 64:  # 1: a head of two words
        return None
    offset = int.from_bytes(body[0:32], "big")
    if offset > MAX_U64 or offset + 32 > len(body):  # 2, and the length word must be in the input
        return None
    length = int.from_bytes(body[offset:offset + 32], "big")
    if length > MAX_U64 or offset + 32 + length > len(body):  # 3 and 4
        return None
    return body[offset + 32:offset + 32 + length]  # 5: nothing more is required


def rlp_decodes_as_list(b: bytes) -> bool:
    """Whether `b` is exactly one RLP list (no trailing byte): the shape a signed legacy transaction
    needs before its fields are read."""
    if not b or b[0] < 0xC0:
        return False
    if b[0] <= 0xF7:
        return 1 + (b[0] - 0xC0) == len(b)
    n = b[0] - 0xF7
    if len(b) < 1 + n:
        return False
    return 1 + n + int.from_bytes(b[1:1 + n], "big") == len(b)


def jump_destinations(code: bytes) -> set[int]:
    out, pc = set(), 0
    while pc < len(code):
        op = code[pc]
        if op == 0x5B:
            out.add(pc)
        pc += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return out


def to_signed(v: int) -> int:
    return v - 2**256 if v >> 255 else v


class Unmodelled(Exception):
    """The case uses something the model does not restate."""


class Halt(Exception):
    """An exceptional halt of the transaction's own frame."""


class OutOfGasBeforeFrame(Exception):
    """A charge before the first frame the transaction cannot pay (SATIN-SCHED-009)."""


class LimitStop(Exception):
    """A write that crosses a resource limit (SATIN-STOP-001, SATIN-LIM-010): the frame that made it is
    stopped with MegaLimitExceeded(kind, limit)."""

    def __init__(self, kind: int, limit: int, why: str):
        super().__init__(why)
        self.kind, self.limit = kind, limit


class Stopped(Exception):
    """A frame stopped by gas detention's crossing (SATIN-DET-018): a regular charge its spendable part
    cannot pay and its whole regular gas can, not made."""

    def __init__(self, limit: int, why: str):
        super().__init__(why)
        self.limit = limit


# --- The derivation record -----------------------------------------------------------------------


@dataclass
class Step:
    group: str  # the observation group the step derives: outcome, state, receipt, gasLedgers, resources
    text: str
    rules: tuple[str, ...]


@dataclass
class Derivation:
    steps: list[Step] = field(default_factory=list)

    def add(self, group: str, text: str, *rules: str) -> None:
        self.steps.append(Step(group, text, tuple(rules)))

    def rules(self, group: str) -> list[str]:
        return sorted({r for s in self.steps if s.group == group for r in s.rules})

    def texts(self, group: str) -> list[str]:
        return [s.text for s in self.steps if s.group == group]


# --- Inputs ---------------------------------------------------------------------------------------


@dataclass
class Account:
    nonce: int = 0
    balance: int = 0
    code: bytes = b""
    storage: dict[int, int] = field(default_factory=dict)

    def empty(self) -> bool:  # EIP-161, SATIN-STATE-011
        return self.nonce == 0 and self.balance == 0 and not self.code


@dataclass
class Tx:
    """A transaction as the model sees it, decoded from the case's bytes."""

    kind: str  # signed, deposit
    ty: int
    sender: bytes
    to: bytes | None
    nonce: int
    gas_limit: int
    value: int
    data: bytes
    chain_id: int | None
    gas_price: int = 0  # legacy and type 1; the effective price of type 2
    max_fee: int = 0
    max_priority: int = 0
    access_list: list[tuple[bytes, list[int]]] = field(default_factory=list)
    mint: int = 0
    # EIP-7702 entries, each (chain id, delegation target, nonce, the authority its signature recovers).
    authorizations: list[tuple[int, bytes, int, bytes]] = field(default_factory=list)


@dataclass
class Env:
    chain_id: int
    coinbase: bytes
    base_fee: int
    block_gas_limit: int
    buckets: dict[int, int]  # bucket id -> capacity (complete: unlisted buckets are minimal)
    timestamp: int = 0


def bucket_multiplier(env: Env, bucket: int) -> int:
    capacity = env.buckets.get(bucket, MIN_BUCKET_SIZE)
    return capacity // MIN_BUCKET_SIZE  # SATIN-STATE-002


def fmt(n: int) -> str:
    return f"{n:,}"


# --- The model --------------------------------------------------------------------------------------


@dataclass
class Result:
    observations: dict
    derivation: Derivation


def h(b: bytes) -> str:
    return "0x" + b.hex()


def q(n: int) -> str:
    return hex(n)


def word(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


def pad_address(a: bytes) -> bytes:
    return b"\x00" * 12 + a


def created_address(sender: bytes, nonce: int) -> bytes:
    return ex.keccak256(ex.rlp([sender, nonce]))[12:]


def memory_cost(words: int) -> int:
    return MEMORY_WORD * words + words * words // 512


class Run:
    """One transaction against a complete pre-state."""

    def __init__(self, env: Env, pre: dict[bytes, Account], tx: Tx, salt_bucket, principles: bool = False,
                 reads: bool = False):
        self.env, self.pre, self.tx = env, pre, tx
        # The `reads` group (SATIN-WIT-001, -002, -008): every account (None: absent) and slot the
        # transaction loads, as the pre-state holds it, and the SALT capacities it is served.
        self.reads = reads
        self.loaded_accounts: dict[bytes, Account | None] = {}
        self.loaded_slots: dict[tuple[bytes, int], int] = {}
        self.served_buckets: dict[int, int] = {}
        self.salt_bucket = salt_bucket  # (address, slot or None) -> bucket id
        self.d = Derivation()
        # The specification states the charge-order principles (`SATIN-HIST-023`, from `5fb2688` on): the
        # derivation cites them where the earlier snapshots leave the orders to the owner's decision (D-58).
        self.principles = principles
        # Gas figures at fixed points of the run, for the cases that set an input from a threshold:
        # "forward" is the caller's regular gas when the first CALL computes its forward, "frame" the
        # regular gas the first frame starts with, "delegate" the regular gas before the delegate's access,
        # "gas" and "gas-reservoir" the frame's regular gas and reservoir at its first GAS, "refused" the
        # regular gas a frame holds at a refused read, "oracle-sload" the regular gas at the first Oracle read;
        # "child-room" and "oracle-sload-room" what the limit leaves the transaction's compute at the first
        # detained child's start and at a detained Oracle read; "list" the regular gas when an authorization
        # list starts to be applied, "balance" the regular gas at the first BALANCE.
        self.probe: dict[str, int] = {}
        # Gas detention (SATIN-DET-009, -012): the transaction's compute, every regular charge its frames
        # make, and the limit the most restrictive volatile read set, None before any read.
        self.compute = 0
        self.limit: int | None = None
        # The stop of the transaction's own frame, (kind, limit), when one is its result.
        self.stop: tuple[int, int] | None = None
        self.frame_start_counts = (0, 0, 0)

    # The refusals of transaction validation, in the order SATIN-VAL-003 fixes for Satin's own
    # checks; the base layer's checks come after, each case failing only one check.
    def validate(self, intrinsic: int, floor: int, body_history: int):
        tx, env = self.tx, self.env
        sender = self.pre.get(tx.sender, Account())
        if tx.kind == "deposit":
            return None
        if tx.chain_id is not None and tx.chain_id != env.chain_id:
            return ("validation", "chain-id-mismatch", "SATIN-VAL-006",
                    f"the transaction carries chain id {tx.chain_id}, the chain's is {env.chain_id}")
        if tx.gas_limit < intrinsic:
            return ("validation", "intrinsic-gas-too-low", "SATIN-VAL-002",
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} (SATIN-VAL-003 step 2)")
        if floor > tx.gas_limit:
            return ("validation", "floor-exceeds-gas-limit", "SATIN-VAL-002",
                    f"floor {fmt(floor)} > gas limit {fmt(tx.gas_limit)} (SATIN-VAL-003 step 3)")
        if tx.gas_limit < intrinsic + body_history:
            return ("validation", "intrinsic-gas-too-low", "SATIN-VAL-002",
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} + body history gas "
                    f"{fmt(body_history)} = {fmt(intrinsic + body_history)} (SATIN-VAL-003 step 5)")
        if tx.gas_limit > env.block_gas_limit:
            # SATIN-BLK-009 and SATIN-BLK-013: a transaction whose gas limit does not fit in what the
            # block's gas limit has left is skipped for the block; in engine isolation the block has
            # all of its gas left, and the skip is reported as a refusal at inclusion (D-50).
            return ("inclusion", "gas-limit-exceeds-block", ("SATIN-BLK-009", "SATIN-BLK-013", "SATIN-BASE-002"),
                    f"gas limit {fmt(tx.gas_limit)} > the {fmt(env.block_gas_limit)} the block's gas limit has left: "
                    "skipped for the block, a refusal at inclusion in engine isolation")
        if sender.code and delegate_of(sender.code) is None:  # EIP-7702 lets a delegated account send
            return ("validation", "sender-has-code", "SATIN-VAL-007",
                    "the sender's account has code (EIP-3607, a base-layer check)")
        if tx.nonce < sender.nonce:
            return ("validation", "nonce-too-low", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} < account nonce {sender.nonce} (a base-layer check)")
        if tx.nonce > sender.nonce:
            return ("validation", "nonce-too-high", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} > account nonce {sender.nonce} (a base-layer check)")
        if tx.ty in (2, 4) and tx.max_priority > tx.max_fee:
            return ("validation", "priority-fee-above-fee-cap", "SATIN-VAL-007",
                    "max priority fee above max fee (a base-layer check)")
        cap = tx.max_fee if tx.ty in (2, 4) else tx.gas_price
        if cap < env.base_fee:
            return ("validation", "fee-cap-below-base-fee", "SATIN-VAL-007",
                    f"fee cap {fmt(cap)} below the base fee {fmt(env.base_fee)} (a base-layer check)")
        cost = tx.gas_limit * cap + tx.value
        if sender.balance < cost:
            return ("validation", "insufficient-funds", "SATIN-VAL-007",
                    f"balance {fmt(sender.balance)} < gas limit x fee cap + value = {fmt(cost)} (a base-layer check)")
        return None

    def run(self) -> Result:
        tx, env, d = self.tx, self.env, self.d
        data = tx.data
        zeros = data.count(0)
        nonzeros = len(data) - zeros
        to_self = tx.to == tx.sender
        create = tx.to is None

        # Intrinsic regular gas, SATIN-SCHED-006.
        parts = [f"TX_BASE_COST {fmt(TX_BASE_COST)}"]
        intrinsic = TX_BASE_COST
        floor_base = TX_BASE_COST
        if create:
            words = (len(data) + 31) // 32
            intrinsic += CREATE_ACCESS + INITCODE_WORD_COST * words
            floor_base += CREATE_ACCESS
            parts += [f"CREATE_ACCESS {fmt(CREATE_ACCESS)}", f"initcode {words} words x {INITCODE_WORD_COST}"]
        elif not to_self:
            intrinsic += COLD_ACCOUNT_ACCESS
            floor_base += COLD_ACCOUNT_ACCESS
            parts.append(f"COLD_ACCOUNT_ACCESS {fmt(COLD_ACCOUNT_ACCESS)}")
            if tx.value:
                intrinsic += TX_VALUE_COST
                floor_base += TX_VALUE_COST
                parts.append(f"TX_VALUE_COST {fmt(TX_VALUE_COST)}")
        calldata = CALLDATA_ZERO * zeros + CALLDATA_NONZERO * nonzeros
        if data:
            intrinsic += calldata
            parts.append(f"calldata {zeros} zero x {CALLDATA_ZERO} + {nonzeros} non-zero x {CALLDATA_NONZERO} = {fmt(calldata)}")
        al_bytes = 0
        for _, keys in tx.access_list:
            intrinsic += ACCESS_LIST_ADDRESS + ACCESS_LIST_KEY * len(keys)
            al_bytes += ACCESS_LIST_ADDRESS_SIZE + ACCESS_LIST_SLOT_SIZE * len(keys)
        if tx.access_list:
            parts.append(f"access list {len(tx.access_list)} addresses x {fmt(ACCESS_LIST_ADDRESS)} + "
                         f"{sum(len(k) for _, k in tx.access_list)} keys x {fmt(ACCESS_LIST_KEY)}")
        auth_bytes = AUTHORIZATION_SIZE * len(tx.authorizations)
        if tx.authorizations:
            intrinsic += PER_AUTH_BASE_COST * len(tx.authorizations)
            parts.append(f"{len(tx.authorizations)} authorization entries x PER_AUTH_BASE_COST {fmt(PER_AUTH_BASE_COST)}")
        floor = floor_base + FLOOR_PER_BYTE * (len(data) + al_bytes)
        body_bytes = TX_BODY_SIZE + len(data) + al_bytes + auth_bytes
        body_history = body_bytes * COST_PER_HISTORY_BYTE

        refusal = self.validate(intrinsic, floor, body_history)
        if refusal:
            phase, reason, rule, why = refusal
            rules = rule if isinstance(rule, tuple) else (rule,)
            d.add("outcome", f"refused at {phase}: {why}", *rules)
            return Result(refused(phase, reason), d)

        d.add("gasLedgers", f"intrinsic regular gas = {' + '.join(parts)} = {fmt(intrinsic)}",
              *(("SATIN-SCHED-006", "SATIN-SCHED-007") if tx.authorizations else ("SATIN-SCHED-006",)))
        d.add("gasLedgers", f"floor = base {fmt(floor_base)} + {FLOOR_PER_BYTE} x {len(data) + al_bytes} calldata and "
              f"access-list bytes = {fmt(floor)}", "SATIN-SCHED-005")
        if tx.authorizations:
            d.add("gasLedgers", f"body = TX_BODY_SIZE {TX_BODY_SIZE} + {len(data)} calldata bytes + {al_bytes} access-list "
                  f"bytes + {len(tx.authorizations)} authorization entries x AUTHORIZATION_SIZE {AUTHORIZATION_SIZE} = "
                  f"{body_bytes} bytes; its history gas {body_bytes} x {COST_PER_HISTORY_BYTE} = {fmt(body_history)}; "
                  "authorization bytes are not floor tokens", "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004")
        else:
            d.add("gasLedgers", f"body = TX_BODY_SIZE {TX_BODY_SIZE} + {len(data)} calldata bytes + {al_bytes} access-list "
                  f"bytes = {body_bytes} bytes; its history gas {body_bytes} x {COST_PER_HISTORY_BYTE} = {fmt(body_history)}",
                  "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004")
        d.add("resources", f"data size starts at the body's {body_bytes} bytes; its five fixed records are not KV updates",
              "SATIN-ACCT-002", "SATIN-HIST-003")

        self.state: dict[bytes, Account] = {a: Account(x.nonce, x.balance, x.code, dict(x.storage)) for a, x in self.pre.items()}
        self.load(tx.sender, "the sender, which validation reads", "SATIN-WIT-002", "SATIN-WIT-008")
        self.data_size = body_bytes
        self.kv: set = set()  # write records: ("a", address) or ("s", address, slot)
        self.growth = 0
        self.logs: list[tuple[bytes, list[bytes], bytes]] = []
        self.refund = 0
        self.state_gas = 0  # kept state charges
        self.history_gas = body_history
        self.history_bytes = body_bytes
        # The access list's slots are warm from the start (EIP-2930, SATIN-SCHED-012).
        self.warm_slots: set = {(a, k) for a, keys in tx.access_list for k in keys}
        self.original: dict[tuple[bytes, int], int] = {}

        # The two pools, SATIN-POOL-005, and the body's history from the reservoir first, POOL-006.
        regular = min(tx.gas_limit, EXECUTION_CAP) - intrinsic
        reservoir = max(0, tx.gas_limit - EXECUTION_CAP)
        d.add("gasLedgers", f"pools: regular budget min({fmt(tx.gas_limit)}, {fmt(EXECUTION_CAP)}) - {fmt(intrinsic)} = "
              f"{fmt(regular)}, reservoir {fmt(reservoir)}", "SATIN-POOL-005")
        from_res = min(reservoir, body_history)
        reservoir -= from_res
        regular -= body_history - from_res
        self.reservoir_after_body = reservoir
        self.hint_bytes = 0  # admitted hints' input bytes, which stay counted whatever follows (SATIN-ORCL-009)
        d.add("gasLedgers", f"body history {fmt(body_history)}: {fmt(from_res)} from the reservoir, "
              f"{fmt(body_history - from_res)} from the regular budget", "SATIN-POOL-006")
        self.regular_charges = 0  # regular charges made by the frame
        self.pre_frame_regular = 0  # regular charges made before the first frame (ACCOUNT_WRITE)
        # Warm from the start: the sender, the recipient, the beneficiary and the access list's
        # addresses (SATIN-SCHED-012, SATIN-SCHED-014).
        self.warm_accounts: set = {tx.sender, env.coinbase} | ({tx.to} if tx.to else set()) | {a for a, _ in tx.access_list}

        sender_acct = self.state.setdefault(tx.sender, Account())
        if tx.kind == "deposit":
            return self.run_deposit(intrinsic, floor, regular, reservoir)

        # Validation's changes to the sender: nonce of a call, the fee (SATIN-ACCT-008).
        price = self.effective_price()
        sender_acct.balance -= tx.gas_limit * price
        if not create:
            sender_acct.nonce += 1

        if tx.authorizations:
            try:
                regular, reservoir = self.apply_authorizations(regular, reservoir)
            except OutOfGasBeforeFrame as e:
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir, str(e))

        # Charges before the first frame, SATIN-SCHED-008 steps 3 and 4.
        pre_frame_state = 0
        pre_frame_history = 0
        recipient = created_address(tx.sender, self.pre.get(tx.sender, Account()).nonce) if create else tx.to
        transfer = tx.value > 0 and not to_self
        start_record = False
        if create:
            existing = self.state.get(recipient)
            if existing and not existing.empty():
                raise Unmodelled("a creation onto an occupied address")
            start_record = True
        elif transfer:
            start_record = True
        if start_record:
            pre_frame_history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            d.add("gasLedgers", f"the first frame's start record ({'created account' if create else 'value recipient'}): "
                  f"{WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(pre_frame_history)} history gas before the frame",
                  "SATIN-HIST-005", "SATIN-SCHED-008")
        new_account = False
        if create:
            new_account = True
        elif transfer:
            rec = self.state.get(recipient)
            new_account = rec is None or rec.empty()
        if new_account:
            m = self.multiplier(self.salt_bucket(recipient, None))
            pre_frame_state = ACCOUNT_STATE * m
            d.add("gasLedgers", f"{'created' if create else 'new'}-account state gas {fmt(ACCOUNT_STATE)} x m={m} = "
                  f"{fmt(pre_frame_state)} at step 4, no legacy share", "SATIN-SCHED-008", "SATIN-STATE-001",
                  "SATIN-STATE-003", "SATIN-POOL-024")
        # Of step 3's history, the authorities' records drew the reservoir first, when the list was
        # applied; the first frame's start record draws what they left (D-58).
        drawn = []  # what the reservoir paid of the start record and of the start's state gas
        for step, (amount, what) in enumerate(((pre_frame_history, "the first frame's start record"),
                                               (pre_frame_state, "the recipient's or created account's state gas"))):
            if step == 1 and recipient != tx.sender:
                self.load(recipient, f"the {'created address' if create else 'recipient'}, at step 4 of the charges "
                          "before the first frame and no earlier", "SATIN-SCHED-008", "SATIN-WIT-008")
            r = min(reservoir, amount)
            if amount - r > regular:
                if tx.authorizations or r or reservoir != self.reservoir_after_body or create:
                    raise Unmodelled("a transaction that cannot pay a charge before its first frame")
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir,
                                                    f"{what}, {fmt(amount)}, with {fmt(regular)} regular gas left")
            reservoir -= r
            regular -= amount - r
            drawn.append(r)
        start_from_reservoir = drawn[0]
        if self.principles and start_record and (tx.authorizations or self.reservoir_after_body):
            records = "the authorities' records" if tx.authorizations else "no authority's record"
            d.add("gasLedgers", f"of step 3's history the reservoir pays {records} first and the first frame's start record "
                  f"with what they leave it: {fmt(start_from_reservoir)} of the record from the reservoir and "
                  f"{fmt(pre_frame_history - start_from_reservoir)} from the regular budget", "SATIN-HIST-005",
                  "SATIN-POOL-024", "SATIN-HIST-023")

        # A recipient that holds an EIP-7702 delegation, after the list applied: its delegate's access,
        # charged as the base layer charges it under EIP-2780, after step 4 — the warm read, then the
        # cold surcharge when the delegate is not warm, the delegate loaded only when the regular gas
        # left pays the surcharge — and the delegate's code runs in the recipient's frame (D-58).
        delegate = None if create else delegate_of(self.state.get(recipient, Account()).code)
        if delegate is not None:
            if int.from_bytes(delegate, "big") <= 0x100:
                raise Unmodelled("a delegation to a precompile")
            cold = delegate not in self.warm_accounts
            access = WARM_READ + (COLD_ACCOUNT_SURCHARGE if cold else 0)
            self.probe.setdefault("delegate", regular)
            if regular < WARM_READ or (cold and regular - WARM_READ < COLD_ACCOUNT_SURCHARGE):
                if start_record or pre_frame_state or regular < WARM_READ:
                    raise Unmodelled("a transaction that cannot pay its delegate's access before its first frame")
                d.add("gasLedgers", f"the recipient holds an EIP-7702 delegation to {h(delegate)}, which is not warm: the "
                      f"delegate's access before the first frame, the warm read {WARM_READ} first, leaving "
                      f"{fmt(regular - WARM_READ)} of regular gas, which cannot pay the cold surcharge "
                      f"{fmt(COLD_ACCOUNT_SURCHARGE)}: the delegate is not loaded", "SATIN-SCHED-003", "SATIN-SCHED-008")
                if self.reads:
                    d.add("reads", f"the delegate {h(delegate)} is not loaded: its cold surcharge cannot be paid",
                          "SATIN-SCHED-008", "SATIN-WIT-012")
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir,
                                                    f"its delegate's cold surcharge, {fmt(COLD_ACCOUNT_SURCHARGE)}, with "
                                                    f"{fmt(regular - WARM_READ)} regular gas left after the warm read")
            regular -= access
            self.pre_frame_regular += access
            self.warm_accounts.add(delegate)
            self.load(delegate, "the recipient's delegate, at step 5, once its access is paid", "SATIN-SCHED-008",
                      "SATIN-WIT-008")
            d.add("gasLedgers", f"the recipient holds an EIP-7702 delegation to {h(delegate)}: the delegate's access before "
                  f"the first frame, after step 4, warm read {WARM_READ}" +
                  (f" + cold surcharge {fmt(COLD_ACCOUNT_SURCHARGE)} = {fmt(access)}, the cold delegate loaded once the "
                   "regular gas left pays the surcharge" if cold else ", the delegate warm") +
                  "; regular gas, and the delegate's code runs in the recipient's frame (" +
                  ("SATIN-SCHED-008 step 5" if self.principles else "D-58") + ")",
                  "SATIN-SCHED-003", "SATIN-SCHED-008")

        # A recognized keylessDeploy call is decided by interception, before the frame start: no value
        # moves for it (SATIN-ICPT-007, SATIN-KEY-018).
        keyless = (not create and recipient == KEYLESS_DEPLOY and data[:4] == KEYLESS_DEPLOY_CALL
                   and keyless_arguments(data) is not None)
        moved = transfer and not keyless

        # The frame starts: its records and transfer log (SATIN-LIM-013, SATIN-ACCT-005, SATIN-LOG-001).
        if moved:
            sender_acct.balance -= tx.value
            rec = self.state.setdefault(recipient, Account())
            rec.balance += tx.value
            self.kv.add(("a", recipient))
            self.data_size += WRITE_RECORD_SIZE + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(tx.sender), pad_address(recipient)],
                              tx.value.to_bytes(32, "big")))
            d.add("resources", f"the value moves: the recipient's write record ({WRITE_RECORD_SIZE} bytes, one KV update) "
                  f"and its EIP-7708 transfer log ({TRANSFER_LOG_SIZE} bytes, no history gas)",
                  "SATIN-ACCT-005", "SATIN-LOG-006")
            d.add("receipt", "the transfer log of the transaction's value is the receipt's first log", "SATIN-LOG-001", "SATIN-LOG-002")
            if new_account:
                self.growth += 1
                d.add("resources", "the recipient is empty under EIP-161: one unit of state growth", "SATIN-ACCT-014")
                if recipient in self.pre:
                    d.add("resources", "the state holds the recipient's leaf, empty under EIP-161: as a value recipient it is "
                          "charged and counted as an absent account, the existence predicate being an authority's alone",
                          "SATIN-ACCT-015", "SATIN-STATE-011")
        elif tx.value and to_self:
            d.add("receipt", "value sent to the sender itself moves nothing and logs nothing", "SATIN-LOG-003")
            d.add("resources", "value to the sender itself changes no account and records nothing", "SATIN-ACCT-007")
        if create:
            sender_acct.nonce += 1
            acct = self.state.setdefault(recipient, Account())
            acct.nonce = 1
            if tx.value:
                raise Unmodelled("a creation with an endowment")
            self.kv.add(("a", recipient))
            self.growth += 1
            self.data_size += WRITE_RECORD_SIZE
            d.add("resources", "the created account: one write record and one unit of state growth", "SATIN-ACCT-005", "SATIN-ACCT-014")
        self.history_gas += pre_frame_history
        self.history_bytes += WRITE_RECORD_SIZE if start_record else 0
        self.state_gas += pre_frame_state

        code = data if create else self.state.get(delegate or recipient, Account()).code
        self.address = recipient
        frame = {"regular": regular, "reservoir": reservoir, "regular_at_start": regular, "reservoir_at_start": reservoir}
        self.probe.setdefault("frame", regular)
        # What the transaction's own frame is given in each dimension: what the transaction has left once the
        # body and the counts made before the first frame are counted (SATIN-LIM-002).
        self.frame_start_counts = (self.data_size, len(self.kv), self.growth)
        snapshot = self.snapshot()
        status, output = "success", b""
        try:
            if keyless:
                status, output = self.keyless_call(frame)
            else:
                if not create and recipient == KEYLESS_DEPLOY and data[:4] == KEYLESS_DEPLOY_CALL:
                    d.add("outcome", "the transaction's own CALL to KeylessDeploy carries keylessDeploy's selector, but its "
                          "arguments fail the decoder's conditions: not recognized, charged nothing, and KeylessDeploy's "
                          "bytecode runs, whose decoder refuses the same arguments", "SATIN-ICPT-006")
                status, output = self.execute(code, frame, create)
        except Halt as e:
            status = "halt"
            d.add("outcome", f"the frame halts: {e}", "SATIN-OUT-007")
        except Stopped as e:
            status, output = "revert", limit_exceeded(DETENTION_STOP, e.limit)
            self.stop = (DETENTION_STOP, e.limit)
            d.add("outcome", f"the transaction's own frame reaches gas detention's crossing at {e}: the charge is not made, "
                  f"and the frame is stopped with MegaLimitExceeded({DETENTION_STOP}, {fmt(e.limit)}), the transaction's "
                  "result", "SATIN-DET-018", "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-021")
        except LimitStop as e:
            status, output = "revert", limit_exceeded(e.kind, e.limit)
            self.stop = (e.kind, e.limit)
            d.add("outcome", f"the transaction's own frame crosses a limit at {e}: the write is not kept, and the frame is "
                  f"stopped with MegaLimitExceeded({e.kind}, {fmt(e.limit)}), the transaction's result",
                  "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-018", "SATIN-STOP-021")

        if status == "success" and create:
            self.deposit_code(output, frame, recipient)

        if status == "halt":
            # SATIN-POOL-014: the halting frame's reservoir becomes what it received, its regular gas
            # is consumed; its records, logs, state and storage are taken back. The start's record
            # and the created account's state gas: the part the reservoir paid returns (POOL-015,
            # HIST-005); here no reservoir paid them unless the case has one.
            if self.hint_bytes:
                raise Unmodelled("a halt after an admitted hint")
            self.restore(snapshot)
            spent_regular = tx.gas_limit - frame["reservoir_at_start"] - (pre_frame_history + pre_frame_state if reservoir else 0)
            if sum(drawn):
                raise Unmodelled("a halt after the reservoir paid a charge for the first frame's start")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state)
            if keyless and start_record:
                self.history_gas -= pre_frame_history
                self.history_bytes -= WRITE_RECORD_SIZE
            if self.principles and start_record:
                d.add("gasLedgers", f"the first frame's start record, {fmt(pre_frame_history)} of history gas charged before "
                      f"the frame{', before interception decides the call,' if keyless else ''} is not kept: the "
                      f"{fmt(start_from_reservoir)} the reservoir paid of it returns to the reservoir, and the "
                      f"{fmt(pre_frame_history - start_from_reservoir)} the regular budget paid is consumed with the frame's "
                      "regular gas" + ("; the authorities' records and state gas are the transaction's own and are kept"
                                       if tx.authorizations else ""),
                      "SATIN-HIST-005", "SATIN-POOL-024", "SATIN-HIST-023",
                      *(("SATIN-AUTH-016",) if tx.authorizations else ()))
            reservoir_left = frame["reservoir_at_start"] + (pre_frame_history + pre_frame_state if frame["reservoir_at_start"] else 0)
            if frame["reservoir_at_start"] and (pre_frame_history or pre_frame_state):
                raise Unmodelled("a halt after start charges the reservoir paid")
            total = tx.gas_limit - frame["reservoir_at_start"]
            d.add("gasLedgers", f"halt: every regular gas the frame held is consumed, the reservoir {fmt(frame['reservoir_at_start'])} "
                  f"returns; total = gas limit {fmt(tx.gas_limit)} - {fmt(frame['reservoir_at_start'])} = {fmt(total)}; the "
                  "frame's state and history charges are not kept, so what regular gas paid of them is on the regular "
                  "ledger (D-51)", "SATIN-POOL-014", "SATIN-POOL-017")
            del spent_regular, reservoir_left
            self.refund = 0
            execution = {"status": "halt", "output": "0x", "createdAddress": None}
        elif status == "revert":
            self.restore(snapshot)
            if self.hint_bytes:
                # An admitted hint is the transaction's, on no frame: it stays counted (SATIN-STOP-012, ORCL-009).
                if self.stop is None:
                    raise Unmodelled("a revert after an admitted hint")
                self.data_size += self.hint_bytes
                d.add("resources", f"the admitted hints' {fmt(self.hint_bytes)} bytes stay counted as data size through the "
                      "stop", "SATIN-STOP-012", "SATIN-ORCL-009")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state)
            if keyless and start_record:
                self.history_gas -= pre_frame_history
                self.history_bytes -= WRITE_RECORD_SIZE
                d.add("gasLedgers", f"the start record's {fmt(pre_frame_history)} history gas, charged before the frame, comes "
                      "back with the revert: the value never moved", "SATIN-HIST-005", "SATIN-KEY-004")
            total = intrinsic + self.pre_frame_regular + self.regular_charges + self.history_gas + self.state_gas
            d.add("gasLedgers", "revert: the frame's state and history charges, and the first frame's start record and "
                  "recipient or created-account state gas, are given back into the reservoir and return to the sender; its "
                  f"regular charges {fmt(self.regular_charges)} stay spent", "SATIN-POOL-014", "SATIN-POOL-015",
                  "SATIN-HIST-005", "SATIN-POOL-017")
            if self.stop is not None:
                d.add("limit", f"the stop of the transaction's own frame is its result: {STOP_DIMENSIONS[self.stop[0]]}, limit "
                      f"{fmt(self.stop[1])}, return data MegaLimitExceeded({self.stop[0]}, {fmt(self.stop[1])}); the "
                      "transaction settles as a revert, keeping what was applied before its first frame",
                      "SATIN-STOP-009", "SATIN-STOP-011", "SATIN-STOP-018", "SATIN-STOP-021")
            self.refund = 0
            execution = {"status": "revert", "output": h(output), "createdAddress": None}
        else:
            total = intrinsic + self.pre_frame_regular + self.regular_charges + self.history_gas + self.state_gas
            # A creation's output is what its initcode returned: the code it deposited.
            execution = {"status": "success", "output": h(output), "createdAddress": h(recipient) if create else None}

        return self.settle(total, floor, price, status, execution, create, recipient)

    def out_of_gas_before_frame(self, intrinsic: int, floor: int, price: int, reservoir: int, what: str) -> Result:
        """SATIN-SCHED-009 and SATIN-SCHED-010: a transaction that cannot pay a charge before its first frame
        runs out of gas without running a frame. The model reaches this path only when nothing but
        validation's changes to the sender was applied before the charge it cannot pay."""
        tx, d = self.tx, self.d
        d.add("outcome", f"the transaction cannot pay {what}: it runs out of gas before its first frame and runs no frame",
              "SATIN-SCHED-009")
        total = tx.gas_limit - reservoir
        d.add("gasLedgers", "out of gas before the first frame: the intrinsic gas and the body's history stay charged, the "
              f"rest of the regular budget is consumed, and the reservoir left, {fmt(reservoir)}, returns to the sender; "
              f"total = gas limit {fmt(tx.gas_limit)} - {fmt(reservoir)} = {fmt(total)}", "SATIN-SCHED-010", "SATIN-POOL-017")
        d.add("resources", "nothing applied before the first frame is kept but validation's changes to the sender: no write "
              "record, no state growth, the data size the body's alone", "SATIN-SCHED-010")
        if self.reads and tx.to is not None and tx.to not in self.loaded_accounts:
            d.add("reads", f"the recipient {h(tx.to)} is not loaded: its load is made at step 4 of the charges before the "
                  "first frame, which the transaction does not reach", "SATIN-SCHED-008")
        self.refund = 0
        return self.settle(total, floor, price, "halt", {"status": "halt", "output": "0x", "createdAddress": None}, False,
                           None)

    def settle(self, total: int, floor: int, price: int, status: str, execution: dict, create: bool,
               recipient: bytes | None) -> Result:
        """The settlement of an admitted transaction that is not a deposit: its refund, floor, gas used,
        fees, ledgers, resources and receipt."""
        tx, env, d = self.tx, self.env, self.d
        sender_acct = self.state[tx.sender]
        self.fee_reads()
        # Refund, floor, gas used (SATIN-POOL-018, SATIN-POOL-020).
        cap = total // REFUND_QUOTIENT
        refund = min(self.refund, cap)
        gas_used = max(total - refund, floor)
        if total - refund < floor:
            refund = 0
        regular_ledger = total - self.state_gas - self.history_gas
        if self.refund:
            d.add("gasLedgers", f"refund min(counter {fmt(self.refund)}, total {fmt(total)} / {REFUND_QUOTIENT} = {fmt(cap)}) = "
                  f"{fmt(refund)}", "SATIN-POOL-018")
        d.add("gasLedgers", f"ledgers: state {fmt(self.state_gas)}, history {fmt(self.history_gas)} "
              f"({self.history_bytes} bytes), regular = total {fmt(total)} - state - history = {fmt(regular_ledger)}",
              "SATIN-POOL-019", "SATIN-HIST-022")
        d.add("gasLedgers", f"gas used max({fmt(total)} - {fmt(refund)}, floor {fmt(floor)}) = {fmt(gas_used)}; the block "
              f"counts max(regular {fmt(regular_ledger)}, floor {fmt(floor)}) = {fmt(max(regular_ledger, floor))}",
              "SATIN-POOL-018", "SATIN-POOL-020")

        # Fees: the sender is returned what it did not use; the base fee vault and the beneficiary
        # are credited (base layer, SATIN-BASE-001).
        sender_acct.balance += (tx.gas_limit - gas_used) * price
        if price:
            base = gas_used * env.base_fee
            tip = gas_used * (price - env.base_fee)
            if base:
                self.state.setdefault(BASE_FEE_VAULT, Account()).balance += base
            if tip:
                self.state.setdefault(env.coinbase, Account()).balance += tip
            d.add("state", f"fees: the sender pays {fmt(gas_used)} x {fmt(price)}; the base fee vault receives "
                  f"{fmt(gas_used)} x {fmt(env.base_fee)}, the beneficiary {fmt(gas_used)} x {fmt(price - env.base_fee)}; "
                  "the L1 data fee and the operator fee are zero, the L1 block contract's fee parameters being zero",
                  "SATIN-BASE-001", "SATIN-BASE-010")

        ledgers = {"total": q(total), "regular": q(regular_ledger), "state": q(self.state_gas), "history": q(self.history_gas),
                   "historyBytes": q(self.history_bytes), "refund": q(refund), "floor": q(floor), "gasUsed": q(gas_used),
                   "blockGas": q(max(regular_ledger, floor))}
        kv = len(self.kv)
        resources = {"dataSize": dim(TX_DATA_LIMIT, self.data_size), "kvUpdates": dim(TX_KV_UPDATE_LIMIT, kv),
                     "stateGrowth": dim(TX_STATE_GROWTH_LIMIT, self.growth)}
        d.add("resources", f"kept: data size {self.data_size} bytes, {kv} KV updates, state growth {self.growth}; the limits "
              f"are the protocol's {fmt(TX_DATA_LIMIT)}, {fmt(TX_KV_UPDATE_LIMIT)} and {fmt(TX_STATE_GROWTH_LIMIT)}",
              "SATIN-LIM-001", "SATIN-LIM-007", "SATIN-ACCT-012")
        receipt = {"type": q(tx.ty), "status": "0x1" if status == "success" else "0x0", "gasUsed": q(gas_used),
                   "logs": [{"address": h(a), "topics": [h(t) for t in ts], "data": h(dt)} for a, ts, dt in self.logs],
                   "depositNonce": None, "depositReceiptVersion": None}
        d.add("receipt", f"status {receipt['status']}, gas used {fmt(gas_used)}, {len(self.logs)} logs in execution order",
              "SATIN-POOL-018")
        outcome = {"admission": {"status": "admitted"}, "execution": execution, "commit": {"status": "committed"}}
        if status == "success":
            d.add("outcome", "admitted; the frame succeeds" + (f" and creates {h(recipient)}" if create else ""),
                  "SATIN-OUT-001" if not create else "SATIN-SCHED-011")
        elif status == "revert" and self.stop is not None:
            d.add("outcome", "admitted; the frame is stopped, and the transaction is included with a failed receipt",
                  "SATIN-STOP-009")
        elif status == "revert":
            d.add("outcome", "admitted; the frame reverts with its REVERT data", "SATIN-OUT-001")
        limit = None
        if self.stop is not None:
            kind, value = self.stop
            limit = {"dimension": STOP_DIMENSIONS[kind], "limit": q(value), "returnData": h(limit_exceeded(kind, value))}
        observations = {"outcome": outcome, "state": self.diff(), "receipt": receipt, "gasLedgers": ledgers,
                        "resources": resources, "limit": limit}
        if self.reads:
            observations["reads"] = self.reads_observation()
        return Result(observations, d)

    def effective_price(self) -> int:
        tx = self.tx
        if tx.ty in (2, 4):
            return min(tx.max_fee, self.env.base_fee + tx.max_priority)
        return tx.gas_price

    # --- one frame ---

    def snapshot(self):
        return ({a: Account(x.nonce, x.balance, x.code, dict(x.storage)) for a, x in self.state.items()},
                set(self.kv), self.data_size, self.growth, list(self.logs), self.history_gas, self.history_bytes,
                self.state_gas)

    def restore(self, snap) -> None:
        (self.state, self.kv, self.data_size, self.growth, self.logs, self.history_gas, self.history_bytes,
         self.state_gas) = snap

    def undo_start(self, transfer, create, recipient, new_account, start_history, start_state) -> None:
        """A failed first frame discards its start: the value, the records, the transfer log, the
        created account, and gives the start's history and state gas back (SATIN-HIST-005,
        SATIN-POOL-015)."""
        tx = self.tx
        if transfer:
            self.state[tx.sender].balance += tx.value
            self.state[recipient].balance -= tx.value
            self.kv.discard(("a", recipient))
            self.data_size -= WRITE_RECORD_SIZE + TRANSFER_LOG_SIZE
            self.logs = [l for l in self.logs if l[0] != TRANSFER_LOG_ADDRESS]
            if new_account:
                self.growth -= 1
        if create:
            self.state.pop(recipient, None)
            self.kv.discard(("a", recipient))
            self.data_size -= WRITE_RECORD_SIZE
            self.growth -= 1
        if transfer or create:
            self.history_gas -= start_history
            self.history_bytes -= WRITE_RECORD_SIZE
            self.state_gas -= start_state
            if recipient in self.state and self.state[recipient].empty() and recipient not in self.pre:
                del self.state[recipient]

    def load(self, address: bytes, why: str, *rules: str) -> None:
        """An account the transaction loads, as the pre-state holds it (absent: None)."""
        if address not in self.loaded_accounts:
            self.loaded_accounts[address] = self.pre.get(address)
            if self.reads:
                self.d.add("reads", f"{h(address)} is loaded: {why}", *rules)

    def load_slot(self, address: bytes, key: int, why: str, *rules: str) -> None:
        """A slot the transaction loads, as the pre-state holds it; an absent account has no slot to load
        (SATIN-WIT-006)."""
        if (address, key) not in self.loaded_slots and self.pre.get(address) is not None:
            self.loaded_slots[(address, key)] = self.pre[address].storage.get(key, 0)
            if self.reads:
                self.d.add("reads", f"slot {key} of {h(address)} is loaded: {why}", *rules)

    def multiplier(self, bucket: int) -> int:
        """The bucket multiplier of a state charge, its capacity served by the SALT environment and exported
        (SATIN-WIT-013)."""
        self.served_buckets.setdefault(bucket, self.env.buckets.get(bucket, MIN_BUCKET_SIZE))
        return bucket_multiplier(self.env, bucket)

    def fee_reads(self) -> None:
        """What every transaction that is not a deposit reads for its fees: the L1 block contract's
        slots, before it runs, and the fee recipients at its settlement (SATIN-WIT-008, -011)."""
        l1 = self.pre.get(L1_BLOCK_ADDRESS)
        self.load(L1_BLOCK_ADDRESS, "the L1 block information the transaction's L1 fee and data-availability "
                  "footprint read, outside its journal, reported with it", "SATIN-WIT-003", "SATIN-WIT-011")
        slots = [L1_BASE_FEE_SLOT, L1_ECOTONE_SCALARS_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_OPERATOR_SCALARS_SLOT]
        if l1 is not None and not l1.storage.get(L1_ECOTONE_SCALARS_SLOT, 0):
            slots.append(L1_FEE_OVERHEAD_SLOT)
        elif l1 is not None:
            raise Unmodelled("an L1 block contract with Ecotone scalars")
        for slot in sorted(slots):
            self.load_slot(L1_BLOCK_ADDRESS, slot, "the L1 fee computation's slots, the overhead slot as the Ecotone "
                           "scalars are empty, and the footprint gas scalar's", "SATIN-WIT-011")
        for who, what in ((self.env.coinbase, "the block beneficiary"), (BASE_FEE_VAULT, "the base fee vault"),
                          (L1_FEE_VAULT, "the L1 fee vault"), (OPERATOR_FEE_VAULT, "the operator fee vault")):
            self.load(who, f"{what}, a fee recipient the settlement credits", "SATIN-WIT-008", "SATIN-BASE-001")

    def reads_observation(self) -> dict:
        """The `reads` group: the accounts and slots loaded, the code of every loaded account that has code
        (the witness holds it whether or not the load brought it, SATIN-WIT-001), and the SALT capacities
        served; no block hash, oracle service answer or hint is in this model's cases."""
        accounts = {h(a): None if x is None else {"nonce": q(x.nonce), "balance": q(x.balance), "codeHash": h(ex.keccak256(x.code))}
                    for a, x in sorted(self.loaded_accounts.items())}
        storage: dict = {}
        for (a, k), v in sorted(self.loaded_slots.items()):
            storage.setdefault(h(a), {})[word(k)] = q(v)
        codes = sorted({h(ex.keccak256(x.code)) for x in self.loaded_accounts.values() if x is not None and x.code})
        self.d.add("reads", f"reads: accounts {len(accounts)}, slots {len(self.loaded_slots)}, codes {len(codes)}, SALT "
                   f"capacities {len(self.served_buckets)}; no block hash, oracle answer or hint",
                   "SATIN-WIT-001", "SATIN-WIT-005", "SATIN-WIT-013")
        return {"accounts": accounts, "storage": storage, "codes": codes, "blockHashes": {},
                "buckets": {q(b): q(c) for b, c in sorted(self.served_buckets.items())}, "oracle": [], "hints": []}

    def hold_to_limits(self, data_size: int, kv: int, growth: int, what: str) -> None:
        """A write of the transaction's own frame held to its limits, in the order data size, KV updates, state
        growth (SATIN-LIM-010), each to the frame's budget first and then to the transaction's limit
        (SATIN-LIM-011). The counts are the write's rises; the transaction's present counts do not hold them yet.
        The frame's budget is what the transaction had left when the frame started (SATIN-LIM-002); an admitted
        hint is on no frame (SATIN-LIM-012)."""
        start = dict(zip((DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP), self.frame_start_counts))
        for kind, rise, used, limit in ((DATA_SIZE_STOP, data_size, self.data_size, TX_DATA_LIMIT),
                                        (KV_UPDATE_STOP, kv, len(self.kv), TX_KV_UPDATE_LIMIT),
                                        (STATE_GROWTH_STOP, growth, self.growth, TX_STATE_GROWTH_LIMIT)):
            if not rise:
                continue
            budget = limit - start[kind]
            net = used - start[kind] - (self.hint_bytes if kind == DATA_SIZE_STOP else 0)
            name = STOP_DIMENSIONS[kind]
            if net + rise > budget:
                self.d.add("limit", f"{what} rises the frame's {name} by {fmt(rise)}, from {fmt(net)} past its budget "
                           f"{fmt(budget)}, what the transaction had left when the frame started: the frame budget is "
                           "crossed, and the stop names it", "SATIN-LIM-002", "SATIN-LIM-004", "SATIN-LIM-010",
                           "SATIN-LIM-011")
                raise LimitStop(kind, budget, f"{what}: its {name} past the frame budget {fmt(budget)}")
            if used + rise > limit:
                self.d.add("limit", f"{what} rises the frame's {name} by {fmt(rise)} to {fmt(net + rise)}, within its "
                           f"budget {fmt(budget)}, and the transaction's from {fmt(used)} to {fmt(used + rise)}, past its "
                           f"limit {fmt(limit)}: the stop names the transaction limit", "SATIN-LIM-005", "SATIN-LIM-010",
                           "SATIN-LIM-011", "SATIN-LIM-012")
                raise LimitStop(kind, limit, f"{what}: the transaction's {name} past its limit {fmt(limit)}")

    def order(self) -> tuple[str, tuple[str, ...]]:
        """Where the order of a call's charges and decisions is stated: the principle of `SATIN-HIST-023`
        from `5fb2688` on, the owner's decision D-58 before it."""
        return ("SATIN-HIST-023", ("SATIN-HIST-023",)) if self.principles else ("D-58", ())

    def charge_regular(self, frame, amount: int, what: str) -> None:
        """A regular charge: compute (SATIN-DET-009), held to a detained frame's spendable part. A charge the
        spendable part cannot pay and the whole regular gas can is the crossing (SATIN-DET-018); one the whole
        cannot pay is an out-of-gas, as without the read (SATIN-DET-020)."""
        spendable = frame.get("spendable")
        if spendable is not None and spendable < amount <= frame["regular"]:
            raise Stopped(self.limit, f"{what}: {fmt(amount)} of regular gas, which the spendable part {fmt(spendable)} "
                                      f"cannot pay and the frame's whole {fmt(frame['regular'])} can")
        if amount > frame["regular"]:
            raise Halt(f"out of gas at {what}: {fmt(amount)} regular gas needed, {fmt(frame['regular'])} left")
        frame["regular"] -= amount
        if spendable is not None:
            frame["spendable"] -= amount
        self.regular_charges += amount
        self.compute += amount

    def draw_regular(self, frame, amount: int) -> None:
        """Regular gas drawn by a forward, or for the part of a state or history charge regular gas pays: not
        compute, and from a detained frame's withheld part first (SATIN-DET-009, SATIN-DET-017)."""
        spendable = frame.get("spendable")
        if spendable is not None:
            frame["spendable"] -= max(0, amount - (frame["regular"] - spendable))
        frame["regular"] -= amount

    def split(self, frame) -> None:
        """SATIN-DET-014: once a limit is set, the frame's spendable part is what the limit leaves the
        transaction, at most its regular gas; applied when a read completes and when a frame starts or resumes."""
        if self.limit is not None:
            frame["spendable"] = min(frame["regular"], max(0, self.limit - self.compute))

    def mark(self, cap: int, what: str) -> None:
        """A volatile read marked at the transaction's present compute: the limit compute + cap, which only goes
        down (SATIN-DET-012)."""
        at, new = self.compute, self.compute + cap
        if self.limit is None or new < self.limit:
            self.limit = new
            self.d.add("gasLedgers", f"{what} is a volatile read, marked at compute {fmt(at)}: the transaction's limit "
                       f"becomes {fmt(at)} + {fmt(cap)} = {fmt(new)}", "SATIN-DET-001", "SATIN-DET-003", "SATIN-DET-012")
        else:
            self.d.add("gasLedgers", f"{what} is a volatile read, marked at compute {fmt(at)}: {fmt(at)} + {fmt(cap)} = "
                       f"{fmt(new)} does not lower the limit {fmt(self.limit)}", "SATIN-DET-001", "SATIN-DET-003",
                       "SATIN-DET-012")

    def charge_state(self, frame, amount: int, legacy: int, what: str) -> None:
        """SATIN-POOL-008: the legacy share from regular gas, then the reservoir, then the spill."""
        if legacy > frame["regular"]:
            raise Halt(f"out of gas paying the legacy share of {what}")
        self.draw_regular(frame, legacy)
        rest = amount - legacy
        r = min(frame["reservoir"], rest)
        frame["reservoir"] -= r
        if rest - r > frame["regular"]:
            raise Halt(f"out of gas paying the state gas of {what}")
        self.draw_regular(frame, rest - r)

    def give_back(self, frame, amount: int) -> None:
        frame["reservoir"] += amount  # SATIN-HIST-012: into the frame's reservoir

    def execute(self, code: bytes, frame, create: bool, ctx=None):
        """Runs one frame. `ctx` is a child frame's context (address, caller, value, calldata); the
        transaction's own frame runs without one."""
        d, tx = self.d, self.tx
        stack: list[int] = []
        mem_words = 0
        memory = bytearray()
        pc = 0
        address = ctx["address"] if ctx else self.address
        caller = ctx["caller"] if ctx else tx.sender
        value_in = ctx["value"] if ctx else tx.value
        calldata = ctx["calldata"] if ctx else (b"" if create else tx.data)
        returndata = b""
        jumpdests = None

        def pop():
            if not stack:
                raise Halt("stack underflow")
            return stack.pop()

        def expand(offset: int, size: int, what: str) -> None:
            nonlocal mem_words, memory
            if size == 0:
                return
            words = (offset + size + 31) // 32
            if words > mem_words:
                cost = memory_cost(words) - memory_cost(mem_words)
                self.charge_regular(frame, cost, f"{what} memory")
                mem_words = words
                memory.extend(b"\x00" * (words * 32 - len(memory)))

        def refuse(access_type: int, what: str):
            """SATIN-MAC-003, -004: a volatile read in a frame whose access is off, refused before any charge."""
            d.add("outcome", f"{what} in a frame whose volatile-data access is off: refused before the opcode charges "
                  f"anything, the frame reverting with VolatileDataAccessDisabled({access_type}) on the "
                  f"{fmt(frame['regular'])} of regular gas it held at the opcode; no read is marked",
                  "SATIN-MAC-003", "SATIN-MAC-004", "SATIN-MAC-005")
            self.probe.setdefault("refused", frame["regular"])
            steps.append(f"{what.split()[0]} refused 0")
            return done("revert", VOLATILE_DATA_ACCESS_DISABLED + access_type.to_bytes(32, "big"))

        def simple(name: str, cost: int, result) -> None:
            self.charge_regular(frame, cost, name)
            stack.append(result % 2**256)
            steps.append(f"{name} {cost}")

        def done(status: str, out: bytes):
            if ctx:
                spent = frame["regular_at_start"] - frame["regular"]
                d.add("gasLedgers", f"the child frame of {h(address)} runs its code: {', '.join(steps) or 'none'}; it "
                      f"spends {fmt(spent)} of its {fmt(frame['regular_at_start'])} regular gas and ends in {status}",
                      "SATIN-POOL-007")
            else:
                d.add("gasLedgers", f"frame opcodes: {', '.join(steps) or 'none'}; regular charges of the frame "
                      f"{fmt(self.regular_charges)}", "SATIN-POOL-007")
            return status, out

        steps = []
        while pc < len(code):
            op = code[pc]
            pc += 1
            if op == 0x00:  # STOP
                steps.append(f"STOP {G_ZERO}")
                break
            if op == 0x5F:  # PUSH0
                self.charge_regular(frame, G_BASE, "PUSH0")
                stack.append(0)
                steps.append(f"PUSH0 {G_BASE}")
            elif 0x60 <= op <= 0x7F:
                n = op - 0x5F
                self.charge_regular(frame, G_VERYLOW, f"PUSH{n}")
                stack.append(int.from_bytes(code[pc:pc + n].ljust(n, b"\x00"), "big"))
                pc += n
                steps.append(f"PUSH{n} {G_VERYLOW}")
            elif op == 0x01:  # ADD
                self.charge_regular(frame, G_VERYLOW, "ADD")
                stack.append((pop() + pop()) % 2**256)
                steps.append(f"ADD {G_VERYLOW}")
            elif op == 0x50:  # POP
                self.charge_regular(frame, G_BASE, "POP")
                pop()
                steps.append(f"POP {G_BASE}")
            elif op == 0x33:  # CALLER
                self.charge_regular(frame, G_BASE, "CALLER")
                stack.append(int.from_bytes(caller, "big"))
                steps.append(f"CALLER {G_BASE}")
            elif op == 0x34:  # CALLVALUE
                self.charge_regular(frame, G_BASE, "CALLVALUE")
                stack.append(value_in)
                steps.append(f"CALLVALUE {G_BASE}")
            elif op == 0x52:  # MSTORE
                offset, value = pop(), pop()
                self.charge_regular(frame, G_VERYLOW, "MSTORE")
                expand(offset, 32, "MSTORE")
                memory[offset:offset + 32] = value.to_bytes(32, "big")
                steps.append(f"MSTORE {G_VERYLOW} + memory to {mem_words} words")
            elif op == 0x54:  # SLOAD
                if ctx and address == ORACLE:
                    key = pop()
                    if frame.get("access_off"):
                        raise Unmodelled("an Oracle read refused")
                    value = self.state.get(ORACLE, Account()).storage.get(key, 0)
                    self.warm_slots.add((ORACLE, key))
                    self.load_slot(ORACLE, key, "the Oracle's SLOAD, which loads the slot before its charge, whatever the "
                                   "charge then does", "SATIN-ORCL-004", "SATIN-WIT-012")
                    if tx.kind != "deposit":
                        raise Unmodelled("an Oracle read that asks the oracle service")
                    d.add("gasLedgers", f"the Oracle's SLOAD of slot {key}, with {fmt(frame['regular'])} of regular gas in "
                          "the frame: the read is made before its charge, the slot loaded and warm, and the read marked; a "
                          "deposit's read asks no oracle service, so the slot's value is pushed", "SATIN-ORCL-002",
                          "SATIN-ORCL-003", "SATIN-ORCL-004", "SATIN-ORCL-005")
                    self.mark(ORACLE_ACCESS_COMPUTE_GAS, f"the Oracle's SLOAD of slot {key}")
                    self.probe.setdefault("oracle-sload", frame["regular"])
                    if frame.get("spendable") is not None:
                        self.probe.setdefault("oracle-sload-room", self.limit - self.compute)
                    d.add("gasLedgers", f"then COLD_SLOAD_COST {fmt(COLD_SLOAD)}, its warm base {WARM_READ} included, as one "
                          "charge: the mark stands whatever the charge does", "SATIN-ORCL-004", "SATIN-DET-003",
                          "SATIN-DET-018")
                    self.charge_regular(frame, COLD_SLOAD, "the Oracle's SLOAD")
                    stack.append(value)
                    self.split(frame)
                    steps.append(f"SLOAD of the Oracle's storage {fmt(COLD_SLOAD)}")
                    continue
                if ctx:
                    raise Unmodelled("an SLOAD in a child frame")
                if frame.get("spendable") is not None:
                    raise Unmodelled("an SLOAD in a detained frame")
                key = pop()
                cold = (address, key) not in self.warm_slots
                cost = COLD_SLOAD if cold else WARM_READ
                self.charge_regular(frame, cost, "SLOAD")
                self.warm_slots.add((address, key))
                self.load_slot(address, key, "SLOAD, once its access is paid", "SATIN-WIT-002", "SATIN-WIT-012")
                stack.append(self.state.get(address, Account()).storage.get(key, 0))
                steps.append(f"SLOAD {'cold' if cold else 'warm'} {fmt(cost)}")
                d.add("gasLedgers", f"SLOAD of slot {key}: {'cold' if cold else 'warm'} {fmt(cost)}", "SATIN-SCHED-003")
            elif op == 0x55:  # SSTORE
                if ctx:
                    raise Unmodelled("an SSTORE in a child frame")
                key, new = pop(), pop()
                steps.append(self.sstore(frame, address, key, new))
            elif 0xA0 <= op <= 0xA4:  # LOGn
                if ctx:
                    raise Unmodelled("a LOG in a child frame")
                n = op - 0xA0
                offset, size = pop(), pop()
                topics = [pop() for _ in range(n)]
                cost = LOG_COST + LOG_TOPIC_COST * n + LOG_DATA_COST * size
                self.charge_regular(frame, cost, f"LOG{n}")
                expand(offset, size, f"LOG{n}")
                payload = bytes(memory[offset:offset + size])
                log_bytes = LOG_BASE_SIZE + LOG_TOPIC_SIZE * n + size
                # The log's bytes pass the limits before its history is charged (SATIN-TAKE-009).
                self.hold_to_limits(log_bytes, 0, 0, f"LOG{n} of {fmt(size)} data bytes")
                history = log_bytes * COST_PER_HISTORY_BYTE
                self.charge_state(frame, history, 0, f"LOG{n}'s history")
                self.history_gas += history
                self.history_bytes += log_bytes
                self.data_size += log_bytes
                self.logs.append((address, [t.to_bytes(32, "big") for t in topics], payload))
                steps.append(f"LOG{n} {fmt(cost)}")
                d.add("gasLedgers", f"LOG{n} of {size} data bytes: regular {LOG_COST} + {LOG_TOPIC_COST} x {n} + "
                      f"{LOG_DATA_COST} x {size} = {fmt(cost)}; history ({LOG_BASE_SIZE} + {LOG_TOPIC_SIZE} x {n} + {size}) x "
                      f"{COST_PER_HISTORY_BYTE} = {fmt(history)}", "SATIN-HIST-002", "SATIN-HIST-006")
                d.add("resources", f"LOG{n} adds {log_bytes} bytes of data size; a log is not a write record",
                      "SATIN-ACCT-001", "SATIN-ACCT-012")
                d.add("receipt", f"LOG{n} from the contract, in execution order", "SATIN-LOG-002")
            elif op in (0xF3, 0xFD):  # RETURN, REVERT
                offset, size = pop(), pop()
                expand(offset, size, "RETURN" if op == 0xF3 else "REVERT")
                out = bytes(memory[offset:offset + size])
                steps.append(("RETURN" if op == 0xF3 else "REVERT") + f" {size} bytes")
                return done("success" if op == 0xF3 else "revert", out)
            elif op == 0xFE:
                steps.append("INVALID")
                raise Halt("INVALID (0xfe)")
            # The inherited opcodes a system contract's dispatcher and decoder use, at their Osaka
            # static gas, which Amsterdam keeps (SATIN-SCHED-002).
            elif op == 0x02:
                simple("MUL", G_LOW, pop() * pop())
            elif op == 0x03:
                a, b = pop(), pop()
                simple("SUB", G_VERYLOW, a - b)
            elif op == 0x04:
                a, b = pop(), pop()
                simple("DIV", G_LOW, a // b if b else 0)
            elif op == 0x10:
                a, b = pop(), pop()
                simple("LT", G_VERYLOW, int(a < b))
            elif op == 0x11:
                a, b = pop(), pop()
                simple("GT", G_VERYLOW, int(a > b))
            elif op == 0x12:
                a, b = pop(), pop()
                simple("SLT", G_VERYLOW, int(to_signed(a) < to_signed(b)))
            elif op == 0x13:
                a, b = pop(), pop()
                simple("SGT", G_VERYLOW, int(to_signed(a) > to_signed(b)))
            elif op == 0x14:
                simple("EQ", G_VERYLOW, int(pop() == pop()))
            elif op == 0x15:
                simple("ISZERO", G_VERYLOW, int(pop() == 0))
            elif op == 0x16:
                simple("AND", G_VERYLOW, pop() & pop())
            elif op == 0x17:
                simple("OR", G_VERYLOW, pop() | pop())
            elif op == 0x18:
                simple("XOR", G_VERYLOW, pop() ^ pop())
            elif op == 0x19:
                simple("NOT", G_VERYLOW, ~pop())
            elif op == 0x1B:
                shift, v = pop(), pop()
                simple("SHL", G_VERYLOW, v << shift if shift < 256 else 0)
            elif op == 0x1C:
                shift, v = pop(), pop()
                simple("SHR", G_VERYLOW, v >> shift if shift < 256 else 0)
            elif op == 0x35:
                i = pop()
                simple("CALLDATALOAD", G_VERYLOW, int.from_bytes(calldata[i:i + 32].ljust(32, b"\x00"), "big") if i < len(calldata) else 0)
            elif op == 0x36:
                simple("CALLDATASIZE", G_BASE, len(calldata))
            elif op == 0x3D:
                simple("RETURNDATASIZE", G_BASE, len(returndata))
            elif op == 0x3E:  # RETURNDATACOPY
                dest, off, size = pop(), pop(), pop()
                words = (size + 31) // 32
                cost = G_VERYLOW + COPY_WORD * words
                self.charge_regular(frame, G_VERYLOW, "RETURNDATACOPY")
                if words:
                    self.charge_regular(frame, COPY_WORD * words, "RETURNDATACOPY's copy")
                expand(dest, size, "RETURNDATACOPY")
                if off + size > len(returndata):
                    raise Halt("RETURNDATACOPY past the return data")
                memory[dest:dest + size] = returndata[off:off + size]
                steps.append(f"RETURNDATACOPY {cost} + memory to {mem_words} words")
            elif op == 0x20:  # KECCAK256
                off, size = pop(), pop()
                words = (size + 31) // 32
                cost = KECCAK_BASE + KECCAK_WORD * words
                self.charge_regular(frame, KECCAK_BASE, "KECCAK256")
                if words:
                    self.charge_regular(frame, KECCAK_WORD * words, "KECCAK256's words")
                expand(off, size, "KECCAK256")
                stack.append(int.from_bytes(ex.keccak256(bytes(memory[off:off + size])), "big"))
                steps.append(f"KECCAK256 {cost} + memory to {mem_words} words")
            elif op == 0x51:  # MLOAD
                off = pop()
                self.charge_regular(frame, G_VERYLOW, "MLOAD")
                expand(off, 32, "MLOAD")
                stack.append(int.from_bytes(memory[off:off + 32], "big"))
                steps.append(f"MLOAD {G_VERYLOW} + memory to {mem_words} words")
            elif op in (0x56, 0x57):  # JUMP, JUMPI
                if jumpdests is None:
                    jumpdests = jump_destinations(code)
                dest = pop()
                cond = pop() if op == 0x57 else 1
                cost = G_MID if op == 0x56 else G_HIGH
                self.charge_regular(frame, cost, "JUMP" if op == 0x56 else "JUMPI")
                steps.append(f"{'JUMP' if op == 0x56 else 'JUMPI'} {cost}")
                if cond:
                    if dest not in jumpdests:
                        raise Halt("a jump to an invalid destination")
                    pc = dest
            elif op == 0x42:  # TIMESTAMP
                if frame.get("access_off"):
                    return refuse(ACCESS_TYPE_TIMESTAMP, "TIMESTAMP")
                self.charge_regular(frame, G_BASE, "TIMESTAMP")
                stack.append(self.env.timestamp)
                steps.append(f"TIMESTAMP {G_BASE}")
                self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, "TIMESTAMP, a read of the block environment, once it completes,")
                self.split(frame)
                d.add("gasLedgers", f"the frame's regular gas {fmt(frame['regular'])} is split: {fmt(frame['spendable'])} "
                      "spendable, what the limit leaves the transaction, and the rest withheld", "SATIN-DET-014")
            elif op == 0x31:  # BALANCE
                who = (pop() % 2**160).to_bytes(20, "big")
                self.probe.setdefault("balance", frame["regular"])
                if self.limit is not None:
                    self.probe.setdefault("balance-room", self.limit - self.compute)
                if frame.get("access_off") and who == self.env.coinbase:
                    return refuse(ACCESS_TYPE_BENEFICIARY, "BALANCE of the block beneficiary")
                self.charge_regular(frame, WARM_READ, "BALANCE's static cost")
                cold = who not in self.warm_accounts
                if cold:
                    if self.reads and COLD_ACCOUNT_SURCHARGE > frame["regular"]:
                        d.add("reads", f"BALANCE's account {h(who)} is not loaded: the regular gas left, "
                              f"{fmt(frame['regular'])}, cannot pay its cold access, and a load gas skipped is not made",
                              "SATIN-WIT-012")
                    self.charge_regular(frame, COLD_ACCOUNT_SURCHARGE, "BALANCE's cold access")
                    self.warm_accounts.add(who)
                if who == self.env.coinbase:
                    raise Unmodelled("a BALANCE of the beneficiary that reads")
                self.load(who, "BALANCE's account, once its access is paid", "SATIN-WIT-002", "SATIN-WIT-012")
                stack.append(self.state.get(who, Account()).balance)
                steps.append(f"BALANCE {fmt(WARM_READ + (COLD_ACCOUNT_SURCHARGE if cold else 0))}")
            elif op == 0x5A:  # GAS
                self.charge_regular(frame, G_BASE, "GAS")
                stack.append(frame["regular"])
                self.probe.setdefault("gas", frame["regular"])
                self.probe.setdefault("gas-reservoir", frame["reservoir"])
                steps.append(f"GAS {G_BASE}")
                d.add("gasLedgers", f"GAS pushes the regular gas the frame has left after its own {G_BASE}, "
                      f"{fmt(frame['regular'])}, and not the reservoir, which holds {fmt(frame['reservoir'])}",
                      "SATIN-POOL-009")
            elif op == 0x5B:
                self.charge_regular(frame, G_JUMPDEST, "JUMPDEST")
                steps.append(f"JUMPDEST {G_JUMPDEST}")
            elif 0x80 <= op <= 0x8F:
                n = op - 0x7F
                if len(stack) < n:
                    raise Halt("stack underflow")
                simple(f"DUP{n}", G_VERYLOW, stack[-n])
            elif 0x90 <= op <= 0x9F:
                n = op - 0x8F
                if len(stack) < n + 1:
                    raise Halt("stack underflow")
                self.charge_regular(frame, G_VERYLOW, f"SWAP{n}")
                stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
                steps.append(f"SWAP{n} {G_VERYLOW}")
            elif op == 0xF1:  # CALL
                gas_req, target_w, value, a_off, a_size, r_off, r_size = [pop() for _ in range(7)]
                target = (target_w % 2**160).to_bytes(20, "big")
                before = self.regular_charges
                self.charge_regular(frame, WARM_READ, "CALL")
                expand(a_off, a_size, "CALL input")
                expand(r_off, r_size, "CALL output")
                if value:
                    self.charge_regular(frame, CALL_VALUE_COST, "the value transfer")
                cold = target not in self.warm_accounts
                if cold:
                    self.charge_regular(frame, COLD_ACCOUNT_SURCHARGE, "the cold access")
                    self.warm_accounts.add(target)
                if ctx:
                    raise Unmodelled("a call below the transaction's own frame, past its regular charges")
                self.load(target, "the CALL's target, once the opcode's access is paid", "SATIN-WIT-002", "SATIN-WIT-008")
                callee = self.state.get(target)
                if frame["reservoir"]:
                    raise Unmodelled("a call from a frame that holds a reservoir")
                opcode_charges = self.regular_charges - before
                new_account = 0
                if value and (callee is None or callee.empty()):
                    if not self.principles:
                        raise Unmodelled("a value call to an account empty under EIP-161")
                    # SATIN-HIST-010 step 2: the new account's state gas, its legacy share first, before the forward.
                    m = self.multiplier(self.salt_bucket(target, None))
                    new_account = ACCOUNT_STATE * m
                    legacy = min(new_account, LEGACY_NEW_ACCOUNT_SHARE)
                    self.charge_state(frame, new_account, legacy, "the new account")
                    self.state_gas += new_account
                    d.add("gasLedgers", f"step 2 of the value CALL to {h(target)}, an account empty under EIP-161, after the "
                          "opcode's regular charges (step 1, below) and before the forward: the new "
                          f"account's state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(new_account)}, its legacy share "
                          f"min({fmt(new_account)}, PRE_FORK_NEW_ACCOUNT_COST {fmt(PRE_FORK_NEW_ACCOUNT_COST)} - 0) = "
                          f"{fmt(legacy)} from regular gas first, then the reservoir, which holds nothing, then the rest "
                          f"{fmt(new_account - legacy)} from regular gas, which the forward is then computed from",
                          "SATIN-HIST-010", "SATIN-STATE-001", "SATIN-STATE-003", "SATIN-STATE-012", "SATIN-POOL-008")
                remaining = frame["regular"]
                self.probe.setdefault("forward", remaining)
                cap = remaining - remaining * GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR
                forward = min(gas_req, cap)
                self.draw_regular(frame, forward)
                self.regular_charges += forward
                child_gas = forward + (CALL_STIPEND if value else 0)
                operand = fmt(gas_req) if gas_req < 2**256 - 1 else "the gas operand 2^256 - 1"
                d.add("gasLedgers", f"CALL to {h(target)} with value {value}: the opcode's own charges {fmt(opcode_charges)} = "
                      f"warm read {WARM_READ}" + (f" + value transfer {fmt(CALL_VALUE_COST)}" if value else "") +
                      (f" + cold surcharge {fmt(COLD_ACCOUNT_SURCHARGE)}" if cold else "") +
                      (" + input memory" if opcode_charges > WARM_READ + (CALL_VALUE_COST if value else 0) +
                       (COLD_ACCOUNT_SURCHARGE if cold else 0) else "") +
                      f"; forward min({operand}, {fmt(remaining)} - {fmt(remaining)} x {GAS_RETAINED_NUMERATOR} / "
                      f"{GAS_RETAINED_DENOMINATOR} = {fmt(cap)}) = {fmt(forward)}"
                      + (f", the child's gas {fmt(forward)} + CALL_STIPEND {CALL_STIPEND} = {fmt(child_gas)}" if value else ""),
                      "SATIN-SCHED-002", "SATIN-SCHED-003", "SATIN-FWD-001", "SATIN-FWD-002", "SATIN-FWD-003",
                      "SATIN-HIST-010", *self.order()[1])
                # The history of the records the start would make, as the state stands now (SATIN-HIST-015):
                # charged by the opcode with its other charges, after the forward (SATIN-HIST-010 step 4) and
                # before the depth gate, interception and the frame start; a start that would make them and
                # does not happen gives it back (D-58). A value the caller cannot fund, and a value to the
                # caller itself, make no record.
                balance = self.state.get(address, Account()).balance
                fundable = value <= balance
                records = [a for a in (address, target)
                           if value and fundable and target != address and ("a", a) not in self.kv and a != tx.sender]
                history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE * len(records)
                if value and not fundable:
                    d.add("gasLedgers", f"the caller's balance {balance} cannot fund the value {value}: as the state stands, "
                          "the start would make no record, so the opcode charges no record history and has none to give "
                          "back", "SATIN-HIST-015", *self.order()[1])
                if history and history > frame["reservoir"] + frame["regular"]:
                    d.add("gasLedgers", f"the opcode charges the history of the {len(records)} records its start would make, "
                          f"{len(records)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(history)}, after the forward: "
                          f"the caller keeps {fmt(frame['regular'])} of regular gas and {fmt(frame['reservoir'])} of reservoir, "
                          "which cannot pay it, so it halts out of gas in the opcode, before the depth gate: no interceptor "
                          "answers, no hint is admitted and no frame starts", "SATIN-HIST-009", "SATIN-HIST-010",
                          "SATIN-ICPT-007", *self.order()[1])
                    raise Halt(f"out of gas paying the history of the start's records, {fmt(history)}, with "
                               f"{fmt(frame['regular'])} regular gas left")
                if history:
                    from_reservoir = min(frame["reservoir"], history)
                    self.charge_state(frame, history, 0, "the start's records")
                    self.history_gas += history
                    self.history_bytes += WRITE_RECORD_SIZE * len(records)
                    whose = " and ".join("the caller's account" if a == address else "the callee's account" for a in records)
                    d.add("gasLedgers", f"the opcode charges the history of the {len(records)} records its start would make "
                          f"({whose}), {len(records)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(history)}, "
                          "with its other charges: after the forward, which it does not reduce, and before the depth gate, "
                          f"interception and the frame start: {fmt(from_reservoir)} from the caller's reservoir, which it "
                          f"draws first, and {fmt(history - from_reservoir)} from its regular gas ({self.order()[0]})",
                          "SATIN-HIST-009", "SATIN-HIST-010", "SATIN-HIST-014", "SATIN-HIST-015", "SATIN-POOL-008",
                          *self.order()[1])
                ok, out, left = self.call(frame, address, target, value, bytes(memory[a_off:a_off + a_size]), child_gas,
                                          records, history, new_account)
                frame["regular"] += left
                self.regular_charges -= left
                self.split(frame)  # the caller resumes (SATIN-DET-014, SATIN-DET-019)
                returndata = out
                if r_size:
                    raise Unmodelled("a call that copies its output")
                stack.append(1 if ok else 0)
                steps.append(f"CALL {fmt(opcode_charges + forward - left)} net")
                d.add("gasLedgers", f"the call returns {fmt(left)} regular gas to its caller; success {int(ok)}, "
                      f"{len(out)} bytes of return data", "SATIN-POOL-012", "SATIN-ICPT-004")
            else:
                raise Unmodelled(f"opcode {op:#x}")
        return done("success", b"")

    def call(self, frame, caller: bytes, target: bytes, value: int, data: bytes, child_gas: int,
             records: list, history: int, new_account: int = 0):
        """A `CALL` from the transaction's own frame, once the opcode's own charges, the forward and
        the history of the start's `records` are made, decided in the order of SATIN-ICPT-007:
        interception, then the frame start. Returns (success, return data, the regular gas the child
        returns)."""
        d = self.d
        # Interception: an interceptor's answer, the sendHint admission and its data-size check.
        if target in INTERCEPTED and data[:4] in INTERCEPTED[target]:
            if not value and target == MEGA_ACCESS_CONTROL and data[:4] == DISABLE_VOLATILE_DATA_ACCESS:
                frame["access_off"] = True
                d.add("outcome", "interception: disableVolatileDataAccess() called without value is answered by the node, "
                      "before the frame start: volatile-data access is off for the calling frame and every frame below "
                      "it, and the answer returns no data", "SATIN-ICPT-001", "SATIN-ICPT-007", "SATIN-MAC-001",
                      "SATIN-MAC-002")
                d.add("gasLedgers", f"the answer charges nothing: the child's {fmt(child_gas)} regular gas returns untouched",
                      "SATIN-ICPT-004", "SATIN-POOL-012")
                return True, b"", child_gas
            if not value:
                raise Unmodelled("an interceptor's own answer")
            d.add("outcome", f"interception: an intercepted method of {h(target)} called with value {value} is answered "
                  "NonZeroTransfer() before any value moves and before the frame start, whether or not the caller can "
                  "fund the value; the method's answer is not made", "SATIN-ICPT-001", "SATIN-ICPT-003", "SATIN-ICPT-007")
            d.add("gasLedgers", f"the answer charges nothing: the child's {fmt(child_gas)} regular gas returns untouched",
                  "SATIN-ICPT-004", "SATIN-POOL-012", *self.order()[1])
            self.give_back_start(frame, records, history, "the answer starts no frame")
            return False, NON_ZERO_TRANSFER, child_gas
        if target == ORACLE and data[:4] == SEND_HINT:
            if child_gas == 0:
                raise Unmodelled("a sendHint call with no gas")
            if self.data_size + len(data) > TX_DATA_LIMIT:
                d.add("outcome", f"interception: the sendHint's {fmt(len(data))} input bytes would take the transaction's "
                      f"data size {fmt(self.data_size)} over TX_DATA_LIMIT {fmt(TX_DATA_LIMIT)}: answered with the data-size "
                      f"stop MegaLimitExceeded(0, {fmt(TX_DATA_LIMIT)}) at admission, before the frame start, whether or not "
                      "the caller can fund the value; nothing forwarded or counted, the caller catches the stop",
                      "SATIN-ORCL-010", "SATIN-ICPT-007", "SATIN-STOP-020", "SATIN-OUT-010")
                d.add("gasLedgers", f"the stop is answered before any frame: the child's {fmt(child_gas)} regular gas returns",
                      "SATIN-POOL-012", "SATIN-LIM-015", *self.order()[1])
                d.add("resources", "the stopped hint counts none of its bytes", "SATIN-ORCL-010", "SATIN-ACCT-002")
                self.give_back_start(frame, records, history, "the stop starts no frame")
                return False, limit_exceeded(0, TX_DATA_LIMIT), child_gas
            self.data_size += len(data)
            self.hint_bytes += len(data)
            if self.principles:
                d.add("resources", f"the sendHint's {fmt(len(data))} input bytes take the transaction's data size from "
                      f"{fmt(self.data_size - len(data))} to {fmt(self.data_size)}, not over TX_DATA_LIMIT "
                      f"{fmt(TX_DATA_LIMIT)}: the data-size check admits it", "SATIN-ORCL-010", "SATIN-LIM-001")
            d.add("resources", f"interception: the sendHint call's gas limit {fmt(child_gas)} is above zero and its frame's "
                  f"volatile-data access is on: admitted, before the frame start; its {fmt(len(data))} input bytes count as "
                  "data size on the transaction, on no frame's budget and with no history gas, and stay counted whatever the "
                  "call then does", "SATIN-ORCL-006", "SATIN-ORCL-009", "SATIN-ICPT-007", "SATIN-ACCT-001", "SATIN-ACCT-002")
        # The frame start: the caller's funds are checked and the value moves (SATIN-LIM-013, -015).
        caller_acct = self.state.setdefault(caller, Account())
        callee = self.state.get(target)
        if value > caller_acct.balance:
            d.add("outcome", f"frame start: the caller's balance {caller_acct.balance} cannot fund the value {value}: the start "
                  "is refused, and the call fails with empty return data, counting nothing and making no record",
                  "SATIN-LIM-015", "SATIN-OUT-010", "SATIN-STOP-020", "SATIN-ICPT-007")
            if history:
                raise Unmodelled("a refused start charged for records")
            d.add("gasLedgers", f"the start is refused: it makes no record and was charged no history; the opcode's regular "
                  f"charges stand, and the child's {fmt(child_gas)} regular gas, the stipend included, returns "
                  f"({'SATIN-HIST-023' if self.principles else 'D-56'})", "SATIN-HIST-015", "SATIN-POOL-012",
                  *self.order()[1])
            if new_account:
                self.give_back(frame, new_account)
                self.state_gas -= new_account
                d.add("gasLedgers", f"the refused start adds no account: the new account's {fmt(new_account)} state gas, its "
                      "legacy share included, is given back into the caller's reservoir, not its regular gas, when the call "
                      "returns", "SATIN-POOL-015", "SATIN-HIST-012", "SATIN-HIST-015")
            return False, b"", child_gas
        if new_account:
            raise Unmodelled("a value call that adds an account")
        if callee is None or not callee.code:
            raise Unmodelled("a call to an account without code")
        if value:
            caller_acct.balance -= value
            callee.balance += value
            for a in records:
                self.kv.add(("a", a))
            self.data_size += WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(caller), pad_address(target)],
                              value.to_bytes(32, "big")))
            d.add("gasLedgers", f"frame start: the value moves and makes the {len(records)} records the opcode charged; "
                  "the start grants the child a history allowance, which enters no gas", "SATIN-HIST-018",
                  "SATIN-ACCT-004", "SATIN-ACCT-005")
            d.add("resources", f"the start's {len(records)} records ({WRITE_RECORD_SIZE} bytes each) and its transfer log "
                  f"({TRANSFER_LOG_SIZE} bytes)", "SATIN-LIM-013", "SATIN-ACCT-002", "SATIN-LOG-006")
        child = {"regular": child_gas, "reservoir": 0, "regular_at_start": child_gas, "reservoir_at_start": 0,
                 "access_off": frame.get("access_off", False)}
        self.split(child)
        if child.get("spendable") is not None:
            self.probe.setdefault("child-room", self.limit - self.compute)
            d.add("gasLedgers", f"the child frame of {h(target)} starts detained: of its {fmt(child_gas)} regular gas, "
                  f"{fmt(child['spendable'])} is spendable, what the limit {fmt(self.limit)} leaves the transaction's compute "
                  f"{fmt(self.compute)}, and the rest withheld", "SATIN-DET-009", "SATIN-DET-014")
        charges = self.regular_charges
        try:
            status, out = self.execute(callee.code, child, False,
                                       ctx={"address": target, "caller": caller, "value": value, "calldata": data})
        except Halt as e:
            status, out = "halt", b""
            d.add("gasLedgers", f"the child frame of {h(target)} halts ({e}): its {fmt(child_gas)} regular gas is consumed",
                  "SATIN-POOL-014", "SATIN-OUT-007")
            if self.limit is not None:
                d.add("gasLedgers", f"what the halting frame burns is not compute: the transaction's compute stays "
                      f"{fmt(self.compute)}", "SATIN-DET-011", "SATIN-DET-020")
        except Stopped as e:
            status, out = "stop", limit_exceeded(DETENTION_STOP, e.limit)
            d.add("outcome", f"the child frame of {h(target)} reaches gas detention's crossing at {e}: the charge is not "
                  f"made and the frame is stopped with MegaLimitExceeded({DETENTION_STOP}, {fmt(e.limit)}), which its "
                  "caller catches", "SATIN-DET-018", "SATIN-STOP-020")
            d.add("gasLedgers", f"what the frame spent before the crossing charge stays spent, and its whole regular gas, "
                  f"{fmt(child['regular'])}, the withheld part included, returns to its caller; the transaction's compute "
                  f"is {fmt(self.compute)}", "SATIN-DET-018", "SATIN-DET-019", "SATIN-POOL-012")
        self.regular_charges = charges
        if status == "success":
            if value or records or history:
                raise Unmodelled("a value call whose child frame succeeds")
            d.add("gasLedgers", f"the child frame of {h(target)} returns {len(out)} bytes and {fmt(child['regular'])} of "
                  "regular gas to its caller", "SATIN-POOL-012", "SATIN-OUT-001")
            return True, out, child["regular"]
        left = child["regular"] if status in ("revert", "stop") else 0
        if value:
            caller_acct.balance += value
            callee.balance -= value
            for a in records:
                self.kv.discard(("a", a))
            self.data_size -= WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE
            self.logs.pop()
            frame["reservoir"] += history
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE * len(records)
            d.add("gasLedgers", f"the failed child discards its start: the value, its records and its transfer log are taken "
                  f"back, and the records' {fmt(history)} history gas is given back into the caller's reservoir",
                  "SATIN-HIST-007", "SATIN-HIST-012", "SATIN-POOL-014", "SATIN-ACCT-011")
        return False, out, left

    def give_back_start(self, frame, records: list, history: int, why: str) -> None:
        """A start that would make records and does not happen gives the history its opcode charged for
        them back into the caller's reservoir (SATIN-HIST-012, D-58)."""
        if not history:
            return
        self.give_back(frame, history)
        self.history_gas -= history
        self.history_bytes -= WRITE_RECORD_SIZE * len(records)
        self.d.add("gasLedgers", f"{why}: the {fmt(history)} history gas the opcode charged for the start's records is given back into the "
                   "caller's reservoir, not its regular gas; there it can pay the caller's later state and history charges, "
                   f"and what is left returns to the sender at the settlement ({self.order()[0]})", "SATIN-HIST-012",
                   "SATIN-POOL-017", *self.order()[1])

    def keyless_call(self, frame):
        """The transaction's own `CALL` to KeylessDeploy that SATIN-ICPT-006 recognizes: steps 1 to 3 of
        the deployment, as far as the refusals of this model's cases."""
        d, tx = self.d, self.tx
        argument = keyless_arguments(tx.data)
        offset = int.from_bytes(tx.data[4:36], "big")
        d.add("outcome", f"the transaction's own CALL to KeylessDeploy carries keylessDeploy's selector, and its arguments meet "
              f"the decoder's conditions (offset {offset}, {len(argument)} bytes of the first argument within the input): "
              "recognized, which is part of interception, before the frame start", "SATIN-ICPT-006", "SATIN-ICPT-007")
        self.charge_regular(frame, KEYLESS_DEPLOY_OVERHEAD_GAS, "KEYLESS_DEPLOY_OVERHEAD_GAS")
        d.add("gasLedgers", f"step 1: KEYLESS_DEPLOY_OVERHEAD_GAS {fmt(KEYLESS_DEPLOY_OVERHEAD_GAS)} regular gas; a refusal "
              "after it reverts the call, and the regular gas it spent stays spent", "SATIN-KEY-004", "SATIN-KEY-005")
        if tx.value:
            d.add("outcome", f"step 2: the call carries value {tx.value}: it reverts with NoEtherTransfer() before any value "
                  "moves and before any frame is built", "SATIN-KEY-005", "SATIN-KEY-018")
            return "revert", NO_ETHER_TRANSFER
        if rlp_decodes_as_list(argument):
            raise Unmodelled("a keyless deployment past step 3's encoding check")
        d.add("outcome", f"step 3: the first argument's {len(argument)} bytes are not the RLP encoding of a transaction: "
              "MalformedEncoding()", "SATIN-KEY-005")
        return "revert", MALFORMED_ENCODING

    def apply_authorizations(self, regular: int, reservoir: int):
        """SATIN-SCHED-008 step 2 and the authorities' records of step 3, for a list that fits and whose
        every entry is accepted."""
        tx, env, d = self.tx, self.env, self.d
        done: set = set()
        for chain_id, target, nonce, authority in tx.authorizations:
            self.load(authority, "an authority the list's simulation loads, the whole list walked, whether or not the "
                      "list is then applied", "SATIN-AUTH-005", "SATIN-WIT-004", "SATIN-WIT-008")
        self.probe.setdefault("list", regular)
        for index, (chain_id, target, nonce, authority) in enumerate(tx.authorizations):
            if chain_id not in (0, env.chain_id) or nonce == MAX_U64:
                raise Unmodelled("an authorization skipped for its chain id or nonce")
            if authority in done or authority == tx.sender:
                raise Unmodelled("a second entry for an authority, or the sender's own")
            acct = self.state.get(authority)
            if acct is not None and acct.code:
                raise Unmodelled("an authority that holds code")
            if (acct.nonce if acct else 0) != nonce:
                raise Unmodelled("an authorization whose nonce does not match")
            done.add(authority)
            charges = []
            if acct is None:
                m = self.multiplier(self.salt_bucket(authority, None))
                new_state = ACCOUNT_STATE * m
                charges.append(("state", new_state))
                self.growth += 1
                d.add("gasLedgers", f"the authority {h(authority)}: the state holds no account at its address, so it is new: "
                      f"new-account state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(new_state)} before the first frame, no "
                      "legacy share", "SATIN-SCHED-008", "SATIN-STATE-011", "SATIN-AUTH-008", "SATIN-POOL-024")
                d.add("resources", "the new authority is one unit of state growth", "SATIN-ACCT-014", "SATIN-AUTH-008")
            else:
                d.add("gasLedgers", f"the authority {h(authority)}: the state holds its leaf (nonce {acct.nonce}, balance "
                      f"{acct.balance}, no code), an existing account whether or not it is empty under EIP-161: no "
                      "new-account state gas", "SATIN-SCHED-008", "SATIN-STATE-011", "SATIN-AUTH-008")
                d.add("resources", "the authority exists, so it is no rise of state growth, empty under EIP-161 though it is",
                      "SATIN-ACCT-015", "SATIN-AUTH-008")
            if not (tx.to == authority and tx.value):
                if ACCOUNT_WRITE > regular:
                    if index or acct is None:
                        raise Unmodelled("an authorization list that runs out of gas after charging")
                    d.add("gasLedgers", f"the first entry's ACCOUNT_WRITE {fmt(ACCOUNT_WRITE)} for the authority "
                          f"{h(authority)} is beyond the {fmt(regular)} of regular gas left: nothing of the list is applied",
                          "SATIN-SCHED-008", "SATIN-SCHED-009", "SATIN-AUTH-015")
                    raise OutOfGasBeforeFrame(f"the first authorization's ACCOUNT_WRITE, {fmt(ACCOUNT_WRITE)}, with "
                                              f"{fmt(regular)} regular gas left")
                self.pre_frame_regular += ACCOUNT_WRITE
                regular -= ACCOUNT_WRITE
                d.add("gasLedgers", f"ACCOUNT_WRITE {fmt(ACCOUNT_WRITE)} regular gas for the authority's first write, which "
                      "the transaction has not paid already", "SATIN-SCHED-003", "SATIN-SCHED-008", "SATIN-TAKE-008",
                      "SATIN-AUTH-015")
            if any(target):
                m = self.multiplier(self.salt_bucket(authority, None))
                indicator = DELEGATION_STATE_BYTES * COST_PER_STATE_BYTE * m
                charges.append(("state", indicator))
                d.add("gasLedgers", f"the delegation indicator: DELEGATION_STATE_BYTES {DELEGATION_STATE_BYTES} x "
                      f"COST_PER_STATE_BYTE {fmt(COST_PER_STATE_BYTE)} x m={m} = {fmt(indicator)} state gas, once, no legacy "
                      "share; not a unit of state growth", "SATIN-AUTH-009", "SATIN-STATE-003", "SATIN-SCHED-008")
            record = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            charges.append(("history", record))
            self.kv.add(("a", authority))
            self.data_size += WRITE_RECORD_SIZE
            self.history_bytes += WRITE_RECORD_SIZE
            d.add("gasLedgers", f"the authority's one write record: {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(record)} "
                  "history gas before the first frame, kept whatever the frame does", "SATIN-HIST-005", "SATIN-SCHED-008",
                  "SATIN-AUTH-016")
            d.add("resources", f"the authority's write record: one KV update, {WRITE_RECORD_SIZE} bytes of data size",
                  "SATIN-AUTH-008", "SATIN-ACCT-005")
            for kind, amount in charges:  # SATIN-POOL-024: the reservoir first, the regular budget for the rest
                r = min(reservoir, amount)
                reservoir -= r
                if amount - r > regular:
                    raise Unmodelled("an authorization whose charges cannot be paid")
                regular -= amount - r
                if kind == "state":
                    self.state_gas += amount
                else:
                    self.history_gas += amount
            if regular < 0:
                raise Unmodelled("an authorization whose charges cannot be paid")
            a = self.state.setdefault(authority, Account())
            a.nonce += 1
            a.code = (b"\xef\x01\x00" + target) if any(target) else b""
            self.warm_accounts.add(authority)
            d.add("state", f"the authority's nonce becomes {a.nonce} and its code the delegation indicator 0xef0100 followed "
                  f"by {h(target)}", "SATIN-AUTH-004")
        return regular, reservoir

    def sstore(self, frame, address: bytes, key: int, new: int) -> str:
        d = self.d
        acct = self.state.setdefault(address, Account())
        present = acct.storage.get(key, 0)
        original = self.original.setdefault((address, key), self.pre.get(address, Account()).storage.get(key, 0))
        if frame.get("spendable") is not None:
            raise Unmodelled("an SSTORE in a detained frame")
        if frame["regular"] <= CALL_STIPEND:
            raise Halt(f"SSTORE with no more than the {fmt(CALL_STIPEND)} stipend left")
        self.load_slot(address, key, "SSTORE, which reads the slot's value", "SATIN-WIT-002")
        cold = (address, key) not in self.warm_slots
        self.warm_slots.add((address, key))
        access = COLD_SSTORE_ACCESS if cold else WARM_READ
        write = 0
        if new != present and present == original:
            write = SSTORE_SET if original == 0 else SSTORE_RESET
        self.charge_regular(frame, access + write, "SSTORE")
        label = f"SSTORE slot {key} {original}->{present}->{new}: {'cold' if cold else 'warm'} access {fmt(access)}"
        rules = ["SATIN-SCHED-003", "SATIN-SCHED-004"] if cold else ["SATIN-SCHED-003"]
        if write:
            label += f" + {'fresh-slot write' if original == 0 else 'reset'} {fmt(write)}"
        # The fresh-slot state charge and its give-back, SATIN-STATE-008, with the legacy share.
        m = None
        if original == 0 and present == 0 and new != 0:
            m = self.multiplier(self.salt_bucket(address, key))
            charge = SLOT_STATE * m
            legacy = min(charge, max(0, LEGACY_SSTORE_SHARE))
            self.charge_state(frame, charge, legacy, "a fresh slot")
            self.state_gas += charge
            self.growth += 1
            label += f"; state gas {fmt(SLOT_STATE)} x m={m} = {fmt(charge)} ({fmt(legacy)} legacy share first)"
            rules += ["SATIN-STATE-001", "SATIN-STATE-002", "SATIN-STATE-008", "SATIN-STATE-012", "SATIN-POOL-008"]
            d.add("resources", f"slot {key} filled from zero: state growth +1", "SATIN-ACCT-016")
        elif original == 0 and present != 0 and new == 0:
            m = self.multiplier(self.salt_bucket(address, key))
            charge = SLOT_STATE * m
            self.give_back(frame, charge)
            self.state_gas -= charge
            self.growth -= 1
            label += f"; state gas {fmt(charge)} given back into the reservoir"
            rules += ["SATIN-STATE-008", "SATIN-HIST-012"]
            d.add("resources", f"slot {key} back to zero: state growth -1", "SATIN-ACCT-016")
        # The refund counter, EIP-2200's transitions at Satin's prices.
        if new != present:
            if original != 0:
                if present == original and new == 0:
                    self.refund += REFUND_CLEARED
                    label += f"; refund +{fmt(REFUND_CLEARED)}"
                elif present != original:
                    if present == 0:
                        self.refund -= REFUND_CLEARED
                    elif new == 0:
                        self.refund += REFUND_CLEARED
            if new == original and present != original:
                bonus = REFUND_RESTORED_FRESH if original == 0 else REFUND_RESTORED_RESET
                self.refund += bonus
                label += f"; refund +{fmt(bonus)} (restored)"
            if self.refund:
                rules.append("SATIN-SCHED-003")
        # The limits on the record, in the order data size, KV updates, state growth (SATIN-TAKE-005).
        record = ("s", address, key)
        was = record in self.kv
        now = new != original
        grew = int(original == 0 and present == 0 and new != 0)
        if (now and not was) or grew:
            self.growth -= grew  # the rise is held to the limits before it is counted
            self.hold_to_limits(WRITE_RECORD_SIZE if now and not was else 0, int(now and not was), grew,
                                f"the SSTORE of slot {key}")
            self.growth += grew
        # The write record and its history, SATIN-ACCT-004 and SATIN-HIST-006.
        if now and not was:
            history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            self.charge_state(frame, history, 0, "the slot's write record")
            self.kv.add(record)
            self.data_size += WRITE_RECORD_SIZE
            self.history_gas += history
            self.history_bytes += WRITE_RECORD_SIZE
            label += f"; write record history {fmt(history)}"
            rules += ["SATIN-HIST-006", "SATIN-ACCT-004"]
            d.add("resources", f"slot {key} differs from its original: one write record, {WRITE_RECORD_SIZE} bytes",
                  "SATIN-ACCT-004", "SATIN-ACCT-012")
        elif was and not now:
            history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            self.give_back(frame, history)
            self.kv.discard(record)
            self.data_size -= WRITE_RECORD_SIZE
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE
            label += f"; write record taken back, {fmt(history)} history given back"
            rules += ["SATIN-HIST-006", "SATIN-ACCT-004"]
            d.add("resources", f"slot {key} written back to its original value: its record is taken back",
                  "SATIN-ACCT-004", "SATIN-ACCT-006")
        if new == 0:
            acct.storage.pop(key, None)
        else:
            acct.storage[key] = new
        d.add("gasLedgers", label, *rules)
        return f"SSTORE {fmt(access + write)}"

    def deposit_code(self, code: bytes, frame, address: bytes) -> None:
        """SATIN-SCHED-011: hashing, state gas and history gas of the deposited code."""
        d = self.d
        words = (len(code) + 31) // 32
        keccak = KECCAK_WORD * words
        self.charge_regular(frame, keccak, "code deposit hashing")
        m = self.multiplier(self.salt_bucket(address, None))
        state = CODE_STATE_PER_BYTE * m * len(code)
        self.charge_state(frame, state, 0, "deposited code")
        history = COST_PER_HISTORY_BYTE * len(code)
        self.charge_state(frame, history, 0, "deposited code's history")
        self.state_gas += state
        self.history_gas += history
        self.history_bytes += len(code)
        self.data_size += len(code)
        self.state[address].code = code
        d.add("gasLedgers", f"code deposit of {len(code)} bytes: hashing {words} words x {KECCAK_WORD} = {keccak}; state "
              f"{CODE_STATE_PER_BYTE} x m={m} x {len(code)} = {fmt(state)}; history {COST_PER_HISTORY_BYTE} x {len(code)} = "
              f"{fmt(history)}", "SATIN-SCHED-011", "SATIN-STATE-003", "SATIN-HIST-002")
        d.add("resources", f"deposited code adds {len(code)} bytes of data size, no state growth of its own",
              "SATIN-ACCT-002", "SATIN-ACCT-013")

    # --- deposits ---

    def run_deposit(self, intrinsic: int, floor: int, regular: int, reservoir: int) -> Result:
        tx, env, d = self.tx, self.env, self.d
        if tx.to is None or tx.to == tx.sender:
            raise Unmodelled("a creating or self-addressed deposit")
        sender = self.state[tx.sender]
        was_empty = self.pre.get(tx.sender) is None or self.pre[tx.sender].empty()
        nonce_before = self.pre.get(tx.sender, Account()).nonce
        sender.balance += tx.mint
        sender.nonce += 1
        caller_state = 0
        if was_empty:
            m = self.multiplier(self.salt_bucket(tx.sender, None))
            caller_state = ACCOUNT_STATE * m
            r = min(reservoir, caller_state)
            reservoir -= r
            if caller_state - r > regular:
                raise Unmodelled("a failed deposit")
            regular -= caller_state - r
            self.growth += 1
            d.add("gasLedgers", f"the caller is empty under EIP-161: its new-account state gas {fmt(ACCOUNT_STATE)} x m={m} = "
                  f"{fmt(caller_state)}, the first charge before the frame", "SATIN-DEP-003", "SATIN-SCHED-008")
            d.add("resources", "the created caller is one unit of state growth", "SATIN-DEP-003", "SATIN-ACCT-014")
        self.state_gas += caller_state
        d.add("state", f"the mint {fmt(tx.mint)} is credited to the sender, its nonce bumped", "SATIN-DEP-004")
        if tx.value:
            raise Unmodelled("a deposit with value")
        code = self.state.get(tx.to, Account()).code
        self.address = tx.to
        self.load(tx.to, "the recipient, at step 4 of the charges before the first frame; a deposit pays no fee and "
                  "reads no L1 block information", "SATIN-SCHED-008", "SATIN-WIT-008")
        frame = {"regular": regular, "reservoir": reservoir, "regular_at_start": regular, "reservoir_at_start": reservoir}
        try:
            status, output = self.execute(code, frame, False)
        except Halt:
            raise Unmodelled("a failed deposit")
        if status != "success":
            raise Unmodelled("a reverting deposit")
        total = intrinsic + self.regular_charges + self.history_gas + self.state_gas
        refund = min(self.refund, total // REFUND_QUOTIENT)
        gas_used = max(total - refund, floor)
        regular_ledger = total - self.state_gas - self.history_gas
        d.add("gasLedgers", f"ledgers: state {fmt(self.state_gas)}, history {fmt(self.history_gas)} (the deposit pays history "
              f"as any transaction; {self.history_bytes} history bytes), regular {fmt(regular_ledger)}, total {fmt(total)}",
              "SATIN-POOL-019", "SATIN-HIST-016", "SATIN-DEP-001", "SATIN-HIST-022")
        d.add("gasLedgers", f"gas used {fmt(gas_used)}, block gas max({fmt(regular_ledger)}, {fmt(floor)})", "SATIN-POOL-018", "SATIN-POOL-020")
        ledgers = {"total": q(total), "regular": q(regular_ledger), "state": q(self.state_gas), "history": q(self.history_gas),
                   "historyBytes": q(self.history_bytes), "refund": q(refund), "floor": q(floor), "gasUsed": q(gas_used),
                   "blockGas": q(max(regular_ledger, floor))}
        resources = {"dataSize": dim(TX_DATA_LIMIT, self.data_size), "kvUpdates": dim(TX_KV_UPDATE_LIMIT, len(self.kv)),
                     "stateGrowth": dim(TX_STATE_GROWTH_LIMIT, self.growth)}
        d.add("resources", f"kept: data size {self.data_size}, {len(self.kv)} KV updates, state growth {self.growth}",
              "SATIN-ACCT-003", "SATIN-LIM-007")
        receipt = {"type": "0x7e", "status": "0x1", "gasUsed": q(gas_used),
                   "logs": [{"address": h(a), "topics": [h(t) for t in ts], "data": h(dt)} for a, ts, dt in self.logs],
                   "depositNonce": q(nonce_before), "depositReceiptVersion": "0x1"}
        d.add("receipt", f"a deposit receipt (the base layer's, type 0x7e): its nonce before the deposit ({nonce_before}) and "
              f"receipt version 1 (D-40); gas used {fmt(gas_used)}, which the deposit does not pay; the mint is not logged",
              "SATIN-BASE-001", "SATIN-POOL-018", "SATIN-DEP-009", "SATIN-LOG-004")
        d.add("outcome", "admitted; the deposit's frame succeeds", "SATIN-DEP-007")
        outcome = {"admission": {"status": "admitted"},
                   "execution": {"status": "success", "output": h(output), "createdAddress": None},
                   "commit": {"status": "committed"}}
        observations = {"outcome": outcome, "state": self.diff(), "receipt": receipt, "gasLedgers": ledgers,
                        "resources": resources, "limit": None}
        if self.reads:
            observations["reads"] = self.reads_observation()
        return Result(observations, d)

    def diff(self) -> dict:
        out = {}
        for a, acct in sorted(self.state.items()):
            before = self.pre.get(a)
            exists = not acct.empty()
            if not exists:
                if before is not None:
                    out[h(a)] = None
                continue
            slots = {}
            for k in sorted(set(acct.storage) | set(before.storage if before else {})):
                was = before.storage.get(k, 0) if before else 0
                now = acct.storage.get(k, 0)
                if was != now:
                    slots[word(k)] = q(now)
            if before is None or (before.nonce, before.balance, before.code) != (acct.nonce, acct.balance, acct.code) or slots:
                out[h(a)] = {"nonce": q(acct.nonce), "balance": q(acct.balance), "code": h(acct.code), "storage": slots}
        return {"accounts": out}


def dim(limit: int, used: int) -> dict:
    return {"limit": q(limit), "net": str(used), "reported": q(max(used, 0))}


def refused(phase: str, reason: str) -> dict:
    return {
        "outcome": {"admission": {"status": "refused", "phase": phase, "reasons": [reason]}, "execution": None,
                    "commit": {"status": "not-committed"}},
        "state": {"accounts": {}},
        "receipt": None,
        "gasLedgers": None,
        "resources": None,
        "limit": None,
    }
