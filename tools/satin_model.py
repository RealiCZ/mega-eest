#!/usr/bin/env python3
"""A small executable model of Satin's transaction rules, for deriving expected values.

This is the independent evidence behind the vertical slice's expectations: it restates, from the
specification at `22a5f4b` (`specs/satin-22a5f4b`), the arithmetic a `state-transition` case's
observations follow, for the narrow class of transactions the slice uses:

- one frame (the transaction's own): the opcodes `STOP`, `ADD`, `POP`, `PUSH0`..`PUSH32`,
  `CALLER`, `CALLVALUE`, `MSTORE`, `SLOAD`, `SSTORE`, `LOG0`..`LOG4`, `RETURN`, `REVERT` and
  `INVALID`; no call, creation opcode, self-destruct or volatile read;
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
SLOT_STATE = 97_920  # SATIN-STATE-003: 64 bytes
ACCOUNT_STATE = 183_600  # SATIN-STATE-003: 120 bytes
CODE_STATE_PER_BYTE = 1_530  # SATIN-STATE-003
LEGACY_SSTORE_SHARE = 20_000 - SSTORE_SET  # SATIN-STATE-012: PRE_FORK_SSTORE_SET_COST - SSTORE_WRITE_COST
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
REFUND_QUOTIENT = 5  # EIP-3529, kept by SATIN-POOL-018
MIN_BUCKET_SIZE = 256  # SATIN-STATE-002
TX_DATA_LIMIT = 13_107_200  # SATIN-LIM-001
TX_KV_UPDATE_LIMIT = 500_000
TX_STATE_GROWTH_LIMIT = 1_000

TRANSFER_LOG_ADDRESS = bytes.fromhex("ff" * 19 + "fe")  # SATIN-LOG-001
TRANSFER_TOPIC = bytes.fromhex("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

BASE_FEE_VAULT = bytes.fromhex("4200000000000000000000000000000000000019")
KECCAK_EMPTY = ex.keccak256(b"")


class Unmodelled(Exception):
    """The case uses something the model does not restate."""


class Halt(Exception):
    """An exceptional halt of the transaction's own frame."""


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


@dataclass
class Env:
    chain_id: int
    coinbase: bytes
    base_fee: int
    block_gas_limit: int
    buckets: dict[int, int]  # bucket id -> capacity (complete: unlisted buckets are minimal)


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

    def __init__(self, env: Env, pre: dict[bytes, Account], tx: Tx, salt_bucket):
        self.env, self.pre, self.tx = env, pre, tx
        self.salt_bucket = salt_bucket  # (address, slot or None) -> bucket id
        self.d = Derivation()

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
            return ("validation", "gas-limit-exceeds-block", "SATIN-BASE-002",
                    f"gas limit {fmt(tx.gas_limit)} > the block's gas limit {fmt(env.block_gas_limit)}")
        if sender.code:
            return ("validation", "sender-has-code", "SATIN-VAL-007",
                    "the sender's account has code (EIP-3607, a base-layer check)")
        if tx.nonce < sender.nonce:
            return ("validation", "nonce-too-low", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} < account nonce {sender.nonce} (a base-layer check)")
        if tx.nonce > sender.nonce:
            return ("validation", "nonce-too-high", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} > account nonce {sender.nonce} (a base-layer check)")
        if tx.ty == 2 and tx.max_priority > tx.max_fee:
            return ("validation", "priority-fee-above-fee-cap", "SATIN-VAL-007",
                    "max priority fee above max fee (a base-layer check)")
        cap = tx.max_fee if tx.ty == 2 else tx.gas_price
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
        floor = floor_base + FLOOR_PER_BYTE * (len(data) + al_bytes)
        body_bytes = TX_BODY_SIZE + len(data) + al_bytes
        body_history = body_bytes * COST_PER_HISTORY_BYTE

        refusal = self.validate(intrinsic, floor, body_history)
        if refusal:
            phase, reason, rule, why = refusal
            d.add("outcome", f"refused at {phase}: {why}", rule)
            return Result(refused(phase, reason), d)

        d.add("gasLedgers", f"intrinsic regular gas = {' + '.join(parts)} = {fmt(intrinsic)}", "SATIN-SCHED-006")
        d.add("gasLedgers", f"floor = base {fmt(floor_base)} + {FLOOR_PER_BYTE} x {len(data) + al_bytes} calldata and "
              f"access-list bytes = {fmt(floor)}", "SATIN-SCHED-005")
        d.add("gasLedgers", f"body = TX_BODY_SIZE {TX_BODY_SIZE} + {len(data)} calldata bytes + {al_bytes} access-list "
              f"bytes = {body_bytes} bytes; its history gas {body_bytes} x {COST_PER_HISTORY_BYTE} = {fmt(body_history)}",
              "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004")
        d.add("resources", f"data size starts at the body's {body_bytes} bytes; its five fixed records are not KV updates",
              "SATIN-ACCT-002", "SATIN-HIST-003")

        self.state: dict[bytes, Account] = {a: Account(x.nonce, x.balance, x.code, dict(x.storage)) for a, x in self.pre.items()}
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
        d.add("gasLedgers", f"body history {fmt(body_history)}: {fmt(from_res)} from the reservoir, "
              f"{fmt(body_history - from_res)} from the regular budget", "SATIN-POOL-006")
        self.regular_charges = 0  # regular charges made by the frame

        sender_acct = self.state.setdefault(tx.sender, Account())
        if tx.kind == "deposit":
            return self.run_deposit(intrinsic, floor, regular, reservoir)

        # Validation's changes to the sender: nonce of a call, the fee (SATIN-ACCT-008).
        price = self.effective_price()
        sender_acct.balance -= tx.gas_limit * price
        if not create:
            sender_acct.nonce += 1

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
            m = bucket_multiplier(env, self.salt_bucket(recipient, None))
            pre_frame_state = ACCOUNT_STATE * m
            d.add("gasLedgers", f"{'created' if create else 'new'}-account state gas {fmt(ACCOUNT_STATE)} x m={m} = "
                  f"{fmt(pre_frame_state)} at step 4, no legacy share", "SATIN-SCHED-008", "SATIN-STATE-001",
                  "SATIN-STATE-003", "SATIN-POOL-024")
        for amount in (pre_frame_history, pre_frame_state):
            r = min(reservoir, amount)
            reservoir -= r
            if amount - r > regular:
                raise Unmodelled("a transaction that cannot pay a charge before its first frame")
            regular -= amount - r

        # The frame starts: its records and transfer log (SATIN-LIM-013, SATIN-ACCT-005, SATIN-LOG-001).
        if transfer:
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

        code = data if create else self.state.get(recipient, Account()).code
        self.address = recipient
        frame = {"regular": regular, "reservoir": reservoir, "regular_at_start": regular, "reservoir_at_start": reservoir}
        snapshot = self.snapshot()
        status, output = "success", b""
        try:
            status, output = self.execute(code, frame, create)
        except Halt as e:
            status = "halt"
            d.add("outcome", f"the frame halts: {e}", "SATIN-OUT-007")

        if status == "success" and create:
            self.deposit_code(output, frame, recipient)

        if status == "halt":
            # SATIN-POOL-014: the halting frame's reservoir becomes what it received, its regular gas
            # is consumed; its records, logs, state and storage are taken back. The start's record
            # and the created account's state gas: the part the reservoir paid returns (POOL-015,
            # HIST-005); here no reservoir paid them unless the case has one.
            self.restore(snapshot)
            spent_regular = tx.gas_limit - frame["reservoir_at_start"] - (pre_frame_history + pre_frame_state if reservoir else 0)
            self.undo_start(transfer, create, recipient, new_account, pre_frame_history, pre_frame_state)
            reservoir_left = frame["reservoir_at_start"] + (pre_frame_history + pre_frame_state if frame["reservoir_at_start"] else 0)
            if frame["reservoir_at_start"] and (pre_frame_history or pre_frame_state):
                raise Unmodelled("a halt after start charges the reservoir paid")
            total = tx.gas_limit - frame["reservoir_at_start"]
            d.add("gasLedgers", f"halt: every regular gas the frame held is consumed, the reservoir {fmt(frame['reservoir_at_start'])} "
                  f"returns; total = gas limit {fmt(tx.gas_limit)} - {fmt(frame['reservoir_at_start'])} = {fmt(total)}",
                  "SATIN-POOL-014", "SATIN-POOL-017")
            del spent_regular, reservoir_left
            self.refund = 0
            execution = {"status": "halt", "output": "0x", "createdAddress": None}
        elif status == "revert":
            self.restore(snapshot)
            self.undo_start(transfer, create, recipient, new_account, pre_frame_history, pre_frame_state)
            total = intrinsic + self.regular_charges + self.history_gas + self.state_gas
            d.add("gasLedgers", "revert: the frame's state and history charges, and the first frame's start record and "
                  "recipient or created-account state gas, are given back into the reservoir and return to the sender; its "
                  f"regular charges {fmt(self.regular_charges)} stay spent", "SATIN-POOL-014", "SATIN-POOL-015",
                  "SATIN-HIST-005", "SATIN-POOL-017")
            self.refund = 0
            execution = {"status": "revert", "output": h(output), "createdAddress": None}
        else:
            total = intrinsic + self.regular_charges + self.history_gas + self.state_gas
            # A creation's output is what its initcode returned: the code it deposited.
            execution = {"status": "success", "output": h(output), "createdAddress": h(recipient) if create else None}

        # Settlement: refund, floor, gas used (SATIN-POOL-018, SATIN-POOL-020).
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
                  f"{fmt(gas_used)} x {fmt(env.base_fee)}, the beneficiary {fmt(gas_used)} x {fmt(price - env.base_fee)}",
                  "SATIN-BASE-001")

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
        elif status == "revert":
            d.add("outcome", "admitted; the frame reverts with its REVERT data", "SATIN-OUT-001")
        return Result({"outcome": outcome, "state": self.diff(), "receipt": receipt, "gasLedgers": ledgers,
                       "resources": resources, "limit": None}, d)

    def effective_price(self) -> int:
        tx = self.tx
        if tx.ty == 2:
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

    def charge_regular(self, frame, amount: int, what: str) -> None:
        if amount > frame["regular"]:
            raise Halt(f"out of gas at {what}: {fmt(amount)} regular gas needed, {fmt(frame['regular'])} left")
        frame["regular"] -= amount
        self.regular_charges += amount

    def charge_state(self, frame, amount: int, legacy: int, what: str) -> None:
        """SATIN-POOL-008: the legacy share from regular gas, then the reservoir, then the spill."""
        if legacy > frame["regular"]:
            raise Halt(f"out of gas paying the legacy share of {what}")
        frame["regular"] -= legacy
        rest = amount - legacy
        r = min(frame["reservoir"], rest)
        frame["reservoir"] -= r
        if rest - r > frame["regular"]:
            raise Halt(f"out of gas paying the state gas of {what}")
        frame["regular"] -= rest - r

    def give_back(self, frame, amount: int) -> None:
        frame["reservoir"] += amount  # SATIN-HIST-012: into the frame's reservoir

    def execute(self, code: bytes, frame, create: bool):
        d, tx = self.d, self.tx
        stack: list[int] = []
        mem_words = 0
        memory = bytearray()
        pc = 0
        address = self.address

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

        steps = []
        while pc < len(code):
            op = code[pc]
            pc += 1
            if op == 0x00:  # STOP
                steps.append("STOP 0")
                break
            if op == 0x5F:  # PUSH0
                self.charge_regular(frame, 2, "PUSH0")
                stack.append(0)
                steps.append("PUSH0 2")
            elif 0x60 <= op <= 0x7F:
                n = op - 0x5F
                self.charge_regular(frame, 3, f"PUSH{n}")
                stack.append(int.from_bytes(code[pc:pc + n].ljust(n, b"\x00"), "big"))
                pc += n
                steps.append(f"PUSH{n} 3")
            elif op == 0x01:  # ADD
                self.charge_regular(frame, 3, "ADD")
                stack.append((pop() + pop()) % 2**256)
                steps.append("ADD 3")
            elif op == 0x50:  # POP
                self.charge_regular(frame, 2, "POP")
                pop()
                steps.append("POP 2")
            elif op == 0x33:  # CALLER
                self.charge_regular(frame, 2, "CALLER")
                stack.append(int.from_bytes(tx.sender, "big"))
                steps.append("CALLER 2")
            elif op == 0x34:  # CALLVALUE
                self.charge_regular(frame, 2, "CALLVALUE")
                stack.append(tx.value)
                steps.append("CALLVALUE 2")
            elif op == 0x52:  # MSTORE
                offset, value = pop(), pop()
                self.charge_regular(frame, 3, "MSTORE")
                expand(offset, 32, "MSTORE")
                memory[offset:offset + 32] = value.to_bytes(32, "big")
                steps.append(f"MSTORE 3 + memory to {mem_words} words")
            elif op == 0x54:  # SLOAD
                key = pop()
                cold = (address, key) not in self.warm_slots
                cost = COLD_SLOAD if cold else WARM_READ
                self.charge_regular(frame, cost, "SLOAD")
                self.warm_slots.add((address, key))
                stack.append(self.state.get(address, Account()).storage.get(key, 0))
                steps.append(f"SLOAD {'cold' if cold else 'warm'} {fmt(cost)}")
                d.add("gasLedgers", f"SLOAD of slot {key}: {'cold' if cold else 'warm'} {fmt(cost)}", "SATIN-SCHED-003")
            elif op == 0x55:  # SSTORE
                key, new = pop(), pop()
                steps.append(self.sstore(frame, address, key, new))
            elif 0xA0 <= op <= 0xA4:  # LOGn
                n = op - 0xA0
                offset, size = pop(), pop()
                topics = [pop() for _ in range(n)]
                cost = LOG_COST + LOG_TOPIC_COST * n + LOG_DATA_COST * size
                self.charge_regular(frame, cost, f"LOG{n}")
                expand(offset, size, f"LOG{n}")
                payload = bytes(memory[offset:offset + size])
                log_bytes = LOG_BASE_SIZE + LOG_TOPIC_SIZE * n + size
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
                d.add("gasLedgers", f"frame opcodes: {', '.join(steps)}; regular charges of the frame {fmt(self.regular_charges)}",
                      "SATIN-POOL-007")
                return ("success" if op == 0xF3 else "revert"), out
            elif op == 0xFE:
                steps.append("INVALID")
                raise Halt("INVALID (0xfe)")
            else:
                raise Unmodelled(f"opcode {op:#x}")
        d.add("gasLedgers", f"frame opcodes: {', '.join(steps) or 'none'}; regular charges of the frame "
              f"{fmt(self.regular_charges)}", "SATIN-POOL-007")
        return "success", b""

    def sstore(self, frame, address: bytes, key: int, new: int) -> str:
        d = self.d
        acct = self.state.setdefault(address, Account())
        present = acct.storage.get(key, 0)
        original = self.original.setdefault((address, key), self.pre.get(address, Account()).storage.get(key, 0))
        if frame["regular"] <= CALL_STIPEND:
            raise Halt("SSTORE with no more than the 2,300 stipend left")
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
            m = bucket_multiplier(self.env, self.salt_bucket(address, key))
            charge = SLOT_STATE * m
            legacy = min(charge, max(0, LEGACY_SSTORE_SHARE))
            self.charge_state(frame, charge, legacy, "a fresh slot")
            self.state_gas += charge
            self.growth += 1
            label += f"; state gas {fmt(SLOT_STATE)} x m={m} = {fmt(charge)} ({fmt(legacy)} legacy share first)"
            rules += ["SATIN-STATE-001", "SATIN-STATE-002", "SATIN-STATE-008", "SATIN-STATE-012", "SATIN-POOL-008"]
            d.add("resources", f"slot {key} filled from zero: state growth +1", "SATIN-ACCT-016")
        elif original == 0 and present != 0 and new == 0:
            m = bucket_multiplier(self.env, self.salt_bucket(address, key))
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
        # The write record and its history, SATIN-ACCT-004 and SATIN-HIST-006.
        record = ("s", address, key)
        was = record in self.kv
        now = new != original
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
        m = bucket_multiplier(self.env, self.salt_bucket(address, None))
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
            m = bucket_multiplier(env, self.salt_bucket(tx.sender, None))
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
              f"as any transaction), regular {fmt(regular_ledger)}, total {fmt(total)}", "SATIN-POOL-019", "SATIN-HIST-016", "SATIN-DEP-001")
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
        d.add("receipt", f"a deposit receipt: its nonce before the deposit ({nonce_before}) and receipt version 1; the mint is not logged",
              "SATIN-LOG-004")
        d.add("outcome", "admitted; the deposit's frame succeeds", "SATIN-DEP-007")
        outcome = {"admission": {"status": "admitted"},
                   "execution": {"status": "success", "output": h(output), "createdAddress": None},
                   "commit": {"status": "committed"}}
        return Result({"outcome": outcome, "state": self.diff(), "receipt": receipt, "gasLedgers": ledgers,
                       "resources": resources, "limit": None}, d)

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
