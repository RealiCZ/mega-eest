"""Settlement and the observations: refund, floor, gas used, fees, ledgers, resources, receipt, the state
diff and the limit group; the snapshot a failed first frame returns to; a deposit's run."""

from __future__ import annotations

from .constants import (
    ACCOUNT_STATE, BASE_FEE_VAULT, limit_exceeded, REFUND_QUOTIENT, STOP_DIMENSIONS, TRANSFER_LOG_ADDRESS,
    TRANSFER_LOG_SIZE, TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT, TX_STATE_GROWTH_LIMIT, WRITE_RECORD_SIZE,
)
from .records import Account, dim, fmt, h, Halt, q, Result, Unmodelled, word


class SettlementMixin:
    """Settlement and the observations: refund, floor, gas used, fees, ledgers, resources, receipt, the state"""

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
        if self.detention and self.limit is not None and self.first_frame is not None:
            end = self.first_frame
            withheld = end["regular"] - end["spendable"] if end.get("spendable") is not None else 0
            d.add("gasLedgers", f"the first frame ends holding {fmt(end['regular'])} of regular gas, {fmt(withheld)} of it "
                  "withheld: the withheld part is unspent gas, returned to the sender with the rest of the unspent gas, "
                  f"and is not part of the total {fmt(total)} that caps the refund", "SATIN-DET-016", "SATIN-POOL-017")
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
        if self.pools:
            observations["gasPools"] = self.pools_observation(status, gas_used)
        return Result(observations, d)

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
        if self.detention:
            d.add("gasLedgers", "the deposit is a user's, not system-originated: it is detained after a read of volatile "
                  "data as any transaction is", "SATIN-DET-026", "SATIN-MST-010", "SATIN-DEP-002")
        kept = self.snapshot()  # the mint, the nonce bump and the created caller, which a failed deposit keeps
        try:
            status, output = self.execute(code, frame, False)
        except Halt as e:
            return self.failed_deposit(kept, nonce_before, was_empty, caller_state, str(e))
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

    def failed_deposit(self, kept, nonce_before: int, was_empty: bool, caller_state: int, why: str) -> Result:
        """A deposit whose own frame halts is a failed deposit (SATIN-DEP-004): it keeps its sender's nonce bump
        and mint and applies nothing else, uses its whole gas limit, reported as regular gas, with no state and
        no history gas (SATIN-DEP-005), keeps its body's data size (SATIN-DEP-006), and counts a caller it created
        as one unit of state growth, uncharged (SATIN-ACCT-020). Its gas ledgers are exactly SATIN-DEP-005's, with
        no floor and no refund (decision D-66)."""
        tx, d = self.tx, self.d
        if self.hint_bytes:
            raise Unmodelled("a failed deposit that admitted a hint")
        self.restore(kept)
        body = self.data_size
        d.add("outcome", f"the deposit's own frame halts ({why}): a failed deposit, which keeps its sender's nonce bump and "
              "its mint and applies nothing else; it is committed and reported with no execution (D-40)", "SATIN-DEP-004",
              "SATIN-TAKE-012")
        self.kv = set()
        self.logs = []
        self.state_gas = self.history_gas = 0
        self.history_bytes = body
        d.add("gasLedgers", f"it uses its whole gas limit, {fmt(tx.gas_limit)}, the reservoir included, reported as regular "
              f"gas, with no state gas and no history gas: the caller's {fmt(caller_state)} of state gas, paid before the "
              "frame, is not reported as state gas, and nothing returns to the sender", "SATIN-DEP-005", "SATIN-DEP-006",
              "SATIN-POOL-017", "SATIN-TAKE-012")
        d.add("gasLedgers", f"its ledgers are exactly those: no settlement applies a floor or a refund, so both are 0 (D-66), "
              f"and the block counts max(regular {fmt(tx.gas_limit)}, floor 0) = {fmt(tx.gas_limit)}, its whole gas limit",
              "SATIN-DEP-005", "SATIN-POOL-020")
        d.add("resources", f"it keeps the data size of its body and calldata, {body} bytes, the history bytes it reports; "
              f"no write record; state growth {self.growth}" + (", the caller it created, counted and not charged"
                                                                  if was_empty else ""),
              "SATIN-DEP-006", "SATIN-ACCT-020", "SATIN-HIST-022", "SATIN-TAKE-012")
        gas = tx.gas_limit
        ledgers = {"total": q(gas), "regular": q(gas), "state": q(0), "history": q(0), "historyBytes": q(body),
                   "refund": q(0), "floor": q(0), "gasUsed": q(gas), "blockGas": q(gas)}
        resources = {"dataSize": dim(TX_DATA_LIMIT, body), "kvUpdates": dim(TX_KV_UPDATE_LIMIT, 0),
                     "stateGrowth": dim(TX_STATE_GROWTH_LIMIT, self.growth)}
        receipt = {"type": "0x7e", "status": "0x0", "gasUsed": q(gas), "logs": [],
                   "depositNonce": q(nonce_before), "depositReceiptVersion": "0x1"}
        d.add("receipt", f"a failed deposit's receipt: status 0x0, gas used {fmt(gas)}, no logs, its nonce before the deposit "
              f"({nonce_before}) and receipt version 1", "SATIN-DEP-004", "SATIN-DEP-009", "SATIN-POOL-018")
        outcome = {"admission": {"status": "failed-deposit"}, "execution": None, "commit": {"status": "committed"}}
        observations = {"outcome": outcome, "state": self.diff(), "receipt": receipt, "gasLedgers": ledgers,
                        "resources": resources, "limit": None}
        if self.reads or self.pools:
            raise Unmodelled("the reads or the pools of a failed deposit")
        return Result(observations, d)

    def diff(self) -> dict:
        out = {}
        for a in sorted(self.destroyed):
            if self.destruction and self.state[a].balance:
                self.d.add("state", f"{h(a)}, marked, is removed at the transaction's end with the {self.state[a].balance} "
                           "wei it holds, which no account receives and no log records; the removal takes no record and "
                           "nothing of the code back again", "SATIN-SD-015", "SATIN-LOG-005")
        for a, acct in sorted(self.state.items()):
            before = self.pre.get(a)
            exists = not acct.empty() and a not in self.destroyed  # a marked account is deleted at the end (EIP-6780)
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
