"""A call from the transaction's own frame, decided in the order of `SATIN-ICPT-007`: interception, then the
frame start, the child frame and what it returns (`SATIN-POOL-012`)."""

from __future__ import annotations

from .constants import (
    DETENTION_STOP, DISABLE_VOLATILE_DATA_ACCESS, INTERCEPTED, limit_exceeded, MEGA_ACCESS_CONTROL,
    NON_ZERO_TRANSFER, ORACLE, SEND_HINT, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC,
    TX_DATA_LIMIT, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, Halt, pad_address, Stopped, Unmodelled


class CallsMixin:
    """A call from the transaction's own frame, decided in the order of `SATIN-ICPT-007`: interception, then the"""

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
