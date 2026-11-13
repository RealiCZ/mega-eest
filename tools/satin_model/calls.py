"""A `CALL`, decided in the order of `SATIN-ICPT-007`: interception, then the frame start, the child frame and
what it returns (`SATIN-POOL-012`), the records a value start makes and takes back (`SATIN-ACCT-006`)."""

from __future__ import annotations

from .constants import (
    COST_PER_HISTORY_BYTE, DISABLE_VOLATILE_DATA_ACCESS, INTERCEPTED, KEYLESS_DEPLOY, KEYLESS_DEPLOY_CALL, KEYLESS_ERRORS,
    limit_exceeded, MEGA_ACCESS_CONTROL, NON_ZERO_TRANSFER, ORACLE, SEND_HINT, SYSTEM_CONTRACTS, TRANSFER_LOG_ADDRESS,
    TRANSFER_LOG_SIZE, TRANSFER_TOPIC,
    TX_DATA_LIMIT, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, pad_address, Unmodelled


def records_of(n: int) -> str:
    return f"{n} record" + ("" if n == 1 else "s")


class CallsMixin:
    """A `CALL`, decided in the order of `SATIN-ICPT-007`: interception, then the frame start, the child frame and"""

    def call(self, frame, caller: bytes, target: bytes, value: int, data: bytes, child_gas: int,
             records: list, history: int, new_account: int = 0, share: int = 0, code: bytes | None = None):
        """A `CALL`, once the opcode's own charges, the forward, the history of the start's `records` and
        the child's reservoir `share` are made, decided in the order of SATIN-ICPT-007: interception, then
        the frame start. A start answered without a frame returns the share untouched (SATIN-POOL-012).
        Returns (success, return data, the regular gas the child returns)."""
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
                frame["reservoir"] += share
                return True, b"", child_gas
            if not value:
                raise Unmodelled("an interceptor's own answer")
            d.add("outcome", f"interception: an intercepted method of {h(target)} called with value {value} is answered "
                  "NonZeroTransfer() before any value moves and before the frame start, whether or not the caller can "
                  "fund the value; the method's answer is not made", "SATIN-ICPT-001", "SATIN-ICPT-003", "SATIN-ICPT-007")
            d.add("gasLedgers", f"the answer charges nothing: the child's {fmt(child_gas)} regular gas returns untouched",
                  "SATIN-ICPT-004", "SATIN-POOL-012", *self.order()[1])
            frame["reservoir"] += share
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
                frame["reservoir"] += share
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
            frame["reservoir"] += share
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
        if callee is None or not callee.code:
            return self.codeless_start(frame, caller, target, value, child_gas, records, history, new_account, share)
        if new_account:
            raise Unmodelled("a value call that adds an account with code")
        name = f"the child frame of {h(target)}"
        child = self.new_child(frame, child_gas, share, allowance=bool(value))
        snap = self.frame_snapshot()
        takes = []
        if value:
            caller_acct.balance -= value
            callee.balance += value
            for a in records:
                self.kv.add(("a", a))
            # SATIN-ACCT-004, -006: a transfer that returns an account to what the transaction loaded takes its record
            # back in the frame it starts; its history comes back to the caller once that frame returned (HIST-009).
            takes = [a for a in (caller, target)
                     if a not in records and a != self.tx.sender and ("a", a) in self.kv and self.as_loaded(a)]
            for a in takes:
                self.kv.discard(("a", a))
            self.data_size += WRITE_RECORD_SIZE * (len(records) - len(takes)) + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(caller), pad_address(target)],
                              value.to_bytes(32, "big")))
            if takes:
                whose = " and ".join("the caller's account" if a == caller else "the callee's account" for a in takes)
                d.add("resources", f"frame start: the value moves and returns {whose} to what the transaction loaded, so "
                      f"the start takes {records_of(len(takes))} back and makes {len(records)}: on the started frame "
                      f"{-len(takes) + len(records):+} KV updates and {-WRITE_RECORD_SIZE * len(takes) + WRITE_RECORD_SIZE * len(records):+} "
                      f"bytes of data size for the records, and +{TRANSFER_LOG_SIZE} for its transfer log",
                      "SATIN-ACCT-004", "SATIN-ACCT-006", "SATIN-LIM-013", "SATIN-LOG-006", "SATIN-TAKE-006")
                d.add("gasLedgers", "the start grants the child a history allowance, which enters no gas; the price of "
                      "the records it takes back is given to the caller once the started frame returned with its start "
                      "kept", "SATIN-HIST-018", "SATIN-HIST-009", "SATIN-HIST-007")
            else:
                d.add("gasLedgers", f"frame start: the value moves and makes the {len(records)} records the opcode charged; "
                      "the start grants the child a history allowance, which enters no gas", "SATIN-HIST-018",
                      "SATIN-ACCT-004", "SATIN-ACCT-005")
                d.add("resources", f"the start's {len(records)} records ({WRITE_RECORD_SIZE} bytes each) and its transfer log "
                      f"({TRANSFER_LOG_SIZE} bytes)", "SATIN-LIM-013", "SATIN-ACCT-002", "SATIN-LOG-006")
        child["name"] = name
        crossing = self.start_crossing(child)
        if crossing:
            if takes or not value:
                raise Unmodelled("a start with code that crosses a limit and takes records back")
            kind, crossed, which, rises = crossing
            d.add("outcome", f"the start of the value CALL to {h(target)} is decided once its value moved, and is held to "
                  f"what it kept, {records_of(len(records))} and a transfer log, {fmt(rises[0])} bytes of data size, "
                  f"{rises[1]} KV updates and {rises[2]} of state growth on the started frame, first to that frame's budget "
                  f"and then to the transaction's limit: it crosses {which}, so the frame is stopped with "
                  f"MegaLimitExceeded({kind}, {fmt(crossed)}) before it runs an instruction, and what its start moved is "
                  "reverted with it: the value, the records and the transfer log", "SATIN-LIM-010", "SATIN-LIM-011",
                  "SATIN-LIM-013", "SATIN-STOP-013", "SATIN-STOP-018", *self.kind_rules())
            self.frame_restore(snap)
            self.caught(frame)
            frame["reservoir"] += share
            self.give_back(frame, history)
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE * len(records)
            d.add("gasLedgers", f"the stopped frame ran nothing: its {fmt(child_gas)} of regular gas, the forward and the "
                  f"stipend, returns to the caller untouched, with its reservoir share; the {fmt(history)} of history the "
                  "opcode charged for the start's records is given back into the caller's reservoir when the stopped "
                  "frame returns", "SATIN-POOL-012", "SATIN-HIST-014", "SATIN-HIST-012", "SATIN-STOP-005")
            return False, limit_exceeded(kind, crossed), child_gas
        keyless = target == KEYLESS_DEPLOY and data[:4] == KEYLESS_DEPLOY_CALL
        if keyless:
            d.add("outcome", "a keylessDeploy call a contract makes is not recognized, the transaction's own frame alone "
                  "being: it runs KeylessDeploy's bytecode, which reverts with " + ("empty data, the method not being "
                  "payable" if value else "NotIntercepted()"), "SATIN-KEY-003", "SATIN-ICPT-006")
        status, out = self.run_child(child, callee.code if code is None else code,
                                     {"address": target, "caller": caller, "value": value, "calldata": data}, name)
        if keyless and (status, out) != ("revert", b"" if value else KEYLESS_ERRORS["NotIntercepted()"]):
            raise Unmodelled("KeylessDeploy's bytecode answering a contract's call otherwise than SATIN-KEY-003 states")
        if status == "success":
            d.add("gasLedgers", f"the child frame of {h(target)} returns {len(out)} bytes and {fmt(child['regular'])} of "
                  "regular gas to its caller", "SATIN-POOL-012", "SATIN-OUT-001")
            left = self.end_child(frame, child, status, snap, name)
            if takes:
                amount = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE * len(takes)
                self.give_back(frame, amount)
                self.history_gas -= amount
                self.history_bytes -= WRITE_RECORD_SIZE * len(takes)
                d.add("gasLedgers", f"the started frame returned with its start kept: the price of the "
                      f"{records_of(len(takes))} the start took back, {len(takes)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(amount)}, is "
                      "given to the caller into its reservoir, after the child's reservoir joined it, now "
                      f"{fmt(frame['reservoir'])}; the regular gas paid for those records stays spent", "SATIN-HIST-009",
                      "SATIN-HIST-007", "SATIN-HIST-012", "SATIN-TAKE-006")
            return True, out, left
        if self.outcomes and status == "revert" and target in SYSTEM_CONTRACTS:
            self.d.add("outcome", f"the system contract at {h(target)} refuses the call with its own error, "
                       f"0x{out[:4].hex()}, a revert of its frame and neither a halt nor a limit stop: its caller catches "
                       "it and the frame's unspent regular gas returns", "SATIN-OUT-009", "SATIN-POOL-012")
        left = self.end_child(frame, child, status, snap, name)
        if takes:
            if history:
                raise Unmodelled("a failed start that both made and took back records")
            d.add("gasLedgers", f"the failed child discards its start: the value and its transfer log are taken back, and "
                  f"the {records_of(len(takes))} the start took back stand again, so nothing is given back", "SATIN-ACCT-006",
                  "SATIN-HIST-009", "SATIN-POOL-014", "SATIN-TAKE-006")
        elif value:
            self.give_back(frame, history)
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
