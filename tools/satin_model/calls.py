"""A `CALL`, decided in the order of `SATIN-ICPT-007`: interception, then the frame start, the child frame and
what it returns (`SATIN-POOL-012`), the records a value start makes and takes back (`SATIN-ACCT-006`)."""

from __future__ import annotations

from .constants import (
    BLOCK_ENV_ACCESS_COMPUTE_GAS, COST_PER_HISTORY_BYTE, FRAME_SHARE_DENOMINATOR, FRAME_SHARE_NUMERATOR, DISABLE_VOLATILE_DATA_ACCESS, INTERCEPTED, KEYLESS_DEPLOY, KEYLESS_DEPLOY_CALL, KEYLESS_ERRORS,
    limit_exceeded, MEGA_ACCESS_CONTROL, MEGA_LIMIT_CONTROL, NON_ZERO_TRANSFER, ORACLE, SEND_HINT, SYSTEM_CONTRACTS,
    TRANSFER_LOG_ADDRESS,
    TRANSFER_LOG_SIZE, TRANSFER_TOPIC,
    TX_DATA_LIMIT, WRITE_RECORD_SIZE, selector, ex, HIGH_PRECISION_TIMESTAMP, HIGH_PRECISION_TIMESTAMP_CODE_HASH,
    TIMESTAMP_BASE_SLOT, TIMESTAMP_MAX_SLOTS,
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
            if not value and self.system_pages and target == MEGA_LIMIT_CONTROL:
                return self.limit_control_answer(frame, child_gas, share, "CALL")
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
            if frame.get("access_off"):
                raise Unmodelled("a sendHint call from a frame whose volatile-data access is off")
            if self.exempt and self.data_size + len(data) > TX_DATA_LIMIT:
                d.add("limit", f"the sendHint's {fmt(len(data))} input bytes take the transaction's data size past "
                      f"TX_DATA_LIMIT {fmt(TX_DATA_LIMIT)}; the transaction is system-originated, which no per-transaction "
                      "limit stops: the hint is admitted and counted", "SATIN-MST-008", "SATIN-ORCL-010")
            if not self.exempt and self.data_size + len(data) > TX_DATA_LIMIT:
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
            if self.system_pages:
                self.hand_hint(caller, data, "the calling frame")
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
        if self.stops and self.current and target not in SYSTEM_CONTRACTS:
            # SATIN-LIM-003, -004: the child's budgets; the transaction's own frame received what the body and the counts
            # made before it left (SATIN-LIM-002), which are on no frame (SATIN-LIM-005).
            remaining = self.frame_remaining(frame)
            d.add("resources", f"{name} receives, in each dimension, its share of what its caller has left, "
                  f"{FRAME_SHARE_NUMERATOR}/{FRAME_SHARE_DENOMINATOR} rounded down: data size {fmt(remaining[0])} -> "
                  f"{fmt(child['budget'][0])}, KV updates {fmt(remaining[1])} -> {fmt(child['budget'][1])}, state growth "
                  f"{fmt(remaining[2])} -> {fmt(child['budget'][2])}", "SATIN-LIM-003", "SATIN-LIM-004")
            if frame is self.first_frame:
                d.add("resources", "its caller, the transaction's own frame, received what the transaction had left once "
                      f"the body and the counts made before the first frame were counted, {fmt(self.frame_start_counts[0])} "
                      f"bytes of data size, {self.frame_start_counts[1]} KV updates and {self.frame_start_counts[2]} of state "
                      "growth: those counts are on no frame, the transaction's net holding them once, so the frames' nets "
                      "do not count them again", "SATIN-LIM-002", "SATIN-LIM-005")
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
        if target == self.env.coinbase:
            if self.limit is None and not self.detention:
                raise Unmodelled("a call to the block beneficiary outside gas detention's cases")
            # SATIN-DET-003: a call opcode's read of the beneficiary's account as its target completes when the start is
            # decided, after the opcode's charges and its forward, before the child runs: the forward is no compute.
            d.add("gasLedgers", f"the CALL's target {h(target)} is the block beneficiary: its read of the beneficiary's "
                  "account completes when the start is decided, after the opcode's charges and its forward and before the "
                  f"child runs its first instruction, at the transaction's compute {fmt(self.compute)}, which leaves out the "
                  f"{fmt(child_gas)} the call forwards", "SATIN-DET-001", "SATIN-DET-003", "SATIN-DET-009")
            self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, "the CALL's read of the block beneficiary's account")
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

    # --- the system contracts' own pages (D-109) -----------------------------------------------------

    def limit_control_answer(self, frame, child_gas: int, share: int, scheme: str):
        """MegaLimitControl's `remainingComputeGas()` called by a `CALL` or a `STATICCALL` without value: answered by the
        node before the frame start (SATIN-ICPT-001, -007), `min(own, allowance)` read when the call reaches the
        interceptor (SATIN-MLC-002): `own` the caller's regular gas after the forward with the forward counted back,
        regular gas only (SATIN-MLC-003), and `allowance` what a compute limit leaves the transaction. The answer
        charges nothing, and the child's regular gas and the reservoir share return (SATIN-ICPT-004)."""
        d = self.d
        own = frame["regular"] + child_gas
        d.add("outcome", f"interception: remainingComputeGas() called by a {scheme} without value is MegaLimitControl's "
              "intercepted method, answered by the node before the frame start; the bytecode does not run",
              "SATIN-ICPT-001", "SATIN-ICPT-007", "SATIN-MLC-001")
        remaining = self.remaining_compute(own, f"the caller's regular gas after the {scheme} drew its forward, "
                                           f"{fmt(frame['regular'])}, with the forward {fmt(child_gas)} counted back",
                                           frame["reservoir"] + share)
        frame["reservoir"] += share
        d.add("gasLedgers", f"the answer charges nothing: the child's {fmt(child_gas)} regular gas returns untouched, and "
              "the reservoir share with it", "SATIN-ICPT-004", "SATIN-POOL-012")
        return True, remaining.to_bytes(32, "big"), child_gas

    def remaining_compute(self, own: int, what: str, reservoir: int) -> int:
        """SATIN-MLC-002, -003: `min(own, allowance)`, the allowance what the compute limit leaves the transaction, absent
        while no limit is set; regular gas only."""
        d = self.d
        d.add("gasLedgers", f"own = {what} = {fmt(own)}, regular gas only: the {fmt(reservoir)} of reservoir the caller "
              "holds is not part of it", "SATIN-MLC-002", "SATIN-MLC-003")
        if self.limit is None:
            d.add("outcome", f"no read of volatile data has set a compute limit, so there is no allowance: the answer is "
                  f"own, {fmt(own)}, ABI-encoded as a uint64", "SATIN-MLC-002")
            return own
        allowance = max(0, self.limit - self.compute)
        remaining = min(own, allowance)
        d.add("outcome", f"the compute limit {fmt(self.limit)} leaves the transaction, at compute {fmt(self.compute)}, the "
              f"allowance {fmt(allowance)}: the answer is min({fmt(own)}, {fmt(allowance)}) = {fmt(remaining)}, ABI-encoded "
              "as a uint64", "SATIN-MLC-002", "SATIN-DET-009", "SATIN-DET-012")
        return remaining

    def system_code_call(self, scheme: str, address: bytes, target: bytes, data: bytes) -> None:
        """A `DELEGATECALL` or `CALLCODE` of a system contract: never intercepted, it runs the contract's bytecode in a
        frame of the caller's own context (SATIN-ICPT-001); of the Oracle's `sendHint` it reaches no service and counts
        nothing (SATIN-ORCL-008), and of MegaLimitControl's method its bytecode answers (SATIN-MLC-001)."""
        d = self.d
        rules = ["SATIN-ICPT-001"]
        what = f"a {scheme} of {h(target)}'s code on {h(address)}"
        if target == ORACLE and data[:4] == SEND_HINT:
            d.add("outcome", f"{what} with sendHint's selector is no sendHint call: only a CALL or a STATICCALL is; the "
                  "Oracle's bytecode runs in the caller's own context, no hint reaches the service and nothing is counted",
                  "SATIN-ORCL-008", "SATIN-ORCL-006", *rules)
            return
        if target == MEGA_LIMIT_CONTROL:
            rules.append("SATIN-MLC-001")
        d.add("outcome", f"{what} is never intercepted, whatever its selector: the contract's bytecode runs in a frame of "
              "the caller's own context", *rules)

    def hand_hint(self, sender: bytes, data: bytes, who: str) -> None:
        """SATIN-ORCL-007, -009: an admitted hint whose input decodes as sendHint(bytes32,bytes) is handed to the service
        with its topic, its data and the address of the frame that made the call; one that does not decode reaches none."""
        decoded = decode_hint(data)
        if decoded is None:
            self.d.add("reads", "the admitted input does not decode as sendHint(bytes32,bytes): it stays counted and "
                       "reaches no service", "SATIN-ORCL-009")
            return
        topic, payload = decoded
        self.hints.append((sender, topic, payload))
        self.d.add("reads", f"the hint is handed to the oracle service before the call returns: its topic {h(topic)}, its "
                   f"{len(payload)} bytes of data and {who}'s address {h(sender)}", "SATIN-ORCL-006", "SATIN-ORCL-007")


    def oracle_method(self, caller: bytes, data: bytes, status: str, out: bytes, where: str) -> None:
        """What the Oracle's bytecode did with one of its methods (SATIN-ORCL-001): its reads, the restricted writes the
        immediate caller is authorized for by the bytecode alone (SATIN-ORCL-011), `multiCall` and `sendHint`."""
        if not self.system_pages:
            return
        d, sel = self.d, data[:4]
        if sel in (ORACLE_SELECTORS["getSlot(uint256)"], ORACLE_SELECTORS["getSlots(uint256[])"]):
            d.add("outcome", f"{where}: the Oracle's read method returns the value at each slot asked, in order, each read "
                  f"by SLOAD in the Oracle's own frame; the frame ends in {status} with {len(out)} bytes", "SATIN-ORCL-001")
        elif sel in RESTRICTED_WRITES:
            live = self.live_system_address()
            if status == "revert" and out[:4] == ORACLE_SELECTORS["InvalidLength(uint256,uint256)"]:
                d.add("outcome", f"{where}: setSlots with arrays of different lengths reverts with InvalidLength before any "
                      "SSTORE and before the caller is checked", "SATIN-ORCL-001")
                return
            allowed = live is not None and caller == live
            named = h(live) if live else "no address, the registry naming none"
            if allowed != (status == "success") or (not allowed and out[:4] != ORACLE_SELECTORS["NotSystemAddress()"]):
                raise Unmodelled("an Oracle write whose bytecode answered otherwise than SATIN-ORCL-011 states")
            d.add("outcome", f"{where}: a restricted write; its body ran first and was charged as it ran, then the Oracle's "
                  f"bytecode checked its immediate caller {h(caller)} against the address SequencerRegistry."
                  f"currentSystemAddress() returns, {named}: " + (
                      "the same, so the write stands" if allowed else
                      "not the same, so the call reverts with NotSystemAddress() and every write and log of the body is "
                      "taken back") + ", by the bytecode's check alone, whatever sent the transaction", "SATIN-ORCL-001",
                  "SATIN-ORCL-011")
        elif sel == ORACLE_SELECTORS["multiCall(bytes[])"]:
            d.add("outcome", f"{where}: multiCall executes each payload by DELEGATECALL into the Oracle, in order, and ends in "
                  f"{status}", "SATIN-ORCL-001")
        elif sel == SEND_HINT:
            d.add("outcome", f"{where}: sendHint is a no-op view method at the bytecode level: the frame ends in {status} "
                  f"with {len(out)} bytes", "SATIN-ORCL-001")


    def contract_method(self, address: bytes, code: bytes, data: bytes, status: str, out: bytes, where: str) -> None:
        """What MegaLimitControl's or the High-Precision Timestamp's own bytecode did (SATIN-MLC-001, SATIN-HPTS-001,
        -002), where a case runs it."""
        if not self.system_pages or not code:
            return
        d, sel = self.d, data[:4]
        if code == self.pre.get(MEGA_LIMIT_CONTROL, Account()).code:
            if status != "revert" or out != NOT_INTERCEPTED:
                raise Unmodelled("MegaLimitControl's bytecode answering otherwise than SATIN-MLC-001 states")
            d.add("outcome", f"{where}: MegaLimitControl's bytecode runs, its intercepted method and every other selector "
                  "reverting with NotIntercepted()", "SATIN-MLC-001")
        elif address == HIGH_PRECISION_TIMESTAMP and ex.keccak256(code) == HIGH_PRECISION_TIMESTAMP_CODE_HASH:
            if sel == selector("timestamp()"):
                d.add("outcome", f"{where}: the High-Precision Timestamp's timestamp() reads Oracle slot "
                      f"TIMESTAMP_BASE_SLOT {TIMESTAMP_BASE_SLOT} through the Oracle's getSlot and ends in {status}"
                      + (f" with {len(out)} bytes" if status == "success" else ", returning the Oracle's revert"),
                      "SATIN-HPTS-001")
                d.add("gasLedgers", "the wrapper's read of the Oracle's storage is an Oracle read: an SLOAD in the Oracle's "
                      "own frame, reached through getSlot, answered as an Oracle read, charged as a cold access, held to "
                      "gas detention, and refused in a frame whose volatile-data access is off", "SATIN-HPTS-002",
                      "SATIN-ORCL-002", "SATIN-ORCL-003")
            elif sel == selector("update(uint256)"):
                d.add("outcome", f"{where}: the High-Precision Timestamp's update forwards to the Oracle's setSlot of slot "
                      f"TIMESTAMP_BASE_SLOT, whose immediate caller is the timestamp contract itself, and ends in {status}",
                      "SATIN-HPTS-001")
            else:
                d.add("outcome", f"{where}: the High-Precision Timestamp's accessor returns the constant of its interface, "
                      f"{len(out)} bytes, ABI-encoded: ORACLE_CONTRACT_ADDRESS, TIMESTAMP_BASE_SLOT {TIMESTAMP_BASE_SLOT} or "
                      f"TIMESTAMP_MAX_SLOTS {TIMESTAMP_MAX_SLOTS} as a uint32", "SATIN-HPTS-001")


def decode_hint(data: bytes):
    """The arguments of sendHint(bytes32,bytes) as the ABI decoder reads them: (topic, data), or None."""
    body = data[4:]
    if len(body) < 64:
        return None
    offset = int.from_bytes(body[32:64], "big")
    if offset + 32 > len(body):
        return None
    length = int.from_bytes(body[offset:offset + 32], "big")
    if offset + 32 + length > len(body):
        return None
    return body[:32], body[offset + 32:offset + 32 + length]


ORACLE_SELECTORS = {name: selector(name) for name in (
    "getSlot(uint256)", "getSlots(uint256[])", "setSlot(uint256,bytes32)", "setSlots(uint256[],bytes32[])",
    "emitLog(bytes32,bytes)", "emitLogs(bytes32,bytes[])", "multiCall(bytes[])", "NotSystemAddress()",
    "InvalidLength(uint256,uint256)")}
RESTRICTED_WRITES = {ORACLE_SELECTORS[n] for n in ("setSlot(uint256,bytes32)", "setSlots(uint256[],bytes32[])",
                                                    "emitLog(bytes32,bytes)", "emitLogs(bytes32,bytes[])")}
NOT_INTERCEPTED = selector("NotIntercepted()")
