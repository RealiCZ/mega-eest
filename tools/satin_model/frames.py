"""Frames below the transaction's own: a child's budgets (`SATIN-LIM-003`) and reservoir share (`SATIN-POOL-011`),
the snapshot its failure returns to, how it ends (`SATIN-POOL-012`, `-014`), a value start answered without a
frame and held to the started frame's budget (`SATIN-LIM-013`, `SATIN-STOP-014`), and `DELEGATECALL`."""

from __future__ import annotations

from .constants import (
    COST_PER_HISTORY_BYTE, DATA_SIZE_STOP, delegate_of, DETENTION_STOP, FRAME_SHARE_DENOMINATOR, FRAME_SHARE_NUMERATOR,
    GAS_RETAINED_DENOMINATOR, GAS_RETAINED_NUMERATOR, HISTORY_ALLOWANCE_BYTES, INTERCEPTED, KV_UPDATE_STOP,
    limit_exceeded, LOG_BASE_SIZE, LOG_TOPIC_SIZE, ORACLE, STATE_GROWTH_STOP, STOP_DIMENSIONS, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE,
    TRANSFER_TOPIC, TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT, TX_STATE_GROWTH_LIMIT, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, Halt, LimitStop, pad_address, Stopped, Unmodelled

KINDS = (DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP)  # SATIN-LIM-010's order
LIMITS = (TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT, TX_STATE_GROWTH_LIMIT)  # SATIN-LIM-001
RECORD_HISTORY = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE


class FramesMixin:
    """Frames below the transaction's own: budgets, reservoir share, rollback, and the starts that build none."""

    # --- what a frame holds -------------------------------------------------------------------------

    def frame_snapshot(self):
        """What a failed frame returns the transaction to: the state, the counts, the logs, the kept charges,
        the refund counter (SATIN-TAKE-003), the warm sets (EIP-2929) and the creations and destructions."""
        return (self.snapshot(), self.refund, set(self.warm_accounts), set(self.warm_slots), set(self.created),
                set(self.destroyed))

    def frame_restore(self, snap) -> None:
        base, self.refund, self.warm_accounts, self.warm_slots, self.created, self.destroyed = snap
        self.restore(base)

    def counts(self) -> tuple[int, int, int]:
        """The transaction's data size, KV updates and state growth, an admitted hint's bytes aside, which are
        on no frame (SATIN-LIM-012)."""
        return (self.data_size - self.hint_bytes, len(self.kv), self.growth)

    def frame_remaining(self, frame) -> tuple[int, int, int]:
        """SATIN-LIM-004: `min(budget, max(0, budget - net))` in each dimension, the net being what the transaction
        counted since the frame started, its successful children's included; the transaction's own frame's budget
        is what the transaction had left when it started (SATIN-LIM-002)."""
        if "budget" in frame:
            budget, start = frame["budget"], frame["counts"]
        else:
            start = self.frame_start_counts
            budget = tuple(limit - s for limit, s in zip(LIMITS, start))
        return tuple(min(b, max(0, b - (n - s))) for b, n, s in zip(budget, self.counts(), start))

    def child_budget(self, frame) -> tuple[int, int, int]:
        """SATIN-LIM-003: a child's budget in each dimension, its share of the parent's remaining."""
        return tuple(r * FRAME_SHARE_NUMERATOR // FRAME_SHARE_DENOMINATOR for r in self.frame_remaining(frame))

    def as_loaded(self, address: bytes) -> bool:
        """SATIN-ACCT-004: whether an account's nonce, balance and code are what the transaction loaded."""
        now, was = self.state.get(address, Account()), self.pre.get(address, Account())
        return (now.nonce, now.balance, now.code) == (was.nonce, was.balance, was.code)

    def reservoir_share(self, frame, who: str) -> int:
        """SATIN-POOL-011: the child's share of the reservoir the caller has left after every charge it made
        for the start; the caller keeps the rest."""
        remaining = frame["reservoir"]
        share = remaining - remaining * GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR
        frame["reservoir"] -= share
        if remaining:
            self.d.add("gasLedgers", f"{who} receives the reservoir share {fmt(remaining)} - {fmt(remaining)} x "
                       f"{GAS_RETAINED_NUMERATOR} / {GAS_RETAINED_DENOMINATOR} = {fmt(share)} of the {fmt(remaining)} the "
                       f"caller has left after the start's charges, and the caller keeps {fmt(remaining - share)}",
                       "SATIN-POOL-011", "SATIN-HIST-010")
        return share

    def new_child(self, frame, regular: int, share: int, allowance: bool = False) -> dict:
        """A child frame's gas and budgets, taken before its start counts anything: the start's counts are the
        started frame's own (SATIN-LIM-013). A value call below the transaction's own frame grants the frame a
        history allowance, which is not gas (SATIN-HIST-018, SATIN-HIST-020)."""
        child = {"regular": regular, "reservoir": share, "regular_at_start": regular, "reservoir_at_start": share,
                 "received": share, "net_charged": 0, "drawn": 0, "budget": self.child_budget(frame),
                 "counts": self.counts(), "access_off": frame.get("access_off", False)}
        if allowance:
            child["allowance"] = HISTORY_ALLOWANCE_BYTES * COST_PER_HISTORY_BYTE
        return child

    # --- running a child and its end ----------------------------------------------------------------

    def run_child(self, child, code: bytes, ctx: dict, name: str, create: bool = False) -> tuple[str, bytes]:
        """Runs a child frame to its end: its status and output. A creation's code is deposited in the child,
        before it returns (SATIN-SCHED-011)."""
        d = self.d
        self.split(child)
        if child.get("spendable") is not None:
            self.probe.setdefault("child-room", self.limit - self.compute)
            d.add("gasLedgers", f"{name} starts detained: of its {fmt(child['regular_at_start'])} regular gas, "
                  f"{fmt(child['spendable'])} is spendable, what the limit {fmt(self.limit)} leaves the transaction's compute "
                  f"{fmt(self.compute)}, and the rest withheld", "SATIN-DET-009", "SATIN-DET-014")
        charges = self.regular_charges
        try:
            status, out = self.execute(code, child, create, ctx=ctx)
            if create and status == "success":
                self.deposit_code(out, child, ctx["address"])
        except Halt as e:
            status, out = "halt", b""
            d.add("gasLedgers", f"{name} halts ({e}): its {fmt(child['regular_at_start'])} regular gas is consumed",
                  "SATIN-POOL-014", "SATIN-OUT-007")
            if self.limit is not None:
                d.add("gasLedgers", f"what the halting frame burns is not compute: the transaction's compute stays "
                      f"{fmt(self.compute)}", "SATIN-DET-011", "SATIN-DET-020")
        except Stopped as e:
            status, out = "stop", limit_exceeded(DETENTION_STOP, e.limit)
            d.add("outcome", f"{name} reaches gas detention's crossing at {e}: the charge is not made and the frame is "
                  f"stopped with MegaLimitExceeded({DETENTION_STOP}, {fmt(e.limit)}), which its caller catches",
                  "SATIN-DET-018", "SATIN-STOP-020")
            d.add("gasLedgers", f"what the frame spent before the crossing charge stays spent, and its whole regular gas, "
                  f"{fmt(child['regular'])}, the withheld part included, returns to its caller; the transaction's compute "
                  f"is {fmt(self.compute)}", "SATIN-DET-018", "SATIN-DET-019", "SATIN-POOL-012")
        except LimitStop:
            raise Unmodelled("a resource limit crossed below the transaction's own frame")
        self.regular_charges = charges
        return status, out

    def end_child(self, frame, child, status: str, snap, name: str) -> int:
        """A child's end (SATIN-POOL-012, -014, SATIN-TAKE-004): its reservoir joins the caller's, and the regular
        gas it returns. A success merges its counts and its net charges into the caller's; a revert or a stop
        gives its net charges back into its own reservoir, and a halt restores the reservoir it received and
        consumes its regular gas; a failure discards its counts, records, logs and writes. The regular gas a frame
        drew for state and history is no regular charge unless the frame halts (SATIN-POOL-019, D-51)."""
        d = self.d
        shown = child["received"] or child["net_charged"] or child["drawn"] or child["reservoir"]
        if status == "success":
            frame["reservoir"] += child["reservoir"]
            frame["net_charged"] = frame.get("net_charged", 0) + child["net_charged"]
            frame["drawn"] = frame.get("drawn", 0) + child["drawn"]
            self.regular_charges -= child["drawn"]
            if shown:
                d.add("gasLedgers", f"{name} succeeds: its reservoir {fmt(child['reservoir'])} joins the "
                      f"{fmt(frame['reservoir'] - child['reservoir'])} its caller kept, now {fmt(frame['reservoir'])}, and "
                      f"its counts and its state and history charges, net {fmt(child['net_charged'])}, merge into the "
                      "caller's" + (f"; the {fmt(child['drawn'])} of regular gas it and its children drew for state and "
                                    "history stays spent and is not given back to regular gas" if child["drawn"] else ""),
                      "SATIN-POOL-012", "SATIN-TAKE-004",
                      "SATIN-LIM-006", "SATIN-HIST-012")
            return child["regular"]
        kept_logs = len(snap[0][4])
        dropped = [log for log in self.logs[kept_logs:] if log[0] != TRANSFER_LOG_ADDRESS]
        unmarked = sorted(self.destroyed - snap[5])
        self.frame_restore(snap)
        if unmarked and self.destruction:
            d.add("gasLedgers", f"{name}'s failure discards the mark of {', '.join(h(a) for a in unmarked)} and every effect "
                  "of the table: the charges the table refilled stand again, the records it took back stand again, and "
                  "the discarded give-back is no further one", "SATIN-SD-010", "SATIN-POOL-014")
            d.add("resources", f"the falls and the records the table took back are discarded with {name}: the "
                  "account's growth and records stand again", "SATIN-SD-010")
        if dropped:
            size = sum(LOG_BASE_SIZE + LOG_TOPIC_SIZE * len(topics) + len(data) for _, topics, data in dropped)
            d.add("resources", f"{name}'s failure discards the {len(dropped)} log{'s' if len(dropped) > 1 else ''} it and "
                  f"its children emitted, {size} bytes of data size, whose history its rollback undoes with its other "
                  "charges", "SATIN-TAKE-009", "SATIN-POOL-014", "SATIN-TAKE-004")
        if status == "halt":
            returned, left = child["received"], 0
            # A test-construction aid, not a rule: the regular gas halted frames drew for state and history.
            self.probe["halted-drawn"] = self.probe.get("halted-drawn", 0) + child["drawn"]
            if shown:
                d.add("gasLedgers", f"{name}'s halt: its reservoir becomes the {fmt(returned)} it received, which joins "
                      f"its caller's reservoir, now {fmt(frame['reservoir'] + returned)}; its regular gas"
                      + (f", with the {fmt(child['drawn'])} it drew for its state and history charges," if child["drawn"] else "")
                      + " is consumed; its counts, records, logs, writes and refund changes are discarded",
                      "SATIN-POOL-014", "SATIN-POOL-012",
                      "SATIN-TAKE-004", "SATIN-TAKE-011")
        else:
            returned, left = child["reservoir"] + child["net_charged"], child["regular"]
            frame["drawn"] = frame.get("drawn", 0) + child["drawn"]
            self.regular_charges -= child["drawn"]
            if shown:
                d.add("gasLedgers", f"{name} {'reverts' if status == 'revert' else 'is stopped'}: its rollback makes its "
                      f"reservoir {fmt(child['reservoir'])} + net_charged {fmt(child['net_charged'])} = {fmt(returned)}, "
                      f"which joins its caller's reservoir, now {fmt(frame['reservoir'] + returned)}; its "
                      f"{fmt(left)} of regular gas returns to the caller's regular gas"
                      + (f", the {fmt(child['drawn'])} it drew for state and history not among it" if child["drawn"] else "")
                      + "; its counts, records, logs, writes and refund changes are discarded, and a record it took back "
                      "stands again", "SATIN-POOL-014", "SATIN-POOL-012",
                      "SATIN-TAKE-004", "SATIN-TAKE-011", "SATIN-HIST-012")
        frame["reservoir"] += returned
        return left

    # --- a value start answered without a frame -----------------------------------------------------

    def codeless_start(self, frame, caller: bytes, target: bytes, value: int, child_gas: int, records: list,
                       history: int, new_account: int, share: int):
        """A value `CALL` to an account without code: the start is decided once the value would move, and what it
        would keep — its records, its transfer log and a new account's leaf — is held to the started frame's own
        budget and then to the transaction's limit (SATIN-LIM-013, SATIN-LIM-010, -011). A crossing replaces the
        answer, a success, by the stop on the child's untouched regular gas (SATIN-STOP-014), and the caller is
        given the start's charges back (SATIN-HIST-014, SATIN-POOL-015). Returns (success, return data, the
        regular gas the child returns)."""
        d = self.d
        if not value:
            raise Unmodelled("a call without value to an account without code")
        if any(("a", a) in self.kv for a in (caller, target)):
            raise Unmodelled("a value start without a frame whose accounts differ already")
        budget = self.child_budget(frame)
        remaining = self.frame_remaining(frame)
        rises = (WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE, len(records), 1 if new_account else 0)
        frame["reservoir"] += share  # a start answered without a frame returns its share (SATIN-POOL-012)
        for kind, rise, b, rem, used, limit in zip(KINDS, rises, budget, remaining, self.counts(), LIMITS):
            if not rise or (rise <= b and used + rise <= limit):
                continue
            name = STOP_DIMENSIONS[kind]
            crossed, which = (b, "the started frame's budget") if rise > b else (limit, "the transaction's limit")
            d.add("limit", f"the value CALL to {h(target)}, an account without code, is a start answered without a frame: "
                  f"once its value would move it would keep {len(records)} records and a transfer log, "
                  f"{fmt(rises[0])} bytes of data size, and {rises[2]} of state growth for the new account; held in "
                  "the order data size, KV updates, state growth, first to the started frame's own budget, the share of "
                  f"the caller's remaining: in {name} the caller has {fmt(rem)} left, so the started frame's budget is "
                  f"{fmt(rem)} x {FRAME_SHARE_NUMERATOR} / {FRAME_SHARE_DENOMINATOR} = {fmt(b)}, and the start's rise of "
                  f"{fmt(rise)} crosses {which}", "SATIN-LIM-003", "SATIN-LIM-004", "SATIN-LIM-010", "SATIN-LIM-011",
                  "SATIN-LIM-013", "SATIN-TAKE-010")
            d.add("outcome", f"the start crosses: the call's answer, a success, is replaced by the stop "
                  f"MegaLimitExceeded({kind}, {fmt(crossed)}) on the child's untouched regular gas, {fmt(child_gas)}, the "
                  "forward and the stipend; no value moves, nothing is counted and no transfer log is kept",
                  "SATIN-STOP-014", "SATIN-STOP-018", "SATIN-POOL-012", "SATIN-TAKE-010")
            self.give_back(frame, history)
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE * len(records)
            self.give_back(frame, new_account)
            self.state_gas -= new_account
            d.add("gasLedgers", f"the caller is given both of the start's charges back into its reservoir, after the "
                  f"child's reservoir joined it: the records' {fmt(history)} of history gas and the new account's "
                  f"{fmt(new_account)} of state gas, its legacy share included, {fmt(history + new_account)} in all; the "
                  "regular gas it paid for them stays spent", "SATIN-HIST-014", "SATIN-POOL-015", "SATIN-HIST-012",
                  "SATIN-TAKE-010")
            return False, limit_exceeded(kind, crossed), child_gas
        caller_acct = self.state.setdefault(caller, Account())
        caller_acct.balance -= value
        self.state.setdefault(target, Account()).balance += value
        for a in records:
            self.kv.add(("a", a))
        self.data_size += rises[0]
        self.growth += rises[2]
        self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(caller), pad_address(target)],
                          value.to_bytes(32, "big")))
        d.add("resources", f"the value CALL to {h(target)}, an account without code, is answered with a success without a "
              f"frame: its start keeps {len(records)} records, a transfer log and {rises[2]} of state growth, within "
              "the started frame's budget and the transaction's limits", "SATIN-LIM-013", "SATIN-ACCT-005", "SATIN-LOG-006")
        return True, b"", child_gas

    # --- DELEGATECALL -------------------------------------------------------------------------------

    def delegatecall(self, frame, address: bytes, caller: bytes, value: int, target: bytes, data: bytes,
                     child_gas: int, share: int):
        """A `DELEGATECALL` once its opcode's charges and the forward are made: `target`'s code runs on the
        calling frame's account and storage, with its caller and value; no value moves and no record is made,
        and the frame gets no history allowance (SATIN-HIST-018). Returns (success, return data, the regular gas
        the child returns)."""
        callee = self.state.get(target)
        if (target in INTERCEPTED or target == ORACLE or callee is None or not callee.code
                or delegate_of(callee.code) is not None):
            raise Unmodelled("a DELEGATECALL to a system contract, an account without code or a delegated account")
        name = f"the DELEGATECALL frame of {h(target)}'s code on {h(address)}"
        child = self.new_child(frame, child_gas, share)
        snap = self.frame_snapshot()
        status, out = self.run_child(child, callee.code, {"address": address, "caller": caller, "value": value,
                                                          "calldata": data, "name": name}, name)
        if status == "success":
            self.d.add("gasLedgers", f"{name} returns {len(out)} bytes and {fmt(child['regular'])} of regular gas to its "
                       "caller", "SATIN-POOL-012", "SATIN-OUT-001")
        left = self.end_child(frame, child, status, snap, name)
        return status == "success", out, left
