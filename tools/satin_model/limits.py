"""The resource limits on a write: the writing frame's budget, then the transaction's limit, in the order of
`SATIN-LIM-010` and `-011`."""

from __future__ import annotations

from .constants import (
    DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP, STOP_DIMENSIONS, TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT,
    TX_STATE_GROWTH_LIMIT,
)
from .records import fmt, LimitStop


class LimitsMixin:
    """The resource limits on a write: the writing frame's budget, then the transaction's limit, in"""

    def hold_to_limits(self, data_size: int, kv: int, growth: int, what: str, frame=None) -> None:
        """A write held to its frame's limits, in the order data size, KV updates, state growth (SATIN-LIM-010),
        each to the frame's budget first and then to the transaction's limit (SATIN-LIM-011). The counts are the
        write's rises; the transaction's present counts do not hold them yet. The transaction's own frame's budget
        is what the transaction had left when the frame started (SATIN-LIM-002); a child's is its share of its
        caller's remaining (SATIN-LIM-003). An admitted hint is on no frame (SATIN-LIM-012)."""
        if frame is not None and "budget" in frame:
            return self.hold_child_to_limits(frame, data_size, kv, growth, what)
        again = self.carried_on(frame)
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
                           "SATIN-LIM-011", *self.kind_rules(), *again)
                raise LimitStop(kind, budget, f"{what}: its {name} past the frame budget {fmt(budget)}")
            if used + rise > limit:
                self.d.add("limit", f"{what} rises the frame's {name} by {fmt(rise)} to {fmt(net + rise)}, within its "
                           f"budget {fmt(budget)}, and the transaction's from {fmt(used)} to {fmt(used + rise)}, past its "
                           f"limit {fmt(limit)}: the stop names the transaction limit", "SATIN-LIM-005", "SATIN-LIM-010",
                           "SATIN-LIM-011", "SATIN-LIM-012", *self.kind_rules(), *again)
                raise LimitStop(kind, limit, f"{what}: the transaction's {name} past its limit {fmt(limit)}")

    def hold_child_to_limits(self, frame, data_size: int, kv: int, growth: int, what: str) -> None:
        """A write of a frame below the transaction's own, held to the frame's budget, its share of its caller's
        remaining when it started (SATIN-LIM-003), by its signed net since then (SATIN-LIM-004), then to the
        transaction's limit (SATIN-LIM-005, -011). An admitted hint's bytes are on no frame (SATIN-LIM-012)."""
        counts = self.counts()
        again = self.carried_on(frame)
        for kind, rise, used, limit, budget, start, now in zip(
                (DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP), (data_size, kv, growth),
                (self.data_size, len(self.kv), self.growth), (TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT, TX_STATE_GROWTH_LIMIT),
                frame["budget"], frame["counts"], counts):
            if not rise:
                continue
            net = now - start
            name = STOP_DIMENSIONS[kind]
            who = frame.get("name", "the frame")
            if net + rise > budget:
                self.d.add("outcome", f"{what} rises the {name} of {who} by {fmt(rise)}, from its net {fmt(net)} past its "
                           f"budget {fmt(budget)}, its share of its caller's remaining when it started: the frame budget is "
                           "crossed, and the stop names it", "SATIN-LIM-003", "SATIN-LIM-004", "SATIN-LIM-010",
                           "SATIN-LIM-011", *self.kind_rules(), *again)
                raise LimitStop(kind, budget, f"{what}: its {name} past the frame budget {fmt(budget)}")
            if used + rise > limit:
                self.d.add("outcome", f"{what} rises the {name} of {who} by {fmt(rise)} to a net of {fmt(net + rise)}, "
                           f"within its budget {fmt(budget)}, and the transaction's from {fmt(used)} to {fmt(used + rise)}, "
                           f"past its limit {fmt(limit)}: the stop names the transaction limit", "SATIN-LIM-005",
                           "SATIN-LIM-010", "SATIN-LIM-011", "SATIN-LIM-012", *self.kind_rules(), *again)
                raise LimitStop(kind, limit, f"{what}: the transaction's {name} past its limit {fmt(limit)}")

    def carried_on(self, frame) -> tuple[str, ...]:
        """SATIN-STOP-007: a caller that caught a stop and carries on is held to what the transaction has left, and a
        write of its own that crosses a limit again stops its own frame in turn; cited where a case pins the page."""
        return ("SATIN-STOP-007",) if self.stops and frame is not None and frame.get("caught") else ()

    def kind_rules(self) -> tuple[str, ...]:
        """The rules that give a stop's kind for its dimension, cited where a case pins the limit-stop page (D-73)."""
        return ("SATIN-STOP-002", "SATIN-STOP-019") if self.stops else ()
