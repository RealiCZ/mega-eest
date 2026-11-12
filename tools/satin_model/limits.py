"""The resource limits on a write of the transaction's own frame: its budget, then the transaction's limit, in
the order of `SATIN-LIM-010` and `-011`."""

from __future__ import annotations

from .constants import (
    DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP, STOP_DIMENSIONS, TX_DATA_LIMIT, TX_KV_UPDATE_LIMIT,
    TX_STATE_GROWTH_LIMIT,
)
from .records import fmt, LimitStop


class LimitsMixin:
    """The resource limits on a write of the transaction's own frame: its budget, then the transaction's limit, in"""

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
