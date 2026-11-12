"""Gas detention: the limit a volatile read sets (`SATIN-DET-012`) and a frame's spendable and withheld
parts (`SATIN-DET-014`)."""

from __future__ import annotations

from .records import fmt


class DetentionMixin:
    """Gas detention: the limit a volatile read sets (`SATIN-DET-012`) and a frame's spendable and withheld"""

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
