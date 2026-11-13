"""Gas detention: the limit a volatile read sets (`SATIN-DET-012`) and a frame's spendable and withheld
parts (`SATIN-DET-014`)."""

from __future__ import annotations

from .constants import BLOCK_ENV_ACCESS_COMPUTE_GAS
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
        if self.detention and not getattr(self, "cap_cited", False):
            # The caps are the protocol's values (D-67): every case that marks a read derives its limit from them.
            self.cap_cited = True
            which = ("BLOCK_ENV_ACCESS_COMPUTE_GAS" if cap == BLOCK_ENV_ACCESS_COMPUTE_GAS else "ORACLE_ACCESS_COMPUTE_GAS")
            self.d.add("gasLedgers", f"the cap is {which}, {fmt(cap)}, a protocol value the specification fixes with the "
                       "other limits and no configuration supplies", "SATIN-DET-013", "SATIN-LIM-017")

    def detain_from_start(self, frame, parties: list[str]) -> None:
        """SATIN-DET-008: a transaction whose sender, call recipient or applied EIP-7702 authority is the block
        beneficiary is detained from its start, as a read of the beneficiary's account made before its first frame,
        at compute zero (SATIN-DET-003), so the limit it sets is the cap."""
        self.d.add("gasLedgers", f"the transaction's {' and '.join(parties)} is the block beneficiary: it is detained "
                   "from its start, as a read of the beneficiary's account made before its first frame, at compute "
                   f"{fmt(self.compute)}, the charges before the first frame being no compute", "SATIN-DET-008",
                   "SATIN-DET-003", "SATIN-DET-009")
        self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, "the read of the beneficiary's account before the first frame")
        self.split(frame)
        self.d.add("gasLedgers", f"the first frame starts detained: of its {fmt(frame['regular'])} regular gas, "
                   f"{fmt(frame['spendable'])} is spendable, the cap, and the rest withheld", "SATIN-DET-014")

    def volatile_read(self, frame, what: str, cap: int = BLOCK_ENV_ACCESS_COMPUTE_GAS) -> None:
        """A volatile read whose opcode completed: marked, then the frame split (SATIN-DET-003, SATIN-DET-014)."""
        self.mark(cap, what)
        self.split(frame)
        self.d.add("gasLedgers", f"the frame's regular gas {fmt(frame['regular'])} is split: {fmt(frame['spendable'])} "
                   "spendable, what the limit leaves the transaction, and the rest withheld", "SATIN-DET-014")

