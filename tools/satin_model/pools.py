"""The two pools: regular charges, held to a detained frame's spendable part (`SATIN-DET-018`), and state
and history charges, their legacy share, the reservoir and the spill (`SATIN-POOL-008`), and the give-back
into the reservoir (`SATIN-HIST-012`)."""

from __future__ import annotations

from .records import fmt, Halt, q, Stopped, Unmodelled


class PoolsMixin:
    """The two pools: regular charges, held to a detained frame's spendable part (`SATIN-DET-018`), and state"""

    def order(self) -> tuple[str, tuple[str, ...]]:
        """Where the order of a call's charges and decisions is stated: the principle of `SATIN-HIST-023`
        from `5fb2688` on, the owner's decision D-58 before it."""
        return ("SATIN-HIST-023", ("SATIN-HIST-023",)) if self.principles else ("D-58", ())

    def charge_regular(self, frame, amount: int, what: str) -> None:
        """A regular charge: compute (SATIN-DET-009), held to a detained frame's spendable part. A charge the
        spendable part cannot pay and the whole regular gas can is the crossing (SATIN-DET-018); one the whole
        cannot pay is an out-of-gas, as without the read (SATIN-DET-020)."""
        spendable = frame.get("spendable")
        if spendable is not None and spendable < amount <= frame["regular"]:
            raise Stopped(self.limit, f"{what}: {fmt(amount)} of regular gas, which the spendable part {fmt(spendable)} "
                                      f"cannot pay and the frame's whole {fmt(frame['regular'])} can")
        if amount > frame["regular"]:
            raise Halt(f"out of gas at {what}: {fmt(amount)} regular gas needed, {fmt(frame['regular'])} left")
        frame["regular"] -= amount
        if spendable is not None:
            frame["spendable"] -= amount
        self.regular_charges += amount
        self.compute += amount

    def draw_regular(self, frame, amount: int) -> None:
        """Regular gas drawn by a forward, or for the part of a state or history charge regular gas pays: not
        compute, and from a detained frame's withheld part first (SATIN-DET-009, SATIN-DET-017)."""
        spendable = frame.get("spendable")
        if spendable is not None:
            frame["spendable"] -= max(0, amount - (frame["regular"] - spendable))
        frame["regular"] -= amount

    def charge_state(self, frame, amount: int, legacy: int, what: str) -> None:
        """SATIN-POOL-008: the legacy share from regular gas, then the reservoir, then the spill."""
        if legacy > frame["regular"]:
            raise Halt(f"out of gas paying the legacy share of {what}")
        self.draw_regular(frame, legacy)
        rest = amount - legacy
        r = min(frame["reservoir"], rest)
        frame["reservoir"] -= r
        if rest - r > frame["regular"]:
            raise Halt(f"out of gas paying the state gas of {what}")
        self.draw_regular(frame, rest - r)
        self.spilled += legacy + rest - r  # regular gas paid for a state or history charge, never credited back

    def pools_observation(self, status: str, gas_used: int) -> dict:
        """The `gasPools` group (decision D-64): the first frame's regular gas and reservoir at its start, after
        the charges before it, and at its end; the regular gas it paid for state and history charges, which no
        give-back credits back (SATIN-POOL-008, SATIN-HIST-012); and the gas returned to the sender."""
        frame, tx = self.first_frame, self.tx
        if frame is None or status != "success":
            raise Unmodelled("the pools of a transaction whose first frame does not succeed")
        returned = tx.gas_limit - gas_used
        self.d.add("gasPools", f"the first frame starts with {fmt(frame['regular_at_start'])} of regular gas and "
                   f"{fmt(frame['reservoir_at_start'])} of reservoir, what the charges before it left, and ends with "
                   f"{fmt(frame['regular'])} and {fmt(frame['reservoir'])}", "SATIN-POOL-005", "SATIN-POOL-010",
                   "SATIN-POOL-024")
        self.d.add("gasPools", f"regular gas paid {fmt(self.spilled)} of the frame's state and history charges, legacy "
                   "shares and spills, which no give-back credits back to it", "SATIN-POOL-008", "SATIN-HIST-012")
        self.d.add("gasPools", f"returned to the sender: gas limit {fmt(tx.gas_limit)} - gas used {fmt(gas_used)} = "
                   f"{fmt(returned)}, the unspent regular gas and the reservoir left", "SATIN-POOL-017")
        return {"regular": {"initial": q(frame["regular_at_start"]), "final": q(frame["regular"])},
                "reservoir": {"initial": q(frame["reservoir_at_start"]), "final": q(frame["reservoir"])},
                "spilled": q(self.spilled), "returned": q(returned)}

    def give_back(self, frame, amount: int) -> None:
        frame["reservoir"] += amount  # SATIN-HIST-012: into the frame's reservoir
