"""The two pools: regular charges, held to a detained frame's spendable part (`SATIN-DET-018`), and state
and history charges, their legacy share, the reservoir and the spill (`SATIN-POOL-008`), and the give-back
into the reservoir (`SATIN-HIST-012`)."""

from __future__ import annotations

from .records import fmt, Halt, q, Stopped


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
            if self.pricing and frame.get("reservoir"):
                self.d.add("gasLedgers", f"{what} needs {fmt(amount)} of regular gas and the frame holds "
                           f"{fmt(frame['regular'])}, with {fmt(frame['reservoir'])} of reservoir: a regular charge draws "
                           "the frame's regular gas alone, and computation is held by no compute limit or ledger of its "
                           "own, so the frame runs out of gas, a halt and no limit stop", "SATIN-POOL-007",
                           "SATIN-POOL-021")
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
            if self.pricing:
                self.d.add("gasLedgers", f"{what}: its legacy share, {fmt(legacy)}, is taken from regular gas before the "
                           f"reservoir pays any of it, and the frame holds {fmt(frame['regular'])} of regular gas: it runs "
                           f"out of gas, whatever its reservoir, {fmt(frame['reservoir'])}, holds", "SATIN-POOL-008",
                           "SATIN-STATE-012")
            raise Halt(f"out of gas paying the legacy share of {what}")
        self.draw_regular(frame, legacy)
        rest = amount - legacy
        r = min(frame["reservoir"], rest)
        frame["reservoir"] -= r
        if rest - r > frame["regular"]:
            raise Halt(f"out of gas paying the state gas of {what}")
        self.draw_regular(frame, rest - r)
        self.spilled += legacy + rest - r  # regular gas paid for a state or history charge, never credited back
        if self.pricing and legacy:
            self.d.add("gasLedgers", f"{what}: its legacy share, {fmt(legacy)}, is taken from regular gas before the "
                       "reservoir pays any of it, one of the departures from EIP-8037 that Satin makes in its own words, "
                       "the profile being frozen at dbc6d457cb", "SATIN-POOL-022", "SATIN-POOL-004")
        # SATIN-POOL-014: what a failed frame's rollback gives back; and the regular gas the frame drew for state and
        # history, which is no regular charge of the transaction unless the frame halts (SATIN-POOL-019).
        frame["net_charged"] = frame.get("net_charged", 0) + amount
        frame["drawn"] = frame.get("drawn", 0) + legacy + rest - r

    def failed_frame_pools(self, frame, status: str) -> tuple[int, int]:
        """The regular gas and reservoir after the frame's own rollback (SATIN-POOL-014)."""
        if status == "halt":
            return 0, frame["reservoir_at_start"]
        return frame["regular"], frame["reservoir"] + frame.get("net_charged", 0)

    def pools_observation(self, status: str, gas_used: int) -> dict:
        """The first frame's pools at entry and after its own settlement (D-64), and the transaction's gas return."""
        frame, tx = self.first_frame, self.tx
        returned = tx.gas_limit - gas_used
        if frame is None:
            self.d.add("gasPools", "no first frame was built, so the observation reports zero regular gas and the "
                       f"{fmt(returned)} gas returned to the sender as reservoir at both ends (D-64)",
                       "SATIN-POOL-017")
            return {"regular": {"initial": q(0), "final": q(0)},
                    "reservoir": {"initial": q(returned), "final": q(returned)},
                    "spilled": q(0), "returned": q(returned)}

        regular_end, reservoir_end = frame["regular"], frame["reservoir"]
        if status != "success":
            regular_end, reservoir_end = self.failed_frame_pools(frame, status)
            if status == "halt":
                self.d.add("gasPools", f"the halt consumes the frame's regular gas and restores the "
                           f"{fmt(reservoir_end)} reservoir it received", "SATIN-POOL-014", "SATIN-OUT-007")
            else:
                ending = "stop" if self.stop else "revert"
                self.d.add("gasPools", f"the {ending} leaves {fmt(regular_end)} regular gas and gives back the "
                           f"frame's net charges {fmt(frame.get('net_charged', 0))} into the reservoir, which becomes "
                           f"{fmt(frame['reservoir'])} + {fmt(frame.get('net_charged', 0))} = {fmt(reservoir_end)}",
                           "SATIN-POOL-014", *(("SATIN-STOP-009",) if self.stop else ()))
        self.d.add("gasPools", f"the first frame starts with {fmt(frame['regular_at_start'])} of regular gas and "
                   f"{fmt(frame['reservoir_at_start'])} of reservoir, what the charges before it left, and ends with "
                   f"{fmt(regular_end)} and {fmt(reservoir_end)}", "SATIN-POOL-005", "SATIN-POOL-010",
                   "SATIN-POOL-024")
        self.d.add("gasPools", f"regular gas paid {fmt(self.spilled)} of the frame's state and history charges, legacy "
                   "shares and spills, which no give-back credits back to it", "SATIN-POOL-008", "SATIN-HIST-012")
        if status == "success" and self.pricing and frame["regular"] == 0:
            self.d.add("gasPools", f"the first frame spent the whole of its regular gas and ends with none, its "
                       f"{fmt(frame['reservoir'])} of reservoir untouched by its computation: no compute limit or ledger of "
                       "its own holds computation, which regular gas pays", "SATIN-POOL-021", "SATIN-POOL-007")
        self.d.add("gasPools", f"returned to the sender: gas limit {fmt(tx.gas_limit)} - receipt gas used {fmt(gas_used)} = "
                   f"{fmt(returned)}", "SATIN-POOL-017")
        if status != "success":
            self.d.add("gasPools", "any give-back of the first frame's start charges belongs to transaction settlement",
                       "SATIN-POOL-015", "SATIN-HIST-005")
        return {"regular": {"initial": q(frame["regular_at_start"]), "final": q(regular_end)},
                "reservoir": {"initial": q(frame["reservoir_at_start"]), "final": q(reservoir_end)},
                "spilled": q(self.spilled), "returned": q(returned)}

    def give_back(self, frame, amount: int) -> None:
        if self.pricing and amount:
            self.d.add("gasLedgers", f"a give-back of {fmt(amount)} credits the frame's reservoir, never its regular gas, "
                       "whatever the frame's regular gas paid of state before: Satin's give-back rule, a departure from "
                       "EIP-8037 at dbc6d457cb, which would credit regular gas first", "SATIN-POOL-022", "SATIN-POOL-004")
        frame["reservoir"] += amount  # SATIN-HIST-012: into the frame's reservoir
        frame["net_charged"] = frame.get("net_charged", 0) - amount  # SATIN-POOL-014: net of the give-backs received
