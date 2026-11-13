"""An EIP-7702 list before the first frame: its simulation's loads, each entry's charges and records
(`SATIN-SCHED-008` step 2), and a list that runs out of gas at its first write."""

from __future__ import annotations

from .constants import (
    ACCOUNT_STATE, ACCOUNT_WRITE, COST_PER_HISTORY_BYTE, COST_PER_STATE_BYTE, delegate_of, DELEGATION_STATE_BYTES,
    KV_UPDATE_STOP, MAX_U64, STATE_GROWTH_STOP, TX_KV_UPDATE_LIMIT, TX_STATE_GROWTH_LIMIT, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, OutOfGasBeforeFrame, Unmodelled


class AuthorizationsMixin:
    """An EIP-7702 list before the first frame: its simulation's loads, each entry's charges and records"""

    def list_crossing(self):
        """SATIN-AUTH-010: the list's KV and state-growth totals, from its simulation of the whole list (SATIN-AUTH-005),
        against what the body and the counts before it left; (kind, the transaction limit) when the list does not fit,
        the KV-update limit first, else None. The simulation charges no gas (SATIN-AUTH-007)."""
        tx, env, d = self.tx, self.env, self.d
        seen: dict[bytes, int] = {}
        for chain_id, target, nonce, authority in tx.authorizations:
            if chain_id not in (0, env.chain_id) or nonce == MAX_U64 or authority == tx.sender:
                raise Unmodelled("a simulated list with an entry the gates skip")
            acct = self.state.get(authority)
            if acct is not None and acct.code:
                raise Unmodelled("an authority that holds code")
            if nonce != (seen[authority] if authority in seen else (acct.nonce if acct else 0)):
                raise Unmodelled("an authorization whose nonce does not match")
            seen[authority] = nonce + 1
        kv = len(seen)
        growth = sum(1 for a in seen if self.state.get(a) is None)
        kv_left, growth_left = TX_KV_UPDATE_LIMIT - len(self.kv), TX_STATE_GROWTH_LIMIT - self.growth
        crossed = ((KV_UPDATE_STOP, TX_KV_UPDATE_LIMIT) if kv > kv_left else
                   (STATE_GROWTH_STOP, TX_STATE_GROWTH_LIMIT) if growth > growth_left else None)
        if crossed is None:
            return None
        if not self.stops:
            raise Unmodelled("a list that does not fit outside the limit-stop cases")
        d.add("limit", f"the list's simulation walks its {fmt(len(tx.authorizations))} entries, charging nothing: "
              f"{fmt(kv)} distinct authorities, {fmt(growth)} of them absent, so the list would make {fmt(kv)} write "
              f"records and {fmt(growth)} of state growth, against the {fmt(kv_left)} KV updates and {fmt(growth_left)} "
              "of state growth the body and the counts before it leave the transaction: its "
              + ("KV" if crossed[0] == KV_UPDATE_STOP else "state-growth") + " total crosses the transaction limit, "
              "so none of the list is applied: no authority's state gas, ACCOUNT_WRITE or record history is charged, no "
              "authority's account, nonce, delegation or record is kept, and no authority is made warm",
              "SATIN-AUTH-005", "SATIN-AUTH-007", "SATIN-AUTH-010", "SATIN-AUTH-011", "SATIN-AUTH-012",
              "SATIN-AUTH-015", "SATIN-STOP-017")
        return crossed

    def apply_authorizations(self, regular: int, reservoir: int):
        """SATIN-SCHED-008 step 2 and the authorities' records of step 3, for a list that fits and whose
        every entry is accepted."""
        tx, env, d = self.tx, self.env, self.d
        done: set = set()
        indicated: set = set()  # the authorities a list entry charged an indicator for (SATIN-AUTH-009)
        self.probe.setdefault("list", regular)
        for index, (chain_id, target, nonce, authority) in enumerate(tx.authorizations):
            if chain_id not in (0, env.chain_id) or nonce == MAX_U64:
                raise Unmodelled("an authorization skipped for its chain id or nonce")
            if authority == tx.sender:
                raise Unmodelled("the sender's own authorization")
            acct = self.state.get(authority)
            if acct is not None and acct.code and not (authority in done and delegate_of(acct.code) is not None):
                raise Unmodelled("an authority that holds code the list did not set")
            if (acct.nonce if acct else 0) != nonce:
                raise Unmodelled("an authorization whose nonce does not match")
            again = authority in done
            done.add(authority)
            charges = []
            if again:
                d.add("gasLedgers", f"a further entry for the authority {h(authority)}, accepted at nonce {nonce}: an earlier "
                      "entry of the list made its account, so it is charged no new-account state gas and is no further rise "
                      "of state growth", "SATIN-SCHED-008", "SATIN-AUTH-009", "SATIN-TAKE-008")
            elif acct is None:
                m = self.multiplier(self.salt_bucket(authority, None))
                new_state = ACCOUNT_STATE * m
                charges.append(("state", new_state))
                self.growth += 1
                d.add("gasLedgers", f"the authority {h(authority)}: the state holds no account at its address, so it is new: "
                      f"new-account state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(new_state)} before the first frame, no "
                      "legacy share", "SATIN-SCHED-008", "SATIN-STATE-011", "SATIN-AUTH-008", "SATIN-POOL-024")
                d.add("resources", "the new authority is one unit of state growth", "SATIN-ACCT-014", "SATIN-AUTH-008")
            else:
                d.add("gasLedgers", f"the authority {h(authority)}: the state holds its leaf (nonce {acct.nonce}, balance "
                      f"{acct.balance}, no code), an existing account whether or not it is empty under EIP-161: no "
                      "new-account state gas", "SATIN-SCHED-008", "SATIN-STATE-011", "SATIN-AUTH-008")
                d.add("resources", "the authority exists, so it is no rise of state growth, empty under EIP-161 though it is",
                      "SATIN-ACCT-015", "SATIN-AUTH-008")
            if again:
                d.add("gasLedgers", "no ACCOUNT_WRITE: the list's first entry for the authority paid its first write",
                      "SATIN-SCHED-008", "SATIN-AUTH-015", "SATIN-TAKE-008")
            elif not (tx.to == authority and tx.value):
                if ACCOUNT_WRITE > regular:
                    if index or acct is None:
                        raise Unmodelled("an authorization list that runs out of gas after charging")
                    d.add("gasLedgers", f"the first entry's ACCOUNT_WRITE {fmt(ACCOUNT_WRITE)} for the authority "
                          f"{h(authority)} is beyond the {fmt(regular)} of regular gas left: nothing of the list is applied",
                          "SATIN-SCHED-008", "SATIN-SCHED-009", "SATIN-AUTH-015")
                    raise OutOfGasBeforeFrame(f"the first authorization's ACCOUNT_WRITE, {fmt(ACCOUNT_WRITE)}, with "
                                              f"{fmt(regular)} regular gas left")
                self.pre_frame_regular += ACCOUNT_WRITE
                regular -= ACCOUNT_WRITE
                d.add("gasLedgers", f"ACCOUNT_WRITE {fmt(ACCOUNT_WRITE)} regular gas for the authority's first write, which "
                      "the transaction has not paid already", "SATIN-SCHED-003", "SATIN-SCHED-008", "SATIN-TAKE-008",
                      "SATIN-AUTH-015")
            if any(target) and authority in indicated:
                raise Unmodelled("a second non-zero authorization for an authority")
            if not any(target) and authority in indicated:
                d.add("gasLedgers", f"the entry clears the delegation: a clear charges no indicator state gas and gives "
                      f"none back, so the {fmt(DELEGATION_STATE_BYTES * COST_PER_STATE_BYTE * self.multiplier(self.salt_bucket(authority, None)))} "
                      "the earlier entry charged for the indicator are given back to no one and stay charged",
                      "SATIN-AUTH-009", "SATIN-TAKE-008")
            if any(target):
                indicated.add(authority)
                m = self.multiplier(self.salt_bucket(authority, None))
                indicator = DELEGATION_STATE_BYTES * COST_PER_STATE_BYTE * m
                charges.append(("state", indicator))
                d.add("gasLedgers", f"the delegation indicator: DELEGATION_STATE_BYTES {DELEGATION_STATE_BYTES} x "
                      f"COST_PER_STATE_BYTE {fmt(COST_PER_STATE_BYTE)} x m={m} = {fmt(indicator)} state gas, once, no legacy "
                      "share; not a unit of state growth", "SATIN-AUTH-009", "SATIN-STATE-003", "SATIN-SCHED-008")
            record = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            if again:
                d.add("resources", "the authority keeps the one write record the list's first entry for it made: no "
                      "further record, KV update or history", "SATIN-AUTH-008", "SATIN-ACCT-004", "SATIN-TAKE-008")
            else:
                charges.append(("history", record))
                self.kv.add(("a", authority))
                self.data_size += WRITE_RECORD_SIZE
                self.history_bytes += WRITE_RECORD_SIZE
            if not again:
                d.add("gasLedgers", f"the authority's one write record: {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = "
                      f"{fmt(record)} history gas before the first frame, kept whatever the frame does", "SATIN-HIST-005",
                      "SATIN-SCHED-008", "SATIN-AUTH-016")
                d.add("resources", f"the authority's write record: one KV update, {WRITE_RECORD_SIZE} bytes of data size",
                      "SATIN-AUTH-008", "SATIN-ACCT-005")
            for kind, amount in charges:  # SATIN-POOL-024: the reservoir first, the regular budget for the rest
                r = min(reservoir, amount)
                reservoir -= r
                if amount - r > regular:
                    raise Unmodelled("an authorization whose charges cannot be paid")
                regular -= amount - r
                if kind == "state":
                    self.state_gas += amount
                else:
                    self.history_gas += amount
            if regular < 0:
                raise Unmodelled("an authorization whose charges cannot be paid")
            a = self.state.setdefault(authority, Account())
            a.nonce += 1
            a.code = (b"\xef\x01\x00" + target) if any(target) else b""
            self.warm_accounts.add(authority)
            if any(target):
                d.add("state", f"the authority's nonce becomes {a.nonce} and its code the delegation indicator 0xef0100 "
                      f"followed by {h(target)}", "SATIN-AUTH-004")
            else:
                d.add("state", f"the authority's nonce becomes {a.nonce} and its delegation is cleared: no code",
                      "SATIN-AUTH-004", "SATIN-TAKE-008")
        return regular, reservoir
