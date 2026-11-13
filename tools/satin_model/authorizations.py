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

    def entry_gate(self, chain_id: int, nonce: int, authority: bytes | None) -> str | None:
        """SATIN-AUTH-002: why an entry is skipped before its authority is read, or None when it passes the gates."""
        if chain_id not in (0, self.env.chain_id):
            return f"its chain id {chain_id} is neither zero nor the chain's, {self.env.chain_id}"
        if nonce == MAX_U64:
            return "its nonce is 2^64 - 1"
        if authority is None:
            return "its signature recovers no authority"
        return None

    def load_authorities(self) -> None:
        """SATIN-AUTH-003, -005: the simulation loads each distinct authority whose entry passed the gates, once, with
        its code, the whole list walked; an entry the gates skip loads nothing (SATIN-AUTH-002, SATIN-WIT-004)."""
        for chain_id, _, nonce, authority in self.tx.authorizations:
            if self.entry_gate(chain_id, nonce, authority) is None:
                self.load(authority, "an authority the list's simulation loads, the whole list walked, whether or not "
                          "the list is then applied", "SATIN-AUTH-005", "SATIN-WIT-004", "SATIN-WIT-008")
            elif self.reads and self.lists:
                self.d.add("reads", f"an entry {self.entry_gate(chain_id, nonce, authority)} is skipped before its "
                           "authority is read: the simulation loads nothing for it", "SATIN-AUTH-002", "SATIN-WIT-004")

    def simulate_list(self):
        """SATIN-AUTH-001 to -005: the list simulated in order, writing, warming and charging nothing. Returns the
        accepted authorities in list order and, for each authority the simulation consulted, whether the state holds
        no account for it."""
        tx = self.tx
        sim: dict[bytes, list] = {}  # authority -> [simulated nonce, its code applies, absent]
        accepted: list[bytes] = []
        for chain_id, _, nonce, authority in tx.authorizations:
            if self.entry_gate(chain_id, nonce, authority) is not None:
                continue
            if authority not in sim:
                acct = self.state.get(authority)  # the sender's nonce already holds validation's bump (SATIN-AUTH-004)
                applies = acct is None or not acct.code or delegate_of(acct.code) is not None
                sim[authority] = [acct.nonce if acct else 0, applies, acct is None]
            s = sim[authority]
            if not s[1] or nonce != s[0]:
                continue
            s[0] += 1
            if authority not in accepted:
                accepted.append(authority)
        return accepted, {a: s[2] for a, s in sim.items()}

    def list_crossing(self):
        """SATIN-AUTH-010: the list's KV and state-growth totals, from its simulation of the whole list (SATIN-AUTH-005),
        against what the body and the counts before it left; (kind, the transaction limit) when the list does not fit,
        the KV-update limit first, else None. The simulation charges no gas (SATIN-AUTH-007)."""
        tx, d = self.tx, self.d
        accepted, absent = self.simulate_list()
        kv = sum(1 for a in accepted if a != tx.sender)
        growth = sum(1 for a in accepted if absent[a])
        kv_left, growth_left = TX_KV_UPDATE_LIMIT - len(self.kv), TX_STATE_GROWTH_LIMIT - self.growth
        crossed = ((KV_UPDATE_STOP, TX_KV_UPDATE_LIMIT) if kv > kv_left else
                   (STATE_GROWTH_STOP, TX_STATE_GROWTH_LIMIT) if growth > growth_left else None)
        if self.lists:
            gated = [self.entry_gate(c, n, a) for c, _, n, a in tx.authorizations]
            gated = [g for g in gated if g is not None]
            consulted = len(absent)
            d.add("limit", f"the list's simulation walks its {fmt(len(tx.authorizations))} entries in order, as it does "
                  "for every list whatever its length, writing nothing, warming nothing and charging nothing, a cold "
                  "access included: " + (f"{fmt(len(gated))} entries are skipped by their gates and read nothing; "
                                         if gated else "") +
                  f"{fmt(consulted)} distinct authorities are consulted, each loaded once with its code; "
                  f"{fmt(len(accepted))} of them are accepted"
                  + (", the sender among them, whose account is a fixed record of the body" if tx.sender in accepted
                     else "") +
                  f", and {fmt(growth)} of those the state holds no account for, so the list would keep {fmt(kv)} write "
                  f"records and {fmt(growth)} of state growth, against the {fmt(kv_left)} KV updates and "
                  f"{fmt(growth_left)} of state growth the body and the counts before it leave the transaction: the list "
                  + ("does not fit" if crossed else "fits"),
                  "SATIN-AUTH-001", "SATIN-AUTH-007", "SATIN-AUTH-008", "SATIN-AUTH-010",
                  *(("SATIN-AUTH-002",) if gated else ()),
                  *(("SATIN-AUTH-003", "SATIN-AUTH-004", "SATIN-AUTH-005") if consulted else ()),
                  *(("SATIN-STATE-011", "SATIN-ACCT-015") if len(accepted) > growth else ()))
        if crossed is None:
            return None
        if not self.stops:
            raise Unmodelled("a list that does not fit outside the limit-stop cases")
        if self.lists:
            # No observation shows what the skip leaves warm: the transaction's own frame never runs (D-89).
            d.add("limit", f"its {'KV' if crossed[0] == KV_UPDATE_STOP else 'state-growth'} total crosses the transaction "
                  "limit, so none of the list is applied: no authority's state gas, ACCOUNT_WRITE or record history is "
                  "charged, and no authority's account, nonce, delegation or record is kept; the list's limit is decided "
                  "before those charges, so the out-of-gas path of the charges before the first frame is not taken",
                  "SATIN-AUTH-010", "SATIN-AUTH-011", "SATIN-AUTH-015", "SATIN-STOP-017")
        else:
            d.add("limit", f"the list's simulation walks its {fmt(len(tx.authorizations))} entries, charging nothing: "
                  f"{fmt(len(accepted))} distinct authorities accepted, {fmt(growth)} of them absent, so the list would make "
                  f"{fmt(kv)} write records and {fmt(growth)} of state growth, against the {fmt(kv_left)} KV updates and "
                  f"{fmt(growth_left)} of state growth the body and the counts before it leave the transaction: its "
                  + ("KV" if crossed[0] == KV_UPDATE_STOP else "state-growth") + " total crosses the transaction limit, "
                  "so none of the list is applied: no authority's state gas, ACCOUNT_WRITE or record history is charged, no "
                  "authority's account, nonce, delegation or record is kept, and no authority is made warm",
                  "SATIN-AUTH-005", "SATIN-AUTH-007", "SATIN-AUTH-010", "SATIN-AUTH-011", "SATIN-AUTH-012",
                  "SATIN-AUTH-015", "SATIN-STOP-017")
        if self.lists:
            kept = [a for a in accepted if a == tx.sender or not absent[a]]
            d.add("state", "the skip is all or nothing: " + (
                f"{fmt(len(kept))} accepted authorities whose accounts exist, which would have fitted by themselves, are "
                "not applied either: their nonces and code stay as the state holds them" if kept else
                "no entry of the list is applied") +
                ("; the sender's own entry is not applied, so its nonce is validation's bump alone and it gets no code"
                 if tx.sender in accepted else ""),
                "SATIN-AUTH-011", "SATIN-AUTH-013")
            d.add("outcome", "the list rule is decided during execution, where the authorities are read: the transaction "
                  "passed validation and is included, its own frame stopped; no pool refuses it before inclusion",
                  "SATIN-AUTH-018", "SATIN-AUTH-013")
        return crossed

    def apply_authorizations(self, regular: int, reservoir: int):
        """SATIN-SCHED-008 step 2 and the authorities' records of step 3, for a list that fits: each entry in list
        order, skipped by its gates, by its authority's code or by its nonce, or accepted and charged."""
        tx, env, d = self.tx, self.env, self.d
        done: set = set()  # the authorities an accepted entry wrote
        indicated: set = set()  # the authorities a list entry set an indicator for (SATIN-AUTH-009)
        self.applied_authorities: set = set()
        self.probe.setdefault("list", regular)
        for index, (chain_id, target, nonce, authority) in enumerate(tx.authorizations):
            gate = self.entry_gate(chain_id, nonce, authority)
            if gate is not None:
                d.add("gasLedgers", f"entry {index}: {gate}: it is skipped before its authority is read, so no account is "
                      "loaded or made warm for it, and it is charged nothing beyond its PER_AUTH_BASE_COST, which "
                      "validation charged", "SATIN-AUTH-002", "SATIN-AUTH-007", "SATIN-AUTH-014", "SATIN-SCHED-007")
                if authority is not None:
                    self.authority_warmth.setdefault(authority, ("is not warm: its only entry the gates skipped, the "
                                                                 "application loaded and warmed nothing for it",
                                                                 ("SATIN-AUTH-002", "SATIN-AUTH-014")))
                continue
            acct = self.state.get(authority)
            if self.lists:
                self.warm_accounts.add(authority)  # the application loads it before its checks (SATIN-AUTH-014)
                self.authority_warmth[authority] = ("is warm: the list's application loaded it",
                                                    ("SATIN-AUTH-014",))
            if acct is not None and acct.code and delegate_of(acct.code) is None:
                if not self.lists:
                    raise Unmodelled("an authority that holds code other than a delegation")
                d.add("gasLedgers", f"entry {index}: the authority {h(authority)} holds code other than a delegation "
                      "indicator: the entry is skipped and its nonce is not bumped; the application loaded the account "
                      "before that check, so the authority is warm", "SATIN-AUTH-003", "SATIN-AUTH-014", "SATIN-AUTH-007")
                continue
            if (acct.nonce if acct else 0) != nonce:
                if not self.lists:
                    raise Unmodelled("an authorization whose nonce does not match")
                d.add("gasLedgers", f"entry {index}: nonce {nonce} against the authority {h(authority)}'s effective "
                      f"nonce {acct.nonce if acct else 0}" + (", the sender's after validation's bump"
                                                               if authority == tx.sender else "") +
                      ": the entry is skipped; the application loaded the account before that check, so the authority is "
                      "warm", "SATIN-AUTH-004", "SATIN-AUTH-014", "SATIN-AUTH-007")
                continue
            again = authority in done
            sender = authority == tx.sender
            at_start = self.pre.get(authority)
            held = at_start is not None and delegate_of(at_start.code) is not None  # an indicator at the tx's start
            done.add(authority)
            self.applied_authorities.add(authority)
            self.warm_accounts.add(authority)
            charges = []
            if sender:
                if not self.lists:
                    raise Unmodelled("the sender's own authorization")
                d.add("gasLedgers", f"entry {index}: the sender's own authorization, accepted at nonce {nonce}, its nonce "
                      "after validation's bump: the sender exists, so no new-account state gas; validation paid its "
                      "account write in TX_BASE_COST, so no ACCOUNT_WRITE; and its account is a fixed record of the body, "
                      "so it makes no write record", "SATIN-AUTH-004", "SATIN-AUTH-008", "SATIN-AUTH-015",
                      "SATIN-SCHED-008", "SATIN-ACCT-008")
            elif again:
                d.add("gasLedgers", f"a further entry for the authority {h(authority)}, accepted at nonce {nonce}: an earlier "
                      "entry of the list made its account, so it is charged no new-account state gas and is no further rise "
                      "of state growth", "SATIN-SCHED-008", "SATIN-AUTH-009", "SATIN-TAKE-008",
                      *(("SATIN-AUTH-008",) if self.lists else ()))
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
                      f"{acct.balance}, " + ("its delegation indicator" if acct.code else "no code") + "), an existing "
                      "account whether or not it is empty under EIP-161: no new-account state gas", "SATIN-SCHED-008",
                      "SATIN-STATE-011", "SATIN-AUTH-008")
                d.add("resources", "the authority exists, so it is no rise of state growth, empty under EIP-161 though it is"
                      if acct.empty() else "the authority exists, so it is no rise of state growth",
                      "SATIN-ACCT-015", "SATIN-AUTH-008")
            if sender:
                pass
            elif again:
                d.add("gasLedgers", "no ACCOUNT_WRITE: the list's first entry for the authority paid its first write",
                      "SATIN-SCHED-008", "SATIN-AUTH-015", "SATIN-TAKE-008")
            elif not (tx.to == authority and tx.value):
                if ACCOUNT_WRITE > regular:
                    if index or acct is None or (self.lists and self.applied_authorities - {authority}):
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
            if any(target) and authority in indicated and not self.lists:
                raise Unmodelled("a second non-zero authorization for an authority")
            if not any(target) and authority in indicated:
                d.add("gasLedgers", f"the entry clears the delegation: a clear charges no indicator state gas and gives "
                      f"none back, so the {fmt(DELEGATION_STATE_BYTES * COST_PER_STATE_BYTE * self.multiplier(self.salt_bucket(authority, None)))} "
                      "the earlier entry charged for the indicator are given back to no one and stay charged",
                      "SATIN-AUTH-009", "SATIN-TAKE-008")
            if any(target) and (held or authority in indicated):
                d.add("gasLedgers", "no delegation-indicator state gas: the authority " +
                      ("holds an indicator at the start of the transaction" if held else
                       "had an indicator set by an earlier entry of the list"), "SATIN-AUTH-009")
            elif any(target):
                indicated.add(authority)
                m = self.multiplier(self.salt_bucket(authority, None))
                indicator = DELEGATION_STATE_BYTES * COST_PER_STATE_BYTE * m
                charges.append(("state", indicator))
                d.add("gasLedgers", f"the delegation indicator: DELEGATION_STATE_BYTES {DELEGATION_STATE_BYTES} x "
                      f"COST_PER_STATE_BYTE {fmt(COST_PER_STATE_BYTE)} x m={m} = {fmt(indicator)} state gas, once, no legacy "
                      "share; not a unit of state growth", "SATIN-AUTH-009", "SATIN-STATE-003", "SATIN-SCHED-008")
            elif self.lists and not again:
                d.add("gasLedgers", "a zero delegation target: the entry bumps the nonce, and creates the account when the "
                      "state holds none, but writes no indicator and is charged no indicator state gas", "SATIN-AUTH-009")
            record = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            if sender:
                pass
            elif again:
                d.add("resources", "the authority keeps the one write record the list's first entry for it made: no "
                      "further record, KV update or history", "SATIN-AUTH-008", "SATIN-ACCT-004", "SATIN-TAKE-008")
            else:
                charges.append(("history", record))
                self.kv.add(("a", authority))
                self.data_size += WRITE_RECORD_SIZE
                self.history_bytes += WRITE_RECORD_SIZE
            if not again and not sender:
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
            if any(target):
                d.add("state", f"the authority's nonce becomes {a.nonce} and its code the delegation indicator 0xef0100 "
                      f"followed by {h(target)}", "SATIN-AUTH-004")
            else:
                d.add("state", f"the authority's nonce becomes {a.nonce} and its delegation is cleared: no code",
                      "SATIN-AUTH-004", "SATIN-TAKE-008")
        return regular, reservoir
