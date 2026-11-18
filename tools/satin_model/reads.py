"""Logical loads, their transaction or block source, and the values they expose."""

from __future__ import annotations

from .constants import (
    BASE_FEE_VAULT, ex, L1_BASE_FEE_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_BLOCK_ADDRESS, L1_ECOTONE_SCALARS_SLOT,
    L1_FEE_OVERHEAD_SLOT, L1_FEE_VAULT, L1_OPERATOR_SCALARS_SLOT, MIN_BUCKET_SIZE, OPERATOR_FEE_VAULT,
)
from .records import Account, bucket_multiplier, h, q, Unmodelled, word


def account_values(account: Account) -> dict:
    return {"nonce": q(account.nonce), "balance": q(account.balance), "codeHash": h(ex.keccak256(account.code))}


class ReadsMixin:
    """Records the logical loads made by the model and the capacities served to it."""

    def load(self, address: bytes, why: str, *rules: str, external: bool = False) -> None:
        """An account the transaction loads, as the pre-state holds it (absent: None)."""
        if self.returned_state and not external:
            self.journal_accounts.add(address)
        if address not in self.loaded_accounts:
            self.loaded_accounts[address] = self.pre.get(address)
            if self.reads:
                self.d.add("reads", f"{h(address)} is loaded: {why}", *rules)

    def load_slot(self, address: bytes, key: int, why: str, *rules: str, external: bool = False) -> None:
        """A slot the transaction loads, as the pre-state holds it; an absent account has no slot to load
        (SATIN-WIT-006)."""
        if self.returned_state and not external:
            self.journal_slots.add((address, key))
        if (address, key) not in self.loaded_slots and self.pre.get(address) is not None:
            if self.reads and not external and address in self.zero_storage and address in self.created:
                raise Unmodelled("reads of storage reset by creation at a pre-existing leaf")
            self.loaded_slots[(address, key)] = self.pre[address].storage.get(key, 0)
            if self.reads:
                self.d.add("reads", f"slot {key} of {h(address)} is loaded: {why}", *rules)

    def multiplier(self, bucket: int, what: str = "") -> int:
        """The bucket multiplier of a state charge, its capacity served by the SALT environment and exported
        (SATIN-WIT-013). A system-originated transaction's charge is priced at m = 1 and reads no capacity
        (SATIN-MST-008). A case of the pricing rules (D-106) cites the bucket's mapping, the one read of its
        capacity in the transaction and, for a deposit or a system-originated transaction, how it is priced (`what`
        names the state the charge or give-back is for)."""
        if self.exempt:
            capacity = self.env.buckets.get(bucket, MIN_BUCKET_SIZE)
            self.d.add("gasLedgers", f"the state charge's bucket {bucket:#x}, of capacity {capacity:,}, would give the "
                       f"multiplier {bucket_multiplier(self.env, bucket)}; the transaction is system-originated, so the charge "
                       "is priced at m = 1 and the bucket's capacity is not read", "SATIN-MST-008")
            if self.pricing:
                self.d.add("gasLedgers", f"{what or 'the state charge'}: priced at m = 1, as every state charge of a "
                           "system-originated transaction is, and no bucket capacity is read for it", "SATIN-STATE-009")
            return 1
        if self.pricing:
            m = bucket_multiplier(self.env, bucket)
            capacity = self.env.buckets.get(bucket, MIN_BUCKET_SIZE)
            if bucket in self.served_buckets:
                self.d.add("gasLedgers", f"{what or 'the state charge'} lands in bucket {bucket:#x}, in which the "
                           f"transaction already made a charge: the same m = {m}, as for every later charge and give-back "
                           "in the bucket, so a give-back cancels its charge exactly", "SATIN-STATE-006", "SATIN-STATE-010")
            else:
                self.d.add("gasLedgers", f"{what or 'the state charge'} lands in bucket {bucket:#x}, the bucket SALT's own "
                           f"mapping (salt-v1) assigns its key; the bucket's capacity, {capacity:,}, gives m = "
                           f"floor({capacity:,} / {MIN_BUCKET_SIZE}) = {m}", "SATIN-STATE-002", "SATIN-STATE-010")
                if self.tx.kind == "deposit":
                    self.d.add("gasLedgers", "the deposit is not system-originated: it is priced by its buckets, as any "
                               "transaction is", "SATIN-STATE-009")
        self.served_buckets.setdefault(bucket, self.env.buckets.get(bucket, MIN_BUCKET_SIZE))
        return bucket_multiplier(self.env, bucket)

    def fee_reads(self) -> None:
        """What every transaction that is not a deposit reads for its fees: the L1 block contract's
        slots, before it runs, and the fee recipients at its settlement (SATIN-WIT-008, -011)."""
        l1 = self.pre.get(L1_BLOCK_ADDRESS)
        self.load(L1_BLOCK_ADDRESS, "the L1 block information the transaction's L1 fee and data-availability "
                  "footprint read, outside its journal, reported with it", "SATIN-WIT-003", "SATIN-WIT-011", external=True)
        slots = [L1_BASE_FEE_SLOT, L1_ECOTONE_SCALARS_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_OPERATOR_SCALARS_SLOT]
        if l1 is not None and not l1.storage.get(L1_ECOTONE_SCALARS_SLOT, 0):
            slots.append(L1_FEE_OVERHEAD_SLOT)
        elif l1 is not None:
            raise Unmodelled("an L1 block contract with Ecotone scalars")
        for slot in sorted(slots):
            self.load_slot(L1_BLOCK_ADDRESS, slot, "the L1 fee computation's slots, the overhead slot as the Ecotone "
                           "scalars are empty, and the footprint gas scalar's", "SATIN-WIT-011", external=True)
        for who, what in ((self.env.coinbase, "the block beneficiary"), (BASE_FEE_VAULT, "the base fee vault"),
                          (L1_FEE_VAULT, "the L1 fee vault"), (OPERATOR_FEE_VAULT, "the operator fee vault")):
            self.load(who, f"{what}, a fee recipient the settlement credits", "SATIN-WIT-008", "SATIN-BASE-001")

    def ask_oracle(self, slot: int) -> int | None:
        """Consumes and records the next answer to an Oracle service request."""
        if self.oracle_entries is None:
            raise Unmodelled("an Oracle read without service input")
        if not self.oracle_entries:
            raise Unmodelled(f"unexpected Oracle request for slot {slot}")
        expected, answer = self.oracle_entries.popleft()
        if expected != slot:
            raise Unmodelled(f"Oracle requested slot {slot}, transcript has {expected}")
        self.oracle_answers.append((slot, answer))
        return answer

    def reads_observation(self) -> dict:
        """The `reads` group: the accounts and slots loaded, the code of every loaded account that has code
        (the witness holds it whether or not the load brought it, SATIN-WIT-001), and the SALT capacities
        served, alongside the Oracle service answers and hints, each in order."""
        accounts = {h(a): None if x is None else account_values(x)
                    for a, x in sorted(self.loaded_accounts.items())}
        storage: dict = {}
        for (a, k), v in sorted(self.loaded_slots.items()):
            storage.setdefault(h(a), {})[word(k)] = q(v)
        codes = sorted({h(ex.keccak256(x.code)) for x in self.loaded_accounts.values() if x is not None and x.code})
        if getattr(self, "lists", False):
            self.d.add("reads", "no transaction reads the SequencerRegistry to be classified: the block resolves the live "
                       "system address once, before its transactions, so neither the registry's account nor its slot 0 "
                       "is in the reads", "SATIN-REG-002")
        self.d.add("reads", f"reads: accounts {len(accounts)}, slots {len(self.loaded_slots)}, codes {len(codes)}, SALT "
                   f"capacities {len(self.served_buckets)}",
                   "SATIN-WIT-001", "SATIN-WIT-005", "SATIN-WIT-013")
        hints = [{"from": h(f), "topic": h(t), "data": h(dt)} for f, t, dt in getattr(self, "hints", [])]
        if hints:
            self.d.add("reads", f"the hints handed to the oracle service, in order: {len(hints)}, each with its topic, its "
                       "data and the address of the frame that made the call", "SATIN-ORCL-007", "SATIN-WIT-001")
        oracle = [{"slot": word(slot), "value": None if answer is None else q(answer)}
                  for slot, answer in self.oracle_answers]
        if oracle:
            self.d.add("reads", "the service requests are recorded in order with their answers. A null answer "
                       "records a request that returned no value", "SATIN-ORCL-002", "SATIN-ORCL-005")
        return {"accounts": accounts, "storage": storage, "codes": codes, "blockHashes": {},
                "buckets": {q(b): q(c) for b, c in sorted(self.served_buckets.items())}, "oracle": oracle, "hints": hints}

    def returned_state_observation(self, forbidden_accounts: tuple[bytes, ...]) -> dict:
        """The journal's loaded keys and the values fixed by the model's settled state."""
        accounts = {h(a): {} if a in self.destroyed else account_values(self.state.get(a, Account()))
                    for a in sorted(self.journal_accounts)}
        storage: dict = {}
        for a, k in sorted(self.journal_slots):
            storage.setdefault(h(a), {})[word(k)] = (
                {} if a in self.destroyed else q(self.state.get(a, Account()).storage.get(k, 0)))
        for a in forbidden_accounts:
            if a in self.journal_accounts:
                raise Unmodelled(f"forbidden returned account {h(a)} was loaded")
            accounts[h(a)] = None
        self.d.add("returnedState", "the execution result names the journal's completed account and slot loads, "
                   "including loads from reverted or halted frames. Entries whose state the transaction leaves "
                   "unchanged carry their pre-state values", "SATIN-WIT-005", "SATIN-WIT-008")
        if self.destroyed & self.journal_accounts:
            self.d.add("returnedState", "accounts removed at settlement keep their completed load keys. "
                       "Their temporary account fields and slot values are unspecified",
                       "SATIN-SD-015", "SATIN-WIT-005", "SATIN-WIT-008")
        if self.tx.kind != "deposit" and not self.promoted:
            self.d.add("returnedState", "the L1 fee and footprint reads are outside the journal",
                       "SATIN-WIT-011")
        if forbidden_accounts:
            self.d.add("returnedState", "the skipped account loads leave no returned entries at "
                       + ", ".join(h(a) for a in forbidden_accounts), "SATIN-WIT-004", "SATIN-WIT-012")
        return {"accounts": accounts, "storage": storage}
