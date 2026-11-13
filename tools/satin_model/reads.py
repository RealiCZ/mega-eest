"""The `reads` group: what the transaction loads, as the stateless witness needs it (`SATIN-WIT-001`)."""

from __future__ import annotations

from .constants import (
    BASE_FEE_VAULT, ex, L1_BASE_FEE_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_BLOCK_ADDRESS, L1_ECOTONE_SCALARS_SLOT,
    L1_FEE_OVERHEAD_SLOT, L1_FEE_VAULT, L1_OPERATOR_SCALARS_SLOT, MIN_BUCKET_SIZE, OPERATOR_FEE_VAULT,
)
from .records import bucket_multiplier, h, q, Unmodelled, word


class ReadsMixin:
    """The `reads` group: what the transaction loads, as the stateless witness needs it (`SATIN-WIT-001`)."""

    def load(self, address: bytes, why: str, *rules: str) -> None:
        """An account the transaction loads, as the pre-state holds it (absent: None)."""
        if address not in self.loaded_accounts:
            self.loaded_accounts[address] = self.pre.get(address)
            if self.reads:
                self.d.add("reads", f"{h(address)} is loaded: {why}", *rules)

    def load_slot(self, address: bytes, key: int, why: str, *rules: str) -> None:
        """A slot the transaction loads, as the pre-state holds it; an absent account has no slot to load
        (SATIN-WIT-006)."""
        if (address, key) not in self.loaded_slots and self.pre.get(address) is not None:
            self.loaded_slots[(address, key)] = self.pre[address].storage.get(key, 0)
            if self.reads:
                self.d.add("reads", f"slot {key} of {h(address)} is loaded: {why}", *rules)

    def multiplier(self, bucket: int) -> int:
        """The bucket multiplier of a state charge, its capacity served by the SALT environment and exported
        (SATIN-WIT-013)."""
        self.served_buckets.setdefault(bucket, self.env.buckets.get(bucket, MIN_BUCKET_SIZE))
        return bucket_multiplier(self.env, bucket)

    def fee_reads(self) -> None:
        """What every transaction that is not a deposit reads for its fees: the L1 block contract's
        slots, before it runs, and the fee recipients at its settlement (SATIN-WIT-008, -011)."""
        l1 = self.pre.get(L1_BLOCK_ADDRESS)
        self.load(L1_BLOCK_ADDRESS, "the L1 block information the transaction's L1 fee and data-availability "
                  "footprint read, outside its journal, reported with it", "SATIN-WIT-003", "SATIN-WIT-011")
        slots = [L1_BASE_FEE_SLOT, L1_ECOTONE_SCALARS_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_OPERATOR_SCALARS_SLOT]
        if l1 is not None and not l1.storage.get(L1_ECOTONE_SCALARS_SLOT, 0):
            slots.append(L1_FEE_OVERHEAD_SLOT)
        elif l1 is not None:
            raise Unmodelled("an L1 block contract with Ecotone scalars")
        for slot in sorted(slots):
            self.load_slot(L1_BLOCK_ADDRESS, slot, "the L1 fee computation's slots, the overhead slot as the Ecotone "
                           "scalars are empty, and the footprint gas scalar's", "SATIN-WIT-011")
        for who, what in ((self.env.coinbase, "the block beneficiary"), (BASE_FEE_VAULT, "the base fee vault"),
                          (L1_FEE_VAULT, "the L1 fee vault"), (OPERATOR_FEE_VAULT, "the operator fee vault")):
            self.load(who, f"{what}, a fee recipient the settlement credits", "SATIN-WIT-008", "SATIN-BASE-001")

    def reads_observation(self) -> dict:
        """The `reads` group: the accounts and slots loaded, the code of every loaded account that has code
        (the witness holds it whether or not the load brought it, SATIN-WIT-001), and the SALT capacities
        served; no block hash, oracle service answer or hint is in this model's cases."""
        accounts = {h(a): None if x is None else {"nonce": q(x.nonce), "balance": q(x.balance), "codeHash": h(ex.keccak256(x.code))}
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
                   f"capacities {len(self.served_buckets)}; no block hash, oracle answer or hint",
                   "SATIN-WIT-001", "SATIN-WIT-005", "SATIN-WIT-013")
        return {"accounts": accounts, "storage": storage, "codes": codes, "blockHashes": {},
                "buckets": {q(b): q(c) for b, c in sorted(self.served_buckets.items())}, "oracle": [], "hints": []}
