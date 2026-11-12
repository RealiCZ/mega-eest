"""`SSTORE` at Satin's prices, its state gas, refund, record and limits (`SATIN-TAKE-005`), and a creation's
deposited code (`SATIN-SCHED-011`)."""

from __future__ import annotations

from .constants import (
    CALL_STIPEND, CODE_STATE_PER_BYTE, COLD_SSTORE_ACCESS, COST_PER_HISTORY_BYTE, KECCAK_WORD,
    LEGACY_SSTORE_SHARE, REFUND_CLEARED, REFUND_RESTORED_FRESH, REFUND_RESTORED_RESET, SLOT_STATE, SSTORE_RESET,
    SSTORE_SET, WARM_READ, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, Halt, Unmodelled


class StorageMixin:
    """`SSTORE` at Satin's prices, its state gas, refund, record and limits (`SATIN-TAKE-005`), and a creation's"""

    def sstore(self, frame, address: bytes, key: int, new: int) -> str:
        d = self.d
        acct = self.state.setdefault(address, Account())
        present = acct.storage.get(key, 0)
        original = self.original.setdefault((address, key), self.pre.get(address, Account()).storage.get(key, 0))
        if frame.get("spendable") is not None:
            raise Unmodelled("an SSTORE in a detained frame")
        if frame["regular"] <= CALL_STIPEND:
            raise Halt(f"SSTORE with no more than the {fmt(CALL_STIPEND)} stipend left")
        self.load_slot(address, key, "SSTORE, which reads the slot's value", "SATIN-WIT-002")
        cold = (address, key) not in self.warm_slots
        self.warm_slots.add((address, key))
        access = COLD_SSTORE_ACCESS if cold else WARM_READ
        write = 0
        if new != present and present == original:
            write = SSTORE_SET if original == 0 else SSTORE_RESET
        self.charge_regular(frame, access + write, "SSTORE")
        label = f"SSTORE slot {key} {original}->{present}->{new}: {'cold' if cold else 'warm'} access {fmt(access)}"
        rules = ["SATIN-SCHED-003", "SATIN-SCHED-004"] if cold else ["SATIN-SCHED-003"]
        if write:
            label += f" + {'fresh-slot write' if original == 0 else 'reset'} {fmt(write)}"
        # The fresh-slot state charge and its give-back, SATIN-STATE-008, with the legacy share.
        m = None
        if original == 0 and present == 0 and new != 0:
            m = self.multiplier(self.salt_bucket(address, key))
            charge = SLOT_STATE * m
            legacy = min(charge, max(0, LEGACY_SSTORE_SHARE))
            self.charge_state(frame, charge, legacy, "a fresh slot")
            self.state_gas += charge
            self.growth += 1
            label += f"; state gas {fmt(SLOT_STATE)} x m={m} = {fmt(charge)} ({fmt(legacy)} legacy share first)"
            rules += ["SATIN-STATE-001", "SATIN-STATE-002", "SATIN-STATE-008", "SATIN-STATE-012", "SATIN-POOL-008"]
            d.add("resources", f"slot {key} filled from zero: state growth +1", "SATIN-ACCT-016")
        elif original == 0 and present != 0 and new == 0:
            m = self.multiplier(self.salt_bucket(address, key))
            charge = SLOT_STATE * m
            self.give_back(frame, charge)
            self.state_gas -= charge
            self.growth -= 1
            label += f"; state gas {fmt(charge)} given back into the reservoir"
            rules += ["SATIN-STATE-008", "SATIN-HIST-012"]
            d.add("resources", f"slot {key} back to zero: state growth -1", "SATIN-ACCT-016")
        # The refund counter, EIP-2200's transitions at Satin's prices.
        if new != present:
            if original != 0:
                if present == original and new == 0:
                    self.refund += REFUND_CLEARED
                    label += f"; refund +{fmt(REFUND_CLEARED)}"
                elif present != original:
                    if present == 0:
                        self.refund -= REFUND_CLEARED
                    elif new == 0:
                        self.refund += REFUND_CLEARED
            if new == original and present != original:
                bonus = REFUND_RESTORED_FRESH if original == 0 else REFUND_RESTORED_RESET
                self.refund += bonus
                label += f"; refund +{fmt(bonus)} (restored)"
            if self.refund:
                rules.append("SATIN-SCHED-003")
        # The limits on the record, in the order data size, KV updates, state growth (SATIN-TAKE-005).
        record = ("s", address, key)
        was = record in self.kv
        now = new != original
        grew = int(original == 0 and present == 0 and new != 0)
        if (now and not was) or grew:
            self.growth -= grew  # the rise is held to the limits before it is counted
            self.hold_to_limits(WRITE_RECORD_SIZE if now and not was else 0, int(now and not was), grew,
                                f"the SSTORE of slot {key}")
            self.growth += grew
        # The write record and its history, SATIN-ACCT-004 and SATIN-HIST-006.
        if now and not was:
            history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            self.charge_state(frame, history, 0, "the slot's write record")
            self.kv.add(record)
            self.data_size += WRITE_RECORD_SIZE
            self.history_gas += history
            self.history_bytes += WRITE_RECORD_SIZE
            label += f"; write record history {fmt(history)}"
            rules += ["SATIN-HIST-006", "SATIN-ACCT-004"]
            d.add("resources", f"slot {key} differs from its original: one write record, {WRITE_RECORD_SIZE} bytes",
                  "SATIN-ACCT-004", "SATIN-ACCT-012")
        elif was and not now:
            history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            self.give_back(frame, history)
            self.kv.discard(record)
            self.data_size -= WRITE_RECORD_SIZE
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE
            label += f"; write record taken back, {fmt(history)} history given back"
            rules += ["SATIN-HIST-006", "SATIN-ACCT-004"]
            d.add("resources", f"slot {key} written back to its original value: its record is taken back",
                  "SATIN-ACCT-004", "SATIN-ACCT-006")
        if new == 0:
            acct.storage.pop(key, None)
        else:
            acct.storage[key] = new
        d.add("gasLedgers", label, *rules)
        return f"SSTORE {fmt(access + write)}"

    def deposit_code(self, code: bytes, frame, address: bytes) -> None:
        """SATIN-SCHED-011: hashing, state gas and history gas of the deposited code."""
        d = self.d
        words = (len(code) + 31) // 32
        keccak = KECCAK_WORD * words
        self.charge_regular(frame, keccak, "code deposit hashing")
        m = self.multiplier(self.salt_bucket(address, None))
        state = CODE_STATE_PER_BYTE * m * len(code)
        self.charge_state(frame, state, 0, "deposited code")
        history = COST_PER_HISTORY_BYTE * len(code)
        self.charge_state(frame, history, 0, "deposited code's history")
        self.state_gas += state
        self.history_gas += history
        self.history_bytes += len(code)
        self.data_size += len(code)
        self.state[address].code = code
        d.add("gasLedgers", f"code deposit of {len(code)} bytes: hashing {words} words x {KECCAK_WORD} = {keccak}; state "
              f"{CODE_STATE_PER_BYTE} x m={m} x {len(code)} = {fmt(state)}; history {COST_PER_HISTORY_BYTE} x {len(code)} = "
              f"{fmt(history)}", "SATIN-SCHED-011", "SATIN-STATE-003", "SATIN-HIST-002")
        d.add("resources", f"deposited code adds {len(code)} bytes of data size, no state growth of its own",
              "SATIN-ACCT-002", "SATIN-ACCT-013")
