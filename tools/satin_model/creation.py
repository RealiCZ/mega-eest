"""A `CREATE` from a frame (`SATIN-HIST-009`, `-011`, `SATIN-LIM-008`), and a `SELFDESTRUCT` of an account created in
the same transaction: its charges, the destruction table's give-back and its positive effects, in the order of
`SATIN-SD-019`."""

from __future__ import annotations

from .constants import (
    ACCOUNT_STATE, CODE_STATE_PER_BYTE, COLD_ACCOUNT_SURCHARGE, COST_PER_HISTORY_BYTE, GAS_RETAINED_DENOMINATOR,
    GAS_RETAINED_NUMERATOR, LEGACY_CREATE_SHARE, LEGACY_SELFDESTRUCT_SHARE, SELFDESTRUCT_COST,
    SELFDESTRUCT_NEW_ACCOUNT_COST, SLOT_STATE, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC,
    WRITE_RECORD_SIZE,
)
from .records import Account, created_address, fmt, h, pad_address, Unmodelled

RECORD_HISTORY = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE


class CreationMixin:
    """A `CREATE` from a frame, and the `SELFDESTRUCT` of an account created in the transaction."""

    def create(self, frame, creator: bytes, value: int, init: bytes):
        """A `CREATE` once its regular charges are made: the created account's state gas before the forward, its
        legacy share first (SATIN-HIST-011, SATIN-STATE-012), the forward, the history of the start's records
        after it (SATIN-HIST-009), the creation's reservoir share (SATIN-POOL-011), the start, the init code and
        the deposit, and the creator's nonce record once the creation returned (SATIN-LIM-008). Returns (the
        created address, the regular gas the creation returns)."""
        d, tx = self.d, self.tx
        creator_acct = self.state.setdefault(creator, Account())
        target = created_address(creator, creator_acct.nonce)
        if value > creator_acct.balance:
            raise Unmodelled("a creation its creator cannot fund")
        self.load(target, "the created address, which the creation reads", "SATIN-WIT-002", "SATIN-WIT-008")
        existing = self.state.get(target)
        if existing is not None and not existing.empty():
            raise Unmodelled("a creation onto an address empty under EIP-161 or occupied")
        self.warm_accounts.add(target)
        m = self.multiplier(self.salt_bucket(target, None))
        state = ACCOUNT_STATE * m
        legacy = min(state, LEGACY_CREATE_SHARE)
        reservoir = frame["reservoir"]
        self.charge_state(frame, state, legacy, "the created account")
        self.state_gas += state
        d.add("gasLedgers", f"CREATE of {h(target)}, an address the state holds no account for: before the forward, the "
              f"created account's state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(state)}, its legacy share min({fmt(state)}, "
              f"PRE_FORK_CREATE_COST - CREATE_ACCESS) = {fmt(legacy)} from regular gas first, then "
              f"{fmt(min(reservoir, state - legacy))} from the reservoir and the rest, "
              f"{fmt(state - legacy - min(reservoir, state - legacy))}, from regular gas", "SATIN-HIST-011",
              "SATIN-STATE-001", "SATIN-STATE-003", "SATIN-STATE-012", "SATIN-POOL-008")
        remaining = frame["regular"]
        forward = remaining - remaining * GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR
        self.draw_regular(frame, forward)
        self.regular_charges += forward
        # The start's records, as the state stands: the created account, and the creator's nonce record when
        # the bump changes an account that did not differ yet (SATIN-HIST-009, SATIN-ACCT-008).
        records = [target] + ([creator] if ("a", creator) not in self.kv and creator != tx.sender else [])
        history = RECORD_HISTORY * len(records)
        if history > frame["reservoir"] + frame["regular"]:
            raise Unmodelled("a creation whose caller cannot pay its records")
        from_reservoir = min(frame["reservoir"], history)
        self.charge_state(frame, history, 0, "the creation's records")
        self.history_gas += history
        self.history_bytes += WRITE_RECORD_SIZE * len(records)
        whose = "the created account's" + (" and the creator's nonce record" if len(records) == 2 else "")
        d.add("gasLedgers", f"the forward {fmt(remaining)} - {fmt(remaining)} x {GAS_RETAINED_NUMERATOR} / "
              f"{GAS_RETAINED_DENOMINATOR} = {fmt(forward)}; after it the history of the start's {len(records)} records "
              f"({whose}), {len(records)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(history)}: "
              f"{fmt(from_reservoir)} from the reservoir and {fmt(history - from_reservoir)} from regular gas",
              "SATIN-FWD-001", "SATIN-FWD-002", "SATIN-HIST-009", "SATIN-HIST-011", "SATIN-POOL-008")
        share = self.reservoir_share(frame, "the creation")
        name = f"the creation of {h(target)}"
        child = self.new_child(frame, forward, share)
        snap = self.frame_snapshot()
        # The start: the creator's nonce bumped, the created account made, the endowment moved (SATIN-LIM-013).
        creator_acct.nonce += 1
        acct = self.state.setdefault(target, Account())
        acct.nonce = 1
        self.kv.add(("a", target))
        self.growth += 1
        self.data_size += WRITE_RECORD_SIZE
        if value:
            creator_acct.balance -= value
            acct.balance += value
            self.data_size += TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(creator), pad_address(target)],
                              value.to_bytes(32, "big")))
        d.add("resources", f"the creation's start: the creator's nonce becomes {creator_acct.nonce}; the created account, "
              f"nonce 1, is one write record ({WRITE_RECORD_SIZE} bytes) and one unit of state growth on the creation"
              + (f", and the endowment of {value} wei moves with its transfer log ({TRANSFER_LOG_SIZE} bytes)" if value else ""),
              "SATIN-LIM-013", "SATIN-ACCT-005", "SATIN-ACCT-014", "SATIN-LOG-001", "SATIN-LOG-006")
        status, out = self.run_child(child, init, {"address": target, "caller": creator, "value": value,
                                                   "calldata": b"", "name": name}, name, create=True)
        if status != "success":
            raise Unmodelled("a creation that fails")
        d.add("gasLedgers", f"{name} returns {fmt(child['regular'])} of regular gas to its creator", "SATIN-POOL-012")
        left = self.end_child(frame, child, status, snap, name)
        self.created.add(target)
        if creator in records:
            self.kv.add(("a", creator))
            self.data_size += WRITE_RECORD_SIZE
            d.add("resources", f"the creator's nonce record ({WRITE_RECORD_SIZE} bytes, one KV update), counted on the "
                  "creator once the creation returned", "SATIN-LIM-008", "SATIN-ACCT-004")
        return target, left

    def selfdestruct(self, frame, address: bytes, beneficiary: bytes) -> None:
        """The first `SELFDESTRUCT` of an account created in the transaction, in the order of SATIN-SD-019: its
        charges; the destruction table's give-back into the destroying frame's reservoir (SATIN-SD-004, -005,
        -007); its positive effects, the beneficiary's record, the transfer log and the beneficiary's rise; the
        history of the records it makes; then the account is deleted (EIP-6780)."""
        d, tx = self.d, self.tx
        if address not in self.created or address in self.destroyed or beneficiary == address:
            raise Unmodelled("a SELFDESTRUCT of an account not created in the transaction, a repeated one, or to itself")
        acct = self.state[address]
        balance = acct.balance
        cold = beneficiary not in self.warm_accounts
        self.load(beneficiary, "the SELFDESTRUCT's beneficiary", "SATIN-WIT-002")
        ben = self.state.get(beneficiary)
        new_ben = bool(balance) and (ben is None or ben.empty())
        regular = SELFDESTRUCT_COST + (COLD_ACCOUNT_SURCHARGE if cold else 0) + (SELFDESTRUCT_NEW_ACCOUNT_COST if new_ben else 0)
        self.charge_regular(frame, regular, "SELFDESTRUCT")
        self.warm_accounts.add(beneficiary)
        state = 0
        reservoir = frame["reservoir"]
        if new_ben:
            m = self.multiplier(self.salt_bucket(beneficiary, None))
            state = ACCOUNT_STATE * m
            legacy = min(state, LEGACY_SELFDESTRUCT_SHARE)
            self.charge_state(frame, state, legacy, "the beneficiary's new account")
            self.state_gas += state
            paid = min(reservoir, state - legacy)
            d.add("gasLedgers", f"SELFDESTRUCT of {h(address)} to {h(beneficiary)}, warm and empty under EIP-161, moving "
                  f"{balance} wei, step 1, its charges: regular {fmt(SELFDESTRUCT_COST)} + the new account of SELFDESTRUCT "
                  f"{fmt(SELFDESTRUCT_NEW_ACCOUNT_COST)} = {fmt(regular)}; the beneficiary's new-account state gas "
                  f"{fmt(ACCOUNT_STATE)} x m={m} = {fmt(state)}, its legacy share min({fmt(state)}, PRE_FORK_NEW_ACCOUNT_COST - "
                  f"SELFDESTRUCT_NEW_ACCOUNT_COST) = {fmt(legacy)} from regular gas first, {fmt(regular + legacy)} of regular "
                  f"gas in all, then {fmt(paid)} from the reservoir and {fmt(state - legacy - paid)} from regular gas; the "
                  "give-back comes only after these charges", "SATIN-SD-019", "SATIN-SD-018", "SATIN-SCHED-002",
                  "SATIN-STATE-012", "SATIN-POOL-008")
        else:
            d.add("gasLedgers", f"SELFDESTRUCT of {h(address)} to {h(beneficiary)}, holding {balance} wei, step 1, its "
                  f"charges: regular {fmt(SELFDESTRUCT_COST)}" + (f" + cold access {fmt(COLD_ACCOUNT_SURCHARGE)}" if cold else
                                                                  f", the beneficiary warm") +
                  (", no beneficiary created" if not balance else ""), "SATIN-SD-019", "SATIN-SCHED-002")
        # Step 2: the destruction table, by each part's value at the transaction's start (SATIN-SD-004).
        refills, history, fall, takes, data = [], 0, 0, [], 0
        m = self.multiplier(self.salt_bucket(address, None))
        if address not in self.pre:
            refills.append(("the absent leaf", ACCOUNT_STATE * m))
            fall += 1
            takes.append(("a", address))
        if acct.code:
            refills.append((f"the code's {len(acct.code)} bytes", CODE_STATE_PER_BYTE * m * len(acct.code)))
            history += COST_PER_HISTORY_BYTE * len(acct.code)
            data += len(acct.code)
        for key, now in sorted(acct.storage.items()):
            if now and self.original.get((address, key), 0) == 0:
                refills.append((f"slot {key}", SLOT_STATE * self.multiplier(self.salt_bucket(address, key))))
                fall += 1
                takes.append(("s", address, key))
        refill = sum(r for _, r in refills)
        history += RECORD_HISTORY * len(takes)
        data += WRITE_RECORD_SIZE * len(takes)
        for record in takes:
            self.kv.discard(record)
        self.give_back(frame, refill + history)
        self.state_gas -= refill
        self.history_gas -= history
        self.history_bytes -= data
        self.data_size -= data
        self.growth -= fall
        d.add("gasLedgers", f"step 2, the destruction table: refills of {', '.join(f'{w} {fmt(r)}' for w, r in refills)}, "
              f"{fmt(refill)} of state gas, and {fmt(history)} of history gas, {len(takes)} records x "
              f"{fmt(RECORD_HISTORY)} and the code's {len(acct.code)} bytes x {COST_PER_HISTORY_BYTE}, given back: "
              f"{fmt(refill + history)} into the destroying frame's reservoir, now {fmt(frame['reservoir'])}, whichever "
              "frame and pool paid them", "SATIN-SD-004", "SATIN-SD-005", "SATIN-SD-007", "SATIN-SD-008", "SATIN-SD-009",
              "SATIN-HIST-007", "SATIN-HIST-012", "SATIN-TAKE-007")
        d.add("resources", f"the destruction counts -{fall} of state growth, -{len(takes)} KV updates and -{fmt(data)} "
              "bytes of data size on the destroying frame", "SATIN-SD-006", "SATIN-SD-007", "SATIN-SD-008",
              "SATIN-TAKE-007")
        # Steps 3 and 4: the positive effects, then the history of the records they make.
        if balance:
            made = [beneficiary] if ("a", beneficiary) not in self.kv and beneficiary != tx.sender else []
            self.hold_to_limits(WRITE_RECORD_SIZE * len(made) + TRANSFER_LOG_SIZE, len(made), int(new_ben),
                                f"the SELFDESTRUCT of {h(address)}")
            acct.balance = 0
            self.state.setdefault(beneficiary, Account()).balance += balance
            for a in made:
                self.kv.add(("a", a))
            self.data_size += WRITE_RECORD_SIZE * len(made) + TRANSFER_LOG_SIZE
            self.growth += int(new_ben)
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(address), pad_address(beneficiary)],
                              balance.to_bytes(32, "big")))
            d.add("resources", f"step 3, after the give-back: the beneficiary's rise ({int(new_ben)}), its record "
                  f"({len(made)} KV update, {WRITE_RECORD_SIZE * len(made)} bytes) and the transfer log "
                  f"({TRANSFER_LOG_SIZE} bytes)", "SATIN-SD-018", "SATIN-SD-019", "SATIN-LOG-001", "SATIN-LOG-006")
            records = RECORD_HISTORY * len(made)
            paid = min(frame["reservoir"], records)
            self.charge_state(frame, records, 0, "the beneficiary's record")
            self.history_gas += records
            self.history_bytes += WRITE_RECORD_SIZE * len(made)
            d.add("gasLedgers", f"step 4: the history of the beneficiary's record, {fmt(records)}, {fmt(paid)} of it from "
                  f"the reservoir and {fmt(records - paid)} from regular gas", "SATIN-SD-019", "SATIN-HIST-013",
                  "SATIN-POOL-008")
        self.state.pop(address)
        self.destroyed.add(address)
