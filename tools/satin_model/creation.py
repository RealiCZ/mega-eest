"""A `CREATE` from a frame (`SATIN-HIST-009`, `-011`, `SATIN-LIM-008`), and a `SELFDESTRUCT` of an account created in
the same transaction: its charges, the destruction table's give-back and its positive effects, in the order of
`SATIN-SD-019`."""

from __future__ import annotations

from .constants import (
    ACCOUNT_STATE, BLOCK_ENV_ACCESS_COMPUTE_GAS, CODE_STATE_PER_BYTE, COLD_ACCOUNT_ACCESS, COST_PER_HISTORY_BYTE,
    GAS_RETAINED_DENOMINATOR, GAS_RETAINED_NUMERATOR, LEGACY_CREATE_SHARE, LEGACY_SELFDESTRUCT_SHARE, SELFDESTRUCT_COST,
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
        if target == self.env.coinbase or creator == self.env.coinbase:
            d.add("outcome", f"the CREATE's {'created address' if target == self.env.coinbase else 'creator'} is the block "
                  "beneficiary: its loads of the creator and the created address are the creation's own checks, so it "
                  "is not marked as a read" + (", and it is not refused though the frame's volatile-data access is off"
                                               if frame.get("access_off") else ""), "SATIN-DET-006")
        self.warm_accounts.add(target)
        m = self.multiplier(self.salt_bucket(target, None))
        state = ACCOUNT_STATE * m
        legacy = min(state, LEGACY_CREATE_SHARE)
        reservoir = frame["reservoir"]
        self.charge_state(frame, state, legacy, "the created account")
        self.state_gas += state
        if target in self.pre:
            if not self.destruction:
                raise Unmodelled("a creation onto an address the state holds a leaf for")
            d.add("gasLedgers", f"CREATE of {h(target)}, whose leaf the state holds with nonce 0, no balance, no code and "
                  f"{len(self.pre[target].storage)} slots: the creation does not collide on storage alone, and the address, "
                  "empty under EIP-161, is charged and counted as a new account", "SATIN-SD-016", "SATIN-SD-017",
                  "SATIN-STATE-011", "SATIN-ACCT-014")
        where = "an address the state holds no account for" if target not in self.pre else "an address empty under EIP-161"
        d.add("gasLedgers", f"CREATE of {h(target)}, {where}: before the forward, the "
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
        self.created.add(target)  # from its start: a constructor can destroy the account it creates (SATIN-SD-014)
        if acct.storage:
            self.storage_reads_zero(target, acct)
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
        if creator in records:
            self.kv.add(("a", creator))
            self.data_size += WRITE_RECORD_SIZE
            d.add("resources", f"the creator's nonce record ({WRITE_RECORD_SIZE} bytes, one KV update), counted on the "
                  "creator once the creation returned", "SATIN-LIM-008", "SATIN-ACCT-004")
        return target, left

    def storage_reads_zero(self, target: bytes, acct: Account) -> None:
        """A creation onto an address whose leaf the state holds with storage (SATIN-SD-016): a slot the
        transaction first accesses after the creation reads zero and has an original of zero (SATIN-SD-003); a
        slot the state held that the transaction never accesses is not read at all."""
        if any((target, k) in self.original for k in acct.storage):
            raise Unmodelled("a slot of a created address the transaction accessed before the creation")
        self.zero_storage.add(target)
        self.d.add("gasLedgers", f"the created account's slots read zero from its creation on: each of the "
                   f"{len(acct.storage)} slots the state holds at {h(target)} that the transaction first accesses after "
                   "the creation has an original of zero, whatever the state held there", "SATIN-SD-003", "SATIN-SD-016")
        acct.storage = {}

    def selfdestruct(self, frame, address: bytes, beneficiary: bytes) -> None:
        """A `SELFDESTRUCT`, in the order of SATIN-SD-019: its charges; for the first effective destruction of an
        account created in the transaction, the destruction table's give-back into the destroying frame's reservoir
        (SATIN-SD-004, -005, -007) and the mark (SATIN-SD-002), and for any other, nothing of the table (SATIN-SD-011,
        -012); its positive effects, the records it makes, the transfer log and the beneficiary's rise; the history
        of the records it makes; and the volatile reads of either end, marked last (SATIN-SD-020). A marked account
        is deleted at the transaction's end (EIP-6780, SATIN-SD-015)."""
        d = self.d
        if beneficiary == address and (address in self.created or not self.destruction):
            raise Unmodelled("a SELFDESTRUCT to itself of an account created in the transaction")
        if frame.get("access_off") and self.env.coinbase in (address, beneficiary):
            raise Unmodelled("a SELFDESTRUCT that reads the block beneficiary with volatile-data access off")
        first = address in self.created and address not in self.destroyed
        if not first and not self.destruction:
            raise Unmodelled("a SELFDESTRUCT of an account not created in the transaction, or a repeated one")
        acct = self.state[address]
        balance = acct.balance
        new_ben = self.destruction_charges(frame, address, beneficiary, balance, first)
        if first:
            self.destruction_table(frame, address, acct)
        elif address in self.destroyed:
            d.add("gasLedgers", f"step 2: {h(address)} is marked by an earlier destruction that stands: this one applies "
                  "the table for nothing, refilling nothing and taking nothing back", "SATIN-SD-011", "SATIN-SD-019")
            d.add("resources", "the repeated destruction subtracts nothing: no fall of state growth, no record taken "
                  "back", "SATIN-SD-011")
        else:
            d.add("gasLedgers", f"step 2: {h(address)} was not created in the transaction: the destruction table does not "
                  "apply and the account is not marked, so nothing is refilled or taken back, and EIP-6780 does not "
                  "delete it", "SATIN-SD-012", "SATIN-SD-001", "SATIN-SD-019")
            d.add("resources", "the destruction of an account the transaction did not create subtracts nothing",
                  "SATIN-SD-012")
        self.destruction_effects(frame, address, beneficiary, balance, new_ben, first)
        if first:
            self.destroyed.add(address)
            if self.destruction:
                d.add("state", f"the first effective destruction of {h(address)}, created in the transaction, applied "
                      "the table to its leaf, its code and each of its slots and marks it: the account stays until the "
                      "transaction ends and is then deleted", "SATIN-SD-001", "SATIN-SD-002")
        for end, who in ((address, "the destroyed account"), (beneficiary, "the beneficiary")):
            if end == self.env.coinbase:
                self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, f"the SELFDESTRUCT's read of {who}, the block beneficiary, once "
                          "its last step that can fail is passed,")
                self.d.add("gasLedgers", "the read is marked only after every step of the SELFDESTRUCT that can fail",
                           "SATIN-SD-020")
                self.split(frame)
                break

    def destruction_charges(self, frame, address: bytes, beneficiary: bytes, balance: int, first: bool) -> bool:
        """Step 1 of SATIN-SD-019: the regular gas, then a new beneficiary's state gas, its legacy share first.
        Returns whether the beneficiary is a new account."""
        d = self.d
        cold = beneficiary not in self.warm_accounts
        self.load(beneficiary, "the SELFDESTRUCT's beneficiary", "SATIN-WIT-002")
        ben = self.state.get(beneficiary)
        new_ben = bool(balance) and (ben is None or ben.empty())
        # A cold beneficiary: SELFDESTRUCT has no warm base, so its access is the whole cold account access, EIP-2929's
        # charge for it at EIP-8038's price (SATIN-SCHED-001, decision D-71).
        regular = SELFDESTRUCT_COST + (COLD_ACCOUNT_ACCESS if cold else 0) + (SELFDESTRUCT_NEW_ACCOUNT_COST if new_ben else 0)
        self.charge_regular(frame, regular, "SELFDESTRUCT")
        self.warm_accounts.add(beneficiary)
        reservoir = frame["reservoir"]
        if new_ben:
            m = self.multiplier(self.salt_bucket(beneficiary, None))
            state = ACCOUNT_STATE * m
            legacy = min(state, LEGACY_SELFDESTRUCT_SHARE)
            if self.destruction and state - legacy > frame["reservoir"] + frame["regular"] - legacy:
                d.add("gasLedgers", f"SELFDESTRUCT of {h(address)} to {h(beneficiary)}, empty under EIP-161, moving {balance} "
                      f"wei, step 1, its charges: regular {fmt(regular)}, then the beneficiary's new-account state gas "
                      f"{fmt(ACCOUNT_STATE)} x m={m} = {fmt(state)}, its legacy share {fmt(legacy)} from regular gas first, "
                      f"which leaves {fmt(frame['regular'] - legacy)} of regular gas and {fmt(frame['reservoir'])} of "
                      f"reservoir, short of the rest, {fmt(state - legacy)}: the frame halts in the opcode's charges, "
                      "before the table, the move and any mark of a volatile read", "SATIN-SD-019", "SATIN-SD-018",
                      "SATIN-SD-020", "SATIN-STATE-012", "SATIN-POOL-008", "SATIN-DET-003")
            self.charge_state(frame, state, legacy, "the beneficiary's new account")
            self.state_gas += state
            paid = min(reservoir, state - legacy)
            d.add("gasLedgers", f"SELFDESTRUCT of {h(address)} to {h(beneficiary)}, {'cold' if cold else 'warm'} and empty "
                  f"under EIP-161, moving {balance} wei, step 1, its charges: regular {fmt(SELFDESTRUCT_COST)} + "
                  + (f"cold access COLD_ACCOUNT_ACCESS {fmt(COLD_ACCOUNT_ACCESS)} + " if cold else "")
                  + "the new account of SELFDESTRUCT "
                  f"{fmt(SELFDESTRUCT_NEW_ACCOUNT_COST)} = {fmt(regular)}; the beneficiary's new-account state gas "
                  f"{fmt(ACCOUNT_STATE)} x m={m} = {fmt(state)}, its legacy share min({fmt(state)}, PRE_FORK_NEW_ACCOUNT_COST - "
                  f"SELFDESTRUCT_NEW_ACCOUNT_COST) = {fmt(legacy)} from regular gas first, {fmt(regular + legacy)} of regular "
                  f"gas in all, then {fmt(paid)} from the reservoir and {fmt(state - legacy - paid)} from regular gas"
                  + ("; the give-back comes only after these charges" if first else ""), "SATIN-SD-019", "SATIN-SD-018",
                  "SATIN-SCHED-002", "SATIN-STATE-012", "SATIN-POOL-008", *(("SATIN-SCHED-001",) if cold else ()))
        else:
            d.add("gasLedgers", f"SELFDESTRUCT of {h(address)} to {h(beneficiary)}, holding {balance} wei, step 1, its "
                  f"charges: regular {fmt(SELFDESTRUCT_COST)}"
                  + (f" + cold access COLD_ACCOUNT_ACCESS {fmt(COLD_ACCOUNT_ACCESS)}" if cold else ", the beneficiary warm")
                  + (", no beneficiary created" if not balance else ""), "SATIN-SD-019", "SATIN-SCHED-002",
                  *(("SATIN-SCHED-001",) if cold else ()))
        return new_ben

    def destruction_table(self, frame, address: bytes, acct: Account) -> None:
        """Step 2 of SATIN-SD-019 for the first effective destruction: the table of SATIN-SD-004, by each part's value
        at the transaction's start, given back into the destroying frame's reservoir."""
        d = self.d
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
        if self.destruction and address in self.pre:
            d.add("gasLedgers", f"the leaf of {h(address)} was present at the transaction's start, empty under EIP-161 with "
                  "storage: its row gives nothing back, so the creation's new-account state gas and its rise stay, and the "
                  "account's write record stands", "SATIN-SD-004", "SATIN-SD-017")
            untouched = sorted(k for k in self.pre[address].storage if (address, k) not in self.original)
            if untouched:
                d.add("resources", f"slot{'s' if len(untouched) > 1 else ''} {', '.join(map(str, untouched))}, which the "
                      "state held and the transaction never accessed, make no record as the account is deleted",
                      "SATIN-SD-016", "SATIN-SD-004")
        refill = sum(r for _, r in refills)
        history += RECORD_HISTORY * len(takes)
        data += WRITE_RECORD_SIZE * len(takes)
        for record in takes:
            self.kv.discard(record)
        self.give_back(frame, refill + history)
        frame["give_back"] = frame.get("give_back", 0) + refill + history  # what returns up the chain (SATIN-SD-010)
        self.state_gas -= refill
        self.history_gas -= history
        self.history_bytes -= data
        self.data_size -= data
        self.growth -= fall
        d.add("gasLedgers", f"step 2, the destruction table: refills of {', '.join(f'{w} {fmt(r)}' for w, r in refills) or 'nothing'}, "
              f"{fmt(refill)} of state gas, and {fmt(history)} of history gas, {len(takes)} records x "
              f"{fmt(RECORD_HISTORY)} and the code's {len(acct.code)} bytes x {COST_PER_HISTORY_BYTE}, given back: "
              f"{fmt(refill + history)} into the destroying frame's reservoir, now {fmt(frame['reservoir'])}, whichever "
              "frame and pool paid them", "SATIN-SD-004", "SATIN-SD-005", "SATIN-SD-007", "SATIN-SD-008", "SATIN-SD-009",
              "SATIN-HIST-007", "SATIN-HIST-012", "SATIN-TAKE-007")
        d.add("resources", f"the destruction counts -{fall} of state growth, -{len(takes)} KV updates and -{fmt(data)} "
              "bytes of data size on the destroying frame", "SATIN-SD-006", "SATIN-SD-007", "SATIN-SD-008",
              "SATIN-TAKE-007")

    def destruction_effects(self, frame, address: bytes, beneficiary: bytes, balance: int, new_ben: bool,
                            first: bool) -> None:
        """Steps 3 and 4 of SATIN-SD-019: the positive effects held to the limits in the dimension order, then the
        history of the records they make."""
        d, tx = self.d, self.tx
        acct = self.state[address]
        if not balance:
            if not first:
                d.add("resources", "step 3: no balance moves, so no account is written, no beneficiary created and no "
                      "transfer log emitted", "SATIN-SD-001", "SATIN-SD-018", "SATIN-SD-019")
            return
        if beneficiary == address:
            d.add("resources", f"step 3: the beneficiary is {h(address)} itself, which the transaction did not create: "
                  "EIP-6780 moves nothing and deletes nothing, so no account is written, no transfer log is emitted and "
                  "nothing rises", "SATIN-SD-001", "SATIN-SD-012", "SATIN-SD-019", "SATIN-LOG-001")
            return
        made = [beneficiary] if ("a", beneficiary) not in self.kv and beneficiary != tx.sender else []
        cleared = []
        if not first and address not in self.destroyed:
            # The account it clears makes its record when this write is the first change to it (SATIN-SD-019 step 3);
            # a write that returns it to what the transaction loaded would take its record back, which no case builds.
            if address == tx.sender or (("a", address) in self.kv and self.pre[address].balance == 0):
                raise Unmodelled("a SELFDESTRUCT that returns its account to what the transaction loaded")
            cleared = [] if ("a", address) in self.kv else [address]
        records_made = cleared + made
        self.hold_to_limits(WRITE_RECORD_SIZE * len(records_made) + TRANSFER_LOG_SIZE, len(records_made), int(new_ben),
                            f"the SELFDESTRUCT of {h(address)}")
        acct.balance = 0
        self.state.setdefault(beneficiary, Account()).balance += balance
        for a in records_made:
            self.kv.add(("a", a))
        self.data_size += WRITE_RECORD_SIZE * len(records_made) + TRANSFER_LOG_SIZE
        self.growth += int(new_ben)
        self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(address), pad_address(beneficiary)],
                          balance.to_bytes(32, "big")))
        records = RECORD_HISTORY * len(records_made)
        if first:
            d.add("resources", f"step 3, after the give-back: the beneficiary's rise ({int(new_ben)}), its record "
                  f"({len(made)} KV update, {WRITE_RECORD_SIZE * len(made)} bytes) and the transfer log "
                  f"({TRANSFER_LOG_SIZE} bytes)", "SATIN-SD-018", "SATIN-SD-019", "SATIN-LOG-001", "SATIN-LOG-006")
            paid = min(frame["reservoir"], records)
            self.charge_state(frame, records, 0, "the beneficiary's record")
            self.history_gas += records
            self.history_bytes += WRITE_RECORD_SIZE * len(made)
            d.add("gasLedgers", f"step 4: the history of the beneficiary's record, {fmt(records)}, {fmt(paid)} of it from "
                  f"the reservoir and {fmt(records - paid)} from regular gas", "SATIN-SD-019", "SATIN-HIST-013",
                  "SATIN-POOL-008")
            return
        whose = [("the cleared account's" if a == address else "the beneficiary's") for a in records_made]
        rules = ["SATIN-SD-001", "SATIN-SD-019", "SATIN-LOG-001", "SATIN-LOG-006", "SATIN-ACCT-004"]
        if address in self.destroyed:
            rules += ["SATIN-SD-013"]
        if new_ben:
            rules += ["SATIN-SD-018"]
        d.add("resources", f"step 3: the balance of {balance} wei moves to the beneficiary: "
              + (f"{' and '.join(whose)} record{'s' if len(whose) > 1 else ''} "
                 f"({len(records_made)} KV update{'s' if len(records_made) > 1 else ''}, "
                 f"{WRITE_RECORD_SIZE * len(records_made)} bytes)" if records_made else "no record")
              + (", the marked account's write making none" if address in self.destroyed else "")
              + f", the transfer log ({TRANSFER_LOG_SIZE} bytes) and the beneficiary's rise ({int(new_ben)})", *rules)
        if records:
            paid = min(frame["reservoir"], records)
            self.charge_state(frame, records, 0, "the SELFDESTRUCT's records")
            self.history_gas += records
            self.history_bytes += WRITE_RECORD_SIZE * len(records_made)
            d.add("gasLedgers", f"step 4: the history of the {len(records_made)} record{'s' if len(records_made) > 1 else ''} "
                  f"it makes, {len(records_made)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(records)}, "
                  f"{fmt(paid)} of it from the reservoir and {fmt(records - paid)} from regular gas", "SATIN-SD-019",
                  "SATIN-HIST-006", "SATIN-HIST-013", "SATIN-POOL-008")
