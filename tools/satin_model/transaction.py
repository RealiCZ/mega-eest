"""The transaction: validation's refusals, the intrinsic gas and the two pools, the charges before the first
frame (`SATIN-SCHED-008`), the first frame and how it ends, and the out-of-gas path before it
(`SATIN-SCHED-009`, `-010`)."""

from __future__ import annotations

from .constants import (
    ACCESS_LIST_ADDRESS, ACCESS_LIST_ADDRESS_SIZE, ACCESS_LIST_KEY, ACCESS_LIST_SLOT_SIZE, ACCOUNT_STATE,
    AUTHORIZATION_SIZE, CALLDATA_NONZERO, CALLDATA_ZERO, COLD_ACCOUNT_ACCESS, COLD_ACCOUNT_SURCHARGE,
    COST_PER_HISTORY_BYTE, CREATE_ACCESS, delegate_of, DETENTION_STOP, ex, EXECUTION_CAP, FLOOR_PER_BYTE,
    INITCODE_WORD_COST, KEYLESS_DEPLOY, KEYLESS_DEPLOY_CALL, KEYLESS_DEPLOY_CODE_HASH, limit_exceeded, MAX_CONTRACT_SIZE,
    MAX_U64, ORACLE, PER_AUTH_BASE_COST,
    STOP_DIMENSIONS, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC, TX_BASE_COST, TX_BODY_SIZE, TX_DATA_LIMIT,
    TX_VALUE_COST, WARM_READ, WRITE_RECORD_SIZE,
)
from .records import (
    Account, created_address, fmt, h, Halt, LimitStop, OutOfGasBeforeFrame, pad_address, refused, Result,
    Stopped, Unmodelled,
)
from .interception import keyless_arguments


class TransactionMixin:
    """The transaction: validation's refusals, the intrinsic gas and the two pools, the charges before the first"""

    # The refusals of transaction validation, in the order SATIN-VAL-003 fixes for Satin's own
    # checks; the base layer's checks come after, each case failing only one check.
    def validate(self, intrinsic: int, floor: int, body_history: int):
        tx, env = self.tx, self.env
        sender = self.pre.get(tx.sender, Account())
        if tx.kind == "deposit":
            return None
        if self.live_system_address() == tx.sender:
            return self.classify_system(intrinsic, body_history)
        if tx.chain_id is not None and tx.chain_id != env.chain_id:
            return ("validation", "chain-id-mismatch", "SATIN-VAL-006",
                    f"the transaction carries chain id {tx.chain_id}, the chain's is {env.chain_id}")
        # A case that pins the order cites it (D-85): the first of Satin's own checks that fails names the refusal.
        own = ("SATIN-VAL-002", "SATIN-VAL-003") if self.outcomes else "SATIN-VAL-002"
        if tx.gas_limit < intrinsic:
            return ("validation", "intrinsic-gas-too-low", own,
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} (SATIN-VAL-003 step 2)"
                    + (f"; it is below the floor {fmt(floor)} too, which step 3 checks after it" if self.outcomes and
                       floor > tx.gas_limit else ""))
        if floor > tx.gas_limit:
            return ("validation", "floor-exceeds-gas-limit", own,
                    f"floor {fmt(floor)} > gas limit {fmt(tx.gas_limit)} (SATIN-VAL-003 step 3)")
        if self.outcomes and floor == tx.gas_limit:
            self.d.add("outcome", f"the gas limit {fmt(tx.gas_limit)} is the floor exactly: step 3 refuses a floor that "
                       "exceeds the gas limit, and this one does not, so the check passes", "SATIN-VAL-002", "SATIN-VAL-003")
        if tx.gas_limit < intrinsic + body_history:
            return ("validation", "intrinsic-gas-too-low", own,
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} + body history gas "
                    f"{fmt(body_history)} = {fmt(intrinsic + body_history)} (SATIN-VAL-003 step 5)")
        if tx.gas_limit > env.block_gas_limit:
            # SATIN-BLK-009 and SATIN-BLK-013: a transaction whose gas limit does not fit in what the
            # block's gas limit has left is skipped for the block; in engine isolation the block has
            # all of its gas left, and the skip is reported as a refusal at inclusion (D-50).
            return ("inclusion", "gas-limit-exceeds-block", ("SATIN-BLK-009", "SATIN-BLK-013", "SATIN-BASE-002"),
                    f"gas limit {fmt(tx.gas_limit)} > the {fmt(env.block_gas_limit)} the block's gas limit has left: "
                    "skipped for the block, a refusal at inclusion in engine isolation")
        if tx.ty == 4 and not tx.authorizations:
            return ("validation", "invalid-authorization-list", "SATIN-VAL-007",
                    "an EIP-7702 transaction with an empty authorization list (a base-layer check)")
        if tx.nonce >= MAX_U64:
            return ("validation", "nonce-overflow", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} is 2^64 - 1, which EIP-2681 refuses (a base-layer check)")
        if sender.code and delegate_of(sender.code) is None:  # EIP-7702 lets a delegated account send
            return ("validation", "sender-has-code", "SATIN-VAL-007",
                    "the sender's account has code (EIP-3607, a base-layer check)")
        if tx.nonce < sender.nonce:
            return ("validation", "nonce-too-low", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} < account nonce {sender.nonce} (a base-layer check)")
        if tx.nonce > sender.nonce:
            return ("validation", "nonce-too-high", "SATIN-VAL-007",
                    f"transaction nonce {tx.nonce} > account nonce {sender.nonce} (a base-layer check)")
        if tx.ty in (2, 4) and tx.max_priority > tx.max_fee:
            return ("validation", "priority-fee-above-fee-cap", "SATIN-VAL-007",
                    "max priority fee above max fee (a base-layer check)")
        cap = tx.max_fee if tx.ty in (2, 4) else tx.gas_price
        if cap < env.base_fee:
            return ("validation", "fee-cap-below-base-fee", "SATIN-VAL-007",
                    f"fee cap {fmt(cap)} below the base fee {fmt(env.base_fee)} (a base-layer check)")
        cost = tx.gas_limit * cap + tx.value
        if sender.balance < cost:
            return ("validation", "insufficient-funds", "SATIN-VAL-007",
                    f"balance {fmt(sender.balance)} < gas limit x fee cap + value = {fmt(cost)} (a base-layer check)")
        if self.outcomes:
            self.d.add("outcome", f"admitted: the gas limit {fmt(tx.gas_limit)} pays the intrinsic regular gas "
                       f"{fmt(intrinsic)} with the body's history {fmt(body_history)}, {fmt(intrinsic + body_history)}, and "
                       f"the floor {fmt(floor)}, and every check of the base layer passes", "SATIN-VAL-002", "SATIN-VAL-003",
                       "SATIN-VAL-007")
            if tx.chain_id is None:
                self.d.add("outcome", "the legacy transaction carries no chain id, signed before EIP-155: valid, as it is "
                           "on Ethereum", "SATIN-VAL-006")
            if tx.nonce == MAX_U64 - 1:
                self.d.add("outcome", f"its nonce {tx.nonce} is below 2^64 - 1, EIP-2681's bound: valid, and the sender's "
                           "nonce becomes 2^64 - 1", "SATIN-VAL-007")
        return None

    def classify_system(self, intrinsic: int, body_history: int):
        """A transaction whose caller is the live system address (SATIN-MST-001 to -005): without the system shape it is
        refused; with it, a Mega System Transaction, held to its own chain-id, nonce and EIP-3607 checks, a failure a
        refusal, and once it passes them promoted to a deposit, which no other check refuses (SATIN-VAL-008)."""
        tx, env, d = self.tx, self.env, self.d
        sender = self.pre.get(tx.sender, Account())
        if not (tx.ty == 0 and tx.to == ORACLE):
            shape = ("a creation" if tx.to is None else f"a type-{tx.ty} transaction" if tx.ty else
                     f"a legacy call to {h(tx.to)}, which is not on MEGA_SYSTEM_TX_WHITELIST")
            return ("validation", "not-system-shape", ("SATIN-VAL-005", "SATIN-MST-001", "SATIN-MST-003"),
                    f"its caller {h(tx.sender)} is the live system address, and {shape} does not have the system shape")
        own = ("SATIN-VAL-007", "SATIN-MST-005")
        if tx.chain_id is None or tx.chain_id != env.chain_id:
            return ("validation", "chain-id-mismatch", ("SATIN-VAL-006",) + own,
                    "a Mega System Transaction must carry the chain's id, and this one carries "
                    + ("none" if tx.chain_id is None else f"{tx.chain_id}"))
        if sender.code and delegate_of(sender.code) is None:
            return ("validation", "sender-has-code", own, "the system address holds code that is no EIP-7702 delegation")
        if tx.nonce >= MAX_U64:
            return ("validation", "nonce-overflow", own, f"transaction nonce {tx.nonce} is 2^64 - 1, which EIP-2681 refuses")
        if tx.nonce != sender.nonce:
            return ("validation", "nonce-too-low" if tx.nonce < sender.nonce else "nonce-too-high", own,
                    f"transaction nonce {tx.nonce} is not the system address's nonce {sender.nonce}")
        self.promoted = True
        d.add("outcome", "a legacy call to the Oracle from the live system address, of the system shape, is a Mega System "
              "Transaction; it carries the chain's id, its nonce is the system address's and that address holds no code, so "
              "it is promoted to a deposit from the system address, with no mint, no fee and no other validation check of "
              "its own: system-originated", "SATIN-MST-002", "SATIN-MST-005", "SATIN-MST-007", "SATIN-VAL-008")
        return None

    def run(self) -> Result:
        tx, env, d = self.tx, self.env, self.d
        data = tx.data
        zeros = data.count(0)
        nonzeros = len(data) - zeros
        to_self = tx.to == tx.sender
        create = tx.to is None

        # Intrinsic regular gas, SATIN-SCHED-006.
        parts = [f"TX_BASE_COST {fmt(TX_BASE_COST)}"]
        intrinsic = TX_BASE_COST
        floor_base = TX_BASE_COST
        if create:
            words = (len(data) + 31) // 32
            intrinsic += CREATE_ACCESS + INITCODE_WORD_COST * words
            floor_base += CREATE_ACCESS
            parts += [f"CREATE_ACCESS {fmt(CREATE_ACCESS)}", f"initcode {words} words x {INITCODE_WORD_COST}"]
        elif not to_self:
            intrinsic += COLD_ACCOUNT_ACCESS
            floor_base += COLD_ACCOUNT_ACCESS
            parts.append(f"COLD_ACCOUNT_ACCESS {fmt(COLD_ACCOUNT_ACCESS)}")
            if tx.value:
                intrinsic += TX_VALUE_COST
                floor_base += TX_VALUE_COST
                parts.append(f"TX_VALUE_COST {fmt(TX_VALUE_COST)}")
        calldata = CALLDATA_ZERO * zeros + CALLDATA_NONZERO * nonzeros
        if data:
            intrinsic += calldata
            parts.append(f"calldata {zeros} zero x {CALLDATA_ZERO} + {nonzeros} non-zero x {CALLDATA_NONZERO} = {fmt(calldata)}")
        al_bytes = 0
        for _, keys in tx.access_list:
            intrinsic += ACCESS_LIST_ADDRESS + ACCESS_LIST_KEY * len(keys)
            al_bytes += ACCESS_LIST_ADDRESS_SIZE + ACCESS_LIST_SLOT_SIZE * len(keys)
        if tx.access_list:
            parts.append(f"access list {len(tx.access_list)} addresses x {fmt(ACCESS_LIST_ADDRESS)} + "
                         f"{sum(len(k) for _, k in tx.access_list)} keys x {fmt(ACCESS_LIST_KEY)}")
        auth_bytes = AUTHORIZATION_SIZE * len(tx.authorizations)
        if tx.authorizations:
            intrinsic += PER_AUTH_BASE_COST * len(tx.authorizations)
            parts.append(f"{len(tx.authorizations)} authorization entries x PER_AUTH_BASE_COST {fmt(PER_AUTH_BASE_COST)}")
        floor = floor_base + FLOOR_PER_BYTE * (len(data) + al_bytes)
        body_bytes = TX_BODY_SIZE + len(data) + al_bytes + auth_bytes
        body_history = body_bytes * COST_PER_HISTORY_BYTE

        refusal = self.validate(intrinsic, floor, body_history)
        if refusal:
            phase, reason, rule, why = refusal
            rules = rule if isinstance(rule, tuple) else (rule,)
            d.add("outcome", f"refused at {phase}: {why}", *rules)
            if self.outcomes:
                d.add("limit", "a transaction that fails validation is rejected, runs no frame and reports no stop",
                      "SATIN-OUT-016", "SATIN-STOP-003")
            return Result(refused(phase, reason), d)
        if self.outcomes and tx.authorizations:
            counted = body_bytes + WRITE_RECORD_SIZE * len(tx.authorizations)
            d.add("outcome", f"the body, {fmt(body_bytes)} bytes, with WRITE_RECORD_SIZE {WRITE_RECORD_SIZE} for each of its "
                  f"{len(tx.authorizations)} authorization entries, whether or not it will apply, is {fmt(counted)} bytes, "
                  f"within the data-size limit {fmt(TX_DATA_LIMIT)}: the first of Satin's own checks passes, before any gas "
                  "is looked at", "SATIN-VAL-001", "SATIN-VAL-003")

        d.add("gasLedgers", f"intrinsic regular gas = {' + '.join(parts)} = {fmt(intrinsic)}",
              *(("SATIN-SCHED-006", "SATIN-SCHED-007") if tx.authorizations else ("SATIN-SCHED-006",)))
        d.add("gasLedgers", f"floor = base {fmt(floor_base)} + {FLOOR_PER_BYTE} x {len(data) + al_bytes} calldata and "
              f"access-list bytes = {fmt(floor)}", "SATIN-SCHED-005")
        if tx.authorizations:
            d.add("gasLedgers", f"body = TX_BODY_SIZE {TX_BODY_SIZE} + {len(data)} calldata bytes + {al_bytes} access-list "
                  f"bytes + {len(tx.authorizations)} authorization entries x AUTHORIZATION_SIZE {AUTHORIZATION_SIZE} = "
                  f"{body_bytes} bytes; its history gas {body_bytes} x {COST_PER_HISTORY_BYTE} = {fmt(body_history)}; "
                  "authorization bytes are not floor tokens", "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004")
        else:
            d.add("gasLedgers", f"body = TX_BODY_SIZE {TX_BODY_SIZE} + {len(data)} calldata bytes + {al_bytes} access-list "
                  f"bytes = {body_bytes} bytes; its history gas {body_bytes} x {COST_PER_HISTORY_BYTE} = {fmt(body_history)}",
                  "SATIN-HIST-002", "SATIN-HIST-003", "SATIN-HIST-004")
        d.add("resources", f"data size starts at the body's {body_bytes} bytes; its five fixed records are not KV updates",
              "SATIN-ACCT-002", "SATIN-HIST-003")

        self.state: dict[bytes, Account] = {a: Account(x.nonce, x.balance, x.code, dict(x.storage)) for a, x in self.pre.items()}
        self.load(tx.sender, "the sender, which validation reads", "SATIN-WIT-002", "SATIN-WIT-008")
        self.data_size = body_bytes
        self.kv: set = set()  # write records: ("a", address) or ("s", address, slot)
        self.growth = 0
        self.logs: list[tuple[bytes, list[bytes], bytes]] = []
        self.refund = 0
        self.state_gas = 0  # kept state charges
        self.history_gas = body_history
        self.history_bytes = body_bytes
        # The access list's slots are warm from the start (EIP-2930, SATIN-SCHED-012).
        self.warm_slots: set = {(a, k) for a, keys in tx.access_list for k in keys}
        self.original: dict[tuple[bytes, int], int] = {}

        # The two pools, SATIN-POOL-005, and the body's history from the reservoir first, POOL-006.
        regular = min(tx.gas_limit, EXECUTION_CAP) - intrinsic
        reservoir = max(0, tx.gas_limit - EXECUTION_CAP)
        d.add("gasLedgers", f"pools: regular budget min({fmt(tx.gas_limit)}, {fmt(EXECUTION_CAP)}) - {fmt(intrinsic)} = "
              f"{fmt(regular)}, reservoir {fmt(reservoir)}", "SATIN-POOL-005")
        from_res = min(reservoir, body_history)
        reservoir -= from_res
        regular -= body_history - from_res
        self.reservoir_after_body = reservoir
        self.hint_bytes = 0  # admitted hints' input bytes, which stay counted whatever follows (SATIN-ORCL-009)
        d.add("gasLedgers", f"body history {fmt(body_history)}: {fmt(from_res)} from the reservoir, "
              f"{fmt(body_history - from_res)} from the regular budget", "SATIN-POOL-006")
        self.regular_charges = 0  # regular charges made by the frame
        self.pre_frame_regular = 0  # regular charges made before the first frame (ACCOUNT_WRITE)
        # Warm from the start: the sender, the recipient, the beneficiary and the access list's
        # addresses (SATIN-SCHED-012, SATIN-SCHED-014).
        self.warm_accounts: set = {tx.sender, env.coinbase} | ({tx.to} if tx.to else set()) | {a for a, _ in tx.access_list}

        sender_acct = self.state.setdefault(tx.sender, Account())
        if tx.kind == "deposit" or self.promoted:
            return self.run_deposit(intrinsic, floor, regular, reservoir, body_history)

        # Validation's changes to the sender: nonce of a call, the fee (SATIN-ACCT-008).
        price = self.effective_price()
        sender_acct.balance -= tx.gas_limit * price
        if not create:
            sender_acct.nonce += 1

        # SATIN-SCHED-010, all of it: a transaction that runs out of gas before its first frame takes back everything
        # applied before that frame except what validation did to its sender (its fee and a call's nonce bump) and a
        # deposit's created caller; its intrinsic gas and body history stay charged, the rest of its regular budget is
        # consumed and the reservoir left returns; a creation's sender keeps the nonce bump the creation would have made;
        # and a deposit becomes a failed deposit instead (run_deposit, which deposits take above). This snapshot is
        # validation's part: out_of_gas_before_frame restores it, then makes a creation's bump, which validation does
        # not make (SATIN-ACCT-008 puts it in the first frame).
        self.validated = self.snapshot()
        if tx.authorizations:
            self.load_authorities()
            skipped = self.list_crossing()
            if skipped:
                return self.list_skipped(skipped, intrinsic, floor, price)
            try:
                regular, reservoir = self.apply_authorizations(regular, reservoir)
            except OutOfGasBeforeFrame as e:
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir, str(e))

        if self.outcomes and tx.authorizations:
            applied = len([k for k in self.kv if k[0] == "a"])
            d.add("resources", f"before the first frame the transaction counts the body's {fmt(body_bytes)} bytes and the "
                  f"records of the {applied} authorities its list applied, {fmt(self.data_size)} bytes of data size in all, "
                  "within what validation admitted: an entry skipped makes no record", "SATIN-VAL-004", "SATIN-AUTH-008")

        # Charges before the first frame, SATIN-SCHED-008 steps 3 and 4.
        pre_frame_state = 0
        pre_frame_history = 0
        recipient = created_address(tx.sender, self.pre.get(tx.sender, Account()).nonce) if create else tx.to
        transfer = tx.value > 0 and not to_self
        start_record = False
        if create:
            existing = self.state.get(recipient)
            if existing and not existing.empty():
                raise Unmodelled("a creation onto an occupied address")
            start_record = True
        elif transfer:
            # An applied authority is changed by the list: the value to it adds no record (SATIN-ACCT-009).
            start_record = ("a", recipient) not in self.kv
            if not start_record:
                d.add("gasLedgers", f"the value's recipient {h(recipient)} is an authority the list applied, whose write "
                      "record the list already made: the value to it makes no record again, so no start record and no "
                      "history for one", "SATIN-ACCT-009", "SATIN-AUTH-015", "SATIN-HIST-005")
        if start_record:
            pre_frame_history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
            d.add("gasLedgers", f"the first frame's start record ({'created account' if create else 'value recipient'}): "
                  f"{WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(pre_frame_history)} history gas before the frame",
                  "SATIN-HIST-005", "SATIN-SCHED-008")
        new_account = False
        if create:
            new_account = True
        elif transfer:
            rec = self.state.get(recipient)
            new_account = rec is None or rec.empty()
        if new_account:
            m = self.multiplier(self.salt_bucket(recipient, None))
            pre_frame_state = ACCOUNT_STATE * m
            d.add("gasLedgers", f"{'created' if create else 'new'}-account state gas {fmt(ACCOUNT_STATE)} x m={m} = "
                  f"{fmt(pre_frame_state)} at step 4, no legacy share", "SATIN-SCHED-008", "SATIN-STATE-001",
                  "SATIN-STATE-003", "SATIN-POOL-024")
        # Of step 3's history, the authorities' records drew the reservoir first, when the list was
        # applied; the first frame's start record draws what they left (D-58).
        drawn = []  # what the reservoir paid of the start record and of the start's state gas
        for step, (amount, what) in enumerate(((pre_frame_history, "the first frame's start record"),
                                               (pre_frame_state, "the recipient's or created account's state gas"))):
            if step == 1 and recipient != tx.sender:
                self.load(recipient, f"the {'created address' if create else 'recipient'}, at step 4 of the charges "
                          "before the first frame and no earlier", "SATIN-SCHED-008", "SATIN-WIT-008")
            r = min(reservoir, amount)
            if amount - r > regular:
                if (tx.authorizations and not self.lists) or r or reservoir != self.reservoir_after_body:
                    raise Unmodelled("a transaction that cannot pay a charge before its first frame")
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir,
                                                    f"{what}, {fmt(amount)}, with {fmt(regular)} regular gas left")
            reservoir -= r
            regular -= amount - r
            drawn.append(r)
        start_from_reservoir = drawn[0]
        if self.outcomes and (pre_frame_history or pre_frame_state):
            d.add("outcome", f"the charges made before the first frame, {fmt(pre_frame_history + pre_frame_state)}, are "
                  "paid: the transaction does not run out of gas before its first frame", "SATIN-OUT-006",
                  "SATIN-SCHED-009")
        if self.principles and start_record and (tx.authorizations or self.reservoir_after_body):
            records = "the authorities' records" if tx.authorizations else "no authority's record"
            d.add("gasLedgers", f"of step 3's history the reservoir pays {records} first and the first frame's start record "
                  f"with what they leave it: {fmt(start_from_reservoir)} of the record from the reservoir and "
                  f"{fmt(pre_frame_history - start_from_reservoir)} from the regular budget", "SATIN-HIST-005",
                  "SATIN-POOL-024", "SATIN-HIST-023")

        # A recipient that holds an EIP-7702 delegation, after the list applied: its delegate's access,
        # charged as the base layer charges it under EIP-2780, after step 4 — the warm read, then the
        # cold surcharge when the delegate is not warm, the delegate loaded only when the regular gas
        # left pays the surcharge — and the delegate's code runs in the recipient's frame (D-58).
        delegate = None if create else delegate_of(self.state.get(recipient, Account()).code)
        if delegate is not None:
            if int.from_bytes(delegate, "big") <= 0x100:
                raise Unmodelled("a delegation to a precompile")
            cold = delegate not in self.warm_accounts
            access = WARM_READ + (COLD_ACCOUNT_SURCHARGE if cold else 0)
            self.probe.setdefault("delegate", regular)
            if regular < WARM_READ or (cold and regular - WARM_READ < COLD_ACCOUNT_SURCHARGE):
                if start_record or pre_frame_state or regular < WARM_READ:
                    raise Unmodelled("a transaction that cannot pay its delegate's access before its first frame")
                d.add("gasLedgers", f"the recipient holds an EIP-7702 delegation to {h(delegate)}, which is not warm: the "
                      f"delegate's access before the first frame, the warm read {WARM_READ} first, leaving "
                      f"{fmt(regular - WARM_READ)} of regular gas, which cannot pay the cold surcharge "
                      f"{fmt(COLD_ACCOUNT_SURCHARGE)}: the delegate is not loaded", "SATIN-SCHED-003", "SATIN-SCHED-008")
                if self.reads:
                    d.add("reads", f"the delegate {h(delegate)} is not loaded: its cold surcharge cannot be paid",
                          "SATIN-SCHED-008", "SATIN-WIT-012")
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir,
                                                    f"its delegate's cold surcharge, {fmt(COLD_ACCOUNT_SURCHARGE)}, with "
                                                    f"{fmt(regular - WARM_READ)} regular gas left after the warm read")
            regular -= access
            self.pre_frame_regular += access
            self.warm_accounts.add(delegate)
            self.load(delegate, "the recipient's delegate, at step 5, once its access is paid", "SATIN-SCHED-008",
                      "SATIN-WIT-008")
            d.add("gasLedgers", f"the recipient holds an EIP-7702 delegation to {h(delegate)}: the delegate's access before "
                  f"the first frame, after step 4, warm read {WARM_READ}" +
                  (f" + cold surcharge {fmt(COLD_ACCOUNT_SURCHARGE)} = {fmt(access)}, the cold delegate loaded once the "
                   "regular gas left pays the surcharge" if cold else ", the delegate warm") +
                  "; regular gas, and the delegate's code runs in the recipient's frame (" +
                  ("SATIN-SCHED-008 step 5" if self.principles else "D-58") + ")",
                  "SATIN-SCHED-003", "SATIN-SCHED-008")

        # A recognized keylessDeploy call is decided by interception, before the frame start: no value
        # moves for it (SATIN-ICPT-007, SATIN-KEY-018).
        keyless = (not create and recipient == KEYLESS_DEPLOY and data[:4] == KEYLESS_DEPLOY_CALL
                   and keyless_arguments(data) is not None)
        moved = transfer and not keyless

        # The frame starts: its records and transfer log (SATIN-LIM-013, SATIN-ACCT-005, SATIN-LOG-001).
        if moved:
            sender_acct.balance -= tx.value
            rec = self.state.setdefault(recipient, Account())
            rec.balance += tx.value
            self.kv.add(("a", recipient))
            self.data_size += (WRITE_RECORD_SIZE if start_record else 0) + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(tx.sender), pad_address(recipient)],
                              tx.value.to_bytes(32, "big")))
            if start_record:
                d.add("resources", f"the value moves: the recipient's write record ({WRITE_RECORD_SIZE} bytes, one KV "
                      f"update) and its EIP-7708 transfer log ({TRANSFER_LOG_SIZE} bytes, no history gas)",
                      "SATIN-ACCT-005", "SATIN-LOG-006")
            else:
                d.add("resources", f"the value moves: its EIP-7708 transfer log ({TRANSFER_LOG_SIZE} bytes, no history gas); "
                      "the recipient's write record is the list's", "SATIN-ACCT-009", "SATIN-LOG-006")
            d.add("receipt", "the transfer log of the transaction's value is the receipt's first log", "SATIN-LOG-001", "SATIN-LOG-002")
            if new_account:
                self.growth += 1
                d.add("resources", "the recipient is empty under EIP-161: one unit of state growth", "SATIN-ACCT-014")
                if recipient in self.pre:
                    d.add("resources", "the state holds the recipient's leaf, empty under EIP-161: as a value recipient it is "
                          "charged and counted as an absent account, the existence predicate being an authority's alone",
                          "SATIN-ACCT-015", "SATIN-STATE-011")
        elif tx.value and to_self:
            d.add("receipt", "value sent to the sender itself moves nothing and logs nothing", "SATIN-LOG-003")
            d.add("resources", "value to the sender itself changes no account and records nothing", "SATIN-ACCT-007")
        if create:
            sender_acct.nonce += 1
            acct = self.state.setdefault(recipient, Account())
            acct.nonce = 1
            if tx.value:
                raise Unmodelled("a creation with an endowment")
            self.kv.add(("a", recipient))
            self.growth += 1
            self.data_size += WRITE_RECORD_SIZE
            d.add("resources", "the created account: one write record and one unit of state growth", "SATIN-ACCT-005", "SATIN-ACCT-014")
        self.history_gas += pre_frame_history
        self.history_bytes += WRITE_RECORD_SIZE if start_record else 0
        self.state_gas += pre_frame_state

        code = data if create else self.state.get(delegate or recipient, Account()).code
        self.address = recipient
        frame = {"regular": regular, "reservoir": reservoir, "regular_at_start": regular, "reservoir_at_start": reservoir}
        self.probe.setdefault("frame", regular)
        self.first_frame = frame
        # SATIN-DET-008: a transaction whose sender, call recipient or applied EIP-7702 authority is the block
        # beneficiary is detained from its start; a creation onto the beneficiary's address is not (SATIN-DET-006).
        parties = [name for name, who in (("sender", tx.sender), ("call recipient", None if create else recipient))
                   if who == env.coinbase]
        if env.coinbase in self.applied_authorities:
            parties.append("applied EIP-7702 authority")
        if parties:
            self.detain_from_start(frame, parties)
        elif self.lists and tx.authorizations:
            skipped = any(a == env.coinbase for *_, a in tx.authorizations)
            d.add("gasLedgers", "no applied authority is the block beneficiary" + (", the sender's own authorization "
                  "among them" if tx.sender in self.applied_authorities else "") + (": the entry whose authority is the "
                  "beneficiary was skipped, and an authority the list loaded or warmed and did not apply is no applied "
                  "authority" if skipped else "") + "; nor is the sender or the recipient: the transaction is not "
                  "detained from its start", "SATIN-DET-008")
        elif create and recipient == env.coinbase:
            d.add("gasLedgers", f"the created address {h(recipient)} is the block beneficiary: the creation transaction is "
                  "not detained from its start for it, its loads of the sender and the created address being the "
                  "creation's own checks", "SATIN-DET-006")
        # What the transaction's own frame is given in each dimension: what the transaction has left once the
        # body and the counts made before the first frame are counted (SATIN-LIM-002).
        self.frame_start_counts = (self.data_size, len(self.kv), self.growth)
        snapshot = self.snapshot()
        status, output = "success", b""
        try:
            if keyless:
                status, output = self.keyless_call(frame)
            else:
                if not create and recipient == KEYLESS_DEPLOY and data[:4] == KEYLESS_DEPLOY_CALL:
                    held = ("KeylessDeploy's bytecode runs, whose decoder refuses the same arguments"
                            if ex.keccak256(code) == KEYLESS_DEPLOY_CODE_HASH else
                            "the code the state holds at the address runs, which is not KeylessDeploy's")
                    d.add("outcome", "the transaction's own CALL to KeylessDeploy carries keylessDeploy's selector, but its "
                          f"arguments fail the decoder's conditions: not recognized, charged nothing, and {held}",
                          "SATIN-ICPT-006")
                elif not create and recipient == KEYLESS_DEPLOY:
                    d.add("outcome", "the transaction's own CALL to KeylessDeploy does not carry keylessDeploy's selector: "
                          "not recognized, charged nothing, and the code the state holds at the address runs",
                          "SATIN-ICPT-006")
                elif not create and data[:4] == KEYLESS_DEPLOY_CALL and keyless_arguments(data) is not None:
                    d.add("outcome", f"the transaction's own CALL carries keylessDeploy's selector and arguments that "
                          f"decode, but to {h(recipient)}, not KEYLESS_DEPLOY_ADDRESS: not recognized, charged nothing, and "
                          "the code the state holds there runs", "SATIN-ICPT-006")
                status, output = self.execute(code, frame, create)
                if create and status == "success" and len(output) > MAX_CONTRACT_SIZE:
                    d.add("outcome", f"the initcode returns {fmt(len(output))} bytes of code to deposit, over "
                          f"MAX_CONTRACT_SIZE {fmt(MAX_CONTRACT_SIZE)}: the size check halts the creation before any of "
                          "the deposit's charges, Ethereum's check at MegaETH's size and no limit stop", "SATIN-SIZE-001",
                          "SATIN-SIZE-003", "SATIN-OUT-003")
                    raise Halt(f"deployed code of {fmt(len(output))} bytes, over MAX_CONTRACT_SIZE")
                if create and status == "success":
                    # The code's deposit is the creation's, in its frame: a charge of it the frame cannot pay halts the
                    # creation (SATIN-SCHED-011, SATIN-OUT-007).
                    self.deposit_code(output, frame, recipient)
                    if self.outcomes:
                        d.add("outcome", f"the creation's frame pays every charge of its {fmt(len(output))}-byte code's "
                              "deposit: it does not halt for one", "SATIN-OUT-007", "SATIN-SCHED-011")
        except Halt as e:
            status = "halt"
            d.add("outcome", f"the frame halts: {e}", "SATIN-OUT-007")
            if self.outcomes:
                d.add("outcome", "a halt of the transaction's own frame ends the transaction with a failed receipt, settled "
                      "as SATIN-POOL-017 settles it; the specification names no halt reason, so the halt is identified "
                      "as a halt alone, whatever label a node gives it", "SATIN-OUT-013", "SATIN-OUT-018",
                      "SATIN-POOL-017")
        except Stopped as e:
            status, output = "revert", limit_exceeded(DETENTION_STOP, e.limit)
            self.stop = (DETENTION_STOP, e.limit)
            d.add("outcome", f"the transaction's own frame reaches gas detention's crossing at {e}: the charge is not made, "
                  f"and the frame is stopped with MegaLimitExceeded({DETENTION_STOP}, {fmt(e.limit)}), the transaction's "
                  "result", "SATIN-DET-018", "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-021", *self.kind_rules())
        except LimitStop as e:
            status, output = "revert", limit_exceeded(e.kind, e.limit)
            self.stop = (e.kind, e.limit)
            d.add("outcome", f"the transaction's own frame crosses a limit at {e}: "
                  + ("" if getattr(e, "resumed", False) else "the write is not kept, and ") + "the frame is "
                  f"stopped with MegaLimitExceeded({e.kind}, {fmt(e.limit)}), the transaction's result",
                  "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-018", "SATIN-STOP-021", *self.kind_rules())

        if self.lists and status != "success" and self.applied_authorities:
            kept = sorted(self.applied_authorities)
            d.add("state", f"the first frame {'halts' if status == 'halt' else 'is stopped' if self.stop else 'reverts'}, "
                  f"and the authorizations the list applied before it are kept: {', '.join(h(a) for a in kept)} keep their "
                  "nonce and delegation writes, their state gas, their write records and the history those cost",
                  "SATIN-AUTH-016")

        if status == "halt":
            # SATIN-POOL-014: the halting frame's reservoir becomes what it received, its regular gas
            # is consumed; its records, logs, state and storage are taken back. The start's record
            # and the created account's state gas: the part the reservoir paid returns (POOL-015,
            # HIST-005); here no reservoir paid them unless the case has one.
            self.restore(snapshot)
            self.destroyed = set()  # the first frame's failure discards every mark (SATIN-SD-010)
            if self.hint_bytes:
                # An admitted hint is the transaction's, on no frame: it stays counted through a halt (SATIN-ORCL-009).
                self.data_size += self.hint_bytes
                d.add("resources", f"the admitted hints' {fmt(self.hint_bytes)} bytes stay counted as data size through the "
                      "halt", "SATIN-ORCL-009", "SATIN-STOP-012")
            if self.stops:
                d.add("limit", "the frame halts: a halt is not a limit stop, so the transaction reports no stop",
                      "SATIN-STOP-002", "SATIN-OUT-007")
            spent_regular = tx.gas_limit - frame["reservoir_at_start"] - (pre_frame_history + pre_frame_state if reservoir else 0)
            if (drawn[1] or (keyless and drawn[0])) and not self.outcomes:
                raise Unmodelled("a halt after the reservoir paid the state gas of the first frame's start, or the start "
                                 "record of an intercepted call")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state, start_record)
            if keyless and start_record:
                self.history_gas -= pre_frame_history
                self.history_bytes -= WRITE_RECORD_SIZE
            if self.principles and start_record:
                d.add("gasLedgers", f"the first frame's start record, {fmt(pre_frame_history)} of history gas charged before "
                      f"the frame{', before interception decides the call,' if keyless else ''} is not kept: the "
                      f"{fmt(start_from_reservoir)} the reservoir paid of it returns to the reservoir, and the "
                      f"{fmt(pre_frame_history - start_from_reservoir)} the regular budget paid is consumed with the frame's "
                      "regular gas" + ("; the authorities' records and state gas are the transaction's own and are kept"
                                       if tx.authorizations else ""),
                      "SATIN-HIST-005", "SATIN-POOL-024", "SATIN-HIST-023",
                      *(("SATIN-AUTH-016",) if (self.applied_authorities if self.lists else tx.authorizations) else ()))
            reservoir_left = frame["reservoir_at_start"] + (pre_frame_history + pre_frame_state if frame["reservoir_at_start"] else 0)
            if frame["reservoir_at_start"] and (pre_frame_history or pre_frame_state) and not start_from_reservoir \
                    and not self.outcomes:
                raise Unmodelled("a halt after start charges the reservoir paid")
            if self.outcomes and drawn[1]:
                # SATIN-POOL-014, -015, SATIN-HIST-005: what the reservoir paid of the start returns to it with the halt.
                d.add("gasLedgers", f"the halt takes the first frame's start back: of its record's history and the created "
                      f"account's state gas the reservoir paid {fmt(sum(drawn))}, which returns to the reservoir; the "
                      "body's history stays charged", "SATIN-POOL-014", "SATIN-POOL-015", "SATIN-HIST-005")
                total = tx.gas_limit - frame["reservoir_at_start"] - sum(drawn)
                d.add("gasLedgers", f"halt: every regular gas the frame held is consumed, the reservoir {fmt(frame['reservoir_at_start'])} "
                      f"returns; total = gas limit {fmt(tx.gas_limit)} - {fmt(frame['reservoir_at_start'])} = {fmt(total)}; the "
                      "frame's state and history charges are not kept, so what regular gas paid of them is on the regular "
                      "ledger (D-51)", "SATIN-POOL-014", "SATIN-POOL-017")
            elif start_from_reservoir:
                # SATIN-HIST-005: the part of the start record the reservoir paid returns to the reservoir.
                total = tx.gas_limit - frame["reservoir_at_start"] - start_from_reservoir
                d.add("gasLedgers", f"halt: every regular gas the frame held is consumed; the reservoir it received, "
                      f"{fmt(frame['reservoir_at_start'])}, returns, and with it the {fmt(start_from_reservoir)} the "
                      f"reservoir paid of the start record; total = gas limit {fmt(tx.gas_limit)} - "
                      f"{fmt(frame['reservoir_at_start'])} - {fmt(start_from_reservoir)} = {fmt(total)}",
                      "SATIN-POOL-014", "SATIN-POOL-017", "SATIN-HIST-005")
            else:
                total = tx.gas_limit - frame["reservoir_at_start"]
                d.add("gasLedgers", f"halt: every regular gas the frame held is consumed, the reservoir {fmt(frame['reservoir_at_start'])} "
                      f"returns; total = gas limit {fmt(tx.gas_limit)} - {fmt(frame['reservoir_at_start'])} = {fmt(total)}; the "
                      "frame's state and history charges are not kept, so what regular gas paid of them is on the regular "
                      "ledger (D-51)", "SATIN-POOL-014", "SATIN-POOL-017")
            del spent_regular, reservoir_left
            self.refund = 0
            execution = {"status": "halt", "output": "0x", "createdAddress": None}
        elif status == "revert":
            if self.stops and self.stop is None:
                d.add("limit", "the frame reverts with data of its own making: what a contract returns, the bytes of "
                      "MegaLimitExceeded or a stop it caught among them, is an ordinary revert and no limit stop, so the "
                      "transaction reports none", "SATIN-STOP-020", "SATIN-STOP-021")
            self.restore(snapshot)
            self.destroyed = set()  # the first frame's failure discards every mark (SATIN-SD-010)
            if self.hint_bytes:
                # An admitted hint is the transaction's, on no frame: it stays counted (SATIN-STOP-012, ORCL-009).
                self.data_size += self.hint_bytes
                if self.stop is None:
                    d.add("resources", f"the admitted hints' {fmt(self.hint_bytes)} bytes stay counted as data size through "
                          "the revert", "SATIN-ORCL-009", "SATIN-STOP-012")
                else:
                    d.add("resources", f"the admitted hints' {fmt(self.hint_bytes)} bytes stay counted as data size through "
                          "the stop", "SATIN-STOP-012", "SATIN-ORCL-009")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state, start_record)
            if keyless and start_record:
                self.history_gas -= pre_frame_history
                self.history_bytes -= WRITE_RECORD_SIZE
                d.add("gasLedgers", f"the start record's {fmt(pre_frame_history)} history gas, charged before the frame, comes "
                      "back with the revert: the value never moved", "SATIN-HIST-005", "SATIN-KEY-004")
            total = intrinsic + self.pre_frame_regular + self.regular_charges + self.history_gas + self.state_gas
            d.add("gasLedgers", "revert: the frame's state and history charges, and the first frame's start record and "
                  "recipient or created-account state gas, are given back into the reservoir and return to the sender; its "
                  f"regular charges {fmt(self.regular_charges)} stay spent", "SATIN-POOL-014", "SATIN-POOL-015",
                  "SATIN-HIST-005", "SATIN-POOL-017")
            if self.stop is not None:
                d.add("limit", f"the stop of the transaction's own frame is its result: {STOP_DIMENSIONS[self.stop[0]]}, limit "
                      f"{fmt(self.stop[1])}, return data MegaLimitExceeded({self.stop[0]}, {fmt(self.stop[1])}); the "
                      "transaction settles as a revert, keeping what was applied before its first frame",
                      "SATIN-STOP-009", "SATIN-STOP-011", "SATIN-STOP-018", "SATIN-STOP-021")
                if self.stops:
                    d.add("limit", "the transaction passed validation and paid every charge made before its first frame, so "
                          "the stop applies to it", "SATIN-STOP-003")
            if self.outcomes and self.stop is None:
                d.add("outcome", "a revert of the transaction's own frame ends the transaction with a failed receipt, "
                      "settled as SATIN-POOL-017 settles it, its REVERT data the output", "SATIN-OUT-014", "SATIN-POOL-017")
            self.refund = 0
            execution = {"status": "revert", "output": h(output), "createdAddress": None}
        else:
            total = intrinsic + self.pre_frame_regular + self.regular_charges + self.history_gas + self.state_gas
            if self.stops and self.caught_stop:
                d.add("outcome", "every stop below the transaction's own frame was caught, and the callers ran on as after "
                      "any failed call: the transaction succeeds, keeping what its frames did and nothing of a frame that "
                      "was stopped", "SATIN-STOP-008")
            # A creation's output is what its initcode returned: the code it deposited.
            execution = {"status": "success", "output": h(output), "createdAddress": h(recipient) if create else None}

        return self.settle(total, floor, price, status, execution, create, recipient)

    def list_skipped(self, crossed, intrinsic: int, floor: int, price: int) -> Result:
        """SATIN-AUTH-010: a list whose KV or state-growth total crosses the transaction's limit is skipped and the
        transaction's own frame is stopped before it runs, naming the transaction limit, no frame budget existing yet;
        the transaction settles as a stop of its own frame (SATIN-STOP-009), keeping its body (SATIN-AUTH-011)."""
        tx, d = self.tx, self.d
        if tx.value or tx.to is None or delegate_of(self.state.get(tx.to, Account()).code) is not None:
            raise Unmodelled("a skipped list on a transaction whose first frame starts with a charge")
        kind, value = crossed
        self.stop = (kind, value)
        if tx.to == KEYLESS_DEPLOY and tx.data[:4] == KEYLESS_DEPLOY_CALL:
            d.add("outcome", "the transaction's own frame is a keylessDeploy call, which the list's stop reaches before "
                  "anything is decided about the call: no keyless recognition, no overhead, no signer read",
                  "SATIN-ICPT-007", "SATIN-AUTH-010")
        d.add("outcome", f"the transaction's own frame is stopped before it runs, with MegaLimitExceeded({kind}, "
              f"{fmt(value)}), the transaction's result: the list's total crosses before the first frame, where no frame "
              "budget exists yet, so the stop names the transaction limit; state growth, like KV updates, can cross "
              "before the first frame only on the authorization list, which is skipped", "SATIN-AUTH-010",
              "SATIN-STOP-001", "SATIN-STOP-017", "SATIN-STOP-018", "SATIN-STOP-021", *self.kind_rules())
        total = intrinsic + self.history_gas
        d.add("gasLedgers", f"the skipped list charges nothing but what validation charged: the intrinsic gas, every entry's "
              f"PER_AUTH_BASE_COST among it, and the body's history, its entries' bytes among them; the frame runs "
              f"nothing; total = {fmt(intrinsic)} + {fmt(self.history_gas)} = {fmt(total)}, the rest returning to the "
              "sender", "SATIN-AUTH-007", "SATIN-AUTH-011", "SATIN-STOP-009", "SATIN-POOL-017")
        d.add("resources", "the skipped list keeps nothing: the body's data size alone, no write record, no state growth",
              "SATIN-AUTH-011", "SATIN-STOP-011")
        d.add("limit", f"the stop of the transaction's own frame is its result: {STOP_DIMENSIONS[kind]}, limit "
              f"{fmt(value)}, return data MegaLimitExceeded({kind}, {fmt(value)}); the transaction settles as a revert, "
              "keeping what was applied before its first frame, of which the skipped list is no part",
              "SATIN-STOP-009", "SATIN-STOP-011", "SATIN-STOP-018", "SATIN-STOP-021")
        self.refund = 0
        return self.settle(total, floor, price, "revert", {"status": "revert", "output": h(limit_exceeded(kind, value)),
                                                           "createdAddress": None}, False, tx.to)

    def out_of_gas_before_frame(self, intrinsic: int, floor: int, price: int, reservoir: int, what: str) -> Result:
        """SATIN-SCHED-009 and SATIN-SCHED-010: a transaction that cannot pay a charge before its first frame
        runs out of gas without running a frame: everything applied before the first frame is taken back to
        what validation left (the snapshot `validated`), the authorizations the list applied among it, and the
        accounts the transaction loaded stay loaded; the sender of a creation keeps the nonce bump the creation
        would have made, which its first frame makes when it runs (SATIN-ACCT-008)."""
        tx, d = self.tx, self.d
        d.add("outcome", f"the transaction cannot pay {what}: it runs out of gas before its first frame and runs no frame",
              "SATIN-SCHED-009")
        if self.outcomes:
            d.add("outcome", "a charge made before the first frame that the transaction cannot pay ends it out of gas "
                  "without running a frame: a transaction other than a deposit is included out of gas, with a failed "
                  "receipt, and reports no stop", "SATIN-OUT-006", "SATIN-SCHED-010", "SATIN-STOP-003")
        if getattr(self, "applied_authorities", None):
            if reservoir != self.reservoir_after_body:
                raise Unmodelled("an out-of-gas before the first frame after the reservoir paid an authorization's charge")
            d.add("state", "everything the list applied is taken back: "
                  + ", ".join(h(a) for a in sorted(self.applied_authorities)) + " return to what validation left, with "
                  "their nonce and delegation writes, their state gas, their write records and the history and state "
                  "growth those counted; the accounts the list's simulation and application loaded stay loaded",
                  "SATIN-SCHED-010", "SATIN-AUTH-015")
        self.restore(self.validated)
        if tx.to is None:
            sender = self.state[tx.sender]
            sender.nonce += 1
            d.add("state", f"the sender of a creation keeps the nonce bump the creation would have made, though no frame "
                  f"runs to make it: its nonce becomes {sender.nonce}, with no created account", "SATIN-SCHED-010",
                  "SATIN-ACCT-008")
        if self.stops:
            d.add("limit", "a transaction that cannot pay a charge made before its first frame reports no stop, whatever "
                  "its frame would have crossed: the stop applies only to a transaction that passes validation and pays "
                  "every charge before its first frame", "SATIN-STOP-003", "SATIN-OUT-006")
        total = tx.gas_limit - reservoir
        d.add("gasLedgers", "out of gas before the first frame: the intrinsic gas and the body's history stay charged, the "
              f"rest of the regular budget is consumed, and the reservoir left, {fmt(reservoir)}, returns to the sender; "
              f"total = gas limit {fmt(tx.gas_limit)} - {fmt(reservoir)} = {fmt(total)}", "SATIN-SCHED-010", "SATIN-POOL-017")
        d.add("resources", "nothing applied before the first frame is kept but validation's changes to the sender: no write "
              "record, no state growth, the data size the body's alone", "SATIN-SCHED-010")
        if self.reads and tx.to is not None and tx.to not in self.loaded_accounts:
            d.add("reads", f"the recipient {h(tx.to)} is not loaded: its load is made at step 4 of the charges before the "
                  "first frame, which the transaction does not reach", "SATIN-SCHED-008")
        self.refund = 0
        return self.settle(total, floor, price, "halt", {"status": "halt", "output": "0x", "createdAddress": None}, False,
                           None)

    def effective_price(self) -> int:
        tx = self.tx
        if tx.ty in (2, 4):
            return min(tx.max_fee, self.env.base_fee + tx.max_priority)
        return tx.gas_price
