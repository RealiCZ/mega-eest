"""The transaction: validation's refusals, the intrinsic gas and the two pools, the charges before the first
frame (`SATIN-SCHED-008`), the first frame and how it ends, and the out-of-gas path before it
(`SATIN-SCHED-009`, `-010`)."""

from __future__ import annotations

from .constants import (
    ACCESS_LIST_ADDRESS, ACCESS_LIST_ADDRESS_SIZE, ACCESS_LIST_KEY, ACCESS_LIST_SLOT_SIZE, ACCOUNT_STATE,
    AUTHORIZATION_SIZE, CALLDATA_NONZERO, CALLDATA_ZERO, COLD_ACCOUNT_ACCESS, COLD_ACCOUNT_SURCHARGE,
    COST_PER_HISTORY_BYTE, CREATE_ACCESS, delegate_of, DETENTION_STOP, EXECUTION_CAP, FLOOR_PER_BYTE,
    INITCODE_WORD_COST, KEYLESS_DEPLOY, KEYLESS_DEPLOY_CALL, limit_exceeded, PER_AUTH_BASE_COST,
    STOP_DIMENSIONS, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC, TX_BASE_COST, TX_BODY_SIZE,
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
        if tx.chain_id is not None and tx.chain_id != env.chain_id:
            return ("validation", "chain-id-mismatch", "SATIN-VAL-006",
                    f"the transaction carries chain id {tx.chain_id}, the chain's is {env.chain_id}")
        if tx.gas_limit < intrinsic:
            return ("validation", "intrinsic-gas-too-low", "SATIN-VAL-002",
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} (SATIN-VAL-003 step 2)")
        if floor > tx.gas_limit:
            return ("validation", "floor-exceeds-gas-limit", "SATIN-VAL-002",
                    f"floor {fmt(floor)} > gas limit {fmt(tx.gas_limit)} (SATIN-VAL-003 step 3)")
        if tx.gas_limit < intrinsic + body_history:
            return ("validation", "intrinsic-gas-too-low", "SATIN-VAL-002",
                    f"gas limit {fmt(tx.gas_limit)} < intrinsic regular gas {fmt(intrinsic)} + body history gas "
                    f"{fmt(body_history)} = {fmt(intrinsic + body_history)} (SATIN-VAL-003 step 5)")
        if tx.gas_limit > env.block_gas_limit:
            # SATIN-BLK-009 and SATIN-BLK-013: a transaction whose gas limit does not fit in what the
            # block's gas limit has left is skipped for the block; in engine isolation the block has
            # all of its gas left, and the skip is reported as a refusal at inclusion (D-50).
            return ("inclusion", "gas-limit-exceeds-block", ("SATIN-BLK-009", "SATIN-BLK-013", "SATIN-BASE-002"),
                    f"gas limit {fmt(tx.gas_limit)} > the {fmt(env.block_gas_limit)} the block's gas limit has left: "
                    "skipped for the block, a refusal at inclusion in engine isolation")
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
            return Result(refused(phase, reason), d)

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
        if tx.kind == "deposit":
            return self.run_deposit(intrinsic, floor, regular, reservoir)

        # Validation's changes to the sender: nonce of a call, the fee (SATIN-ACCT-008).
        price = self.effective_price()
        sender_acct.balance -= tx.gas_limit * price
        if not create:
            sender_acct.nonce += 1

        if tx.authorizations:
            try:
                regular, reservoir = self.apply_authorizations(regular, reservoir)
            except OutOfGasBeforeFrame as e:
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir, str(e))

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
            start_record = True
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
                if tx.authorizations or r or reservoir != self.reservoir_after_body or create:
                    raise Unmodelled("a transaction that cannot pay a charge before its first frame")
                return self.out_of_gas_before_frame(intrinsic, floor, price, reservoir,
                                                    f"{what}, {fmt(amount)}, with {fmt(regular)} regular gas left")
            reservoir -= r
            regular -= amount - r
            drawn.append(r)
        start_from_reservoir = drawn[0]
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
            self.data_size += WRITE_RECORD_SIZE + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(tx.sender), pad_address(recipient)],
                              tx.value.to_bytes(32, "big")))
            d.add("resources", f"the value moves: the recipient's write record ({WRITE_RECORD_SIZE} bytes, one KV update) "
                  f"and its EIP-7708 transfer log ({TRANSFER_LOG_SIZE} bytes, no history gas)",
                  "SATIN-ACCT-005", "SATIN-LOG-006")
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
        if any(authority == env.coinbase for *_, authority in tx.authorizations):
            parties.append("applied EIP-7702 authority")
        if parties:
            self.detain_from_start(frame, parties)
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
                    d.add("outcome", "the transaction's own CALL to KeylessDeploy carries keylessDeploy's selector, but its "
                          "arguments fail the decoder's conditions: not recognized, charged nothing, and KeylessDeploy's "
                          "bytecode runs, whose decoder refuses the same arguments", "SATIN-ICPT-006")
                status, output = self.execute(code, frame, create)
        except Halt as e:
            status = "halt"
            d.add("outcome", f"the frame halts: {e}", "SATIN-OUT-007")
        except Stopped as e:
            status, output = "revert", limit_exceeded(DETENTION_STOP, e.limit)
            self.stop = (DETENTION_STOP, e.limit)
            d.add("outcome", f"the transaction's own frame reaches gas detention's crossing at {e}: the charge is not made, "
                  f"and the frame is stopped with MegaLimitExceeded({DETENTION_STOP}, {fmt(e.limit)}), the transaction's "
                  "result", "SATIN-DET-018", "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-021")
        except LimitStop as e:
            status, output = "revert", limit_exceeded(e.kind, e.limit)
            self.stop = (e.kind, e.limit)
            d.add("outcome", f"the transaction's own frame crosses a limit at {e}: the write is not kept, and the frame is "
                  f"stopped with MegaLimitExceeded({e.kind}, {fmt(e.limit)}), the transaction's result",
                  "SATIN-STOP-001", "SATIN-STOP-004", "SATIN-STOP-018", "SATIN-STOP-021")

        if status == "success" and create:
            self.deposit_code(output, frame, recipient)

        if status == "halt":
            # SATIN-POOL-014: the halting frame's reservoir becomes what it received, its regular gas
            # is consumed; its records, logs, state and storage are taken back. The start's record
            # and the created account's state gas: the part the reservoir paid returns (POOL-015,
            # HIST-005); here no reservoir paid them unless the case has one.
            if self.hint_bytes:
                raise Unmodelled("a halt after an admitted hint")
            self.restore(snapshot)
            self.destroyed = set()  # the first frame's failure discards every mark (SATIN-SD-010)
            spent_regular = tx.gas_limit - frame["reservoir_at_start"] - (pre_frame_history + pre_frame_state if reservoir else 0)
            if sum(drawn):
                raise Unmodelled("a halt after the reservoir paid a charge for the first frame's start")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state)
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
                      *(("SATIN-AUTH-016",) if tx.authorizations else ()))
            reservoir_left = frame["reservoir_at_start"] + (pre_frame_history + pre_frame_state if frame["reservoir_at_start"] else 0)
            if frame["reservoir_at_start"] and (pre_frame_history or pre_frame_state):
                raise Unmodelled("a halt after start charges the reservoir paid")
            total = tx.gas_limit - frame["reservoir_at_start"]
            d.add("gasLedgers", f"halt: every regular gas the frame held is consumed, the reservoir {fmt(frame['reservoir_at_start'])} "
                  f"returns; total = gas limit {fmt(tx.gas_limit)} - {fmt(frame['reservoir_at_start'])} = {fmt(total)}; the "
                  "frame's state and history charges are not kept, so what regular gas paid of them is on the regular "
                  "ledger (D-51)", "SATIN-POOL-014", "SATIN-POOL-017")
            del spent_regular, reservoir_left
            self.refund = 0
            execution = {"status": "halt", "output": "0x", "createdAddress": None}
        elif status == "revert":
            self.restore(snapshot)
            self.destroyed = set()  # the first frame's failure discards every mark (SATIN-SD-010)
            if self.hint_bytes:
                # An admitted hint is the transaction's, on no frame: it stays counted (SATIN-STOP-012, ORCL-009).
                if self.stop is None:
                    raise Unmodelled("a revert after an admitted hint")
                self.data_size += self.hint_bytes
                d.add("resources", f"the admitted hints' {fmt(self.hint_bytes)} bytes stay counted as data size through the "
                      "stop", "SATIN-STOP-012", "SATIN-ORCL-009")
            self.undo_start(moved, create, recipient, new_account, pre_frame_history, pre_frame_state)
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
            self.refund = 0
            execution = {"status": "revert", "output": h(output), "createdAddress": None}
        else:
            total = intrinsic + self.pre_frame_regular + self.regular_charges + self.history_gas + self.state_gas
            # A creation's output is what its initcode returned: the code it deposited.
            execution = {"status": "success", "output": h(output), "createdAddress": h(recipient) if create else None}

        return self.settle(total, floor, price, status, execution, create, recipient)

    def out_of_gas_before_frame(self, intrinsic: int, floor: int, price: int, reservoir: int, what: str) -> Result:
        """SATIN-SCHED-009 and SATIN-SCHED-010: a transaction that cannot pay a charge before its first frame
        runs out of gas without running a frame. The model reaches this path only when nothing but
        validation's changes to the sender was applied before the charge it cannot pay."""
        tx, d = self.tx, self.d
        d.add("outcome", f"the transaction cannot pay {what}: it runs out of gas before its first frame and runs no frame",
              "SATIN-SCHED-009")
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
