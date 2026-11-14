"""One frame's bytecode: the opcodes the slice's cases and the system contracts' dispatchers use, each charge
at the schedule's price, the volatile reads and their refusal, and a call's opcode charges."""

from __future__ import annotations

from .constants import (
    ACCESS_TYPE_BENEFICIARY, ACCESS_TYPE_TIMESTAMP, ACCOUNT_STATE, BLOCK_ENV_ACCESS_COMPUTE_GAS, BLOCKHASH_WINDOW,
    CALL_STIPEND, delegate_of, G_BLOCKHASH, HISTORY_STORAGE_ADDRESS, PRECOMPILE_SET,
    CALL_VALUE_COST, COLD_ACCOUNT_SURCHARGE, COLD_SLOAD, COPY_WORD, COST_PER_HISTORY_BYTE, CREATE_ACCESS, ex, G_BASE,
    G_HIGH, G_JUMPDEST, G_LOW, G_MID, G_VERYLOW, G_ZERO, GAS_RETAINED_DENOMINATOR, GAS_RETAINED_NUMERATOR,
    INITCODE_WORD_COST, KECCAK_BASE,
    KECCAK_WORD, LEGACY_NEW_ACCOUNT_SHARE, LOG_BASE_SIZE, LOG_COST, LOG_DATA_COST, LOG_TOPIC_COST,
    LOG_TOPIC_SIZE, MAX_INITCODE_SIZE, ORACLE, ORACLE_ACCESS_COMPUTE_GAS, PRE_FORK_NEW_ACCOUNT_COST,
    VOLATILE_DATA_ACCESS_DISABLED, WARM_READ, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, Halt, memory_cost, Stopped, Unmodelled


def jump_destinations(code: bytes) -> set[int]:
    out, pc = set(), 0
    while pc < len(code):
        op = code[pc]
        if op == 0x5B:
            out.add(pc)
        pc += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return out


def to_signed(v: int) -> int:
    return v - 2**256 if v >> 255 else v


# The block environment's opcodes that read it whatever their operands (SATIN-DET-001), besides TIMESTAMP, NUMBER and
# BLOCKHASH, each at its inherited static gas of 2.
BLOCK_ENV_READS = {0x41: "COINBASE", 0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x48: "BASEFEE", 0x4A: "BLOBBASEFEE",
                   0x4B: "SLOTNUM"}


class InterpreterMixin:
    """One frame's bytecode: the opcodes the slice's cases and the system contracts' dispatchers use, each charge"""

    def block_field(self, op: int) -> int:
        """What a block-environment opcode pushes: the block's own field; SLOTNUM pushes zero (SATIN-BASE-005)."""
        env = self.env
        return {0x41: int.from_bytes(env.coinbase, "big"), 0x44: env.prev_randao, 0x45: env.block_gas_limit,
                0x48: env.base_fee, 0x4A: env.blob_base_fee, 0x4B: 0}[op]

    def execute(self, code: bytes, frame, create: bool, ctx=None):
        """Runs one frame. `ctx` is a child frame's context (address, caller, value, calldata); the
        transaction's own frame runs without one."""
        d, tx = self.d, self.tx
        stack: list[int] = []
        mem_words = 0
        memory = bytearray()
        pc = 0
        address = ctx["address"] if ctx else self.address
        caller = ctx["caller"] if ctx else tx.sender
        value_in = ctx["value"] if ctx else tx.value
        calldata = ctx["calldata"] if ctx else (b"" if create else tx.data)
        returndata = b""
        jumpdests = None

        def pop():
            if not stack:
                raise Halt("stack underflow")
            return stack.pop()

        def expand(offset: int, size: int, what: str) -> None:
            nonlocal mem_words, memory
            if size == 0:
                return
            words = (offset + size + 31) // 32
            if words > mem_words:
                cost = memory_cost(words) - memory_cost(mem_words)
                self.probe.setdefault("expand", frame["regular"])  # the regular gas before the first expansion
                self.charge_regular(frame, cost, f"{what} memory")
                mem_words = words
                memory.extend(b"\x00" * (words * 32 - len(memory)))

        def refuse(access_type: int, what: str):
            """SATIN-MAC-003, -004: a volatile read in a frame whose access is off, refused before any charge."""
            d.add("outcome", f"{what} in a frame whose volatile-data access is off: refused before the opcode charges "
                  f"anything, the frame reverting with VolatileDataAccessDisabled({access_type}) on the "
                  f"{fmt(frame['regular'])} of regular gas it held at the opcode; no read is marked",
                  "SATIN-MAC-003", "SATIN-MAC-004", "SATIN-MAC-005")
            if self.outcomes:
                d.add("outcome", f"the refusal is a revert of the frame that made the read, with its own error "
                      f"VolatileDataAccessDisabled({access_type}): not a halt, so the frame's unspent regular gas returns "
                      "to its caller, and not a limit stop", "SATIN-OUT-008")
            self.probe.setdefault("refused", frame["regular"])
            steps.append(f"{what.split()[0]} refused 0")
            return done("revert", VOLATILE_DATA_ACCESS_DISABLED + access_type.to_bytes(32, "big"))

        def simple(name: str, cost: int, result) -> None:
            self.charge_regular(frame, cost, name)
            stack.append(result % 2**256)
            steps.append(f"{name} {cost}")

        def done(status: str, out: bytes):
            if ctx:
                spent = frame["regular_at_start"] - frame["regular"]
                d.add("gasLedgers", f"{ctx.get('name') or 'the child frame of ' + h(address)} runs its code: "
                      f"{', '.join(steps) or 'none'}; it "
                      f"spends {fmt(spent)} of its {fmt(frame['regular_at_start'])} regular gas and ends in {status}",
                      "SATIN-POOL-007")
            else:
                d.add("gasLedgers", f"frame opcodes: {', '.join(steps) or 'none'}; regular charges of the frame "
                      f"{fmt(self.regular_charges)}", "SATIN-POOL-007")
            return status, out

        steps = []
        while pc < len(code):
            op = code[pc]
            pc += 1
            if op == 0x00:  # STOP
                steps.append(f"STOP {G_ZERO}")
                if not ctx and frame.get("spendable") is not None:
                    self.probe.setdefault("end-spendable", frame["spendable"])
                break
            if op == 0x5F:  # PUSH0
                self.charge_regular(frame, G_BASE, "PUSH0")
                stack.append(0)
                steps.append(f"PUSH0 {G_BASE}")
            elif 0x60 <= op <= 0x7F:
                n = op - 0x5F
                self.charge_regular(frame, G_VERYLOW, f"PUSH{n}")
                stack.append(int.from_bytes(code[pc:pc + n].ljust(n, b"\x00"), "big"))
                pc += n
                steps.append(f"PUSH{n} {G_VERYLOW}")
            elif op == 0x01:  # ADD
                self.charge_regular(frame, G_VERYLOW, "ADD")
                stack.append((pop() + pop()) % 2**256)
                steps.append(f"ADD {G_VERYLOW}")
            elif op == 0x50:  # POP
                self.charge_regular(frame, G_BASE, "POP")
                pop()
                steps.append(f"POP {G_BASE}")
            elif op == 0x33:  # CALLER
                self.charge_regular(frame, G_BASE, "CALLER")
                stack.append(int.from_bytes(caller, "big"))
                steps.append(f"CALLER {G_BASE}")
            elif op == 0x32:  # ORIGIN
                self.charge_regular(frame, G_BASE, "ORIGIN")
                stack.append(int.from_bytes(tx.sender, "big"))
                steps.append(f"ORIGIN {G_BASE}")
                d.add("outcome", f"ORIGIN pushes the transaction's sender, {h(tx.sender)}", "SATIN-BASE-001")
            elif op == 0x3A:  # GASPRICE
                self.charge_regular(frame, G_BASE, "GASPRICE")
                stack.append(self.effective_price())
                steps.append(f"GASPRICE {G_BASE}")
                d.add("outcome", f"GASPRICE pushes the transaction's effective gas price, {fmt(self.effective_price())}",
                      "SATIN-BASE-001")
            elif 0x0C <= op <= 0x0F:  # undefined in Osaka, which Satin's base keeps: an exceptional halt
                steps.append(f"undefined {op:#04x}")
                raise Halt(f"the undefined opcode {op:#04x}")
            elif op == 0x34:  # CALLVALUE
                self.charge_regular(frame, G_BASE, "CALLVALUE")
                stack.append(value_in)
                steps.append(f"CALLVALUE {G_BASE}")
            elif op == 0x46:  # CHAINID: the chain's id
                self.charge_regular(frame, G_BASE, "CHAINID")
                stack.append(self.env.chain_id)
                steps.append(f"CHAINID {G_BASE}")
            elif op == 0x52:  # MSTORE
                offset, value = pop(), pop()
                self.charge_regular(frame, G_VERYLOW, "MSTORE")
                expand(offset, 32, "MSTORE")
                memory[offset:offset + 32] = value.to_bytes(32, "big")
                steps.append(f"MSTORE {G_VERYLOW} + memory to {mem_words} words")
            elif op == 0x54:  # SLOAD
                if ctx and address == ORACLE:
                    key = pop()
                    if frame.get("access_off"):
                        raise Unmodelled("an Oracle read refused")
                    value = self.state.get(ORACLE, Account()).storage.get(key, 0)
                    self.warm_slots.add((ORACLE, key))
                    self.load_slot(ORACLE, key, "the Oracle's SLOAD, which loads the slot before its charge, whatever the "
                                   "charge then does", "SATIN-ORCL-004", "SATIN-WIT-012")
                    if tx.kind != "deposit":
                        raise Unmodelled("an Oracle read that asks the oracle service")
                    d.add("gasLedgers", f"the Oracle's SLOAD of slot {key}, with {fmt(frame['regular'])} of regular gas in "
                          "the frame: the read is made before its charge, the slot loaded and warm, and the read marked; a "
                          "deposit's read asks no oracle service, so the slot's value is pushed", "SATIN-ORCL-002",
                          "SATIN-ORCL-003", "SATIN-ORCL-004", "SATIN-ORCL-005")
                    self.mark(ORACLE_ACCESS_COMPUTE_GAS, f"the Oracle's SLOAD of slot {key}")
                    self.probe.setdefault("oracle-sload", frame["regular"])
                    if frame.get("spendable") is not None:
                        self.probe.setdefault("oracle-sload-room", self.limit - self.compute)
                    d.add("gasLedgers", f"then COLD_SLOAD_COST {fmt(COLD_SLOAD)}, its warm base {WARM_READ} included, as one "
                          "charge: the mark stands whatever the charge does", "SATIN-ORCL-004", "SATIN-DET-003",
                          "SATIN-DET-018")
                    self.charge_regular(frame, COLD_SLOAD, "the Oracle's SLOAD")
                    stack.append(value)
                    self.split(frame)
                    steps.append(f"SLOAD of the Oracle's storage {fmt(COLD_SLOAD)}")
                    continue
                if ctx:
                    raise Unmodelled("an SLOAD in a child frame")
                if frame.get("spendable") is not None:
                    raise Unmodelled("an SLOAD in a detained frame")
                key = pop()
                cold = (address, key) not in self.warm_slots
                cost = COLD_SLOAD if cold else WARM_READ
                self.charge_regular(frame, cost, "SLOAD")
                self.warm_slots.add((address, key))
                self.load_slot(address, key, "SLOAD, once its access is paid", "SATIN-WIT-002", "SATIN-WIT-012")
                stack.append(self.state.get(address, Account()).storage.get(key, 0))
                steps.append(f"SLOAD {'cold' if cold else 'warm'} {fmt(cost)}")
                d.add("gasLedgers", f"SLOAD of slot {key}: {'cold' if cold else 'warm'} {fmt(cost)}", "SATIN-SCHED-003")
            elif op == 0x55:  # SSTORE
                key, new = pop(), pop()
                steps.append(self.sstore(frame, address, key, new))
            elif 0xA0 <= op <= 0xA4:  # LOGn
                n = op - 0xA0
                offset, size = pop(), pop()
                topics = [pop() for _ in range(n)]
                cost = LOG_COST + LOG_TOPIC_COST * n + LOG_DATA_COST * size
                self.probe.setdefault("log", frame["regular"])  # the regular gas before the first LOG's charge
                self.charge_regular(frame, cost, f"LOG{n}")
                expand(offset, size, f"LOG{n}")
                payload = bytes(memory[offset:offset + size])
                log_bytes = LOG_BASE_SIZE + LOG_TOPIC_SIZE * n + size
                # The log's bytes pass the limits before its history is charged (SATIN-TAKE-009).
                self.hold_to_limits(log_bytes, 0, 0, f"LOG{n} of {fmt(size)} data bytes", frame)
                history = log_bytes * COST_PER_HISTORY_BYTE
                # SATIN-HIST-019, -020: a value call's frame draws its history allowance first, which is no gas
                # and on no gas ledger; its bytes still count.
                allowance = min(history, frame.get("allowance", 0))
                if allowance:
                    frame["allowance"] -= allowance
                    d.add("gasLedgers", f"LOG{n}'s history {fmt(history)} draws the frame's history allowance first: "
                          f"{fmt(allowance)} from the allowance, which is not gas and is on no gas ledger, and "
                          f"{fmt(history - allowance)} from the frame's gas; its {log_bytes} bytes still count",
                          "SATIN-HIST-019", "SATIN-HIST-020", "SATIN-TAKE-009")
                self.charge_state(frame, history - allowance, 0, f"LOG{n}'s history")
                self.history_gas += history - allowance
                self.history_bytes += log_bytes
                self.data_size += log_bytes
                self.logs.append((address, [t.to_bytes(32, "big") for t in topics], payload))
                steps.append(f"LOG{n} {fmt(cost)}")
                d.add("gasLedgers", f"LOG{n} of {size} data bytes: regular {LOG_COST} + {LOG_TOPIC_COST} x {n} + "
                      f"{LOG_DATA_COST} x {size} = {fmt(cost)}; history ({LOG_BASE_SIZE} + {LOG_TOPIC_SIZE} x {n} + {size}) x "
                      f"{COST_PER_HISTORY_BYTE} = {fmt(history)}", "SATIN-HIST-002", "SATIN-HIST-006")
                d.add("resources", f"LOG{n} adds {log_bytes} bytes of data size; a log is not a write record",
                      "SATIN-ACCT-001", "SATIN-ACCT-012")
                d.add("receipt", f"LOG{n} from the contract, in execution order", "SATIN-LOG-002")
            elif op in (0xF3, 0xFD):  # RETURN, REVERT
                offset, size = pop(), pop()
                expand(offset, size, "RETURN" if op == 0xF3 else "REVERT")
                out = bytes(memory[offset:offset + size])
                steps.append(("RETURN" if op == 0xF3 else "REVERT") + f" {size} bytes")
                return done("success" if op == 0xF3 else "revert", out)
            elif op == 0xFE:
                steps.append("INVALID")
                raise Halt("INVALID (0xfe)")
            # The inherited opcodes a system contract's dispatcher and decoder use, at their Osaka
            # static gas, which Amsterdam keeps (SATIN-SCHED-002).
            elif op == 0x02:
                simple("MUL", G_LOW, pop() * pop())
            elif op == 0x03:
                a, b = pop(), pop()
                simple("SUB", G_VERYLOW, a - b)
            elif op == 0x04:
                a, b = pop(), pop()
                simple("DIV", G_LOW, a // b if b else 0)
            elif op == 0x10:
                a, b = pop(), pop()
                simple("LT", G_VERYLOW, int(a < b))
            elif op == 0x11:
                a, b = pop(), pop()
                simple("GT", G_VERYLOW, int(a > b))
            elif op == 0x12:
                a, b = pop(), pop()
                simple("SLT", G_VERYLOW, int(to_signed(a) < to_signed(b)))
            elif op == 0x13:
                a, b = pop(), pop()
                simple("SGT", G_VERYLOW, int(to_signed(a) > to_signed(b)))
            elif op == 0x14:
                simple("EQ", G_VERYLOW, int(pop() == pop()))
            elif op == 0x15:
                simple("ISZERO", G_VERYLOW, int(pop() == 0))
            elif op == 0x16:
                simple("AND", G_VERYLOW, pop() & pop())
            elif op == 0x17:
                simple("OR", G_VERYLOW, pop() | pop())
            elif op == 0x18:
                simple("XOR", G_VERYLOW, pop() ^ pop())
            elif op == 0x19:
                simple("NOT", G_VERYLOW, ~pop())
            elif op == 0x1B:
                shift, v = pop(), pop()
                simple("SHL", G_VERYLOW, v << shift if shift < 256 else 0)
            elif op == 0x1C:
                shift, v = pop(), pop()
                simple("SHR", G_VERYLOW, v >> shift if shift < 256 else 0)
            elif op == 0x35:
                i = pop()
                simple("CALLDATALOAD", G_VERYLOW, int.from_bytes(calldata[i:i + 32].ljust(32, b"\x00"), "big") if i < len(calldata) else 0)
            elif op == 0x36:
                simple("CALLDATASIZE", G_BASE, len(calldata))
            elif op == 0x3D:
                simple("RETURNDATASIZE", G_BASE, len(returndata))
            elif op == 0x3E:  # RETURNDATACOPY
                dest, off, size = pop(), pop(), pop()
                words = (size + 31) // 32
                cost = G_VERYLOW + COPY_WORD * words
                self.charge_regular(frame, G_VERYLOW, "RETURNDATACOPY")
                if words:
                    self.charge_regular(frame, COPY_WORD * words, "RETURNDATACOPY's copy")
                expand(dest, size, "RETURNDATACOPY")
                if off + size > len(returndata):
                    raise Halt("RETURNDATACOPY past the return data")
                memory[dest:dest + size] = returndata[off:off + size]
                steps.append(f"RETURNDATACOPY {cost} + memory to {mem_words} words")
            elif op == 0x20:  # KECCAK256
                off, size = pop(), pop()
                words = (size + 31) // 32
                cost = KECCAK_BASE + KECCAK_WORD * words
                self.charge_regular(frame, KECCAK_BASE, "KECCAK256")
                if words:
                    self.charge_regular(frame, KECCAK_WORD * words, "KECCAK256's words")
                expand(off, size, "KECCAK256")
                stack.append(int.from_bytes(ex.keccak256(bytes(memory[off:off + size])), "big"))
                steps.append(f"KECCAK256 {cost} + memory to {mem_words} words")
            elif op == 0x51:  # MLOAD
                off = pop()
                self.charge_regular(frame, G_VERYLOW, "MLOAD")
                expand(off, 32, "MLOAD")
                stack.append(int.from_bytes(memory[off:off + 32], "big"))
                steps.append(f"MLOAD {G_VERYLOW} + memory to {mem_words} words")
            elif op in (0x56, 0x57):  # JUMP, JUMPI
                if jumpdests is None:
                    jumpdests = jump_destinations(code)
                dest = pop()
                cond = pop() if op == 0x57 else 1
                cost = G_MID if op == 0x56 else G_HIGH
                self.charge_regular(frame, cost, "JUMP" if op == 0x56 else "JUMPI")
                steps.append(f"{'JUMP' if op == 0x56 else 'JUMPI'} {cost}")
                if cond:
                    if dest not in jumpdests:
                        raise Halt("a jump to an invalid destination")
                    pc = dest
            elif op == 0x06:
                a, b = pop(), pop()
                simple("MOD", G_LOW, a % b if b else 0)
            elif op == 0x43:  # NUMBER
                if frame.get("access_off"):
                    raise Unmodelled("a refused NUMBER")
                self.charge_regular(frame, G_BASE, "NUMBER")
                stack.append(self.env.number)
                steps.append(f"NUMBER {G_BASE}")
                if address == HISTORY_STORAGE_ADDRESS:
                    self.history_number = True
                    d.add("gasLedgers", "the EIP-2935 history contract's code completes its NUMBER: the call is a read of "
                          "the block environment there, and the call itself was not marked", "SATIN-DET-005")
                self.volatile_read(frame, "NUMBER, a read of the block environment, once it completes,")
            elif op == 0x40:  # BLOCKHASH
                if frame.get("access_off"):
                    raise Unmodelled("a refused BLOCKHASH")
                n = pop()
                self.charge_regular(frame, G_BLOCKHASH, "BLOCKHASH")
                number = self.env.number
                in_range = number - BLOCKHASH_WINDOW <= n < number
                if in_range and n not in self.env.block_hashes:
                    raise Unmodelled("a BLOCKHASH of a block whose hash the case does not give")
                answer = int.from_bytes(self.env.block_hashes[n], "big") if in_range else 0
                stack.append(answer)
                steps.append(f"BLOCKHASH {G_BLOCKHASH}")
                where = ("the current block" if n == number else "a future block" if n > number else
                         "a block outside the last " + str(BLOCKHASH_WINDOW) if not in_range else "a block in range")
                d.add("gasLedgers", f"BLOCKHASH of block {n if n < 2**64 else '2^256 - 1' if n == 2**256 - 1 else n}, "
                      f"{where} of block {number}, pushes " + ("its hash" if in_range else "zero") + ": it loads the block "
                      "number before it decides whether its operand is in range, so it is a read of the block environment "
                      "whatever its operand", "SATIN-DET-004")
                self.volatile_read(frame, "BLOCKHASH, a read of the block environment, once it completes,")
            elif op in BLOCK_ENV_READS:  # COINBASE, PREVRANDAO, GASLIMIT, BASEFEE, BLOBBASEFEE, SLOTNUM
                name, value = BLOCK_ENV_READS[op], self.block_field(op)
                if frame.get("access_off"):
                    raise Unmodelled(f"a refused {name}")
                self.charge_regular(frame, G_BASE, name)
                stack.append(value)
                steps.append(f"{name} {G_BASE}")
                self.volatile_read(frame, f"{name}, a read of the block environment, once it completes,")
            elif op in (0x3B, 0x3F):  # EXTCODESIZE, EXTCODEHASH
                who = (pop() % 2**160).to_bytes(20, "big")
                name = "EXTCODESIZE" if op == 0x3B else "EXTCODEHASH"
                if who != self.env.coinbase or frame.get("access_off"):
                    raise Unmodelled(f"an {name} of an account other than the block beneficiary, or refused")
                static = 2 * WARM_READ if op == 0x3B else WARM_READ  # SATIN-SCHED-002, -003
                self.charge_regular(frame, static, f"{name}'s static cost")
                acct = self.state.get(who)
                ext = acct.code if acct is not None else b""
                stack.append(len(ext) if op == 0x3B else
                             0 if acct is None or acct.empty() else int.from_bytes(ex.keccak256(ext), "big"))
                steps.append(f"{name} {static}")
                d.add("gasLedgers", f"{name} of the block beneficiary {h(who)}, warm from the transaction's start: its static "
                      f"cost {static}, no cold access", "SATIN-SCHED-002", "SATIN-SCHED-003", "SATIN-SCHED-012")
                self.volatile_read(frame, f"{name} of the block beneficiary's account, once it completes,")
            elif op == 0x49:  # BLOBHASH
                i = pop()
                self.charge_regular(frame, G_VERYLOW, "BLOBHASH")
                if tx.ty != 0:
                    raise Unmodelled("a BLOBHASH outside a legacy transaction")
                stack.append(0)
                steps.append(f"BLOBHASH {G_VERYLOW}")
                d.add("gasLedgers", f"BLOBHASH of index {i} pushes zero, the transaction carrying no blob hash; it reads the "
                      "transaction's own blob hashes and is no volatile read: nothing is marked", "SATIN-DET-002")
            elif op == 0x47:  # SELFBALANCE
                if frame.get("access_off") and address == self.env.coinbase:
                    raise Unmodelled("a refused SELFBALANCE")
                self.charge_regular(frame, G_LOW, "SELFBALANCE")
                stack.append(self.state.get(address, Account()).balance)
                steps.append(f"SELFBALANCE {G_LOW}")
                if address == self.env.coinbase:
                    d.add("gasLedgers", f"the frame runs as the block beneficiary {h(address)}: its own SELFBALANCE is a "
                          "read of the beneficiary's account", "SATIN-DET-007", "SATIN-DET-001")
                    self.volatile_read(frame, "SELFBALANCE of the beneficiary's own frame, once it completes,")
                elif self.detention:
                    d.add("gasLedgers", f"SELFBALANCE of {h(address)}, which is not the block beneficiary, reads nothing "
                          "volatile", "SATIN-DET-001")
            elif op == 0x42:  # TIMESTAMP
                if frame.get("access_off"):
                    return refuse(ACCESS_TYPE_TIMESTAMP, "TIMESTAMP")
                self.charge_regular(frame, G_BASE, "TIMESTAMP")
                stack.append(self.env.timestamp)
                steps.append(f"TIMESTAMP {G_BASE}")
                self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, "TIMESTAMP, a read of the block environment, once it completes,")
                self.split(frame)
                d.add("gasLedgers", f"the frame's regular gas {fmt(frame['regular'])} is split: {fmt(frame['spendable'])} "
                      "spendable, what the limit leaves the transaction, and the rest withheld", "SATIN-DET-014")
            elif op == 0x31:  # BALANCE
                who = (pop() % 2**160).to_bytes(20, "big")
                self.probe.setdefault("balance", frame["regular"])
                if self.limit is not None:
                    self.probe.setdefault("balance-room", self.limit - self.compute)
                if frame.get("access_off") and who == self.env.coinbase:
                    return refuse(ACCESS_TYPE_BENEFICIARY, "BALANCE of the block beneficiary")
                self.charge_regular(frame, WARM_READ, "BALANCE's static cost")
                cold = who not in self.warm_accounts
                if cold:
                    if self.reads and COLD_ACCOUNT_SURCHARGE > frame["regular"]:
                        d.add("reads", f"BALANCE's account {h(who)} is not loaded: the regular gas left, "
                              f"{fmt(frame['regular'])}, cannot pay its cold access, and a load gas skipped is not made",
                              "SATIN-WIT-012")
                    self.charge_regular(frame, COLD_ACCOUNT_SURCHARGE, "BALANCE's cold access")
                    self.warm_accounts.add(who)
                if who == self.env.coinbase:
                    raise Unmodelled("a BALANCE of the beneficiary that reads")
                note = self.authority_warmth.get(who) if self.lists else None
                if note is not None and cold == note[0].startswith("is not"):
                    d.add("gasLedgers", f"BALANCE's account {h(who)}, an authority of the list, {note[0]}: its access costs "
                          f"{fmt(WARM_READ + (COLD_ACCOUNT_SURCHARGE if cold else 0))}", *note[1])
                self.load(who, "BALANCE's account, once its access is paid", "SATIN-WIT-002", "SATIN-WIT-012")
                stack.append(self.state.get(who, Account()).balance)
                steps.append(f"BALANCE {fmt(WARM_READ + (COLD_ACCOUNT_SURCHARGE if cold else 0))}")
            elif op == 0x5A:  # GAS
                self.charge_regular(frame, G_BASE, "GAS")
                stack.append(frame["regular"])
                self.probe.setdefault("gas", frame["regular"])
                self.probe.setdefault("gas-reservoir", frame["reservoir"])
                steps.append(f"GAS {G_BASE}")
                d.add("gasLedgers", f"GAS pushes the regular gas the frame has left after its own {G_BASE}, "
                      f"{fmt(frame['regular'])}, and not the reservoir, which holds {fmt(frame['reservoir'])}",
                      "SATIN-POOL-009")
                if self.detention and frame.get("spendable") is not None:
                    d.add("gasLedgers", f"the frame is detained: GAS sees both parts, the {fmt(frame['spendable'])} spendable "
                          f"and the {fmt(frame['regular'] - frame['spendable'])} withheld, not the spendable part alone",
                          "SATIN-DET-015")
            elif op == 0x5B:
                self.charge_regular(frame, G_JUMPDEST, "JUMPDEST")
                steps.append(f"JUMPDEST {G_JUMPDEST}")
            elif 0x80 <= op <= 0x8F:
                n = op - 0x7F
                if len(stack) < n:
                    raise Halt("stack underflow")
                simple(f"DUP{n}", G_VERYLOW, stack[-n])
            elif 0x90 <= op <= 0x9F:
                n = op - 0x8F
                if len(stack) < n + 1:
                    raise Halt("stack underflow")
                self.charge_regular(frame, G_VERYLOW, f"SWAP{n}")
                stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
                steps.append(f"SWAP{n} {G_VERYLOW}")
            elif op == 0xF1:  # CALL
                gas_req, target_w, value, a_off, a_size, r_off, r_size = [pop() for _ in range(7)]
                target = (target_w % 2**160).to_bytes(20, "big")
                before = self.regular_charges
                self.charge_regular(frame, WARM_READ, "CALL")
                expand(a_off, a_size, "CALL input")
                expand(r_off, r_size, "CALL output")
                if value:
                    self.charge_regular(frame, CALL_VALUE_COST, "the value transfer")
                cold = target not in self.warm_accounts and target not in PRECOMPILE_SET
                if cold:
                    self.charge_regular(frame, COLD_ACCOUNT_SURCHARGE, "the cold access")
                    self.warm_accounts.add(target)
                elif target in PRECOMPILE_SET:
                    d.add("gasLedgers", f"the precompile at {h(target)} is warm from the transaction's start: the CALL makes "
                          "no cold access, its own regular charges coming first, as any opcode's", "SATIN-SCHED-012",
                          "SATIN-DET-021")
                self.load(target, "the CALL's target, once the opcode's access is paid", "SATIN-WIT-002", "SATIN-WIT-008")
                callee = self.state.get(target)
                delegate = delegate_of(callee.code) if callee is not None else None
                if delegate is not None:
                    # EIP-7702, kept by the base layer: a call to an account holding a delegation runs its delegate's
                    # code, and pays the delegate's access with the opcode's other charges, before the forward.
                    if int.from_bytes(delegate, "big") <= 0x100 or self.keyless_signer != target:
                        raise Unmodelled("a CALL to a delegated account other than a keyless creation's signer")
                    dcold = delegate not in self.warm_accounts
                    self.charge_regular(frame, WARM_READ + (COLD_ACCOUNT_SURCHARGE if dcold else 0), "the delegate's access")
                    self.warm_accounts.add(delegate)
                    self.load(delegate, "the delegate of the CALL's target, once its access is paid", "SATIN-WIT-002",
                              "SATIN-WIT-008")
                    d.add("gasLedgers", f"the CALL's target {h(target)} holds an EIP-7702 delegation to {h(delegate)}: the "
                          f"delegate's access, warm read {WARM_READ}" + (f" + cold surcharge {fmt(COLD_ACCOUNT_SURCHARGE)}"
                                                                          if dcold else "")
                          + ", is one of the opcode's charges, and the delegate's code runs in the target's frame",
                          "SATIN-BASE-001", "SATIN-SCHED-001", "SATIN-SCHED-003")
                opcode_charges = self.regular_charges - before
                new_account = 0
                if value and (callee is None or callee.empty()):
                    if target in PRECOMPILE_SET:
                        raise Unmodelled("a value call to a precompile the state holds no account for")
                    if not self.principles:
                        raise Unmodelled("a value call to an account empty under EIP-161")
                    # SATIN-HIST-010 step 2: the new account's state gas, its legacy share first, before the forward.
                    m = self.multiplier(self.salt_bucket(target, None))
                    new_account = ACCOUNT_STATE * m
                    legacy = min(new_account, LEGACY_NEW_ACCOUNT_SHARE)
                    self.charge_state(frame, new_account, legacy, "the new account")
                    self.state_gas += new_account
                    d.add("gasLedgers", f"step 2 of the value CALL to {h(target)}, an account empty under EIP-161, after the "
                          "opcode's regular charges (step 1, below) and before the forward: the new "
                          f"account's state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(new_account)}, its legacy share "
                          f"min({fmt(new_account)}, PRE_FORK_NEW_ACCOUNT_COST {fmt(PRE_FORK_NEW_ACCOUNT_COST)} - 0) = "
                          f"{fmt(legacy)} from regular gas first, then the reservoir, which holds nothing, then the rest "
                          f"{fmt(new_account - legacy)} from regular gas, which the forward is then computed from",
                          "SATIN-HIST-010", "SATIN-STATE-001", "SATIN-STATE-003", "SATIN-STATE-012", "SATIN-POOL-008")
                remaining = frame["regular"]
                self.probe.setdefault("forward", remaining)
                self.probe.setdefault("forward:" + target.hex(), remaining)  # each target's first CALL
                self.probe.setdefault("reservoir:" + target.hex(), frame["reservoir"])
                cap = remaining - remaining * GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR
                forward = min(gas_req, cap)
                if self.detention and frame.get("spendable") is not None:
                    d.add("gasLedgers", f"the frame is detained, {fmt(frame['spendable'])} of its {fmt(remaining)} regular "
                          "gas spendable: the forward is computed from the whole regular gas, the withheld part included, "
                          "and drawn from the withheld part first; it is not compute", "SATIN-DET-015", "SATIN-DET-017",
                          "SATIN-DET-009")
                self.draw_regular(frame, forward)
                self.regular_charges += forward
                child_gas = forward + (CALL_STIPEND if value else 0)
                operand = fmt(gas_req) if gas_req < 2**256 - 1 else "the gas operand 2^256 - 1"
                d.add("gasLedgers", f"CALL to {h(target)} with value {value}: the opcode's own charges {fmt(opcode_charges)} = "
                      f"warm read {WARM_READ}" + (f" + value transfer {fmt(CALL_VALUE_COST)}" if value else "") +
                      (f" + cold surcharge {fmt(COLD_ACCOUNT_SURCHARGE)}" if cold else "") +
                      (" + input memory" if opcode_charges > WARM_READ + (CALL_VALUE_COST if value else 0) +
                       (COLD_ACCOUNT_SURCHARGE if cold else 0) else "") +
                      f"; forward min({operand}, {fmt(remaining)} - {fmt(remaining)} x {GAS_RETAINED_NUMERATOR} / "
                      f"{GAS_RETAINED_DENOMINATOR} = {fmt(cap)}) = {fmt(forward)}"
                      + (f", the child's gas {fmt(forward)} + CALL_STIPEND {CALL_STIPEND} = {fmt(child_gas)}" if value else ""),
                      "SATIN-SCHED-002", "SATIN-SCHED-003", "SATIN-FWD-001", "SATIN-FWD-002", "SATIN-FWD-003",
                      "SATIN-HIST-010", *self.order()[1])
                # The history of the records the start would make, as the state stands now (SATIN-HIST-015):
                # charged by the opcode with its other charges, after the forward (SATIN-HIST-010 step 4) and
                # before the depth gate, interception and the frame start; a start that would make them and
                # does not happen gives it back (D-58). A value the caller cannot fund, and a value to the
                # caller itself, make no record.
                balance = self.state.get(address, Account()).balance
                fundable = value <= balance
                records = [a for a in (address, target)
                           if value and fundable and target != address and ("a", a) not in self.kv and a != tx.sender
                           and a not in self.destroyed and a != self.keyless_signer]
                if value and fundable and self.keyless_signer in (address, target):
                    d.add("gasLedgers", f"the keyless signer {h(self.keyless_signer)}, whose nonce the creation's start "
                          "bumped, differs from what the transaction loaded already: the transfer makes no record of it, "
                          "and its record is counted on the call when the creation has returned", "SATIN-KEY-012",
                          "SATIN-KEY-013", "SATIN-HIST-009", "SATIN-ACCT-004")
                if value and fundable and target in self.destroyed:
                    d.add("resources", f"the value sent to {h(target)}, which a destruction marked, is no rise and makes "
                          "no record for it", "SATIN-SD-015")
                history = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE * len(records)
                if value and not fundable:
                    d.add("gasLedgers", f"the caller's balance {balance} cannot fund the value {value}: as the state stands, "
                          "the start would make no record, so the opcode charges no record history and has none to give "
                          "back", "SATIN-HIST-015", *self.order()[1])
                if history and history > frame["reservoir"] + frame["regular"]:
                    d.add("gasLedgers", f"the opcode charges the history of the {len(records)} records its start would make, "
                          f"{len(records)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(history)}, after the forward: "
                          f"the caller keeps {fmt(frame['regular'])} of regular gas and {fmt(frame['reservoir'])} of reservoir, "
                          "which cannot pay it, so it halts out of gas in the opcode, before the depth gate: no interceptor "
                          "answers, no hint is admitted and no frame starts", "SATIN-HIST-009", "SATIN-HIST-010",
                          "SATIN-ICPT-007", *self.order()[1])
                    raise Halt(f"out of gas paying the history of the start's records, {fmt(history)}, with "
                               f"{fmt(frame['regular'])} regular gas left")
                if history:
                    from_reservoir = min(frame["reservoir"], history)
                    self.charge_state(frame, history, 0, "the start's records")
                    self.history_gas += history
                    self.history_bytes += WRITE_RECORD_SIZE * len(records)
                    whose = " and ".join("the caller's account" if a == address else "the callee's account" for a in records)
                    d.add("gasLedgers", f"the opcode charges the history of the {len(records)} records its start would make "
                          f"({whose}), {len(records)} x {WRITE_RECORD_SIZE} x {COST_PER_HISTORY_BYTE} = {fmt(history)}, "
                          "with its other charges: after the forward, which it does not reduce, and before the depth gate, "
                          f"interception and the frame start: {fmt(from_reservoir)} from the caller's reservoir, which it "
                          f"draws first, and {fmt(history - from_reservoir)} from its regular gas ({self.order()[0]})",
                          "SATIN-HIST-009", "SATIN-HIST-010", "SATIN-HIST-014", "SATIN-HIST-015", "SATIN-POOL-008",
                          *self.order()[1])
                share = self.reservoir_share(frame, f"the start of the CALL to {h(target)}")
                self.history_number = False
                if target in PRECOMPILE_SET:
                    ok, out, left = self.precompile_call(frame, address, target, value, bytes(memory[a_off:a_off + a_size]),
                                                         child_gas, records, history, share)
                else:
                    ok, out, left = self.call(frame, address, target, value, bytes(memory[a_off:a_off + a_size]),
                                              child_gas, records, history, new_account, share,
                                              code=self.state[delegate].code if delegate is not None else None)
                frame["regular"] += left
                self.regular_charges -= left
                self.resume(frame, f"the CALL to {h(target)}")
                self.split(frame)  # the caller resumes (SATIN-DET-014, SATIN-DET-019)
                if self.detention and target == HISTORY_STORAGE_ADDRESS and not self.history_number:
                    d.add("gasLedgers", "the call to the EIP-2935 history contract ended without its code completing a "
                          "NUMBER: the call itself is not marked, so it is no read", "SATIN-DET-005", "SATIN-DET-003")
                if self.detention and value and ok and self.limit is not None and target not in PRECOMPILE_SET:
                    d.add("gasLedgers", f"the value call returns: what its callee ran on the {fmt(CALL_STIPEND)} stipend was "
                          f"compute, and the {fmt(left)} it left, the rest of the stipend among it, comes back to the caller "
                          f"without lowering the compute, {fmt(self.compute)}", "SATIN-DET-010", "SATIN-DET-009")
                if self.detention and frame.get("spendable") is not None:
                    d.add("gasLedgers", f"the caller resumes on {fmt(frame['regular'])} of regular gas, the gas the call "
                          f"returned among it: {fmt(frame['spendable'])} spendable, what the limit leaves the transaction",
                          "SATIN-DET-014", "SATIN-DET-015", "SATIN-DET-019")
                returndata = out
                if r_size:
                    raise Unmodelled("a call that copies its output")
                stack.append(1 if ok else 0)
                steps.append(f"CALL {fmt(opcode_charges + forward - left)} net")
                d.add("gasLedgers", f"the call returns {fmt(left)} regular gas to its caller; success {int(ok)}, "
                      f"{len(out)} bytes of return data", "SATIN-POOL-012", "SATIN-ICPT-004")
            elif op == 0xF4:  # DELEGATECALL
                gas_req, target_w, a_off, a_size, r_off, r_size = [pop() for _ in range(6)]
                target = (target_w % 2**160).to_bytes(20, "big")
                before = self.regular_charges
                self.charge_regular(frame, WARM_READ, "DELEGATECALL")
                expand(a_off, a_size, "DELEGATECALL input")
                expand(r_off, r_size, "DELEGATECALL output")
                cold = target not in self.warm_accounts
                if cold:
                    self.charge_regular(frame, COLD_ACCOUNT_SURCHARGE, "the cold access")
                    self.warm_accounts.add(target)
                self.load(target, "the DELEGATECALL's code account, once the opcode's access is paid", "SATIN-WIT-002",
                          "SATIN-WIT-008")
                opcode_charges = self.regular_charges - before
                remaining = frame["regular"]
                cap = remaining - remaining * GAS_RETAINED_NUMERATOR // GAS_RETAINED_DENOMINATOR
                forward = min(gas_req, cap)
                self.draw_regular(frame, forward)
                self.regular_charges += forward
                d.add("gasLedgers", f"DELEGATECALL to {h(target)}: the opcode's own charges {fmt(opcode_charges)}; forward "
                      f"min(the gas operand, {fmt(remaining)} - {fmt(remaining)} x {GAS_RETAINED_NUMERATOR} / "
                      f"{GAS_RETAINED_DENOMINATOR} = {fmt(cap)}) = {fmt(forward)}; it moves no value and makes no record",
                      "SATIN-SCHED-002", "SATIN-SCHED-003", "SATIN-FWD-001", "SATIN-FWD-002", "SATIN-FWD-003")
                share = self.reservoir_share(frame, f"the DELEGATECALL frame running {h(target)}'s code")
                ok, out, left = self.delegatecall(frame, address, caller, value_in, target,
                                                  bytes(memory[a_off:a_off + a_size]), forward, share)
                frame["regular"] += left
                self.regular_charges -= left
                self.resume(frame, f"the DELEGATECALL running {h(target)}'s code")
                self.split(frame)
                returndata = out
                if r_size:
                    raise Unmodelled("a call that copies its output")
                stack.append(1 if ok else 0)
                steps.append(f"DELEGATECALL {fmt(opcode_charges + forward - left)} net")
            elif op in (0xF0, 0xF5):  # CREATE, and CREATE2 as far as its salt operand
                name = "CREATE" if op == 0xF0 else "CREATE2"
                if len(stack) < 3:
                    # SATIN-SIZE-005 step 2: the operands are read before any charge, so a creation short of them fails
                    # with nothing charged, a halt of its frame (SATIN-OUT-012).
                    d.add("outcome", f"{name} finds {len(stack)} of its value, offset and size operands on the stack: it "
                          "fails reading them, before any of its checks or charges, and halts its frame", "SATIN-OUT-012",
                          "SATIN-SIZE-005")
                    raise Halt(f"{name} short of its operands")
                value, c_off, c_size = pop(), pop(), pop()
                if c_size > MAX_INITCODE_SIZE:
                    # SATIN-SIZE-005 step 3: the initcode's size is checked before EIP-3860's cost and the memory.
                    d.add("outcome", f"{name} with {fmt(c_size)} bytes of initcode, over MAX_INITCODE_SIZE "
                          f"{fmt(MAX_INITCODE_SIZE)}: the size check, made after the operands and before any charge, halts "
                          "the creating frame at the opcode, Ethereum's check at MegaETH's size and no limit stop",
                          "SATIN-SIZE-002", "SATIN-SIZE-003", "SATIN-SIZE-005", "SATIN-OUT-003")
                    raise Halt(f"initcode of {fmt(c_size)} bytes, over MAX_INITCODE_SIZE")
                if self.outcomes:
                    d.add("outcome", f"{name} with {fmt(c_size)} bytes of initcode, within MAX_INITCODE_SIZE "
                          f"{fmt(MAX_INITCODE_SIZE)}: the size check passes and the creation goes on to its charges",
                          "SATIN-SIZE-002", "SATIN-SIZE-003", "SATIN-OUT-003")
                words = (c_size + 31) // 32
                before = self.regular_charges
                # SATIN-SIZE-005 steps 4 to 6: EIP-3860's initcode cost, the memory the initcode is read from, then
                # (CREATE2's salt, then) CREATE_ACCESS; each part is a charge of its own under gas detention.
                try:
                    self.charge_regular(frame, INITCODE_WORD_COST * words, f"{name}'s init code")
                    expand(c_off, c_size, name)
                except Stopped:
                    if op == 0xF5 and not stack:
                        d.add("outcome", "CREATE2 short of its salt makes its initcode and memory charges before the "
                              "missing operand fails, and one of them is gas detention's crossing: the frame is stopped, "
                              "a revert, where the missing salt would have halted it", "SATIN-OUT-012", "SATIN-SIZE-006")
                    raise
                if op == 0xF5:
                    if not stack:
                        d.add("outcome", f"CREATE2 has paid its initcode cost and its memory, {fmt(self.regular_charges - before)}, "
                              "and finds no salt operand: it fails on the missing operand and halts its frame",
                              "SATIN-OUT-012", "SATIN-SIZE-005", "SATIN-SIZE-006")
                        raise Halt("CREATE2 short of its salt")
                    raise Unmodelled("a CREATE2 with its salt")
                self.charge_regular(frame, CREATE_ACCESS, "CREATE")
                opcode_charges = self.regular_charges - before
                d.add("gasLedgers", f"CREATE with {c_size} bytes of init code and {value} wei: regular {words} words x "
                      f"{INITCODE_WORD_COST} + memory, then CREATE_ACCESS {fmt(CREATE_ACCESS)} = {fmt(opcode_charges)}",
                      "SATIN-SCHED-002", "SATIN-SCHED-003", "SATIN-SIZE-005")
                created, left, returndata = self.create(frame, address, value, bytes(memory[c_off:c_off + c_size]))
                frame["regular"] += left
                self.regular_charges -= left
                stack.append(int.from_bytes(created, "big"))
                steps.append(f"CREATE {fmt(opcode_charges)} + the creation")
            elif op == 0xFF:  # SELFDESTRUCT
                beneficiary = (pop() % 2**160).to_bytes(20, "big")
                if not ctx and (create or address in self.created or not self.destruction):
                    raise Unmodelled("a SELFDESTRUCT of the transaction's own frame")
                self.selfdestruct(frame, address, beneficiary)
                steps.append("SELFDESTRUCT")
                return done("success", b"")
            else:
                raise Unmodelled(f"opcode {op:#x}")
        return done("success", b"")
