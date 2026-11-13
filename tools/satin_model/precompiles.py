"""A call to a precompile, decided under gas detention from its price (`SATIN-DET-021` to `-024`): the identity
precompile, ModExp's EIP-7883 price over and under EIP-7823's bound, and the BN254 pairing over its size limit."""

from __future__ import annotations

from .constants import (
    BN254_PAIRING, BN254_PAIRING_MAX_INPUT_SIZE, DETENTION_STOP, IDENTITY, IDENTITY_BASE, IDENTITY_WORD,
    limit_exceeded, MODEXP, MODEXP_MAX_INPUT_SIZE, MODEXP_MIN_GAS, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE,
    TRANSFER_TOPIC, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, pad_address, Unmodelled


def modexp_lengths(data: bytes) -> tuple[int, int, int]:
    """ModExp's three lengths, the input read as right-padded with zeros."""
    head = data[:96].ljust(96, b"\x00")
    return tuple(int.from_bytes(head[i:i + 32], "big") for i in (0, 32, 64))


def modexp_price(data: bytes) -> tuple[int, int, int]:
    """EIP-7883's price (SATIN-PCMP-002): the multiplication complexity, 16 up to 32 bytes and twice the square of
    the words of the longer of base and modulus above, times the iteration count, at least MODEXP_MIN_GAS; with the
    complexity and the iteration count."""
    base_len, exp_len, mod_len = modexp_lengths(data)
    longest = max(base_len, mod_len)
    complexity = 16 if longest <= 32 else 2 * ((longest + 7) // 8) ** 2
    body = data[96:]
    head = int.from_bytes(body[base_len:base_len + min(exp_len, 32)].ljust(min(exp_len, 32), b"\x00"), "big")
    if exp_len <= 32:
        iterations = max(head.bit_length() - 1, 0)
    else:
        iterations = 16 * (exp_len - 32) + max(head.bit_length() - 1, 0)
    iterations = max(iterations, 1)
    return max(MODEXP_MIN_GAS, complexity * iterations), complexity, iterations


class PrecompilesMixin:
    """A call to a precompile: warm, its own charges made in the opcode, then decided from its price."""

    def precompile_price(self, target: bytes, data: bytes) -> tuple[int, str, bool]:
        """The precompile's price for this input, read before it runs (SATIN-DET-023), how it is priced, and whether
        the input fails a check the precompile makes after its gas charge or before any (SATIN-PCMP-005, -007)."""
        if target == IDENTITY:
            words = (len(data) + 31) // 32
            price = IDENTITY_BASE + IDENTITY_WORD * words
            return price, f"the identity precompile's {IDENTITY_BASE} + {IDENTITY_WORD} x {words} words = {fmt(price)}", False
        if target == MODEXP:
            base_len, exp_len, mod_len = modexp_lengths(data)
            price, complexity, iterations = modexp_price(data)
            over = max(base_len, exp_len, mod_len) > MODEXP_MAX_INPUT_SIZE
            return price, (f"ModExp's EIP-7883 price for a base of {fmt(base_len)} bytes, an exponent of {fmt(exp_len)} and "
                           f"a modulus of {fmt(mod_len)}: max({MODEXP_MIN_GAS}, multiplication complexity {fmt(complexity)} "
                           f"x iteration count {fmt(iterations)}) = {fmt(price)}"
                           + (f", whatever the lengths: the base is over EIP-7823's bound of {fmt(MODEXP_MAX_INPUT_SIZE)} "
                              "bytes, which ModExp checks after it charges that price" if over else "")), over
        if target == BN254_PAIRING:
            if len(data) <= BN254_PAIRING_MAX_INPUT_SIZE:
                raise Unmodelled("a BN254 pairing within its size limit")
            return 0, (f"zero: the BN254 pairing's {fmt(len(data))} input bytes are over its size limit of "
                       f"{fmt(BN254_PAIRING_MAX_INPUT_SIZE)}, refused before any gas check"), True
        raise Unmodelled(f"the precompile at {h(target)}")

    def precompile_call(self, frame, caller: bytes, target: bytes, value: int, data: bytes, child_gas: int,
                        records: list, history: int, share: int):
        """A call to a precompile once the opcode's charges, the forward and the history of the start's records are
        made: the funds check, then, once a limit is set, the decision from the price (SATIN-DET-021). Returns
        (success, return data, the regular gas the call returns)."""
        d = self.d
        frame["reservoir"] += share  # no frame is built: the share returns untouched (SATIN-POOL-012)
        if self.limit is not None:
            self.probe.setdefault("precompile-room", max(0, self.limit - self.compute))
        caller_acct = self.state.setdefault(caller, Account())
        if value > caller_acct.balance:
            if history:
                raise Unmodelled("a refused start charged for records")
            d.add("outcome", f"the call to the precompile at {h(target)} carries a value its caller's balance "
                  f"{caller_acct.balance} cannot fund: refused on the caller's account, it runs no precompile and is answered "
                  "as without the read, failing with empty return data", "SATIN-DET-024", "SATIN-LIM-015",
                  "SATIN-OUT-010")
            d.add("gasLedgers", f"the refused call returns the child's {fmt(child_gas)} regular gas, the stipend included, "
                  "and charges nothing beyond the opcode's", "SATIN-POOL-012", "SATIN-DET-024")
            return False, b"", child_gas
        price, how, fails = self.precompile_price(target, data)
        if self.limit is not None:
            allowance = max(0, self.limit - self.compute)
            if child_gas > allowance:
                if allowance < price <= child_gas:
                    d.add("outcome", f"the call to the precompile at {h(target)} is forwarded {fmt(child_gas)}, more than the "
                          f"allowance {fmt(allowance)} the limit {fmt(self.limit)} leaves the transaction's compute "
                          f"{fmt(self.compute)}, so it is decided from its price, read before it runs: {how}, past the "
                          "allowance and within the forward: it does not run and is the crossing, its result the "
                          f"compute stop MegaLimitExceeded({DETENTION_STOP}, {fmt(self.limit)}), which its caller catches",
                          "SATIN-DET-021", "SATIN-DET-023", "SATIN-STOP-014", "SATIN-STOP-020",
                          *(("SATIN-DET-024",) if fails else ()), *(("SATIN-DET-022",) if value else ()))
                    if value:
                        d.add("outcome", f"its value {value} has not moved when the price is consulted: held to the price "
                              "alone, the stop is kind 2, and the start makes none of the records or the transfer log its "
                              "value transfer would have made", "SATIN-DET-022", "SATIN-LIM-010", "SATIN-STOP-016")
                    d.add("gasLedgers", f"the crossing bills nothing of the price: the forward, {fmt(child_gas)}, returns to "
                          "the caller, which resumes held to what the limit leaves the transaction", "SATIN-DET-011",
                          "SATIN-DET-019", "SATIN-STOP-005")
                    if history:
                        self.give_back_start(frame, records, history, "the crossing starts no frame and moves nothing")
                    return False, limit_exceeded(DETENTION_STOP, self.limit), child_gas
                d.add("gasLedgers", f"the call to the precompile at {h(target)} is forwarded {fmt(child_gas)}, more than the "
                      f"allowance {fmt(allowance)}, so it is decided from its price: {how}, "
                      + ("within the allowance: it runs on its whole forward" if price <= allowance else
                         "past its whole forward: it runs on its forward and fails, as without the read"),
                      "SATIN-DET-021", "SATIN-DET-023")
        if value:
            if price > child_gas or fails or target != IDENTITY:
                raise Unmodelled("a value call to a precompile that fails")
            # The start: the value moves and makes the records the opcode charged, and its transfer log (SATIN-LIM-013).
            caller_acct.balance -= value
            self.state.setdefault(target, Account()).balance += value
            for a in records:
                self.kv.add(("a", a))
            self.data_size += WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(caller), pad_address(target)],
                              value.to_bytes(32, "big")))
            d.add("resources", f"the value moves to the precompile: the start's {len(records)} records and its transfer "
                  "log", "SATIN-LIM-013", "SATIN-ACCT-005", "SATIN-LOG-006")
        if price > child_gas:
            d.add("outcome", f"the precompile at {h(target)} is priced {fmt(price)}, past the {fmt(child_gas)} it is "
                  "forwarded: it fails out of gas and consumes its forward", "SATIN-OUT-007", "SATIN-DET-021")
            d.add("gasLedgers", f"what the failed precompile burns, its forward of {fmt(child_gas)}, is not compute: the "
                  f"transaction's compute stays {fmt(self.compute)}", "SATIN-DET-011", "SATIN-DET-020")
            return False, b"", 0
        self.compute += price
        if fails:
            d.add("outcome", f"the precompile at {h(target)} runs on its forward of {fmt(child_gas)}, charges its price "
                  f"{fmt(price)}, then fails its input's check and consumes the whole forward, as without the read",
                  "SATIN-PCMP-005", "SATIN-PCMP-007", "SATIN-DET-021")
            d.add("gasLedgers", f"its charged price {fmt(price)} is compute, now {fmt(self.compute)}; the rest of the "
                  "forward it burns is not", "SATIN-DET-009", "SATIN-DET-011", "SATIN-DET-019")
            return False, b"", 0
        d.add("outcome", f"the precompile at {h(target)} runs on its forward of {fmt(child_gas)}, charges its price "
              f"{fmt(price)} and returns its {fmt(len(data))} input bytes", "SATIN-DET-021", "SATIN-OUT-001")
        d.add("gasLedgers", f"the precompile's price is compute, now {fmt(self.compute)}; it returns "
              f"{fmt(child_gas - price)} to its caller", "SATIN-DET-009", "SATIN-POOL-012")
        if target != IDENTITY:
            raise Unmodelled("the output of a precompile other than the identity")
        return True, data, child_gas - price
