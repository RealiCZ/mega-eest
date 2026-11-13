"""A keyless deployment past step 3's encoding check (`SATIN-KEY-005`): the carried transaction decoded and its signer
recovered, steps 3 to 15 in the table's order with the first refusal answering (`SATIN-KEY-006`), the reads of the
signer and the deploy address (`SATIN-KEY-007`, `-010`), the creation the call starts (`SATIN-KEY-011`), the signer's
nonce and records once it returned (`SATIN-KEY-012`, `-013`), `gasUsed` (`SATIN-KEY-015`) and the answer
(`SATIN-KEY-014`)."""

from __future__ import annotations

from .constants import (
    ACCOUNT_STATE, BLOCK_ENV_ACCESS_COMPUTE_GAS, COST_PER_HISTORY_BYTE, CREATE_GAS, delegate_of, ex, INITCODE_WORD_COST,
    KEYLESS_ERRORS, LEGACY_CREATE_SHARE, LEGACY_NEW_ACCOUNT_SHARE, MAX_INITCODE_SIZE, MAX_U64, SECP256K1_G,
    SECP256K1_N, SECP256K1_P, TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC, WRITE_RECORD_SIZE,
)
from .records import Account, created_address, fmt, h, Halt, pad_address, Unmodelled

RECORD_HISTORY = WRITE_RECORD_SIZE * COST_PER_HISTORY_BYTE
MAX_U128 = 2**128 - 1


def keyless_error(name: str, *args: int) -> bytes:
    """A KeylessDeploy error, ABI-encoded as a Solidity custom error: the selector, then each argument as a word
    (SATIN-KEY-001)."""
    return KEYLESS_ERRORS[name] + b"".join(a.to_bytes(32, "big") for a in args)


def padded(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 32)


def execution_reverted(gas_used: int, output: bytes) -> bytes:
    """`ExecutionReverted(uint64 gasUsed, bytes output)`: the head word, the offset of the bytes, their length, the
    bytes padded to a word (SATIN-KEY-001)."""
    return (KEYLESS_ERRORS["ExecutionReverted(uint64,bytes)"] + gas_used.to_bytes(32, "big") + (64).to_bytes(32, "big")
            + len(output).to_bytes(32, "big") + padded(output))


def keyless_answer(gas_used: int, deployed: bytes, error: bytes) -> bytes:
    """The return value `(uint64 gasUsed, address deployedAddress, bytes errorData)`, ABI-encoded (SATIN-KEY-001,
    SATIN-KEY-014)."""
    return (gas_used.to_bytes(32, "big") + pad_address(deployed) + (96).to_bytes(32, "big")
            + len(error).to_bytes(32, "big") + padded(error))


def rlp_strings(b: bytes) -> list[bytes]:
    """The items of an RLP list that holds byte strings alone, each canonically encoded: what a signed legacy
    transaction's nine fields are. Anything else is not modelled: whether a decoder refuses it is not this model's."""
    n = b[0] - 0xF7 if b[0] > 0xF7 else 0
    pos, out = 1 + n, []
    while pos < len(b):
        p = b[pos]
        if p < 0x80:
            out.append(b[pos:pos + 1])
            pos += 1
        elif p <= 0xB7:
            size = p - 0x80
            item = b[pos + 1:pos + 1 + size]
            if size == 1 and item[0] < 0x80:
                raise Unmodelled("a carried transaction with a non-canonical RLP string")
            out.append(item)
            pos += 1 + size
        elif p <= 0xBF:
            k = p - 0xB7
            size = int.from_bytes(b[pos + 1:pos + 1 + k], "big")
            if size < 56 or b[pos + 1] == 0:
                raise Unmodelled("a carried transaction with a non-canonical RLP string")
            out.append(b[pos + 1 + k:pos + 1 + k + size])
            pos += 1 + k + size
        else:
            raise Unmodelled("a carried transaction whose RLP list holds a list")
    if pos != len(b):
        raise Unmodelled("a carried transaction whose RLP items overrun the list")
    return out


def scalar(b: bytes, bound: int, what: str) -> int:
    """An RLP integer: big-endian, without a leading zero, within the field's type."""
    if b[:1] == b"\x00":
        raise Unmodelled(f"a carried transaction whose {what} has a leading zero")
    v = int.from_bytes(b, "big")
    if v > bound:
        raise Unmodelled(f"a carried transaction whose {what} overflows its type")
    return v


def decode_carried(argument: bytes) -> dict:
    """Step 3's decode of the first argument, one RLP list (the caller checked it is exactly one): a signed legacy
    transaction's nine fields, `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`."""
    fields = rlp_strings(argument)
    if len(fields) != 9:
        raise Unmodelled(f"a carried RLP list of {len(fields)} strings, not a legacy transaction's nine")
    nonce, price, gas, to, value, data, v, r, s = fields
    if len(to) not in (0, 20):
        raise Unmodelled("a carried transaction whose to is neither empty nor an address")
    tx = {"nonce": scalar(nonce, MAX_U64, "nonce"), "gasPrice": scalar(price, MAX_U128, "gas price"),
          "gasLimit": scalar(gas, MAX_U64, "gas limit"), "to": to, "value": scalar(value, 2**256 - 1, "value"),
          "data": data, "v": scalar(v, MAX_U64, "v"), "r": scalar(r, 2**256 - 1, "r"), "s": scalar(s, 2**256 - 1, "s")}
    if tx["v"] in (27, 28):
        tx["chainId"] = None
    elif tx["v"] >= 35:
        tx["chainId"] = (tx["v"] - 35) // 2
    else:
        raise Unmodelled("a carried signature whose v is neither 27, 28 nor an EIP-155 value")
    return tx


# --- step 7: the signer, recovered from the signature, low or high s ----------------------------


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    p = SECP256K1_P
    if a[0] == b[0] and (a[1] + b[1]) % p == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, p) % p
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return x, (lam * (a[0] - x) - a[1]) % p


def _mul(k: int, point):
    out = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)
        k >>= 1
    return out


def recover_signer(tx: dict) -> bytes | None:
    """The signer of a pre-EIP-155 legacy transaction: the public key the signature `(v, r, s)` recovers from
    `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))`, or None when none can be recovered. EIP-2's
    bound on `s` is not applied (SATIN-KEY-005 step 7)."""
    n, p = SECP256K1_N, SECP256K1_P
    r, s, parity = tx["r"], tx["s"], tx["v"] - 27
    if not (0 < r < n and 0 < s < n):
        return None
    alpha = (r * r * r + 7) % p
    beta = pow(alpha, (p + 1) // 4, p)
    if beta * beta % p != alpha:
        return None  # r is the x of no curve point
    point_r = (r, beta if beta % 2 == parity else p - beta)
    z = int.from_bytes(ex.keccak256(ex.rlp([tx["nonce"], tx["gasPrice"], tx["gasLimit"], tx["to"], tx["value"],
                                            tx["data"]])), "big")
    inv = pow(r, -1, n)
    key = _add(_mul(s * inv % n, point_r), _mul((-z * inv) % n, SECP256K1_G))
    if key is None:
        return None
    return ex.keccak256(key[0].to_bytes(32, "big") + key[1].to_bytes(32, "big"))[12:]


class KeylessMixin:
    """A keyless deployment past step 3's encoding check: steps 3 to 15, the creation, the settlement and the answer."""

    def keyless_predicates(self, tx: dict, signer: bytes | None, override: int) -> list[tuple[int, str]]:
        """The steps of 3 to 13 that would refuse the call, judged on the state as it stands, each with its error; step
        11, which the gas the earlier steps leave decides, and step 10, a charge, are not judged here."""
        out = []
        if tx["to"]:
            out.append((3, "NotContractCreation()"))
        elif tx["chainId"] is not None:
            out.append((3, "NotPreEIP155()"))
        if tx["nonce"]:
            out.append((4, "NonZeroTxNonce(uint64)"))
        if len(tx["data"]) > MAX_INITCODE_SIZE:
            out.append((5, "InitCodeTooLarge(uint64,uint64)"))
        if min(override, MAX_U64) < tx["gasLimit"]:
            out.append((6, "GasLimitTooLow(uint64,uint64)"))
        if tx["chainId"] is not None:
            return out  # no pre-EIP-155 signature to recover a signer from: steps 7 to 13 are not judged
        if signer is None:
            out.append((7, "InvalidSignature()"))
            return out
        acct = self.state.get(signer, Account())
        if acct.nonce > 1:
            out.append((8, "SignerNonceTooHigh(uint64)"))
        if acct.code and delegate_of(acct.code) is None:
            out.append((9, "SignerHasCode()"))
        deploy = self.state.get(created_address(signer, 0))
        if deploy is not None and deploy.code:
            out.append((12, "ContractAlreadyExists()"))
        if acct.balance < tx["value"]:
            out.append((13, "InsufficientBalance()"))
        return out

    def keyless_refusal(self, step: int, error: bytes, why: str, predicates: list) -> tuple[str, bytes]:
        """A step's refusal: the call reverts with the error; the state and history gas it was charged come back into
        its reservoir and its regular gas stays spent (SATIN-KEY-004). When a later step of 3 to 13 would refuse too,
        the first in the table's order answers (SATIN-KEY-006)."""
        d = self.d
        later = sorted({s for s, _ in predicates if s > step})
        d.add("outcome", f"step {step}: {why}: the call reverts with {KEYLESS_ERRORS_BY_SELECTOR[error[:4]]}, ABI-encoded "
              f"as a custom error, {len(error)} bytes", "SATIN-KEY-001", "SATIN-KEY-004", "SATIN-KEY-005")
        if later:
            d.add("outcome", f"step{'s' if len(later) > 1 else ''} {', '.join(map(str, later))} would refuse the call too: "
                  f"the first refusing step in the table's order, step {step}, answers", "SATIN-KEY-006")
        return "revert", error

    def halting(self, step: int, charge) -> None:
        """A step's charge, which halts the call out of gas when the call cannot pay it (SATIN-KEY-004)."""
        try:
            charge()
        except Halt as e:
            self.d.add("outcome", f"step {step} cannot pay its charge ({e}): the call halts out of gas, consuming its "
                       "regular gas, and no step after it is made", "SATIN-KEY-004", "SATIN-KEY-005")
            raise

    def keyless_deploy(self, frame, argument: bytes, override: int) -> tuple[str, bytes]:
        """Steps 3 to 15 of a recognized keylessDeploy call whose first argument is one RLP list, then the creation, the
        settlement and the answer. Returns the call's (status, output)."""
        d, tx, env = self.d, self.tx, self.env
        carried = decode_carried(argument)
        signer = recover_signer(carried) if carried["chainId"] is None else None
        predicates = self.keyless_predicates(carried, signer, override)
        gas, value, init = carried["gasLimit"], carried["value"], carried["data"]
        # Step 3: a signed legacy transaction that is a creation and carries no chain id, in step 3's own order.
        if carried["to"]:
            if carried["chainId"] is not None:
                d.add("outcome", f"step 3: the carried transaction has to set ({h(carried['to'])}) and carries chain id "
                      f"{carried['chainId']}: step 3 refuses it for both, with the first error in its own order, "
                      "NotContractCreation()", "SATIN-KEY-006")
            return self.keyless_refusal(3, keyless_error("NotContractCreation()"), "the carried transaction has to set, "
                                        f"{h(carried['to'])}: it is no creation", predicates)
        if carried["chainId"] is not None:
            return self.keyless_refusal(3, keyless_error("NotPreEIP155()"), f"the carried signature's v "
                                        f"{carried['v']} carries chain id {carried['chainId']}", predicates)
        d.add("outcome", f"step 3: the first argument's {len(argument)} bytes are one RLP list of a signed legacy "
              f"transaction, a creation (to empty) with v {carried['v']}, no chain id, and no trailing byte",
              "SATIN-KEY-005")
        # Steps 4 to 6.
        if carried["nonce"]:
            return self.keyless_refusal(4, keyless_error("NonZeroTxNonce(uint64)", carried["nonce"]),
                                        f"the carried transaction's nonce is {carried['nonce']}, not 0", predicates)
        if len(init) > MAX_INITCODE_SIZE:
            return self.keyless_refusal(5, keyless_error("InitCodeTooLarge(uint64,uint64)", len(init), MAX_INITCODE_SIZE),
                                        f"the initcode's {fmt(len(init))} bytes exceed MAX_INITCODE_SIZE "
                                        f"{fmt(MAX_INITCODE_SIZE)}", predicates)
        read = min(override, MAX_U64)
        shown = fmt(override) if override <= MAX_U64 else "a value above MAX_UINT64, read as MAX_UINT64"
        if read < gas:
            return self.keyless_refusal(6, keyless_error("GasLimitTooLow(uint64,uint64)", gas, read),
                                        f"gasLimitOverride {shown} is below the signed gas limit {fmt(gas)}", predicates)
        d.add("outcome", f"steps 4 to 6: nonce 0, {fmt(len(init))} bytes of initcode within MAX_INITCODE_SIZE "
              f"{fmt(MAX_INITCODE_SIZE)}, and gasLimitOverride {shown} at least the signed gas limit {fmt(gas)}",
              "SATIN-KEY-005")
        # Step 7: the signer.
        high = carried["s"] > SECP256K1_N // 2
        if signer is None:
            return self.keyless_refusal(7, keyless_error("InvalidSignature()"), "no signer can be recovered from the "
                                        "signature", predicates)
        d.add("outcome", f"step 7: the signature recovers the signer {h(signer)}" +
              (", its s above half the curve order: EIP-2's bound on s does not apply" if high else ""), "SATIN-KEY-005")
        # The read of the signer's account, warm, with its code (EIP-3607 is not disabled), uncharged.
        self.load(signer, "the keyless signer's account, read warm with its code before step 8", "SATIN-KEY-007",
                  "SATIN-WIT-008")
        self.warm_accounts.add(signer)
        d.add("gasLedgers", f"the signer's account is read into the transaction's state warm, with its code, and the read "
              "is not charged", "SATIN-KEY-007")
        if signer == env.coinbase:
            d.add("gasLedgers", f"the signer {h(signer)} is the block beneficiary: its read, after step 7 and before step "
                  f"8, is a read of the beneficiary's account, at the compute of step 1's overhead, {fmt(self.compute)}",
                  "SATIN-KEY-010", "SATIN-DET-003")
            self.mark(BLOCK_ENV_ACCESS_COMPUTE_GAS, "the keyless signer's read, the block beneficiary's account,")
            self.split(frame)
            d.add("gasLedgers", f"the call's regular gas {fmt(frame['regular'])} is split: {fmt(frame['spendable'])} "
                  "spendable, what the limit leaves the transaction, and the rest withheld", "SATIN-DET-014",
                  "SATIN-KEY-010")
        acct = self.state.get(signer, Account())
        n0 = acct.nonce
        # Steps 8 and 9.
        if n0 > 1:
            return self.keyless_refusal(8, keyless_error("SignerNonceTooHigh(uint64)", n0), f"the signer's nonce is {n0}",
                                        predicates)
        if acct.code and delegate_of(acct.code) is None:
            return self.keyless_refusal(9, keyless_error("SignerHasCode()"), f"the signer holds {len(acct.code)} bytes of "
                                        "code that are no EIP-7702 delegation indicator", predicates)
        d.add("outcome", f"steps 8 and 9: the signer's nonce {n0} is at most 1, and its code is "
              + ("an EIP-7702 delegation indicator" if acct.code else "empty"), "SATIN-KEY-005")
        # Step 10: the signer's new account.
        empty_signer = acct.empty()
        signer_state = 0
        self.probe.setdefault("keyless-10", frame["regular"])
        if empty_signer:
            m = self.multiplier(self.salt_bucket(signer, None))
            signer_state = ACCOUNT_STATE * m
            legacy = min(signer_state, LEGACY_NEW_ACCOUNT_SHARE)
            paid = min(frame["reservoir"], signer_state - legacy)
            self.halting(10, lambda: self.charge_state(frame, signer_state, legacy, "the keyless signer's new account"))
            self.state_gas += signer_state
            d.add("gasLedgers", f"step 10: the signer is empty under EIP-161: the state gas of a new account "
                  f"{fmt(ACCOUNT_STATE)} x m={m} = {fmt(signer_state)}, its legacy share min({fmt(signer_state)}, "
                  f"PRE_FORK_NEW_ACCOUNT_COST - 0) = {fmt(legacy)} from regular gas first, then {fmt(paid)} from the "
                  f"reservoir and {fmt(signer_state - legacy - paid)} from regular gas", "SATIN-KEY-005", "SATIN-STATE-001",
                  "SATIN-STATE-003", "SATIN-STATE-011", "SATIN-STATE-012", "SATIN-POOL-008")
        # Step 11: the forward the call could make, its withheld part included.
        self.probe.setdefault("keyless-11", frame["regular"])
        forward = min(read, frame["regular"])
        if forward < gas:
            return self.keyless_refusal(11, keyless_error("GasLimitTooLow(uint64,uint64)", gas, forward),
                                        f"min(gasLimitOverride, the {fmt(frame['regular'])} of regular gas the call holds) = "
                                        f"{fmt(forward)} is below the signed gas limit {fmt(gas)}", predicates)
        d.add("outcome", f"step 11: min(gasLimitOverride, the {fmt(frame['regular'])} of regular gas the call holds, its "
              f"withheld part included) = {fmt(forward)} is at least the signed gas limit {fmt(gas)}", "SATIN-KEY-005")
        # Step 12: the deploy address, read warm without its code; its code alone is checked.
        deploy = created_address(signer, 0)
        self.load(deploy, "the deploy address, read warm without its code at step 12", "SATIN-KEY-007", "SATIN-WIT-008")
        self.warm_accounts.add(deploy)
        there = self.state.get(deploy)
        if there is not None and there.code:
            return self.keyless_refusal(12, keyless_error("ContractAlreadyExists()"), f"the deploy address {h(deploy)} "
                                        f"holds {len(there.code)} bytes of code", predicates)
        if there is not None and (there.nonce or there.balance):
            d.add("outcome", f"step 12: the deploy address {h(deploy)} holds nonce {there.nonce} and balance "
                  f"{there.balance} but no code: step 12 checks its code alone, and passes", "SATIN-KEY-008")
        else:
            d.add("outcome", f"step 12: the deploy address keccak256(rlp([signer, 0]))[12:] = {h(deploy)} holds no code; "
                  "the read is not charged", "SATIN-KEY-005", "SATIN-KEY-007")
        if there is not None and there.storage:
            raise Unmodelled("a keyless deploy address that holds storage")
        # Step 13.
        if acct.balance < value:
            return self.keyless_refusal(13, keyless_error("InsufficientBalance()"), f"the signer's balance "
                                        f"{fmt(acct.balance)} is below the carried value {fmt(value)}", predicates)
        d.add("outcome", f"step 13: the signer's balance {fmt(acct.balance)} covers the carried value {fmt(value)}",
              "SATIN-KEY-005")
        # Step 14: what a CREATE charges its frame for the start.
        self.probe.setdefault("keyless-14", frame["regular"])
        words = (len(init) + 31) // 32
        regular = CREATE_GAS + INITCODE_WORD_COST * words
        self.halting(14, lambda: self.charge_regular(frame, regular, "step 14's CREATE_GAS and initcode"))
        deploy_empty = there is None or there.empty()
        created_state = 0
        text = (f"step 14: CREATE_GAS {fmt(CREATE_GAS)} + {words} initcode words x {INITCODE_WORD_COST} = {fmt(regular)} "
                "of regular gas")
        rules = ["SATIN-KEY-005", "SATIN-SCHED-003"]
        if deploy_empty:
            m = self.multiplier(self.salt_bucket(deploy, None))
            created_state = ACCOUNT_STATE * m
            legacy = min(created_state, LEGACY_CREATE_SHARE)
            paid = min(frame["reservoir"], created_state - legacy)
            self.halting(14, lambda: self.charge_state(frame, created_state, legacy,
                                                       "the keyless creation's created account"))
            self.state_gas += created_state
            text += (f"; the created account's state gas {fmt(ACCOUNT_STATE)} x m={m} = {fmt(created_state)}, its legacy "
                     f"share min({fmt(created_state)}, PRE_FORK_CREATE_COST - CREATE_ACCESS) = {fmt(legacy)} from regular "
                     f"gas first, then {fmt(paid)} from the reservoir and {fmt(created_state - legacy - paid)} from regular "
                     "gas")
            rules += ["SATIN-STATE-001", "SATIN-STATE-003", "SATIN-STATE-012", "SATIN-POOL-008"]
        else:
            text += f"; the deploy address is not empty under EIP-161, so no created-account state gas"
            rules += ["SATIN-KEY-008", "SATIN-STATE-011"]
        deploy_changed = ("a", deploy) in self.kv
        signer_changed = ("a", signer) in self.kv or signer == tx.sender
        if deploy_changed:
            raise Unmodelled("a keyless deploy address the transaction changed already")
        records = [deploy] + ([] if signer_changed else [signer])
        history = RECORD_HISTORY * len(records)
        paid = min(frame["reservoir"], history)
        self.halting(14, lambda: self.charge_state(frame, history, 0, "step 14's records"))
        self.history_gas += history
        self.history_bytes += WRITE_RECORD_SIZE * len(records)
        text += (f"; the history of {'the created account' if len(records) == 1 else 'the created account and the signer'}"
                 f"'s record{'s' if len(records) > 1 else ''}, {len(records)} x {WRITE_RECORD_SIZE} x "
                 f"{COST_PER_HISTORY_BYTE} = {fmt(history)}, {fmt(paid)} from the reservoir and {fmt(history - paid)} from "
                 "regular gas")
        if signer_changed:
            text += ("; none for the signer's nonce record: the signer is the transaction's sender" if signer == tx.sender
                     else "; none for the signer's nonce record: the transaction changed the signer's account already")
            rules += ["SATIN-ACCT-008"] if signer == tx.sender else ["SATIN-ACCT-004"]
        d.add("gasLedgers", text, *rules, "SATIN-HIST-002")
        # Step 15.
        self.probe.setdefault("keyless-15", frame["regular"])
        forward = min(read, frame["regular"])
        if forward < gas:
            return self.keyless_refusal(15, keyless_error("GasLimitTooLow(uint64,uint64)", gas, forward),
                                        f"after step 14, min(gasLimitOverride, the {fmt(frame['regular'])} of regular gas "
                                        f"the call holds) = {fmt(forward)} is below the signed gas limit {fmt(gas)}",
                                        predicates)
        return self.keyless_creation(frame, carried, signer, deploy, read, forward, n0, empty_signer, signer_state,
                                     deploy_empty, created_state, records, signer_changed,
                                     there is not None and there.nonce != 0)

    def keyless_creation(self, frame, carried: dict, signer: bytes, deploy: bytes, read: int, forward: int, n0: int,
                         empty_signer: bool, signer_state: int, deploy_empty: bool, created_state: int, records: list,
                         signer_changed: bool, collides: bool) -> tuple[str, bytes]:
        """The creation once step 15 passed (SATIN-KEY-011), its return, the signer's nonce and records (SATIN-KEY-012,
        -013), gasUsed (SATIN-KEY-015) and the answer (SATIN-KEY-014)."""
        d, tx = self.d, self.tx
        value, init = carried["value"], carried["data"]
        remaining = frame["regular"]
        self.draw_regular(frame, forward)
        self.regular_charges += forward
        d.add("gasLedgers", f"step 15: min(gasLimitOverride {fmt(read)}, the {fmt(remaining)} of regular gas the call "
              f"holds, its withheld part included) = {fmt(forward)} is at least the signed gas limit "
              f"{fmt(carried['gasLimit'])}: the creation is forwarded {fmt(forward)}, drawn from the withheld part first, "
              "without the 98/100 cap of a CREATE", "SATIN-KEY-005", "SATIN-KEY-011")
        share = self.reservoir_share(frame, "the keyless creation")
        if not frame["reservoir"] and not share:
            d.add("gasLedgers", "the call has no reservoir left after step 14: the creation's reservoir share is 0",
                  "SATIN-KEY-011", "SATIN-POOL-011")
        else:
            d.add("gasLedgers", f"the creation's reservoir share {fmt(share)} is the share of what the call has left after "
                  f"step 14; the call keeps {fmt(frame['reservoir'])}", "SATIN-KEY-011", "SATIN-POOL-011")
        name = f"the keyless creation of {h(deploy)}"
        signer_acct = self.state.setdefault(signer, Account())
        signer_acct.nonce += 1  # the creation's start bumps its creator's nonce, which its failure keeps
        if collides:
            return self.keyless_collision(frame, signer, deploy, forward, share, n0, empty_signer, signer_state, records,
                                          signer_changed)
        child = self.new_child(frame, forward, share)
        child["name"] = name
        snap = self.frame_snapshot()
        acct = self.state.setdefault(deploy, Account())
        acct.nonce = 1
        self.created.add(deploy)
        self.kv.add(("a", deploy))
        self.data_size += WRITE_RECORD_SIZE
        self.growth += int(deploy_empty)
        if value:
            signer_acct.balance -= value
            acct.balance += value
            self.data_size += TRANSFER_LOG_SIZE
            self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(signer), pad_address(deploy)],
                              value.to_bytes(32, "big")))
        d.add("resources", f"the creation starts one call level below the call, a creation by the signer at the deploy "
              f"address with the signed initcode ({fmt(len(init))} bytes) and value {fmt(value)}: its budgets are the child "
              f"share of the call's, {', '.join(fmt(b) for b in child['budget'])}; its start bumps the signer's nonce to "
              f"{signer_acct.nonce}, a bump the call keeps whatever the creation does, and the created account is one "
              f"write record ({WRITE_RECORD_SIZE} bytes)"
              + (" and one unit of state growth" if deploy_empty else ", and no rise, the address not being empty")
              + (f"; the value moves with its transfer log ({TRANSFER_LOG_SIZE} bytes)" if value else ""),
              "SATIN-KEY-002", "SATIN-KEY-011", "SATIN-LIM-003", "SATIN-LIM-013", "SATIN-ACCT-005",
              *(("SATIN-ACCT-014",) if deploy_empty else ("SATIN-KEY-008",)),
              *(("SATIN-LOG-001", "SATIN-LOG-006") if value else ()))
        d.add("gasLedgers", "from its start the creation is an ordinary creation frame; ORIGIN and GASPRICE in its initcode "
              "are the transaction's own", "SATIN-KEY-002", "SATIN-KEY-011")
        if self.start_crossing(child):
            raise Unmodelled("a keyless creation whose start crosses a limit")
        ctx = {"address": deploy, "caller": signer, "value": value, "calldata": b"", "name": name, "keyless": True}
        status, out = self.run_child(child, init, ctx, name, create=True)
        destroyed = status == "success" and deploy in self.destroyed
        before = frame["reservoir"]
        left = self.end_child(frame, child, status, snap, name)
        returned = frame["reservoir"] - before
        frame["regular"] += left
        self.regular_charges -= left
        self.split(frame)
        # gasUsed: both pools netted together, plus the give-backs of step 14's charges the creation received.
        added = 0
        if destroyed:
            if deploy in self.pre:
                raise Unmodelled("a keyless constructor that destroys a deploy address the state held")
            added = created_state + RECORD_HISTORY
        gas_used = (forward - left) + (share - returned) + added
        if gas_used < 0:
            raise Unmodelled("a keyless creation whose gasUsed is negative")
        self.probe["keyless-gas-used"] = gas_used
        d.add("outcome", f"gasUsed = (regular given {fmt(forward)} - regular returned {fmt(left)}) + (reservoir given "
              f"{fmt(share)} - reservoir returned {fmt(returned)})"
              + (f" + the give-backs of step 14's charges the creation received, the destruction table's for the account "
                 f"it created, {fmt(created_state)} of state gas and {fmt(RECORD_HISTORY)} of history gas" if destroyed
                 else "") + f" = {fmt(gas_used)}; the call's own charges of steps 1 and 14 are no part of it",
              "SATIN-KEY-015")
        if status != "success":
            # A failed creation: the created account's leaf and its record are not added, so step 14's charges for them
            # come back into the call's reservoir after the creation's reservoir joined it (SATIN-POOL-015, SATIN-TAKE-007).
            self.give_back(frame, created_state + RECORD_HISTORY)
            self.state_gas -= created_state
            self.history_gas -= RECORD_HISTORY
            self.history_bytes -= WRITE_RECORD_SIZE
            d.add("gasLedgers", f"the creation failed: its created account and its record are not added, so step 14's "
                  f"charges for them, {fmt(created_state)} of state gas, its legacy share included, and {fmt(RECORD_HISTORY)} "
                  f"of history gas, come back into the call's reservoir, now {fmt(frame['reservoir'])}, after the "
                  "creation's reservoir joined it; the signer's nonce record and its history are kept",
                  "SATIN-KEY-016" if status == "stop" else "SATIN-KEY-011", "SATIN-POOL-015", "SATIN-HIST-012", "SATIN-TAKE-007", "SATIN-LIM-008")
        self.keyless_settle(frame, signer, n0, empty_signer, signer_state, records, signer_changed)
        # The answer.
        code = self.state.get(deploy, Account()).code
        if status == "success" and not destroyed and code:
            output = keyless_answer(gas_used, deploy, b"")
            d.add("outcome", f"the deploy address holds {len(code)} bytes of code: the call succeeds and returns "
                  f"({fmt(gas_used)}, {h(deploy)}, empty errorData)", "SATIN-KEY-001", "SATIN-KEY-014")
        elif ctx.get("empty_refused") or destroyed:
            error = keyless_error("EmptyCodeDeployed(uint64)", gas_used)
            output = keyless_answer(gas_used, bytes(20), error)
            d.add("outcome", "the deploy address holds no code, its constructor having "
                  + ("returned empty code, refused" if not destroyed else "destroyed the account it was creating")
                  + f": the call succeeds and returns ({fmt(gas_used)}, the zero address, EmptyCodeDeployed({fmt(gas_used)}))",
                  "SATIN-KEY-001", "SATIN-KEY-009", "SATIN-KEY-014")
        elif status in ("revert", "stop"):
            error = execution_reverted(gas_used, out)
            output = keyless_answer(gas_used, bytes(20), error)
            if status == "stop":
                d.add("outcome", f"the creation was stopped by a limit, with {len(out)} bytes of revert data: the call "
                      f"succeeds and returns ({fmt(gas_used)}, the zero address, ExecutionReverted({fmt(gas_used)}, the "
                      "stop's revert data)); it answers with no error the interface no longer declares, neither "
                      "InsufficientComputeGas nor ParentBudgetExceeded", "SATIN-KEY-001", "SATIN-KEY-014",
                      "SATIN-KEY-016", "SATIN-KEY-017")
            else:
                d.add("outcome", f"the creation reverted with {len(out)} bytes of revert data: the call succeeds and "
                      f"returns ({fmt(gas_used)}, the zero address, ExecutionReverted({fmt(gas_used)}, those bytes))",
                      "SATIN-KEY-001", "SATIN-KEY-014")
        elif status == "halt":
            error = keyless_error("ExecutionHalted(uint64)", gas_used)
            output = keyless_answer(gas_used, bytes(20), error)
            d.add("outcome", f"the creation halted: the call succeeds and returns ({fmt(gas_used)}, the zero address, "
                  f"ExecutionHalted({fmt(gas_used)}))", "SATIN-KEY-001", "SATIN-KEY-014")
        else:
            raise Unmodelled(f"a keyless creation ending in {status}")
        return "success", output

    def keyless_collision(self, frame, signer: bytes, deploy: bytes, forward: int, share: int, n0: int,
                          empty_signer: bool, signer_state: int, records: list, signer_changed: bool) -> tuple[str, bytes]:
        """A creation onto a deploy address that holds a nonce but no code: it collides there once the signer's nonce
        was bumped, and fails before its initcode runs, its whole forward spent (SATIN-KEY-008, SATIN-SD-016,
        SATIN-LIM-016)."""
        d = self.d
        nonce = self.state[deploy].nonce
        frame["reservoir"] += share  # the failed start's reservoir is what it received (SATIN-POOL-014)
        d.add("outcome", f"the creation collides at the deploy address, which holds nonce {nonce} and no code: it fails "
              f"on the collision after the signer's nonce was bumped, before its initcode runs, and its whole forward, "
              f"{fmt(forward)}, is spent; its reservoir share comes back; its start keeps no record, no account and no "
              "transfer log", "SATIN-KEY-008", "SATIN-SD-016", "SATIN-LIM-016", "SATIN-LOG-007")
        self.give_back(frame, RECORD_HISTORY)
        self.history_gas -= RECORD_HISTORY
        self.history_bytes -= WRITE_RECORD_SIZE
        d.add("gasLedgers", f"the collision adds no account: the address was not empty, so step 14 charged no state gas "
              f"for it, and the {fmt(RECORD_HISTORY)} of history gas step 14 charged for the created account's record "
              f"comes back into the call's reservoir, now {fmt(frame['reservoir'])}", "SATIN-KEY-008",
              "SATIN-TAKE-007", "SATIN-HIST-012")
        gas_used = forward
        self.probe["keyless-gas-used"] = gas_used
        d.add("outcome", f"gasUsed = (regular given {fmt(forward)} - regular returned 0) + (reservoir given {fmt(share)} - "
              f"reservoir returned {fmt(share)}) = {fmt(gas_used)}", "SATIN-KEY-015")
        self.keyless_settle(frame, signer, n0, empty_signer, signer_state, records, signer_changed)
        d.add("outcome", f"the creation halted on the collision: the call succeeds and returns ({fmt(gas_used)}, the zero "
              f"address, ExecutionHalted({fmt(gas_used)}))", "SATIN-KEY-001", "SATIN-KEY-008", "SATIN-KEY-014")
        return "success", keyless_answer(gas_used, bytes(20), keyless_error("ExecutionHalted(uint64)", gas_used))

    def keyless_settle(self, frame, signer: bytes, n0: int, empty_signer: bool, signer_state: int, records: list,
                       signer_changed: bool) -> None:
        """Once the creation returned: the nonce rule, then the signer's write record and its unit of state growth,
        counted on the call (SATIN-KEY-012, -013, SATIN-LIM-008)."""
        d, tx = self.d, self.tx
        acct = self.state[signer]
        if acct.nonce != n0 + 1:
            raise Unmodelled("a signer whose own code spent a nonce during the keyless creation")
        if n0 == 1:
            acct.nonce = 1
            d.add("state", "the deployment is from signer nonce 1 and the creation's bump is the last change of the "
                  "signer's nonce it made: the bump is taken back, the nonce set to 1", "SATIN-KEY-013")
        else:
            d.add("state", "the deployment is from signer nonce 0: the creation's bump is kept, the nonce 1",
                  "SATIN-KEY-013")
        if empty_signer and acct.nonce == n0:
            raise Unmodelled("a signer charged at step 10 whose nonce stands where it was")
        rise = int(empty_signer and not acct.empty())
        if signer in records:
            if self.as_loaded(signer):
                self.give_back(frame, RECORD_HISTORY)
                self.history_gas -= RECORD_HISTORY
                self.history_bytes -= WRITE_RECORD_SIZE
                d.add("gasLedgers", f"the nonce set back leaves the signer's account as the transaction loaded it: no "
                      f"record stands, and the {fmt(RECORD_HISTORY)} of history gas step 14 charged for it is given back "
                      "into the call's reservoir", "SATIN-KEY-013", "SATIN-HIST-012", "SATIN-ACCT-004")
                d.add("resources", "the signer's account is as the transaction loaded it: no record", "SATIN-KEY-013",
                      "SATIN-ACCT-004")
                return
            self.hold_to_limits(WRITE_RECORD_SIZE, 1, rise, "the keyless signer's nonce record", frame)
            self.kv.add(("a", signer))
            self.data_size += WRITE_RECORD_SIZE
            self.growth += rise
            d.add("resources", f"the signer's account differs from what the transaction loaded: its write record "
                  f"({WRITE_RECORD_SIZE} bytes, one KV update)" + (" and its unit of state growth, the creation's bump "
                                                                    "having created the account," if rise else "")
                  + " counted on the call once the creation returned and the nonce rule applied", "SATIN-KEY-012",
                  "SATIN-KEY-013", "SATIN-LIM-008", "SATIN-ACCT-004", *(("SATIN-ACCT-014",) if rise else ()))
            return
        if rise:
            raise Unmodelled("a signer created by the bump whose record step 14 did not charge")
        d.add("resources", "the signer's record is not counted again: "
              + ("the signer is the transaction's sender, never recorded again" if signer == tx.sender else
                 "the transaction changed the signer's account before the call, and its record stands from then"),
              "SATIN-KEY-012", "SATIN-KEY-013", *(("SATIN-ACCT-008",) if signer == tx.sender else ("SATIN-ACCT-004",)))


KEYLESS_ERRORS_BY_SELECTOR = {sel: name for name, sel in KEYLESS_ERRORS.items()}
