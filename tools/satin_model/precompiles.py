"""A call to a precompile, decided under gas detention from its price (`SATIN-DET-021` to `-024`): the identity
precompile, ModExp's EIP-7883 price over and under EIP-7823's bound, and the BN254 pairing over its size limit; and,
for the precompile page's own cases (D-103), KZG point evaluation, `P256VERIFY`, ModExp, and the BN254 and BLS12-381
precompiles at their size limits, where no limit is set."""

from __future__ import annotations

import hashlib

from .constants import (
    BLS12_G1_MSM, BLS12_G1_MSM_MAX_DISCOUNT, BLS12_G1_MSM_MAX_INPUT_SIZE, BLS12_G1_MSM_PAIR_SIZE, BLS12_G1_MUL_GAS,
    BLS12_G2_MSM, BLS12_G2_MSM_MAX_DISCOUNT, BLS12_G2_MSM_MAX_INPUT_SIZE, BLS12_G2_MSM_PAIR_SIZE, BLS12_G2_MUL_GAS,
    BLS12_MSM_MULTIPLIER, BLS12_MSM_TABLE_PAIRS, BLS12_PAIRING, BLS12_PAIRING_BASE, BLS12_PAIRING_MAX_INPUT_SIZE,
    BLS12_PAIRING_PAIR_SIZE, BLS12_PAIRING_PER_PAIR, BLS_MODULUS, FIELD_ELEMENTS_PER_BLOB, KZG_INPUT_SIZE,
    INFINITY_ARITHMETIC, BLS12_G1_ADD, BLS12_G2_ADD, BN254_ADD, BN254_MUL,
    KZG_POINT_EVALUATION, KZG_POINT_EVALUATION_GAS, P256_A, P256_B, P256_G, P256_N, P256_P, P256VERIFY, P256VERIFY_GAS,
    P256VERIFY_INPUT_SIZE, VERSIONED_HASH_VERSION_KZG,
    BN254_PAIR_SIZE, BN254_PAIRING, BN254_PAIRING_BASE, BN254_PAIRING_MAX_INPUT_SIZE, BN254_PAIRING_PER_PAIR, DETENTION_STOP, IDENTITY, IDENTITY_BASE, IDENTITY_WORD,
    limit_exceeded, ECRECOVER, ECRECOVER_GAS, MODEXP, MODEXP_MAX_INPUT_SIZE, MODEXP_MIN_GAS, RIPEMD160, RIPEMD160_BASE,
    RIPEMD160_WORD, SHA256, SHA256_BASE, SHA256_WORD,
    TRANSFER_LOG_ADDRESS, TRANSFER_LOG_SIZE, TRANSFER_TOPIC, WRITE_RECORD_SIZE,
)
from .records import Account, fmt, h, Halt, pad_address, Stopped, Unmodelled

# SATIN-PCMP-001, -004: the OP precompiles' input size limits, by address.
SIZE_LIMITS = {BN254_PAIRING: BN254_PAIRING_MAX_INPUT_SIZE, BLS12_G1_MSM: BLS12_G1_MSM_MAX_INPUT_SIZE,
               BLS12_G2_MSM: BLS12_G2_MSM_MAX_INPUT_SIZE, BLS12_PAIRING: BLS12_PAIRING_MAX_INPUT_SIZE}
NAMES = {KZG_POINT_EVALUATION: "KZG point evaluation", P256VERIFY: "P256VERIFY", MODEXP: "ModExp",
         BN254_PAIRING: "the BN254 pairing", BLS12_G1_MSM: "the BLS12-381 G1 MSM", BLS12_G2_MSM: "the BLS12-381 G2 MSM",
         BLS12_PAIRING: "the BLS12-381 pairing", BN254_ADD: "the BN254 addition", BN254_MUL: "the BN254 multiplication",
         BLS12_G1_ADD: "the BLS12-381 G1 addition", BLS12_G2_ADD: "the BLS12-381 G2 addition"}
# The infinity point of BLS12-381's G1 in the compressed encoding a KZG commitment and proof use: the compression and
# infinity flags, and nothing else.
G1_INFINITY_COMPRESSED = b"\xc0" + bytes(47)


def p256_add(p, q):
    """The sum of two points of P-256 in affine coordinates, None the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p == q:
        slope = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    return x3, (slope * (x1 - x3) - y1) % P256_P


def p256_mul(k: int, p):
    """k times the point p of P-256, by double-and-add."""
    out = None
    while k:
        if k & 1:
            out = p256_add(out, p)
        p = p256_add(p, p)
        k >>= 1
    return out


def p256_verify(data: bytes) -> tuple[bool, str]:
    """EIP-7951's verification at the revision SATIN-PCMP-003 pins: the input is the message hash, r, s and the public
    key's two coordinates, each a 32-byte word; whether the signature verifies, and why not."""
    if len(data) != P256VERIFY_INPUT_SIZE:
        return False, f"its input is {fmt(len(data))} bytes, not {P256VERIFY_INPUT_SIZE}"
    e, r, s, qx, qy = (int.from_bytes(data[i:i + 32], "big") for i in range(0, P256VERIFY_INPUT_SIZE, 32))
    if not (0 < r < P256_N and 0 < s < P256_N):
        return False, "its r or s is not in (0, n)"
    if qx >= P256_P or qy >= P256_P or (qx, qy) == (0, 0) or (qy * qy - qx ** 3 - P256_A * qx - P256_B) % P256_P:
        return False, "its public key is no point of the curve"
    w = pow(s, -1, P256_N)
    point = p256_add(p256_mul(e * w % P256_N, P256_G), p256_mul(r * w % P256_N, (qx, qy)))
    if point is None or point[0] % P256_N != r:
        return False, "its signature does not verify"
    return True, "its signature verifies"


def kzg_evaluation(data: bytes) -> tuple[bool, str]:
    """EIP-4844's point evaluation (SATIN-PCMP-001, -006) on an input whose commitment and proof are both G1's point at
    infinity: whether it succeeds, and why not. With both at infinity, the pairing check
    e(commitment - [y]G1, -G2) * e(proof, [tau - z]G2) = 1 is e([y]G1, G2) = 1, which holds exactly when y is zero."""
    if len(data) != KZG_INPUT_SIZE:
        return False, f"its input is {fmt(len(data))} bytes, not {KZG_INPUT_SIZE}"
    versioned, z, y = data[:32], int.from_bytes(data[32:64], "big"), int.from_bytes(data[64:96], "big")
    commitment, proof = data[96:144], data[144:192]
    if versioned != bytes([VERSIONED_HASH_VERSION_KZG]) + hashlib.sha256(commitment).digest()[1:]:
        return False, "its versioned hash is not the commitment's, 0x01 followed by the last 31 bytes of its SHA-256"
    if z >= BLS_MODULUS or y >= BLS_MODULUS:
        return False, (f"its {'z' if z >= BLS_MODULUS else 'y'} is not below the scalar field's modulus, so it is no "
                       "canonical field element and is not reduced: the input fails")
    if commitment != G1_INFINITY_COMPRESSED or proof != G1_INFINITY_COMPRESSED:
        raise Unmodelled("a KZG commitment or proof other than the point at infinity")
    if y:
        return False, (f"its commitment and proof are both the point at infinity and its y is {y}, not zero, so the "
                       "pairing check, which reduces to e([y]G1, G2) = 1, fails: the proof does not verify")
    return True, ("its versioned hash is its commitment's, and its commitment and proof are both the point at infinity "
                  "with y zero, the zero polynomial's proof at any point, so the pairing check, which reduces to "
                  "e([y]G1, G2) = 1, holds")


def bls12_price(target: bytes, pairs: int) -> int:
    """EIP-2537's price for `pairs` pairs (SATIN-PCMP-001, as Karst defines it): an MSM's
    pairs x multiplication cost x discount / 1000, at its table's largest discount from 128 pairs on, and the pairing's
    37,700 + 32,600 a pair."""
    if target == BLS12_PAIRING:
        return BLS12_PAIRING_BASE + BLS12_PAIRING_PER_PAIR * pairs
    if pairs < BLS12_MSM_TABLE_PAIRS:
        raise Unmodelled("an MSM of fewer pairs than its discount table's last entry")
    mul, discount = ((BLS12_G1_MUL_GAS, BLS12_G1_MSM_MAX_DISCOUNT) if target == BLS12_G1_MSM else
                     (BLS12_G2_MUL_GAS, BLS12_G2_MSM_MAX_DISCOUNT))
    return pairs * mul * discount // BLS12_MSM_MULTIPLIER


def pair_size(target: bytes) -> int:
    return {BN254_PAIRING: BN254_PAIR_SIZE, BLS12_G1_MSM: BLS12_G1_MSM_PAIR_SIZE, BLS12_G2_MSM: BLS12_G2_MSM_PAIR_SIZE,
            BLS12_PAIRING: BLS12_PAIRING_PAIR_SIZE}[target]


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 (Dobbertin, Bosselaers and Preneel), the digest the precompile at 0x03 returns, written out here so
    that the model shares no code with either implementation."""
    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    fs = (lambda x, y, z: x ^ y ^ z, lambda x, y, z: (x & y) | (~x & z), lambda x, y, z: (x | ~y) ^ z,
          lambda x, y, z: (x & z) | (y & ~z), lambda x, y, z: x ^ (y | ~z))
    kl, kr = (0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E), (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0)
    rl = [list(range(16)), [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
          [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12], [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
          [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]]
    rr = [[5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12], [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
          [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13], [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
          [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]]
    sl = [[11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8], [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
          [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5], [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
          [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]]
    sr = [[8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6], [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
          [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5], [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
          [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]]
    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    hs = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for i in range(0, len(msg), 64):
        x = [int.from_bytes(msg[i + 4 * j:i + 4 * j + 4], "little") for j in range(16)]
        al, bl, cl, dl, el = hs
        ar, br, cr, dr, er = hs
        for r in range(5):
            for j in range(16):
                t = rol((al + fs[r](bl, cl, dl) + x[rl[r][j]] + kl[r]) & 0xFFFFFFFF, sl[r][j]) + el
                al, bl, cl, dl, el = el, t & 0xFFFFFFFF, bl, rol(cl, 10), dl
                t = rol((ar + fs[4 - r](br, cr, dr) + x[rr[r][j]] + kr[r]) & 0xFFFFFFFF, sr[r][j]) + er
                ar, br, cr, dr, er = er, t & 0xFFFFFFFF, br, rol(cr, 10), dr
        t = (hs[1] + cl + dr) & 0xFFFFFFFF
        hs = [t, (hs[2] + dl + er) & 0xFFFFFFFF, (hs[3] + el + ar) & 0xFFFFFFFF, (hs[4] + al + br) & 0xFFFFFFFF,
              (hs[0] + bl + cr) & 0xFFFFFFFF]
    return b"".join(v.to_bytes(4, "little") for v in hs)


def precompile_output(target: bytes, data: bytes) -> bytes:
    """What a precompile the model runs returns: the identity its input, RIPEMD-160 its digest left-padded to a word;
    for the precompile page's cases, KZG point evaluation's two words, P256VERIFY's word 1 or nothing, and an MSM's or a
    pairing's answer for points at infinity."""
    if target == IDENTITY:
        return data
    if target == RIPEMD160:
        return ripemd160(data).rjust(32, b"\x00")
    if target == SHA256:
        return hashlib.sha256(data).digest()
    if target == ECRECOVER:
        v = data[32:64].ljust(32, b"\x00")
        if v[:31] != bytes(31) or v[31] not in (27, 28):
            return b""  # a v other than 27 or 28 recovers nothing: an empty output, the call succeeding
        raise Unmodelled("an ecrecover input whose v is 27 or 28")
    if target == KZG_POINT_EVALUATION:
        if not kzg_evaluation(data)[0]:
            raise Unmodelled("the output of a KZG evaluation that fails")
        return FIELD_ELEMENTS_PER_BLOB.to_bytes(32, "big") + BLS_MODULUS.to_bytes(32, "big")
    if target == P256VERIFY:
        return (1).to_bytes(32, "big") if p256_verify(data)[0] else b""
    if target in INFINITY_ARITHMETIC:  # a sum or a multiple of points at infinity is the point at infinity
        return bytes(INFINITY_ARITHMETIC[target][2])
    if target in (BLS12_G1_MSM, BLS12_G2_MSM):  # an MSM of points at infinity is the point at infinity, all zero bytes
        return bytes(128 if target == BLS12_G1_MSM else 256)
    if target in (BN254_PAIRING, BLS12_PAIRING):  # a pairing of points at infinity is the identity: the word 1
        return (1).to_bytes(32, "big")
    if target == MODEXP:
        base_len, exp_len, mod_len = modexp_lengths(data)
        if max(base_len, exp_len, mod_len) > MODEXP_MAX_INPUT_SIZE:
            raise Unmodelled("the output of a ModExp input over EIP-7823's bound")
        body = data[96:].ljust(base_len + exp_len + mod_len, b"\x00")
        base, exp, mod = (int.from_bytes(body[a:b], "big") for a, b in
                          ((0, base_len), (base_len, base_len + exp_len), (base_len + exp_len, base_len + exp_len + mod_len)))
        return (pow(base, exp, mod) if mod else 0).to_bytes(mod_len, "big")
    raise Unmodelled("the output of a precompile the model does not run")


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


# How a precompile's input fails (SATIN-PCMP-005, -007): over a size limit, before any gas check; or on a check made
# after the gas charge, ModExp's EIP-7823 bound.
SIZE_LIMIT, AFTER_CHARGE = "size-limit", "after-charge"


class PrecompilesMixin:
    """A call to a precompile: warm, its own charges made in the opcode, then decided from its price."""

    def precompile_price(self, target: bytes, data: bytes) -> tuple[int, str, str | None]:
        """The precompile's price for this input, read before it runs (SATIN-DET-023), how it is priced, and how the
        input fails, if it does: `SIZE_LIMIT`, over a size limit, before any gas check and charging no price
        (SATIN-PCMP-005), or `AFTER_CHARGE`, on a check the precompile makes after its gas charge (SATIN-PCMP-007)."""
        if target == IDENTITY:
            words = (len(data) + 31) // 32
            price = IDENTITY_BASE + IDENTITY_WORD * words
            return price, f"the identity precompile's {IDENTITY_BASE} + {IDENTITY_WORD} x {words} words = {fmt(price)}", None
        if target == SHA256:
            words = (len(data) + 31) // 32
            price = SHA256_BASE + SHA256_WORD * words
            return price, (f"SHA-256's {SHA256_BASE} + {SHA256_WORD} x {words} words = {fmt(price)}, the price Karst "
                           "gives it, which it charges before it hashes"), None
        if target == ECRECOVER:
            return ECRECOVER_GAS, (f"ecrecover's fixed {fmt(ECRECOVER_GAS)}, the price Karst gives it, which it charges "
                                   "before it reads its input"), None
        if target == RIPEMD160:
            words = (len(data) + 31) // 32
            price = RIPEMD160_BASE + RIPEMD160_WORD * words
            return price, (f"RIPEMD-160's {RIPEMD160_BASE} + {RIPEMD160_WORD} x {words} words = {fmt(price)}, the price "
                           "Karst gives it, which it charges before it hashes"), None
        if target == MODEXP:
            base_len, exp_len, mod_len = modexp_lengths(data)
            price, complexity, iterations = modexp_price(data)
            over = max(base_len, exp_len, mod_len) > MODEXP_MAX_INPUT_SIZE
            over_length = ("base" if base_len > MODEXP_MAX_INPUT_SIZE else "exponent" if exp_len > MODEXP_MAX_INPUT_SIZE
                           else "modulus")
            if price >= 2**64:  # SATIN-PCMP-007: lengths too large to price
                return price, (f"ModExp's EIP-7883 price for lengths too large to price, whose largest is "
                               f"{max(base_len, exp_len, mod_len).bit_length()} bits long: past any gas a call can hold"), \
                    (AFTER_CHARGE if over else None)
            return price, (f"ModExp's EIP-7883 price for a base of {fmt(base_len)} bytes, an exponent of {fmt(exp_len)} and "
                           f"a modulus of {fmt(mod_len)}: max({MODEXP_MIN_GAS}, multiplication complexity {fmt(complexity)} "
                           f"x iteration count {fmt(iterations)}) = {fmt(price)}"
                           + (f", whatever the lengths: the {over_length} is over EIP-7823's bound of "
                              f"{fmt(MODEXP_MAX_INPUT_SIZE)} bytes, which ModExp checks after it charges that price"
                              if over else "")), \
                (AFTER_CHARGE if over else None)
        if target == BN254_PAIRING:
            if len(data) <= BN254_PAIRING_MAX_INPUT_SIZE:
                if any(data) or len(data) % BN254_PAIR_SIZE or not (self.outcomes or self.precompile_page):
                    raise Unmodelled("a BN254 pairing within its size limit other than of points at infinity")
                pairs = len(data) // BN254_PAIR_SIZE
                price = BN254_PAIRING_BASE + BN254_PAIRING_PER_PAIR * pairs
                return price, (f"the BN254 pairing's EIP-1108 price for {pairs} pairs, {fmt(BN254_PAIRING_BASE)} + "
                               f"{fmt(BN254_PAIRING_PER_PAIR)} x {pairs} = {fmt(price)}"), None
            return 0, (f"zero: the BN254 pairing's {fmt(len(data))} input bytes are over its size limit of "
                       f"{fmt(BN254_PAIRING_MAX_INPUT_SIZE)}, refused before any gas check"), SIZE_LIMIT
        if self.precompile_page:
            return self.page_price(target, data)
        raise Unmodelled(f"the precompile at {h(target)}")

    def page_price(self, target: bytes, data: bytes) -> tuple[int, str, str | None]:
        """The price of a precompile only the precompile page's cases call (D-103), read as precompile_price reads
        one: KZG point evaluation's fixed price, P256VERIFY's, and a BLS12-381 MSM's or pairing's, or none over its
        size limit."""
        if target == KZG_POINT_EVALUATION:
            ok, why = kzg_evaluation(data)
            return KZG_POINT_EVALUATION_GAS, (f"KZG point evaluation's fixed KZG_POINT_EVALUATION_GAS, "
                                              f"{fmt(KZG_POINT_EVALUATION_GAS)}, whatever its input; {why}"), \
                (None if ok else AFTER_CHARGE)
        if target == P256VERIFY:
            _, why = p256_verify(data)
            return P256VERIFY_GAS, (f"P256VERIFY's P256VERIFY_GAS, {fmt(P256VERIFY_GAS)}, whatever its input; {why}"), None
        if target in INFINITY_ARITHMETIC:
            size, price, answer = INFINITY_ARITHMETIC[target]
            if len(data) != size or any(data):
                raise Unmodelled("an addition or a multiplication other than of points at infinity")
            return price, (f"{NAMES[target]}'s fixed price as Karst defines it, {fmt(price)}, for its {size}-byte input "
                           f"of points at infinity, whose answer is the point at infinity, {answer} zero bytes"), None
        if target in (BLS12_G1_MSM, BLS12_G2_MSM, BLS12_PAIRING):
            limit, size = SIZE_LIMITS[target], pair_size(target)
            if len(data) > limit:
                return 0, (f"zero: {NAMES[target]}'s {fmt(len(data))} input bytes are over its size limit of "
                           f"{fmt(limit)}, refused before any gas check"), SIZE_LIMIT
            if not data or len(data) % size or any(data):
                raise Unmodelled("a BLS12-381 input other than pairs of points at infinity")
            pairs = len(data) // size
            price = bls12_price(target, pairs)
            how = (f"EIP-2537's pairing price for {pairs} pairs, {fmt(BLS12_PAIRING_BASE)} + "
                   f"{fmt(BLS12_PAIRING_PER_PAIR)} x {pairs} = {fmt(price)}" if target == BLS12_PAIRING else
                   f"EIP-2537's MSM price for {pairs} pairs, {pairs} x "
                   f"{fmt(BLS12_G1_MUL_GAS if target == BLS12_G1_MSM else BLS12_G2_MUL_GAS)} x the largest discount "
                   f"{BLS12_G1_MSM_MAX_DISCOUNT if target == BLS12_G1_MSM else BLS12_G2_MSM_MAX_DISCOUNT}, its table's from "
                   f"{BLS12_MSM_TABLE_PAIRS} pairs on, / {fmt(BLS12_MSM_MULTIPLIER)} = {fmt(price)}")
            return price, how, None
        raise Unmodelled(f"the precompile at {h(target)}")

    def own_precompile(self, frame, target: bytes, data: bytes) -> tuple[str, bytes]:
        """The transaction's own call of a precompile, its first frame's gas the forward: decided from the price
        once a limit is set, as any call to a precompile (SATIN-DET-021, -023), and the stop the transaction's."""
        d = self.d
        regular = frame["regular"]
        price, how, fails = self.precompile_price(target, data)
        if self.limit is not None:
            allowance = max(0, self.limit - self.compute)
            self.probe.setdefault("precompile-room", allowance)
            if regular > allowance:
                if allowance < price <= regular:
                    d.add("outcome", f"the transaction's own call of the precompile at {h(target)} is given its first "
                          f"frame's {fmt(regular)} of regular gas, more than the allowance {fmt(allowance)} the limit "
                          f"{fmt(self.limit)} leaves the transaction's compute {fmt(self.compute)}, so it is decided from "
                          f"its price, read before it runs: {how}, past the allowance and within the forward: it does not "
                          "run and is the crossing, the transaction's own stop, on its untouched gas", "SATIN-DET-021",
                          "SATIN-DET-023", "SATIN-STOP-014" if self.current else "SATIN-DET-018")
                    raise Stopped(self.limit, f"the price of the precompile at {h(target)}, {fmt(price)}")
                d.add("gasLedgers", f"the transaction's own call of the precompile at {h(target)} is given {fmt(regular)}, "
                      f"more than the allowance {fmt(allowance)}, so it is decided from its price: {how}, "
                      + ("within the allowance: it runs on its whole forward" if price <= allowance else
                         "past its whole forward: it runs on its forward and fails, as without the read"),
                      "SATIN-DET-021", "SATIN-DET-023")
        if price > regular:
            d.add("outcome", f"the precompile at {h(target)} is priced {fmt(price)}, past the {fmt(regular)} of regular gas "
                  "the transaction's own frame holds: it fails out of gas and consumes it", "SATIN-OUT-007",
                  "SATIN-DET-021")
            if self.limit is not None:
                d.add("gasLedgers", f"what the failed precompile burns, its {fmt(regular)}, is not compute: the "
                      f"transaction's compute stays {fmt(self.compute)}", "SATIN-DET-011", "SATIN-DET-020")
            raise Halt(f"the precompile's price {fmt(price)} past its {fmt(regular)} of regular gas")
        if fails:
            raise Unmodelled("the transaction's own call of a precompile that fails its input")
        out = precompile_output(target, data)
        self.charge_regular(frame, price, f"the price of the precompile at {h(target)}")
        d.add("outcome", f"the transaction's own call of the precompile at {h(target)} runs on its {fmt(regular)} of "
              f"regular gas, charges its price {fmt(price)}, compute now {fmt(self.compute)}, and returns "
              f"{fmt(len(out))} bytes", "SATIN-DET-021", "SATIN-DET-009", "SATIN-OUT-001")
        return "success", out

    def precompile_value_start(self, frame, caller_acct, caller: bytes, target: bytes, value: int, data: bytes,
                               child_gas: int, records: list, history: int, price: int, fails: str | None):
        """A value call to the identity precompile where no limit is set (D-85): the start moves the value and makes its
        records and transfer log; a precompile that then fails takes them back, counts nothing and is no stop
        (SATIN-LIM-014); one that would succeed has its start held to the limits first (SATIN-LIM-013)."""
        d = self.d
        if target != IDENTITY or fails or self.state.get(target) is None or self.state[target].empty():
            raise Unmodelled("a value call to a precompile other than an existing identity precompile")
        child = self.new_child(frame, child_gas, 0)
        snap = self.frame_snapshot()
        caller_acct.balance -= value
        self.state[target].balance += value
        for a in records:
            self.kv.add(("a", a))
        self.data_size += WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE
        self.logs.append((TRANSFER_LOG_ADDRESS, [TRANSFER_TOPIC, pad_address(caller), pad_address(target)],
                          value.to_bytes(32, "big")))
        moved = WRITE_RECORD_SIZE * len(records) + TRANSFER_LOG_SIZE
        d.add("resources", f"the start moves the value {value} to the precompile and makes the {len(records)} records the "
              f"opcode charged and the transfer log, {fmt(moved)} bytes of data size", "SATIN-LIM-013", "SATIN-ACCT-005",
              "SATIN-LOG-006")

        def take_back(why: str) -> None:
            self.frame_restore(snap)
            self.give_back(frame, history)
            self.history_gas -= history
            self.history_bytes -= WRITE_RECORD_SIZE * len(records)
            d.add("gasLedgers", f"{why}: the value, its records and its transfer log are taken back, and the "
                  f"{fmt(history)} of history the opcode charged for the records is given back into the caller's reservoir",
                  "SATIN-HIST-012", "SATIN-HIST-014", "SATIN-POOL-014")

        if price > child_gas:
            d.add("outcome", f"the identity precompile is priced {fmt(price)}, past the {fmt(child_gas)} its start was "
                  "given: it fails after its value moved, so its start kept nothing, counts nothing and is not stopped by "
                  f"a limit, though the {fmt(moved)} bytes it moved would not have fit; its result is the failure, which "
                  "consumes the gas forwarded to it", "SATIN-LIM-014", "SATIN-OUT-011", "SATIN-OUT-007")
            if self.stops:
                d.add("outcome", f"a precompile answered with a failure kept nothing: its answer is not replaced by a stop, "
                      f"and it consumes the {fmt(child_gas)} forwarded to it, the stipend included, as without a limit",
                      "SATIN-STOP-014", "SATIN-STOP-020")
            take_back("the failed precompile's start")
            return False, b"", 0
        crossing = self.start_crossing(child)
        if crossing:
            kind, crossed, which, rises = crossing
            d.add("outcome", f"the identity precompile's forward {fmt(child_gas)} pays its price {fmt(price)}, so its start "
                  f"is decided and held to what it kept, {fmt(rises[0])} bytes of data size: it crosses {which}, so the "
                  f"start is stopped with MegaLimitExceeded({kind}, {fmt(crossed)}) before the precompile runs, a stop its "
                  "caller catches, and its gas returns", "SATIN-LIM-013", "SATIN-STOP-013", "SATIN-OUT-002",
                  "SATIN-OUT-011", *self.kind_rules())
            if self.stops:
                d.add("outcome", f"the precompile would answer with a success without running a frame: its start crosses, "
                      f"so its answer is replaced by the stop on the child's whole regular gas, {fmt(child_gas)}, untouched, "
                      f"the forward and the stipend, its price {fmt(price)} not taken from it", "SATIN-STOP-014",
                      "SATIN-STOP-013", "SATIN-POOL-012")
            take_back("the stopped start")
            self.caught(frame)
            return False, limit_exceeded(kind, crossed), child_gas
        raise Unmodelled("a value call to the identity precompile whose start fits")

    def precompile_call(self, frame, caller: bytes, target: bytes, value: int, data: bytes, child_gas: int,
                        records: list, history: int, share: int, inherited: tuple | None = None):
        """A call to a precompile once the opcode's charges, the forward and the history of the start's records are
        made: the funds check, then, once a limit is set, the decision from the price (SATIN-DET-021). A DELEGATECALL
        passes the value its frame `inherited`, which it does not transfer. Returns (success, return data, the regular
        gas the call returns)."""
        d = self.d
        frame["reservoir"] += share  # no frame is built: the share returns untouched (SATIN-POOL-012)
        if inherited is not None:
            carried, whose = inherited
            balance = self.state.get(whose, Account()).balance
            d.add("outcome", f"a DELEGATECALL of the precompile at {h(target)} runs it with the value its frame inherited, "
                  f"{carried}, and the frame's own caller {h(whose)}, whose balance is now {balance}: a DELEGATECALL "
                  "transfers no "
                  "value, so no value moves and no caller's account is checked; only a call that moves a value its caller "
                  "cannot fund is refused on its caller's account", "SATIN-DET-024", "SATIN-DET-021")
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
        if self.precompile_page and self.limit is None:
            if value or inherited is not None:
                raise Unmodelled("a precompile page's call that carries a value or is a DELEGATECALL")
            return self.page_call(target, data, child_gas, price, how, fails)
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
                              "value transfer would have made", "SATIN-DET-022", "SATIN-LIM-010",
                              "SATIN-STOP-014" if self.current else "SATIN-STOP-016")
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
        if value and not (self.limit is None and (self.outcomes or self.stops)):
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
        if self.limit is None and (self.outcomes or self.stops):  # a precompile call where no limit is set (D-85)
            if value:
                return self.precompile_value_start(frame, caller_acct, caller, target, value, data, child_gas, records,
                                                   history, price, fails)
            if fails == AFTER_CHARGE:
                raise Unmodelled("a precompile that fails a check after its gas charge where no limit is set")
            if fails:
                d.add("outcome", f"the precompile at {h(target)} is given {fmt(len(data))} input bytes, over its size limit: "
                      f"the call fails before any gas check and consumes all the gas forwarded to it, {fmt(child_gas)}, a "
                      "halt of the call, not of its caller, which resumes on what it kept", "SATIN-OUT-004",
                      "SATIN-OUT-011", "SATIN-PCMP-005")
                return False, b"", 0
            if price > child_gas:
                d.add("outcome", f"the precompile at {h(target)} is priced {fmt(price)}, past the {fmt(child_gas)} it is "
                      "forwarded: it fails out of gas and consumes all the gas forwarded to it, and its caller resumes on "
                      "what it kept", "SATIN-OUT-011", "SATIN-OUT-007")
                return False, b"", 0
            if target == BN254_PAIRING:
                d.add("outcome", f"the BN254 pairing is given {fmt(len(data))} input bytes, within its size limit of "
                      f"{fmt(BN254_PAIRING_MAX_INPUT_SIZE)}: {how}, which its forward {fmt(child_gas)} pays; every pair is "
                      "the point at infinity on both curves, so the pairing check holds and it returns the word 1, and "
                      f"returns the {fmt(child_gas - price)} it did not charge", "SATIN-OUT-004", "SATIN-PCMP-001",
                      "SATIN-POOL-012")
                self.compute += price
                return True, (1).to_bytes(32, "big"), child_gas - price
            if target != IDENTITY:
                raise Unmodelled("the output of a precompile other than the identity")
            d.add("outcome", f"the precompile at {h(target)} is priced {fmt(price)} and forwarded {fmt(child_gas)}, which "
                  f"pays it: it succeeds, returns its {fmt(len(data))} input bytes and returns the "
                  f"{fmt(child_gas - price)} it did not charge", "SATIN-OUT-011", "SATIN-POOL-012")
            self.compute += price
            return True, data, child_gas - price
        if price > child_gas:
            d.add("outcome", f"the precompile at {h(target)} is priced {fmt(price)}, past the {fmt(child_gas)} it is "
                  "forwarded: it fails out of gas and consumes its forward", "SATIN-OUT-007", "SATIN-DET-021")
            d.add("gasLedgers", f"what the failed precompile burns, its forward of {fmt(child_gas)}, is not compute: the "
                  f"transaction's compute stays {fmt(self.compute)}", "SATIN-DET-011", "SATIN-DET-020")
            return False, b"", 0
        if fails == SIZE_LIMIT:
            d.add("outcome", f"the precompile at {h(target)} is given {fmt(len(data))} input bytes, over its size limit: "
                  f"the call fails before any gas check, charging no price, and consumes its whole forward of "
                  f"{fmt(child_gas)}, as without the read", "SATIN-PCMP-005", "SATIN-DET-021",
                  *(("SATIN-PCMP-001", "SATIN-PCMP-004") if self.precompile_page else ()))
        elif fails:
            d.add("outcome", f"the precompile at {h(target)} runs on its forward of {fmt(child_gas)}, charges its price "
                  f"{fmt(price)}, then fails its input's check and consumes the whole forward, as without the read",
                  "SATIN-PCMP-007", "SATIN-DET-021")
        if fails:
            # A halting precompile counts none of what it burns as compute: its charged price, when it charged one, is
            # part of the forward it burns and not paid work that still counts; only the crossing returns its forward
            # (SATIN-DET-011 from c130558 on, D-78; its size-limit halt and SATIN-DET-019's exception from bcf260d on,
            # D-96).
            charged = ("charging no price, as it fails before any gas check" if fails == SIZE_LIMIT else
                       f"its charged price {fmt(price)} included, which is no paid work that still counts")
            d.add("gasLedgers", f"a precompile that halts burns its whole forward, {fmt(child_gas)}, {charged}, and none "
                  f"of it is compute: the transaction's compute stays {fmt(self.compute)}; only a precompile that is the "
                  "crossing returns its forward", "SATIN-DET-009", "SATIN-DET-011", "SATIN-DET-019", "SATIN-DET-021")
            return False, b"", 0
        out = precompile_output(target, data)
        self.compute += price
        d.add("outcome", f"the precompile at {h(target)} runs on its forward of {fmt(child_gas)}, charges its price "
              f"{fmt(price)} and returns " + (f"its {fmt(len(data))} input bytes" if target == IDENTITY else
                                              f"{fmt(len(out))} bytes, its output for {fmt(len(data))} input bytes"),
              "SATIN-DET-021", "SATIN-OUT-001")
        d.add("gasLedgers", f"the precompile's price is compute, now {fmt(self.compute)}; it returns "
              f"{fmt(child_gas - price)} to its caller", "SATIN-DET-009", "SATIN-POOL-012")
        return True, out, child_gas - price

    def page_call(self, target: bytes, data: bytes, child_gas: int, price: int, how: str, fails: str | None):
        """A call to a precompile in a case of the precompile page's own rules (D-103), where no limit is set: an input
        over a size limit fails before any gas check (SATIN-PCMP-005); a price the forward cannot pay fails out of gas,
        KZG point evaluation's before any verification (SATIN-PCMP-006) and ModExp's in the order of SATIN-PCMP-007; a
        check made after the charge fails; and otherwise the precompile charges its price and answers. A failure
        consumes all the gas forwarded to it. Returns (success, return data, the regular gas the call returns)."""
        d = self.d
        name = NAMES.get(target, f"the precompile at {h(target)}")
        own = {KZG_POINT_EVALUATION: ("SATIN-PCMP-001", "SATIN-PCMP-006"), P256VERIFY: ("SATIN-PCMP-001", "SATIN-PCMP-003"),
               MODEXP: ("SATIN-PCMP-001", "SATIN-PCMP-002")}.get(
            target, ("SATIN-PCMP-001", "SATIN-PCMP-004") if target in SIZE_LIMITS else ("SATIN-PCMP-001",))
        if fails == SIZE_LIMIT:
            d.add("outcome", f"{name} is given {fmt(len(data))} input bytes, over its size limit of "
                  f"{fmt(SIZE_LIMITS[target])}: the call fails before any gas check, charging no price, and consumes all "
                  f"the gas forwarded to it, {fmt(child_gas)}, a halt of the call; its caller resumes on what it kept",
                  "SATIN-PCMP-001", "SATIN-PCMP-004", "SATIN-PCMP-005", "SATIN-OUT-004")
            return False, b"", 0
        if target in SIZE_LIMITS:
            d.add("outcome", f"{name} is given {fmt(len(data))} input bytes, within its size limit of "
                  f"{fmt(SIZE_LIMITS[target])}: the limit lets the call go on to its price", "SATIN-PCMP-001",
                  "SATIN-PCMP-004")
        if price > child_gas:
            if target == KZG_POINT_EVALUATION:
                why = (f"less than KZG_POINT_EVALUATION_GAS: it fails out of gas before any verification runs",
                       ("SATIN-PCMP-006",))
            elif target == MODEXP and child_gas < MODEXP_MIN_GAS:
                why = (f"less than its minimum MODEXP_MIN_GAS, {fmt(MODEXP_MIN_GAS)}: it fails out of gas before its "
                       "lengths are read", ("SATIN-PCMP-002", "SATIN-PCMP-007"))
            elif target == MODEXP:
                over = max(modexp_lengths(data)) > MODEXP_MAX_INPUT_SIZE
                why = (f"enough for its minimum MODEXP_MIN_GAS, {fmt(MODEXP_MIN_GAS)}, and not for the rest of its "
                       "formula price: it fails out of gas" + (" before EIP-7823's bound is checked" if over else ""),
                       ("SATIN-PCMP-002", "SATIN-PCMP-007"))
            else:
                why = "less than its price: it fails out of gas", ()
            priced = f"{fmt(price)}" if price < 2**64 else "past any gas a call can hold, its lengths too large to price"
            d.add("outcome", f"{name} is priced {priced} ({how}) and forwarded {fmt(child_gas)}, {why[0]}, and consumes "
                  f"all the gas forwarded to it; its caller resumes on what it kept", *own, *why[1], "SATIN-OUT-011")
            return False, b"", 0
        if fails:
            if target == MODEXP:
                d.add("outcome", f"ModExp's forward {fmt(child_gas)} pays its minimum and then the rest of its formula "
                      f"price, {fmt(price)} in all ({how}); only then is EIP-7823's bound checked, which the input is over: "
                      f"the call fails after its whole formula price is charged and consumes all the gas forwarded to it",
                      "SATIN-PCMP-001", "SATIN-PCMP-002", "SATIN-PCMP-007", "SATIN-OUT-011")
            else:
                d.add("outcome", f"{name}'s forward {fmt(child_gas)} pays its price, {how}: given at least its price, the "
                      f"call fails otherwise and consumes all the gas forwarded to it, {fmt(child_gas)}", *own,
                      "SATIN-OUT-011")
            return False, b"", 0
        out = precompile_output(target, data)
        self.compute += price
        answer = ("the word 1" if out == (1).to_bytes(32, "big") else
                  f"{fmt(len(out))} byte{'s' if len(out) > 1 else ''}" if out else "no bytes, a success with empty output")
        d.add("outcome", f"{name} is priced {fmt(price)} ({how}) and forwarded {fmt(child_gas)}, which pays it: it is "
              f"charged exactly its price, answers {answer}, and returns the {fmt(child_gas - price)} it did not charge",
              *own, *(("SATIN-PCMP-007",) if target == MODEXP else ()), "SATIN-POOL-012")
        return True, out, child_gas - price
