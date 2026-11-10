#!/usr/bin/env python3
"""SALT's key-to-bucket mapping `salt-v1`, in standard-library Python.

`SATIN-STATE-010` makes the bucket an account or a storage slot lands in an input of the
specification: it is SALT's own definition. This module restates that definition so a fixture's
bucket ids can be computed without either implementation, and the spec descriptors bind it by
value (`salt` member, docs/spec-identity.md):

- the key of an account is its 20 address bytes; the key of a storage slot is the 20 address
  bytes followed by the 32-byte big-endian slot;
- the hash is AHash v0.8.12's deterministic fallback hasher (folded multiply, little-endian
  reads) built with the fixed seeds `SEEDS`;
- the bucket is `hash mod (BUCKETS - META_BUCKETS) + META_BUCKETS`: the first `META_BUCKETS` of
  the 2^24 buckets hold metadata and no key lands in them.

The reference this port follows is the production hasher of the revm-based implementation
(mega-evm `crates/mega-evm/src/external/hasher/`), whose stability tests are `VECTORS`.

Usage:
    tools/salt_mapping.py account <address>
    tools/salt_mapping.py slot <address> <slot>
    tools/salt_mapping.py --check        # the vectors
"""

from __future__ import annotations

import sys

MASK64 = (1 << 64) - 1
PI2 = (0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917)
MULTIPLE = 6364136223846793005
ROT = 23

SEEDS = (0x921321F4, 0x2CCB667E, 0x60D68842, 0x077ADA9D)
BUCKETS = 1 << 24
META_BUCKETS = BUCKETS // 256
MIN_BUCKET_SIZE = 256

# (input, 64-bit hash): the stability tests of the reference hasher.
VECTORS = (
    (b"hello", 1027176506268606463),
    (b"world", 2337896903564117184),
    (b"hash test", 2116618212096523432),
)


def _folded_multiply(s: int, by: int) -> int:
    product = (s & MASK64) * (by & MASK64)
    return (product & MASK64) ^ (product >> 64)


def _rotl(x: int, r: int) -> int:
    r %= 64
    return ((x << r) | (x >> (64 - r))) & MASK64 if r else x


def _le(data: bytes) -> int:
    return int.from_bytes(data, "little")


def ahash(data: bytes, seeds: tuple[int, int, int, int] = SEEDS) -> int:
    """AHash v0.8.12's fallback `write(data)` then `finish()`, with `RandomState::with_seeds`."""
    k0, k1, k2, k3 = (seed ^ pi for seed, pi in zip(seeds, PI2))
    buffer, pad, extra = k1, k0, (k2, k3)

    def large_update(value: int) -> None:
        nonlocal buffer
        lo, hi = value & MASK64, value >> 64
        combined = _folded_multiply(lo ^ extra[0], hi ^ extra[1])
        buffer = _rotl(((buffer + pad) & MASK64) ^ combined, ROT)

    buffer = ((buffer + len(data)) * MULTIPLE) & MASK64
    if len(data) > 8:
        if len(data) > 16:
            large_update(_le(data[-16:]))
            rest = data
            while len(rest) > 16:
                large_update(_le(rest[:16]))
                rest = rest[16:]
        else:
            large_update(_le(data[:8]) | (_le(data[-8:]) << 64))
    else:
        if len(data) >= 4:
            small = (_le(data[:4]), _le(data[-4:]))
        elif len(data) >= 2:
            small = (_le(data[:2]), data[-1])
        elif data:
            small = (data[0], data[0])
        else:
            small = (0, 0)
        large_update(small[0] | (small[1] << 64))
    return _rotl(_folded_multiply(buffer, pad), buffer & 63)


def bucket_of_key(key: bytes) -> int:
    return ahash(key) % (BUCKETS - META_BUCKETS) + META_BUCKETS


def _address(text: str) -> bytes:
    raw = bytes.fromhex(text[2:] if text.startswith("0x") else text)
    if len(raw) != 20:
        raise ValueError(f"not a 20-byte address: {text}")
    return raw


def account_bucket(address: str) -> int:
    """The bucket of an account (its leaf)."""
    return bucket_of_key(_address(address))


def slot_bucket(address: str, slot: int) -> int:
    """The bucket of a storage slot."""
    return bucket_of_key(_address(address) + slot.to_bytes(32, "big"))


def check() -> list[str]:
    return [f"ahash({data!r}) = {ahash(data)}, expected {want}" for data, want in VECTORS if ahash(data) != want]


def main(argv: list[str]) -> int:
    if argv[1:] == ["--check"]:
        errors = check()
        for e in errors:
            print(f"salt_mapping: {e}", file=sys.stderr)
        print("salt_mapping: ok" if not errors else "salt_mapping: FAILED")
        return 1 if errors else 0
    if len(argv) == 3 and argv[1] == "account":
        print(hex(account_bucket(argv[2])))
        return 0
    if len(argv) == 4 and argv[1] == "slot":
        print(hex(slot_bucket(argv[2], int(argv[3], 0))))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
