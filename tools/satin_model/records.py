"""What a run reads and writes: the model's exceptions, the derivation record, the inputs (accounts, the
transaction, the block environment), the result, and the value formats of the observations."""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import ex, MEMORY_WORD, MIN_BUCKET_SIZE


class Unmodelled(Exception):
    """The case uses something the model does not restate."""


class Halt(Exception):
    """An exceptional halt of the transaction's own frame."""


class OutOfGasBeforeFrame(Exception):
    """A charge before the first frame the transaction cannot pay (SATIN-SCHED-009)."""


class LimitStop(Exception):
    """A write that crosses a resource limit (SATIN-STOP-001, SATIN-LIM-010): the frame that made it is
    stopped with MegaLimitExceeded(kind, limit)."""

    def __init__(self, kind: int, limit: int, why: str):
        super().__init__(why)
        self.kind, self.limit = kind, limit


class Stopped(Exception):
    """A frame stopped by gas detention's crossing (SATIN-DET-018): a regular charge its spendable part
    cannot pay and its whole regular gas can, not made."""

    def __init__(self, limit: int, why: str):
        super().__init__(why)
        self.limit = limit


@dataclass
class Step:
    group: str  # the observation group the step derives: outcome, state, receipt, gasLedgers, resources
    text: str
    rules: tuple[str, ...]


@dataclass
class Derivation:
    steps: list[Step] = field(default_factory=list)

    def add(self, group: str, text: str, *rules: str) -> None:
        self.steps.append(Step(group, text, tuple(rules)))

    def rules(self, group: str) -> list[str]:
        return sorted({r for s in self.steps if s.group == group for r in s.rules})

    def texts(self, group: str) -> list[str]:
        return [s.text for s in self.steps if s.group == group]


@dataclass
class Account:
    nonce: int = 0
    balance: int = 0
    code: bytes = b""
    storage: dict[int, int] = field(default_factory=dict)

    def empty(self) -> bool:  # EIP-161, SATIN-STATE-011
        return self.nonce == 0 and self.balance == 0 and not self.code


@dataclass
class Tx:
    """A transaction as the model sees it, decoded from the case's bytes."""

    kind: str  # signed, deposit
    ty: int
    sender: bytes
    to: bytes | None
    nonce: int
    gas_limit: int
    value: int
    data: bytes
    chain_id: int | None
    gas_price: int = 0  # legacy and type 1; the effective price of type 2
    max_fee: int = 0
    max_priority: int = 0
    access_list: list[tuple[bytes, list[int]]] = field(default_factory=list)
    mint: int = 0
    # EIP-7702 entries, each (chain id, delegation target, nonce, the authority its signature recovers).
    authorizations: list[tuple[int, bytes, int, bytes]] = field(default_factory=list)


@dataclass
class Env:
    chain_id: int
    coinbase: bytes
    base_fee: int
    block_gas_limit: int
    buckets: dict[int, int]  # bucket id -> capacity (complete: unlisted buckets are minimal)
    timestamp: int = 0


def bucket_multiplier(env: Env, bucket: int) -> int:
    capacity = env.buckets.get(bucket, MIN_BUCKET_SIZE)
    return capacity // MIN_BUCKET_SIZE  # SATIN-STATE-002


def fmt(n: int) -> str:
    return f"{n:,}"


@dataclass
class Result:
    observations: dict
    derivation: Derivation


def h(b: bytes) -> str:
    return "0x" + b.hex()


def q(n: int) -> str:
    return hex(n)


def word(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


def pad_address(a: bytes) -> bytes:
    return b"\x00" * 12 + a


def created_address(sender: bytes, nonce: int) -> bytes:
    return ex.keccak256(ex.rlp([sender, nonce]))[12:]


def memory_cost(words: int) -> int:
    return MEMORY_WORD * words + words * words // 512


def dim(limit: int, used: int) -> dict:
    return {"limit": q(limit), "net": str(used), "reported": q(max(used, 0))}


def refused(phase: str, reason: str) -> dict:
    return {
        "outcome": {"admission": {"status": "refused", "phase": phase, "reasons": [reason]}, "execution": None,
                    "commit": {"status": "not-committed"}},
        "state": {"accounts": {}},
        "receipt": None,
        "gasLedgers": None,
        "resources": None,
        "limit": None,
    }
