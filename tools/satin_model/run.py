"""One transaction against a complete pre-state: the run state, and the mixins that restate each domain
of the rules over it (docs/model.md)."""

from __future__ import annotations

from .records import Account, Derivation, Env, Tx
from .authorizations import AuthorizationsMixin
from .calls import CallsMixin
from .detention import DetentionMixin
from .interception import InterceptionMixin
from .interpreter import InterpreterMixin
from .limits import LimitsMixin
from .pools import PoolsMixin
from .reads import ReadsMixin
from .settlement import SettlementMixin
from .storage import StorageMixin
from .transaction import TransactionMixin


class Run(TransactionMixin, SettlementMixin, PoolsMixin, DetentionMixin, InterpreterMixin, CallsMixin, InterceptionMixin, AuthorizationsMixin, StorageMixin, ReadsMixin, LimitsMixin):
    """One transaction against a complete pre-state."""

    def __init__(self, env: Env, pre: dict[bytes, Account], tx: Tx, salt_bucket, principles: bool = False,
                 reads: bool = False):
        self.env, self.pre, self.tx = env, pre, tx
        # The `reads` group (SATIN-WIT-001, -002, -008): every account (None: absent) and slot the
        # transaction loads, as the pre-state holds it, and the SALT capacities it is served.
        self.reads = reads
        self.loaded_accounts: dict[bytes, Account | None] = {}
        self.loaded_slots: dict[tuple[bytes, int], int] = {}
        self.served_buckets: dict[int, int] = {}
        self.salt_bucket = salt_bucket  # (address, slot or None) -> bucket id
        self.d = Derivation()
        # The specification states the charge-order principles (`SATIN-HIST-023`, from `5fb2688` on): the
        # derivation cites them where the earlier snapshots leave the orders to the owner's decision (D-58).
        self.principles = principles
        # Gas figures at fixed points of the run, for the cases that set an input from a threshold:
        # "forward" is the caller's regular gas when the first CALL computes its forward, "frame" the
        # regular gas the first frame starts with, "delegate" the regular gas before the delegate's access,
        # "gas" and "gas-reservoir" the frame's regular gas and reservoir at its first GAS, "refused" the
        # regular gas a frame holds at a refused read, "oracle-sload" the regular gas at the first Oracle read;
        # "child-room" and "oracle-sload-room" what the limit leaves the transaction's compute at the first
        # detained child's start and at a detained Oracle read; "list" the regular gas when an authorization
        # list starts to be applied, "balance" the regular gas at the first BALANCE.
        self.probe: dict[str, int] = {}
        # Gas detention (SATIN-DET-009, -012): the transaction's compute, every regular charge its frames
        # make, and the limit the most restrictive volatile read set, None before any read.
        self.compute = 0
        self.limit: int | None = None
        # The stop of the transaction's own frame, (kind, limit), when one is its result.
        self.stop: tuple[int, int] | None = None
        self.frame_start_counts = (0, 0, 0)
