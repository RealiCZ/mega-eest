"""One transaction against a complete pre-state: the run state, and the mixins that restate each domain
of the rules over it (docs/model.md)."""

from __future__ import annotations

from .records import Account, Derivation, Env, Tx
from .authorizations import AuthorizationsMixin
from .calls import CallsMixin
from .creation import CreationMixin
from .detention import DetentionMixin
from .frames import FramesMixin
from .interception import InterceptionMixin
from .interpreter import InterpreterMixin
from .limits import LimitsMixin
from .precompiles import PrecompilesMixin
from .pools import PoolsMixin
from .reads import ReadsMixin
from .settlement import SettlementMixin
from .storage import StorageMixin
from .transaction import TransactionMixin


class Run(TransactionMixin, SettlementMixin, PoolsMixin, DetentionMixin, InterpreterMixin, CallsMixin, FramesMixin, CreationMixin, InterceptionMixin, AuthorizationsMixin, StorageMixin, ReadsMixin, LimitsMixin,
          PrecompilesMixin):
    """One transaction against a complete pre-state."""

    def __init__(self, env: Env, pre: dict[bytes, Account], tx: Tx, salt_bucket, principles: bool = False,
                 reads: bool = False, pools: bool = False, destruction: bool = False, detention: bool = False,
                 stops: bool = False, lists: bool = False):
        self.env, self.pre, self.tx = env, pre, tx
        # A case of the authorization page's own rules (decision D-88): its derivation cites the list's simulation,
        # each entry's gates and checks, and the warmth the application leaves (SATIN-AUTH-001 to -018).
        self.lists = lists
        self.applied_authorities: set = set()  # the authorities an accepted entry of the list wrote
        self.authority_warmth: dict = {}  # an authority -> (what the list left of its warmth, the rules)
        # The cases of the destruction page's own rules (decision D-70) cite them where their steps apply them:
        # the first effective destruction and its mark, a destruction without the table, the marked account and
        # its removal at the transaction's end (SATIN-SD-001 to -003, -010 to -017, -020).
        self.destruction = destruction
        # The cases of gas detention's rules at `cdded1e` (decision D-67): their derivations cite the rules of the
        # readers that see the withheld part, the stipend, the settlement and the caps where the run reaches them.
        self.detention = detention
        # A case that pins the limit-stop page (decision D-73): the derivation also cites the rules that give a
        # stop its kind and say which endings are stops (SATIN-STOP-002, -003, -019).
        self.stops = stops
        self.caught_stop = False  # a frame below the transaction's own was stopped and its caller ran on
        # The `gasPools` group (decision D-64): the first frame's pools at its start and end, and the
        # regular gas it and its children paid for state and history charges.
        self.pools = pools
        self.first_frame: dict | None = None
        self.spilled = 0
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
        # list starts to be applied, "balance" the regular gas at the first BALANCE; "log" and "expand" the regular
        # gas before the first LOG's charge and before the first memory expansion's.
        self.probe: dict[str, int] = {}
        # Gas detention (SATIN-DET-009, -012): the transaction's compute, every regular charge its frames
        # make, and the limit the most restrictive volatile read set, None before any read.
        self.compute = 0
        self.limit: int | None = None
        # The stop of the transaction's own frame, (kind, limit), when one is its result.
        self.stop: tuple[int, int] | None = None
        self.frame_start_counts = (0, 0, 0)
        # The accounts created in the transaction, which a SELFDESTRUCT deletes (EIP-6780), and those destroyed: the
        # marked accounts, which stay until the transaction's end (SATIN-SD-015).
        self.created: set[bytes] = set()
        self.record_frames: dict = {}  # each storage write record and the frame that made it
        self.destroyed: set[bytes] = set()
        # The created accounts whose slots read zero from the creation on, the state having held storage there
        # (SATIN-SD-003, -016).
        self.zero_storage: set[bytes] = set()
