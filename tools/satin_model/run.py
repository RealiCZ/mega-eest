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
from .keyless import KeylessMixin
from .limits import LimitsMixin
from .precompiles import PrecompilesMixin
from .pools import PoolsMixin
from .reads import ReadsMixin
from .settlement import SettlementMixin
from .storage import StorageMixin
from .transaction import TransactionMixin


class Run(TransactionMixin, SettlementMixin, PoolsMixin, DetentionMixin, InterpreterMixin, CallsMixin, FramesMixin, CreationMixin, InterceptionMixin, KeylessMixin, AuthorizationsMixin, StorageMixin, ReadsMixin, LimitsMixin,
          PrecompilesMixin):
    """One transaction against a complete pre-state."""

    def __init__(self, env: Env, pre: dict[bytes, Account], tx: Tx, salt_bucket, principles: bool = False,
                 reads: bool = False, pools: bool = False, destruction: bool = False, detention: bool = False,
                 stops: bool = False, lists: bool = False, outcomes: bool = False, system_tx: bool = False,
                 current: bool = False, system_pages: bool = False, precompile_page: bool = False,
                 size_page: bool = False, pricing: bool = False, returned_state: bool = False):
        self.env, self.pre, self.tx = env, pre, tx
        # A case of the precompile page's own rules (decision D-103): a call to a precompile where no limit is set is
        # decided by SATIN-PCMP-001 to -007, and the model runs KZG point evaluation, P256VERIFY and the BLS12-381
        # precompiles for it.
        self.precompile_page = precompile_page
        # A case of the contract-limits page's own rules (decision D-104): its derivation cites the size checks and the
        # order of a creation's checks and charges where the run passes them (SATIN-SIZE-001 to -006).
        self.size_page = size_page
        # A case citing the snapshot `c130558`, which retires SATIN-STOP-016: a value precompile's crossing is held to the
        # price by SATIN-STOP-014 and SATIN-DET-022 there (D-78).
        self.current = current
        # A case of the gas pools', state gas's and gas schedule's own rules (decision D-106): its derivation also cites
        # the EIP-8037 profile, where each state charge is made and what its multiplier scales, the bucket it lands in
        # and the multiplier's one read, the forward's and the code deposit's departures from Amsterdam, and the
        # accounts warm from the transaction's start, where its steps apply them (SATIN-POOL-001 to -004, -021, -022,
        # SATIN-STATE-004 to -006, -009, -010, SATIN-SCHED-001, -002, -012, -014).
        self.pricing = pricing
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
        # A case that pins the outcomes page or the order of validation's refusals (decision D-85): the derivation also
        # cites the class each ending is in, the rule that makes a refusal the first failing step, and what a failed
        # deposit and a refused transaction report (SATIN-OUT-002 to -018, SATIN-VAL-003, -004, -008).
        self.outcomes = outcomes
        # A case of the system-transaction page or of gas forwarding (decision D-82): the derivation cites the rules that
        # classify the transaction's origin and say what that origin exempts it from (SATIN-MST-001 to -009).
        self.system_tx = system_tx
        self.promoted = False  # a Mega System Transaction promoted to a deposit (SATIN-MST-005)
        # A case of the deposits page or of a system contract's page (decision D-109): the derivation cites the rules of
        # those pages where its steps apply them, and the model runs the system contracts' own code where a case reaches
        # it: the Oracle's reads and restricted writes, the SequencerRegistry's answer, the High-Precision Timestamp,
        # MegaLimitControl's answer, and a deposit's charges at steps 4 and 5 of SATIN-SCHED-008.
        self.system_pages = system_pages
        self.hints: list[tuple[bytes, bytes, bytes]] = []  # the hints handed to the oracle service: (from, topic, data)
        # A system-originated transaction (SATIN-MST-007): priced at m = 1, held to no per-transaction limit or frame
        # budget and not detained, its usage counted and its history paid (SATIN-MST-008, D-83).
        self.exempt = False
        self.exempt_noted: set = set()  # the exemptions a derivation has stated once
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
        self.returned_state = returned_state
        # These logical loads survive frame rollback. External reads can share their keys.
        self.journal_accounts: set[bytes] = set()
        self.journal_slots: set[tuple[bytes, int]] = set()
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
        # gas before the first LOG's charge and before the first memory expansion's; "forward-last" the caller's
        # regular gas when the last CALL computes its forward, "delegate-forward" and "create-forward" when the first
        # DELEGATECALL and the first CREATE compute theirs.
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
        # The deploy address of a keyless creation while its initcode runs, None otherwise (SATIN-KEY-009).
        self.keyless_active: bytes | None = None
        # Its signer while it runs: its account differs already, its record counted on the call (SATIN-KEY-012).
        self.keyless_signer: bytes | None = None
