# The model

`tools/satin_model/` is the executable restatement of Satin's rules that the vertical slice's
expectations come from (decision D-43). `tools/make_slice.py` authors each case, a hand-built
transaction against a hand-built pre-state, and the model derives what the case expects, one step per
charge or decision, each step naming the rule it applies. No implementation is run to make an
expectation: the two implementations are compared with the model's figures, never the other way round.

This page bounds the model (decision D-63): what it derives, what it does not, and where that other
coverage lives.

When a case opts into `returnedState` (D-150), the model records account and slot keys where
a logical journal load completes. The sets survive frame rollback. L1 fee and footprint reads
are marked at their source and stay in the witness reads. A separate journal load of a key
counts even when an external read named the same key. Block and service exports have their own
observations. The returned slot set follows journal loads, while `SATIN-WIT-006` excludes
slots of accounts absent before the block from the witness. The model reads the settled values
at surviving journal entries, so a rolled-back write or a transfer exactly undone leaves the
pre-state value in the expectation. For accounts destroyed at settlement, it asserts the loaded
account and slot keys alone. This accommodates engine lifecycle finalization while preserving
which keys were returned.

## Scope

The model derives **the expected values of small cases at the edges of rules**, from the
specification's text and constants:

- **Atomic rules.** A price, a predicate, an encoding, a record, a give-back: what one charge costs,
  which pool pays it, what it counts toward a limit, and what comes back when a frame fails.
- **The order of charges and decisions.** Around a frame start (the opcode's charges, then the depth
  gate, interception and the frame start, `SATIN-HIST-023`), before the first frame
  (`SATIN-SCHED-008`), under gas detention (each part an opcode deducts as its own charge,
  `SATIN-DET-018`), at a resource limit (`SATIN-LIM-010`, `-011`), and in what a transaction loads
  (`SATIN-WIT-001`).
- **Small hand-built scenarios.** One transaction in engine isolation, with a frame and the few
  levels of calls below it the case builds, and code written for the case: an input is chosen to sit
  on an edge, often set from the model's own figure at a point of the run (a gas limit one below a
  threshold, D-59).
- **The shapes of the take-back page's worked examples** (D-65): a child frame that writes, logs,
  calls, succeeds, reverts or halts, with its reservoir share and its rollback (`SATIN-POOL-011`,
  `-012`, `-014`); `DELEGATECALL`, a writer's record taken back by another frame on the same
  storage; a value start that makes and takes back account records; a successful `CREATE`, its
  constructor's writes and its deposited code, and the first `SELFDESTRUCT` of an account created
  in the transaction, with the destruction table; a value start without a frame held to the started
  frame's budget; an EIP-7702 list whose second entry for one authority clears the delegation; a
  deposit whose own frame halts.
- **Failed first-frame gas pools** (D-170): a non-deposit transaction's own frame starts
  after the pre-frame charges (`SATIN-POOL-010`, `-024`). On revert or limit stop, the pools
  observation keeps its unspent regular gas and adds the frame's net state and history
  charges to its remaining reservoir (`SATIN-POOL-014`, `SATIN-STOP-009`). On exceptional halt,
  the regular balance becomes zero and the reservoir returns to the amount the frame received
  (`SATIN-OUT-007`). The observation records regular gas paid for state and history as
  `spilled`. A give-back of a charge made before the frame is reflected in the transaction's
  gas return (`SATIN-POOL-015`, `SATIN-HIST-005`). If the transaction settles without a first
  frame, D-64's convention records the gas returned at both reservoir endpoints and zero
  regular gas and spill.
- **The destruction page's shapes** (D-70): a `SELFDESTRUCT` of an account the transaction did not
  create, to another account, to the sender or to itself; a repeated one while the mark stands; the
  marked account, kept until the transaction ends, its stores, a code deposit after its constructor
  destroyed it, a value sent to it and its removal; a creation onto an address whose leaf the state
  holds with storage, whose slots read zero; a mark a failed frame discards; and the read of a
  destruction's beneficiary that is the block beneficiary, marked last.
- **The stops below the first frame** (D-74): a child's write held to its frame budget and then the
  transaction's limit, and the stop its caller catches; a value call's start and a `CREATE`'s held to
  what they kept before the frame runs, with the creator's nonce record held to the creator's limits;
  a hint admitted in a frame that fails, and the data-size stop of the frame the failure returns into;
  a deposit whose own frame is stopped; an EIP-7702 list that does not fit, skipped.
- **The authorization page's shapes** (D-88): an EIP-7702 entry skipped by its gates (its chain id,
  a nonce of `2^64 − 1`, a signature that recovers no authority), unread and unwarmed; an authority
  with code other than a delegation indicator, or whose nonce does not match, loaded, warm and
  skipped; the sender's own authorization; an authority holding an indicator at the transaction's
  start; a list at the state-growth limit and one past it, with entries that keep nothing; a first
  frame that halts after the reservoir paid its start record; and the frame's `ORIGIN` and
  `GASPRICE`. The list's charges are made in the order of `SATIN-SCHED-008`, every entry's step-2
  charges and then step 3's records, and an out-of-gas before the first frame takes back everything
  after validation, the applied authorizations among it, keeping what was loaded; an authority that
  is the value's recipient makes the one record the value does not make again.
- **The edges of gas detention's rules** (D-67): the volatile reads of the block environment
  (`NUMBER`, `BLOCKHASH`, `COINBASE`, `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBBASEFEE`, `SLOTNUM`), of
  the beneficiary's account (`SELFBALANCE` of its own frame, `EXTCODESIZE`, `EXTCODEHASH`) and their
  absence (`BLOBHASH`, a creation onto the beneficiary); a transaction detained from its start; an
  `SSTORE` in a detained frame; and a call to a precompile decided from its price: the identity
  precompile, ModExp's EIP-7883 price over and under EIP-7823's bound, and the BN254 pairing over its
  size limit. A precompile that halts burns its whole forward and counts none of it as compute, its
  charged price included (`SATIN-DET-011` at `c130558`, D-78); an input over a size limit fails before
  any gas check and charges no price, and a halting precompile's charged price is no paid work that
  still counts (`SATIN-DET-011`, `-019` at `bcf260d`, D-96).
- **The outcomes page's classes and validation's order** (D-85): a child stopped by gas detention's
  limit or halting beyond its whole gas, a refused read in a child, a system contract's
  `NotIntercepted()`, KeylessDeploy's step 1 overhead unpaid; a precompile call that fails where no
  limit is set (the identity's price, the BN254 pairing over its size limit), the BN254 pairing of
  points at infinity within it, and a value call to the identity precompile whose start is held to
  the limits (`SATIN-LIM-013`, `-014`); `CREATE`'s and `CREATE2`'s operands, initcode size, initcode
  cost, memory and then `CREATE_ACCESS` in the order of `SATIN-SIZE-005`, `CREATE2` only as far as a
  missing salt; a creation's code over `MAX_CONTRACT_SIZE` and its code deposit in its frame, and a
  creation's halt after the reservoir paid its start; `CHAINID`, on the case's chain,
  and a legacy transaction without a chain id; a nonce of 2^64 - 1 and an empty authorization list;
  a deposit that fails validation, carries the base layer's system-transaction flag, cannot pay its
  empty caller or its start record, carries a value to an existing account or one its minted balance
  cannot fund, or whose own frame reverts, and a failed deposit's reads, which keep the load step 4
  makes for its first frame's start and hold none when it fails earlier (`SATIN-DEP-012` at
  `bcf260d`, D-96); a creation transaction that
  cannot pay a charge before its first frame, whose sender keeps the nonce bump the creation would
  have made (`SATIN-SCHED-010`); and a live system address resolved from a registry holding version
  2.0.0's code, from which a deposit is a failed deposit and a Mega System Transaction is refused for
  its own checks or promoted to a deposit that fails validation (D-87), with a legacy receipt whose
  status and gas used are the failed deposit's (`SATIN-MST-005` at `bcf260d`, D-96).
- **A keyless deployment** (D-79): the transaction's own `keylessDeploy` call past step 3's
  encoding check, its carried transaction decoded as a legacy transaction's nine RLP strings and its
  signer recovered from the signature, high `s` included (`SATIN-KEY-005` step 7); steps 3 to 15 in
  the table's order, the first refusal answering and the steps that would also refuse named
  (`SATIN-KEY-006`); the warm reads of the signer and the deploy address (`SATIN-KEY-007`) and a
  signer that is the block beneficiary read as the beneficiary's account (`SATIN-KEY-010`); the
  charges of steps 10 and 14 with their legacy shares and a halt at either; the creation forwarded
  `min(gasLimitOverride, the call's regular gas)` with the reservoir share and the child budgets
  (`SATIN-KEY-011`), its constructor reverting, halting, refused its empty deposit
  (`SATIN-KEY-009`) or its `0xEF` code (EIP-3541), running out of gas in its deposit, destroying
  the deploy address, landing on an address that holds only a balance or colliding with one that
  holds a nonce (`SATIN-KEY-008`), and a failed creation's step-14 charges given back
  (`SATIN-POOL-015`); the creation's start held to its budget and stopped before its initcode, and
  its writes stopped in its initcode by gas detention, its data-size budget or the transaction's
  limit, or its state-growth budget (`SATIN-KEY-016`); `gasUsed` (`SATIN-KEY-015`), the nonce rule,
  every bump kept when the signer's own delegated code spent a nonce during the creation, and the
  signer's record and rise on the call, which can cross the call's budget or the transaction's
  limit and stop the call (`SATIN-KEY-012`, `-013`, `-016`), and the answer (`SATIN-KEY-014`). A
  contract's `keylessDeploy` call, from a contract or from a keyless constructor, runs the bytecode
  (`SATIN-KEY-003`). The interpreter gained `ORIGIN` (`0x32`), `GASPRICE` (`0x3a`), both the
  transaction's own in every frame, the opcodes Osaka leaves undefined at `0x0c` to `0x0f`, each an
  exceptional halt, and a `CALL` to a keyless signer that holds an EIP-7702 delegation, which runs
  its delegate's code, with the delegate's access among the opcode's charges (D-80); a `CREATE` by
  that signer whose initcode fails gives the created account's charges back (`SATIN-TAKE-007`).
- **The system-transaction page and gas forwarding** (D-82, D-83): a transaction from the live system
  address without the system shape, refused; one from an address the registry does not name, a
  user's; a Mega System Transaction promoted and run as a deposit, its receipt its envelope's and its
  Oracle reads asking no service; and the protocol's own transactions, decided on their own fields
  (`SATIN-MST-007`) — a promoted transaction, a deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH`
  and a synthetic message from `SYSTEM_CALLER` — priced at `m = 1` without reading a bucket's
  capacity, not detained, held to no limit or frame budget, a hint past the data-size limit admitted,
  their usage counted and reported and their history paid (`SATIN-MST-008`). The forward's figures
  are read at more points (the last `CALL`'s, the first `DELEGATECALL`'s, `CALLCODE`'s,
  `STATICCALL`'s and creation's, and a creator's reservoir before its share), so that a case can sit
  on the cap's small remainders. Since D-84 the model also runs `CALLCODE`, whose value moves from
  the calling account to itself and makes no record (`SATIN-ACCT-007`), and grants a history
  allowance; `STATICCALL` of a frame that changes no state; `CREATE2` past its salt, onto its salted
  address with the initcode's hashing among its charges; a creation whose initcode reverts or halts,
  for any creator (`SATIN-TAKE-007`); a deposit from the live system address whatever its
  destination; and a synthetic message with an authorization list.
- **The first batch's edges two reviews found** (D-91): RIPEMD-160's price, read before it runs, and
  its digest (`ripemd160` in `precompiles.py`, written out from the algorithm), SHA-256's and
  ecrecover's prices and outputs (ecrecover only on an input whose `v` recovers nothing), and
  ModExp's output; a `DELEGATECALL` of a precompile, which carries the value its frame inherited and
  moves none (`SATIN-DET-024`); the transaction's own call of a precompile, decided from its price
  at the transaction's compute; `BALANCE` and `EXTCODECOPY` (`0x3c`, added for the beneficiary
  alone) of the block beneficiary, a `CALL` and a `DELEGATECALL` to it, and a transaction's
  recipient delegating to it, reads marked once the opcode completes, or for a call when its start
  is decided, at a compute that leaves out the forward, and none when the opcode fails
  (`SATIN-DET-003`); `BLOBHASH` with access off, not refused; `CALL` and `CALLCODE` short of their
  seven operands, a stack underflow before any refusal (`SATIN-MAC-003`); `SELFDESTRUCT`'s static
  cost and its dynamic part as two charges (`SATIN-DET-018`); a created account's first
  `SELFDESTRUCT` to itself, which burns its balance at once and silently (`SATIN-LOG-005`), and one
  in a creation transaction's own frame, whose table gives back the charges made before that frame
  once; a `CREATE` of any creator stopped in a limit-stop case, and the creator's resume after a
  failed creation, held to the data-size limit (`SATIN-STOP-006`); a creation's reset of its
  address's storage, a slot it does not write being zero afterwards (`SATIN-BASE-001`, D-93); a
  value call to the identity precompile where no limit is set in a limit-stop case, its answer
  replaced by the start's stop or its failure kept (`SATIN-STOP-014`); and the block's number as a
  case's input. A precompile's address that holds code is priced and run as the precompile
  (`SATIN-PCMP-008`), and an account the state holds with storage, empty under EIP-161, that the
  transaction leaves as it found it is no change of the state diff.
- **The deposits page and the small system contracts** (D-109): a deposit's charges at steps 3 to 5
  of `SATIN-SCHED-008`, its start record, the load of its recipient or created address at step 4
  with a new or created account's state gas, and a delegated recipient's delegate access at step 5,
  each failing into a failed deposit that keeps what it loaded (`SATIN-DEP-012`); a creating deposit
  without an endowment, a deposit to its own sender, and a creation from a sender at `MAX_NONCE`,
  which creates nothing (`SATIN-DEP-010`); a failed deposit that keeps the hints it admitted
  (`SATIN-DEP-006`); the hints handed to the oracle service, in `reads`, and the transaction's own
  `sendHint` (`SATIN-ORCL-006`, `-007`, `-009`); MegaLimitControl's answer to a `CALL`, a
  `STATICCALL` and the transaction's own call (`SATIN-MLC-001` to `-004`); and the system contracts'
  own code where a case reaches it: the Oracle's reads, its restricted writes with the
  SequencerRegistry's answer (`SATIN-ORCL-001`, `-011`), `multiCall` and a `DELEGATECALL` of
  `sendHint` (`SATIN-ORCL-008`), the High-Precision Timestamp (`SATIN-HPTS-001`, `-002`) and an Oracle
  read refused with access off. For that code the interpreter runs an `SLOAD` below the transaction's
  own frame, a call that copies its output, `EXTCODESIZE` of any account, `ADDMOD` (`0x08`), `EXP`
  (`0x0a`), `ADDRESS` (`0x30`), `CALLDATACOPY` (`0x37`) and `MCOPY` (`0x5e`), in the cases that carry
  `system_pages` alone. After a review the model also takes the transaction's own call of the Oracle
  as the Oracle's own frame, every read there cold; a deposit detained from its start as any
  transaction, and its own `remainingComputeGas()`; a hint dropped before any size check, its call
  starting with no gas or sent with access off, and the transaction's own on a first frame of no
  gas; a `STATICCALL` of `sendHint` and a `STATICCALL` from a static frame; a `CALLCODE` of the
  Oracle, MegaLimitControl or KeylessDeploy and a `DELEGATECALL` of KeylessDeploy, which run the
  held code; a transaction's own value call of an intercepted method, answered `NonZeroTransfer()`
  at depth 0; a creation from `MAX_NONCE` with a value its sender funds; and a reverted deposit's
  reads.

- **The history page and the resource-accounting page** (D-100, D-101): the history allowance spent
  by several logs and drawn whole by a log past it, and the starts that grant none; an `SSTORE` and
  a log that fail after their write was observed, at a regular charge or at their history, and a log
  held to a limit before its history; the transaction's whole state-growth limit, with a fall that
  makes room; a value `CALL` to the calling account itself, which moves nothing, makes no record and
  logs nothing (`SATIN-ACCT-007`, `SATIN-LOG-003`); a value start without a frame held to the
  transaction's limit with the admitted hints counted (`SATIN-LIM-012`); the floor above the
  regular ledger (`SATIN-HIST-017`); and the settlement's credits to an empty fee account
  (`SATIN-ACCT-017`); a `SELFDESTRUCT` that returns an account to what the transaction loaded, taking
  its record back (`SATIN-ACCT-006`), one whose frame cannot pay its beneficiary's cold access, which
  loads nothing (`SATIN-WIT-012`), a creation refused for an endowment its creator cannot fund
  (`SATIN-HIST-015`), and a successful creation onto an address a transfer of the transaction funded
  (`SATIN-ACCT-005`); and validation's step 4, the execution cap (`SATIN-VAL-003`). No opcode was
  added for them.

- **The precompile page's own rules** (D-103): a call to a precompile where no limit is set,
  decided by the page: an input over a size limit fails before any gas check and consumes its
  forward (`SATIN-PCMP-005`); a price the forward cannot pay fails out of gas, KZG point
  evaluation's before any verification (`SATIN-PCMP-006`) and ModExp's below its minimum before
  its lengths are read, past it before EIP-7823's bound (`SATIN-PCMP-007`); a check after the
  charge consumes the forward; and otherwise the precompile is charged exactly its price and
  answers. The model runs KZG point evaluation (`kzg_evaluation`) on an input whose commitment and
  proof are G1's point at infinity, where the pairing check reduces to `y = 0`, with its length and
  versioned-hash checks; `P256VERIFY` (`p256_verify`, EIP-7951's checks and ECDSA over P-256,
  written out from the curve); EIP-2537's MSM and pairing prices from 128 pairs on, and the BN254
  and BLS12-381 precompiles on points at infinity, at and over their size limits; and ModExp's
  lengths too large to price. After a review's edges: a KZG point or value outside the scalar field
  as a failure; Karst's BN254 addition and multiplication and BLS12-381 G1 and G2 additions on
  points at infinity at their prices; and a `CALL` to a precompile's address that holds an
  EIP-7702 indicator, which pays the delegate's access and runs the precompile, or, in a frame
  whose access is off with the beneficiary as the delegate, is refused at the delegate's load and
  settled on its static cost and memory (`SATIN-MAC-007`, `-004`).
- **The contract-limits page's own rules** (D-104): a creation transaction's initcode over
  `MAX_INITCODE_SIZE`, refused at validation (`initcode-too-large`), and a deposit's top-level
  creation over it, which is not checked against the limit and runs as the deposits page's creating
  deposits do, where the model made it a failed deposit before `83c0d26` (`SATIN-SIZE-004`,
  `SATIN-VAL-008` at `83c0d26`, D-112); a creation's deposited code over
  `MAX_CONTRACT_SIZE` from `CREATE` or `CREATE2`, which halts the creation; a creation in a frame a
  `STATICCALL` started, which halts it before its operands and charges (`SATIN-SIZE-005` step 1,
  `-006`); the offset of empty initcode left unchecked, a non-empty one's checked after its
  initcode cost (step 5); `CREATE2`'s `CREATE_ACCESS` and the hashing of its initcode as one
  charge, as the base layer deducts them (`SATIN-DET-018`); and a keyless deployment's step 5 at
  the limit and over it.
- **The gas pools', state gas's and gas schedule's own rules** (D-106, D-107): a case that sets
  `pricing` cites the EIP-8037 profile, its execution cap and the total-gas cap it declines
  (`SATIN-POOL-001`, `-003`), each of Satin's departures where it is applied (`SATIN-POOL-004`,
  `-022`), a returned reservoir joining its caller's (`SATIN-POOL-002`), where each state charge is
  made and what its multiplier scales, a `SELFDESTRUCT`'s beneficiary decided by EIP-161 emptiness
  among them (`SATIN-STATE-004`, `-005`, `-011`), the bucket SALT maps a key to and one multiplier
  for every charge and give-back in a bucket (`SATIN-STATE-006`, `-010`), a deposit's and a
  system-originated transaction's pricing (`SATIN-STATE-009`), the forward's and the code deposit's
  departures from Amsterdam (`SATIN-SCHED-001`), a legacy share or a code deposit's charge a frame
  cannot pay (`SATIN-POOL-008`, `SATIN-STATE-012`, `SATIN-SCHED-011`), a regular charge past the
  regular gas with a reservoir left, a halt that no compute limit makes a stop (`SATIN-POOL-021`),
  and why an account is warm from the transaction's start (`SATIN-SCHED-012`, `-014`). Under it the
  interpreter runs `EXTCODESIZE` (`0x3b`), `EXTCODEHASH` (`0x3f`) and `EXTCODECOPY` (`0x3c`) of any
  account outside a detained frame, warm or cold, where it ran them for the block beneficiary alone
  (`SATIN-SCHED-002`), and a `CALL` without value to an account without code, a start answered
  without a frame. No opcode is added.

- **A call refused at its target's EIP-7702 delegate** (D-115, D-116): in a frame whose
  volatile-data access is off, a `CALL`, `CALLCODE`, `DELEGATECALL` or `STATICCALL` whose target
  operand is the block beneficiary is refused once its operands are on the stack, before its static
  cost (`SATIN-MAC-003`, `-004`). One whose target operand is not, and whose target holds an
  indicator naming the beneficiary, makes the steps before its delegate's load as with access on
  (`SATIN-MAC-007`): its static cost, its memory expansion and a value-transfer cost, each a charge
  that can halt it or be gas detention's crossing; the load of its target, skipped with an
  out-of-gas halt when the target is not warm and the regular gas left, both parts counted, is
  below the cold surcharge; and the delegation guard, the target's cold surcharge not yet deducted
  plus `WARM_STORAGE_READ_COST`. At the delegate's load it is refused and settled
  (`SATIN-MAC-004`): its regular gas, both parts, and the transaction's compute are restored to what
  they were at the opcode, and it is charged its static cost, its memory expansion (the growth from
  the words its frame held at the opcode to the words its two ranges reach) and, last, its target's
  cold surcharge when the target was not warm, the one charge that can be gas detention's crossing
  (`SATIN-DET-018`). The frame then reverts with `VolatileDataAccessDisabled(10)` or is stopped with
  `MegaLimitExceeded(2, limit)` (`SATIN-OUT-008`, `SATIN-STOP-020`); its end rolls the warm set back
  to its checkpoint, and the target's completed read stays in the reads (`SATIN-WIT-012`). The
  target is warm when it is in the warm set as it stands at its load: warm from the transaction's
  start or warmed by an earlier access no rollback took back, an authorization's application
  among them (`SATIN-AUTH-014`). A precompile's address holding such an indicator takes the same path
  and never reaches dispatch (`SATIN-PCMP-008`). In a frame a `STATICCALL` started, a value `CALL`
  halts at its static-context check, after its static cost. For these cases the model also copies a
  call's output into its caller's memory, runs a `CALL` of an account delegating to an ordinary
  account outside gas detention (one hop, the delegate's code as it is), and halts at 0xEF. On the
  inherited path, `BALANCE` and a call load a cold account before its surcharge whenever the whole
  regular gas covers it, so a crossing at that charge keeps the account in the reads
  (`SATIN-WIT-012`, D-117). No opcode is added.

- **Reads and records at transaction boundaries** (D-122, D-127, D-128). A keyless halt at
  step 10 prevents the step-12 deploy-address load. The `reads` group therefore omits that
  address. A marked account's undetained frame can `SLOAD` the slot its store warmed and return
  the word. A value start without a frame can restore the caller's balance to what was loaded. Its budget
  and the transaction's counts use the net records, and a successful start gives back the
  restored account's record history after the child share is returned. The transaction's own
  zero-value call to an absent recipient accounts for no recipient record or rise.

- **System entry checks and a static KeylessDeploy call** (D-129, D-130). A transaction's own
  `isVolatileDataAccessDisabled()` query answers false at its four-byte selector. Nonmatching
  inputs run the held code. A child `STATICCALL` with KeylessDeploy's selector runs its bytecode
  in the static frame and returns its result. A promoted signed transaction can start with its
  sender absent, so the existing deposit account charge applies to a missing leaf.

Every price is a constant in `constants.py`, every figure in a case's text is written from those
constants (D-57), and anything outside the class of transactions the package's docstring lists
raises `Unmodelled` rather than guessing. A pre-state the specification excludes raises
`InvalidPrestate` before anything is derived: storage at a system contract's address in an account
without code (`SATIN-SYSC-005`, D-97).

## Not in scope

| Not in the model | Where it is covered instead |
| --- | --- |
| A general EVM: arbitrary bytecode, the whole opcode set, the precompiles other than the identity's, RIPEMD-160's, SHA-256's and ecrecover's prices and runs, ModExp's prices and output, KZG point evaluation on commitments and proofs at the point at infinity, `P256VERIFY`, and the BN254 and BLS12-381 precompiles on points at infinity (an MSM's price below 128 pairs among the rest); a `CALLCODE` of a system contract and a `STATICCALL` of one other than the Oracle's reads, the SequencerRegistry, MegaLimitControl's answer and the KeylessDeploy selector (D-109, D-129), a precompile, an account without code or a delegated account, a `CALLCODE` its caller cannot fund, and any state change, call or creation in a frame a `STATICCALL` started, but a creation, which halts it; a creation that collides, is stopped other than at its start or in a limit-stop case (D-91), or lands on an address with a balance, other than a keyless deployment's (D-79); a `CALL` to an account that holds an EIP-7702 delegation under gas detention, other than a keyless signer's or a precompile's address, or one whose delegate is a precompile or a system contract, and any other call opcode of such an account, but a call refused at a delegate that is the block beneficiary (D-116); a keyless deploy address the transaction changed already or that holds storage; a keyless creation stopped in KV updates, which the protocol's limits reach only after data size; and a node configuration that disables EIP-3607; a repeated `SELFDESTRUCT` to itself of an account created in the transaction; a store of a marked account that moves the refund counter, and a slot of a created address accessed before the creation (D-72); a start that crosses a limit and takes records back; nesting a case does not build | Each implementation is a full EVM; the slice runs both against the model's figures (`tools/run-slice.sh`) |
| Wide combinations of frames, calls and limits, and their many orders | The differential gates of the evm2-based implementation's repository (`next/diff`), which compare two independent engines over thousands of shared scenarios |
| Blocks, block building and the stateless witness as profiles | Later phases of the suite, and the same differential gates |
| A pre-state outside the specification: storage at a system contract's address in an account without code (`SATIN-SYSC-005`); and the pre-block deployment of the system contracts that would run on it (`SATIN-SYSC-003`, `SATIN-REG-008`), which no single transaction runs | Nothing: no execution from such a state is specified, so no case holds one (D-97). The deployment from a valid state belongs to the block profiles |
| A creating deposit with an endowment other than from `MAX_NONCE`, a failed deposit from a sender at `MAX_NONCE`, an Oracle read the service answers, a transaction's own hint stopped at the data-size limit, and MegaAccessControl's answers other than `disableVolatileDataAccess()` and the transaction's own state query (D-109, D-110, D-130) | Each implementation; the evm2-based implementation's own tests and differential gates |
| An expectation two engines agree on but the model does not derive | Nothing, today. Such a case would be a different kind of expectation, an agreement rather than a derivation from the specification, and would have to be labelled apart from the spec-derived cases (its own provenance status and evidence) if it were ever added |

The model is not the executable specification of Satin. A specification that runs is a direction the
model could grow towards; it is not a decision, and nothing in the suite assumes it.

## Modules

`Run` (`run.py`) holds one run's state; each mixin restates one domain of the rules over it, and
`__init__.py` re-exports what the slice's tools use, so `import satin_model as model` reads as before.

| Module | Domain |
| --- | --- |
| `__init__.py` | The package's docstring (the class of transactions the model restates) and the re-exports |
| `constants.py` | The specification's constants and prices with the rules that state them, the system contracts' addresses and selectors, and the encodings built from them; `tools/check_derived_text.py` changes these in turn |
| `records.py` | The model's exceptions, the derivation record, the inputs (accounts, the transaction, the block environment), the result, and the observations' value formats |
| `run.py` | `Run`: the run state, composed of the mixins below |
| `transaction.py` | Validation's refusals in the order of `SATIN-VAL-003` and the base layer's after them, a creation's initcode over `MAX_INITCODE_SIZE` among them, the system shape, a Mega System Transaction's own checks and a caller the registry does not name, the transaction's origin (`SATIN-MST-007`), intrinsic gas and the two pools, the charges before the first frame, the first frame and how it ends, a creation's code over `MAX_CONTRACT_SIZE`, the out-of-gas path before it |
| `settlement.py` | Refund, floor, gas used, fees, ledgers, resources, receipt, the state diff and the limit group; the snapshot a failed first frame returns to; the live system address; a deposit's run, its validation (from the live system address whatever its destination; a creating deposit's initcode over `MAX_INITCODE_SIZE` is not checked, from `83c0d26` on), its value and its start record, its charges at steps 3 to 5 and its first frame (`deposit_frame`), a creation from `MAX_NONCE`, a reverted deposit, a stopped deposit, and a failed deposit, its hints and its reads; a promoted Mega System Transaction's run and a system-originated transaction's history and usage |
| `precompiles.py` | A call to a precompile, by any call opcode the model has or as the transaction's own: the funds check, the price read before it runs, and under gas detention the decision from it (`SATIN-DET-021` to `-024`); the identity's, RIPEMD-160's and ModExp's outputs; and the precompile page's own call (D-103): the OP size limits, KZG point evaluation, `P256VERIFY` and the BLS12-381 precompiles |
| `pools.py` | Regular charges and the spendable part they are held to, state and history charges with their legacy share, reservoir and spill, rollback of either pool and the first frame's pool observation |
| `detention.py` | The limit a volatile read sets, the caps it is set from, a frame's spendable and withheld parts, and a transaction detained from its start |
| `interpreter.py` | One frame's bytecode: the opcodes the cases and the system contracts' dispatchers use (`ORIGIN` and `GASPRICE` among them since D-88), the volatile reads and their refusal, a call of the block beneficiary refused and a call refused at its target's beneficiary delegate with its settlement (D-116), the opcode charges of a call, a `CALLCODE`, a `DELEGATECALL`, a `STATICCALL`, a `CREATE` or `CREATE2` and a `SELFDESTRUCT`, a creation's checks in the order of `SATIN-SIZE-005` and one in a static frame; under gas detention's cases, the readers of the whole regular gas |
| `calls.py` | A call decided in the order of `SATIN-ICPT-007`: interception, the frame start, the records a value start makes and takes back, the child and what it returns; MegaLimitControl's answer, the hints handed to the service, and what the Oracle's, MegaLimitControl's and the High-Precision Timestamp's own code did |
| `frames.py` | A child frame's budgets and reservoir share, the snapshot its failure returns to, how it ends (`SATIN-POOL-012`, `-014`), a creation's code over `MAX_CONTRACT_SIZE`, a stop it catches, a start held to the started frame's budget, a failed frame's hints and the data-size stop of the frame it returns into, `DELEGATECALL`, and `CALLCODE` and `STATICCALL` |
| `creation.py` | A `CREATE` or `CREATE2` from a frame, onto an absent address or one whose storage then reads zero, stopped at its start with its creator's nonce record, or whose initcode reverts or halts; a `SELFDESTRUCT` in the order of `SATIN-SD-019`: the first of an account created in the transaction with the destruction table and its mark, a repeated one, and one of an account the transaction did not create |
| `interception.py` | The transaction's own `keylessDeploy` call: the decoder's conditions and the deployment's first steps |
| `keyless.py` | A keyless deployment past step 3's encoding check: the carried transaction and its signer, steps 3 to 15, the creation, its collision, the signer's nonce and records, `gasUsed` and the answer (D-79) |
| `authorizations.py` | An EIP-7702 list before the first frame: its simulation, each entry's gates and the checks of its authority's code and nonce, a list that does not fit and is skipped, each entry's charges and records, the sender's own entry, a further entry for one authority |
| `storage.py` | `SSTORE` at Satin's prices, with its state gas, refund, record and limits, a store of a marked account, in a detained frame its static cost apart and its state and history drawn from the withheld part first, and a creation's deposited code |
| `reads.py` | The witness reads and hints, the keys and values of the returned transaction state, and the capacity served for each state charge |
| `limits.py` | A write held to its frame's budget, the transaction's own or a child's, and then the transaction's limit, and the rules a case that pins the limit-stop page cites (D-73); a system-originated transaction's write, held to neither |

A case's explanation, which `tools/make_slice.py --explain <caseId>` prints, names the model by its
package, `tools/satin_model/`. Until schema 2 (D-76) that sentence was part of every case's bytes
and named the module the model was before this split, `tools/satin_model.py`; no case file carries
it now.

## Relation to the specification

The model reads the specification; it does not replace it. Each derivation step cites the rule it
applies, and a case's explanation (`--explain`) carries the text digest of every rule its derivation
applied, so a reviewer holds a figure to the rule text, not to the model's code. A case file stores
neither: it lists the rules it pins (D-76). Where the text leaves an order or a reading open, the model
follows a recorded decision (`docs/decisions.md`) and says so in the step, and the decision is
withdrawn once the specification states it (as D-58 was by `SATIN-HIST-023`).
