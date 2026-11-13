# The model

`tools/satin_model/` is the executable restatement of Satin's rules that the vertical slice's
expectations come from (decision D-43). `tools/make_slice.py` authors each case, a hand-built
transaction against a hand-built pre-state, and the model derives what the case expects, one step per
charge or decision, each step naming the rule it applies. No implementation is run to make an
expectation: the two implementations are compared with the model's figures, never the other way round.

This page bounds the model (decision D-63): what it derives, what it does not, and where that other
coverage lives.

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
  `GASPRICE`.
- **The edges of gas detention's rules** (D-67): the volatile reads of the block environment
  (`NUMBER`, `BLOCKHASH`, `COINBASE`, `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBBASEFEE`, `SLOTNUM`), of
  the beneficiary's account (`SELFBALANCE` of its own frame, `EXTCODESIZE`, `EXTCODEHASH`) and their
  absence (`BLOBHASH`, a creation onto the beneficiary); a transaction detained from its start; an
  `SSTORE` in a detained frame; and a call to a precompile decided from its price: the identity
  precompile, ModExp's EIP-7883 price over and under EIP-7823's bound, and the BN254 pairing over its
  size limit. A precompile that halts burns its whole forward and counts none of it as compute, its
  charged price included (`SATIN-DET-011` at `c130558`, D-78).

Every price is a constant in `constants.py`, every figure in a case's text is written from those
constants (D-57), and anything outside the class of transactions the package's docstring lists
raises `Unmodelled` rather than guessing.

## Not in scope

| Not in the model | Where it is covered instead |
| --- | --- |
| A general EVM: arbitrary bytecode, the whole opcode set, the precompiles other than the identity's run and the prices of ModExp and of an over-size BN254 pairing; `CREATE2`, `CALLCODE` and `STATICCALL`; a creation that fails or collides other than at its start, or lands on an address with a balance; a `SELFDESTRUCT` to itself of an account created in the transaction, or in a creation transaction's own frame; a store of a marked account that moves the refund counter, and a slot of a created address accessed before the creation (D-72); a start that crosses a limit and takes records back; nesting a case does not build | Each implementation is a full EVM; the slice runs both against the model's figures (`tools/run-slice.sh`) |
| Wide combinations of frames, calls and limits, and their many orders | The differential gates of the evm2-based implementation's repository (`next/diff`), which compare two independent engines over thousands of shared scenarios |
| Blocks, block building and the stateless witness as profiles | Later phases of the suite, and the same differential gates |
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
| `transaction.py` | Validation's refusals, intrinsic gas and the two pools, the charges before the first frame, the first frame and how it ends, the out-of-gas path before it |
| `settlement.py` | Refund, floor, gas used, fees, ledgers, resources, receipt, the state diff and the limit group; the snapshot a failed first frame returns to; a deposit's run, a stopped deposit, and a failed deposit |
| `precompiles.py` | A call to a precompile: the funds check, the price read before it runs, and under gas detention the decision from it (`SATIN-DET-021` to `-024`) |
| `pools.py` | Regular charges and the spendable part they are held to, state and history charges with their legacy share, reservoir and spill, the give-back into the reservoir |
| `detention.py` | The limit a volatile read sets, the caps it is set from, a frame's spendable and withheld parts, and a transaction detained from its start |
| `interpreter.py` | One frame's bytecode: the opcodes the cases and the system contracts' dispatchers use (`ORIGIN` and `GASPRICE` among them since D-88), the volatile reads and their refusal, the opcode charges of a call, a `DELEGATECALL`, a creation and a `SELFDESTRUCT`; under gas detention's cases, the readers of the whole regular gas |
| `calls.py` | A call decided in the order of `SATIN-ICPT-007`: interception, the frame start, the records a value start makes and takes back, the child and what it returns |
| `frames.py` | A child frame's budgets and reservoir share, the snapshot its failure returns to, how it ends (`SATIN-POOL-012`, `-014`), a stop it catches, a start held to the started frame's budget, a failed frame's hints and the data-size stop of the frame it returns into, and `DELEGATECALL` |
| `creation.py` | A `CREATE` from a frame, onto an absent address or one whose storage then reads zero, or stopped at its start with its creator's nonce record; a `SELFDESTRUCT` in the order of `SATIN-SD-019`: the first of an account created in the transaction with the destruction table and its mark, a repeated one, and one of an account the transaction did not create |
| `interception.py` | The transaction's own `keylessDeploy` call: the decoder's conditions and the deployment's first steps |
| `authorizations.py` | An EIP-7702 list before the first frame: its simulation, each entry's gates and the checks of its authority's code and nonce, a list that does not fit and is skipped, each entry's charges and records, the sender's own entry, a further entry for one authority |
| `storage.py` | `SSTORE` at Satin's prices, with its state gas, refund, record and limits, a store of a marked account, in a detained frame its static cost apart and its state and history drawn from the withheld part first, and a creation's deposited code |
| `reads.py` | The `reads` group: what the transaction loads, as the stateless witness needs it |
| `limits.py` | A write held to its frame's budget, the transaction's own or a child's, and then the transaction's limit, and the rules a case that pins the limit-stop page cites (D-73) |

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
