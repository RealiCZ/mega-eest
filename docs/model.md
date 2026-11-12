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
- **Small hand-built scenarios.** One transaction in engine isolation, with a frame and at most one
  level of calls below it, and code written for the case: an input is chosen to sit on an edge,
  often set from the model's own figure at a point of the run (a gas limit one below a threshold,
  D-59).

Every price is a constant in `constants.py`, every figure in a case's text is written from those
constants (D-57), and anything outside the class of transactions the package's docstring lists
raises `Unmodelled` rather than guessing.

## Not in scope

| Not in the model | Where it is covered instead |
| --- | --- |
| A general EVM: arbitrary bytecode, the whole opcode set, precompiles, the creation opcodes, `SELFDESTRUCT`, frames nested past one call | Each implementation is a full EVM; the slice runs both against the model's figures (`tools/run-slice.sh`) |
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
| `settlement.py` | Refund, floor, gas used, fees, ledgers, resources, receipt, the state diff and the limit group; the snapshot a failed first frame returns to; a deposit's run |
| `pools.py` | Regular charges and the spendable part they are held to, state and history charges with their legacy share, reservoir and spill, the give-back into the reservoir |
| `detention.py` | The limit a volatile read sets, and a frame's spendable and withheld parts |
| `interpreter.py` | One frame's bytecode: the opcodes the cases and the system contracts' dispatchers use, the volatile reads and their refusal, a call's opcode charges |
| `calls.py` | A call decided in the order of `SATIN-ICPT-007`: interception, the frame start, the child and what it returns |
| `interception.py` | The transaction's own `keylessDeploy` call: the decoder's conditions and the deployment's first steps |
| `authorizations.py` | An EIP-7702 list before the first frame: its simulation's loads, each entry's charges and records |
| `storage.py` | `SSTORE` at Satin's prices, with its state gas, refund, record and limits, and a creation's deposited code |
| `reads.py` | The `reads` group: what the transaction loads, as the stateless witness needs it |
| `limits.py` | A write of the transaction's own frame held to its budget and then the transaction's limit |

The cases' provenance names the model by the module it was before this split,
`tools/satin_model.py`; that text is part of every case's bytes, which this split keeps, and is
updated when the cases are next regenerated with a reason to change.

## Relation to the specification

The model reads the specification; it does not replace it. Each derivation step cites the rule it
applies and each case carries the text digest of every rule it cites, so a reviewer holds a figure to
the rule text, not to the model's code. Where the text leaves an order or a reading open, the model
follows a recorded decision (`docs/decisions.md`) and says so in the step, and the decision is
withdrawn once the specification states it (as D-58 was by `SATIN-HIST-023`).
