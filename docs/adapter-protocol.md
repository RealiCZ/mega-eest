# Adapter protocol

An adapter connects one implementation to the suite. It converts a fixture's input into the
implementation's own types, runs the implementation, and converts the implementation's results
back into the observation model of `expected`. The format crate
(`crates/mega-fixture-format`) decodes, validates and compares; it never executes, and no
implementation receives an expected result as an input.

## What an adapter provides

1. **A capability declaration**: the profiles it runs and the `requires` entries it supports
   (observation groups and features), plus the implementation, adapter and build identities it
   reports (revision, backend, instrumentation).
2. **An executor per supported profile** that takes a validated input and returns an actual
   observation document shaped like the profile's `expected` and valid against its schema. It
   carries every group the case requires and may carry other optional groups.
3. **Plain and instrumented runs** when it collects checkpoints, reads or detention through
   instrumentation: final observations must be identical between the two, and instrumentation
   never supplies a value the plain run cannot produce.

An adapter must not read `expected`, regenerate inputs from seeds, rewrite fixtures, or fall back
to network or defaults for a missing input.

## The consumer loop

For every case of the selected manifest subset:

1. Verify the case's file digest against the manifest, then decode and validate it against the
   bundled specs. A case that does not validate is an `error` of the release.
2. If any `requires` entry is outside the declared capabilities, report `unsupported` with the
   missing entries and do not run it.
3. Run the executor on the input. A panic, timeout, harness failure or missing input is `error`.
4. Compare the actual document with `expected` (`mega_fixture_format::compare`). Canonical
   values compare exactly by default. Ignore optional groups the case does not require.
   A `reasons` set matches when the implementation reports exactly one of its entries, or
   none when the set is empty. For `returnedState`, the actual account and slot keys must
   exactly match the non-null expected keys. An expected `null` requires the key to be
   absent. Compare only the account fields the expectation lists. A slot expectation of
   `{}` requires the key to be present, and a quantity also checks its value. See the
   [returned-state comparison rules](format.md#returned-transaction-state).
5. Map the verdict: `pass`; `fail` with the first differing semantic path and both values;
   `known-fail` when the consumer's own waiver list names this case and exactly this difference;
   `unsupported`; `error`.

## Result statuses

| Status | Meaning | Counts as passing |
| --- | --- | --- |
| `pass` | every required observation matched | yes |
| `fail` | a required observation differed or is missing | no |
| `known-fail` | a waived, expiring, exactly described failure of this consumer | no |
| `unsupported` | the consumer lacks a requirement of the case | no |
| `error` | the case did not run to completion: harness error, panic, timeout, missing input, malformed actual output | no |

The run report lists every case with its status. Its summary gives the manifest digest, the subset
and its expected case count, the counts per status, and the executed-rule coverage of the passing
cases. A count that differs from the subset's expected count fails the run.

## Mismatch reports

A `fail` reports the release, manifest digest, `caseId`, the case's file and semantic digests, the
digests of the actual document's canonical bytes, the implementation and adapter versions, the
first differing pointer with both values, and the rules the case pins. The process exits nonzero.

## Mapping notes

- Representation differences between an implementation and the format (error names, account
  representations of destroyed accounts) are the adapter's to map, with tests of their own. A
  difference the format does not define as equivalent is a failure, not something to normalize.
- Engine-isolation profiles take `depositOnly` and `activation` as inputs; block profiles must let
  the node derive them, and the adapter must not force the expected fork or flags.
- The oracle transcript feeds only engine-isolation runs. A validator adapter reads oracle values
  from state.

## The process interface (1.0)

An adapter is a program the consumer runs; the format crate never links an implementation.

- `<adapter> capabilities` prints one strict JSON document, `format` `mega-fixture-adapter`:
  `adapter` (`name`, `version`), `implementation` (its `name`, `engine`, `repository` and the
  `commit` the build resolved, and any further pinned component), `build` (compiler and profile),
  `specs` (the spec names it executes), `profiles`, `requires` (the requirement entries it
  supports) and `modes` (`plain`, `instrumented`).
- `<adapter> run [--instrumented]` reads one run request on standard input and prints one
  response. The run request is `{format: "mega-fixture-run", schemaVersion, caseId, specRef,
  profile, requires, input}`: the case without `rules`, `expected` and `provenance`, so an
  adapter cannot read what it is held to. Its `schemaVersion` is the run request's own, 1.0, not
  the fixture's.
- The response is `{status: "ok", mode, inputDigest, observations, diagnostics}`, or
  `{status: "unsupported", reason}`, or `{status: "error", error}`. `inputDigest` is the SHA-256
  of the canonical bytes of the `input` the adapter ran; the consumer reports `error` when it is
  not the case's. `observations` is shaped like the profile's `expected`. `diagnostics` is
  non-normative (frame counts of an instrumented run) and never compared.
- A run that exceeds the consumer's time limit (300 s), exits without a parsable response, or
  answers anything else is `error`.

`mega-fixture consume --adapter <program> [--instrumented] [--jobs <N>] [--report <file>] <paths>` is the
consumer loop above: read-only, one line per case, a `CONSUME` summary line, and a JSON report
with each case's file, semantic, input and observation digests and its status (with the first
differing path, both values and the case's pinned rules for a `fail`). Each path is a fixture file
or a directory, searched for `*.json` at any depth in path order, so `slice/cases`, whose cases
sit at `slice/cases/<caseId>.json`, is one argument. `mega-fixture fill` is the
candidate filler: it runs an adapter on authoring documents (fixtures without `requires` and
`expected`) and writes each filled fixture, `provenance.status` `candidate` with the filler's
identity, into a directory that is neither `examples/` nor a `release` directory.

Both commands accept `--jobs <N>` (a positive integer, default `1`) to run up to N cases at
once. Case lines, summaries, reports and candidate writes retain the input order and the same
bytes as a serial run. The process transport writes standard input and drains standard output
and standard error concurrently; the 300 s deadline covers the process and all three pipes.

## Mapping definitions

These definitions settle what an implementation's result means in the observation model; each
adapter implements them on its own (decisions D-40, D-41):

- `outcome.execution.output` of a creation is what its initcode returned, the code it deposited;
  a halt's output is empty; a failed deposit has no execution. A Mega System Transaction, which
  runs as a deposit (`SATIN-MST-005`), fails as one: its admission is `failed-deposit` whatever its
  envelope (D-94).
- `gasLedgers`: `total` is what the transaction spent from both pools before the refund and the
  floor; `regular = total − state − history` (`SATIN-POOL-019`); `refund` is the refund the
  receipt's gas used applies, zero when the floor sets the gas used (`SATIN-POOL-018`); `floor` is
  the EIP-7623 floor; `blockGas` is `max(regular, floor)` (`SATIN-POOL-020`). A failed deposit's
  ledgers are exactly `SATIN-DEP-005`'s: its gas limit as `total`, `regular`, `gasUsed` and
  `blockGas`, and `state`, `history`, `refund` and `floor` 0 (decision D-66).
- `resources`: `limit` is the transaction limit (`SATIN-LIM-001`), `net` the transaction's signed
  net at its end, `reported` its `max(net, 0)` (`SATIN-LIM-007`).
- `state` lists every account whose existence, nonce, balance, code or storage differs from the
  pre-state after the transaction is committed: an account destroyed, or left empty under EIP-161,
  does not exist afterwards.
- A deposit receipt's `depositNonce` is the sender's nonce before the deposit and its
  `depositReceiptVersion` is 1.
- `limit`: the stop the implementation reports for the transaction's own frame, by its dimension
  and limit, with the frame's revert output as `returnData`; `null` when the frame's result is not a
  stop's revert, a stop a caller caught and a contract's own revert with the same bytes included
  (`SATIN-STOP-021`). Neither implementation's result carries a stop's scope, call path,
  operation, phase or commit flags, so neither adapter reports these diagnostics, nor fills them
  from instrumentation (decision D-62).
- Refusal reasons are mapped from the implementation's error variants by a table in each adapter;
  an error the table does not name is `error`, never a guessed reason.

### Reads

`reads` is what the transaction loaded from its inputs, as the stateless witness needs it
(`SATIN-WIT-001`, `-002`, `-008`): the transaction's contribution to the block's witness and
exports. An adapter of this repository reports it for a case that requires `group:reads`, in plain
and instrumented runs alike, from a recording layer over its own inputs; it reports no `reads` for
a case that does not require them (decision D-61).

- **The recording layer.** The fixture database, the SALT environment and the oracle service of a
  run record every load that reaches them. A run builds them afresh, so the first load of each item
  is what the transaction read, with the value the input served.
- `accounts`: every account loaded, with its nonce, balance and code hash as the pre-state holds
  it, or `null` for an account read and absent.
- `storage`: every slot loaded, with its pre-state value; an absent account has no slot to load
  (`SATIN-WIT-006`).
- `codes`: the code hash of every account in `accounts` whose code is not empty, with any code
  loaded by hash: the witness holds the code of every account it names, whether or not the load
  that named the account brought it (`SATIN-WIT-001`). Whether an engine loads code with the
  account or by hash does not change the set.
- `blockHashes`: every hash `BLOCKHASH` was served (`SATIN-WIT-014`).
- `buckets`: every SALT capacity the environment served with a valid capacity
  (`SATIN-WIT-013`).
- `oracle`: the oracle service's answers in order, for a recorded transcript; a read the service
  does not answer pushes the slot's value, which `storage` holds. The evm2-based adapter runs no
  transcript, and a deposit's read asks no service (`SATIN-ORCL-005`), so its list is empty.
- `hints`: the hints the implementation handed the service, in order, with the address of the
  frame that sent each, its topic and its data.
- **The transaction, not the block.** The evm2-based implementation's factory resolves the live
  system address off the SequencerRegistry when it makes the EVM, as a block resolves it once
  before its transactions (`SATIN-REG-002`); its adapter records from the transaction's start, and
  adds an account or slot the factory loaded first only when the transaction's returned state
  names it, which the EVM's cache served. The revm-based adapter reads the live system address
  off the case's pre-state outside its recording, as a node reads it for its block, and hands it
  to the implementation's context (`MegaContext::new_with_system_address`), which then reads
  nothing for it; the adapter records every load the run makes, never hiding one (D-94).
- The consumer compares `reads` exactly. A missing required load or an extra load is a difference.

### Returned transaction state

For a case requiring `group:returned-state`, both adapters project every entry in the transaction
result in plain and instrumented runs. The revm adapter reads `MegaTransactionOutcome.state`
including each storage entry's `present_value`. The evm2 adapter reads
`ExecutedTx::account_changes()` including each storage entry's current value, before
`ExecutedTx::commit()`. Both read the account metadata and slots before the state diff filters
for touches and changes. The projection keeps absent-account keys and explicit zero slots.
Adapters export all metadata fields and slot values they observe, even when the fixture
asserts only presence. Lifecycle finalization can clear the temporary values of an account
created and destroyed by the same transaction. The account and slot keys still identify
completed loads.

The expected keys come from the model's transaction journal loads. The recording layer for
`reads` also observes L1 fee and footprint reads made outside the journal
(`SATIN-WIT-011`). A journal load of the same address still belongs to `returnedState`. Block
pre-execution reads, fees read outside the journal, and exports such as bucket capacities are
accounted for separately by the witness rules.

### Gas pools

`gasPools` describes the transaction's first frame (decision D-64). An adapter of this repository
reports it for a case that requires `group:gas-pools`, in plain and instrumented runs alike, from a
passive recorder of frame starts and ends that changes nothing the run does; it reports none for a
case that does not require it.

- `regular.initial` and `reservoir.initial`: the regular gas and the reservoir the first frame starts
  with, after every charge made before it (the authorities', the pre-frame history, a new or created
  account's state gas, a delegate's access); the revm-based implementation's depth-0 call or create
  inputs (`gas_limit`, `reservoir`), the evm2-based implementation's first message (`gas_limit`,
  `reservoir`).
- `regular.final` and `reservoir.final` are the first frame's balances after its own rollback
  settlement and before transaction settlement (D-170, D-172). The revm adapter settles a
  copy of the outer frame's end tracker with the engine's settlement helper. The evm2 end
  callback supplies the settled balances.
- `spilled` counts regular gas the first frame and its children paid for state and history,
  including legacy shares. Both current pins expose this accumulator as
  `state_gas_spilled()`. The revm adapter takes it from the original tracker before settling
  the copy.
- `returned` is the gas limit less the receipt's gas used. It also reflects any give-back of a
  pre-frame charge at transaction settlement.
- An out-of-gas before the first frame has zero regular gas and spill. Both reservoir
  endpoints equal the gas returned to the sender. The evm2 adapter uses `top_started` to
  distinguish this path from a frame that enters with a zero budget. The instrumented
  `inspectorMessageStarts` diagnostic still counts the tracer's synthetic root message.
- An authorization list that exceeds a limit ends the transaction's own frame with a stop.
  Both endpoints are the regular gas and reservoir left after the intrinsic and body charges.

## The adapters of this repository

| Adapter | Implementation | Pinned by | Build |
| --- | --- | --- | --- |
| `adapters/revm` (`adapter-revm`) | revm-based Satin: `megaeth-labs/mega-evm` at `1a981f4b`, through `MegaEvm::execute_transaction` | a cargo git dependency at that commit, with the patches of its own root manifest | `cd adapters/revm && cargo build --locked` |
| `adapters/evm2` (`adapter-evm2`) | evm2-based Satin: `RealiCZ/mega-evm` `next/` at `62f2964a` with `RealiCZ/evm2` at `c0a91cbb`, through the single-transaction EVM of its factory (`SatinFactory::evm`) and `Evm::transact` | `tools/fetch-implementations.sh` checks both out under `vendor/` (git-ignored), so the implementation's relative `../../evm2` path resolves | `bash tools/fetch-implementations.sh && cd adapters/evm2 && cargo build --locked` |

Both declare `state-transition` with its mandatory groups, `group:gas-pools`, `group:limit-stop`,
`group:reads`, `group:returned-state` and the features `deposit`, `salt` and `synthetic-transaction`. The revm-based adapter
also runs a recorded `oracle-transcript`; the evm2-based adapter does not consume transcripts
(D-45). Its connected service records hints and supplies no answers, so Oracle reads use the
slot's value. Neither runs sparse pre-states, injected faults, or engine isolation of a deposit-only
or activation block. Both use the production SALT mapping and the implementation's own toolchain,
and each reports its build identity from what its build resolved (the lockfile's commit, the `vendor/` checkouts' heads).
Each hands its implementation the case's SALT input as the format defines it (a listed bucket at
its capacity; an unlisted one at the minimum when the input is complete, otherwise a missing
input), through the revm-based implementation's SALT environment and the evm2-based
implementation's SALT snapshot of the parent state. The evm2-based implementation resolves the live
system address from the pre-state's SequencerRegistry when its EVM is made (D-52); the revm-based
adapter reads it from there and hands it to its implementation (D-94).
Instrumented runs attach a recorder of every frame start and end; `tools/run-slice.sh` holds the
plain and instrumented observations of every case to the same bytes.
