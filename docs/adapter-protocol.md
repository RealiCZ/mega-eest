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
4. Compare the actual document with `expected` (`mega_fixture_format::compare`). Equality is
   exact on canonical values, with two rules: an optional group the case does not require is
   ignored, and a `reasons` set matches when the implementation reports exactly one of its
   entries (or none when it is empty).
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
first differing pointer with both values, and the rules whose assertions cover that pointer (the
assertions whose path is a prefix of it). The process exits nonzero.

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
  profile, requires, input}`: the case without `rules`, `assertions`, `expected` and
  `provenance`, so an adapter cannot read what it is held to.
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
differing path, both values and the covering rules for a `fail`). `mega-fixture fill` is the
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
  a halt's output is empty; a failed deposit has no execution.
- `gasLedgers`: `total` is what the transaction spent from both pools before the refund and the
  floor; `regular = total − state − history` (`SATIN-POOL-019`); `refund` is the refund the
  receipt's gas used applies, zero when the floor sets the gas used (`SATIN-POOL-018`); `floor` is
  the EIP-7623 floor; `blockGas` is `max(regular, floor)` (`SATIN-POOL-020`).
- `resources`: `limit` is the transaction limit (`SATIN-LIM-001`), `net` the transaction's signed
  net at its end, `reported` its `max(net, 0)` (`SATIN-LIM-007`).
- `state` lists every account whose existence, nonce, balance, code or storage differs from the
  pre-state after the transaction is committed: an account destroyed, or left empty under EIP-161,
  does not exist afterwards.
- A deposit receipt's `depositNonce` is the sender's nonce before the deposit and its
  `depositReceiptVersion` is 1.
- `limit`: neither implementation's result carries a stop's scope, call path, operation, phase and
  commit flags, so an adapter reports `error` for a transaction that ends in a limit stop rather
  than fill those fields from instrumentation.
- Refusal reasons are mapped from the implementation's error variants by a table in each adapter;
  an error the table does not name is `error`, never a guessed reason.

## The adapters of this repository

| Adapter | Implementation | Pinned by | Build |
| --- | --- | --- | --- |
| `adapters/revm` (`adapter-revm`) | revm-based Satin: `megaeth-labs/mega-evm` at `4e39cfd6`, through `MegaEvm::execute_transaction` | a cargo git dependency at that commit, with the patches of its own root manifest | `cd adapters/revm && cargo build --locked` |
| `adapters/evm2` (`adapter-evm2`) | evm2-based Satin: `RealiCZ/mega-evm` `next/` at `f3d84454` with `RealiCZ/evm2` at `390a3876`, through the single-transaction EVM of its factory (`SatinFactory::evm`) and `Evm::transact` | `tools/fetch-implementations.sh` checks both out under `vendor/` (git-ignored), so the implementation's relative `../../evm2` path resolves | `bash tools/fetch-implementations.sh && cd adapters/evm2 && cargo build --locked` |

Both declare `state-transition` with its mandatory groups and the features `deposit`, `salt` and
`synthetic-transaction`; the revm-based adapter also runs a recorded `oracle-transcript`, which
the other implementation's map-based oracle service cannot check (D-45). Neither runs sparse
pre-states, injected faults, or engine isolation of a deposit-only or activation block. Both use
the production SALT mapping and the implementation's own toolchain, and each reports its build
identity from what its build resolved (the lockfile's commit, the `vendor/` checkouts' heads).
Each hands its implementation the case's SALT input as the format defines it (a listed bucket at
its capacity; an unlisted one at the minimum when the input is complete, otherwise a missing
input), through the revm-based implementation's SALT environment and the evm2-based
implementation's SALT snapshot of the parent state. The evm2-based implementation resolves the live
system address from the pre-state's SequencerRegistry when its EVM is made (D-52).
Instrumented runs attach a recorder of every frame start and end; `tools/run-slice.sh` holds the
plain and instrumented observations of every case to the same bytes.
