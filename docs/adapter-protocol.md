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
