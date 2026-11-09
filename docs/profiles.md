# Profiles and capabilities

A profile fixes what a case's input contains and which observations its expected result must carry.
Consumers declare the profiles and requirements they support; anything else is reported
`unsupported` and never counted as a pass.

## The profiles

| Profile | Input | Expected | Typical consumer |
| --- | --- | --- | --- |
| `state-transition` | One transaction (signed, deposit or synthetic) against the state immediately before it, with explicit block context, chain id, block hashes and optional SALT, oracle transcript and faults | Its outcome, state diff, receipt, gas ledgers, resources and limit stop; optionally pools, detention, reads and checkpoints | An EVM engine through its transaction entry point |
| `transaction-validation` | Raw EIP-2718 bytes (malformed ones included), chain id, optional block context and optional pre-state | Accepted with sender, hash and intrinsic gas, or rejected with phase and acceptable reasons | A decoder and validator; no execution |
| `block-import` | Chain schedule, anchor header, pre-state, ancestors, optional SALT and faults, ordered blocks | Per block: valid with derived flags, pre-block effects, per-transaction outcomes and receipts, counters, commitments and state diff, or invalid with failure phase and reason; the last accepted head; the state diff to it | A node's import path |
| `block-build` | Chain schedule, anchor, pre-state, the builder's header fields, policy budgets, candidates and an execute/commit/abandon action sequence; optional SALT, oracle transcript and faults | One decision per candidate (included, skipped or rejected, with reasons), committed order, results of the committed transactions, counters, commitments, state diff | A block builder |
| `stateless-block` | A block-import input whose pre-state is the witness's closed sparse values, with the witness anchor and an optional versioned proof attachment | The witness verdict; when verified, the same block results, head and state as a stateful import; when failed, the failing stage, reason and read | A stateless validator |

`block-import` never skips: a transaction present in a block that the rules forbid makes the block
invalid, and the import stops there with the previous head and state intact. `block-build` may skip
a candidate and continue; a skip leaves no receipt, state or counter contribution and is not an
invalid on-chain transaction. The two profiles keep builder policy from defining validity.

## Observation groups by profile

M: mandatory, always required. O: optional, required exactly when the case carries it. T: per
transaction result. —: not part of the profile.

| Group | state-transition | transaction-validation | block-import | block-build | stateless-block |
| --- | --- | --- | --- | --- | --- |
| outcome | M | — | M (T) | M (T) | M (T) |
| state | M | — | M | M | M |
| receipts | M | — | M (T) | M (T) | M (T) |
| gas-ledgers | M | — | O (T) | O (T) | O (T) |
| resources | M | — | O (T) | O (T) | O (T) |
| limit | M | — | O (T) | O (T) | O (T) |
| gas-pools | O | — | O (T) | O (T) | O (T) |
| detention | O | — | O (T) | O (T) | O (T) |
| reads | O | — | O (T) | O (T) | O (T) |
| checkpoints | O | — | — | — | — |
| validation | — | M | — | — | — |
| blocks | — | — | M | M | M |
| decisions | — | — | — | M | — |
| witness | — | — | — | — | M |

Final public observations are mandatory in every profile. Intermediate checkpoints and the
detention and pool groups are required by the cases that claim rules about them; node and proof
consumers may declare a narrower set of optional groups and report the rest unsupported.

## Features by profile

| Feature | state-transition | transaction-validation | block-import | block-build | stateless-block |
| --- | --- | --- | --- | --- | --- |
| deposit | yes | yes | (inside blocks) | yes | (inside blocks) |
| synthetic-transaction | yes | — | — | — | — |
| salt | yes | — | yes | yes | yes |
| oracle-transcript | yes | — | — | yes | — |
| injected-faults | yes | — | yes | yes | — |
| sparse-state | yes | yes | yes | yes | — (always witness) |
| schedule | — | — | yes | yes | yes |
| raw-chain-config | — | — | yes | yes | yes |
| proof-attachment | — | — | — | — | yes |

## Conformance lanes

A consumer's report names its lane, the manifest digest, the subset it ran and its declared
capabilities. Recommended lanes:

| Lane | Profiles | Required groups and features |
| --- | --- | --- |
| Engine conformance | state-transition, transaction-validation | every group and feature of those profiles |
| Node import | block-import, transaction-validation | mandatory groups, salt, injected-faults, schedule, raw-chain-config |
| Builder | block-build | mandatory groups, salt, oracle-transcript |
| Stateless | stateless-block | mandatory groups, salt; proof-attachment for the proof shard |

A lane that lacks a capability its cases require fails that lane; it may run a narrower lane
instead, and says so.
