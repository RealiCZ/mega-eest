# The vertical slice

112 `state-transition` cases of Satin, run on both Satin implementations by `tools/run-slice.sh`:
63 at specification commit `d34e626` (`specs/satin-d34e626`), 15 for interception, the
keylessDeploy decoder and EIP-7702 existence at `d334ef8` (`specs/satin-d334ef8`), 20 for the
edges of the charge-order principles, 5 for gas detention, 5 for the stops of a transaction's own
frame and 2 that observe the gas pools at `5fb2688` (`specs/satin-5fb2688`), and 2 for the
take-back page's worked examples at `cdded1e` (`specs/satin-cdded1e`), each case naming its own
spec (decisions D-54, D-59, D-60, D-62, D-64, D-65). The cases whose expected `limit` is a stop are schema 1.1; every other case is
1.0. They are reviewed candidates: `provenance.status` is `candidate` until
the owner approves them.

Every file here is written by `tools/make_slice.py` (`--check` verifies it), and every figure in a
case's text that depends on a constant of the specification is written from that constant
(`tools/check_derived_text.py` checks it, D-57). Each case is
authored there — its setup, its transaction as real signed bytes or a deposit envelope, the SALT
capacities its state lands in — and its expectation is derived by `tools/satin_model/`, an
executable restatement of the cited rules that shares no code with either implementation. No
implementation's output is copied into a case: the filler's candidates are compared with the
derivation, and the two implementations run against it.

## What a case records

- `rules` and `assertions`: one assertion per observation group the derivation reached, citing
  the rules its steps applied.
- `provenance.derivation`: for each assertion path, the steps in order, with their arithmetic.
- `provenance.review.ruleTexts`: the text digest of every cited rule, so a review is tied to the
  exact rule text; `provenance.authoring.intent` and `boundary`: what the case tests.
- `provenance.transaction`: a decoded view of the transaction bytes, a review aid only.

## The cases

| Area | Cases | What they distinguish |
| --- | --- | --- |
| `intrinsic` | 9 | intrinsic regular gas (`SATIN-SCHED-006`), the body's history (`SATIN-HIST-003`, `-004`), the floor and the block's figure (`SATIN-SCHED-005`, `SATIN-POOL-020`), calldata, access lists, a transaction to its own sender |
| `value-transfer` | 7 | the start record before the frame (`SATIN-HIST-005`), transfer logs (`SATIN-LOG-001`, `-006`), a new recipient's state gas without legacy share (`SATIN-SCHED-008`, `SATIN-POOL-024`) at two multipliers, a reverted transfer, fees |
| `sstore` | 16 | every SSTORE transition priced at Satin's schedule (`SATIN-SCHED-003`, `-004`), fresh-slot state gas and its legacy share (`SATIN-STATE-001`, `-008`, `-012`) at four multipliers and with a reservoir, refunds and the spec's own worked example (`SATIN-POOL-019`), write records and state growth (`SATIN-ACCT-004`, `-016`) |
| `logs` | 6 | log history bytes (`SATIN-HIST-002`, `-006`) and data size, log order with transfer logs |
| `outcomes` | 9 | revert and halt settlement (`SATIN-POOL-014`, `-017`, `SATIN-OUT-007`), give-backs into the reservoir (`SATIN-HIST-012`), out of gas at a state charge, a halt with a reservoir |
| `creation` | 6 | the created account's charges before the frame, code deposit (`SATIN-SCHED-011`, `SATIN-STATE-003`), a reverted creation, a slot written by initcode |
| `validation` | 11 | refusals in the order of `SATIN-VAL-003` (intrinsic gas, floor, the body's history), chain id (`SATIN-VAL-006`), the base layer's checks (`SATIN-VAL-007`) and a gas limit above the block's (`SATIN-BLK-009`, `-013`: a refusal at inclusion, D-50) |
| `interception` | 10 | interception before the frame start, the funds check included (`SATIN-ICPT-007`): a contract's value `sendHint` its caller can and cannot fund (`SATIN-ORCL-006`, `-009`, `SATIN-OUT-010`, `SATIN-LIM-015`), a hint over the data-size limit, and a hint landing exactly on it against one byte over (`SATIN-ORCL-010`), MegaAccessControl's and MegaLimitControl's `NonZeroTransfer()` funded or not (`SATIN-ICPT-003`), and the transaction's own value `keylessDeploy` (`SATIN-KEY-018`) |
| `keyless` | 4 | the decoder set of `SATIN-ICPT-006`: unpadded bytes, an offset into the head and offset zero are recognized and refused at step 3; one byte short is not recognized, and KeylessDeploy's bytecode reverts without the overhead |
| `authorizations` | 2 | an EIP-7702 authority present as an empty leaf exists (`SATIN-STATE-011`, `SATIN-AUTH-008`, `SATIN-ACCT-015`): the indicator's state gas alone; an absent one is new |
| `call-order` | 9 | the order around a frame start (`SATIN-HIST-023`): a caller that cannot pay a funded value call's records halts in the opcode, before any interceptor answers or hint is admitted, one gas below the threshold and at it, forwarding all it may or nothing (`SATIN-HIST-009`, `SATIN-ICPT-007`); a value its caller cannot fund makes no record (`SATIN-HIST-015`), and the refused or answered start returns the child's whole regular gas, the stipend included (`SATIN-POOL-012`), which `GAS` shows (`SATIN-POOL-009`) |
| `delegated-recipient` | 6 | the delegate's access before the first frame (`SATIN-SCHED-008` step 5): warm, cold, against the same account without its delegation, one gas short of the cold access (out of gas before the first frame, `SATIN-SCHED-009`, `-010`) and exactly at it, and a transaction to its own delegated sender |
| `detention` | 5 | one charge under gas detention (`SATIN-DET-018`): a detained child frame whose spendable part cannot pay `BALANCE`'s static cost is stopped with `MegaLimitExceeded(2, limit)` when its whole regular gas can pay it and runs out of gas when it cannot (`SATIN-DET-020`); the spendable part one below the static cost and at it, the static cost staying spent once paid; a value `CALL` stopped at its value transfer after its static cost |
| `limit-stops` | 5 | a stop of the transaction's own frame, its result (`SATIN-STOP-009`, `-021`), settled as a revert: gas detention's crossing at one memory expansion and at `BALANCE`'s static cost (kind 2); the fresh slot that takes the frame's state growth past its budget (kind 3, `SATIN-LIM-002`, `-010`); and, after hints used what the transaction had left, a log one byte past the transaction's data-size limit while the frame's budget holds it (kind 0, `SATIN-LIM-011`, `-012`), with the log that lands exactly on the limit |
| `gas-pools` | 2 | the first frame's pools observed directly (`gasPools`, D-64): a plain transfer as the control, and a fresh slot whose state gas a small reservoir pays in part, regular gas paying the legacy share, the rest and the record (`SATIN-POOL-008`) |
| `take-backs` | 2 | the worked examples of the take-back page (`SATIN-TAKE-005` to `-012`), one case each, of which these two gate: a list whose two entries for one absent authority delegate and then clear (`SATIN-TAKE-008`, `SATIN-AUTH-009`), and a value round trip whose earlier transfer turns the signs, the second start's records charged to a caller left too little regular gas, which runs out of gas (`SATIN-TAKE-006`, `SATIN-HIST-009`); the other fourteen are quarantined below |
| `pre-frame` | 3 | the reservoir pays the authorities' records first (`SATIN-HIST-005`), shown by a first frame that halts; the transaction's own start record charged before interception answers its `keylessDeploy` call, one gas below step 1's overhead and at it |

The `value-transfer` area also holds the contrast to the authority: a value recipient present as an
empty leaf is new under EIP-161. Each case of the `interception`, `keyless` and `authorizations`
areas, and each case of the last three areas that calls a system contract, holds the code of the
system contracts a call can reach (D-55).

121 rules in 19 areas are cited. `index.json` lists each case with its area, rules and file digest.

## Quarantine and the wrong expectation

- `quarantine/`: thirty-nine cases the revm-based implementation fails against a decided rule it
  has not made yet, each passing on the evm2-based implementation:
  - four deposit cases. `SATIN-HIST-016` and `SATIN-DEP-001` make a deposit pay history gas for its
    body, its logs and its write records; the revm-based implementation charges none. The
    verdicts of the first three name the build they were first recorded against, `5e3f30ad`; all
    four fail the same way at the pin, `4e39cfd6`.
  - six cases that store `GAS` after a give-back: of the history a funded value call's records were
    charged when an interceptor answers it or a hint's data-size stop replaces it, of a refused
    start's new-account state gas, and of a fresh slot written back to zero. `SATIN-HIST-012`
    credits every give-back to the frame's reservoir, which `GAS` does not read
    (`SATIN-POOL-009`); the revm-based implementation at `4e39cfd6` credits it to regular gas.
  - three deposits whose call to the Oracle's `getSlot` reaches its `SLOAD` short of the warm base,
    short of the cold access, or detained at the crossing. `SATIN-ORCL-004` reads the slot and marks
    the read before one charge of the cold access; the revm-based implementation charges the warm
    base first and skips the read, so it marks nothing, or crosses on the warm base. A deposit's
    read asks no oracle service (`SATIN-ORCL-005`), which is why these cases are deposits.
  - two refused reads of the block beneficiary's balance in a frame whose volatile-data access is
    off. `SATIN-MAC-003` and `SATIN-MAC-004` refuse it before any charge; the revm-based
    implementation charges the static cost first, and runs out of gas when the frame cannot pay
    it.
  - seven cases that carry `reads` (D-61): a two-entry EIP-7702 list that runs out of gas at its
    first entry and the same list applied, both authorities loaded by the list's simulation
    (`SATIN-AUTH-005`); a delegate not loaded when its cold surcharge cannot be paid and loaded
    when it can (`SATIN-SCHED-008`); a cold `BALANCE` whose access cannot be paid, which loads
    nothing, and one whose access is paid (`SATIN-WIT-012`); and a deposit's Oracle slot, loaded
    before its charge (`SATIN-ORCL-004`). The revm-based implementation reads the
    SequencerRegistry in every transaction's validation, which `SATIN-REG-002` excludes, and its
    reads differ at the registry's account; the list case also lacks its second authority, and the
    deposit its Oracle slot and its history.
  - three cases that observe the gas pools (D-64): an answered value call whose records' history
    and a fresh slot written back to zero whose state and history gas are given back, where the
    revm-based implementation credits the give-back to regular gas (`SATIN-HIST-012`), and a fresh
    slot under a large reservoir, where it draws no legacy share from regular gas
    (`SATIN-STATE-012`, `SATIN-POOL-008`).
  - fourteen of the take-back page's worked examples (D-65): a slot's record another frame takes
    back by `DELEGATECALL` (four endings); a value round trip, after a nonce bump, and with its
    signs turned by an earlier transfer, the second start paid; a creation destroyed with no balance
    and to a new beneficiary; a log in a reverted child and in a value call's child whose allowance
    pays it; a value start answered without a frame that crosses its frame budget; and a child with
    a reservoir share that reverts or halts. The first frame's
    pools show where each give-back lands: `SATIN-HIST-012` and `SATIN-POOL-014` put it in a
    reservoir; the revm-based implementation credits it to regular gas, and, where a frame halts,
    its spill counter drops what the halted frame paid.

  The expectation is the rule's; the cases stay out of the gating slice until that implementation
  is fixed, and `tools/run-slice.sh` checks that each still fails exactly as `index.json` records
  (path and both values) and passes on the other implementation.
- `negative/`: a fresh-slot case with its state ledger one above the derivation. Every consumer
  must fail it at `/expected/gasLedgers/state`, and consuming it rewrites nothing.

## Not in this slice

A stop's diagnostics (scope, call path, operation, phase and commit flags, which neither
implementation's result carries, D-62), a stop of the KV-update limit (half a million write
records cost more gas than a transaction holds; for the same reason the answer-stopped example's KV
budget of 3 is pinned on the state-growth budget instead, D-65), gas detention beyond `TIMESTAMP`, a
deposit's Oracle read and `BALANCE`, frames and creations beyond the shapes the take-back examples
build (D-65), EIP-7702 lists beyond one accepted entry, two applied ones or one authority's
delegation and clear, an Oracle read that asks the oracle service (the evm2-based adapter runs no
oracle transcript), a gating case with `reads` (the revm-based implementation reads the
SequencerRegistry in every transaction, D-61), the failed-deposit example (both implementations
report its floor as 0, D-65), and every block, building and witness profile: they need
observations or consumers the next phases add.

## Running it

```bash
bash tools/run-slice.sh
```

builds the format CLI and both adapters (fetching the evm2-based implementation into `vendor/`),
consumes `cases/` with each adapter plain and instrumented, and prints

```text
SLICE cases=112 adapters=2 pass=224 fail=0 unsupported=0 error=0 digests=identical
PARITY adapters=2 cases=112 mismatches=0
NEGATIVE wrong-expected verdict=fail rewritten=no
```
