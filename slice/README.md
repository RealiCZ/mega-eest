# The vertical slice

63 `state-transition` cases of Satin at specification commit `d34e626` (`specs/satin-d34e626`),
run on both Satin implementations by `tools/run-slice.sh`. They are reviewed candidates:
`provenance.status` is `candidate` until the owner approves them.

Every file here is written by `tools/make_slice.py` (`--check` verifies it). Each case is
authored there — its setup, its transaction as real signed bytes or a deposit envelope, the SALT
capacities its state lands in — and its expectation is derived by `tools/satin_model.py`, an
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
| `value-transfer` | 6 | the start record before the frame (`SATIN-HIST-005`), transfer logs (`SATIN-LOG-001`, `-006`), a new recipient's state gas without legacy share (`SATIN-SCHED-008`, `SATIN-POOL-024`) at two multipliers, a reverted transfer, fees |
| `sstore` | 16 | every SSTORE transition priced at Satin's schedule (`SATIN-SCHED-003`, `-004`), fresh-slot state gas and its legacy share (`SATIN-STATE-001`, `-008`, `-012`) at four multipliers and with a reservoir, refunds and the spec's own worked example (`SATIN-POOL-019`), write records and state growth (`SATIN-ACCT-004`, `-016`) |
| `logs` | 6 | log history bytes (`SATIN-HIST-002`, `-006`) and data size, log order with transfer logs |
| `outcomes` | 9 | revert and halt settlement (`SATIN-POOL-014`, `-017`, `SATIN-OUT-007`), give-backs into the reservoir (`SATIN-HIST-012`), out of gas at a state charge, a halt with a reservoir |
| `creation` | 6 | the created account's charges before the frame, code deposit (`SATIN-SCHED-011`, `SATIN-STATE-003`), a reverted creation, a slot written by initcode |
| `validation` | 11 | refusals in the order of `SATIN-VAL-003` (intrinsic gas, floor, the body's history), chain id (`SATIN-VAL-006`), the base layer's checks (`SATIN-VAL-007`) and a gas limit above the block's (`SATIN-BLK-009`, `-013`: a refusal at inclusion, D-50) |

55 rules in 11 areas are cited. `index.json` lists each case with its area, rules and file digest.

## Quarantine and the wrong expectation

- `quarantine/`: three deposit cases. `SATIN-HIST-016` and `SATIN-DEP-001` make a deposit pay
  history gas for its body; the evm2-based implementation does, the revm-based implementation at
  `5e3f30ad` charges none. The expectation is the rule's; the cases stay out of the gating slice
  until that implementation is fixed, and `tools/run-slice.sh` checks that each still fails exactly
  as `index.json` records (path and both values) and passes on the other implementation.
- `negative/`: a fresh-slot case with its state ledger one above the derivation. Every consumer
  must fail it at `/expected/gasLedgers/state`, and consuming it rewrites nothing.

## Not in this slice

Limit stops (neither implementation's result carries what the `limit` group needs, D-41), gas
detention, nested frames, EIP-7702 authorizations, oracle reads, and every block, building and
witness profile: they need observations or consumers the next phases add.

## Running it

```bash
bash tools/run-slice.sh
```

builds the format CLI and both adapters (fetching the evm2-based implementation into `vendor/`),
consumes `cases/` with each adapter plain and instrumented, and prints

```text
SLICE cases=63 adapters=2 pass=126 fail=0 unsupported=0 error=0 digests=identical
PARITY adapters=2 cases=63 mismatches=0
NEGATIVE wrong-expected verdict=fail rewritten=no
```
