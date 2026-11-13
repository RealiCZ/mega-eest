# The vertical slice

220 `state-transition` cases of Satin, run on both Satin implementations by `tools/run-slice.sh`:
63 at specification commit `d34e626` (`specs/satin-d34e626`), 15 for interception, the
keylessDeploy decoder and EIP-7702 existence at `d334ef8` (`specs/satin-d334ef8`), 20 for the
edges of the charge-order principles, 5 for gas detention, 2 for the refused volatile read, 5 for
the stops of a transaction's own frame and 2 that observe the gas pools at `5fb2688`
(`specs/satin-5fb2688`), and 2 for the take-back page's worked examples, 28 for the destruction
page's own rules, 54 for gas detention's rules and 24 for the limit-stop page's rules at `cdded1e`
(`specs/satin-cdded1e`), each case naming its own spec (decisions D-54, D-59, D-60, D-62, D-64,
D-65, D-66, D-67, D-70, D-73, D-74, D-77). Every
case is schema 2.0 (D-76). They are reviewed candidates: `provenance.status` is `candidate` until
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

Each case is the file `<group>/<caseId>.json`: `cases/satin/<area>/.../<case>.json` for a gating
case, `quarantine/satin/<area>/.../<case>.json` for a quarantined one and
`negative/satin/negative/...` for the wrong expectation (D-76). A case holds:

- `input` and `expected`, what a consumer runs and compares, and `requires`;
- `rules`: the rules the case pins, the rules its derivation applied that are in its area's scope
  or that its definition names (`AREA_SCOPE` in `tools/make_slice.py`, D-76). The rules every
  transaction's derivation applies — the intrinsic cost, the body's history, the pools, the
  ledgers, the receipt, the limits — are pinned only by the areas that test them;
- `provenance`: `status`, the `generator`, the `definition` the case comes from (the function of
  `tools/make_slice.py` that defines it), the `specCommit` it was derived at, its
  `authoring.intent` and `boundary`, what the case tests, and, for a quarantined case, its
  `quarantine` record.

A case's derivation is not stored. `python3 -I tools/make_slice.py --explain <caseId>` derives it
again and prints, as JSON, the steps of every observation group in order with their arithmetic and
the rules each applies, every rule the derivation applied with its text digest, so a review is tied
to the exact rule text, the decoded transaction, and the case's pins and its area's scope.

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
| `detention` | 59 | one charge under gas detention (`SATIN-DET-018`): a detained child frame whose spendable part cannot pay `BALANCE`'s static cost is stopped with `MegaLimitExceeded(2, limit)` when its whole regular gas can pay it and runs out of gas when it cannot (`SATIN-DET-020`); the spendable part one below the static cost and at it, the static cost staying spent once paid; a value `CALL` stopped at its value transfer after its static cost. And gas detention's rules at `cdded1e` (D-67), each at its edge: what is volatile — `BLOCKHASH` whatever its operand (`SATIN-DET-004`), the other reads of the block environment and of the beneficiary's account (`SATIN-DET-001`), a call to the EIP-2935 history contract only where its code completes `NUMBER` (`SATIN-DET-005`), the beneficiary's own `SELFBALANCE` (`SATIN-DET-007`) — and what is not: `BLOBHASH` (`SATIN-DET-002`), other accounts, a creation onto the beneficiary (`SATIN-DET-006`); a transaction detained from its start by its sender, recipient or authority (`SATIN-DET-008`); the limit at the cap exactly, after a larger spend, under a second read, after a spill and after a give-back (`SATIN-DET-009`, `-012`, `-013`), and with a stipend's work (`SATIN-DET-010`); the readers of the whole regular gas, the settlement and the withheld part drawn first (`SATIN-DET-015` to `-017`); a precompile decided from its price, at and one past the allowance and the forward, with value, unfunded, ModExp over EIP-7823's bound and a BN254 pairing over its size limit (`SATIN-DET-021` to `-024`); a user's deposit (`SATIN-DET-026`) |
| `access-control` | 2 | a volatile read refused in a frame whose volatile-data access is off (`SATIN-MAC-003`, `-004`): a `BALANCE` of the block beneficiary after `disableVolatileDataAccess()` reverts the frame with `VolatileDataAccessDisabled(10)` before any charge, on the gas it held at the opcode, and is refused all the same when the frame cannot pay its static cost |
| `limit-stops` | 29 | a stop of the transaction's own frame, its result (`SATIN-STOP-009`, `-021`), settled as a revert: gas detention's crossing at one memory expansion and at `BALANCE`'s static cost (kind 2); the fresh slot that takes the frame's state growth past its budget (kind 3, `SATIN-LIM-002`, `-010`); and, after hints used what the transaction had left, a log one byte past the transaction's data-size limit while the frame's budget holds it (kind 0, `SATIN-LIM-011`, `-012`), with the log that lands exactly on the limit; and the page's other rules (D-73): a child stopped by the transaction's data-size limit or by its state-growth budget, whose caller catches the stop, its counts discarded, and is held to what is left, exactly or one unit past (`SATIN-STOP-005` to `-008`); a take-back's room filled by a hint in a frame that succeeds, reverts, halts or is stopped, the failure leaving the caller to return the data-size stop (`SATIN-STOP-006`); a value call's and a creation's start held to what it kept before the frame runs, the creator keeping its nonce bump and record (`SATIN-STOP-013`, `-015`); a log's regular charge paid (the stop) or one gas short (a halt); a value call one gas short of its start record (no stop); a stopped deposit settled as a revert (`SATIN-STOP-002`, `-003`, `-010`, `-019`); an EIP-7702 list one authority past the state-growth limit, skipped (`SATIN-STOP-017`); a contract's revert with a stop's bytes and a caller re-raising a caught stop, no stop (`SATIN-STOP-020`, `-021`); a stop above the execution cap; and a budget three calls deep |
| `gas-pools` | 2 | the first frame's pools observed directly (`gasPools`, D-64): a plain transfer as the control, and a fresh slot whose state gas a small reservoir pays in part, regular gas paying the legacy share, the rest and the record (`SATIN-POOL-008`) |
| `take-backs` | 2 | the worked examples of the take-back page (`SATIN-TAKE-005` to `-012`), one case each, of which these two gate: a list whose two entries for one absent authority delegate and then clear (`SATIN-TAKE-008`, `SATIN-AUTH-009`), and a value round trip whose earlier transfer turns the signs, the second start's records charged to a caller left too little regular gas, which runs out of gas (`SATIN-TAKE-006`, `SATIN-HIST-009`); the other fifteen are quarantined below |
| `selfdestruct` | 28 | the destruction page's own rules (D-70): a destruction of an account the transaction did not create moves the balance, writes the account it clears and its beneficiary, and applies no table (`SATIN-SD-001`, `-012`), to an existing, a new, a changed or the sending account, to itself, with no balance, at a bucket multiplier of 2 and under a reverting caller; the first effective destruction of an account created in the transaction (`SATIN-SD-002`), at an absent address and at one whose leaf the state holds with storage, which does not collide, keeps its leaf's charge and reads its slots as zero (`SATIN-SD-003`, `-016`, `-017`), in its constructor and after a slot restored to zero; a repeated destruction that applies the table for nothing (`SATIN-SD-011`); the marked account, whose stores pay their regular gas and no state gas (`SATIN-SD-013`, on little gas against the unmarked control), whose code deposited after the mark keeps no state gas (`SATIN-SD-014`), and which keeps its logs and is removed with a value sent to it (`SATIN-SD-015`); a mark discarded by a frame that reverts or halts (`SATIN-SD-010`); and the read of a destruction's beneficiary, the block beneficiary, marked once the destruction completed and not when it halts in its charges (`SATIN-SD-020`); one more, the give-back kept as reservoir through a halting child, is quarantined below |
| `pre-frame` | 3 | the reservoir pays the authorities' records first (`SATIN-HIST-005`), shown by a first frame that halts; the transaction's own start record charged before interception answers its `keylessDeploy` call, one gas below step 1's overhead and at it |

The `value-transfer` area also holds the contrast to the authority: a value recipient present as an
empty leaf is new under EIP-161. Each case of the `interception`, `keyless` and `authorizations`
areas, and each case of the last three areas that calls a system contract, holds the code of the
system contracts a call can reach (D-55).

The gating cases pin 156 rules in 19 areas of the specification. `index.json` lists each case with
its area, the rules it pins, its file and its file digest.

## Quarantine and the wrong expectation

- `quarantine/`: forty-two cases the revm-based implementation fails against a decided rule it
  has not made yet, each passing on the evm2-based implementation. Each fails as recorded at the
  pin, `7110d87b`. A record names the revision it was made at: `4e39cfd6`, or `7110d87b` for the
  five the pin's move changed (D-77), and the first three deposits' `5e3f30ad` (D-53):
  - four deposit cases. `SATIN-HIST-016` and `SATIN-DEP-001` make a deposit pay history gas for its
    body, its logs and its write records; the revm-based implementation charges none. The
    verdicts of the first three name the build they were first recorded against, `5e3f30ad`; all
    four fail the same way at the pin, `7110d87b`.
  - six cases that store `GAS` after a give-back: of the history a funded value call's records were
    charged when an interceptor answers it or a hint's data-size stop replaces it, of a refused
    start's new-account state gas, and of a fresh slot written back to zero. `SATIN-HIST-012`
    credits every give-back to the frame's reservoir, which `GAS` does not read
    (`SATIN-POOL-009`); the revm-based implementation credits it to regular gas.
  - three deposits whose call to the Oracle's `getSlot` reaches its `SLOAD` short of the warm base,
    short of the cold access, or detained at the crossing. `SATIN-ORCL-004` reads the slot and marks
    the read before one charge of the cold access, which the revm-based implementation does at
    `7110d87b`: their regular ledger is the rule's. A deposit's read asks no oracle service
    (`SATIN-ORCL-005`), which is why these cases are deposits, and the deposit's history, which that
    implementation does not charge (`SATIN-HIST-016`), is their first difference.
  - seven cases that carry `reads` (D-61): a two-entry EIP-7702 list that runs out of gas at its
    first entry and the same list applied, both authorities loaded by the list's simulation
    (`SATIN-AUTH-005`); a delegate not loaded when its cold surcharge cannot be paid and loaded
    when it can (`SATIN-SCHED-008`); a cold `BALANCE` whose access cannot be paid, which loads
    nothing, and one whose access is paid (`SATIN-WIT-012`); and a deposit's Oracle slot, loaded
    before its charge (`SATIN-ORCL-004`). The revm-based implementation reads the
    SequencerRegistry in every transaction's validation, which `SATIN-REG-002` excludes, and its
    reads differ at the registry's account; the deposit's gas used also lacks its history. The
    list's simulation and the Oracle slot are the rule's at `7110d87b`.
  - three cases that observe the gas pools (D-64): an answered value call whose records' history
    and a fresh slot written back to zero whose state and history gas are given back, where the
    revm-based implementation credits the give-back to regular gas (`SATIN-HIST-012`), and a fresh
    slot under a large reservoir, where it draws no legacy share from regular gas
    (`SATIN-STATE-012`, `SATIN-POOL-008`).
  - fifteen of the take-back page's worked examples (D-65): a slot's record another frame takes
    back by `DELEGATECALL` (four endings); a value round trip, after a nonce bump, and with its
    signs turned by an earlier transfer, the second start paid; a creation destroyed with no balance
    and to a new beneficiary; a log in a reverted child and in a value call's child whose allowance
    pays it; a value start answered without a frame that crosses its frame budget; a child with a
    reservoir share that reverts or halts; and a failed deposit. The first frame's pools show where
    each give-back lands: `SATIN-HIST-012` and `SATIN-POOL-014` put it in a reservoir; the
    revm-based implementation credits it to regular gas, and, where a frame halts, its spill counter
    drops what the halted frame paid. The failed deposit's ledgers are `SATIN-DEP-005`'s, with floor
    and refund 0 (D-66); the revm-based implementation reports its history bytes, the body and
    calldata it keeps (`SATIN-HIST-022`), as 0.
  - one destruction case (D-70): a creation destroyed, whose give-back returns to its creator as
    reservoir (`SATIN-SD-005`, `SATIN-SD-010`), before the creator calls a child that halts. The
    revm-based implementation credits the give-back to regular gas, so the creator forwards most of
    it to the child, which burns it: its gas used is above the rule's, a difference no pool
    observation is needed to see.
  - two limit-stop deposits (D-74). A deposit whose own frame is stopped settles as a revert
    (`SATIN-STOP-010`) and keeps its body's history (`SATIN-HIST-016`), which the revm-based
    implementation does not charge; holding that history more regular gas, the same deposit one gas
    short of the crossing charge pays it and is stopped, where the rule's runs out of gas and fails
    (`SATIN-DET-020`).

  - one of gas detention's cases (D-68): a user's deposit, detained as `SATIN-DET-026` has it but
    charged no history gas for its body (`SATIN-HIST-016`). The ModExp input over EIP-7823's bound
    priced one past the allowance, which `SATIN-DET-023` and `-024` make the crossing, gates since
    the pin moved to `7110d87b` (D-77).

  The expectation is the rule's; the cases stay out of the gating slice until that implementation
  is fixed, and `tools/run-slice.sh` checks that each still fails exactly as `index.json` records
  (path and both values) and passes on the other implementation.
- `negative/`: a fresh-slot case with its state ledger one above the derivation. Every consumer
  must fail it at `/expected/gasLedgers/state`, and consuming it rewrites nothing.

## Not in this slice

A stop's diagnostics (scope, call path, operation, phase and commit flags, which neither
implementation's result carries, D-62), a stop of the KV-update limit (half a million write
records cost more gas than a transaction holds; for the same reason the answer-stopped example's KV
budget of 3 is pinned on the state-growth budget instead, D-65), gas detention's crossing at an
intercepted answer that spends regular gas (`SATIN-DET-025`), a node's own precompiles
(`SATIN-DET-027`), a system-originated transaction (`SATIN-DET-026`; the block resolves the system
address), the precompiles beyond the identity's run and the prices of ModExp and an over-size BN254
pairing (D-67) and a destruction's read of the block beneficiary, frames and
creations beyond the shapes the take-back examples and the destruction page's cases build (D-65,
D-70), a slot of an address the transaction accessed before creating onto it and a store after a
destruction's mark that moves the refund counter (D-72), EIP-7702 lists beyond one accepted entry, two applied ones or one authority's
delegation and clear, an Oracle read that asks the oracle service (the evm2-based adapter runs no
oracle transcript), a gating case with `reads` (the revm-based implementation reads the
SequencerRegistry in every transaction, D-61), and every block, building and witness profile: they
need observations or consumers the next phases add.

## Running it

```bash
bash tools/run-slice.sh
```

builds the format CLI and both adapters (fetching the evm2-based implementation into `vendor/`),
consumes `cases/` with each adapter plain and instrumented, and prints

```text
SLICE cases=220 adapters=2 pass=440 fail=0 unsupported=0 error=0 digests=identical
PARITY adapters=2 cases=220 mismatches=0
NEGATIVE wrong-expected verdict=fail rewritten=no
```
