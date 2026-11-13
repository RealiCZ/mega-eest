# Specification decisions fixtures depend on

The specification's owner resolved its open questions in `plan/decisions.md` of the
specification repository. Fixture expectations follow the pinned rule text, not this log, but the
log explains why a rule reads as it does and which disagreements between implementations it
settled. A reviewer approving an expectation that touches one of these items should read the
decision.

Source: `plan/decisions.md` at `cac999a7123d20bb801be98aed03cefecaaf8aea`, SHA-256
`f4e0475dd71ea18bdd5311e9041e4284eb036e95c7809b7a185792b94693c5cd` of its bytes. Items are
cited by their id; the summaries below are this suite's, and the log's own wording governs.

Column "Fixtures" says what the decision means for cases: **expect** (it fixes an expected
observation), **input** (it constrains a valid input), **scope** (it removes something from what
fixtures may assert), or **none**.

## Questions (QA to QH)

| Id | Decision, in brief | Rules | Fixtures |
| --- | --- | --- | --- |
| QA-01 | What a tracer or inspector is shown is outside the specification | `SATIN-OUT-017` | scope: no inspector or trace field is an expectation |
| QA-02 | The specification names no halt reason | `SATIN-OUT-018` | scope: `execution.status` is `halt` with no reason |
| QA-03 | Which transactions are refused is fixed, not which error names a multiply-failing one; Satin's own check order stays normative | `SATIN-VAL-003` | expect: `reasons` lists every reason the specification allows |
| QA-04 | The bucket mapping is SALT's own definition, an input like the capacities | `SATIN-STATE-010` | input: `salt.mapping` names the mapping |
| QA-05 | `SLOTNUM` pushes zero and stays a volatile read | `SATIN-BASE-005` | expect |
| QA-06 | No per-frame cap beyond the frame budgets | `SATIN-LIM-009` | expect |
| QA-07 | A deposit envelope carrying a gas price is malformed and outside the specification | — | scope: no expectation for such an envelope beyond its refusal at decoding |
| QA-08 | A creation transaction whose sender nonce cannot be bumped creates nothing | `SATIN-LIM-015` | expect |
| QA-09 | The due-change predicate is stated at the storage level | `SATIN-PBLK-004` | expect: witness and reads carry those slots |
| QA-10 | Every Rex-era rule both implementations keep is restated as Satin's | — | none: Satin cases cite Satin ids only |
| QB-01 | The schedule's second half-check is dropped | — | scope |
| QB-02 | The executor derives deposit-only blocks from the schedule and parent timestamp | `SATIN-ACT-010` | expect: block profiles assert the derived flags; only engine isolation takes them as inputs |
| QC-01 | The activation block's predeploy check stays | `SATIN-ACT-005` | expect |
| QC-02 | Transaction limits, frame share and detention caps are protocol values | `SATIN-LIM-017`, `SATIN-DET-013` | input: chain-conformance cases use production values; overrides belong to a non-conformance lane ([decisions](decisions.md), D-11) |
| QC-03 | A creation whose created address is the beneficiary is not detained from its start | `SATIN-DET-006`, `SATIN-DET-008` | expect |
| QC-04 | With EIP-3607 disabled, keyless step 9 neither loads nor refuses the signer's code | `SATIN-KEY-005` | expect; disabled EIP-3607 is a simulation configuration, not a block input |
| QC-05 | A precompile address runs as the precompile whatever code it holds | `SATIN-PCMP-008` | expect |
| QC-06 | The chain configuration's consensus parts are in the specification | — | input: block profiles carry the schedule; malformed configurations use `rawConfig` |
| QD-01 | Every authority passing the chain-id, nonce and signature gates is loaded by the list simulation; no short-list fast path | `SATIN-AUTH-001`, `SATIN-AUTH-005`, `SATIN-WIT-004` | expect: reads include every such authority |
| QE-01 | ModExp charges its formula price, then checks EIP-7823's bound | `SATIN-PCMP-007`, `SATIN-DET-023` | expect |
| QE-02 | A deposit failing before its first frame loads nothing of its recipient | — | expect: reads |
| QE-03 | A prestate where a deposit's balance plus mint overflows is invalid and outside the specification | — | input: such prestates are not valid fixtures |
| QF-01 | Satin succeeds Rex6; there is no Rex7 | — | input: the schedule ladder |
| QF-02 | The section's place, groups and file names as laid out | — | none |
| QF-03 | Every Satin page is marked `spec: Satin`, `maturity: unstable` | — | none: the descriptor records the maturity |
| QF-04 | The draft is frozen until the section is written, then becomes the informative delta | — | none: fixtures cite the section, never the draft |
| QF-05 | Short glossary entries | — | none |
| QF-06 | A spec never changes earlier blocks; contracts keep working | — | expect: historical cases keep their spec |
| QF-07 | No Satin reference implementation is named | — | scope: two engines agreeing is evidence, never the definition |
| QF-08 | Each rule has one home; gathering pages link the detail | — | none: one registry entry per id |
| QF-09 | The rule-id scheme is adopted | — | input: a case's `rules` cite these ids |
| QG-01 | Every EIP-8037 rule an outcome depends on is restated, the EIP cited for provenance | — | none |
| QG-02 | Each applied EIP is pinned to a commit | — | none |
| QG-03 | Current values are written | — | expect: values may change with a new spec digest |
| QG-04 | Implementation-specific statements are restated as behaviour | — | scope |
| QG-05 | Node-integrator parts that decide consensus are in the specification; pool and RPC behaviour is not | — | scope: no RPC or pool fixture |
| QG-06 | Executions outside a block are node documentation; `SATIN-LIM-018` retired | `SATIN-LIM-018` | scope: no call or estimate fixture |
| QG-07 | Each of the nine EIPs is pinned at its revision current at the EIP-8037 freeze `dbc6d457cb` | `SATIN-SCHED-001`, `SATIN-POOL-020`, `SATIN-LOG-001`, `SATIN-PCMP-003`, `SATIN-BASE-004`, `SATIN-BASE-005` | expect |
| QH-01 | Every give-back of state or history gas except the destruction table's goes to the frame that makes it, in the refill order of `SATIN-HIST-012` | `SATIN-HIST-007`, `SATIN-HIST-012`, `SATIN-POOL-014` | expect: checkpoints and pools |
| QH-02 | Authority newness uses leaf existence; every other new-account charge uses EIP-161 emptiness | `SATIN-STATE-011`, `SATIN-ACCT-015`, `SATIN-WIT-017` | expect: absent and present-empty accounts are different pre-states |
| QH-03 | Every give-back credits the reservoir of the frame that makes it; a flat legacy share is charged to regular gas first | `SATIN-HIST-012`, `SATIN-POOL-012`, `SATIN-POOL-014`, `SATIN-STATE-012`, `SATIN-POOL-022` | expect: pools, ledgers, checkpoints |

## Rex6 parity (QI)

| Id | Decision, in brief | Rules | Fixtures |
| --- | --- | --- | --- |
| QI-01 | Oracle values are persisted by a Mega System Transaction before the reading transaction; validators run no service and read the slot; no record of answers beside the block; a transaction is left out only when no value written before it reproduces all its reads | `SATIN-ORCL-012`, `SATIN-ORCL-013`, `SATIN-ORCL-002`; `SATIN-WIT-015` retired | input: the oracle transcript is an engine-isolation input only (`state-transition`, `block-build`); block-import and stateless-block carry none ([decisions](decisions.md), D-05) |
| QI-02 | In the deposit-only activation block the node asks the oracle nothing | `SATIN-ORCL-005`, `SATIN-BASE-008` | expect |
| QI-03 | Rex6's per-block system-contract deployment is Satin's; Satin may be active from genesis | `SATIN-SYSC-003`, `SATIN-REG-008`, `SATIN-REG-009`, `SATIN-ACT-012`, `SATIN-PBLK-003`, `SATIN-ACT-005`; `SATIN-ACT-006` retired | input: Satin cases may start from a Satin genesis; pre-block steps are executed, never seeded invisibly |
| QI-04 | The Oracle prose follows its bytecode; no new restriction | `SATIN-ORCL-011`, `SATIN-BASE-008`, `SATIN-ORCL-002` | expect |
| QI-05 | `sendHint` is admitted without a value condition | `SATIN-ORCL-006`, `SATIN-ICPT-003` | expect: hints |
| QI-06 | An Oracle `SLOAD` with too little gas still loads, asks and marks the read | `SATIN-ORCL-004`, `SATIN-DET-003`, `SATIN-WIT-012` | expect: reads, detention |
| QI-07 | The timestamp snapshot is above the parent's and never below an earlier one | `SATIN-HPTS-001` | expect |
| QI-08 | A refused volatile read costs nothing; always-volatile opcodes are refused before operand checks | `SATIN-MAC-003`, `SATIN-MAC-004` | expect |
| QI-09 | `keylessDeploy` arguments are decoded before recognition | `SATIN-ICPT-006`, `SATIN-KEY-005/step-3` | expect |
| QI-10 | The live system address is resolved once per block after the pre-block steps; no transaction reads the registry for its classification | `SATIN-REG-002`; `SATIN-REG-003`, `SATIN-SCHED-013` retired | expect: reads attribute the registry read to the pre-block step |
| QI-11 | An absent registry, foreign code, or no system address makes the block invalid | `SATIN-REG-004` | expect: block-import failure (see the invalid-block example) |
| QI-12 | Mega System Transactions are held to the block budgets and building policy; deposits stay exempt | `SATIN-BLK-003`, `SATIN-BLK-006`, `SATIN-BLK-007`, `SATIN-BLK-011`, `SATIN-BLK-013` | expect: block-build decisions |
| QI-13 | Deposits and Mega System Transactions pay history gas; pre-block system calls are exempt; system work keeps minimum-bucket pricing | `SATIN-HIST-016`, `SATIN-HIST-022`, `SATIN-MST-008`, `SATIN-MST-010`, `SATIN-DEP-001`, `SATIN-TAKE-012` | expect: ledgers |
| QI-14 | Satin follows its Optimism base forks with their whole rule set | `SATIN-BASE-001` | input: inherited cases cite `SATIN-BASE-001` plus the upstream reference |
| QI-15 | The L1 block contract is read on demand; every slot a fee computation reads is in the witness | `SATIN-WIT-011`, `SATIN-WIT-003`, `SATIN-PBLK-003`, `SATIN-BASE-010` | expect: reads, witness |
| QI-16 | Kept Satin changes from Rex6, each stated as a change with its reason | various | expect |
| QI-17 | Every Rex6 defect Satin fixes is labelled in the page's Rationale | — | none: such inputs make good regression cases for the Rex6 slice and Satin |
| QI-18 | The SequencerRegistry layout is append-only after slot 13; a configuration scheduling Satin climbs the whole Mega spec ladder | `SATIN-REG-001`, `SATIN-ACT-011` | input: schedules list every rung |
