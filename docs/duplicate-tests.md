# Duplicate tests

Each Satin implementation, (a) the revm-based one and (b) the evm2-based one, keeps tests of its
own. Many of them check a behaviour that a gating case of this suite also pins. This page is the
rule both implementations use to decide when such a test duplicates a case, what to record for the
decision, and what happens to a test that does not. This suite's case set is the one kept for the
long term: each behaviour is tested in one place.

## 1. What the suite tests

Given a pre-state, an environment and one transaction, a case states the result Satin requires of
the engine:

| Result | Where a case records it |
| --- | --- |
| Admission or refusal, by refusal class | `outcome.admission`, a refusal's `reasons` |
| The execution's result: success, revert or halt, and the return data | `outcome.execution` |
| The three gas ledgers: regular, state and history gas | `gasLedgers`; where the first frame's gas came from and went, `gasPools` |
| State changes | `state` |
| Resource use and the limit stops | `resources`, `limit` |
| Logs and the receipt | `receipt` |
| The logical reads the specification requires a node to keep for the witness | `reads` |
| Effects that bytecode can observe | what the case's own code returns or stores: `outcome.execution.output`, `state` |

The groups are those of [format.md](format.md#observations). The slice's cases are
`state-transition` cases: one transaction in engine isolation, run through each adapter's entry
point. What only block execution shows is outside them (category 2 below).

## 2. The unit and the decision question

### The unit: an obligation

The unit is an **obligation**: one behaviour that the old test can tell apart and that the
specification requires to be told apart. A test can carry several obligations. Each is judged on its
own, and different cases can take over different obligations of one test.

For each obligation, record:

- the entry point and the preconditions;
- the specification predicate that decides the result, quoting the rule's full text, and its table
  row where it has one;
- the test's assertion, and where the asserted value comes from;
- the gating case that takes it over, and the field of that case that would fail.

An obligation names a boundary, not a rule. "A keyless deployment whose available gas is one below
the signed gas limit at step 11, with a deploy address that holds code, is refused at step 11 and
never reads the deploy address" is an obligation (`SATIN-KEY-005/step-11`, `SATIN-KEY-005/step-12`,
`SATIN-KEY-006`, `SATIN-KEY-007`, `SATIN-WIT-012`). "Covers `SATIN-KEY-006`" is not.

### The decision question

> If an implementation got this boundary wrong, which gating case fails, in which field?

- A gating case is a case under `slice/cases/` at the suite revision the implementation's repository
  pins and runs in its CI. A quarantined case, a case the implementation's consumer waives as
  `known-fail`, and a case the consumer reports `unsupported` for its adapter gate nothing for that
  implementation: they point at evidence, they are not gates.
- The field must be in a group the case requires: the consumer ignores a group that a case does not
  require ([adapter-protocol.md](adapter-protocol.md#the-consumer-loop)).
- For the obligation above, the answer is `satin/keyless/refusal/step-11-before-taken`. An
  implementation that reads the deploy address before step 11 fails it in `reads.accounts`; one that
  makes step 12 first fails it in `outcome.execution.output`, which holds step 11's
  `GasLimitTooLow(uint64,uint64)`.
- A test goes into a deletion batch only when every obligation it carries has an answer, and the
  test carries no contract of the implementation's own interface (category 3).
- An error that shows only when two conditions hold together needs an assertion on exactly that
  combination. A keyless deployment that makes step 12 of `SATIN-KEY-005` before step 10 returns
  `ContractAlreadyExists()` instead of halting only when the call cannot pay step 10 and its deploy
  address holds code. With an empty deploy address it halts either way, and only its reads differ.

### What does not justify a deletion

A case that looks like the test does not take over an obligation when:

- **A parameter change removed the assertion's power.** The case differs from the test in an input
  that decides whether a wrong implementation fails. A case refused at step 9 of `SATIN-KEY-005`
  (`SignerHasCode()`) with a carried value of zero cannot catch an implementation that checks the
  signer's balance, step 13, first: no balance check fails. A test whose signer also cannot fund the
  value can.
- **The value comes from an adapter constant.** A field the adapter writes from its mapping, not
  from the implementation's result, tests the adapter. Both adapters write a deposit receipt's
  `depositReceiptVersion` as 1 and its `depositNonce` from the pre-state
  ([adapter-protocol.md](adapter-protocol.md#mapping-definitions)), so a case's receipt does not
  test the block's receipt builder.
- **The value comes from a later probe.** A probe the case makes afterwards can produce the observed
  value by another path. A `BALANCE` of a call's target at the end of the transaction loads the
  target again, so it hides an implementation that drops a refused call's completed read of its
  target from the witness (`SATIN-WIT-012`): the reads are the same set either way. That obligation
  needs a case in which nothing else loads the target.
- **The entry point is wrong.** The case reaches the behaviour through a different entry point from
  the one the test pins. A `state-transition` case runs one transaction in engine isolation: it does
  not take over a test of a path that only block execution takes (category 2), or of another entry
  point's own contract (category 3).

### The order of evidence

Weigh evidence in this order:

1. the rule's full text and its table rows;
2. the test's real inputs and assertions;
3. the case's input and expectation, the value the adapter reports for the field, and the
   comparator;
4. the gate at the suite revision the implementation's repository pins;
5. a proof over the whole deletion batch: with the batch deleted, no covered line is lost and no
   killed mutant survives.

Test maps, rule tags, line coverage and the agreement of the two implementations help find evidence.
None of them alone shows that a case and a test pin the same behaviour.

## 3. Dispositions

Every obligation falls into one of four categories:

| Category | Disposition | Notes |
| --- | --- | --- |
| 1. A single transaction's protocol behaviour | Delete the test once a gating case pins it. Where there is a gap, add the case to this suite first, then delete | Prefer strengthening an existing case to adding one; do not add a file for each old loop value, error variant or child-frame record. Test a child frame's forwarding and settlement through what its parent sees: the return value, success or failure, a balance, or whether a later charge can be paid. The ABI selectors and return arguments a contract can read, the precedence of conditions, the different treatment of the gas left at a halt and at a revert, and a stop the parent frame catches all belong here. A witness read is an obligation of its own: a refused path can leave the same state and receipt and still differ in its reads |
| 2. Protocol behaviour that needs block execution | Keep the test. Move it only after a replay of the `mega-evme` corpus runs the behaviour through the real entry point and its results are checked | The block budgets, the pre-block calls, effects across transactions, the block's receipt builder (`depositNonce`, for example), the merge of the block witness across transactions, and old rules replayed at historical heights |
| 3. Implementation, product and tool contracts | Keep, as the smallest targeted unit test | Interfaces, assembly, entry points, serialization and decoders; the inspector and tracer interfaces; internal invariants; product settings (overrides, how a default propagates, which entry points take a setting); fault handling; the factory's routing of historical forks; performance, `no_std` and ZK |
| 4. Differences a duplicate check can ignore | Delete the test; the suite does not change | The test differs only in a label of the same effect, or only in an internal trace or scaffolding, and its other obligations are covered. A halt's sub-reason is such a label (`SATIN-OUT-018`). So is the name of a refusal merged into one class, provided each input that could be wrongly accepted has its case: `chain-id-mismatch` refuses both a transaction signed for another chain (`satin/validation/chain-id-mismatch`) and a type-2 transaction carrying chain id 0 (`satin/validation/chain-id/fee-market-chain-zero`, `SATIN-VAL-006`) |

**Configured caps.** A test that borrows a smaller cap only to measure with can ignore the cap's
absolute value (category 4). It must be shown that the spendable gas, the gas withheld, the one
charge that crosses the limit and the stop bytes vary with the limit in the same way at the smaller
cap and at the protocol's. The caps are protocol values (`SATIN-LIM-017`), so a case uses the
protocol's. Where the configuration is itself a product contract, the test is category 3.

**Differential scenarios.** A differential scenario mixes three things: a targeted regression, the
framework's comparison of the whole record, and a name that probes refer to. Only the targeted
protocol effect that a case can tell apart moves to category 1. The framework and the probes that
refer to scenarios by name are category 3: they retire with the cross-implementation corpus, when
the two implementations are no longer compared.

## 4. One case for several variants

Variants of one behaviour, such as one refusal under different gas limits or one destruction after
different creations, can share a representative case only when they are shown to be the same in:

- when the charge is made;
- the branch reached;
- the pre-state;
- the effects observable afterwards.

If the gas left, the identity of an address, a rollback or the source of a read differs between
them, the variant gets its own case. A `CREATE2` ahead of a `SELFDESTRUCT` is not the same variant
as a `CREATE`: the sixth check of `SATIN-SIZE-005` makes it take a salt and pay the initcode's
hashing cost, which can move a gas crossing, and its address is derived differently, which can
change what the pre-state holds there and so which rows of `SATIN-SD-004` the destruction applies.
