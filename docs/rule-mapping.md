# How rules and assertions map to the registry

## Citations

A rule citation is a rule id, optionally qualified by a table row:

```text
SATIN-POOL-019            the rule
SATIN-KEY-005/step-12     row "step-12" of SATIN-KEY-005's table
```

A citation resolves against the rule registry of the case's spec, `specRef.descriptor` → the
descriptor → its `registry` digest → `rules.json` ([spec-identity.md](spec-identity.md)):

1. The id must be a key of the registry (`unknown-rule`).
2. A row qualifier must be one of the rule's `rows` (`unknown-rule-row`).
3. The rule must be `active` at that spec (`retired-rule`). A rule retired by a later spec does not
   affect a case pinned to an earlier one: each case resolves against its own registry.

The registry also gives the citation's text digest, so a review record can name the exact text an
expectation was approved against, and a consumer can detect that a new spec reworded it.

## Assertions

`assertions` says which observation distinguishes which rule. Each entry is a JSON Pointer into
`expected` and the rules for which the value at that pointer is the discriminating evidence:

```json
{"path": "/expected/gasLedgers", "rules": ["SATIN-POOL-019", "SATIN-STATE-008"]}
```

- The pointer must resolve (a `null` value resolves) (`unbound-assertion`); it may name a whole
  group, one block, one transaction or a single field.
- Every rule of an assertion must be in the case's `rules` (`assertion-rule-not-cited`), and every
  rule of `rules` must be used by some assertion (`uncovered-rule`). `rules` is therefore exactly
  the set of rules the case claims to cover, and citing a rule without saying which observation
  shows it is rejected.
- Assertions do not restrict comparison: every required group is compared in full. An assertion
  states what a failure at or below its pointer means for coverage.

Authoring intent (setup, triggering operation, boundary, arithmetic) belongs in `provenance`;
reviewers check it against the pinned rule text.

## Coverage

From a manifest's cases and their registries:

- **Referenced-rule coverage**: active rules cited by at least one approved case, over all active
  in-scope rules.
- **Asserted-rule coverage**: rules with a reviewed assertion in an approved case, over the same.
  In this format the two coincide case by case, since a citation requires an assertion; they
  differ once review status is tracked per assertion.
- **Executed-rule coverage** of a consumer: asserted rules of the cases that consumer ran and
  passed. A failure, `known-fail`, `unsupported` or `error` case contributes nothing, and a subset
  cannot claim coverage from cases outside it.

Imported Ethereum cases cite `SATIN-BASE-001` (the inherited base layer) and keep the upstream test
identity and specification reference in provenance. Historical specs need their own registries;
a Satin id is never cited for Rex6 behaviour.
