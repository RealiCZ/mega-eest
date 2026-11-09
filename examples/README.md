# Examples

One fixture per profile, written by `tools/make_examples.py`:

| File | Profile | Shows |
| --- | --- | --- |
| `state-transition-sstore-fresh-slot.json` | state-transition | a signed legacy transaction filling an empty slot; SALT capacities; reads with an absent account and an explicit zero slot |
| `deposit-state-transition-new-caller.json` | state-transition | a deposit envelope from a caller with no account (`SATIN-DEP-003`) |
| `transaction-validation-gas-below-intrinsic.json` | transaction-validation | a refusal at step 2 of `SATIN-VAL-003`, with its set of acceptable reasons |
| `invalid-block-foreign-registry-code.json` | block-import | an invalid block (foreign code at the SequencerRegistry, `SATIN-REG-004`): the failure phase and reason, and the previous head kept |
| `stateless-block-witness-wrong-parent-anchor.json` | stateless-block | a witness anchored to another parent: a typed witness failure and no block results |
| `block-build-policy-skip.json` | block-build | a candidate skipped for building policy (`SATIN-BLK-011`) after another was committed: decisions, the action sequence and the committed order |

The encodings are real: transactions are signed with Ethereum's well-known test key
(`0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b`), deposits and headers are RLP-encoded, and block
parent hashes are the Keccak-256 of the anchor header. **The expected values are illustrative**:
they show the shape of the format and have not been executed by an implementation or reviewed
against the specification; each example's provenance says so.

`negative/` holds fixtures with exactly one defect each. The part of the file name before `--` is
the error code both readers must report.
