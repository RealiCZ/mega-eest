# MegaETH execution conformance fixtures

A specification-led fixture suite for MegaETH's execution layer: published inputs and expected
results that any implementation can consume through a thin adapter, without the implementation
that filled them. Expectations are frozen per release, every case is traceable to rule ids of a
pinned specification, and identity is content plus logical names, independent of where the files
are hosted.

This repository currently holds the contract of the suite: the pinned inputs (phase 0) and the
wire format (phase 1). It holds no filled expectations yet.

- First authoritative specification: the Satin section of
  `https://github.com/RealiCZ/mega-evm-satin-spec` at commit `cac999a`
  ([spec identity](docs/spec-identity.md)).
- Fixture format: `mega-execution-fixture` 1.0, five profiles: `state-transition`,
  `transaction-validation`, `block-import`, `block-build`, `stateless-block`
  ([format](docs/format.md), [profiles](docs/profiles.md)).

## Layout

| Path | Content |
| --- | --- |
| [`schema/`](schema) | JSON Schemas: `fixture.json` (envelope), one file per profile, `common.json`, `manifest.json` |
| [`specs/satin-cac999a/`](specs/satin-cac999a) | The spec descriptor, the rule registry (407 ids with status, rows and text digests) and the source page digests |
| [`crates/mega-fixture-format/`](crates/mega-fixture-format) | Rust format crate: strict decoding, validation, canonical JSON, digests, comparison; a `mega-fixture` CLI. No engine dependency |
| [`tools/check_vectors.py`](tools/check_vectors.py) | An independent second reader in standard-library Python |
| [`vectors/`](vectors/README.md) | Canonicalization and digest vectors, accepted and rejected |
| [`examples/`](examples) | One example per profile (two for state-transition, one of them a deposit) and negative examples under `examples/negative/` |
| [`tools/`](tools) | Generators of the registry, the examples and the vectors |
| [`docs/`](docs) | The specification of the format and the phase 0 records |

## Documents

| Document | Content |
| --- | --- |
| [spec-identity.md](docs/spec-identity.md) | The pinned specification and the registry snapshot |
| [spec-decisions.md](docs/spec-decisions.md) | The specification's own decision log, as fixtures depend on it |
| [corpus-inventory.md](docs/corpus-inventory.md) | Existing test assets and what happens to each |
| [case-identity.md](docs/case-identity.md) | `caseId` rules and the semantic digest |
| [format.md](docs/format.md) | The envelope, requirements, state, external inputs, observations and semantic checks |
| [canonical-json.md](docs/canonical-json.md) | Canonical JSON, error codes and digests |
| [profiles.md](docs/profiles.md) | The profile and capability matrix |
| [adapter-protocol.md](docs/adapter-protocol.md) | What an implementation's adapter provides and reports |
| [rule-mapping.md](docs/rule-mapping.md) | How rule citations and assertions resolve against the registry |
| [versioning.md](docs/versioning.md) | Spec, schema, suite and content identities; manifests |
| [decisions.md](docs/decisions.md) | Choices made where the design was open |

## Checks

```bash
cargo test --locked                                      # the Rust reader: vectors, examples, comparison
python3 -I tools/check_vectors.py vectors                # the independent reader; last line says ok
python3 -I tools/make_examples.py --check                # examples are what their generator writes
python3 -I tools/gen_registry.py <spec-checkout> cac999a specs/satin-cac999a --check
```

To validate fixtures and print their digests:

```bash
cargo run -q -p mega-fixture-format --bin mega-fixture -- check examples/*.json
```

`tools/make_vectors.py <path-to-mega-fixture>` rewrites the vectors with expected outputs computed
by the Rust CLI; `check_vectors.py` then reproduces them without it.

## Status

Phases 0 and 1 of the suite's plan: the contract inputs are pinned and the wire contract is
specified, with two independent readers that agree on every vector. Next come adapters for both
Satin implementations, a candidate filler and a reviewed vertical slice. The specification is
unstable; no stable release exists.
