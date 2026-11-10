# MegaETH execution conformance fixtures

A specification-led fixture suite for MegaETH's execution layer: published inputs and expected
results that any implementation can consume through a thin adapter, without the implementation
that filled them. Expectations are frozen per release, every case is traceable to rule ids of a
pinned specification, and identity is content plus logical names, independent of where the files
are hosted.

This repository holds the contract of the suite — the pinned inputs (phase 0) and the wire format
(phase 1) — and its first vertical slice on both Satin implementations (phase 2): two adapters, a
read-only consumer, a candidate filler, an exporter from the differential scenarios, and 63
reviewed `state-transition` cases whose expectations are derived from the specification.

- Specification: the Satin section of `https://github.com/RealiCZ/mega-evm-satin-spec`, snapshots
  at `cac999a`, `22a5f4b` and `d34e626` (the slice pins `d34e626`), and a registry of the frozen
  Rex6 text ([spec identity](docs/spec-identity.md)).
- Fixture format: `mega-execution-fixture` 1.0, five profiles: `state-transition`,
  `transaction-validation`, `block-import`, `block-build`, `stateless-block`
  ([format](docs/format.md), [profiles](docs/profiles.md)).

## Layout

| Path | Content |
| --- | --- |
| [`schema/`](schema) | JSON Schemas: `fixture.json` (envelope), one file per profile, `common.json`, `manifest.json` |
| [`specs/`](specs) | Spec bundles (descriptor, rule registry with text digests, source page digests): `satin-cac999a`, `satin-22a5f4b`, `satin-d34e626`, `rex6-d4c913c5` |
| [`crates/mega-fixture-format/`](crates/mega-fixture-format) | Rust format crate: strict decoding, validation, canonical JSON, digests, comparison, the consumer loop and the filler; a `mega-fixture` CLI. No engine dependency |
| [`adapters/`](adapters) | One adapter per Satin implementation, each its own workspace, pinned by commit ([adapter protocol](docs/adapter-protocol.md)) |
| [`exporter/`](exporter) | Dumps the differential gates' scenarios for `tools/export_scenarios.py` |
| [`slice/`](slice/README.md) | The vertical slice: cases, quarantine, a deliberately wrong expectation, index |
| [`tools/`](tools) | Registry generators, the SALT mapping, the spec-derived model and slice generator, the exporter, `run-slice.sh`, the readers' checks |
| [`vectors/`](vectors/README.md) | Canonicalization and digest vectors, accepted and rejected |
| [`examples/`](examples) | One illustrative example per profile and negative examples under `examples/negative/` |
| [`docs/`](docs) | The specification of the format and the records of each phase |

`vendor/` (the evm2-based implementation, fetched by `tools/fetch-implementations.sh`),
`candidates/` (exported and filled candidates) and `target/` are git-ignored.

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
| [adapter-protocol.md](docs/adapter-protocol.md) | What an adapter provides and reports, its process interface, the mapping definitions and this repository's two adapters |
| [corpus-archive.md](docs/corpus-archive.md) | The verified differential-corpus archive and the old-member-to-new-case rule |
| [rule-mapping.md](docs/rule-mapping.md) | How rule citations and assertions resolve against the registry |
| [versioning.md](docs/versioning.md) | Spec, schema, suite and content identities; manifests |
| [decisions.md](docs/decisions.md) | Choices made where the design was open |

## Checks

```bash
cargo test --locked                                      # the Rust reader: vectors, examples, comparison, consumer
python3 -I tools/check_vectors.py vectors                # the independent reader: vectors, examples, the slice
python3 -I tools/make_examples.py --check                # examples are what their generator writes
python3 -I tools/make_slice.py --check                   # the slice is what its generator derives
python3 -I tools/salt_mapping.py --check                 # the salt-v1 port reproduces its reference vectors
python3 -I tools/gen_registry.py <spec-checkout> d34e626 specs/satin-d34e626 --members tools/descriptor-members/satin.json --check
bash tools/run-slice.sh                                  # both implementations on the slice
```

`tools/run-slice.sh` builds the format CLI and both adapters (fetching the evm2-based
implementation into `vendor/`) and prints the `SLICE`, `PARITY` and `NEGATIVE` lines of
[slice/README.md](slice/README.md). `tools/export-scenarios.sh` exports the differential scenarios
into `candidates/exported/`; `mega-fixture fill` fills candidates, `mega-fixture consume` runs any
cases on an adapter, read-only.

## Status

Phases 0 to 2 of the suite's plan. The slice's 63 cases pass on both implementations, plain and
instrumented, with identical input digests; three deposit cases are quarantined, the revm-based
implementation charging deposits no history gas against `SATIN-HIST-016`. The expectations are
candidates until the owner approves them. Next come the block and proof consumers. The
specification is unstable; no stable release exists.
