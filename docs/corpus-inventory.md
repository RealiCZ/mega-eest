# Old-corpus inventory and disposition

Existing test assets are inputs to this suite, never its expectations. Each family below is listed
with its pinned revision, what it holds, and what happens to it: **convert** (inputs are
materialized into candidate fixtures and re-filled), **evidence** (kept as provenance or migration
evidence, never as an expected value), **separate lane** (stays where it is, as its own gate), or
**excluded** (with the reason). No asset is imported in bulk in phases 0 and 1; conversions happen
from phase 2 on, into a candidate namespace, each candidate keeping its original identity as an
alias.

## 1. The differential scenario crate (mega-evm `next/diff`)

Pinned at mega-evm commit `aa8ea49abe55fce5331441c8c932910e324a8753` (`next/diff/shared`, the
engine-neutral scenario definitions; `next/diff/scripts/common.sh` holds the gated counts).

| Asset | Size at the pin | Disposition |
| --- | --- | --- |
| Main scenarios: hand-written, the pre-frame sweep and the default fuzz seeds | 2,889 gated (2,293 matching, 5 listed differences, 591 accepted by a class) | **Convert** into `state-transition` candidates (block-build or block-import where the scenario has earlier transactions of its block). Names (`p6_dupn`) and group keys (`p5`, `q2`, `edge`, `bd`, …) become aliases in provenance |
| Pre-frame sweep (`sweep.rs`) | part of the main set | **Convert**, keeping its sender, target, envelope and charge-boundary matrix; each boundary's derivation is reviewed independently before promotion |
| Fuzz generators (`fz.rs`, `fz/*.rs`) with modes 1 to 15 | 19 full batches, 66,314 scenarios (mode, seed range and count per batch in `FULL_FUZZ_BATCHES`); the sample is 12 batches | **Convert** minimized regressions and reviewed boundary cases; record generator revision, mode and seed as provenance. A seed alone is never a fixture; the bulk batches stay a discovery lane |
| Recorded mainnet blocks | 263: 63 sampled across the chain's history (`d4`), 200 consecutive at the current spec (`p9`); 5 registry-rotation variants outside the gates; a 20-block sample in the repository | **Evidence** for the historical lanes: original receipts anchor gas, status and logs under the block's own spec. Replays under Satin become new cases with their own spec and provenance, never relabelled historical receipts. Captures with unexplained misses are completed or quarantined: the block database answers a miss with a default, which this format treats as a missing input |
| Reference outputs (`next/reference`, the revm-based Satin implementation) and the engine's outputs | per scenario and block | **Evidence** only: one implementation's observations, archived with their build identity as migration evidence |
| Accepted differences (`known-differences.toml`, 14 entries: classes and listed differences), negative controls, mutant suppressions | — | **Excluded** from conformance: an accepted difference is not a correct value. Each is classified when its cases are converted (representation-only, implementation bug, specification ambiguity, instrumentation-only) |
| Gate scripts and comparison code | — | **Separate lane**: the A/B gates keep finding bugs; their record fields are a checklist for the observation model, not the model |

What a conversion must change:

- Small integer conveniences (`u64` slots and values) become full-width keys and values.
- Per-transaction limit and detention-cap overrides (`Limits`), and the simulation switches
  `skip_nonce_check` and `skip_eip3607`, are not chain-valid inputs (`SATIN-LIM-017`,
  `SATIN-BLK-010`; decision QC-02 of the specification). Such scenarios go to a
  parameterized-model lane outside conformance, and each claimed rule gets a production-constant
  counterpart ([decisions](decisions.md), D-11).
- Pre-recovered EIP-7702 authorities become `synthetic` transactions, which cannot count toward
  signature coverage, or are re-signed as real envelopes.
- Deposits (`deposit: Some(mint)`) become deposit envelope bytes; oracle answers become a recorded
  transcript; SALT `(address, slot, multiplier or capacity)` entries become bucket capacities
  under the named mapping.

The count gated at the pin is 2,889. A later working revision of the same tooling gates 2,890 (one
scenario added after the pin); the inventory follows the pin and moves with it.

## 2. mega-evm state tests and transition tools

Pinned at mega-evm commit `4e39cfd6`, the revm-based implementation's pin (`crates/mega-state-test`,
`crates/state-test`, `bin/mega-evme`). Every count below is the same as at the previous pin; the
deviation registry gained one entry, `slotnum-pushes-zero` (12 Amsterdam entries).

| Asset | Disposition |
| --- | --- |
| `mega-state-test` runner: Ethereum state and blockchain tests through the Satin engine, in an equivalence mode (a gate with a registry of intended deviations) and a Satin mode (a report) | **Separate lane**: Ethereum equivalence stays its own gate. Its neutral configuration, base-fee-vault pruning and predeploy seeding are accommodations of that lane and must not become expectations here |
| Its outcome-digest and read-set records (`digest.rs`) | **Evidence**: a checklist for the outcome and reads groups; the format defines its own model |
| Its deviation registry (`DEVIATIONS.md`) | **Evidence**: tells which Ethereum cases need Satin-specific expectations when converted |
| Its integration tests (`tests/runner.rs`, `blockchain.rs`, `witness.rs`: 16, 12 and 3 tests) | **Separate lane** |
| The earlier MegaETH state-test unit (`megaEnv` SALT and oracle pairs, `megaGasUsed`, `megaStatus`) described by the design at mega-evm `d4c913c5` | **Convert** inputs: SALT pairs to `salt`, oracle pairs to a recorded transcript. Its optional gas and status results are evidence only |
| `mega-evme replay --dump-fixture` dumps and the replay fixtures (`bin/mega-evme/tests/fixtures`, 37 files) | **Convert** representable inputs (the dump builder refuses deposits and EIP-7702 transactions) into `state-transition` candidates with chain provenance; recorded receipts are independent anchors for the claims they cover |
| `mega-t8n` | **Separate**: a candidate filler entry point once extended; not a source of fixtures |

## 3. Ethereum execution-spec-tests fixtures

The shared fixture copy is the EEST release whose index (`.meta/index.json`) has root hash
`0xc9f9db837189f64011d8195b97fcaaa43f7d2456ebcae95ed6429b4919cf3a68`, created 2026-10-07, listing
354,684 test cases. The copy holds `state_tests` (11,296 files) and `blockchain_tests` (12,272
files) for Frontier to Amsterdam and the transition forks; the engine, sync and transaction-test
formats listed in the index are not in the copy.

| Subset | Cases in the index | Disposition |
| --- | --- | --- |
| Osaka state tests | 14,716 | **Convert** selectively: expand data, gas and value indexes into one concrete `state-transition` case each, keep the EEST test id and file as source identity, and re-fill under Satin (Satin prices state and history and logs value transfers, so most expectations differ). Cases cite `SATIN-BASE-001` and the upstream reference. The equivalence lane keeps running them unconverted |
| Osaka blockchain tests | 17,550 | **Convert** selectively into `block-import`, excluding what an OP chain cannot express (withdrawals, blob transactions, requests, header-only exceptions), each exclusion counted with its reason |
| Amsterdam state and blockchain tests | 16,955 and 26,398 | **Excluded** from release one, except targeted imports for the Amsterdam behaviour Satin adopts (EIP-8038 access prices, EIP-7708 transfer logs, the EIP-8037 profile) |
| Earlier forks and transition-fork tests | — | **Excluded**: not Satin's base |
| Transaction tests | 720 (92 for Osaka) | **Convert** for `transaction-validation` once obtained; not in the shared copy |
| `ethereum/legacytests` (36,535 files) | — | **Excluded**: covered by EEST's static re-fills |

## 4. The full corpus archive and the first export

The full differential corpus release `corpus-2026-11-10` was downloaded and verified against its
published digest (`7a6e3dd2512e5631d18ac8367a8b6a8ea1ad5a255d456b13321fb50268da62fa`); its member
inventory and the rule that maps an old member to a new case are in
[corpus-archive.md](corpus-archive.md). It is not mirrored yet (D-47). The earlier release named by
the design (`corpus-2026-11-05`) is superseded by it for conversion purposes.

The exporter (`exporter/`, `tools/export_scenarios.py`, run by `tools/export-scenarios.sh`)
converts the scenario crate at the evm2-based implementation's pin (`f3d84454`), which defines
3,857 hand-written scenarios, into `state-transition` candidates under the git-ignored
`candidates/exported/`. Against the `d34e626` registry:

| Disposition | Scenarios |
| --- | --- |
| Converted into a candidate authoring document | 871 |
| Limit or detention-cap override: parameterized-model lane (D-11) | 1,035 |
| Cites no active rule of the pinned registry: needs authored rules | 1,877 |
| Earlier transactions of its block: needs a block profile | 44 |
| Oracle answers without their request order: a transcript needs a recorded run | 22 |
| Simulation switch (`skip_nonce_check`, `skip_eip3607`) | 7 |
| An L1 fee: needs signed bytes the keyless sender cannot give | 1 |

`summary.json` lists every excluded scenario by name under its reason. A converted candidate's
transaction is a synthetic message (the scenario senders have no keys) or a deposit envelope; it
cites the scenario's own rule ids as its rules, unreviewed until a reviewer names the rules it pins,
and keeps its name and group as aliases; it sits at `candidates/exported/<caseId>.json`. `mega-fixture fill` completes it with an implementation's
observations into `candidates/filled/<adapter>/`; none is promoted without review. stateless-validator's
`test_data/` is still inventoried by reference only; it belongs to the proof profile of phase 3.
