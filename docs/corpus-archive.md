# The differential-corpus archive

The differential gates of the evm2-based implementation keep their full corpus as a release
asset of a separate repository. This page records the verification of one release and the rule
that maps its members to cases of this suite. The archive is not mirrored here: where its bytes
are kept is the owner's decision (D-47).

## The verified release

| Item | Value |
| --- | --- |
| Repository | `https://github.com/RealiCZ/mega-evm2-corpus` |
| Release | `corpus-2026-11-10` ("corpus 2026-11-10 (4250 scenarios)"), published 2026-11-09 |
| Asset | `mega-evm2-corpus.tar.zst`, 34,296,641 bytes |
| SHA-256 | `7a6e3dd2512e5631d18ac8367a8b6a8ea1ad5a255d456b13321fb50268da62fa`, the digest the release publishes and the digest of the downloaded bytes |

`tools/verify_corpus.sh <archive>` checks the digest against that pin and prints the inventory
below; it reads the archive only.

| Member | Content |
| --- | --- |
| `real-blocks/d4/<number>.json` | 63 recorded blocks sampled across the chain's history, with `manifest.json`, `blocks.csv`, `blocks.txt` and `<number>.perf.json` timing files |
| `real-blocks/p9/<number>.json` | 200 consecutive recorded blocks (26,400,000 onwards), with the same index files |
| `real-blocks/rot/<number>.json` | 5 registry-rotation variants, with `manifest.json` |
| `real-blocks/<set>.convert.log` | the capture conversion logs |
| `reference/reference-outputs.tar.zst` | the revm-based implementation's outputs: `satin-oracle.json` (4,250 scenario records, by group: `edge` 1,691, `port` 1,370, `fz` 400, `bd` 265, `q8` 143, `blk` 88, `q2` 62, `p6` 52, `gb` 52, `p5` 51, `par` 25, `rev` 24, `p7` 18, `cap` 9), `oracles/<mode>.json` (19 fuzz batches, 66,314 records) and `raw/satin` and `raw/satin-block` (per-block outputs of `d4` and `p9`, 263 each) |

The archive has 541 files. Its reference records are one implementation's observations: they are
migration evidence, never expectations (corpus-inventory.md §1).

## From an old member to a new case

A case converted from the archive keeps the member it came from, so the mapping is exact in both
directions:

1. **Identity.** Every new case's provenance names its source: `source.archive` (the archive's
   SHA-256), `source.member` (the path inside the archive, and inside the nested reference archive
   when it is one) and the member's own SHA-256; a scenario record adds its `name` and `group`, a
   fuzz record its batch (mode) and seed, a recorded block its set and number. These are also its
   aliases. An archive digest names the bytes, so a moved or mirrored archive maps the same way.
2. **Scenario records** (`satin-oracle.json`, by `name`) map to the candidate the exporter makes
   from the scenario of that name at the implementation's pin: `satin/exported/<group>/<name>`
   (lowercase, runs of other characters as `-`), its input from the scenario definition, not from
   the record. The record is kept as the revm-based observation of that input; it never becomes the
   expectation.
3. **Fuzz records** (`oracles/<mode>.json`) map to a candidate only when promoted: a minimized
   regression or a reviewed boundary case becomes `satin/fuzz/<mode>/<seed>` with the generator's
   revision, mode and seed in provenance. The bulk batches stay a discovery lane: a seed alone is
   never a fixture.
4. **Recorded blocks** (`real-blocks/<set>/<number>.json`) map to block-profile cases of the
   historical lane under the block's own spec, `<spec line>/recorded/<set>/<number>`, their receipts
   anchoring gas, status and logs; a replay under Satin is a new case with its own spec and
   provenance. A capture whose conversion log records misses is completed or quarantined, never
   defaulted. Timing files are diagnostics and map to nothing.
5. **Exclusions are recorded.** A member that maps to no case — an excluded scenario (see the
   exporter's `summary.json`), an unpromoted fuzz record, a timing file — is listed with its reason,
   so the counts of every release can be reconciled member by member.

One member maps to at most one case per spec; a case maps back to exactly one member.
