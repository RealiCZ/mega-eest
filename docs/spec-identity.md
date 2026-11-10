# Specification identity and the rule registry

Every fixture of this suite names the protocol spec it was written against, and every rule it
cites must resolve offline. This page pins the first authoritative specification and defines the
registry snapshot that makes its rule ids resolvable without a checkout.

## The pinned specification

| Item | Value |
| --- | --- |
| Spec name (`specRef.name`) | `megaeth/Satin` |
| Maturity | unstable: rules and values may change before Satin is frozen |
| Source repository | `https://github.com/RealiCZ/mega-evm-satin-spec` |
| Commit | `cac999a7123d20bb801be98aed03cefecaaf8aea` (`cac999a`, committed 2026-11-09) |
| Section | `docs/spec/satin/` (the Satin section; `rules.md` is its generated rule index) |
| Base | Optimism Karst (Ethereum Osaka), as `SATIN-BASE-001` states |
| Rule ids | 407: 398 active, 9 retired, in 32 areas |

The repository and commit are a locator for the source text, not the spec's identity inside
fixtures. Fixtures reference the spec by the digest of its descriptor:

| Bundle file | Digest (SHA-256 of canonical bytes) |
| --- | --- |
| `specs/satin-cac999a/descriptor.json` | `sha256:2980c959d5e53e4b2f6227ae59bfa6cf953a9ec68b0d862d3459741549678768` |
| `specs/satin-cac999a/rules.json` | `sha256:c5dae40a0596b55ddb960f813d47ad12288dfd1cbc1d60f059f3847142c61a63` |
| `specs/satin-cac999a/sources.json` | `sha256:a05ff235a1c261a410af13e5dbeb9402e8f64d41f5e14abb23750f51e8e68e65` |

The descriptor binds the registry and the source list by those digests, so a fixture's
`specRef.descriptor` transitively fixes every rule's status and text. Moving the specification to
another repository or organization changes where the text is fetched from, never these digests.

An unstable snapshot is pinned on purpose: a new spec commit becomes a new descriptor with a new
digest, and existing fixtures keep resolving against the registry they were written for.
Cases on rules whose semantics are still open are withheld from stable releases
([decisions](decisions.md), D-03).

## The registry snapshot

`tools/gen_registry.py <spec-checkout> <commit> specs/<dir>` reads every page of the section from
git objects at the commit (the working tree is ignored) and writes three files:

- `rules.json`: one entry per rule id: `status` (`active` or `retired` at this spec), `page`
  (relative to the section), `section` (the heading path inside the page), `rows` (the row names a
  citation may use), `replacedBy` (ids a retired rule names as its replacement), `text` (the rule
  text defined below) and `textDigest` (`sha256:` of the text's UTF-8 bytes).
- `sources.json`: every page of the section at the commit, with the SHA-256 of its exact bytes.
- `descriptor.json`: name, maturity, base, source coordinates and the digests of the other two.

`--check` regenerates in memory and fails when a committed file differs. The script fails,
writing nothing, when an id is stated twice or when the ids it finds differ from the ids of the
specification's own generated index (`rules.md`); at `cac999a` both list the same 407 ids.

### Where a rule's text starts and ends

The specification states each rule as a list item that starts with its id in inline code (its
writing rules require this, and its own index generator relies on it). The registry's rule text
is that list item's block:

1. It starts at the line holding `` `<ID>` `` at the start of a list item, outside fenced code.
2. It continues over every following line until the first line that is a heading, the start of
   another rule, or a non-blank line at column 0 that is neither a table row (`|`) nor the start
   of a fenced code block. Column-0 tables and fenced code blocks directly under a rule (for
   example `SATIN-KEY-005`'s step table or `SATIN-MLC-001`'s interface) belong to the rule; a
   fenced block is taken whole.
3. Trailing whitespace is removed from every line and trailing blank lines are dropped; the lines
   are joined with `\n` and no final newline.

The text keeps its Markdown, links included. `textDigest` changes exactly when that block's
bytes change, which is what a reviewer needs to see: a fixture approved against a rule's text can
detect that the text moved under it.

### Status, retirement and rows

A rule is `retired` when it is listed under a heading containing "Retired" or its text starts
with "Retired". `replacedBy` collects the ids named after "replaced by" or "merged into" in a
retired rule's text. At `cac999a` the retired ids are `SATIN-ACT-006`, `SATIN-LIM-018`,
`SATIN-PBLK-005`, `SATIN-POOL-013`, `SATIN-POOL-016`, `SATIN-REG-003`, `SATIN-SCHED-013`,
`SATIN-VAL-009` and `SATIN-WIT-015`.

The specification cites a table row as `<id>/<first cell>` (for example `SATIN-KEY-005/step-12`).
`rows` lists the first cells of the body rows of every table in the rule's block, with Markdown
links reduced to their text and backticks removed, keeping only names that occur once and contain
no `/`; a name that occurs twice cannot be cited unambiguously and is left out. Twenty-two rules
have citable rows at `cac999a`.

[Rule mapping](rule-mapping.md) states how fixtures cite these ids and how a consumer resolves
them.

## Rule areas at `cac999a`

| Area | Ids | Area | Ids | Area | Ids | Area | Ids |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ACCT | 20 | ACT | 12 | AUTH | 18 | BASE | 10 |
| BLK | 13 | DEP | 13 | DET | 27 | FWD | 7 |
| HIST | 22 | HPTS | 2 | ICPT | 6 | KEY | 18 |
| LIM | 18 | LOG | 7 | MAC | 7 | MLC | 4 |
| MST | 10 | ORCL | 13 | OUT | 18 | PBLK | 6 |
| PCMP | 8 | POOL | 23 | REG | 9 | SCHED | 14 |
| SD | 20 | SIZE | 6 | STATE | 12 | STOP | 21 |
| SYSC | 4 | TAKE | 12 | VAL | 10 | WIT | 17 |

Counts include retired ids.

## Later snapshots of the specification

The specification's main moved after `cac999a`; each commit is a snapshot of its own, generated by
the same script, beside the earlier ones (decision D-35):

| Snapshot | Commit | Ids | Change from the previous snapshot |
| --- | --- | --- | --- |
| `specs/satin-22a5f4b` | `22a5f4bc95dd2abbcc9e75146e24be781e08aadd` | 407 (398 active) | no oracle service for deposits, Mega System Transactions or system calls: eight rules reworded |
| `specs/satin-d34e626` | `d34e6266e6d7b69963701baa5ae25ccb8a548260` | 408 (399 active) | `SATIN-BASE-011` added (a value transfer that would overflow its recipient's balance is outside the specification); `SATIN-ORCL-004` to `-006` reworded |

The vertical slice pins `d34e626`, the newest. Digests (SHA-256 of canonical bytes):

| Bundle | descriptor.json | rules.json | sources.json |
| --- | --- | --- | --- |
| `satin-22a5f4b` | `sha256:04146ac1a233e90a99504054aeedaac316ecc4100240e7e6408e2b55027c1a05` | `sha256:c78032df0748bc94e36058d492d29482765b1c57d3d59d313b6b9c495d9e3997` | `sha256:db1fe168a9b474034697898b8c7d19b941acb0b44c7a5a3d5e20d159d40337b2` |
| `satin-d34e626` | `sha256:bf97cc6429597c157dc18040ac45cdfb62a4c9646a1b1a715573a61ea6f884b2` | `sha256:e0103bf0e84d208865e712d99d510ac561f2bd7f2e726c36c0e3d157f59c1139` | `sha256:991a2ef5ea66ebfb19ee4e681ddc17746c1c02ed7d502d6e46c132d8c5128503` |
| `rex6-d4c913c5` | `sha256:93186256dad9ae5c4b7bdde48243732cdeb6b1cdc5127823cbcf1dd4c4782a57` | `sha256:38a3669c27ae74755aae16efbbbba822ec00e147ae52ae814c9a4d85e030d00a` | `sha256:36445afc3cc90eaffefe3484c81088c47db4adc116731576436dd25b2dcc9d5d` |

```bash
python3 -I tools/gen_registry.py <spec-checkout> 22a5f4b specs/satin-22a5f4b --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> d34e626 specs/satin-d34e626 --members tools/descriptor-members/satin.json --check
```

## Descriptor members: codecs and the SALT mapping

The descriptors written from `22a5f4b` on (and the Rex6 descriptor) carry two members besides the
identity and the digests, so a consumer needs no knowledge outside the bundle (decision D-37):

- `codecs.header`: the header's fields in RLP order (the Prague header: the format's decoded
  `Header` members) and its hash, the block hash; `codecs.transaction`: the EIP-2718 types
  (legacy, 2930, 1559, 7702 and the OP Stack deposit, `0x7e`) and the transactions root;
  `codecs.receipt`: each receipt envelope, a deposit's with its nonce and receipt version, the log
  encoding and the receipts root.
- `salt`: `salt-v1`, SALT's own key-to-bucket mapping, which `SATIN-STATE-010` takes as an input,
  stated by value: AHash v0.8.12's deterministic fallback hasher with four fixed seeds, the account
  key (20 address bytes) and the slot key (20 address bytes, then the slot as 32 big-endian bytes),
  `bucket = hash mod (2^24 − 2^16) + 2^16`, the minimum bucket of 256 and the multiplier
  `floor(capacity / 256)`; hash vectors from the reference implementation and bucket vectors; and
  the reference it was read from (mega-evm `5e3f30ad`, `crates/mega-evm/src/external/hasher`).
  `tools/salt_mapping.py` is a standard-library port (`--check` runs the hash vectors).

The members are written from `tools/descriptor-members/` by `--members`. The `cac999a` descriptor
has none and keeps its digest; cases under it are examples only.

## Historical specs: Rex6

Release one also carries a separately identified Rex6 slice, and Rex6 to Satin crossing cases need
the Rex6 registry. The Rex6 text names no rule ids, so `tools/gen_rex6_registry.py` assigns them
(decision D-36) and writes `specs/rex6-d4c913c5`:

| Item | Value |
| --- | --- |
| Spec name | `megaeth/Rex6` |
| Maturity | frozen |
| Source | `https://github.com/megaeth-labs/mega-evm`, commit `d4c913c5ff3383a4721cce7ebc59c9e05d7b005e`, `docs/spec/` |
| Pages | the 22 pages whose front matter says `spec: Rex6` (the EVM and system-contract pages and the indexes); the upgrade pages, summaries without that field, give no rules |
| Rules | 358 ids in 18 areas, all active |

A rule is a normative block of a page's `## Specification` section: a paragraph or top-level list
item that uses a BCP 14 keyword in capitals, with the table or fenced block directly under it. Its
id is `REX6-<AREA>-<NNN>`, the page's area code and the block's ordinal on the page; its text and
text digest are defined as for Satin. A Satin id never resolves under Rex6, and a Rex6 id never
under Satin.

```bash
python3 -I tools/gen_rex6_registry.py <mega-evm-checkout> d4c913c5 specs/rex6-d4c913c5 --members tools/descriptor-members/rex6.json --check
```

Neither Satin implementation runs Rex6 (both execute Satin alone), so Rex6 cases validate but have
no consumer in this repository yet; the owner's decision checks the Rex6 slice against the frozen
legacy engine.
