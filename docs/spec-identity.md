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
| `specs/satin-d334ef8` | `d334ef8748a6fb09dfcf1162704539fe22373aef` | 409 (400 active) | `SATIN-ICPT-007` added (interception before the frame start, the funds check included); `SATIN-ICPT-003`, `-006`, `SATIN-KEY-005`, `-018`, `SATIN-LIM-015`, `SATIN-ORCL-006`, `-010`, `SATIN-OUT-010` and `SATIN-STOP-020` reworded (the keyless decoder's conditions among them) |
| `specs/satin-5fb2688` | `5fb26884b5ed1d02bb622073dfdf1d7ea814f1be` | 410 (401 active) | `SATIN-HIST-023` added (the order of charges and decisions around a frame start, as a principle); `SATIN-DET-018`, `SATIN-HIST-005`, `-009`, `-015`, `SATIN-ICPT-002`, `-004`, `-007`, `SATIN-POOL-012`, `SATIN-SCHED-008`, `-009`, `SATIN-STOP-014`, `SATIN-TAKE-006` and `-010` reworded (the delegate's access before the first frame, the reservoir paying the authorities' records first, one charge under gas detention among them) |
| `specs/satin-cdded1e` | `cdded1e1d131a1d16a2c4b1cd873557f16a6a558` | 410 (401 active) | 52 rules reworded and no id added or retired: each rule has one home that the others cite (the give-back rule in `SATIN-HIST-012`, the frame it credits in `SATIN-HIST-007`, the `SSTORE` transitions in `SATIN-STATE-008`, a start that does not happen in `SATIN-HIST-023`), worked examples move into conformance cases once their cases exist, and a statement no execution reaches is marked once in its home |
| `specs/satin-c130558` | `c130558e2f38a913982dc17f0cd8eb8834967262` | 410 (400 active) | `SATIN-STOP-016` retired (no transaction reaches it) and 25 rules reworded: a call refused at its target's EIP-7702 delegate pays its target's access and its memory expansion, and stops with `MegaLimitExceeded(2, limit)` when its cold surcharge is gas detention's crossing (`SATIN-MAC-003`, `-004`, `-007`, `SATIN-DET-018`, `SATIN-OUT-008`, `SATIN-PCMP-008`, `SATIN-STOP-020`, `SATIN-WIT-012`); a precompile that halts burns its whole forward and counts none of it as compute, and a value call to a precompile's absent or empty account pays its new-account state gas (`SATIN-DET-011`, `-021`, `-022`); the first fill batch's clarifications (`SATIN-SCHED-003`, `-004`, `SATIN-SD-013`, `SATIN-STOP-017`); the take-back page's worked examples, and the conformance cases the text named, removed (`SATIN-TAKE-005` to `-012`, `SATIN-ICPT-006`, `SATIN-POOL-019`) |

The vertical slice's first 63 cases and its quarantine pin `d34e626`; the cases added for
interception, the keyless decoder and EIP-7702 existence pin `d334ef8` (decision D-54); the cases
added for the edges of the charge-order principles pin `5fb2688` (decision D-59); the cases for the
take-back page's worked examples pin `cdded1e`, the newest (decision D-65).
Digests (SHA-256 of canonical bytes):

| Bundle | descriptor.json | rules.json | sources.json |
| --- | --- | --- | --- |
| `satin-22a5f4b` | `sha256:04146ac1a233e90a99504054aeedaac316ecc4100240e7e6408e2b55027c1a05` | `sha256:c78032df0748bc94e36058d492d29482765b1c57d3d59d313b6b9c495d9e3997` | `sha256:db1fe168a9b474034697898b8c7d19b941acb0b44c7a5a3d5e20d159d40337b2` |
| `satin-d34e626` | `sha256:bf97cc6429597c157dc18040ac45cdfb62a4c9646a1b1a715573a61ea6f884b2` | `sha256:e0103bf0e84d208865e712d99d510ac561f2bd7f2e726c36c0e3d157f59c1139` | `sha256:991a2ef5ea66ebfb19ee4e681ddc17746c1c02ed7d502d6e46c132d8c5128503` |
| `satin-d334ef8` | `sha256:6fa989a0bb4e83353b71c6c30f75a5e77c27a07f73b97f786514b975429aeea2` | `sha256:c930551351f5986fbdfef9d905c61ec5f3b8b35a9c9dd5b516ce6bd417254ce5` | `sha256:4a413161486c0b7006dba4253cfd8f2083539d57a3087f93fd3d161d9cf35571` |
| `satin-5fb2688` | `sha256:22ab05bff4fadbe600e2ff73d675b70d91d24ac3bc5b83e95c9afb2a27f71da6` | `sha256:74e3c428ff05249dc89572db23a7ba8aa4b89208e31b57a5244c3bf17daaeac9` | `sha256:49891ca547f3cca748ec3900e378ae4b7d5eeddeac44b3817d96072d61148234` |
| `satin-cdded1e` | `sha256:b0dad919e6da8e9357c15505bcda41cb16e7ef68dacfbde58e9a334c63439658` | `sha256:e175134bd65d0cef4f81de55b68ea1d9f62e5c3f92c0f11ae69f9d260af69bf9` | `sha256:cb21a9c3129bbda223c253346dbd326a5c78cc13d5bf3d0c686ae8f9fd03c3e1` |
| `satin-c130558` | `sha256:a0510f1fa0dc8f173a8a2a2dfe27ed3caaaa56a03e667ba70e579c0706b467da` | `sha256:9abb2cfa2d022251bc7415704bfc49a4d43057c8cd690791840bdf836bcec07f` | `sha256:f430f5f5ed753ba075ed89a070d8d02707531b8331d1d54d03e62e73b252f12c` |
| `rex6-d4c913c5` | `sha256:93186256dad9ae5c4b7bdde48243732cdeb6b1cdc5127823cbcf1dd4c4782a57` | `sha256:38a3669c27ae74755aae16efbbbba822ec00e147ae52ae814c9a4d85e030d00a` | `sha256:36445afc3cc90eaffefe3484c81088c47db4adc116731576436dd25b2dcc9d5d` |

The same files' bytes as committed, which `shasum -a 256` prints (the generator writes them indented, so
these differ from the canonical digests above, which are what a descriptor binds):

| Bundle | descriptor.json | rules.json | sources.json |
| --- | --- | --- | --- |
| `satin-22a5f4b` | `sha256:44c3bf7d17576560c7c37238f94b5df5ea4dbbe3b523e36594553561bb2ce36d` | `sha256:29c0c64ddafa456db17cc740c27fe9330f00c2cb1563c8dcb4f10fbca50f2075` | `sha256:0b7268888e49f18078e47441760f1f99cb742ccbf55784b40922c2ee8abc9814` |
| `satin-d34e626` | `sha256:66fa7a63c2f2c15085621ab56f0c13a0e6371ae47638750075ef40de33236fde` | `sha256:e90acaedc0598f3259028b90eb0b549f45aa90bf602232c278df94f573de2647` | `sha256:78bb9c661eadd99d5e8154258a179793e83e1f2710ca8033a0759ebfab7a788c` |
| `satin-d334ef8` | `sha256:aabb2499105ce4f35ce30633940a88a3cf3347fb4be051eb94ce0849dfc10316` | `sha256:9b85c722af6f0d70f3864cfa881a5dc2a7c0a81c01047b81ba4fde05d6e86ae8` | `sha256:04b1738fe14891fdd7e468c0b48d78b9efe01dbea613fc85379fe952819cdc0b` |
| `satin-5fb2688` | `sha256:09324c0dcfbf4a639786c063ca19d0db8eb49b003d003a295982a24c4865aaa5` | `sha256:1ed7ed85696074148a843234d853579c4c76d96a861663c6c6f8635ec7dc59b7` | `sha256:70c22156ad1eee866eb87ef1eba295beb85d263bfa464bd490b8fbbdb7603de6` |
| `satin-cdded1e` | `sha256:b054985e28671b3f2f2ef32403a5155a2acf2e8d7e1f8fb1278e38f0f0a5892c` | `sha256:3214fcacb2f2bbf6fe0b3b7d397950edde796055a7cde036c85b6d60ceaeb8f6` | `sha256:526b77be0a6520edc2d4908e0dd483633b02b6e3388dd7c5a0df89ae1fe94969` |
| `satin-c130558` | `sha256:4c7f6b9f55ff712dd1111ea04015aa6bb38f644e6d927642aef1a812b9e1b779` | `sha256:ae6ba522fec39968efd036fb18bbafef3d04ae7ee0e8e22061c4e6e8b96ebc35` | `sha256:6c8951d1d9650cff104748f30b618293d8e74d431483ee7a1aa71be124d04651` |
| `rex6-d4c913c5` | `sha256:c956666034af309dc1e1db9896c2f7934ae1d8e714e0d894cf2069f217d27d9e` | `sha256:de097f03a1b6a138e33760e671bd70eff8054b510d1e612e407d165a07f3e39c` | `sha256:0e2de0c86d2cd07d139c639125fdb0ec2588920608aab224e7535e316c782e8d` |

```bash
python3 -I tools/gen_registry.py <spec-checkout> 22a5f4b specs/satin-22a5f4b --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> d34e626 specs/satin-d34e626 --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> d334ef8 specs/satin-d334ef8 --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> 5fb2688 specs/satin-5fb2688 --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> cdded1e specs/satin-cdded1e --members tools/descriptor-members/satin.json --check
python3 -I tools/gen_registry.py <spec-checkout> c130558 specs/satin-c130558 --members tools/descriptor-members/satin.json --check
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
