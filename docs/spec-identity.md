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

## Historical specs

Release one also carries a separately identified Rex6 slice. Rex6 has no generated rule registry
yet; its descriptor and registry are a prerequisite of the Rex6 slice and of every Rex6 to Satin
crossing case (`feature:schedule`), and are not invented here. Until then those cases cannot pass
validation, which is the intended failure: a case may not cite rules that do not resolve.
