# Decisions of this suite

Where the design of the suite left a choice open, or a later owner decision changed one of its
assumptions, the choice made here is recorded with its reason. Each is the smallest defensible
option; any of them can be revisited by a new schema minor or major version.

## Inputs and scope

**D-01. The first authoritative specification is the published Satin section at `cac999a`.**
The design pinned an earlier specification-work snapshot whose plan outline listed 384 draft rule
entries. The owner since published the written Satin section; its generated index lists 407 ids
(398 active, 9 retired), and that section, not the plan outline, is the registry's source.

**D-02. The old-corpus inventory follows its pinned revision.** At mega-evm `aa8ea49a` the gated
main set is 2,889 scenarios and the full fuzz set 66,314 scenarios in 19 batches; the design's
figures (2,678 and 57,300) predate it, and a later working revision gates 2,890. Counts are
inventory facts at a pin, not coverage targets.

**D-03. An unstable snapshot is pinned now.** Cases on rules still open are withheld from stable
releases; a new spec commit is a new descriptor digest, and existing cases keep their registry.

**D-04. Satin may start at genesis; crossings are their own group.** Satin cases may use a Satin
genesis (system contracts are deployed every block, as in Rex6). Rex6 to Satin crossing cases use
the `rex6-satin` case-id line and `feature:schedule`. Release one is Satin plus a separate Rex6
slice; the Rex6 registry is a prerequisite of both and is not invented here.

**D-05. The oracle transcript is an engine-isolation input only.** Under Satin's front-running
model validators run no oracle service and read the slot, which a Mega System Transaction persisted
earlier. `state-transition` and `block-build` may carry a transcript (`recorded` or `disabled`);
`block-import` and `stateless-block` carry none, and their schemas have no member for one.

**D-06. Release one is Satin plus the Rex6 slice; distribution, signing and approval are the
owner's.** Nothing here is published or signed; `provenance.status` records `example`,
`candidate`, `approved` or `superseded`, and only the owner promotes to `approved`.

## Encoding

**D-07. No JSON numbers at all.** The design forbids floating-point numbers and writes quantities
as strings; this format forbids every number, so the canonical form needs no number syntax and
two readers cannot disagree on integer formatting. Counts, indexes and ordinals are quantities.
Schema files, which contain JSON Schema numbers, are hashed as blobs.

**D-08. Object members sort by code point.** Code point order equals UTF-8 byte order, which every
language provides directly; RFC 8785's UTF-16 order would make Rust and Python readers convert.
A vector pins a case where the orders differ.

**D-09. Signed nets are decimal strings within 128 bits.** The design asks for canonical decimal
strings; the range bound makes the type finite in every reader.

**D-10. Error codes are part of the contract for single-defect inputs.** Both readers report the
same code, and below the JSON layer the same pointer, for every rejection vector and negative
example. JSON-layer pointers are informative only, since a streaming JSON parser may not know them.

## The envelope

**D-11. No limit overrides in conformance inputs.** Inputs have no member for test-only limits or
caps (`SATIN-LIM-017`, `SATIN-BLK-010`), so a parameterized-model case cannot pass as a chain
conformance case. A later minor version may add such a lane behind its own feature, outside
conformance coverage.

**D-12. `requires` is exactly the derived set.** It lists every group carried and every feature
used, nothing else. That makes it a reliable capability header (a consumer decides `unsupported`
without parsing the body) and catches a filler or reader that drops a group.

**D-13. Mandatory groups.** The owner decided final public observations are mandatory in every
profile and intermediate checkpoints are rule-specific. Here `state-transition` always carries
outcome, state, receipt, gas ledgers, resources and limit (nullable when a transaction has no
outcome); pools, detention, reads and checkpoints are optional, carried by the cases that cover
rules about them. Block profiles always carry block results, outcomes, receipts and state; their
optional per-transaction groups are carried by all transactions of a case or by none.

**D-14. The semantic digest excludes `caseId` and `provenance` only.** The design lists
schema/spec/profile/rules/assertions/input/expected; `requires` is included as well, because it
decides which observations a consumer compares.

**D-15. Assertions carry no prose, and citations need assertions.** An assertion is a pointer and
rules; explanations live in provenance. Every cited rule must be used by an assertion and every
assertion rule must be cited, so `rules` cannot accumulate unsupported citations.

**D-16. Refusal reasons are sets.** The specification fixes which transactions are refused but,
where several checks fail, not which reason a node names (decision QA-03). An expected `reasons`
array lists every acceptable reason; an implementation reports one of them.

**D-17. Deposits are raw envelope bytes.** A deposit's source hash, mint and system flag stay in
the authoritative bytes; decoded views are review aids. Synthetic messages cover pre-recovered
isolation and never count toward signature or envelope coverage.

**D-18. Block inputs are decoded headers with raw transactions, or raw block bytes.** The decoded
form is readable and hand-reviewable; the raw form preserves malformed encodings. The header codec
is the one of the chain's spec; a descriptor member naming codecs explicitly is left to phase 2,
together with the SALT mapping's binding to a SALT revision (`salt-v1` names the mapping of the
pinned spec).

**D-19. A schedule lists the specs whose rules apply to some block of the case.** `SATIN-ACT-011`
requires a configuration that schedules Satin to schedule every lower rung of the Mega spec ladder;
rungs activated at or before the anchor are implied, and a case testing configuration validation
carries the configuration's own bytes in `rawConfig`.

**D-20. A failed witness has no block results.** In `stateless-block`, `blocks`, `head` and `state`
are present exactly when the witness verified; a failure is typed by stage, reason and read.

**D-21. No MPT state root over partial state.** `mpt-state-root` is refused with a sparse or witness
pre-state; `salt-state-root` and the other typed commitments stay available.

**D-22. Checkpoints are provisional in shape.** They are keyed by call path, phase and ordinal as
the design recommends; their exact boundaries are settled when the first engine adapter exists, as
a minor version if the shape must grow.

## The packages

**D-23. Examples are illustrative.** Their encodings are real (signed with Ethereum's well-known
test key, RLP-encoded, anchors hashed with Keccak-256), but their expected values are neither
executed nor reviewed, and their provenance says so (`status: example`). Filling is phase 2.

**D-24. The second reader interprets the schemas.** `tools/check_vectors.py` shares no code with the
Rust crate: it executes the JSON Schemas (with the `x-` annotations) and its own port of the
semantic checks, so the schemas themselves are tested by the vectors. The Rust crate decodes into
typed structures with hand-written strict decoders instead.

**D-25. The Rust crate parses JSON itself and depends only on `sha2`.** A general JSON library
silently keeps the last of two duplicate members of a map, and numbers would need special
handling; a 300-line strict parser gives exact error codes. The crate depends on no execution
engine, node or transition tool.

**D-26. No license file yet.** The repository is to become public; the owner chooses its license
before publication.

## Contract tightening after review

A read-only review fuzzed both readers against each other (no disagreement found) and listed
contradictions the format still accepted. These were closed:

**D-27. Block-build actions form a state machine.** `commit` and `abandon` need a pending
`execute` of the same candidate; `committed` is a subsequence of the `commit` actions' order,
because a commit-time recheck (`SATIN-BLK-004`, `SATIN-BLK-005`) can refuse a commit the builder
attempted.

**D-28. The deposit feature comes from the bytes.** `feature:deposit` is derived from a `0x7e`
type byte of any transaction bytes in the input, `fields`-encoded block transactions included, and a
source's kind must agree with its bytes. A consumer without deposit support is told `unsupported`
for block cases too (every OP block starts with a deposit).

**D-29. `activeSpec` names a scheduled spec.** It must be the name of a schedule entry, and a
schedule names each spec once; the name is then unambiguous within a case.

**D-30. Assertions are ordered by path, one per path.** The last set-like array without an order
now has one.

**D-31. Failed imports and failed deposits are constrained.** With no accepted block, the head is
the anchor's number and the state diff is empty (the head hash needs Keccak-256, which the format
readers do not carry: consumers compare it); a failed deposit has no execution or a halted one; an
invalid block's spec and flags may be `null`, and only when it failed to decode.

**D-32. Synthetic messages must fit their type.** Fee fields, recipient, access list and
authorization list are checked against the EIP-2718 type; `null` means "not part of this type",
never zero.

**D-33. The registry is checked on load.** Both readers recompute each rule's `textDigest`, refuse
an unknown status or a non-string row, and require the descriptor to bind `sources.json` as well as
`rules.json`.

**D-34. Known limits of 1.0.** The header shape is the Satin-era header, every member required;
headers of forks that lack a member need a feature in a later minor version. A header's
`stateRoot` means what the chain's spec says it commits to; typed commitments in block results say
which root a case asserts. Envelope members cannot be added in a minor version.

## Phase 2: the vertical slice

**D-35. The registry follows the specification's main; older snapshots stay.** Two snapshots are
added beside `specs/satin-cac999a`: `specs/satin-22a5f4b` (407 ids; eight rules reworded around the
oracle service for deposits, Mega System Transactions and system calls) and `specs/satin-d34e626`
(408 ids, 399 active, 9 retired: `SATIN-BASE-011` added for a value transfer that would overflow
its recipient's balance, and `SATIN-ORCL-004` to `-006` reworded). The slice pins `d34e626`, the
newest; none of the rules it cites changed text between `22a5f4b` and `d34e626`. The older
snapshots are unchanged, because pinned material references their descriptor digests (the
examples and vectors reference `cac999a`'s): each case resolves against the registry it was
written for.

**D-36. Rex6 rule ids are assigned, mechanically.** The Rex6 text (mega-evm `d4c913c5`,
`docs/spec/`) names no rule ids. `tools/gen_rex6_registry.py` makes every normative block of the
`## Specification` section of each `spec: Rex6` page a rule: a paragraph or top-level list item
that uses a BCP 14 keyword in capitals, with the table or fenced block directly under it. The id is
`REX6-<AREA>-<NNN>`: the page's area code (the Satin code where the page has a Satin counterpart:
`LIM`, `ACCT`, `DET`, `KEY`, ...) and the block's ordinal on the page. The upgrade pages are
summaries without a `spec` field and give no rules. Rex6 is frozen, so the ordinals are stable for
this snapshot and every rule is active; a reworded Rex6 text would be a new registry, and its ids
would be assigned again. The result is 358 ids in 18 areas. The ids are this suite's, not the
specification's: a Rex6 case resolves them against this registry only, and a Satin id never
resolves under Rex6.

**D-37. Descriptors bind the codecs and the SALT mapping by value.** The descriptors of
`satin-22a5f4b` and `rex6-d4c913c5` carry `codecs` (the header's RLP field order and hash, the
EIP-2718 transaction types with the deposit, the receipt encodings with the deposit receipt's
nonce and version, and both trie roots) and `salt`: the mapping `salt-v1` stated as SALT defines
it (AHash 0.8.12's fallback hasher with fixed seeds, the 20-byte account key and the 52-byte slot
key, `hash mod (2^24 - 2^16) + 2^16`, the minimum bucket of 256, the multiplier), with hash and
bucket vectors and the reference implementation it was read from. `tools/salt_mapping.py` is a
standard-library port. Its bucket ids are the ones both implementations charge: the slice's
multiplier cases would be priced at the minimum bucket under any other mapping, and
`satin/sstore/fresh-slot/bucket-x16` lists its bucket alone with `complete: false`, so any other
bucket would be a missing input. The
members come from `tools/descriptor-members/`, passed with `--members`; the `cac999a` descriptor
has none and keeps its digest.

**D-38. An absent `salt` or `oracle` is no input, not a default.** In `state-transition`, a case
without `salt` states no capacity, so any bucket read is a missing input and the consumer reports
`error`; `{"complete": true, "buckets": {}}` is the way to say that every bucket is minimal. A case
without `oracle` states no service, so any oracle request is a missing input; `{"mode":
"disabled"}` is the way to say that the service answers nothing. Each meaning has one encoding.

**D-39. The adapter process interface.** An adapter is a program: `capabilities` prints its
declaration (profiles, specs by name, supported requirements, modes, and its build identity: the
implementation's repository and commit as its build resolved them, the compiler, the profile), and
`run [--instrumented]` reads one run request on standard input and prints one response. The run
request is the case's `caseId`, `specRef`, `profile`, `requires` and `input`, and nothing else, so
no adapter can read an expectation. The response carries the status (`ok`, `unsupported`,
`error`), the digest of the input the adapter ran, the observations and non-normative
diagnostics. The consumer refuses a response whose input digest is not the case's
(docs/adapter-protocol.md).

**D-40. Observation definitions the first adapters fixed.** Where the format named a value but not
its exact source, the definition is: a creation's `execution.output` is what its initcode returned
(the deposited code); `gasLedgers.refund` is the refund the receipt's gas used applies, zero when
the floor sets the gas used (`SATIN-POOL-018`); `gasLedgers.blockGas` is `max(regular, floor)`
(`SATIN-POOL-020`); a resource's `net` is the transaction's signed net at its end and `reported`
its `max(net, 0)` (`SATIN-LIM-007`), which coincide at the transaction's end, where no net is
negative; a deposit receipt's `depositNonce` is its sender's nonce before the deposit and its
`depositReceiptVersion` is 1; a failed deposit has no `execution`. Both adapters implement each
definition independently.

**D-41. Limit-stop cases wait for an observation the implementations do not expose.** The `limit`
group needs a stop's scope, call path, operation, phase and commit flags. Neither implementation's
public result carries more than the stop's dimension and limit, and deriving the rest through an
inspector would let instrumentation supply values the plain run cannot produce. Each adapter
therefore reports `error` for a case that ends in a limit stop, and the slice has none: a
limit-stop or rollback case needs an engine-side observation first.

**D-42. A synthetic message has no envelope.** Adapters run a synthetic message with empty
enveloped bytes, so its L1 data fee is that of an empty envelope; a case whose L1 fee matters
carries signed bytes. The slice uses signed transactions and deposit envelopes throughout, with
the L1 block contract present and its fee parameters zero.

**D-43. The slice's expectations come from an executable model of the rules.** `tools/satin_model.py`
restates the cited rules for the slice's class of transactions (one frame, a fixed set of opcodes,
calls, value transfers, creations, deposits, refusals), with every charge a step that names its
rule. `tools/make_slice.py` derives each case's expectation from it and records the derivation of
every assertion in `provenance.derivation`, and the text digest of every cited rule in
`provenance.review.ruleTexts`. The model was written from the rule text before either
implementation ran; one definition was corrected afterwards, a creation's output (D-40), which no
rule states. Cases stay `candidate` until the owner approves them.

**D-44. A disagreement is settled by the rule text, and a defect is quarantined, never outvoted.**
The revm-based implementation charges a deposit no history gas; `SATIN-HIST-016` and
`SATIN-DEP-001` make a deposit pay it for its body as any transaction does, and the evm2-based
implementation and the derivation agree with the rule. The three deposit cases keep the rule's
expectation, are kept out of the gating slice in `slice/quarantine/`, and record the implementation,
the first differing path and both values; `tools/run-slice.sh` checks that they still fail
exactly so on that implementation and pass on the other. When the implementation is fixed, they
move back.

**D-45. The evm2-based adapter declares no oracle transcript.** That implementation's oracle
service is a map from slot to value, which can check neither a transcript's order nor an answer of
none; the adapter says `unsupported` rather than approximate a transcript. The revm-based adapter
answers from the transcript in order and fails a request it does not answer or an entry no request
used.

**D-46. The exporter converts hand-written scenarios only.** `exporter/` dumps the hand-written
scenarios of the evm2-based implementation's differential crate at its pin; the fuzz batches stay
a discovery lane. Their senders have no keys, so every converted transaction is a synthetic
message; a scenario with a limit override, a simulation switch, earlier transactions of its block,
oracle answers without their order or an L1 fee is excluded with that reason, and so is one that
cites no active rule of the pinned registry. A converted candidate cites the scenario's rules
through one unreviewed assertion over the whole expected result and keeps its name and group as
aliases.

**D-47. The corpus archive is verified, not mirrored.** The release archive's bytes match the
published digest; its member inventory and the rule that maps an old member to a new case are in
[corpus-archive.md](corpus-archive.md). Where it is mirrored is the owner's decision.

**D-48. Each implementation is pinned by commit and built with its own toolchain.** The revm-based
implementation is a cargo git dependency at `5e3f30ad` with the patches of its own root manifest;
the evm2-based implementation and its evm2 fork are checked out by `tools/fetch-implementations.sh`
under the git-ignored `vendor/`, laid out so their relative `../../evm2` path resolves, and the
script refuses a fork pin that differs from the implementation's own `next/evm2-fork.env`. The
evm2-based pin moved from `6ef8c136` (fork `28e20011`) to `9e55185f` (fork `1a70ed94`, on upstream
evm2 `e0d398a6`) with no change to the slice's results, then to `f3d84454` (D-52). Each
adapter's lockfile starts from its implementation's own and builds `--locked`, with the
implementation's toolchain (`nightly-2026-04-23`). Neither adapter is a member of the root
workspace, so the format crate depends on no engine.

**D-49. The slice's file layout.** A case file is named by its `caseId` with `/` written as `--`;
`slice/index.json` lists the gating cases with their area, rules and file digest, the quarantine
with its recorded failure, and the negative case with the path it is wrong at. Both readers
validate every slice file, and the Python reader checks the recorded file digests.

From the review of the slice's derivations:

**D-50. In engine isolation, a gas limit above the block's is a refusal at inclusion.**
`SATIN-BLK-009` and `SATIN-BLK-013` make a transaction whose declared gas limit does not fit in
what the block's gas limit has left a skip for the current block, not an invalid transaction.
A `state-transition` case runs one transaction against an explicit block environment, whose gas
limit is all left; it reports that skip as `refused` at phase `inclusion` with reason
`gas-limit-exceeds-block`. Both adapters map the implementations' error to that phase. The
`block-build` profile, where a skip is a decision, is where the packing behaviour itself is tested.

**D-51. A halted frame's state and history charges are on the regular ledger.**
`SATIN-POOL-019` puts on the state and history ledgers the charges the transaction kept, and
`SATIN-POOL-014` consumes a halting frame's regular gas with the part of its charges regular gas
paid. A halted frame keeps none of its charges, so what regular gas paid of them is regular gas on
the ledgers: after a halt, the state ledger holds the charges kept before the frame and the history
ledger the body's, as `SATIN-DEP-005` has it for a failed deposit. The halt cases of the slice say
so in their intent; the specification's owner may confirm the reading.

From the move of the evm2-based pin:

**D-52. The evm2-based adapter makes its EVM through the implementation's factory.** The
evm2-based pin moved from `9e55185f` (fork `1a70ed94`) to `f3d84454` (fork `390a3876`, on upstream
evm2 `66687c18`). At that revision the implementation makes every EVM through a factory over a
validated chain configuration, prices state by a SALT snapshot of the parent state that the caller
supplies, and resolves the live system address once, when a single transaction's EVM is made, from
the SequencerRegistry in the state it runs on (`SATIN-REG-002`). The adapter supplies what the case
defines:

- the chain: Satin and every fork below it active from genesis, at the case's chain id. A validated
  configuration also carries the registry's bootstrap values, which seed a new registry in a
  block's pre-block sequence; a single transaction's EVM runs no such sequence, so the adapter's
  placeholders reach no observation;
- the SALT snapshot: the case's `salt` input as the format defines it (a listed bucket at its
  capacity; an unlisted one at the minimum when the input is complete, otherwise a missing input,
  as is every bucket of a case without `salt`, D-38). A capacity the snapshot cannot give fails the
  transaction inside the implementation, and the adapter reports the missing input by bucket;
- the live system address: whatever the pre-state's SequencerRegistry names, read by the
  implementation itself.

The adapter also builds evm2 and op-evm2 without their default features, as the implementation's
own workspace does, so the engine's precompile backends are the ones its members choose; the
adapter's lockfile is the implementation's, less what the adapter does not build, plus the adapter
and the format crate. Every observation of every slice case, the quarantined and the negative
included, is byte-identical to the one at `9e55185f`.
