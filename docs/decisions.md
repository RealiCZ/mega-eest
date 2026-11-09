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
