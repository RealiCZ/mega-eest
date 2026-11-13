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
limit-stop or rollback case needs an engine-side observation first. Superseded by D-62.

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
implementation is a cargo git dependency at `5e3f30ad`, later `4e39cfd6` (D-53), with the patches
of its own root manifest;
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

**D-53. The revm-based pin moves to `4e39cfd6`; the SALT member keeps the revision it was read
at.** The revm-based pin moved from `5e3f30ad` to `4e39cfd6`, on the same revm and op-revm forks
(`4c8f0d43`, `8c0db939`) and with the same root manifest, lockfile and toolchain, so the adapter's
versions and patches are unchanged and only the revision moves. The revision adopts four rules of
the specification:

- `SLOTNUM` pushes zero (`SATIN-BASE-005`);
- a value-bearing `sendHint` is admitted (`SATIN-ORCL-006`);
- a deposit and a Mega System Transaction ask the Oracle service nothing (`SATIN-ORCL-005`);
- `keylessDeploy` is recognized only once its arguments decode (`SATIN-ICPT-006`).

It also derives the activation-block rules in its block executor and has its test database apply
EIP-161 on commit; the adapter uses neither, as it runs `MegaEvm::execute_transaction` over its
own database, so no adapter change was needed. The revision still prices no history gas for a
deposit: the three quarantined cases fail on it exactly as recorded and pass on the evm2-based
implementation. Their records name `5e3f30ad`, the revision they were recorded against, and the
verdict holds at `4e39cfd6`. Every observation of every slice case, the quarantined and the
negative included, is byte-identical to the one at `5e3f30ad`.

The SALT member of the descriptors (`tools/descriptor-members/`, `salt.reference`) names the
revision its mapping was read from, `5e3f30ad`. The mapping's source
(`crates/mega-evm/src/external/hasher`) is byte-identical at `4e39cfd6`, so the member's data is
the same at both revisions, and the member keeps the revision it was read at: the descriptor
digest, which every case's `specRef` carries, does not move with an implementation's pin.

From the cases for interception, the keyless decoder and EIP-7702 existence:

**D-54. Cases added after the first slice cite the newest snapshot.** The cases added for
interception before the frame start, the keylessDeploy decoder and EIP-7702 existence cite
`specs/satin-d334ef8`, which states `SATIN-ICPT-007`; the first 63 cases, the quarantine and the
negative case keep `specs/satin-d34e626` and stay byte-identical. Each case carries its own
`specRef`, and an entry of `slice/index.json` names its spec when it is not the index's.

**D-55. A case's pre-state carries the code of every system contract a call can reach.** The new
cases hold the Oracle 2.0.0, KeylessDeploy 1.0.0, MegaAccessControl 1.0.0 and MegaLimitControl
1.0.0 at their addresses, with the code the specification names by hash (its system-contracts
overview at `d334ef8`), nonce zero and no balance, as the pre-block deployment leaves an address
that held no account. `tools/system-contracts.json` holds that code, read from the revm-based
implementation's versioned artifacts at `4e39cfd6`, and `tools/make_slice.py` refuses an entry
whose keccak256 is not the specification's hash. The first 63 cases make no call: the L1 block
contract and the SequencerRegistry hold a placeholder (`0xfe`) there that no call reaches.

**D-56. Readings the call derivations fix.**

- A start its frame start refuses (a value the caller cannot fund) and a call an interceptor
  answers return the child's whole regular gas to the caller, `CALL_STIPEND` included: the
  child's gas is the forward plus the stipend (`SATIN-FWD-003`), the forwarded gas returns
  untouched (`SATIN-ICPT-004`), and the caller's regular gas rises by what the child returns
  (`SATIN-POOL-012`). This is an owner decision, and it is the base layer's behaviour: a call that
  starts no frame returns the stipend with the rest of the child's gas, and both implementations
  do so. Such a value call therefore costs its caller 9,000 of the value transfer's 11,300.
- A value start's records, the caller's account and the callee's, are charged by the calling
  opcode after the forward, which they do not reduce (`SATIN-HIST-009`, `SATIN-HIST-010` step 4),
  and before the depth gate, interception and the frame start (D-58), as the state stands: a value
  the caller cannot fund makes no record and is charged none (`SATIN-HIST-015`). When a start
  that makes records does not happen, or the child fails, their history goes back into the
  caller's reservoir (`SATIN-HIST-007`, `-012`), never into its regular gas. The caller's next state charge pays its
  legacy share from regular gas first, and only then draws that reservoir (`SATIN-POOL-008`); a
  history charge, which has no legacy share, draws it first.
- An authority's `ACCOUNT_WRITE` is regular gas: `SATIN-TAKE-008` puts it in the regular-gas
  column of an authorization list's writes, and `SATIN-SCHED-003` lists it, EIP-2780's account
  write, among the gas schedule's entries at 9,000. `SATIN-AUTH-015` says when it is charged:
  before the first frame, and only for an authority whose write the transaction has not paid.
  The delegation indicator's state gas is `DELEGATION_STATE_BYTES` × 1,530 at the authority's
  bucket, 35,190 at the minimum.
- The data-size stop of a hint is reached without a 13 MB fixture: twelve admitted hints of 1 MiB,
  each forwarded 1 gas and halting at the Oracle's first opcode, count 12,582,912 bytes, so the
  thirteenth would cross `TX_DATA_LIMIT`.

**D-57. Every figure in the slice's text follows the model's constants.** A figure in a case's
intent or boundary, its derivation, a quarantine verdict or `slice/README.md` that depends on a
constant of the specification is written from that constant in `tools/satin_model.py` or
`tools/make_slice.py`, never typed: prices, the products and sums of them, the inherited opcode
costs the interpreter charges, and the inputs a case derives from them (a gas limit one below a
threshold, the number of hints that fit under the data-size limit). The worked example of
`SATIN-POOL-019` is computed from the constants by its own arithmetic, and the slice refuses a
derivation that does not reproduce it. `tools/check_derived_text.py` regenerates the slice with
`COST_PER_HISTORY_BYTE`, `COST_PER_STATE_BYTE` and `KEYLESS_DEPLOY_OVERHEAD_GAS` each changed in
turn and fails if any text still shows a figure computed from the old value; `tools/run-slice.sh`
runs it. The quarantine's recorded failures (`knownFail`'s expected and actual values) are records
of an implementation's run, not text, and stay as recorded.

**D-58. Orders the owner decided for calls and for the charges before the first frame.** The
specification at `d334ef8` leaves these orders implicit; the owner decided them as both
implementations already run them, and the specification is to state them as a principle in its
next round. `tools/satin_model.py` follows them.

- History before interception. A calling opcode charges the history of the records its start
  would make, as the state stands when the opcode runs, with its other charges: after the forward
  (`SATIN-HIST-010` step 4), which it does not reduce, and before the depth gate, interception
  and the frame start (`SATIN-ICPT-007`). `SATIN-HIST-015` holds, and the model follows it: a
  value the caller cannot fund makes no record, so the opcode charges no record history for it
  and has none to give back, as both implementations do. A start whose records exist, the caller
  able to fund the value, and which does not happen (an interceptor's answer, a hint's data-size
  stop) gives that charge back into the caller's reservoir when the call returns
  (`SATIN-HIST-012`); a refusal for depth is unreachable under the execution cap. A start that
  happens makes the records at the frame start, where nothing more is charged for them. The
  model used to charge the records at the frame start, so an answered call was charged nothing.
  No figure of a case moved. In the three interception cases whose caller can fund its value,
  the caller's regular gas pays the records' history in the opcode, and its reservoir holds that
  history after the call (an interceptor's answer, or a child that reverts), pays part of the
  next state charge once regular gas has paid its legacy share, and returns what is left to the
  sender. The four whose caller cannot fund it, the hint stopped for the data-size limit among
  them, are charged no record history.
- The delegate's access. A transaction whose recipient holds an EIP-7702 delegation once the
  list is applied pays its delegate's access before the first frame, after step 4 of
  `SATIN-SCHED-008`, in regular gas, as the base layer charges it under EIP-2780: the warm read,
  then the cold account surcharge when the delegate is not warm (`SATIN-SCHED-003`). The
  delegate is loaded only when the regular gas left after the warm read pays the surcharge; a
  transaction that cannot pay it takes the out-of-gas path before the first frame, which the
  model leaves unmodelled. The delegate's code runs in the recipient's frame. No case sends a
  transaction to a delegated recipient, so no figure moved.
- The authorities' records first. Of the history charged before the first frame
  (`SATIN-SCHED-008` step 3), the applied authorities' records draw the reservoir first, as the
  list is applied, and the first frame's start record draws what they left (`SATIN-POOL-024`).
  The model already charged them in that order.

**D-59. The edges of the charge-order principles.** The specification at `5fb2688` states as
principles the orders D-58 recorded as the owner's decisions: the order around a frame start
(`SATIN-HIST-023`), the delegate's access before the first frame (`SATIN-SCHED-008` step 5) and the
reservoir paying the authorities' records first (`SATIN-HIST-005`). Twenty-seven cases pin their
edges, and those of two decided rules the revm-based implementation has not made yet.

- The new cases cite `specs/satin-5fb2688`. The model cites the principles for them, and D-58 for
  the cases at `d334ef8`, whose text stays as it was; every earlier case, the quarantine and the
  negative case are byte-identical.
- One input, one case: a boundary is two cases, one gas or one byte each side of it. A case on a
  gas threshold sets its gas limit from the model's own figure at a point of its run (the regular
  gas when the call computes its forward, when the first frame starts, or before the delegate's
  access), so the input follows the constants as the text does (D-57).
- Observables. No adapter reports the pools, the reservoir or the read set, so the cases observe
  what both implementations report: `GAS` stored in a slot right after the call, before any later
  state charge draws the reservoir, for a charge given back into the reservoir (`SATIN-POOL-009`
  makes `GAS` read regular gas alone); the outcome and gas used for a caller that cannot pay the
  records; the data size for a hint. The read set of an authorization list that runs out of gas
  part-way, and whether a delegate was loaded, are not observed.
- Out of gas before the first frame (`SATIN-SCHED-009`, `-010`) is modelled for a transaction
  with nothing applied before the charge it cannot pay but validation's changes to the sender:
  the execution halts with empty output, gas used is the gas limit less the reservoir left, and
  the ledgers hold the intrinsic gas and the body's history alone. A transaction whose list was
  applied, or whose reservoir paid part of the charge, stays outside the model.
- The transaction's own start record before interception answers its `keylessDeploy` call: the
  input that separates charging it before the first frame from not charging it at all is a gas
  limit that covers everything but one gas of it, with which the frame cannot pay step 1's
  overhead and halts. A transaction that cannot pay the record itself runs out of gas before its
  first frame, but a transaction that never charged the record would not be answered either, so
  that input does not separate the orders.
- The model adds `GAS`; a value `CALL` to an account empty under EIP-161 (the new account's state
  gas with its legacy share at `SATIN-HIST-010` step 2, before the forward, given back into the
  caller's reservoir when the start is refused, `SATIN-POOL-015`); a caller that cannot pay its
  start's records halting in the opcode; an EIP-7702 delegated sender, which EIP-3607 admits; and
  a recognized `keylessDeploy` call that halts at step 1.
- Seven cases fail on the revm-based implementation at `4e39cfd6` and are quarantined: six store
  `GAS` after a give-back, which that implementation credits to regular gas (`SATIN-HIST-012`),
  and one is a deposit with a log, which it charges no history gas (`SATIN-HIST-016`). Their
  `knownFail` figures are derived as their verdicts state them, the rule's figure plus the
  reservoir the frame holds when `GAS` reads, or less the deposit's history, so they follow the
  constants as the text does; each was checked equal to that implementation's run, and
  `tools/run-slice.sh` checks it again on every run.
- `tools/check_derived_text.py` moves `KEYLESS_DEPLOY_OVERHEAD_GAS` by seven instead of one: a
  case one gas below the overhead would otherwise show the old value as its own, correctly
  derived, figure.

**D-60. Gas detention, the Oracle's reads and the refused volatile read.** Ten cases at `5fb2688`
pin the remaining edges of the charge-order principles, one charge under gas detention
(`SATIN-DET-018`, `-020`), and two decided rules the revm-based implementation has not made yet:
the Oracle's `SLOAD` reads and marks before its one charge (`SATIN-ORCL-004`), and a refused
volatile read charges nothing (`SATIN-MAC-003`, `-004`).

- The model restates detention for the reads these cases make: `TIMESTAMP`, a deposit's `SLOAD` in
  the Oracle's frame, and `BALANCE` of an account that is not the beneficiary. A read sets the
  limit `compute + cap` (`SATIN-DET-012`); compute is every regular charge a frame makes, never a
  forward nor the regular part of a state or history charge, which draw a detained frame's
  withheld part first (`SATIN-DET-009`, `-017`). A frame is split into spendable and withheld parts
  when a read completes and when it starts or resumes (`SATIN-DET-014`). Each part an opcode
  deducts is a charge of its own: `RETURNDATACOPY` and `KECCAK256` now charge their static cost
  and their per-word cost apart, which moves no figure. A charge the spendable part cannot pay
  and the whole regular gas can is the crossing, which stops a child frame with
  `MegaLimitExceeded(2, limit)` and returns its whole regular gas; one the whole cannot pay is an
  out-of-gas. An `SSTORE`, or an `SLOAD` outside the Oracle's frame, in a detained frame stays
  outside the model, as does a stop of the transaction's own frame (D-41).
- A detained frame's spendable part is reached by burning compute after `TIMESTAMP`: one memory
  expansion and a run of `JUMPDEST`s, sized from the model's own figure for what the limit leaves
  the transaction where the case needs it (D-57, D-59). Since the limit then leaves the caller
  almost nothing, the caller returns its child's return data as the transaction's output, which
  costs no more than it has; where the static cost leaves it nothing, it stops.
- The Oracle cases are deposits: a deposit's read asks no oracle service (`SATIN-ORCL-005`), and
  the evm2-based adapter runs no oracle transcript, so a transaction's read could not run on both
  implementations. A read short of its charge shows its mark through a later call whose one memory
  expansion passes the Oracle's cap, which the mark stops.
- `disableVolatileDataAccess()` is answered by the node for the calling frame; a `BALANCE` of the
  beneficiary after it reverts the frame with `VolatileDataAccessDisabled(10)` before any charge.
- Five cases fail on the revm-based implementation at `4e39cfd6` and are quarantined; their first
  difference is the regular ledger the block counts. The two refusals' figures are derived, as
  their verdicts state them. The three Oracle reads' figures are that implementation's run,
  recorded: they follow from what it does once it skips the read or crosses early, which the
  model does not restate.

**D-61. Both adapters report `reads`, compared exactly.** A case that requires `group:reads`
holds what its transaction loaded, as the stateless witness needs it (`SATIN-WIT-001`, `-002`,
`-008`), and the comparison holds an implementation to that set exactly, as every group is held:
a load the specification does not require is a difference as much as a missing one, so a load the
gas skipped (`SATIN-WIT-012`) and a delegate not loaded (`SATIN-SCHED-008` step 5) can be pinned.

- Each adapter records the loads that reach its fixture database, its SALT environment and its
  oracle service, building them afresh for each run; it reports `reads` for a case that requires
  the group, in plain and instrumented runs alike, so the two runs' observations stay the same
  bytes (`tools/run-slice.sh`), and none for a case that does not. No engine changes.
- `codes` is the code hash of every account read whose code is not empty, with any code loaded
  by hash: the witness holds the code of every account it names, however the engine loaded it.
- The transaction's reads are its own. The evm2-based implementation resolves the live system
  address off the SequencerRegistry when its factory makes the EVM, as a block does once before
  its transactions (`SATIN-REG-002`); its adapter records from the transaction's start and adds
  what the transaction's returned state names that the factory loaded first. The revm-based
  implementation reads the registry's account and slot 0 in every transaction's validation; its
  adapter reports the read, which `SATIN-REG-002` excludes, so every case with `reads` fails on it
  at the registry's account, or earlier, and is quarantined with that verdict.
- The model derives the reads of the new cases only: the sender at validation; each authority the
  list's simulation loads, the whole list walked (`SATIN-AUTH-005`); the recipient at step 4 and
  the delegate at step 5, each only once reached and paid (`SATIN-SCHED-008`); every account and
  slot a frame loads, an Oracle slot before its charge (`SATIN-ORCL-004`) and a cold load only
  once its access is paid (`SATIN-WIT-012`); the SALT capacities its state charges are served; and,
  for a transaction that is not a deposit, the L1 block contract's slots 1, 3, 7, 8 and, with empty
  Ecotone scalars, 5 (`SATIN-WIT-011`), and the four fee recipients its settlement credits.
- `oracle` lists the service's answers to a recorded transcript; the cases are deposits, whose
  reads ask no service (`SATIN-ORCL-005`), and the evm2-based adapter runs no transcript, so no
  case pins it. `hints` lists the hints each implementation hands its service.

**D-62. The `limit` group keeps what the implementations expose; D-41 is superseded.** D-41 held
limit-stop cases out of the slice because the stop record required a scope, call path, operation,
phase and commit flags that neither implementation's public result carries. The cost was that no
case stopped the transaction's own frame, so the resource-limit and stop rules (`SATIN-LIM-*`,
`SATIN-STOP-*`) were pinned only through stops a caller caught. The owner approved splitting the
record, and schema 1.1 does so:

- **Mandatory.** A stop carries its `dimension`, its `limit` and its `returnData`,
  `MegaLimitExceeded(kind, limit)` of the two. Both implementations report the stop of a
  transaction's own frame by its kind and limit (`SATIN-STOP-021`: the revert data alone is not
  the stop), and the frame's revert output is the return data. A reader checks that the output,
  the return data and the dimension and limit agree.
- **Optional diagnostics.** `scope`, `callPath`, `operation`, `phase`, `operationCommitted` and
  `enclosingCommitted` are each optional, carried behind `group:limit-diagnostics`, and compared
  only where a case carries them. An adapter supplies one only where its implementation's result
  carries it, never from an inspector; neither adapter supplies any today.
- **Versioning.** The change is a minor version (`docs/versioning.md`): a 1.1 stop requires
  `group:limit-stop`, so a 1.0 reader stops at `unknown-requirement` instead of misreading it. A
  1.0 file means what it meant: a 1.0 stop carries every member and requires neither new group, and
  every existing fixture, whose `limit` is `null`, stays 1.0 and byte-identical. Only a case whose
  expected `limit` is a stop is written as 1.1.
- **Adapters.** Each reports a stop of the transaction's own frame from its implementation's report
  of it (the revm-based implementation's `limit_stop()`, the evm2-based implementation's top-frame
  stop when the frame's result is that stop's revert) instead of `error`, and declares
  `group:limit-stop`.
- **The model** settles a stop of the transaction's own frame as a revert (`SATIN-STOP-009`,
  `-011`): gas detention's crossing (`SATIN-DET-018`), and the limits on an `SSTORE`'s record and a
  log's bytes, held to the frame's budget and then the transaction's limit in the order of
  `SATIN-LIM-010` and `-011`, the frame's budget being what the transaction had left when it started
  (`SATIN-LIM-002`) and an admitted hint on no frame (`SATIN-LIM-012`, `SATIN-STOP-012`).

**D-63. The model derives the edges of rules, and is cut into modules by domain.** The model behind
the slice's expectations (D-43) derives the expected values of small, hand-built cases at the edges
of rules: atomic rules (a price, a predicate, an encoding, a record, a give-back) and the order of
charges and decisions, from the specification's text and constants. It is not a general EVM, does
not run arbitrary bytecode, and does not cover wide combinations of frames, calls and limits: the
implementations and the differential gates of the evm2-based implementation's repository
(`next/diff`), which compare two independent engines over thousands of shared scenarios, cover that
breadth. An expectation taken from two engines' agreement rather than derived from the specification
would be a different kind, labelled apart if it is ever added. The model is not the executable
specification; that is a direction, not a decision. `docs/model.md` states the scope and maps the
modules.

- To keep it bounded before the take-back cases, `tools/satin_model.py` became the package
  `tools/satin_model/`: the constants, the records, and a `Run` composed of one mixin per domain (the
  transaction, settlement, the pools, gas detention, the interpreter, calls, interception,
  authorizations, storage, reads and the resource limits). The code moved verbatim: every generated
  byte is the same, and `import satin_model as model` reads as before.
- `tools/check_derived_text.py` copies the package and changes the constants in its `constants.py`.
- The cases' provenance and `slice/README.md` still name `tools/satin_model.py`: the text is part of
  the cases' bytes, which the split keeps, and changes when the cases are next regenerated.

**D-64. `gasPools` describes the transaction's first frame, read by a passive recorder.** The
take-back rules are about which pool receives a give-back, so the pools are now observed directly
instead of through a stored `GAS` (D-59). Both adapters report `gasPools` for a case that requires
`group:gas-pools`, from a recorder of frame starts and ends that changes nothing the run does,
attached in plain and instrumented runs alike so the two stay the same bytes (`PARITY`); the
mandatory groups still come from the implementations' results alone. No engine changes.

- **Start.** Neither implementation exposes the pools before the charges made before the first
  frame, so `initial` is the first frame's start: the regular gas and the reservoir its depth-0 call
  or create, or first message, receives, after the authorities', the pre-frame history, a new or
  created account's state gas and a delegate's access. The model derives the pools from the
  transaction's own start where a case needs them.
- **End.** `final` is what the first frame's gas holds when its outcome returns.
- **No frame.** A transaction that runs out of gas before its first frame has no frame to observe:
  its regular gas is zero at both ends and its reservoir, at both ends, is what returns to the
  sender (`SATIN-SCHED-010`).
- **`spilled`** is exactly the format's: the regular gas the first frame and the children that
  returned to it paid for state and history charges, legacy shares included, which no give-back
  credits back (`SATIN-POOL-008`, `SATIN-HIST-012`). Both implementations count it in
  `state_gas_spilled`; the revm-based implementation's counter falls when it credits a give-back to
  regular gas and has no legacy share in it, so its figure differs on exactly the cases where its
  rule does, and those cases are quarantined with that rule's verdict.
- **`returned`** is the gas limit less the receipt's gas used.
- The model derives `gasPools` for the cases that ask, from the first frame's pools and a running
  count of the regular gas its state and history charges drew, for a first frame that succeeds.

**D-65. The take-back page's worked examples are cases, and the model learns their shapes.** The
specification's rule is that a worked example lives in a conformance case, the case coming first and
the example leaving the text after it (the owner's QI-30 at `cdded1e`). The nine examples of the
take-back page (`SATIN-TAKE-005` to `-012`) are now derived at `cdded1e` (`specs/satin-cdded1e`), in
the area `take-backs`: seventeen cases, an example's endings and variants each a case of its own. Each
reproduces its example's figures; where the observation is which pool receives a give-back, the case
carries `gasPools`, and a frame whose own end the example is about is a child of the first frame, so
that what it returns shows in the first frame's reservoir.

- **The model's scope grows to these shapes** (D-63 amended, `docs/model.md`): child frames at the
  depth a case builds that write, log, call, succeed, revert or halt, with their reservoir share
  (`SATIN-POOL-011`), budgets (`SATIN-LIM-003`) and rollback (`SATIN-POOL-014`); value starts that
  make and take back account records (`SATIN-ACCT-006`, `SATIN-HIST-009`); a value start to an
  account without code held to the started frame's budget (`SATIN-LIM-013`, `SATIN-STOP-014`); a
  value child's history allowance (`SATIN-HIST-019`); an EIP-7702 list whose second entry for one
  authority clears the delegation (`SATIN-AUTH-009`); and a deposit whose own frame halts
  (`SATIN-DEP-004`, `-005`). The interpreter gains three opcodes, `DELEGATECALL`, `CREATE` and
  `SELFDESTRUCT`, each in the narrow form the examples use: a `CREATE` that succeeds, and the first
  `SELFDESTRUCT` of an account created in the transaction. Anything else stays `Unmodelled`.
- **A child's state and history charges are no regular charge.** The regular gas a child draws for
  them is on the state and history ledgers when kept, or in a reservoir when given back; it is on the
  regular ledger only when the frame halts and its regular gas is consumed with them
  (`SATIN-POOL-019`, D-51).
- **`spilled` keeps D-64's definition through a halt.** The regular gas a halted frame paid for state
  and history stays spent (`SATIN-POOL-014`, `SATIN-HIST-012`), so it stays in `spilled`. The
  evm2-based implementation reports it so; the revm-based implementation's counter drops it, and the
  two halt cases are quarantined with that verdict.
- **What the cases cannot hold of the text.** The answer-stopped example's KV budget of 3 cannot be
  reached under the protocol's KV limit of 500,000 (half a million records cost more gas than a
  transaction holds), so the same start is pinned on the state-growth budget: P is the first frame,
  whose budget is the transaction's whole 1,000 (`SATIN-LIM-002`), its 999 fresh slots leave it 1,
  and the stop is `MegaLimitExceeded(3, 0)` in place of the text's `(1, 0)`; every other figure of
  the example is the text's, and the first frame's final reservoir is exactly the two charges the
  stop gives back. The reverted and halted child
  receives 50,009 of regular gas, so that it holds the text's 50,000 at its write, the 9 being the
  operands it pushes first.
- **The failed-deposit example's floor.** Both implementations report a failed deposit's `floor` as
  0, where the model first derived the transaction's EIP-7623 floor (`SATIN-POOL-020`). The
  specification states no floor for a failed deposit, which settles in place of the settlement
  (`SATIN-TAKE-012`); D-66 decides it, and the case follows D-66.

**D-66. A failed deposit's gas ledgers are exactly `SATIN-DEP-005`'s; D-40 is amended.**
`SATIN-DEP-005` fixes a failed deposit's ledgers: its whole gas limit as regular gas, and no state
and no history gas. No settlement applies a floor or a refund to it, so the format reports both as
0: `gasLedgers` of a failed deposit is `total = regular = gasUsed = blockGas =` the gas limit,
`state = history = refund = floor = 0`, and `historyBytes` the bytes it keeps (`SATIN-HIST-022`,
`SATIN-DEP-006`). `blockGas = max(regular, floor)` is then the gas limit whatever the floor is, so no
consensus figure depends on the choice: it is a reporting convention of the format, of D-40's kind,
not a rule of the specification. Both implementations already report it so. D-40's `floor`, "the
EIP-7623 floor", now reads: the EIP-7623 floor the settlement applies, and 0 for a failed deposit.

**D-67. Gas detention's uncited rules are cases at `cdded1e`, and the model learns the reads and the
precompiles they need.** Fifty-five cases under `satin/detention/` cite the gas detention page of
`cdded1e` (`specs/satin-cdded1e`; the page is unchanged at the specification's later commits). Each
pins a rule where its outcome changes, most as a pair: one case tuned to land exactly on the edge
and its twin one step past it, sized from the model's own figure (D-57, D-59).

- **What is volatile.** A read shows in one memory expansion past the cap after it, which the read
  stops with `MegaLimitExceeded(2, limit)` and nothing else does: `BLOBHASH` is no read
  (`SATIN-DET-002`); `BLOCKHASH` of the current, a future and an in-range block is
  (`SATIN-DET-004`), as are `COINBASE`, `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBBASEFEE`, `SLOTNUM`
  and `EXTCODESIZE` and `EXTCODEHASH` of the beneficiary (`SATIN-DET-001`); `BALANCE` of another
  account, a contract's own `SELFBALANCE` and its own storage are not. A call to the EIP-2935 history
  contract is a read when its code completes `NUMBER`, forwarded exactly the gas to it, and none when
  forwarded one gas less or refused by its input check (`SATIN-DET-005`). A creation onto the
  beneficiary's address is no read, from a transaction or by `CREATE` with access off; its initcode,
  running as the beneficiary, reads by `SELFBALANCE` (`SATIN-DET-006`, `-007`). A transaction whose
  sender, recipient or applied authority is the beneficiary is detained from its start, its limit
  the cap exactly (`SATIN-DET-008`).
- **Compute and the cap.** The limit is the compute at the read plus the protocol's cap, exactly,
  after a spend larger than the cap too, and a later read with a higher limit binds nothing
  (`SATIN-DET-012`, `-013`); state and history gas paid before the read is no compute, and a
  give-back after it lifts nothing (`SATIN-DET-009`); what a value call's callee runs on its stipend is compute, and the stipend's rest
  lowers nothing when it returns (`SATIN-DET-010`). A user's deposit is detained (`SATIN-DET-026`).
- **The withheld part.** `GAS`, the forward and `SSTORE`'s minimum-gas check read the whole regular
  gas (`SATIN-DET-015`); the settlement returns the withheld part and leaves it out of the refund's cap
  (`SATIN-DET-016`); a fresh slot's state gas and its record's history draw it first
  (`SATIN-DET-017`).
- **Precompiles.** The identity precompile priced at the allowance runs, one past it is the crossing,
  priced at its forward is the crossing and one past its forward runs and fails, burning no compute;
  a value call priced past the allowance moves nothing, one its caller cannot fund is refused as
  without the read, and one within the allowance runs (`SATIN-DET-021`, `-022`, `-024`). ModExp over
  EIP-7823's bound is priced by its formula and is the crossing one past the allowance; a BN254
  pairing over its size limit is priced at zero (`SATIN-DET-023`, `-024`).
- **The model.** The interpreter gains `NUMBER`, `BLOCKHASH`, `BLOBHASH`, `SELFBALANCE`, `COINBASE`,
  `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBBASEFEE`, `SLOTNUM`, `MOD`, and `EXTCODESIZE` and
  `EXTCODEHASH` of the beneficiary; `SSTORE` in a detained frame, its static cost a charge of its own
  (`SATIN-SCHED-002`, `-003`, `SATIN-DET-018`); a call to a precompile, warm from the start
  (`SATIN-SCHED-012`), decided from its price for the identity precompile, ModExp and the BN254
  pairing over its size limit (`precompiles.py`); the beneficiary's detention before the first frame;
  and the CREATE and creation onto the beneficiary. The steps that cite the readers, the stipend, the
  settlement and the caps are written for these cases alone (`Run(detention=True)`), so every case
  made before stays byte-identical.
- **Not cased.** `SATIN-DET-025` needs an intercepted answer that spends regular gas; MegaAccessControl's
  and MegaLimitControl's answers charge nothing (`SATIN-ICPT-004`), and KeylessDeploy's from a frame is
  outside the model. `SATIN-DET-027` is a node's local choice of precompiles, which no transaction can
  show. The system-originated half of `SATIN-DET-026` needs the block's live system address, which the
  pre-block sequence resolves (`SATIN-REG-002`): a block profile's.

**D-68. Two detention cases are quarantined against the revm-based implementation.** At
`4e39cfd6` it fails two of D-67's cases, each against a decided rule; both pass on the evm2-based
implementation, and their first differences are derived. A user's deposit is detained as the rule
has it, but its gas used is short by its body's history (`SATIN-HIST-016`), as every deposit case's
is. A ModExp input over EIP-7823's bound priced one past the allowance is run instead of answered with
the crossing (`SATIN-DET-023`, `-024`): the call fails and consumes its forward, so the regular ledger
is above the rule's by that forward, less the copy of the stop's return data the rule's caller makes.

**D-69. The readings D-67's cases take where the page leaves a figure open.** None of them moves a
figure a case asserts; each is stated in the derivation that uses it.

- A precompile priced within the allowance that then fails a check made after its gas charge (ModExp
  over EIP-7823's bound) counts its charged price as compute and the rest of the forward it consumes
  as none: paid work before the halt counts and what a halting frame burns does not
  (`SATIN-DET-011`, `-019`). The case that runs it ends with no further charge. Superseded by D-78.
- A value call's forward, against which a precompile's price is held, is the child's whole regular
  gas, the stipend included, as `SATIN-DET-011` and `SATIN-STOP-014` count it; the value cases sit far
  from that edge.
- A value call to a precompile is made to an account the state holds, so the start makes no new
  account: the model does not restate the state gas of a precompile's account created by a value.

**D-70. The destruction page's own rules are cases, and the model learns the destruction's other
shapes.** The rules of SELFDESTRUCT and the Destruction Table that no case cited (`SATIN-SD-001`,
`-002`, `-003`, `-010` to `-017` and `-020`) are now derived at `cdded1e` (`specs/satin-cdded1e`;
the page is the same bytes at the specification's later main, so no snapshot is added), in the area
`selfdestruct`: 29 cases, each pinning a rule where its outcome changes, with a control beside it
where one is cheap. The scenarios come from the existing tests of both implementations; every
expected value comes from the specification through the model.

- **Citations.** A case of the area runs the model with `destruction` set, and the steps that apply
  the page's own rules cite them: the first effective destruction and its mark (`SATIN-SD-002`), a
  destruction of an account the transaction did not create (`SATIN-SD-012`), one while the mark
  stands (`SATIN-SD-011`), a store or a code deposit of the marked account (`SATIN-SD-013`, `-014`),
  value sent to it and its removal at the transaction's end (`SATIN-SD-015`), a mark a failed frame
  discards (`SATIN-SD-010`), the slots of an address created onto that read zero (`SATIN-SD-003`,
  `-016`), its present leaf (`SATIN-SD-017`) and a read of the block beneficiary marked last
  (`SATIN-SD-020`). The take-back examples (D-65) run without it, so their derivations, and every
  existing slice file, are unchanged.
- **The model's scope grows** (D-63 amended, `docs/model.md`): a `SELFDESTRUCT` of an account the
  transaction did not create, in the transaction's own frame or below it, to another account, to the
  sender or to itself; a repeated `SELFDESTRUCT` while the mark stands; the marked account, kept until
  the transaction ends with its code, which still runs, and then removed with the balance it holds;
  an `SSTORE` of its slots that leaves the refund counter as it is; code deposited after a
  constructor destroyed its own account by `DELEGATECALL`; a creation onto an address whose leaf the
  state holds with nonce zero, no balance, no code and storage; a destruction in a frame that fails;
  and a destruction whose beneficiary is the block beneficiary, a volatile read. No opcode is added to
  the interpreter: the `SELFDESTRUCT`, `CREATE` and `DELEGATECALL` of D-65 take these shapes. Anything
  else stays `Unmodelled`.
- **The marked account is deleted at the end, not at the opcode.** The model removed a destroyed
  account at its `SELFDESTRUCT`; it now keeps it in the run's state, marked, so that a later call runs
  its code and a later value reaches it (`SATIN-SD-015`), and the state diff deletes it. The take-back
  examples' figures do not move.
- **One quarantine.** The 28 gating cases pass on both implementations; none observes the pools.
  A 29th shows where the table's give-back lands without them: once it is back in its creator's
  reservoir (`SATIN-SD-005`, `SATIN-SD-010`), the creator calls a child that halts, which burns the
  regular gas it was forwarded and returns its reservoir share (`SATIN-POOL-014`). The revm-based
  implementation credits the give-back to regular gas (its departure from `SATIN-HIST-012`, D-65),
  so the creator forwards most of it and the child burns it; its gas used is above the rule's by
  what the forward grows by, a figure the generator derives from the run. The case is quarantined
  with that verdict and passes on the evm2-based implementation.

**D-71. A `SELFDESTRUCT` to a cold beneficiary pays the whole cold account access.**
`SATIN-SCHED-003` lists the cold account access as an addition to the warm read, which is how an
opcode whose static gas is the warm read pays it. `SELFDESTRUCT` pays no warm read: EIP-2929
charges its cold beneficiary the whole cold account access, which EIP-8038 prices at
`COLD_ACCOUNT_ACCESS`, and `SATIN-SCHED-001` keeps every entry the table does not restate at
Amsterdam's. The model charged the addition alone, on a path no gating case had reached (the
take-back examples warm their beneficiary first); both implementations charge `COLD_ACCOUNT_ACCESS`.
The model now charges it and cites `SATIN-SCHED-001` with it. The table of `SATIN-SCHED-003` could
state the entry; until it does, this decision reads the inherited one.

**D-72. What the destruction cases do not pin.** Each of these is outside what a transaction-level
case expresses, or what the text states:

- **A slot of the created address that the transaction accessed before the creation**
  (`SATIN-SD-003`'s second clause, `SATIN-SD-016`'s last). No instruction reads or writes another
  account's storage, the address has no code to run before it is created, and an access list only
  warms a slot: only a tool's load reaches it. The cases pin the other clauses: a slot first accessed
  after the creation reads zero, and a slot never accessed makes no record.
- **A store after the mark that clears or restores a slot.** `SATIN-SD-013` fixes its regular gas and
  that nothing rises, falls, charges or refills, and does not say whether it moves the EIP-3529 refund
  counter. The model raises `Unmodelled` there; the cases pin a fresh slot written after the mark,
  which moves no counter.
- **Block level and configuration.** Whether a leaf an earlier transaction of the block destroyed or
  funded is absent or present at the next one's start, and a destruction under a reconfigured
  state-growth, KV-update or compute limit: the block profiles and the next phases.
- **Outside the model** (D-63): a limit crossed below the transaction's own frame by a destruction's
  positive effects, a creation transaction whose own frame destroys the account it creates, a
  `SELFDESTRUCT` to itself of an account created in the transaction, a creation onto an address with
  a balance, and a destruction in a static frame.

**D-73. The limit-stop page's uncited rules are cases.** Twelve rules of the limit-stop page had no
case (`docs/rule-index.md`). Twenty-six cases at `cdded1e` (`specs/satin-cdded1e`, whose page is
the same text at the specification's later `be819ae`) now pin eleven of them, in the area
`limit-stops`, each at the edge where its outcome changes, most in pairs one unit apart, and hold
what the existing tests of both implementations check of the page under the protocol's limits:

- **A stop below the transaction's own frame** (`SATIN-STOP-005` to `-008`): a child stopped by the
  transaction's data-size limit after hints used what it had left, its kept log discarded, and its
  caller's log exactly the room the discard gave back or one byte past it; a child stopped by its
  state-growth budget, the share of the ten its caller left, and its caller's fresh slots exactly
  filling its own budget or one past it. The caller returns the child's return data, the stop's
  bytes, when it succeeds.
- **The hint exception** (`SATIN-STOP-006`): a frame running on its caller's storage takes the
  caller's record back, sends a hint into the room that freed, and succeeds, reverts, halts or is
  itself stopped; a failure puts the record back with the hint still counted, and the caller returns
  the stop of the transaction's data-size limit before its next instruction.
- **A start that crosses** (`SATIN-STOP-013`, `-015`): a value call to a contract whose start's
  records and transfer log land exactly on the data-size limit or one byte past it; a creation with an
  endowment stopped at its start, whose creator keeps its nonce bump and its record, which lands on
  the limit or one byte past it and then stops the creator.
- **Which endings are stops** (`SATIN-STOP-002`, `-003`, `-010`, `-019`): a log one byte past the
  data-size limit with exactly its regular charge (the stop) and one gas less (a halt, no stop); a
  value call one gas short of its start record's history (out of gas before the first frame, no stop)
  and with the gas to run (the compute stop); a deposit holding exactly the charge that crosses gas
  detention (a stop, settled as a revert) and one gas less (a halt, a failed deposit).
- **A list that does not fit** (`SATIN-STOP-017`, `SATIN-AUTH-010`): 1,001 entries of absent
  authorities, one more than the state-growth limit, are skipped and the first frame is stopped
  before it runs, naming the transaction limit.
- **What else the tests check of the page**: a contract reverting with `MegaLimitExceeded`'s bytes,
  of each of the four kinds, and a caller re-raising a stop it caught, both ordinary reverts with no
  stop reported (`SATIN-STOP-020`, `-021`); a stop above the execution cap, whose reservoir returns
  (`SATIN-STOP-009`); and a frame three calls deep stopped by its budget of 940, its relays returning
  the stop's bytes (`SATIN-LIM-003`).

A case that pins the page carries `stops` (`tools/make_slice.py`): its derivation also cites the
rules that give a stop its kind and say which endings are stops (`SATIN-STOP-002`, `-003`, `-007`,
`-008`, `-019`). The flag adds citations only; the older cases do not carry it and keep their bytes.
`SATIN-STOP-016` has no case: D-75.

**D-74. The model learns the stops below the first frame (D-63 and D-65 amended).** The model held
only the transaction's own frame to the limits. It now also derives:

- a write of a child frame held to its budget, its share of its caller's remaining
  (`SATIN-LIM-003`, `-004`), and then to the transaction's limit (`SATIN-LIM-011`), the stop a
  revert its caller catches, whose counts the failure discards (`SATIN-STOP-005`, `-006`);
- a decided start of a value call to a contract, and of a `CREATE`, held to what it kept before the
  frame runs (`SATIN-LIM-013`, `SATIN-STOP-013`): the start is reverted, the child's regular gas
  returns untouched with its reservoir share, and the start's history and the created account's state
  gas are given back to the caller (`SATIN-HIST-014`, `SATIN-POOL-015`); a creator's nonce record,
  counted on it once the creation returned and held to its limits (`SATIN-LIM-008`,
  `SATIN-STOP-015`), the creation's regular gas being the creator's again before the record is held;
- a hint admitted in a frame that then fails stays counted, and the frame the failure returns into
  returns the data-size stop when that leaves the transaction over its limit (`SATIN-STOP-006`,
  `-012`); a first frame that halts after admitted hints keeps them counted (`SATIN-ORCL-009`);
- a deposit whose own frame is stopped, settled as a revert that keeps the mint, the nonce bump and a
  created caller with its state gas (`SATIN-STOP-009` to `-011`);
- an EIP-7702 list whose KV or state-growth total crosses the transaction's limit, skipped from its
  simulation and the first frame stopped before it runs (`SATIN-AUTH-010` to `-012`).

No opcode is added to the interpreter. Two probes are: the regular gas before the first `LOG` and
before the first memory expansion, so that a case sits on a charge. A tuned case may be a deposit,
whose gas limit is its envelope's. The revm-based implementation fails the two deposit cases, both
for the history gas it does not charge a deposit (`SATIN-HIST-016`): the stopped deposit's gas used is
below the rule's by its body's history, and the deposit one gas short of the crossing holds that
history more regular gas, pays the charge and is stopped where the rule's runs out of gas and fails.
Both are quarantined with that verdict; the evm2-based implementation passes every case.

**D-75. What the limit-stop cases cannot hold.**

- **`SATIN-STOP-016`** asks that a frame answered without running, whose answer gas detention
  rewrites to the stop, have what its start moved reverted. The answers detention rewrites are a
  precompile's, decided from its price before the value moves (`SATIN-DET-021`, `-022`), and an
  interceptor's (`SATIN-DET-025`), which answers before the frame start and moves nothing: neither
  has moved anything when it is rewritten, so no transaction shows the rule, and the precompiles are
  outside the model (D-63).
- **`SATIN-STOP-017`'s first clause** is validation's: a body that, with a record's bytes for each
  authorization entry, crosses the 13,107,200-byte data-size limit is refused. A case would carry
  that body in its transaction bytes, over 26 MB of hex. Its second clause has the case of D-73.
- **KV stops** stay out of reach (half a million records cost more gas than a transaction holds),
  and a frame's data-size budget is reached only through its own logs and records, whose history
  costs over a billion gas: the data-size stops below the first frame name the transaction limit,
  after hints used what it had left (`SATIN-LIM-012`), and the frame budget is named on state
  growth.
- **The list that fits**, 1,000 absent authorities applied, is the skipped list's control; it is not
  cheap (over 200,000,000 of state gas and a thousand accounts in the state diff) and is left out.

**D-76. Schema 2: a case lists the rules it pins, stores no derivation, and sits at its id's path.**
The cases were mostly metadata. The 28 gating destruction cases held 13,942 lines, 44% of them one
rule id each (alone, or with its text digest), and a case held 499 lines on average, about a third
of them `input` and `expected`; the rest was a rule list per observation group (the gas ledgers alone about 38 rules, most of them the same rules of
the schedule, the pools and history gas in every case), their union again as `rules`, and in
provenance the derivation, a review block and a decoded transaction. An Ethereum EEST fixture keeps
one `_info` per fixture (the EIP's reference and version, a link to the test source, a description
and a hash) and neither per-assertion rule lists nor a stored derivation. The format follows it:

- **The envelope.** `assertions` is removed and `rules` is the sorted set of the rules the case
  pins, at least one. Removing a required member is a major change: the format is
  `mega-execution-fixture` 2.0, a reader of 2.x rejects a schema 1 file (`unsupported-schema-version`)
  and an `assertions` member (`unknown-field`), and 2.0's limit stops are 1.1's, behind
  `group:limit-stop` and `group:limit-diagnostics`. The codes `unbound-assertion`,
  `assertion-rule-not-cited` and `uncovered-rule` are retired with the check that raised them. No
  consumer read the per-path lists to decide what to compare: the comparison was and is the whole
  `expected`, and `requires` says which groups it holds. A `fail` now reports the case's pinned
  rules where it reported the rules whose assertion paths covered the first difference.
- **What a case pins** (`tools/make_slice.py`, `AREA_SCOPE` and `pinned`), one rule for every case:
  a case pins the rules its derivation applied that are in its area's scope or that its definition
  names. The area is the second segment of the case id. Its scope names whole pages of the
  specification, by rule family, where the area tests that page (`detention` the gas-detention
  page, `selfdestruct` the destruction page and state gas, `limit-stops` the limit-stop and
  resource-limit pages, `gas-pools` the gas model, `outcomes` the outcomes page), and single rules
  of the six pages every transaction passes through — the gas schedule, history gas, the gas
  model, resource accounting, resource limits, outcomes — where an area tests those rules and not
  the page (`intrinsic` the intrinsic cost, the floor, the body's bytes and history and the block's
  figure; `sstore` `SSTORE`'s prices, records and refunds; `deposits` the deposit rules of other
  pages). The definition names a rule by its full id in the case's intent or boundary, or, for a
  quarantined case, in its known failure's verdict, so a quarantined case pins the rule its
  quarantine is about. The derivation bounds the pins: no case pins a rule its derivation did not
  apply. The rules every derivation applies (the intrinsic cost, the body's history, the pools'
  split, the ledgers, the receipt, the resource limits, the success class) are thereby pinned by
  the areas that test them and by no other. The scopes were read from what each area's row of
  `slice/README.md` says it distinguishes; the rule is applied by the generator, never by hand.
- **Provenance** keeps a pointer: `status`, the `generator`, the `definition` (the function of
  `tools/make_slice.py` that defines the case), the `specCommit` it was derived at, its
  `authoring` intent and boundary, and a quarantined case's `quarantine` record. The derivation of
  every group, every rule it applied with its text digest, the decoded transaction and the evidence
  sentence are derived again on demand by `tools/make_slice.py --explain <caseId>`, which prints
  them as JSON with the case's file digest, pins and scope; `tools/check_derived_text.py` scans that
  derivation as it scanned the stored one (the same 21,948 texts). No content hash is stored in a
  case: `slice/index.json` binds each file by its digest, and a release manifest binds file and
  semantic digests.
- **The layout** is EEST's in spirit: a case is the file `slice/<group>/<caseId>.json`, so
  `slice/cases/satin/<area>/.../<case>.json`; quarantined cases sit at
  `slice/quarantine/<caseId>.json` and the wrong expectation at `slice/negative/<caseId>.json`, one
  rule for the three groups. `slice/index.json` keeps every case's `caseId`, its group (`cases` or
  `quarantine`), its `file`, `area`, pinned `rules` and `fileDigest`, and each quarantined case's
  `knownFail`. `mega-fixture consume` already walked directories at any depth, in path order.
- **What a consumer compares is unchanged**: every case keeps its `caseId`, its group, its `input`,
  its `expected` and its `knownFail`; `requires` is unchanged too, since every case whose `limit`
  is a stop was already schema 1.1.

The case files shrink from 130,754 lines to 47,468 (36%), and the rule citations of the 262 cases
from 9,119 to 1,942. The rule-to-case index now cites 193 rules where it cited 228, and 217 of the
latest registry's 410 rules are uncited where 182 were (208 active, 9 retired, where 173 and 9
were): the 35 rules no longer cited were reached by derivations without being what any case was
written to distinguish — among them the forwarding rules (`SATIN-FWD-001` to `-003`, 111 cases),
the opcodes' static gas (`SATIN-SCHED-002`, 127), a value call's charge order (`SATIN-HIST-010`, 109),
data size's counting points and the KV count (`SATIN-ACCT-002`, `-012`, 251 and 241) and the base
layer (`SATIN-BASE-001`, 17). That is the index's truthful picture, not a loss of coverage: the
expectations are the same values.

From the move of the revm-based pin to `7110d87b`:

**D-77. The revm-based pin moves to `7110d87b`; three quarantined cases gate, five records are
made again.** The revm-based pin moved from `4e39cfd6` to `7110d87b`. Its root manifest moves the
revm fork from `4c8f0d43` to `a125b2c4`, the fork revision that charges ModExp's price before
EIP-7823's input-size bound, and keeps the op-revm fork (`8c0db939`), the OP monorepo revision
(`f67d87cd`), the crates.io versions and the toolchain. The adapter's manifest moves its twelve
revm patches with it, and its lockfile moves those crates, mega-evm and mega-system-contracts,
nothing else. The revision drops `read_l1_block_info` from the crate's exports and changes the
block executor and the L1 block contract's report; the adapter uses none of it, as it runs
`MegaEvm::execute_transaction` over its own database, so it builds unchanged and no adapter change
was needed. The system contracts' versioned artifacts
(D-55) and the SALT mapping's source (D-53) are byte-identical at both revisions, so
`tools/system-contracts.json` and the SALT member keep the revision they were read at, as does the
corpus inventory, which was read at `4e39cfd6` and is not read again here.

The revision adopts four rules the quarantine is about:

- the Oracle's `SLOAD` reads the slot and marks the read before any of its charge
  (`SATIN-ORCL-004`);
- a refused volatile read charges nothing (`SATIN-MAC-003`, `-004`);
- ModExp is priced before its input-size bound, so an input over EIP-7823's bound priced past the
  allowance is the crossing (`SATIN-DET-023`, `-024`);
- every EIP-7702 authorization list is simulated before the first frame, whatever its length
  (`SATIN-AUTH-005`, `SATIN-WIT-004`).

Every gating case passes on it, plain and instrumented. Of the forty-five quarantined cases:

- three pass on both implementations and gate: the two refused reads (D-60) and the ModExp input
  over the bound priced one past the allowance (D-68). Their verdicts named only rules their areas'
  scopes hold or their derivations did not apply, so each pins the rules it pinned. The slice gates
  220 cases, which pin 156 rules in 19 areas: `access-control` is an area of the gating slice.
- five still fail, but their first difference moved or their verdict's account of it no longer
  holds; their records are made again at `7110d87b` and name it. The three Oracle reads' regular
  ledger is the rule's, and their first difference is the deposit's gas used, short of the rule's
  by its body's history (`SATIN-HIST-016`), derived as every deposit's is, where D-60 recorded that
  implementation's run. The list that runs out of gas at its first entry still differs first at
  the registry's account, but its simulation loads both authorities; the deposit's Oracle slot
  still differs first at its history, but its reads hold the slot. Each verdict says its edge is
  the rule's and names the rules it named, so each case pins the rules it pinned.
- the other thirty-seven fail exactly as recorded, path and both values, and pass on the
  evm2-based implementation. Their records keep the revision they were made at, `4e39cfd6`, and the
  first three deposits `5e3f30ad`, as D-53 kept them; `tools/run-slice.sh` checks each at the pin.

No case's `input` or `expected` changes, and no case's pinned rules: the rule-to-case index cites
the same 193 rules, and only the three cases' group moves in it.

From the specification at `c130558`:

**D-78. The specification at `c130558` is bundled, and a precompile that halts counts none of its
forward as compute; D-69's first reading is superseded.** `specs/satin-c130558` is the
specification's main after four merged changes: the take-back page's worked examples removed, a
call refused at its target's EIP-7702 delegate paying its target's access and its memory
expansion, the first fill batch's clarifications, and that refusal's follow-ups. It holds 410 ids,
400 active: `SATIN-STOP-016` is retired, 25 rules are reworded and none is added
([spec identity](spec-identity.md)). It is the snapshot new cases cite (`CURRENT_SPEC` in
`tools/make_slice.py`).

- **The reading.** D-69 counted the charged price of a precompile that halts on a check made after
  its gas charge (ModExp over EIP-7823's bound) as compute, where the page at `cdded1e` left that
  figure open. `SATIN-DET-011` at `c130558` decides it the other way: a precompile that halts, out
  of gas or on a check made after its gas charge, burns its whole forward, its charged price and a
  value call's stipend included, and counts none of it as compute; only a precompile that is the
  crossing (`SATIN-DET-021`) returns its forward. The model takes that reading
  (`tools/satin_model/precompiles.py`), and the step cites `SATIN-DET-009`, `-011` and `-021`.
- **The cases that move.** Two derivations take it, and both cases now cite `specs/satin-c130558`:
  `satin/detention/precompile/modexp/over-bound-at-allowance` and
  `satin/detention/precompile/bn254-pairing-over-size-limit`. In the first, the transaction's
  compute after the call no longer includes ModExp's price, so the caller resumes with all of its
  regular gas spendable rather than none. The caller makes no regular charge after the call, so no
  figure moves. The second is priced at zero, so its compute is the same under both readings. Their
  `input`, `expected` and pinned rules are unchanged, and every rule they pin is active at
  `c130558`; only their `specRef` and `specCommit` move. D-69 was right that no asserted figure
  depends on the reading.
- **What `c130558` now states that the model already read.** The forward a precompile's price is
  held against is the child's whole regular gas, a value call's stipend included (`SATIN-DET-021`,
  D-69's second reading). A value call to a precompile whose account is absent or empty pays its
  new-account state gas (`SATIN-DET-022`); the value cases' identity precompile holds a balance, so
  none of them reaches it (D-69's third reading). A cold `SELFDESTRUCT` beneficiary costs the whole
  `COLD_ACCOUNT_ACCESS`, now a row of `SATIN-SCHED-003`'s table (D-71). A detained `SSTORE`'s static
  cost is a charge of its own, and the rest of its access is charged with the write
  (`SATIN-SCHED-004`, D-67). Each of these cases keeps the snapshot it names.
- **Every other case keeps its snapshot.** Each rule reworded or retired between `cdded1e` and
  `c130558` was held against the cases that pin it, through the model. Every expected value still
  holds under the new text. The value crossing to the identity precompile applies
  `SATIN-STOP-016`, which `c130558` retires: that case stays at `cdded1e`, and to move it, its
  derivation would have to cite `SATIN-DET-022` and `SATIN-STOP-014` instead. `tools/make_slice.py`
  now refuses a case that applies a rule its own snapshot retires.
- **The corpus inventory.** Section 2 of [the corpus inventory](corpus-inventory.md) is read again
  at the revm-based pin, `7110d87b`. Its integration tests, replay fixtures and deviation registry are
  byte-identical to `4e39cfd6`'s, so every count stands.

**D-79. A keyless deployment past step 3 is derived, from KeylessDeploy's page at `c130558`.** The
model restated a keyless deployment only as far as step 3's encoding check and the value refusal.
It now runs the whole call, in `tools/satin_model/keyless.py`. 42 new cases under
`satin/keyless/` cite `specs/satin-c130558`: 40 gate, and 2 are quarantined against the revm-based
implementation. `satin/keyless/` is the `keyless` area, whose scope is `SATIN-KEY` and
`SATIN-ICPT`. The model decodes the carried transaction as a legacy transaction's
nine RLP strings, canonically encoded, and recovers its signer from the signature on the secp256k1
curve, a high `s` included (step 7). A carried list of another shape, a non-canonical string or a
`v` that is neither 27, 28 nor an EIP-155 value raises `Unmodelled`, so what a decoder does with
them is no case's. Where the page leaves a reading open, the model takes these:

- **The forward's checks.** Steps 11 and 15 read "available gas" as the call's whole regular gas,
  its withheld part included, without the 98/100 cap: `SATIN-KEY-011` forbids the cap on the
  forward that the two steps bound. The cases `refusal/step-11-one-short`,
  `refusal/step-15-one-short` and `deploy/forward-at-signed-gas` sit on that edge, one gas short
  and exactly at it.
- **Which refusals answer.** Steps 3 to 13 are judged in the table's order, and the first refusal
  answers. When a later step would refuse too, the derivation names it and cites
  `SATIN-KEY-006`. Steps 10 and 11 are not judged that way: 10 is a charge, and 11 depends on the
  gas the earlier steps leave.
- **A failed creation is an ordinary failed creation.** A creation that reverts, halts, is
  stopped, or is refused its empty deposit leaves the call what a failed `CREATE` leaves its
  creator (`SATIN-KEY-011`, `-016`). Step 14's created-account state gas and the created account's
  record history come back into the call's reservoir after the creation's reservoir joined it
  (`SATIN-POOL-015`, `SATIN-TAKE-007` failed-create). The signer's bump, its nonce record and that
  record's history stay. A creation that collides with a deploy address holding a nonce gives back
  that record's history alone, since step 14 charged no state gas for a non-empty address
  (`SATIN-TAKE-007` collision). The creation's whole forward is spent, its reservoir share comes
  back, `gasUsed` is the forward, and the answer is `ExecutionHalted` (`SATIN-KEY-008`).
- **`gasUsed`** is `SATIN-KEY-015`'s formula: the two pools netted together, plus the destruction
  table's give-back of step 14's charges when the constructor destroyed the deploy address. The
  page's two figures are checks a case must reproduce: 12,109 for the reverted fresh slot
  (`deploy/fresh-slot-reverts`) and 5,002 for `ORIGIN; SELFDESTRUCT`
  (`deploy/destroyed-in-constructor`).
- **`SATIN-KEY-017`** is cited where a limit stops the creation (`detention/signer-is-beneficiary`):
  the call answers `ExecutionReverted` with the stop's data, and none of the errors the interface
  no longer declares. Its other clauses are reached by no transaction: a read the node fails to
  make is a fault, and `AddressMismatch()` and `NoContractCreated()` answer a creation reported at
  another address or at none.
- **Recognition whatever code the state holds.** Three cases put the undefined opcode `0x0c` at
  `KEYLESS_DEPLOY_ADDRESS` (`SATIN-ICPT-006`). A recognized call deploys there. An unrecognized
  call, by its arguments or by another selector, runs that code and halts. The model now treats
  Osaka's undefined `0x0c` to `0x0f` as exceptional halts.
- **The reads cases.** `refusal/signer-nonce-two` and `refusal/taken-and-unfunded` carry the reads
  group: the signer is read and the deploy address is not when step 8 refuses, and both are read
  when step 12 refuses (`SATIN-KEY-007`). The revm-based implementation fails both for the
  registry read alone, which every reads case records (D-61). Its keyless reads were checked
  against the expectation with the registry's account, slot and code added: they are the rule's.
  The two cases are quarantined at `7110d87b` with that verdict.
- **Inputs that stay clear of the derived-text check.** `tools/check_derived_text.py` flags any
  figure in a case's text that equals a figure some case moves under a mutated constant. The
  keyless cases therefore sign at a gas limit of 90,000, not 100,000, which is
  `KEYLESS_DEPLOY_OVERHEAD_GAS`. Where a constructor's own cost is free, it starts with sixteen
  `JUMPDEST`s. The fresh-slot example is signed at the largest `u128` gas price, and the `0x32ff`
  example passes its bytes unpadded (`SATIN-ICPT-006` condition 5), because both constructors'
  bytes are the page's. Otherwise a 196-byte calldata gives a floor of 27,544, which is
  `satin/creation/initcode-reverts`'s history ledger. None of these choices changes what a case
  tests.

The model added `ORIGIN` (`0x32`) and `GASPRICE` (`0x3a`), each the transaction's own in every
frame (`SATIN-KEY-011`), and the halting `0x0c` to `0x0f`. Out of the model: a keyless creation
whose start crosses a limit, or that a data-size, KV-update or state-growth limit stops; a signer's
nonce record that crosses the call's budget; a signer whose own code spends a nonce during the
creation; a deploy address the transaction changed or that holds storage; and a node
configuration that disables EIP-3607 (docs/model.md).

From the cases of the outcomes page and of validation's order:

**D-85. The outcomes page and validation's order are pinned by cases that ask for them.** The outcomes
page gathers rules whose detail lives elsewhere, and validation's order names which of Satin's own
checks refuses a transaction; every derivation already ends in one class or another, but no case
cited the class it ended in. A case may now ask for it (`outcomes` in `tools/make_slice.py`, as
`stops` did for the limit-stop page, D-73): its derivation also cites the class each ending is in
(`SATIN-OUT-002` to `-018`), the step of `SATIN-VAL-003` that names a refusal or the checks an
admitted transaction passes, and what a failed deposit and a refused transaction report. No other
case's derivation changes, so no existing case pins more than it did. The cases, all at `c130558`,
sit in the `outcomes` and `validation` areas:

- **Stops, refusals and halts below the first frame**: a child that crosses gas detention's limit is
  stopped and its caller catches the stop, against the same charge beyond the child's whole regular
  gas, an out-of-gas (`SATIN-OUT-002`); a volatile read refused in a child, a revert its caller
  catches (`SATIN-OUT-008`); MegaLimitControl's `NotIntercepted()`, and KeylessDeploy's step 1
  overhead one gas short, a halt, and paid, `MalformedEncoding()` (`SATIN-OUT-009`).
- **Precompiles**: the identity precompile one gas short of its price and at it; the BN254 pairing
  of 300 pairs of points at infinity, at its size limit, which runs and answers 1, and of 301, one
  pair over it, which fails before any gas check, both forwarded more than their price, so that the
  size limit alone decides (`SATIN-OUT-004`, `-011`); a value call to the identity precompile whose
  start would cross the transaction's data-size limit, failing on its stipend, which keeps nothing
  and is no stop (`SATIN-LIM-014`), and priced within it, whose start is held to its limits and
  stopped (`SATIN-LIM-013`).
- **The size checks and creation's order** (`SATIN-SIZE-005`, `-006`): a `CREATE` of initcode one
  byte over `MAX_INITCODE_SIZE` against one at it; a creation transaction whose code is one byte
  over `MAX_CONTRACT_SIZE`, on a gas limit that could pay that code's deposit, so the size check
  alone halts it (`SATIN-OUT-003`); one byte of code whose deposit is one gas short, a halt, and
  paid (`SATIN-OUT-007`, `SATIN-SCHED-011`); a `CREATE` short of its operands and a `DUP1` of an
  empty stack, halts with no reason the specification names (`SATIN-OUT-012`, `-013`, `-018`); and
  under gas detention a `CREATE2` missing only its salt, whose initcode cost is the crossing (a
  stop) or is paid with its memory (a halt on the salt), and a `CREATE` of oversized initcode, which
  halts at the size check before any charge could be the crossing.
- **Reverts, and charges before the first frame**: a frame that reverts with `ORIGIN` and `CHAINID`,
  a transaction's and a deposit's, which is no failed deposit, and a deposit's revert with a value or
  from a caller it created (`SATIN-OUT-014`); a value transfer whose gas limit pays its start record
  exactly, a new recipient's state gas one gas short and paid, a creation transaction one gas short
  of its created account's state gas, whose sender keeps the nonce bump the creation would have made
  (`SATIN-SCHED-010`), and one that pays it exactly, and a deposit one gas short of its start record
  or of its new caller's state gas and at each (`SATIN-OUT-006`); a deposit whose own frame halts, below and above the
  execution cap, or cannot fund its value, a failed deposit, which keeps its reads (`SATIN-OUT-005`,
  `-013`, `SATIN-WIT-002`).
- **Validation**: a gas limit at the floor exactly (step 5 refuses), at the intrinsic gas exactly
  below the floor (step 3) and below both (step 2), and a call and a transfer to the sender at the
  least gas limit, admitted (`SATIN-VAL-003`); a legacy transaction without a chain id, admitted,
  and transactions of types 1, 2 and 4 carrying chain id 0, refused (`SATIN-VAL-006`); a nonce of
  2^64 - 1, refused, one below it, admitted, and an empty authorization list, refused
  (`SATIN-VAL-007`); a deposit one gas short of its intrinsic gas with its body's history, and one
  carrying the base layer's system-transaction flag, failed deposits, and one at that gas
  (`SATIN-VAL-008`, `SATIN-OUT-016`); an authorization entry applied and one skipped for its chain
  id, whose record step 1 counts either way and the data size before the first frame counts only for
  the applied one (`SATIN-VAL-001`, `-004`); and the transactions from the live system address of
  D-87.

The model grows only as far as these cases need (docs/model.md): the opcode `CHAINID` (`ORIGIN` is
D-88's), and `CREATE2` as far as its salt operand; `CREATE`'s operands, its initcode size, its initcode cost,
its memory and then `CREATE_ACCESS`, in the order of `SATIN-SIZE-005`, where the model had charged
`CREATE_ACCESS` first (no committed case moves: every one pays all three or none); a creation's
code over `MAX_CONTRACT_SIZE`, its code deposit charged in its frame, and a creation's halt after the
reservoir paid its start; a precompile call that fails where no limit is set, the BN254 pairing of
points at infinity within its size limit, and a value call to the identity precompile whose start is
held to the limits; a deposit that fails validation, carries the system-transaction flag, cannot pay
its empty caller or its start record, carries a value, or whose own frame reverts, and a failed
deposit's reads; a nonce of 2^64 - 1 and an empty authorization list; and a case's chain id, which
`CHAINID` reads, so that a deposit's `CHAINID` is not 1 by default, and which a legacy transaction
may omit. The entry skipped for its chain id is D-88's gate (`SATIN-AUTH-002`).

A creation transaction that cannot pay a charge before its first frame was outside the model. D-88's
rollback to what validation left would leave its sender's nonce unbumped, since `SATIN-ACCT-008`
makes a creation's bump in its first frame, but `SATIN-SCHED-010`'s second sentence keeps it: "the
sender of a creation keeps the nonce bump the creation would have made". The model now bumps a
creation's sender's nonce on that path, after the rollback, and the creation one gas short of its
created account's state gas is a case, at nonce 1; both implementations bump it. No other case
reaches that path.

Three of the listed rules no transaction-level case holds:

- **`SATIN-OUT-015` and `SATIN-VAL-010`**, the faults: a failed read is an injected fault
  (`input.faults`), which neither adapter runs (`unsupported`).
- **`SATIN-OUT-017`**: what a tracer is shown is no observation of the format.

`SATIN-VAL-001` is held on its admitting side only: its refusal needs a body over the data-size
limit, over 26 MB of hex in a case (D-75); for the same reason step 1 and step 4 of `SATIN-VAL-003`
have no refusing case. `SATIN-VAL-005` is held on its deposit side only (D-87).

**D-86. The deposits of the outcomes page and of validation are quarantined against the revm-based
implementation.** Sixteen of the cases of D-85 are deposits, a Mega System Transaction promoted to
one among them, and the revm-based implementation at its pin, `7110d87b`, charges a deposit and a
system-originated transaction no history gas (`SATIN-HIST-016`, `SATIN-DEP-001`, `SATIN-MST-008`).
Each fails there as its record says, made at `7110d87b`, and passes on the evm2-based
implementation:

- a deposit that runs, reverting or succeeding, uses its whole history less than the rule's
  (`gasUsed`);
- a failed deposit, its own frame halting, its value unfunded, its flag the base layer's
  system-transaction flag or its sender the live system address, reports its kept body as no history
  bytes (`historyBytes`, `SATIN-HIST-022`, `SATIN-DEP-006`);
- a deposit one gas short of its intrinsic gas with its body's history, of its start record or of
  its new caller's state gas is admitted and runs, counting its intrinsic regular gas alone, where
  the rule makes it a failed deposit whose block gas is its whole gas limit (`blockGas`,
  `SATIN-VAL-008`, `SATIN-DEP-004`, `-005`); the promoted Mega System Transaction short of its
  history runs the Oracle's bytecode on its empty input, which reverts, and the block gas it counts
  is recorded as observed at the pin, the model not running the Oracle's dispatcher there.

The deposit side of `SATIN-OUT-005`, `-016`, `SATIN-VAL-005` and `-008` is pinned by these cases
alone; the slice gates 307 cases and quarantines sixty-two.

**D-87. A case can name a live system address.** Every other case's SequencerRegistry holds other
code, so it resolves no live system address. These cases hold the registry's version 2.0.0 runtime
code, read from the revm-based implementation's versioned artifacts at its pin and refused unless
its keccak256 is the specification's `SEQUENCER_REGISTRY_CODE_HASH`, with slot 0 naming the case's
sender; the model resolves the address as `SATIN-REG-002` states and classifies the transaction as
`SATIN-MST-001` to `-005` do. The code is held in `tools/make_slice.py`, not in
`tools/system-contracts.json`, which lists the contracts a call can reach (D-55): no case calls the
registry.

- **A deposit from the live system address** never has the system shape and is a failed deposit
  (`SATIN-VAL-005`, `SATIN-MST-003`, `SATIN-DEP-008`).
- **A Mega System Transaction** (a legacy call to the Oracle from that address) is refused for its
  own checks before its promotion: carrying no chain id, its sender holding code, its nonce above
  the system address's, or both at 2^64 - 1 (`SATIN-VAL-006`, `-007`, `SATIN-MST-005`). One that
  passes them and is one gas short of its intrinsic gas with its body's history is promoted and is a
  failed deposit (`SATIN-VAL-008`). The specification does not say which receipt a promoted
  transaction has; it is a legacy transaction in its block, so the model gives it the envelope's
  receipt, type `0x0` with no deposit fields, which both implementations report. A promoted
  transaction that runs is not modelled.
- **The refusal of a transaction without the system shape** from that address has no case: neither
  adapter maps it to a reason (each reports an error for it), and only the evm2-based adapter may
  change here, which alone would not let the case gate or be quarantined.

From the authorization page's uncited rules:

**D-88. The authorization page's own rules are cases at `c130558`, and the model learns the list's
other entries (D-63 and D-75 amended).** Twelve rules of the EIP-7702 page had no case:
`SATIN-AUTH-001` to `-003`, `-006`, `-007`, `-010` to `-014`, `-017` and `-018`. The area
`authorizations` gains sixteen gating cases and two quarantined ones (D-90), each at an edge of a
rule, with its control where one is cheap, citing `specs/satin-c130558`:

- **The gates** (`SATIN-AUTH-002`): an entry for chain 2, at nonce `2^64 − 1`, or whose signature,
  all zero, recovers no authority, is skipped before any authority is read; the frame's `BALANCE` of
  the account its key signs for pays the cold access, and the entry pays its `PER_AUTH_BASE_COST`
  alone (`SATIN-AUTH-007`, `-014`, `SATIN-SCHED-007`). The control is an entry for chain id zero,
  applied and warm.
- **The authority's code** (`SATIN-AUTH-003`): code other than a delegation indicator skips the entry
  after the load, which warms the authority; an indicator does not, and the authority, delegated
  again, is charged no indicator (`SATIN-AUTH-009`). A nonce that does not match skips the entry
  after the load too (`SATIN-AUTH-004`, `-014`).
- **The sender's own authorization**: at its nonce after validation's bump it is applied with the
  indicator's state gas and no `ACCOUNT_WRITE` or record (`SATIN-AUTH-008`, `-015`); at its nonce
  before the bump it is skipped; and applied, it does not detain the transaction, its sender not
  being the block beneficiary (`SATIN-DET-008`), so a frame computing past the cap succeeds.
- **The start record when the list keeps no record**: the reservoir pays the first frame's start
  record whole, and the first frame's halt returns that part (`SATIN-HIST-005`).
- **A frame of a list's transaction** reads its sender as `ORIGIN` and its effective price as
  `GASPRICE`.
- **The state-growth total at the limit** (`SATIN-AUTH-008`, `-010`): 1,000 new authorities, each with
  a zero delegation target, fit and are applied; so do they after three accepted entries whose
  authorities exist (an empty leaf, an account with a balance, one holding a delegation, which the
  third entry clears: `SATIN-STATE-011`, `SATIN-ACCT-015`), and with five entries that keep nothing (a
  chain-2 entry, a nonce of `2^64 − 1`, an unrecoverable signature, a nonce that does not match, and a
  second accepted entry for one of the 1,000). One new authority more skips the whole list, an
  existing authority and the sender's own entry that would have fitted included: the sender keeps
  validation's bump alone and the transaction is included with its frame stopped (`SATIN-AUTH-011`,
  `-013`, `-018`).
- **The caller a deposit creates** is no authorization (`SATIN-AUTH-017`): a caller whose leaf the
  state holds, empty under EIP-161, is new by emptiness, not by existence.

D-75 left the list at the limit out as costly. It is in now: the totals are where the simulation's
predicates show, and with zero targets each fitting case is about 360 KB, its state diff a thousand
accounts at nonce 1. Its state gas, 183,600,000, is paid from a reservoir of 200,000,000.

The model (`tools/satin_model/authorizations.py`) learns, for every list: the gates, which skip an
entry unread (the simulation no longer loads a gated entry's authority); an authority with code
other than an indicator and a nonce that does not match, skipped after the load, which warms the
authority; the sender's own entry, at its nonce after validation's bump, with no `ACCOUNT_WRITE`
and no record; an authority holding an indicator at the start of the transaction, charged no
indicator; and the list's totals from the same simulation. Only the authorities an applied entry
wrote detain a transaction whose beneficiary they are (`SATIN-DET-008`); before, the model counted
every entry's authority, which no case's derivation told apart. A halt of a first frame whose start
record the reservoir paid returns that part to the reservoir (`SATIN-HIST-005`), where the model
raised `Unmodelled`. The interpreter learns `ORIGIN` (0x32) and `GASPRICE` (0x3A).

A case of the page carries `lists` (`Case.lists`, `Run.lists`): its derivation cites the list's
simulation for every list (`SATIN-AUTH-001`, `-007`, `-008`, `-010`, and `-002` to `-005` where an
entry reaches them), what each skipped entry leaves warm (`SATIN-AUTH-014`), and the skip's
all-or-nothing and its inclusion (`SATIN-AUTH-013`, `-018`). The cases before it do not, so their
pinned rules stay as they were; no file of theirs changes.

`tools/make_slice.py` signs through `signing_hash`, which refuses a pre-image of 135 bytes modulo
136. `make_examples.keccak256` pads such an input as two blocks where Keccak's padding is the one
byte `0x81`, so its hash is not Keccak-256: the first draft of the `ORIGIN` case signed a 135-byte
payload, and both implementations recovered another sender and refused the transaction for its
funds. No committed case has such a pre-image, nor a code hash or address over one, since each
passes on both implementations; `make_examples.py` is left as it is, its inputs never reaching that
length. The case now carries a priority fee of 1,000, and its payload is 134 bytes.

An independent review of these cases listed fourteen edges they left open and two model errors, which a second
set of 27 cases closes (25 gating, two quarantined, D-90):

- **The out-of-gas path takes the list back.** The model kept an applied authorization when a later charge before
  the first frame could not be paid: the path restored nothing. It now snapshots the run after validation and
  restores it on that path, the authorities' nonces and code, their state gas, records, history and growth with
  it; what the list loaded stays loaded (`SATIN-SCHED-010`). The list's charges follow `SATIN-SCHED-008`: every
  entry's step-2 charges in list order (a new account's state gas, `ACCOUNT_WRITE`, the indicator), then step 3's
  history of the authorities' records, each able to run out of gas. Cases: the sender's own authorization taken
  back when the recipient's cold delegate access is one gas short, with its control at the access; and an
  authorization taken back at a second entry's `ACCOUNT_WRITE`, at its indicator and at its record's history.
- **The authority that is the value's recipient.** The model charged a second record for the value's start. An
  applied authority's write is the list's, and the value to it makes no record again (`SATIN-ACCT-009`): the
  example of `SATIN-AUTH-015` is a case, at 68,504 gas, with an absent authority the list creates and one whose
  delegate reverts the frame, which keeps the authority's record.
- **The other edges**: the indicator's charge across set, clear and set again, for an authority holding one at the
  start, absent or existing (`SATIN-AUTH-009`); entries rejected before and after an acceptance, and the sender's own
  entries in sequence (`SATIN-AUTH-004`); the last nonce an authorization can carry, `2^64 − 2`; the beneficiary's
  entry skipped or gated, which does not detain (`SATIN-DET-008`); the authority's own bucket pricing both its
  charges (`SATIN-STATE-003`); the reservoir paying 1 of the start record after the authority's; the target an
  entry names, which the application does not warm (`SATIN-AUTH-014`); an explicit revert after the sender's own
  authorization and after an absent authority's, which keep them (`SATIN-AUTH-016`); a skipped list at a non-zero
  price; signatures with a y_parity of 2 and with r at secp256k1's order (`SATIN-AUTH-002`); and two lists whose
  reads show the simulation's gates and code loads and its walk past the crossing entry (`SATIN-AUTH-005`).
- **What each case pins.** `SATIN-AUTH-016` is cited where a first frame fails after the list applied an
  authorization, and no longer at the record's charge; `SATIN-AUTH-004` where an entry reaches the nonce
  comparison; the reads of the page's cases cite `SATIN-REG-002`, which their quarantine is about; the frame's
  `ORIGIN` and `GASPRICE` cite `SATIN-BASE-001`, which the case names.

**D-89. What the authorization cases cannot hold.**

- **`SATIN-AUTH-006`**, a failed read of an authority, needs an injected fault (`input.faults`), which
  both adapters report unsupported; a case would be unsupported on both.
- **`SATIN-AUTH-012`**, the warmth a skipped list leaves. A skip stops the transaction's own frame
  before it runs, so no opcode reads an authority's warmth after it. The one access left is a
  delegated recipient's delegate access at `SATIN-SCHED-008` step 5, but whether steps 3 to 5 are
  made for a transaction whose list is skipped, before its frame is stopped, is not stated
  (`SATIN-AUTH-010` and `SATIN-STOP-009` name the frame's stop and its settlement, not those
  charges). The model keeps raising `Unmodelled` for a skip whose first frame starts with a charge,
  and D-88's skipped case does not cite `SATIN-AUTH-012`. Both implementations load the recipient of a
  skipped list's transaction, as step 4 would, before the frame is stopped; the model does not, so
  the skipped case with `reads` is sent to its own sender, which validation loads.
- **A KV total over its limit** (`SATIN-AUTH-010`'s kind 1, and the kind when both totals cross). A
  list keeps at most one record for each distinct authority, so it crosses the 500,000 KV updates
  only with more entries than validation lets a transaction carry: the execution cap of
  `SATIN-VAL-003` step 4 holds a list to at most 25,587 entries at `PER_AUTH_BASE_COST`, for a
  zero-value transaction to its own sender, whose intrinsic gas is `TX_BASE_COST` alone (25,586 for
  any other recipient), and the data-size limit of step 1 to 92,956. That clause is unreachable, and so is any difference in the
  simulation's record count alone.
- **`SATIN-AUTH-018`** is pinned by the skipped case's outcome, an included transaction whose frame is
  stopped; no pool profile is part of the slice.

**D-90. Four authorization cases are quarantined against the revm-based implementation.** At
`7110d87b` it fails four of D-88's cases, each for a rule the quarantine already names, each case's
own edge being the rule's there:

- `satin/authorizations/reads/short-list-out-of-gas`, `.../reads/short-list-gates-and-code` and
  `.../reads/simulation-past-crossing` carry `reads` (D-61): the first difference of each is the
  registry's account, which that implementation reads in every transaction with its slot 0
  (`SATIN-REG-002`); its simulation is the rule's, the gated entries' authorities unread, the
  authority holding code loaded with it, and the authority after the crossing entry loaded.
- `satin/authorizations/deposit-caller/empty-leaf` is a deposit: its gas used is short by its body's
  history, which that implementation does not charge a deposit (`SATIN-HIST-016`); its created
  caller is the rule's.

The evm2-based implementation passes all forty-five cases.
