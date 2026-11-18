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

**D-80. The keyless edges a review found unpinned are filled; the model's keyless reach grows, and
two survivors are equivalent.** An independent review of D-79's cases listed fifteen gaps, where no
case's outcome distinguished a reading an implementation could get wrong. 63 cases under
`satin/keyless/` fill them, all at the protocol's own constants and every one a single
transaction. 56 gate, and 7 are quarantined against the revm-based implementation. The readings
and choices:

- **What the cases now observe.**
  - The creation's reservoir share at its rounding edge, 50 and 51 left after step 14
    (`reservoir/share-*`), and the legacy shares coming from regular gas above the execution cap,
    the call then one gas short at step 15 (`reservoir/legacy-shares-from-regular`).
  - The signer's record on the call, against the transaction's data-size limit after a
    constructor's hints (`settlement/*`), and against the call's own state-growth budget after
    998 to 1,001 new EIP-7702 authorities (`authorizations/*`), the last one skipped before the
    frame (`SATIN-ICPT-007`).
  - The creation's 980 state-growth budget (`budget/*`), its LOG held to the transaction's
    data-size limit (`limits/*`), and its start stopped before its initcode.
  - A delegated signer's own nonces kept or discarded with the creation (`nonce-rule/delegate-*`),
    and the record decided on the whole account (`nonce-rule/value-*`).
  - An empty deposit refused with effects to undo, against a destruction whose effects stand
    (`empty-code/*`, `destroyed/*`).
  - The refund outside `gasUsed`; an earlier detention limit standing, and the withheld part
    forwarded (`detention/*`); signed gas 0.
  - The exact-paying partners of the step-10 and step-14 halts, and the forward's refusals before
    later steps.
  - The uint64 clamp at 2^64, the ABI's accepted and refused shapes, RLP lists that are no legacy
    transaction, signatures with r = 0 or s = n, the outer warm set, and the reads of the early
    refusals.
  - An ordinary contract holding `0x0c`, a keylessDeploy call from a keyless constructor, an
    unknown selector, `0xEF` and `0xEE` deposits, a deposit one gas short of its history, and
    revert data of 1, 31 and 33 bytes.
- **A call to a delegated account.** The model runs a `CALL` to a keyless signer that holds an
  EIP-7702 delegation as the base layer does (`SATIN-BASE-001`): the delegate's code runs in the
  signer's frame. The delegate's access, a warm read and the cold surcharge, is charged with the
  opcode's other charges, before the forward. No Satin rule places it further. The cases forward
  less than the 98/100 cap, so the place moves no figure. Calls to other delegated accounts raise
  `Unmodelled`.
- **The signer while its creation runs.** The creation's start bumped the signer's nonce, so its
  account differs from what the transaction loaded already. A start inside the creation that
  changes the signer, a value call or the signer's own `CREATE`, therefore makes no record of it,
  and charges no history for one (`SATIN-HIST-009`, `SATIN-ACCT-004`). The signer's one record is
  counted on the call after the nonce rule, from its whole account (`SATIN-KEY-012`, `-013`).
- **A `CREATE` by that signer whose initcode fails** is `SATIN-TAKE-007`'s failed-create. The
  created account's state gas and its record's history come back to the creator, and the
  creator's nonce bump stays: the signer's own code spent that nonce, so `SATIN-KEY-013` keeps
  every bump.
- **The keyless creation's start** is held to its budget and the transaction's limit as a
  `CREATE`'s is (`SATIN-LIM-013`, `SATIN-STOP-013`, `-015`). A crossing stops it before its
  initcode. The call answers `ExecutionReverted` with the stop, and the failed creation's step-14
  charges come back.
- **`MalformedEncoding()`** answers a first argument that is one RLP list but no legacy
  transaction's canonical encoding: a field count other than nine, a list among the fields, an
  integer with a leading zero byte or wider than its field, a non-canonical string, or a `to` of
  another length. That is step 3's "an RLP encoding that does not decode". A `v` that is neither
  27, 28 nor an EIP-155 value still raises `Unmodelled`. When the argument's leading list would
  decode and be refused for its own fields, the derivation names `SATIN-KEY-006`.
- **`0xEF` code.** An ordinary creation refuses deployed code that starts with `0xEF` (EIP-3541,
  kept by the base layer, the check `SATIN-SCHED-011` places before the deposit charges), and so
  does the keyless creation (`SATIN-KEY-011`).
- **A destroyed deploy address the state held** gets nothing back from the destruction table
  (`SATIN-SD-004`), and step 14 charged it no state gas, so `gasUsed` adds nothing back.
- **Held code.** The three `held-code-*` cases test recognition whatever code the state holds
  (`SATIN-ICPT-006`), in engine isolation. Their intents say they are not states a chain reaches.
  `recognition/ordinary-contract` gives the same discrimination with the canonical code: an
  ordinary contract holding `0x0c`, sent a keylessDeploy call's whole input, halts.
- **Survivors.** The two padding mutations, 58:45 and 69:46, are equivalent under the wrapping
  arithmetic a release build uses: `(32 - L + 32) mod 2^w mod 32 = (-L) mod 32`. D-79 counted the
  debug build's overflow panic as a kill. 184:51 stays killed on `SATIN-ICPT-006`'s domain. Over
  the states a chain reaches it is equivalent.
- **The revm-based implementation's new keyless failures.**
  - `reservoir/legacy-shares-from-regular` and `reservoir/share-50`: it holds the call more regular
    gas at step 15, and leaves the creation no reservoir share, as it would if the reservoir paid
    the legacy shares (`SATIN-STATE-012`, the gas-pools records' defect).
  - `destroyed/log-and-value`: it leaves a kept log's history out of `gasUsed` when the constructor
    destroys the deploy address (`SATIN-KEY-015`).
  - Four more reads cases fail for the registry read alone (D-61). Their keyless reads were checked
    as D-79's were.
- **Inputs chosen against coincidences.** `tools/check_derived_text.py` takes any figure equal to
  one that some case moves under a changed constant for a stale one. So the new cases avoid them:
  - a canonical keyless input of 196 bytes, whose floor, 27,544, is another case's history ledger,
    passes its bytes unpadded, or adds one byte after the encoding when they fill their words;
  - the 980 slot keys start at 1,000,001;
  - one carried transaction is signed at gas price 1, another carries 300 wei;
  - the unknown selector's override is 2^64;
  - the 63-byte head is sent by an EIP-2930 transaction whose access list names KeylessDeploy's
    address, which the transaction warms anyway, since its body would otherwise hold 33,176 of
    history, a figure another case's text shows.

  None of this changes what a case tests.

From the system-transaction page and gas forwarding:

**D-82. The system-transaction page and gas forwarding are pinned by cases at `bcf260d`.** No case
cited `SATIN-MST-001` to `-009` or `SATIN-FWD-001` to `-007`, though every call's derivation applied
the forward. Two areas hold them: `system-tx` (scope: the page's family, `SATIN-VAL-005` and
`SATIN-REG-002`) and `gas-forwarding` (the forward's family and `SATIN-POOL-011`). A case of either
asks for the page's rules (`system_tx` in `tools/make_slice.py`, as `outcomes` did, D-85): its
derivation also cites how the transaction's origin is decided and what that origin exempts it
from; the forward, the `CREATE` forward and the reservoir share now cite the rules that state them
(`SATIN-FWD-004` to `-007`), which no other area's scope holds, so no existing case pins more than
it did. Both adapters now map the refusal of a transaction from the live system address without
the system shape to `not-system-shape`, each from its implementation's own message for it, so
D-87's third point is withdrawn and the refusal's main clause has cases. The cases were written at
`c130558` and cite `bcf260d`, the snapshot new cases cite (D-96), which rewords two of the page's
rules without moving a reading the cases take: `SATIN-MST-004` leaves system origin to
`SATIN-MST-007`, and `SATIN-MST-005` states the promoted transaction's legacy receipt that D-87
read. The cases:

- **The system shape.** From the live system address, a legacy call to MegaLimitControl, a system
  contract off `MEGA_SYSTEM_TX_WHITELIST`, a legacy creation, and type-1, type-2 and type-4 calls to
  the Oracle, each otherwise valid, are refused (`SATIN-VAL-005`, `SATIN-MST-001`, `-003`).
- **Other callers.** The system shape from an address a rotation retired is a user's, its fee
  charged and credited, and one gas short of its intrinsic gas with its body's history it is refused,
  where the live address's is a failed deposit; an untrusted registry names no live address, so a
  typed call to the Oracle from the address it names is admitted (`SATIN-MST-004`, `SATIN-REG-002`).
- **A promoted transaction that runs.** A Mega System Transaction to the Oracle's `getSlot`, signed at
  a gas price from a system address holding no balance, runs as a deposit with no fee charged or
  credited, its nonce bumped and its history paid (`SATIN-MST-002`, `-005`, `-008`).
- **The protocol's own transactions.** A deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH` from
  an ordinary sender, and an execution message from `SYSTEM_CALLER`, write in a bucket at twice the
  minimum capacity at `m = 1`, against a user's deposit and a user's message there at `m = 2`; such a
  deposit reads `TIMESTAMP` and runs past detention's cap, and logs past the data-size limit, its
  usage reported over it; from the live system address it is a failed deposit (`SATIN-MST-003`,
  `-007` to `-010`).
- **The forward.** The cap against a request one below and one above it; the remainders 1, 49, 50
  and 99; the specification's value call with 10,000 left after its transfer charge, whose caller's
  account and callee's an earlier transfer recorded, so that it charges no history after the
  forward; a `DELEGATECALL` in a frame entered with value and an endowed `CREATE`, neither adding a
  stipend; the reservoir share of 99 and of 1, read by the child's `GAS` after a fresh slot the share
  pays in part; a value call requesting no gas whose child's share pays the history past its
  allowance; and a source-hash deposit's share of 99 (`SATIN-FWD-001` to `-007`).

An independent review then listed edges these cases left unpinned, and 44 more cases pin those a
transaction's observations reach:

- **The promotion.** A Mega System Transaction from a system address empty under EIP-161, its
  bucket at twice the minimum capacity, that cannot pay its created caller's state gas, a failed
  deposit, and that pays it once at `m = 1` with no capacity read (`SATIN-DEP-003`); one signed for
  another chain and one below the address's nonce, rejected; one from an address holding an EIP-7702
  delegation indicator, promoted; and one carrying 1 wei from an address holding 1, whose Oracle
  call reverts with the value taken back, against one holding none, a failed deposit, since no mint
  funds it (`SATIN-MST-002`, `-005`).
- **The protocol's own transactions.** A source-hash deposit and a `SYSTEM_CALLER` message whose
  reads serve no SALT capacity, and a source-hash deposit whose SALT input is incomplete and holds
  no bucket; `SYSTEM_CALLER`'s legacy, type-1 and type-4 messages and its deposit with another
  source hash, at `m = 1`, against the address one above it, a user's; a source-hash deposit whose
  child writes 981 fresh slots, one past a child's state-growth budget, and one that writes 1,001
  in its own frame, one past the limit, both kept and reported, against a user's deposit stopped at
  each; and the history of a created account's code and a child's rollback, the same for a
  source-hash deposit as for a user's (`SATIN-MST-007` to `-010`).
- **Any destination.** A deposit from the live system address that creates, and one addressed to
  that address, both failed deposits (`SATIN-MST-003`, `SATIN-VAL-005`).
- **The other opcodes' forwards.** `CALLCODE` with and without value against a request one either
  side of its cap, at the remainders 49, 50 and 99, and with a value and no gas requested, its share
  paying the history past its allowance; `STATICCALL` against the request and at the same
  remainders; `CREATE2` at the remainders 50 and 99, its initcode halting, endowed with its address
  decided by its salt, and its share of 99; and the reservoir shares of 49 and 50
  (`SATIN-FWD-001` to `-006`).

Two rules have no case. `SATIN-MST-006`'s source hash is carried by no observation of a
`state-transition` case: the promoted transaction's receipt is its envelope's (D-87), and the hash
decides nothing the transaction's origin does not already decide. `SATIN-MST-009`'s block counters
and packing budgets need a block; its first clause, the usage reported, is pinned with
`SATIN-MST-008`'s. What else no case pins is D-84's.

**D-83. The model learns the protocol's own transactions.** `tools/satin_model/` now decides a
transaction's origin on its own fields (`SATIN-MST-007`): a promoted Mega System Transaction, a
transaction from `SYSTEM_CALLER`, or a deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH`. Such a
transaction's state charges are priced at `m = 1` and read no bucket's capacity, a volatile read sets
no limit, no write or start is held to a frame budget or a transaction limit, a hint past the
data-size limit is admitted, and its usage is counted and reported in every dimension; it pays
history gas as any transaction (`SATIN-MST-008`), and its children receive the reservoir share
(`SATIN-FWD-007`). A promoted Mega System Transaction that passes its deposit's checks now runs as a
deposit, its receipt its envelope's (D-87), and its Oracle reads ask no service
(`SATIN-ORCL-005`). Since no key signs for `SYSTEM_CALLER`, its transaction is a synthetic message
(docs/format.md, "Transactions"), the first in the slice; both adapters run synthetic messages.

- **An empty system address.** A promoted transaction from a system address empty under EIP-161 is
  a deposit whose caller it creates (`SATIN-DEP-003`, which names the Mega System Transaction), and
  the model charges that caller's state gas before the first frame, at `m = 1`.
- **A promoted transaction's value** reaches the Oracle, whose methods are not payable, so its frame
  reverts; the Oracle's restricted writes, which ask `SequencerRegistry.currentSystemAddress()` by a
  call, are not modelled.
- **The other call opcodes and `CREATE2`.** For the review's edges the model runs `CALLCODE`, whose
  value moves from the calling account to itself, changing no account and recording none
  (`SATIN-ACCT-007`), with the stipend and the history allowance of a value call
  (`SATIN-HIST-018`); `STATICCALL`, of a frame that changes no state (anything else in such a frame
  is unmodelled); `CREATE2` past its salt, its charges in the order of `SATIN-SIZE-005` and its
  address EIP-1014's; and a creation whose initcode reverts or halts, for any creator, with the
  failed-create row of `SATIN-TAKE-007`, which the model applied to a keyless signer's alone
  (D-80). A deposit from the live system address is a failed deposit whatever its destination,
  decided before the creating and self-addressed deposits the model does not run; and a synthetic
  message may carry an authorization list, each entry with its recovered authority.
- **The text.** `SATIN-MST-004` holds a transaction from any address but the live one to being
  validated and charged as a user's, and `SATIN-MST-008` prices a `SYSTEM_CALLER` transaction at
  `m = 1`; the model reads the first as the transaction's validation and fee and the second as the
  exemptions its origin gives, which the `SYSTEM_CALLER` cases take together. At `bcf260d`
  `SATIN-MST-004` says so itself: it does not decide system origin, which `SATIN-MST-007` decides,
  and `SATIN-MST-008` overrides a system-originated transaction's pricing and resource treatment.

**D-84. Every case of D-82 gates at the revm-based pin `1a981f4b`.** At its previous pin,
`7110d87b`, the revm-based implementation charged a system-originated transaction and a deposit no
history gas, against `SATIN-MST-008` and `SATIN-HIST-016`: the promoted transaction, the source-hash
deposits, the `SYSTEM_CALLER` message, the user's deposit in the crowded bucket and the source-hash
deposit's reservoir share used less gas there than the rule's, by their history bytes at the history
price, and the source-hash deposit from the live system address, a failed deposit, reported no
history bytes. At `1a981f4b` it charges them history gas (D-94), and all eight pass on both
implementations, plain and instrumented; none is quarantined, and each pins the rules its own
derivation cites. So do the 44 cases of the review's edges.

The review's other edges need what a `state-transition` case does not observe, and no case pins
them:

- **A child's pools at its entry.** A `STATICCALL`'s reservoir share, which its frame can neither
  spend on a fresh slot nor a log; a call without value requesting no gas, whose child stops at once
  and returns its share unspent; a nested share, A's 99 giving B 98 and B's giving C 97; a
  `DELEGATECALL` at the remainder 99; and the cap taken after a first memory expansion, or after a
  value call's new account, whose callee holds no code: what the child received is gone by the time
  any later opcode reads the caller, and the `gasPools` group observes the first frame alone.
- **A child's data budget.** An admitted hint is on no frame (`SATIN-LIM-012`), so hints do not lower
  a child's data budget, its share of what its caller's own counts leave; bringing that budget near a
  log a case can pay for takes the caller's own logs or records, which cost more regular gas than the
  execution cap.
- **The KV-update limit** of a system-originated transaction: half a million write records cost more
  gas than a transaction holds (as D-65 found for the limit-stop page).
- **The caller a promoted transaction's recipient sees**, which only the Oracle's restricted writes
  observe, through a call the model does not make.
- **A deposit whose source hash is the promotion's and whose other fields are another type's**: a
  deposit envelope's type is fixed by its first byte, and no synthetic message carries a source hash.
- **A system call's outermost frame** (`SATIN-FWD-007`'s other side, `SATIN-POOL-010`), which only a
  block's pre-block calls run; a `SYSTEM_CALLER` message is no system call.

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
- **The refusal of a transaction without the system shape** from that address had no case: neither
  adapter mapped it to a reason (each reported an error for it). Withdrawn by D-82, under which both
  adapters map it to `not-system-shape` and the refusal has cases.

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

From a review of the first fill batch:

**D-91. The first batch's edges two reviews found unpinned are cases at `bcf260d`, and the model's
reach grows with them (D-63 amended).** An independent review of the detention, destruction and
limit-stop cases listed the edges they leave unpinned and the mutations of the evm2-based
implementation's engine no case of that implementation's own suite kills; a second review of the
first cases found more. Sixty-four cases at `bcf260d` (`CURRENT_SPEC`, D-96), in the three areas,
now take the edges a transaction can show, most in pairs one unit apart, sized from the model's
own figures (D-57, D-59); every expected value comes from the specification through the model.
Every one passes on both implementations.

- **Gas detention (34).** A ModExp input over EIP-7823's bound that halts after its gas charge burns
  its whole forward and counts none of it as compute (`SATIN-DET-011`, `-019`, D-78, D-96): priced
  at the allowance and followed by one more charge, which fits, and forwarded less than the
  allowance and followed by the caller's compute to the limit exactly and one past it. RIPEMD-160,
  SHA-256 and ecrecover each priced at the allowance and one past it (`SATIN-DET-021`, `-023`). A
  `DELEGATECALL` of the identity precompile that carries the value its frame inherited from a sender
  whose balance is now zero: it moves no value and checks no account, so it is the crossing
  (`SATIN-DET-024`). The transaction's own call of ModExp at the block beneficiary's address,
  detained from its start: priced past the allowance (its own stop, its gas untouched), within it,
  and past its gas (`SATIN-DET-008`, `-021`). A child that halts on its value call's start record,
  and a value call's callee that halts on its stipend, each followed by the caller at the limit and
  one past it: what they burn is no compute, the forward and the stipend's rest among it, and their
  paid work is (`SATIN-DET-009` to `-011`, `-019`). `BLOCKHASH` of the oldest block in range and of
  one older, in block 300 (`SATIN-DET-004`). The beneficiary's account read by `BALANCE`, by
  `EXTCODECOPY` that completes and not by one that runs out of gas at its copy, as a `CALL`'s and a
  `DELEGATECALL`'s target, marked when the start is decided at a compute that leaves out the
  forward, and as a recipient's EIP-7702 delegate, which detains the transaction from its start
  (`SATIN-DET-001`, `-003`, `-008`). A read in a child that then reverts or halts, which stays
  marked. A creation by the beneficiary, and `BLOBHASH`, with access off (`SATIN-DET-006`, `-002`).
  A `CALL` and a `CALLCODE` one operand short of a target whose delegate is the beneficiary, which
  fail on the stack as with access on (`SATIN-MAC-003`). A finite forward between the spendable part
  and what the whole regular gas lets a call forward (`SATIN-DET-015`). A deposit's Oracle read at a
  whole regular gas of exactly its one charge, the crossing, and one gas short, an out-of-gas
  (`SATIN-ORCL-004`, `SATIN-DET-018`, `-020`).
- **Limit stops (14).** A precompile that would answer with a success, its start crossing the
  transaction's data-size limit: its answer is replaced by the stop on the call's whole regular gas,
  nothing of its price taken from it; one that fails kept nothing and its failure stands, also when
  the address holds code (`SATIN-STOP-014`, `SATIN-PCMP-008`); one priced past gas detention's
  allowance whose start would cross data size as well is the compute stop. A frame's own data-size
  budget reached through logs whose history a reservoir pays: the transaction's own frame one byte
  past it, the stop naming the budget and not the limit, and a child at its budget and one byte past
  (`SATIN-LIM-002` to `-005`, `-011`, `SATIN-STOP-018`). The first frame's value start counted on the
  transaction with the hints that follow, a log at what is left and one byte past. Two applied
  authorities' growth, 501 fresh slots and a child's start that fits, whose empty return data the
  transaction returns. A creation whose initcode calls its creator back to take two records back
  and send a hint into the room that freed, and then reverts, halts or is stopped: the records stand
  again with the hint counted, and the creator, whose nonce bump makes no record, returns the
  data-size stop before its next instruction; and its control, which succeeds exactly at the limit
  (`SATIN-STOP-006`, `-012`, `-015`).
- **Destruction (16).** Two accounts created in one transaction at different multipliers, one with a
  fresh slot, each destroyed by its own table, and the first destruction discarded by a reverting
  frame (`SATIN-SD-002`, `-004`, `-005`, `-008`). A created account destroyed to itself, its balance
  burned at once and silently (`SATIN-LOG-005`). A destruction in a frame whose state-growth budget
  is zero: an absent leaf's fall makes room for the beneficiary's rise, and a present leaf gives
  none, so the rise crosses (`SATIN-SD-018`, `-019`). The opcode's static cost a charge of its own
  under gas detention, the crossing though its dynamic part would not fit, and one gas below it an
  out-of-gas (`SATIN-DET-018`, `-020`). Its charges before its table: a new beneficiary's state gas
  one gas short halts before the table's give-back, and paid it completes (`SATIN-SD-009`, `-019`).
  Its positive effects crossing the data-size limit after the table's take-backs, which leaves the
  beneficiary's read unmarked, and fitting exactly, which marks it (`SATIN-SD-020`). A creation
  transaction's own frame that destroys the account it creates, with and without a fresh slot, its
  table giving back the charges made before the first frame once, and its own end the
  beneficiary's account, a read that binds the constructor (`SATIN-SD-001`, `-007`,
  `SATIN-DET-007`). A creation over a storage-bearing leaf that survives, and one its creator's
  revert rolls back (D-93).
- **The model's reach** (`docs/model.md`). RIPEMD-160's price and digest, SHA-256's and ecrecover's
  prices and outputs, ModExp's output; a `DELEGATECALL` of a precompile, and a transaction's own call
  of one; `BALANCE`, `EXTCODECOPY` and a `DELEGATECALL` of the beneficiary, a `CALL`'s read of it as
  its target, and a recipient delegating to it, as reads; `BLOBHASH` with access off; `CALL` and
  `CALLCODE` short of their operands, a halt before the opcode's charges (D-84 runs `CALLCODE` with
  them); `SELFDESTRUCT`'s static cost and its dynamic part as two charges; a created account's first
  `SELFDESTRUCT` to itself, and one in a creation transaction's own frame; a `CREATE` of any creator
  stopped in a limit-stop case, and the hint exception on the creator's resume after a failed
  creation (D-84 models a reverted or halted one for any creator); a value call to the identity
  precompile where no limit is set in a limit-stop case; the reset of a created address's storage
  (D-93); and the block's number as a case's parameter. A case at the current snapshot cites
  `SATIN-STOP-014` where a value precompile's crossing cited `SATIN-STOP-016`, which `c130558`
  retired (D-78). An account the state holds with storage, empty under EIP-161, that the
  transaction leaves as it found it, is no change of the state diff. Every existing slice file is
  byte-identical.

**D-92. What the reviews corrected, and what stays out.**

- **A frame's own data-size budget is reached.** D-75 held that a frame's data-size budget is out of
  reach because the history of its logs and records costs over a billion gas. The execution cap
  bounds regular gas, not the reservoir: a transaction of 2,000,000,000 gas in a block of
  10,000,000,000 pays that history from its reservoir, and D-91's cases reach the budget of the
  transaction's own frame and of a child. D-75's third item is withdrawn for data size; the KV
  updates stay out of reach.
- **A creator that is the beneficiary is reached without a read.** A creation transaction onto the
  beneficiary's address is not detained from its start (`SATIN-DET-006`), so its initcode is a
  creator running as the beneficiary that has read nothing; with access off, its `CREATE` is neither
  refused nor marked.
- **D-69's first reading, re-derived.** The case that halts ModExp at the allowance and then makes one
  more charge was proposed under D-69's reading, by which the charge would cross. Under
  `SATIN-DET-011` (D-78, D-96) the halt counts none of the forward as compute, its price included,
  so the charge fits and the transaction completes.
- **`SATIN-DET-025` has no case.** The answers it applies to are a system contract's intercepted
  answers that spend regular gas. MegaAccessControl's and MegaLimitControl's spend none
  (`SATIN-ICPT-004`), and an admitted `sendHint` is no answer: the call then runs the Oracle's
  code, a frame held to the limit as any (`SATIN-ORCL-006`). KeylessDeploy's is the only answer
  that spends regular gas, and only the transaction's own call is intercepted (`SATIN-KEY-003`): it
  answers at compute zero, where the allowance is the whole cap, which its overhead is far below,
  and the creation it runs is a frame held to the limit by its own charges. No transaction makes an
  intercepted answer whose regular spend exceeds its frame's allowance.
- **What earlier cases already cover.** A deposit's start record at its affordability edge and
  validation's deposit refusals are cases since the outcomes page's (D-85, D-86):
  `satin/outcomes/pre-frame/deposit-start-record-{one-short,paid}` and
  `satin/validation/deposit/intrinsic-and-history-{one-short,paid}`; a list that fits the
  state-growth limit, gated entries and a beneficiary authority that does not detain are the
  authorization page's (D-88), and a keyless deployment applies a thousand absent authorities
  (D-80). No new case repeats them.
- **What no transaction can show.** A transaction's own `sendHint` large enough to fill the
  data-size limit before its value start: its calldata's floor alone, 64 gas a byte, is above the
  execution cap, so validation refuses it before any hint is admitted (`SATIN-VAL-003`,
  `SATIN-SCHED-005`), and no other body bytes can make up the rest. `SATIN-DET-025`, above.
- **D-72's refund point is superseded.** D-72 held that a store after a destruction's mark that
  clears or restores a slot does not say whether it moves the refund counter. `SATIN-SD-013` at
  `c130558` keeps the inherited EIP-3529 refund for those stores; the case is a transaction's, not
  yet made.
- **Still open, model work this change does not make.** A collision on a nonce or on code, and a
  re-creation by `CREATE2` onto an address the transaction destroyed; a destruction that returns an ordinary
  account to its original balance and takes its record back; a creation over an address funded
  earlier in the transaction; a store after the mark that restores a slot; a destruction's last
  record history unpaid; a descendant's take-back and a later child's budget; a code deposit after
  the mark that cannot pay its history or its data size; dimensions competing at one start; a
  nonzero-value deposit whose own frame is stopped; the rest of the precompile catalogue and its
  word and length thresholds; an ordinary cold `SLOAD`, an exhausted withheld part and the
  creation's and the code deposit's charging sites under detention; several stipends returning;
  the call opcode's own charges before a precompile's price; and `STATICCALL`, a refused
  `SELFDESTRUCT` and the Oracle's own storage with access off.

**D-93. A successful creation resets its address's storage, and both adapters list the slots it
cleared.** The base layer's create transition destroys the address's storage before the initcode
runs, and a creation rolled back restores it (`SATIN-BASE-001`, which keeps every base-layer
transition Satin does not restate). `SATIN-SD-003` and `-016` say what a slot of the created
account reads and what its original is in the transaction's accounting; they do not replace that
reset. So a slot that a leaf held before a creation that survives, and that the created account
does not write, is zero afterwards, the slots the transaction never accesses among them; the reset
makes no write record, charges no history and moves no state growth.

- **The format.** The state diff is a complete change set (`docs/format.md`): such a slot changed
  from its pre-state value to zero and is listed as `0x0`. Both adapters walked only the slots the
  run wrote. They now merge the case's declared pre-state keys of an account whose storage a
  surviving creation reset and compare every final value with the pre-state, so a slot written back
  to its pre-state value stays unlisted. The evm2-based adapter takes the reset from the account
  being created or its storage wiped; the revm-based adapter from the account being created.
- **The cases.** `satin/selfdestruct/creation-over-storage/survives`: a creation over a leaf with
  three slots that survives, one slot never accessed (cleared), one written, one written back to its
  pre-state value (unlisted). `satin/selfdestruct/creation-over-storage/creator-reverts`: the same
  creation rolled back with its creator, the leaf unchanged. Both implementations reset the slot.
- **Round 1's sidestep withdrawn.** The case at a zero state-growth budget whose present leaf's rise
  crosses ended with its creator's revert to keep its observations off this question; it keeps that
  shape, which the creation's rollback now explains.

From the move of the revm-based pin to `1a981f4b`:

**D-94. The revm-based pin moves to `1a981f4b`; every quarantined case gates.** The revm-based pin
moved from `7110d87b` to `1a981f4b`. Its root manifest moves the revm fork from `a125b2c4` to
`2b71cb61`, the fork revision that credits every give-back to a reservoir, and keeps the op-revm
fork (`8c0db939`), the OP monorepo revision (`f67d87cd`), the crates.io versions and the toolchain.
The adapter's manifest moves its twelve revm patches with it, and its lockfile moves those crates,
mega-evm and mega-system-contracts, nothing else. The system contracts' versioned artifacts (D-55)
and the SALT mapping's source (D-53) are byte-identical at both revisions, so
`tools/system-contracts.json` and the SALT member keep the revision they were read at, as does the
corpus inventory, read at `7110d87b` (D-78) and not read again here.

The revision adopts the rules the quarantine was about:

- a deposit and a system-originated transaction pay history gas as any transaction does
  (`SATIN-HIST-016`, `SATIN-DEP-001`, `SATIN-MST-008`), so a Mega System Transaction short of its
  body's history fails its promoted deposit's check (`SATIN-MST-005`);
- every give-back credits a reservoir, never regular gas (`SATIN-HIST-012`), and a fresh state
  charge takes its legacy share from regular gas (`SATIN-STATE-012`);
- the live system address is resolved once for the block, outside every transaction
  (`SATIN-REG-002`): a context built given the address reads nothing for it.

Every record named one of these rules, or a figure that follows from one, but for a keyless
constructor that logs and destroys the deploy address, whose kept log's history `SATIN-KEY-015`
counts in `gasUsed`; it passes too.

The adapter makes two changes, and keeps its protocol behaviour otherwise; the revision's API
moved in no other way the adapter uses, and it builds with these alone:

- **The live system address.** The revision reads the live system address when its context is
  built (`MegaContext::new_with_external_envs`), a database read outside every transaction. The
  adapter records reads at its database, so that read would put the registry's account in every
  case's reads, and its slot 0 where it holds the registry's code, which `SATIN-REG-002` excludes.
  The adapter reads the address off the case's pre-state through a view of the database that
  records nothing, with the implementation's own `system::live_system_address`, and builds the
  context with `MegaContext::new_with_system_address`, as a node hands in the address it resolved
  for its block. Only the seventeen cases that carry `reads` move: the registry's account, and its
  code hash where no other account holds that code, leave their reads, and nothing else does.
- **The failed-deposit label.** The adapter reported a `FailedDeposit` halt as a failed deposit only
  for a deposit envelope. A Mega System Transaction's envelope is legacy and its implementation
  runs it as a deposit, so its failed deposit was reported as an admitted transaction whose
  execution halted. op-revm halts with `FailedDeposit` only a transaction it runs as a deposit, so
  every such halt is now a failed deposit. Only
  `satin/validation/system-address/system-tx-below-intrinsic-and-history` moves.

Every gating case passes on the revision, plain and instrumented, and so do the seventy-one
quarantined cases, which pass on the evm2-based implementation too, with identical observations
plain and instrumented. They gate, and `tools/make_slice.py` holds no quarantine record; its
`QUARANTINE` table stays, empty, for the next one. The slice gates 474 cases, which pin 232 rules
in 22 areas: `deposits`, `oracle` and `reads` are areas of the gating slice.

No case's `input` or `expected` changes. A returned case pins the rules its derivation applied that
its area's scope holds or its definition names; its verdict no longer names any (D-76). Sixty-four
of them pin fewer rules, and eight rules that only verdicts named are pinned by no case now:
`SATIN-DEP-005`, `-006`, `SATIN-HIST-022`, `SATIN-MST-005`, `-010`, `SATIN-POOL-011`, `-015` and
`SATIN-REG-002`. Their figures are still derived in every case that applies them, and compared
there; only the rule-to-case index no longer lists them, as D-76 has it.

From the specification at `bcf260d`:

**D-96. The specification at `bcf260d` is bundled; a precompile's halt, a failed deposit's step-4
load and a promoted system transaction's receipt are read from it.** `specs/satin-bcf260d` is the
specification's main after two merged changes. The first is its QI-36, five wordings; the second
is its QI-37, two wordings on the Mega System Transaction page. The snapshot holds 411 ids, 401
active: `SATIN-SYSC-005` is added, `SATIN-DEP-012`, `SATIN-DET-011`, `-019`, `SATIN-MST-004`,
`-005` and `SATIN-REG-008` are reworded, and none is retired ([spec identity](spec-identity.md)).
It is the snapshot new cases cite (`CURRENT_SPEC` in `tools/make_slice.py`); the cases that cite
`c130558` name it as `FILL_SPEC`.

- **A precompile's halt.** `SATIN-DET-011` now names a third halt of a precompile: an input over
  its size limit, which fails the call before any gas check (`SATIN-PCMP-005`). Such a precompile
  burns its whole forward, "its charged price, when it has charged one", and counts none of it as
  compute. `SATIN-DET-019` now excepts a halting precompile's charged price from "paid work before
  the halt still counts". That is the reading D-78 took from `SATIN-DET-011` alone.
  - The model now tells the two failures apart (`tools/satin_model/precompiles.py`). An input over
    a size limit fails before any gas check and charges no price. Its step cites `SATIN-PCMP-005`
    and `SATIN-DET-021`. It no longer says that the pairing charges a price of zero and then fails
    a check, and no longer cites ModExp's order (`SATIN-PCMP-007`). ModExp over EIP-7823's bound
    still charges its price and then fails.
  - For either failure, the ledger step cites `SATIN-DET-019` beside `SATIN-DET-009`, `-011` and
    `-021`. No figure moves: the compute after either call is what D-78 derived.
  - Where no limit is set, a precompile that fails a check after its gas charge is now
    `Unmodelled`. No case makes that call, and the step would have described it as a size-limit
    failure.
- **A failed deposit's step-4 load.** `SATIN-DEP-012` now forbids the load for the first frame's
  start only to a deposit that fails validation or cannot pay a charge of steps 1 to 3 of
  `SATIN-SCHED-008`. A deposit that reaches step 4 makes that load, of its recipient or its created
  address. It keeps the load when it then fails: at step 4, at step 5 or in its first frame.
  - The model already loaded the recipient at step 4, and kept that load when the first frame
    could not fund the value (D-85). A failed deposit's reads now cite `SATIN-DEP-012` for that
    load, and say that a deposit failing validation or before step 4 makes none.
  - No case observes the reads of a deposit that fails before step 4.
  - The model derives no deposit that fails at step 4 or 5: a deposit's value to an account empty
    under EIP-161, and a deposit to a delegated recipient, stay `Unmodelled`.
- **A promoted system transaction's receipt.** `SATIN-MST-005` now says that promotion changes
  execution only. The block holds a legacy transaction, so its receipt is a legacy (type `0x0`)
  receipt, with no deposit fields, whose status and gas used follow the promoted execution. That is
  D-87's reading, which the model already took. The receipt step for a Mega System Transaction
  promoted to a failed deposit now cites `SATIN-MST-005` instead of D-87. `SATIN-MST-004` now says
  that it does not decide system origin: `SATIN-MST-007` decides it, and `SATIN-MST-008`
  overrides a system-originated transaction's pricing. The model derives no transaction from
  `SYSTEM_CALLER` and no deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH`, so no reading of
  it moves.
- **The registry's deployment.** `SATIN-REG-008` now keeps an account's storage where it used to
  clear it. A `state-transition` case runs one transaction against its pre-state, with no pre-block
  sequence (D-52, D-55). The model reads nothing of the deployment, so no reading moves. Under
  `SATIN-SYSC-005`, no state within the specification tells the new text from the old (D-97).
- **The cases that move.** Four derivations take a changed reading, and those four cases now cite
  `specs/satin-bcf260d`. Each moves from `c130558`:
  - `satin/detention/precompile/modexp/over-bound-at-allowance` and
    `satin/detention/precompile/bn254-pairing-over-size-limit`, whose precompiles halt;
  - `satin/outcomes/deposit/value-unfunded-reads`, whose reads keep the step-4 load;
  - `satin/validation/system-address/system-tx-below-intrinsic-and-history`, whose receipt is the
    promoted transaction's.

  Every rule they pin is active at `bcf260d`. Their `input`, `expected` and pinned rules are
  unchanged; only their `specRef` and `specCommit` move.
- **Every other case keeps its snapshot.** Each rule added or reworded between `c130558` and
  `bcf260d` was held against the cases that pin it, through the model. Every expected value still
  holds under the new text.
  - `SATIN-DET-011` is pinned by nine cases and `SATIN-DET-019` by nineteen. Of these, only the two
    that move have a precompile that halts. In the others, a frame halts, a precompile runs out of
    gas, a precompile is the crossing or a caller resumes, and those sentences did not change.
  - No case pins `SATIN-DEP-012`, `SATIN-MST-004`, `-005`, `SATIN-REG-008` or `SATIN-SYSC-005`.
    `SATIN-MST-005` is applied by five cases; four of them are refused before promotion and have no
    receipt.
  - One more case fails a precompile on its size limit: the BN254 pairing where no limit is set
    (`satin/outcomes/precompile/bn254-pairing-over-size-limit`). It applies no rule of gas
    detention, since no compute is counted there, so it keeps `c130558`.

**D-97. A pre-state that `SATIN-SYSC-005` excludes is no case's.** Under `SATIN-SYSC-005`, a state
a block starts from is an invalid prestate when it holds storage at a system contract's address in
an account without code. Executing a block from such a state lies outside the specification,
whether `SATIN-SYSC-003` or `SATIN-REG-008` deploys the contract. A case runs no pre-block sequence
(D-52, D-55), so its pre-state stands for the state its block starts from. Nothing a case expects
can be derived from such a state, and no case may hold one.

- **The cases.** No case holds such a pre-state. At the six addresses `SATIN-SYSC-001` lists, a
  case's pre-state holds:
  - the Oracle, KeylessDeploy, MegaAccessControl and MegaLimitControl, with their code and no
    storage (169 cases; D-55);
  - the SequencerRegistry with the `0xfe` placeholder and no storage (468 cases), or with version
    2.0.0's code and its slot 0 (6 cases; D-87);
  - nothing at the High-Precision Timestamp's address.
- **The model.** The model refuses such a pre-state. `Run.run()` raises `InvalidPrestate`, an
  `Unmodelled`, before it derives anything, when the pre-state holds non-zero storage in an account
  without code at one of the six addresses (`SYSTEM_CONTRACT_ADDRESSES`). `tools/make_slice.py` then
  stops for that case.
  - Before this change, the model took such a state as in scope: it read a registry without code as
    naming no live system address (`SATIN-REG-002`).
  - Storage in an account that holds code stays in scope, as the second sentence of
    `SATIN-SYSC-005` says. The registry of the six D-87 cases is one.
- **No case pins it.** `SATIN-SYSC-005` bounds the inputs, and no derivation step applies it. The
  rule-to-case index lists it among the uncited rules.

From the move of the evm2-based pin to `ccbdb23e`:

**D-98. The evm2-based pin moves to `ccbdb23e`; the adapter, its lockfile and every observation
stay as they were.** The evm2-based pin moved from `353608b9` (fork `390a3876`) to `ccbdb23e`
(fork `c0a91cbb`, upstream evm2 `e681662b` with the implementation's patches), the fork the
revision's own `next/evm2-fork.env` pins. Its toolchain (`nightly-2026-04-23`) is unchanged.
Between the two revisions the implementation:

- reports what a block reads, for its stateless witness. A transaction's fee computation now
  reads the L1 block contract's account, and its slots only when the account exists
  (`SATIN-WIT-011`); the slots it reads, and their order, are unchanged. The pre-block sequence no
  longer reads the contract;
- keeps the storage of an account without code that a new SequencerRegistry is installed over
  (`SATIN-REG-008` at `bcf260d`). That is a step of the pre-block sequence, which a single
  transaction's EVM never runs (D-52, D-97);
- moves its fork onto upstream `e681662b`. Upstream's #898 drops `GasSettlement::state_refund`,
  which the implementation always set to zero; `OpPrecompiles` delegates `warm_addresses`; and
  the step tracers of `evm2-inspectors` leave the state gas a step spills out of its cost. The
  adapter calls none of these.

No API the adapter uses moved, and it builds `--locked` with no change to its source or its
manifest. Its lockfile stays the implementation's, less what the adapter does not build, plus
the adapter and the format crate (D-52). The implementation's lockfile only gains eighty
packages, removes none and moves no version. The new packages are the dependencies of its
inspector tests (`evm2-inspectors` with the JavaScript tracer, `alloy-rpc-types-trace`), which
the adapter does not build. Every package in the adapter's lockfile is in the implementation's
at the same version, source and checksum, and each of its dependency edges is there too.

The read of the L1 block contract is the only change an observation could show: a case without
the contract would no longer report its slots among its `reads`. Every case's pre-state holds the
contract, so none moves. Every gating case passes on both adapters, plain and instrumented, with
identical observations, and the negative case fails as it must. The evm2-based adapter's
response to every run request of the slice, its 611 gating cases and the negative case, plain and
instrumented, is byte-identical at `353608b9` and at `ccbdb23e`. No case, model rule or tool
changes.

From the history page's and the resource-accounting page's uncited rules:

**D-100. Two areas pin the history page and the resource-accounting page, whole, at `bcf260d`.**
Every transaction's derivation applies the history page (`SATIN-HIST`) and the resource-accounting
page (`SATIN-ACCT`), and the areas that cite them name single rules (D-76), so twenty-four of their
rules were applied by many cases and pinned by none. Two areas now take the pages whole: `history`,
whose scope is `SATIN-HIST`, and `accounting`, whose scope is `SATIN-ACCT`. Their seventy-seven cases
cite `specs/satin-bcf260d` and sit at the rules' edges, with a control where one is cheap. Forty
were written first; an independent review then named the edges they left unpinned, and thirty-seven
more fill them.

- `history` (39): history unscaled in buckets of m = 2 and 4 (`SATIN-HIST-001`); an `SSTORE` and a
  `SELFDESTRUCT` one gas short of a regular charge after their load, one short of their records'
  history, and paying it (`SATIN-HIST-008`, `-013`); a log crossing the data-size limit while its
  frame cannot pay its history, a stop, against one that fits, a halt (`SATIN-HIST-013`); a value
  call's start under a crossing limit, its caller one gas short of the records' history, which
  halts first, and paying it, which is stopped and given the charge back (`SATIN-HIST-014`); a
  `SELFDESTRUCT` one gas short of its beneficiary's cold access, which loads nothing; a value call to a
  new account
  whose caller keeps one gas short of the records' history after a forward computed past the new
  account's state gas, and exactly it (`SATIN-HIST-010`); the forward a constructor reads, by
  `CREATE` and `CREATE2`, its created account's state gas paid from regular gas or from the
  reservoir before it (`SATIN-HIST-011`); the history allowance, spent by one log and by five, one
  log past it, a log past it one gas short of its rest and paying it, a record's history, a fresh
  slot's state gas and computation it does not pay, two sibling value calls each with its own, and
  the starts that grant none: a call without value, also from a frame holding one, a `DELEGATECALL`
  in a frame entered with value, an endowed creation and the transaction's own frame
  (`SATIN-HIST-018` to `-021`); the specification's two examples of the history bytes
  (`SATIN-HIST-022`); a descendant's give-back paying its next record (`SATIN-HIST-007`); and a
  regular ledger one below and one above the floor, and a deposit's (`SATIN-HIST-017`);
- `accounting` (38): a value `CALLCODE` and a value call to the calling account itself
  (`SATIN-ACCT-007`); value to the sender, also from the sender's own delegated frame, whose storage
  is recorded (`SATIN-ACCT-008`), and to an applied authority, also one that is the block
  beneficiary (`SATIN-ACCT-009`); value to the base fee vault from a call and as the transaction's
  own value to the vault the state does not hold, a destruction to it, and the sender as the block
  beneficiary, the settlement's credits no rise (`SATIN-ACCT-010`, `-017`); account records across
  transfers: two to one recipient, one to each of two, a failed transfer followed by a sibling or
  by a retry, a partial return, a pass-on of exactly what was received, a destruction that returns
  one or both accounts to what was loaded, in a frame kept and in one that fails, and a creation
  onto an address the transaction funded, against its unfunded control (`SATIN-ACCT-004` to `-006`);
  a creator's nonce record surviving one and two failed creations, a creation refused for an
  endowment its creator cannot fund, a destruction's mark surviving a failed sibling, and a child's
  log merging after a large one of its caller's (`SATIN-ACCT-011`, `-012`); an access list's entries,
  one and the same one twice, counted as body bytes and as no record; the transaction's whole
  state-growth limit, a fall at it and the rise it made room for, and a second rise that crosses,
  in the first frame and in a child whose signed net goes below zero; and a child's remaining
  clamped to its budget, its callee's share at it and one past it (`SATIN-ACCT-016`, `-018`, `-019`);
  and a failed deposit from an empty leaf and from a caller of nonce 1 (`SATIN-ACCT-020`).

No existing case changes: no other area's scope holds either page whole. Every new case passes on
both implementations, plain and instrumented.

**D-101. The model cites the two pages where they decide, and grows where the cases need.**
The derivations cite the rules at the steps where they decide: the bucket's m beside an unscaled
history charge (`SATIN-HIST-001`), an `SSTORE` or a `SELFDESTRUCT` that fails at a regular charge
after its load (`SATIN-HIST-008`), a log held to the limits before its history and a record's or a
log's history the frame cannot pay (`SATIN-HIST-013`), the floor where it is above the regular
ledger (`SATIN-HIST-017`), a log in a frame no value start granted an allowance and a record's
history in one that holds an allowance (`SATIN-HIST-018`, `-019`), a value start's transfer log
(`SATIN-HIST-021`), value to the sender, to an applied authority and to a fee account
(`SATIN-ACCT-008` to `-010`), a child's end and a failed creation's creator record
(`SATIN-ACCT-011`), a marked account's store (`SATIN-ACCT-016`), the settlement's credits to an
empty fee account (`SATIN-ACCT-017`), a slot's fall (`SATIN-ACCT-018`) and a state-growth crossing
(`SATIN-ACCT-019`). No opcode is added. Two paths no case had run are corrected:

- A value `CALL` to the calling account itself moved the value and emitted a transfer log. It now
  moves nothing, makes no record and logs nothing, as `SATIN-ACCT-007` and `SATIN-LOG-003` state,
  and still grants its child the allowance.
- A value start answered without a frame was held to the transaction's limit with the admitted
  hints left out. A hint is on no frame's budget and on the transaction (`SATIN-LIM-012`), so the
  start is now held to the transaction's limit with them, as a start with a frame already was.

Four shapes the model refused now derive:

- A `SELFDESTRUCT` of an account the transaction did not create that returns an account to what the
  transaction loaded takes its record back where it completed, giving the record's history into the
  destroying frame's reservoir before what it makes is held and charged (`SATIN-ACCT-004`, `-006`,
  `SATIN-HIST-006`, `-007`). Each end's record is decided on the balances the move leaves it.
- A `CREATE` or `CREATE2` whose endowment its creator cannot fund is refused before any charge for
  the start and before the created address is read: no nonce bump, no record, nothing charged but
  the opcode's regular gas (`SATIN-HIST-015`, `-023`).
- A creation onto an address a transfer of the transaction funded, which holds a balance and nothing
  else: not empty under EIP-161, so no leaf charge and no rise, and changed already, so no record
  (`SATIN-ACCT-005`, `-014`, `-015`). Its failure and its stop are not modelled.

Two checks the model lacked are added, which no earlier case reached:

- `SATIN-VAL-003` step 4: a gas limit above `EXECUTION_CAP` while the larger of the intrinsic regular
  gas and the floor exceeds it is refused, `floor-exceeds-gas-limit`.
- A `SELFDESTRUCT` whose frame pays its static cost and not its beneficiary's cold access halts before
  the beneficiary is loaded (`SATIN-WIT-012`); the model loaded it first.

**D-102. What the two pages leave to no transaction-level case.**

- **The floor never raises a Satin transaction's gas used.** Let `B` be the floor's base (12,000 to
  the sender itself, 15,000 for a call, 21,000 for a value call, 24,000 for a creation), `C` the
  calldata bytes and `A` the access-list bytes. The body's history and the intrinsic charges are
  never refunded or given back, so the spend before the refund is `S >= B + 88 x 310 + 92 x C + 88 x A`,
  a zero byte being the cheapest calldata (4 and 88 of history); the access list's and the
  authorizations' regular charges and all execution only add to it. The refund is at most `S / 5`,
  and the floor is `F = B + 64 x (C + A)`, so `S - refund - F >= 4/5 x S - F >= 21,824 - B / 5 +
  48/5 x C + 32/5 x A >= 17,024 > 0`. The branch of `SATIN-HIST-017` and `SATIN-POOL-018` where the
  gas used is the floor is therefore not reachable at these constants, for a creation, all-zero
  calldata and access-list tokens included. A failed deposit settles at its whole gas limit apart
  from this (D-66). Its cases pin the block's figure, `max(regular, floor)`, on either side of the
  floor, and a deposit's.
- **`SATIN-ACCT-012`'s KV check.** At these constants `TX_KV_UPDATE_LIMIT` records weigh more than
  `TX_DATA_LIMIT` bytes, so the data-size limit stops a transaction first. The KV check is made,
  and no transaction can show it.
- **A hint admitted before the transaction's own start never makes that start cross.** The one hint
  counted before the first frame's start is the transaction's own call to the Oracle's `sendHint`,
  whose input is its calldata, `L` bytes. The start crosses only if the body, the authorities'
  records and the hint, `310 + 2 x L + A + 141 x N` bytes with `A` access-list bytes and `N`
  authorizations, come within the start's 200 bytes of `TX_DATA_LIMIT`. Validation bounds them: the
  floor, `21,000 + 64 x (L + A)`, and the intrinsic regular gas, `21,000 + 4 x L + 7,816 x N` and
  more, must not exceed `EXECUTION_CAP` (`SATIN-VAL-002`, `SATIN-VAL-003` steps 3 and 4), and a
  deposit failing them is a failed deposit (`SATIN-VAL-008`). So `L + A <= 3,124,671`, and with that
  `L`, `N <= 23,986`: at most `310 + 6,249,342 + 3,382,026 = 9,631,678` bytes, short of the limit by
  more than 3.4 MB. A transaction of 6.5 MB of calldata, which the crossing would need, has a floor of
  over 419,000,000 and is refused at step 4.

From the precompile page's and the contract-limits page's uncited rules:

**D-103. The precompile page's own rules are cases at `bcf260d`, and the model runs KZG point
evaluation, `P256VERIFY` and the BLS12-381 precompiles for them.** No case pinned
`SATIN-PCMP-001` to `-007`. The precompile cases so far sat in the detention and outcomes areas,
whose scopes leave the page's rules out (D-76). Twenty-four cases under `satin/precompiles/`, at
`bcf260d` (`CURRENT_SPEC`), now pin all seven. Each makes a contract call a precompile where no
limit is set, mostly in pairs one gas or one pair apart. The detention side of these
precompiles stays in `satin/detention/precompile/`, which no new case repeats. Every one passes on
both implementations.

- **KZG point evaluation (6).** The input verifies: its commitment and proof are both G1's point at
  infinity, the zero polynomial's proof, with `y = 0`. Forwarded one below
  `KZG_POINT_EVALUATION_GAS`, it fails out of gas before any verification. Forwarded the price and
  three times it, it is charged exactly the price and returns `FIELD_ELEMENTS_PER_BLOB` and the
  modulus. Given three times the price, an input one byte short, a versioned hash that does not
  match and a proof that does not verify (`y = 1`) each consume the whole forward
  (`SATIN-PCMP-001`, `-006`).
- **`P256VERIFY` (3).** An ECDSA signature over P-256 that verifies, forwarded one below
  `P256VERIFY_GAS` and at it. One that does not verify, forwarded twice the price, is a success with
  empty output charged the same price (`SATIN-PCMP-003`, EIP-7951 at the pinned revision).
- **ModExp (7).** One-byte operands at `MODEXP_MIN_GAS` and one below it. Operands of 33 bytes, past
  which EIP-7883 doubles the complexity's words and multiplies the exponent's length by 16, at their
  formula price and one below. A modulus at EIP-7823's bound, which runs, and one byte over, which is
  charged its whole formula price and then fails. A base length of `2^256 − 1`, too large to price,
  which no forward pays (`SATIN-PCMP-002`, `-007`).
- **The OP size limits (8).** Zero bytes are pairs of points at infinity, valid at any length the pair
  size divides. The BN254 pairing at its limit, forwarded one below its price and at it. The
  BLS12-381 G1 MSM, G2 MSM and pairing at their limits and one pair over, each forwarded the price of
  its input: at the limit the precompile runs and answers the point at infinity or the word 1; one
  pair over, the call fails before any gas check and consumes the forward (`SATIN-PCMP-004`, `-005`).
- **The model's reach** (`docs/model.md`). `Run.precompile_page` decides such a call by the page's
  own rules. KZG point evaluation runs on commitments and proofs at the point at infinity, where the
  pairing check reduces to `y = 0`, with its length and versioned-hash checks. `P256VERIFY` runs
  EIP-7951's checks and ECDSA over P-256, written out from the curve. The model has EIP-2537's MSM
  prices from 128 pairs on and its pairing price, the answers for points at infinity, and ModExp's
  lengths too large to price. No opcode is added.
- **Mutations.** In the evm2-based implementation's OP precompile set, four mutations that its own
  suite does not kill are killed: each OP limit's `>` made `>=`, for the BN254 pairing and for the
  BLS12-381 G1 MSM, G2 MSM and pairing.
- **What no transaction-level case pins.** `SATIN-PCMP-005`'s call forwarded no gas fails whether
  the size check or the gas check comes first, so the order cannot be observed there. The page's
  orders matter under gas detention, where the price read before a call decides it:
  `SATIN-PCMP-007`'s charge before the bound is pinned there by the ModExp cases of
  `satin/detention/precompile/modexp/` (D-91).
- **The edges a review found (34 more).** An independent review listed the edges the first 24 left
  unpinned. In its rank order:
  - **`SATIN-PCMP-008`.** A precompile's address holding an EIP-7702 indicator: the call pays the
    delegate's access with its other charges, and dispatch runs the identity, which returns its
    input and not the delegate's word. Under gas detention, such a call is decided by the
    identity's price, one past the allowance, and is the crossing. The same indicator naming the
    beneficiary in a frame whose access is off has no case yet (D-105).
  - **The BLS12-381 size limits under gas detention.** Each over-limit input, whose pairs would be
    priced one past the allowance, is priced at zero: no crossing, a failure that consumes the
    forward (`SATIN-PCMP-004`, `-005`).
  - **`P256VERIFY`.** A key whose x is the order plus 3, for which R's x verifies only reduced
    modulo n. Eleven inputs EIP-7951 rejects before verification: 159 and 161 bytes, r and s at 0
    and n, a key at (0, 0), off the curve, or with x or y at p, and an R at infinity. Each is a
    success with empty output charged `P256VERIFY_GAS`; the case returns the call's success flag
    with the output.
  - **ModExp.** The exponent's length at EIP-7823's bound and one byte over, and the base's at it.
    EIP-7883's thresholds one at a time, with a 32-byte exponent of top bit alone: widths 32 one
    below and at the price, a base of 33, and widths 40 and 41, the last one below and at the
    price. The long exponents are all bytes 0x01, so the first 32 bytes and the low 256 bits that
    EIP-7883's text and its implementations read for the iteration count are the same; an
    exponent whose head is zero would set the two readings apart.
  - **KZG point evaluation.** An input one byte long, z and y at the scalar field's modulus, and z
    one below it at the price.
  - **`SATIN-PCMP-001`.** Karst's BN254 addition and multiplication and BLS12-381 G1 and G2 additions
    on points at infinity, each at its price.

  The model gained a `CALL` to a precompile's address holding an indicator, with its refusal at a
  beneficiary delegate in a frame whose access is off (`SATIN-MAC-007`, and `SATIN-MAC-004`'s
  settlement on the static cost and the memory); scalars outside the field as KZG's failure; and
  the four arithmetic precompiles on points at infinity at their prices.

**D-104. The contract-limits page's own rules are cases at `bcf260d`.** Thirteen cases under
`satin/contract-limits/` pin `SATIN-SIZE-001` to `-006`, which the outcomes area's size cases
(D-85) applied without pinning. Every one passes on both implementations.

- **The limits at their exact bytes.**
  - A creation transaction's initcode at `MAX_INITCODE_SIZE` runs, and one byte over is refused
    with `initcode-too-large` (`SATIN-SIZE-002`, `-004`).
  - Deployed code at `MAX_CONTRACT_SIZE` is deposited, from a creation transaction and from
    `CREATE`, the creation transaction's one byte over being `satin/outcomes/size/`'s.
  - `CREATE`'s code one byte over halts the creation, its regular gas consumed and the created
    account's charges given back, while its creator runs on and returns zero (`SATIN-SIZE-001`,
    `-003`).
  - A child's `CREATE` of initcode at the limit creates; one byte over halts the child at the opcode,
    and its caller resumes with no stop's return data.
- **The order of a creation's checks and charges** (`SATIN-SIZE-005`, `-006`).
  - Empty initcode at an offset of `2^256 − 1`, for `CREATE` and for `CREATE2`, creates: its offset is
    not checked. One byte there halts after its initcode cost (step 5).
  - Under gas detention, a child left 1 of spendable gas halts at a `CREATE2` of initcode over the
    limit and at a `CREATE` in a frame a `STATICCALL` started: the size check and the static context
    come before every charge, any of which would have been the crossing and stopped it.
  - A `CREATE2` short of its salt pays its initcode cost, and then its memory is the crossing: the
    memory comes before the salt (`SATIN-SIZE-006`). D-85's cases put the crossing at the initcode
    cost and let both charges be paid.
- **The model's reach.**
  - A creation transaction's initcode over `MAX_INITCODE_SIZE` is refused at validation.
  - A creating deposit's is a failed deposit (D-105).
  - A creation's code over `MAX_CONTRACT_SIZE` from `CREATE` or `CREATE2` halts the creation.
  - A creation in a static frame halts it before its operands, where the model raised `Unmodelled`.
  - With `Run.size_page`, the derivation cites the size checks and the offset rule where a run passes
    them. No opcode is added.
- **The edges a review found (11 more).**
  - **`CREATE2`, salt present:** initcode at `MAX_INITCODE_SIZE`, and deployed code at
    `MAX_CONTRACT_SIZE` and one byte over.
  - **A `CREATE` whose code is one byte over, under gas detention.** The creation is left 1 of
    spendable gas after its `RETURN`, below its deposit's hashing, and halts on the size check.
  - **`CREATE2`'s `CREATE_ACCESS` and hashing.** With the spendable part one short of them and at
    them, they are one charge.
  - **One byte of initcode at an out-of-range offset, under gas detention, for `CREATE` and
    `CREATE2`.** Its initcode cost is the crossing, a stop: that cost comes before the offset's
    range.
  - **`CREATE2` in a static frame.**
  - **A keyless deployment's initcode at the limit and one byte over.** Step 5 passes, and step 6
    answers; or step 5 refuses with `InitCodeTooLarge` (`SATIN-SIZE-004`'s keyless clause).
- **The review's premise corrected: one charge, not two.** The review proposed `CREATE2`'s
  `CREATE_ACCESS` and hashing as two charges under gas detention, and the model had made them two.
  `SATIN-DET-018` makes each part an inherited opcode deducts one charge "as the base layer has
  them". The base layer deducts `CREATE2`'s access and its hashing together, after the salt, and
  both implementations do the same. The model now charges them as one.
- **Narrower pins.** A size check is cited as `SATIN-SIZE-001` to `-004` only where the code or
  initcode sits at its limit. Elsewhere it is cited as `SATIN-SIZE-005`'s step 3, so a 32-byte
  creation no longer pins the size limits.
- **The other surviving mutations.** The evm2-based implementation's other surviving mutations in
  its OP precompile set change no outcome these pages define. The Isthmus functions are replaced in
  the Karst set Satin builds on, and the OP provider wrapper is a type the Satin engine never
  builds. Its FastLZ estimate's survivors belong to the base layer's L1 fee and data-availability
  footprint (`SATIN-BASE-009`, `-010`), which the model leaves at zero.

**D-105. Two cases wait: a deposit whose initcode is over `MAX_INITCODE_SIZE`, and a call refused at
a precompile address's beneficiary delegate.**
`SATIN-SIZE-004` at `bcf260d` says that "a deposit is never rejected, and one that fails this check
is a failed deposit". `SATIN-VAL-008` and `SATIN-DEP-004` say the same of any validation check. A
case was derived for it: a deposit minting 1 ether that creates with `MAX_INITCODE_SIZE + 1` zero
bytes, its gas limit paying its intrinsic gas and its body's history. The derivation makes it a
failed deposit that uses its whole gas limit and creates nothing.

Both implementations instead admit the deposit and run its creation. It succeeds, creates an
account, and reports the gas it used. The two return identical observations. The evm2-based
implementation's deposit preparation skips the initcode-size check, as op-revm's deposit validation
does, and the revm-based implementation builds on op-revm. So their agreement is not independent
evidence against the text.

The case stays out of the slice until the owner decides between fixing both implementations and
changing the text. The model keeps the rule, so the case can be derived again unchanged.

The second case waits for the evm2-based pin. The identity precompile's address holds an indicator
naming the block beneficiary, and a contract whose volatile-data access is off calls it. By
`SATIN-MAC-007` the call is refused at its delegate's load and never reaches dispatch. By
`SATIN-MAC-004` it is then charged its static cost and its memory, and nothing else.

The revm-based implementation at `1a981f4b` gives exactly that. The evm2-based implementation at
`ccbdb23e` gives the same revert but refuses the call before charging anything, 100 gas less. That
revision predates its implementation of the delegate-refusal settlement, which lands at
`acdd9d62`. The evm2-based adapter built against `acdd9d62`, whose evm2 fork is the same, passes the
case. The case enters the slice when the evm2-based pin moves past it; the model keeps the path.


From the gas pools', state gas's and gas schedule's uncited rules:

**D-106. The rules of the two gas pools, state gas and the gas schedule that no case pinned are
cases at `bcf260d`, in two new areas besides `gas-pools`.** Seventeen rules of the pages Two-Pool
Gas, State Gas and SALT Pricing, and Gas Schedule and Intrinsic Gas had no case: `SATIN-POOL-001` to
`-004`, `-015`, `-021`, `-022`, `SATIN-STATE-004` to `-007`, `-009`, `-010`, and `SATIN-SCHED-001`,
`-002`, `-012`, `-014`. Fifty-seven cases at `bcf260d` (`CURRENT_SPEC`) pin sixteen of them, twenty
of them added for the edges an independent review of the first thirty-seven found unpinned; each
expected value comes from the specification through the model. Every one passes on both
implementations, plain and instrumented.

- **The areas.** The nineteen new pool cases join `gas-pools`, whose scope is the pool page's
  family. `state-gas` (twenty cases) scopes the `SATIN-STATE` family and `schedule` (eighteen
  cases) the `SATIN-SCHED` family. No existing case changes area or pins.
- **Their citations.** A case of these rules sets `pricing` (`Case`, `Run`). Its derivation then
  cites what every other derivation applies without citing: the EIP-8037 profile and its execution
  cap (`SATIN-POOL-001`), the cap on a transaction's total gas Satin does not apply, where a gas
  limit passes it, and the regular gas a charge before the first frame drew staying spent
  (`SATIN-POOL-003`), each of Satin's departures where it is applied, with the frozen profile
  (`SATIN-POOL-004`, `-022`), a returned reservoir joining its caller's (`SATIN-POOL-002`), where
  each state charge is made and what its multiplier scales (`SATIN-STATE-004`, `-005`), the bucket
  SALT maps a key to and one multiplier for every charge and give-back in a bucket
  (`SATIN-STATE-006`, `-010`), the pricing of a deposit and of a system-originated transaction
  (`SATIN-STATE-009`), the forward's and the code deposit's departures from Amsterdam
  (`SATIN-SCHED-001`), and why an account is warm from the transaction's start (`SATIN-SCHED-012`,
  `-014`). Without `pricing` no derivation step changes, so every existing case's file and pins
  stay as they were.
- **The gas pools (19).** A gas limit at the execution cap and one above it. One above EIP-8037's
  `TX_MAX_TOTAL_GAS_LIMIT`, `2^32 − 1`, and one at the block's gas limit, both admitted
  (`SATIN-POOL-003`; one above the block's is `satin/validation/gas-limit-above-block`). A creation
  transaction whose start record and created account the reservoir pays in part: its initcode
  halts, and the part the regular budget paid is consumed, nothing of it returning, or reverts, and
  the whole is given back into the reservoir (`SATIN-POOL-003`, `-015`, `-024`); and a value
  start's record, paid by the regular budget below the cap, consumed when the first frame halts. A
  first frame that spills on a fresh slot and then calls a child that fills and restores one: the
  child's give-back returns as reservoir and joins the caller's, crediting none of the caller's
  spill back to regular gas (`SATIN-POOL-002`, `-012`); and a reservoir share of 99 returned unspent
  through two successful merges and through one (`SATIN-POOL-011`). A first frame's revert after an
  EIP-7702 list applied from the reservoir: the list's charges stay (`SATIN-POOL-002`, `-024`). A
  `CREATE` from a frame with a reservoir whose initcode reverts or halts, and a value call its
  caller cannot fund to an account the state does not hold: the account's state gas, its legacy
  share included, comes back into the reservoir (`SATIN-POOL-015`). A child forwarded one gas
  short of its fresh slot's regular charges with the legacy share, whose reservoir share could pay
  the whole charge, and forwarded exactly that (`SATIN-POOL-008`, `SATIN-STATE-012`). Computation,
  a memory expansion and a run of `JUMPDEST`s, to the last gas of the regular budget, which
  completes with the reservoir untouched, and one gas past it, a halt and no stop
  (`SATIN-POOL-021`). And the transaction's own `keylessDeploy` call whose constructor fills a fresh
  slot before destroying the deploy address: the call's `gasUsed` adds back the table's give-back
  of the account and its one record, not the slot's (`SATIN-KEY-015`, `SATIN-SD-004`).
- **State gas (20).** A `CREATE` at `m = 3` deploying ten bytes, and a value call to an absent
  account at `m = 5`: the account's and the code's state gas scale; the legacy share, the regular
  charges and the history do not (`SATIN-STATE-004`, `-005`). A call without value to an absent
  account, under an incomplete SALT input holding no bucket: no account is added, so no capacity is
  read (`SATIN-STATE-004`). A `SELFDESTRUCT` moving a balance to a beneficiary present as an empty
  leaf at `m = 3`, with and without a slot, a new account, and to one with nonce 1, not
  (`SATIN-STATE-004`, `-011`). Two slots of one contract that `salt-v1` maps to one bucket, both
  filled and one restored; a `CREATE` at `m = 3` whose initcode reverts; a creation whose
  constructor fills a slot at `m = 4`, one gas short of its code deposit's history and exactly
  paying it, the slot's charge going with its rollback and the account's coming back at `m = 3`
  (`SATIN-POOL-015`, `SATIN-SCHED-011`); a write at `m = 4` two frames deep that reverts, and its
  kept control; and a created account destroyed by a call after a second creation deposited code at
  another multiplier, whose table gives its code back at its own (`SATIN-STATE-006`). A
  creation's account at `m = 2` and its constructor's slot at `m = 6` (`SATIN-STATE-010`). A
  bucket listed alone at the minimum capacity, at one below twice it and at twice it
  (`SATIN-STATE-002`). A deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH` that fills two
  slots and restores one, and one that creates an account, both under an incomplete SALT input
  holding no bucket, against a user's deposit whose value call adds an account at `m = 4`
  (`SATIN-STATE-009`).
- **The gas schedule (18).** A `CALL` from a caller holding 1,000 of regular gas: it forwards 980,
  the specification's own example (`SATIN-SCHED-001`). `EXTCODESIZE` of a cold contract and of the
  warm recipient, and `EXTCODEHASH` of the warm sender: two warm reads against one; `EXTCODECOPY` of
  a cold contract twice with zero bytes, the static gas and the access paid all the same, and once
  copying its code (`SATIN-SCHED-002`, `-014`). `BALANCE` of the sender, of the recipient and of an
  account not accessed (`SATIN-SCHED-014`). `EXTCODESIZE` of a precompile; a `CALL` and a
  `STATICCALL` whose first access is to an address an access list names without storage keys, a
  `BALANCE` and a `CALL` of one, a `CALL` of one named with a key, a `CALLCODE` of one named
  without; a `SELFDESTRUCT` to an access-listed beneficiary; and a `CALL` of the block beneficiary
  (`SATIN-SCHED-012`). A `CREATE` that deploys 33 bytes, its code's history priced where Amsterdam
  prices none (`SATIN-SCHED-001`). Creation transactions whose initcode is 96 and 97 bytes, across
  EIP-3860's word step (`SATIN-SCHED-006`).

**D-107. The model's reach grows by three reads and one start, and two steps are reworded.**
Under `pricing` alone:

- `EXTCODESIZE` (`0x3b`), `EXTCODEHASH` (`0x3f`) and `EXTCODECOPY` (`0x3c`), which the model ran
  only for the block beneficiary, run for any account outside a detained frame and with access on:
  the static gas, two warm reads for `EXTCODESIZE` and `EXTCODECOPY` and one for `EXTCODEHASH`, then
  the additional cold account access for an account that is not warm, and for `EXTCODECOPY` its copy
  and memory (`SATIN-SCHED-002`, `-003`). No opcode is added.
- A `CALL` without value to an account without code is a start answered without a frame: a
  success, no return data, nothing kept, the child's regular gas and its reservoir share returned
  (`SATIN-POOL-012`, `SATIN-LIM-013`). It raised `Unmodelled` before, and still does without
  `pricing`.
- A `CALL`'s, `CALLCODE`'s or `STATICCALL`'s target, a `BALANCE`'s, `EXTCODESIZE`'s or
  `EXTCODECOPY`'s account and a `SELFDESTRUCT`'s beneficiary that is warm say why: the sender and
  the recipient (`SATIN-SCHED-014`), a precompile, the beneficiary or an access list's address
  (`SATIN-SCHED-012`), or an earlier access. A `SELFDESTRUCT` that moves a balance says whether its
  beneficiary is new by EIP-161 emptiness (`SATIN-STATE-004`, `-011`).
- A legacy share the frame's regular gas cannot pay, and a code deposit's charge the creation
  cannot pay, say so at the charge (`SATIN-POOL-008`, `SATIN-STATE-012`, `SATIN-SCHED-011`).
- A first frame's revert cites the give-back of its recipient's or created account's state gas
  (`SATIN-POOL-015`) only where step 4 charged one.

The step of a first frame's halt after the reservoir paid part of its start (D-85) wrote its total
as the gas limit less the reservoir the frame received alone; it now writes the reservoir given
back with it, the sum the figure was always computed from. No figure moves, and no case file
stores the step. `TX_MAX_TOTAL_GAS_LIMIT` (`2^32 − 1`, Base Layer) joins the model's constants.

**D-108. What the pricing cases do not pin, and the readings they take.**

- **`SATIN-STATE-007` has no failing case.** A bucket capacity below `MIN_BUCKET_SIZE`, or one the
  node cannot read, is a fault of the node, with no outcome. The format records a fault as an
  outcome (`commit.status: fault`, through `input.faults`), but neither adapter runs injected
  faults: both report an engine's internal error, and a bucket an incomplete input does not hold,
  as `error`, which a consumer never takes for a pass. A case expecting the fault would fail on
  both until an adapter maps the error, which this change does not make. Its valid side is pinned:
  a capacity listed at the minimum is a bucket, priced at `m = 1`. A capacity below the minimum
  that no charge reads is not a case: SALT holds no such bucket, so such an input is no state the
  specification executes on, as D-97 holds of an invalid prestate. The rule stays in the index's
  uncited rules.
- **`SATIN-STATE-006`'s single read is not pinned.** The capacities are fixed inputs and the
  `reads` group lists each served bucket once, so no observation tells one lookup from several of
  the same capacity. The cases pin what a reuse decides: every later charge and give-back in a
  bucket priced at the multiplier of its first, a give-back cancelling its charge exactly. A case
  with one charge in its bucket does not cite the rule.
- **`SATIN-POOL-004` is pinned where a departure is applied.** The frozen profile decides a figure
  only through what it keeps and what it departs from: the cases that show the reservoir share,
  the legacy share and the give-back into the reservoir cite it with `SATIN-POOL-022`. No change
  to EIP-8037 after `dbc6d457cb` that the rule names moves a figure, so no case can show one
  declined.
- **A case of another page's rule in these areas.** The keyless case pins `SATIN-KEY-015` and
  `SATIN-SD-004` by naming them: a `gasUsed` that adds back the table's give-back of the account
  and its record, which a constructor's fresh slot does not enlarge.
- **What stays out.** A `STATICCALL` of a precompile, a system call's outermost frame (block-level),
  a call at the call-depth limit (no transaction reaches it under the 98/100 forward), and
  `DUPN`, `SWAPN`, `EXCHANGE` and `CLZ`, which the model does not run.

From the deposits page, the Oracle and the small system contracts:

**D-109. The deposits page, the Oracle's, MegaLimitControl's and the High-Precision Timestamp's
pages are pinned by cases at `bcf260d`, and the model runs the system contracts' own code where they
reach it (D-63 amended).** Twenty-three rules of these pages and of interception had no case. A
hundred and one cases at `bcf260d` (`CURRENT_SPEC`), forty-six and then fifty-five after a review,
pin sixteen of them, most in pairs one unit apart, sized from the model's own figures (D-57,
D-59). Every expected value comes from the specification through the model, and every case passes
on both implementations. The cases carry the flag `system_pages`, which
gates the model's new reach and its citations, so no earlier case moves.

The first forty-six:

- **Deposits (21, area `deposits`).** The load for the first frame's start (`SATIN-DEP-012` at
  `bcf260d`, D-96), each case with its reads:
  - a deposit of 1 wei to an absent account one gas short of the recipient's new-account state gas
    at step 4 of `SATIN-SCHED-008`, a failed deposit that keeps the recipient's load, and at it;
  - the same gas limit to an account holding a balance and no code, which owes no step-4 charge and
    succeeds, so that only the recipient's state tells the pair apart;
  - a creating deposit one gas short of the created account's state gas, which keeps the load of
    its created address, absent, and at it;
  - a deposit to its own sender one below its intrinsic gas with the body's history, and at it:
    its value moves nothing and makes no record, and its recipient is loaded in its role as sender;
  - a deposit failing validation, and one short of its start record at step 3: no load of its
    recipient;
  - a recipient holding an EIP-7702 delegation, with the regular gas at step 5 one short of the
    warm read, one short of the cold delegate's access and at it: the failed deposits keep the
    recipient's load and load no delegate; and a delegate that is the sender, warm, at the warm
    read exactly.

  A failed deposit's report (`SATIN-DEP-005`, `-006`): one whose contract sends a hint and halts,
  which keeps the hint's bytes as data size and hands the hint to the service with the contract's
  address; one above the execution cap, detained, that halts and returns no withheld gas, unspent
  gas or reservoir; and one from an absent caller, whose created caller carries no state gas and
  counts one unit of state growth. The deposits that are failed deposits whatever they carry
  (`SATIN-DEP-008`): from the live system address, carrying the promotion's source hash from it, and
  carrying the base layer's system-transaction flag. A creating deposit from a sender at
  `MAX_NONCE`, which creates nothing, runs no initcode and leaves the nonce as it was
  (`SATIN-DEP-010`). A user's deposit writing a fresh slot in a bucket of four times the minimum
  capacity, priced at `m = 4` (`SATIN-DEP-002`).
- **The Oracle (8, area `oracle`).** A deposit's `getSlots` of two slots, answered in the order asked
  (`SATIN-ORCL-001`). `setSlot` from a user, whose body writes and is charged before the bytecode's
  check reverts it with `NotSystemAddress()`, and from a Mega System Transaction, whose write stands
  (`SATIN-ORCL-011`). `setSlots` with arrays of different lengths, `InvalidLength(2, 1)`. A hint
  sent by a contract and by the transaction's own call, handed to the service with the contract's
  address and with the sender's (`SATIN-ORCL-007`), the own call's input counted twice. A
  `DELEGATECALL` of `sendHint` and a `multiCall` of a `sendHint` payload, which reach no service and
  count nothing (`SATIN-ORCL-008`).
- **MegaLimitControl and the High-Precision Timestamp (17, new area `system-contracts`).**
  `remainingComputeGas()` as the transaction's own call, below the execution cap, above it and
  detained from its start by a sender that is the block beneficiary (`SATIN-MLC-003`, `-004`); as a
  contract's `CALL` and `STATICCALL`, with no limit set, and after a `TIMESTAMP` with the allowance
  below the caller's own regular gas and above it (`SATIN-MLC-002`); and its bytecode's
  `NotIntercepted()` for a `DELEGATECALL` and for a selector it does not intercept
  (`SATIN-MLC-001`). The timestamp read by a deposit through the Oracle's `getSlot`, its read marked
  so that a later charge past the Oracle's cap is stopped, and refused with
  `VolatileDataAccessDisabled(11)` in a frame whose access is off (`SATIN-HPTS-002`); its `update`
  reverting while another address is the live system address and committing while the timestamp
  contract is (`SATIN-HPTS-001`, `SATIN-ORCL-011`); and its three accessors. The timestamp's runtime
  code is read from the revm-based implementation at its pin and checked against
  `HIGH_PRECISION_TIMESTAMP_CODE_HASH`; no earlier case holds code at its address (D-97).
- **The model (`tools/satin_model/`).**
  - A deposit's charges at steps 3 to 5 of `SATIN-SCHED-008` and its first frame (`deposit_frame` in
    `settlement.py`): the start record, the load of the recipient or the created address at step 4
    and its new or created account's state gas, a delegated recipient's delegate access at step 5,
    each a charge whose failure makes a failed deposit that keeps what it loaded; a creating
    deposit with no endowment, its initcode run and its code deposited; a deposit to its own sender;
    and a creation from a sender at `MAX_NONCE`. D-96's `Unmodelled` edges are derived.
  - A failed deposit that admitted a hint keeps its bytes as data size, with no history.
  - The `reads` group lists the hints handed to the service, each with its topic, its data and the
    address of the frame that sent it. The transaction's own `sendHint` is admitted on its first
    frame's regular gas and counted twice.
  - MegaLimitControl's answer to a `CALL` or `STATICCALL` without value and to the transaction's
    own call, and its bytecode for a `DELEGATECALL`.
  - The system contracts' own code: a `STATICCALL` of the Oracle or the SequencerRegistry, a
    `DELEGATECALL` of the Oracle, an `SLOAD` in a frame below the transaction's own, a call that
    copies its output, `EXTCODESIZE` of any account, and the opcodes their compiled code uses
    besides: `ADDMOD` (`0x08`), `EXP` (`0x0a`), `ADDRESS` (`0x30`), `CALLDATACOPY` (`0x37`) and
    `MCOPY` (`0x5e`). The Oracle's methods, the High-Precision Timestamp's and MegaLimitControl's
    `NotIntercepted()` are derived from that code, and a step names what the method did.
  - An Oracle read in a frame whose volatile-data access is off is refused with
    `VolatileDataAccessDisabled(11)`, asking nothing and marking nothing.

An independent review of these cases listed twenty-three edges they left unpinned, found no wrong
expectation, and showed one shape the model got wrong. Fifty-five more cases at `bcf260d` take the
edges a transaction can show, in the review's order; every one passes on both implementations.

- **The review's High edges (24).** A user's deposit whose sender or recipient is the block
  beneficiary, detained from its start, its compute stopped at the cap where the same deposit with
  neither succeeds; a deposit's own `remainingComputeGas()`, detained and not (`SATIN-DEP-002`,
  `SATIN-MLC-004`). Hints never admitted, and so never size-checked: one past the data-size limit
  from a frame whose access is off and one forwarded no gas; a child's gas of 0 and 1, and a value
  call's stipend, funded and not; sendHint's selector alone, a canonical input with a trailing byte
  and an unpadded one, each counted whole (`SATIN-ORCL-006`, `-009`, `-010`). The Oracle's write
  from code the live system address delegates to, in a user's deposit, and the deposit's own call,
  refused (`SATIN-ORCL-011`). The timestamp updated and then read in one deposit, and `getSlots` of
  one slot twice, each read cold. The Oracle's `getSlot` run by `DELEGATECALL` on another account's
  storage, an ordinary read that marks nothing (`SATIN-ORCL-002`). A `STATICCALL` of `sendHint`,
  from a contract and from a static frame (`SATIN-ORCL-008`). A creation from `MAX_NONCE` carrying
  a value its mint funds (`SATIN-DEP-010`). A deposit's own `sendHint` on a first frame of 0 and 1
  regular gas (`SATIN-ORCL-006`, `SATIN-DEP-006`).
- **The Medium and Low edges (31).** A creating deposit whose initcode reverts, with the created
  address's bucket crowded and with the bucket of the address nonce 0 would derive crowded, its
  reads naming the created address's alone, and a creation priced at `m = 4`. Dispatch by the
  address and the four selector bytes: a trailing byte, a three-byte input, the selector at another
  address, and other code at MegaLimitControl's address (`SATIN-ICPT-001`, `SATIN-MLC-001`). A
  transaction's own value call of MegaLimitControl and of MegaAccessControl, `NonZeroTransfer()` at
  depth 0 (`SATIN-ICPT-003`). MegaLimitControl forwarded 0 and 1 gas, a contract call above the
  execution cap, the allowance across a nested frame, and detention by an applied authority that is
  the beneficiary (`SATIN-MLC-002` to `-004`). `CALLCODE` of `sendHint` and of
  `remainingComputeGas()`. Three hints in order across a reverted child and a failed deposit.
  `multiCall`'s first failing payload and its empty-revert error, `emitLog` refused and standing,
  `setSlots` of one slot twice. A sender the state holds empty under EIP-161 one short of its
  account's state gas at `m = 2`, at it, and with a nonce of 1. A creating deposit one gas short of
  its one byte's code deposit and paying it, and its initcode reverting with data. The timestamp
  read twice. A contract's `DELEGATECALL` and `CALLCODE` of KeylessDeploy with arguments that
  decode, which run the held code (`SATIN-ICPT-006`).
- **The model.** An `SLOAD` in the Oracle's own frame at depth 0, the transaction's own call of the
  Oracle, is an Oracle read: before, the model priced it as an ordinary `SLOAD`, warm after a first
  read of the slot. That changed no figure of the cases committed before (each read its slots
  once), and adds `SATIN-ORCL-002` to `-005` to the rules `satin/oracle/get-slots/in-order` pins,
  whose expectation is unchanged. A deposit is detained from its start as any transaction, and its
  own `remainingComputeGas()` is answered. A hint whose call would start with no regular gas, or
  that a frame with access off sends, is dropped before any size check; a `STATICCALL` of `sendHint`
  is admitted; a `STATICCALL` runs in a static frame; a `CALLCODE` of the Oracle, MegaLimitControl
  or KeylessDeploy, and a `DELEGATECALL` of KeylessDeploy, run the held code. A transaction's own
  value call of an intercepted method is answered `NonZeroTransfer()` and its start record's history
  given back. A creation from `MAX_NONCE` may carry a value its sender funds. A reverted deposit
  reports its reads. A creating deposit's output is the code it deposited.

**D-110. What the deposits and system-contract cases cannot hold.** Seven of the twenty-three rules
stay without a case:

- **`SATIN-DEP-011` and `SATIN-DEP-013`.** Each states that an input lies outside the
  specification: a sender's balance and mint above `MAX_BALANCE`, and a deposit envelope carrying a
  gas price. Nothing a case expects can be derived from either, as for `SATIN-SYSC-005` (D-97).
- **`SATIN-ORCL-012` and `SATIN-ORCL-013`.** What a sequencer persists, and which transactions a
  block may include, are decided over a block and its Mega System Transactions, not by one
  transaction against its pre-state. Their deposit and Mega System Transaction clauses follow from
  `SATIN-ORCL-005`, which the deposits' Oracle reads pin.
- **`SATIN-ICPT-002`.** A call past `CALL_STACK_LIMIT` needs a frame at depth 1,024. A call
  forwards at most `g − ⌊g × 2 / 100⌋` of the `g` its caller holds once the opcode's own charges are
  made (`SATIN-FWD-001`, integer division), which is at most `0.98 × g + 1`; and every call first
  pays at least `WARM_STORAGE_READ_COST`, 100, and the pushes of its operands. So a frame's regular
  gas is at most 0.98 times its caller's, the rounding's one gas being far below the charges, and a
  value call's `CALL_STIPEND` of 2,300 is no way around it, its value-transfer charge of 11,300
  being larger. From the execution cap of 200,000,000 the frame at depth 1,024 holds at most
  `0.98^1024 × 200,000,000`, under one gas, and cannot pay the 100 its own call needs: no
  transaction reaches the gate.
- **`SATIN-ICPT-005`.** As for `SATIN-DET-025` (D-92): MegaAccessControl's and MegaLimitControl's
  answers spend no regular gas, an admitted `sendHint` is no answer, and KeylessDeploy's answer,
  the only one that spends, is made at compute zero, where the allowance is the whole cap.
- **`SATIN-MST-006`.** The source hash the promotion stamps shows in no observation of a
  `state-transition` case: the promoted transaction's receipt is its envelope's, a legacy receipt
  with no deposit fields (`SATIN-MST-005`), and it is system-originated by `SATIN-MST-007`'s first
  clause whether or not the hash is stamped.

Of the review's twenty-three edges, two stay out for their size, and parts of three:

- **A transaction's own hint at the data-size limit, and a body over it.** The own call counts its
  input twice, so its total is `310 + 2L`: the hint reaches the limit only with some 6.5 MB of
  calldata, and a deposit's body over the limit needs 13 MB. Each case would hold more than the
  whole slice holds today, its calldata in hex; the child's hint at the limit and one byte past it
  are cases (D-91). They wait for the owner's word on fixtures of that size.
- **MegaAccessControl's dispatch matrix, `emitLogs`, and the timestamp's reserved slots.**
  MegaLimitControl's matrix, `emitLog` and the timestamp read twice stand for them; the model runs
  MegaAccessControl's answer only for `disableVolatileDataAccess()`.

Of the pinned rules, `SATIN-DEP-010`'s second sentence is not a case: a sender at `MAX_NONCE` that
cannot fund its creation's value is a failed deposit, which must bump the sender's nonce
(`SATIN-DEP-004`), and the text does not say what a bump of `MAX_NONCE` leaves. The model raises
`Unmodelled` for a failed deposit from such a sender.

**D-111. A deposit's reads and the protocol's own interception are read as the implementations
run them.** Two readings the cases take where the text is terse:

- **A failed deposit's SALT reads.** A deposit that fails at step 4 has read the capacity of the
  bucket its recipient's or created address's state gas is priced in, which the charge needs before
  it can fail. `SATIN-WIT-013` exports every capacity the environment served, a failed execution's
  included, so the case reports it among its reads, as it reports the recipient's load.
- **The transaction's own call of `remainingComputeGas()`.** `SATIN-MLC-004` makes `own` the gas the
  transaction's own frame was given. A transaction is detained from its start when its sender, its
  call recipient or an EIP-7702 authority it applies is the block beneficiary (`SATIN-DET-008`);
  `SATIN-MLC-004`'s parenthesis names the sender and the authority only, and for a direct call the
  recipient is MegaLimitControl itself. The allowance at that start is the whole cap, the charges
  before the first frame being no compute, so the answer is `BLOCK_ENV_ACCESS_COMPUTE_GAS` itself
  when the frame holds more; the cases detain by the sender and by an authority.

Both implementations answer every case as the model derives it.

From the specification at `83c0d26`:

**D-112. The specification at `83c0d26` is bundled; a deposit's top-level creation is not checked
against `MAX_INITCODE_SIZE`.** `specs/satin-83c0d26` is the specification's main after one merged
change, its QI-38. The snapshot holds 411 ids, 401 active: `SATIN-SIZE-002`, `-004`, `SATIN-VAL-008`
and `SATIN-DEP-004` are reworded, none is added or retired, and the contract-limits page's constant
table names the exception in its `MAX_INITCODE_SIZE` row ([spec identity](spec-identity.md)). It is
the snapshot new cases cite (`CURRENT_SPEC` in `tools/make_slice.py`); the cases that cite `bcf260d`
name it as `SECOND_FILL_SPEC`. `Run.current` holds for the cases of both (`CURRENT_SPECS`), as it held
for `bcf260d`'s: `83c0d26` moves none of the readings it gates.

- **The new reading of `SATIN-SIZE-004`.** At `bcf260d` the rule said that "a deposit is never
  rejected, and one that fails this check is a failed deposit", and the model made a creating
  deposit whose initcode is over `MAX_INITCODE_SIZE` a failed deposit that creates nothing (D-104).
  At `83c0d26` only a creation transaction other than a deposit is rejected for its initcode, and "a
  deposit's top-level creation MUST NOT be checked against this initcode size limit; its creation
  MUST be executed subject to its other applicable checks and charges".
  - The model now makes no check of a deposit's own initcode (`tools/satin_model/settlement.py`,
    `run_deposit`). Its step says the limit does not apply and the creation runs, and cites
    `SATIN-SIZE-002`, `-004`, `SATIN-VAL-008` and `SATIN-DEP-004`. The creation then runs as the
    deposits page's creating deposits do (`deposit_frame`, D-109): its intrinsic gas pays for the
    initcode as any creation transaction's does, and its start record and created account are
    charged at steps 3 and 4.
  - The exemption is that creation's alone (`SATIN-SIZE-002`). A `CREATE` or `CREATE2` that a
    deposit's initcode runs is checked as any creation opcode is, and a keyless deployment that a
    deposit makes is refused by its own step 5. The model's checks for both are unchanged.
- **A check that applies to deposits.** `SATIN-VAL-008` and `SATIN-DEP-004` now make a failed deposit
  of a check "that applies to deposits", and keep the base layer's deposit exemptions in force. The
  model makes a deposit fail validation for three checks, and a rule names each as a deposit's: the
  base layer's system-transaction flag and a caller that is the live system address
  (`SATIN-DEP-008`, `SATIN-MST-003`), and a gas limit below its intrinsic regular gas and its body's
  history (`SATIN-DEP-001`). No reading of them moves.
- **No existing case moves.** Each rule reworded between `bcf260d` and `83c0d26` was held against the
  cases that pin it and the cases whose derivation applies it, through the model. Every expected
  value still holds, and every case keeps its snapshot.
  - `SATIN-DEP-004` is pinned by 43 cases and applied by 114, and `SATIN-VAL-008` is pinned by 5
    and applied by 35. Each of their failed deposits fails one of the three checks above, a charge
    before its first frame, or its own frame, none of which the change touches.
  - `SATIN-SIZE-002` is pinned by eight cases and applied by 13: a creation transaction other than
    a deposit, a creation opcode in a child, `CREATE2` and a keyless deployment, each at or over the
    limit. `SATIN-SIZE-004` is pinned and applied by four of them, the creation transaction's and the
    keyless deployment's. Each is checked under the new text as under the old.
  - Eleven cases make a creating deposit, none with more than 39 bytes of initcode, so none takes
    the new step. The only case that takes it is the deposit D-105 held, which now enters (D-114).

From the move of the evm2-based pin to `62f2964a`:

**D-113. The evm2-based pin moves to `62f2964a`; the adapter and its lockfile stay as they were.**
Implementation (b) moved from `ccbdb23e` to `62f2964a`, its integration head. Its evm2 fork stays at
`c0a91cbb`, the fork `next/evm2-fork.env` still pins. Between the two revisions the implementation:

- refuses a call at its target's EIP-7702 delegate after the call's steps
  (`SATIN-MAC-004`, `-007`). The call pays its static cost, its memory expansion and its target's
  access, which is a cold surcharge, held to the spendable part, only when the target was not warm.
  Before, a call whose target delegated to the block beneficiary was refused before it charged
  anything. The change is in `next/mega-evm2/src/` (`lib.rs`, `ledger.rs`, `satin_ext.rs`);
- tests the refusal, admits it in its differential harness as a signed-off class, and drops the
  engine tests and keyless scenarios that Mega EEST's cases duplicate.

No API the adapter uses moved. It builds `--locked` with no change to its source, its manifest or
its lockfile. The implementation's lockfile, its manifests and its fork pin are unchanged between
the two revisions. Every gating case, the 928 of the slice and the two of D-114, passes on both
adapters, plain and instrumented, and the negative case fails as it must.

**D-114. The two cases D-105 held enter the slice at `83c0d26`, and the hold is closed.** Both are
gating and cite `83c0d26`, the snapshot new cases cite. Every rule they pin is active there. The
slice holds 930 cases.

- **`satin/contract-limits/deposit/initcode-over-limit`.** Its input is the held case's: a deposit
  minting 1 ether that creates with `MAX_INITCODE_SIZE + 1` zero bytes of initcode, with a gas limit
  of 150,000,000. At `bcf260d` the model derived a failed deposit that used its whole gas limit. At
  `83c0d26` it derives the executed creation (D-112): the deposit is admitted, its initcode stops at
  once, and it creates an account without code at `0x0c243ebe6a031753dc0dd850acf422844a3efb76`. Its
  regular ledger is 4,283,846, its state ledger 183,600 and its history ledger 92,305,576. Its gas
  used is 96,773,022 and its block gas the floor, 67,132,928. The receipt has status 1, deposit
  nonce 3 and receipt version 1. Data size is 1,048,927, with one KV update and one unit of state
  growth. Every observation group matches both implementations' fills of the held input exactly.
  Its intent now states the exemption, and it carries `system_pages`, so the model derives its
  creation as the deposits page's creating deposits do. It pins `SATIN-SIZE-002` and `-004`.
- **`satin/precompiles/delegated-address/beneficiary-delegate-access-off`.** It derives exactly as
  held: the same input, expected value and pinned rule (`SATIN-PCMP-008`). Its block gas is 18,155
  and its gas used 45,435, the call refused at its delegate's load having paid its static cost.
  Implementation (a), at `1a981f4b`, already matched it. Implementation (b) at `ccbdb23e` charged 100
  less; at `62f2964a` it matches the case, plain and instrumented (D-113).

From a call refused at its target's EIP-7702 delegate:

**D-115. Thirty-six cases pin the refusal at its target's delegate, at `83c0d26`.** Specification
changes #8 and #10 moved a call whose target delegates to the block beneficiary, in a frame whose
volatile-data access is off, from a refusal before any charge to a refusal at the delegate's load,
settled on the call's static cost, its memory expansion and its target's access (`SATIN-MAC-003`,
`-004`, `-007`). Both implementations implement it at their pins, (a) at `1a981f4b` and (b) at
`62f2964a` (D-113), and every case below gates on both, plain and instrumented. Each cites
`83c0d26` and is defined by `delegate_refusal_cases` in `tools/make_slice.py`. The transaction's own
frame switches its access off and calls a frame, `REFUSING`, forwarding what leaves its call the
regular gas the case names; under gas detention it first reads `TIMESTAMP` and burns compute so that
the limit leaves `REFUSING` the spendable part the case names.

- **`satin/access-control/delegate-refusal/`, 24 cases.**
  - The control: a value `CALL` of the beneficiary itself with 1 MiB of input from 50 of regular
    gas, and a `DELEGATECALL` of it from 10, each refused for nothing.
  - A cold delegator at 2,999 (its load skipped, not read), 3,000 (loaded, then halted by the
    delegation guard), 3,099 (one short of the guard) and 3,100 (refused, paying 3,000, the caller's
    `BALANCE` of it after the frame's revert paying the cold access), each with the reads; the same
    3,100 by `CALL`, `CALLCODE` and `DELEGATECALL` without value, and followed by a memory expansion
    past the cap, which completes, a refused read marking nothing.
  - A delegator the access list warms at 199 and 200 (refused, paying 100, still warm for the
    caller).
  - A value `CALL` from a frame without balance at 14,400, the guard exactly (refused, the value
    transfer given back), and at 14,399 (halted after the target's load); a value `CALLCODE` at
    15,000.
  - The memory expansion: an output range of 1,024 bytes (98, kept), the same range within memory
    the frame holds (nothing), ranges partly past it (the growth, 112, not the frame's whole memory
    cost), input and output ranges together with value and a cold target, and a 1 MiB input that
    halts before the target's load.
  - A refusal after the frame gave a fresh slot's state gas back into its reservoir, which the
    settlement leaves as it found it; and the warmth the call pays for: a warming the frame took
    itself, rolled back by its revert; one from before the frame, which stays; and one a reverted
    sibling took, which does not count.
- **`satin/detention/delegate-refusal/`, 10 cases.** `REFUSING` holds 5,200 at a cold
  `STATICCALL`: spendable 99 (stopped at the static cost, not read), 200 and 2,999 (the cold
  surcharge, charged last, is the crossing: `MegaLimitExceeded(2, limit)`, 5,100 handed back, the
  target read) and 3,000 (refused, paying 3,000); a warm target at 100 (refused); with an output
  range whose memory costs 98, spendable 197 (stopped at the memory, not read) and 300 (stopped at
  the surcharge, the memory kept, 5,002 handed back); a value `CALL` holding 20,000 at 11,400
  (refused, the restored value transfer leaving room for the surcharge, 17,000 handed back) and
  11,399 (stopped at the value transfer, not read); and a `STATICCALL` with 0x320000 bytes of input
  forwarded 40,000,000 under the protocol's cap, stopped at its memory with 39,999,886 handed back,
  the frame's gas at the opcode less its static cost.
- **`satin/precompiles/delegated-address/`, 2 cases.** The identity precompile's address delegating
  to the beneficiary, at 199 (halted by the guard) and 200 (refused, paying 100): neither reaches
  dispatch.

Together they pin `SATIN-MAC-003`, `-004` and `-007` (the last for the first time), `SATIN-OUT-008`,
`SATIN-STOP-020`, `SATIN-WIT-012`, `SATIN-DET-018` and `SATIN-PCMP-008` at the refusal's edges,
and `SATIN-WIT-002` and `SATIN-POOL-014` where their intents name them. The
conformance figures proposed with the specification change were derived again by the model: a direct
call refused for nothing from 50; a cold delegator halting unread at 2,999, halting read at 3,050,
refused at 3,100 with 100 handed back; a warm one halting at 199 and refused at 200; a value `CALL`
at 15,000 with 12,000 handed back; a memory crossing that reads nothing; and spendable 200 of 5,200
stopped at the surcharge with 5,100 handed back. None differs. The memory crossing's "whole less
100" is the frame's gas at the opcode: from a 40,000,000 forward the frame's pushes first take 14.
An independent review then found ten edges unpinned and three citation errors; 31 more cases and
the corrections follow from it (D-117). The slice holds 997 cases.

**D-116. How the model reads the refusal.** The model gained one path, in `interpreter.py`, for the
four call opcodes; no opcode was added and no existing case moved. The readings it takes:

- **The direct refusal.** A call opcode whose target operand is the beneficiary, in a frame whose
  access is off, is refused once its operands are on the stack, before its static cost, a memory
  expansion or a value transfer, so a frame holding less than any of them is refused and does not
  run out of gas (`SATIN-MAC-003`'s second item, `-004`). The model refused only `BALANCE` there
  before.
- **Which calls take the refusal path.** One whose target operand is not the beneficiary and whose
  target, as the state stands when the call reaches it, holds an EIP-7702 indicator naming it. A
  precompile's address holding one takes the same path (`SATIN-PCMP-008`).
- **The steps before the delegate's load.** The static cost, the memory expansion of the input and
  then the output range, and the value-transfer cost of a `CALL` or `CALLCODE` carrying value, each
  a regular charge held to the spendable part. One that fails halts the frame and one that is the
  crossing stops it, the target not loaded (`SATIN-MAC-007`, `SATIN-WIT-004`, `-012`). The
  static-context check of a value `CALL` is not reached: the model runs no call in a static frame.
- **The target's load and the guard.** A target that is not warm is loaded only when the regular
  gas left, both parts counted, covers the cold surcharge, and an out-of-gas halt ends the call
  otherwise. The delegation guard then asks that gas for the surcharge not yet deducted (2,900, or
  nothing for a warm target) plus 100 for the delegate's access, and halts the call short of it,
  the target loaded (`SATIN-MAC-007`, `SATIN-DET-015`).
- **Warmth.** The target is warm when the warm set holds it as it stands at the load: the
  addresses warm from the transaction's start, the access list's among them, and those an earlier
  access warmed that no rollback took back. The precompiles are warm from the start. The call's
  own load does not count. A frame's end restores the warm set to its checkpoint, as every failed
  frame does in the model.
- **The settlement.** At the delegate's load, the frame's regular gas, both parts, and the
  transaction's compute are put back to their values at the opcode. The call is then charged, as
  regular charges and in order, its static cost, its memory expansion and, for a target that was
  not warm, the cold surcharge. The memory expansion is the cost of the words its two ranges reach
  less the cost of the words the frame held at the opcode. So the static cost and the memory count
  as compute once, and the value-transfer cost does not (`SATIN-DET-009`). The reservoir is not
  touched.
- **The crossing.** Only the cold surcharge can be gas detention's crossing at the settlement, and
  the model raises its stop there. It checks that the settlement charged exactly the target's
  access and the memory, which the guard guarantees, and raises `Unmodelled` otherwise
  (`SATIN-MAC-004`, `-007`, `SATIN-DET-018`).
- **The ending.** The frame reverts with `VolatileDataAccessDisabled(10)`, or is stopped with
  `MegaLimitExceeded(2, limit)` at the crossing (`SATIN-OUT-008`, `SATIN-STOP-020`). The refusal marks
  nothing, and the target's completed read stays in the reads (`SATIN-WIT-012`).

- **The error's encoding.** The revert data is `VolatileDataAccessDisabled`'s selector and access
  type 10, ABI-encoded, which the step cites (`SATIN-MAC-005`).
- **Warmth an authorization gave.** A target the transaction's EIP-7702 list applied, or one an entry
  skipped after loading it, is warm from the list's application (`SATIN-AUTH-014`). The refusal
  path names that warmth.
- **A value `CALL` in a static frame.** In a frame a `STATICCALL` started whose access is off, a value
  `CALL` of the beneficiary is refused before any charge. One of any other account pays its static
  cost and then halts at EIP-214's static-context check, before its memory, its value transfer and
  its target's load (`SATIN-MAC-007`'s first item). The model still runs no other call in a static
  frame.
- **What the cases around the refusal need.**
  - A call's output copied into its caller's memory is modelled in the cases citing `bcf260d` and
    `83c0d26`. Before, only the cases of the system pages modelled it.
  - A `CALL` of an account delegating to an ordinary account, neither a precompile, a system
    contract nor the beneficiary, is modelled outside gas detention: the delegate's access is one of
    the opcode's charges, the one hop alone is resolved, and the delegate's code runs as it is. Under
    detention the base layer's single charge for both accesses is not modelled, and the model raises
    `Unmodelled`.
  - The byte 0xEF, which Osaka leaves undefined, halts its frame.

The existing case that took the refusal, `satin/precompiles/delegated-address/beneficiary-delegate-access-off`
(D-114), now derives through this path. Its file, its pins and its digest are unchanged.

**D-117. A review's edges, the inherited path's cold load, and what stays without a case.** An
independent review of D-115's cases found no wrong expected value, ten unpinned edges and three
citation errors. Thirty-one cases fill nine of the ten edges, each at the boundary the review
named. Every figure comes from the model, and the review's figures agree with it. Every new case
gates on both implementations, plain and instrumented.

- **The edges.**
  1. **A value `CALL` in a frame a `STATICCALL` started.** With 100 at the call it halts at its
     static-context check, its target not read (`static-frame-value-call-halts`). One of the
     beneficiary itself, from 50, is refused for nothing. The review's companion at 99 halts at the
     static cost instead. Both halts consume the frame's gas and read nothing, so no observation
     tells them apart, and it is not a case.
  2. **The whole regular gas at the load and the guard, under detention.** With the spendable part
     held at the static cost, 100, a cold target at a whole 2,999 (halted, not read), 3,000 and
     3,099 (halted at the guard, read) and 3,100 (refused, the surcharge the crossing, 3,000 handed
     back), and a warm one at 199 and 200 (`whole-gas-*`, `warm-whole-gas-*`).
  3. **Above the execution cap**, where the frame holds a reservoir share. The give-back case again,
     with the pools observed, and a stop at the cold surcharge returning its 5,100 and its share
     untouched.
  4. **The warmth an authorization gives the target** (`SATIN-AUTH-014`): an authority the list
     applies, one whose entry's nonce does not match (loaded and warmed, then skipped), each
     refused for 100 at 200; and one whose entry its chain-id gate skips, left cold and not read.
  5. **The inherited path's cold load,** below.
  6. **Memory edges.** Empty ranges at the offset 2^256 − 1 grow nothing, so the call is refused for
     100. An output range of 2 bytes at offset 31 grows two words, 6, so the call is refused for
     106 at 206 and halts at 205.
  7. **A requested forward of 2^256 − 1** changes nothing before the refusal: cold, warm, a value
     call and a precompile's address.
  8. **The precompile's address with memory:** input `(0, 64)` and output `(64, 64)`, four words, 12.
     The call is refused for 112 at 212 and halts at the guard at 211.
  9. **The one hop.** A delegator of an ordinary account is not refused: it pays both accounts'
     access, 6,000, and its delegate's code runs, with access off and on. A delegate whose own code is
     an indicator naming the beneficiary is not followed: its code runs as it is, and its first byte,
     0xEF, halts the frame.
  10. **The error's identity at the exact boundaries.** `surcharge-paid` and the detained
      `warm-target-refused` leave their caller no allowance. Instead of ending with `STOP`, the
      caller now calls with a 68-byte output range over memory it already holds, the size pushed
      beforehand. It returns that range with the call's status as the offset, which costs nothing.
      So the observation shows `VolatileDataAccessDisabled(10)`, followed by the buffer's zeros, and
      not `MegaLimitExceeded`. Gap 2's cases end the same way.
- **The citation errors.**
  - A refusal at the delegate now cites `SATIN-MAC-005` where it encodes the error.
  - The two exact-boundary cases above observe the error they pin.
  - Under D-76's filter a case pins a rule its area does not scope only when its intent names it.
    The intents now name `SATIN-MAC-007` and `SATIN-WIT-002` where a detained case decides the
    whole-gas load and the failed frame's kept read, `SATIN-WIT-004` where a case's target is not
    loaded, and `SATIN-SCHED-003` where a case's figure decides the warm read, the cold surcharge or
    the value transfer.
  - `SATIN-MAC-005` stays unpinned by the detention cases whose intent does not name it, and
    `SATIN-WIT-004` by the `BALANCE` twin whose load is skipped. That twin's reads note is shared
    with an existing reads case, which would change.
- **The CALL refusals' caller probes.** `CALL`, `CALLCODE` and `DELEGATECALL` at 3,100 are now each
  followed by the caller's `BALANCE` of the delegator, which pays the cold access. Two more cases
  probe the caller after the halts at 2,999 and 3,000.
- **The inherited path's cold load.** The model charged a cold account's surcharge before it loaded
  the account, so a crossing at that charge left the account out of the reads. `SATIN-WIT-012`
  skips a cold load only when the whole regular gas cannot pay its surcharge.
  - The model now loads the account first whenever the whole regular gas covers the surcharge. This
    covers `BALANCE` and the `CALL`, `CALLCODE`, `STATICCALL` and `DELEGATECALL` of an account
    without a beneficiary delegate.
  - The change is a load's order alone, and no existing case's file moves. In
    `satin/detention/balance-static-paid`, the one existing case that crosses there, the account is
    loaded and not observed: it carries no reads group.
  - `satin/detention/cold-load-crossing/` holds its current-specification twin with the reads, at a
    whole 5,000 (loaded, then the crossing). It also holds the companions at 2,999 (halted, not
    loaded) and 3,000 (loaded, then the crossing), and a `CALL` with access off whose target
    surcharge crosses with the target loaded.
  - An `SLOAD` in a detained frame is not modelled, so it has no such crossing.
- **What stays without a case.**
  - **A failed read of the target.** `SATIN-MAC-007` makes the target's load a required read whose
    failure has no outcome (`SATIN-VAL-010`). A state-transition case's pre-state is complete, so no
    case can inject that failure.
  - **The block's witness.** The reads group holds what the transaction loads. The witness a block
    carries, and its replay, belong to the stateless-block profile, which no consumer runs yet.
  - **A detention cap other than the protocol's.** Both implementations' tests build stacks of tens
    of levels under a cap they configure. The cases use the protocol's cap (D-67), and one level's
    crossing stands for the tail.

**D-118. Warmth after rollback and the reads of a refused call.** In
`satin/access-control/delegate-refusal/warmth-a-revert-took-back`, the parent probes the target with
`BALANCE` after both child frames have reverted. The original refusal data still returns, and the
parent's probe pays the cold access (`SATIN-MAC-007`, `SATIN-SCHED-003`). Separate cases observe the
read at the refusal. The cold and access-list-warm `max-forward-*-target-refused` cases observe
`STATICCALL`, and the cold `*-cold-target-refusal-reads` cases observe `CALL`, `CALLCODE` and
`DELEGATECALL`. Each gets its only read of the target from the refused call, so a missing entry in
`reads.accounts` fails the case (`SATIN-WIT-002`, `SATIN-WIT-012`). The earlier price probes still
cover the parent's `BALANCE`.

**D-119. A refused call's value-transfer charge and target read.** The value `CALL` at its
delegation guard and the value `CALL` and `CALLCODE` with the same larger budget observe the target
read. They pay the value-transfer charge before the target load and get it back once the delegate
is refused. The regular gas ledger measures the retained static and cold-access charges and the
return data identifies the refusal. Together with the witness entries, these observations pin
`SATIN-MAC-007`, `SATIN-SCHED-003`, `SATIN-WIT-002` and `SATIN-WIT-012`.

**D-120. Pool settlement on successful keyless deployment.** `satin/keyless/deploy/with-reservoir`
observes the first frame's two pools at entry and exit. The creation gives back its unused regular
gas and reservoir to the corresponding pools (`SATIN-POOL-012`). Its ABI `gasUsed` nets what the
creation received and returned across both pools (`SATIN-KEY-015`). The failure settlement of
`SATIN-POOL-014` has its own frame rollback cases.

**D-121. Reads of a contract's unintercepted keyless call.** In
`satin/keyless/contract-call/no-value`, the parent's storage still records the length and hash of
`NotIntercepted()` (`SATIN-KEY-003`). The reads group observes the KeylessDeploy account and code,
and the absence of reads of the signer and potential deploy address. Each would be an extra
`reads.accounts` entry, even if the call returned the same error (`SATIN-WIT-002`).

**D-122. Keyless checks that compete.** An empty signer one gas short of step 10's charge halts
even when its deploy address holds code. The original unoccupied case is the control. The occupied
case observes the signer's read and the absence of the later deploy-address read (`SATIN-KEY-005`,
`SATIN-KEY-007`, `SATIN-WIT-012`). The successively later refusal pairs at steps 6 and 12, 8 and 12,
8 and 13, 9 and 12, and 9 and 13 all make both predicates true. The returned custom error pins
which check comes first (`SATIN-KEY-006`), as the existing occupied-and-unfunded case does for
steps 12 and 13.

**D-123. Keyless decoder boundaries and the funded forward.** A selector without an argument head
runs the held bytecode. The empty revert data and regular ledger show that there was no
interception overhead (`SATIN-ICPT-006`). A valid ABI bytes argument carrying a truncated RLP list
is dispatched and then refused with `MalformedEncoding()` at step 3. A funded signer with a forward
one below its signed gas limit after step 14 is refused at step 15. The encoded limits and the
regular ledger distinguish that from an earlier refusal (`SATIN-KEY-005`).

**D-124. An empty deposit caller with zero mint.** A deposit with no mint or value succeeds from
an empty account leaf, charging that caller's new-account state gas once and reporting one unit
of state growth (`SATIN-DEP-003`, `SATIN-STATE-011`). The successful minted and the failed deposit
cases exercise their own boundaries.

**D-125. Scaled charges through refusal and rollback.** A refused value call gives back the
scaled new-account charge (`SATIN-POOL-015`). A first-frame revert gives back a scaled fresh-slot
charge and the scaled beneficiary charge of a successful child that destroys a pre-existing
contract (`SATIN-POOL-014`, `SATIN-SD-012`). The ledger retains exactly the state charges left
standing by each transaction. An applied authorization from a crowded bucket keeps its new-account
and indicator charges after that first frame reverts (`SATIN-STATE-001`, `SATIN-AUTH-016`).

**D-126. Effective nonces and the deepest share.** Two entries for one absent authority both
pass the admission gates. A repeated nonce is skipped after the first entry advances the effective
nonce. Sequential nonces both apply, keeping the same single new-account and indicator charges,
one record and one unit of growth (`SATIN-AUTH-004`, `SATIN-AUTH-008`). The third-level state-growth
budget has both edges observed. The exact share keeps its writes and a further write returns a
child stop to the first frame (`SATIN-LIM-003`).

**D-127. Zero-balance destruction and stores after a mark.** A pre-existing contract with no
balance destroys itself to an absent beneficiary in a crowded bucket. It owes no beneficiary state
gas and creates no leaf (`SATIN-SD-018`). Below the cost of an ordinary fresh store, a marked
contract stores a value and reads it back (`SATIN-SD-013`). The parent returns the child's success
flag and bytes. The unmarked control returns failure and no child bytes, and the slot stays zero.

**D-128. Transfer records at the absent-recipient boundary.** A top-level zero-value transaction
to an absent recipient succeeds without creating the account, emitting a transfer log or making a
recipient record (`SATIN-ACCT-005`). When a contract passes all the value it just received to a
previously absent recipient, the middle contract's balance returns to its starting value. The
successful start takes back its record and its record history. The first sender's and final
recipient's records and both logs stand, with the new recipient the only rise (`SATIN-ACCT-004`,
`SATIN-ACCT-014`, `SATIN-HIST-009`).

**D-129. Keyless bytecode and the first signer nonce.** The four call opcodes reach the real
KeylessDeploy bytecode below the first frame. Each parent returns the child's failure flag and
`NotIntercepted()` bytes, and the gas ledger checks that the deployment overhead was never charged
(`SATIN-KEY-003`, `SATIN-ICPT-006`). Calls of replacement bytecode remain separate controls. The
nonce-zero signer with ordinary code and insufficient funds still receives `SignerHasCode()`
(`SATIN-KEY-005`, `SATIN-KEY-006`).

**D-130. Entry checks and charges.** A two-entry authorization list walks both absent authorities
in simulation even if applying the first would exhaust regular gas before the first frame
(`SATIN-AUTH-005`). The six top-level MegaAccessControl query calls isolate the selector boundary
at depth zero (`SATIN-ICPT-001`). Two promoted `setSlots` transactions share one slot write. Only
the one from an absent system address adds a caller charge and a unit of state growth, and it adds
no write record for the caller (`SATIN-DEP-003`, `SATIN-ACCT-008`).

**D-131. History at its allowance and deposit boundaries.** A word `LOG3` consumes the entire
history allowance with either a stipend alone or an additional regular forward. In the two-log
case the child can pay both regular charges from the stipend and the forward. The second log's
history exhausts its gas, so both logs and the failed start are taken back (`SATIN-HIST-018` to
`SATIN-HIST-020`, `SATIN-HIST-022`). A user's deposit independently prices seven calldata bytes,
four write records, one word `LOG0` and one word of deposited code with the transaction body. The
transfer and the creator's nonce write share an account record (`SATIN-HIST-002`, `SATIN-HIST-016`).

**D-132. Records across account changes and child failures.** Separate recipients add separate
records and growth. Repeated calls to the same new recipient add only one record for either
endpoint. A value creation followed by a transfer shares its creator record. A value call to
`INVALID` discards its start's writes and logs, leaving a zero-request value call to record the
sender and a different recipient (`SATIN-ACCT-004`, `SATIN-ACCT-006`, `SATIN-ACCT-011`). Code
delegated by the transaction's sender can fund an absent account without recording the sender.
An absent authorization authority and a distinct value recipient each count their own state
growth. If the authority installs a delegation at the value recipient, its account has one
record and one rise. A successful delegate can take back its parent's fresh-slot write. The same
write stands when the delegate restores the slot and then halts.

**D-133. Execution writes at fee addresses.** Independent calls and destructions isolate
execution's writes to each fee address. A write to a fee address other than the sender is an
ordinary record. A write to the sender is part of the transaction body even when the sender is
also the beneficiary (`SATIN-ACCT-008`, `SATIN-ACCT-010`).

**D-134. Admitted hints through transaction settlement.** Compare the service input and data
size after both a non-value hint with a regular forward and a value hint on a stipend, followed
by a first-frame revert. A successful caller sends two distinct hints and the observation compares
them in the order the service received them (`SATIN-ORCL-006`, `SATIN-ORCL-009`).

**D-135. Exact return and empty-initcode refusal.** A contract initially at zero balance returns
the value it received to its sender. Both records and their history are taken back. The
transaction's calldata and both transfer logs still count (`SATIN-ACCT-006`, `SATIN-HIST-009`).
A nonce-zero creation caller attempts an unfunded endowment with empty initcode. Its return word
is zero and its nonce and records stay as they were (`SATIN-ACCT-005`, `SATIN-SIZE-005`).

**D-136. Returned state for the accounting and dispatch cases.** The exact-return case requires
both participant entries and their restored balances. The empty-initcode refusal requires the
untouched creator entry and its original nonce. These cases and the new dispatch, log, hint and
accounting scenarios observe the unfiltered keys and values through `group:returned-state`
(`SATIN-WIT-005`, `SATIN-WIT-008`).

**D-150. Observe the transaction state returned for commitment.** The optional
`group:returned-state` checks completed account and slot loads in the unfiltered execution
result (`SATIN-WIT-005`, `SATIN-WIT-008`). Each adapter is compared independently to the
model. A null expectation names a forbidden key, and the comparator rejects all additional
keys. Account metadata and current slot values are read before touch or change filtering.
The model's settled state supplies the expected values, including the pre-state value of
any entry the transaction leaves unchanged. A required key can carry a partial account
expectation or express presence alone. The model asserts the keys of an account deleted
at settlement and leaves its temporary values unspecified (`SATIN-SD-015`).

**D-151. Track the source of a load.** The model records journal keys at the logical load
site and retains them across frame rollback. L1 fee and footprint reads are outside the
journal (`SATIN-WIT-011`) and enter the witness through block-level reporting. A journal
load of the same key still belongs to the returned state. A slot loaded in the journal is
distinct from a witness slot, which `SATIN-WIT-006` excludes for an account absent before
the block.

**D-152. Use the existing inputs that isolate returned-state obligations.** The refusal
cases make no later probe of the target. A memory crossing and an unpaid cold balance read
test skipped loads. The keyless inner call forbids both derived keys. The value-bearing
LimitControl refusal and unfunded Oracle hint check the zero balances in the returned state.
Existing cases keep their schema envelope and gain the capability requirement with the new
observation.

**D-153. Observe both pools around keyless creations.** Keep the earlier inputs and run the
new deployment shapes below and above the execution cap. A successful first frame can report
its pools after an inner revert, halt or stop. The low-tier step 15 refusal checks its error,
spent regular gas and returned signer without requesting the failed frame's pools
(`SATIN-KEY-004`, `SATIN-KEY-005`, `SATIN-POOL-008`, `SATIN-POOL-014`).

**D-154. Separate the two leaf charges and the code deposit.** A balance-only deploy address
keeps its balance without a created-leaf charge. Compare it with an empty address for the same
runtime. Vary the signer and deploy-address buckets independently. Both leaf charges use their
own multiplier, but the ABI gasUsed sees only the creation's deposit. The legacy shares are
fixed (`SATIN-KEY-008`, `SATIN-KEY-015`, `SATIN-STATE-001`, `SATIN-STATE-012`).

**D-155. Observe the whole signer after settlement.** Compare a pre-existing delegation with
one installed by the transaction's authorization. In each tier a nonce-one signer restores its
bump, including after a creation that reverts or stops. Funded nonce-zero comparisons keep
their nonce records. With carried value the balance change keeps the record even when the bump
is restored. Use both exact and surplus balances to observe the retained signer amount and the
endowment (`SATIN-KEY-005`, `SATIN-KEY-013`, `SATIN-STATE-011`).

**D-156. Distinguish constructor spending and refund.** A write followed by a clear earns a
transaction refund. The keyless ABI reports the constructor's spend before that refund and the
receipt deducts it. A three-byte revert, a revert after a storage write, and a bare empty revert
remain separate. Each rollback returns the created account's charge, while leaving the nonce-zero
signer's leaf and one record (`SATIN-KEY-014`, `SATIN-KEY-015`, `SATIN-POOL-015`).

**D-157. Observe three reasons a creation halts.** A nonce-only target passes step 12 and then
collides before initcode. An undefined opcode halts in initcode. A constructor that returns
0xef-prefixed code halts at deposit under EIP-3541. For the collision and undefined opcode,
check both an override equal to the signed limit and a larger override. The ABI and regular
ledger show the actual forward was spent (`SATIN-KEY-008`, `SATIN-KEY-011`, `SATIN-KEY-014`,
`SATIN-OUT-007`).

**D-158. Distinguish an empty deposit from empty initcode.** Zero-byte initcode and an explicit
empty RETURN have different constructor gas. Both refuse the empty deposit and restore the
create effects. A separate constructor emits a nonempty log and writes a slot before the refusal.
An empty creation made by the constructor itself succeeds and leaves a nonce-one account with
empty code (`SATIN-KEY-009`, `SATIN-POOL-015`).

**D-159. Observe nested dispatch and the constructor environment.** The nested contract call
stores its success bit, return length and error selector. The inner signer and deploy address
are forbidden returned keys. A separate constructor stores its initial GAS, ORIGIN, GASPRICE
and CALLER to distinguish the whole forward, the outer transaction's environment and the signer
(`SATIN-KEY-003`, `SATIN-KEY-011`, `SATIN-WIT-008`).

**D-160. Check the typed operands of the pool return formula.** The gas used in the full
returned-to-sender formula belongs to the current case's ledger. Confirm the transaction gas
limit and the returned amount and check their subtraction before allowing either output to
coincide with a stale value from another case. Include moved returned amounts in the global
scan, so an old return fails even if no ledger or receipt held that number.
