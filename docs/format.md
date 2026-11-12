# The fixture format: `mega-execution-fixture` 1.1

A fixture is one filled case: a concrete input, the spec it runs under, the observations a
conforming implementation must produce, the rules those observations cover, and non-normative
provenance. The JSON Schemas under [`schema/`](../schema) are the normative shape; this page states
the meaning. [canonical-json.md](canonical-json.md) states the encoding and the error codes.

The format reuses Ethereum execution-spec-tests vocabulary for state and transactions, but it is
not an EEST fixture and unmodified EEST consumers do not accept it.

## Envelope

| Member | Meaning |
| --- | --- |
| `format` | Always `mega-execution-fixture` |
| `schemaVersion` | `1.<minor>`. A reader of 1.0 reads every 1.x file whose features it knows: a minor version adds constructs inside `input` and `expected` only behind a new `feature:` or `group:` requirement, so an older reader stops at `unknown-requirement` instead of misreading; a new profile stops it at `unknown-profile`. A new envelope member is a major change. A different major is rejected. 1.1 adds the limit stop's requirements (`group:limit-stop`, `group:limit-diagnostics`, below); a 1.0 file means what it meant |
| `caseId` | The logical name ([case-identity.md](case-identity.md)) |
| `specRef` | `{name, descriptor}`: the spec name and the SHA-256 of its bundled descriptor ([spec-identity.md](spec-identity.md)). Never an unqualified "latest" |
| `profile` | One of `state-transition`, `transaction-validation`, `block-import`, `block-build`, `stateless-block` ([profiles.md](profiles.md)) |
| `requires` | Sorted set of every observation group the expected result carries and every input feature the case uses ([Requirements](#requirements)) |
| `rules` | Sorted set of rule citations the case covers: exactly the union of its assertions' rules |
| `assertions` | `{path, rules}`, strictly ordered by path (one assertion per path): a JSON Pointer into `expected` and the sorted rule citations whose distinguishing observation is the value there ([rule-mapping.md](rule-mapping.md)) |
| `input` | The profile's input |
| `expected` | The profile's expected observations |
| `provenance` | Non-normative and open: `status` (`example`, `candidate`, `approved`, `superseded`) and anything else (authoring intent, generator, seeds, aliases, review record, observations). Excluded from the semantic digest, bound by the file digest |

Unknown members are errors everywhere except inside `provenance`.

## Requirements

`requires` is a capability header. A consumer reads it first and reports `unsupported` for any
entry it lacks, without running the case and without counting it as a pass. The reader derives the
same set from the case's content and rejects the case when the two differ
(`requirement-mismatch`), so a filler or reader that drops a group is caught.

Observation groups:

| Group | Where it lives |
| --- | --- |
| `group:outcome` | `outcome` of each transaction |
| `group:state` | `state` (a state diff) of the case, and of each valid block |
| `group:receipts` | `receipt` of each transaction |
| `group:gas-pools` | `gasPools` |
| `group:gas-ledgers` | `gasLedgers` |
| `group:resources` | `resources` |
| `group:limit` | `limit` |
| `group:limit-stop` | a stop in `limit` (schema 1.1): its `dimension`, `limit` and `returnData` |
| `group:limit-diagnostics` | a stop's diagnostic members in `limit` (schema 1.1): `scope`, `callPath`, `operation`, `phase`, `operationCommitted`, `enclosingCommitted` |
| `group:detention` | `detention` |
| `group:reads` | `reads` |
| `group:checkpoints` | `checkpoints` (state-transition) |
| `group:validation` | `validation` (transaction-validation) |
| `group:blocks` | the per-block results, counters, commitments and head of block profiles |
| `group:decisions` | the decisions and committed order of block-build |
| `group:witness` | the witness verdict of stateless-block |

Each profile has mandatory groups, always listed, and optional groups, listed exactly when carried
([profiles.md](profiles.md)). In block profiles an optional per-transaction group is carried by
every transaction result or by none.

Features (input constructs a consumer must support):

| Feature | Used when |
| --- | --- |
| `feature:deposit` | any transaction bytes of the input start with type `0x7e`: the transaction (state-transition), a candidate (block-build), the raw bytes (transaction-validation), or a transaction of a `fields`-encoded block (block-import, stateless-block). Raw `rlp` blocks are not inspected |
| `feature:synthetic-transaction` | the transaction is a synthetic message |
| `feature:salt` | `input.salt` is present |
| `feature:oracle-transcript` | `input.oracle` is present |
| `feature:injected-faults` | `input.faults` is present |
| `feature:sparse-state` | `input.pre.completeness` is `sparse` |
| `feature:schedule` | the chain schedule has more than one spec |
| `feature:raw-chain-config` | `input.chain.rawConfig` is not null |
| `feature:proof-attachment` | `input.witness.proof` is not null |

## State

### Pre-state completeness

`pre.completeness` is a tag:

- `complete`: every account the case can touch is listed; an unlisted account is absent and an
  unlisted slot of a listed account is zero. Zero slots are therefore never listed
  (`zero-slot-in-complete-state`). Accounts are `{nonce, balance, code, storage}`.
- `sparse`: listed values are evidence and nothing else is known. An account is
  `{nonce, balance, code, storage, storageComplete}`, or `null` when it is known to be absent;
  `storageComplete: true` makes its unlisted slots zero, `false` makes them missing; a listed
  `0x0` slot is a known zero. Any undeclared account, slot, code, bucket or ancestor hash is a
  missing input. An account created during the case has complete empty storage under the
  specification's lifecycle rules, and earlier committed writes can serve later reads.
- `witness`: sparse values that a stateless validator receives together with the witness anchor
  and, optionally, a proof attachment (stateless-block only).

A missing input is a harness or data error: the consumer reports `error`, never a pass and never an
expected refusal. A missing input the case intends is an injected fault (`input.faults`), which has
a typed expected outcome.

### Post-state: the state diff

`state` is a complete semantic change set: `{accounts: {address: account | null}}`. Every account
whose existence, nonce, balance, code or storage changed is listed, with its whole post nonce,
balance and code and only its changed slots (`0x0` for a cleared slot); `null` means the account
does not exist afterwards. An unlisted account is unchanged. So an absent account (`null`) and a
present empty account (`{"nonce":"0x0","balance":"0x0","code":"0x","storage":{}}`) are different
observations, as are a slot cleared to zero and a slot never touched.

### Commitments

`commitments` maps a typed kind to a 32-byte value: `mpt-state-root`, `salt-state-root`,
`mpt-receipts-root`, `mpt-transactions-root`, `mpt-withdrawals-storage-root`, `block-hash`. An MPT
state root and a SALT state root are never the same field. No `mpt-state-root` may be asserted over
a sparse or witness pre-state (`root-over-sparse-state`): a root over a partial state is fiction.

## External inputs

- **SALT** (`salt`): `{mapping, complete, buckets}`. `mapping` names SALT's key-to-bucket mapping
  (`salt-v1`, which the spec descriptor's `salt` member states by value); `buckets` maps a bucket
  id to its capacity; with `complete: true` an unlisted bucket has the minimum capacity, otherwise
  it is a missing input. A case without `salt` states no capacity: any bucket read is a missing
  input (decision D-38).
- **Oracle transcript** (`oracle`, engine-isolation profiles only: state-transition and
  block-build): `{mode: "recorded", entries: [{slot, answer}]}` in request order, `answer: null`
  being the service answering none; or `{mode: "disabled"}`, no service. In recorded mode an
  unexpected request or an unused entry fails the case. A case without `oracle` states no service:
  any oracle request is a missing input (decision D-38). Validators run no oracle service: Satin's
  front-running model persists answers on chain before the reading transaction, so block-import and
  stateless-block take the oracle's values from state and carry no transcript.
- **Injected faults** (`faults`): provider reads made to fail, each
  `{source: account|storage|code|block-hash|bucket, ...key}`. The expected outcome records the
  fault in `commit` (`status: fault`, its stage, the read and how the node reports it).
- **Block hashes** (`blockHashes`, `ancestors`): historical hashes by number; a `BLOCKHASH` of an
  unlisted number inside the window is a missing input.

## Transactions

A transaction source is tagged by `kind`:

- `signed`: EIP-2718 bytes, from which the sender is recovered.
- `deposit`: an unsigned deposit envelope (type `0x7e`), its source hash, mint and system flag
  inside the bytes.
- `synthetic`: a pre-recovered execution message (type, chain id, nonce, sender, recipient or
  `null` for a creation, value, data, gas limit, fee fields, access list, and EIP-7702
  authorizations with their recovered authority or `null`). For execution isolation only: it never
  counts toward signature, envelope or validation coverage, and transaction-validation and block
  profiles do not accept it.

Bytes are authoritative; any decoded view in provenance must match them. A source's kind must agree
with its bytes (a deposit's, and only a deposit's, start with `0x7e`), and a synthetic message's fee,
recipient, access-list and authorization fields must fit its type (`inconsistent-transaction`).

## Block context

For engine isolation (`state-transition`, `transaction-validation`) the block is `BlockEnv`:
number, timestamp, coinbase, gas limit, base fee, prevrandao, parent hash and timestamp, parent
beacon block root, extra data, slot number, blob base fee, and the explicit flags `depositOnly` and
`activation`. Block profiles never take those flags as inputs: the node derives them from the chain
schedule and the parent timestamp, and each block result asserts them with the resolved
`activeSpec`.

Block profiles carry `chain` (`chainId`, `schedule` of `{spec, timestamp}` in strictly increasing
timestamps, and `rawConfig`, the original configuration bytes for configuration-stage cases), the
`anchor` header (the parent of the first block, whose state `pre` is), `ancestors`, and `blocks`,
each either `{encoding: "fields", header, transactions}` (a decoded header and the EIP-2718 bytes
of each transaction) or `{encoding: "rlp", raw}` (raw block bytes, for malformed-encoding cases).
No system account or contract is inserted invisibly: the pre-block sequence runs as the spec
states it.

## Observations

| Group | Content |
| --- | --- |
| `outcome` | `admission`: `admitted`, `failed-deposit` or `refused` with its `phase` (`decode`, `validation`, `inclusion`) and the set of acceptable `reasons`; `execution`: `success`, `revert` or `halt` with output and created address, or `null`; `commit`: `committed`, `not-committed`, or `fault` with stage, read and report |
| `receipt` | type, status, gas used, logs in order and the deposit fields; block profiles add cumulative gas and the logs bloom |
| `gasPools` | where gas was available and paid from, for the transaction's first frame: its regular gas and reservoir at its start, after the charges made before it, and at its end (`regular`, `reservoir`, each `initial` and `final`); the regular gas it and the children that returned to it paid for state and history charges, legacy shares included, which no give-back credits back (`spilled`); and the gas returned to the sender, the gas limit less the gas used (`returned`). A transaction that ran no frame has regular gas zero at both ends and the reservoir it returns (D-64) |
| `gasLedgers` | `total`, `regular`, `state`, `history`, `historyBytes`, `refund`, `floor`, the receipt's `gasUsed`, and the block-gas contribution; regular = total − state − history |
| `resources` | data size, KV updates and state growth: the transaction limit, the signed net and the reported count |
| `limit` | the stop that ended the transaction's own frame, `null` when none. Every stop carries its `dimension` (`data-size`, `kv-updates`, `compute`, `state-growth`), its `limit` and its `returnData`, `MegaLimitExceeded(kind, limit)` of the two, which is the execution's revert output; these are what an implementation's result exposes. Its diagnostics, the transaction or frame `scope`, the `callPath`, `operation` and `phase` and whether the operation and the enclosing writes committed, are optional from schema 1.1 on, carried behind `group:limit-diagnostics` and compared only where the case carries them; a 1.0 stop carries all of them (D-62) |
| `detention` | each volatile read (category, admitted or failed, call path, compute at the read, cap), the final compute limit (`null` if none), gas withheld, released and burned |
| `reads` | logical reads the spec requires a node to load and export: accounts (`null`: read and absent), slots with the value read (explicit zero), code hashes, block hashes, SALT capacities served, oracle reads in order with their values, admitted hints in order. For a transaction these are its loads in the stateless witness's sense (`SATIN-WIT-001`, `-008`): values as the state held them before it, the code hash of every account read that has code, compared as an exact set ([adapter-protocol.md](adapter-protocol.md#reads), D-61) |
| `checkpoints` | ledger checkpoints at rule-defined boundaries, keyed by call path (child ordinal under each parent), phase and ordinal |

What each value means where an implementation's result could be read two ways — a creation's
output, the refund when the floor binds, the block-gas figure, the signed net and the reported
count, a deposit receipt's fields — is fixed in
[adapter-protocol.md](adapter-protocol.md#mapping-definitions).

Raw opcode traces, cache behaviour, timing, backend names, inspector-only frames and debug strings
are never observations. A refused or faulted transaction has no receipt, ledgers or resources
(`null`), never a fabricated receipt.

## Semantic checks

After the schema check, a reader runs these checks in this order; the first failure is the
rejection.

1. **Specs**: `specRef.descriptor` and every schedule entry's descriptor are bundled
   (`unknown-spec`) under the stated name (`spec-name-mismatch`); schedule timestamps strictly
   increase (`unsorted-set`); a schedule names each spec once (`invalid-reference`); every non-null
   `activeSpec` of a block result is a spec of the schedule (`spec-name-mismatch`).
2. **Envelope sets**: `requires`, `rules`, the assertions' paths and each assertion's `rules` are
   strictly ascending (`unsorted-set`).
3. **Rules**: each cited id is in the case's registry (`unknown-rule`), its row qualifier is a
   citable row (`unknown-rule-row`), and it is active at the case's spec (`retired-rule`).
4. **Assertions**: each path resolves to a value, `null` included (`unbound-assertion`); each
   assertion rule is in `rules` (`assertion-rule-not-cited`); each cited rule is used by an
   assertion (`uncovered-rule`).
5. **Transaction sources**: in state-transition and block-build, each source's kind agrees with
   its bytes and each synthetic message's fields fit its type, checked in the order chain id,
   recipient, gas price, max fee, max priority fee, access list, authorization list
   (`inconsistent-transaction`).
6. **Requirements**: `requires` equals the derived set (`requirement-mismatch`).
7. **Outcomes**: a refused transaction has no execution and is not committed; a faulted one has no
   execution; an admitted one executes and commits unless a fault stops it; a failed deposit is
   committed and has no execution or a halted one; a transaction without an outcome has no receipt, ledgers, resources, limit, pools or
   detention, and an executed one has a receipt, ledgers and resources; the receipt status is
   `0x1` exactly when execution succeeded; every transaction of a valid block is executed or a
   failed deposit; a stateless case has block results exactly when its witness verified, and a
   verified proof exactly when one is attached; an invalid block's spec and flags are `null` only
   when it failed to decode (`inconsistent-outcome`).
8. **State**: no zero slot in complete state (`zero-slot-in-complete-state`); no MPT state root
   over sparse or witness state (`root-over-sparse-state`).
9. **Observation sets**: refusal and decision `reasons` and `reads.codes` are strictly ascending
   (`unsorted-set`).
10. **References**: block results stop at the first invalid block and otherwise match the input
    blocks one to one, with one transaction result per transaction; the head is the anchor when no
    block was accepted (with an empty state diff) and otherwise has the number of the last accepted
    `fields`-encoded block. Block-build actions name existing candidates and follow the action
    machine: `execute` makes a candidate's execution pending, `commit` and `abandon` each need a
    pending execution and end it; there is one decision per candidate; committed indices exist and
    are unique; a candidate is included exactly when committed and has reasons exactly when not
    included; `committed` lists candidates in the order of their `commit` actions (a commit-time
    recheck may refuse a commit, so it is a subsequence of them); there is one transaction result
    per committed candidate (`invalid-reference`, `inconsistent-outcome`).
