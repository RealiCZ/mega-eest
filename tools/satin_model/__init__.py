#!/usr/bin/env python3
"""A small executable model of Satin's transaction rules, for deriving expected values.

This is the independent evidence behind the vertical slice's expectations: it restates, from the
specification at `d34e626` (`specs/satin-d34e626`), for calls, interception and EIP-7702 at
`d334ef8` (`specs/satin-d334ef8`), for the charge-order principles at `5fb2688`
(`specs/satin-5fb2688`), for the take-back page's worked examples and the destruction page's own
rules at `cdded1e` (`specs/satin-cdded1e`), for a precompile that halts at `c130558`
(`specs/satin-c130558`), and for a precompile's halt over its size limit, a failed deposit's step-4
load and a promoted system transaction's receipt at `bcf260d` (`specs/satin-bcf260d`), the
arithmetic a `state-transition` case's observations follow, for the narrow class of transactions
the slice uses:

- the transaction's own frame: the opcodes `STOP`, `ADD`, `POP`, `PUSH0`..`PUSH32`, `CALLER`, `ORIGIN`,
  `GASPRICE`, `CHAINID`, `CALLVALUE`, `GAS`, `TIMESTAMP`, `BALANCE`, `MSTORE`, `SLOAD`, `SSTORE`,
  `LOG0`..`LOG4`, `RETURN`, `REVERT`, `INVALID` and the undefined `0x0c`..`0x0f`, and the stack, arithmetic,
  calldata, jump, return-data and `KECCAK256` opcodes a system contract's dispatcher and decoder use, and the
  `DELEGATECALL`, `CREATE` and `SELFDESTRUCT` of the take-back examples, below; of the volatile reads only those below;
- a `CALL` from that frame to a system contract, decided in the order of `SATIN-ICPT-007`: an
  interceptor's `NonZeroTransfer()`, the `sendHint` admission and its data-size stop, the frame
  start that refuses a value the caller cannot fund, and a child frame that reverts or halts; the
  opcode charges the history of the records its start would make, as the state stands, before all
  of these, and a caller that cannot pay it halts in the opcode; a value `CALL` its caller cannot
  fund to any other account, a contract or one empty under EIP-161, refused at its frame start;
- the take-back examples' frames: a child frame at any depth a case builds that writes, logs,
  calls, succeeds, reverts or halts, with its reservoir share (`SATIN-POOL-011`), its budgets
  (`SATIN-LIM-003`) and its rollback (`SATIN-POOL-014`); a value start that makes or takes back
  account records (`SATIN-ACCT-006`), and one to an account without code held to the started
  frame's budget (`SATIN-LIM-013`); `DELEGATECALL` to a contract; a `CREATE` that succeeds, and the
  first `SELFDESTRUCT` of an account created in the transaction (`SATIN-SD-019`); a value child's
  history allowance (`SATIN-HIST-019`);
- the destruction page's shapes: a `SELFDESTRUCT` of an account the transaction did not create
  (`SATIN-SD-012`), to another account or to itself, and a repeated one while the mark stands
  (`SATIN-SD-011`); the marked account, its stores (`SATIN-SD-013`), a code deposit after its
  constructor destroyed it (`SATIN-SD-014`), a value sent to it and its removal at the end
  (`SATIN-SD-015`); a creation onto an address whose leaf the state holds with storage, its slots
  reading zero (`SATIN-SD-003`, `-016`, `-017`); a mark a failed frame discards (`SATIN-SD-010`); and
  the read of a destruction's beneficiary that is the block beneficiary (`SATIN-SD-020`);
- a transaction's own `keylessDeploy` call, recognized or not (`SATIN-ICPT-006`), as far as the
  refusals of steps 2 and 3 or a halt at step 1; and, at `c130558`, a deployment past step 3: the
  carried transaction and its signer, steps 3 to 15, the creation it starts and how it ends, the
  signer's nonce and records, `gasUsed` and the answer (KeylessDeploy's page, D-79); a contract's
  `keylessDeploy` call, which runs the bytecode;
- EIP-7702 lists whose entries are accepted, the authority present or absent, a second entry for
  one authority clearing the delegation the first set (`SATIN-AUTH-009`); entries skipped by their
  gates, by their authority's code or by their nonce, the sender's own entry, an authority holding
  an indicator at the start (`SATIN-AUTH-002` to `-004`); and a
  transaction to an account holding a delegation, its sender's own among them, which pays its
  delegate's access before the first frame;
- a transaction that runs out of gas before its first frame, everything applied after validation's
  changes to its sender taken back, an authorization list's charges, applied entries and all, and a
  delegate's access among the charges it cannot pay; a creation's sender keeps the nonce bump the
  creation would have made (`SATIN-SCHED-010`);
- for the cases that ask, the `reads` group: what the transaction loads, as the stateless witness
  needs it, and the `gasPools` group: the first frame's pools at its start and end;
- a stop of the transaction's own frame, its result: gas detention's crossing, and an `SSTORE`'s
  record or a log's bytes held to the frame's budget and the transaction's limit;
- the stops below it (D-74): a child's write held to its budget and the transaction's limit, the
  stop its caller catches, a value call's or a `CREATE`'s start held to what it kept, the creator's
  nonce record, a failed frame's hints and the data-size stop of the frame it returns into, a
  deposit whose own frame is stopped, and an EIP-7702 list that does not fit, skipped;
- gas detention: `TIMESTAMP`, a deposit's `SLOAD` in the Oracle's frame and `BALANCE` as reads, the
  limit they set, every frame's spendable and withheld parts, each part an opcode deducts as one
  charge, the crossing that stops a child frame and the out-of-gas beyond its whole gas; and
  `disableVolatileDataAccess()` with the refusal of a volatile read in a frame whose access is off;
- for gas detention's rules at `cdded1e`: `NUMBER`, `BLOCKHASH`, `COINBASE`, `PREVRANDAO`, `GASLIMIT`,
  `BASEFEE`, `BLOBBASEFEE` and `SLOTNUM` as reads, `SELFBALANCE` of the beneficiary's own frame and its
  `EXTCODESIZE` and `EXTCODEHASH`, `BLOBHASH` and a creation onto the beneficiary as none, a transaction
  detained from its start, an `SSTORE` in a detained frame, and a call to a precompile decided from its
  price (the identity precompile, ModExp's price, a BN254 pairing over its size limit);
- for the first batch's edges two reviews found (D-91): RIPEMD-160's price and digest and
  ModExp's output; a `DELEGATECALL` of a precompile and a transaction's own call of one; `BALANCE` of
  the beneficiary and a `CALL` to it as reads; `BLOBHASH` with access off; `CALL` and `CALLCODE` short
  of their operands; a created account's first `SELFDESTRUCT` to itself; and a limit-stop case's value
  call to the identity precompile where no limit is set; and at `bcf260d`: SHA-256's and ecrecover's
  prices; `EXTCODECOPY` and a `DELEGATECALL` of the beneficiary and a recipient delegating to it as
  reads; `SELFDESTRUCT`'s two charges and one in a creation transaction's own frame; a limit-stop
  case's stopped `CREATE` and its creator's resume; and a creation's reset of its address's storage;
- calls, value transfers, creation transactions and deposits, with or without a reservoir, and a
  deposit whose own frame halts (`SATIN-DEP-004`);
- for the outcomes page and validation's order (D-85): `CREATE`'s and `CREATE2`'s operands, size check
  and charges in the order of `SATIN-SIZE-005` (`CREATE2` as far as its salt), a creation's code over
  `MAX_CONTRACT_SIZE` and its code deposit, each failure a halt; a precompile call that fails where no
  limit is set, a BN254 pairing of points at infinity, and a value call to the identity precompile
  whose start is held to the limits; a deposit that fails validation, cannot pay a charge before its
  first frame, carries a value, or whose own frame reverts, and a failed deposit's reads; an empty
  authorization list and a sender's nonce of 2^64 - 1; and the transactions from a live system
  address the registry names, refused or promoted (D-87);
- for the system-transaction page and gas forwarding (D-82, D-83): a transaction from the live system
  address without the system shape, a promoted Mega System Transaction that runs, and the protocol's
  own transactions (a promoted one, a deposit carrying `MEGA_SYSTEM_TRANSACTION_SOURCE_HASH`, a
  synthetic message from `SYSTEM_CALLER`, of any type, and a deposit from it), priced at m = 1, not
  detained and held to no limit; and the forward of `CALLCODE`, `STATICCALL` and `CREATE2`, and a
  creation whose initcode fails (D-84);
- for the history page and the resource-accounting page (D-100, D-101): a value `CALL` to the calling account
  itself, which moves nothing, makes no record and logs nothing (`SATIN-ACCT-007`, `SATIN-LOG-003`), and a value start
  without a frame held to the transaction's limit with the admitted hints counted (`SATIN-LIM-012`); a `SELFDESTRUCT`
  that returns an account to what the transaction loaded (`SATIN-ACCT-006`); a creation its creator cannot endow,
  refused (`SATIN-HIST-015`); and a successful creation onto an address the transaction funded (`SATIN-ACCT-005`);
- for the precompile page's and the contract-limits page's own rules at `bcf260d` (D-103, D-104): a call
  to a precompile where no limit is set, decided by `SATIN-PCMP-001` to `-007`, with KZG point evaluation
  on commitments and proofs at the point at infinity, `P256VERIFY`, ModExp's lengths too large to price
  and the BN254 and BLS12-381 precompiles on points at infinity, at and over their size limits; a
  creation transaction's initcode over `MAX_INITCODE_SIZE`, refused, and a deposit's, a failed deposit;
  a creation's code over `MAX_CONTRACT_SIZE` from `CREATE` or `CREATE2`; a creation in a static frame;
  and the offset of empty initcode, unchecked;
- the refusals of transaction validation.

Every charge is a step of a derivation that names the rule it applies, so a reviewer can check
each number against the pinned rule text, and the case's assertions cite exactly the rules its
steps applied. The model shares no code with either implementation or adapter. It is not an
implementation of Satin: anything outside the class above raises `Unmodelled`, and a pre-state the
specification excludes, storage at a system contract's address in an account without code
(`SATIN-SYSC-005`), raises `InvalidPrestate` before anything is derived (D-97). Its scope, and what
lies outside it, is docs/model.md's.

The package is cut by domain (docs/model.md, "Modules"): `constants` and `records` hold the
specification's values and the run's inputs and outputs; `run.Run` composes the mixins that
restate each domain over one run state: the transaction, settlement, the pools, gas detention, the
interpreter, calls, frames, creation and destruction, interception, authorizations, storage, reads
and the resource limits.

Standard library only.
"""

from __future__ import annotations

# What the slice's tools use: the constants, the records and helpers, and the run.
from .constants import *  # noqa: F401,F403
from .records import *  # noqa: F401,F403
from .interception import keyless_arguments, rlp_decodes_as_list  # noqa: F401
from .interpreter import jump_destinations, to_signed  # noqa: F401
from .precompiles import bls12_price, G1_INFINITY_COMPRESSED, modexp_price, p256_mul  # noqa: F401
from .run import Run  # noqa: F401
