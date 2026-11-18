"""The constants of the Satin specification the model uses, with the rules that state them, the addresses
and selectors of the system contracts, and the encodings built from them. Every price a case's figure
depends on is written here once (decision D-57); `tools/check_derived_text.py` changes these in turn."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import make_examples as ex  # noqa: E402  (Keccak-256, RLP)

EXECUTION_CAP = 200_000_000  # SATIN-POOL-005
TX_MAX_TOTAL_GAS_LIMIT = 2**32 - 1  # EIP-8037's cap on a transaction's total gas, which Satin does not apply (SATIN-POOL-003)
TX_BASE_COST = 12_000  # SATIN-SCHED-006
COLD_ACCOUNT_ACCESS = 3_000  # SATIN-SCHED-006
TX_VALUE_COST = 6_000  # SATIN-SCHED-006
CREATE_ACCESS = 12_000  # SATIN-SCHED-006
INITCODE_WORD_COST = 2  # EIP-3860, kept by SATIN-SCHED-001
CALLDATA_ZERO = 4  # inherited calldata cost, kept by SATIN-SCHED-001
CALLDATA_NONZERO = 16
ACCESS_LIST_ADDRESS = 4_180  # SATIN-SCHED-003
ACCESS_LIST_KEY = 4_048  # SATIN-SCHED-003
FLOOR_PER_BYTE = 16 * 4  # SATIN-SCHED-005: TOTAL_COST_FLOOR_PER_TOKEN x FLOOR_TOKENS_PER_BYTE
WARM_READ = 100  # SATIN-SCHED-003
COLD_SLOAD = 2_100  # SATIN-SCHED-003 (2,000 additional) and SATIN-SCHED-004
COLD_SSTORE_ACCESS = 2_100  # SATIN-SCHED-004
SSTORE_SET = 10_000  # SATIN-SCHED-003, fresh slot before the load cost
SSTORE_RESET = 10_000  # SATIN-SCHED-003, reset before the cold load
REFUND_RESTORED_FRESH = 10_000  # SATIN-SCHED-003
REFUND_RESTORED_RESET = 10_000  # SATIN-SCHED-003
REFUND_CLEARED = 11_616  # SATIN-SCHED-003
CALL_STIPEND = 2_300  # inherited EIP-2200 sentry
KECCAK_WORD = 6  # SATIN-SCHED-011
COST_PER_STATE_BYTE = 1_530  # SATIN-STATE-003
SLOT_STATE_BYTES = 64  # SATIN-STATE-003: the EIP-8037 byte count of a storage slot
ACCOUNT_STATE_BYTES = 120  # SATIN-STATE-003: the EIP-8037 byte count of an account leaf
SLOT_STATE = SLOT_STATE_BYTES * COST_PER_STATE_BYTE  # SATIN-STATE-003
ACCOUNT_STATE = ACCOUNT_STATE_BYTES * COST_PER_STATE_BYTE  # SATIN-STATE-003
CODE_STATE_PER_BYTE = COST_PER_STATE_BYTE  # SATIN-STATE-003: deployed code, per byte
PRE_FORK_SSTORE_SET_COST = 20_000  # SATIN-STATE-012
LEGACY_SSTORE_SHARE = PRE_FORK_SSTORE_SET_COST - SSTORE_SET  # SATIN-STATE-012: PRE_FORK_SSTORE_SET_COST - SSTORE_WRITE_COST
COST_PER_HISTORY_BYTE = 88  # SATIN-HIST-001
TX_BODY_SIZE = 310  # SATIN-HIST-003
WRITE_RECORD_SIZE = 40  # SATIN-HIST-002
ACCESS_LIST_ADDRESS_SIZE = 20
ACCESS_LIST_SLOT_SIZE = 32
LOG_BASE_SIZE = 32
LOG_TOPIC_SIZE = 32
TRANSFER_LOG_SIZE = 160  # SATIN-ACCT-001, SATIN-LOG-006
LOG_COST = 375  # inherited
LOG_TOPIC_COST = 375
LOG_DATA_COST = 8
MEMORY_WORD = 3
# The inherited static gas tiers of the opcodes the model runs (Osaka's, kept by SATIN-SCHED-002).
G_ZERO, G_JUMPDEST, G_BASE, G_VERYLOW, G_LOW, G_MID, G_HIGH = 0, 1, 2, 3, 5, 8, 10
G_EXP, G_EXP_BYTE = 10, 50  # inherited EXP: its static gas and its price per byte of the exponent
REFUND_QUOTIENT = 5  # EIP-3529, kept by SATIN-POOL-018
MIN_BUCKET_SIZE = 256  # SATIN-STATE-002
TX_DATA_LIMIT = 13_107_200  # SATIN-LIM-001
TX_KV_UPDATE_LIMIT = 500_000
TX_STATE_GROWTH_LIMIT = 1_000
MAX_CONTRACT_SIZE = 524_288  # SATIN-SIZE-001
MAX_INITCODE_SIZE = 2 * MAX_CONTRACT_SIZE  # SATIN-SIZE-002

TRANSFER_LOG_ADDRESS = bytes.fromhex("ff" * 19 + "fe")  # SATIN-LOG-001
TRANSFER_TOPIC = bytes.fromhex("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

BASE_FEE_VAULT = bytes.fromhex("4200000000000000000000000000000000000019")
# The reads of a transaction (the stateless witness, at `5fb2688`): the fee recipients besides the
# beneficiary, and the L1 block contract's slots every non-deposit transaction reads (SATIN-WIT-011).
L1_FEE_VAULT = bytes.fromhex("420000000000000000000000000000000000001a")
OPERATOR_FEE_VAULT = bytes.fromhex("420000000000000000000000000000000000001b")
L1_BLOCK_ADDRESS = bytes.fromhex("4200000000000000000000000000000000000015")
L1_BASE_FEE_SLOT, L1_ECOTONE_SCALARS_SLOT, L1_FEE_OVERHEAD_SLOT, L1_BLOB_BASE_FEE_SLOT, L1_OPERATOR_SCALARS_SLOT = 1, 3, 5, 7, 8
KECCAK_EMPTY = ex.keccak256(b"")

# Calls, interception and EIP-7702 (the specification at `d334ef8`).
COLD_ACCOUNT_SURCHARGE = 2_900  # SATIN-SCHED-003: cold account access, additional to the warm read
CALL_VALUE_COST = 11_300  # SATIN-SCHED-003: value transfer of a call, with its 2,300 stipend
GAS_RETAINED_NUMERATOR, GAS_RETAINED_DENOMINATOR = 2, 100  # SATIN-FWD-001
KECCAK_BASE = 30  # inherited KECCAK256 static gas, kept by SATIN-SCHED-002
COPY_WORD = 3  # inherited per-word copy cost (RETURNDATACOPY), kept by SATIN-SCHED-001
PER_AUTH_BASE_COST = 7_816  # SATIN-SCHED-003: EIP-7702 authorization, intrinsic regular gas
ACCOUNT_WRITE = 9_000  # SATIN-SCHED-003: EIP-8038 account write of an authority
DELEGATION_STATE_BYTES = 23  # SATIN-STATE-003: the EIP-8037 byte count of a delegation indicator
AUTHORIZATION_SIZE = 101  # SATIN-HIST-002: bytes of an authorization entry
KEYLESS_DEPLOY_OVERHEAD_GAS = 100_000  # SATIN-KEY-005 step 1
MAX_U64 = 2**64 - 1
# The charge-order principles (the specification at `5fb2688`).
PRE_FORK_NEW_ACCOUNT_COST = 25_000  # SATIN-STATE-012: the pre-Satin price of a new account
LEGACY_NEW_ACCOUNT_SHARE = PRE_FORK_NEW_ACCOUNT_COST - 0  # SATIN-STATE-012: a value CALL's new account has no execution charge
DELEGATION_PREFIX = b"\xef\x01\x00"  # EIP-7702's delegation indicator, followed by the delegate's address
# The take-back page's worked examples (the specification at `cdded1e`).
HISTORY_ALLOWANCE_BYTES = 160  # SATIN-HIST-018: the history bytes a value call's frame may log without paying
FRAME_SHARE_NUMERATOR, FRAME_SHARE_DENOMINATOR = 98, 100  # SATIN-LIM-003: a child's share of its parent's remaining
PRE_FORK_CREATE_COST = 32_000  # SATIN-STATE-012: the pre-Satin price of a CREATE
LEGACY_CREATE_SHARE = PRE_FORK_CREATE_COST - CREATE_ACCESS  # SATIN-STATE-012: a created account's legacy share
SELFDESTRUCT_COST = 5_000  # SATIN-SCHED-002: SELFDESTRUCT's static gas
SELFDESTRUCT_NEW_ACCOUNT_COST = 9_000  # SATIN-SCHED-003: the "new account of SELFDESTRUCT" entry
LEGACY_SELFDESTRUCT_SHARE = PRE_FORK_NEW_ACCOUNT_COST - SELFDESTRUCT_NEW_ACCOUNT_COST  # SATIN-STATE-012: a beneficiary's
# Gas detention, the Oracle's reads and the access-control refusal (the specification at `5fb2688`).
BLOCK_ENV_ACCESS_COMPUTE_GAS = 20_000_000  # SATIN-DET-012: the cap after a read of the block environment
ORACLE_ACCESS_COMPUTE_GAS = 20_000_000  # SATIN-DET-012: the cap after a read of the Oracle's storage
DETENTION_STOP = 2  # SATIN-DET-018: the kind of MegaLimitExceeded a crossing stops a frame with
# Gas detention's other volatile reads and the precompiles it prices (the specification at `cdded1e`).
G_BLOCKHASH = 20  # inherited BLOCKHASH static gas, kept by SATIN-SCHED-002
BLOCKHASH_WINDOW = 256  # inherited: BLOCKHASH answers the last 256 blocks
HISTORY_STORAGE_ADDRESS = bytes.fromhex("0000f90827f1c53a10cb7a02335b175320002935")  # EIP-2935's history contract
# The precompile set of SATIN-PCMP-001, warm from the transaction's start (SATIN-SCHED-012): Karst's 0x01 to 0x11
# and P256VERIFY at 0x100. The precompile page's own constants are below, with the BN254 pairing's.
PRECOMPILE_SET = frozenset([i.to_bytes(20, "big") for i in range(1, 0x12)] + [(0x100).to_bytes(20, "big")])
IDENTITY = (4).to_bytes(20, "big")
ECRECOVER = (1).to_bytes(20, "big")
SHA256 = (2).to_bytes(20, "big")
RIPEMD160 = (3).to_bytes(20, "big")
MODEXP = (5).to_bytes(20, "big")
BN254_PAIRING = (8).to_bytes(20, "big")
IDENTITY_BASE, IDENTITY_WORD = 15, 3  # inherited identity price: 15 + 3 a word
ECRECOVER_GAS = 3_000  # inherited ecrecover price, as Karst defines it (SATIN-PCMP-001)
SHA256_BASE, SHA256_WORD = 60, 12  # inherited SHA-256 price, as Karst defines it (SATIN-PCMP-001): 60 + 12 a word
RIPEMD160_BASE, RIPEMD160_WORD = 600, 120  # inherited RIPEMD-160 price, as Karst defines it (SATIN-PCMP-001): 600 + 120 a word
MODEXP_MIN_GAS = 500  # SATIN-PCMP-002: EIP-7883's minimum
MODEXP_MAX_INPUT_SIZE = 1_024  # SATIN-PCMP-002: EIP-7823's bound on each length
BN254_PAIRING_MAX_INPUT_SIZE = 57_600  # SATIN-PCMP-001, SATIN-PCMP-004
BN254_PAIRING_BASE, BN254_PAIRING_PER_PAIR, BN254_PAIR_SIZE = 45_000, 34_000, 192  # inherited EIP-1108 price, 192-byte pairs
# The precompile page's own rules (the specification at `bcf260d`, D-103): KZG point evaluation at its fixed price,
# P256VERIFY at EIP-7951's, and the BLS12-381 precompiles under the OP input size limits.
KZG_POINT_EVALUATION = (0x0A).to_bytes(20, "big")
P256VERIFY = (0x100).to_bytes(20, "big")
BLS12_G1_MSM = (0x0C).to_bytes(20, "big")
BLS12_G2_MSM = (0x0E).to_bytes(20, "big")
BLS12_PAIRING = (0x0F).to_bytes(20, "big")
KZG_POINT_EVALUATION_GAS = 100_000  # SATIN-PCMP-001, SATIN-PCMP-006
P256VERIFY_GAS = 6_900  # SATIN-PCMP-003
BLS12_G1_MSM_MAX_INPUT_SIZE = 288_960  # SATIN-PCMP-001, SATIN-PCMP-004
BLS12_G2_MSM_MAX_INPUT_SIZE = 278_784  # SATIN-PCMP-001, SATIN-PCMP-004
BLS12_PAIRING_MAX_INPUT_SIZE = 156_672  # SATIN-PCMP-001, SATIN-PCMP-004
# EIP-4844's point evaluation, as Karst defines it but for its price (SATIN-PCMP-001): a 192-byte input, the versioned
# hash's version byte, the scalar field's modulus and the two words a successful evaluation returns.
KZG_INPUT_SIZE = 192
VERSIONED_HASH_VERSION_KZG = 0x01
BLS_MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
FIELD_ELEMENTS_PER_BLOB = 4_096
# EIP-2537's BLS12-381 operations, as Karst defines them (SATIN-PCMP-001): each pair's bytes, the multiplication cost
# each MSM is priced from, the largest discount of its table, which applies from 128 pairs on, and the pairing's price.
BLS12_G1_MSM_PAIR_SIZE, BLS12_G2_MSM_PAIR_SIZE, BLS12_PAIRING_PAIR_SIZE = 160, 288, 384
BLS12_G1_MUL_GAS, BLS12_G2_MUL_GAS = 12_000, 22_500
BLS12_G1_MSM_MAX_DISCOUNT, BLS12_G2_MSM_MAX_DISCOUNT, BLS12_MSM_MULTIPLIER, BLS12_MSM_TABLE_PAIRS = 519, 524, 1_000, 128
BLS12_PAIRING_BASE, BLS12_PAIRING_PER_PAIR = 37_700, 32_600
# EIP-7951's curve, secp256r1 (P-256), at the revision SATIN-PCMP-003 pins: its field, coefficients, order and generator.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
P256VERIFY_INPUT_SIZE = 160
# Karst's simplest arithmetic precompiles (SATIN-PCMP-001, as Karst defines them), run here on points at infinity: the
# BN254 addition and multiplication at their Istanbul prices (EIP-1108), and EIP-2537's G1 and G2 additions; each
# address, its input size, its price and its answer's size.
BN254_ADD, BN254_MUL = (0x06).to_bytes(20, "big"), (0x07).to_bytes(20, "big")
BLS12_G1_ADD, BLS12_G2_ADD = (0x0B).to_bytes(20, "big"), (0x0D).to_bytes(20, "big")
BN254_ADD_GAS, BN254_MUL_GAS, BLS12_G1_ADD_GAS, BLS12_G2_ADD_GAS = 150, 6_000, 375, 600
INFINITY_ARITHMETIC = {BN254_ADD: (128, BN254_ADD_GAS, 64), BN254_MUL: (96, BN254_MUL_GAS, 64),
                       BLS12_G1_ADD: (256, BLS12_G1_ADD_GAS, 128), BLS12_G2_ADD: (512, BLS12_G2_ADD_GAS, 256)}
# SATIN-STOP-002, SATIN-STOP-018: the kind of each dimension's stop, and the dimension the format names it by.
DATA_SIZE_STOP, KV_UPDATE_STOP, STATE_GROWTH_STOP = 0, 1, 3
STOP_DIMENSIONS = {DATA_SIZE_STOP: "data-size", KV_UPDATE_STOP: "kv-updates", DETENTION_STOP: "compute",
                   STATE_GROWTH_STOP: "state-growth"}

ORACLE = bytes.fromhex("6342000000000000000000000000000000000001")
HIGH_PRECISION_TIMESTAMP = bytes.fromhex("6342000000000000000000000000000000000002")
KEYLESS_DEPLOY = bytes.fromhex("6342000000000000000000000000000000000003")
MEGA_ACCESS_CONTROL = bytes.fromhex("6342000000000000000000000000000000000004")
MEGA_LIMIT_CONTROL = bytes.fromhex("6342000000000000000000000000000000000005")
# SATIN-HPTS-001: the High-Precision Timestamp's code by hash, the Oracle's address embedded, and its storage allocation.
HIGH_PRECISION_TIMESTAMP_CODE_HASH = bytes.fromhex("1b2df8ca5350cd7106d67ed95532584526f97a5ca267c8eef73a1831f53720f2")
TIMESTAMP_BASE_SLOT, TIMESTAMP_MAX_SLOTS = 0, 8
# SATIN-REG-001, -002: the SequencerRegistry, its version 2.0.0 code by hash, and the slot that holds the system address.
SEQUENCER_REGISTRY = bytes.fromhex("6342000000000000000000000000000000000006")
SEQUENCER_REGISTRY_CODE_HASH = bytes.fromhex("abd7e8f1c8f0f9ca0346df585b65d9791a7e9ba5c431cc4eda5d2c2f1f5e9c43")
CURRENT_SYSTEM_ADDRESS_SLOT = 0
# SATIN-MST-001, -006, -007: the contracts a Mega System Transaction may call, the source hash its promotion stamps, and
# the caller of the pre-block calls, whose transactions are the protocol's own.
MEGA_SYSTEM_TX_WHITELIST = frozenset({bytes.fromhex("6342000000000000000000000000000000000001")})
MEGA_SYSTEM_TRANSACTION_SOURCE_HASH = bytes.fromhex("852c082c0faff590c6300c2c34815d1f79882552fa95ba413cd5aeb1dba84957")
SYSTEM_CALLER = bytes.fromhex("fffffffffffffffffffffffffffffffffffffffe")
SYSTEM_CONTRACTS = frozenset({ORACLE, KEYLESS_DEPLOY, MEGA_ACCESS_CONTROL, MEGA_LIMIT_CONTROL})  # the cases' system contracts
# SATIN-SYSC-001: the six system contracts' addresses, every one of them, which SATIN-SYSC-005 bounds a pre-state at.
SYSTEM_CONTRACT_ADDRESSES = frozenset({ORACLE, HIGH_PRECISION_TIMESTAMP, KEYLESS_DEPLOY, MEGA_ACCESS_CONTROL,
                                       MEGA_LIMIT_CONTROL, SEQUENCER_REGISTRY})


def selector(signature: str) -> bytes:
    return ex.keccak256(signature.encode())[:4]


SEND_HINT = selector("sendHint(bytes32,bytes)")
KEYLESS_DEPLOY_CALL = selector("keylessDeploy(bytes,uint256)")
# KeylessDeploy's KEYLESS_DEPLOY_CODE_HASH (SATIN-KEY-001), version 1.0.0.
KEYLESS_DEPLOY_CODE_HASH = bytes.fromhex("55020d41649acf7a84add6e628b887f802218d9ac86f142ef0994da43ea5eeb6")
# SATIN-ICPT-001: the intercepted methods of the two contracts whose answer is the node's.
IS_VOLATILE_DATA_ACCESS_DISABLED = selector("isVolatileDataAccessDisabled()")
INTERCEPTED = {
    MEGA_ACCESS_CONTROL: {selector("disableVolatileDataAccess()"), selector("enableVolatileDataAccess()"),
                          IS_VOLATILE_DATA_ACCESS_DISABLED},
    MEGA_LIMIT_CONTROL: {selector("remainingComputeGas()")},
}
NON_ZERO_TRANSFER = selector("NonZeroTransfer()")  # SATIN-ICPT-003
NO_ETHER_TRANSFER = selector("NoEtherTransfer()")  # SATIN-KEY-005 step 2
MALFORMED_ENCODING = selector("MalformedEncoding()")  # SATIN-KEY-005 step 3
# A keyless deployment past step 3 (the specification at `c130558`, KeylessDeploy's page): its constants, and the
# custom errors of SATIN-KEY-001's interface, each the four-byte selector of its signature.
# SATIN-KEY-005 step 5 holds the initcode to MAX_INITCODE_SIZE, SATIN-SIZE-002's, defined above.
CREATE_GAS = CREATE_ACCESS  # SATIN-KEY-005 step 14: KeylessDeploy's CREATE_GAS, SATIN-SCHED-003's CREATE, 12,000
SECP256K1_P = 2**256 - 2**32 - 977  # the secp256k1 curve of a legacy transaction's signature (step 7)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
               0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
KEYLESS_ERRORS = {name: selector(name) for name in (
    "NotContractCreation()", "NotPreEIP155()", "NonZeroTxNonce(uint64)", "InvalidSignature()", "InsufficientBalance()",
    "ContractAlreadyExists()", "SignerNonceTooHigh(uint64)", "ExecutionReverted(uint64,bytes)",
    "ExecutionHalted(uint64)", "EmptyCodeDeployed(uint64)", "GasLimitTooLow(uint64,uint64)",
    "InitCodeTooLarge(uint64,uint64)", "SignerHasCode()", "NotIntercepted()")}
DISABLE_VOLATILE_DATA_ACCESS = selector("disableVolatileDataAccess()")  # SATIN-MAC-001
VOLATILE_DATA_ACCESS_DISABLED = selector("VolatileDataAccessDisabled(uint8)")  # SATIN-MAC-004
ACCESS_TYPE_TIMESTAMP, ACCESS_TYPE_BENEFICIARY, ACCESS_TYPE_ORACLE = 1, 10, 11  # SATIN-MAC-005


def delegate_of(code: bytes) -> bytes | None:
    """The delegate an EIP-7702 delegation indicator names, or None for any other code."""
    return code[3:] if len(code) == 23 and code[:3] == DELEGATION_PREFIX else None


def limit_exceeded(kind: int, limit: int) -> bytes:
    """`MegaLimitExceeded(uint8,uint64)` with its two arguments (SATIN-STOP-020)."""
    return selector("MegaLimitExceeded(uint8,uint64)") + kind.to_bytes(32, "big") + limit.to_bytes(32, "big")
