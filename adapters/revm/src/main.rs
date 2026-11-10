//! `adapter-revm`: the fixture adapter of the revm-based Satin implementation (mega-evm).
//!
//! It speaks the process interface of docs/adapter-protocol.md:
//!
//! - `adapter-revm capabilities` prints what it runs and its build identity;
//! - `adapter-revm run [--instrumented]` reads one run request (a case without its expectation)
//!   on standard input and prints the observations of that run.
//!
//! Everything that converts between the fixture format and the implementation lives here; the
//! implementation is used through its public transaction entry point,
//! `MegaEvm::execute_transaction`. This adapter shares no execution, fee or observation code with
//! the adapter of the evm2-based implementation.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Read as _;
use std::process::ExitCode;

use alloy_consensus::transaction::SignerRecoverable as _;
use alloy_eips::eip2718::Decodable2718 as _;
use alloy_evm::FromTxWithEncoded as _;
use alloy_op_evm::OpTx;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use mega_evm::{
    AHashBucketHasher, BucketHasher as _, BucketId, ExternalEnvs, MegaContext, MegaEvm, MegaSpecId,
    MegaTransaction, MegaTransactionOutcome, OracleEnv, ProtocolLimits, SaltEnv, MIN_BUCKET_SIZE,
};
use mega_fixture_format::json::{self, Value};
use op_alloy_consensus::OpTxEnvelope;
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::{
        block::BlobExcessGasAndPrice,
        result::{EVMError, ExecutionResult, Output},
    },
    interpreter::{interpreter::EthInterpreter, CallInputs, CallOutcome, CreateInputs, CreateOutcome},
    state::{AccountInfo, Bytecode},
    Database, Inspector,
};

const IMPLEMENTATION_REPOSITORY: &str = "https://github.com/megaeth-labs/mega-evm";
const SPEC: &str = "megaeth/Satin";

/// The requirements this adapter supports: the mandatory groups of state-transition and the
/// input features it converts.
const SUPPORTED: [&str; 10] = [
    "feature:deposit",
    "feature:oracle-transcript",
    "feature:salt",
    "feature:synthetic-transaction",
    "group:gas-ledgers",
    "group:limit",
    "group:outcome",
    "group:receipts",
    "group:resources",
    "group:state",
];

// ---------------------------------------------------------------------------------------------
// JSON helpers

fn s(v: impl Into<String>) -> Value {
    Value::String(v.into())
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn hex_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * b.len());
    out.push_str("0x");
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

fn qty_u64(v: u64) -> Value {
    s(format!("{v:#x}"))
}

fn qty_u256(v: U256) -> Value {
    s(format!("{v:#x}"))
}

fn address(a: &Address) -> Value {
    s(hex_bytes(a.as_slice()))
}

fn b256(h: &B256) -> Value {
    s(hex_bytes(h.as_slice()))
}

/// Why a run produced no observations.
enum Fail {
    /// The case needs something this adapter does not provide.
    Unsupported(String),
    /// The case did not run to completion: a missing input, an unmappable result.
    Error(String),
}

type Res<T> = Result<T, Fail>;

fn bad(msg: impl Into<String>) -> Fail {
    Fail::Error(msg.into())
}

fn member<'a>(v: &'a Value, key: &str) -> Res<&'a Value> {
    v.get(key).ok_or_else(|| bad(format!("input: missing member {key:?}")))
}

fn text<'a>(v: &'a Value, key: &str) -> Res<&'a str> {
    member(v, key)?.as_str().ok_or_else(|| bad(format!("input: {key:?} is not a string")))
}

fn flag(v: &Value, key: &str) -> Res<bool> {
    match member(v, key)? {
        Value::Bool(b) => Ok(*b),
        _ => Err(bad(format!("input: {key:?} is not a boolean"))),
    }
}

fn parse_u256(t: &str) -> Res<U256> {
    let digits = t.strip_prefix("0x").ok_or_else(|| bad(format!("not a quantity: {t}")))?;
    U256::from_str_radix(digits, 16).map_err(|_| bad(format!("not a quantity: {t}")))
}

fn parse_u64(t: &str) -> Res<u64> {
    let v = parse_u256(t)?;
    u64::try_from(v).map_err(|_| bad(format!("quantity above 64 bits: {t}")))
}

fn parse_bytes(t: &str) -> Res<Vec<u8>> {
    let digits = t.strip_prefix("0x").ok_or_else(|| bad(format!("not bytes: {t}")))?;
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| bad(format!("not bytes: {t}"))))
        .collect()
}

fn parse_address(t: &str) -> Res<Address> {
    let b = parse_bytes(t)?;
    (b.len() == 20).then(|| Address::from_slice(&b)).ok_or_else(|| bad(format!("not an address: {t}")))
}

fn parse_b256(t: &str) -> Res<B256> {
    let b = parse_bytes(t)?;
    (b.len() == 32).then(|| B256::from_slice(&b)).ok_or_else(|| bad(format!("not 32 bytes: {t}")))
}

fn entries(v: &Value) -> Res<&BTreeMap<String, Value>> {
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(bad("input: expected an object")),
    }
}

// ---------------------------------------------------------------------------------------------
// The pre-state and the external inputs

/// A complete pre-state: an unlisted account is absent, an unlisted slot zero. A block hash the
/// case does not list is a missing input, never a default.
#[derive(Debug, Default)]
struct FixtureDb {
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    codes: HashMap<B256, Bytecode>,
    block_hashes: HashMap<u64, B256>,
}

#[derive(Debug, Clone)]
struct MissingInput(String);

impl std::fmt::Display for MissingInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing input: {}", self.0)
    }
}

impl std::error::Error for MissingInput {}
impl revm::database_interface::DBErrorMarker for MissingInput {}

impl Database for FixtureDb {
    type Error = MissingInput;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == revm::primitives::KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        self.codes.get(&code_hash).cloned().ok_or_else(|| MissingInput(format!("code {code_hash}")))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or_default())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hashes.get(&number).copied().ok_or_else(|| MissingInput(format!("block hash {number}")))
    }
}

/// One account of the pre-state as the case states it.
struct PreAccount {
    nonce: u64,
    balance: U256,
    code: Vec<u8>,
    storage: BTreeMap<U256, U256>,
}

fn bytecode(code: &[u8]) -> Res<Bytecode> {
    Bytecode::new_raw_checked(Bytes::copy_from_slice(code)).map_err(|e| bad(format!("pre-state code: {e:?}")))
}

fn pre_state(pre: &Value) -> Res<(FixtureDb, BTreeMap<Address, PreAccount>)> {
    if text(pre, "completeness")? != "complete" {
        return Err(Fail::Unsupported("a pre-state that is not complete".into()));
    }
    let mut db = FixtureDb::default();
    let mut accounts = BTreeMap::new();
    for (a, acc) in entries(member(pre, "accounts")?)? {
        let address = parse_address(a)?;
        let code = parse_bytes(text(acc, "code")?)?;
        let mut storage = BTreeMap::new();
        for (k, v) in entries(member(acc, "storage")?)? {
            let key = U256::from_be_bytes(parse_b256(k)?.0);
            let value = parse_u256(v.as_str().ok_or_else(|| bad("storage value"))?)?;
            db.storage.insert((address, key), value);
            storage.insert(key, value);
        }
        let account = PreAccount {
            nonce: parse_u64(text(acc, "nonce")?)?,
            balance: parse_u256(text(acc, "balance")?)?,
            code,
            storage,
        };
        let code = bytecode(&account.code)?;
        let hash = code.hash_slow();
        db.codes.insert(hash, code.clone());
        db.accounts.insert(address, AccountInfo::new(account.balance, account.nonce, hash, code));
        accounts.insert(address, account);
    }
    Ok((db, accounts))
}

/// SALT capacities by bucket id, under the production mapping (`salt-v1`).
#[derive(Debug, Clone, Default)]
struct FixtureSalt {
    known: bool,
    complete: bool,
    buckets: BTreeMap<BucketId, u64>,
}

impl SaltEnv for FixtureSalt {
    type Error = String;

    fn get_bucket_capacity(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        match self.buckets.get(&bucket_id) {
            Some(c) => Ok(*c),
            None if self.known && self.complete => Ok(MIN_BUCKET_SIZE as u64),
            None => Err(format!("missing input: SALT bucket {bucket_id:#x}")),
        }
    }

    fn bucket_id_for_account(account: Address) -> BucketId {
        AHashBucketHasher::bucket_id(account.as_slice())
    }

    fn bucket_id_for_slot(address: Address, key: U256) -> BucketId {
        let mut k = [0u8; 52];
        k[..20].copy_from_slice(address.as_slice());
        k[20..].copy_from_slice(&key.to_be_bytes::<32>());
        AHashBucketHasher::bucket_id(&k)
    }
}

fn salt(input: &Value) -> Res<FixtureSalt> {
    let Some(salt) = input.get("salt") else { return Ok(FixtureSalt::default()) };
    if text(salt, "mapping")? != "salt-v1" {
        return Err(Fail::Unsupported("a SALT mapping other than salt-v1".into()));
    }
    let mut buckets = BTreeMap::new();
    for (id, cap) in entries(member(salt, "buckets")?)? {
        let id = u32::try_from(parse_u64(id)?).map_err(|_| bad(format!("bucket id {id} above 32 bits")))?;
        buckets.insert(id, parse_u64(cap.as_str().ok_or_else(|| bad("capacity"))?)?);
    }
    Ok(FixtureSalt { known: true, complete: flag(salt, "complete")?, buckets })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleMode {
    /// The case states no oracle input: any request is a missing input.
    Absent,
    Disabled,
    Recorded,
}

/// The oracle service, answering from the case's ordered transcript.
#[derive(Debug)]
struct FixtureOracle {
    mode: OracleMode,
    entries: RefCell<VecDeque<(U256, Option<U256>)>>,
    errors: RefCell<Vec<String>>,
}

impl OracleEnv for FixtureOracle {
    fn get_oracle_storage(&self, slot: U256) -> Option<U256> {
        match self.mode {
            OracleMode::Disabled => None,
            OracleMode::Absent => {
                self.errors.borrow_mut().push(format!("missing input: an oracle request for slot {slot:#x}"));
                None
            }
            OracleMode::Recorded => match self.entries.borrow_mut().pop_front() {
                Some((expected, answer)) if expected == slot => answer,
                Some((expected, _)) => {
                    self.errors.borrow_mut().push(format!("oracle request for slot {slot:#x}, transcript has {expected:#x}"));
                    None
                }
                None => {
                    self.errors.borrow_mut().push(format!("unexpected oracle request for slot {slot:#x}"));
                    None
                }
            },
        }
    }

    fn on_hint(&self, _from: Address, _topic: B256, _data: Bytes) {}
}

fn oracle(input: &Value) -> Res<FixtureOracle> {
    let mut entries = VecDeque::new();
    let mode = match input.get("oracle") {
        None => OracleMode::Absent,
        Some(o) if text(o, "mode")? == "disabled" => OracleMode::Disabled,
        Some(o) => {
            let Value::Array(list) = member(o, "entries")? else { return Err(bad("oracle entries")) };
            for e in list {
                let slot = U256::from_be_bytes(parse_b256(text(e, "slot")?)?.0);
                let answer = match member(e, "answer")? {
                    Value::Null => None,
                    Value::String(t) => Some(parse_u256(t)?),
                    _ => return Err(bad("oracle answer")),
                };
                entries.push_back((slot, answer));
            }
            OracleMode::Recorded
        }
    };
    Ok(FixtureOracle { mode, entries: RefCell::new(entries), errors: RefCell::new(Vec::new()) })
}

type Envs = (FixtureSalt, FixtureOracle);

// ---------------------------------------------------------------------------------------------
// The transaction

/// What the observations need to know of the transaction beside the engine's result.
struct TxFacts {
    tx_type: u8,
    sender: Address,
    deposit: bool,
}

/// A refusal decided before the engine runs: the bytes do not decode or do not recover.
struct EarlyRefusal {
    phase: &'static str,
    reason: &'static str,
}

fn transaction(tx: &Value) -> Res<Result<(MegaTransaction, TxFacts), EarlyRefusal>> {
    match text(tx, "kind")? {
        kind @ ("signed" | "deposit") => {
            let raw = parse_bytes(text(tx, "raw")?)?;
            let mut slice = raw.as_slice();
            let Ok(envelope) = OpTxEnvelope::decode_2718(&mut slice) else {
                return Ok(Err(EarlyRefusal { phase: "decode", reason: "malformed-envelope" }));
            };
            if !slice.is_empty() {
                return Ok(Err(EarlyRefusal { phase: "decode", reason: "malformed-envelope" }));
            }
            let deposit = matches!(envelope, OpTxEnvelope::Deposit(_));
            if deposit != (kind == "deposit") {
                return Err(bad("transaction kind disagrees with its bytes"));
            }
            let sender = match &envelope {
                OpTxEnvelope::Deposit(d) => d.inner().from,
                other => match other.recover_signer() {
                    Ok(a) => a,
                    Err(_) => return Ok(Err(EarlyRefusal { phase: "decode", reason: "invalid-signature" })),
                },
            };
            let tx_type = raw.first().copied().filter(|b| *b < 0x80).unwrap_or(0);
            let built = OpTx::from_encoded_tx(&envelope, sender, Bytes::from(raw.clone()));
            Ok(Ok((built, TxFacts { tx_type, sender, deposit })))
        }
        "synthetic" => synthetic(tx).map(Ok),
        other => Err(bad(format!("transaction kind {other}"))),
    }
}

fn opt_u128(v: &Value) -> Res<Option<u128>> {
    match v {
        Value::Null => Ok(None),
        Value::String(t) => u128::try_from(parse_u256(t)?).map(Some).map_err(|_| bad("fee above 128 bits")),
        _ => Err(bad("fee field")),
    }
}

fn synthetic(tx: &Value) -> Res<(MegaTransaction, TxFacts)> {
    use alloy_eips::eip7702::{Authorization, RecoveredAuthority, RecoveredAuthorization};
    let tx_type = parse_u64(text(tx, "type")?)? as u8;
    let sender = parse_address(text(tx, "sender")?)?;
    let kind = match member(tx, "to")? {
        Value::Null => TxKind::Create,
        Value::String(t) => TxKind::Call(parse_address(t)?),
        _ => return Err(bad("to")),
    };
    let chain_id = match member(tx, "chainId")? {
        Value::Null => None,
        Value::String(t) => Some(parse_u64(t)?),
        _ => return Err(bad("chainId")),
    };
    let (gas_price, priority) = match tx_type {
        0 | 1 => (opt_u128(member(tx, "gasPrice")?)?.unwrap_or_default(), None),
        _ => (
            opt_u128(member(tx, "maxFeePerGas")?)?.unwrap_or_default(),
            opt_u128(member(tx, "maxPriorityFeePerGas")?)?,
        ),
    };
    let Value::Array(access) = member(tx, "accessList")? else { return Err(bad("accessList")) };
    let mut access_list = Vec::new();
    for e in access {
        let Value::Array(keys) = member(e, "storageKeys")? else { return Err(bad("storageKeys")) };
        let keys = keys.iter().map(|k| parse_b256(k.as_str().unwrap_or_default())).collect::<Res<Vec<_>>>()?;
        access_list.push(alloy_eips::eip2930::AccessListItem { address: parse_address(text(e, "address")?)?, storage_keys: keys });
    }
    let Value::Array(auths) = member(tx, "authorizationList")? else { return Err(bad("authorizationList")) };
    let mut recovered = Vec::new();
    for a in auths {
        let authority = match member(a, "authority")? {
            Value::Null => RecoveredAuthority::Invalid,
            Value::String(t) => RecoveredAuthority::Valid(parse_address(t)?),
            _ => return Err(bad("authority")),
        };
        recovered.push(RecoveredAuthorization::new_unchecked(
            Authorization {
                chain_id: parse_u256(text(a, "chainId")?)?,
                address: parse_address(text(a, "address")?)?,
                nonce: parse_u64(text(a, "nonce")?)?,
            },
            authority,
        ));
    }
    let mut builder = TxEnv::builder()
        .tx_type(Some(tx_type))
        .caller(sender)
        .kind(kind)
        .data(Bytes::from(parse_bytes(text(tx, "data")?)?))
        .value(parse_u256(text(tx, "value")?)?)
        .gas_limit(parse_u64(text(tx, "gasLimit")?)?)
        .gas_price(gas_price)
        .gas_priority_fee(priority)
        .chain_id(chain_id)
        .nonce(parse_u64(text(tx, "nonce")?)?)
        .access_list(alloy_eips::eip2930::AccessList(access_list));
    if tx_type == 4 {
        builder = builder.authorization_list_recovered(recovered);
    }
    let base = builder.build_fill();
    // A synthetic message has no envelope: it is priced for L1 data as an empty one.
    let built = OpTx(op_revm::OpTransaction { base, enveloped_tx: Some(Bytes::new()), deposit: Default::default() });
    Ok((built, TxFacts { tx_type, sender, deposit: false }))
}

fn block_env(block: &Value) -> Res<BlockEnv> {
    if flag(block, "depositOnly")? || flag(block, "activation")? {
        return Err(Fail::Unsupported("engine isolation of a deposit-only or activation block".into()));
    }
    let base_fee = parse_u256(text(block, "baseFee")?)?;
    let blob = parse_u256(text(block, "blobBaseFee")?)?;
    Ok(BlockEnv {
        number: U256::from(parse_u64(text(block, "number")?)?),
        beneficiary: parse_address(text(block, "coinbase")?)?,
        timestamp: U256::from(parse_u64(text(block, "timestamp")?)?),
        gas_limit: parse_u64(text(block, "gasLimit")?)?,
        basefee: u64::try_from(base_fee).map_err(|_| bad("base fee above 64 bits"))?,
        difficulty: U256::ZERO,
        prevrandao: Some(parse_b256(text(block, "prevRandao")?)?),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice {
            excess_blob_gas: 0,
            blob_gasprice: u128::try_from(blob).map_err(|_| bad("blob base fee"))?,
        }),
        slot_num: parse_u64(text(block, "slotNumber")?)?,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------------------------
// Instrumentation

/// The instrumented run's recorder: it follows every frame start and end. It changes nothing;
/// the run's observations must equal the plain run's.
#[derive(Default)]
struct FrameRecorder {
    open: usize,
    frames: u64,
}

impl<CTX> Inspector<CTX, EthInterpreter> for FrameRecorder {
    fn call(&mut self, _: &mut CTX, _: &mut CallInputs) -> Option<CallOutcome> {
        self.open += 1;
        self.frames += 1;
        None
    }
    fn call_end(&mut self, _: &mut CTX, _: &CallInputs, _: &mut CallOutcome) {
        self.open -= 1;
    }
    fn create(&mut self, _: &mut CTX, _: &mut CreateInputs) -> Option<CreateOutcome> {
        self.open += 1;
        self.frames += 1;
        None
    }
    fn create_end(&mut self, _: &mut CTX, _: &CreateInputs, _: &mut CreateOutcome) {
        self.open -= 1;
    }
}

// ---------------------------------------------------------------------------------------------
// Running a case

struct Run {
    observations: Value,
    diagnostics: Value,
}

fn context(input: &Value, db: FixtureDb) -> Res<MegaContext<FixtureDb, Envs>> {
    let envs = ExternalEnvs { salt_env: salt(input)?, oracle_env: oracle(input)? };
    let ctx = MegaContext::new_with_external_envs(db, MegaSpecId::SATIN, envs);
    let mut cfg = ctx.mega_cfg().clone();
    cfg.chain_id = parse_u64(text(member(input, "chain")?, "chainId")?)?;
    Ok(ctx.with_cfg(cfg).with_block(block_env(member(input, "block")?)?))
}

type Executed = Result<MegaTransactionOutcome, EVMError<MissingInput, mega_evm::MegaTransactionError>>;

fn run(request: &Value, instrumented: bool) -> Res<Run> {
    if text(request, "profile")? != "state-transition" {
        return Err(Fail::Unsupported(format!("profile {}", text(request, "profile")?)));
    }
    if text(member(request, "specRef")?, "name")? != SPEC {
        return Err(Fail::Unsupported(format!("spec {}", text(member(request, "specRef")?, "name")?)));
    }
    let input = member(request, "input")?;
    for unsupported in ["faults"] {
        if input.get(unsupported).is_some() {
            return Err(Fail::Unsupported(format!("input member {unsupported}")));
        }
    }
    let (mut db, pre) = pre_state(member(input, "pre")?)?;
    for (n, h) in entries(member(input, "blockHashes")?)? {
        db.block_hashes.insert(parse_u64(n)?, parse_b256(h.as_str().ok_or_else(|| bad("block hash"))?)?);
    }
    let ctx = context(input, db)?;
    let (tx, facts) = match transaction(member(input, "transaction")?)? {
        Ok(t) => t,
        Err(refusal) => {
            return Ok(Run { observations: refused(refusal.phase, refusal.reason), diagnostics: obj(vec![]) })
        }
    };
    let (executed, oracle_errors, frames): (Executed, Vec<String>, Option<u64>) = if instrumented {
        let mut evm = MegaEvm::new(ctx).with_inspector(FrameRecorder::default());
        let r = evm.execute_transaction(tx);
        let errors = oracle_errors_of(&evm.ctx().external_envs().oracle_env);
        let rec = evm.inspector();
        if rec.open != 0 {
            return Err(bad("instrumentation: unbalanced frames"));
        }
        (r, errors, Some(rec.frames))
    } else {
        let mut evm = MegaEvm::new(ctx);
        let r = evm.execute_transaction(tx);
        let errors = oracle_errors_of(&evm.ctx().external_envs().oracle_env);
        (r, errors, None)
    };
    if let Some(e) = oracle_errors.first() {
        return Err(bad(e.clone()));
    }
    let observations = match executed {
        Ok(outcome) => executed_observations(&outcome, &facts, &pre)?,
        Err(EVMError::Transaction(e)) => {
            let reason = refusal_reason(&format!("{e:?}")).ok_or_else(|| bad(format!("unmapped refusal {e:?}")))?;
            // A gas limit above what the block has left is a skip at inclusion (SATIN-BLK-013).
            refused(if reason == "gas-limit-exceeds-block" { "inclusion" } else { "validation" }, reason)
        }
        Err(e) => return Err(bad(format!("the implementation failed: {e}"))),
    };
    let diagnostics = match frames {
        Some(n) => obj(vec![("frames", qty_u64(n))]),
        None => obj(vec![]),
    };
    Ok(Run { observations, diagnostics })
}

/// What went wrong with the oracle transcript: a request it does not answer, or an entry no request
/// used (a recorded transcript must be used exactly).
fn oracle_errors_of(oracle: &FixtureOracle) -> Vec<String> {
    let mut errors = oracle.errors.borrow().clone();
    let left = oracle.entries.borrow().len();
    if left > 0 {
        errors.push(format!("{left} oracle transcript entries were not requested"));
    }
    errors
}

/// The refusal reason of an implementation error, by the variant's name.
fn refusal_reason(debug: &str) -> Option<&'static str> {
    const TABLE: [(&str, &str); 16] = [
        ("NonceTooLow", "nonce-too-low"),
        ("NonceTooHigh", "nonce-too-high"),
        ("NonceOverflowInTransaction", "nonce-overflow"),
        ("LackOfFundForMaxFee", "insufficient-funds"),
        ("OverflowPaymentInTransaction", "insufficient-funds"),
        ("GasPriceLessThanBasefee", "fee-cap-below-base-fee"),
        ("PriorityFeeGreaterThanMaxFee", "priority-fee-above-fee-cap"),
        ("CallGasCostMoreThanGasLimit", "intrinsic-gas-too-low"),
        ("GasFloorMoreThanGasLimit", "floor-exceeds-gas-limit"),
        ("CallerGasLimitMoreThanBlock", "gas-limit-exceeds-block"),
        ("InvalidChainId", "chain-id-mismatch"),
        ("MissingChainId", "chain-id-mismatch"),
        ("RejectCallerWithCode", "sender-has-code"),
        ("CreateInitCodeSizeLimit", "initcode-too-large"),
        ("EmptyAuthorizationList", "invalid-authorization-list"),
        ("AuthorizationListInvalidFields", "invalid-authorization-list"),
    ];
    TABLE.iter().find(|(name, _)| debug.contains(name)).map(|(_, r)| *r)
}

fn refused(phase: &str, reason: &str) -> Value {
    obj(vec![
        (
            "outcome",
            obj(vec![
                ("admission", obj(vec![("status", s("refused")), ("phase", s(phase)), ("reasons", Value::Array(vec![s(reason)]))])),
                ("execution", Value::Null),
                ("commit", obj(vec![("status", s("not-committed"))])),
            ]),
        ),
        ("state", obj(vec![("accounts", obj(vec![]))])),
        ("receipt", Value::Null),
        ("gasLedgers", Value::Null),
        ("resources", Value::Null),
        ("limit", Value::Null),
    ])
}

fn executed_observations(o: &MegaTransactionOutcome, facts: &TxFacts, pre: &BTreeMap<Address, PreAccount>) -> Res<Value> {
    if o.limit_stop().is_some() {
        return Err(bad(
            "a limit stop: the implementation reports its dimension and limit, not the scope, call path, operation, \
             phase and commit flags the limit group needs",
        ));
    }
    let failed_deposit = facts.deposit && format!("{:?}", o.result).contains("FailedDeposit");
    let (admission, execution) = match &o.result {
        _ if failed_deposit => ("failed-deposit", Value::Null),
        ExecutionResult::Success { output, .. } => {
            let created = match output {
                Output::Create(_, Some(a)) => address(a),
                _ => Value::Null,
            };
            ("admitted", obj(vec![("status", s("success")), ("output", s(hex_bytes(output.data()))), ("createdAddress", created)]))
        }
        ExecutionResult::Revert { output, .. } => {
            ("admitted", obj(vec![("status", s("revert")), ("output", s(hex_bytes(output))), ("createdAddress", Value::Null)]))
        }
        ExecutionResult::Halt { .. } => {
            ("admitted", obj(vec![("status", s("halt")), ("output", s("0x")), ("createdAddress", Value::Null)]))
        }
    };
    let logs: Vec<Value> = o
        .result
        .logs()
        .iter()
        .map(|l| {
            obj(vec![
                ("address", address(&l.address)),
                ("topics", Value::Array(l.topics().iter().map(b256).collect())),
                ("data", s(hex_bytes(&l.data.data))),
            ])
        })
        .collect();
    let deposit_nonce = if facts.deposit { qty_u64(pre.get(&facts.sender).map_or(0, |a| a.nonce)) } else { Value::Null };
    let receipt = obj(vec![
        ("type", qty_u64(if facts.deposit { 0x7e } else { facts.tx_type as u64 })),
        ("status", s(if o.result.is_success() { "0x1" } else { "0x0" })),
        ("gasUsed", qty_u64(o.gas.gas_used)),
        ("logs", Value::Array(logs)),
        ("depositNonce", deposit_nonce),
        ("depositReceiptVersion", if facts.deposit { qty_u64(1) } else { Value::Null }),
    ]);
    let g = &o.gas;
    let ledgers = obj(vec![
        ("total", qty_u64(g.regular + g.state + g.history)),
        ("regular", qty_u64(g.regular)),
        ("state", qty_u64(g.state)),
        ("history", qty_u64(g.history)),
        ("historyBytes", qty_u64(g.history_bytes)),
        ("refund", qty_u64(o.result.gas().final_refunded())),
        ("floor", qty_u64(g.floor)),
        ("gasUsed", qty_u64(g.gas_used)),
        ("blockGas", qty_u64(g.block_execution_gas())),
    ]);
    let limits = ProtocolLimits::for_spec(MegaSpecId::SATIN).tx_runtime_limits;
    // The implementation reports what the transaction kept in each dimension; at the
    // transaction's end that is its net, which is never negative there.
    let dimension = |limit: u64, used: u64| {
        obj(vec![("limit", qty_u64(limit)), ("net", s(used.to_string())), ("reported", qty_u64(used))])
    };
    let resources = obj(vec![
        ("dataSize", dimension(limits.tx_data_size_limit, o.usage.data_size)),
        ("kvUpdates", dimension(limits.tx_kv_update_limit, o.usage.write_records)),
        ("stateGrowth", dimension(limits.tx_state_growth_limit, o.usage.state_growth)),
    ]);
    Ok(obj(vec![
        (
            "outcome",
            obj(vec![
                ("admission", obj(vec![("status", s(admission))])),
                ("execution", execution),
                ("commit", obj(vec![("status", s("committed"))])),
            ]),
        ),
        ("state", state_diff(o, pre)?),
        ("receipt", receipt),
        ("gasLedgers", ledgers),
        ("resources", resources),
        ("limit", Value::Null),
    ]))
}

/// The state diff: every account whose existence, nonce, balance, code or storage differs from
/// the pre-state, as the journal leaves it once the transaction is committed (EIP-161 removes a
/// touched empty account; a destroyed account is removed).
fn state_diff(o: &MegaTransactionOutcome, pre: &BTreeMap<Address, PreAccount>) -> Res<Value> {
    let mut out = BTreeMap::new();
    for (a, acc) in o.state.iter() {
        if !acc.is_touched() {
            continue;
        }
        let before = pre.get(a);
        let exists = !acc.is_selfdestructed() && !acc.is_empty();
        if !exists {
            if before.is_some() {
                out.insert(hex_bytes(a.as_slice()), Value::Null);
            }
            continue;
        }
        let code = match &acc.info.code {
            Some(c) => c.original_bytes().to_vec(),
            None if acc.info.code_hash == revm::primitives::KECCAK_EMPTY => Vec::new(),
            None => before.map(|b| b.code.clone()).ok_or_else(|| bad(format!("{a}: code not loaded")))?,
        };
        let mut slots = BTreeMap::new();
        for (k, slot) in acc.storage.iter() {
            let original = before.and_then(|b| b.storage.get(k).copied()).unwrap_or_default();
            if slot.present_value != original {
                slots.insert(hex_bytes(&k.to_be_bytes::<32>()), qty_u256(slot.present_value));
            }
        }
        let changed = match before {
            None => true,
            Some(b) => b.nonce != acc.info.nonce || b.balance != acc.info.balance || b.code != code || !slots.is_empty(),
        };
        if changed {
            out.insert(
                hex_bytes(a.as_slice()),
                obj(vec![
                    ("nonce", qty_u64(acc.info.nonce)),
                    ("balance", qty_u256(acc.info.balance)),
                    ("code", s(hex_bytes(&code))),
                    ("storage", Value::Object(slots)),
                ]),
            );
        }
    }
    Ok(obj(vec![("accounts", Value::Object(out))]))
}

// ---------------------------------------------------------------------------------------------
// The process interface

fn capabilities() -> Value {
    obj(vec![
        ("format", s("mega-fixture-adapter")),
        ("schemaVersion", s("1.0")),
        ("adapter", obj(vec![("name", s(env!("CARGO_PKG_NAME"))), ("version", s(env!("CARGO_PKG_VERSION")))])),
        (
            "implementation",
            obj(vec![
                ("name", s("mega-evm")),
                ("engine", s("revm")),
                ("repository", s(IMPLEMENTATION_REPOSITORY)),
                ("commit", s(env!("ADAPTER_IMPL_COMMIT"))),
            ]),
        ),
        ("build", obj(vec![("rustc", s(env!("ADAPTER_RUSTC"))), ("profile", s(env!("ADAPTER_PROFILE")))])),
        ("specs", Value::Array(vec![s(SPEC)])),
        ("profiles", Value::Array(vec![s("state-transition")])),
        ("requires", Value::Array(SUPPORTED.iter().map(|r| s(*r)).collect())),
        ("modes", Value::Array(vec![s("plain"), s("instrumented")])),
    ])
}

fn respond(v: &Value) {
    let mut out = json::to_canonical(v);
    out.push(b'\n');
    let _ = std::io::Write::write_all(&mut std::io::stdout(), &out);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let instrumented = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["capabilities"] => {
            respond(&capabilities());
            return ExitCode::SUCCESS;
        }
        ["run"] => false,
        ["run", "--instrumented"] => true,
        _ => {
            eprintln!("usage: adapter-revm capabilities | adapter-revm run [--instrumented]");
            return ExitCode::from(2);
        }
    };
    let mut bytes = Vec::new();
    if std::io::stdin().read_to_end(&mut bytes).is_err() {
        respond(&obj(vec![("status", s("error")), ("error", s("cannot read the run request"))]));
        return ExitCode::FAILURE;
    }
    let request = match json::parse(&bytes) {
        Ok(v) => v,
        Err(e) => {
            respond(&obj(vec![("status", s("error")), ("error", s(format!("run request: {e}")))]));
            return ExitCode::FAILURE;
        }
    };
    let input_digest = request.get("input").map(|i| mega_fixture_format::sha256_digest(&json::to_canonical(i)));
    match run(&request, instrumented) {
        Ok(r) => {
            respond(&obj(vec![
                ("status", s("ok")),
                ("mode", s(if instrumented { "instrumented" } else { "plain" })),
                ("inputDigest", s(input_digest.unwrap_or_default())),
                ("observations", r.observations),
                ("diagnostics", r.diagnostics),
            ]));
            ExitCode::SUCCESS
        }
        Err(Fail::Unsupported(why)) => {
            respond(&obj(vec![("status", s("unsupported")), ("reason", s(why))]));
            ExitCode::SUCCESS
        }
        Err(Fail::Error(why)) => {
            respond(&obj(vec![("status", s("error")), ("error", s(why))]));
            ExitCode::FAILURE
        }
    }
}
