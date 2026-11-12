//! `adapter-evm2`: the fixture adapter of the evm2-based Satin implementation (mega-evm's `next/`
//! workspace on the evm2 fork).
//!
//! The process interface is docs/adapter-protocol.md's: `capabilities`, and `run
//! [--instrumented]` with one run request on standard input. The implementation is driven through
//! the single-transaction EVM its factory makes (`SatinFactory::evm`: Satin's version for the
//! case's chain id, Satin's transaction limits, the production SALT mapping, the live system
//! address resolved from the pre-state), then `Evm::transact`. SALT capacities come from the
//! case's `salt` input as a snapshot of the parent state. Nothing here is shared with the adapter
//! of the revm-based implementation.
//!
//! A case that requires `group:reads` is answered with what the transaction loaded: the pre-state
//! database and the SALT snapshot record every load that reaches them while the transaction runs,
//! in plain and instrumented runs alike, and a run builds them afresh, so the first load of each
//! item is what the run read (docs/adapter-protocol.md, "Reads").
//!
//! A case that requires `group:gas-pools` is answered with the pools of the transaction's first
//! message, read by a passive recorder at the message's start and end, in plain and instrumented
//! runs alike (docs/adapter-protocol.md, "Gas pools").

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use alloy_consensus::{
    transaction::{Recovered, SignerRecoverable},
    Transaction as _,
    TxEip1559, TxEip2930, TxEip7702, TxEnvelope, TxLegacy,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_rlp::{Decodable, Header};
use evm2::{
    bytecode::Bytecode,
    env::BlockEnv,
    evm::{AccountInfo, Database},
    inspector::Inspector,
    interpreter::{Interpreter, Message, MessageResult, Word},
    registry::HandlerError,
    TxResult,
};
use mega_evm2::{
    chain::{BootstrapInput, ChainConfig},
    factory::SatinFactory,
    oracle::{OracleAnswers, OracleServices, RecordingOracle},
    BucketId, MegaTypes, SaltReadError, SaltSnapshot, SnapshotId, MIN_BUCKET_SIZE,
};
use mega_fixture_format::json::{self, Value};
use op_evm2::{OpTxEnvelope, TxDeposit};

const SPEC: &str = "megaeth/Satin";
const IMPLEMENTATION_REPOSITORY: &str = "https://github.com/RealiCZ/mega-evm";
const FORK_REPOSITORY: &str = "https://github.com/RealiCZ/evm2";

/// What this adapter can run: state-transition's mandatory groups and the features below. The
/// oracle transcript is not among them: this adapter's service records hints but supplies no
/// answers, so Oracle reads use the slot's value.
const CAPABILITIES: &[&str] = &[
    "feature:deposit",
    "feature:salt",
    "feature:synthetic-transaction",
    "group:gas-ledgers",
    "group:gas-pools",
    "group:limit",
    "group:limit-stop",
    "group:outcome",
    "group:reads",
    "group:receipts",
    "group:resources",
    "group:state",
];

/// The outcome of handling a request that is not a successful run.
#[derive(Debug)]
enum Stop {
    Unsupported(String),
    Error(String),
}

fn error<T>(msg: impl Into<String>) -> Result<T, Stop> {
    Err(Stop::Error(msg.into()))
}

// ---------------------------------------------------------------------------------------------
// Reading the request

struct Reader<'a>(&'a Value, &'static str);

impl<'a> Reader<'a> {
    fn at(&self, key: &'static str) -> Result<Reader<'a>, Stop> {
        match self.0.get(key) {
            Some(v) => Ok(Reader(v, key)),
            None => error(format!("request: no {key:?} under {:?}", self.1)),
        }
    }
    fn opt(&self, key: &'static str) -> Option<Reader<'a>> {
        self.0.get(key).map(|v| Reader(v, key))
    }
    fn str(&self) -> Result<&'a str, Stop> {
        self.0.as_str().ok_or_else(|| Stop::Error(format!("request: {:?} is not a string", self.1)))
    }
    fn is_null(&self) -> bool {
        matches!(self.0, Value::Null)
    }
    fn boolean(&self) -> Result<bool, Stop> {
        match self.0 {
            Value::Bool(b) => Ok(*b),
            _ => error(format!("request: {:?} is not a boolean", self.1)),
        }
    }
    fn map(&self) -> Result<&'a BTreeMap<String, Value>, Stop> {
        match self.0 {
            Value::Object(m) => Ok(m),
            _ => error(format!("request: {:?} is not an object", self.1)),
        }
    }
    fn list(&self) -> Result<&'a [Value], Stop> {
        match self.0 {
            Value::Array(a) => Ok(a),
            _ => error(format!("request: {:?} is not an array", self.1)),
        }
    }
    fn word(&self) -> Result<U256, Stop> {
        word(self.str()?)
    }
    fn u64(&self) -> Result<u64, Stop> {
        let w = self.word()?;
        w.try_into().or_else(|_| error(format!("request: {:?} does not fit 64 bits", self.1)))
    }
    fn u128(&self) -> Result<u128, Stop> {
        let w = self.word()?;
        w.try_into().or_else(|_| error(format!("request: {:?} does not fit 128 bits", self.1)))
    }
    fn bytes(&self) -> Result<Vec<u8>, Stop> {
        unhex(self.str()?)
    }
    fn address(&self) -> Result<Address, Stop> {
        let b = self.bytes()?;
        if b.len() != 20 {
            return error(format!("request: {:?} is not an address", self.1));
        }
        Ok(Address::from_slice(&b))
    }
    fn hash(&self) -> Result<B256, Stop> {
        let b = self.bytes()?;
        if b.len() != 32 {
            return error(format!("request: {:?} is not 32 bytes", self.1));
        }
        Ok(B256::from_slice(&b))
    }
}

fn word(t: &str) -> Result<U256, Stop> {
    match t.strip_prefix("0x").map(|d| U256::from_str_radix(d, 16)) {
        Some(Ok(v)) => Ok(v),
        _ => error(format!("request: {t:?} is not a quantity")),
    }
}

fn unhex(t: &str) -> Result<Vec<u8>, Stop> {
    let Some(d) = t.strip_prefix("0x") else { return error(format!("request: {t:?} is not hex")) };
    let mut out = Vec::with_capacity(d.len() / 2);
    for pair in d.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(pair).unwrap_or("zz");
        match u8::from_str_radix(pair, 16) {
            Ok(b) => out.push(b),
            Err(_) => return error(format!("request: {t:?} is not hex")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Writing observations

fn hexs(b: &[u8]) -> Value {
    let mut out = String::from("0x");
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    Value::String(out)
}

fn q<T: std::fmt::LowerHex>(v: T) -> Value {
    Value::String(format!("{v:#x}"))
}

fn str_value(t: &str) -> Value {
    Value::String(t.to_string())
}

fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

// ---------------------------------------------------------------------------------------------
// The pre-state

/// The case's complete pre-state, served to the engine: a block hash it does not list is a missing
/// input.
#[derive(Debug, Default)]
struct PreState {
    accounts: HashMap<Address, AccountInfo>,
    code: HashMap<B256, Bytecode>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<u64, B256>,
    loaded: Loads,
}

/// What the transaction loaded from the case's inputs, each item as its first load served it:
/// accounts (`None`: absent) with their nonce, balance and code hash, slots, code hashes, block
/// hashes and SALT capacities. Loads are recorded once `recording` is set, when the transaction
/// starts: the factory's own reads when it makes the EVM, the live system address resolved off the
/// registry, are the block's (SATIN-REG-002), not the transaction's. An account or slot the factory
/// loaded first and the transaction loads again is served by the EVM's cache; the transaction's
/// returned state names it, and `reads` adds it from there.
#[derive(Debug, Default)]
struct Loaded {
    recording: bool,
    accounts: BTreeMap<Address, Option<(u64, U256, B256)>>,
    storage: BTreeMap<(Address, U256), U256>,
    codes: BTreeSet<B256>,
    block_hashes: BTreeMap<u64, B256>,
    buckets: BTreeMap<u64, u64>,
    before_accounts: BTreeMap<Address, Option<(u64, U256, B256)>>,
    before_slots: BTreeMap<(Address, U256), U256>,
}

/// The recorder the database and the SALT snapshot of one run share.
type Loads = Rc<RefCell<Loaded>>;

#[derive(Debug)]
struct Missing(String);

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing input: {}", self.0)
    }
}

impl std::error::Error for Missing {}

impl Database for PreState {
    type Error = Missing;
    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        let info = self.accounts.get(address).cloned();
        let mut l = self.loaded.borrow_mut();
        let seen = info.as_ref().map(|i| (i.nonce, i.balance, i.code_hash));
        if l.recording {
            l.accounts.entry(*address).or_insert(seen);
        } else {
            l.before_accounts.entry(*address).or_insert(seen);
        }
        Ok(info)
    }
    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        let code = self.code.get(code_hash).cloned().ok_or_else(|| Missing(format!("code {code_hash}")))?;
        let mut l = self.loaded.borrow_mut();
        if l.recording {
            l.codes.insert(*code_hash);
        }
        Ok(code)
    }
    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Self::Error> {
        let value = self.storage.get(&(*address, *key)).copied().unwrap_or(U256::ZERO);
        let mut l = self.loaded.borrow_mut();
        if l.recording {
            l.storage.entry((*address, *key)).or_insert(value);
        } else {
            l.before_slots.entry((*address, *key)).or_insert(value);
        }
        Ok(value)
    }
    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Self::Error> {
        let n: u64 = (*number).try_into().map_err(|_| Missing(format!("block hash {number}")))?;
        let hash = self.block_hashes.get(&n).copied().ok_or_else(|| Missing(format!("block hash {n}")))?;
        let mut l = self.loaded.borrow_mut();
        if l.recording {
            l.block_hashes.entry(n).or_insert(hash);
        }
        Ok(hash)
    }
}

/// The case's SALT input as the implementation reads it: a snapshot of the parent state's bucket
/// capacities. A listed bucket has its capacity; an unlisted one has the minimum capacity when the
/// input is complete, and is otherwise a missing input, as is every bucket of a case without
/// `salt` (docs/format.md). The first bucket refused is kept, to report the missing input by name.
struct FixtureSalt {
    id: SnapshotId,
    buckets: HashMap<u64, u64>,
    complete: bool,
    refused: Cell<Option<u64>>,
    loaded: Loads,
}

impl FixtureSalt {
    fn read(salt: Option<Reader<'_>>, parent_hash: B256) -> Result<Self, Stop> {
        let mut snapshot = FixtureSalt {
            id: SnapshotId { parent_hash, state_root: B256::ZERO },
            buckets: HashMap::new(),
            complete: false,
            refused: Cell::new(None),
            loaded: Loads::default(),
        };
        if let Some(salt) = salt {
            if salt.at("mapping")?.str()? != "salt-v1" {
                return Err(Stop::Unsupported("a SALT mapping other than salt-v1".into()));
            }
            for (id, capacity) in salt.at("buckets")?.map()? {
                let id: u64 = word(id)?.try_into().or_else(|_| error("bucket id"))?;
                snapshot.buckets.insert(id, Reader(capacity, "capacity").u64()?);
            }
            snapshot.complete = salt.at("complete")?.boolean()?;
        }
        Ok(snapshot)
    }
}

impl SaltSnapshot for FixtureSalt {
    fn id(&self) -> SnapshotId {
        self.id
    }

    fn capacity(&self, bucket: BucketId) -> Result<u64, SaltReadError> {
        let id = u64::from(bucket);
        let served = match self.buckets.get(&id) {
            Some(capacity) => Some(*capacity),
            None if self.complete => Some(MIN_BUCKET_SIZE),
            None => None,
        };
        if let Some(capacity) = served {
            let mut l = self.loaded.borrow_mut();
            if l.recording {
                l.buckets.entry(id).or_insert(capacity);
            }
        }
        match served {
            Some(capacity) => Ok(capacity),
            None => {
                if self.refused.get().is_none() {
                    self.refused.set(Some(id));
                }
                Err(SaltReadError::Missing)
            }
        }
    }
}

/// The chain the case runs on: Satin and every fork below it active from genesis, at the case's
/// chain id. The registry bootstrap values a validated configuration carries seed a new registry in
/// a block's pre-block sequence, which a single transaction's EVM never runs; these are
/// placeholders and reach no observation.
fn chain(chain_id: u64) -> Result<ChainConfig, Stop> {
    let bootstrap = BootstrapInput {
        initial_sequencer: Some(Address::repeat_byte(0x5e)),
        initial_admin: Some(Address::repeat_byte(0xad)),
        min_rotation_delay: Some(1),
    };
    ChainConfig::satin_from_genesis(chain_id, bootstrap).or_else(|e| error(format!("chain configuration: {e:?}")))
}

/// An account as the case's pre-state lists it.
#[derive(Clone)]
struct Listed {
    nonce: u64,
    balance: U256,
    code: Vec<u8>,
    slots: BTreeMap<U256, U256>,
}

fn load_pre(pre: &Reader<'_>) -> Result<(PreState, BTreeMap<Address, Listed>), Stop> {
    if pre.at("completeness")?.str()? != "complete" {
        return Err(Stop::Unsupported("a pre-state that is not complete".into()));
    }
    let mut db = PreState::default();
    let mut listed = BTreeMap::new();
    for (address, account) in pre.at("accounts")?.map()? {
        let address = Reader(&Value::String(address.clone()), "address").address()?;
        let a = Reader(account, "account");
        let code = a.at("code")?.bytes()?;
        let mut slots = BTreeMap::new();
        for (k, v) in a.at("storage")?.map()? {
            let key = U256::from_be_bytes(Reader(&Value::String(k.clone()), "slot").hash()?.0);
            let value = Reader(v, "value").word()?;
            db.storage.insert((address, key), value);
            slots.insert(key, value);
        }
        let entry = Listed { nonce: a.at("nonce")?.u64()?, balance: a.at("balance")?.word()?, code, slots };
        let mut info = AccountInfo::default().with_balance(entry.balance);
        info.nonce = entry.nonce;
        if !entry.code.is_empty() {
            let bytecode = Bytecode::new_raw_checked(Bytes::from(entry.code.clone()))
                .or_else(|e| error(format!("pre-state code of {address}: {e:?}")))?;
            db.code.insert(bytecode.hash_slow(), bytecode.clone());
            info = info.with_code(bytecode);
        }
        db.accounts.insert(address, info);
        listed.insert(address, entry);
    }
    Ok((db, listed))
}

// ---------------------------------------------------------------------------------------------
// The transaction

struct Sent {
    tx: Recovered<OpTxEnvelope>,
    ty: u8,
    deposit: bool,
}

/// A refusal decided while decoding the bytes, before the engine runs.
struct Undecodable(&'static str);

fn decode_deposit(raw: &[u8]) -> Option<TxDeposit> {
    let mut body = raw.strip_prefix(&[0x7e])?;
    let header = Header::decode(&mut body).ok()?;
    if !header.list || header.payload_length != body.len() {
        return None;
    }
    let source_hash = B256::decode(&mut body).ok()?;
    let from = Address::decode(&mut body).ok()?;
    let to = TxKind::decode(&mut body).ok()?;
    let mint = u128::decode(&mut body).ok()?;
    let value = U256::decode(&mut body).ok()?;
    let gas_limit = u64::decode(&mut body).ok()?;
    let is_system_transaction = bool::decode(&mut body).ok()?;
    let input = Bytes::decode(&mut body).ok()?;
    body.is_empty().then_some(TxDeposit { source_hash, from, to, mint, value, gas_limit, is_system_transaction, input })
}

fn signed(raw: &[u8]) -> Result<Result<Sent, Undecodable>, Stop> {
    let mut rest = raw;
    let Ok(envelope) = TxEnvelope::decode_2718(&mut rest) else { return Ok(Err(Undecodable("malformed-envelope"))) };
    if !rest.is_empty() {
        return Ok(Err(Undecodable("malformed-envelope")));
    }
    let Ok(signer) = envelope.recover_signer() else { return Ok(Err(Undecodable("invalid-signature"))) };
    let enveloped = Some(Bytes::copy_from_slice(raw));
    let (ty, tx) = match envelope {
        TxEnvelope::Legacy(s) => (0, OpTxEnvelope::new(s.strip_signature(), enveloped)),
        TxEnvelope::Eip2930(s) => (1, OpTxEnvelope::new(s.strip_signature(), enveloped)),
        TxEnvelope::Eip1559(s) => (2, OpTxEnvelope::new(s.strip_signature(), enveloped)),
        TxEnvelope::Eip7702(s) => (4, OpTxEnvelope::new(s.strip_signature(), enveloped)),
        _ => return Ok(Err(Undecodable("unsupported-type"))),
    };
    Ok(Ok(Sent { tx: Recovered::new_unchecked(tx, signer), ty, deposit: false }))
}

fn synthetic(t: &Reader<'_>) -> Result<Sent, Stop> {
    let ty = t.at("type")?.u64()? as u8;
    let sender = t.at("sender")?.address()?;
    let to = {
        let to = t.at("to")?;
        if to.is_null() { TxKind::Create } else { TxKind::Call(to.address()?) }
    };
    let chain = t.at("chainId")?;
    let chain_id = if chain.is_null() { None } else { Some(chain.u64()?) };
    let fee = |key: &'static str| -> Result<u128, Stop> {
        let f = t.at(key)?;
        if f.is_null() { Ok(0) } else { f.u128() }
    };
    let nonce = t.at("nonce")?.u64()?;
    let gas_limit = t.at("gasLimit")?.u64()?;
    let value = t.at("value")?.word()?;
    let input = Bytes::from(t.at("data")?.bytes()?);
    let mut access_list = Vec::new();
    for entry in t.at("accessList")?.list()? {
        let e = Reader(entry, "accessList");
        let keys = e.at("storageKeys")?.list()?.iter().map(|k| Reader(k, "storageKey").hash()).collect::<Result<Vec<_>, _>>()?;
        access_list.push(alloy_eips::eip2930::AccessListItem { address: e.at("address")?.address()?, storage_keys: keys });
    }
    let access_list = alloy_eips::eip2930::AccessList(access_list);
    let envelope = Some(Bytes::new()); // a synthetic message has no envelope: no L1 data
    let tx = match ty {
        0 => OpTxEnvelope::new(TxLegacy { chain_id, nonce, gas_price: fee("gasPrice")?, gas_limit, to, value, input }, envelope),
        1 => OpTxEnvelope::new(
            TxEip2930 { chain_id: chain_id.unwrap_or_default(), nonce, gas_price: fee("gasPrice")?, gas_limit, to, value, access_list, input },
            envelope,
        ),
        2 => OpTxEnvelope::new(
            TxEip1559 {
                chain_id: chain_id.unwrap_or_default(),
                nonce,
                gas_limit,
                max_fee_per_gas: fee("maxFeePerGas")?,
                max_priority_fee_per_gas: fee("maxPriorityFeePerGas")?,
                to,
                value,
                access_list,
                input,
            },
            envelope,
        ),
        4 => {
            let TxKind::Call(to) = to else { return error("a type-4 message has a recipient") };
            let mut auths = Vec::new();
            let mut authorities = Vec::new();
            for a in t.at("authorizationList")?.list()? {
                let a = Reader(a, "authorization");
                let inner = alloy_eips::eip7702::Authorization {
                    chain_id: a.at("chainId")?.word()?,
                    address: a.at("address")?.address()?,
                    nonce: a.at("nonce")?.u64()?,
                };
                auths.push(alloy_eips::eip7702::SignedAuthorization::new_unchecked(inner, 0, U256::ZERO, U256::ZERO));
                let who = a.at("authority")?;
                authorities.push(if who.is_null() { None } else { Some(who.address()?) });
            }
            let tx = TxEip7702 {
                chain_id: chain_id.unwrap_or_default(),
                nonce,
                gas_limit,
                max_fee_per_gas: fee("maxFeePerGas")?,
                max_priority_fee_per_gas: fee("maxPriorityFeePerGas")?,
                to,
                value,
                access_list,
                authorization_list: auths,
                input,
            };
            OpTxEnvelope::new(evm2::ethereum::LazyTxEip7702::from_cached_recovered_authorizations(tx, authorities), envelope)
        }
        other => return error(format!("synthetic type {other}")),
    };
    Ok(Sent { tx: Recovered::new_unchecked(tx, sender), ty, deposit: false })
}

fn transaction(t: &Reader<'_>) -> Result<Result<Sent, Undecodable>, Stop> {
    match t.at("kind")?.str()? {
        "signed" => signed(&t.at("raw")?.bytes()?),
        "deposit" => {
            let raw = t.at("raw")?.bytes()?;
            let Some(d) = decode_deposit(&raw) else { return Ok(Err(Undecodable("malformed-envelope"))) };
            let from = d.from;
            Ok(Ok(Sent { tx: Recovered::new_unchecked(OpTxEnvelope::deposit(d), from), ty: 0x7e, deposit: true }))
        }
        "synthetic" => synthetic(t).map(Ok),
        other => error(format!("transaction kind {other}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Instrumentation

/// The instrumented run's recorder: it sees every message start and end and changes nothing.
#[derive(Debug, Default)]
struct Messages {
    depth: i64,
    seen: u64,
    /// The first message's regular gas and reservoir at its start, and its tracker's remaining
    /// gas, reservoir and `state_gas_spilled` at its end (decision D-64).
    start: Option<(u64, u64)>,
    end: Option<(u64, u64, u64)>,
}

impl Messages {
    fn started(&mut self, m: &Message<MegaTypes>) {
        if self.depth == 0 {
            self.start = Some((m.gas_limit, m.reservoir));
        }
        self.depth += 1;
        self.seen += 1;
    }
    fn ended(&mut self, r: &MessageResult<MegaTypes>) {
        self.depth -= 1;
        if self.depth == 0 {
            self.end = Some((r.gas.remaining(), r.gas.reservoir(), r.gas.state_gas_spilled()));
        }
    }
}

impl Inspector<MegaTypes> for Messages {
    fn call(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, m: &mut Message<MegaTypes>) -> Option<MessageResult<MegaTypes>> {
        self.started(m);
        None
    }
    fn call_end(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &Message<MegaTypes>, r: &mut MessageResult<MegaTypes>) {
        self.ended(r);
    }
    fn create(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, m: &mut Message<MegaTypes>) -> Option<MessageResult<MegaTypes>> {
        self.started(m);
        None
    }
    fn create_end(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &Message<MegaTypes>, r: &mut MessageResult<MegaTypes>) {
        self.ended(r);
    }
}

/// The `gasPools` group of the transaction's first message (decision D-64). A transaction that ran
/// no message has no frame pools: what the charges before its first frame left is its reservoir,
/// which returns to the sender, and its regular gas is consumed.
fn pools(m: &Messages, gas_limit: u64, gas_used: u64) -> Result<Value, Stop> {
    let Some(returned) = gas_limit.checked_sub(gas_used) else { return error("gas used above the gas limit") };
    let ((regular, reservoir), (regular_end, reservoir_end, spilled)) = match (m.start, m.end) {
        (Some(s), Some(e)) => (s, e),
        (None, None) => ((0, returned), (0, returned, 0)),
        _ => return error("instrumentation: a first message without its end"),
    };
    let pool = |initial: u64, last: u64| object([("initial", q(initial)), ("final", q(last))]);
    Ok(object([
        ("regular", pool(regular, regular_end)),
        ("reservoir", pool(reservoir, reservoir_end)),
        ("spilled", q(spilled)),
        ("returned", q(returned)),
    ]))
}

// ---------------------------------------------------------------------------------------------
// One run

/// What the engine reported for one account the transaction touched.
struct Touched {
    address: Address,
    current: Option<AccountInfo>,
    new_code: Option<Vec<u8>>,
    selfdestructed: bool,
    slots: Vec<(U256, U256)>,
}

fn reason_of(e: &HandlerError) -> Option<&'static str> {
    Some(match e {
        HandlerError::InvalidNonce { expected, got } if got < expected => "nonce-too-low",
        HandlerError::InvalidNonce { .. } => "nonce-too-high",
        HandlerError::InvalidChainId { .. } | HandlerError::MissingChainId => "chain-id-mismatch",
        HandlerError::IntrinsicGasTooLow { .. } => "intrinsic-gas-too-low",
        HandlerError::GasLimitBelowFloor { .. } => "floor-exceeds-gas-limit",
        HandlerError::InsufficientFunds { .. } => "insufficient-funds",
        HandlerError::RejectCallerWithCode => "sender-has-code",
        HandlerError::NonceOverflow => "nonce-overflow",
        HandlerError::GasLimitMoreThanBlock { .. } => "gas-limit-exceeds-block",
        HandlerError::CreateInitCodeSizeLimit { .. } => "initcode-too-large",
        HandlerError::FeeCapLessThanBaseFee { .. } => "fee-cap-below-base-fee",
        HandlerError::PriorityFeeGreaterThanMaxFee => "priority-fee-above-fee-cap",
        HandlerError::EmptyAuthorizationList => "invalid-authorization-list",
        _ => return None,
    })
}

fn refusal(phase: &str, reason: &str) -> Value {
    object([
        (
            "outcome",
            object([
                ("admission", object([("status", str_value("refused")), ("phase", str_value(phase)), ("reasons", Value::Array(vec![str_value(reason)]))])),
                ("execution", Value::Null),
                ("commit", object([("status", str_value("not-committed"))])),
            ]),
        ),
        ("state", object([("accounts", Value::Object(BTreeMap::new()))])),
        ("receipt", Value::Null),
        ("gasLedgers", Value::Null),
        ("resources", Value::Null),
        ("limit", Value::Null),
    ])
}

fn run(request: &Value, instrumented: bool) -> Result<(Value, Value), Stop> {
    let req = Reader(request, "request");
    let profile = req.at("profile")?.str()?;
    if profile != "state-transition" {
        return Err(Stop::Unsupported(format!("profile {profile}")));
    }
    let spec = req.at("specRef")?.at("name")?.str()?;
    if spec != SPEC {
        return Err(Stop::Unsupported(format!("spec {spec}")));
    }
    let input = req.at("input")?;
    if input.opt("faults").is_some() {
        return Err(Stop::Unsupported("injected faults".into()));
    }
    let oracle = input.opt("oracle");
    if let Some(o) = &oracle {
        if o.at("mode")?.str()? != "disabled" {
            return Err(Stop::Unsupported("a recorded oracle transcript".into()));
        }
    }
    let (mut db, listed) = load_pre(&input.at("pre")?)?;
    for (n, h) in input.at("blockHashes")?.map()? {
        db.block_hashes.insert(word(n)?.try_into().or_else(|_| error("block number"))?, Reader(h, "blockHash").hash()?);
    }
    let block = input.at("block")?;
    if block.at("depositOnly")?.boolean()? || block.at("activation")?.boolean()? {
        return Err(Stop::Unsupported("engine isolation of a deposit-only or activation block".into()));
    }
    let sent = match transaction(&input.at("transaction")?)? {
        Ok(s) => s,
        Err(Undecodable(reason)) => return Ok((refusal("decode", reason), object([]))),
    };

    let factory = SatinFactory::new(chain(input.at("chain")?.at("chainId")?.u64()?)?);
    let env = BlockEnv::<MegaTypes> {
        number: U256::from(block.at("number")?.u64()?),
        timestamp: U256::from(block.at("timestamp")?.u64()?),
        gas_limit: U256::from(block.at("gasLimit")?.u64()?),
        basefee: block.at("baseFee")?.word()?,
        prevrandao: U256::from_be_bytes(block.at("prevRandao")?.hash()?.0),
        blob_basefee: block.at("blobBaseFee")?.word()?,
        slot_num: U256::from(block.at("slotNumber")?.u64()?),
        beneficiary: block.at("coinbase")?.address()?,
        ..BlockEnv::<MegaTypes>::default()
    };
    // The engine's snapshot trait asks for no thread bound and this run is single-threaded; the
    // factory takes the snapshot in an `Arc`.
    #[allow(clippy::arc_with_non_send_sync)]
    let mut salt = FixtureSalt::read(input.opt("salt"), block.at("parentHash")?.hash()?)?;
    let loaded = db.loaded.clone();
    salt.loaded = loaded.clone();
    let wants_reads = matches!(req.at("requires")?.0, Value::Array(r) if r.iter().any(|x| x.as_str() == Some("group:reads")));
    #[allow(clippy::arc_with_non_send_sync)]
    let salt = Arc::new(salt);
    // Record forwarded hints without supplying answers: Oracle reads still use the slot's value.
    let oracle_service = Arc::new(RecordingOracle::new(OracleAnswers::default()));
    // The factory installs Satin's version, limits, registry and precompiles, has storage of an
    // account the database lacks read, and resolves the live system address from the pre-state's
    // SequencerRegistry, as a block resolves it once (SATIN-REG-002).
    let mut evm = match factory.evm(env, evm2::evm::Db::new(db), salt.clone(), OracleServices::service(oracle_service.clone())) {
        Ok(evm) => evm,
        Err(e) => return error(format!("the implementation could not start the transaction's EVM: {e:?}")),
    };
    let wants_pools = matches!(req.at("requires")?.0, Value::Array(r) if r.iter().any(|x| x.as_str() == Some("group:gas-pools")));
    if instrumented || wants_pools {
        evm.set_inspector(Messages::default());
    }
    loaded.borrow_mut().recording = true;

    let missing_bucket = |salt: &FixtureSalt| salt.refused.get().map(|b| format!("missing input: SALT bucket {b:#x}"));
    let executed = match evm.transact(&sent.tx) {
        Ok(executed) => executed,
        // A capacity the snapshot could not give fails the transaction as an internal error.
        Err(_) if salt.refused.get().is_some() => return error(missing_bucket(&salt).unwrap_or_default()),
        Err(e) if mega_evm2::error::database_error(&e).is_some() => {
            return error(format!("the implementation could not read its input: {e:?}"))
        }
        Err(e) => match reason_of(&e) {
            // A gas limit above what the block has left is a skip at inclusion (SATIN-BLK-013).
            Some(reason) => {
                let phase = if reason == "gas-limit-exceeds-block" { "inclusion" } else { "validation" };
                return Ok((refusal(phase, reason), object([])));
            }
            None => return error(format!("unmapped refusal or failure: {e:?}")),
        },
    };
    // What the factory loaded first and the transaction loaded again, which the EVM's cache served.
    {
        let mut l = loaded.borrow_mut();
        for c in executed.account_changes() {
            if !l.accounts.contains_key(&c.address) {
                if let Some(seen) = l.before_accounts.get(&c.address).copied() {
                    l.accounts.insert(c.address, seen);
                }
            }
            for key in c.storage.slots.keys() {
                if !l.storage.contains_key(&(c.address, *key)) {
                    if let Some(value) = l.before_slots.get(&(c.address, *key)).copied() {
                        l.storage.insert((c.address, *key), value);
                    }
                }
            }
        }
    }
    let touched: Vec<Touched> = executed
        .account_changes()
        .filter(|c| c.touched)
        .map(|c| Touched {
            address: c.address,
            current: c.current.cloned(),
            new_code: c.code.map(|(_, b)| b.original_bytes().to_vec()),
            selfdestructed: c.selfdestructed,
            slots: c.storage.changed_slots().map(|(k, s)| (*k, s.current)).collect(),
        })
        .collect();
    let r: TxResult<MegaTypes> = executed.commit();
    let recorded = if instrumented || wants_pools {
        let m = evm.clear_inspector_as::<Messages>().ok_or_else(|| Stop::Error("instrumentation: recorder lost".into()))?;
        if m.depth != 0 {
            return error("instrumentation: unbalanced messages");
        }
        Some(m)
    } else {
        None
    };
    let diagnostics = match (&recorded, instrumented) {
        (Some(m), true) => object([("messages", q(m.seen))]),
        _ => object([]),
    };
    let gas_pools = match (&recorded, wants_pools) {
        (Some(m), true) => Some(pools(m, sent.tx.gas_limit(), r.tx_gas_used())?),
        _ => None,
    };
    let ext = evm.ext();
    if oracle.is_none() && ext.oracle_reads > 0 {
        return error("missing input: the transaction asked the oracle service and the case states no oracle input");
    }
    if let Some(missing) = missing_bucket(&salt) {
        return error(missing);
    }
    // The `limit` group: the stop the implementation reports for the transaction's own frame, when the
    // frame's result is that stop's revert (a stop a caller caught, or a contract's own revert with the
    // same bytes, is none: SATIN-STOP-021), by its kind and limit, with the frame's return data. The
    // implementation reports no scope, call path, operation, phase or commit flag, so the stop carries
    // no diagnostics (decision D-62).
    let limit = match ext.top_stop {
        Some((k, l)) if !r.status && r.is_revert() && r.output.as_ref() == mega_evm2::limit_exceeded_output(k, l).as_slice() => {
            let dimension = match k {
                0 => "data-size",
                1 => "kv-updates",
                2 => "compute",
                3 => "state-growth",
                _ => return error(format!("a limit stop of kind {k}")),
            };
            object([("dimension", str_value(dimension)), ("limit", q(l)), ("returnData", hexs(&r.output))])
        }
        _ => Value::Null,
    };
    let mut observations = observe(&r, ext, &sent, &listed, &touched);
    if let Value::Object(m) = &mut observations {
        m.insert("limit".into(), limit);
        if let Some(p) = gas_pools {
            m.insert("gasPools".into(), p);
        }
    }
    if wants_reads {
        if let Value::Object(m) = &mut observations {
            m.insert("reads".into(), reads(&loaded.borrow(), &listed, &oracle_service.hints()));
        }
    }
    Ok((observations, diagnostics))
}

/// The `reads` group: what the transaction loaded, each item as the case's inputs served it. The
/// code hashes are those of every account read whose code is not empty, with any code loaded by
/// hash: the code the witness holds for every account it names, whether or not the load that named
/// the account brought the code (SATIN-WIT-001). The implementation answers no oracle read from a
/// service in the cases this adapter runs (no transcript), so `oracle` is empty; `hints` are the
/// hints the implementation forwarded, in order.
fn reads(l: &Loaded, listed: &BTreeMap<Address, Listed>, hints: &[(Address, B256, Bytes)]) -> Value {
    let mut codes = l.codes.clone();
    let accounts = l
        .accounts
        .iter()
        .map(|(a, seen)| {
            let v = match seen {
                None => Value::Null,
                Some((nonce, balance, code_hash)) => {
                    if listed.get(a).is_some_and(|p| !p.code.is_empty()) {
                        codes.insert(*code_hash);
                    }
                    object([("nonce", q(*nonce)), ("balance", q(*balance)), ("codeHash", hexs(code_hash.as_slice()))])
                }
            };
            (format!("{a:#x}"), v)
        })
        .collect();
    let mut storage: BTreeMap<String, Value> = BTreeMap::new();
    for ((a, k), v) in &l.storage {
        if let Value::Object(slots) = storage.entry(format!("{a:#x}")).or_insert_with(|| Value::Object(BTreeMap::new())) {
            slots.insert(format!("{:#066x}", k), q(*v));
        }
    }
    object([
        ("accounts", Value::Object(accounts)),
        ("storage", Value::Object(storage)),
        ("codes", Value::Array(codes.iter().map(|c| hexs(c.as_slice())).collect())),
        ("blockHashes", Value::Object(l.block_hashes.iter().map(|(n, h)| (format!("{n:#x}"), hexs(h.as_slice()))).collect())),
        ("buckets", Value::Object(l.buckets.iter().map(|(b, c)| (format!("{b:#x}"), q(*c))).collect())),
        ("oracle", Value::Array(Vec::new())),
        (
            "hints",
            Value::Array(
                hints
                    .iter()
                    .map(|(f, t, d)| object([("from", hexs(f.as_slice())), ("topic", hexs(t.as_slice())), ("data", hexs(d))]))
                    .collect(),
            ),
        ),
    ])
}

fn observe(r: &TxResult<MegaTypes>, ext: &mega_evm2::Lite, sent: &Sent, listed: &BTreeMap<Address, Listed>, touched: &[Touched]) -> Value {
    let failed_deposit = ext.failed_deposit;
    let execution = if failed_deposit {
        Value::Null
    } else if r.status {
        let created = r.created_address.map_or(Value::Null, |a| hexs(a.as_slice()));
        object([("status", str_value("success")), ("output", hexs(&r.output)), ("createdAddress", created)])
    } else if r.is_revert() {
        object([("status", str_value("revert")), ("output", hexs(&r.output)), ("createdAddress", Value::Null)])
    } else {
        object([("status", str_value("halt")), ("output", str_value("0x")), ("createdAddress", Value::Null)])
    };
    let admission = if failed_deposit { "failed-deposit" } else { "admitted" };
    let logs = r
        .logs
        .iter()
        .map(|l| {
            object([
                ("address", hexs(l.address.as_slice())),
                ("topics", Value::Array(l.topics().iter().map(|t| hexs(t.as_slice())).collect())),
                ("data", hexs(&l.data.data)),
            ])
        })
        .collect();
    let sender_nonce = listed.get(&sent.tx.signer()).map_or(0, |a| a.nonce);
    let receipt = object([
        ("type", q(sent.ty)),
        ("status", str_value(if r.status { "0x1" } else { "0x0" })),
        ("gasUsed", q(r.tx_gas_used())),
        ("logs", Value::Array(logs)),
        ("depositNonce", if sent.deposit { q(sender_nonce) } else { Value::Null }),
        ("depositReceiptVersion", if sent.deposit { q(1u8) } else { Value::Null }),
    ]);
    // The engine books history gas as state gas (both draw the reservoir); its extension keeps
    // the history part apart.
    let (history, history_bytes) = ext.history(r.status);
    let state_and_history = r.state_gas_spent;
    let ledgers = object([
        ("total", q(r.total_gas_spent)),
        ("regular", q(r.total_gas_spent - state_and_history)),
        ("state", q(state_and_history - history)),
        ("history", q(history)),
        ("historyBytes", q(history_bytes)),
        ("refund", q(r.final_refunded())),
        ("floor", q(r.floor_gas)),
        ("gasUsed", q(r.tx_gas_used())),
        ("blockGas", q(r.execution_gas_spent())),
    ]);
    let reported = ext.usage(r.status);
    let net = |i: usize| -> i64 {
        let kept = if r.status { ext.frames.first().map_or(0, |f| f.net[i]) } else { 0 };
        ext.tx_net[i] + if i == 2 { ext.tx_growth } else { 0 } + kept
    };
    let dimension = |i: usize| object([("limit", q(ext.limits.tx[i])), ("net", Value::String(net(i).to_string())), ("reported", q(reported[i]))]);
    let resources = object([("dataSize", dimension(0)), ("kvUpdates", dimension(1)), ("stateGrowth", dimension(2))]);
    object([
        (
            "outcome",
            object([
                ("admission", object([("status", str_value(admission))])),
                ("execution", execution),
                ("commit", object([("status", str_value("committed"))])),
            ]),
        ),
        ("state", diff(listed, touched)),
        ("receipt", receipt),
        ("gasLedgers", ledgers),
        ("resources", resources),
        ("limit", Value::Null),
    ])
}

/// The state diff against the case's pre-state. An account the transaction leaves destroyed, or
/// empty under EIP-161, does not exist afterwards.
fn diff(listed: &BTreeMap<Address, Listed>, touched: &[Touched]) -> Value {
    let mut accounts = BTreeMap::new();
    for t in touched {
        let before = listed.get(&t.address);
        let after = t.current.as_ref().filter(|c| {
            !t.selfdestructed && !(c.nonce == 0 && c.balance.is_zero() && c.code_hash == alloy_primitives::KECCAK256_EMPTY)
        });
        let key = format!("{:#x}", t.address);
        let Some(after) = after else {
            if before.is_some() {
                accounts.insert(key, Value::Null);
            }
            continue;
        };
        let code = match (&t.new_code, &after.code, before) {
            (Some(c), _, _) => c.clone(),
            _ if after.code_hash == alloy_primitives::KECCAK256_EMPTY => Vec::new(),
            (None, Some(c), _) => c.original_bytes().to_vec(),
            (None, None, Some(b)) => b.code.clone(),
            (None, None, None) => Vec::new(),
        };
        let mut slots = BTreeMap::new();
        for (k, v) in &t.slots {
            let was = before.and_then(|b| b.slots.get(k)).copied().unwrap_or(U256::ZERO);
            if *v != was {
                slots.insert(format!("0x{}", hex32(k)), q(*v));
            }
        }
        let changed = before.is_none_or(|b| b.nonce != after.nonce || b.balance != after.balance || b.code != code || !slots.is_empty());
        if changed {
            accounts.insert(
                key,
                object([("nonce", q(after.nonce)), ("balance", q(after.balance)), ("code", hexs(&code)), ("storage", Value::Object(slots))]),
            );
        }
    }
    object([("accounts", Value::Object(accounts))])
}

fn hex32(k: &U256) -> String {
    k.to_be_bytes::<32>().iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------

fn capabilities() -> Value {
    object([
        ("format", str_value("mega-fixture-adapter")),
        ("schemaVersion", str_value("1.0")),
        ("adapter", object([("name", str_value(env!("CARGO_PKG_NAME"))), ("version", str_value(env!("CARGO_PKG_VERSION")))])),
        (
            "implementation",
            object([
                ("name", str_value("mega-evm2")),
                ("engine", str_value("evm2")),
                ("repository", str_value(IMPLEMENTATION_REPOSITORY)),
                ("commit", str_value(env!("ADAPTER_IMPL_COMMIT"))),
                ("evm2Repository", str_value(FORK_REPOSITORY)),
                ("evm2Commit", str_value(env!("ADAPTER_FORK_COMMIT"))),
            ]),
        ),
        ("build", object([("rustc", str_value(env!("ADAPTER_RUSTC"))), ("profile", str_value(env!("ADAPTER_PROFILE")))])),
        ("specs", Value::Array(vec![str_value(SPEC)])),
        ("profiles", Value::Array(vec![str_value("state-transition")])),
        ("requires", Value::Array(CAPABILITIES.iter().map(|c| str_value(c)).collect())),
        ("modes", Value::Array(vec![str_value("plain"), str_value("instrumented")])),
    ])
}

fn print(v: &Value) {
    let mut bytes = json::to_canonical(v);
    bytes.push(b'\n');
    let _ = std::io::stdout().write_all(&bytes);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let instrumented = match args.as_slice() {
        [c] if c == "capabilities" => {
            print(&capabilities());
            return ExitCode::SUCCESS;
        }
        [r] if r == "run" => false,
        [r, i] if r == "run" && i == "--instrumented" => true,
        _ => {
            eprintln!("usage: adapter-evm2 capabilities | adapter-evm2 run [--instrumented]");
            return ExitCode::from(2);
        }
    };
    let mut bytes = Vec::new();
    let request = match std::io::stdin().read_to_end(&mut bytes).map_err(|e| e.to_string()).and_then(|_| json::parse(&bytes).map_err(|e| e.to_string())) {
        Ok(r) => r,
        Err(e) => {
            print(&object([("status", str_value("error")), ("error", Value::String(format!("run request: {e}")))]));
            return ExitCode::FAILURE;
        }
    };
    let digest = request.get("input").map(|i| mega_fixture_format::sha256_digest(&json::to_canonical(i))).unwrap_or_default();
    match run(&request, instrumented) {
        Ok((observations, diagnostics)) => {
            print(&object([
                ("status", str_value("ok")),
                ("mode", str_value(if instrumented { "instrumented" } else { "plain" })),
                ("inputDigest", Value::String(digest)),
                ("observations", observations),
                ("diagnostics", diagnostics),
            ]));
            ExitCode::SUCCESS
        }
        Err(Stop::Unsupported(why)) => {
            print(&object([("status", str_value("unsupported")), ("reason", Value::String(why))]));
            ExitCode::SUCCESS
        }
        Err(Stop::Error(why)) => {
            print(&object([("status", str_value("error")), ("error", Value::String(why))]));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(input: &str) -> FixtureSalt {
        let v = json::parse(input.as_bytes()).expect("json");
        FixtureSalt::read(Some(Reader(&v, "salt")), B256::ZERO).expect("a SALT input")
    }

    fn bucket(id: u32) -> BucketId {
        BucketId::new(id).expect("a bucket id")
    }

    #[test]
    fn a_listed_bucket_has_its_capacity_and_a_complete_input_the_minimum_elsewhere() {
        let s = salt(r#"{"mapping":"salt-v1","complete":true,"buckets":{"0x10000":"0x400"}}"#);
        assert_eq!(s.capacity(bucket(0x10000)), Ok(0x400));
        assert_eq!(s.capacity(bucket(0x10001)), Ok(MIN_BUCKET_SIZE));
        assert_eq!(s.refused.get(), None);
    }

    #[test]
    fn an_unlisted_bucket_of_an_incomplete_input_is_a_missing_input_named_by_the_first_refusal() {
        let s = salt(r#"{"mapping":"salt-v1","complete":false,"buckets":{"0x10000":"0x400"}}"#);
        assert_eq!(s.capacity(bucket(0x10000)), Ok(0x400));
        assert_eq!(s.capacity(bucket(0x20000)), Err(SaltReadError::Missing));
        assert_eq!(s.capacity(bucket(0x30000)), Err(SaltReadError::Missing));
        assert_eq!(s.refused.get(), Some(0x20000));
    }

    #[test]
    fn a_case_without_salt_states_no_capacity() {
        let s = FixtureSalt::read(None, B256::ZERO).expect("no SALT input");
        assert_eq!(s.capacity(bucket(0x10000)), Err(SaltReadError::Missing));
        assert_eq!(s.refused.get(), Some(0x10000));
    }

    #[test]
    fn another_mapping_is_unsupported() {
        let v = json::parse(br#"{"mapping":"salt-v2","complete":true,"buckets":{}}"#).expect("json");
        assert!(matches!(FixtureSalt::read(Some(Reader(&v, "salt")), B256::ZERO), Err(Stop::Unsupported(_))));
    }
}
