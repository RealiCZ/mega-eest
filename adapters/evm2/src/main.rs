//! `adapter-evm2`: the fixture adapter of the evm2-based Satin implementation (mega-evm's `next/`
//! workspace on the evm2 fork).
//!
//! The process interface is docs/adapter-protocol.md's: `capabilities`, and `run
//! [--instrumented]` with one run request on standard input. The implementation is driven through
//! `Evm::transact` with the configuration its block executor uses (`satin_version`, Satin's
//! transaction limits, the production SALT mapping). Nothing here is shared with the adapter of
//! the revm-based implementation.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::process::ExitCode;

use alloy_consensus::{
    transaction::{Recovered, SignerRecoverable},
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
    Evm, ExecutionConfig, TxResult,
};
use mega_evm2::{MegaSpec, MegaTypes};
use mega_fixture_format::json::{self, Value};
use op_evm2::{OpTxEnvelope, TxDeposit};

const SPEC: &str = "megaeth/Satin";
const IMPLEMENTATION_REPOSITORY: &str = "https://github.com/RealiCZ/mega-evm";
const FORK_REPOSITORY: &str = "https://github.com/RealiCZ/evm2";

/// What this adapter can run: state-transition's mandatory groups and the features below. The
/// oracle transcript is not among them: the implementation's oracle service is a map from slot to
/// value, which can check neither a transcript's order nor an answer of none.
const CAPABILITIES: &[&str] = &[
    "feature:deposit",
    "feature:salt",
    "feature:synthetic-transaction",
    "group:gas-ledgers",
    "group:limit",
    "group:outcome",
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
}

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
        Ok(self.accounts.get(address).cloned())
    }
    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.code.get(code_hash).cloned().ok_or_else(|| Missing(format!("code {code_hash}")))
    }
    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Self::Error> {
        Ok(self.storage.get(&(*address, *key)).copied().unwrap_or(U256::ZERO))
    }
    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Self::Error> {
        let n: u64 = (*number).try_into().map_err(|_| Missing(format!("block hash {number}")))?;
        self.block_hashes.get(&n).copied().ok_or_else(|| Missing(format!("block hash {n}")))
    }
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
}

impl Inspector<MegaTypes> for Messages {
    fn call(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &mut Message<MegaTypes>) -> Option<MessageResult<MegaTypes>> {
        self.depth += 1;
        self.seen += 1;
        None
    }
    fn call_end(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &Message<MegaTypes>, _: &mut MessageResult<MegaTypes>) {
        self.depth -= 1;
    }
    fn create(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &mut Message<MegaTypes>) -> Option<MessageResult<MegaTypes>> {
        self.depth += 1;
        self.seen += 1;
        None
    }
    fn create_end(&mut self, _: &mut Interpreter<'_, '_, MegaTypes>, _: &Message<MegaTypes>, _: &mut MessageResult<MegaTypes>) {
        self.depth -= 1;
    }
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

    let mut version = mega_evm2::satin_version();
    version.chain_id = input.at("chain")?.at("chainId")?.u64()?;
    let config = ExecutionConfig::<MegaTypes>::for_spec_and_version(MegaSpec::Satin, version);
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
    let mut evm = Evm::<MegaTypes>::new_with_execution_config(
        config,
        MegaSpec::Satin,
        env,
        mega_evm2::tx::registry(),
        evm2::evm::Db::new(db),
        mega_evm2::precompiles(),
    );
    evm.state_mut().set_read_absent_storage(true);
    let (salt_known, salt_complete) = match input.opt("salt") {
        None => (false, false),
        Some(salt) => {
            if salt.at("mapping")?.str()? != "salt-v1" {
                return Err(Stop::Unsupported("a SALT mapping other than salt-v1".into()));
            }
            for (id, capacity) in salt.at("buckets")?.map()? {
                let id: u64 = word(id)?.try_into().or_else(|_| error("bucket id"))?;
                evm.ext_mut().cfg.buckets.insert(id, Reader(capacity, "capacity").u64()?);
            }
            (true, salt.at("complete")?.boolean()?)
        }
    };
    evm.ext_mut().limits = mega_evm2::TxLimits::SATIN;
    if instrumented {
        evm.set_inspector(Messages::default());
    }

    let executed = match evm.transact(&sent.tx) {
        Ok(executed) => executed,
        Err(HandlerError::Database(e)) => return error(format!("the implementation could not read its input: {e}")),
        Err(e) => match reason_of(&e) {
            // A gas limit above what the block has left is a skip at inclusion (SATIN-BLK-013).
            Some(reason) => {
                let phase = if reason == "gas-limit-exceeds-block" { "inclusion" } else { "validation" };
                return Ok((refusal(phase, reason), object([])));
            }
            None => return error(format!("unmapped refusal or failure: {e:?}")),
        },
    };
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
    let diagnostics = if instrumented {
        let m = evm.clear_inspector_as::<Messages>().ok_or_else(|| Stop::Error("instrumentation: recorder lost".into()))?;
        if m.depth != 0 {
            return error("instrumentation: unbalanced messages");
        }
        object([("messages", q(m.seen))])
    } else {
        object([])
    };
    let ext = evm.ext();
    if oracle.is_none() && ext.oracle_reads > 0 {
        return error("missing input: the transaction asked the oracle service and the case states no oracle input");
    }
    if salt_known && !salt_complete || !salt_known {
        let listed_buckets: Vec<u64> = ext.cfg.buckets.keys().copied().collect();
        if let Some(b) = ext.bucket_reads.iter().find(|b| !listed_buckets.contains(b)) {
            return error(format!("missing input: SALT bucket {b:#x}"));
        }
    }
    if let Some((k, l)) = ext.top_stop {
        if !r.status && r.output.as_ref() == mega_evm2::limit_exceeded_output(k, l).as_slice() {
            return error(
                "a limit stop: the implementation reports its kind and limit, not the scope, call path, operation, phase \
                 and commit flags the limit group needs",
            );
        }
    }
    Ok((observe(&r, ext, &sent, &listed, &touched), diagnostics))
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
