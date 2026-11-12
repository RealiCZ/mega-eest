//! Typed fixtures: the envelope, the five profiles and the observation groups of schema/*.json.
//!
//! Every type decodes strictly from a [`Value`]: closed objects, checked scalars, tagged unions
//! dispatched on their tag. Decoding is the schema check; [`crate::validate`] adds the semantic
//! checks the schema cannot state.

use crate::decode::*;
use crate::error::{child, Error, ErrorCode};
use crate::json::Value;
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------------------------
// Scalars

/// A 256-bit unsigned integer, big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// A 20-byte address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 20]);

/// 32 bytes: a hash, a root or a storage key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct B256(pub [u8; 32]);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex::encode(&self.0))
    }
}

impl fmt::Display for B256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex::encode(&self.0))
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = crate::hex::encode(&self.0);
        let digits = hex[2..].trim_start_matches('0');
        write!(f, "0x{}", if digits.is_empty() { "0" } else { digits })
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

fn spec_name_ok(s: &str) -> bool {
    let Some((owner, spec)) = s.split_once('/') else { return false };
    name_ok(owner)
        && !spec.is_empty()
        && spec.split(['.', '-']).all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
        && !spec.contains('/')
}

pub(crate) fn case_id_ok(s: &str) -> bool {
    let segments: Vec<&str> = s.split('/').collect();
    s.len() <= 160 && (3..=8).contains(&segments.len()) && segments.iter().all(|seg| name_ok(seg))
}

/// A rule citation: a rule id and, optionally, the first cell of one of its table rows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleRef {
    pub id: String,
    pub row: Option<String>,
}

impl RuleRef {
    pub fn parse(s: &str) -> Option<RuleRef> {
        let (id, row) = match s.split_once('/') {
            Some((id, row)) => (id, Some(row)),
            None => (s, None),
        };
        let parts: Vec<&str> = id.split('-').collect();
        let upper = |p: &str, first_alpha: bool| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                && (!first_alpha || p.as_bytes()[0].is_ascii_uppercase())
        };
        let ok = parts.len() == 3
            && upper(parts[0], true)
            && upper(parts[1], true)
            && parts[2].len() == 3
            && parts[2].bytes().all(|b| b.is_ascii_digit());
        let row_ok = row.map_or(true, |r| !r.is_empty() && !r.contains('/'));
        (ok && row_ok).then(|| RuleRef { id: id.to_string(), row: row.map(str::to_string) })
    }
}

impl fmt::Display for RuleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.row {
            Some(row) => write!(f, "{}/{}", self.id, row),
            None => f.write_str(&self.id),
        }
    }
}

fn rule_ref(v: &Value, p: &str) -> Result<RuleRef> {
    let s = string(v, p)?;
    RuleRef::parse(s).ok_or_else(|| Error::new(ErrorCode::InvalidRuleRef, p, format!("{s:?} is not a rule citation")))
}

fn spec_name(v: &Value, p: &str) -> Result<String> {
    Ok(patterned(v, p, ErrorCode::InvalidValue, spec_name_ok)?.to_string())
}

fn call_path(v: &Value, p: &str) -> Result<Vec<u64>> {
    array(v, p, 0, None, u64q)
}

fn operation(v: &Value, p: &str) -> Result<String> {
    let ok = |s: &str| !s.is_empty() && s.split('-').all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric()));
    Ok(patterned(v, p, ErrorCode::InvalidValue, ok)?.to_string())
}

// ---------------------------------------------------------------------------------------------
// Envelope

/// The five consumer profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Profile {
    StateTransition,
    TransactionValidation,
    BlockImport,
    BlockBuild,
    StatelessBlock,
}

pub const PROFILES: [(&str, Profile); 5] = [
    ("state-transition", Profile::StateTransition),
    ("transaction-validation", Profile::TransactionValidation),
    ("block-import", Profile::BlockImport),
    ("block-build", Profile::BlockBuild),
    ("stateless-block", Profile::StatelessBlock),
];

impl Profile {
    pub fn as_str(self) -> &'static str {
        PROFILES.iter().find(|(_, p)| *p == self).map(|(n, _)| *n).expect("listed")
    }

    /// The profile named `name`.
    pub fn parse(name: &str) -> Option<Profile> {
        PROFILES.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
    }
}

/// An entry of `requires`: an observation group or a format feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Requirement {
    Group(Group),
    Feature(Feature),
}

/// Observation groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Blocks,
    Checkpoints,
    Decisions,
    Detention,
    GasLedgers,
    GasPools,
    Limit,
    LimitDiagnostics,
    LimitStop,
    Outcome,
    Reads,
    Receipts,
    Resources,
    State,
    Validation,
    Witness,
}

/// Format features: input constructs a consumer must support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    Deposit,
    InjectedFaults,
    OracleTranscript,
    ProofAttachment,
    RawChainConfig,
    Salt,
    Schedule,
    SparseState,
    SyntheticTransaction,
}

pub const REQUIREMENTS: [(&str, Requirement); 25] = [
    ("feature:deposit", Requirement::Feature(Feature::Deposit)),
    ("feature:injected-faults", Requirement::Feature(Feature::InjectedFaults)),
    ("feature:oracle-transcript", Requirement::Feature(Feature::OracleTranscript)),
    ("feature:proof-attachment", Requirement::Feature(Feature::ProofAttachment)),
    ("feature:raw-chain-config", Requirement::Feature(Feature::RawChainConfig)),
    ("feature:salt", Requirement::Feature(Feature::Salt)),
    ("feature:schedule", Requirement::Feature(Feature::Schedule)),
    ("feature:sparse-state", Requirement::Feature(Feature::SparseState)),
    ("feature:synthetic-transaction", Requirement::Feature(Feature::SyntheticTransaction)),
    ("group:blocks", Requirement::Group(Group::Blocks)),
    ("group:checkpoints", Requirement::Group(Group::Checkpoints)),
    ("group:decisions", Requirement::Group(Group::Decisions)),
    ("group:detention", Requirement::Group(Group::Detention)),
    ("group:gas-ledgers", Requirement::Group(Group::GasLedgers)),
    ("group:gas-pools", Requirement::Group(Group::GasPools)),
    ("group:limit", Requirement::Group(Group::Limit)),
    ("group:limit-diagnostics", Requirement::Group(Group::LimitDiagnostics)),
    ("group:limit-stop", Requirement::Group(Group::LimitStop)),
    ("group:outcome", Requirement::Group(Group::Outcome)),
    ("group:reads", Requirement::Group(Group::Reads)),
    ("group:receipts", Requirement::Group(Group::Receipts)),
    ("group:resources", Requirement::Group(Group::Resources)),
    ("group:state", Requirement::Group(Group::State)),
    ("group:validation", Requirement::Group(Group::Validation)),
    ("group:witness", Requirement::Group(Group::Witness)),
];

impl Requirement {
    pub fn as_str(self) -> &'static str {
        REQUIREMENTS.iter().find(|(_, r)| *r == self).map(|(n, _)| *n).expect("listed")
    }

    pub fn parse(s: &str) -> Option<Requirement> {
        REQUIREMENTS.iter().find(|(n, _)| *n == s).map(|(_, r)| *r)
    }
}

/// A protocol spec reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecRef {
    pub name: String,
    pub descriptor: String,
}

fn spec_ref(v: &Value, p: &str) -> Result<SpecRef> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["name", "descriptor"], &[])?;
    let (n, np) = o.req("name");
    let (d, dp) = o.req("descriptor");
    Ok(SpecRef { name: spec_name(n, &np)?, descriptor: digest(d, &dp)? })
}

/// An assertion: a pointer into `expected` and the rules it distinguishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub path: String,
    pub rules: Vec<RuleRef>,
}

/// Provenance status (the rest of provenance is open, non-normative metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvenanceStatus {
    Example,
    Candidate,
    Approved,
    Superseded,
}

/// A decoded fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct Fixture {
    pub schema_minor: u32,
    pub case_id: String,
    pub spec_ref: SpecRef,
    pub profile: Profile,
    pub requires: Vec<Requirement>,
    pub rules: Vec<RuleRef>,
    pub assertions: Vec<Assertion>,
    pub body: Body,
    pub provenance_status: ProvenanceStatus,
}

/// The profile-specific input and expected result.
// A fixture is decoded once and held whole; boxing the larger variants would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    StateTransition { input: StateTransitionInput, expected: StateTransitionExpected },
    TransactionValidation { input: ValidationInput, expected: ValidationExpected },
    BlockImport { input: BlockImportInput, expected: BlockImportExpected },
    BlockBuild { input: BlockBuildInput, expected: BlockBuildExpected },
    StatelessBlock { input: StatelessInput, expected: StatelessExpected },
}

pub(crate) const ENVELOPE: [&str; 11] =
    ["format", "schemaVersion", "caseId", "specRef", "profile", "requires", "rules", "assertions", "input", "expected", "provenance"];

impl Fixture {
    /// Decodes a fixture from a parsed value (the schema check; no semantic checks).
    pub fn decode(value: &Value) -> Result<Fixture> {
        let mut o = Obj::new(value, "")?;
        o.shape(&ENVELOPE, &[])?;
        let (v, p) = o.req("format");
        constant(v, &p, "mega-execution-fixture", ErrorCode::UnsupportedFormat)?;
        let (v, p) = o.req("schemaVersion");
        let version = string(v, &p)?;
        let schema_minor = version
            .strip_prefix("1.")
            .filter(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) && (*m == "0" || !m.starts_with('0')))
            .and_then(|m| m.parse::<u32>().ok())
            .ok_or_else(|| Error::new(ErrorCode::UnsupportedSchemaVersion, &p, format!("{version:?} is not schema version 1.x")))?;
        let (v, p) = o.req("caseId");
        let case_id = patterned(v, &p, ErrorCode::InvalidCaseId, case_id_ok)?.to_string();
        let (v, p) = o.req("specRef");
        let spec_ref = spec_ref(v, &p)?;
        let (v, p) = o.req("profile");
        let profile = one_of(v, &p, &PROFILES, ErrorCode::UnknownProfile)?;
        let (v, p) = o.req("requires");
        let requires = array(v, &p, 1, None, |v, p| one_of(v, p, &REQUIREMENTS, ErrorCode::UnknownRequirement))?;
        let (v, p) = o.req("rules");
        let rules = array(v, &p, 1, None, rule_ref)?;
        let (v, p) = o.req("assertions");
        let assertions = array(v, &p, 1, None, assertion)?;
        let (input, ip) = o.req("input");
        let (expected, ep) = o.req("expected");
        let body = match profile {
            Profile::StateTransition => Body::StateTransition {
                input: st_input(input, &ip)?,
                expected: st_expected(expected, &ep)?,
            },
            Profile::TransactionValidation => Body::TransactionValidation {
                input: tv_input(input, &ip)?,
                expected: tv_expected(expected, &ep)?,
            },
            Profile::BlockImport => Body::BlockImport {
                input: bi_input(input, &ip)?,
                expected: bi_expected(expected, &ep)?,
            },
            Profile::BlockBuild => Body::BlockBuild {
                input: bb_input(input, &ip)?,
                expected: bb_expected(expected, &ep)?,
            },
            Profile::StatelessBlock => Body::StatelessBlock {
                input: sb_input(input, &ip)?,
                expected: sb_expected(expected, &ep)?,
            },
        };
        let (v, p) = o.req("provenance");
        let prov = Obj::new(v, &p)?;
        prov.require(&["status"])?;
        let status = one_of(
            v.get("status").expect("required"),
            &child(&p, "status"),
            &[
                ("example", ProvenanceStatus::Example),
                ("candidate", ProvenanceStatus::Candidate),
                ("approved", ProvenanceStatus::Approved),
                ("superseded", ProvenanceStatus::Superseded),
            ],
            ErrorCode::InvalidValue,
        )?;
        Ok(Fixture { schema_minor, case_id, spec_ref, profile, requires, rules, assertions, body, provenance_status: status })
    }
}

fn assertion(v: &Value, p: &str) -> Result<Assertion> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["path", "rules"], &[])?;
    let (pv, pp) = o.req("path");
    let path = patterned(pv, &pp, ErrorCode::UnboundAssertion, |s| s == "/expected" || s.starts_with("/expected/"))?.to_string();
    let (rv, rp) = o.req("rules");
    Ok(Assertion { path, rules: array(rv, &rp, 1, None, rule_ref)? })
}

// ---------------------------------------------------------------------------------------------
// State and external inputs

/// Pre-state completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    Sparse,
    Witness,
}

/// A pre-state account. `storage_complete` is `None` in complete state, where it is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code: Vec<u8>,
    pub storage: BTreeMap<B256, U256>,
    pub storage_complete: Option<bool>,
}

/// A pre-state: complete, sparse or witness. A `None` account is known to be absent (sparse and
/// witness only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub completeness: Completeness,
    pub accounts: BTreeMap<Address, Option<PreAccount>>,
}

fn storage(v: &Value, p: &str) -> Result<BTreeMap<B256, U256>> {
    map(v, p, b256, u256)
}

fn block_hashes(v: &Value, p: &str) -> Result<BTreeMap<u64, B256>> {
    map(v, p, u64q, b256)
}

fn pre_account(v: &Value, p: &str, sparse: bool) -> Result<PreAccount> {
    let mut o = Obj::new(v, p)?;
    if sparse {
        o.shape(&["nonce", "balance", "code", "storage", "storageComplete"], &[])?;
    } else {
        o.shape(&["nonce", "balance", "code", "storage"], &[])?;
    }
    let (n, np) = o.req("nonce");
    let (b, bp) = o.req("balance");
    let (c, cp) = o.req("code");
    let (s, sp) = o.req("storage");
    let storage_complete = match o.opt("storageComplete") {
        Some((v, p)) => Some(boolean(v, &p)?),
        None => None,
    };
    Ok(PreAccount { nonce: u64q(n, &np)?, balance: u256(b, &bp)?, code: bytes(c, &cp)?, storage: storage(s, &sp)?, storage_complete })
}

/// Decodes a state whose completeness must be one of `allowed`.
fn state(v: &Value, p: &str, allowed: &[Completeness]) -> Result<State> {
    let mut o = Obj::new(v, p)?;
    o.require(&["completeness"])?;
    let (cv, cp) = o.req("completeness");
    let completeness = one_of(
        cv,
        &cp,
        &[("complete", Completeness::Complete), ("sparse", Completeness::Sparse), ("witness", Completeness::Witness)],
        ErrorCode::InvalidValue,
    )?;
    o.shape(&["completeness", "accounts"], &[])?;
    let (av, ap) = o.req("accounts");
    let sparse = completeness != Completeness::Complete;
    let accounts = map(av, &ap, address, |v, p| {
        if sparse {
            nullable(v, p, |v, p| pre_account(v, p, true))
        } else {
            pre_account(v, p, false).map(Some)
        }
    })?;
    if !allowed.contains(&completeness) {
        return Err(Error::new(ErrorCode::InvalidValue, cp, "completeness not allowed in this profile"));
    }
    Ok(State { completeness, accounts })
}

/// SALT bucket capacities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Salt {
    pub mapping: String,
    pub complete: bool,
    pub buckets: BTreeMap<u64, u64>,
}

fn salt(v: &Value, p: &str) -> Result<Salt> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["mapping", "complete", "buckets"], &[])?;
    let (m, mp) = o.req("mapping");
    let mapping = one_of(m, &mp, &[("salt-v1", "salt-v1")], ErrorCode::InvalidValue)?.to_string();
    let (c, cp) = o.req("complete");
    let (b, bp) = o.req("buckets");
    Ok(Salt { mapping, complete: boolean(c, &cp)?, buckets: map(b, &bp, u64q, u64q)? })
}

/// The oracle service transcript of an engine-isolation case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Oracle {
    /// Ordered `(slot, answer)`; `None` is the service answering none.
    Recorded(Vec<(B256, Option<U256>)>),
    Disabled,
}

fn oracle(v: &Value, p: &str) -> Result<Oracle> {
    let mut o = Obj::new(v, p)?;
    o.require(&["mode"])?;
    let (m, mp) = o.req("mode");
    let recorded = one_of(m, &mp, &[("recorded", true), ("disabled", false)], ErrorCode::InvalidValue)?;
    if !recorded {
        o.shape(&["mode"], &[])?;
        return Ok(Oracle::Disabled);
    }
    o.shape(&["mode", "entries"], &[])?;
    let (e, ep) = o.req("entries");
    let entries = array(e, &ep, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["slot", "answer"], &[])?;
        let (s, sp) = o.req("slot");
        let (a, ap) = o.req("answer");
        Ok((b256(s, &sp)?, nullable(a, &ap, u256)?))
    })?;
    Ok(Oracle::Recorded(entries))
}

/// The key of a provider read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderRead {
    Account(Address),
    Storage(Address, B256),
    Code(B256),
    BlockHash(u64),
    Bucket(u64),
}

fn provider_read(v: &Value, p: &str) -> Result<ProviderRead> {
    let mut o = Obj::new(v, p)?;
    o.require(&["source"])?;
    let (s, sp) = o.req("source");
    let source = one_of(s, &sp, &[("account", 0), ("storage", 1), ("code", 2), ("block-hash", 3), ("bucket", 4)], ErrorCode::InvalidValue)?;
    Ok(match source {
        0 => {
            o.shape(&["source", "address"], &[])?;
            let (a, ap) = o.req("address");
            ProviderRead::Account(address(a, &ap)?)
        }
        1 => {
            o.shape(&["source", "address", "slot"], &[])?;
            let (a, ap) = o.req("address");
            let (k, kp) = o.req("slot");
            ProviderRead::Storage(address(a, &ap)?, b256(k, &kp)?)
        }
        2 => {
            o.shape(&["source", "codeHash"], &[])?;
            let (h, hp) = o.req("codeHash");
            ProviderRead::Code(b256(h, &hp)?)
        }
        3 => {
            o.shape(&["source", "number"], &[])?;
            let (n, np) = o.req("number");
            ProviderRead::BlockHash(u64q(n, &np)?)
        }
        _ => {
            o.shape(&["source", "bucket"], &[])?;
            let (b, bp) = o.req("bucket");
            ProviderRead::Bucket(u64q(b, &bp)?)
        }
    })
}

fn faults(v: &Value, p: &str) -> Result<Vec<ProviderRead>> {
    array(v, p, 1, None, provider_read)
}

// ---------------------------------------------------------------------------------------------
// Transactions and block context

/// An EIP-2930 access-list entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListEntry {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

/// An EIP-7702 authorization of a synthetic message, its authority already recovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticAuthorization {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: u64,
    pub authority: Option<Address>,
}

/// A synthetic execution message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synthetic {
    pub tx_type: u64,
    pub chain_id: Option<u64>,
    pub nonce: u64,
    pub sender: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub access_list: Vec<AccessListEntry>,
    pub authorization_list: Vec<SyntheticAuthorization>,
}

/// A transaction source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transaction {
    /// Signed EIP-2718 bytes: the sender is recovered from them.
    Signed(Vec<u8>),
    /// An unsigned protocol deposit envelope (type 0x7e).
    Deposit(Vec<u8>),
    /// A pre-recovered message; never counts toward signature or envelope coverage.
    Synthetic(Box<Synthetic>),
}

fn transaction(v: &Value, p: &str, allow_synthetic: bool) -> Result<Transaction> {
    let mut o = Obj::new(v, p)?;
    o.require(&["kind"])?;
    let (k, kp) = o.req("kind");
    let kinds: &[(&str, u8)] =
        if allow_synthetic { &[("signed", 0), ("deposit", 1), ("synthetic", 2)] } else { &[("signed", 0), ("deposit", 1)] };
    let kind = one_of(k, &kp, kinds, ErrorCode::InvalidValue)?;
    if kind < 2 {
        o.shape(&["kind", "raw"], &[])?;
        let (r, rp) = o.req("raw");
        let raw = bytes(r, &rp)?;
        return Ok(if kind == 0 { Transaction::Signed(raw) } else { Transaction::Deposit(raw) });
    }
    o.shape(
        &[
            "kind", "type", "chainId", "nonce", "sender", "to", "value", "data", "gasLimit", "gasPrice",
            "maxFeePerGas", "maxPriorityFeePerGas", "accessList", "authorizationList",
        ],
        &[],
    )?;
    let (t, tp) = o.req("type");
    let tx_type = one_of(t, &tp, &[("0x0", 0u64), ("0x1", 1), ("0x2", 2), ("0x4", 4)], ErrorCode::InvalidValue)?;
    let (v, vp) = o.req("chainId");
    let chain_id = nullable(v, &vp, u64q)?;
    let (v, vp) = o.req("nonce");
    let nonce = u64q(v, &vp)?;
    let (v, vp) = o.req("sender");
    let sender = address(v, &vp)?;
    let (v, vp) = o.req("to");
    let to = nullable(v, &vp, address)?;
    let (v, vp) = o.req("value");
    let value = u256(v, &vp)?;
    let (v, vp) = o.req("data");
    let data = bytes(v, &vp)?;
    let (v, vp) = o.req("gasLimit");
    let gas_limit = u64q(v, &vp)?;
    let (v, vp) = o.req("gasPrice");
    let gas_price = nullable(v, &vp, u256)?;
    let (v, vp) = o.req("maxFeePerGas");
    let max_fee_per_gas = nullable(v, &vp, u256)?;
    let (v, vp) = o.req("maxPriorityFeePerGas");
    let max_priority_fee_per_gas = nullable(v, &vp, u256)?;
    let (v, vp) = o.req("accessList");
    let access_list = array(v, &vp, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["address", "storageKeys"], &[])?;
        let (a, ap) = o.req("address");
        let (k, kp) = o.req("storageKeys");
        Ok(AccessListEntry { address: address(a, &ap)?, storage_keys: array(k, &kp, 0, None, b256)? })
    })?;
    let (v, vp) = o.req("authorizationList");
    let authorization_list = array(v, &vp, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["chainId", "address", "nonce", "authority"], &[])?;
        let (c, cp) = o.req("chainId");
        let (a, ap) = o.req("address");
        let (n, np) = o.req("nonce");
        let (au, aup) = o.req("authority");
        Ok(SyntheticAuthorization {
            chain_id: u256(c, &cp)?,
            address: address(a, &ap)?,
            nonce: u64q(n, &np)?,
            authority: nullable(au, &aup, address)?,
        })
    })?;
    Ok(Transaction::Synthetic(Box::new(Synthetic {
        tx_type,
        chain_id,
        nonce,
        sender,
        to,
        value,
        data,
        gas_limit,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        access_list,
        authorization_list,
    })))
}

/// Block context for engine isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEnv {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: Address,
    pub gas_limit: u64,
    pub base_fee: U256,
    pub prev_randao: B256,
    pub parent_hash: B256,
    pub parent_timestamp: u64,
    pub parent_beacon_block_root: Option<B256>,
    pub extra_data: Vec<u8>,
    pub slot_number: u64,
    pub blob_base_fee: U256,
    pub deposit_only: bool,
    pub activation: bool,
}

fn block_env(v: &Value, p: &str) -> Result<BlockEnv> {
    let mut o = Obj::new(v, p)?;
    o.shape(
        &[
            "number", "timestamp", "coinbase", "gasLimit", "baseFee", "prevRandao", "parentHash", "parentTimestamp",
            "parentBeaconBlockRoot", "extraData", "slotNumber", "blobBaseFee", "depositOnly", "activation",
        ],
        &[],
    )?;
    let mut q = |name| {
        let (v, p) = o.req(name);
        (v, p)
    };
    let (v, p) = q("number");
    let number = u64q(v, &p)?;
    let (v, p) = q("timestamp");
    let timestamp = u64q(v, &p)?;
    let (v, p) = q("coinbase");
    let coinbase = address(v, &p)?;
    let (v, p) = q("gasLimit");
    let gas_limit = u64q(v, &p)?;
    let (v, p) = q("baseFee");
    let base_fee = u256(v, &p)?;
    let (v, p) = q("prevRandao");
    let prev_randao = b256(v, &p)?;
    let (v, p) = q("parentHash");
    let parent_hash = b256(v, &p)?;
    let (v, p) = q("parentTimestamp");
    let parent_timestamp = u64q(v, &p)?;
    let (v, p) = q("parentBeaconBlockRoot");
    let parent_beacon_block_root = nullable(v, &p, b256)?;
    let (v, p) = q("extraData");
    let extra_data = bytes(v, &p)?;
    let (v, p) = q("slotNumber");
    let slot_number = u64q(v, &p)?;
    let (v, p) = q("blobBaseFee");
    let blob_base_fee = u256(v, &p)?;
    let (v, p) = q("depositOnly");
    let deposit_only = boolean(v, &p)?;
    let (v, p) = q("activation");
    let activation = boolean(v, &p)?;
    Ok(BlockEnv {
        number,
        timestamp,
        coinbase,
        gas_limit,
        base_fee,
        prev_randao,
        parent_hash,
        parent_timestamp,
        parent_beacon_block_root,
        extra_data,
        slot_number,
        blob_base_fee,
        deposit_only,
        activation,
    })
}

/// A decoded block header. Field values are kept as decoded values of their schema type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub fields: BTreeMap<&'static str, HeaderValue>,
}

/// A header field value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderValue {
    Hash(B256),
    Address(Address),
    Quantity(u64),
    Big(U256),
    Bytes(Vec<u8>),
    Bloom(Vec<u8>),
    Nonce([u8; 8]),
}

const HEADER_FIELDS: [(&str, u8); 21] = [
    ("parentHash", 0),
    ("ommersHash", 0),
    ("beneficiary", 1),
    ("stateRoot", 0),
    ("transactionsRoot", 0),
    ("receiptsRoot", 0),
    ("logsBloom", 5),
    ("difficulty", 3),
    ("number", 2),
    ("gasLimit", 2),
    ("gasUsed", 2),
    ("timestamp", 2),
    ("extraData", 4),
    ("mixHash", 0),
    ("nonce", 6),
    ("baseFeePerGas", 3),
    ("withdrawalsRoot", 0),
    ("blobGasUsed", 2),
    ("excessBlobGas", 2),
    ("parentBeaconBlockRoot", 0),
    ("requestsHash", 0),
];

fn header(v: &Value, p: &str) -> Result<Header> {
    let mut o = Obj::new(v, p)?;
    let names: Vec<&str> = HEADER_FIELDS.iter().map(|(n, _)| *n).collect();
    o.shape(&names, &[])?;
    let mut fields = BTreeMap::new();
    for (name, kind) in HEADER_FIELDS {
        let (v, p) = o.req(name);
        let value = match kind {
            0 => HeaderValue::Hash(b256(v, &p)?),
            1 => HeaderValue::Address(address(v, &p)?),
            2 => HeaderValue::Quantity(u64q(v, &p)?),
            3 => HeaderValue::Big(u256(v, &p)?),
            4 => HeaderValue::Bytes(bytes(v, &p)?),
            5 => HeaderValue::Bloom(fixed::<256>(v, &p)?.to_vec()),
            _ => HeaderValue::Nonce(fixed::<8>(v, &p)?),
        };
        fields.insert(name, value);
    }
    Ok(Header { fields })
}

fn anchor(v: &Value, p: &str) -> Result<Header> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["header"], &[])?;
    let (h, hp) = o.req("header");
    header(h, &hp)
}

/// One entry of a chain's spec schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleEntry {
    pub spec: SpecRef,
    pub timestamp: u64,
}

/// The chain descriptor of a block profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInput {
    pub chain_id: u64,
    pub schedule: Vec<ScheduleEntry>,
    pub raw_config: Option<Vec<u8>>,
}

fn chain_id_only(v: &Value, p: &str) -> Result<u64> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chainId"], &[])?;
    let (c, cp) = o.req("chainId");
    u64q(c, &cp)
}

fn chain_input(v: &Value, p: &str) -> Result<ChainInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chainId", "schedule", "rawConfig"], &[])?;
    let (c, cp) = o.req("chainId");
    let (s, sp) = o.req("schedule");
    let (r, rp) = o.req("rawConfig");
    Ok(ChainInput {
        chain_id: u64q(c, &cp)?,
        schedule: array(s, &sp, 1, None, |v, p| {
            let mut o = Obj::new(v, p)?;
            o.shape(&["spec", "timestamp"], &[])?;
            let (s, sp) = o.req("spec");
            let (t, tp) = o.req("timestamp");
            Ok(ScheduleEntry { spec: spec_ref(s, &sp)?, timestamp: u64q(t, &tp)? })
        })?,
        raw_config: nullable(r, &rp, bytes)?,
    })
}

/// A block of a block profile's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockInput {
    /// A decoded header and the EIP-2718 bytes of its transactions.
    Fields { header: Header, transactions: Vec<Vec<u8>> },
    /// Raw block bytes, kept for malformed-byte cases.
    Rlp(Vec<u8>),
}

fn block_input(v: &Value, p: &str) -> Result<BlockInput> {
    let mut o = Obj::new(v, p)?;
    o.require(&["encoding"])?;
    let (e, ep) = o.req("encoding");
    let fields = one_of(e, &ep, &[("fields", true), ("rlp", false)], ErrorCode::InvalidValue)?;
    if fields {
        o.shape(&["encoding", "header", "transactions"], &[])?;
        let (h, hp) = o.req("header");
        let (t, tp) = o.req("transactions");
        Ok(BlockInput::Fields { header: header(h, &hp)?, transactions: array(t, &tp, 0, None, bytes)? })
    } else {
        o.shape(&["encoding", "raw"], &[])?;
        let (r, rp) = o.req("raw");
        Ok(BlockInput::Rlp(bytes(r, &rp)?))
    }
}

// ---------------------------------------------------------------------------------------------
// Observations

/// Admission outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    FailedDeposit,
    Refused { phase: String, reasons: Vec<String> },
}

/// Execution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub status: ExecStatus,
    pub output: Vec<u8>,
    pub created_address: Option<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecStatus {
    Success,
    Revert,
    Halt,
}

/// Commit outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Commit {
    Committed,
    NotCommitted,
    Fault { stage: String, read: ProviderRead, report: String },
}

/// Admission, execution and commit outcomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub admission: Admission,
    pub execution: Option<Execution>,
    pub commit: Commit,
}

pub(crate) const REFUSAL_REASONS: [&str; 20] = [
    "malformed-envelope", "unsupported-type", "invalid-signature", "chain-id-mismatch",
    "data-size-exceeded", "intrinsic-gas-too-low", "floor-exceeds-gas-limit", "not-system-shape",
    "nonce-too-low", "nonce-too-high", "nonce-overflow", "insufficient-funds", "sender-has-code",
    "fee-cap-below-base-fee", "priority-fee-above-fee-cap", "gas-limit-exceeds-block",
    "block-gas-exhausted", "deposit-only-block", "initcode-too-large", "invalid-authorization-list",
];

pub(crate) const DECISION_EXTRA_REASONS: [&str; 6] =
    ["block-data-size", "block-kv-updates", "block-state-growth", "policy-limit", "stale-candidate", "oracle-unreproducible"];

fn closed_word(v: &Value, p: &str, words: &[&str], code: ErrorCode) -> Result<String> {
    let s = string(v, p)?;
    if words.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(Error::new(code, p, format!("{s:?} is not one of the allowed values")))
    }
}

fn reasons(v: &Value, p: &str, words: &[&str], min: usize) -> Result<Vec<String>> {
    array(v, p, min, None, |v, p| closed_word(v, p, words, ErrorCode::InvalidValue))
}

fn outcome(v: &Value, p: &str) -> Result<Outcome> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["admission", "execution", "commit"], &[])?;
    let (a, ap) = o.req("admission");
    let mut ao = Obj::new(a, &ap)?;
    ao.require(&["status"])?;
    let (s, sp) = ao.req("status");
    let status = one_of(s, &sp, &[("admitted", 0), ("failed-deposit", 1), ("refused", 2)], ErrorCode::InvalidValue)?;
    let admission = match status {
        0 | 1 => {
            ao.shape(&["status"], &[])?;
            if status == 0 { Admission::Admitted } else { Admission::FailedDeposit }
        }
        _ => {
            ao.shape(&["status", "phase", "reasons"], &[])?;
            let (ph, php) = ao.req("phase");
            let (r, rp) = ao.req("reasons");
            Admission::Refused {
                phase: closed_word(ph, &php, &["decode", "validation", "inclusion"], ErrorCode::InvalidValue)?,
                reasons: reasons(r, &rp, &REFUSAL_REASONS, 1)?,
            }
        }
    };
    let (e, ep) = o.req("execution");
    let execution = nullable(e, &ep, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["status", "output", "createdAddress"], &[])?;
        let (s, sp) = o.req("status");
        let (out, op) = o.req("output");
        let (c, cp) = o.req("createdAddress");
        Ok(Execution {
            status: one_of(s, &sp, &[("success", ExecStatus::Success), ("revert", ExecStatus::Revert), ("halt", ExecStatus::Halt)], ErrorCode::InvalidValue)?,
            output: bytes(out, &op)?,
            created_address: nullable(c, &cp, address)?,
        })
    })?;
    let (c, cp) = o.req("commit");
    let mut co = Obj::new(c, &cp)?;
    co.require(&["status"])?;
    let (s, sp) = co.req("status");
    let status = one_of(s, &sp, &[("committed", 0), ("not-committed", 1), ("fault", 2)], ErrorCode::InvalidValue)?;
    let commit = match status {
        0 | 1 => {
            co.shape(&["status"], &[])?;
            if status == 0 { Commit::Committed } else { Commit::NotCommitted }
        }
        _ => {
            co.shape(&["status", "stage", "read", "report"], &[])?;
            let (st, stp) = co.req("stage");
            let (r, rp) = co.req("read");
            let (re, rep) = co.req("report");
            Commit::Fault {
                stage: closed_word(st, &stp, &["validation", "pre-frame", "execution", "settlement", "block"], ErrorCode::InvalidValue)?,
                read: provider_read(r, &rp)?,
                report: closed_word(re, &rep, &["internal-error", "invalid-block"], ErrorCode::InvalidValue)?,
            }
        }
    };
    Ok(Outcome { admission, execution, commit })
}

/// An account after a change; `storage` holds only the changed slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code: Vec<u8>,
    pub storage: BTreeMap<B256, U256>,
}

/// A complete semantic change set; `None`: absent after the change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDiff {
    pub accounts: BTreeMap<Address, Option<PostAccount>>,
}

fn state_diff(v: &Value, p: &str) -> Result<StateDiff> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["accounts"], &[])?;
    let (a, ap) = o.req("accounts");
    let accounts = map(a, &ap, address, |v, p| {
        nullable(v, p, |v, p| {
            let mut o = Obj::new(v, p)?;
            o.shape(&["nonce", "balance", "code", "storage"], &[])?;
            let (n, np) = o.req("nonce");
            let (b, bp) = o.req("balance");
            let (c, cp) = o.req("code");
            let (s, sp) = o.req("storage");
            Ok(PostAccount { nonce: u64q(n, &np)?, balance: u256(b, &bp)?, code: bytes(c, &cp)?, storage: storage(s, &sp)? })
        })
    })?;
    Ok(StateDiff { accounts })
}

/// A log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

fn log(v: &Value, p: &str) -> Result<Log> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["address", "topics", "data"], &[])?;
    let (a, ap) = o.req("address");
    let (t, tp) = o.req("topics");
    let (d, dp) = o.req("data");
    Ok(Log { address: address(a, &ap)?, topics: array(t, &tp, 0, Some(4), b256)?, data: bytes(d, &dp)? })
}

/// Receipt facts. `cumulative_gas_used` and `logs_bloom` exist in block profiles only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tx_type: u64,
    pub success: bool,
    pub gas_used: u64,
    pub cumulative_gas_used: Option<u64>,
    pub logs: Vec<Log>,
    pub logs_bloom: Option<Vec<u8>>,
    pub deposit_nonce: Option<u64>,
    pub deposit_receipt_version: Option<u64>,
}

fn receipt(v: &Value, p: &str, block: bool) -> Result<Receipt> {
    let mut o = Obj::new(v, p)?;
    if block {
        o.shape(&["type", "status", "gasUsed", "cumulativeGasUsed", "logs", "logsBloom", "depositNonce", "depositReceiptVersion"], &[])?;
    } else {
        o.shape(&["type", "status", "gasUsed", "logs", "depositNonce", "depositReceiptVersion"], &[])?;
    }
    let (t, tp) = o.req("type");
    let (s, sp) = o.req("status");
    let (g, gp) = o.req("gasUsed");
    let cumulative_gas_used = match o.opt("cumulativeGasUsed") {
        Some((v, p)) => Some(u64q(v, &p)?),
        None => None,
    };
    let (l, lp) = o.req("logs");
    let logs_bloom = match o.opt("logsBloom") {
        Some((v, p)) => Some(fixed::<256>(v, &p)?.to_vec()),
        None => None,
    };
    let (dn, dnp) = o.req("depositNonce");
    let (dv, dvp) = o.req("depositReceiptVersion");
    Ok(Receipt {
        tx_type: u64q(t, &tp)?,
        success: one_of(s, &sp, &[("0x0", false), ("0x1", true)], ErrorCode::InvalidValue)?,
        gas_used: u64q(g, &gp)?,
        cumulative_gas_used,
        logs: array(l, &lp, 0, None, log)?,
        logs_bloom,
        deposit_nonce: nullable(dn, &dnp, u64q)?,
        deposit_receipt_version: nullable(dv, &dvp, u64q)?,
    })
}

/// Gas pools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasPools {
    pub regular: (u64, u64),
    pub reservoir: (u64, u64),
    pub spilled: u64,
    pub returned: u64,
}

fn gas_pools(v: &Value, p: &str) -> Result<GasPools> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["regular", "reservoir", "spilled", "returned"], &[])?;
    let balance = |v: &Value, p: &str| -> Result<(u64, u64)> {
        let mut o = Obj::new(v, p)?;
        o.shape(&["initial", "final"], &[])?;
        let (i, ip) = o.req("initial");
        let (f, fp) = o.req("final");
        Ok((u64q(i, &ip)?, u64q(f, &fp)?))
    };
    let (r, rp) = o.req("regular");
    let (rs, rsp) = o.req("reservoir");
    let (s, sp) = o.req("spilled");
    let (re, rep) = o.req("returned");
    Ok(GasPools { regular: balance(r, &rp)?, reservoir: balance(rs, &rsp)?, spilled: u64q(s, &sp)?, returned: u64q(re, &rep)? })
}

/// Gas ledgers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasLedgers {
    pub total: u64,
    pub regular: u64,
    pub state: u64,
    pub history: u64,
    pub history_bytes: u64,
    pub refund: u64,
    pub floor: u64,
    pub gas_used: u64,
    pub block_gas: u64,
}

fn gas_ledgers(v: &Value, p: &str) -> Result<GasLedgers> {
    let mut o = Obj::new(v, p)?;
    let names = ["total", "regular", "state", "history", "historyBytes", "refund", "floor", "gasUsed", "blockGas"];
    o.shape(&names, &[])?;
    let mut get = |n| {
        let (v, p) = o.req(n);
        u64q(v, &p)
    };
    Ok(GasLedgers {
        total: get("total")?,
        regular: get("regular")?,
        state: get("state")?,
        history: get("history")?,
        history_bytes: get("historyBytes")?,
        refund: get("refund")?,
        floor: get("floor")?,
        gas_used: get("gasUsed")?,
        block_gas: get("blockGas")?,
    })
}

/// One resource dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dimension {
    pub limit: u64,
    pub net: i128,
    pub reported: u64,
}

/// Resource accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resources {
    pub data_size: Dimension,
    pub kv_updates: Dimension,
    pub state_growth: Dimension,
}

fn resources(v: &Value, p: &str) -> Result<Resources> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["dataSize", "kvUpdates", "stateGrowth"], &[])?;
    let dim = |v: &Value, p: &str| -> Result<Dimension> {
        let mut o = Obj::new(v, p)?;
        o.shape(&["limit", "net", "reported"], &[])?;
        let (l, lp) = o.req("limit");
        let (n, np) = o.req("net");
        let (r, rp) = o.req("reported");
        Ok(Dimension { limit: u64q(l, &lp)?, net: signed(n, &np)?, reported: u64q(r, &rp)? })
    };
    let (d, dp) = o.req("dataSize");
    let (k, kp) = o.req("kvUpdates");
    let (s, sp) = o.req("stateGrowth");
    Ok(Resources { data_size: dim(d, &dp)?, kv_updates: dim(k, &kp)?, state_growth: dim(s, &sp)? })
}

/// The members of a limit stop every reader requires: what both implementations' results expose.
pub const LIMIT_STOP_MEMBERS: [&str; 3] = ["dimension", "limit", "returnData"];

/// The members of a limit stop that are diagnostics: from schema 1.1 on each is optional, carried
/// behind `group:limit-diagnostics`; a 1.0 stop carries all of them.
pub const LIMIT_DIAGNOSTICS: [&str; 6] = ["scope", "callPath", "operation", "phase", "operationCommitted", "enclosingCommitted"];

/// The stop kinds of `MegaLimitExceeded(uint8 kind, uint64 limit)`, by dimension.
pub const LIMIT_KINDS: [(&str, u8); 4] = [("data-size", 0), ("kv-updates", 1), ("compute", 2), ("state-growth", 3)];

/// A limit stop: its dimension, its limit and its return data, and the diagnostics a producer could
/// supply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitStop {
    pub dimension: String,
    pub limit: u64,
    pub return_data: Vec<u8>,
    pub scope: Option<String>,
    pub call_path: Option<Vec<u64>>,
    pub operation: Option<String>,
    pub phase: Option<String>,
    pub operation_committed: Option<bool>,
    pub enclosing_committed: Option<bool>,
}

fn limit_stop(v: &Value, p: &str) -> Result<LimitStop> {
    let mut o = Obj::new(v, p)?;
    o.shape(&LIMIT_STOP_MEMBERS, &LIMIT_DIAGNOSTICS)?;
    let (d, dp) = o.req("dimension");
    let (l, lp) = o.req("limit");
    let (r, rp) = o.req("returnData");
    let dimensions: Vec<&str> = LIMIT_KINDS.iter().map(|(d, _)| *d).collect();
    Ok(LimitStop {
        dimension: closed_word(d, &dp, &dimensions, ErrorCode::InvalidValue)?,
        limit: u64q(l, &lp)?,
        return_data: bytes(r, &rp)?,
        scope: o.opt("scope").map(|(s, sp)| closed_word(s, &sp, &["transaction", "frame"], ErrorCode::InvalidValue)).transpose()?,
        call_path: o.opt("callPath").map(|(c, cp)| call_path(c, &cp)).transpose()?,
        operation: o.opt("operation").map(|(op, opp)| operation(op, &opp)).transpose()?,
        phase: o
            .opt("phase")
            .map(|(ph, php)| closed_word(ph, &php, &["pre-frame", "frame-start", "execution", "frame-return"], ErrorCode::InvalidValue))
            .transpose()?,
        operation_committed: o.opt("operationCommitted").map(|(oc, ocp)| boolean(oc, &ocp)).transpose()?,
        enclosing_committed: o.opt("enclosingCommitted").map(|(ec, ecp)| boolean(ec, &ecp)).transpose()?,
    })
}

/// A volatile read under gas detention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolatileRead {
    pub category: String,
    pub status: String,
    pub call_path: Vec<u64>,
    pub compute_at_read: u64,
    pub cap: u64,
}

/// Gas detention observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detention {
    pub reads: Vec<VolatileRead>,
    pub limit: Option<u64>,
    pub withheld: u64,
    pub released: u64,
    pub burned: u64,
}

fn detention(v: &Value, p: &str) -> Result<Detention> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["reads", "limit", "withheld", "released", "burned"], &[])?;
    let (r, rp) = o.req("reads");
    let reads = array(r, &rp, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["category", "status", "callPath", "computeAtRead", "cap"], &[])?;
        let (c, cp) = o.req("category");
        let (s, sp) = o.req("status");
        let (cl, clp) = o.req("callPath");
        let (ca, cap) = o.req("computeAtRead");
        let (k, kp) = o.req("cap");
        Ok(VolatileRead {
            category: closed_word(c, &cp, &["block-env", "beneficiary", "oracle"], ErrorCode::InvalidValue)?,
            status: closed_word(s, &sp, &["admitted", "failed"], ErrorCode::InvalidValue)?,
            call_path: call_path(cl, &clp)?,
            compute_at_read: u64q(ca, &cap)?,
            cap: u64q(k, &kp)?,
        })
    })?;
    let (l, lp) = o.req("limit");
    let (w, wp) = o.req("withheld");
    let (re, rep) = o.req("released");
    let (b, bp) = o.req("burned");
    Ok(Detention { reads, limit: nullable(l, &lp, u64q)?, withheld: u64q(w, &wp)?, released: u64q(re, &rep)?, burned: u64q(b, &bp)? })
}

/// An account as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRead {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
}

/// Logical reads and external effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reads {
    pub accounts: BTreeMap<Address, Option<AccountRead>>,
    pub storage: BTreeMap<Address, BTreeMap<B256, U256>>,
    pub codes: Vec<B256>,
    pub block_hashes: BTreeMap<u64, B256>,
    pub buckets: BTreeMap<u64, u64>,
    pub oracle: Vec<(B256, U256)>,
    pub hints: Vec<(Address, B256, Vec<u8>)>,
}

fn reads(v: &Value, p: &str) -> Result<Reads> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["accounts", "storage", "codes", "blockHashes", "buckets", "oracle", "hints"], &[])?;
    let (a, ap) = o.req("accounts");
    let accounts = map(a, &ap, address, |v, p| {
        nullable(v, p, |v, p| {
            let mut o = Obj::new(v, p)?;
            o.shape(&["nonce", "balance", "codeHash"], &[])?;
            let (n, np) = o.req("nonce");
            let (b, bp) = o.req("balance");
            let (c, cp) = o.req("codeHash");
            Ok(AccountRead { nonce: u64q(n, &np)?, balance: u256(b, &bp)?, code_hash: b256(c, &cp)? })
        })
    })?;
    let (s, sp) = o.req("storage");
    let storage_reads = map(s, &sp, address, storage)?;
    let (c, cp) = o.req("codes");
    let codes = array(c, &cp, 0, None, b256)?;
    let (bh, bhp) = o.req("blockHashes");
    let (bu, bup) = o.req("buckets");
    let (or, orp) = o.req("oracle");
    let oracle_reads = array(or, &orp, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["slot", "value"], &[])?;
        let (s, sp) = o.req("slot");
        let (x, xp) = o.req("value");
        Ok((b256(s, &sp)?, u256(x, &xp)?))
    })?;
    let (h, hp) = o.req("hints");
    let hints = array(h, &hp, 0, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["from", "topic", "data"], &[])?;
        let (f, fp) = o.req("from");
        let (t, tp) = o.req("topic");
        let (d, dp) = o.req("data");
        Ok((address(f, &fp)?, b256(t, &tp)?, bytes(d, &dp)?))
    })?;
    Ok(Reads {
        accounts,
        storage: storage_reads,
        codes,
        block_hashes: block_hashes(bh, &bhp)?,
        buckets: map(bu, &bup, u64q, u64q)?,
        oracle: oracle_reads,
        hints,
    })
}

/// A semantic ledger checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub call_path: Vec<u64>,
    pub phase: String,
    pub ordinal: u64,
    pub regular: u64,
    pub reservoir: u64,
    pub state: i128,
    pub history: i128,
}

fn checkpoint(v: &Value, p: &str) -> Result<Checkpoint> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["callPath", "phase", "ordinal", "regular", "reservoir", "state", "history"], &[])?;
    let (c, cp) = o.req("callPath");
    let (ph, php) = o.req("phase");
    let (or, orp) = o.req("ordinal");
    let (r, rp) = o.req("regular");
    let (rs, rsp) = o.req("reservoir");
    let (s, sp) = o.req("state");
    let (h, hp) = o.req("history");
    Ok(Checkpoint {
        call_path: call_path(c, &cp)?,
        phase: closed_word(ph, &php, &["pre-frame", "start-charge", "child-merge", "detention-update", "rollback", "settlement"], ErrorCode::InvalidValue)?,
        ordinal: u64q(or, &orp)?,
        regular: u64q(r, &rp)?,
        reservoir: u64q(rs, &rsp)?,
        state: signed(s, &sp)?,
        history: signed(h, &hp)?,
    })
}

/// Typed commitments.
pub type Commitments = BTreeMap<String, B256>;

pub(crate) const COMMITMENT_KINDS: [&str; 6] =
    ["mpt-state-root", "salt-state-root", "mpt-receipts-root", "mpt-transactions-root", "mpt-withdrawals-storage-root", "block-hash"];

fn commitments(v: &Value, p: &str) -> Result<Commitments> {
    map(v, p, |k, kp| closed_word(k, kp, &COMMITMENT_KINDS, ErrorCode::UnknownCommitment), b256)
}

/// Observations of one transaction of a block. Optional groups are `None` when absent; `limit`
/// is `Some(None)` when present as null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTransaction {
    pub outcome: Outcome,
    pub receipt: Receipt,
    pub gas_pools: Option<GasPools>,
    pub gas_ledgers: Option<GasLedgers>,
    pub resources: Option<Resources>,
    pub limit: Option<Option<LimitStop>>,
    pub detention: Option<Detention>,
    pub reads: Option<Reads>,
}

pub(crate) const BLOCK_TX_OPTIONAL: [&str; 6] = ["gasPools", "gasLedgers", "resources", "limit", "detention", "reads"];

fn block_transaction(v: &Value, p: &str) -> Result<BlockTransaction> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["outcome", "receipt"], &BLOCK_TX_OPTIONAL)?;
    let (oc, ocp) = o.req("outcome");
    let (r, rp) = o.req("receipt");
    Ok(BlockTransaction {
        outcome: outcome(oc, &ocp)?,
        receipt: receipt(r, &rp, true)?,
        gas_pools: o.opt("gasPools").map(|(v, p)| gas_pools(v, &p)).transpose()?,
        gas_ledgers: o.opt("gasLedgers").map(|(v, p)| gas_ledgers(v, &p)).transpose()?,
        resources: o.opt("resources").map(|(v, p)| resources(v, &p)).transpose()?,
        limit: o.opt("limit").map(|(v, p)| nullable(v, &p, limit_stop)).transpose()?,
        detention: o.opt("detention").map(|(v, p)| detention(v, &p)).transpose()?,
        reads: o.opt("reads").map(|(v, p)| reads(v, &p)).transpose()?,
    })
}

/// A pre-block step's effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreBlockStep {
    pub step: String,
    pub state: StateDiff,
}

/// Block counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counters {
    pub gas_used: u64,
    pub data_size: u64,
    pub kv_updates: u64,
    pub state_growth: u64,
}

fn counters(v: &Value, p: &str) -> Result<Counters> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["gasUsed", "dataSize", "kvUpdates", "stateGrowth"], &[])?;
    let mut get = |n| {
        let (v, p) = o.req(n);
        u64q(v, &p)
    };
    Ok(Counters { gas_used: get("gasUsed")?, data_size: get("dataSize")?, kv_updates: get("kvUpdates")?, state_growth: get("stateGrowth")? })
}

/// The result of one imported block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockResult {
    Valid {
        active_spec: String,
        deposit_only: bool,
        activation: bool,
        pre_block: Vec<PreBlockStep>,
        transactions: Vec<BlockTransaction>,
        counters: Counters,
        commitments: Commitments,
        state: StateDiff,
    },
    /// `active_spec`, `deposit_only` and `activation` are `None` only for a block that failed to
    /// decode.
    Invalid {
        active_spec: Option<String>,
        deposit_only: Option<bool>,
        activation: Option<bool>,
        phase: String,
        reason: String,
        transaction_index: Option<u64>,
    },
}

const BLOCK_FAILURE_REASONS: [&str; 15] = [
    "malformed-block", "invalid-header", "invalid-transaction", "deposit-only-block",
    "block-gas-limit", "block-data-size", "block-kv-updates", "block-state-growth",
    "missing-factory", "invalid-registry", "state-root-mismatch", "receipts-root-mismatch",
    "gas-used-mismatch", "logs-bloom-mismatch", "invalid-configuration",
];

fn block_result(v: &Value, p: &str) -> Result<BlockResult> {
    let mut o = Obj::new(v, p)?;
    o.require(&["status"])?;
    let (s, sp) = o.req("status");
    let valid = one_of(s, &sp, &[("valid", true), ("invalid", false)], ErrorCode::InvalidValue)?;
    if valid {
        o.shape(&["status", "activeSpec", "depositOnly", "activation", "preBlock", "transactions", "counters", "commitments", "state"], &[])?;
    } else {
        o.shape(&["status", "activeSpec", "depositOnly", "activation", "failure"], &[])?;
    }
    let (a, ap) = o.req("activeSpec");
    let (d, dp) = o.req("depositOnly");
    let (ac, acp) = o.req("activation");
    if valid {
        let active_spec = spec_name(a, &ap)?;
        let deposit_only = boolean(d, &dp)?;
        let activation = boolean(ac, &acp)?;
        let (pb, pbp) = o.req("preBlock");
        let pre_block = array(pb, &pbp, 0, None, |v, p| {
            let mut o = Obj::new(v, p)?;
            o.shape(&["step", "state"], &[])?;
            let (s, sp) = o.req("step");
            let (st, stp) = o.req("state");
            Ok(PreBlockStep {
                step: closed_word(s, &sp, &["beacon-root", "history-storage", "system-contracts", "sequencer-registry"], ErrorCode::InvalidValue)?,
                state: state_diff(st, &stp)?,
            })
        })?;
        let (t, tp) = o.req("transactions");
        let (c, cp) = o.req("counters");
        let (cm, cmp) = o.req("commitments");
        let (st, stp) = o.req("state");
        Ok(BlockResult::Valid {
            active_spec,
            deposit_only,
            activation,
            pre_block,
            transactions: array(t, &tp, 0, None, block_transaction)?,
            counters: counters(c, &cp)?,
            commitments: commitments(cm, &cmp)?,
            state: state_diff(st, &stp)?,
        })
    } else {
        let active_spec = nullable(a, &ap, spec_name)?;
        let deposit_only = nullable(d, &dp, boolean)?;
        let activation = nullable(ac, &acp, boolean)?;
        let (f, fp) = o.req("failure");
        let mut fo = Obj::new(f, &fp)?;
        fo.shape(&["phase", "reason", "transactionIndex"], &[])?;
        let (ph, php) = fo.req("phase");
        let (r, rp) = fo.req("reason");
        let (ti, tip) = fo.req("transactionIndex");
        Ok(BlockResult::Invalid {
            active_spec,
            deposit_only,
            activation,
            phase: closed_word(ph, &php, &["decode", "header", "pre-block", "transaction", "post-block", "commitment"], ErrorCode::InvalidValue)?,
            reason: closed_word(r, &rp, &BLOCK_FAILURE_REASONS, ErrorCode::InvalidValue)?,
            transaction_index: nullable(ti, &tip, u64q)?,
        })
    }
}

/// The last accepted block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub number: u64,
    pub hash: B256,
}

fn head(v: &Value, p: &str) -> Result<Head> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["number", "hash"], &[])?;
    let (n, np) = o.req("number");
    let (h, hp) = o.req("hash");
    Ok(Head { number: u64q(n, &np)?, hash: b256(h, &hp)? })
}

// ---------------------------------------------------------------------------------------------
// Profiles

/// state-transition input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateTransitionInput {
    pub chain_id: u64,
    pub block: BlockEnv,
    pub block_hashes: BTreeMap<u64, B256>,
    pub pre: State,
    pub transaction: Transaction,
    pub salt: Option<Salt>,
    pub oracle: Option<Oracle>,
    pub faults: Option<Vec<ProviderRead>>,
}

/// state-transition expected result. Mandatory groups are plain fields (nullable where a refused
/// or faulted transaction has none); optional groups are `None` when the case does not require
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateTransitionExpected {
    pub outcome: Outcome,
    pub state: StateDiff,
    pub receipt: Option<Receipt>,
    pub gas_ledgers: Option<GasLedgers>,
    pub resources: Option<Resources>,
    pub limit: Option<LimitStop>,
    pub gas_pools: Option<Option<GasPools>>,
    pub detention: Option<Option<Detention>>,
    pub reads: Option<Reads>,
    pub checkpoints: Option<Vec<Checkpoint>>,
}

fn st_input(v: &Value, p: &str) -> Result<StateTransitionInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chain", "block", "blockHashes", "pre", "transaction"], &["salt", "oracle", "faults"])?;
    let (c, cp) = o.req("chain");
    let (b, bp) = o.req("block");
    let (h, hp) = o.req("blockHashes");
    let (pr, prp) = o.req("pre");
    let (t, tp) = o.req("transaction");
    Ok(StateTransitionInput {
        chain_id: chain_id_only(c, &cp)?,
        block: block_env(b, &bp)?,
        block_hashes: block_hashes(h, &hp)?,
        pre: state(pr, &prp, &[Completeness::Complete, Completeness::Sparse])?,
        transaction: transaction(t, &tp, true)?,
        salt: o.opt("salt").map(|(v, p)| salt(v, &p)).transpose()?,
        oracle: o.opt("oracle").map(|(v, p)| oracle(v, &p)).transpose()?,
        faults: o.opt("faults").map(|(v, p)| faults(v, &p)).transpose()?,
    })
}

fn st_expected(v: &Value, p: &str) -> Result<StateTransitionExpected> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["outcome", "state", "receipt", "gasLedgers", "resources", "limit"], &["gasPools", "detention", "reads", "checkpoints"])?;
    let (oc, ocp) = o.req("outcome");
    let (s, sp) = o.req("state");
    let (r, rp) = o.req("receipt");
    let (g, gp) = o.req("gasLedgers");
    let (re, rep) = o.req("resources");
    let (l, lp) = o.req("limit");
    Ok(StateTransitionExpected {
        outcome: outcome(oc, &ocp)?,
        state: state_diff(s, &sp)?,
        receipt: nullable(r, &rp, |v, p| receipt(v, p, false))?,
        gas_ledgers: nullable(g, &gp, gas_ledgers)?,
        resources: nullable(re, &rep, resources)?,
        limit: nullable(l, &lp, limit_stop)?,
        gas_pools: o.opt("gasPools").map(|(v, p)| nullable(v, &p, gas_pools)).transpose()?,
        detention: o.opt("detention").map(|(v, p)| nullable(v, &p, detention)).transpose()?,
        reads: o.opt("reads").map(|(v, p)| reads(v, &p)).transpose()?,
        checkpoints: o.opt("checkpoints").map(|(v, p)| array(v, &p, 0, None, checkpoint)).transpose()?,
    })
}

/// transaction-validation input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationInput {
    pub chain_id: u64,
    pub block: Option<BlockEnv>,
    pub pre: Option<State>,
    pub raw: Vec<u8>,
}

/// transaction-validation expected result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationExpected {
    Accepted { sender: Address, hash: B256, intrinsic: Option<(u64, u64, u64)> },
    Rejected { phase: String, reasons: Vec<String> },
}

fn tv_input(v: &Value, p: &str) -> Result<ValidationInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chain", "block", "pre", "raw"], &[])?;
    let (c, cp) = o.req("chain");
    let (b, bp) = o.req("block");
    let (pr, prp) = o.req("pre");
    let (r, rp) = o.req("raw");
    Ok(ValidationInput {
        chain_id: chain_id_only(c, &cp)?,
        block: nullable(b, &bp, block_env)?,
        pre: nullable(pr, &prp, |v, p| state(v, p, &[Completeness::Complete, Completeness::Sparse]))?,
        raw: bytes(r, &rp)?,
    })
}

fn tv_expected(v: &Value, p: &str) -> Result<ValidationExpected> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["validation"], &[])?;
    let (vv, vp) = o.req("validation");
    let mut o = Obj::new(vv, &vp)?;
    o.require(&["status"])?;
    let (s, sp) = o.req("status");
    let accepted = one_of(s, &sp, &[("accepted", true), ("rejected", false)], ErrorCode::InvalidValue)?;
    if accepted {
        o.shape(&["status", "sender", "hash", "intrinsic"], &[])?;
        let (se, sep) = o.req("sender");
        let (h, hp) = o.req("hash");
        let (i, ip) = o.req("intrinsic");
        Ok(ValidationExpected::Accepted {
            sender: address(se, &sep)?,
            hash: b256(h, &hp)?,
            intrinsic: nullable(i, &ip, |v, p| {
                let mut o = Obj::new(v, p)?;
                o.shape(&["regular", "history", "floor"], &[])?;
                let (r, rp) = o.req("regular");
                let (h, hp) = o.req("history");
                let (f, fp) = o.req("floor");
                Ok((u64q(r, &rp)?, u64q(h, &hp)?, u64q(f, &fp)?))
            })?,
        })
    } else {
        o.shape(&["status", "phase", "reasons"], &[])?;
        let (ph, php) = o.req("phase");
        let (r, rp) = o.req("reasons");
        Ok(ValidationExpected::Rejected {
            phase: closed_word(ph, &php, &["decode", "validation"], ErrorCode::InvalidValue)?,
            reasons: reasons(r, &rp, &REFUSAL_REASONS, 1)?,
        })
    }
}

/// block-import input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockImportInput {
    pub chain: ChainInput,
    pub anchor: Header,
    pub pre: State,
    pub ancestors: BTreeMap<u64, B256>,
    pub salt: Option<Salt>,
    pub faults: Option<Vec<ProviderRead>>,
    pub blocks: Vec<BlockInput>,
}

/// block-import expected result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockImportExpected {
    pub blocks: Vec<BlockResult>,
    pub head: Head,
    pub state: StateDiff,
}

fn bi_input(v: &Value, p: &str) -> Result<BlockImportInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chain", "anchor", "pre", "ancestors", "blocks"], &["salt", "faults"])?;
    let (c, cp) = o.req("chain");
    let (a, ap) = o.req("anchor");
    let (pr, prp) = o.req("pre");
    let (an, anp) = o.req("ancestors");
    let (b, bp) = o.req("blocks");
    Ok(BlockImportInput {
        chain: chain_input(c, &cp)?,
        anchor: anchor(a, &ap)?,
        pre: state(pr, &prp, &[Completeness::Complete, Completeness::Sparse])?,
        ancestors: block_hashes(an, &anp)?,
        salt: o.opt("salt").map(|(v, p)| salt(v, &p)).transpose()?,
        faults: o.opt("faults").map(|(v, p)| faults(v, &p)).transpose()?,
        blocks: array(b, &bp, 1, None, block_input)?,
    })
}

fn bi_expected(v: &Value, p: &str) -> Result<BlockImportExpected> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["blocks", "head", "state"], &[])?;
    let (b, bp) = o.req("blocks");
    let (h, hp) = o.req("head");
    let (s, sp) = o.req("state");
    Ok(BlockImportExpected { blocks: array(b, &bp, 1, None, block_result)?, head: head(h, &hp)?, state: state_diff(s, &sp)? })
}

/// A builder's action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildOp {
    Execute,
    Commit,
    Abandon,
}

/// block-build input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBuildInput {
    pub chain: ChainInput,
    pub anchor: Header,
    pub pre: State,
    pub ancestors: BTreeMap<u64, B256>,
    pub salt: Option<Salt>,
    pub oracle: Option<Oracle>,
    pub faults: Option<Vec<ProviderRead>>,
    pub block: BTreeMap<&'static str, HeaderValue>,
    pub policy: [Option<u64>; 4],
    pub candidates: Vec<Transaction>,
    pub actions: Vec<(BuildOp, u64)>,
}

/// One candidate's final decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub decision: String,
    pub reasons: Vec<String>,
}

/// block-build expected result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBuildExpected {
    pub decisions: Vec<Decision>,
    pub committed: Vec<u64>,
    pub transactions: Vec<BlockTransaction>,
    pub counters: Counters,
    pub commitments: Commitments,
    pub state: StateDiff,
}

fn bb_input(v: &Value, p: &str) -> Result<BlockBuildInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chain", "anchor", "pre", "ancestors", "block", "policy", "candidates", "actions"], &["salt", "oracle", "faults"])?;
    let (c, cp) = o.req("chain");
    let (a, ap) = o.req("anchor");
    let (pr, prp) = o.req("pre");
    let (an, anp) = o.req("ancestors");
    let (b, bp) = o.req("block");
    let mut bo = Obj::new(b, &bp)?;
    let block_fields: [(&str, u8); 8] = [
        ("number", 2),
        ("timestamp", 2),
        ("beneficiary", 1),
        ("gasLimit", 2),
        ("baseFeePerGas", 3),
        ("prevRandao", 0),
        ("parentBeaconBlockRoot", 0),
        ("extraData", 4),
    ];
    let names: Vec<&str> = block_fields.iter().map(|(n, _)| *n).collect();
    bo.shape(&names, &[])?;
    let mut block = BTreeMap::new();
    for (name, kind) in block_fields {
        let (v, p) = bo.req(name);
        let value = match kind {
            0 => HeaderValue::Hash(b256(v, &p)?),
            1 => HeaderValue::Address(address(v, &p)?),
            2 => HeaderValue::Quantity(u64q(v, &p)?),
            3 => HeaderValue::Big(u256(v, &p)?),
            _ => HeaderValue::Bytes(bytes(v, &p)?),
        };
        block.insert(name, value);
    }
    let (po, pop) = o.req("policy");
    let mut pol = Obj::new(po, &pop)?;
    pol.shape(&["gas", "dataSize", "kvUpdates", "stateGrowth"], &[])?;
    let mut policy = [None; 4];
    for (i, name) in ["gas", "dataSize", "kvUpdates", "stateGrowth"].into_iter().enumerate() {
        let (v, p) = pol.req(name);
        policy[i] = nullable(v, &p, u64q)?;
    }
    let (ca, cap) = o.req("candidates");
    let (ac, acp) = o.req("actions");
    Ok(BlockBuildInput {
        chain: chain_input(c, &cp)?,
        anchor: anchor(a, &ap)?,
        pre: state(pr, &prp, &[Completeness::Complete, Completeness::Sparse])?,
        ancestors: block_hashes(an, &anp)?,
        salt: o.opt("salt").map(|(v, p)| salt(v, &p)).transpose()?,
        oracle: o.opt("oracle").map(|(v, p)| oracle(v, &p)).transpose()?,
        faults: o.opt("faults").map(|(v, p)| faults(v, &p)).transpose()?,
        block,
        policy,
        candidates: array(ca, &cap, 1, None, |v, p| transaction(v, p, false))?,
        actions: array(ac, &acp, 1, None, |v, p| {
            let mut o = Obj::new(v, p)?;
            o.shape(&["op", "candidate"], &[])?;
            let (op, opp) = o.req("op");
            let (c, cp) = o.req("candidate");
            Ok((
                one_of(op, &opp, &[("execute", BuildOp::Execute), ("commit", BuildOp::Commit), ("abandon", BuildOp::Abandon)], ErrorCode::InvalidValue)?,
                u64q(c, &cp)?,
            ))
        })?,
    })
}

fn bb_expected(v: &Value, p: &str) -> Result<BlockBuildExpected> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["decisions", "committed", "transactions", "counters", "commitments", "state"], &[])?;
    let all_reasons: Vec<&str> = REFUSAL_REASONS.iter().chain(DECISION_EXTRA_REASONS.iter()).copied().collect();
    let (d, dp) = o.req("decisions");
    let decisions = array(d, &dp, 1, None, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["decision", "reasons"], &[])?;
        let (dv, dvp) = o.req("decision");
        let (r, rp) = o.req("reasons");
        Ok(Decision {
            decision: closed_word(dv, &dvp, &["included", "skipped", "rejected"], ErrorCode::InvalidValue)?,
            reasons: reasons(r, &rp, &all_reasons, 0)?,
        })
    })?;
    let (c, cp) = o.req("committed");
    let (t, tp) = o.req("transactions");
    let (co, cop) = o.req("counters");
    let (cm, cmp) = o.req("commitments");
    let (s, sp) = o.req("state");
    Ok(BlockBuildExpected {
        decisions,
        committed: array(c, &cp, 0, None, u64q)?,
        transactions: array(t, &tp, 0, None, block_transaction)?,
        counters: counters(co, &cop)?,
        commitments: commitments(cm, &cmp)?,
        state: state_diff(s, &sp)?,
    })
}

/// A versioned proof attachment, stored as a content-addressed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofAttachment {
    pub codec: String,
    pub digest: String,
    pub size: u64,
}

/// stateless-block input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatelessInput {
    pub chain: ChainInput,
    pub anchor: Header,
    pub pre: State,
    pub ancestors: BTreeMap<u64, B256>,
    pub salt: Option<Salt>,
    pub blocks: Vec<BlockInput>,
    pub parent_hash: B256,
    pub parent_state_root: B256,
    pub proof: Option<ProofAttachment>,
}

/// The witness verdict of a stateless-block case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessResult {
    /// `proof_valid` is true when an attached proof verified, false when none was attached.
    Verified { proof_valid: bool },
    Failed { stage: String, reason: String, read: Option<ProviderRead> },
}

/// stateless-block expected result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatelessExpected {
    pub witness: WitnessResult,
    pub blocks: Option<Vec<BlockResult>>,
    pub head: Option<Head>,
    pub state: Option<StateDiff>,
}

fn sb_input(v: &Value, p: &str) -> Result<StatelessInput> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["chain", "anchor", "pre", "ancestors", "blocks", "witness"], &["salt"])?;
    let (c, cp) = o.req("chain");
    let (a, ap) = o.req("anchor");
    let (pr, prp) = o.req("pre");
    let (an, anp) = o.req("ancestors");
    let (b, bp) = o.req("blocks");
    let (w, wp) = o.req("witness");
    let mut wo = Obj::new(w, &wp)?;
    wo.shape(&["parentHash", "parentStateRoot", "proof"], &[])?;
    let (ph, php) = wo.req("parentHash");
    let (sr, srp) = wo.req("parentStateRoot");
    let (pf, pfp) = wo.req("proof");
    let proof = nullable(pf, &pfp, |v, p| {
        let mut o = Obj::new(v, p)?;
        o.shape(&["codec", "digest", "size"], &[])?;
        let (c, cp) = o.req("codec");
        let (d, dp) = o.req("digest");
        let (s, sp) = o.req("size");
        let codec_ok = |s: &str| match s.split_once('/') {
            Some((name, version)) => {
                name_ok(name) && !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        };
        Ok(ProofAttachment {
            codec: patterned(c, &cp, ErrorCode::InvalidValue, codec_ok)?.to_string(),
            digest: digest(d, &dp)?,
            size: u64q(s, &sp)?,
        })
    })?;
    Ok(StatelessInput {
        chain: chain_input(c, &cp)?,
        anchor: anchor(a, &ap)?,
        pre: state(pr, &prp, &[Completeness::Witness])?,
        ancestors: block_hashes(an, &anp)?,
        salt: o.opt("salt").map(|(v, p)| salt(v, &p)).transpose()?,
        blocks: array(b, &bp, 1, None, block_input)?,
        parent_hash: b256(ph, &php)?,
        parent_state_root: b256(sr, &srp)?,
        proof,
    })
}

fn sb_expected(v: &Value, p: &str) -> Result<StatelessExpected> {
    let mut o = Obj::new(v, p)?;
    o.shape(&["witness", "blocks", "head", "state"], &[])?;
    let (w, wp) = o.req("witness");
    let mut wo = Obj::new(w, &wp)?;
    wo.require(&["status"])?;
    let (s, sp) = wo.req("status");
    let verified = one_of(s, &sp, &[("verified", true), ("failed", false)], ErrorCode::InvalidValue)?;
    let witness = if verified {
        wo.shape(&["status", "proof"], &[])?;
        let (pf, pfp) = wo.req("proof");
        let proof_valid = nullable(pf, &pfp, |v, p| constant(v, p, "valid", ErrorCode::InvalidValue))?.is_some();
        WitnessResult::Verified { proof_valid }
    } else {
        wo.shape(&["status", "stage", "reason", "read"], &[])?;
        let (st, stp) = wo.req("stage");
        let (r, rp) = wo.req("reason");
        let (rd, rdp) = wo.req("read");
        WitnessResult::Failed {
            stage: closed_word(st, &stp, &["anchor", "proof", "closure", "replay"], ErrorCode::InvalidValue)?,
            reason: closed_word(
                r,
                &rp,
                &["wrong-parent-anchor", "tampered-proof", "unsupported-codec", "missing-input", "undeclared-read", "replay-mismatch"],
                ErrorCode::InvalidValue,
            )?,
            read: nullable(rd, &rdp, provider_read)?,
        }
    };
    let (b, bp) = o.req("blocks");
    let (h, hp) = o.req("head");
    let (st, stp) = o.req("state");
    Ok(StatelessExpected {
        witness,
        blocks: nullable(b, &bp, |v, p| array(v, p, 1, None, block_result))?,
        head: nullable(h, &hp, head)?,
        state: nullable(st, &stp, state_diff)?,
    })
}

/// Decodes a profile's expected result on its own (an adapter's actual observations).
pub(crate) fn decode_expected(profile: Profile, v: &Value, p: &str) -> Result<()> {
    match profile {
        Profile::StateTransition => st_expected(v, p).map(|_| ()),
        Profile::TransactionValidation => tv_expected(v, p).map(|_| ()),
        Profile::BlockImport => bi_expected(v, p).map(|_| ()),
        Profile::BlockBuild => bb_expected(v, p).map(|_| ()),
        Profile::StatelessBlock => sb_expected(v, p).map(|_| ()),
    }
}
