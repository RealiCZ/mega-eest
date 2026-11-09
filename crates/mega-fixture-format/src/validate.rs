//! Semantic validation: the checks a schema cannot state, run after decoding, in the order of
//! docs/format.md ("Semantic checks"). They operate on the decoded value tree, whose shape
//! decoding has already guaranteed.

use crate::error::{child, index, Error, ErrorCode};
use crate::json::Value;
use crate::model::{Fixture, Profile, RuleRef};
use crate::registry::SpecStore;
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, Error>;

fn err(code: ErrorCode, path: impl Into<String>, detail: impl Into<String>) -> Error {
    Error::new(code, path, detail)
}

fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn arr(v: &Value) -> &[Value] {
    match v {
        Value::Array(items) => items,
        _ => &[],
    }
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

/// Strictly ascending strings (a sorted set without duplicates), compared by code point.
fn check_sorted(items: &[Value], path: &str) -> Result<()> {
    for pair in items.windows(2) {
        if str_of(&pair[0]) >= str_of(&pair[1]) {
            return Err(err(ErrorCode::UnsortedSet, path, "not sorted, or holds a duplicate"));
        }
    }
    Ok(())
}

/// Runs every semantic check on a decoded fixture.
pub fn validate(value: &Value, fixture: &Fixture, store: &SpecStore) -> Result<()> {
    // 1. Specs.
    let spec = store
        .get(&fixture.spec_ref.descriptor)
        .ok_or_else(|| err(ErrorCode::UnknownSpec, "/specRef/descriptor", "no bundled descriptor has this digest"))?;
    if spec.name != fixture.spec_ref.name {
        return Err(err(ErrorCode::SpecNameMismatch, "/specRef/name", format!("the descriptor names {}", spec.name)));
    }
    let input = get(value, "input");
    let expected = get(value, "expected");
    let block_profile = matches!(fixture.profile, Profile::BlockImport | Profile::BlockBuild | Profile::StatelessBlock);
    if block_profile {
        let schedule = arr(get(get(input, "chain"), "schedule"));
        for (i, entry) in schedule.iter().enumerate() {
            let base = index("/input/chain/schedule", i);
            let spec_v = get(entry, "spec");
            let found = store
                .get(str_of(get(spec_v, "descriptor")))
                .ok_or_else(|| err(ErrorCode::UnknownSpec, format!("{base}/spec/descriptor"), "no bundled descriptor has this digest"))?;
            if found.name != str_of(get(spec_v, "name")) {
                return Err(err(ErrorCode::SpecNameMismatch, format!("{base}/spec/name"), format!("the descriptor names {}", found.name)));
            }
        }
        for pair in schedule.windows(2) {
            let t0 = u64::from_str_radix(&str_of(get(&pair[0], "timestamp"))[2..], 16).unwrap_or(0);
            let t1 = u64::from_str_radix(&str_of(get(&pair[1], "timestamp"))[2..], 16).unwrap_or(0);
            if t0 >= t1 {
                return Err(err(ErrorCode::UnsortedSet, "/input/chain/schedule", "activation timestamps must strictly increase"));
            }
        }
    }

    // 2. Sorted sets of the envelope.
    check_sorted(arr(get(value, "requires")), "/requires")?;
    check_sorted(arr(get(value, "rules")), "/rules")?;
    for (i, a) in arr(get(value, "assertions")).iter().enumerate() {
        check_sorted(arr(get(a, "rules")), &format!("/assertions/{i}/rules"))?;
    }

    // 3. Every cited rule resolves against the case's registry, active at that spec.
    for (i, rule) in fixture.rules.iter().enumerate() {
        let path = index("/rules", i);
        let info = spec.rules.get(&rule.id).ok_or_else(|| err(ErrorCode::UnknownRule, &path, format!("{} is not in the registry", rule.id)))?;
        if let Some(row) = &rule.row {
            if !info.rows.contains(row) {
                return Err(err(ErrorCode::UnknownRuleRow, &path, format!("{} has no citable row {row:?}", rule.id)));
            }
        }
        if !info.active {
            return Err(err(ErrorCode::RetiredRule, &path, format!("{} is retired at this spec", rule.id)));
        }
    }

    // 4. Assertions are bound and cover exactly the cited rules.
    let cited: BTreeSet<&RuleRef> = fixture.rules.iter().collect();
    let mut covered: BTreeSet<&RuleRef> = BTreeSet::new();
    for (i, a) in fixture.assertions.iter().enumerate() {
        if value.pointer(&a.path).is_none() {
            return Err(err(ErrorCode::UnboundAssertion, format!("/assertions/{i}/path"), format!("{} resolves to nothing", a.path)));
        }
        for (j, rule) in a.rules.iter().enumerate() {
            if !cited.contains(rule) {
                return Err(err(ErrorCode::AssertionRuleNotCited, format!("/assertions/{i}/rules/{j}"), format!("{rule} is not in rules")));
            }
            covered.insert(rule);
        }
    }
    for (i, rule) in fixture.rules.iter().enumerate() {
        if !covered.contains(rule) {
            return Err(err(ErrorCode::UncoveredRule, index("/rules", i), format!("no assertion distinguishes {rule}")));
        }
    }

    // 5. requires lists exactly the groups carried and the features used.
    let derived = derive_requirements(fixture.profile, input, expected)?;
    let listed: BTreeSet<String> = arr(get(value, "requires")).iter().map(|v| str_of(v).to_string()).collect();
    if derived != listed {
        let missing: Vec<_> = derived.difference(&listed).collect();
        let extra: Vec<_> = listed.difference(&derived).collect();
        return Err(err(ErrorCode::RequirementMismatch, "/requires", format!("missing {missing:?}, not used {extra:?}")));
    }

    // 6. Outcomes are consistent with the other groups.
    check_consistency(fixture.profile, input, expected)?;

    // 7. State checks.
    check_state(fixture.profile, input, expected)?;

    // 8. Remaining sorted sets.
    check_observation_sets(fixture.profile, expected)?;

    // 9. References between input and expected.
    check_references(fixture.profile, input, expected)
}

/// The group and feature requirements a case's content implies.
pub(crate) fn derive_requirements(profile: Profile, input: &Value, expected: &Value) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut add = |s: &str| {
        out.insert(s.to_string());
    };
    let tx_groups = |txs: &[&Value], out: &mut BTreeSet<String>| -> Result<()> {
        for (key, group) in [
            ("gasPools", "group:gas-pools"),
            ("gasLedgers", "group:gas-ledgers"),
            ("resources", "group:resources"),
            ("limit", "group:limit"),
            ("detention", "group:detention"),
            ("reads", "group:reads"),
        ] {
            let carried = txs.iter().filter(|t| t.get(key).is_some()).count();
            if carried > 0 && carried < txs.len() {
                return Err(err(ErrorCode::RequirementMismatch, "/requires", format!("{group} is carried by some transactions only")));
            }
            if carried > 0 {
                out.insert(group.to_string());
            }
        }
        Ok(())
    };
    match profile {
        Profile::StateTransition => {
            for g in ["group:outcome", "group:state", "group:receipts", "group:gas-ledgers", "group:resources", "group:limit"] {
                add(g);
            }
            for (key, group) in [("gasPools", "group:gas-pools"), ("detention", "group:detention"), ("reads", "group:reads"), ("checkpoints", "group:checkpoints")] {
                if expected.get(key).is_some() {
                    add(group);
                }
            }
            match str_of(get(get(input, "transaction"), "kind")) {
                "deposit" => add("feature:deposit"),
                "synthetic" => add("feature:synthetic-transaction"),
                _ => {}
            }
        }
        Profile::TransactionValidation => {
            add("group:validation");
            if str_of(get(input, "raw")).starts_with("0x7e") {
                add("feature:deposit");
            }
        }
        Profile::BlockImport | Profile::StatelessBlock | Profile::BlockBuild => {
            for g in ["group:blocks", "group:state", "group:outcome", "group:receipts"] {
                add(g);
            }
            let mut txs: Vec<&Value> = Vec::new();
            if profile == Profile::BlockBuild {
                add("group:decisions");
                txs.extend(arr(get(expected, "transactions")));
                if arr(get(input, "candidates")).iter().any(|c| str_of(get(c, "kind")) == "deposit") {
                    add("feature:deposit");
                }
            } else {
                for block in arr(get(expected, "blocks")) {
                    txs.extend(arr(get(block, "transactions")));
                }
            }
            if profile == Profile::StatelessBlock {
                add("group:witness");
                if !is_null(get(get(input, "witness"), "proof")) {
                    add("feature:proof-attachment");
                }
            }
            let chain = get(input, "chain");
            if arr(get(chain, "schedule")).len() > 1 {
                add("feature:schedule");
            }
            if !is_null(get(chain, "rawConfig")) {
                add("feature:raw-chain-config");
            }
            tx_groups(&txs, &mut out)?;
        }
    }
    if input.get("salt").is_some() {
        out.insert("feature:salt".into());
    }
    if input.get("oracle").is_some() {
        out.insert("feature:oracle-transcript".into());
    }
    if input.get("faults").is_some() {
        out.insert("feature:injected-faults".into());
    }
    if str_of(get(get(input, "pre"), "completeness")) == "sparse" {
        out.insert("feature:sparse-state".into());
    }
    Ok(out)
}

/// The admission/execution/commit consistency of one outcome; returns whether the transaction
/// has observations (it was executed or included as a failed deposit).
fn check_outcome(outcome: &Value, path: &str) -> Result<bool> {
    let admission = str_of(get(get(outcome, "admission"), "status"));
    let execution = get(outcome, "execution");
    let commit = str_of(get(get(outcome, "commit"), "status"));
    let bad = |why: &str| Err(err(ErrorCode::InconsistentOutcome, path, why.to_string()));
    match (admission, commit) {
        ("refused", "not-committed") if is_null(execution) => Ok(false),
        ("refused", _) => bad("a refused transaction has no execution and is not committed"),
        (_, "fault") if is_null(execution) => Ok(false),
        (_, "fault") => bad("a faulted transaction has no execution outcome"),
        ("admitted", "committed") if !is_null(execution) => Ok(true),
        ("admitted", _) => bad("an admitted transaction executes and commits unless a fault stops it"),
        ("failed-deposit", "committed") => Ok(true),
        _ => bad("a failed deposit is committed"),
    }
}

/// Receipt status agrees with the execution outcome.
fn check_receipt_status(outcome: &Value, receipt: &Value, path: &str) -> Result<()> {
    let success = str_of(get(get(outcome, "execution"), "status")) == "success";
    let status = str_of(get(receipt, "status"));
    if (status == "0x1") != success {
        return Err(err(ErrorCode::InconsistentOutcome, path, "receipt status disagrees with the execution outcome"));
    }
    Ok(())
}

fn check_block_tx(tx: &Value, path: &str) -> Result<()> {
    let outcome_path = child(path, "outcome");
    let outcome = get(tx, "outcome");
    let executed = check_outcome(outcome, &outcome_path)?;
    if !executed {
        return Err(err(ErrorCode::InconsistentOutcome, outcome_path, "a transaction of a block is executed or a failed deposit"));
    }
    check_receipt_status(outcome, get(tx, "receipt"), &format!("{path}/receipt/status"))
}

fn valid_blocks(blocks: &Value) -> impl Iterator<Item = (usize, &Value)> {
    arr(blocks).iter().enumerate().filter(|(_, b)| str_of(get(b, "status")) == "valid")
}

fn check_consistency(profile: Profile, input: &Value, expected: &Value) -> Result<()> {
    match profile {
        Profile::StateTransition => {
            let outcome = get(expected, "outcome");
            let executed = check_outcome(outcome, "/expected/outcome")?;
            let mut groups = vec!["receipt", "gasLedgers", "resources"];
            if !executed {
                groups.push("limit");
                for optional in ["gasPools", "detention"] {
                    if expected.get(optional).is_some() {
                        groups.push(optional);
                    }
                }
                for g in groups {
                    if !is_null(get(expected, g)) {
                        return Err(err(ErrorCode::InconsistentOutcome, child("/expected", g), "a transaction without an outcome has none of this group"));
                    }
                }
            } else {
                for g in groups {
                    if is_null(get(expected, g)) {
                        return Err(err(ErrorCode::InconsistentOutcome, child("/expected", g), "an executed transaction has this group"));
                    }
                }
                check_receipt_status(outcome, get(expected, "receipt"), "/expected/receipt/status")?;
            }
        }
        Profile::TransactionValidation => {}
        Profile::BlockImport | Profile::StatelessBlock => {
            let blocks = get(expected, "blocks");
            for (i, block) in valid_blocks(blocks) {
                for (j, tx) in arr(get(block, "transactions")).iter().enumerate() {
                    check_block_tx(tx, &format!("/expected/blocks/{i}/transactions/{j}"))?;
                }
            }
            if profile == Profile::StatelessBlock {
                let witness = get(expected, "witness");
                let verified = str_of(get(witness, "status")) == "verified";
                for key in ["blocks", "head", "state"] {
                    if is_null(get(expected, key)) == verified {
                        return Err(err(ErrorCode::InconsistentOutcome, child("/expected", key), "present exactly when the witness verified"));
                    }
                }
                let attached = !is_null(get(get(input, "witness"), "proof"));
                if verified && (str_of(get(witness, "proof")) == "valid") != attached {
                    return Err(err(ErrorCode::InconsistentOutcome, "/expected/witness/proof", "valid exactly when a proof is attached"));
                }
            }
        }
        Profile::BlockBuild => {
            for (j, tx) in arr(get(expected, "transactions")).iter().enumerate() {
                check_block_tx(tx, &format!("/expected/transactions/{j}"))?;
            }
        }
    }
    Ok(())
}

fn check_state(profile: Profile, input: &Value, expected: &Value) -> Result<()> {
    let pre = get(input, "pre");
    let completeness = str_of(get(pre, "completeness"));
    if completeness == "complete" {
        if let Value::Object(accounts) = get(pre, "accounts") {
            for (address, account) in accounts {
                if let Value::Object(slots) = get(account, "storage") {
                    for (key, value) in slots {
                        if str_of(value) == "0x0" {
                            let path = child(&child(&child("/input/pre/accounts", address), "storage"), key);
                            return Err(err(ErrorCode::ZeroSlotInCompleteState, path, "a zero slot of complete state is omitted"));
                        }
                    }
                }
            }
        }
    }
    if completeness != "complete" {
        let mut roots: Vec<(String, &Value)> = Vec::new();
        match profile {
            Profile::BlockImport | Profile::StatelessBlock => {
                for (i, block) in valid_blocks(get(expected, "blocks")) {
                    roots.push((format!("/expected/blocks/{i}/commitments"), get(block, "commitments")));
                }
            }
            Profile::BlockBuild => roots.push(("/expected/commitments".into(), get(expected, "commitments"))),
            _ => {}
        }
        for (path, commitments) in roots {
            if commitments.get("mpt-state-root").is_some() {
                return Err(err(ErrorCode::RootOverSparseState, child(&path, "mpt-state-root"), "no global MPT root over sparse state"));
            }
        }
    }
    Ok(())
}

fn check_reads(reads: &Value, path: &str) -> Result<()> {
    check_sorted(arr(get(reads, "codes")), &child(path, "codes"))
}

fn check_tx_sets(tx: &Value, path: &str) -> Result<()> {
    let admission = get(get(tx, "outcome"), "admission");
    if let Some(reasons) = admission.get("reasons") {
        check_sorted(arr(reasons), &format!("{path}/outcome/admission/reasons"))?;
    }
    if let Some(reads) = tx.get("reads") {
        check_reads(reads, &child(path, "reads"))?;
    }
    Ok(())
}

fn check_observation_sets(profile: Profile, expected: &Value) -> Result<()> {
    match profile {
        Profile::StateTransition => check_tx_sets(expected, "/expected"),
        Profile::TransactionValidation => {
            let validation = get(expected, "validation");
            match validation.get("reasons") {
                Some(reasons) => check_sorted(arr(reasons), "/expected/validation/reasons"),
                None => Ok(()),
            }
        }
        Profile::BlockImport | Profile::StatelessBlock => {
            for (i, block) in valid_blocks(get(expected, "blocks")) {
                for (j, tx) in arr(get(block, "transactions")).iter().enumerate() {
                    check_tx_sets(tx, &format!("/expected/blocks/{i}/transactions/{j}"))?;
                }
            }
            Ok(())
        }
        Profile::BlockBuild => {
            for (i, d) in arr(get(expected, "decisions")).iter().enumerate() {
                check_sorted(arr(get(d, "reasons")), &format!("/expected/decisions/{i}/reasons"))?;
            }
            for (j, tx) in arr(get(expected, "transactions")).iter().enumerate() {
                check_tx_sets(tx, &format!("/expected/transactions/{j}"))?;
            }
            Ok(())
        }
    }
}

fn quantity(v: &Value) -> u64 {
    u64::from_str_radix(str_of(v).trim_start_matches("0x"), 16).unwrap_or(u64::MAX)
}

fn check_references(profile: Profile, input: &Value, expected: &Value) -> Result<()> {
    match profile {
        Profile::BlockImport | Profile::StatelessBlock => {
            let inputs = arr(get(input, "blocks"));
            let results = arr(get(expected, "blocks"));
            if results.is_empty() {
                return Ok(()); // a failed witness: no block results
            }
            for (i, block) in results.iter().enumerate() {
                if i + 1 < results.len() && str_of(get(block, "status")) != "valid" {
                    return Err(err(ErrorCode::InconsistentOutcome, format!("/expected/blocks/{i}"), "import stops at the first invalid block"));
                }
            }
            let last_valid = str_of(get(&results[results.len() - 1], "status")) == "valid";
            if (last_valid && results.len() != inputs.len()) || results.len() > inputs.len() {
                return Err(err(ErrorCode::InvalidReference, "/expected/blocks", "one result per imported block"));
            }
            for (i, block) in results.iter().enumerate() {
                let txs_in = get(&inputs[i], "transactions");
                if str_of(get(&inputs[i], "encoding")) != "fields" {
                    continue;
                }
                let n_in = arr(txs_in).len();
                if str_of(get(block, "status")) == "valid" {
                    if arr(get(block, "transactions")).len() != n_in {
                        return Err(err(ErrorCode::InvalidReference, format!("/expected/blocks/{i}/transactions"), "one result per transaction of the block"));
                    }
                } else {
                    let ti = get(get(block, "failure"), "transactionIndex");
                    if !is_null(ti) && quantity(ti) >= n_in as u64 {
                        return Err(err(ErrorCode::InvalidReference, format!("/expected/blocks/{i}/failure/transactionIndex"), "no such transaction"));
                    }
                }
            }
        }
        Profile::BlockBuild => {
            let candidates = arr(get(input, "candidates")).len() as u64;
            for (i, action) in arr(get(input, "actions")).iter().enumerate() {
                if quantity(get(action, "candidate")) >= candidates {
                    return Err(err(ErrorCode::InvalidReference, format!("/input/actions/{i}/candidate"), "no such candidate"));
                }
            }
            let decisions = arr(get(expected, "decisions"));
            if decisions.len() as u64 != candidates {
                return Err(err(ErrorCode::InvalidReference, "/expected/decisions", "one decision per candidate"));
            }
            let mut committed = BTreeSet::new();
            for (i, c) in arr(get(expected, "committed")).iter().enumerate() {
                let n = quantity(c);
                if n >= candidates || !committed.insert(n) {
                    return Err(err(ErrorCode::InvalidReference, format!("/expected/committed/{i}"), "no such candidate, or committed twice"));
                }
            }
            for (i, d) in decisions.iter().enumerate() {
                let included = str_of(get(d, "decision")) == "included";
                let has_reasons = !arr(get(d, "reasons")).is_empty();
                if included != committed.contains(&(i as u64)) || included == has_reasons {
                    return Err(err(ErrorCode::InconsistentOutcome, format!("/expected/decisions/{i}"), "included exactly when committed, with reasons exactly when not included"));
                }
            }
            if arr(get(expected, "transactions")).len() != committed.len() {
                return Err(err(ErrorCode::InvalidReference, "/expected/transactions", "one result per committed candidate"));
            }
        }
        _ => {}
    }
    Ok(())
}
