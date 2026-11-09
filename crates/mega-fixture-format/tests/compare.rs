//! The comparison seam: a consumer's actual observations against a frozen expectation.

mod common;

use mega_fixture_format::{compare, json, Case, Requirement, Value, Verdict};
use std::collections::BTreeSet;

fn case() -> Case {
    Case::from_bytes(&common::read("examples/state-transition-sstore-fresh-slot.json"), &common::store()).unwrap()
}

fn all() -> BTreeSet<Requirement> {
    mega_fixture_format::model::REQUIREMENTS.iter().map(|(_, r)| *r).collect()
}

fn expected_of(case: &Case) -> Value {
    case.value.get("expected").unwrap().clone()
}

#[test]
fn identical_observations_pass() {
    let c = case();
    assert_eq!(compare(&c, &expected_of(&c), &all()), Verdict::Pass);
}

#[test]
fn one_changed_value_fails_at_its_semantic_path() {
    let c = case();
    let mut actual = expected_of(&c);
    // The example expects 97,920 (0x17e80) of state gas; the consumer reports one more.
    common::set(&mut actual, "/gasLedgers/state", Value::String("0x17e81".into()));
    match compare(&c, &actual, &all()) {
        Verdict::Fail { path, expected, actual } => {
            assert_eq!(path, "/expected/gasLedgers/state");
            assert_eq!(expected, Some(Value::String("0x17e80".into())));
            assert_eq!(actual, Some(Value::String("0x17e81".into())));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unexpected_state_change_fails() {
    let c = case();
    let mut actual = expected_of(&c);
    common::set(
        &mut actual,
        "/state/accounts/0x00000000000000000000000000000000000000ff",
        json::parse(br#"{"nonce":"0x0","balance":"0x1","code":"0x","storage":{}}"#).unwrap(),
    );
    match compare(&c, &actual, &all()) {
        Verdict::Fail { path, expected: None, .. } => assert_eq!(path, "/expected/state/accounts/0x00000000000000000000000000000000000000ff"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_missing_capability_is_unsupported_never_a_pass() {
    let c = case();
    let mut supported = all();
    supported.remove(&Requirement::parse("feature:salt").unwrap());
    assert_eq!(compare(&c, &expected_of(&c), &supported), Verdict::Unsupported { missing: vec![Requirement::parse("feature:salt").unwrap()] });
}

#[test]
fn a_dropped_required_group_fails_and_malformed_output_is_an_error() {
    let c = case();
    let mut actual = expected_of(&c);
    if let Value::Object(m) = &mut actual {
        m.remove("reads");
    }
    assert!(matches!(compare(&c, &actual, &all()), Verdict::Fail { ref path, actual: None, .. } if path == "/expected/reads"));
    let mut malformed = expected_of(&c);
    common::set(&mut malformed, "/receipt/gasUsed", Value::String("0x0249f0".into()));
    assert!(matches!(compare(&c, &malformed, &all()), Verdict::Error(_)));
}

#[test]
fn an_extra_optional_group_is_ignored() {
    let c = case();
    let mut actual = expected_of(&c);
    common::set(&mut actual, "/detention", Value::Null);
    assert_eq!(compare(&c, &actual, &all()), Verdict::Pass);
}

#[test]
fn a_refusal_matches_any_one_listed_reason() {
    let c = Case::from_bytes(&common::read("examples/transaction-validation-gas-below-intrinsic.json"), &common::store()).unwrap();
    let mut actual = expected_of(&c);
    common::set(&mut actual, "/validation/reasons", Value::Array(vec![Value::String("intrinsic-gas-too-low".into())]));
    assert_eq!(compare(&c, &actual, &all()), Verdict::Pass);
    common::set(&mut actual, "/validation/reasons", Value::Array(vec![Value::String("nonce-too-low".into())]));
    assert!(matches!(compare(&c, &actual, &all()), Verdict::Fail { ref path, .. } if path == "/expected/validation/reasons"));
}

#[test]
fn a_mismatch_cites_the_rules_whose_assertions_cover_its_path() {
    let c = case();
    let cited: Vec<String> = mega_fixture_format::compare::rules_at(&c, "/expected/gasLedgers/state").iter().map(|r| r.to_string()).collect();
    assert_eq!(cited, ["SATIN-POOL-019", "SATIN-STATE-008"]);
    assert!(mega_fixture_format::compare::rules_at(&c, "/expected/gasLedgersX").is_empty());
}
