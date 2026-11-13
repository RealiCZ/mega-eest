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

// A stop of the transaction's own frame (decision D-62): its dimension, limit and return data are
// mandatory behind `group:limit-stop`; its diagnostics are optional behind `group:limit-diagnostics`,
// and compared only where the case carries them.

fn stop_case() -> Case {
    Case::from_bytes(&common::read("slice/cases/satin/limit-stops/compute-at-one-charge.json"), &common::store()).unwrap()
}

fn with_value(case: &Case, pointer: &str, value: Value) -> Result<Case, mega_fixture_format::Error> {
    let mut v = case.value.clone();
    common::set(&mut v, pointer, value);
    Case::from_value(v, &common::store())
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::String((*s).into())).collect())
}

fn requires_of(case: &Case) -> Vec<String> {
    match case.value.get("requires") {
        Some(Value::Array(r)) => r.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => panic!("requires"),
    }
}

#[test]
fn a_stop_requires_group_limit_stop() {
    let c = stop_case();
    assert_eq!(c.value.get("schemaVersion").and_then(Value::as_str), Some("2.0"));
    let requires = requires_of(&c);
    assert!(requires.iter().any(|r| r == "group:limit-stop"), "{requires:?}");
    let without: Vec<&str> = requires.iter().map(String::as_str).filter(|r| *r != "group:limit-stop").collect();
    let e = with_value(&c, "/requires", strings(&without)).expect_err("a stop without its requirement");
    assert_eq!(e.code, mega_fixture_format::ErrorCode::RequirementMismatch);
}

// Schema 2 (decision D-76) dropped the envelope's `assertions`: a file of another major, or one that
// still carries per-path rule lists, is rejected rather than misread.

#[test]
fn another_major_is_rejected() {
    let c = stop_case();
    for version in ["1.0", "1.1", "3.0"] {
        let e = with_value(&c, "/schemaVersion", Value::String(version.into())).expect_err(version);
        assert_eq!(e.code, mega_fixture_format::ErrorCode::UnsupportedSchemaVersion, "{version}");
    }
}

#[test]
fn an_assertions_member_is_an_unknown_field() {
    let c = stop_case();
    let assertion = json::parse(br#"[{"path":"/expected/limit","rules":["SATIN-STOP-009"]}]"#).unwrap();
    let e = with_value(&c, "/assertions", assertion).expect_err("schema 2 has no assertions");
    assert_eq!(e.code, mega_fixture_format::ErrorCode::UnknownField);
    assert_eq!(e.path, "/assertions");
}

#[test]
fn a_stop_agrees_with_the_revert_output() {
    let c = stop_case();
    let other = "0x84b902670000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000001312d02";
    let e = with_value(&c, "/expected/limit/returnData", Value::String(other.into())).expect_err("another return data");
    assert_eq!(e.code, mega_fixture_format::ErrorCode::InconsistentOutcome);
    let e = with_value(&c, "/expected/limit/dimension", Value::String("data-size".into())).expect_err("another dimension");
    assert_eq!(e.code, mega_fixture_format::ErrorCode::InconsistentOutcome);
}

#[test]
fn a_stop_with_diagnostics_requires_group_limit_diagnostics() {
    let c = stop_case();
    let mut v = c.value.clone();
    common::set(&mut v, "/expected/limit/scope", Value::String("transaction".into()));
    let e = Case::from_value(v.clone(), &common::store()).expect_err("diagnostics without their requirement");
    assert_eq!(e.code, mega_fixture_format::ErrorCode::RequirementMismatch);
    let mut requires = requires_of(&c);
    requires.push("group:limit-diagnostics".into());
    requires.sort();
    let requires: Vec<&str> = requires.iter().map(String::as_str).collect();
    common::set(&mut v, "/requires", strings(&requires));
    Case::from_value(v, &common::store()).expect("diagnostics behind group:limit-diagnostics");
}

#[test]
fn diagnostics_the_case_does_not_carry_are_not_compared() {
    let c = stop_case();
    let mut actual = expected_of(&c);
    common::set(&mut actual, "/limit/scope", Value::String("transaction".into()));
    common::set(&mut actual, "/limit/callPath", Value::Array(Vec::new()));
    assert_eq!(compare(&c, &actual, &all()), Verdict::Pass);
    common::set(&mut actual, "/limit/limit", Value::String("0x1".into()));
    match compare(&c, &actual, &all()) {
        Verdict::Fail { path, .. } => assert_eq!(path, "/expected/limit/limit"),
        other => panic!("{other:?}"),
    }
    let mut none = expected_of(&c);
    common::set(&mut none, "/limit", Value::Null);
    match compare(&c, &none, &all()) {
        Verdict::Fail { path, .. } => assert_eq!(path, "/expected/limit"),
        other => panic!("{other:?}"),
    }
}
