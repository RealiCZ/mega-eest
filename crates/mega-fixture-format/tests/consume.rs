//! The consumer loop and the filler, at their public seam: a case's bytes and an adapter in,
//! a status out; an authoring document and observations in, a candidate fixture out.

mod common;

use mega_fixture_format::consume::{self, Adapter, Capabilities, Status};
use mega_fixture_format::{json, sha256_digest, Case, Value};
use std::cell::RefCell;
use std::path::Path;

const EXAMPLE: &str = "examples/state-transition-sstore-fresh-slot.json";

/// A test double standing in for an implementation: it answers every run with fixed
/// observations, and records the requests it was sent.
struct Scripted {
    observations: Value,
    digest: Option<String>,
    requests: RefCell<Vec<Value>>,
}

impl Adapter for Scripted {
    fn capabilities(&self) -> Result<Value, String> {
        Ok(capabilities(&["group:gas-ledgers", "group:limit", "group:outcome", "group:reads", "group:receipts", "group:resources", "group:state", "feature:salt"]))
    }
    fn run(&self, request: &Value, _instrumented: bool) -> Result<Value, String> {
        self.requests.borrow_mut().push(request.clone());
        let digest = self.digest.clone().unwrap_or_else(|| sha256_digest(&json::to_canonical(request.get("input").unwrap())));
        Ok(object(vec![
            ("status", Value::String("ok".into())),
            ("inputDigest", Value::String(digest)),
            ("observations", self.observations.clone()),
        ]))
    }
}

fn object(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.to_string())).collect())
}

fn capabilities(requires: &[&str]) -> Value {
    object(vec![
        ("format", Value::String("mega-fixture-adapter".into())),
        ("adapter", object(vec![("name", Value::String("scripted".into()))])),
        ("specs", strings(&["megaeth/Satin"])),
        ("profiles", strings(&["state-transition"])),
        ("requires", strings(requires)),
        ("modes", strings(&["plain"])),
    ])
}

fn example() -> (Vec<u8>, Value) {
    let bytes = common::read(EXAMPLE);
    let expected = json::parse(&bytes).unwrap().get("expected").unwrap().clone();
    (bytes, expected)
}

fn consume_with(adapter: &Scripted) -> consume::CaseReport {
    let caps = Capabilities::from_value(adapter.capabilities().unwrap()).unwrap();
    consume::consume_case(EXAMPLE, &example().0, &common::store(), adapter, &caps, false)
}

#[test]
fn matching_observations_pass_and_the_request_carries_no_expectation() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let report = consume_with(&adapter);
    assert_eq!(report.status, Status::Pass);
    let requests = adapter.requests.borrow();
    let Value::Object(request) = &requests[0] else { panic!("an object") };
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    assert_eq!(keys, ["caseId", "format", "input", "profile", "requires", "schemaVersion", "specRef"]);
}

#[test]
fn a_wrong_value_fails_with_its_path_and_rules() {
    let (_, mut observations) = example();
    // The example expects one state-growth unit; an implementation reporting two fails there.
    common::set(&mut observations, "/resources/stateGrowth/reported", Value::String("0x2".into()));
    let adapter = Scripted { observations, digest: None, requests: RefCell::new(Vec::new()) };
    match consume_with(&adapter).status {
        Status::Fail { path, expected, actual, rules } => {
            assert_eq!(path, "/expected/resources/stateGrowth/reported");
            assert_eq!(expected, Some(Value::String("0x1".into())));
            assert_eq!(actual, Some(Value::String("0x2".into())));
            // No assertion of the example covers resources.
            assert!(rules.is_empty(), "{rules:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_adapter_that_ran_other_input_is_an_error() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: Some(sha256_digest(b"other")), requests: RefCell::new(Vec::new()) };
    assert!(matches!(consume_with(&adapter).status, Status::Error { .. }));
}

#[test]
fn a_missing_capability_is_unsupported_and_nothing_runs() {
    let (bytes, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let caps = Capabilities::from_value(capabilities(&["group:outcome"])).unwrap();
    let report = consume::consume_case(EXAMPLE, &bytes, &common::store(), &adapter, &caps, false);
    match report.status {
        Status::Unsupported { missing } => assert!(missing.contains(&"group:reads".to_string()), "{missing:?}"),
        other => panic!("{other:?}"),
    }
    assert!(adapter.requests.borrow().is_empty());
}

#[test]
fn an_invalid_case_is_an_error_of_the_release() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let caps = Capabilities::from_value(adapter.capabilities().unwrap()).unwrap();
    let report = consume::consume_case("x.json", b"{\"format\":1}", &common::store(), &adapter, &caps, false);
    assert!(matches!(report.status, Status::Error { .. }));
    assert!(adapter.requests.borrow().is_empty());
}

#[test]
fn candidates_never_go_to_examples_or_a_release() {
    assert!(consume::is_forbidden_fill_dir(Path::new("examples")));
    assert!(consume::is_forbidden_fill_dir(Path::new("a/examples/b")));
    assert!(consume::is_forbidden_fill_dir(Path::new("release-1.0")));
    assert!(!consume::is_forbidden_fill_dir(Path::new("candidates/filled/revm")));
}

#[test]
fn fill_writes_a_valid_candidate_with_derived_requirements() {
    let (bytes, expected) = example();
    let Value::Object(mut authoring) = json::parse(&bytes).unwrap() else { panic!() };
    authoring.remove("expected");
    authoring.remove("requires");
    let filler = object(vec![("adapter", Value::String("scripted".into()))]);
    let case: Case = consume::fill(&Value::Object(authoring.clone()), &expected, &filler, &common::store()).unwrap();
    let provenance = case.value.get("provenance").unwrap();
    assert_eq!(provenance.get("status").and_then(Value::as_str), Some("candidate"));
    assert_eq!(provenance.get("filler"), Some(&filler));
    // The derived requirements are the example's own.
    let original = json::parse(&bytes).unwrap();
    assert_eq!(case.value.get("requires"), original.get("requires"));
    // An authoring document that already has an expectation is refused.
    authoring.insert("expected".into(), expected.clone());
    assert!(consume::fill(&Value::Object(authoring), &expected, &filler, &common::store()).is_err());
}
