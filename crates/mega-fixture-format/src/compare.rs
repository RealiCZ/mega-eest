//! Comparing an implementation's actual observations with a fixture's expected result.
//!
//! The comparison never fills: it reads both documents and reports the first semantic path at
//! which they differ, in canonical order. A missing capability is `Unsupported`, never a pass.

use crate::error::{child, index, Error};
use crate::json::Value;
use crate::model::{decode_expected, Profile, Requirement, BLOCK_TX_OPTIONAL};
use crate::Case;
use std::collections::BTreeSet;

/// The verdict of one case on one consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every required observation matched.
    Pass,
    /// The first differing semantic path, with both values (`None`: absent).
    Fail { path: String, expected: Option<Value>, actual: Option<Value> },
    /// The consumer lacks these requirements; the case did not run and is not a pass.
    Unsupported { missing: Vec<Requirement> },
    /// The actual observations are not a well-formed expected result of the profile.
    Error(Error),
}

/// Compares `actual` (shaped like the case's `expected`) with the case.
pub fn compare(case: &Case, actual: &Value, supported: &BTreeSet<Requirement>) -> Verdict {
    let missing: Vec<Requirement> = case.fixture.requires.iter().filter(|r| !supported.contains(r)).copied().collect();
    if !missing.is_empty() {
        return Verdict::Unsupported { missing };
    }
    let profile = case.fixture.profile;
    if let Err(e) = decode_expected(profile, actual, "/expected") {
        return Verdict::Error(e);
    }
    let expected = case.value.get("expected").expect("decoded fixture has expected");
    match diff(profile, expected, actual, "/expected") {
        None => Verdict::Pass,
        Some((path, e, a)) => Verdict::Fail { path, expected: e, actual: a },
    }
}

type Difference = (String, Option<Value>, Option<Value>);

/// Optional groups a container may carry beyond what the case requires.
fn optional_groups(profile: Profile, path: &str) -> &'static [&'static str] {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let block_tx = matches!(segments.as_slice(), ["expected", "blocks", _, "transactions", _])
        || matches!(segments.as_slice(), ["expected", "transactions", _]);
    if profile == Profile::StateTransition && path == "/expected" {
        &["gasPools", "detention", "reads", "checkpoints"]
    } else if block_tx {
        &BLOCK_TX_OPTIONAL
    } else {
        &[]
    }
}

fn diff(profile: Profile, expected: &Value, actual: &Value, path: &str) -> Option<Difference> {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            let keys: BTreeSet<&String> = e.keys().chain(a.keys()).collect();
            let skippable = optional_groups(profile, path);
            for key in keys {
                let at = child(path, key);
                match (e.get(key), a.get(key)) {
                    (Some(ev), Some(av)) if key == "reasons" => {
                        if !reasons_match(ev, av) {
                            return Some((at, Some(ev.clone()), Some(av.clone())));
                        }
                    }
                    (Some(ev), Some(av)) => {
                        if let Some(d) = diff(profile, ev, av, &at) {
                            return Some(d);
                        }
                    }
                    (None, Some(_)) if skippable.contains(&key.as_str()) => {}
                    (ev, av) => return Some((at, ev.cloned(), av.cloned())),
                }
            }
            None
        }
        (Value::Array(e), Value::Array(a)) => {
            for i in 0..e.len().max(a.len()) {
                let at = index(path, i);
                match (e.get(i), a.get(i)) {
                    (Some(ev), Some(av)) => {
                        if let Some(d) = diff(profile, ev, av, &at) {
                            return Some(d);
                        }
                    }
                    (ev, av) => return Some((at, ev.cloned(), av.cloned())),
                }
            }
            None
        }
        (e, a) if e == a => None,
        (e, a) => Some((path.to_string(), Some(e.clone()), Some(a.clone()))),
    }
}

/// An expected `reasons` list is the set of acceptable reasons: the implementation reports
/// exactly one of them, or none when none is expected.
fn reasons_match(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Array(e), Value::Array(a)) if e.is_empty() => a.is_empty(),
        (Value::Array(e), Value::Array(a)) => a.len() == 1 && e.contains(&a[0]),
        _ => false,
    }
}

/// The rules whose assertions cover `path`: those whose assertion path is `path` or one of its
/// ancestors. A mismatch report cites them for the first differing path.
pub fn rules_at<'a>(case: &'a Case, path: &str) -> Vec<&'a crate::model::RuleRef> {
    let mut out: Vec<&crate::model::RuleRef> = case
        .fixture
        .assertions
        .iter()
        .filter(|a| path == a.path || path.starts_with(&format!("{}/", a.path)))
        .flat_map(|a| a.rules.iter())
        .collect();
    out.sort();
    out.dedup();
    out
}
