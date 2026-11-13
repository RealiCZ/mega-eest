//! The bundled rule registry of the pinned specification.

mod common;

#[test]
fn the_satin_registry_holds_every_rule_id_of_the_pinned_commit() {
    let store = common::store();
    let spec = store.specs().find(|s| s.name == "megaeth/Satin").expect("Satin is bundled");
    assert_eq!(spec.rules.len(), 407);
    assert_eq!(spec.rules.values().filter(|r| !r.active).count(), 9);
    assert!(spec.rules["SATIN-KEY-005"].rows.contains("step-12"));
    assert!(!spec.rules["SATIN-POOL-013"].active);
    assert!(spec.rules["SATIN-POOL-019"].text_digest.starts_with("sha256:"));
}

#[test]
fn a_descriptor_that_does_not_bind_its_registry_is_refused() {
    let mut store = mega_fixture_format::SpecStore::new();
    let descriptor = common::read("specs/satin-cac999a/descriptor.json");
    let registry = String::from_utf8(common::read("specs/satin-cac999a/rules.json")).unwrap().replacen("\"active\"", "\"retired\"", 1);
    assert!(store.add(&descriptor, registry.as_bytes()).is_err());
}

#[test]
fn a_registry_entry_whose_text_does_not_match_its_digest_or_status_is_refused() {
    let descriptor = common::read("specs/satin-cac999a/descriptor.json");
    let registry = String::from_utf8(common::read("specs/satin-cac999a/rules.json")).unwrap();
    // Either edit also changes the registry digest, so rebind the descriptor to isolate the entry check.
    for edited in [registry.replacen("\"status\": \"active\"", "\"status\": \"Active\"", 1), registry.replacen("MUST", "SHOULD", 1)] {
        let digest = mega_fixture_format::sha256_digest(&mega_fixture_format::canonicalize(edited.as_bytes()).unwrap());
        let mut d = mega_fixture_format::json::parse(&descriptor).unwrap();
        common::set(&mut d, "/registry", mega_fixture_format::Value::String(digest));
        let rebound = mega_fixture_format::json::to_canonical(&d);
        assert!(mega_fixture_format::SpecStore::new().add(&rebound, edited.as_bytes()).is_err());
    }
}

#[test]
fn the_six_satin_snapshots_and_the_rex6_registry_are_bundled() {
    let store = common::store();
    let names: Vec<&str> = store.specs().map(|s| s.name.as_str()).collect();
    assert_eq!(names.iter().filter(|n| **n == "megaeth/Satin").count(), 6, "{names:?}");
    let ids: Vec<usize> = store.specs().filter(|s| s.name == "megaeth/Satin").map(|s| s.rules.len()).collect();
    assert!(ids.contains(&407) && ids.contains(&408) && ids.contains(&409) && ids.contains(&410), "{ids:?}");
    let rex6 = store.specs().find(|s| s.name == "megaeth/Rex6").expect("Rex6 is bundled");
    assert_eq!(rex6.rules.len(), 358);
    assert!(rex6.rules.values().all(|r| r.active), "a frozen spec retires nothing");
    assert!(rex6.rules.keys().all(|id| id.starts_with("REX6-")));
}

/// The slice's descriptor binds codecs and the SALT mapping by value, so an adapter needs no
/// out-of-band knowledge of them.
#[test]
fn the_current_descriptors_bind_codecs_and_the_salt_mapping() {
    for dir in ["specs/satin-22a5f4b", "specs/satin-d34e626", "specs/satin-d334ef8", "specs/satin-5fb2688", "specs/satin-cdded1e", "specs/rex6-d4c913c5"] {
        let d = mega_fixture_format::json::parse(&common::read(&format!("{dir}/descriptor.json"))).unwrap();
        for member in ["/codecs/header/fields", "/codecs/receipt/encoding", "/codecs/transaction/types", "/salt/seeds"] {
            assert!(d.pointer(member).is_some(), "{dir}: {member}");
        }
        assert_eq!(d.pointer("/salt/mapping").and_then(|v| v.as_str()), Some("salt-v1"));
    }
}

/// A Rex6 case cites Rex6 rules and resolves against the Rex6 registry; a Satin id does not
/// resolve there.
#[test]
fn a_rex6_case_validates_against_the_rex6_registry_only() {
    use mega_fixture_format::{json, Case, Value};
    let store = common::store();
    let rex6 = store.specs().find(|s| s.name == "megaeth/Rex6").unwrap();
    let mut case = json::parse(&common::read("slice/cases/satin/intrinsic/call/contract-stop.json")).unwrap();
    common::set(&mut case, "/specRef/name", Value::String("megaeth/Rex6".into()));
    common::set(&mut case, "/specRef/descriptor", Value::String(rex6.descriptor_digest.clone()));
    let rules = Value::Array(vec![Value::String("REX6-LIM-002".into())]);
    common::set(&mut case, "/rules", rules);
    Case::from_value(case.clone(), &store).expect("a Rex6 citation resolves");
    let satin_id = Value::Array(vec![Value::String("SATIN-POOL-019".into())]);
    common::set(&mut case, "/rules", satin_id);
    let err = Case::from_value(case, &store).unwrap_err();
    assert_eq!(err.code.as_str(), "unknown-rule", "{err}");
}
