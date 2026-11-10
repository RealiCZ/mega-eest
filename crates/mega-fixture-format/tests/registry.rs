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
