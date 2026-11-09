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
