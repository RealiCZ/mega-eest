//! The format keeps apart what a fixture must never confuse: absent and zero, skipped and
//! invalid, MPT and SALT roots.

mod common;

use mega_fixture_format::model::{Address, B256, Body, StateDiff};
use mega_fixture_format::{json, Case, ErrorCode, SpecStore};

fn example(name: &str) -> Case {
    Case::from_bytes(&common::read(&format!("examples/{name}")), &common::store()).unwrap()
}

fn with(case: &Case, pointer: &str, value: &str, store: &SpecStore) -> Result<Case, mega_fixture_format::Error> {
    let mut v = case.value.clone();
    common::set(&mut v, pointer, json::parse(value.as_bytes()).unwrap());
    Case::from_value(v, store)
}

fn state_of(case: &Case) -> &StateDiff {
    match &case.fixture.body {
        Body::StateTransition { expected, .. } => &expected.state,
        _ => panic!(),
    }
}

#[test]
fn an_absent_account_differs_from_a_present_empty_one_and_a_cleared_slot_from_an_untouched_one() {
    let store = common::store();
    let base = example("state-transition-sstore-fresh-slot.json");
    let ghost = "0x00000000000000000000000000000000000000ff";
    let absent = with(&base, &format!("/expected/state/accounts/{ghost}"), "null", &store).unwrap();
    let empty = with(&base, &format!("/expected/state/accounts/{ghost}"), r#"{"nonce":"0x0","balance":"0x0","code":"0x","storage":{}}"#, &store).unwrap();
    let mut ghost_bytes = [0u8; 20];
    ghost_bytes[19] = 0xff;
    let addr = Address(ghost_bytes);
    assert_eq!(state_of(&absent).accounts[&addr], None);
    assert!(state_of(&empty).accounts[&addr].is_some());
    assert_ne!(absent.semantic_digest(), empty.semantic_digest());

    let contract = "0x00000000000000000000000000000000000c0de0";
    let cleared = with(&base, &format!("/expected/state/accounts/{contract}/storage"), r#"{"0x0000000000000000000000000000000000000000000000000000000000000001":"0x0"}"#, &store).unwrap();
    let untouched = with(&base, &format!("/expected/state/accounts/{contract}/storage"), "{}", &store).unwrap();
    let slot1 = B256({
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    });
    let contract_addr = state_of(&cleared).accounts.keys().find(|a| a.to_string() == contract).copied().unwrap();
    assert!(state_of(&cleared).accounts[&contract_addr].as_ref().unwrap().storage[&slot1].is_zero());
    assert!(!state_of(&untouched).accounts[&contract_addr].as_ref().unwrap().storage.contains_key(&slot1));
    assert_ne!(cleared.semantic_digest(), untouched.semantic_digest());
}

#[test]
fn a_skipped_candidate_is_not_an_invalid_block() {
    // A block-import result has no "skipped" status: a forbidden inclusion makes the block invalid.
    let store = common::store();
    let base = example("invalid-block-foreign-registry-code.json");
    let err = with(&base, "/expected/blocks/0/status", r#""skipped""#, &store).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidValue);
    assert_eq!(err.path, "/expected/blocks/0/status");
}

#[test]
fn mpt_and_salt_roots_are_different_typed_commitments() {
    let store = common::store();
    let base = example("invalid-block-foreign-registry-code.json");
    let valid = r#"{"status":"valid","activeSpec":"megaeth/Satin","depositOnly":false,"activation":false,"preBlock":[],"transactions":[],
        "counters":{"gasUsed":"0x0","dataSize":"0x0","kvUpdates":"0x0","stateGrowth":"0x0"},
        "commitments":{"salt-state-root":"0x0000000000000000000000000000000000000000000000000000000000005a18"},"state":{"accounts":{}}}"#;
    let salt = with(&base, "/expected/blocks/0", valid, &store).unwrap();
    let mpt = with(&base, "/expected/blocks/0", &valid.replace("salt-state-root", "mpt-state-root"), &store).unwrap_err();
    assert_eq!(mpt.code, ErrorCode::RootOverSparseState, "an MPT root over sparse state is refused");
    let unknown = with(&base, "/expected/blocks/0", &valid.replace("salt-state-root", "state-root"), &store).unwrap_err();
    assert_eq!(unknown.code, ErrorCode::UnknownCommitment, "an untyped root is refused");
    assert!(salt.semantic_digest().starts_with("sha256:"));
}
