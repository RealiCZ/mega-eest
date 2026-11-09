//! The examples: every positive example validates; every negative example fails with the code its
//! file name starts with.

mod common;

use mega_fixture_format::{Case, ErrorCode, Profile};

fn json_files(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(common::root().join(dir))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_example_validates_and_every_profile_has_one() {
    let store = common::store();
    let mut profiles = Vec::new();
    for name in json_files("examples") {
        let case = Case::from_bytes(&common::read(&format!("examples/{name}")), &store).unwrap_or_else(|e| panic!("{name}: {e}"));
        profiles.push(case.fixture.profile);
    }
    for p in [Profile::StateTransition, Profile::TransactionValidation, Profile::BlockImport, Profile::StatelessBlock] {
        assert!(profiles.contains(&p), "no example of {p:?}");
    }
}

#[test]
fn every_negative_example_fails_with_its_code() {
    let store = common::store();
    let names = json_files("examples/negative");
    assert!(names.len() >= 8);
    for name in names {
        let want = ErrorCode::parse(name.trim_end_matches(".json").split("--").next().unwrap()).expect("file name starts with a code");
        let err = Case::from_bytes(&common::read(&format!("examples/negative/{name}")), &store).expect_err(&name);
        assert_eq!(err.code, want, "{name}: {err}");
    }
}
