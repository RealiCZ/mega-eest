//! Shared helpers of the integration tests: the repository root and its bundled specs.
#![allow(dead_code)]

use mega_fixture_format::SpecStore;
use std::path::PathBuf;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn store() -> SpecStore {
    SpecStore::load_dir(&root().join("specs")).expect("bundled specs load")
}

pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Replaces (or inserts) the value at a JSON Pointer whose parent exists.
pub fn set(v: &mut mega_fixture_format::Value, pointer: &str, new: mega_fixture_format::Value) {
    use mega_fixture_format::Value;
    let (parent, key) = pointer.rsplit_once('/').expect("a pointer below the root");
    let mut cur = v;
    for token in parent.split('/').skip(1) {
        cur = match cur {
            Value::Object(m) => m.get_mut(token).expect("parent exists"),
            Value::Array(a) => &mut a[token.parse::<usize>().expect("index")],
            _ => panic!("{pointer}: parent is a scalar"),
        };
    }
    match cur {
        Value::Object(m) => {
            m.insert(key.to_string(), new);
        }
        Value::Array(a) => a[key.parse::<usize>().expect("index")] = new,
        _ => panic!("{pointer}: parent is a scalar"),
    }
}
