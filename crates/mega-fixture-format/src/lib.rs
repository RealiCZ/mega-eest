//! The wire contract of MegaETH execution fixtures (`mega-execution-fixture` 1.x).
//!
//! This crate decodes and validates fixtures, writes their canonical JSON, computes their digests
//! and compares an implementation's observations with a fixture's expected result. It depends on
//! no execution engine: adapters convert between these types and an implementation's own.
//!
//! The JSON Schemas under `schema/` and the documents under `docs/` are the specification; this
//! crate is one reader of it, and `tools/check_vectors.py` is an independent second one.
//!
//! ```no_run
//! use mega_fixture_format::{Case, SpecStore};
//! let store = SpecStore::load_dir(std::path::Path::new("specs")).unwrap();
//! let case = Case::from_bytes(&std::fs::read("examples/state-transition-sstore-fresh-slot.json").unwrap(), &store).unwrap();
//! println!("{} {}", case.fixture.case_id, case.semantic_digest());
//! ```

pub mod compare;
mod decode;
pub mod error;
pub mod hex;
pub mod json;
pub mod manifest;
pub mod model;
pub mod registry;
pub mod validate;

pub use compare::{compare, Verdict};
pub use error::{Error, ErrorCode};
pub use json::Value;
pub use manifest::Manifest;
pub use model::{Fixture, Profile, Requirement};
pub use registry::SpecStore;

use sha2::{Digest as _, Sha256};

/// Parses strict JSON and returns its canonical bytes.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(json::to_canonical(&json::parse(bytes)?))
}

/// `sha256:` and the lowercase hex SHA-256 of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::from("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The envelope members the semantic digest leaves out: the logical name and the provenance.
pub const NON_SEMANTIC: [&str; 2] = ["caseId", "provenance"];

/// A validated fixture: its value tree and its typed form.
#[derive(Clone, Debug)]
pub struct Case {
    pub value: Value,
    pub fixture: Fixture,
}

impl Case {
    /// Parses, decodes and validates a fixture against the specs of `store`.
    pub fn from_bytes(bytes: &[u8], store: &SpecStore) -> Result<Case, Error> {
        let value = json::parse(bytes)?;
        Case::from_value(value, store)
    }

    /// Decodes and validates a parsed fixture.
    pub fn from_value(value: Value, store: &SpecStore) -> Result<Case, Error> {
        let fixture = Fixture::decode(&value)?;
        validate::validate(&value, &fixture, store)?;
        Ok(Case { value, fixture })
    }

    /// The canonical bytes of the whole fixture: what a release stores and its manifest hashes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        json::to_canonical(&self.value)
    }

    /// The file digest: SHA-256 of the canonical bytes.
    pub fn file_digest(&self) -> String {
        sha256_digest(&self.canonical_bytes())
    }

    /// The semantic digest: SHA-256 of the canonical bytes of the fixture without `caseId` and
    /// `provenance`. Two fixtures with equal semantic digests test the same thing.
    pub fn semantic_digest(&self) -> String {
        sha256_digest(&json::to_canonical(&semantic_projection(&self.value)))
    }
}

/// The fixture without its non-semantic members.
pub fn semantic_projection(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            Value::Object(map.iter().filter(|(k, _)| !NON_SEMANTIC.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect())
        }
        other => other.clone(),
    }
}
