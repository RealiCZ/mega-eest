//! The published vectors, read by the Rust reader (tools/check_vectors.py is the second reader).

mod common;

use mega_fixture_format::{canonicalize, json, sha256_digest, Case, ErrorCode, Manifest, Value};

/// What a reader produces for an accepted vector: canonical bytes and the named digests.
type Produced<'a> = Result<(Vec<u8>, Vec<(&'a str, String)>), mega_fixture_format::Error>;

const JSON_LAYER: [&str; 6] = ["invalid-utf8", "byte-order-mark", "invalid-json", "duplicate-key", "number-not-allowed", "invalid-unicode-escape"];

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("member {k}"))
}

#[test]
fn every_vector_is_reproduced() {
    let store = common::store();
    let index = json::parse(&common::read("vectors/index.json")).unwrap();
    let Some(Value::Array(vectors)) = index.get("vectors") else { panic!("vectors") };
    assert!(vectors.len() >= 40, "the vector set shrank");
    let mut rejected = 0;
    for v in vectors {
        let id = s(v, "id");
        let input = common::read(&format!("vectors/{}", s(v, "input")));
        let kind = s(v, "kind");
        let result: Produced = match kind {
            "json" => canonicalize(&input).map(|c| {
                let d = sha256_digest(&c);
                (c, vec![("digest", d)])
            }),
            "case" => Case::from_bytes(&input, &store)
                .map(|c| (c.canonical_bytes(), vec![("fileDigest", c.file_digest()), ("semanticDigest", c.semantic_digest())])),
            "manifest" => Manifest::from_bytes(&input).map(|m| (m.canonical_bytes(), vec![("digest", m.digest())])),
            other => panic!("{id}: unknown kind {other}"),
        };
        match (result, v.get("error")) {
            (Ok((canonical, digests)), None) => {
                assert_eq!(canonical, common::read(&format!("vectors/{}", s(v, "canonical"))), "{id}: canonical bytes");
                for (key, digest) in digests {
                    assert_eq!(digest, s(v, key), "{id}: {key}");
                }
            }
            (Err(e), Some(want)) => {
                rejected += 1;
                assert_eq!(e.code, ErrorCode::parse(s(want, "code")).expect("known code"), "{id}: {e}");
                if !JSON_LAYER.contains(&s(want, "code")) {
                    assert_eq!(e.path, s(want, "path"), "{id}: path");
                }
            }
            (Ok(_), Some(want)) => panic!("{id}: accepted, expected {}", s(want, "code")),
            (Err(e), None) => panic!("{id}: rejected: {e}"),
        }
    }
    assert!(rejected >= 20, "the rejection vectors shrank");
}

#[test]
fn renaming_a_case_keeps_its_semantic_digest_and_changes_its_file_digest() {
    let store = common::store();
    let original = Case::from_bytes(&common::read("vectors/accept/case-state-transition-sstore-fresh-slot.in.json"), &store).unwrap();
    let renamed = Case::from_bytes(&common::read("vectors/accept/case-same-semantics-other-name.in.json"), &store).unwrap();
    assert_ne!(original.fixture.case_id, renamed.fixture.case_id);
    assert_eq!(original.semantic_digest(), renamed.semantic_digest());
    assert_ne!(original.file_digest(), renamed.file_digest());
}
