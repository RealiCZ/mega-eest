//! The canonical JSON seam: input bytes in, canonical bytes or a stable error code out.

use mega_fixture_format::{canonicalize, sha256_digest, ErrorCode};

fn canon(input: &str) -> String {
    String::from_utf8(canonicalize(input.as_bytes()).expect("accepted")).unwrap()
}

fn rejected(input: &[u8]) -> ErrorCode {
    canonicalize(input).expect_err("rejected").code
}

#[test]
fn members_are_sorted_by_code_point_and_whitespace_dropped() {
    assert_eq!(canon(" { \"b\" : [true , null] ,\n\t\"a\":\"x\", \"B\": {} }\r\n"), r#"{"B":{},"a":"x","b":[true,null]}"#);
    // U+00E9 sorts after "z"; U+1F600 after U+FFFD (code point order, not UTF-16 order).
    assert_eq!(canon(r#"{"z":"","é":"","😀":"","�":""}"#), "{\"z\":\"\",\"é\":\"\",\"\u{fffd}\":\"\",\"😀\":\"\"}");
}

#[test]
fn strings_use_the_prescribed_escapes() {
    assert_eq!(canon(r#""A\/\b\f\n\r\t\u0001\u001F\u007fé😀\"\\""#), "\"A/\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é😀\\\"\\\\\"");
    assert_eq!(canon("\"\u{2028}\""), "\"\u{2028}\"");
}

#[test]
fn arrays_keep_their_order() {
    assert_eq!(canon(r#"["b","a",["c"]]"#), r#"["b","a",["c"]]"#);
}

#[test]
fn the_digest_is_sha256_of_the_canonical_bytes() {
    // SHA-256 of the two bytes "{}".
    assert_eq!(sha256_digest(b"{}"), "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
}

#[test]
fn non_canonical_inputs_are_rejected_with_their_code() {
    assert_eq!(rejected(br#"{"a":"1","a":"2"}"#), ErrorCode::DuplicateKey);
    assert_eq!(rejected(br#"{"a":"1","a":"2"}"#), ErrorCode::DuplicateKey);
    assert_eq!(rejected(br#"{"a":1.5}"#), ErrorCode::NumberNotAllowed);
    assert_eq!(rejected(br#"{"a":-1}"#), ErrorCode::NumberNotAllowed);
    assert_eq!(rejected(br#"[0]"#), ErrorCode::NumberNotAllowed);
    assert_eq!(rejected(b"\xef\xbb\xbf{}"), ErrorCode::ByteOrderMark);
    assert_eq!(rejected(b"{\"a\":\"\xff\"}"), ErrorCode::InvalidUtf8);
    assert_eq!(rejected(br#"["\ud800"]"#), ErrorCode::InvalidUnicodeEscape);
    assert_eq!(rejected(br#"["\udc00\ud800"]"#), ErrorCode::InvalidUnicodeEscape);
    assert_eq!(rejected(br#"{"a":"1",}"#), ErrorCode::InvalidJson);
    assert_eq!(rejected(br#"{"a":NaN}"#), ErrorCode::InvalidJson);
    assert_eq!(rejected(br#"{"a":-Infinity}"#), ErrorCode::InvalidJson);
    assert_eq!(rejected(b"{\"a\":\"tab\there\"}"), ErrorCode::InvalidJson);
    assert_eq!(rejected(br#"{} {}"#), ErrorCode::InvalidJson);
    assert_eq!(rejected(b""), ErrorCode::InvalidJson);
}
