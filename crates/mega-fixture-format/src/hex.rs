//! Hex-encoded scalars and the classification of a malformed one into a stable error code
//! (docs/canonical-json.md, "Hex strings").

use crate::error::ErrorCode;

/// The kinds of hex string the format uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexKind {
    /// A nonnegative integer of at most `bits` bits: minimal lowercase hex, `0x0` for zero.
    Quantity { bits: usize },
    /// A byte string of any length: even-length lowercase hex.
    Bytes,
    /// Exactly `bytes` bytes.
    Fixed { bytes: usize },
    /// `sha256:` and 32 bytes of lowercase hex.
    Digest,
}

/// Checks a hex string of the given kind, reporting the first failing check in the documented
/// order: prefix, characters, case, then the kind's own shape.
pub fn check(s: &str, kind: HexKind) -> Result<&str, ErrorCode> {
    let digits = match kind {
        HexKind::Digest => s.strip_prefix("sha256:").ok_or(ErrorCode::InvalidDigest)?,
        _ => s.strip_prefix("0x").ok_or(ErrorCode::MissingHexPrefix)?,
    };
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ErrorCode::InvalidHex);
    }
    if digits.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ErrorCode::UppercaseHex);
    }
    match kind {
        HexKind::Quantity { bits } => {
            if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
                return Err(ErrorCode::NonMinimalQuantity);
            }
            if digits.len() > bits / 4 {
                return Err(ErrorCode::QuantityOverflow);
            }
        }
        HexKind::Bytes => {
            if digits.len() % 2 != 0 {
                return Err(ErrorCode::OddLengthBytes);
            }
        }
        HexKind::Fixed { bytes } => {
            if digits.len() != 2 * bytes {
                return Err(ErrorCode::WrongWidth);
            }
        }
        HexKind::Digest => {
            if digits.len() != 64 {
                return Err(ErrorCode::WrongWidth);
            }
        }
    }
    Ok(digits)
}

/// Decodes checked lowercase hex digits of even length into bytes.
pub(crate) fn to_bytes(digits: &str) -> Vec<u8> {
    let raw = digits.as_bytes();
    let nibble = |b: u8| (b as char).to_digit(16).expect("checked hex") as u8;
    (0..raw.len() / 2).map(|i| nibble(raw[2 * i]) << 4 | nibble(raw[2 * i + 1])).collect()
}

/// Decodes checked quantity digits into a big-endian 32-byte array.
pub(crate) fn quantity_to_be32(digits: &str) -> [u8; 32] {
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    out.copy_from_slice(&to_bytes(&padded));
    out
}

/// Lowercase hex of bytes with a `0x` prefix.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
