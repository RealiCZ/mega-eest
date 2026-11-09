//! Errors: a stable code from docs/canonical-json.md, the JSON Pointer of the value at fault and a
//! human-readable detail. Codes are part of the contract; details are not.

use std::fmt;

macro_rules! codes {
    ($($variant:ident => $text:literal,)*) => {
        /// A stable error code. Its text form is what vectors and reports carry.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorCode { $($variant,)* }

        impl ErrorCode {
            /// The code's text form, such as `duplicate-key`.
            pub fn as_str(self) -> &'static str {
                match self { $(ErrorCode::$variant => $text,)* }
            }

            /// The code whose text form is `text`.
            pub fn parse(text: &str) -> Option<ErrorCode> {
                match text { $($text => Some(ErrorCode::$variant),)* _ => None }
            }
        }
    };
}

codes! {
    // JSON layer.
    InvalidUtf8 => "invalid-utf8",
    ByteOrderMark => "byte-order-mark",
    InvalidJson => "invalid-json",
    DuplicateKey => "duplicate-key",
    NumberNotAllowed => "number-not-allowed",
    InvalidUnicodeEscape => "invalid-unicode-escape",
    // Schema layer.
    UnknownField => "unknown-field",
    MissingField => "missing-field",
    WrongType => "wrong-type",
    InvalidValue => "invalid-value",
    UnsupportedFormat => "unsupported-format",
    UnsupportedSchemaVersion => "unsupported-schema-version",
    UnknownProfile => "unknown-profile",
    UnknownRequirement => "unknown-requirement",
    UnknownCommitment => "unknown-commitment",
    MissingHexPrefix => "missing-hex-prefix",
    InvalidHex => "invalid-hex",
    UppercaseHex => "uppercase-hex",
    NonMinimalQuantity => "non-minimal-quantity",
    QuantityOverflow => "quantity-overflow",
    OddLengthBytes => "odd-length-bytes",
    WrongWidth => "wrong-width",
    InvalidDigest => "invalid-digest",
    InvalidSignedInteger => "invalid-signed-integer",
    InvalidRuleRef => "invalid-rule-ref",
    InvalidCaseId => "invalid-case-id",
    TooFewItems => "too-few-items",
    TooManyItems => "too-many-items",
    UnboundAssertion => "unbound-assertion",
    // Semantic layer.
    UnsortedSet => "unsorted-set",
    RequirementMismatch => "requirement-mismatch",
    UnknownSpec => "unknown-spec",
    SpecNameMismatch => "spec-name-mismatch",
    UnknownRule => "unknown-rule",
    UnknownRuleRow => "unknown-rule-row",
    RetiredRule => "retired-rule",
    AssertionRuleNotCited => "assertion-rule-not-cited",
    UncoveredRule => "uncovered-rule",
    InconsistentOutcome => "inconsistent-outcome",
    ZeroSlotInCompleteState => "zero-slot-in-complete-state",
    RootOverSparseState => "root-over-sparse-state",
    InvalidReference => "invalid-reference",
}

/// A rejection: why an input is not a valid fixture (or not canonical JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The stable code.
    pub code: ErrorCode,
    /// JSON Pointer of the value at fault; empty for JSON-layer errors and the whole document.
    pub path: String,
    /// Free text for humans.
    pub detail: String,
}

impl Error {
    pub(crate) fn new(code: ErrorCode, path: impl Into<String>, detail: impl Into<String>) -> Self {
        Error { code, path: path.into(), detail: detail.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}: {}", self.code.as_str(), self.detail)
        } else {
            write!(f, "{} at {}: {}", self.code.as_str(), self.path, self.detail)
        }
    }
}

impl std::error::Error for Error {}

/// Appends one reference token to a JSON Pointer (RFC 6901 escaping).
pub(crate) fn child(path: &str, token: &str) -> String {
    let mut out = String::with_capacity(path.len() + token.len() + 1);
    out.push_str(path);
    out.push('/');
    for c in token.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
    out
}

/// Appends an array index to a JSON Pointer.
pub(crate) fn index(path: &str, i: usize) -> String {
    format!("{path}/{i}")
}
