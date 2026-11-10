//! Strict decoding helpers: every object is closed, every scalar is checked against its schema
//! definition, and each failure carries the code and JSON Pointer the schema assigns it.

use crate::error::{child, index, Error, ErrorCode};
use crate::hex::{self, HexKind};
use crate::json::Value;
use crate::model::{Address, B256, U256};
use std::collections::BTreeMap;

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) fn wrong_type(path: &str, want: &str, got: &Value) -> Error {
    Error::new(ErrorCode::WrongType, path, format!("expected {want}, found {}", got.type_name()))
}

/// A closed object being decoded: members are taken one by one and `finish` rejects the rest.
pub(crate) struct Obj<'a> {
    map: &'a BTreeMap<String, Value>,
    pub(crate) path: String,
    taken: Vec<&'a str>,
}

impl<'a> Obj<'a> {
    pub(crate) fn new(value: &'a Value, path: &str) -> Result<Obj<'a>> {
        match value {
            Value::Object(map) => Ok(Obj { map, path: path.to_string(), taken: Vec::new() }),
            other => Err(wrong_type(path, "object", other)),
        }
    }

    /// Checks that every listed member is present, before any member is decoded.
    pub(crate) fn require(&self, names: &[&str]) -> Result<()> {
        for name in names {
            if !self.map.contains_key(*name) {
                return Err(Error::new(ErrorCode::MissingField, child(&self.path, name), format!("missing member {name:?}")));
            }
        }
        Ok(())
    }

    /// Checks that no member outside `allowed` is present.
    pub(crate) fn closed(&self, allowed: &[&str]) -> Result<()> {
        for key in self.map.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(Error::new(ErrorCode::UnknownField, child(&self.path, key), format!("unknown member {key:?}")));
            }
        }
        Ok(())
    }

    /// Requires `required`, allows `optional` too, and rejects anything else.
    pub(crate) fn shape(&self, required: &[&str], optional: &[&str]) -> Result<()> {
        self.require(required)?;
        let allowed: Vec<&str> = required.iter().chain(optional.iter()).copied().collect();
        self.closed(&allowed)
    }

    /// A required member (checked present by `shape`).
    pub(crate) fn req(&mut self, name: &'a str) -> (&'a Value, String) {
        self.taken.push(name);
        let value = self.map.get(name).expect("presence checked by shape");
        (value, child(&self.path, name))
    }

    /// An optional member.
    pub(crate) fn opt(&mut self, name: &'a str) -> Option<(&'a Value, String)> {
        self.taken.push(name);
        self.map.get(name).map(|v| (v, child(&self.path, name)))
    }
}

pub(crate) fn string<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| wrong_type(path, "string", value))
}

pub(crate) fn boolean(value: &Value, path: &str) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        other => Err(wrong_type(path, "boolean", other)),
    }
}

pub(crate) fn hex_str<'a>(value: &'a Value, path: &str, kind: HexKind) -> Result<&'a str> {
    let s = string(value, path)?;
    hex::check(s, kind).map_err(|code| Error::new(code, path, format!("{s:?} is not a valid {kind:?}")))
}

pub(crate) fn u64q(value: &Value, path: &str) -> Result<u64> {
    let digits = hex_str(value, path, HexKind::Quantity { bits: 64 })?;
    Ok(u64::from_str_radix(digits, 16).expect("checked 64-bit quantity"))
}

pub(crate) fn u256(value: &Value, path: &str) -> Result<U256> {
    let digits = hex_str(value, path, HexKind::Quantity { bits: 256 })?;
    Ok(U256(hex::quantity_to_be32(digits)))
}

pub(crate) fn bytes(value: &Value, path: &str) -> Result<Vec<u8>> {
    Ok(hex::to_bytes(hex_str(value, path, HexKind::Bytes)?))
}

pub(crate) fn fixed<const N: usize>(value: &Value, path: &str) -> Result<[u8; N]> {
    let digits = hex_str(value, path, HexKind::Fixed { bytes: N })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&hex::to_bytes(digits));
    Ok(out)
}

pub(crate) fn address(value: &Value, path: &str) -> Result<Address> {
    Ok(Address(fixed::<20>(value, path)?))
}

pub(crate) fn b256(value: &Value, path: &str) -> Result<B256> {
    Ok(B256(fixed::<32>(value, path)?))
}

pub(crate) fn digest(value: &Value, path: &str) -> Result<String> {
    hex_str(value, path, HexKind::Digest)?;
    Ok(string(value, path)?.to_string())
}

/// A canonical signed decimal in [-2^127, 2^127 - 1].
pub(crate) fn signed(value: &Value, path: &str) -> Result<i128> {
    let s = string(value, path)?;
    let bad = || Error::new(ErrorCode::InvalidSignedInteger, path, format!("{s:?} is not a canonical signed integer"));
    let digits = s.strip_prefix('-').unwrap_or(s);
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && s != "-0";
    if !canonical {
        return Err(bad());
    }
    s.parse::<i128>().map_err(|_| bad())
}

/// A value matching `pattern` (a closed set of characters and shapes checked by `ok`).
pub(crate) fn patterned<'a>(value: &'a Value, path: &str, code: ErrorCode, ok: impl Fn(&str) -> bool) -> Result<&'a str> {
    let s = string(value, path)?;
    if ok(s) {
        Ok(s)
    } else {
        Err(Error::new(code, path, format!("{s:?} does not have the required form")))
    }
}

/// One of a closed set of strings, mapped to its typed value.
pub(crate) fn one_of<T: Copy>(value: &Value, path: &str, table: &[(&str, T)], code: ErrorCode) -> Result<T> {
    let s = string(value, path)?;
    table
        .iter()
        .find(|(name, _)| *name == s)
        .map(|(_, v)| *v)
        .ok_or_else(|| Error::new(code, path, format!("{s:?} is not one of the allowed values")))
}

/// A string constant.
pub(crate) fn constant(value: &Value, path: &str, want: &str, code: ErrorCode) -> Result<()> {
    let s = string(value, path)?;
    if s == want {
        Ok(())
    } else {
        Err(Error::new(code, path, format!("expected {want:?}, found {s:?}")))
    }
}

pub(crate) fn nullable<T>(value: &Value, path: &str, f: impl FnOnce(&Value, &str) -> Result<T>) -> Result<Option<T>> {
    match value {
        Value::Null => Ok(None),
        other => f(other, path).map(Some),
    }
}

pub(crate) fn array<T>(value: &Value, path: &str, min: usize, max: Option<usize>, mut f: impl FnMut(&Value, &str) -> Result<T>) -> Result<Vec<T>> {
    let items = match value {
        Value::Array(items) => items,
        other => return Err(wrong_type(path, "array", other)),
    };
    if items.len() < min {
        return Err(Error::new(ErrorCode::TooFewItems, path, format!("at least {min} item(s) required")));
    }
    if let Some(max) = max {
        if items.len() > max {
            return Err(Error::new(ErrorCode::TooManyItems, path, format!("at most {max} item(s) allowed")));
        }
    }
    items.iter().enumerate().map(|(i, item)| f(item, &index(path, i))).collect()
}

/// An object used as a map: each key is checked by `key` (as a string value at the member's
/// pointer), each value by `val`.
pub(crate) fn map<K: Ord, T>(
    value: &Value,
    path: &str,
    mut key: impl FnMut(&Value, &str) -> Result<K>,
    mut val: impl FnMut(&Value, &str) -> Result<T>,
) -> Result<BTreeMap<K, T>> {
    let members = match value {
        Value::Object(map) => map,
        other => return Err(wrong_type(path, "object", other)),
    };
    let mut out = BTreeMap::new();
    for (k, v) in members {
        let member = child(path, k);
        let typed_key = key(&Value::String(k.clone()), &member)?;
        out.insert(typed_key, val(v, &member)?);
    }
    Ok(out)
}
