//! Strict JSON for fixtures: the parser accepts only the JSON subset of docs/canonical-json.md
//! (UTF-8 without byte-order mark, no numbers, no duplicate members, no lone surrogates) and the
//! writer produces its unique canonical bytes.

use crate::error::{child, Error, ErrorCode};
use std::collections::BTreeMap;

/// A JSON value without numbers. Object members are kept in canonical (code point) order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// The member `key` of an object, if this is an object holding it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Resolves a JSON Pointer (RFC 6901).
    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        if pointer.is_empty() {
            return Some(self);
        }
        let rest = pointer.strip_prefix('/')?;
        let mut current = self;
        for raw in rest.split('/') {
            let token = raw.replace("~1", "/").replace("~0", "~");
            current = match current {
                Value::Object(map) => map.get(&token)?,
                Value::Array(items) => {
                    if token.is_empty()
                        || (token.len() > 1 && token.starts_with('0'))
                        || !token.bytes().all(|b| b.is_ascii_digit())
                    {
                        return None;
                    }
                    items.get(token.parse::<usize>().ok()?)?
                }
                _ => return None,
            };
        }
        Some(current)
    }

    /// The JSON type name used in error details.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

/// At most this many arrays and objects may nest.
const MAX_DEPTH: usize = 256;

/// Parses strict JSON bytes.
pub fn parse(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error::new(ErrorCode::ByteOrderMark, "", "input starts with a UTF-8 byte-order mark"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::new(ErrorCode::InvalidUtf8, "", format!("invalid UTF-8 at byte {}", e.valid_up_to())))?;
    let mut parser = Parser { text: text.as_bytes(), pos: 0 };
    parser.skip_ws();
    let value = parser.value(0, "")?;
    parser.skip_ws();
    if parser.pos != parser.text.len() {
        return Err(parser.syntax("trailing content after the value"));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn syntax(&self, what: &str) -> Error {
        Error::new(ErrorCode::InvalidJson, "", format!("{what} at byte {}", self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, Error> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.syntax("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize, path: &str) -> Result<Value, Error> {
        if depth >= MAX_DEPTH && matches!(self.peek(), Some(b'{' | b'[')) {
            return Err(self.syntax("more than 256 nested arrays and objects"));
        }
        match self.peek() {
            None => Err(self.syntax("unexpected end of input")),
            Some(b'{') => self.object(depth, path),
            Some(b'[') => self.array(depth, path),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'0'..=b'9') => Err(self.number(path)),
            Some(b'-') if matches!(self.text.get(self.pos + 1), Some(b'0'..=b'9')) => Err(self.number(path)),
            Some(_) => Err(self.syntax("unexpected character")),
        }
    }

    fn number(&self, path: &str) -> Error {
        Error::new(ErrorCode::NumberNotAllowed, path, format!("a JSON number at byte {}: quantities are strings", self.pos))
    }

    fn object(&mut self, depth: usize, path: &str) -> Result<Value, Error> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.syntax("expected a member name"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.syntax("expected ':'"));
            }
            self.pos += 1;
            self.skip_ws();
            let member = child(path, &key);
            if map.contains_key(&key) {
                return Err(Error::new(ErrorCode::DuplicateKey, member, format!("member {key:?} appears twice")));
            }
            let value = self.value(depth + 1, &member)?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.syntax("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize, path: &str) -> Result<Value, Error> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            let item_path = format!("{path}/{}", items.len());
            items.push(self.value(depth + 1, &item_path)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let digits = self.text.get(self.pos..self.pos + 4).ok_or_else(|| self.syntax("short \\u escape"))?;
        let mut value = 0u32;
        for &d in digits {
            let v = (d as char).to_digit(16).ok_or_else(|| self.syntax("invalid \\u escape"))?;
            value = value * 16 + v;
        }
        self.pos += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, Error> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // The input is valid UTF-8 and the scan stopped at an ASCII byte, so this is a char boundary.
            out.push_str(std::str::from_utf8(&self.text[start..self.pos]).expect("utf-8 checked"));
            match self.peek() {
                None => return Err(self.syntax("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escape = self.peek().ok_or_else(|| self.syntax("unterminated escape"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&unit) {
                                if self.text[self.pos..].starts_with(b"\\u") {
                                    self.pos += 2;
                                    let low = self.hex4()?;
                                    if !(0xdc00..0xe000).contains(&low) {
                                        return Err(lone_surrogate(self.pos));
                                    }
                                    0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                                } else {
                                    return Err(lone_surrogate(self.pos));
                                }
                            } else if (0xdc00..0xe000).contains(&unit) {
                                return Err(lone_surrogate(self.pos));
                            } else {
                                unit
                            };
                            out.push(char::from_u32(code).expect("surrogates handled"));
                        }
                        _ => return Err(self.syntax("invalid escape")),
                    }
                }
                Some(_) => return Err(self.syntax("control character in a string")),
            }
        }
    }
}

fn lone_surrogate(pos: usize) -> Error {
    Error::new(ErrorCode::InvalidUnicodeEscape, "", format!("unpaired UTF-16 surrogate escape before byte {pos}"))
}

/// The canonical bytes of a value: sorted members, no whitespace, the escaping of
/// docs/canonical-json.md.
pub fn to_canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write(item, out);
            }
            out.push(b'}');
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}
