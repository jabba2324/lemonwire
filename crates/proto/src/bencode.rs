//! A small, strict bencode decoder/encoder.
//!
//! Torrent infohashes are the SHA-1 of the *exact* bytes of the `info` dictionary, so
//! besides a normal [`Value`] tree this module can split a dictionary into raw
//! `(key, bytes)` entries. That lets us strip or inject top-level keys (announce,
//! comment, …) while copying `info` byte for byte.

use std::collections::BTreeMap;

const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BencodeError {
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid bencode at byte {0}")]
    Invalid(usize),
    #[error("nesting too deep")]
    TooDeep,
    #[error("trailing data after value")]
    Trailing,
    #[error("duplicate dictionary key")]
    DuplicateKey,
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict()?.get(key.as_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(i) => {
                out.push(b'i');
                out.extend_from_slice(i.to_string().as_bytes());
                out.push(b'e');
            }
            Value::Bytes(b) => encode_bytes(b, out),
            Value::List(l) => {
                out.push(b'l');
                for v in l {
                    v.encode_into(out);
                }
                out.push(b'e');
            }
            Value::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    encode_bytes(k, out);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Bytes(s.as_bytes().to_vec())
    }
}

pub fn encode_bytes(b: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(b.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(b);
}

/// Decode a complete bencoded value.
pub fn decode(input: &[u8]) -> Result<Value, BencodeError> {
    let mut p = Parser { input, pos: 0 };
    let v = p.value(0)?;
    if p.pos != input.len() {
        return Err(BencodeError::Trailing);
    }
    Ok(v)
}

/// `(key, raw value bytes)` pairs of a dictionary.
pub type RawEntries<'a> = Vec<(Vec<u8>, &'a [u8])>;

/// Split a top-level dictionary into raw entries, in input order.
pub fn decode_dict_raw(input: &[u8]) -> Result<RawEntries<'_>, BencodeError> {
    let mut p = Parser { input, pos: 0 };
    if p.peek()? != b'd' {
        return Err(BencodeError::Invalid(0));
    }
    p.pos += 1;
    let mut entries: RawEntries = Vec::new();
    while p.peek()? != b'e' {
        let key = p.bytes()?;
        if entries.iter().any(|(k, _)| *k == key) {
            return Err(BencodeError::DuplicateKey);
        }
        let start = p.pos;
        p.value(1)?;
        entries.push((key, &input[start..p.pos]));
    }
    p.pos += 1;
    if p.pos != input.len() {
        return Err(BencodeError::Trailing);
    }
    Ok(entries)
}

/// Encode `(key, raw value)` pairs as a dictionary, sorting keys as bencode requires.
pub fn encode_dict_raw(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = vec![b'd'];
    for (k, v) in sorted {
        encode_bytes(k, &mut out);
        out.extend_from_slice(v);
    }
    out.push(b'e');
    out
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Result<u8, BencodeError> {
        self.input.get(self.pos).copied().ok_or(BencodeError::Eof)
    }

    fn value(&mut self, depth: usize) -> Result<Value, BencodeError> {
        if depth > MAX_DEPTH {
            return Err(BencodeError::TooDeep);
        }
        match self.peek()? {
            b'i' => {
                self.pos += 1;
                let end = self.find(b'e')?;
                let n = self.parse_int(self.pos, end)?;
                self.pos = end + 1;
                Ok(Value::Int(n))
            }
            b'l' => {
                self.pos += 1;
                let mut list = Vec::new();
                while self.peek()? != b'e' {
                    list.push(self.value(depth + 1)?);
                }
                self.pos += 1;
                Ok(Value::List(list))
            }
            b'd' => {
                self.pos += 1;
                let mut dict = BTreeMap::new();
                while self.peek()? != b'e' {
                    let key = self.bytes()?;
                    let v = self.value(depth + 1)?;
                    if dict.insert(key, v).is_some() {
                        return Err(BencodeError::DuplicateKey);
                    }
                }
                self.pos += 1;
                Ok(Value::Dict(dict))
            }
            b'0'..=b'9' => Ok(Value::Bytes(self.bytes()?)),
            _ => Err(BencodeError::Invalid(self.pos)),
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, BencodeError> {
        let colon = self.find(b':')?;
        let len = self.parse_int(self.pos, colon)?;
        let len = usize::try_from(len).map_err(|_| BencodeError::Invalid(self.pos))?;
        let start = colon + 1;
        let end = start.checked_add(len).ok_or(BencodeError::Eof)?;
        if end > self.input.len() {
            return Err(BencodeError::Eof);
        }
        self.pos = end;
        Ok(self.input[start..end].to_vec())
    }

    fn find(&self, byte: u8) -> Result<usize, BencodeError> {
        self.input[self.pos..]
            .iter()
            .position(|&b| b == byte)
            .map(|i| self.pos + i)
            .ok_or(BencodeError::Eof)
    }

    fn parse_int(&self, start: usize, end: usize) -> Result<i64, BencodeError> {
        let s = std::str::from_utf8(&self.input[start..end])
            .map_err(|_| BencodeError::Invalid(start))?;
        let digits = s.strip_prefix('-').unwrap_or(s);
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
            && s != "-0";
        if !canonical {
            return Err(BencodeError::Invalid(start));
        }
        s.parse().map_err(|_| BencodeError::Invalid(start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let input = b"d3:bar4:spam3:fooi42e4:listl1:ai-3eee";
        let v = decode(input).unwrap();
        assert_eq!(v.get("foo").unwrap().as_int(), Some(42));
        assert_eq!(v.get("bar").unwrap().as_str(), Some("spam"));
        assert_eq!(v.encode(), input);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode(b"i01e").is_err());
        assert!(decode(b"i-0e").is_err());
        assert!(decode(b"ie").is_err());
        assert!(decode(b"5:abc").is_err());
        assert!(decode(b"d1:ai1e1:ai2ee").is_err());
        assert_eq!(decode(b"i1ei2e"), Err(BencodeError::Trailing));
        let deep = "l".repeat(100) + &"e".repeat(100);
        assert_eq!(decode(deep.as_bytes()), Err(BencodeError::TooDeep));
    }

    #[test]
    fn raw_dict_keeps_bytes() {
        // Unsorted keys inside `info` must survive untouched.
        let input = b"d8:announce3:url4:infod4:name1:x6:lengthi1eee";
        let entries = decode_dict_raw(input).unwrap();
        assert_eq!(entries[1].0, b"info");
        assert_eq!(entries[1].1, b"d4:name1:x6:lengthi1ee");
        let rebuilt: Vec<_> = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.to_vec()))
            .collect();
        assert_eq!(encode_dict_raw(&rebuilt), input);
    }
}
