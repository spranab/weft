//! Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding), the
//! subset Weft objects use: ints, byte strings, text, arrays, maps, bool,
//! null. Canonical bytes are the object — relays never re-serialize, so the
//! decoder REJECTS non-canonical input (non-minimal ints, unsorted map keys).

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Arr(Vec<V>),
    Map(Vec<(V, V)>),
}

#[derive(Debug)]
pub struct CborError(pub String);
impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cbor: {}", self.0)
    }
}
impl std::error::Error for CborError {}

fn err<T>(m: &str) -> Result<T, CborError> {
    Err(CborError(m.into()))
}

pub fn encode(v: &V) -> Vec<u8> {
    let mut out = Vec::new();
    enc(v, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    match n {
        0..=23 => out.push(major << 5 | n as u8),
        24..=0xFF => {
            out.push(major << 5 | 24);
            out.push(n as u8);
        }
        0x100..=0xFFFF => {
            out.push(major << 5 | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(major << 5 | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(major << 5 | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

fn enc(v: &V, out: &mut Vec<u8>) {
    match v {
        V::Null => out.push(0xf6),
        V::Bool(true) => out.push(0xf5),
        V::Bool(false) => out.push(0xf4),
        V::Int(i) => {
            if *i >= 0 {
                head(0, *i as u64, out)
            } else {
                head(1, (-1 - *i) as u64, out)
            }
        }
        V::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend(b);
        }
        V::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend(s.as_bytes());
        }
        V::Arr(a) => {
            head(4, a.len() as u64, out);
            for x in a {
                enc(x, out)
            }
        }
        V::Map(m) => {
            let mut items: Vec<(Vec<u8>, Vec<u8>)> =
                m.iter().map(|(k, val)| (encode(k), encode(val))).collect();
            items.sort();
            head(5, items.len() as u64, out);
            for (k, val) in items {
                out.extend(k);
                out.extend(val);
            }
        }
    }
}

pub fn decode(b: &[u8]) -> Result<V, CborError> {
    let (v, used) = dec(b)?;
    if used != b.len() {
        return err("trailing bytes");
    }
    Ok(v)
}

fn dec(b: &[u8]) -> Result<(V, usize), CborError> {
    if b.is_empty() {
        return err("truncated");
    }
    let (major, ai) = (b[0] >> 5, b[0] & 0x1f);
    let mut i = 1usize;
    let n: u64 = match ai {
        0..=23 => ai as u64,
        24..=27 => {
            let size = 1usize << (ai - 24);
            if b.len() < i + size {
                return err("truncated int");
            }
            let mut n: u64 = 0;
            for &byte in &b[i..i + size] {
                n = n << 8 | byte as u64;
            }
            i += size;
            let min: u64 = if size == 1 { 24 } else { 1 << (8 * (size / 2)) };
            if n < min {
                return err("non-minimal int encoding");
            }
            n
        }
        _ => return err("unsupported additional info"),
    };
    match major {
        0 => Ok((V::Int(i64::try_from(n).map_err(|_| CborError("int overflow".into()))?), i)),
        1 => Ok((V::Int(-1 - i64::try_from(n).map_err(|_| CborError("int overflow".into()))?), i)),
        2 | 3 => {
            let n = n as usize;
            if b.len() < i + n {
                return err("truncated string");
            }
            let s = &b[i..i + n];
            i += n;
            if major == 2 {
                Ok((V::Bytes(s.to_vec()), i))
            } else {
                Ok((V::Text(String::from_utf8(s.to_vec())
                    .map_err(|_| CborError("invalid utf-8".into()))?), i))
            }
        }
        4 => {
            let mut a = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let (v, used) = dec(&b[i..])?;
                a.push(v);
                i += used;
            }
            Ok((V::Arr(a), i))
        }
        5 => {
            let mut m = Vec::with_capacity(n as usize);
            let mut last: Option<Vec<u8>> = None;
            for _ in 0..n {
                let (k, used) = dec(&b[i..])?;
                i += used;
                let ek = encode(&k);
                if let Some(prev) = &last {
                    if &ek <= prev {
                        return err("non-canonical map key order");
                    }
                }
                last = Some(ek);
                let (v, used) = dec(&b[i..])?;
                i += used;
                m.push((k, v));
            }
            Ok((V::Map(m), i))
        }
        7 => match ai {
            20 => Ok((V::Bool(false), i)),
            21 => Ok((V::Bool(true), i)),
            22 => Ok((V::Null, i)),
            _ => err("unsupported simple value"),
        },
        _ => err("unsupported major type"),
    }
}

// ------------------------------------------------------------ helpers ------

impl V {
    pub fn map(pairs: Vec<(&str, V)>) -> V {
        V::Map(pairs.into_iter().map(|(k, v)| (V::Text(k.into()), v)).collect())
    }
    pub fn get(&self, key: &str) -> Option<&V> {
        if let V::Map(m) = self {
            m.iter().find(|(k, _)| matches!(k, V::Text(t) if t == key)).map(|(_, v)| v)
        } else {
            None
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        if let V::Bytes(b) = self { Some(b) } else { None }
    }
    pub fn text(&self) -> Option<&str> {
        if let V::Text(t) = self { Some(t) } else { None }
    }
    pub fn int(&self) -> Option<i64> {
        if let V::Int(i) = self { Some(*i) } else { None }
    }
    pub fn arr(&self) -> Option<&[V]> {
        if let V::Arr(a) = self { Some(a) } else { None }
    }
}
