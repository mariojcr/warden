// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Minimal CBOR (RFC 8949) decoder for WebAuthn attestation objects and COSE keys.
//!
//! Definite lengths only (WebAuthn requires canonical CBOR). Depth and item counts are capped because
//! the input comes from a browser. Tags are unwrapped; simple values and floats are skipped.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Other,
}

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: u64 = 256;

impl Value {
    pub fn int_key(&self, k: i128) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(key, _)| *key == Value::Int(k)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn text_key(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(key, _)| matches!(key, Value::Text(t) if t == k)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
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
}

/// Also returns the bytes consumed: in `authData`, extensions may follow the COSE key.
pub fn decode(data: &[u8]) -> Result<(Value, usize), String> {
    let mut pos = 0;
    let v = item(data, &mut pos, 0)?;
    Ok((v, pos))
}

fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = pos.checked_add(n).filter(|e| *e <= data.len()).ok_or("CBOR: truncated")?;
    let s = &data[*pos..end];
    *pos = end;
    Ok(s)
}

fn argument(data: &[u8], pos: &mut usize, info: u8) -> Result<u64, String> {
    Ok(match info {
        0..=23 => info as u64,
        24 => take(data, pos, 1)?[0] as u64,
        25 => u16::from_be_bytes(take(data, pos, 2)?.try_into().unwrap()) as u64,
        26 => u32::from_be_bytes(take(data, pos, 4)?.try_into().unwrap()) as u64,
        27 => u64::from_be_bytes(take(data, pos, 8)?.try_into().unwrap()),
        31 => return Err("CBOR: indefinite lengths are not allowed".into()),
        _ => return Err("CBOR: reserved header".into()),
    })
}

fn item(data: &[u8], pos: &mut usize, depth: usize) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err("CBOR: nested too deep".into());
    }
    let head = take(data, pos, 1)?[0];
    let (major, info) = (head >> 5, head & 0x1f);
    if major == 7 {
        match info {
            0..=23 => {}
            24 => {
                take(data, pos, 1)?;
            }
            25 => {
                take(data, pos, 2)?;
            }
            26 => {
                take(data, pos, 4)?;
            }
            27 => {
                take(data, pos, 8)?;
            }
            _ => return Err("CBOR: unexpected break or reserved simple value".into()),
        }
        return Ok(Value::Other);
    }
    let arg = argument(data, pos, info)?;
    Ok(match major {
        0 => Value::Int(arg as i128),
        1 => Value::Int(-1 - arg as i128),
        2 => Value::Bytes(take(data, pos, usize::try_from(arg).map_err(|_| "CBOR: too long")?)?.to_vec()),
        3 => {
            let raw = take(data, pos, usize::try_from(arg).map_err(|_| "CBOR: too long")?)?;
            Value::Text(String::from_utf8(raw.to_vec()).map_err(|_| "CBOR: text is not UTF-8")?)
        }
        4 => {
            if arg > MAX_ITEMS {
                return Err("CBOR: array too long".into());
            }
            let mut list = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                list.push(item(data, pos, depth + 1)?);
            }
            Value::Array(list)
        }
        5 => {
            if arg > MAX_ITEMS {
                return Err("CBOR: map too long".into());
            }
            let mut map = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                let k = item(data, pos, depth + 1)?;
                let v = item(data, pos, depth + 1)?;
                if map.iter().any(|(seen, _)| *seen == k) {
                    return Err("CBOR: duplicate map key".into());
                }
                map.push((k, v));
            }
            Value::Map(map)
        }
        6 => item(data, pos, depth + 1)?,
        _ => unreachable!("major type is three bits"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_an_authenticator_writes_and_nothing_else() {
        // {"fmt": "none", "attStmt": {}, "authData": h'0102'}
        let mut obj = vec![0xa3, 0x63];
        obj.extend(b"fmt");
        obj.push(0x64);
        obj.extend(b"none");
        obj.push(0x67);
        obj.extend(b"attStmt");
        obj.push(0xa0);
        obj.push(0x68);
        obj.extend(b"authData");
        obj.extend([0x42, 1, 2]);
        let (v, used) = decode(&obj).unwrap();
        assert_eq!(used, obj.len());
        assert_eq!(v.text_key("authData").unwrap().as_bytes(), Some(&[1u8, 2][..]));
        assert_eq!(v.text_key("fmt"), Some(&Value::Text("none".into())));

        // Integer keys, negatives included; trailing bytes are left unread.
        let (v, used) = decode(&[0xa3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0xff]).unwrap();
        assert_eq!(used, 7);
        assert_eq!(v.int_key(3).and_then(Value::as_int), Some(-7));
        assert_eq!(v.int_key(-1).and_then(Value::as_int), Some(1));

        for bad in [&[0x5f][..], &[0x42, 1], &[0xa2, 0x01, 0x02, 0x01, 0x03], &[0x9f], &[0x1c], &[0xff]] {
            assert!(decode(bad).is_err(), "{bad:02x?}");
        }
        // No unbounded nesting, and a length prefix can't make us allocate.
        assert!(decode(&[0x81; 20]).is_err());
        assert!(decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(decode(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
