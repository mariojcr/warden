// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Hand-built git pushes for tests (pkt-lines, commits, packs with deltas). Shared with the
//! integration tests (tests/flow.rs includes it via `#[path]`).
#![allow(dead_code)]
use std::io::Write;

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";

pub fn pkt(s: &str) -> Vec<u8> {
    let mut out = format!("{:04x}", s.len() + 4).into_bytes();
    out.extend_from_slice(s.as_bytes());
    out
}

pub fn commit_content(parents: &[&str], msg: &str) -> Vec<u8> {
    let mut s = String::from("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
    for p in parents {
        s.push_str(&format!("parent {p}\n"));
    }
    s.push_str(&format!("author A <a@b> 1700000000 +0000\ncommitter A <a@b> 1700000000 +0000\n\n{msg}\n"));
    s.into_bytes()
}

pub fn oid_of_commit(content: &[u8]) -> String {
    let mut data = format!("commit {}\0", content.len()).into_bytes();
    data.extend_from_slice(content);
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Copies the common prefix and inserts the rest.
pub fn delta_against(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    varint(base.len(), &mut d);
    varint(target.len(), &mut d);
    let common = base.iter().zip(target).take_while(|(a, b)| a == b).count().min(0xffff);
    if common > 0 {
        let mut op = 0x80u8;
        let mut sizes = Vec::new();
        if common & 0xff != 0 {
            op |= 0x10;
            sizes.push((common & 0xff) as u8);
        }
        if (common >> 8) & 0xff != 0 {
            op |= 0x20;
            sizes.push(((common >> 8) & 0xff) as u8);
        }
        d.push(op);
        d.extend(sizes);
    }
    for chunk in target[common..].chunks(127) {
        d.push(chunk.len() as u8);
        d.extend_from_slice(chunk);
    }
    d
}

/// `OfsDelta` points at the n-th object of the same pack; `RefDelta` at an oid.
pub enum Obj {
    Plain(u8, Vec<u8>),
    OfsDelta(usize, Vec<u8>),
    RefDelta(String, Vec<u8>),
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn pack(objects: &[Obj]) -> Vec<u8> {
    let mut p = b"PACK".to_vec();
    p.extend(2u32.to_be_bytes());
    p.extend((objects.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    for o in objects {
        let at = p.len();
        offsets.push(at);
        let (kind, data, extra) = match o {
            Obj::Plain(k, d) => (*k, d.clone(), Vec::new()),
            Obj::OfsDelta(base, d) => {
                let mut rel = at - offsets[*base];
                let mut bytes = vec![(rel & 0x7f) as u8];
                rel >>= 7;
                while rel > 0 {
                    rel -= 1;
                    bytes.push(0x80 | (rel & 0x7f) as u8);
                    rel >>= 7;
                }
                bytes.reverse();
                (6, d.clone(), bytes)
            }
            Obj::RefDelta(oid, d) => {
                let raw: Vec<u8> = (0..20).map(|i| u8::from_str_radix(&oid[2 * i..2 * i + 2], 16).unwrap()).collect();
                (7, d.clone(), raw)
            }
        };
        let mut size = data.len();
        let mut first = (kind << 4) | (size & 0x0f) as u8;
        size >>= 4;
        if size > 0 {
            first |= 0x80;
        }
        p.push(first);
        while size > 0 {
            let mut b = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                b |= 0x80;
            }
            p.push(b);
        }
        p.extend(extra);
        p.extend(zlib(&data));
    }
    let sum = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &p);
    p.extend_from_slice(sum.as_ref());
    p
}

/// Commands are (old, new, ref).
pub fn push_body(commands: &[(&str, &str, &str)], pack: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    for (i, (old, new, r)) in commands.iter().enumerate() {
        let caps = if i == 0 { "\0report-status side-band-64k agent=git/2.50" } else { "" };
        body.extend(pkt(&format!("{old} {new} {r}{caps}\n")));
    }
    body.extend(b"0000");
    if let Some(p) = pack {
        body.extend_from_slice(p);
    }
    body
}
