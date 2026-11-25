// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Reads `git push` bodies (git-receive-pack) to work out which powers a push needs.
//!
//! New commits are not on GitHub until the pack applies, so fast-forwards are checked against the pack
//! as it streams while the proxy holds back its 20-byte trailer, without which GitHub applies nothing.
//! GitHub rejects a command whose old id is not the ref's current value, so checking from that id is
//! checking from what was there.
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use flate2::{Decompress, FlushDecompress, Status};

use crate::scope::Power;

/// Bytes of commands, push-options included.
pub const COMMANDS_MAX: usize = 1 << 20;
const OID_HEX: usize = 40;
const ZERO: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    pub old: String,
    pub new: String,
    pub refname: String,
}

impl Command {
    pub fn is_create(&self) -> bool {
        self.old == ZERO
    }
    pub fn is_delete(&self) -> bool {
        self.new == ZERO
    }
}

/// Also returns the bytes taken, flushes and push-options included. `None` means more bytes are needed.
pub fn parse_commands(buf: &[u8]) -> Result<Option<(Vec<Command>, usize)>, String> {
    let mut pos = 0;
    let mut commands = Vec::new();
    let mut caps = String::new();
    let mut section = 0; // 0: commands, 1: push-options
    loop {
        let Some(len_hex) = buf.get(pos..pos + 4) else {
            return Ok(None);
        };
        let len_str = std::str::from_utf8(len_hex).map_err(|_| "malformed pkt-line")?;
        if !len_str.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("malformed pkt-line".into());
        }
        let len = usize::from_str_radix(len_str, 16).map_err(|_| "malformed pkt-line")?;
        if len == 0 {
            pos += 4;
            if section == 0 && caps.split(' ').any(|c| c == "push-options") {
                section = 1;
                continue;
            }
            break;
        }
        if len < 4 {
            return Err("unexpected special pkt-line in a push".into());
        }
        let Some(payload) = buf.get(pos + 4..pos + len) else {
            return Ok(None);
        };
        pos += len;
        if section == 1 {
            continue;
        }
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        let (line, rest) = match payload.iter().position(|&b| b == 0) {
            Some(n) => (&payload[..n], Some(&payload[n + 1..])),
            None => (payload, None),
        };
        let line = std::str::from_utf8(line).map_err(|_| "a push command is not UTF-8")?;
        if let Some(rest) = rest {
            caps = String::from_utf8_lossy(rest).into_owned();
        }
        if line.starts_with("shallow ") {
            continue;
        }
        if line.starts_with("push-cert") {
            return Err("signed pushes (push certificates) are not supported through warden".into());
        }
        let mut parts = line.split(' ');
        let (Some(old), Some(new), Some(refname), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(format!("not a push command: «{}»", line.chars().take(120).collect::<String>()));
        };
        let hex = |s: &str| s.len() == OID_HEX && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if !hex(old) || !hex(new) {
            return Err("push commands must use SHA-1 object ids".into());
        }
        if refname.is_empty() || !refname.starts_with("refs/") {
            return Err(format!("not a ref warden can check: «{refname}»"));
        }
        commands.push(Command {
            old: old.into(),
            new: new.into(),
            refname: refname.into(),
        });
        if pos > COMMANDS_MAX {
            return Err("too many push commands".into());
        }
    }
    if commands.is_empty() {
        return Err("a push without commands".into());
    }
    Ok(Some((commands, pos)))
}

#[derive(Debug, Default, PartialEq)]
pub struct Needs {
    pub powers: BTreeSet<Power>,
    /// (old, new, ref)
    pub fast_forwards: Vec<(String, String, String)>,
}

/// Deleting a branch needs `force_push`, so delete-and-recreate is no disguised force push. Refs that
/// are neither branches nor tags are not needed for work, and some change what git sees.
pub fn needs(commands: &[Command], default_branch: &str) -> Needs {
    let mut n = Needs::default();
    let mut seen = HashSet::new();
    for c in commands {
        // Case-folded: GitHub may not tell them apart, and when in doubt the power is required.
        if !seen.insert(c.refname.to_ascii_lowercase()) {
            n.powers.insert(Power::ForcePush);
        }
        match c.refname.strip_prefix("refs/heads/") {
            Some(branch) => {
                if branch.eq_ignore_ascii_case(default_branch) {
                    n.powers.insert(Power::DefaultBranch);
                }
                if c.is_delete() {
                    n.powers.insert(Power::ForcePush);
                } else if !c.is_create() {
                    n.fast_forwards.push((c.old.clone(), c.new.clone(), c.refname.clone()));
                }
            }
            // Any tag change needs `tags`, and its history is not checked. An odd spelling GitHub might
            // still take for a tag also needs `force_push`.
            None if c.refname.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("refs/tags/")) => {
                n.powers.insert(Power::Tags);
                if !c.refname.starts_with("refs/tags/") {
                    n.powers.insert(Power::ForcePush);
                }
            }
            None => {
                n.powers.insert(Power::ForcePush);
            }
        }
    }
    n
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Commit,
    Other,
    /// A delta whose base is not in the pack (a thin pack).
    Unknown,
}

struct Inflating {
    z: Decompress,
    offset: u64,
    size: u64,
    keep: Option<Vec<u8>>,
    kind: Kind,
    base: Option<Arc<[u8]>>,
}

/// Keeps only the pack's commits, as oid → parents.
pub struct PackScanner {
    buf: Vec<u8>,
    /// Pack offset of the next object, which offset deltas refer to.
    consumed: u64,
    header: Option<u32>,
    done: u32,
    cur: Option<Inflating>,
    /// Only commits: git deltas only between objects of the same type, and a map of every object
    /// would let a push of millions of tiny objects fill memory.
    commit_at: HashMap<u64, Arc<[u8]>>,
    commit_by_oid: HashMap<String, Arc<[u8]>>,
    pub commits: HashMap<String, Vec<String>>,
    kept: usize,
    scratch: Vec<u8>,
}

/// Commit bytes kept per push.
const KEEP_MAX: usize = 64 << 20;
const COMMIT_MAX: usize = 1 << 20;

pub fn commit_oid(content: &[u8]) -> String {
    let mut data = format!("commit {}\0", content.len()).into_bytes();
    data.extend_from_slice(content);
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Only the `parent` lines right after `tree`, as git reads them: a later one would let a commit
/// without history pass as a fast-forward.
fn parents_of(content: &[u8]) -> Vec<String> {
    let oid = |h: &[u8]| h.len() == OID_HEX && h.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
    let mut lines = content.split(|&b| b == b'\n');
    match lines.next().and_then(|l| l.strip_prefix(b"tree ")) {
        Some(t) if oid(t) => {}
        _ => return Vec::new(),
    }
    let mut out = Vec::new();
    for line in lines {
        match line.strip_prefix(b"parent ") {
            Some(p) if oid(p) => out.push(String::from_utf8_lossy(p).into_owned()),
            _ => break,
        }
    }
    out
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    let mut i = 0;
    let varint = |i: &mut usize| -> Result<u64, String> {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let b = *delta.get(*i).ok_or("truncated delta")?;
            *i += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 56 {
                return Err("delta size too large".into());
            }
        }
    };
    let src = varint(&mut i)? as usize;
    let dst = varint(&mut i)? as usize;
    if src != base.len() || dst > COMMIT_MAX {
        return Err("delta does not fit its base".into());
    }
    let mut out = Vec::with_capacity(dst);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            let mut off = 0usize;
            let mut size = 0usize;
            for k in 0..4 {
                if op & (1 << k) != 0 {
                    off |= usize::from(*delta.get(i).ok_or("truncated delta")?) << (8 * k);
                    i += 1;
                }
            }
            for k in 0..3 {
                if op & (0x10 << k) != 0 {
                    size |= usize::from(*delta.get(i).ok_or("truncated delta")?) << (8 * k);
                    i += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let piece = base
                .get(off..off.checked_add(size).ok_or("delta copy overflows")?)
                .ok_or("delta copy out of the base")?;
            out.extend_from_slice(piece);
        } else if op != 0 {
            let piece = delta.get(i..i + usize::from(op)).ok_or("truncated delta")?;
            out.extend_from_slice(piece);
            i += usize::from(op);
        } else {
            return Err("invalid delta instruction".into());
        }
        if out.len() > dst {
            return Err("delta grows past its size".into());
        }
    }
    if out.len() != dst {
        return Err("delta result has the wrong size".into());
    }
    Ok(out)
}

impl Default for PackScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PackScanner {
    pub fn new() -> PackScanner {
        PackScanner {
            buf: Vec::new(),
            consumed: 0,
            header: None,
            done: 0,
            cur: None,
            commit_at: HashMap::new(),
            commit_by_oid: HashMap::new(),
            commits: HashMap::new(),
            kept: 0,
            scratch: vec![0; 64 << 10],
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), String> {
        self.buf.extend_from_slice(data);
        let mut pos = 0;
        let result = self.run(&mut pos);
        self.buf.drain(..pos);
        result
    }

    fn run(&mut self, pos: &mut usize) -> Result<(), String> {
        loop {
            if self.header.is_none() {
                let Some(h) = self.buf.get(*pos..*pos + 12) else {
                    return Ok(());
                };
                if &h[..4] != b"PACK" {
                    return Err("the push does not carry a pack".into());
                }
                let version = u32::from_be_bytes(h[4..8].try_into().expect("4 bytes"));
                if version != 2 && version != 3 {
                    return Err(format!("pack version {version} is not supported"));
                }
                self.header = Some(u32::from_be_bytes(h[8..12].try_into().expect("4 bytes")));
                *pos += 12;
                self.consumed += 12;
            }
            let count = self.header.expect("set above");
            if self.cur.is_none() {
                if self.done == count {
                    // Only the 20-byte trailer may follow.
                    if self.buf.len() - *pos > 20 {
                        return Err("data after the pack".into());
                    }
                    return Ok(());
                }
                match self.object_header(*pos)? {
                    None => return Ok(()),
                    Some((used, inf)) => {
                        *pos += used;
                        self.consumed += used as u64;
                        self.cur = Some(inf);
                    }
                }
            }
            if !self.inflate(pos)? {
                return Ok(());
            }
        }
    }

    /// `None` means more bytes are needed.
    fn object_header(&mut self, pos: usize) -> Result<Option<(usize, Inflating)>, String> {
        let b = &self.buf[pos..];
        let offset = self.consumed;
        let mut i = 0;
        let Some(&first) = b.first() else {
            return Ok(None);
        };
        let kind = (first >> 4) & 7;
        let mut size = u64::from(first & 0x0f);
        let mut shift = 4;
        let mut c = first;
        i += 1;
        while c & 0x80 != 0 {
            let Some(&n) = b.get(i) else { return Ok(None) };
            c = n;
            i += 1;
            size |= u64::from(c & 0x7f) << shift;
            shift += 7;
            if shift > 60 {
                return Err("object size too large".into());
            }
        }
        let (kind, keep, base) = match kind {
            1 => (Kind::Commit, true, None),
            2..=4 => (Kind::Other, false, None),
            6 => {
                let Some(&c0) = b.get(i) else { return Ok(None) };
                i += 1;
                let mut rel = u64::from(c0 & 0x7f);
                let mut c = c0;
                while c & 0x80 != 0 {
                    let Some(&n) = b.get(i) else { return Ok(None) };
                    c = n;
                    i += 1;
                    rel = ((rel + 1) << 7) | u64::from(c & 0x7f);
                }
                let base_at = offset.checked_sub(rel).ok_or("delta base before the pack")?;
                match self.commit_at.get(&base_at) {
                    Some(base) => (Kind::Commit, true, Some(base.clone())),
                    None => (Kind::Other, false, None),
                }
            }
            7 => {
                let Some(raw) = b.get(i..i + 20) else {
                    return Ok(None);
                };
                i += 20;
                let oid: String = raw.iter().map(|x| format!("{x:02x}")).collect();
                match self.commit_by_oid.get(&oid) {
                    Some(base) => (Kind::Commit, true, Some(base.clone())),
                    // If the base was a commit on GitHub (thin pack), the walk cannot reach it and
                    // the push is refused; `git push --no-thin` avoids that.
                    None => (Kind::Unknown, false, None),
                }
            }
            k => return Err(format!("unknown pack object type {k}")),
        };
        if keep && size as usize > COMMIT_MAX {
            return Err("a commit larger than 1 MiB".into());
        }
        let inf = Inflating {
            z: Decompress::new(true),
            offset,
            size,
            keep: keep.then(Vec::new),
            kind,
            base,
        };
        Ok(Some((i, inf)))
    }

    /// `true` once the current object is complete.
    fn inflate(&mut self, pos: &mut usize) -> Result<bool, String> {
        let inf = self.cur.as_mut().expect("an object in progress");
        loop {
            let (in0, out0) = (inf.z.total_in(), inf.z.total_out());
            let status = inf
                .z
                .decompress(&self.buf[*pos..], &mut self.scratch, FlushDecompress::None)
                .map_err(|e| format!("corrupt object in the pack: {e}"))?;
            let used = (inf.z.total_in() - in0) as usize;
            let made = (inf.z.total_out() - out0) as usize;
            *pos += used;
            self.consumed += used as u64;
            if inf.z.total_out() > inf.size {
                return Err("an object inflates past its size".into());
            }
            if let Some(keep) = inf.keep.as_mut() {
                keep.extend_from_slice(&self.scratch[..made]);
            }
            match status {
                Status::StreamEnd => break,
                _ if used == 0 && made == 0 => return Ok(false),
                _ => {}
            }
        }
        let inf = self.cur.take().expect("an object in progress");
        if inf.z.total_out() != inf.size {
            return Err("an object inflates to the wrong size".into());
        }
        self.done += 1;
        let _ = inf.kind;
        if let Some(data) = inf.keep {
            let content = match &inf.base {
                Some(base) => apply_delta(base, &data)?,
                None => data,
            };
            self.kept += content.len();
            if self.kept > KEEP_MAX {
                return Err("too many commits in one push".into());
            }
            let oid = commit_oid(&content);
            self.commits.insert(oid.clone(), parents_of(&content));
            let content: Arc<[u8]> = content.into();
            self.commit_at.insert(inf.offset, content.clone());
            self.commit_by_oid.insert(oid, content);
        }
        Ok(true)
    }

    pub fn finish(&self) -> Result<(), String> {
        match self.header {
            Some(count) if self.done == count && self.cur.is_none() && self.buf.len() == 20 => Ok(()),
            None => Err("the push ended before its pack".into()),
            _ => Err("the pack is incomplete".into()),
        }
    }
}

pub enum Walk {
    Reached,
    /// Commits outside the pack; GitHub must say whether any descends from `old`.
    Ask(Vec<String>),
}

/// Shared by every branch of a push, so many long chains cannot keep warden walking forever.
pub const WALK_BUDGET: usize = 200_000;

pub fn walk(commits: &HashMap<String, Vec<String>>, old: &str, new: &str, budget: &mut usize) -> Result<Walk, String> {
    let mut seen = HashSet::new();
    let mut stack = vec![new.to_string()];
    let mut outside = Vec::new();
    while let Some(oid) = stack.pop() {
        if oid == old {
            return Ok(Walk::Reached);
        }
        if !seen.insert(oid.clone()) {
            continue;
        }
        if *budget == 0 {
            return Err("the push has too many commits to check".into());
        }
        *budget -= 1;
        match commits.get(&oid) {
            Some(parents) => stack.extend(parents.iter().cloned()),
            None => outside.push(oid),
        }
    }
    Ok(Walk::Ask(outside))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpack::*;

    #[test]
    fn commits_hash_like_git() {
        // As computed by `git hash-object -t commit`.
        let c = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 1700000000 +0000\ncommitter A <a@b> 1700000000 +0000\n\nfirst\n";
        assert_eq!(commit_oid(c), "a0d0a7322b6ad14cd9934535320d716cd7f6980e");
    }

    #[test]
    fn push_commands_are_read_with_their_capabilities_shallows_and_options() {
        let (a, b) = ("a".repeat(40), "b".repeat(40));
        let mut body = pkt(&format!("shallow {a}\n"));
        body.extend(pkt(&format!("{a} {b} refs/heads/feature\0report-status push-options side-band-64k\n")));
        body.extend(pkt(&format!("{ZERO} {b} refs/tags/v1\n")));
        body.extend(b"0000");
        body.extend(pkt("ci.skip\n"));
        body.extend(b"0000");
        body.extend(b"PACK");
        let (cmds, used) = parse_commands(&body).unwrap().unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0],
            Command {
                old: a.clone(),
                new: b.clone(),
                refname: "refs/heads/feature".into()
            }
        );
        assert_eq!(&body[used..], b"PACK", "the push options are part of the commands section");
        assert!(parse_commands(&body[..10]).unwrap().is_none(), "incomplete: wait for more");
        for bad in [
            format!("{a} {b}\n"),
            format!("{a} {b} HEAD\n"),
            format!("{} {b} refs/heads/x\n", "a".repeat(64)),
            "push-cert\0caps\n".into(),
        ] {
            let mut body = pkt(&bad);
            body.extend(b"0000");
            assert!(parse_commands(&body).is_err(), "{bad}");
        }
        assert!(parse_commands(b"zzzz").is_err());
        assert!(parse_commands(b"0000").is_err(), "a push without commands");
    }

    fn cmd(old: &str, new: &str, r: &str) -> Command {
        Command {
            old: old.into(),
            new: new.into(),
            refname: r.into(),
        }
    }

    #[test]
    fn what_a_push_needs() {
        let (a, b) = ("a".repeat(40), "b".repeat(40));
        let n = needs(&[cmd(ZERO, &b, "refs/heads/feature")], "main");
        assert!(n.powers.is_empty() && n.fast_forwards.is_empty(), "a new branch needs nothing");
        let n = needs(&[cmd(&a, &b, "refs/heads/feature")], "main");
        assert_eq!((n.powers.len(), n.fast_forwards.len()), (0, 1), "moving a branch must fast-forward");
        for (c, p) in [
            (cmd(&a, &b, "refs/heads/main"), Power::DefaultBranch),
            (cmd(&a, &b, "refs/heads/Main"), Power::DefaultBranch),
            (cmd(ZERO, &b, "refs/heads/main"), Power::DefaultBranch),
            (cmd(&a, ZERO, "refs/heads/feature"), Power::ForcePush),
            (cmd(&a, &b, "refs/notes/commits"), Power::ForcePush),
        ] {
            assert!(needs(std::slice::from_ref(&c), "main").powers.contains(&p), "{c:?}");
        }
        for c in [cmd(ZERO, &b, "refs/tags/v9.9.9"), cmd(&a, &b, "refs/tags/v1"), cmd(&a, ZERO, "refs/tags/v1")] {
            let n = needs(std::slice::from_ref(&c), "main");
            assert_eq!(n.powers.iter().copied().collect::<Vec<_>>(), vec![Power::Tags], "{c:?}");
            assert!(n.fast_forwards.is_empty(), "{c:?}");
        }
        let n = needs(&[cmd(ZERO, &b, "refs/TAGS/v1")], "main");
        assert!(n.powers.contains(&Power::Tags) && n.powers.contains(&Power::ForcePush), "a tag spelled oddly");
        let n = needs(&[cmd(ZERO, &a, "refs/heads/release"), cmd(ZERO, &a, "refs/tags/v9.9.9")], "main");
        assert!(n.powers.contains(&Power::Tags));
        for other in ["refs/replace/abc", "refs/notes/commits", "refs/pull/1/head"] {
            assert!(needs(&[cmd(ZERO, &b, other)], "main").powers.contains(&Power::ForcePush), "creating {other}");
        }
        // A disguised force push: delete and recreate the branch in one push.
        let n = needs(&[cmd(&a, ZERO, "refs/heads/feature"), cmd(ZERO, &b, "refs/heads/feature")], "main");
        assert!(n.powers.contains(&Power::ForcePush));
        let n = needs(&[cmd(ZERO, &a, "refs/heads/x"), cmd(ZERO, &b, "refs/heads/X")], "main");
        assert!(n.powers.contains(&Power::ForcePush), "the same ref twice, whatever the case");
    }

    #[test]
    fn the_scanner_finds_commits_plain_and_as_deltas() {
        let c1 = commit_content(&[], "one");
        let c2 = commit_content(&[&commit_oid(&c1)], "two");
        let c3 = commit_content(&[&commit_oid(&c2)], "three, a longer message so the delta copies most of it");
        let objects = vec![
            Obj::Plain(1, c1.clone()),
            Obj::Plain(3, b"a blob that is not a commit".repeat(100)),
            Obj::Plain(1, c2.clone()),
            Obj::OfsDelta(2, delta_against(&c2, &c3)),
            Obj::RefDelta(commit_oid(&c1), delta_against(&c1, &commit_content(&[&commit_oid(&c1)], "four"))),
            Obj::RefDelta("f".repeat(40), b"\x05\x05\x05hello".to_vec()),
        ];
        let pack = pack(&objects);
        // Fed in 7-byte chunks: nothing may depend on how it arrives.
        let mut s = PackScanner::new();
        for chunk in pack.chunks(7) {
            s.feed(chunk).unwrap();
        }
        s.finish().unwrap();
        assert_eq!(s.commits.len(), 4);
        assert_eq!(s.commits[&commit_oid(&c3)], vec![commit_oid(&c2)]);
        assert_eq!(s.commits[&commit_oid(&c1)], Vec::<String>::new());
        assert!(matches!(
            walk(&s.commits, &commit_oid(&c1), &commit_oid(&c3), &mut WALK_BUDGET.clone()).unwrap(),
            Walk::Reached
        ));
        let mut budget = 1;
        assert!(walk(&s.commits, &commit_oid(&c1), &commit_oid(&c3), &mut budget).is_err());
        assert_eq!(budget, 0);
        match walk(&s.commits, &"9".repeat(40), &commit_oid(&c3), &mut WALK_BUDGET.clone()).unwrap() {
            Walk::Ask(v) => assert!(v.is_empty(), "c1 has no parents: nothing outside to ask"),
            Walk::Reached => panic!("9999 is not in the history"),
        }
        let mut s = PackScanner::new();
        s.feed(&pack[..pack.len() - 30]).unwrap();
        assert!(s.finish().is_err());
        let mut s = PackScanner::new();
        let mut longer = pack.clone();
        longer.extend(b"garbage after the trailer");
        assert!(s.feed(&longer).is_err());
    }

    #[test]
    fn parents_are_read_where_git_reads_them() {
        let (old, t) = ("a".repeat(40), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
        let good = format!("tree {t}\nparent {old}\nparent {}\nauthor A <a@b> 1 +0000\n\nmsg\n", "b".repeat(40));
        assert_eq!(parents_of(good.as_bytes()), vec![old.clone(), "b".repeat(40)]);
        for bad in [
            format!("tree {t}\nauthor A <a@b> 1 +0000\nparent {old}\n\nmsg\n"),
            format!("tree {t}\nauthor A <a@b> 1 +0000\n\nparent {old}\n"),
            format!("parent {old}\ntree {t}\nauthor A <a@b> 1 +0000\n\nmsg\n"),
            format!("author A <a@b> 1 +0000\nparent {old}\n\nmsg\n"),
            format!("tree {t}\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\nparent {old}\n\nmsg\n"),
            format!("tree {t}\nparent {old}\r\nauthor A <a@b> 1 +0000\n\nmsg\n"),
            format!("tree {t}\nparent {}\nauthor A <a@b> 1 +0000\n\nmsg\n", old.to_uppercase()),
        ] {
            assert!(!parents_of(bad.as_bytes()).contains(&old), "{bad:?}");
        }
    }

    #[test]
    fn deltas_are_applied_like_git() {
        let base = b"0123456789abcdef".to_vec();
        // Copy 4 bytes from offset 10, insert «XY», copy 2 from offset 0.
        let delta = [vec![16, 8], vec![0x91, 10, 4], vec![2, b'X', b'Y'], vec![0x90, 2]].concat();
        assert_eq!(apply_delta(&base, &delta).unwrap(), b"abcdXY01");
        assert!(apply_delta(b"short", &delta).is_err(), "the base size must match");
        assert!(apply_delta(&base, &[16, 8, 0x91, 200, 4]).is_err(), "a copy out of the base");
    }
}
