// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};

/// Unix time in seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).expect("the system random source failed");
    b
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Unguessable and safe to show (URLs, cards): `req_…`, `grt_…`.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", b64url(&random::<16>()))
}

pub fn new_secret(prefix: &str) -> String {
    format!("{prefix}_{}", b64url(&random::<32>()))
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accepts only what `new_id` produces, so a path segment can't smuggle anything else.
pub fn is_id(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn iso_utc(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // days_to_civil from "chrono-Compatible Low-Level Date Algorithms".
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, secs % 3600 / 60)
}

pub fn human_duration(secs: i64) -> String {
    let secs = secs.max(0);
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    match (h, m) {
        (0, 0) => format!("{secs} s"),
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_durations_read_well() {
        assert_eq!(iso_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(iso_utc(1_795_132_800), "2026-11-20 00:00 UTC");
        assert_eq!(iso_utc(951_782_400 + 3600 * 13 + 60 * 7), "2000-02-29 13:07 UTC");
        assert_eq!(human_duration(7200), "2 h");
        assert_eq!(human_duration(5400), "1 h 30 min");
        assert_eq!(human_duration(2700), "45 min");
        assert_eq!(human_duration(20), "20 s");
    }

    #[test]
    fn ids_are_ours_or_nothing() {
        let id = new_id("req");
        assert!(is_id(&id), "{id}");
        assert_ne!(id, new_id("req"));
        for bad in ["", "short", "../../etc", "req_a/b", "req_a%2Fb", "req_a b", &"x".repeat(65)] {
            assert!(!is_id(bad), "{bad}");
        }
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
