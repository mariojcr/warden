// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Per-session audit budget. The audit log is append-only, so a session that never stopped asking
//! could fill the disk. Each session has a per-minute and a lifetime cap; past either, requests are
//! refused (429) without being performed, so nothing happens unaudited. Per-minute refusals are
//! summarized in one `audit.throttled` line once the session has room again, and exhausting the
//! lifetime cap logs `audit.budget_exhausted` once. The lifetime count is seeded from the database,
//! so a restart doesn't reset it.
use std::collections::HashMap;
use std::sync::Mutex;

struct Entry {
    minute: i64,
    used: u32,
    /// Refused by the per-minute cap and not yet logged.
    dropped: u32,
    /// Seeded from the database the first time the session is seen.
    total: u64,
    spent_noted: bool,
    seen: i64,
}

#[derive(Debug, PartialEq)]
pub enum Take {
    /// `throttled`: earlier refusals to log now in one line (already counted).
    Go { throttled: u32 },
    /// `first`: the first refusal this minute, for the log.
    Slow { retry_after: i64, first: bool },
    /// `first`: the first time; its single audit line is already counted.
    Spent { first: bool },
}

pub struct SessionBudget {
    per_minute: u32,
    per_session: u64,
    entries: Mutex<HashMap<String, Entry>>,
}

/// Past this many sessions in memory, idle ones are evicted; their lifetime count is reloaded from
/// the database if they come back.
const KEEP: usize = 256;
const FORGET_AFTER: i64 = 3600;

impl SessionBudget {
    pub fn new(per_minute: u32, per_session: u64) -> SessionBudget {
        SessionBudget {
            per_minute,
            per_session,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn per_minute(&self) -> u32 {
        self.per_minute
    }

    pub fn per_session(&self) -> u64 {
        self.per_session
    }

    /// `rows` returns the session's existing audit lines. It runs only on first sight and without the
    /// lock held; if it fails the count is unknown, so this errors and the caller refuses.
    pub fn take(&self, session: &str, now: i64, rows: impl FnOnce() -> anyhow::Result<u64>) -> anyhow::Result<Take> {
        let known = self.lock().contains_key(session);
        let stored = if known { None } else { Some(rows()?) };
        let mut entries = self.lock();
        if entries.len() > KEEP {
            entries.retain(|_, e| now - e.seen < FORGET_AFTER);
        }
        let minute = now.div_euclid(60);
        let e = entries.entry(session.to_string()).or_insert_with(|| Entry {
            minute,
            used: 0,
            dropped: 0,
            total: stored.unwrap_or(0),
            spent_noted: false,
            seen: now,
        });
        e.seen = now;
        if e.minute != minute {
            e.minute = minute;
            e.used = 0;
        }
        if e.total >= self.per_session {
            let first = !e.spent_noted;
            e.spent_noted = true;
            if first {
                e.total += 1;
            }
            return Ok(Take::Spent { first });
        }
        if e.used >= self.per_minute {
            e.dropped += 1;
            return Ok(Take::Slow {
                retry_after: (minute + 1) * 60 - now,
                first: e.dropped == 1,
            });
        }
        let throttled = std::mem::take(&mut e.dropped);
        e.used += 1;
        e.total += 1 + u64::from(throttled > 0);
        Ok(Take::Go { throttled })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> anyhow::Result<u64> {
        Ok(0)
    }

    #[test]
    fn a_session_gets_so_many_lines_a_minute_and_the_rest_is_counted_once() {
        let b = SessionBudget::new(3, 1000);
        let t = 6000; // start of a minute
        for i in 0..3 {
            assert_eq!(b.take("s1", t + i, none).unwrap(), Take::Go { throttled: 0 });
        }
        assert_eq!(b.take("s1", t + 10, none).unwrap(), Take::Slow { retry_after: 50, first: true });
        assert_eq!(b.take("s1", t + 59, none).unwrap(), Take::Slow { retry_after: 1, first: false });
        assert_eq!(b.take("s2", t + 10, none).unwrap(), Take::Go { throttled: 0 });
        assert_eq!(b.take("s1", t + 60, none).unwrap(), Take::Go { throttled: 2 });
        assert_eq!(b.take("s1", t + 61, none).unwrap(), Take::Go { throttled: 0 });
    }

    #[test]
    fn a_session_runs_out_for_good_and_it_is_said_once() {
        let b = SessionBudget::new(100, 10);
        let mut asked = 0;
        let mut rows = || {
            asked += 1;
            Ok(7)
        };
        assert_eq!(b.take("s1", 6000, &mut rows).unwrap(), Take::Go { throttled: 0 });
        assert_eq!(b.take("s1", 6001, &mut rows).unwrap(), Take::Go { throttled: 0 });
        assert_eq!(b.take("s1", 6002, &mut rows).unwrap(), Take::Go { throttled: 0 });
        assert_eq!(asked, 1, "the base is asked once per session");
        assert_eq!(b.take("s1", 6003, none).unwrap(), Take::Spent { first: true });
        for t in [6004, 9000, 90_000] {
            assert_eq!(b.take("s1", t, none).unwrap(), Take::Spent { first: false });
        }
        // Per-minute refusals count too: their summary is a line.
        let b = SessionBudget::new(1, 3);
        assert_eq!(b.take("s", 6000, none).unwrap(), Take::Go { throttled: 0 });
        assert!(matches!(b.take("s", 6001, none).unwrap(), Take::Slow { .. }));
        assert_eq!(b.take("s", 6060, none).unwrap(), Take::Go { throttled: 1 });
        assert_eq!(b.take("s", 6120, none).unwrap(), Take::Spent { first: true }, "1 + 1 + its summary line = 3");
    }

    #[test]
    fn without_the_count_nothing_passes() {
        let b = SessionBudget::new(10, 10);
        assert!(b.take("s", 6000, || anyhow::bail!("the base is gone")).is_err());
        // The next call asks again.
        assert_eq!(b.take("s", 6001, || Ok(9)).unwrap(), Take::Go { throttled: 0 });
        assert_eq!(b.take("s", 6002, none).unwrap(), Take::Spent { first: true });
    }

    #[test]
    fn forgetting_a_session_does_not_reset_it() {
        let b = SessionBudget::new(10, 5);
        assert_eq!(b.take("old", 0, || Ok(4)).unwrap(), Take::Go { throttled: 0 });
        for i in 0..=KEEP {
            b.take(&format!("s{i}"), 2 * FORGET_AFTER, none).unwrap();
        }
        b.take("other", 2 * FORGET_AFTER, none).unwrap();
        assert!(!b.lock().contains_key("old"), "forgotten");
        assert_eq!(b.take("old", 2 * FORGET_AFTER, || Ok(5)).unwrap(), Take::Spent { first: true });
    }
}
