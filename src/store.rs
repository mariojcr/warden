// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! warden's SQLite database: connections (sealed), sessions, requests, grants, OAuth flows and the
//! audit log. Every state change is written in the same transaction as its audit row.
//!
//! The audit log is append-only (triggers) and chained with an HMAC keyed from the master key, which
//! is not on the volume, so whoever can write the file cannot edit a row and rebuild the chain. Rows
//! from before the key (plain sha256) are sealed once, and only if the config pins their head
//! (`audit_legacy_head`); otherwise dropping the seal and rewriting them would pass. Truncating the
//! tail is not detectable without an external anchor.
//!
//! Session tokens and OAuth `state`s are stored as sha256, so a copy of the database cannot be used
//! as a session or to finish a flow.
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde_json::{Value, json};

use crate::crypto::AuditKey;
use crate::scope::{NewRequest, Repo, scope_repos};
use crate::util::{new_id, new_secret, sha256_hex};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS connections (
  provider TEXT PRIMARY KEY,
  account TEXT NOT NULL,
  scopes TEXT NOT NULL,
  sealed BLOB NOT NULL,
  connected_at INTEGER NOT NULL,
  expires_at INTEGER,
  refresh_expires_at INTEGER,
  refreshed_at INTEGER,
  broken_at INTEGER,
  broken_reason TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  system TEXT NOT NULL,
  scope TEXT NOT NULL,
  mode TEXT NOT NULL,
  duration_secs INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  decided_at INTEGER,
  decided_by TEXT
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES requests(id),
  session_id TEXT NOT NULL REFERENCES sessions(id),
  system TEXT NOT NULL,
  scope TEXT NOT NULL,
  mode TEXT NOT NULL,
  approved_by TEXT NOT NULL,
  auth_time INTEGER NOT NULL,
  starts_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoked_by TEXT,
  end_recorded_at INTEGER
);
CREATE INDEX IF NOT EXISTS grants_session ON grants(session_id);
CREATE TABLE IF NOT EXISTS flows (
  state_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  browser_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS owner_sessions (
  token_hash TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  request_id TEXT,
  grant_id TEXT,
  session_id TEXT,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_session ON audit(session_id);
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL UNIQUE,
  sub TEXT NOT NULL,
  name TEXT NOT NULL,
  alg INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL,
  aaguid TEXT NOT NULL,
  backup_eligible INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  revoked_by TEXT
);
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge_hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  request_id TEXT,
  channel TEXT NOT NULL,
  browser_hash TEXT,
  sub TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS webauthn_challenges_request ON webauthn_challenges(request_id, channel);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
"#;

/// Columns added after their table was created, which `CREATE TABLE IF NOT EXISTS` does not add.
/// NULL is the right value for old rows: no refresh token, so the token never expires.
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("connections", "expires_at", "INTEGER"),
    ("connections", "refresh_expires_at", "INTEGER"),
    ("connections", "refreshed_at", "INTEGER"),
    ("connections", "broken_at", "INTEGER"),
    ("connections", "broken_reason", "TEXT"),
];

fn add_missing_columns(conn: &Connection) -> rusqlite::Result<()> {
    for (table, column, kind) in ADDED_COLUMNS {
        let has = conn
            .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))?
            .exists([column])?;
        if !has {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"))?;
        }
    }
    Ok(())
}

/// Seconds allowed for an OAuth round trip.
pub const FLOW_TTL: i64 = 600;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub label: String,
    pub origin: Value,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RequestRow {
    pub id: String,
    pub session_id: String,
    pub session_label: String,
    pub system: String,
    pub scope: Value,
    pub mode: String,
    pub duration_secs: i64,
    pub reason: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
}

impl RequestRow {
    pub fn repos(&self) -> Vec<Repo> {
        scope_repos(&self.scope)
    }

    /// A pending request past its deadline reads as expired before the sweep records it.
    pub fn status_at(&self, now: i64) -> &str {
        if self.status == "pending" && now >= self.expires_at {
            "expired"
        } else {
            &self.status
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrantRow {
    pub id: String,
    pub request_id: String,
    pub session_id: String,
    pub system: String,
    pub scope: Value,
    pub mode: String,
    pub approved_by: String,
    pub auth_time: i64,
    pub starts_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

impl GrantRow {
    pub fn repos(&self) -> Vec<Repo> {
        scope_repos(&self.scope)
    }

    pub fn active_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.starts_at <= now && now < self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionRow {
    pub provider: String,
    pub account: String,
    pub scopes: String,
    /// Sealed token and refresh token. Each write uses a fresh nonce, so this also identifies the
    /// version: renewals only write over the one they read.
    pub sealed: Vec<u8>,
    pub connected_at: i64,
    /// None: no refresh token, so the token does not expire.
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
    pub refreshed_at: Option<i64>,
    /// Set when a renewal failed for good: the proxy stops using the token until it is reconnected.
    pub broken: Option<(i64, String)>,
}

const CONNECTION_COLS: &str = "provider, account, scopes, sealed, connected_at, expires_at, refresh_expires_at, refreshed_at, broken_at, broken_reason";

fn connection_row(r: &Row) -> rusqlite::Result<ConnectionRow> {
    let broken_at: Option<i64> = r.get(8)?;
    let broken_reason: Option<String> = r.get(9)?;
    Ok(ConnectionRow {
        provider: r.get(0)?,
        account: r.get(1)?,
        scopes: r.get(2)?,
        sealed: r.get(3)?,
        connected_at: r.get(4)?,
        expires_at: r.get(5)?,
        refresh_expires_at: r.get(6)?,
        refreshed_at: r.get(7)?,
        broken: broken_at.map(|at| (at, broken_reason.unwrap_or_default())),
    })
}

pub struct Renewed {
    pub sealed: Vec<u8>,
    pub scopes: String,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
}

/// An OAuth flow between the redirect and the callback.
#[derive(Debug, Clone)]
pub struct Flow {
    /// "oidc" or "github".
    pub kind: String,
    /// "approve", "login", "connect" or "disconnect".
    pub action: String,
    /// The request being approved, or the `sub` of the owner connecting GitHub.
    pub target: String,
    pub nonce: String,
    pub verifier: String,
    /// sha256 of the starting browser's cookie: the callback must come from the same browser.
    pub browser_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub seq: i64,
    pub at: i64,
    pub actor: String,
    pub event: String,
    pub request_id: Option<String>,
    pub grant_id: Option<String>,
    pub session_id: Option<String>,
    pub detail: Value,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct Audit {
    pub actor: String,
    pub event: String,
    pub request_id: Option<String>,
    pub grant_id: Option<String>,
    pub session_id: Option<String>,
    pub detail: Value,
}

impl Audit {
    pub fn new(actor: impl Into<String>, event: &str, detail: Value) -> Audit {
        Audit {
            actor: actor.into(),
            event: event.into(),
            request_id: None,
            grant_id: None,
            session_id: None,
            detail,
        }
    }
    pub fn request(mut self, id: &str) -> Audit {
        self.request_id = Some(id.to_string());
        self
    }
    pub fn grant(mut self, id: &str) -> Audit {
        self.grant_id = Some(id.to_string());
        self
    }
    pub fn session(mut self, id: &str) -> Audit {
        self.session_id = Some(id.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct Approval {
    pub sub: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub via: Via,
}

#[derive(Debug, Clone)]
pub enum Via {
    PocketId,
    /// A warden passkey signature, verified except for the sign counter, which is checked in the
    /// granting transaction.
    Passkey {
        passkey_id: String,
        sign_count: u32,
        channel: String,
        origin: String,
    },
}

#[derive(Debug, Clone)]
pub struct ChallengeRow {
    /// "approve" (uses `request_id` and `channel`) or "register" (uses `browser_hash` and `sub`).
    pub purpose: String,
    pub request_id: Option<String>,
    pub channel: String,
    pub browser_hash: Option<String>,
    pub sub: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: String,
    /// The WebAuthn `rawId`, base64url.
    pub credential_id: String,
    pub sub: String,
    pub name: String,
    pub alg: i64,
    /// COSE key as returned by the authenticator.
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub aaguid: String,
    pub backup_eligible: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

const PASSKEY_COLS: &str = "id, credential_id, sub, name, alg, public_key, sign_count, aaguid, backup_eligible, created_at, last_used_at, revoked_at";

fn passkey_row(r: &Row) -> rusqlite::Result<PasskeyRow> {
    Ok(PasskeyRow {
        id: r.get(0)?,
        credential_id: r.get(1)?,
        sub: r.get(2)?,
        name: r.get(3)?,
        alg: r.get(4)?,
        public_key: r.get(5)?,
        sign_count: r.get(6)?,
        aaguid: r.get(7)?,
        backup_eligible: r.get(8)?,
        created_at: r.get(9)?,
        last_used_at: r.get(10)?,
        revoked_at: r.get(11)?,
    })
}

pub struct Store {
    conn: Mutex<Connection>,
    key: AuditKey,
}

/// A JSON array, so field boundaries are unambiguous.
fn row_bytes(prev: &str, at: i64, a: &Audit, detail: &str) -> Vec<u8> {
    json!([prev, at, a.actor, a.event, a.request_id, a.grant_id, a.session_id, detail])
        .to_string()
        .into_bytes()
}

fn legacy_hash(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// Event of the row that seals the rows from before keyed hashes.
pub const SEAL_EVENT: &str = "audit.keyed";

fn append(conn: &Connection, key: &AuditKey, a: &Audit, at: i64) -> rusqlite::Result<()> {
    let prev: String = conn
        .query_row("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| GENESIS.to_string());
    let detail = a.detail.to_string();
    let hash = key.mac_hex(&row_bytes(&prev, at, a, &detail));
    conn.execute(
        "INSERT INTO audit (at, actor, event, request_id, grant_id, session_id, detail, prev_hash, hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![at, a.actor, a.event, a.request_id, a.grant_id, a.session_id, detail, prev, hash],
    )?;
    Ok(())
}

const REQUEST_COLS: &str =
    "r.id, r.session_id, s.label, r.system, r.scope, r.mode, r.duration_secs, r.reason, r.created_at, r.expires_at, r.status, r.decided_at, r.decided_by";

fn request_row(r: &Row) -> rusqlite::Result<RequestRow> {
    Ok(RequestRow {
        id: r.get(0)?,
        session_id: r.get(1)?,
        session_label: r.get(2)?,
        system: r.get(3)?,
        scope: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
        mode: r.get(5)?,
        duration_secs: r.get(6)?,
        reason: r.get(7)?,
        created_at: r.get(8)?,
        expires_at: r.get(9)?,
        status: r.get(10)?,
        decided_at: r.get(11)?,
        decided_by: r.get(12)?,
    })
}

const GRANT_COLS: &str = "id, request_id, session_id, system, scope, mode, approved_by, auth_time, starts_at, expires_at, revoked_at";

fn grant_row(r: &Row) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: r.get(0)?,
        request_id: r.get(1)?,
        session_id: r.get(2)?,
        system: r.get(3)?,
        scope: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
        mode: r.get(5)?,
        approved_by: r.get(6)?,
        auth_time: r.get(7)?,
        starts_at: r.get(8)?,
        expires_at: r.get(9)?,
        revoked_at: r.get(10)?,
    })
}

fn session_row(r: &Row) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: r.get(0)?,
        label: r.get(1)?,
        origin: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or(Value::Null),
        created_at: r.get(3)?,
        expires_at: r.get(4)?,
        revoked_at: r.get(5)?,
    })
}

fn audit_row(r: &Row) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        seq: r.get(0)?,
        at: r.get(1)?,
        actor: r.get(2)?,
        event: r.get(3)?,
        request_id: r.get(4)?,
        grant_id: r.get(5)?,
        session_id: r.get(6)?,
        detail: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
        hash: r.get(9)?,
    })
}

#[derive(Debug, PartialEq)]
pub struct Chain {
    pub rows: usize,
    /// Leading rows hashed with plain sha256, from before keyed hashes.
    pub legacy_rows: usize,
    /// False when the whole chain is from before keyed hashes and unsealed.
    pub keyed: bool,
    /// Hash of the last unkeyed row: the value `audit_legacy_head` pins.
    pub legacy_head: Option<String>,
}

struct Link {
    seq: i64,
    at: i64,
    audit: Audit,
    detail: String,
    prev: String,
    hash: String,
}

const LINK_COLS: &str = "seq, at, actor, event, request_id, grant_id, session_id, detail, prev_hash, hash";

fn link(r: &Row) -> rusqlite::Result<Link> {
    Ok(Link {
        seq: r.get(0)?,
        at: r.get(1)?,
        audit: Audit {
            actor: r.get(2)?,
            event: r.get(3)?,
            request_id: r.get(4)?,
            grant_id: r.get(5)?,
            session_id: r.get(6)?,
            detail: Value::Null,
        },
        detail: r.get(7)?,
        prev: r.get(8)?,
        hash: r.get(9)?,
    })
}

impl Link {
    fn bytes(&self) -> Vec<u8> {
        row_bytes(&self.prev, self.at, &self.audit, &self.detail)
    }
}

/// Unkeyed rows may come first; the first keyed row after them must be the seal that names their
/// count and last hash. Err names the first row that does not verify.
fn verify_chain(conn: &Connection, key: &AuditKey) -> rusqlite::Result<Result<Chain, String>> {
    let mut st = conn.prepare(&format!("SELECT {LINK_COLS} FROM audit ORDER BY seq"))?;
    let mut rows = st.query([])?;
    let mut prev = GENESIS.to_string();
    let (mut n, mut legacy, mut keyed) = (0usize, 0usize, false);
    let mut legacy_head = None;
    while let Some(r) = rows.next()? {
        let l = link(r)?;
        if l.prev != prev {
            return Ok(Err(format!("audit row {} does not follow the row before it", l.seq)));
        }
        let bytes = l.bytes();
        if key.verifies(&bytes, &l.hash) {
            if !keyed && legacy > 0 {
                let d: Value = serde_json::from_str(&l.detail).unwrap_or(Value::Null);
                if l.audit.event != SEAL_EVENT || d["legacy_rows"].as_u64() != Some(legacy as u64) || d["legacy_head"].as_str() != Some(prev.as_str()) {
                    return Ok(Err(format!(
                        "audit row {} is the first keyed row but not the seal of the {legacy} rows before it",
                        l.seq
                    )));
                }
            }
            keyed = true;
        } else if !keyed && legacy_hash(&bytes) == l.hash {
            legacy += 1;
            legacy_head = Some(l.hash.clone());
        } else {
            return Ok(Err(format!("audit row {} does not match the chain", l.seq)));
        }
        prev = l.hash;
        n += 1;
    }
    Ok(Ok(Chain {
        rows: n,
        legacy_rows: legacy,
        keyed: keyed || n == 0,
        legacy_head,
    }))
}

fn unsealed(c: &Chain) -> String {
    format!(
        "the {} audit rows are hashed without a key and nothing seals them (the last one hashes to {}): warden seals them when it starts with \"audit_legacy_head\" set to that in its config; if it already did, the seal and every row after it were removed",
        c.legacy_rows,
        c.legacy_head.as_deref().unwrap_or("?")
    )
}

/// Seals an unkeyed chain once, in an IMMEDIATE transaction, if it verifies and ends at `pin`.
/// On any mismatch (pin, hashes, master key) warden refuses to start.
fn seal_legacy(conn: &mut Connection, key: &AuditKey, pin: Option<&str>, now: i64) -> anyhow::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let last = tx
        .query_row(&format!("SELECT {LINK_COLS} FROM audit ORDER BY seq DESC LIMIT 1"), [], link)
        .optional()?;
    let Some(last) = last else {
        anyhow::ensure!(
            pin.is_none(),
            "\"audit_legacy_head\" is set but the audit log is empty: the rows from before keyed hashes are gone (or this is another database); warden does not start"
        );
        return Ok(());
    };
    let bytes = last.bytes();
    if key.verifies(&bytes, &last.hash) {
        if let Some(pin) = pin {
            let seal = tx
                .query_row(
                    &format!("SELECT {LINK_COLS} FROM audit WHERE event = ?1 ORDER BY seq LIMIT 1"),
                    [SEAL_EVENT],
                    link,
                )
                .optional()?;
            let sealed = seal
                .filter(|l| key.verifies(&l.bytes(), &l.hash))
                .and_then(|l| serde_json::from_str::<Value>(&l.detail).ok());
            anyhow::ensure!(
                sealed.as_ref().and_then(|d| d["legacy_head"].as_str()) == Some(pin),
                "\"audit_legacy_head\" is {pin}, but no seal in the audit log is for it: the rows from before keyed hashes are not the pinned ones; warden does not start"
            );
        }
        return Ok(());
    }
    anyhow::ensure!(
        legacy_hash(&bytes) == last.hash,
        "the last audit row ({}) matches neither this master key nor the unkeyed hash of before: the audit log was changed, or this is not the master key it was written with. warden does not start: restore the master key, or move warden.sqlite aside",
        last.seq
    );
    let chain = match verify_chain(&tx, key)? {
        Ok(c) if !c.keyed && c.legacy_rows == c.rows => c,
        Ok(_) => anyhow::bail!("the audit log has keyed rows followed by unkeyed ones; warden does not start"),
        Err(e) => anyhow::bail!(
            "the audit log from before keyed hashes does not verify ({e}); warden does not seal it nor start. Check it with `warden audit-verify` of the warden version that wrote it"
        ),
    };
    match pin {
        None => anyhow::bail!(
            "the audit log has {} rows from before keyed hashes, and the last one (row {}) hashes to {}. warden seals them with the master key only when its config pins that: set \"audit_legacy_head\": \"{}\" (after checking that the chain holds with `warden audit-verify` of the warden that wrote it) and start again",
            chain.rows,
            last.seq,
            last.hash,
            last.hash
        ),
        Some(p) if p != last.hash => anyhow::bail!(
            "the rows from before keyed hashes end in {}, not in the pinned {p}: they were changed (or this is another database); warden does not seal them nor start",
            last.hash
        ),
        Some(_) => {}
    }
    let detail = json!({"legacy_rows": chain.rows, "legacy_head": last.hash, "mac": "hmac-sha256"});
    append(&tx, key, &Audit::new("system", SEAL_EVENT, detail), now)?;
    tx.commit()?;
    tracing::info!(
        legacy_rows = chain.rows,
        "audit: the chain from before keyed hashes verifies and is now sealed with the master key"
    );
    Ok(())
}

impl Store {
    /// Seals an audit log from before keyed hashes if it ends at `legacy_head` (see `seal_legacy`).
    pub fn open(path: &Path, key: AuditKey, legacy_head: Option<&str>) -> anyhow::Result<Store> {
        let conn = Connection::open(path).map_err(|e| anyhow::anyhow!("cannot open {}: {e}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Store::init(conn, key, legacy_head)
    }

    pub fn open_in_memory(key: AuditKey) -> anyhow::Result<Store> {
        Store::init(Connection::open_in_memory()?, key, None)
    }

    fn init(mut conn: Connection, key: AuditKey, legacy_head: Option<&str>) -> anyhow::Result<Store> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        add_missing_columns(&conn)?;
        seal_legacy(&mut conn, &key, legacy_head, crate::util::now())?;
        Ok(Store { conn: Mutex::new(conn), key })
    }

    /// `warden audit-verify`: read-only, never seals. An unsealed unkeyed chain fails, as does one
    /// sealed over a head other than `legacy_head`.
    pub fn verify_file(path: &Path, key: &AuditKey, legacy_head: Option<&str>) -> anyhow::Result<Result<Chain, String>> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(verify_chain(&conn, key)?.and_then(|c| match legacy_head {
            _ if !c.keyed => Err(unsealed(&c)),
            Some(pin) if c.legacy_head.as_deref() != Some(pin) => Err(format!(
                "the audit chain holds, but its rows from before keyed hashes end in {}, not in the pinned {pin}",
                c.legacy_head.as_deref().unwrap_or("nothing (there are none)")
            )),
            _ => Ok(c),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // Transactions roll back on panic, so a poisoned lock leaves nothing half-written.
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn audit(&self, a: Audit, now: i64) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        append(&tx, &self.key, &a, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn session_audit_rows(&self, session_id: &str) -> anyhow::Result<u64> {
        let conn = self.lock();
        let n: i64 = conn.query_row("SELECT count(*) FROM audit WHERE session_id = ?1", [session_id], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// Newest first.
    pub fn audit_tail(&self, limit: usize) -> anyhow::Result<Vec<AuditRow>> {
        let conn = self.lock();
        let mut st = conn.prepare("SELECT * FROM audit ORDER BY seq DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], audit_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Ok(row count) only if the chain verifies and ends keyed.
    pub fn verify_audit(&self) -> anyhow::Result<Result<usize, String>> {
        let conn = self.lock();
        Ok(verify_chain(&conn, &self.key)?.and_then(|c| if c.keyed { Ok(c.rows) } else { Err(unsealed(&c)) }))
    }

    /// The token is returned only here; only its sha256 is stored. `per_alloc` is (Nomad allocation,
    /// max live sessions).
    pub fn create_session(
        &self,
        label: &str,
        origin: Value,
        per_alloc: Option<(&str, i64)>,
        ttl: i64,
        now: i64,
    ) -> anyhow::Result<Result<(SessionRow, String), String>> {
        let token = new_secret("wds");
        let row = SessionRow {
            id: new_id("ses"),
            label: label.to_string(),
            origin,
            created_at: now,
            expires_at: now + ttl,
            revoked_at: None,
        };
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        if let Some((alloc, max)) = per_alloc {
            let live: i64 = tx.query_row(
                "SELECT count(*) FROM sessions WHERE json_extract(origin, '$.alloc') = ?1 AND revoked_at IS NULL AND expires_at > ?2",
                params![alloc, now],
                |r| r.get(0),
            )?;
            if live >= max {
                return Ok(Err(format!("this allocation already has {live} open warden sessions; reuse the one you have")));
            }
        }
        tx.execute(
            "INSERT INTO sessions (id, token_hash, label, origin, created_at, expires_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                row.id,
                sha256_hex(token.as_bytes()),
                row.label,
                row.origin.to_string(),
                row.created_at,
                row.expires_at
            ],
        )?;
        append(
            &tx,
            &self.key,
            &Audit::new(
                "system",
                "session.created",
                json!({"label": label, "origin": row.origin, "expires_at": row.expires_at}),
            )
            .session(&row.id),
            now,
        )?;
        tx.commit()?;
        Ok(Ok((row, token)))
    }

    pub fn session_by_token(&self, token: &str, now: i64) -> anyhow::Result<Option<SessionRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, label, origin, created_at, expires_at, revoked_at FROM sessions WHERE token_hash = ?1",
                [sha256_hex(token.as_bytes())],
                session_row,
            )
            .optional()?;
        Ok(row.filter(|s| s.revoked_at.is_none() && now < s.expires_at))
    }

    pub fn create_request(&self, session: &SessionRow, r: &NewRequest, ttl: i64, max_pending: i64, now: i64) -> anyhow::Result<Result<RequestRow, String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM requests WHERE session_id = ?1 AND status = 'pending' AND expires_at > ?2",
            params![session.id, now],
            |x| x.get(0),
        )?;
        if pending >= max_pending {
            return Ok(Err(format!(
                "this session already has {pending} requests waiting for the owner; wait for an answer (or withdraw one) before asking again."
            )));
        }
        let id = new_id("req");
        let scope = r.scope();
        let expires_at = now + ttl;
        tx.execute(
            "INSERT INTO requests (id, session_id, system, scope, mode, duration_secs, reason, created_at, expires_at, status) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending')",
            params![id, session.id, r.system, scope.to_string(), r.mode_str(), r.duration_secs, r.reason, now, expires_at],
        )?;
        let detail = json!({"system": r.system, "scope": scope, "mode": r.mode_str(), "powers": scope["powers"], "duration_secs": r.duration_secs,
                            "reason": r.reason, "session": session.label, "expires_at": expires_at});
        append(
            &tx,
            &self.key,
            &Audit::new(format!("session:{}", session.id), "request.created", detail)
                .request(&id)
                .session(&session.id),
            now,
        )?;
        let row = tx.query_row(
            &format!("SELECT {REQUEST_COLS} FROM requests r JOIN sessions s ON s.id = r.session_id WHERE r.id = ?1"),
            [&id],
            request_row,
        )?;
        tx.commit()?;
        Ok(Ok(row))
    }

    pub fn request(&self, id: &str) -> anyhow::Result<Option<RequestRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("SELECT {REQUEST_COLS} FROM requests r JOIN sessions s ON s.id = r.session_id WHERE r.id = ?1"),
                [id],
                request_row,
            )
            .optional()?)
    }

    /// Oldest first.
    pub fn pending_requests(&self, now: i64) -> anyhow::Result<Vec<RequestRow>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!(
            "SELECT {REQUEST_COLS} FROM requests r JOIN sessions s ON s.id = r.session_id WHERE r.status = 'pending' AND r.expires_at > ?1 ORDER BY r.created_at, r.id"
        ))?;
        let rows = st.query_map([now], request_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn close_request(&self, id: &str, status: &str, actor: &str, only_session: Option<&str>, now: i64) -> anyhow::Result<Result<RequestRow, String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let Some(r) = tx
            .query_row(
                &format!("SELECT {REQUEST_COLS} FROM requests r JOIN sessions s ON s.id = r.session_id WHERE r.id = ?1"),
                [id],
                request_row,
            )
            .optional()?
        else {
            return Ok(Err("no such request".into()));
        };
        if only_session.is_some_and(|s| s != r.session_id) {
            return Ok(Err("no such request".into()));
        }
        if r.status_at(now) != "pending" {
            return Ok(Err(format!("the request is already {}", r.status_at(now))));
        }
        tx.execute(
            "UPDATE requests SET status = ?2, decided_at = ?3, decided_by = ?4 WHERE id = ?1",
            params![id, status, now, actor],
        )?;
        let event = if status == "refused" { "request.refused" } else { "request.withdrawn" };
        append(
            &tx,
            &self.key,
            &Audit::new(actor, event, json!({"repos": r.scope["repos"], "mode": r.mode}))
                .request(id)
                .session(&r.session_id),
            now,
        )?;
        tx.commit()?;
        Ok(Ok(RequestRow {
            status: status.into(),
            decided_at: Some(now),
            decided_by: Some(actor.into()),
            ..r
        }))
    }

    pub fn refuse_request(&self, id: &str, actor: &str, now: i64) -> anyhow::Result<Result<RequestRow, String>> {
        self.close_request(id, "refused", actor, None, now)
    }

    pub fn withdraw_request(&self, id: &str, session_id: &str, now: i64) -> anyhow::Result<Result<RequestRow, String>> {
        self.close_request(id, "withdrawn", &format!("session:{session_id}"), Some(session_id), now)
    }

    /// The caller has already verified the approval. Only a pending, unexpired request from a live
    /// session is granted; the grant starts now and lasts the requested duration.
    pub fn approve_request(&self, id: &str, approval: &Approval, now: i64) -> anyhow::Result<Result<GrantRow, String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let Some(r) = tx
            .query_row(
                &format!("SELECT {REQUEST_COLS} FROM requests r JOIN sessions s ON s.id = r.session_id WHERE r.id = ?1"),
                [id],
                request_row,
            )
            .optional()?
        else {
            return Ok(Err("That request does not exist.".into()));
        };
        let actor = format!("owner:{}", approval.sub);
        let refuse = |why: &str| {
            Audit::new(actor.clone(), "approval.rejected", json!({"reason": why, "status": r.status_at(now)}))
                .request(id)
                .session(&r.session_id)
        };
        if r.status_at(now) != "pending" {
            append(&tx, &self.key, &refuse("not pending"), now)?;
            tx.commit()?;
            return Ok(Err(format!("The request is already {}.", status_label(r.status_at(now)))));
        }
        let session_alive: bool = tx.query_row(
            "SELECT revoked_at IS NULL AND expires_at > ?2 FROM sessions WHERE id = ?1",
            params![r.session_id, now],
            |x| x.get(0),
        )?;
        if !session_alive {
            append(&tx, &self.key, &refuse("session ended"), now)?;
            tx.commit()?;
            return Ok(Err("The session that asked for it has already ended.".into()));
        }
        // The counter is checked here, inside the transaction, so two concurrent signatures cannot both
        // pass with the same value. Synced passkeys always report 0, so it only applies if either is
        // nonzero.
        let mut via = json!({"via": "pocket-id"});
        if let Via::Passkey {
            passkey_id,
            sign_count,
            channel,
            origin,
        } = &approval.via
        {
            let stored: Option<(i64, Option<i64>, String)> = tx
                .query_row("SELECT sign_count, revoked_at, sub FROM passkeys WHERE id = ?1", [passkey_id], |x| {
                    Ok((x.get(0)?, x.get(1)?, x.get(2)?))
                })
                .optional()?;
            let fail = |why: &str, text: &str| -> anyhow::Result<Result<GrantRow, String>> {
                let detail = json!({"reason": why, "status": "pending", "via": "passkey", "passkey": passkey_id, "channel": channel});
                append(
                    &tx,
                    &self.key,
                    &Audit::new(actor.clone(), "approval.rejected", detail).request(id).session(&r.session_id),
                    now,
                )?;
                Ok(Err(text.to_string()))
            };
            match stored {
                Some((_, None, sub)) if sub != approval.sub => {
                    let out = fail("the passkey belongs to another owner", "That passkey is not yours.");
                    tx.commit()?;
                    return out;
                }
                Some((count, None, _)) => {
                    let new = *sign_count as i64;
                    if (count != 0 || new != 0) && new <= count {
                        let out = fail(
                            &format!("the sign counter did not increase ({new} after {count}): a cloned authenticator?"),
                            "The passkey's counter did not go up: has it been cloned? Nothing was granted.",
                        );
                        tx.commit()?;
                        return out;
                    }
                }
                _ => {
                    let out = fail("the passkey is revoked or unknown", "That passkey is no longer valid.");
                    tx.commit()?;
                    return out;
                }
            }
            tx.execute(
                "UPDATE passkeys SET sign_count = ?2, last_used_at = ?3 WHERE id = ?1",
                params![passkey_id, *sign_count as i64, now],
            )?;
            via = json!({"via": "passkey", "passkey": passkey_id, "channel": channel, "origin": origin, "sign_count": sign_count});
        }
        let grant = GrantRow {
            id: new_id("grt"),
            request_id: r.id.clone(),
            session_id: r.session_id.clone(),
            system: r.system.clone(),
            scope: r.scope.clone(),
            mode: r.mode.clone(),
            approved_by: actor.clone(),
            auth_time: approval.auth_time,
            starts_at: now,
            expires_at: now + r.duration_secs,
            revoked_at: None,
        };
        tx.execute(
            "UPDATE requests SET status = 'approved', decided_at = ?2, decided_by = ?3 WHERE id = ?1",
            params![id, now, actor],
        )?;
        tx.execute(
            &format!("INSERT INTO grants ({GRANT_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL)"),
            params![
                grant.id,
                grant.request_id,
                grant.session_id,
                grant.system,
                grant.scope.to_string(),
                grant.mode,
                grant.approved_by,
                grant.auth_time,
                grant.starts_at,
                grant.expires_at
            ],
        )?;
        let mut detail = json!({"sub": approval.sub, "auth_time": approval.auth_time, "amr": approval.amr, "system": r.system,
                                "scope": r.scope, "mode": r.mode, "powers": r.scope["powers"], "starts_at": grant.starts_at, "expires_at": grant.expires_at});
        for (k, v) in via.as_object().into_iter().flatten() {
            detail[k] = v.clone();
        }
        append(
            &tx,
            &self.key,
            &Audit::new(actor.clone(), "request.approved", detail)
                .request(id)
                .grant(&grant.id)
                .session(&r.session_id),
            now,
        )?;
        tx.commit()?;
        Ok(Ok(grant))
    }

    pub fn grants_of_session(&self, session_id: &str, now: i64) -> anyhow::Result<Vec<GrantRow>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!(
            "SELECT {GRANT_COLS} FROM grants WHERE session_id = ?1 AND revoked_at IS NULL AND starts_at <= ?2 AND expires_at > ?2 ORDER BY starts_at"
        ))?;
        let rows = st.query_map(params![session_id, now], grant_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Each live grant with its session's label.
    pub fn active_grants(&self, now: i64) -> anyhow::Result<Vec<(GrantRow, String)>> {
        let conn = self.lock();
        let cols = GRANT_COLS.split(", ").map(|c| format!("g.{c}")).collect::<Vec<_>>().join(", ");
        let mut st = conn.prepare(&format!(
            "SELECT {cols}, s.label FROM grants g JOIN sessions s ON s.id = g.session_id WHERE g.revoked_at IS NULL AND g.starts_at <= ?1 AND g.expires_at > ?1 ORDER BY g.expires_at"
        ))?;
        let rows = st
            .query_map([now], |r| Ok((grant_row(r)?, r.get::<_, String>(11)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The longest-lived grant from `task_grants` whose scope names `claude_session`.
    pub fn claude_grant(&self, session: &SessionRow, tasks: &[String], now: i64) -> anyhow::Result<Option<GrantRow>> {
        Ok(self
            .task_grants(crate::claude::SYSTEM, session, tasks, now)?
            .into_iter()
            .find(|g| crate::scope::grants_claude_session(&g.scope)))
    }

    /// Live grants of `system` for this session, plus those of other sessions of the same Nomad task
    /// and allocation: a session lasts hours but a sandbox weeks, and a reopened session keeps the
    /// grants. A Nomad session whose task is not in `tasks` gets none. Latest expiry first.
    pub fn task_grants(&self, system: &str, session: &SessionRow, tasks: &[String], now: i64) -> anyhow::Result<Vec<GrantRow>> {
        let conn = self.lock();
        let cols = GRANT_COLS.split(", ").map(|c| format!("g.{c}")).collect::<Vec<_>>().join(", ");
        let nomad = session.origin["kind"] == "nomad";
        let alloc = session.origin["alloc"].as_str().filter(|a| nomad && !a.is_empty());
        let task = session.origin["task"].as_str().unwrap_or("");
        if nomad && !tasks.iter().any(|t| t == task) {
            return Ok(Vec::new());
        }
        let mut st = conn.prepare(&format!(
            "SELECT {cols} FROM grants g JOIN sessions s ON s.id = g.session_id \
             WHERE g.system = ?1 AND g.revoked_at IS NULL AND g.starts_at <= ?2 AND g.expires_at > ?2 \
               AND (g.session_id = ?3 OR (?4 IS NOT NULL AND json_extract(s.origin, '$.kind') = 'nomad' \
                    AND json_extract(s.origin, '$.alloc') = ?4 AND json_extract(s.origin, '$.task') = ?5)) \
             ORDER BY g.expires_at DESC"
        ))?;
        let rows = st
            .query_map(params![system, now, session.id, alloc, task], grant_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn grant(&self, id: &str) -> anyhow::Result<Option<GrantRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(&format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?1"), [id], grant_row)
            .optional()?)
    }

    pub fn grant_for_request(&self, request_id: &str) -> anyhow::Result<Option<GrantRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(&format!("SELECT {GRANT_COLS} FROM grants WHERE request_id = ?1"), [request_id], grant_row)
            .optional()?)
    }

    /// With `only_session`, a session can only revoke its own grants.
    pub fn revoke_grant(&self, id: &str, actor: &str, only_session: Option<&str>, now: i64) -> anyhow::Result<Result<GrantRow, String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let Some(g) = tx
            .query_row(&format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?1"), [id], grant_row)
            .optional()?
        else {
            return Ok(Err("no such grant".into()));
        };
        if only_session.is_some_and(|s| s != g.session_id) {
            return Ok(Err("no such grant".into()));
        }
        if !g.active_at(now) {
            return Ok(Err("the grant has already ended".into()));
        }
        tx.execute(
            "UPDATE grants SET revoked_at = ?2, revoked_by = ?3, end_recorded_at = ?2 WHERE id = ?1",
            params![id, now, actor],
        )?;
        let detail = json!({"scope": g.scope, "mode": g.mode, "remaining_secs": g.expires_at - now});
        append(
            &tx,
            &self.key,
            &Audit::new(actor, "grant.revoked", detail)
                .grant(id)
                .request(&g.request_id)
                .session(&g.session_id),
            now,
        )?;
        tx.commit()?;
        Ok(Ok(GrantRow { revoked_at: Some(now), ..g }))
    }

    /// Replaces any existing connection for the provider and clears its renewal and broken state.
    pub fn put_connection(&self, c: &ConnectionRow, actor: &str, now: i64) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO connections (provider, account, scopes, sealed, connected_at, expires_at, refresh_expires_at, refreshed_at, broken_at, broken_reason)
             VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,NULL,NULL)
             ON CONFLICT(provider) DO UPDATE SET account = excluded.account, scopes = excluded.scopes, sealed = excluded.sealed,
               connected_at = excluded.connected_at, expires_at = excluded.expires_at, refresh_expires_at = excluded.refresh_expires_at,
               refreshed_at = NULL, broken_at = NULL, broken_reason = NULL",
            params![c.provider, c.account, c.scopes, c.sealed, c.connected_at, c.expires_at, c.refresh_expires_at],
        )?;
        let detail = json!({"provider": c.provider, "account": c.account, "scopes": c.scopes, "expires": c.expires_at.is_some(), "expires_at": c.expires_at});
        append(&tx, &self.key, &Audit::new(actor, "connection.connected", detail), now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn connection(&self, provider: &str) -> anyhow::Result<Option<ConnectionRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("SELECT {CONNECTION_COLS} FROM connections WHERE provider = ?1"),
                [provider],
                connection_row,
            )
            .optional()?)
    }

    /// Compare-and-swap on the sealed envelope read before renewing (`from`): writes nothing and
    /// returns false if the connection changed meanwhile or is broken.
    pub fn renew_connection(&self, provider: &str, from: &[u8], r: &Renewed, audit: Audit, now: i64) -> anyhow::Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let n = tx.execute(
            "UPDATE connections SET sealed = ?3, scopes = ?4, expires_at = ?5, refresh_expires_at = ?6, refreshed_at = ?7
             WHERE provider = ?1 AND sealed = ?2 AND broken_at IS NULL",
            params![provider, from, r.sealed, r.scopes, r.expires_at, r.refresh_expires_at, now],
        )?;
        if n == 0 {
            return Ok(false);
        }
        append(&tx, &self.key, &audit, now)?;
        tx.commit()?;
        Ok(true)
    }

    /// Same compare-and-swap as `renew_connection`.
    pub fn break_connection(&self, provider: &str, from: &[u8], reason: &str, audit: Audit, now: i64) -> anyhow::Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let n = tx.execute(
            "UPDATE connections SET broken_at = ?3, broken_reason = ?4 WHERE provider = ?1 AND sealed = ?2 AND broken_at IS NULL",
            params![provider, from, now, reason],
        )?;
        if n == 0 {
            return Ok(false);
        }
        append(&tx, &self.key, &audit, now)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn delete_connection(&self, provider: &str, actor: &str, detail: Value, now: i64) -> anyhow::Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let gone = tx.execute("DELETE FROM connections WHERE provider = ?1", [provider])? > 0;
        if gone {
            append(&tx, &self.key, &Audit::new(actor, "connection.disconnected", detail), now)?;
        }
        tx.commit()?;
        Ok(gone)
    }

    /// Stored under the sha256 of `state`.
    pub fn put_flow(&self, state: &str, f: &Flow) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO flows (state_hash, kind, action, target, nonce, verifier, browser_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                sha256_hex(state.as_bytes()),
                f.kind,
                f.action,
                f.target,
                f.nonce,
                f.verifier,
                f.browser_hash,
                f.created_at
            ],
        )?;
        Ok(())
    }

    /// Single use: the flow is deleted even when the kind does not match or it has expired.
    pub fn take_flow(&self, state: &str, kind: &str, now: i64) -> anyhow::Result<Option<Flow>> {
        let conn = self.lock();
        let f = conn
            .query_row(
                "DELETE FROM flows WHERE state_hash = ?1 RETURNING kind, action, target, nonce, verifier, browser_hash, created_at",
                [sha256_hex(state.as_bytes())],
                |r| {
                    Ok(Flow {
                        kind: r.get(0)?,
                        action: r.get(1)?,
                        target: r.get(2)?,
                        nonce: r.get(3)?,
                        verifier: r.get(4)?,
                        browser_hash: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(f.filter(|f| f.kind == kind && now - f.created_at <= FLOW_TTL))
    }

    pub fn create_owner_session(&self, sub: &str, ttl: i64, now: i64) -> anyhow::Result<String> {
        let token = new_secret("wdo");
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO owner_sessions (token_hash, sub, created_at, expires_at) VALUES (?1,?2,?3,?4)",
            params![sha256_hex(token.as_bytes()), sub, now, now + ttl],
        )?;
        append(&tx, &self.key, &Audit::new(format!("owner:{sub}"), "owner.login", json!({})), now)?;
        tx.commit()?;
        Ok(token)
    }

    pub fn owner_session(&self, token: &str, now: i64) -> anyhow::Result<Option<String>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT sub FROM owner_sessions WHERE token_hash = ?1 AND expires_at > ?2",
                params![sha256_hex(token.as_bytes()), now],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn end_owner_session(&self, token: &str) -> anyhow::Result<()> {
        self.lock()
            .execute("DELETE FROM owner_sessions WHERE token_hash = ?1", [sha256_hex(token.as_bytes())])?;
        Ok(())
    }

    /// Stores the challenge's sha256 and keeps only the `keep` newest per request and channel (or per
    /// browser when registering), so asking for challenges cannot grow the database.
    pub fn put_challenge(&self, challenge: &str, c: &ChallengeRow, keep: i64) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO webauthn_challenges (challenge_hash, purpose, request_id, channel, browser_hash, sub, created_at, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![sha256_hex(challenge.as_bytes()), c.purpose, c.request_id, c.channel, c.browser_hash, c.sub, c.created_at, c.expires_at],
        )?;
        tx.execute(
            "DELETE FROM webauthn_challenges WHERE purpose = ?1 AND request_id IS ?2 AND channel = ?3 AND browser_hash IS ?4 AND challenge_hash NOT IN \
             (SELECT challenge_hash FROM webauthn_challenges WHERE purpose = ?1 AND request_id IS ?2 AND channel = ?3 AND browser_hash IS ?4 \
              ORDER BY created_at DESC, rowid DESC LIMIT ?5)",
            params![c.purpose, c.request_id, c.channel, c.browser_hash, keep],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Single use. Expiry is not checked here; the caller does it.
    pub fn take_challenge(&self, challenge: &str) -> anyhow::Result<Option<ChallengeRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "DELETE FROM webauthn_challenges WHERE challenge_hash = ?1 RETURNING purpose, request_id, channel, browser_hash, sub, created_at, expires_at",
                [sha256_hex(challenge.as_bytes())],
                |r| {
                    Ok(ChallengeRow {
                        purpose: r.get(0)?,
                        request_id: r.get(1)?,
                        channel: r.get(2)?,
                        browser_hash: r.get(3)?,
                        sub: r.get(4)?,
                        created_at: r.get(5)?,
                        expires_at: r.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn add_passkey(&self, p: &PasskeyRow, max_active: i64, actor: &str, now: i64) -> anyhow::Result<Result<(), String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let active: i64 = tx.query_row("SELECT count(*) FROM passkeys WHERE sub = ?1 AND revoked_at IS NULL", [&p.sub], |r| r.get(0))?;
        if active >= max_active {
            return Ok(Err(format!("There are already {active} warden passkeys: remove one before adding another.")));
        }
        let taken: bool = tx.query_row("SELECT count(*) > 0 FROM passkeys WHERE credential_id = ?1", [&p.credential_id], |r| r.get(0))?;
        if taken {
            return Ok(Err("That passkey was already registered.".into()));
        }
        tx.execute(
            &format!("INSERT INTO passkeys ({PASSKEY_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL)"),
            params![
                p.id,
                p.credential_id,
                p.sub,
                p.name,
                p.alg,
                p.public_key,
                p.sign_count,
                p.aaguid,
                p.backup_eligible,
                p.created_at
            ],
        )?;
        let detail = json!({"passkey": p.id, "name": p.name, "alg": p.alg, "aaguid": p.aaguid, "backup_eligible": p.backup_eligible,
                            "credential_id_sha256": sha256_hex(p.credential_id.as_bytes())});
        append(&tx, &self.key, &Audit::new(actor, "passkey.registered", detail), now)?;
        tx.commit()?;
        Ok(Ok(()))
    }

    /// Live passkeys only, newest first.
    pub fn passkeys(&self, sub: &str) -> anyhow::Result<Vec<PasskeyRow>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!(
            "SELECT {PASSKEY_COLS} FROM passkeys WHERE sub = ?1 AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC"
        ))?;
        let rows = st.query_map([sub], passkey_row)?.collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Includes revoked passkeys.
    pub fn passkey_by_credential(&self, credential_id: &str) -> anyhow::Result<Option<PasskeyRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("SELECT {PASSKEY_COLS} FROM passkeys WHERE credential_id = ?1"),
                [credential_id],
                passkey_row,
            )
            .optional()?)
    }

    pub fn revoke_passkey(&self, id: &str, actor: &str, now: i64) -> anyhow::Result<Result<PasskeyRow, String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let Some(p) = tx
            .query_row(&format!("SELECT {PASSKEY_COLS} FROM passkeys WHERE id = ?1"), [id], passkey_row)
            .optional()?
        else {
            return Ok(Err("That passkey does not exist.".into()));
        };
        if p.revoked_at.is_some() {
            return Ok(Err("That passkey was already removed.".into()));
        }
        tx.execute("UPDATE passkeys SET revoked_at = ?2, revoked_by = ?3 WHERE id = ?1", params![id, now, actor])?;
        append(
            &tx,
            &self.key,
            &Audit::new(actor, "passkey.revoked", json!({"passkey": id, "name": p.name})),
            now,
        )?;
        tx.commit()?;
        Ok(Ok(PasskeyRow { revoked_at: Some(now), ..p }))
    }

    /// Records each expired request and grant once and drops stale flows, challenges and owner
    /// sessions. Returns whether anything visible changed.
    pub fn sweep(&self, now: i64) -> anyhow::Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let expired: Vec<(String, String)> = {
            let mut st = tx.prepare("SELECT id, session_id FROM requests WHERE status = 'pending' AND expires_at <= ?1")?;
            st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
        };
        for (id, session) in &expired {
            tx.execute(
                "UPDATE requests SET status = 'expired', decided_at = ?2, decided_by = 'system' WHERE id = ?1",
                params![id, now],
            )?;
            append(
                &tx,
                &self.key,
                &Audit::new("system", "request.expired", json!({})).request(id).session(session),
                now,
            )?;
        }
        let ended: Vec<(String, String, String, i64)> = {
            let mut st = tx.prepare(
                "SELECT id, request_id, session_id, expires_at FROM grants WHERE revoked_at IS NULL AND end_recorded_at IS NULL AND expires_at <= ?1",
            )?;
            st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?
        };
        for (id, request, session, at) in &ended {
            tx.execute("UPDATE grants SET end_recorded_at = ?2 WHERE id = ?1", params![id, now])?;
            append(
                &tx,
                &self.key,
                &Audit::new("system", "grant.expired", json!({"expired_at": at}))
                    .grant(id)
                    .request(request)
                    .session(session),
                now,
            )?;
        }
        tx.execute("DELETE FROM flows WHERE created_at < ?1", [now - FLOW_TTL])?;
        tx.execute("DELETE FROM webauthn_challenges WHERE expires_at <= ?1", [now])?;
        tx.execute("DELETE FROM owner_sessions WHERE expires_at <= ?1", [now])?;
        tx.commit()?;
        Ok(!expired.is_empty() || !ended.is_empty())
    }
}

pub fn status_label(s: &str) -> &'static str {
    match s {
        "pending" => "pending",
        "approved" => "granted",
        "refused" => "refused",
        "expired" => "expired",
        "withdrawn" => "withdrawn",
        _ => "in another state",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{Mode, parse_request};

    fn key() -> AuditKey {
        AuditKey::derive(&[7; 32]).unwrap()
    }

    fn setup() -> (Store, SessionRow) {
        let s = Store::open_in_memory(key()).unwrap();
        let (session, _) = s.create_session("claude · test", json!({"kind": "test"}), None, 3600, 1000).unwrap().unwrap();
        (s, session)
    }

    fn new_request(repo: &str, mode: &str) -> NewRequest {
        parse_request(
            &json!({"system": "github", "scope": [repo], "mode": mode, "duration": "1h", "reason": "work on the thing"}),
            4 * 3600,
        )
        .unwrap()
    }

    fn approval() -> Approval {
        Approval {
            sub: "owner".into(),
            auth_time: 1009,
            amr: vec!["phr".into()],
            via: Via::PocketId,
        }
    }

    fn events(s: &Store) -> Vec<String> {
        let mut rows = s.audit_tail(1000).unwrap();
        rows.reverse();
        rows.into_iter().map(|r| r.event).collect()
    }

    #[test]
    fn every_step_of_a_request_leaves_its_audit_line() {
        let (s, session) = setup();
        let r1 = s.create_request(&session, &new_request("o/r", "write"), 900, 3, 1000).unwrap().unwrap();
        let r2 = s.create_request(&session, &new_request("o/x", "read"), 900, 3, 1001).unwrap().unwrap();
        let r3 = s.create_request(&session, &new_request("o/y", "read"), 900, 3, 1002).unwrap().unwrap();
        let g = s.approve_request(&r1.id, &approval(), 1010).unwrap().unwrap();
        assert_eq!((g.starts_at, g.expires_at, g.mode.as_str()), (1010, 1010 + 3600, "write"));
        s.refuse_request(&r2.id, "heimdall", 1011).unwrap().unwrap();
        // r3 is never answered: the sweep expires it exactly once.
        assert!(s.sweep(1002 + 900).unwrap());
        assert!(!s.sweep(1002 + 901).unwrap());
        assert_eq!(s.request(&r3.id).unwrap().unwrap().status, "expired");
        s.revoke_grant(&g.id, "heimdall", None, 1020).unwrap().unwrap();
        // Already revoked, so the sweep does not record it as expired too.
        assert!(!s.sweep(1010 + 3600).unwrap());
        assert_eq!(
            events(&s),
            [
                "session.created",
                "request.created",
                "request.created",
                "request.created",
                "request.approved",
                "request.refused",
                "request.expired",
                "grant.revoked"
            ]
        );
        let approved = s.audit_tail(1000).unwrap().into_iter().find(|r| r.event == "request.approved").unwrap();
        assert_eq!(approved.actor, "owner:owner");
        assert_eq!(approved.detail["auth_time"], 1009);
        assert_eq!(approved.grant_id.as_deref(), Some(g.id.as_str()));
        let created = s
            .audit_tail(1000)
            .unwrap()
            .into_iter()
            .find(|r| r.request_id.as_deref() == Some(r1.id.as_str()) && r.event == "request.created")
            .unwrap();
        assert_eq!(created.detail["reason"], "work on the thing");
        assert_eq!(created.detail["duration_secs"], 3600);
        assert_eq!(created.detail["scope"]["repos"][0], "o/r");
    }

    #[test]
    fn grants_that_run_out_are_recorded_once() {
        let (s, session) = setup();
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 1000).unwrap().unwrap();
        let g = s.approve_request(&r.id, &approval(), 1010).unwrap().unwrap();
        assert!(!s.sweep(g.expires_at - 1).unwrap());
        assert!(s.sweep(g.expires_at).unwrap());
        assert!(!s.sweep(g.expires_at + 5).unwrap());
        assert_eq!(events(&s).iter().filter(|e| *e == "grant.expired").count(), 1);
        assert!(s.grants_of_session(&session.id, g.expires_at).unwrap().is_empty());
        assert!(s.revoke_grant(&g.id, "heimdall", None, g.expires_at + 1).unwrap().is_err());
    }

    #[test]
    fn only_a_pending_request_in_time_can_be_approved() {
        let (s, session) = setup();
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 1000).unwrap().unwrap();
        // Past its deadline, even though the sweep has not run.
        assert!(s.approve_request(&r.id, &approval(), 1000 + 900).unwrap().is_err());
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 2000).unwrap().unwrap();
        s.refuse_request(&r.id, "heimdall", 2001).unwrap().unwrap();
        assert!(s.approve_request(&r.id, &approval(), 2002).unwrap().is_err(), "a refused request stays refused");
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 3000).unwrap().unwrap();
        s.approve_request(&r.id, &approval(), 3001).unwrap().unwrap();
        assert!(s.approve_request(&r.id, &approval(), 3002).unwrap().is_err(), "approving twice makes one grant");
        assert!(events(&s).iter().filter(|e| *e == "approval.rejected").count() == 3);
        // A session cannot flood the owner with pending requests.
        let full: Vec<_> = (0..4)
            .map(|i| s.create_request(&session, &new_request("o/r", "read"), 900, 3, 4000 + i).unwrap())
            .collect();
        assert!(full[3].as_ref().unwrap_err().contains("already has 3"));
    }

    #[test]
    fn a_session_only_sees_and_releases_its_own() {
        let (s, a) = setup();
        let (b, _) = s.create_session("other", json!({}), None, 3600, 1000).unwrap().unwrap();
        let r = s.create_request(&a, &new_request("o/r", "write"), 900, 3, 1000).unwrap().unwrap();
        assert!(s.withdraw_request(&r.id, &b.id, 1001).unwrap().is_err());
        let g = s.approve_request(&r.id, &approval(), 1002).unwrap().unwrap();
        assert!(s.revoke_grant(&g.id, &format!("session:{}", b.id), Some(&b.id), 1003).unwrap().is_err());
        assert_eq!(s.grants_of_session(&a.id, 1003).unwrap().len(), 1);
        assert!(s.grants_of_session(&b.id, 1003).unwrap().is_empty());
        let mine = s.grants_of_session(&a.id, 1003).unwrap();
        assert_eq!(
            crate::scope::find_grant(&a.id, &mine, &Repo::parse("o/r").unwrap(), Mode::Write, &[], 1003)
                .unwrap()
                .id,
            g.id
        );
    }

    #[test]
    fn one_allocation_opens_a_bounded_number_of_sessions() {
        let s = Store::open_in_memory(key()).unwrap();
        let origin = |alloc: &str| json!({"kind": "nomad", "alloc": alloc});
        for _ in 0..3 {
            s.create_session("claude", origin("a1"), Some(("a1", 3)), 60, 1000).unwrap().unwrap();
        }
        assert!(
            s.create_session("claude", origin("a1"), Some(("a1", 3)), 60, 1000)
                .unwrap()
                .unwrap_err()
                .contains("already has 3")
        );
        assert!(
            s.create_session("claude", origin("a2"), Some(("a2", 3)), 60, 1000).unwrap().is_ok(),
            "another allocation"
        );
        assert!(
            s.create_session("claude", origin("a1"), Some(("a1", 3)), 60, 1060).unwrap().is_ok(),
            "once they expire"
        );
    }

    #[test]
    fn session_tokens_are_stored_hashed_and_expire() {
        let s = Store::open_in_memory(key()).unwrap();
        let (row, token) = s.create_session("x", json!({}), None, 60, 1000).unwrap().unwrap();
        assert_eq!(s.session_by_token(&token, 1059).unwrap().unwrap().id, row.id);
        assert!(s.session_by_token(&token, 1060).unwrap().is_none());
        assert!(s.session_by_token("wds_nope", 1000).unwrap().is_none());
        let stored: String = s.lock().query_row("SELECT token_hash FROM sessions", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, token);
    }

    #[test]
    fn the_audit_log_cannot_be_rewritten() {
        let (s, session) = setup();
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 1000).unwrap().unwrap();
        s.approve_request(&r.id, &approval(), 1001).unwrap().unwrap();
        assert_eq!(s.verify_audit().unwrap(), Ok(3));
        let conn = s.lock();
        assert!(conn.execute("UPDATE audit SET actor = 'eve' WHERE seq = 2", []).is_err());
        assert!(conn.execute("DELETE FROM audit WHERE seq = 2", []).is_err());
        // Bypassing the triggers, as someone editing the file would: the chain catches it.
        conn.execute_batch("DROP TRIGGER audit_no_update; UPDATE audit SET detail = '{}' WHERE seq = 2;")
            .unwrap();
        drop(conn);
        assert!(s.verify_audit().unwrap().unwrap_err().contains("row 2"));
    }

    #[test]
    fn rewriting_history_and_the_chain_after_it_needs_the_master_key() {
        let (s, session) = setup();
        let r = s.create_request(&session, &new_request("o/r", "read"), 900, 3, 1000).unwrap().unwrap();
        s.approve_request(&r.id, &approval(), 1001).unwrap().unwrap();
        s.refuse_request(
            &s.create_request(&session, &new_request("o/x", "read"), 900, 3, 1002).unwrap().unwrap().id,
            "heimdall",
            1003,
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.verify_audit().unwrap(), Ok(5));
        let rehash = |s: &Store, with: &dyn Fn(&[u8]) -> String| {
            let conn = s.lock();
            conn.execute_batch("DROP TRIGGER IF EXISTS audit_no_update; UPDATE audit SET detail = '{\"sub\":\"eve\"}' WHERE event = 'request.approved';")
                .unwrap();
            let links: Vec<Link> = conn
                .prepare(&format!("SELECT {LINK_COLS} FROM audit ORDER BY seq"))
                .unwrap()
                .query_map([], link)
                .unwrap()
                .map(|l| l.unwrap())
                .collect();
            let mut prev = GENESIS.to_string();
            for mut l in links {
                l.prev = prev.clone();
                let hash = with(&l.bytes());
                conn.execute("UPDATE audit SET prev_hash = ?2, hash = ?3 WHERE seq = ?1", params![l.seq, l.prev, hash])
                    .unwrap();
                prev = hash;
            }
        };
        // Rebuilt with plain sha256 it reads as an unsealed unkeyed chain, which fails.
        rehash(&s, &|b| legacy_hash(b));
        assert!(s.verify_audit().unwrap().unwrap_err().contains("nothing seals them"));
        let other = AuditKey::derive(&[8; 32]).unwrap();
        rehash(&s, &|b| other.mac_hex(b));
        assert!(s.verify_audit().unwrap().unwrap_err().contains("does not match"));
        // Control: the right key verifies, so the failures above are about the key.
        rehash(&s, &|b| key().mac_hex(b));
        assert_eq!(s.verify_audit().unwrap(), Ok(5));
    }

    /// A database from before keyed hashes, with `n` audit rows hashed as warden wrote them then.
    fn legacy_db(name: &str, n: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-legacy-{}", crate::util::new_id(name)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("warden.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let mut prev = GENESIS.to_string();
        for i in 0..n {
            let a = Audit::new(
                format!("session:ses_{i}"),
                "proxy",
                json!({"path": format!("/o/r.git/info/refs/{i}"), "ñ": "«»"}),
            )
            .session(&format!("ses_{i}"));
            let detail = a.detail.to_string();
            let at = 1_763_400_000 + i as i64;
            let hash = legacy_hash(&row_bytes(&prev, at, &a, &detail));
            conn.execute(
                "INSERT INTO audit (at, actor, event, request_id, grant_id, session_id, detail, prev_hash, hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![at, a.actor, a.event, a.request_id, a.grant_id, a.session_id, detail, prev, hash],
            )
            .unwrap();
            prev = hash;
        }
        path
    }

    fn rows_of(path: &std::path::Path) -> Vec<(i64, String, String)> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        conn.prepare("SELECT seq, event, hash FROM audit ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn a_legacy_chain_is_checked_sealed_once_when_pinned_and_keeps_verifying() {
        let path = legacy_db("seal", 56);
        let before = rows_of(&path);
        let head = before[55].2.clone();
        let e = Store::verify_file(&path, &key(), None).unwrap().unwrap_err();
        assert!(e.contains("56 audit rows are hashed without a key") && e.contains(&head), "{e}");
        let e = Store::open(&path, key(), None).err().unwrap().to_string();
        assert!(e.contains(&format!("\"audit_legacy_head\": \"{head}\"")), "{e}");
        assert!(
            Store::open(&path, key(), Some(&"0".repeat(64)))
                .err()
                .unwrap()
                .to_string()
                .contains("not in the pinned")
        );
        assert_eq!(rows_of(&path), before);
        let s = Store::open(&path, key(), Some(&head)).unwrap();
        let after = rows_of(&path);
        assert_eq!(after.len(), 57);
        assert_eq!(&after[..56], &before[..], "the rows from before are left as they were");
        assert_eq!(after[56].1, SEAL_EVENT);
        let seal = s.audit_tail(1).unwrap().remove(0);
        assert_eq!(
            (seal.actor.as_str(), &seal.detail["legacy_rows"], &seal.detail["legacy_head"]),
            ("system", &json!(56), &json!(head))
        );
        assert_eq!(s.verify_audit().unwrap(), Ok(57));
        s.audit(Audit::new("system", "x", json!({})), 2_000_000_000).unwrap();
        drop(s);
        // Reopening does not seal again.
        let s = Store::open(&path, key(), Some(&head)).unwrap();
        assert_eq!(s.verify_audit().unwrap(), Ok(58));
        drop(s);
        assert!(
            Store::open(&path, key(), Some(&"0".repeat(64)))
                .err()
                .unwrap()
                .to_string()
                .contains("no seal in the audit log is for it")
        );
        let chain = Chain {
            rows: 58,
            legacy_rows: 56,
            keyed: true,
            legacy_head: Some(head.clone()),
        };
        assert_eq!(Store::verify_file(&path, &key(), Some(&head)).unwrap(), Ok(chain));
        assert!(
            Store::verify_file(&path, &key(), Some(&"0".repeat(64)))
                .unwrap()
                .unwrap_err()
                .contains("not in the pinned")
        );
        let other = AuditKey::derive(&[8; 32]).unwrap();
        assert!(Store::verify_file(&path, &other, Some(&head)).unwrap().is_err());
        assert!(
            Store::open(&path, AuditKey::derive(&[8; 32]).unwrap(), Some(&head))
                .err()
                .unwrap()
                .to_string()
                .contains("not the master key")
        );
        assert_eq!(rows_of(&path).len(), 58, "nothing written with the wrong key");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn the_legacy_part_cannot_be_rewritten_once_sealed_and_a_broken_one_is_not_sealed() {
        let path = legacy_db("tamper", 10);
        let head = rows_of(&path)[9].2.clone();
        drop(Store::open(&path, key(), Some(&head)).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;").unwrap();
        let links: Vec<Link> = conn
            .prepare(&format!("SELECT {LINK_COLS} FROM audit WHERE seq <= 10 ORDER BY seq"))
            .unwrap()
            .query_map([], link)
            .unwrap()
            .map(|l| l.unwrap())
            .collect();
        let mut prev = GENESIS.to_string();
        for mut l in links {
            if l.seq == 3 {
                l.detail = json!({"path": "/something/else"}).to_string();
            }
            l.prev = prev.clone();
            let hash = legacy_hash(&l.bytes());
            conn.execute(
                "UPDATE audit SET detail = ?2, prev_hash = ?3, hash = ?4 WHERE seq = ?1",
                params![l.seq, l.detail, l.prev, hash],
            )
            .unwrap();
            prev = hash;
        }
        assert!(
            Store::verify_file(&path, &key(), Some(&head))
                .unwrap()
                .unwrap_err()
                .contains("row 11 does not follow"),
            "the seal points to the old head"
        );
        conn.execute("DELETE FROM audit WHERE seq >= 11", []).unwrap();
        drop(conn);
        assert!(
            Store::verify_file(&path, &key(), Some(&head))
                .unwrap()
                .unwrap_err()
                .contains("nothing seals them")
        );
        let before = rows_of(&path);
        assert!(
            Store::open(&path, key(), Some(&head)).err().unwrap().to_string().contains("not in the pinned"),
            "the rewritten rows are not sealed"
        );
        assert_eq!(rows_of(&path), before);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();

        let path = legacy_db("broken", 5);
        let head = rows_of(&path)[4].2.clone();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TRIGGER audit_no_update; UPDATE audit SET detail = '{}' WHERE seq = 2;")
            .unwrap();
        drop(conn);
        let before = rows_of(&path);
        assert!(Store::open(&path, key(), Some(&head)).err().unwrap().to_string().contains("does not verify"));
        assert_eq!(rows_of(&path), before, "a broken chain is not sealed");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// With a pin set, an empty or unsealed database means the unkeyed rows are gone.
    #[test]
    fn a_new_database_is_keyed_from_the_first_row() {
        let dir = std::env::temp_dir().join(format!("warden-new-{}", crate::util::new_id("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("warden.sqlite");
        assert!(Store::open(&path, key(), Some(&"a".repeat(64))).err().unwrap().to_string().contains("empty"));
        let s = Store::open(&path, key(), None).unwrap();
        s.audit(Audit::new("system", "x", json!({})), 1000).unwrap();
        drop(s);
        assert_eq!(
            Store::verify_file(&path, &key(), None).unwrap(),
            Ok(Chain {
                rows: 1,
                legacy_rows: 0,
                keyed: true,
                legacy_head: None
            })
        );
        assert!(Store::open(&path, key(), Some(&"a".repeat(64))).err().unwrap().to_string().contains("no seal"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Run against a copy, never the live file:
    /// `WARDEN_LEGACY_DB=<path> cargo test -- --ignored a_copy_of_a_real_legacy_db`.
    #[test]
    #[ignore]
    fn a_copy_of_a_real_legacy_db_is_sealed_and_verifies() {
        let original =
            std::path::PathBuf::from(std::env::var("WARDEN_LEGACY_DB").expect("WARDEN_LEGACY_DB=<a copy of a warden.sqlite from before keyed hashes>"));
        let dir = std::env::temp_dir().join(format!("warden-legacy-{}", crate::util::new_id("copy")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("warden.sqlite");
        std::fs::copy(&original, &path).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        let original_rows = rows_of(&original);
        let n = original_rows.len();
        assert!(n > 0);
        let head = original_rows[n - 1].2.clone();
        assert!(Store::open(&path, key(), None).err().unwrap().to_string().contains(&head));
        let s = Store::open(&path, key(), Some(&head)).unwrap();
        assert_eq!(s.verify_audit().unwrap(), Ok(n + 1));
        drop(s);
        assert_eq!(
            Store::verify_file(&path, &key(), Some(&head)).unwrap(),
            Ok(Chain {
                rows: n + 1,
                legacy_rows: n,
                keyed: true,
                legacy_head: Some(head)
            })
        );
        assert_eq!(rows_of(&original), original_rows, "the original is not touched");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn flows_work_once_and_only_while_fresh() {
        let s = Store::open_in_memory(key()).unwrap();
        let f = Flow {
            kind: "oidc".into(),
            action: "approve".into(),
            target: "req_x".into(),
            nonce: "n".into(),
            verifier: "v".into(),
            browser_hash: "b".into(),
            created_at: 1000,
        };
        s.put_flow("st_1", &f).unwrap();
        assert!(s.take_flow("st_1", "github", 1001).unwrap().is_none(), "another kind of flow");
        s.put_flow("st_2", &f).unwrap();
        assert!(s.take_flow("st_2", "oidc", 1000 + FLOW_TTL + 1).unwrap().is_none(), "too old");
        s.put_flow("st_3", &f).unwrap();
        assert_eq!(s.take_flow("st_3", "oidc", 1001).unwrap().unwrap().target, "req_x");
        assert!(s.take_flow("st_3", "oidc", 1001).unwrap().is_none(), "a state works once");
    }

    #[test]
    fn a_connection_from_before_expiring_tokens_reads_as_one_that_does_not_expire() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE connections (provider TEXT PRIMARY KEY, account TEXT NOT NULL, scopes TEXT NOT NULL, sealed BLOB NOT NULL, connected_at INTEGER NOT NULL);
             INSERT INTO connections VALUES ('github', 'owner', 'repo', x'01020304', 1000);",
        )
        .unwrap();
        let s = Store::init(conn, key(), None).unwrap();
        let c = s.connection("github").unwrap().unwrap();
        assert_eq!((c.account.as_str(), c.sealed.as_slice(), c.connected_at), ("owner", &[1u8, 2, 3, 4][..], 1000));
        assert_eq!(
            (c.expires_at, c.refresh_expires_at, c.refreshed_at, c.broken.is_none()),
            (None, None, None, true)
        );
        // Reopening is idempotent.
        let conn = s.conn.into_inner().unwrap();
        let s = Store::init(conn, key(), None).unwrap();
        assert!(s.connection("github").unwrap().is_some());
    }

    fn github_row(sealed: &[u8], expires_at: Option<i64>) -> ConnectionRow {
        ConnectionRow {
            provider: "github".into(),
            account: "owner".into(),
            scopes: "repo".into(),
            sealed: sealed.to_vec(),
            connected_at: 1000,
            expires_at,
            refresh_expires_at: expires_at.map(|t| t + 100),
            refreshed_at: None,
            broken: None,
        }
    }

    fn renewed(sealed: &[u8], expires_at: i64) -> Renewed {
        Renewed {
            sealed: sealed.to_vec(),
            scopes: "repo".into(),
            expires_at: Some(expires_at),
            refresh_expires_at: Some(expires_at + 100),
        }
    }

    #[test]
    fn renewing_or_breaking_only_writes_over_the_connection_that_was_read() {
        let s = Store::open_in_memory(key()).unwrap();
        s.put_connection(&github_row(b"v1", Some(2000)), "owner:owner", 1000).unwrap();
        let lines = || events(&s).len();
        let before = lines();
        assert!(
            !s.renew_connection(
                "github",
                b"v0",
                &renewed(b"v2", 3000),
                Audit::new("system", "connection.refreshed", json!({})),
                1500
            )
            .unwrap()
        );
        assert_eq!(lines(), before, "nothing written, not even the audit line");
        assert!(
            s.renew_connection(
                "github",
                b"v1",
                &renewed(b"v2", 3000),
                Audit::new("system", "connection.refreshed", json!({})),
                1500
            )
            .unwrap()
        );
        let c = s.connection("github").unwrap().unwrap();
        assert_eq!((c.sealed.as_slice(), c.expires_at, c.refreshed_at), (&b"v2"[..], Some(3000), Some(1500)));
        // v1 is stale now.
        assert!(
            !s.renew_connection(
                "github",
                b"v1",
                &renewed(b"v3", 4000),
                Audit::new("system", "connection.refreshed", json!({})),
                1600
            )
            .unwrap()
        );
        assert!(
            !s.break_connection(
                "github",
                b"v1",
                "bad_refresh_token",
                Audit::new("system", "connection.refresh_failed", json!({})),
                1600
            )
            .unwrap()
        );
        assert!(s.connection("github").unwrap().unwrap().broken.is_none());
        assert!(
            s.break_connection(
                "github",
                b"v2",
                "bad_refresh_token",
                Audit::new("system", "connection.refresh_failed", json!({})),
                1700
            )
            .unwrap()
        );
        assert_eq!(s.connection("github").unwrap().unwrap().broken, Some((1700, "bad_refresh_token".to_string())));
        // v2 is current but broken.
        assert!(
            !s.renew_connection(
                "github",
                b"v2",
                &renewed(b"v3", 4000),
                Audit::new("system", "connection.refreshed", json!({})),
                1800
            )
            .unwrap()
        );
        assert!(
            !s.break_connection("github", b"v2", "again", Audit::new("system", "connection.refresh_failed", json!({})), 1800)
                .unwrap()
        );
        assert_eq!(events(&s).iter().filter(|e| e.starts_with("connection.refresh")).count(), 2);
        s.put_connection(&github_row(b"w1", None), "owner:owner", 1900).unwrap();
        let c = s.connection("github").unwrap().unwrap();
        assert_eq!((c.expires_at, c.refresh_expires_at, c.refreshed_at, c.broken), (None, None, None, None));
        assert_eq!(s.verify_audit().unwrap(), Ok(events(&s).len()));
    }
}
