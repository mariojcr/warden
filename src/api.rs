// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! The internal listener's API.
//!
//! For a sandbox session (with its session token, never a credential):
//!   POST   /api/sessions             the job's Nomad identity → {token}
//!   POST   /api/requests             {system, scope, mode, duration, reason} → a pending request
//!   GET    /api/requests/{id}?wait=N its status; waits up to N s (max 30) for a change
//!   DELETE /api/requests/{id}        withdraw it while pending
//!   GET    /api/grants               live grants
//!   DELETE /api/grants/{id}          release one early
//!   POST   /api/claude/token         {have?} → the claude.ai access token (needs a grant; claude.rs)
//! For heimdall (its token can refuse and revoke; approving also needs a warden passkey signature
//! made by the owner on its screen, webauthn.rs):
//!   GET  /api/heimdall/state?since=V&wait=N   pending and live; waits for a new version
//!   POST /api/heimdall/requests/{id}/refuse
//!   POST /api/heimdall/grants/{id}/revoke
//!   POST /api/heimdall/requests/{id}/challenge  a one-time, short-lived passkey challenge
//!   POST /api/heimdall/requests/{id}/approve    {credential_id, client_data, authenticator_data, signature}
//! Answers to sessions are read by a model: English, and saying what to do next.
// Helpers return an axum Response as the error, which the handler returns as is.
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::proxy::presented_token;
use crate::scope::{SHAPE, parse_request_for};
use crate::store::{Audit, GrantRow, RequestRow, SessionRow};
use crate::util::{ct_eq, is_id, iso_utc, now};

/// A Nomad identity can be reused; without a cap one task could open endless sessions, and through
/// them flood the owner's screen with requests.
pub const MAX_SESSIONS_PER_ALLOC: i64 = 3;

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

fn over_budget(over: crate::app::OverBudget) -> Response {
    let mut resp = error(over.status, over.message.clone());
    over.stamp(&mut resp);
    resp
}

fn internal(e: anyhow::Error) -> Response {
    tracing::error!(error = %e, "api: internal error");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn session_of(app: &App, headers: &HeaderMap) -> Result<SessionRow, Response> {
    let token = presented_token(headers).ok_or_else(|| error(StatusCode::UNAUTHORIZED, "send your warden session token as Authorization: Bearer"))?;
    match app.store.session_by_token(&token, now()) {
        Ok(Some(s)) => Ok(s),
        Ok(None) => Err(error(StatusCode::UNAUTHORIZED, "the warden session token is unknown or has expired")),
        Err(e) => Err(internal(e)),
    }
}

pub async fn create_session(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(nomad) = &app.nomad else {
        return error(StatusCode::NOT_FOUND, "sessions from Nomad workload identities are not enabled");
    };
    let Some(jwt) = bearer_long(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "send the job's Nomad workload identity as Authorization: Bearer");
    };
    let at = now();
    match nomad.verify(&jwt, at).await {
        Err(why) => {
            tracing::warn!(reason = %why, "a Nomad identity was refused");
            app.audit_anonymous(Audit::new("anonymous", "session.refused", json!({"reason": why})), at);
            error(StatusCode::FORBIDDEN, format!("the identity was not accepted: {why}"))
        }
        Ok(w) => {
            let origin = json!({"kind": "nomad", "namespace": w.namespace, "job": w.job_id, "alloc": w.alloc_id, "task": w.task});
            match app.store.create_session(
                &w.label(),
                origin,
                Some((&w.alloc_id, MAX_SESSIONS_PER_ALLOC)),
                app.cfg.limits.session_ttl_secs,
                at,
            ) {
                Ok(Err(why)) => error(StatusCode::TOO_MANY_REQUESTS, why),
                Ok(Ok((s, token))) => {
                    tracing::info!(session = %s.id, label = %s.label, "session opened");
                    (
                        StatusCode::CREATED,
                        Json(json!({"session_id": s.id, "token": token, "expires_at": s.expires_at, "label": s.label})),
                    )
                        .into_response()
                }
                Err(e) => internal(e),
            }
        }
    }
}

/// Nomad JWTs exceed the 200 characters `presented_token` allows for a session token.
fn bearer_long(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = v.split_once(' ')?;
    let rest = rest.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty() && rest.len() <= 8192).then(|| rest.to_string())
}

fn hint(status: &str, id: &str, grant: Option<&GrantRow>, system: &str) -> String {
    match (status, grant) {
        ("pending", _) if system == crate::claude::SYSTEM => format!(
            "Waiting for the owner to approve the claude.ai session with a passkey, in the companion app or on warden's page. Poll GET /api/requests/{id}?wait=25 until the status changes; do not ask again meanwhile."
        ),
        ("approved", Some(g)) if g.active_at(now()) && g.system == crate::claude::SYSTEM => format!(
            "Granted until {}. POST /api/claude/token gives the current claude.ai access token (never the refresh token); ask again before it expires.",
            iso_utc(g.expires_at)
        ),
        ("pending", _) if system == crate::google::SYSTEM => format!(
            "Waiting for the owner to approve the registry grant with a passkey on warden's page. Poll GET /api/requests/{id}?wait=25 until the status changes; do not ask again meanwhile."
        ),
        ("approved", Some(g)) if g.active_at(now()) && g.system == crate::google::SYSTEM => format!(
            "Granted until {}. Read the preset's images and packages through /registry/<host>/… with this session's token; nothing else is reachable.",
            iso_utc(g.expires_at)
        ),
        ("pending", _) => format!(
            "Waiting for the owner to approve it with a passkey, in the companion app or on warden's page. Poll GET /api/requests/{id}?wait=25 until the status changes; do not ask again meanwhile."
        ),
        ("approved", Some(g)) if g.active_at(now()) => format!(
            "Granted until {}. Use git with the warden URL (https://<warden>/git/github.com/<owner>/<repo>.git, already set up as a rewrite of https://github.com/) or the REST API under /api/v3/repos/<owner>/<repo>/…; only the granted repositories and mode work.",
            iso_utc(g.expires_at)
        ),
        ("approved", _) => "It was granted but has ended (expired or revoked). Ask again only if you still need it, and say why.".into(),
        ("refused", _) => {
            "the owner refused it. Do not ask again for the same thing; explain in your answer what you needed it for, or find another way.".into()
        }
        ("expired", _) => "Nobody answered in time. Ask again only if you still need it.".into(),
        ("withdrawn", _) => "You withdrew it.".into(),
        _ => String::new(),
    }
}

/// Includes the claude.ai power when named: without it, heimdall would see a claude.ai request with
/// nothing to grant and hide it, since it only renders complete shapes.
fn powers_of(scope: &Value) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = crate::scope::scope_powers(scope).iter().map(|p| p.as_str()).collect();
    if crate::scope::grants_claude_session(scope) {
        out.push(crate::claude::POWER);
    }
    out
}

fn grant_json(g: &GrantRow, at: i64) -> Value {
    json!({"id": g.id, "system": g.system, "repos": g.scope["repos"], "mode": g.mode, "powers": powers_of(&g.scope), "starts_at": g.starts_at,
           "expires_at": g.expires_at, "expires": iso_utc(g.expires_at), "active": g.active_at(at), "revoked_at": g.revoked_at})
}

fn request_json(r: &RequestRow, grant: Option<&GrantRow>, at: i64) -> Value {
    let status = r.status_at(at);
    let mut v = json!({"id": r.id, "status": status, "system": r.system, "repos": r.scope["repos"], "mode": r.mode, "powers": powers_of(&r.scope),
                       "duration_secs": r.duration_secs, "reason": r.reason, "created_at": r.created_at,
                       "expires_at": r.expires_at, "decided_at": r.decided_at, "hint": hint(status, &r.id, grant, &r.system)});
    if r.system == crate::google::SYSTEM {
        v["preset"] = r.scope["preset"].clone();
    }
    if let Some(g) = grant {
        v["grant"] = grant_json(g, at);
    }
    v
}

/// JSON, or a form, so `curl --data-urlencode` can escape the reason without building JSON in bash:
/// system, repo (repeated or comma-separated), mode, duration, reason.
fn request_body(headers: &HeaderMap, body: &[u8]) -> Result<Value, String> {
    let form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    if !form {
        return serde_json::from_slice(body).map_err(|e| format!("the body is not JSON ({e}). Give {SHAPE}."));
    }
    let mut v = json!({});
    let mut repos = Vec::new();
    for (k, val) in url::form_urlencoded::parse(body) {
        match k.as_ref() {
            "repo" | "repos" => repos.extend(val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
            "power" | "powers" => {
                let mut list: Vec<Value> = v["powers"].as_array().cloned().unwrap_or_default();
                list.extend(val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| json!(s)));
                v["powers"] = json!(list);
            }
            "system" | "mode" | "duration" | "reason" => v[k.as_ref()] = json!(val),
            _ => {}
        }
    }
    v["scope"] = json!({"repos": repos});
    Ok(v)
}

pub async fn create_request(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let v = match request_body(&headers, &body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let req = match parse_request_for(
        &v,
        app.cfg.limits.max_duration_secs,
        app.cfg.claude.as_ref().map(|c| c.max_grant_secs),
        app.cfg.gcp.as_ref(),
    ) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    // Only the guardian task (`claude.tasks`) asks for the claude.ai session, not the sandbox itself:
    // otherwise the owner would see two identical requests from one allocation.
    if req.system == crate::claude::SYSTEM
        && session.origin["kind"] == "nomad"
        && let Some(c) = &app.cfg.claude
        && !c.tasks.iter().any(|t| session.origin["task"].as_str() == Some(t.as_str()))
    {
        return error(
            StatusCode::FORBIDDEN,
            format!("only the task(s) {} may ask for the claude.ai session", c.tasks.join(", ")),
        );
    }
    // Same for registries: the guardian uses them on the sandbox's behalf.
    if req.is_gcp()
        && session.origin["kind"] == "nomad"
        && let Some(g) = &app.cfg.gcp
        && !g.tasks.iter().any(|t| session.origin["task"].as_str() == Some(t.as_str()))
    {
        return error(
            StatusCode::FORBIDDEN,
            format!("only the task(s) {} may ask for a registry grant", g.tasks.join(", ")),
        );
    }
    let at = now();
    if let Err(over) = app.session_audit_slot(&session.id, at) {
        return over_budget(over);
    }
    let l = &app.cfg.limits;
    match app.store.create_request(&session, &req, l.request_ttl_secs, l.max_pending_per_session, at) {
        Ok(Ok(row)) => {
            tracing::info!(request = %row.id, session = %session.label, mode = %row.mode, "access requested");
            app.changed();
            (StatusCode::CREATED, Json(request_json(&row, None, at))).into_response()
        }
        Ok(Err(why)) => error(StatusCode::TOO_MANY_REQUESTS, why),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct WaitQuery {
    #[serde(default)]
    wait: Option<u64>,
    #[serde(default)]
    since: Option<u64>,
}

/// Another session's request is reported as nonexistent.
fn own_request(app: &App, session: &SessionRow, id: &str) -> Result<RequestRow, Response> {
    if !is_id(id) {
        return Err(error(StatusCode::NOT_FOUND, "no such request"));
    }
    match app.store.request(id) {
        Ok(Some(r)) if r.session_id == session.id => Ok(r),
        Ok(_) => Err(error(StatusCode::NOT_FOUND, "no such request")),
        Err(e) => Err(internal(e)),
    }
}

pub async fn get_request(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<WaitQuery>) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait.unwrap_or(0).min(30));
    let mut rx = app.changes.subscribe();
    loop {
        rx.borrow_and_update();
        let row = match own_request(&app, &session, &id) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let at = now();
        if row.status_at(at) != "pending" || tokio::time::Instant::now() >= deadline {
            let grant = match app.store.grant_for_request(&id) {
                Ok(g) => g,
                Err(e) => return internal(e),
            };
            return Json(request_json(&row, grant.as_ref(), at)).into_response();
        }
        let left = Duration::from_secs((row.expires_at - at).max(0) as u64);
        let until = deadline.min(tokio::time::Instant::now() + left);
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { tokio::time::sleep_until(until).await },
            _ = tokio::time::sleep_until(until) => {}
        }
    }
}

pub async fn withdraw_request(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = own_request(&app, &session, &id) {
        return r;
    }
    if let Err(over) = app.session_audit_slot(&session.id, now()) {
        return over_budget(over);
    }
    match app.store.withdraw_request(&id, &session.id, now()) {
        Ok(Ok(row)) => {
            app.changed();
            Json(request_json(&row, None, now())).into_response()
        }
        Ok(Err(why)) => error(StatusCode::CONFLICT, why),
        Err(e) => internal(e),
    }
}

pub async fn list_grants(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let at = now();
    match app.store.grants_of_session(&session.id, at) {
        Ok(gs) => Json(json!({"grants": gs.iter().map(|g| grant_json(g, at)).collect::<Vec<_>>()})).into_response(),
        Err(e) => internal(e),
    }
}

pub async fn release_grant(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !is_id(&id) {
        return error(StatusCode::NOT_FOUND, "no such grant");
    }
    if let Err(over) = app.session_audit_slot(&session.id, now()) {
        return over_budget(over);
    }
    match app.store.revoke_grant(&id, &format!("session:{}", session.id), Some(&session.id), now()) {
        Ok(Ok(g)) => {
            app.live.revoke(&g.id);
            app.changed();
            Json(json!({"released": g.id})).into_response()
        }
        Ok(Err(why)) => error(StatusCode::CONFLICT, why),
        Err(e) => internal(e),
    }
}

fn heimdall_ok(app: &App, headers: &HeaderMap) -> Result<(), Response> {
    let Some(expected) = &app.heimdall_token else {
        return Err(error(StatusCode::NOT_FOUND, "the heimdall API is not enabled"));
    };
    match presented_token(headers) {
        Some(t) if ct_eq(t.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => {
            tracing::warn!("heimdall API request without a valid token");
            Err(error(StatusCode::UNAUTHORIZED, "token required"))
        }
    }
}

pub async fn heimdall_state(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<WaitQuery>) -> Response {
    if let Err(r) = heimdall_ok(&app, &headers) {
        return r;
    }
    if let Some(since) = q.since {
        let mut rx = app.changes.subscribe();
        if *rx.borrow_and_update() == since {
            let wait = Duration::from_secs(q.wait.unwrap_or(25).min(30));
            let _ = tokio::time::timeout(wait, async {
                while rx.changed().await.is_ok() {
                    if *rx.borrow_and_update() != since {
                        break;
                    }
                }
            })
            .await;
        }
    }
    // Version before data: a change landing in between shows up on the next round.
    let version = *app.changes.borrow();
    let at = now();
    let (pending, active) = match (app.store.pending_requests(at), app.store.active_grants(at)) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => return internal(e),
    };
    let pending: Vec<Value> = pending
        .iter()
        .map(|r| {
            json!({"id": r.id, "system": r.system, "repos": r.scope["repos"], "mode": r.mode, "powers": powers_of(&r.scope), "duration_secs": r.duration_secs,
                   "reason": r.reason, "session": r.session_label, "created_at": r.created_at, "expires_at": r.expires_at})
        })
        .collect();
    let active: Vec<Value> = active
        .iter()
        .map(|(g, label)| {
            json!({"id": g.id, "request_id": g.request_id, "system": g.system, "repos": g.scope["repos"], "mode": g.mode, "powers": powers_of(&g.scope),
                   "starts_at": g.starts_at, "expires_at": g.expires_at, "session": label})
        })
        .collect();
    Json(json!({"version": version, "now": at, "pending": pending, "active": active})).into_response()
}

pub async fn heimdall_refuse(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = heimdall_ok(&app, &headers) {
        return r;
    }
    if !is_id(&id) {
        return error(StatusCode::NOT_FOUND, "no such request");
    }
    match app.store.refuse_request(&id, "heimdall", now()) {
        Ok(Ok(r)) => {
            tracing::info!(request = %id, "request refused from heimdall");
            app.changed();
            Json(json!({"id": r.id, "status": r.status})).into_response()
        }
        Ok(Err(why)) => error(StatusCode::CONFLICT, why),
        Err(e) => internal(e),
    }
}

fn refused(r: crate::webauthn::Refusal) -> Response {
    (r.status, Json(json!({"error": r.reason, "message": r.message}))).into_response()
}

pub async fn heimdall_challenge(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = heimdall_ok(&app, &headers) {
        return r;
    }
    if !is_id(&id) {
        return error(StatusCode::NOT_FOUND, "no such request");
    }
    match crate::webauthn::issue_approve_challenge(&app, &id, crate::webauthn::Channel::Heimdall) {
        Ok(v) => Json(v).into_response(),
        Err(r) => refused(r),
    }
}

/// heimdall's token only allows the call; what grants is the owner's passkey signature.
pub async fn heimdall_approve(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Err(r) = heimdall_ok(&app, &headers) {
        return r;
    }
    if !is_id(&id) {
        return error(StatusCode::NOT_FOUND, "no such request");
    }
    let Ok(assertion) = serde_json::from_slice::<crate::webauthn::AssertionIn>(&body) else {
        return error(StatusCode::BAD_REQUEST, "send the passkey assertion as JSON");
    };
    match crate::webauthn::approve_with_assertion(&app, &id, crate::webauthn::Channel::Heimdall, &assertion) {
        Ok(g) => Json(json!({"id": id, "status": "approved", "grant_id": g.id, "expires_at": g.expires_at})).into_response(),
        Err(r) => refused(r),
    }
}

/// Ends it now, including traffic already in flight through the proxy.
pub async fn heimdall_revoke(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = heimdall_ok(&app, &headers) {
        return r;
    }
    if !is_id(&id) {
        return error(StatusCode::NOT_FOUND, "no such grant");
    }
    match app.store.revoke_grant(&id, "heimdall", None, now()) {
        Ok(Ok(g)) => {
            tracing::info!(grant = %id, "grant revoked from heimdall");
            app.live.revoke(&g.id);
            app.changed();
            Json(json!({"id": g.id, "revoked_at": g.revoked_at})).into_response()
        }
        Ok(Err(why)) => error(StatusCode::CONFLICT, why),
        Err(e) => internal(e),
    }
}

/// The guardian polls every few minutes with `have` (no delivery if unchanged) and gets a new token
/// every few hours.
pub const CLAUDE_DELIVERIES_PER_HOUR: u32 = 30;

#[derive(Deserialize, Default)]
struct TokenAsk {
    /// Hex sha256 of the access token already held: if still current, it isn't sent again.
    #[serde(default)]
    have: Option<String>,
}

fn claude_delivery_allowed(app: &App, session: &str, at: i64) -> bool {
    let hour = at / 3600;
    let mut m = app.claude_deliveries.lock().unwrap_or_else(|p| p.into_inner());
    m.retain(|_, (h, _)| *h == hour);
    let e = m.entry(session.to_string()).or_insert((hour, 0));
    if e.1 >= CLAUDE_DELIVERIES_PER_HOUR {
        return false;
    }
    e.1 += 1;
    true
}

/// Never the refresh token: only warden uses it (claude.rs). Every delivery is audited with a
/// fingerprint instead of the token; asking with a current `have` delivers and logs nothing.
pub async fn claude_token(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let session = match session_of(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(cfg) = &app.cfg.claude else {
        return error(StatusCode::NOT_FOUND, "the claude.ai session is not enabled in this warden");
    };
    let ask: TokenAsk = if body.is_empty() {
        TokenAsk::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(a) => a,
            Err(e) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    format!("the body is not JSON ({e}): send {{}} or {{\"have\": \"<sha256 of your token>\"}}"),
                );
            }
        }
    };
    let at = now();
    // Grant first: without one the token isn't even read, let alone renewed.
    let grant = match app.store.claude_grant(&session, &cfg.tasks, at) {
        Ok(Some(g)) => g,
        Ok(None) => {
            return error(
                StatusCode::FORBIDDEN,
                format!(
                    "no active grant lets this session use the owner's claude.ai session. Ask for one: POST /api/requests {} and wait for the approval.",
                    crate::scope::CLAUDE_SHAPE
                ),
            );
        }
        Err(e) => return internal(e),
    };
    let current = match app.claude_token(&session.id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return error(
                StatusCode::CONFLICT,
                "claude.ai is not connected in warden: the owner has to connect it on warden's page",
            );
        }
        Err(crate::connection::TokenError::Reconnect(why)) => {
            return error(
                StatusCode::CONFLICT,
                format!("the owner has to connect claude.ai again on warden's page ({why})"),
            );
        }
        Err(crate::connection::TokenError::Unavailable(why)) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("claude.ai did not answer the token renewal ({why}); ask again in a minute"),
            );
        }
        Err(crate::connection::TokenError::Internal(e)) => return internal(e),
    };
    let at = now();
    match app.store.grant(&grant.id) {
        Ok(Some(g)) if g.active_at(at) => {}
        Ok(_) => {
            return error(StatusCode::FORBIDDEN, "the grant ended while the token was being renewed");
        }
        Err(e) => return internal(e),
    }
    let fingerprint = crate::util::sha256_hex(current.access_token.as_bytes());
    let base = json!({"expires_at": current.expires_at, "grant_id": grant.id, "grant_expires_at": grant.expires_at});
    if ask
        .have
        .as_deref()
        .is_some_and(|h| crate::util::ct_eq(h.trim().to_ascii_lowercase().as_bytes(), fingerprint.as_bytes()))
    {
        let mut v = base;
        v["unchanged"] = json!(true);
        return Json(v).into_response();
    }
    if !claude_delivery_allowed(&app, &session.id, at) {
        tracing::warn!(session = %session.label, "too many claude.ai token deliveries to one session this hour");
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many token requests this hour; send \"have\" with the sha256 of the token you hold and ask every few minutes",
        );
    }
    let detail = json!({"session": session.label, "expires_at": current.expires_at, "token_sha256": &fingerprint[..16]});
    if let Err(e) = app.store.audit(
        Audit::new(format!("session:{}", session.id), "claude.token_issued", detail)
            .grant(&grant.id)
            .session(&session.id),
        at,
    ) {
        // No audit line, no delivery.
        return internal(e);
    }
    tracing::info!(session = %session.label, grant = %grant.id, expires_at = current.expires_at, "claude.ai access token handed out");
    let mut v = base;
    v["access_token"] = json!(current.access_token);
    v["scopes"] = json!(current.scopes);
    v["subscription_type"] = json!(current.subscription_type);
    v["rate_limit_tier"] = json!(current.rate_limit_tier);
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], Json(v)).into_response()
}
