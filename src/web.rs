// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! The owner's browser pages (`public_url`): requests, the panel, connections and passkeys.
//! A request page's URL is the capability (128 random bits). Anything that grants or connects needs a
//! fresh passkey login.
//!
//! CSRF: every POST repeats the `__Host-warden_csrf` cookie token in its body and must come from
//! `public_url`. `__Host-` stops a sibling subdomain, which is the same site, from planting the cookie.
//! Each OAuth flow is bound to the browser that started it and its `state` is single-use (store.rs).
use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::app::App;
use std::time::Duration;

use crate::github::{AAD, Issued, Poll};
use crate::pages::{self, Kind};
use crate::store::{Approval, Audit, ConnectionRow, FLOW_TTL, Flow, Via};
use crate::util::{b64url, ct_eq, is_id, now, random, sha256_hex};

pub const CSRF_COOKIE: &str = "__Host-warden_csrf";
pub const FLOW_COOKIE: &str = "__Host-warden_flow";
pub const OWNER_COOKIE: &str = "__Host-warden_owner";

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn set_cookie(name: &str, value: &str, same_site: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age={max_age}")).expect("cookie values are base64url")
}

fn page(status: StatusCode, html: String) -> Response {
    (status, Html(html)).into_response()
}

fn fail(status: StatusCode, title: &str, text: &str) -> Response {
    page(status, pages::message(title, text, Kind::Err))
}

fn csrf_for(headers: &HeaderMap) -> (String, Option<HeaderValue>) {
    match cookie(headers, CSRF_COOKIE).filter(|c| c.len() >= 32 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
        Some(c) => (c, None),
        None => {
            let c = b64url(&random::<32>());
            let set = set_cookie(CSRF_COOKIE, &c, "Strict", 12 * 3600);
            (c, Some(set))
        }
    }
}

/// Without `Origin`, the `Referer` must be on our origin.
pub fn csrf_ok(headers: &HeaderMap, form_token: &str, origin: &str) -> bool {
    let Some(c) = cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    if c.len() < 32 || !ct_eq(c.as_bytes(), form_token.as_bytes()) {
        return false;
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(o) => o == origin,
        None => headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|r| r == origin || r.starts_with(&format!("{origin}/"))),
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

fn with_cookie(mut resp: Response, set: Option<HeaderValue>) -> Response {
    if let Some(v) = set {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

fn see_other(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location.to_string())]).into_response()
}

fn redirect_uri(app: &App, path: &str) -> String {
    format!("{}{path}", app.cfg.public_origin())
}

fn audit(app: &App, actor: &str, event: &str, detail: serde_json::Value, request: Option<&str>) {
    let mut a = Audit::new(actor, event, detail);
    if let Some(r) = request {
        a = a.request(r);
    }
    if let Err(e) = app.store.audit(a, now()) {
        tracing::error!(error = %e, event, "cannot write an audit line");
    }
}

/// `fresh` forces a new passkey login rather than reusing the provider's session.
async fn start_oidc(app: &App, headers: &HeaderMap, action: &str, target: &str, fresh: bool) -> Response {
    let state = b64url(&random::<32>());
    let nonce = b64url(&random::<32>());
    let verifier = b64url(&random::<32>());
    let (browser, set) = match cookie(headers, FLOW_COOKIE).filter(|c| c.len() >= 32) {
        Some(b) => (b, None),
        None => {
            let b = b64url(&random::<32>());
            let set = set_cookie(FLOW_COOKIE, &b, "Lax", FLOW_TTL);
            (b, Some(set))
        }
    };
    let flow = Flow {
        kind: "oidc".into(),
        action: action.into(),
        target: target.into(),
        nonce: nonce.clone(),
        verifier: verifier.clone(),
        browser_hash: sha256_hex(browser.as_bytes()),
        created_at: now(),
    };
    if let Err(e) = app.store.put_flow(&state, &flow) {
        tracing::error!(error = %e, "cannot store an OIDC flow");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not start the login.");
    }
    match app
        .oidc
        .authorize_url(&redirect_uri(app, "/oidc/callback"), &state, &nonce, &verifier, fresh)
        .await
    {
        Ok(url) => with_cookie(see_other(&url), set),
        Err(e) => {
            tracing::error!(error = %e, "Pocket ID discovery failed");
            fail(
                StatusCode::BAD_GATEWAY,
                "Pocket ID is not answering",
                "Could not reach Pocket ID. Try again in a moment.",
            )
        }
    }
}

pub async fn request_page(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !is_id(&id) {
        return fail(StatusCode::NOT_FOUND, "Not found", "That request does not exist.");
    }
    let (row, grant) = match (app.store.request(&id), app.store.grant_for_request(&id)) {
        (Ok(Some(r)), Ok(g)) => (r, g),
        (Ok(None), _) => {
            return fail(StatusCode::NOT_FOUND, "Not found", "That request does not exist.");
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!(error = %e, "request page");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the request.");
        }
    };
    let passkey = app.cfg.webauthn.is_some() && app.store.passkeys(&app.cfg.oidc.owner_sub).map(|p| !p.is_empty()).unwrap_or(false);
    let (csrf, set) = csrf_for(&headers);
    with_cookie(page(StatusCode::OK, pages::request(&row, grant.as_ref(), &csrf, now(), passkey)), set)
}

/// The grant is only created on the OIDC callback, after a fresh passkey login.
pub async fn approve(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(
            StatusCode::FORBIDDEN,
            "Not allowed",
            "This form did not come from warden's page. Open the request again.",
        );
    }
    if !is_id(&id) {
        return fail(StatusCode::NOT_FOUND, "Not found", "That request does not exist.");
    }
    match app.store.request(&id) {
        Ok(Some(r)) if r.status_at(now()) == "pending" => start_oidc(&app, &headers, "approve", &id, true).await,
        Ok(Some(r)) => fail(
            StatusCode::CONFLICT,
            "Too late",
            &format!("The request is already {}.", crate::store::status_label(r.status_at(now()))),
        ),
        Ok(None) => fail(StatusCode::NOT_FOUND, "Not found", "That request does not exist."),
        Err(e) => {
            tracing::error!(error = %e, "approve");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the request.")
        }
    }
}

/// Refusing only takes away, so it needs no passkey.
pub async fn refuse(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if !is_id(&id) {
        return fail(StatusCode::NOT_FOUND, "Not found", "That request does not exist.");
    }
    match app.store.refuse_request(&id, "web", now()) {
        Ok(Ok(_)) => {
            app.changed();
            page(
                StatusCode::OK,
                pages::message("Refused", "Claude will see it the next time it checks.", Kind::Ok),
            )
        }
        Ok(Err(why)) => fail(StatusCode::CONFLICT, "Too late", &why),
        Err(e) => {
            tracing::error!(error = %e, "refuse");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not refuse it.")
        }
    }
}

pub async fn revoke(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if !is_id(&id) {
        return fail(StatusCode::NOT_FOUND, "Not found", "That grant does not exist.");
    }
    match app.store.revoke_grant(&id, "web", None, now()) {
        Ok(Ok(g)) => {
            app.live.revoke(&g.id);
            app.changed();
            page(
                StatusCode::OK,
                pages::message("Revoked", "It stops working now, and anything in progress is cut off.", Kind::Ok),
            )
        }
        Ok(Err(why)) => fail(StatusCode::CONFLICT, "Too late", &why),
        Err(e) => {
            tracing::error!(error = %e, "revoke");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not revoke it.")
        }
    }
}

pub async fn dashboard(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let at = now();
    let owner = cookie(&headers, OWNER_COOKIE).map(|t| app.store.owner_session(&t, at));
    match owner {
        Some(Ok(Some(_))) => {}
        Some(Err(e)) => {
            tracing::error!(error = %e, "owner session");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the session.");
        }
        _ => return see_other("/login"),
    }
    let data = (|| -> anyhow::Result<pages::Dashboard> {
        Ok(pages::Dashboard {
            pending: app.store.pending_requests(at)?,
            active: app.store.active_grants(at)?,
            github: app.store.connection("github")?,
            claude: match &app.claude {
                Some(_) => Some(app.store.connection(crate::claude::PROVIDER)?),
                None => None,
            },
            google: match &app.google {
                Some(g) => Some((app.store.connection(crate::google::PROVIDER)?, g.cfg.expected_email.clone())),
                None => None,
            },
            github_settings: app.github.settings_url(),
            audit: app.store.audit_tail(80)?,
            passkeys: match &app.cfg.webauthn {
                Some(_) => Some(app.store.passkeys(&app.cfg.oidc.owner_sub)?),
                None => None,
            },
            now: at,
        })
    })();
    match data {
        Ok(d) => {
            let (csrf, set) = csrf_for(&headers);
            with_cookie(page(StatusCode::OK, pages::dashboard(&d, &csrf)), set)
        }
        Err(e) => {
            tracing::error!(error = %e, "dashboard");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the state.")
        }
    }
}

pub async fn login(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    start_oidc(&app, &headers, "login", "", false).await
}

pub async fn logout(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if let Some(t) = cookie(&headers, OWNER_COOKIE) {
        let _ = app.store.end_owner_session(&t);
    }
    with_cookie(
        page(StatusCode::OK, pages::message("Logged out", "You have logged out of the panel.", Kind::Info)),
        Some(set_cookie(OWNER_COOKIE, "", "Lax", 0)),
    )
}

pub async fn connect_github(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    start_oidc(&app, &headers, "connect", "", true).await
}

pub async fn disconnect_github(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    start_oidc(&app, &headers, "disconnect", "", true).await
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

fn same_browser(headers: &HeaderMap, flow: &Flow) -> bool {
    cookie(headers, FLOW_COOKIE).is_some_and(|b| ct_eq(sha256_hex(b.as_bytes()).as_bytes(), flow.browser_hash.as_bytes()))
}

pub async fn oidc_callback(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<Callback>) -> Response {
    let at = now();
    let flow = match q.state.as_deref().map(|s| app.store.take_flow(s, "oidc", at)) {
        Some(Ok(Some(f))) => f,
        Some(Err(e)) => {
            tracing::error!(error = %e, "take flow");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the flow.");
        }
        _ => {
            return fail(
                StatusCode::BAD_REQUEST,
                "Link expired",
                "This link is no longer valid (it expired or was already used). Start again from the request.",
            );
        }
    };
    let event = format!("{}.failed", flow.action);
    let request = (flow.action == "approve").then_some(flow.target.as_str());
    let refuse = |reason: &str, status: StatusCode, text: &str| {
        tracing::warn!(action = %flow.action, reason, "OIDC flow refused");
        audit(&app, "web", &event, json!({"reason": reason}), request);
        fail(status, "Not confirmed", text)
    };
    if !same_browser(&headers, &flow) {
        return refuse(
            "the callback came to another browser than the one that started the flow",
            StatusCode::BAD_REQUEST,
            "This did not come back to the browser that started it. Start again.",
        );
    }
    if q.iss.as_deref().is_some_and(|i| i != app.cfg.oidc.issuer) {
        return refuse(
            "the callback names another issuer",
            StatusCode::BAD_REQUEST,
            "The answer did not come from Pocket ID.",
        );
    }
    if let Some(err) = &q.error {
        let err: String = err.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect();
        audit(&app, "web", &format!("{}.cancelled", flow.action), json!({"error": err}), request);
        return page(
            StatusCode::OK,
            pages::message("Cancelled", "It was not confirmed in Pocket ID; nothing has changed.", Kind::Info),
        );
    }
    let Some(code) = q.code.as_deref() else {
        return refuse("no code", StatusCode::BAD_REQUEST, "The code from Pocket ID is missing.");
    };
    let id_token = match app.oidc.exchange(code, &redirect_uri(&app, "/oidc/callback"), &flow.verifier).await {
        Ok(t) => t,
        Err(e) => {
            return refuse(
                &format!("code exchange failed: {e}"),
                StatusCode::BAD_GATEWAY,
                "Pocket ID did not accept the code.",
            );
        }
    };
    let fresh = flow.action != "login";
    let owner = match app.oidc.verify(&id_token, &flow.nonce, flow.created_at, fresh, now()).await {
        Ok(o) => o,
        Err(why) => {
            return refuse(
                &why,
                StatusCode::FORBIDDEN,
                "Could not confirm that it is you with a fresh passkey. Nothing has changed.",
            );
        }
    };
    let actor = format!("owner:{}", owner.sub);
    match flow.action.as_str() {
        "approve" => {
            let approval = Approval {
                sub: owner.sub.clone(),
                auth_time: owner.auth_time,
                amr: owner.amr.clone(),
                via: Via::PocketId,
            };
            match app.store.approve_request(&flow.target, &approval, now()) {
                Ok(Ok(grant)) => {
                    tracing::info!(request = %flow.target, grant = %grant.id, "request approved with a fresh passkey");
                    app.changed();
                    match app.store.request(&flow.target) {
                        Ok(Some(r)) => page(StatusCode::OK, pages::granted(&r, &grant, now())),
                        _ => page(StatusCode::OK, pages::message("Granted", "Granted.", Kind::Ok)),
                    }
                }
                Ok(Err(why)) => fail(StatusCode::CONFLICT, "Not granted", &why),
                Err(e) => {
                    tracing::error!(error = %e, "approve");
                    fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not save the grant.")
                }
            }
        }
        "login" => match app.store.create_owner_session(&owner.sub, app.cfg.limits.owner_session_ttl_secs, now()) {
            Ok(t) => with_cookie(see_other("/"), Some(set_cookie(OWNER_COOKIE, &t, "Lax", app.cfg.limits.owner_session_ttl_secs))),
            Err(e) => {
                tracing::error!(error = %e, "owner session");
                fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not open the session.")
            }
        },
        "connect" => start_device(&app, &flow.browser_hash, &owner.sub).await,
        "passkey-add" => {
            let Some(w) = &app.cfg.webauthn else {
                return fail(StatusCode::NOT_FOUND, "Not available", "The warden passkey is not enabled.");
            };
            let (challenge, existing) = match (
                crate::webauthn::issue_register_challenge(&app, &flow.browser_hash, &owner.sub),
                app.store.passkeys(&owner.sub),
            ) {
                (Ok(c), Ok(p)) => (c, p),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::error!(error = %e, "passkey registration challenge");
                    return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not prepare the registration.");
                }
            };
            audit(&app, &actor, "passkey.register_started", json!({}), None);
            let exclude: Vec<String> = existing.into_iter().map(|p| p.credential_id).collect();
            let (csrf, set) = csrf_for(&headers);
            let html = pages::passkey_register(&challenge, &w.rp_id, &crate::webauthn::user_handle(&owner.sub), &exclude, &csrf);
            // The flow cookie binds the registration to this browser, so it must outlive the challenge.
            let flow_cookie = cookie(&headers, FLOW_COOKIE).map(|b| set_cookie(FLOW_COOKIE, &b, "Lax", crate::webauthn::REGISTER_TTL + 60));
            with_cookie(with_cookie(page(StatusCode::OK, html), set), flow_cookie)
        }
        "passkey-revoke" => match app.store.revoke_passkey(&flow.target, &actor, now()) {
            Ok(Ok(p)) => {
                tracing::info!(passkey = %p.id, "warden passkey revoked");
                page(
                    StatusCode::OK,
                    pages::message("Passkey removed", &format!("“{}” no longer approves anything.", p.name), Kind::Ok),
                )
            }
            Ok(Err(why)) => fail(StatusCode::CONFLICT, "Not removed", &why),
            Err(e) => {
                tracing::error!(error = %e, "revoke passkey");
                fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not remove the passkey.")
            }
        },
        "claude-connect" => start_claude(&app, &headers, &flow.browser_hash, &owner.sub),
        "google-connect" => start_google(&app, &headers, &flow.browser_hash, &owner.sub),
        "google-disconnect" => {
            let account = app.store.connection(crate::google::PROVIDER).ok().flatten().map(|c| c.account);
            // Revoke at Google too, or a leaked refresh token would stay valid outside warden.
            let refresh = app.google_refresh_token();
            match app.store.delete_connection(
                crate::google::PROVIDER,
                &actor,
                json!({"provider": crate::google::PROVIDER, "account": account}),
                now(),
            ) {
                Ok(gone) => {
                    let revoked = match (gone, refresh, &app.google) {
                        (true, Some(t), Some(g)) => match g.revoke(&t).await {
                            Ok(()) => true,
                            Err(why) => {
                                tracing::warn!(reason = %why, "Google did not revoke the refresh token");
                                audit(
                                    &app,
                                    &actor,
                                    "connection.revoke_failed",
                                    json!({"provider": crate::google::PROVIDER, "reason": why}),
                                    None,
                                );
                                false
                            }
                        },
                        _ => false,
                    };
                    page(StatusCode::OK, pages::google_disconnected(gone, revoked))
                }
                Err(e) => {
                    tracing::error!(error = %e, "disconnect Google");
                    fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not delete the connection.")
                }
            }
        }
        "claude-disconnect" => {
            let account = app.store.connection(crate::claude::PROVIDER).ok().flatten().map(|c| c.account);
            match app.store.delete_connection(
                crate::claude::PROVIDER,
                &actor,
                json!({"provider": crate::claude::PROVIDER, "account": account}),
                now(),
            ) {
                Ok(gone) => page(StatusCode::OK, pages::claude_disconnected(gone)),
                Err(e) => {
                    tracing::error!(error = %e, "disconnect claude.ai");
                    fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not delete the connection.")
                }
            }
        }
        "disconnect" => {
            let account = app.store.connection("github").ok().flatten().map(|c| c.account);
            match app
                .store
                .delete_connection("github", &actor, json!({"provider": "github", "account": account}), now())
            {
                Ok(gone) => page(StatusCode::OK, pages::disconnected(gone, &app.github.settings_url())),
                Err(e) => {
                    tracing::error!(error = %e, "disconnect");
                    fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not delete the connection.")
                }
            }
        }
        other => {
            tracing::error!(action = other, "unknown flow action");
            fail(StatusCode::BAD_REQUEST, "Error", "Unknown flow.")
        }
    }
}

/// One at a time: starting another supersedes it. Only the browser that started it sees the code,
/// since anyone who sees it can enter it with their own account.
#[derive(Clone, Debug)]
pub struct Device {
    pub id: String,
    pub browser_hash: String,
    pub sub: String,
    pub user_code: String,
    pub expires_at: i64,
    pub status: DeviceStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceStatus {
    Pending,
    /// `expires_at` is None when GitHub gave no refresh token, so the token does not expire.
    Connected {
        account: String,
        scopes: String,
        expires_at: Option<i64>,
    },
    WrongAccount(String),
    Denied,
    Expired,
    Failed(String),
}

async fn start_device(app: &Arc<App>, browser_hash: &str, sub: &str) -> Response {
    let code = match app.github.device_code().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "GitHub device flow could not start");
            audit(app, &format!("owner:{sub}"), "connect.failed", json!({"reason": e.to_string()}), None);
            return fail(
                StatusCode::BAD_GATEWAY,
                "GitHub is not answering",
                "GitHub gave no code. Does the OAuth App have “Enable Device Flow” turned on?",
            );
        }
    };
    let device = Device {
        id: crate::util::new_id("dev"),
        browser_hash: browser_hash.to_string(),
        sub: sub.to_string(),
        user_code: code.user_code.clone(),
        expires_at: now() + code.expires_in,
        status: DeviceStatus::Pending,
    };
    *app.device.lock().await = Some(device.clone());
    audit(
        app,
        &format!("owner:{sub}"),
        "connect.started",
        json!({"provider": "github", "method": "device", "expires_at": device.expires_at}),
        None,
    );
    tokio::spawn(poll_device(app.clone(), device.id.clone(), code.device_code, code.interval, device.expires_at));
    see_other("/connections/github/device")
}

/// `device_code` never leaves this task.
async fn poll_device(app: Arc<App>, id: String, device_code: String, interval: u64, expires_at: i64) {
    let mut wait = Duration::from_secs(interval).max(Duration::from_millis(200));
    let set = |status: DeviceStatus| {
        let app = app.clone();
        let id = id.clone();
        async move {
            let mut d = app.device.lock().await;
            match d.as_mut() {
                Some(d) if d.id == id => {
                    d.status = status;
                    true
                }
                _ => false,
            }
        }
    };
    loop {
        tokio::time::sleep(wait).await;
        let (sub, current) = match app.device.lock().await.as_ref() {
            Some(d) if d.id == id && d.status == DeviceStatus::Pending => (d.sub.clone(), true),
            _ => (String::new(), false),
        };
        if !current {
            return;
        }
        let actor = format!("owner:{sub}");
        if now() >= expires_at {
            audit(
                &app,
                &actor,
                "connect.failed",
                json!({"provider": "github", "reason": "the device code expired"}),
                None,
            );
            set(DeviceStatus::Expired).await;
            return;
        }
        match app.github.poll(&device_code).await {
            Poll::Pending => {}
            Poll::SlowDown => wait += Duration::from_secs(5),
            Poll::Failed(e) => {
                tracing::warn!(error = %e, "GitHub device flow poll failed; trying again")
            }
            Poll::Denied => {
                audit(&app, &actor, "connect.cancelled", json!({"provider": "github", "error": "access_denied"}), None);
                set(DeviceStatus::Denied).await;
                return;
            }
            Poll::Expired => {
                audit(
                    &app,
                    &actor,
                    "connect.failed",
                    json!({"provider": "github", "reason": "the device code expired"}),
                    None,
                );
                set(DeviceStatus::Expired).await;
                return;
            }
            Poll::Token(token) => {
                let still = matches!(app.device.lock().await.as_ref(), Some(d) if d.id == id && d.status == DeviceStatus::Pending);
                if !still {
                    tracing::warn!("a replaced GitHub device flow was authorised; token discarded");
                    return;
                }
                let status = keep_token(&app, &actor, token).await;
                set(status).await;
                return;
            }
        }
    }
}

async fn keep_token(app: &App, actor: &str, issued: Issued) -> DeviceStatus {
    let fail_with = |reason: String| {
        audit(app, actor, "connect.failed", json!({"provider": "github", "reason": reason}), None);
        DeviceStatus::Failed(reason)
    };
    let token = issued.token;
    let account = match app.github.login(&token.access_token).await {
        Ok(a) => a,
        Err(e) => return fail_with(format!("cannot read the GitHub account: {e}")),
    };
    let expected = app.github.cfg.expected_login.trim();
    if !expected.is_empty() && !account.eq_ignore_ascii_case(expected) {
        tracing::warn!(account = %account, expected, "a GitHub device code was authorised by another account; token discarded");
        audit(
            app,
            actor,
            "connect.failed",
            json!({"provider": "github", "reason": "another account authorised the code", "account": account}),
            None,
        );
        return DeviceStatus::WrongAccount(account);
    }
    let extra = crate::github::unrequested_scopes(&token.scope, &app.github.cfg.scopes);
    if !extra.is_empty() {
        return fail_with(format!("GitHub issued scopes that were not asked for: {}", extra.join(", ")));
    }
    let plain = match serde_json::to_vec(&token) {
        Ok(p) => p,
        Err(e) => return fail_with(e.to_string()),
    };
    let at = now();
    let row = ConnectionRow {
        provider: "github".into(),
        account: account.clone(),
        scopes: token.scope.clone(),
        sealed: app.sealer.seal(&plain, AAD),
        connected_at: at,
        expires_at: issued.expires_in.map(|s| at + s),
        refresh_expires_at: issued.refresh_expires_in.map(|s| at + s),
        refreshed_at: None,
        broken: None,
    };
    if let Err(e) = app.store.put_connection(&row, actor, at) {
        tracing::error!(error = %e, "store connection");
        return fail_with("cannot store the connection".into());
    }
    tracing::info!(account = %account, scopes = %token.scope, expires_at = ?row.expires_at, "GitHub connected (device flow)");
    DeviceStatus::Connected {
        account,
        scopes: token.scope,
        expires_at: row.expires_at,
    }
}

pub async fn device_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let device = app.device.lock().await.clone();
    let Some(d) = device.filter(|d| cookie(&headers, FLOW_COOKIE).is_some_and(|b| ct_eq(sha256_hex(b.as_bytes()).as_bytes(), d.browser_hash.as_bytes())))
    else {
        return fail(
            StatusCode::NOT_FOUND,
            "Nothing in progress",
            "No GitHub connection is in progress in this browser. Start from the panel.",
        );
    };
    let status = if d.status == DeviceStatus::Pending && now() >= d.expires_at {
        DeviceStatus::Expired
    } else {
        d.status.clone()
    };
    page(
        StatusCode::OK,
        pages::device(
            &d.user_code,
            &status,
            &app.github.device_url(),
            &app.github.settings_url(),
            d.expires_at - now(),
        ),
    )
}

pub async fn connect_claude(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if app.claude.is_none() {
        return fail(StatusCode::NOT_FOUND, "Not available", "The claude.ai session is not enabled in this warden.");
    }
    start_oidc(&app, &headers, "claude-connect", "", true).await
}

pub async fn disconnect_claude(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    start_oidc(&app, &headers, "claude-disconnect", "", true).await
}

fn start_claude(app: &App, headers: &HeaderMap, browser_hash: &str, sub: &str) -> Response {
    let Some(claude) = &app.claude else {
        return fail(StatusCode::NOT_FOUND, "Not available", "The claude.ai session is not enabled in this warden.");
    };
    let state = b64url(&random::<32>());
    let verifier = b64url(&random::<32>());
    let flow = Flow {
        kind: "claude".into(),
        action: "connect".into(),
        target: sub.into(),
        nonce: String::new(),
        verifier: verifier.clone(),
        browser_hash: browser_hash.to_string(),
        created_at: now(),
    };
    if let Err(e) = app.store.put_flow(&state, &flow) {
        tracing::error!(error = %e, "cannot store a claude.ai flow");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not start the connection.");
    }
    audit(
        app,
        &format!("owner:{sub}"),
        "connect.started",
        json!({"provider": crate::claude::PROVIDER, "method": "pkce"}),
        None,
    );
    let (csrf, set) = csrf_for(headers);
    // The flow cookie binds the pasted code to this browser, so it must outlive the flow.
    let flow_cookie = cookie(headers, FLOW_COOKIE).map(|b| set_cookie(FLOW_COOKIE, &b, "Lax", FLOW_TTL));
    with_cookie(
        with_cookie(
            page(StatusCode::OK, pages::claude_connect(&claude.authorize_url(&state, &verifier), &state, &csrf)),
            set,
        ),
        flow_cookie,
    )
}

#[derive(Deserialize)]
pub struct ClaudeCodeForm {
    #[serde(default)]
    csrf: String,
    /// The flow's `state`, in case only the code is pasted.
    #[serde(default)]
    flow: String,
    /// claude.ai shows «code#state».
    #[serde(default)]
    code: String,
}

/// Whitespace is dropped: a terminal may wrap a pasted code.
pub fn split_pasted_code(raw: &str) -> Option<(String, Option<String>)> {
    let raw: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let (code, state) = match raw.split_once('#') {
        Some((c, s)) => (c.to_string(), Some(s.to_string()).filter(|s| !s.is_empty())),
        None => (raw, None),
    };
    let ok = |s: &str| !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'));
    (ok(&code) && state.as_deref().is_none_or(ok)).then_some((code, state))
}

pub async fn claude_code(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<ClaudeCodeForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    let Some(claude) = &app.claude else {
        return fail(StatusCode::NOT_FOUND, "Not available", "The claude.ai session is not enabled in this warden.");
    };
    let Some((code, pasted_state)) = split_pasted_code(&f.code) else {
        return fail(
            StatusCode::BAD_REQUEST,
            "Invalid code",
            "Paste the code exactly as claude.ai shows it (code#state). Start again from the panel.",
        );
    };
    // A pasted state wins, but must match this page's flow.
    let state = match pasted_state {
        Some(s) if !f.flow.is_empty() && !ct_eq(s.as_bytes(), f.flow.as_bytes()) => {
            audit(
                &app,
                "web",
                "connect.failed",
                json!({"provider": crate::claude::PROVIDER, "reason": "the pasted code is for another flow"}),
                None,
            );
            return fail(
                StatusCode::BAD_REQUEST,
                "Wrong code",
                "That code is for another connection, started earlier. Start again from the panel.",
            );
        }
        Some(s) => s,
        None => f.flow.clone(),
    };
    let flow = match app.store.take_flow(&state, "claude", now()) {
        Ok(Some(fl)) => fl,
        Ok(None) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "Expired",
                "This connection is no longer valid (it expired or was already used). Start again from the panel.",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "take claude flow");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the flow.");
        }
    };
    let actor = format!("owner:{}", flow.target);
    if !same_browser(&headers, &flow) {
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::claude::PROVIDER, "reason": "the code came to another browser than the one that started"}),
            None,
        );
        return fail(
            StatusCode::BAD_REQUEST,
            "Wrong browser",
            "This code did not come from the browser that started it. Start again from the panel.",
        );
    }
    let issued = match claude.exchange(&code, &state, &flow.verifier).await {
        Ok(t) => t,
        Err(why) => {
            tracing::warn!(reason = %why, "claude.ai did not accept the pasted code");
            audit(
                &app,
                &actor,
                "connect.failed",
                json!({"provider": crate::claude::PROVIDER, "reason": why}),
                None,
            );
            return fail(
                StatusCode::BAD_GATEWAY,
                "Not connected",
                &format!("claude.ai did not accept the code ({why}). Start again from the panel."),
            );
        }
    };
    let extra = crate::claude::extra_scopes(&issued.scopes, &claude.cfg.scopes);
    if !extra.is_empty() {
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::claude::PROVIDER, "reason": "scopes that were not asked for", "scopes": extra}),
            None,
        );
        return fail(
            StatusCode::BAD_GATEWAY,
            "Not connected",
            &format!(
                "claude.ai gave more permissions than were asked for ({}): warden does not keep that token.",
                extra.join(" ")
            ),
        );
    }
    let Some(refresh_token) = issued.refresh_token.clone() else {
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::claude::PROVIDER, "reason": "no refresh token"}),
            None,
        );
        return fail(
            StatusCode::BAD_GATEWAY,
            "Not connected",
            "claude.ai gave no refresh token: warden could not renew it.",
        );
    };
    let profile = claude.profile(&issued.access_token).await.unwrap_or_default();
    let email = profile.email.clone().or(issued.email.clone()).unwrap_or_default();
    let expected = claude.cfg.expected_email.trim();
    if !expected.is_empty() && !email.eq_ignore_ascii_case(expected) {
        tracing::warn!(account = %email, expected, "claude.ai was authorised by another account; token discarded");
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::claude::PROVIDER, "reason": "another account authorised the code", "account": email}),
            None,
        );
        return fail(
            StatusCode::FORBIDDEN,
            "Wrong account",
            &format!(
                "You authorized with the account “{email}”, which is not the expected one: warden has kept nothing. Sign in to claude.ai with the expected account and start again."
            ),
        );
    }
    let token = crate::claude::StoredToken {
        access_token: issued.access_token,
        refresh_token,
        scopes: issued.scopes.clone(),
        subscription_type: profile.subscription_type.clone(),
        rate_limit_tier: profile.rate_limit_tier.clone(),
    };
    let plain = match serde_json::to_vec(&token) {
        Ok(p) => p,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", &e.to_string()),
    };
    let at = now();
    let row = ConnectionRow {
        provider: crate::claude::PROVIDER.into(),
        account: if email.is_empty() { "?".into() } else { email.clone() },
        scopes: token.scopes.join(" "),
        sealed: app.sealer.seal(&plain, crate::claude::AAD),
        connected_at: at,
        expires_at: Some(at + issued.expires_in),
        refresh_expires_at: None,
        refreshed_at: None,
        broken: None,
    };
    if let Err(e) = app.store.put_connection(&row, &actor, at) {
        tracing::error!(error = %e, "store claude.ai connection");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not save the connection.");
    }
    tracing::info!(account = %row.account, subscription = ?token.subscription_type, "claude.ai connected");
    page(
        StatusCode::OK,
        pages::claude_connected(&row.account, &row.scopes, token.subscription_type.as_deref()),
    )
}

pub async fn connect_google(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if app.google.is_none() {
        return fail(StatusCode::NOT_FOUND, "Not available", "The Google connection is not enabled in this warden.");
    }
    start_oidc(&app, &headers, "google-connect", "", true).await
}

pub async fn disconnect_google(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    start_oidc(&app, &headers, "google-disconnect", "", true).await
}

const GOOGLE_CALLBACK: &str = "/connections/google/callback";

fn start_google(app: &App, headers: &HeaderMap, browser_hash: &str, sub: &str) -> Response {
    let Some(google) = &app.google else {
        return fail(StatusCode::NOT_FOUND, "Not available", "The Google connection is not enabled in this warden.");
    };
    let state = b64url(&random::<32>());
    let verifier = b64url(&random::<32>());
    let flow = Flow {
        kind: "google".into(),
        action: "connect".into(),
        target: sub.into(),
        nonce: String::new(),
        verifier: verifier.clone(),
        browser_hash: browser_hash.to_string(),
        created_at: now(),
    };
    if let Err(e) = app.store.put_flow(&state, &flow) {
        tracing::error!(error = %e, "cannot store a Google flow");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not start the connection.");
    }
    audit(
        app,
        &format!("owner:{sub}"),
        "connect.started",
        json!({"provider": crate::google::PROVIDER, "method": "pkce"}),
        None,
    );
    // The flow cookie binds the callback to this browser, so it must outlive the flow.
    let flow_cookie = cookie(headers, FLOW_COOKIE).map(|b| set_cookie(FLOW_COOKIE, &b, "Lax", FLOW_TTL));
    with_cookie(
        see_other(&google.authorize_url(&redirect_uri(app, GOOGLE_CALLBACK), &state, &verifier)),
        flow_cookie,
    )
}

/// The token is kept only if it is for this client, the expected account and the scopes asked for.
pub async fn google_callback(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<Callback>) -> Response {
    let Some(google) = &app.google else {
        return fail(StatusCode::NOT_FOUND, "Not available", "The Google connection is not enabled in this warden.");
    };
    let flow = match q.state.as_deref().map(|s| app.store.take_flow(s, "google", now())) {
        Some(Ok(Some(f))) => f,
        Some(Err(e)) => {
            tracing::error!(error = %e, "take Google flow");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not read the flow.");
        }
        _ => {
            return fail(
                StatusCode::BAD_REQUEST,
                "Expired",
                "This connection is no longer valid (it expired or was already used). Start again from the panel.",
            );
        }
    };
    let actor = format!("owner:{}", flow.target);
    let failed = |reason: &str, status: StatusCode, text: &str| {
        tracing::warn!(reason, "Google connection refused");
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::google::PROVIDER, "reason": reason}),
            None,
        );
        fail(status, "Not connected", text)
    };
    if !same_browser(&headers, &flow) {
        return failed(
            "the callback came to another browser than the one that started",
            StatusCode::BAD_REQUEST,
            "This did not come back to the browser that started it. Start again from the panel.",
        );
    }
    if let Some(err) = &q.error {
        let err: String = err.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect();
        audit(
            &app,
            &actor,
            "connect.cancelled",
            json!({"provider": crate::google::PROVIDER, "error": err}),
            None,
        );
        return page(
            StatusCode::OK,
            pages::message("Cancelled", "It was not authorized on Google; nothing has changed.", Kind::Info),
        );
    }
    let Some(code) = q.code.as_deref() else {
        return failed("no code", StatusCode::BAD_REQUEST, "The code from Google is missing.");
    };
    let issued = match google.exchange(code, &redirect_uri(&app, GOOGLE_CALLBACK), &flow.verifier).await {
        Ok(t) => t,
        Err(why) => {
            return failed(
                &why,
                StatusCode::BAD_GATEWAY,
                &format!("Google did not accept the code ({why}). Start again from the panel."),
            );
        }
    };
    let info = match google.token_info(&issued.access_token).await {
        Ok(i) => i,
        Err(why) => {
            return failed(
                &format!("tokeninfo: {why}"),
                StatusCode::BAD_GATEWAY,
                "Google did not say whose token it is: warden has kept nothing.",
            );
        }
    };
    if let Err(why) = google.accept(&info) {
        audit(
            &app,
            &actor,
            "connect.failed",
            json!({"provider": crate::google::PROVIDER, "reason": why, "account": info.email, "scopes": info.scopes}),
            None,
        );
        return fail(StatusCode::FORBIDDEN, "Not connected", &format!("{why}: warden has kept nothing."));
    }
    let Some(refresh_token) = issued.refresh_token.clone() else {
        return failed(
            "no refresh token",
            StatusCode::BAD_GATEWAY,
            "Google gave no refresh token: warden could not renew it. Remove “warden” from the apps with access to your Google account and start again.",
        );
    };
    let token = crate::google::StoredToken {
        access_token: issued.access_token,
        refresh_token,
        scopes: info.scopes.clone(),
    };
    let plain = match serde_json::to_vec(&token) {
        Ok(p) => p,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", &e.to_string()),
    };
    let at = now();
    let row = ConnectionRow {
        provider: crate::google::PROVIDER.into(),
        account: info.email.to_ascii_lowercase(),
        scopes: token.scopes.join(" "),
        sealed: app.sealer.seal(&plain, crate::google::AAD),
        connected_at: at,
        expires_at: Some(at + issued.expires_in),
        refresh_expires_at: None,
        refreshed_at: None,
        broken: None,
    };
    if let Err(e) = app.store.put_connection(&row, &actor, at) {
        tracing::error!(error = %e, "store Google connection");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Error", "Could not save the connection.");
    }
    tracing::info!(account = %row.account, "Google connected");
    page(StatusCode::OK, pages::google_connected(&row.account, &row.scopes))
}

/// The only script: the CSP allows just `script-src 'self'`.
pub async fn script() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("../static/warden.js")).into_response()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({"error": message}))).into_response()
}

fn json_refused(r: crate::webauthn::Refusal) -> Response {
    json_error(r.status, &r.message)
}

#[derive(Deserialize)]
pub struct CsrfJson {
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct WebAssertion {
    #[serde(default)]
    csrf: String,
    #[serde(flatten)]
    assertion: crate::webauthn::AssertionIn,
}

const NOT_OURS: &str = "This did not come from warden's page. Open the request again.";

pub async fn passkey_challenge(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: axum::body::Bytes) -> Response {
    let f: CsrfJson = serde_json::from_slice(&body).unwrap_or(CsrfJson { csrf: String::new() });
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return json_error(StatusCode::FORBIDDEN, NOT_OURS);
    }
    if !is_id(&id) {
        return json_error(StatusCode::NOT_FOUND, "That request does not exist.");
    }
    match crate::webauthn::issue_approve_challenge(&app, &id, crate::webauthn::Channel::Web) {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => json_refused(r),
    }
}

pub async fn passkey_approve(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: axum::body::Bytes) -> Response {
    let Ok(f) = serde_json::from_slice::<WebAssertion>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "The passkey's answer does not have the expected shape.");
    };
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return json_error(StatusCode::FORBIDDEN, NOT_OURS);
    }
    if !is_id(&id) {
        return json_error(StatusCode::NOT_FOUND, "That request does not exist.");
    }
    match crate::webauthn::approve_with_assertion(&app, &id, crate::webauthn::Channel::Web, &f.assertion) {
        Ok(g) => axum::Json(json!({"ok": true, "grant_id": g.id, "expires_at": g.expires_at})).into_response(),
        Err(r) => json_refused(r),
    }
}

pub async fn passkey_new(State(app): State<Arc<App>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if app.cfg.webauthn.is_none() {
        return fail(StatusCode::NOT_FOUND, "Not available", "The warden passkey is not enabled.");
    }
    start_oidc(&app, &headers, "passkey-add", "", true).await
}

pub async fn passkey_register(State(app): State<Arc<App>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let Ok(r) = serde_json::from_slice::<crate::webauthn::RegistrationIn>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "The browser's answer does not have the expected shape.");
    };
    if !csrf_ok(&headers, &r.csrf, &app.cfg.public_origin()) {
        return json_error(StatusCode::FORBIDDEN, NOT_OURS);
    }
    match crate::webauthn::register(&app, cookie(&headers, FLOW_COOKIE).as_deref(), &r) {
        Ok(p) => axum::Json(json!({"ok": true, "name": p.name})).into_response(),
        Err(r) => {
            if r.status != StatusCode::INTERNAL_SERVER_ERROR {
                tracing::warn!(reason = %r.reason, "passkey registration refused");
                app.audit_anonymous(Audit::new("web", "passkey.register_failed", json!({"reason": r.reason})), now());
            }
            json_refused(r)
        }
    }
}

pub async fn passkey_revoke(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&headers, &f.csrf, &app.cfg.public_origin()) {
        return fail(StatusCode::FORBIDDEN, "Not allowed", "This form did not come from warden's page.");
    }
    if !is_id(&id) {
        return fail(StatusCode::NOT_FOUND, "Not found", "That passkey does not exist.");
    }
    start_oidc(&app, &headers, "passkey-revoke", &id, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn a_post_needs_our_cookie_token_and_our_origin() {
        let tok = "a".repeat(43);
        let origin = "https://warden.example.com";
        let cookie = format!("{CSRF_COOKIE}={tok}");
        assert!(csrf_ok(&headers(&[("cookie", &cookie), ("origin", origin)]), &tok, origin));
        assert!(csrf_ok(
            &headers(&[("cookie", &cookie), ("referer", "https://warden.example.com/r/req_x")]),
            &tok,
            origin
        ));
        assert!(!csrf_ok(&headers(&[("cookie", &cookie), ("origin", origin)]), &"b".repeat(43), origin));
        assert!(!csrf_ok(&headers(&[("origin", origin)]), &tok, origin));
        assert!(!csrf_ok(
            &headers(&[("cookie", &cookie), ("origin", "https://heimdall.example.com")]),
            &tok,
            origin
        ));
        assert!(!csrf_ok(
            &headers(&[("cookie", &cookie), ("referer", "https://warden.example.com.evil.com/")]),
            &tok,
            origin
        ));
        assert!(!csrf_ok(&headers(&[("cookie", &cookie)]), &tok, origin));
        assert!(!csrf_ok(
            &headers(&[("cookie", &cookie), ("origin", "null"), ("referer", "https://warden.example.com/r/x")]),
            &tok,
            origin
        ));
        // Without the `__Host-` prefix, a sibling subdomain could have planted it.
        let tossed = format!("warden_csrf={tok}");
        assert!(!csrf_ok(&headers(&[("cookie", &tossed), ("origin", origin)]), &tok, origin));
        let short = format!("{CSRF_COOKIE}=abc");
        assert!(!csrf_ok(&headers(&[("cookie", &short), ("origin", origin)]), "abc", origin));
    }

    #[test]
    fn a_pasted_claude_code_is_its_code_and_its_state() {
        assert_eq!(split_pasted_code(" abc-DEF_1#st_9 \n"), Some(("abc-DEF_1".into(), Some("st_9".into()))));
        assert_eq!(split_pasted_code("abc"), Some(("abc".into(), None)));
        assert_eq!(split_pasted_code("abc#"), Some(("abc".into(), None)));
        assert_eq!(split_pasted_code("a b c"), Some(("abc".into(), None)), "a code split by the terminal");
        for bad in ["", "#st", "abc#st#x", "a/b", "a\"><script>", &"x".repeat(513)] {
            assert_eq!(split_pasted_code(bad), None, "{bad}");
        }
    }
}
