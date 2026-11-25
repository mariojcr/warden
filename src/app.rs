// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Service state and its two listeners: the browser one (approvals, connections, passkeys, the panel)
//! and the API one (sandbox sessions, the git and API proxies, heimdall). Plus the sweeper, which
//! records expiries and wakes whoever is waiting.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{any, delete, get, post};
use tokio::sync::watch;

use crate::budget::{SessionBudget, Take};
use crate::claude::Claude;
use crate::config::{Config, read_secret};
use crate::crypto::Sealer;
use crate::github::Github;
use crate::google::Google;
use crate::nomad::NomadIdentity;
use crate::oidc::Oidc;
use crate::store::Store;
use crate::{api, proxy, web};

/// Grants revoked while warden runs, used to cut in-flight proxy traffic (proxy.rs, `guard`). New
/// traffic is always authorized from the database; this only cuts.
pub struct Live {
    epoch: watch::Sender<u64>,
    revoked: Mutex<HashSet<String>>,
}

impl Live {
    fn new() -> Live {
        Live {
            epoch: watch::channel(0).0,
            revoked: Mutex::new(HashSet::new()),
        }
    }

    pub fn revoke(&self, grant_id: &str) {
        self.revoked.lock().unwrap_or_else(|p| p.into_inner()).insert(grant_id.to_string());
        self.epoch.send_modify(|e| *e += 1);
    }

    pub fn is_revoked(&self, grant_id: &str) -> bool {
        self.revoked.lock().unwrap_or_else(|p| p.into_inner()).contains(grant_id)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.epoch.subscribe()
    }
}

pub struct App {
    pub cfg: Config,
    pub store: Store,
    pub sealer: Sealer,
    pub oidc: Oidc,
    pub github: Github,
    pub nomad: Option<NomadIdentity>,
    /// Never follows redirects: the client gets them, so warden never follows one with the token attached.
    pub http: reqwest::Client,
    /// Bumped on every request or grant change; heimdall and sessions wait on it.
    pub changes: watch::Sender<u64>,
    pub live: Live,
    pub heimdall_token: Option<String>,
    /// Anonymous denials audited (and dropped) this minute: an unauthenticated peer must not be able to
    /// fill the disk with an append-only audit log.
    anonymous: Mutex<(i64, u32, u32)>,
    pub device: tokio::sync::Mutex<Option<web::Device>>,
    /// One renewal at a time: GitHub rotates the refresh token.
    pub github_renew: tokio::sync::Mutex<()>,
    pub claude: Option<Claude>,
    /// One renewal at a time: claude.ai rotates the refresh token too.
    pub claude_renew: tokio::sync::Mutex<()>,
    /// claude.ai token deliveries per session this hour (api.rs), so a session can't flood the audit.
    pub claude_deliveries: Mutex<std::collections::HashMap<String, (i64, u32)>>,
    /// When claude.ai last failed to answer a renewal. Retries wait `claude::RETRY_AFTER`, or every
    /// sandbox request would be another call.
    pub claude_failed_at: Mutex<Option<i64>>,
    pub google: Option<Google>,
    pub google_renew: tokio::sync::Mutex<()>,
    pub google_failed_at: Mutex<Option<i64>>,
    pub budget: SessionBudget,
}

/// Returned as is, without performing or auditing the action. Claude reads it, so it is English and
/// says what to do.
#[derive(Debug)]
pub struct OverBudget {
    pub status: axum::http::StatusCode,
    pub retry_after: Option<i64>,
    pub message: String,
}

impl OverBudget {
    pub fn stamp(&self, resp: &mut Response) {
        if let Some(s) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&s.max(1).to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
}

/// Anonymous denials audited per minute; the rest only go to the log, plus one row with their count.
pub const ANONYMOUS_AUDIT_PER_MINUTE: u32 = 30;

impl App {
    pub fn new(cfg: Config) -> anyhow::Result<Arc<App>> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| anyhow::anyhow!("cannot create the data dir {}: {e}", cfg.data_dir.display()))?;
        let master = crate::crypto::read_master_key(&cfg.master_key_file)?;
        let sealer = Sealer::from_key(&master)?;
        let store = Store::open(
            &cfg.data_dir.join("warden.sqlite"),
            crate::crypto::AuditKey::derive(&master)?,
            cfg.audit_legacy_head.as_deref(),
        )?;
        let oidc_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        let oidc = Oidc::new(cfg.oidc.clone(), oidc_http)?;
        let github = Github::new(cfg.github.clone())?;
        let claude = cfg.claude.clone().map(Claude::new).transpose()?;
        let google = match &cfg.gcp {
            Some(g) => Some(Google::new(g.clone(), read_secret(&g.client_secret_file, "the Google OAuth client secret")?)?),
            None => None,
        };
        let nomad = cfg.nomad.clone().map(NomadIdentity::new).transpose()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(120))
            .build()?;
        let heimdall_token = cfg.heimdall_token_file.as_deref().map(|p| read_secret(p, "the heimdall token")).transpose()?;
        if let Some(t) = &heimdall_token {
            anyhow::ensure!(t.len() >= 32, "the heimdall token is too short (32 characters at least)");
        }
        let limits = cfg.limits.clone();
        Ok(Arc::new(App {
            cfg,
            store,
            sealer,
            oidc,
            github,
            nomad,
            http,
            changes: watch::channel(0).0,
            live: Live::new(),
            heimdall_token,
            anonymous: Mutex::new((0, 0, 0)),
            device: tokio::sync::Mutex::new(None),
            github_renew: tokio::sync::Mutex::new(()),
            claude,
            claude_renew: tokio::sync::Mutex::new(()),
            claude_deliveries: Mutex::new(std::collections::HashMap::new()),
            claude_failed_at: Mutex::new(None),
            google,
            google_renew: tokio::sync::Mutex::new(()),
            google_failed_at: Mutex::new(None),
            budget: SessionBudget::new(limits.session_audit_per_minute, limits.session_audit_max),
        }))
    }

    /// Every audited session action (each proxied request; asking for, withdrawing or releasing a grant)
    /// goes through here first. On `Err` there is no room: answer without doing or auditing it.
    pub fn session_audit_slot(&self, session_id: &str, now: i64) -> Result<(), OverBudget> {
        let take = match self.budget.take(session_id, now, || self.store.session_audit_rows(session_id)) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "cannot count a session's audit lines");
                return Err(OverBudget {
                    status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    retry_after: None,
                    message: "warden: internal error".into(),
                });
            }
        };
        let line = |event: &str, detail: serde_json::Value| {
            let a = crate::store::Audit::new("system", event, detail).session(session_id);
            if let Err(e) = self.store.audit(a, now) {
                tracing::error!(error = %e, event, "cannot write an audit budget line");
            }
        };
        match take {
            Take::Go { throttled } => {
                if throttled > 0 {
                    line(
                        "audit.throttled",
                        serde_json::json!({"denied": throttled, "per_minute": self.budget.per_minute()}),
                    );
                }
                Ok(())
            }
            Take::Slow { retry_after, first } => {
                if first {
                    tracing::warn!(
                        session = session_id,
                        per_minute = self.budget.per_minute(),
                        "a session is over its per-minute audit budget; denying without audit lines"
                    );
                }
                Err(OverBudget {
                    status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                    retry_after: Some(retry_after),
                    message: format!(
                        "warden: this session did more than {} audited things in a minute (every request through warden leaves an audit line, and the audit log cannot be pruned); slow down and try again in {retry_after} s",
                        self.budget.per_minute()
                    ),
                })
            }
            Take::Spent { first } => {
                if first {
                    tracing::warn!(
                        session = session_id,
                        max = self.budget.per_session(),
                        "a session used up its audit budget; denying from now on"
                    );
                    line("audit.budget_exhausted", serde_json::json!({"limit": self.budget.per_session()}));
                }
                Err(OverBudget {
                    status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                    retry_after: None,
                    message: format!(
                        "warden: this session has used up its {} audited actions (the audit log cannot be pruned); open a new warden session to go on",
                        self.budget.per_session()
                    ),
                })
            }
        }
    }

    /// On a new minute, also records how many were dropped in the previous one.
    pub fn audit_anonymous(&self, a: crate::store::Audit, now: i64) {
        let minute = now / 60;
        let (write, dropped_before) = {
            let mut st = self.anonymous.lock().unwrap_or_else(|p| p.into_inner());
            let mut dropped_before = 0;
            if st.0 != minute {
                dropped_before = st.2;
                *st = (minute, 0, 0);
            }
            if st.1 < ANONYMOUS_AUDIT_PER_MINUTE {
                st.1 += 1;
                (true, dropped_before)
            } else {
                st.2 += 1;
                (false, dropped_before)
            }
        };
        if dropped_before > 0 {
            let summary = crate::store::Audit::new("system", "anonymous.dropped", serde_json::json!({"count": dropped_before}));
            if let Err(e) = self.store.audit(summary, now) {
                tracing::error!(error = %e, "cannot write the audit line of dropped anonymous denials");
            }
        }
        if write {
            if let Err(e) = self.store.audit(a, now) {
                tracing::error!(error = %e, "cannot write an anonymous audit line");
            }
        } else {
            tracing::warn!(event = %a.event, "anonymous denial over the per-minute audit budget; not written to the audit log");
        }
    }

    pub fn changed(&self) {
        self.changes.send_modify(|v| *v += 1);
    }

    pub fn api_router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok\n" }))
            .route("/api/sessions", post(api::create_session))
            .route("/api/requests", post(api::create_request))
            .route("/api/requests/{id}", get(api::get_request).delete(api::withdraw_request))
            .route("/api/grants", get(api::list_grants))
            .route("/api/grants/{id}", delete(api::release_grant))
            .route("/api/claude/token", post(api::claude_token))
            .route("/api/heimdall/state", get(api::heimdall_state))
            .route("/api/heimdall/requests/{id}/refuse", post(api::heimdall_refuse))
            .route("/api/heimdall/grants/{id}/revoke", post(api::heimdall_revoke))
            .route("/api/heimdall/requests/{id}/challenge", post(api::heimdall_challenge))
            .route("/api/heimdall/requests/{id}/approve", post(api::heimdall_approve))
            .route("/git/github.com/{*rest}", any(proxy::git))
            .route("/api/v3/{*rest}", any(proxy::api))
            .route("/registry/{*rest}", any(crate::registry::proxy))
            .with_state(self.clone())
    }

    pub fn browser_router(self: &Arc<Self>) -> Router {
        // Forms post to warden, which redirects to the OIDC provider (form-action covers the redirect). The
        // only script is /static/warden.js; nothing inline.
        let csp = format!(
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self' {}",
            origin_of(&self.cfg.oidc.issuer),
        );
        let csp = HeaderValue::from_str(&csp).unwrap_or(HeaderValue::from_static("default-src 'none'"));
        Router::new()
            .route("/", get(web::dashboard))
            .route("/health", get(|| async { "ok\n" }))
            .route("/login", get(web::login))
            .route("/logout", post(web::logout))
            .route("/r/{id}", get(web::request_page))
            .route("/r/{id}/approve", post(web::approve))
            .route("/r/{id}/refuse", post(web::refuse))
            .route("/g/{id}/revoke", post(web::revoke))
            .route("/connections/github", post(web::connect_github))
            .route("/connections/github/disconnect", post(web::disconnect_github))
            .route("/oidc/callback", get(web::oidc_callback))
            .route("/connections/github/device", get(web::device_page))
            .route("/connections/claude", post(web::connect_claude))
            .route("/connections/claude/code", post(web::claude_code))
            .route("/connections/claude/disconnect", post(web::disconnect_claude))
            .route("/connections/google", post(web::connect_google))
            .route("/connections/google/callback", get(web::google_callback))
            .route("/connections/google/disconnect", post(web::disconnect_google))
            .route("/static/warden.js", get(web::script))
            .route("/r/{id}/passkey/challenge", post(web::passkey_challenge))
            .route("/r/{id}/passkey/approve", post(web::passkey_approve))
            .route("/passkeys/new", post(web::passkey_new))
            .route("/passkeys/register", post(web::passkey_register))
            .route("/passkeys/{id}/revoke", post(web::passkey_revoke))
            .layer(axum::middleware::from_fn(move |req: Request, next: Next| {
                let csp = csp.clone();
                async move {
                    let mut resp: Response = next.run(req).await;
                    let h = resp.headers_mut();
                    h.insert(header::CONTENT_SECURITY_POLICY, csp);
                    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
                    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
                    // Request URLs are capabilities: keep them out of cross-site Referers. `same-origin` rather
                    // than `no-referrer`, because with `no-referrer` browsers send `Origin: null` on their own
                    // form POSTs and the CSRF check would reject them all.
                    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
                    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                    resp
                }
            }))
            .with_state(self.clone())
    }
}

pub fn origin_of(u: &str) -> String {
    url::Url::parse(u).map(|u| u.origin().ascii_serialization()).unwrap_or_default()
}

pub async fn sweeper(app: Arc<App>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        match app.store.sweep(crate::util::now()) {
            Ok(true) => app.changed(),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e, "sweep failed"),
        }
    }
}

async fn listen(addr: &str, router: Router, tls: Option<axum_server::tls_rustls::RustlsConfig>, what: &'static str) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = addr.parse().map_err(|e| anyhow::anyhow!("{what} listen address «{addr}»: {e}"))?;
    match tls {
        Some(tls) => {
            tracing::info!(%addr, what, "listening (https)");
            axum_server::bind_rustls(addr, tls).serve(router.into_make_service()).await?;
        }
        None => {
            tracing::info!(%addr, what, "listening (http)");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}

/// If either listener fails, warden exits (and Nomad restarts it).
pub async fn serve(app: Arc<App>) -> anyhow::Result<()> {
    let tls = match &app.cfg.tls {
        Some(t) => Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(&t.cert, &t.key).await?),
        None => None,
    };
    tokio::spawn(sweeper(app.clone()));
    let browser = listen(&app.cfg.browser_listen, app.browser_router(), tls.clone(), "browser");
    let api = listen(&app.cfg.api_listen, app.api_router(), tls, "api");
    tokio::try_join!(browser, api)?;
    Ok(())
}
