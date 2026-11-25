// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! The owner's claude.ai session: warden keeps the refresh token and sandboxes only ever get a
//! short-lived access token. The OAuth values mirror Claude Code 2.1.311's paste-the-code `/login`.
//!
//! The refresh token rotates on every renewal, so two renewals with the same one would kill the
//! connection: only warden renews, one at a time, deciding inside the lock on a freshly read row.
//! A handed-out access token cannot be revoked on its own, so it stays valid until it expires.
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::config::ClaudeConfig;
use crate::connection::TokenError;
use crate::store::{Audit, ConnectionRow, Renewed};
use crate::util::now;

/// Claude Code's public OAuth client.
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// The subscription login used by `claude auth login --claudeai` in 2.1.311.
pub const AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
/// Shows the code to copy, as in Claude Code's manual `/login`.
pub const REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
/// Claude Code's scopes minus `org:create_api_key`, which would let a sandbox mint a lasting API key
/// warden cannot control. Remote Control needs `user:profile` too (`token_scope_limited` without it).
pub const SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
    "user:plugins",
];
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const USER_AGENT: &str = "claude-cli/2.1.311 (external, cli)";
/// Required on calls made with a subscription token.
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Binds the sealed token to this use (crypto.rs), so it cannot be opened as anything else.
pub const AAD: &str = "warden/connection/claude";
pub const PROVIDER: &str = "claude";
pub const SYSTEM: &str = "claude";
pub const POWER: &str = "claude_session";

/// Also the shortest life left on a handed-out token.
pub const RENEW_MARGIN: i64 = 1800;
/// After a renewal claude.ai did not answer.
pub const RETRY_AFTER: i64 = 60;
const DEFAULT_EXPIRES_IN: i64 = 8 * 3600;

/// No `Debug`: it holds the tokens.
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    /// «max», «pro»…: what Claude Code writes as `subscriptionType`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_tier: Option<String>,
}

/// No `Debug`: it holds the tokens.
pub struct Issued {
    pub access_token: String,
    /// None on renewal means it did not rotate.
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub expires_in: i64,
    pub email: Option<String>,
}

pub enum Refreshed {
    Token(Issued),
    /// An OAuth error: the connection has to be connected again.
    Rejected(String),
    /// Unknown whether the refresh token was spent; if it was, the next attempt gets `invalid_grant`.
    Unreachable(String),
}

/// A token with scopes that were not asked for is neither stored nor handed out.
pub fn extra_scopes(issued: &[String], asked: &[String]) -> Vec<String> {
    issued.iter().filter(|s| !asked.contains(s)).cloned().collect()
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Profile {
    pub email: Option<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

fn scopes_of(v: &Value) -> Vec<String> {
    v["scope"].as_str().unwrap_or("").split_whitespace().map(String::from).collect()
}

fn issued(v: &Value) -> Option<Issued> {
    let access = v["access_token"].as_str().filter(|t| !t.is_empty())?;
    Some(Issued {
        access_token: access.to_string(),
        refresh_token: v["refresh_token"].as_str().filter(|t| !t.is_empty()).map(String::from),
        scopes: scopes_of(v),
        // At least ten minutes, or an `expires_in` of 0 would renew on every request.
        expires_in: v["expires_in"].as_i64().unwrap_or(DEFAULT_EXPIRES_IN).max(600),
        email: v["account"]["email_address"].as_str().map(String::from),
    })
}

/// Same names as Claude Code.
pub fn subscription_of(org_type: &str) -> Option<String> {
    match org_type {
        "claude_max" => Some("max".into()),
        "claude_pro" => Some("pro".into()),
        "claude_enterprise" => Some("enterprise".into()),
        "claude_team" => Some("team".into()),
        _ => None,
    }
}

/// Trimmed and without `secrets`: it goes to the audit log and the logs.
fn said(v: &Value, status: reqwest::StatusCode, secrets: &[&str]) -> String {
    let mut s = match (v["error"].as_str(), v["error_description"].as_str()) {
        (Some(e), Some(d)) => format!("{e}: {d}"),
        (Some(e), None) => e.to_string(),
        _ => format!("claude.ai answered HTTP {status} without a token"),
    };
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        s = s.replace(secret, "…");
    }
    let s: String = s.chars().filter(|c| !c.is_control()).take(300).collect();
    if s.is_empty() { "claude.ai refused".into() } else { s }
}

/// Only an OAuth error proves the refresh token is bad; an error page from a proxy in front does not.
fn oauth_error(v: &Value) -> bool {
    v["error"].as_str().is_some_and(|e| !e.is_empty())
}

pub struct Claude {
    pub cfg: ClaudeConfig,
    http: reqwest::Client,
}

impl Claude {
    pub fn new(cfg: ClaudeConfig) -> anyhow::Result<Claude> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Claude { cfg, http })
    }

    pub fn authorize_url(&self, state: &str, verifier: &str) -> String {
        let mut u = url::Url::parse(&self.cfg.authorize_url).expect("checked in Config::check");
        u.query_pairs_mut()
            .append_pair("code", "true")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.cfg.redirect_uri)
            .append_pair("scope", &self.cfg.scopes.join(" "))
            .append_pair("code_challenge", &crate::oidc::challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state);
        u.to_string()
    }

    async fn post_token(&self, body: Value) -> Result<(reqwest::StatusCode, Option<Value>), String> {
        let resp = self
            .http
            .post(&self.cfg.token_url)
            .header(reqwest::header::USER_AGENT, &self.cfg.user_agent)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let status = resp.status();
        Ok((status, resp.json::<Value>().await.ok()))
    }

    pub async fn exchange(&self, code: &str, state: &str, verifier: &str) -> Result<Issued, String> {
        let body = json!({"grant_type": "authorization_code", "code": code, "state": state, "client_id": self.cfg.client_id,
                          "redirect_uri": self.cfg.redirect_uri, "code_verifier": verifier});
        let (status, v) = self.post_token(body).await?;
        let v = v.unwrap_or(Value::Null);
        if status.is_success()
            && let Some(t) = issued(&v)
        {
            return Ok(t);
        }
        Err(said(&v, status, &[code, verifier]))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Refreshed {
        if refresh_token.is_empty() {
            return Refreshed::Rejected("there is no refresh token".into());
        }
        let body = json!({"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.cfg.client_id,
                          "scope": self.cfg.scopes.join(" ")});
        let (status, v) = match self.post_token(body).await {
            Ok(r) => r,
            Err(e) => return Refreshed::Unreachable(e),
        };
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Refreshed::Unreachable(format!("claude.ai answered HTTP {status}"));
        }
        match v {
            Some(v) if status.is_success() => match issued(&v) {
                Some(t) => Refreshed::Token(t),
                None => Refreshed::Unreachable(format!("claude.ai answered HTTP {status} without a token")),
            },
            Some(v) if oauth_error(&v) => Refreshed::Rejected(said(&v, status, &[refresh_token])),
            _ => Refreshed::Unreachable(format!("claude.ai answered HTTP {status} without an OAuth error")),
        }
    }

    /// Optional: Claude Code fetches it itself when the subscription type is missing.
    pub async fn profile(&self, access_token: &str) -> Option<Profile> {
        let resp = self
            .http
            .get(&self.cfg.profile_url)
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, &self.cfg.user_agent)
            .header("anthropic-beta", OAUTH_BETA)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: Value = resp.json().await.ok()?;
        let s = |x: &Value| x.as_str().filter(|s| !s.is_empty()).map(String::from);
        Some(Profile {
            email: s(&v["account"]["email"]).or_else(|| s(&v["account"]["email_address"])),
            subscription_type: v["organization"]["organization_type"].as_str().and_then(subscription_of),
            rate_limit_tier: s(&v["organization"]["rate_limit_tier"]),
        })
    }
}

/// No `Debug`: it holds the token.
pub struct Current {
    pub access_token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

/// No `Debug`: it holds the tokens.
struct Open {
    row: ConnectionRow,
    token: StoredToken,
}

impl Open {
    fn current(&self) -> Current {
        Current {
            access_token: self.token.access_token.clone(),
            expires_at: self.row.expires_at.unwrap_or(0),
            scopes: self.token.scopes.clone(),
            subscription_type: self.token.subscription_type.clone(),
            rate_limit_tier: self.token.rate_limit_tier.clone(),
        }
    }

    /// Half the lifetime caps the margin, so very short tokens are not renewed on every request.
    fn needs_renewal(&self, at: i64) -> bool {
        let Some(exp) = self.row.expires_at else {
            return true;
        };
        let since = self.row.refreshed_at.unwrap_or(self.row.connected_at);
        let margin = RENEW_MARGIN.min((exp - since).max(0) / 2);
        exp - at <= margin
    }
}

impl App {
    fn claude_open(&self) -> Result<Option<Open>, TokenError> {
        let Some(row) = self.store.connection(PROVIDER)? else {
            return Ok(None);
        };
        let plain = self.sealer.open(&row.sealed, AAD)?;
        let token: StoredToken = serde_json::from_slice(&plain).map_err(anyhow::Error::from)?;
        Ok(Some(Open { row, token }))
    }

    /// For when the row changed during a renewal: whatever is there now wins.
    fn claude_as_is(&self) -> Result<Option<Current>, TokenError> {
        match self.claude_open()? {
            None => Ok(None),
            Some(o) => match &o.row.broken {
                Some((_, why)) => Err(TokenError::Reconnect(why.clone())),
                None => Ok(Some(o.current())),
            },
        }
    }

    /// The caller has already checked the grant; `session` is only for the renewal's audit line.
    pub async fn claude_token(self: &Arc<Self>, session: &str) -> Result<Option<Current>, TokenError> {
        match self.claude_open()? {
            None => return Ok(None),
            Some(o) => {
                if let Some((_, why)) = &o.row.broken {
                    return Err(TokenError::Reconnect(why.clone()));
                }
                if !o.needs_renewal(now()) {
                    return Ok(Some(o.current()));
                }
            }
        }
        // Spawned so a client disconnect cannot cancel it: claude.ai would have spent the refresh token
        // with nobody storing the new one.
        let app = self.clone();
        let session = session.to_string();
        match tokio::spawn(async move { app.claude_renew(&session).await }).await {
            Ok(r) => r,
            Err(e) => Err(TokenError::Internal(anyhow::anyhow!("the renewal task failed: {e}"))),
        }
    }

    /// One at a time, deciding again on the current row.
    async fn claude_renew(&self, session: &str) -> Result<Option<Current>, TokenError> {
        let Some(claude) = &self.claude else {
            return Ok(None);
        };
        let _one = self.claude_renew.lock().await;
        let Some(o) = self.claude_open()? else {
            return Ok(None);
        };
        if let Some((_, why)) = &o.row.broken {
            return Err(TokenError::Reconnect(why.clone()));
        }
        if !o.needs_renewal(now()) {
            return Ok(Some(o.current()));
        }
        // claude.ai just failed to answer: serve the current token while it lasts instead of retrying.
        let failed = *self.claude_failed_at.lock().unwrap_or_else(|p| p.into_inner());
        if failed.is_some_and(|at| now() - at < RETRY_AFTER) {
            if o.row.expires_at.is_some_and(|e| e - now() > 60) {
                return Ok(Some(o.current()));
            }
            return Err(TokenError::Unavailable(
                "claude.ai did not answer the last renewal; trying again in a minute".into(),
            ));
        }
        let actor = format!("session:{session}");
        let line = |event: &str, detail: Value| Audit::new(actor.clone(), event, detail).session(session);
        let refreshed = claude.refresh(&o.token.refresh_token).await;
        *self.claude_failed_at.lock().unwrap_or_else(|p| p.into_inner()) = matches!(refreshed, Refreshed::Unreachable(_)).then(now);
        let refreshed = match refreshed {
            Refreshed::Token(t) if !extra_scopes(&t.scopes, &claude.cfg.scopes).is_empty() => Refreshed::Rejected(format!(
                "claude.ai gave scopes that were not asked for: {}",
                extra_scopes(&t.scopes, &claude.cfg.scopes).join(" ")
            )),
            other => other,
        };
        match refreshed {
            Refreshed::Token(issued) => {
                let at = now();
                let token = StoredToken {
                    access_token: issued.access_token,
                    refresh_token: issued.refresh_token.unwrap_or_else(|| o.token.refresh_token.clone()),
                    scopes: if issued.scopes.is_empty() { o.token.scopes.clone() } else { issued.scopes },
                    subscription_type: o.token.subscription_type.clone(),
                    rate_limit_tier: o.token.rate_limit_tier.clone(),
                };
                let renewed = Renewed {
                    sealed: self.sealer.seal(&serde_json::to_vec(&token).map_err(anyhow::Error::from)?, AAD),
                    scopes: token.scopes.join(" "),
                    expires_at: Some(at + issued.expires_in),
                    refresh_expires_at: None,
                };
                let detail = json!({"provider": PROVIDER, "account": o.row.account, "expires_at": renewed.expires_at,
                                    "rotated": token.refresh_token != o.token.refresh_token});
                if self
                    .store
                    .renew_connection(PROVIDER, &o.row.sealed, &renewed, line("connection.refreshed", detail), at)?
                {
                    tracing::info!(account = %o.row.account, expires_at = ?renewed.expires_at, "claude.ai token renewed");
                    let row = ConnectionRow {
                        expires_at: renewed.expires_at,
                        refreshed_at: Some(at),
                        ..o.row
                    };
                    Ok(Some(Open { row, token }.current()))
                } else {
                    tracing::warn!("the claude.ai connection changed while its token was being renewed; the renewed token is discarded");
                    self.claude_as_is()
                }
            }
            Refreshed::Rejected(why) => {
                let detail = json!({"provider": PROVIDER, "account": o.row.account, "reason": why, "reconnect": true});
                if self
                    .store
                    .break_connection(PROVIDER, &o.row.sealed, &why, line("connection.refresh_failed", detail), now())?
                {
                    tracing::error!(account = %o.row.account, reason = %why, "claude.ai refused to renew the token: the connection has to be connected again");
                    return Err(TokenError::Reconnect(why));
                }
                // Reconnected meanwhile: the rejected refresh token was the old one.
                self.claude_as_is()
            }
            Refreshed::Unreachable(why) => {
                tracing::warn!(account = %o.row.account, reason = %why, "claude.ai did not answer the token renewal; the next request tries again");
                let detail = json!({"provider": PROVIDER, "account": o.row.account, "reason": why, "reconnect": false});
                if let Err(e) = self.store.audit(line("connection.refresh_failed", detail), now()) {
                    tracing::error!(error = %e, "cannot write the audit line of a failed renewal");
                }
                if o.row.expires_at.is_some_and(|e| e - now() > 60) {
                    return Ok(Some(o.current()));
                }
                Err(TokenError::Unavailable(why))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_answer_is_read_without_trusting_its_shape() {
        let t = issued(
            &json!({"access_token": "a", "refresh_token": "r", "expires_in": 28800, "scope": "user:inference user:profile",
                               "account": {"email_address": "m@example.com"}}),
        )
        .unwrap();
        assert_eq!((t.access_token.as_str(), t.refresh_token.as_deref(), t.expires_in), ("a", Some("r"), 28800));
        assert_eq!(t.scopes, vec!["user:inference", "user:profile"]);
        assert_eq!(t.email.as_deref(), Some("m@example.com"));
        assert!(issued(&json!({"access_token": ""})).is_none());
        assert!(issued(&json!({"error": "invalid_grant"})).is_none());
        let t = issued(&json!({"access_token": "a", "expires_in": 0})).unwrap();
        assert_eq!((t.refresh_token, t.expires_in), (None, 600));
    }

    #[test]
    fn what_claude_ai_says_never_carries_a_secret() {
        let v = json!({"error": "invalid_grant", "error_description": "refresh token sk-ant-ort01-XYZ is not valid\n"});
        let s = said(&v, reqwest::StatusCode::BAD_REQUEST, &["sk-ant-ort01-XYZ"]);
        assert_eq!(s, "invalid_grant: refresh token … is not valid");
        assert!(oauth_error(&v));
        assert!(!oauth_error(&json!({"message": "blocked"})));
    }

    #[test]
    fn subscription_names_are_claude_codes() {
        assert_eq!(subscription_of("claude_max").as_deref(), Some("max"));
        assert_eq!(subscription_of("claude_pro").as_deref(), Some("pro"));
        assert_eq!(subscription_of("api"), None);
    }

    #[test]
    fn a_token_is_renewed_with_margin_and_never_on_every_request() {
        let row = |connected: i64, exp: Option<i64>| ConnectionRow {
            provider: PROVIDER.into(),
            account: "m".into(),
            scopes: String::new(),
            sealed: vec![],
            connected_at: connected,
            expires_at: exp,
            refresh_expires_at: None,
            refreshed_at: None,
            broken: None,
        };
        let open = |connected: i64, exp: Option<i64>| Open {
            row: row(connected, exp),
            token: StoredToken {
                access_token: "a".into(),
                refresh_token: "r".into(),
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
            },
        };
        assert!(!open(0, Some(28_800)).needs_renewal(28_800 - RENEW_MARGIN - 1));
        assert!(open(0, Some(28_800)).needs_renewal(28_800 - RENEW_MARGIN));
        // A 20-minute token renews at half its life, not on every request.
        assert!(!open(0, Some(1200)).needs_renewal(500));
        assert!(open(0, Some(1200)).needs_renewal(600));
        assert!(open(0, None).needs_renewal(1));
    }
}
