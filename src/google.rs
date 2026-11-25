// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! The owner's Google connection, used to read Artifact Registry and GCS for sandboxes (registry.rs).
//! No sandbox ever sees a Google token: warden proxies.
//!
//! A user account rather than a service account: SA keys are not allowed, and minting SA tokens needs
//! the `iam` scope, with which a stolen refresh token could impersonate any SA the owner can. With only
//! `devstorage.read_only`, a stolen refresh token can at worst read GCS and Artifact Registry.
//!
//! `access_type=offline` and `prompt=consent` make Google issue a refresh token, and
//! `include_granted_scopes=false` keeps earlier grants out. `tokeninfo` must confirm the client, the
//! account and exactly the requested scopes, since granular consent lets the user untick the read one.
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::config::GcpConfig;
use crate::connection::TokenError;
use crate::store::{Audit, ConnectionRow, Renewed};
use crate::util::now;

pub const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";
pub const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
/// Not `cloud-platform` nor `cloud-platform.read-only`: those read all of GCP. Artifact Registry
/// accepts this one as it does for Container Registry.
pub const READ_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
/// The read scope plus just enough to identify the account.
pub const SCOPES: &[&str] = &["openid", "https://www.googleapis.com/auth/userinfo.email", READ_SCOPE];

pub const AAD: &str = "warden/connection/google";
pub const PROVIDER: &str = "google";
pub const SYSTEM: &str = "gcp";

pub const RENEW_MARGIN: i64 = 600;
/// After a renewal Google didn't answer, wait this long before trying another.
pub const RETRY_AFTER: i64 = 60;
const DEFAULT_EXPIRES_IN: i64 = 3600;

/// Deliberately not `Debug`: it holds the tokens.
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
}

pub struct Issued {
    pub access_token: String,
    /// Google usually omits it on refresh, and the old one stays valid.
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub expires_in: i64,
}

pub enum Refreshed {
    Token(Issued),
    /// An OAuth error: the connection must be made again.
    Rejected(String),
    /// No answer, a 5xx, a 429 or a non-OAuth error: the next request retries.
    Unreachable(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenInfo {
    /// `aud`, or `azp` if missing.
    pub client: String,
    pub email: String,
    pub email_verified: bool,
    pub scopes: Vec<String>,
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
        // Never under five minutes: an `expires_in` of 0 would renew on every request.
        expires_in: v["expires_in"].as_i64().unwrap_or(DEFAULT_EXPIRES_IN).max(300),
    })
}

/// Granted but not requested (Google adds earlier grants under `include_granted_scopes`); such a
/// token is neither stored nor used.
pub fn extra_scopes(issued: &[String], asked: &[String]) -> Vec<String> {
    issued.iter().filter(|s| !asked.contains(s)).cloned().collect()
}

/// Trimmed and scrubbed of `secrets`: it goes to the audit and the log.
fn said(v: &Value, status: reqwest::StatusCode, secrets: &[&str]) -> String {
    let mut s = match (v["error"].as_str(), v["error_description"].as_str()) {
        (Some(e), Some(d)) => format!("{e}: {d}"),
        (Some(e), None) => e.to_string(),
        _ => format!("Google answered HTTP {status} without a token"),
    };
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        s = s.replace(secret, "…");
    }
    let s: String = s.chars().filter(|c| !c.is_control()).take(300).collect();
    if s.is_empty() { "Google refused".into() } else { s }
}

fn oauth_error(v: &Value) -> bool {
    v["error"].as_str().is_some_and(|e| !e.is_empty())
}

fn token_info(v: &Value) -> Option<TokenInfo> {
    let client = v["aud"].as_str().or_else(|| v["azp"].as_str()).filter(|s| !s.is_empty())?;
    Some(TokenInfo {
        client: client.to_string(),
        email: v["email"].as_str().unwrap_or("").to_string(),
        // tokeninfo returns it as a string.
        email_verified: v["email_verified"] == json!(true) || v["email_verified"] == json!("true"),
        scopes: scopes_of(v),
    })
}

pub struct Google {
    pub cfg: GcpConfig,
    client_secret: String,
    http: reqwest::Client,
}

impl Google {
    pub fn new(cfg: GcpConfig, client_secret: String) -> anyhow::Result<Google> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Google { cfg, client_secret, http })
    }

    pub fn scopes(&self) -> Vec<String> {
        self.cfg.scopes.clone()
    }

    /// `hd` limits the account picker to the expected email's domain.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, verifier: &str) -> String {
        let mut u = url::Url::parse(&self.cfg.authorize_url).expect("checked in Config::check");
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &self.cfg.scopes.join(" "))
                .append_pair("access_type", "offline")
                .append_pair("prompt", "consent")
                .append_pair("include_granted_scopes", "false")
                .append_pair("code_challenge", &crate::oidc::challenge(verifier))
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", state)
                .append_pair("login_hint", &self.cfg.expected_email);
            if let Some((_, domain)) = self.cfg.expected_email.rsplit_once('@') {
                q.append_pair("hd", domain);
            }
        }
        u.to_string()
    }

    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<(reqwest::StatusCode, Option<Value>), String> {
        let resp = self
            .http
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let status = resp.status();
        Ok((status, resp.json::<Value>().await.ok()))
    }

    pub async fn exchange(&self, code: &str, redirect_uri: &str, verifier: &str) -> Result<Issued, String> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.cfg.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        let (status, v) = self.post_form(&self.cfg.token_url, &form).await?;
        let v = v.unwrap_or(Value::Null);
        if status.is_success()
            && let Some(t) = issued(&v)
        {
            return Ok(t);
        }
        Err(said(&v, status, &[code, verifier, &self.client_secret]))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Refreshed {
        if refresh_token.is_empty() {
            return Refreshed::Rejected("there is no refresh token".into());
        }
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.cfg.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        let (status, v) = match self.post_form(&self.cfg.token_url, &form).await {
            Ok(r) => r,
            Err(e) => return Refreshed::Unreachable(e),
        };
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Refreshed::Unreachable(format!("Google answered HTTP {status}"));
        }
        match v {
            Some(v) if status.is_success() => match issued(&v) {
                Some(t) => Refreshed::Token(t),
                None => Refreshed::Unreachable(format!("Google answered HTTP {status} without a token")),
            },
            Some(v) if oauth_error(&v) => Refreshed::Rejected(said(&v, status, &[refresh_token, &self.client_secret])),
            _ => Refreshed::Unreachable(format!("Google answered HTTP {status} without an OAuth error")),
        }
    }

    pub async fn token_info(&self, access_token: &str) -> Result<TokenInfo, String> {
        let (status, v) = self.post_form(&self.cfg.tokeninfo_url, &[("access_token", access_token)]).await?;
        let v = v.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(said(&v, status, &[access_token]));
        }
        token_info(&v).ok_or_else(|| "Google's tokeninfo answer has no audience".to_string())
    }

    /// Best effort: by the time this runs the token is already gone from warden.
    pub async fn revoke(&self, refresh_token: &str) -> Result<(), String> {
        let (status, v) = self.post_form(&self.cfg.revoke_url, &[("token", refresh_token)]).await?;
        if status.is_success() {
            return Ok(());
        }
        Err(said(&v.unwrap_or(Value::Null), status, &[refresh_token]))
    }

    /// Errors are shown to the owner as is.
    pub fn accept(&self, info: &TokenInfo) -> Result<(), String> {
        if info.client != self.cfg.client_id {
            return Err("the token is for another OAuth client".into());
        }
        if !info.email_verified || !info.email.eq_ignore_ascii_case(self.cfg.expected_email.trim()) {
            return Err(format!(
                "you authorized with the account “{}”, which is not the expected one ({})",
                info.email, self.cfg.expected_email
            ));
        }
        if !info.scopes.iter().any(|s| s == READ_SCOPE) {
            return Err("the permission to read Artifact Registry (devstorage.read_only) is missing: tick it when you authorize".into());
        }
        let extra = extra_scopes(&info.scopes, &self.cfg.scopes);
        if !extra.is_empty() {
            return Err(format!("Google gave more permissions than were asked for ({})", extra.join(" ")));
        }
        Ok(())
    }
}

/// Deliberately not `Debug`: it holds the tokens.
struct Open {
    row: ConnectionRow,
    token: StoredToken,
}

impl Open {
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
    fn google_open(&self) -> Result<Option<Open>, TokenError> {
        let Some(row) = self.store.connection(PROVIDER)? else {
            return Ok(None);
        };
        let plain = self.sealer.open(&row.sealed, AAD)?;
        let token: StoredToken = serde_json::from_slice(&plain).map_err(anyhow::Error::from)?;
        Ok(Some(Open { row, token }))
    }

    fn google_as_is(&self) -> Result<Option<String>, TokenError> {
        match self.google_open()? {
            None => Ok(None),
            Some(o) => match &o.row.broken {
                Some((_, why)) => Err(TokenError::Reconnect(why.clone())),
                None => Ok(Some(o.token.access_token)),
            },
        }
    }

    pub fn google_refresh_token(&self) -> Option<String> {
        self.google_open().ok().flatten().map(|o| o.token.refresh_token)
    }

    /// The caller must already have checked the grant; `session` is for the renewal's audit line.
    pub async fn google_token(self: &Arc<Self>, session: &str) -> Result<Option<String>, TokenError> {
        match self.google_open()? {
            None => return Ok(None),
            Some(o) => {
                if let Some((_, why)) = &o.row.broken {
                    return Err(TokenError::Reconnect(why.clone()));
                }
                if !o.needs_renewal(now()) {
                    return Ok(Some(o.token.access_token));
                }
            }
        }
        // In its own task, so a client hanging up midway doesn't cut the renewal.
        let app = self.clone();
        let session = session.to_string();
        match tokio::spawn(async move { app.google_renew(&session).await }).await {
            Ok(r) => r,
            Err(e) => Err(TokenError::Internal(anyhow::anyhow!("the renewal task failed: {e}"))),
        }
    }

    async fn google_renew(&self, session: &str) -> Result<Option<String>, TokenError> {
        let Some(google) = &self.google else {
            return Ok(None);
        };
        let _one = self.google_renew.lock().await;
        let Some(o) = self.google_open()? else {
            return Ok(None);
        };
        if let Some((_, why)) = &o.row.broken {
            return Err(TokenError::Reconnect(why.clone()));
        }
        if !o.needs_renewal(now()) {
            return Ok(Some(o.token.access_token));
        }
        let failed = *self.google_failed_at.lock().unwrap_or_else(|p| p.into_inner());
        if failed.is_some_and(|at| now() - at < RETRY_AFTER) {
            if o.row.expires_at.is_some_and(|e| e - now() > 60) {
                return Ok(Some(o.token.access_token));
            }
            return Err(TokenError::Unavailable(
                "Google did not answer the last renewal; trying again in a minute".into(),
            ));
        }
        let actor = format!("session:{session}");
        let line = |event: &str, detail: Value| Audit::new(actor.clone(), event, detail).session(session);
        let refreshed = google.refresh(&o.token.refresh_token).await;
        *self.google_failed_at.lock().unwrap_or_else(|p| p.into_inner()) = matches!(refreshed, Refreshed::Unreachable(_)).then(now);
        let asked = google.scopes();
        let refreshed = match refreshed {
            Refreshed::Token(t) if !extra_scopes(&t.scopes, &asked).is_empty() => Refreshed::Rejected(format!(
                "Google gave scopes that were not asked for: {}",
                extra_scopes(&t.scopes, &asked).join(" ")
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
                    tracing::info!(account = %o.row.account, expires_at = ?renewed.expires_at, "Google token renewed");
                    Ok(Some(token.access_token))
                } else {
                    tracing::warn!("the Google connection changed while its token was being renewed; the renewed token is discarded");
                    self.google_as_is()
                }
            }
            Refreshed::Rejected(why) => {
                let detail = json!({"provider": PROVIDER, "account": o.row.account, "reason": why, "reconnect": true});
                if self
                    .store
                    .break_connection(PROVIDER, &o.row.sealed, &why, line("connection.refresh_failed", detail), now())?
                {
                    tracing::error!(account = %o.row.account, reason = %why, "Google refused to renew the token: the connection has to be connected again");
                    return Err(TokenError::Reconnect(why));
                }
                self.google_as_is()
            }
            Refreshed::Unreachable(why) => {
                tracing::warn!(account = %o.row.account, reason = %why, "Google did not answer the token renewal; the next request tries again");
                let detail = json!({"provider": PROVIDER, "account": o.row.account, "reason": why, "reconnect": false});
                if let Err(e) = self.store.audit(line("connection.refresh_failed", detail), now()) {
                    tracing::error!(error = %e, "cannot write the audit line of a failed renewal");
                }
                if o.row.expires_at.is_some_and(|e| e - now() > 60) {
                    return Ok(Some(o.token.access_token));
                }
                Err(TokenError::Unavailable(why))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google(email: &str) -> Google {
        let cfg: GcpConfig = serde_json::from_value(json!({
            "client_id": "cid.apps.googleusercontent.com",
            "client_secret_file": "/s",
            "expected_email": email,
            "presets": {}
        }))
        .unwrap();
        Google::new(cfg, "shh".into()).unwrap()
    }

    #[test]
    fn the_authorize_link_asks_offline_and_only_the_read_scope() {
        let u = url::Url::parse(&google("m@example.com").authorize_url("https://w.example/connections/google/callback", "st", "ver")).unwrap();
        let q: std::collections::HashMap<String, String> = u.query_pairs().into_owned().collect();
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["include_granted_scopes"], "false");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["hd"], "example.com");
        assert_eq!(q["login_hint"], "m@example.com");
        let scopes: Vec<&str> = q["scope"].split(' ').collect();
        assert!(scopes.contains(&READ_SCOPE));
        assert!(!scopes.iter().any(|s| s.contains("cloud-platform") || s.ends_with("/iam")), "{scopes:?}");
    }

    #[test]
    fn only_a_token_of_this_client_this_account_and_the_asked_scopes_is_kept() {
        let g = google("m@example.com");
        let ok = TokenInfo {
            client: "cid.apps.googleusercontent.com".into(),
            email: "M@example.com".into(),
            email_verified: true,
            scopes: SCOPES.iter().map(|s| s.to_string()).collect(),
        };
        assert_eq!(g.accept(&ok), Ok(()));
        assert!(
            g.accept(&TokenInfo {
                client: "other".into(),
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            g.accept(&TokenInfo {
                email: "x@example.com".into(),
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            g.accept(&TokenInfo {
                email_verified: false,
                ..ok.clone()
            })
            .is_err()
        );
        // The read scope unticked under granular consent.
        assert!(
            g.accept(&TokenInfo {
                scopes: vec!["openid".into()],
                ..ok.clone()
            })
            .is_err()
        );
        // Google added a scope the account had granted before.
        let mut more = ok.scopes.clone();
        more.push("https://www.googleapis.com/auth/cloud-platform".into());
        assert!(g.accept(&TokenInfo { scopes: more, ..ok }).is_err());
    }

    #[test]
    fn tokeninfo_and_token_answers_are_read_without_trusting_their_shape() {
        let i = token_info(&json!({"aud": "cid", "email": "m@example.com", "email_verified": "true", "scope": "openid a b"})).unwrap();
        assert_eq!((i.client.as_str(), i.email_verified, i.scopes.len()), ("cid", true, 3));
        assert!(token_info(&json!({"email": "m@example.com"})).is_none());
        let t = issued(&json!({"access_token": "a", "expires_in": 0})).unwrap();
        assert_eq!((t.refresh_token, t.expires_in), (None, 300));
        assert!(issued(&json!({"error": "invalid_grant"})).is_none());
    }

    #[test]
    fn what_google_says_never_carries_a_secret() {
        let v = json!({"error": "invalid_grant", "error_description": "Token 1//0abc has been expired or revoked.\n"});
        assert_eq!(
            said(&v, reqwest::StatusCode::BAD_REQUEST, &["1//0abc"]),
            "invalid_grant: Token … has been expired or revoked."
        );
    }
}
