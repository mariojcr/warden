// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! GitHub connection: an OAuth App connected with the device flow, like `gh auth login`, so only the
//! client id is needed (no secret, no callback to warden).
//!
//! Scopes are `repo` and `offline_access`. Without `workflow` GitHub refuses changes under
//! `.github/workflows` (config.rs won't request it), but writes still trigger the repo's existing
//! Actions (push, pull_request, tag-triggered releases) with its secrets. That is why the approval page
//! warns about Actions on every write and tags are a separate grant (`tags`, scope.rs).
//!
//! `offline_access` yields an 8 h token plus a refresh token even if the app hasn't enabled expiring
//! tokens. Device-flow tokens refresh without the client secret, and each refresh invalidates the old
//! pair (connection.rs serializes renewals). The token covers every repo of the account, so it never
//! leaves warden; lacking a client secret, warden can't revoke it on GitHub when disconnecting.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::GithubConfig;

pub const AAD: &str = "warden/connection/github";

/// Deliberately not `Debug`: it holds the tokens.
#[derive(Serialize, Deserialize)]
pub struct StoredToken {
    pub access_token: String,
    pub scope: String,
    /// None for connections made before `offline_access`: their token doesn't expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

pub const OFFLINE_ACCESS: &str = "offline_access";

/// Scopes GitHub issued that were not asked for: with `workflow`, a push could change
/// `.github/workflows`, which the approval page says a grant cannot do.
pub fn unrequested_scopes(issued: &str, asked: &[String]) -> Vec<String> {
    issued
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty() && *s != OFFLINE_ACCESS && !asked.iter().any(|a| a == s))
        .map(str::to_string)
        .collect()
}

/// GitHub's documented lifetime, used when `expires_in` is missing.
const DEFAULT_EXPIRES_IN: i64 = 8 * 3600;

pub struct Issued {
    pub token: StoredToken,
    /// None when there is no refresh token: the access token doesn't expire.
    pub expires_in: Option<i64>,
    /// Lifetime of the refresh token if left unused.
    pub refresh_expires_in: Option<i64>,
}

pub enum Refreshed {
    Token(Issued),
    /// Refused (`bad_refresh_token`: expired, used or revoked) or not a token: retrying won't help, the
    /// connection must be made again.
    Rejected(String),
    /// No answer, a 5xx or a 429: GitHub may or may not have spent the refresh token. The next request
    /// retries; if it was spent, GitHub will say `bad_refresh_token` then.
    Unreachable(String),
}

fn issued(v: &Value) -> Option<Issued> {
    let access = v["access_token"].as_str().filter(|t| !t.is_empty())?;
    let refresh = v["refresh_token"].as_str().filter(|t| !t.is_empty()).map(String::from);
    // Never under two minutes: an `expires_in` of 0 would renew on every request.
    let expires_in = refresh.as_ref().map(|_| v["expires_in"].as_i64().unwrap_or(DEFAULT_EXPIRES_IN).max(120));
    let refresh_expires_in = refresh.as_ref().and_then(|_| v["refresh_token_expires_in"].as_i64()).map(|s| s.max(0));
    Some(Issued {
        token: StoredToken {
            access_token: access.to_string(),
            scope: v["scope"].as_str().unwrap_or("").to_string(),
            refresh_token: refresh,
        },
        expires_in,
        refresh_expires_in,
    })
}

pub struct Github {
    pub cfg: GithubConfig,
    http: reqwest::Client,
    /// Cached briefly: every push and every write that touches the default branch checks it.
    branches: std::sync::Mutex<std::collections::HashMap<String, (String, i64)>>,
}

const BRANCH_TTL: i64 = 60;

/// GitHub requires a User-Agent on every API call.
pub const USER_AGENT: &str = "warden";

#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub expires_in: i64,
    pub interval: u64,
}

/// Deliberately not `Debug`: `Token` holds the token.
pub enum Poll {
    Pending,
    SlowDown,
    Token(Issued),
    Denied,
    Expired,
    Failed(String),
}

impl Github {
    pub fn new(cfg: GithubConfig) -> anyhow::Result<Github> {
        anyhow::ensure!(!cfg.client_id.trim().is_empty(), "github.client_id is empty");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Github {
            cfg,
            http,
            branches: Default::default(),
        })
    }

    fn web(&self) -> &str {
        self.cfg.web_base.trim_end_matches('/')
    }

    fn api(&self) -> &str {
        self.cfg.api_base.trim_end_matches('/')
    }

    pub fn device_url(&self) -> String {
        format!("{}/login/device", self.web())
    }

    pub fn settings_url(&self) -> String {
        format!("{}/settings/connections/applications/{}", self.web(), self.cfg.client_id)
    }

    pub fn scopes(&self) -> String {
        let mut scopes: Vec<&str> = self.cfg.scopes.iter().map(String::as_str).filter(|s| *s != OFFLINE_ACCESS).collect();
        scopes.push(OFFLINE_ACCESS);
        scopes.join(" ")
    }

    pub async fn device_code(&self) -> anyhow::Result<DeviceCode> {
        let resp = self
            .http
            .post(format!("{}/login/device/code", self.web()))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[("client_id", self.cfg.client_id.as_str()), ("scope", self.scopes().as_str())])
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "GitHub answered HTTP {} to the device code request", resp.status());
        let v: Value = resp.json().await?;
        if let Some(err) = v["error"].as_str() {
            anyhow::bail!("GitHub refused the device flow: {err} (is «Enable Device Flow» ticked in the OAuth App?)");
        }
        let user_code = v["user_code"].as_str().unwrap_or("");
        // It is rendered in a page: allow only letters, digits and dashes, as GitHub issues them.
        anyhow::ensure!(
            !user_code.is_empty() && user_code.len() <= 16 && user_code.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "GitHub gave an unexpected user code"
        );
        let device_code = v["device_code"]
            .as_str()
            .filter(|d| !d.is_empty())
            .ok_or_else(|| anyhow::anyhow!("GitHub gave no device_code"))?;
        Ok(DeviceCode {
            device_code: device_code.to_string(),
            user_code: user_code.to_string(),
            expires_in: v["expires_in"].as_i64().unwrap_or(900).clamp(60, 1800),
            interval: v["interval"].as_u64().unwrap_or(5).min(60),
        })
    }

    pub async fn poll(&self, device_code: &str) -> Poll {
        let sent = self
            .http
            .post(format!("{}/login/oauth/access_token", self.web()))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.cfg.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await;
        let resp = match sent {
            Ok(r) => r,
            Err(e) => return Poll::Failed(e.without_url().to_string()),
        };
        let v: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return Poll::Failed(e.to_string()),
        };
        if let Some(t) = issued(&v) {
            return Poll::Token(t);
        }
        match v["error"].as_str() {
            Some("authorization_pending") => Poll::Pending,
            Some("slow_down") => Poll::SlowDown,
            Some("access_denied") => Poll::Denied,
            Some("expired_token") => Poll::Expired,
            Some(other) => Poll::Failed(format!("GitHub said {other}")),
            None => Poll::Failed("GitHub gave neither a token nor an error".into()),
        }
    }

    /// The used refresh token and the previous access token stop working. No client secret: device-flow
    /// tokens don't need one.
    pub async fn refresh(&self, refresh_token: &str) -> Refreshed {
        if refresh_token.is_empty() {
            return Refreshed::Rejected("there is no refresh token".into());
        }
        let sent = self
            .http
            .post(format!("{}/login/oauth/access_token", self.web()))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.cfg.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await;
        let resp = match sent {
            Ok(r) => r,
            Err(e) => return Refreshed::Unreachable(e.without_url().to_string()),
        };
        let status = resp.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Refreshed::Unreachable(format!("GitHub answered HTTP {status}"));
        }
        let v: Value = match resp.json().await {
            Ok(v) => v,
            // A 4xx without JSON is a refusal; an unreadable 2xx is unknown.
            Err(_) if status.is_client_error() => {
                return Refreshed::Rejected(format!("GitHub answered HTTP {status}"));
            }
            Err(e) => {
                return Refreshed::Unreachable(format!("GitHub's answer could not be read ({})", e.without_url()));
            }
        };
        if let Some(t) = issued(&v) {
            return Refreshed::Token(t);
        }
        // Scrub the token just in case: this goes to the audit and the log.
        let said = match (v["error"].as_str(), v["error_description"].as_str()) {
            (Some(e), Some(d)) => format!("{e}: {d}"),
            (Some(e), None) => e.to_string(),
            _ => format!("GitHub answered HTTP {status} without a token"),
        };
        let mut said: String = said.replace(refresh_token, "…").chars().filter(|c| !c.is_control()).take(300).collect();
        if said.is_empty() {
            said = "GitHub refused".into();
        }
        Refreshed::Rejected(said)
    }

    pub async fn login(&self, token: &str) -> anyhow::Result<String> {
        let resp = self
            .http
            .get(format!("{}/user", self.api()))
            .bearer_auth(token)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "GitHub /user answered HTTP {}", resp.status());
        let v: Value = resp.json().await?;
        v["login"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("GitHub /user gave no login"))
    }

    /// Checked on /user, which works with any scope. Some(false) only on a 401; None when unknown.
    pub async fn token_alive(&self, token: &str) -> Option<bool> {
        let resp = self
            .http
            .get(format!("{}/user", self.api()))
            .bearer_auth(token)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .ok()?;
        match resp.status() {
            s if s.is_success() => Some(true),
            reqwest::StatusCode::UNAUTHORIZED => Some(false),
            _ => None,
        }
    }

    pub async fn default_branch(&self, repo: &crate::scope::Repo, token: &str) -> anyhow::Result<String> {
        let now = crate::util::now();
        if let Some((b, at)) = self.branches.lock().unwrap_or_else(|p| p.into_inner()).get(&repo.key())
            && now - at < BRANCH_TTL
        {
            return Ok(b.clone());
        }
        let resp = self
            .http
            .get(format!("{}/repos/{}/{}", self.api(), repo.owner, repo.name))
            .bearer_auth(token)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "GitHub answered HTTP {}", resp.status());
        let v: Value = resp.json().await?;
        let b = v["default_branch"]
            .as_str()
            .filter(|b| !b.is_empty())
            .ok_or_else(|| anyhow::anyhow!("no default_branch"))?
            .to_string();
        self.branches.lock().unwrap_or_else(|p| p.into_inner()).insert(repo.key(), (b.clone(), now));
        Ok(b)
    }

    /// Whether `oid` is `old` or descends from it, per GitHub's compare API; errors if GitHub lacks `oid`.
    pub async fn is_ancestor(&self, repo: &crate::scope::Repo, token: &str, old: &str, oid: &str) -> Result<bool, String> {
        let hex = |s: &str| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit());
        if !hex(old) || !hex(oid) {
            return Err("not a commit id".into());
        }
        let resp = self
            .http
            .get(format!("{}/repos/{}/{}/compare/{old}...{oid}?per_page=1", self.api(), repo.owner, repo.name))
            .bearer_auth(token)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        match resp.status() {
            s if s.is_success() => {
                let v: Value = resp.json().await.map_err(|e| e.to_string())?;
                Ok(matches!(v["status"].as_str(), Some("ahead" | "identical")))
            }
            reqwest::StatusCode::NOT_FOUND => Err(format!("commit {oid} is neither in the push nor on GitHub")),
            s => Err(format!("GitHub answered HTTP {s} to a comparison")),
        }
    }

    /// Returns (head repo as `owner/name`, head branch).
    pub async fn pull_head(&self, repo: &crate::scope::Repo, number: &str, token: &str) -> Result<(String, String), String> {
        if number.is_empty() || !number.bytes().all(|c| c.is_ascii_digit()) {
            return Err("not a pull request number".into());
        }
        let resp = self
            .http
            .get(format!("{}/repos/{}/{}/pulls/{number}", self.api(), repo.owner, repo.name))
            .bearer_auth(token)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(format!("GitHub answered HTTP {}", resp.status()));
        }
        let v: Value = resp.json().await.map_err(|e| e.to_string())?;
        let full = v["head"]["repo"]["full_name"].as_str().ok_or("the pull request's head has no repository")?;
        let branch = v["head"]["ref"].as_str().ok_or("the pull request has no head branch")?;
        Ok((full.to_string(), branch.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_scopes_asked_for_are_kept() {
        let asked = vec!["repo".to_string()];
        assert!(unrequested_scopes("repo", &asked).is_empty());
        assert!(unrequested_scopes("repo offline_access", &asked).is_empty());
        assert_eq!(unrequested_scopes("repo,workflow", &asked), vec!["workflow"]);
        assert_eq!(unrequested_scopes("repo workflow read:org", &asked), vec!["workflow", "read:org"]);
    }
}
