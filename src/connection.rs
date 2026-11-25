// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! The GitHub token in use, renewed before it expires.
//!
//! GitHub rotates the pair on every refresh and the used refresh token dies, so two concurrent
//! renewals, or one cut off midway, would break the connection. Renewals therefore take a
//! per-connection lock and re-read the row inside it, run in their own task, and write only if the row
//! is unchanged (store.rs). A rejected refresh marks the connection broken in the same transaction as
//! its audit line; an unreachable GitHub fails the request and the next one retries. The old token is
//! never used after a failed renewal. Connections without a refresh token don't expire.
use std::sync::Arc;

use serde_json::json;

use crate::app::App;
use crate::github::{AAD, Refreshed, StoredToken};
use crate::store::{Audit, ConnectionRow, Renewed};
use crate::util::now;

pub const RENEW_MARGIN: i64 = 300;

#[derive(Debug)]
pub enum TokenError {
    Reconnect(String),
    Unavailable(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for TokenError {
    fn from(e: anyhow::Error) -> TokenError {
        TokenError::Internal(e)
    }
}

/// Deliberately not `Debug`: it holds the tokens.
struct Open {
    row: ConnectionRow,
    token: StoredToken,
}

/// `rejected`: `stale` (the token GitHub just answered 401 to) is still the stored one; `renew` then
/// checks that it is really dead.
fn renew_reason(o: &Open, stale: Option<&str>, at: i64) -> Option<&'static str> {
    o.token.refresh_token.as_ref()?;
    if o.row.expires_at.is_some_and(|t| t - at <= RENEW_MARGIN) {
        return Some("expiring");
    }
    (stale == Some(o.token.access_token.as_str())).then_some("rejected")
}

impl App {
    fn github_open(&self) -> Result<Option<Open>, TokenError> {
        let Some(row) = self.store.connection("github")? else {
            return Ok(None);
        };
        let plain = self.sealer.open(&row.sealed, AAD)?;
        let token: StoredToken = serde_json::from_slice(&plain).map_err(anyhow::Error::from)?;
        Ok(Some(Open { row, token }))
    }

    /// The stored token unchanged, for callers that lost a race with a renewal or a reconnect.
    fn github_as_is(&self) -> Result<Option<String>, TokenError> {
        match self.github_open()? {
            None => Ok(None),
            Some(o) => match &o.row.broken {
                Some((_, why)) => Err(TokenError::Reconnect(why.clone())),
                None => Ok(Some(o.token.access_token)),
            },
        }
    }

    /// `stale` is the token GitHub just rejected with a 401, if any; `session` is for the audit.
    pub async fn github_token(self: &Arc<Self>, session: Option<&str>, stale: Option<&str>) -> Result<Option<String>, TokenError> {
        match self.github_open()? {
            None => return Ok(None),
            Some(o) => {
                if let Some((_, why)) = &o.row.broken {
                    return Err(TokenError::Reconnect(why.clone()));
                }
                if renew_reason(&o, stale, now()).is_none() {
                    return Ok(Some(o.token.access_token));
                }
            }
        }
        // In its own task so a dropped request can't cut it midway: GitHub would have spent the refresh
        // token with nobody storing the new pair.
        let app = self.clone();
        let (session, stale) = (session.map(String::from), stale.map(String::from));
        match tokio::spawn(async move { app.renew(session.as_deref(), stale.as_deref()).await }).await {
            Ok(r) => r,
            Err(e) => Err(TokenError::Internal(anyhow::anyhow!("the renewal task failed: {e}"))),
        }
    }

    /// One at a time, re-deciding with the current row: someone else may have renewed meanwhile.
    async fn renew(&self, session: Option<&str>, stale: Option<&str>) -> Result<Option<String>, TokenError> {
        // A 401 on one route doesn't mean the token is dead (some routes reject OAuth tokens); only a 401
        // from /user does. Otherwise any session with a grant could force a rotation per request. Checked
        // before taking the lock so it doesn't queue.
        let dead = match stale {
            Some(t) => self.github.token_alive(t).await == Some(false),
            None => false,
        };
        let _one = self.github_renew.lock().await;
        let at = now();
        let Some(o) = self.github_open()? else {
            return Ok(None);
        };
        if let Some((_, why)) = &o.row.broken {
            return Err(TokenError::Reconnect(why.clone()));
        }
        let Some(trigger) = renew_reason(&o, stale, at) else {
            return Ok(Some(o.token.access_token));
        };
        if trigger == "rejected" && !dead {
            tracing::info!("GitHub answered 401 to a request, but /user does not say the token is dead: not renewed");
            return Ok(Some(o.token.access_token));
        }
        let refresh_token = o.token.refresh_token.clone().unwrap_or_default();
        let actor = session.map(|s| format!("session:{s}")).unwrap_or_else(|| "system".into());
        let line = |event: &str, detail: serde_json::Value| {
            let a = Audit::new(actor.clone(), event, detail);
            match session {
                Some(s) => a.session(s),
                None => a,
            }
        };
        match self.github.refresh(&refresh_token).await {
            Refreshed::Token(issued) => {
                let at = now();
                let token = StoredToken {
                    access_token: issued.token.access_token,
                    // Refreshing doesn't change scopes (per GitHub docs); keep the old ones if omitted.
                    scope: if issued.token.scope.is_empty() {
                        o.token.scope.clone()
                    } else {
                        issued.token.scope
                    },
                    refresh_token: issued.token.refresh_token,
                };
                let renewed = Renewed {
                    sealed: self.sealer.seal(&serde_json::to_vec(&token).map_err(anyhow::Error::from)?, AAD),
                    scopes: if token.scope.is_empty() { o.row.scopes.clone() } else { token.scope.clone() },
                    expires_at: issued.expires_in.map(|s| at + s),
                    refresh_expires_at: issued.refresh_expires_in.map(|s| at + s),
                };
                let detail = json!({
                    "provider": "github",
                    "account": o.row.account,
                    "trigger": trigger,
                    "expires_at": renewed.expires_at,
                    "refresh_expires_at": renewed.refresh_expires_at,
                });
                if self
                    .store
                    .renew_connection("github", &o.row.sealed, &renewed, line("connection.refreshed", detail), at)?
                {
                    tracing::info!(account = %o.row.account, trigger, expires_at = ?renewed.expires_at, "GitHub token renewed");
                    Ok(Some(token.access_token))
                } else {
                    // Reconnected or disconnected meanwhile: the current row wins.
                    tracing::warn!("the GitHub connection changed while its token was being renewed; the renewed token is discarded");
                    self.github_as_is()
                }
            }
            Refreshed::Rejected(why) => {
                let detail = json!({"provider": "github", "account": o.row.account, "trigger": trigger, "reason": why, "reconnect": true});
                if self
                    .store
                    .break_connection("github", &o.row.sealed, &why, line("connection.refresh_failed", detail), now())?
                {
                    tracing::error!(account = %o.row.account, reason = %why, "GitHub refused to renew the token: the connection has to be connected again");
                    Err(TokenError::Reconnect(why))
                } else {
                    self.github_as_is()
                }
            }
            Refreshed::Unreachable(why) => {
                tracing::warn!(account = %o.row.account, reason = %why, "GitHub did not answer the token renewal; the next request tries again");
                let detail = json!({"provider": "github", "account": o.row.account, "trigger": trigger, "reason": why, "reconnect": false});
                if let Err(e) = self.store.audit(line("connection.refresh_failed", detail), now()) {
                    tracing::error!(error = %e, "cannot write the audit line of a failed renewal");
                }
                Err(TokenError::Unavailable(why))
            }
        }
    }
}
