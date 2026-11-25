// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Owner authentication against the OIDC provider (Pocket ID).
//!
//! Approving, connecting and disconnecting demand a fresh login: code flow with PKCE, `prompt=login`
//! and `max_age=0`, which force re-authentication and stamp `auth_time`. Besides the signature, the ID
//! token must match issuer (exactly), audience/azp, nonce and owner `sub`, be issued during this flow,
//! and carry a recent `auth_time` and an `amr` with "phr" (passkey; an emailed code gives "otp").
//! Logging into the panel skips the freshness checks.
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::config::{OidcConfig, read_secret};
use crate::jwt::KeySet;
use crate::util::ct_eq;

const SKEW: i64 = 30;

struct Meta {
    authorization_endpoint: String,
    token_endpoint: String,
    keys: KeySet,
}

pub struct Oidc {
    pub cfg: OidcConfig,
    client_secret: String,
    http: reqwest::Client,
    meta: tokio::sync::OnceCell<Arc<Meta>>,
}

pub struct Expect<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub owner_sub: &'a str,
    pub nonce: &'a str,
    pub flow_started_at: i64,
    /// Require a passkey used during this flow (approve, connect, disconnect).
    pub fresh: bool,
    pub max_auth_age: i64,
    pub require_amr: &'a str,
}

#[derive(Debug, Clone)]
pub struct Owner {
    pub sub: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

fn int(claims: &Map<String, Value>, k: &str) -> Option<i64> {
    claims.get(k).and_then(Value::as_i64)
}

/// Errors go to the log and the audit; the owner is shown something shorter.
pub fn check_claims(claims: &Map<String, Value>, e: &Expect, now: i64) -> Result<Owner, String> {
    if claims.get("iss").and_then(Value::as_str) != Some(e.issuer) {
        return Err(format!("issuer is {:?}, not {}", claims.get("iss"), e.issuer));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == e.client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|a| a.as_str() == Some(e.client_id)) && (list.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(e.client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err("the token is not for this client (aud/azp)".into());
    }
    let exp = int(claims, "exp").ok_or("no exp")?;
    if now > exp + SKEW {
        return Err("the token has expired".into());
    }
    let iat = int(claims, "iat").ok_or("no iat")?;
    if iat > now + SKEW || iat < e.flow_started_at - SKEW {
        return Err("the token was not issued during this flow (iat)".into());
    }
    match claims.get("nonce").and_then(Value::as_str) {
        Some(n) if ct_eq(n.as_bytes(), e.nonce.as_bytes()) => {}
        _ => return Err("nonce does not match this flow".into()),
    }
    let sub = claims.get("sub").and_then(Value::as_str).unwrap_or("");
    if sub.is_empty() || sub != e.owner_sub {
        return Err(format!("sub «{sub}» is not the owner"));
    }
    let amr: Vec<String> = claims
        .get("amr")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if !e.require_amr.is_empty() && !amr.iter().any(|m| m == e.require_amr) {
        return Err(format!("authentication method {amr:?} is not {}", e.require_amr));
    }
    let auth_time = int(claims, "auth_time");
    if e.fresh {
        let at = auth_time.ok_or("no auth_time: cannot tell when the passkey was used")?;
        if at < e.flow_started_at - SKEW {
            return Err("the passkey was used before this approval started (auth_time); a fresh login is required".into());
        }
        if at > now + SKEW || now - at > e.max_auth_age {
            return Err(format!("auth_time is not within the last {} s", e.max_auth_age));
        }
    }
    Ok(Owner {
        sub: sub.to_string(),
        auth_time: auth_time.unwrap_or(0),
        amr,
    })
}

/// PKCE S256.
pub fn challenge(verifier: &str) -> String {
    crate::util::b64url(&crate::util::sha256(verifier.as_bytes()))
}

impl Oidc {
    pub fn new(cfg: OidcConfig, http: reqwest::Client) -> anyhow::Result<Oidc> {
        let client_secret = read_secret(&cfg.client_secret_file, "the Pocket ID client secret")?;
        Ok(Oidc {
            cfg,
            client_secret,
            http,
            meta: tokio::sync::OnceCell::new(),
        })
    }

    /// Lazy, so warden still starts when the provider is down; a failure is retried on next use.
    async fn meta(&self) -> anyhow::Result<Arc<Meta>> {
        self.meta
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer.trim_end_matches('/'));
                let resp = self.http.get(&url).timeout(Duration::from_secs(10)).send().await?;
                anyhow::ensure!(resp.status().is_success(), "{url}: HTTP {}", resp.status());
                let d: Value = resp.json().await?;
                // A discovery document for another issuer makes everything else in it untrustworthy.
                anyhow::ensure!(
                    d["issuer"].as_str() == Some(self.cfg.issuer.as_str()),
                    "the discovery says issuer {:?}, not {}",
                    d["issuer"],
                    self.cfg.issuer
                );
                let field = |k: &str| d[k].as_str().map(String::from).ok_or_else(|| anyhow::anyhow!("the discovery has no {k}"));
                Ok(Arc::new(Meta {
                    authorization_endpoint: field("authorization_endpoint")?,
                    token_endpoint: field("token_endpoint")?,
                    keys: KeySet::new(field("jwks_uri")?, self.http.clone()),
                }))
            })
            .await
            .cloned()
    }

    /// `fresh`: ask for the passkey again even if the provider already has a session.
    pub async fn authorize_url(&self, redirect_uri: &str, state: &str, nonce: &str, verifier: &str, fresh: bool) -> anyhow::Result<String> {
        let meta = self.meta().await?;
        let mut url = url::Url::parse(&meta.authorization_endpoint)?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", "openid")
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", &challenge(verifier))
                .append_pair("code_challenge_method", "S256");
            if fresh {
                q.append_pair("prompt", "login").append_pair("max_age", "0");
            }
        }
        Ok(url.into())
    }

    pub async fn exchange(&self, code: &str, redirect_uri: &str, verifier: &str) -> anyhow::Result<String> {
        let meta = self.meta().await?;
        let resp = self
            .http
            .post(&meta.token_endpoint)
            .basic_auth(&self.cfg.client_id, Some(&self.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ])
            .timeout(Duration::from_secs(15))
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        anyhow::ensure!(
            status.is_success(),
            "the token endpoint answered HTTP {status} ({})",
            body["error"].as_str().unwrap_or("no error code")
        );
        body["id_token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("the token endpoint gave no id_token"))
    }

    pub async fn verify(&self, id_token: &str, nonce: &str, flow_started_at: i64, fresh: bool, now: i64) -> Result<Owner, String> {
        let meta = self.meta().await.map_err(|e| e.to_string())?;
        let claims = meta.keys.verify(id_token).await.map_err(|e| e.to_string())?;
        let expect = Expect {
            issuer: &self.cfg.issuer,
            client_id: &self.cfg.client_id,
            owner_sub: &self.cfg.owner_sub,
            nonce,
            flow_started_at,
            fresh,
            max_auth_age: self.cfg.max_auth_age_secs,
            require_amr: &self.cfg.require_amr,
        };
        check_claims(&claims, &expect, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{Jwks, verify_rs256};
    use crate::testkey::{IDP_KEY_B64, OTHER_KEY_B64, jwk, sign};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const STARTED: i64 = NOW - 40;

    fn expect(fresh: bool) -> Expect<'static> {
        Expect {
            issuer: "https://id.example.com",
            client_id: "warden-client",
            owner_sub: "owner-sub",
            nonce: "n-123",
            flow_started_at: STARTED,
            fresh,
            max_auth_age: 120,
            require_amr: "phr",
        }
    }

    fn claims() -> Value {
        json!({"iss": "https://id.example.com", "aud": "warden-client", "sub": "owner-sub", "nonce": "n-123",
               "iat": NOW - 5, "exp": NOW + 300, "auth_time": NOW - 10, "amr": ["phr"]})
    }

    fn with(k: &str, v: Value) -> Map<String, Value> {
        let mut c = claims();
        if v.is_null() {
            c.as_object_mut().unwrap().remove(k);
        } else {
            c[k] = v;
        }
        c.as_object().unwrap().clone()
    }

    #[test]
    fn a_fresh_passkey_login_of_the_owner_passes() {
        let o = check_claims(claims().as_object().unwrap(), &expect(true), NOW).unwrap();
        assert_eq!((o.sub.as_str(), o.auth_time), ("owner-sub", NOW - 10));
        let c = with("aud", json!(["warden-client", "other"]));
        let mut c2 = c.clone();
        c2.insert("azp".into(), json!("warden-client"));
        assert!(check_claims(&c2, &expect(true), NOW).is_ok());
        assert!(check_claims(&c, &expect(true), NOW).is_err(), "several audiences without azp");
    }

    #[test]
    fn each_claim_is_checked() {
        let e = expect(true);
        let bad = |k: &str, v: Value| check_claims(&with(k, v), &e, NOW).unwrap_err();
        assert!(bad("iss", json!("https://id.evil.com")).contains("issuer"));
        assert!(bad("iss", json!("https://id.example.com/")).contains("issuer"), "letter by letter");
        assert!(bad("aud", json!("someone-else")).contains("aud"));
        assert!(bad("nonce", json!("n-999")).contains("nonce"));
        assert!(bad("nonce", Value::Null).contains("nonce"));
        assert!(bad("sub", json!("eve-sub")).contains("not the owner"));
        assert!(bad("exp", json!(NOW - 100)).contains("expired"));
        assert!(bad("iat", json!(STARTED - 600)).contains("iat"), "a token from an older flow");
        assert!(bad("amr", json!(["otp"])).contains("authentication method"));
        assert!(bad("amr", Value::Null).contains("authentication method"));
        // auth_time before the flow (a reused provider session), in the future, or missing.
        assert!(bad("auth_time", json!(STARTED - 3600)).contains("before this approval"));
        assert!(bad("auth_time", json!(NOW + 600)).contains("auth_time"));
        assert!(bad("auth_time", Value::Null).contains("auth_time"));
        let slow = Expect {
            flow_started_at: NOW - 1000,
            ..expect(true)
        };
        let mut c = with("auth_time", json!(NOW - 500));
        c.insert("iat".into(), json!(NOW - 1));
        assert!(check_claims(&c, &slow, NOW).unwrap_err().contains("within the last 120"));
    }

    #[test]
    fn logging_into_the_panel_does_not_need_a_fresh_passkey() {
        assert!(check_claims(&with("auth_time", json!(STARTED - 3600)), &expect(false), NOW).is_ok());
        // It must still be the owner, with a passkey.
        assert!(check_claims(&with("sub", json!("eve")), &expect(false), NOW).is_err());
        assert!(check_claims(&with("amr", json!(["otp"])), &expect(false), NOW).is_err());
    }

    #[test]
    fn the_signature_comes_first() {
        let jwks = Jwks::parse(&json!({"keys": [jwk(IDP_KEY_B64, "pocket")]})).unwrap();
        let good = sign(IDP_KEY_B64, &json!({"alg": "RS256", "kid": "pocket"}), &claims());
        let c = verify_rs256(&good, &jwks).unwrap();
        assert!(check_claims(&c, &expect(true), NOW).is_ok());
        let forged = sign(OTHER_KEY_B64, &json!({"alg": "RS256", "kid": "pocket"}), &claims());
        assert!(verify_rs256(&forged, &jwks).is_err());
    }

    #[test]
    fn pkce_challenge_is_s256() {
        // RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
