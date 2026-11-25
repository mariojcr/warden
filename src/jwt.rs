// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Signature checks for incoming JWTs (OIDC ID tokens and Nomad workload identities). Both issuers
//! sign with RS256, so only RS256 with an RSA key from the JWKS is accepted: no `none`, no HS256 keyed
//! with the public key, no key embedded in the token. Callers validate the claims.
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::{Map, Value};

#[derive(Debug, PartialEq)]
pub enum JwtError {
    Malformed(&'static str),
    Algorithm(String),
    UnknownKey,
    BadSignature,
    Keys(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed(what) => write!(f, "malformed token ({what})"),
            JwtError::Algorithm(a) => write!(f, "algorithm «{a}» is not accepted (only RS256)"),
            JwtError::UnknownKey => write!(f, "signed with a key that is not in the JWKS"),
            JwtError::BadSignature => write!(f, "bad signature"),
            JwtError::Keys(e) => write!(f, "cannot read the JWKS: {e}"),
        }
    }
}

struct RsaKey {
    kid: Option<String>,
    n: Vec<u8>,
    e: Vec<u8>,
}

pub struct Jwks {
    keys: Vec<RsaKey>,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

impl Jwks {
    pub fn parse(v: &Value) -> anyhow::Result<Jwks> {
        let list = v["keys"].as_array().ok_or_else(|| anyhow::anyhow!("a JWKS needs \"keys\""))?;
        let mut keys = Vec::new();
        for k in list {
            let rsa = k["kty"] == "RSA";
            let sig = k.get("use").is_none_or(|u| u == "sig");
            let rs256 = k.get("alg").is_none_or(|a| a == "RS256");
            let (Some(n), Some(e)) = (k["n"].as_str().and_then(b64), k["e"].as_str().and_then(b64)) else {
                continue;
            };
            if rsa && sig && rs256 {
                // ring rejects a modulus with leading zeros, and some JWKS include them.
                let strip = |b: Vec<u8>| b.iter().position(|&x| x != 0).map(|p| b[p..].to_vec()).unwrap_or_default();
                keys.push(RsaKey {
                    kid: k["kid"].as_str().map(String::from),
                    n: strip(n),
                    e: strip(e),
                });
            }
        }
        anyhow::ensure!(!keys.is_empty(), "the JWKS has no RSA signing key");
        Ok(Jwks { keys })
    }

    fn find(&self, kid: Option<&str>) -> Option<&RsaKey> {
        match kid {
            Some(kid) => self.keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }
}

fn json_part(part: &str, what: &'static str) -> Result<Map<String, Value>, JwtError> {
    let raw = b64(part).ok_or(JwtError::Malformed(what))?;
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(JwtError::Malformed(what)),
    }
}

/// Unverified: only used to decide whether the JWKS needs a refetch.
pub fn header_kid(token: &str) -> Option<String> {
    let header = json_part(token.split('.').next()?, "header").ok()?;
    header.get("kid")?.as_str().map(String::from)
}

/// Checks only the signature; the caller must validate the claims.
pub fn verify_rs256(token: &str, jwks: &Jwks) -> Result<Map<String, Value>, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(JwtError::Malformed("not three parts"));
    };
    let header = json_part(h, "header")?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "RS256" {
        return Err(JwtError::Algorithm(alg.to_string()));
    }
    // RFC 7515 §4.1.11: unknown critical extensions must be rejected.
    if header.contains_key("crit") {
        return Err(JwtError::Malformed("crit"));
    }
    let key = jwks.find(header.get("kid").and_then(Value::as_str)).ok_or(JwtError::UnknownKey)?;
    let sig = b64(s).ok_or(JwtError::Malformed("signature"))?;
    let signed = &token[..h.len() + 1 + p.len()];
    RsaPublicKeyComponents { n: &key.n, e: &key.e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)?;
    json_part(p, "payload")
}

/// Refetches when a token names an unknown `kid` (key rotation), at most once per `REFRESH_EVERY`,
/// so forged tokens can't make warden hammer the JWKS endpoint.
pub struct KeySet {
    url: String,
    http: reqwest::Client,
    cache: tokio::sync::Mutex<(Option<std::sync::Arc<Jwks>>, i64)>,
}

const REFRESH_EVERY: i64 = 30;

impl KeySet {
    pub fn new(url: String, http: reqwest::Client) -> KeySet {
        KeySet {
            url,
            http,
            cache: tokio::sync::Mutex::new((None, 0)),
        }
    }

    async fn fetch(&self) -> Result<Jwks, JwtError> {
        let resp = self
            .http
            .get(&self.url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| JwtError::Keys(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(JwtError::Keys(format!("HTTP {}", resp.status())));
        }
        let v: Value = resp.json().await.map_err(|e| JwtError::Keys(e.to_string()))?;
        Jwks::parse(&v).map_err(|e| JwtError::Keys(e.to_string()))
    }

    pub async fn verify(&self, token: &str) -> Result<Map<String, Value>, JwtError> {
        let kid = header_kid(token);
        let mut cache = self.cache.lock().await;
        let now = crate::util::now();
        let stale = match (&cache.0, &kid) {
            (None, _) => true,
            (Some(jwks), Some(kid)) => !jwks.keys.iter().any(|k| k.kid.as_deref() == Some(kid.as_str())),
            (Some(_), None) => false,
        };
        if stale && (cache.0.is_none() || now - cache.1 >= REFRESH_EVERY) {
            match self.fetch().await {
                Ok(jwks) => *cache = (Some(std::sync::Arc::new(jwks)), now),
                Err(e) if cache.0.is_none() => return Err(e),
                Err(e) => {
                    tracing::warn!(url = %self.url, error = %e, "cannot refresh the JWKS; keeping the cached one")
                }
            }
        }
        let jwks = cache.0.clone().expect("fetched above");
        drop(cache);
        verify_rs256(token, &jwks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkey::{IDP_KEY_B64, OTHER_KEY_B64, jwk, sign};
    use serde_json::json;

    fn jwks() -> Jwks {
        Jwks::parse(&json!({"keys": [jwk(IDP_KEY_B64, "k1"), {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"}]})).unwrap()
    }

    #[test]
    fn a_good_signature_gives_the_claims() {
        let t = sign(IDP_KEY_B64, &json!({"alg": "RS256", "kid": "k1"}), &json!({"sub": "owner"}));
        assert_eq!(verify_rs256(&t, &jwks()).unwrap()["sub"], "owner");
        let t = sign(IDP_KEY_B64, &json!({"alg": "RS256"}), &json!({"sub": "owner"}));
        assert!(verify_rs256(&t, &jwks()).is_ok());
    }

    #[test]
    fn only_rs256_from_the_jwks_is_accepted() {
        let claims = URL_SAFE_NO_PAD.encode(json!({"sub": "owner"}).to_string());
        let none = format!("{}.{claims}.", URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string()));
        assert_eq!(verify_rs256(&none, &jwks()), Err(JwtError::Algorithm("none".into())));
        let hs = format!("{}.{claims}.AAAA", URL_SAFE_NO_PAD.encode(json!({"alg": "HS256", "kid": "k1"}).to_string()));
        assert_eq!(verify_rs256(&hs, &jwks()), Err(JwtError::Algorithm("HS256".into())));
        let other = sign(OTHER_KEY_B64, &json!({"alg": "RS256", "kid": "k1"}), &json!({"sub": "owner"}));
        assert_eq!(verify_rs256(&other, &jwks()), Err(JwtError::BadSignature));
        let unknown = sign(IDP_KEY_B64, &json!({"alg": "RS256", "kid": "k9"}), &json!({"sub": "owner"}));
        assert_eq!(verify_rs256(&unknown, &jwks()), Err(JwtError::UnknownKey));
        let good = sign(IDP_KEY_B64, &json!({"alg": "RS256", "kid": "k1"}), &json!({"sub": "owner"}));
        let parts: Vec<&str> = good.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(json!({"sub": "eve"}).to_string()), parts[2]);
        assert_eq!(verify_rs256(&forged, &jwks()), Err(JwtError::BadSignature));
        let crit = sign(IDP_KEY_B64, &json!({"alg": "RS256", "kid": "k1", "crit": ["x"]}), &json!({}));
        assert_eq!(verify_rs256(&crit, &jwks()), Err(JwtError::Malformed("crit")));
        assert!(matches!(verify_rs256("a.b", &jwks()), Err(JwtError::Malformed(_))));
    }
}
