// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! warden's own passkey: approve from the heimdall card (or the request page) without a round trip
//! through the OIDC provider.
//!
//! A WebAuthn credential owned by warden, with an RP ID (`webauthn.rp_id`) covering both the heimdall
//! and warden hosts. Registering or removing one requires a fresh OIDC passkey login.
//!
//! To approve, whoever shows the request asks for a challenge bound to that request and that path
//! (single use, `challenge_ttl_secs`), and the owner's browser signs it with user verification. warden
//! then checks the challenge (spent on presentation, whatever the outcome); that `clientDataJSON` is a
//! `get` from exactly that path's origin and not cross-origin (in heimdall's Android app the origin is
//! its `android:apk-key-hash:…`); that `authenticatorData` is for the RP ID with UP and UV; the
//! signature; and, in the granting transaction, that the passkey is alive and its counter increased.
//!
//! heimdall's token alone grants nothing. Attestation is not verified (`none` is requested): it is the
//! owner registering their own passkey right after the OIDC login.
use axum::http::StatusCode;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::cbor;
use crate::store::{Approval, Audit, ChallengeRow, GrantRow, PasskeyRow, Via};
use crate::util::{b64url, ct_eq, now, random, sha256, sha256_hex};

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

/// Accepted COSE algorithms, in order of preference.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;
pub const ALGS: [i64; 3] = [ES256, EDDSA, RS256];

pub const MAX_PASSKEYS: i64 = 5;
/// Live challenges per request and path, so asking for many can't fill the database.
pub const MAX_CHALLENGES: i64 = 5;
pub const REGISTER_TTL: i64 = 300;

/// Upper bounds per field, in decoded bytes.
const CREDENTIAL_ID_MAX: usize = 1023;
const CLIENT_DATA_MAX: usize = 4096;
const AUTH_DATA_MAX: usize = 2048;
const SIGNATURE_MAX: usize = 1024;
const ATTESTATION_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKey {
    /// Uncompressed point (0x04 ‖ x ‖ y).
    P256(Vec<u8>),
    Ed25519(Vec<u8>),
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// An accepted COSE key (RFC 9053) and its algorithm; it must span all of `bytes`.
    pub fn from_cose(bytes: &[u8]) -> Result<(PublicKey, i64), String> {
        let (v, used) = cbor::decode(bytes)?;
        if used != bytes.len() {
            return Err("the COSE key has trailing bytes".into());
        }
        let int = |k| v.int_key(k).and_then(cbor::Value::as_int);
        let bytes_of = |k| v.int_key(k).and_then(cbor::Value::as_bytes);
        let alg = int(3).ok_or("the COSE key has no algorithm")?;
        match (int(1), alg) {
            (Some(2), a) if a == ES256 as i128 => {
                let (Some(x), Some(y)) = (bytes_of(-2), bytes_of(-3)) else {
                    return Err("the EC2 key has no coordinates".into());
                };
                if int(-1) != Some(1) || x.len() != 32 || y.len() != 32 {
                    return Err("only P-256 EC2 keys are accepted".into());
                }
                let mut point = vec![0x04];
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                Ok((PublicKey::P256(point), ES256))
            }
            (Some(1), a) if a == EDDSA as i128 => {
                let x = bytes_of(-2).ok_or("the OKP key has no x")?;
                if int(-1) != Some(6) || x.len() != 32 {
                    return Err("only Ed25519 OKP keys are accepted".into());
                }
                Ok((PublicKey::Ed25519(x.to_vec()), EDDSA))
            }
            (Some(3), a) if a == RS256 as i128 => {
                let (Some(n), Some(e)) = (bytes_of(-1), bytes_of(-2)) else {
                    return Err("the RSA key has no n or e".into());
                };
                let n = n.iter().skip_while(|b| **b == 0).copied().collect::<Vec<u8>>();
                if n.len() < 256 || e.is_empty() || e.len() > 8 {
                    return Err("only RSA keys of 2048 bits or more are accepted".into());
                }
                Ok((PublicKey::Rsa { n, e: e.to_vec() }, RS256))
            }
            _ => Err(format!("unsupported key type or algorithm ({alg})")),
        }
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::P256(point) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(msg, sig).is_ok(),
            PublicKey::Ed25519(x) => UnparsedPublicKey::new(&ED25519, x).verify(msg, sig).is_ok(),
            PublicKey::Rsa { n, e } => RsaPublicKeyComponents { n, e }.verify(&RSA_PKCS1_2048_8192_SHA256, msg, sig).is_ok(),
        }
    }
}

#[derive(Debug)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<Attested>,
}

#[derive(Debug)]
pub struct Attested {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub cose: Vec<u8>,
}

pub fn parse_auth_data(b: &[u8]) -> Result<AuthData, String> {
    if b.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    let rp_id_hash: [u8; 32] = b[..32].try_into().unwrap();
    let flags = b[32];
    let sign_count = u32::from_be_bytes(b[33..37].try_into().unwrap());
    let mut pos = 37;
    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if b.len() < pos + 18 {
            return Err("attested credential data is too short".into());
        }
        let aaguid: [u8; 16] = b[pos..pos + 16].try_into().unwrap();
        let len = u16::from_be_bytes([b[pos + 16], b[pos + 17]]) as usize;
        pos += 18;
        if len == 0 || len > CREDENTIAL_ID_MAX || b.len() < pos + len {
            return Err("bad credential id length".into());
        }
        let credential_id = b[pos..pos + len].to_vec();
        pos += len;
        let (_, used) = cbor::decode(&b[pos..])?;
        let cose = b[pos..pos + used].to_vec();
        pos += used;
        attested = Some(Attested { aaguid, credential_id, cose });
    }
    if flags & FLAG_ED != 0 {
        let (ext, used) = cbor::decode(&b[pos..])?;
        if !matches!(ext, cbor::Value::Map(_)) {
            return Err("extensions are not a map".into());
        }
        pos += used;
    }
    if pos != b.len() {
        return Err("authenticator data has trailing bytes".into());
    }
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

#[derive(Debug)]
pub struct ClientData {
    pub kind: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool,
}

pub fn parse_client_data(b: &[u8]) -> Result<ClientData, String> {
    let v: Value = serde_json::from_slice(b).map_err(|_| "clientDataJSON is not JSON")?;
    let s = |k: &str| v[k].as_str().map(String::from).ok_or(format!("clientDataJSON has no {k}"));
    Ok(ClientData {
        kind: s("type")?,
        challenge: s("challenge")?,
        origin: s("origin")?,
        cross_origin: match &v["crossOrigin"] {
            Value::Null => false,
            Value::Bool(b) => *b,
            _ => return Err("clientDataJSON crossOrigin is not a boolean".into()),
        },
    })
}

#[derive(Debug)]
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    pub cose: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub aaguid: String,
    pub backup_eligible: bool,
}

/// `credential_id` is the browser's `rawId`; it must match the one inside.
pub fn verify_registration(
    credential_id: &[u8],
    client_data: &[u8],
    attestation: &[u8],
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> Result<NewPasskey, String> {
    let cd = parse_client_data(client_data)?;
    if cd.kind != "webauthn.create" {
        return Err(format!(
            "clientDataJSON type is {:?}, not webauthn.create",
            cd.kind.chars().take(40).collect::<String>()
        ));
    }
    if !ct_eq(cd.challenge.as_bytes(), challenge.as_bytes()) {
        return Err("the challenge does not match".into());
    }
    if cd.origin != origin || cd.cross_origin {
        return Err(format!("the origin {:?} is not warden's", cd.origin.chars().take(200).collect::<String>()));
    }
    let (obj, used) = cbor::decode(attestation)?;
    if used != attestation.len() {
        return Err("the attestation object has trailing bytes".into());
    }
    let auth_data = obj
        .text_key("authData")
        .and_then(cbor::Value::as_bytes)
        .ok_or("the attestation object has no authData")?;
    let ad = parse_auth_data(auth_data)?;
    if !ct_eq(&ad.rp_id_hash, &sha256(rp_id.as_bytes())) {
        return Err("the passkey is for another RP ID".into());
    }
    if ad.flags & FLAG_UP == 0 || ad.flags & FLAG_UV == 0 {
        return Err("the authenticator did not verify the user (UP and UV are required)".into());
    }
    let at = ad.attested.ok_or("no attested credential data")?;
    if !ct_eq(&at.credential_id, credential_id) {
        return Err("the credential id does not match the authenticator data".into());
    }
    let (_, alg) = PublicKey::from_cose(&at.cose)?;
    Ok(NewPasskey {
        credential_id: at.credential_id,
        cose: at.cose,
        alg,
        sign_count: ad.sign_count,
        aaguid: at.aaguid.iter().map(|b| format!("{b:02x}")).collect(),
        backup_eligible: ad.flags & FLAG_BE != 0,
    })
}

#[derive(Debug)]
pub struct Asserted {
    pub sign_count: u32,
    pub origin: String,
}

/// The sign counter is checked by the granting transaction (store.rs).
pub fn verify_assertion(
    client_data: &[u8],
    auth_data: &[u8],
    signature: &[u8],
    key: &PublicKey,
    challenge: &str,
    origins: &[String],
    rp_id: &str,
) -> Result<Asserted, String> {
    let cd = parse_client_data(client_data)?;
    if cd.kind != "webauthn.get" {
        return Err(format!(
            "clientDataJSON type is {:?}, not webauthn.get",
            cd.kind.chars().take(40).collect::<String>()
        ));
    }
    if !ct_eq(cd.challenge.as_bytes(), challenge.as_bytes()) {
        return Err("the challenge does not match".into());
    }
    if !origins.contains(&cd.origin) {
        return Err(format!(
            "the origin {:?} may not approve this way",
            cd.origin.chars().take(200).collect::<String>()
        ));
    }
    if cd.cross_origin {
        return Err("the passkey was asked for inside a cross-origin frame".into());
    }
    let ad = parse_auth_data(auth_data)?;
    if !ct_eq(&ad.rp_id_hash, &sha256(rp_id.as_bytes())) {
        return Err("the assertion is for another RP ID".into());
    }
    if ad.flags & FLAG_UP == 0 {
        return Err("the authenticator did not see the user (UP not set)".into());
    }
    if ad.flags & FLAG_UV == 0 {
        return Err("the authenticator did not verify the user (UV not set)".into());
    }
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&sha256(client_data));
    if !key.verify(&msg, signature) {
        return Err("the signature does not verify with the registered passkey".into());
    }
    Ok(Asserted {
        sign_count: ad.sign_count,
        origin: cd.origin,
    })
}

/// Stable per owner, without exposing their `sub`.
pub fn user_handle(sub: &str) -> String {
    b64url(&sha256(format!("warden-user:{sub}").as_bytes())[..16])
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Channel {
    Heimdall,
    Web,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Heimdall => "heimdall",
            Channel::Web => "web",
        }
    }

    fn origins(self, app: &App) -> Vec<String> {
        match (self, &app.cfg.webauthn) {
            (Channel::Heimdall, Some(w)) => w.heimdall_origins.clone(),
            (Channel::Web, Some(_)) => vec![app.cfg.public_origin()],
            (_, None) => Vec::new(),
        }
    }
}

/// `reason` is English, for the audit and the log; `message` is shown to the owner.
#[derive(Debug)]
pub struct Refusal {
    pub status: StatusCode,
    pub reason: String,
    pub message: String,
    /// Already audited by whoever refused, inside its transaction.
    pub recorded: bool,
}

fn refusal(status: StatusCode, reason: impl Into<String>, message: &str) -> Refusal {
    Refusal {
        status,
        reason: reason.into(),
        message: message.into(),
        recorded: false,
    }
}

fn internal(e: anyhow::Error) -> Refusal {
    tracing::error!(error = %e, "passkey: internal error");
    refusal(StatusCode::INTERNAL_SERVER_ERROR, "internal error", "Internal error in warden.")
}

#[derive(Deserialize, Debug, Clone)]
pub struct AssertionIn {
    #[serde(default)]
    pub credential_id: String,
    #[serde(default)]
    pub client_data: String,
    #[serde(default)]
    pub authenticator_data: String,
    #[serde(default)]
    pub signature: String,
}

pub fn unb64(s: &str, max: usize, what: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let s = s.trim_end_matches('=');
    if s.is_empty() || s.len() > max * 4 / 3 + 4 {
        return Err(format!("{what} is missing or too long"));
    }
    let b = URL_SAFE_NO_PAD.decode(s).map_err(|_| format!("{what} is not base64url"))?;
    if b.len() > max {
        return Err(format!("{what} is too long"));
    }
    Ok(b)
}

pub fn issue_approve_challenge(app: &App, request_id: &str, channel: Channel) -> Result<Value, Refusal> {
    let Some(w) = &app.cfg.webauthn else {
        return Err(refusal(
            StatusCode::NOT_FOUND,
            "passkey approval is not enabled",
            "The warden passkey is not enabled.",
        ));
    };
    let at = now();
    match app.store.request(request_id).map_err(internal)? {
        Some(r) if r.status_at(at) == "pending" => {}
        Some(r) => {
            return Err(refusal(
                StatusCode::CONFLICT,
                format!("the request is already {}", r.status_at(at)),
                &format!("The request is already {}.", crate::store::status_label(r.status_at(at))),
            ));
        }
        None => {
            return Err(refusal(StatusCode::NOT_FOUND, "no such request", "That request does not exist."));
        }
    }
    let passkeys = app.store.passkeys(&app.cfg.oidc.owner_sub).map_err(internal)?;
    if passkeys.is_empty() {
        return Err(refusal(
            StatusCode::CONFLICT,
            "no warden passkey is registered",
            "There is no warden passkey yet: register one in warden's panel, or approve with Pocket ID.",
        ));
    }
    let challenge = b64url(&random::<32>());
    let row = ChallengeRow {
        purpose: "approve".into(),
        request_id: Some(request_id.to_string()),
        channel: channel.as_str().into(),
        browser_hash: None,
        sub: None,
        created_at: at,
        expires_at: at + w.challenge_ttl_secs,
    };
    app.store.put_challenge(&challenge, &row, MAX_CHALLENGES).map_err(internal)?;
    Ok(json!({
        "challenge": challenge,
        "rp_id": w.rp_id,
        "allow": passkeys.iter().map(|p| p.credential_id.clone()).collect::<Vec<_>>(),
        "timeout_ms": w.challenge_ttl_secs * 1000,
        "user_verification": "required",
    }))
}

/// Failures are audited. Only one that spent a heimdall challenge (asked for with heimdall's token)
/// is audited without limit; the rest (web, or garbage before matching a challenge) goes through the
/// anonymous cap, since the caller has proven nothing yet and the audit can't be pruned.
pub fn approve_with_assertion(app: &App, request_id: &str, channel: Channel, a: &AssertionIn) -> Result<GrantRow, Refusal> {
    let mut passkey_id = None;
    let mut used_challenge = false;
    let result = check_and_approve(app, request_id, channel, a, &mut passkey_id, &mut used_challenge);
    if let Err(r) = &result {
        tracing::warn!(request = request_id, channel = channel.as_str(), reason = %r.reason, "passkey approval refused");
        if r.status != StatusCode::INTERNAL_SERVER_ERROR && !r.recorded {
            let detail = json!({"via": "passkey", "channel": channel.as_str(), "reason": r.reason, "passkey": passkey_id});
            let line = Audit::new(format!("passkey:{}", channel.as_str()), "approval.rejected", detail).request(request_id);
            if channel == Channel::Heimdall && used_challenge {
                if let Err(e) = app.store.audit(line, now()) {
                    tracing::error!(error = %e, "cannot write an audit line");
                }
            } else {
                app.audit_anonymous(line, now());
            }
        }
    }
    result
}

fn check_and_approve(
    app: &App,
    request_id: &str,
    channel: Channel,
    a: &AssertionIn,
    passkey_id: &mut Option<String>,
    used_challenge: &mut bool,
) -> Result<GrantRow, Refusal> {
    let Some(w) = &app.cfg.webauthn else {
        return Err(refusal(
            StatusCode::NOT_FOUND,
            "passkey approval is not enabled",
            "The warden passkey is not enabled.",
        ));
    };
    let bad = |reason: String| refusal(StatusCode::BAD_REQUEST, reason, "The passkey's answer does not have the expected shape.");
    let credential_id = unb64(&a.credential_id, CREDENTIAL_ID_MAX, "credential_id").map_err(bad)?;
    let client_data = unb64(&a.client_data, CLIENT_DATA_MAX, "client_data").map_err(bad)?;
    let auth_data = unb64(&a.authenticator_data, AUTH_DATA_MAX, "authenticator_data").map_err(bad)?;
    let signature = unb64(&a.signature, SIGNATURE_MAX, "signature").map_err(bad)?;
    let cd = parse_client_data(&client_data).map_err(bad)?;
    let denied = |reason: String| {
        refusal(
            StatusCode::FORBIDDEN,
            reason,
            "The passkey was not accepted for this request. Nothing has changed.",
        )
    };

    // The challenge is spent here, whatever the outcome.
    let at = now();
    let Some(ch) = app.store.take_challenge(&cd.challenge).map_err(internal)? else {
        return Err(denied("unknown or already used challenge".into()));
    };
    *used_challenge = ch.purpose == "approve" && ch.request_id.as_deref() == Some(request_id) && ch.channel == channel.as_str();
    if ch.purpose != "approve" {
        return Err(denied("the challenge was not issued to approve".into()));
    }
    if ch.request_id.as_deref() != Some(request_id) {
        return Err(denied("the challenge was issued for another request".into()));
    }
    if ch.channel != channel.as_str() {
        return Err(denied(format!("the challenge was issued for the {} path", ch.channel)));
    }
    if ch.expires_at <= at {
        return Err(denied("the challenge expired".into()));
    }
    let passkey = match app.store.passkey_by_credential(&b64url(&credential_id)).map_err(internal)? {
        Some(p) if p.revoked_at.is_none() => p,
        Some(p) => {
            *passkey_id = Some(p.id);
            return Err(denied("the passkey was revoked".into()));
        }
        None => return Err(denied("unknown passkey".into())),
    };
    *passkey_id = Some(passkey.id.clone());
    if passkey.sub != app.cfg.oidc.owner_sub {
        return Err(denied("the passkey belongs to another owner".into()));
    }
    let (key, _) = PublicKey::from_cose(&passkey.public_key).map_err(|e| internal(anyhow::anyhow!("stored passkey key: {e}")))?;
    let asserted = verify_assertion(&client_data, &auth_data, &signature, &key, &cd.challenge, &channel.origins(app), &w.rp_id).map_err(denied)?;
    let approval = Approval {
        sub: passkey.sub.clone(),
        auth_time: at,
        amr: vec!["webauthn".into(), "uv".into()],
        via: Via::Passkey {
            passkey_id: passkey.id.clone(),
            sign_count: asserted.sign_count,
            channel: channel.as_str().into(),
            origin: asserted.origin,
        },
    };
    match app.store.approve_request(request_id, &approval, at).map_err(internal)? {
        Ok(g) => {
            tracing::info!(request = request_id, grant = %g.id, passkey = %passkey.id, channel = channel.as_str(), "request approved with the warden passkey");
            app.changed();
            Ok(g)
        }
        // Already audited by approve_request (not pending, session ended, counter): just answer.
        Err(why) => Err(Refusal {
            status: StatusCode::CONFLICT,
            reason: "refused when granting (see the audit log)".into(),
            message: why,
            recorded: true,
        }),
    }
}

pub fn issue_register_challenge(app: &App, browser_hash: &str, sub: &str) -> anyhow::Result<String> {
    let at = now();
    let challenge = b64url(&random::<32>());
    let row = ChallengeRow {
        purpose: "register".into(),
        request_id: None,
        channel: Channel::Web.as_str().into(),
        browser_hash: Some(browser_hash.to_string()),
        sub: Some(sub.to_string()),
        created_at: at,
        expires_at: at + REGISTER_TTL,
    };
    app.store.put_challenge(&challenge, &row, MAX_CHALLENGES)?;
    Ok(challenge)
}

#[derive(Deserialize, Debug)]
pub struct RegistrationIn {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub credential_id: String,
    #[serde(default)]
    pub client_data: String,
    #[serde(default)]
    pub attestation: String,
}

pub fn clean_name(s: &str) -> String {
    let s: String = s
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '·' | '(' | ')'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let s: String = s.chars().take(40).collect();
    if s.is_empty() { "passkey".into() } else { s }
}

/// `browser` is the flow cookie that bound the OIDC login to this browser.
pub fn register(app: &App, browser: Option<&str>, r: &RegistrationIn) -> Result<PasskeyRow, Refusal> {
    let Some(w) = &app.cfg.webauthn else {
        return Err(refusal(StatusCode::NOT_FOUND, "passkeys are not enabled", "The warden passkey is not enabled."));
    };
    let bad = |reason: String| refusal(StatusCode::BAD_REQUEST, reason, "The browser's answer does not have the expected shape.");
    let credential_id = unb64(&r.credential_id, CREDENTIAL_ID_MAX, "credential_id").map_err(bad)?;
    let client_data = unb64(&r.client_data, CLIENT_DATA_MAX, "client_data").map_err(bad)?;
    let attestation = unb64(&r.attestation, ATTESTATION_MAX, "attestation").map_err(bad)?;
    let cd = parse_client_data(&client_data).map_err(bad)?;
    let denied = |reason: String| {
        refusal(
            StatusCode::FORBIDDEN,
            reason,
            "The passkey was not registered. Start again from the panel (with Pocket ID).",
        )
    };
    let Some(ch) = app.store.take_challenge(&cd.challenge).map_err(internal)? else {
        return Err(denied("unknown or already used challenge".into()));
    };
    if ch.purpose != "register" || ch.expires_at <= now() {
        return Err(denied("the registration challenge is not valid any more".into()));
    }
    let same_browser = match (browser, &ch.browser_hash) {
        (Some(b), Some(h)) => ct_eq(sha256_hex(b.as_bytes()).as_bytes(), h.as_bytes()),
        _ => false,
    };
    if !same_browser {
        return Err(denied("the registration was not started in this browser".into()));
    }
    let sub = ch.sub.unwrap_or_default();
    if sub != app.cfg.oidc.owner_sub {
        return Err(denied("the registration was not started by the owner".into()));
    }
    let new = verify_registration(&credential_id, &client_data, &attestation, &cd.challenge, &app.cfg.public_origin(), &w.rp_id).map_err(denied)?;
    let row = PasskeyRow {
        id: crate::util::new_id("psk"),
        credential_id: b64url(&new.credential_id),
        sub: sub.clone(),
        name: clean_name(&r.name),
        alg: new.alg,
        public_key: new.cose,
        sign_count: new.sign_count as i64,
        aaguid: new.aaguid,
        backup_eligible: new.backup_eligible,
        created_at: now(),
        last_used_at: None,
        revoked_at: None,
    };
    match app.store.add_passkey(&row, MAX_PASSKEYS, &format!("owner:{sub}"), now()).map_err(internal)? {
        Ok(()) => {
            tracing::info!(passkey = %row.id, alg = row.alg, "warden passkey registered");
            Ok(row)
        }
        Err(why) => Err(refusal(StatusCode::CONFLICT, "the passkey was not added (limit or already registered)", &why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testauthn::{Authenticator, cose_ec2};

    const RP: &str = "example.com";
    const HEIMDALL: &str = "https://heimdall.example.com";

    fn origins() -> Vec<String> {
        vec![HEIMDALL.to_string()]
    }

    fn pk(a: &Authenticator) -> PublicKey {
        PublicKey::from_cose(&a.cose()).unwrap().0
    }

    #[test]
    fn a_registration_is_checked_against_challenge_origin_rp_and_flags() {
        let auth = Authenticator::es256();
        let (cd, att) = auth.attest("chal", "https://warden.example.com", RP, FLAG_UP | FLAG_UV);
        let p = verify_registration(&auth.credential_id, &cd, &att, "chal", "https://warden.example.com", RP).unwrap();
        assert_eq!((p.alg, p.credential_id.clone()), (ES256, auth.credential_id.clone()));
        assert_eq!(PublicKey::from_cose(&p.cose).unwrap().0, pk(&auth));

        let reg = |cd: &[u8], att: &[u8], cid: &[u8], chal: &str, origin: &str, rp: &str| verify_registration(cid, cd, att, chal, origin, rp).unwrap_err();
        assert!(reg(&cd, &att, &auth.credential_id, "other", "https://warden.example.com", RP).contains("challenge"));
        assert!(reg(&cd, &att, &auth.credential_id, "chal", "https://heimdall.example.com", RP).contains("origin"));
        assert!(reg(&cd, &att, &auth.credential_id, "chal", "https://warden.example.com", "evil.com").contains("RP ID"));
        assert!(reg(&cd, &att, b"another id", "chal", "https://warden.example.com", RP).contains("credential id"));
        let (cd2, att2) = auth.attest("chal", "https://warden.example.com", RP, FLAG_UP);
        assert!(reg(&cd2, &att2, &auth.credential_id, "chal", "https://warden.example.com", RP).contains("UV"));
        let (cd3, _, _) = auth.assert("chal", "https://warden.example.com", RP, FLAG_UP | FLAG_UV, 1);
        assert!(reg(&cd3, &att, &auth.credential_id, "chal", "https://warden.example.com", RP).contains("webauthn.create"));
    }

    #[test]
    fn an_assertion_needs_our_origin_challenge_rp_uv_and_key() {
        for auth in [Authenticator::es256(), Authenticator::ed25519(), Authenticator::rs256()] {
            let key = pk(&auth);
            let (cd, ad, sig) = auth.assert("c1", HEIMDALL, RP, FLAG_UP | FLAG_UV, 7);
            let ok = verify_assertion(&cd, &ad, &sig, &key, "c1", &origins(), RP).unwrap();
            assert_eq!((ok.sign_count, ok.origin.as_str()), (7, HEIMDALL));

            let err = |cd: &[u8], ad: &[u8], sig: &[u8], key: &PublicKey, chal: &str| verify_assertion(cd, ad, sig, key, chal, &origins(), RP).unwrap_err();
            assert!(err(&cd, &ad, &sig, &key, "c2").contains("challenge"));
            let (cd_o, ad_o, sig_o) = auth.assert("c1", "https://evil.example.com", RP, FLAG_UP | FLAG_UV, 7);
            assert!(err(&cd_o, &ad_o, &sig_o, &key, "c1").contains("origin"));
            let (cd_r, ad_r, sig_r) = auth.assert("c1", HEIMDALL, "evil.com", FLAG_UP | FLAG_UV, 7);
            assert!(err(&cd_r, &ad_r, &sig_r, &key, "c1").contains("RP ID"));
            let (cd_u, ad_u, sig_u) = auth.assert("c1", HEIMDALL, RP, FLAG_UP, 7);
            assert!(err(&cd_u, &ad_u, &sig_u, &key, "c1").contains("UV"));
            let (cd_p, ad_p, sig_p) = auth.assert("c1", HEIMDALL, RP, FLAG_UV, 7);
            assert!(err(&cd_p, &ad_p, &sig_p, &key, "c1").contains("UP"));
            let other = pk(&Authenticator::es256());
            assert!(err(&cd, &ad, &sig, &other, "c1").contains("signature"));
            let mut ad2 = ad.clone();
            ad2[36] ^= 1;
            assert!(err(&cd, &ad2, &sig, &key, "c1").contains("signature"));
        }
        let auth = Authenticator::es256();
        let cd = json!({"type": "webauthn.get", "challenge": "c1", "origin": HEIMDALL, "crossOrigin": true})
            .to_string()
            .into_bytes();
        let ad = auth.auth_data(RP, FLAG_UP | FLAG_UV, 1);
        let sig = auth.sign(&ad, &cd);
        assert!(
            verify_assertion(&cd, &ad, &sig, &pk(&auth), "c1", &origins(), RP)
                .unwrap_err()
                .contains("cross-origin")
        );
    }

    #[test]
    fn only_known_keys_and_well_formed_data_are_read() {
        assert!(PublicKey::from_cose(&cose_ec2(&[1; 32], &[2; 32], ES256)).is_ok());
        assert!(PublicKey::from_cose(&cose_ec2(&[1; 32], &[2; 32], -35)).is_err(), "ES384 is not accepted");
        assert!(PublicKey::from_cose(&cose_ec2(&[1; 31], &[2; 32], ES256)).is_err());
        let mut trailing = cose_ec2(&[1; 32], &[2; 32], ES256);
        trailing.push(0);
        assert!(PublicKey::from_cose(&trailing).is_err());
        assert!(parse_auth_data(&[0; 36]).is_err());
        let mut ad = vec![0; 37];
        ad.push(1);
        assert!(parse_auth_data(&ad).is_err(), "trailing bytes");
        assert!(parse_client_data(b"{\"type\":\"webauthn.get\",\"challenge\":\"x\"}").is_err());
        assert!(unb64("", 10, "x").is_err());
        assert!(unb64("AAAA", 2, "x").is_err());
        assert!(unb64("A+/=", 10, "x").is_err());
        assert_eq!(unb64("AQI", 10, "x").unwrap(), vec![1, 2]);
        assert_eq!(clean_name("  Zoë's <b>phone</b>\n"), "Zoës bphoneb");
        assert_eq!(clean_name("<>"), "passkey");
    }
}
