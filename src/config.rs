// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! warden's config: a JSON file (`--config` or `WARDEN_CONFIG`). Secrets never go inline, only the
//! paths of the files that hold them.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Owner-facing: approvals, connections and the panel.
    pub browser_listen: String,
    /// For sessions (requests and the git and API proxy) and heimdall.
    pub api_listen: String,
    /// For both listeners. Without it, plain HTTP and loopback only.
    #[serde(default)]
    pub tls: Option<Tls>,
    /// The browser listener as the owner reaches it: OAuth redirects and the origin forms must carry.
    pub public_url: String,
    /// 32 bytes in base64 that encrypt the stored connections.
    pub master_key_file: PathBuf,
    /// Lets heimdall list pending requests and deny or revoke, never approve. Without it, that API is off.
    #[serde(default)]
    pub heimdall_token_file: Option<PathBuf>,
    pub oidc: OidcConfig,
    pub github: GithubConfig,
    /// warden keeps the claude.ai refresh token and hands each granted sandbox only a short-lived access
    /// token (claude.rs). Without it, the «claude» system is off.
    #[serde(default)]
    pub claude: Option<ClaudeConfig>,
    /// Google connection and the artifact presets sandboxes read through the registry proxy. Without it,
    /// the «gcp» system is off.
    #[serde(default)]
    pub gcp: Option<GcpConfig>,
    /// Sessions opened with a Nomad workload identity. Without it, only `warden mint-session`.
    #[serde(default)]
    pub nomad: Option<NomadConfig>,
    /// warden's own passkey, to approve from heimdall without going through the OIDC provider.
    #[serde(default)]
    pub webauthn: Option<WebauthnConfig>,
    #[serde(default)]
    pub limits: Limits,
    /// Hash of the last audit row written before the chain was signed, so warden can seal those rows
    /// (store.rs). Only for older databases; warden prints the value when it is missing.
    #[serde(default)]
    pub audit_legacy_head: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct WebauthnConfig {
    /// Must cover the hosts of `public_url` and every heimdall origin, or browsers refuse the passkey there.
    pub rp_id: String,
    /// Exact web origins, or `android:apk-key-hash:<base64url SHA-256 of the signing cert>` for the
    /// Android app, whose WebView asks for the passkey as the app (Digital Asset Links).
    #[serde(default)]
    pub heimdall_origins: Vec<String>,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_secs: i64,
}

fn default_challenge_ttl() -> i64 {
    120
}

/// Android's `clientDataJSON` origin prefix when an app asks for the passkey.
pub const ANDROID_APP_ORIGIN: &str = "android:apk-key-hash:";

/// Only unpadded base64url of 32 bytes, so each certificate has a single spelling.
fn android_app_origin(o: &str) -> bool {
    o.strip_prefix(ANDROID_APP_ORIGIN)
        .is_some_and(|h| URL_SAFE_NO_PAD.decode(h).is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(&b) == h))
}

fn under(host: &str, rp_id: &str) -> bool {
    host == rp_id || host.strip_suffix(rp_id).is_some_and(|h| h.ends_with('.'))
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Must match the discovery `issuer` and every ID token's `iss` exactly.
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    /// The only subject that can approve or connect.
    pub owner_sub: String,
    /// Max age of the login behind an approval (`auth_time`).
    #[serde(default = "default_max_auth_age")]
    pub max_auth_age_secs: i64,
    /// «phr» means a passkey login, not an emailed code. Empty: not checked.
    #[serde(default = "default_amr")]
    pub require_amr: String,
}

fn default_max_auth_age() -> i64 {
    120
}

fn default_amr() -> String {
    "phr".into()
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// An OAuth App with Device Flow enabled; the device flow needs no client secret.
    pub client_id: String,
    /// `workflow` is rejected: without it, files under `.github/workflows` cannot be created or changed.
    #[serde(default = "default_github_scopes")]
    pub scopes: Vec<String>,
    /// Anyone who sees the device code can enter it, so a token for another account is discarded.
    pub expected_login: String,
    /// Overridable for tests.
    #[serde(default = "default_github_web")]
    pub web_base: String,
    #[serde(default = "default_github_api")]
    pub api_base: String,
}

fn default_github_scopes() -> Vec<String> {
    vec!["repo".into()]
}

fn default_github_web() -> String {
    "https://github.com".into()
}

fn default_github_api() -> String {
    "https://api.github.com".into()
}

/// Claude Code's OAuth with PKCE (`/login` with a pasted code). Defaults are those of Claude Code
/// 2.1.311 (see claude.rs).
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClaudeConfig {
    #[serde(default = "default_claude_client_id")]
    pub client_id: String,
    #[serde(default = "default_claude_authorize")]
    pub authorize_url: String,
    #[serde(default = "default_claude_token")]
    pub token_url: String,
    /// Where claude.ai shows the code to copy.
    #[serde(default = "default_claude_redirect")]
    pub redirect_uri: String,
    #[serde(default = "default_claude_scopes")]
    pub scopes: Vec<String>,
    /// Account email and plan, stored with the token as Claude Code does.
    #[serde(default = "default_claude_profile")]
    pub profile_url: String,
    #[serde(default = "default_claude_user_agent")]
    pub user_agent: String,
    /// Empty: any account, and the panel shows which one connected.
    #[serde(default)]
    pub expected_email: String,
    #[serde(default = "default_claude_max_grant")]
    pub max_grant_secs: i64,
    /// Nomad tasks that may ask for it: the sandbox's keeper, not the sandbox itself, which could
    /// replay the keeper's request in a way the owner could not tell apart.
    #[serde(default = "default_claude_tasks")]
    pub tasks: Vec<String>,
}

fn default_claude_tasks() -> Vec<String> {
    vec!["keeper".into()]
}

fn default_claude_client_id() -> String {
    crate::claude::CLIENT_ID.into()
}

fn default_claude_authorize() -> String {
    crate::claude::AUTHORIZE_URL.into()
}

fn default_claude_token() -> String {
    crate::claude::TOKEN_URL.into()
}

fn default_claude_redirect() -> String {
    crate::claude::REDIRECT_URI.into()
}

fn default_claude_scopes() -> Vec<String> {
    crate::claude::SCOPES.iter().map(|s| s.to_string()).collect()
}

fn default_claude_profile() -> String {
    crate::claude::PROFILE_URL.into()
}

fn default_claude_user_agent() -> String {
    crate::claude::USER_AGENT.into()
}

fn default_claude_max_grant() -> i64 {
    30 * 24 * 3600
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GcpConfig {
    pub client_id: String,
    pub client_secret_file: PathBuf,
    #[serde(default = "default_gcp_authorize")]
    pub authorize_url: String,
    #[serde(default = "default_gcp_token")]
    pub token_url: String,
    #[serde(default = "default_gcp_tokeninfo")]
    pub tokeninfo_url: String,
    #[serde(default = "default_gcp_revoke")]
    pub revoke_url: String,
    #[serde(default = "default_gcp_scopes")]
    pub scopes: Vec<String>,
    /// The only account that can connect; every read is made as it.
    pub expected_email: String,
    #[serde(default = "default_gcp_max_grant")]
    pub max_grant_secs: i64,
    /// As in `claude.tasks`: the keeper, not the sandbox.
    #[serde(default = "default_claude_tasks")]
    pub tasks: Vec<String>,
    /// The only hosts the registry proxy reaches, with their protocol.
    #[serde(default = "default_gcp_registries")]
    pub registries: BTreeMap<String, crate::registry::Kind>,
    /// A registry's real origin when it is not `https://{host}` (tests).
    #[serde(default)]
    pub upstreams: BTreeMap<String, String>,
    /// A grant stores the preset's list as it was when requested, so editing the config never widens
    /// what was already granted.
    pub presets: BTreeMap<String, Preset>,
}

/// Artifacts are `host/project/repo/image` (docker), `host/project/repo/@scope/package` (npm) or
/// `host/vendor/package` (composer).
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    /// Shown to the owner on approval.
    #[serde(default)]
    pub description: String,
    pub artifacts: Vec<String>,
}

fn default_gcp_authorize() -> String {
    crate::google::AUTHORIZE_URL.into()
}

fn default_gcp_token() -> String {
    crate::google::TOKEN_URL.into()
}

fn default_gcp_tokeninfo() -> String {
    crate::google::TOKENINFO_URL.into()
}

fn default_gcp_revoke() -> String {
    crate::google::REVOKE_URL.into()
}

fn default_gcp_scopes() -> Vec<String> {
    crate::google::SCOPES.iter().map(|s| s.to_string()).collect()
}

fn default_gcp_max_grant() -> i64 {
    7 * 24 * 3600
}

fn default_gcp_registries() -> BTreeMap<String, crate::registry::Kind> {
    use crate::registry::Kind;
    BTreeMap::from([
        ("europe-docker.pkg.dev".to_string(), Kind::Docker),
        ("europe-west1-docker.pkg.dev".to_string(), Kind::Docker),
        ("europe-west1-npm.pkg.dev".to_string(), Kind::Npm),
    ])
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct NomadConfig {
    pub jwks_url: String,
    /// Only if Nomad's certificate is not publicly signed.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// The `aud` set by the job's `identity` block.
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Jobs in `namespace` that may open a session, including their `dispatch-…` and `periodic-…` children.
    pub jobs: Vec<String>,
    /// Allowed jobs in other namespaces, where the remaining jobs must not open sessions.
    #[serde(default)]
    pub other_namespaces: BTreeMap<String, Vec<String>>,
}

fn default_audience() -> String {
    "warden".into()
}

fn default_namespace() -> String {
    "default".into()
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_duration_secs: i64,
    pub request_ttl_secs: i64,
    pub session_ttl_secs: i64,
    pub owner_session_ttl_secs: i64,
    /// So one session cannot flood the owner's screen.
    pub max_pending_per_session: i64,
    /// Audited actions per session, per minute and over its lifetime (budget.rs): the audit log cannot
    /// be trimmed, so without a cap one session could grow it forever.
    pub session_audit_per_minute: u32,
    pub session_audit_max: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_duration_secs: 4 * 3600,
            request_ttl_secs: 15 * 60,
            session_ttl_secs: 12 * 3600,
            owner_session_ttl_secs: 8 * 3600,
            max_pending_per_session: 3,
            // 5/s over a minute and 30,000 over a 12 h session (~40/min): plenty for real work, and at
            // most ~12 MB of audit per session.
            session_audit_per_minute: 300,
            session_audit_max: 30_000,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read the config {}: {e}", path.display()))?;
        let cfg: Config = serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        cfg.check()?;
        Ok(cfg)
    }

    pub fn check(&self) -> anyhow::Result<()> {
        let public = url::Url::parse(&self.public_url).map_err(|e| anyhow::anyhow!("public_url «{}»: {e}", self.public_url))?;
        anyhow::ensure!(
            public.path() == "/" && public.query().is_none() && public.host_str().is_some(),
            "public_url must be just an origin, like https://warden.example.com"
        );
        let loopback = |addr: &str| addr.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback());
        anyhow::ensure!(
            self.tls.is_some() || (loopback(&self.browser_listen) && loopback(&self.api_listen)),
            "without «tls», warden only listens on 127.0.0.1: the session and heimdall tokens would cross the network in clear"
        );
        let public_loopback = matches!(public.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        anyhow::ensure!(public.scheme() == "https" || public_loopback, "public_url must be https (cookies are Secure)");
        // Over plain http, whoever sits on the path serves their own keys and mints logins or sessions
        let secure = |name: &str, raw: &str| -> anyhow::Result<()> {
            let u = url::Url::parse(raw).map_err(|e| anyhow::anyhow!("{name} «{raw}»: {e}"))?;
            let local = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
            anyhow::ensure!(u.scheme() == "https" || local, "{name} must be https");
            Ok(())
        };
        secure("oidc.issuer", &self.oidc.issuer)?;
        if let Some(n) = &self.nomad {
            secure("nomad.jwks_url", &n.jwks_url)?;
        }
        anyhow::ensure!(!self.oidc.owner_sub.trim().is_empty(), "oidc.owner_sub is empty: nobody could approve");
        anyhow::ensure!(
            !self.github.expected_login.trim().is_empty(),
            "github.expected_login is empty: any account that entered the device code would be connected"
        );
        anyhow::ensure!(
            !self.github.scopes.iter().any(|s| s.trim().eq_ignore_ascii_case("workflow")),
            "github.scopes cannot include «workflow»: a pushed workflow would run with the repository's secrets"
        );
        anyhow::ensure!(self.oidc.max_auth_age_secs > 0, "oidc.max_auth_age_secs must be positive");
        if let Some(h) = &self.audit_legacy_head {
            anyhow::ensure!(
                h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "audit_legacy_head must be the 64 lowercase hex digits warden prints"
            );
        }
        let l = &self.limits;
        anyhow::ensure!(
            l.max_duration_secs >= 60
                && l.request_ttl_secs >= 60
                && l.session_ttl_secs >= 60
                && l.max_pending_per_session >= 1
                && l.session_audit_per_minute >= 1
                && l.session_audit_max >= 10,
            "limits are too small"
        );
        if let Some(c) = &self.claude {
            for (what, u) in [
                ("authorize_url", &c.authorize_url),
                ("token_url", &c.token_url),
                ("redirect_uri", &c.redirect_uri),
                ("profile_url", &c.profile_url),
            ] {
                let parsed = url::Url::parse(u).map_err(|e| anyhow::anyhow!("claude.{what} «{u}»: {e}"))?;
                anyhow::ensure!(
                    parsed.scheme() == "https" || matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")),
                    "claude.{what} must be https: the code and the tokens go through it"
                );
            }
            anyhow::ensure!(
                !c.client_id.trim().is_empty() && !c.scopes.is_empty(),
                "claude.client_id and claude.scopes cannot be empty"
            );
            anyhow::ensure!(
                !c.tasks.is_empty() && c.tasks.iter().all(|t| !t.trim().is_empty()),
                "claude.tasks needs at least one task, none empty"
            );
            anyhow::ensure!(
                (3600..=90 * 24 * 3600).contains(&c.max_grant_secs),
                "claude.max_grant_secs must be between one hour and 90 days"
            );
        }
        if let Some(g) = &self.gcp {
            for (what, u) in [
                ("authorize_url", &g.authorize_url),
                ("token_url", &g.token_url),
                ("tokeninfo_url", &g.tokeninfo_url),
                ("revoke_url", &g.revoke_url),
            ] {
                let parsed = url::Url::parse(u).map_err(|e| anyhow::anyhow!("gcp.{what} «{u}»: {e}"))?;
                anyhow::ensure!(
                    parsed.scheme() == "https" || matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")),
                    "gcp.{what} must be https: the code and the tokens go through it"
                );
            }
            anyhow::ensure!(!g.client_id.trim().is_empty(), "gcp.client_id cannot be empty");
            anyhow::ensure!(
                g.expected_email.contains('@') && g.expected_email.trim() == g.expected_email,
                "gcp.expected_email must be the account that connects (an email)"
            );
            // A refresh token with broader scopes would be a bigger risk.
            for s in &g.scopes {
                anyhow::ensure!(
                    crate::google::SCOPES.contains(&s.as_str()),
                    "gcp.scopes «{s}» is not allowed: only {}",
                    crate::google::SCOPES.join(", ")
                );
            }
            anyhow::ensure!(
                g.scopes.iter().any(|s| s == crate::google::READ_SCOPE),
                "gcp.scopes must include {}",
                crate::google::READ_SCOPE
            );
            anyhow::ensure!(
                !g.tasks.is_empty() && g.tasks.iter().all(|t| !t.trim().is_empty()),
                "gcp.tasks needs at least one task, none empty"
            );
            anyhow::ensure!(
                (3600..=30 * 24 * 3600).contains(&g.max_grant_secs),
                "gcp.max_grant_secs must be between one hour and 30 days"
            );
            for host in g.registries.keys() {
                anyhow::ensure!(
                    crate::registry::valid_host(host),
                    "gcp.registries «{host}» must be a lowercase host name, without scheme, port or path"
                );
            }
            for (host, base) in &g.upstreams {
                anyhow::ensure!(g.registries.contains_key(host), "gcp.upstreams «{host}» is not in gcp.registries");
                let u = url::Url::parse(base).map_err(|e| anyhow::anyhow!("gcp.upstreams.{host} «{base}»: {e}"))?;
                anyhow::ensure!(
                    (u.scheme() == "https" || matches!(u.host_str(), Some("127.0.0.1" | "localhost"))) && u.path() == "/" && u.query().is_none(),
                    "gcp.upstreams.{host} must be an https origin (the token goes there)"
                );
            }
            for (name, p) in &g.presets {
                anyhow::ensure!(
                    crate::registry::valid_preset_name(name),
                    "gcp.presets «{name}»: a preset name is lowercase letters, digits and «-»"
                );
                anyhow::ensure!(!p.artifacts.is_empty(), "gcp.presets.{name} lists no artifact");
                for a in &p.artifacts {
                    crate::registry::Artifact::parse(a, &g.registries).map_err(|e| anyhow::anyhow!("gcp.presets.{name}: {e}"))?;
                }
            }
        }
        if let Some(n) = &self.nomad {
            anyhow::ensure!(!n.jobs.is_empty(), "nomad.jobs is empty: no job could open a session");
            for (ns, jobs) in &n.other_namespaces {
                anyhow::ensure!(!ns.trim().is_empty(), "nomad.other_namespaces has an empty namespace");
                anyhow::ensure!(
                    !jobs.is_empty() && jobs.iter().all(|j| !j.trim().is_empty()),
                    "nomad.other_namespaces.{ns} needs at least one job, none empty"
                );
            }
        }
        if let Some(w) = &self.webauthn {
            let rp = &w.rp_id;
            // Browsers treat «localhost» as a secure origin, so it is allowed for local testing only.
            let dev = rp == "localhost" && public.host_str() == Some("localhost");
            anyhow::ensure!(
                dev || (rp.contains('.')
                    && !rp.starts_with('.')
                    && !rp.ends_with('.')
                    && rp.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')),
                "webauthn.rp_id «{rp}» must be a lowercase domain like example.com"
            );
            anyhow::ensure!(
                public.host_str().is_some_and(|h| under(h, rp)) || public_loopback,
                "public_url is not under webauthn.rp_id «{rp}»: the browser would not use the passkey there"
            );
            for o in &w.heimdall_origins {
                // Tied to the RP ID by assetlinks.json on the domain, not by warden.
                if android_app_origin(o) {
                    continue;
                }
                let u = url::Url::parse(o).map_err(|e| anyhow::anyhow!("webauthn.heimdall_origins «{o}»: {e}"))?;
                anyhow::ensure!(
                    u.scheme() == "https" && u.origin().ascii_serialization() == *o && u.host_str().is_some_and(|h| under(h, rp)),
                    "webauthn.heimdall_origins «{o}» must be an https origin (no path, no trailing slash) under «{rp}», or android:apk-key-hash: and the base64url SHA-256 of an app's certificate"
                );
            }
            anyhow::ensure!(
                (30..=600).contains(&w.challenge_ttl_secs),
                "webauthn.challenge_ttl_secs must be between 30 and 600"
            );
        }
        Ok(())
    }

    pub fn public_origin(&self) -> String {
        self.public_url.trim_end_matches('/').to_string()
    }
}

pub fn read_secret(path: &Path, what: &str) -> anyhow::Result<String> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {what} from {}: {e}", path.display()))?;
    let s = s.trim().to_string();
    anyhow::ensure!(!s.is_empty(), "{what} in {} is empty", path.display());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(browser: &str, api: &str, public: &str, tls: bool) -> Config {
        let mut v = json!({"data_dir": "/d", "browser_listen": browser, "api_listen": api, "public_url": public, "master_key_file": "/k",
                           "oidc": {"issuer": "https://id.example", "client_id": "c", "client_secret_file": "/s", "owner_sub": "owner"},
                           "github": {"client_id": "g", "expected_login": "owner"}});
        if tls {
            v["tls"] = json!({"cert": "/c", "key": "/k"});
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn tokens_never_cross_the_network_in_clear() {
        assert!(cfg("127.0.0.1:1", "127.0.0.1:2", "http://127.0.0.1:1", false).check().is_ok());
        assert!(cfg("192.0.2.11:8780", "192.0.2.11:8781", "https://warden.example.com", true).check().is_ok());
        assert!(cfg("192.0.2.11:8780", "127.0.0.1:2", "https://warden.example.com", false).check().is_err());
        assert!(cfg("127.0.0.1:1", "0.0.0.0:8781", "http://127.0.0.1:1", false).check().is_err());
        assert!(cfg("192.0.2.11:8780", "192.0.2.11:8781", "http://warden.example.com", true).check().is_err());
        assert!(cfg("192.0.2.11:8780", "192.0.2.11:8781", "https://warden.example.com/x", true).check().is_err());
        let mut c = cfg("127.0.0.1:1", "127.0.0.1:2", "http://127.0.0.1:1", false);
        c.github.expected_login = " ".into();
        assert!(c.check().unwrap_err().to_string().contains("expected_login"));
    }

    /// The approval page promises that writes never change Actions workflows.
    #[test]
    fn the_github_connection_never_asks_for_workflow() {
        let mut c = cfg("127.0.0.1:1", "127.0.0.1:2", "http://127.0.0.1:1", false);
        assert!(c.check().is_ok());
        for scopes in [vec!["repo", "workflow"], vec!["repo", " Workflow "]] {
            c.github.scopes = scopes.iter().map(|s| s.to_string()).collect();
            assert!(c.check().unwrap_err().to_string().contains("workflow"), "{scopes:?}");
        }
    }

    #[test]
    fn the_passkey_domain_covers_warden_and_heimdall() {
        let with = |rp: &str, origins: &[&str]| {
            let mut c = cfg("192.0.2.11:8780", "192.0.2.11:8781", "https://warden.example.com", true);
            c.webauthn = Some(WebauthnConfig {
                rp_id: rp.into(),
                heimdall_origins: origins.iter().map(|s| s.to_string()).collect(),
                challenge_ttl_secs: 120,
            });
            c.check()
        };
        assert!(with("example.com", &["https://heimdall.example.com"]).is_ok());
        assert!(with("warden.example.com", &[]).is_ok());
        assert!(with("example.com", &["https://heimdall.example.com/"]).is_err(), "an origin, letter by letter");
        assert!(with("example.com", &["http://heimdall.example.com"]).is_err());
        assert!(with("example.com", &["https://heimdall.evil.com"]).is_err());
        assert!(with("example.com", &["https://evilexample.com"]).is_err());
        assert!(
            with("heimdall.example.com", &["https://heimdall.example.com"]).is_err(),
            "warden is not under it"
        );
        assert!(with("com", &[]).is_err());
        assert!(with("localhost", &[]).is_err(), "localhost only when warden itself is on localhost");
        assert!(with("Example.COM", &[]).is_err());
    }

    #[test]
    fn the_identity_provider_and_the_jwks_go_over_https() {
        let mut c = cfg("127.0.0.1:1", "127.0.0.1:2", "http://127.0.0.1:1", false);
        c.oidc.issuer = "http://id.example".into();
        assert!(c.check().unwrap_err().to_string().contains("oidc.issuer"));
        c.oidc.issuer = "http://127.0.0.1:9000".into();
        c.check().unwrap();
    }

    #[test]
    fn the_android_app_is_its_certificate_hash() {
        let with = |origins: &[&str]| {
            let mut c = cfg("192.0.2.11:8780", "192.0.2.11:8781", "https://warden.example.com", true);
            c.webauthn = Some(WebauthnConfig {
                rp_id: "example.com".into(),
                heimdall_origins: origins.iter().map(|s| s.to_string()).collect(),
                challenge_ttl_secs: 120,
            });
            c.check()
        };
        let app = "android:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu4";
        assert!(with(&["https://heimdall.example.com", app]).is_ok());
        assert!(with(&[app]).is_ok());
        assert!(with(&["android:apk-key-hash:"]).is_err(), "no hash");
        assert!(
            with(&["android:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu4="]).is_err(),
            "padding is another spelling"
        );
        assert!(
            with(&["android:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW/vg0yuO0GnHj6yiu4"]).is_err(),
            "base64url, not base64"
        );
        assert!(
            with(&["android:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu"]).is_err(),
            "not 32 bytes"
        );
        assert!(
            with(&["android:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu5"]).is_err(),
            "trailing bits make it another spelling"
        );
        assert!(
            with(&["android:apk-key-hash:cb757350fb1635c5ef2a6a341257e93731a6356fef834cae3b41a71e3eb28aee"]).is_err(),
            "hex is not the format"
        );
        assert!(with(&["android:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu4"]).is_err());
        assert!(with(&["ANDROID:apk-key-hash:y3VzUPsWNcXvKmo0ElfpNzGmNW_vg0yuO0GnHj6yiu4"]).is_err());
    }
}
