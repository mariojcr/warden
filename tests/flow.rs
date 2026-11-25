// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests against fake identity provider, GitHub, claude.ai, Google and registry servers
//! on 127.0.0.1.
#[path = "../src/testauthn.rs"]
mod testauthn;
#[path = "../src/testkey.rs"]
mod testkey;
#[path = "../src/testpack.rs"]
mod testpack;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use testauthn::Authenticator;
use testkey::{IDP_KEY_B64, OTHER_KEY_B64, jwk, sign};
use testpack::{Obj, ZERO_OID, commit_content, oid_of_commit, pack, push_body};
use warden::app::App;
use warden::config::Config;
use warden::util::now;

const CLIENT_ID: &str = "warden-test";
const OWNER: &str = "owner-sub-0001";
const GH_TOKEN: &str = "gho_TESTTOKEN_never_leaves_warden";
const RP_ID: &str = "example.com";
const HEIMDALL_ORIGIN: &str = "https://heimdall.example.com";
/// WebAuthn flags UP | UV, as set by an unlocked passkey.
const UP_UV: u8 = 0x01 | 0x04;

#[derive(Clone, Default)]
struct Idp {
    issuer: Arc<Mutex<String>>,
    /// code -> id_token
    codes: Arc<Mutex<HashMap<String, String>>>,
    exchanges: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

impl Idp {
    fn issuer(&self) -> String {
        self.issuer.lock().unwrap().clone()
    }

    fn issue(&self, code: &str, nonce: &str, patch: Value, key: &str) {
        let at = now();
        let mut claims = json!({"iss": self.issuer(), "aud": CLIENT_ID, "sub": OWNER, "nonce": nonce,
                                "iat": at, "exp": at + 300, "auth_time": at, "amr": ["phr"]});
        for (k, v) in patch.as_object().unwrap() {
            claims[k] = v.clone();
        }
        let token = sign(key, &json!({"alg": "RS256", "kid": "pocket"}), &claims);
        self.codes.lock().unwrap().insert(code.to_string(), token);
    }
}

async fn idp_discovery(State(idp): State<Idp>) -> Response {
    let i = idp.issuer();
    axum::Json(json!({"issuer": i, "authorization_endpoint": format!("{i}/authorize"),
                      "token_endpoint": format!("{i}/token"), "jwks_uri": format!("{i}/jwks")}))
    .into_response()
}

async fn idp_jwks() -> Response {
    axum::Json(json!({"keys": [jwk(IDP_KEY_B64, "pocket")]})).into_response()
}

async fn idp_token(State(idp): State<Idp>, headers: HeaderMap, body: Bytes) -> Response {
    let mut form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    form.insert("authorization".into(), auth);
    idp.exchanges.lock().unwrap().push(form.clone());
    match idp.codes.lock().unwrap().remove(form.get("code").map(String::as_str).unwrap_or("")) {
        Some(t) => axum::Json(json!({"id_token": t, "access_token": "x", "token_type": "Bearer"})).into_response(),
        None => (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response(),
    }
}

async fn nomad_jwks() -> Response {
    axum::Json(json!({"keys": [jwk(IDP_KEY_B64, "nomad-1")]})).into_response()
}

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: String,
    authorization: String,
    body_len: usize,
    /// False when warden cut the body short.
    complete: bool,
}

/// GitHub's expiring tokens (`offline_access`): each refresh token works once and renewing
/// returns a new pair.
#[derive(Default)]
struct Expiring {
    /// Issue expiring tokens to clients that ask for `offline_access`.
    on: bool,
    /// Defaults to 8 h.
    expires_in: Option<i64>,
    refresh: Option<String>,
    renewed: u32,
    requests: Vec<HashMap<String, String>>,
    /// "bad" answers `bad_refresh_token`, "down" a 502.
    refuse: Option<&'static str>,
    /// Reply delay for renewals; the refresh token is already spent by then, as on GitHub.
    delay_ms: u64,
}

#[derive(Clone, Default)]
struct Gh {
    seen: Arc<Mutex<Vec<Seen>>>,
    exp: Arc<Mutex<Expiring>>,
    /// /user answers 403 (rate limited), which says nothing about the token.
    user_limited: Arc<Mutex<bool>>,
    /// When set, any other access token gets a 401; issuing or renewing a token updates it.
    valid: Arc<Mutex<Option<String>>>,
    device_requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
    polls: Arc<Mutex<u32>>,
    login_as: Arc<Mutex<Option<String>>>,
    /// Commits the compare API reports as ahead of any base.
    ahead: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl Gh {
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn last(&self) -> Seen {
        self.seen.lock().unwrap().last().cloned().unwrap()
    }
    fn renewals(&self) -> Vec<HashMap<String, String>> {
        self.exp.lock().unwrap().requests.clone()
    }
    fn reject_current_token(&self) {
        *self.valid.lock().unwrap() = Some("gho_nobody_has_this".into());
    }
}

fn presented(authorization: &str) -> String {
    if let Some(t) = authorization.strip_prefix("Bearer ") {
        return t.to_string();
    }
    let basic = authorization.strip_prefix("Basic ").and_then(|b| STANDARD.decode(b).ok()).unwrap_or_default();
    String::from_utf8_lossy(&basic).split_once(':').map(|(_, t)| t.to_string()).unwrap_or_default()
}

fn basic(token: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("x-access-token:{token}")))
}

async fn gh_device_code(State(gh): State<Gh>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    gh.device_requests.lock().unwrap().push(form);
    *gh.polls.lock().unwrap() = 0;
    axum::Json(
        json!({"device_code": "dev-123", "user_code": "WDJB-MJHT", "verification_uri": "https://github.com/login/device",
                      "expires_in": 900, "interval": 0}),
    )
    .into_response()
}

async fn gh_access_token(State(gh): State<Gh>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
        return gh_refresh(gh, form).await;
    }
    let ok = form.get("grant_type").map(String::as_str) == Some("urn:ietf:params:oauth:grant-type:device_code")
        && form.get("device_code").map(String::as_str) == Some("dev-123")
        && form.get("client_id").map(String::as_str) == Some("gh-client")
        && !form.contains_key("client_secret");
    if !ok {
        return axum::Json(json!({"error": "incorrect_device_code"})).into_response();
    }
    let n = {
        let mut p = gh.polls.lock().unwrap();
        *p += 1;
        *p
    };
    if n < 2 {
        return axum::Json(json!({"error": "authorization_pending"})).into_response();
    }
    let offline = gh
        .device_requests
        .lock()
        .unwrap()
        .last()
        .is_some_and(|r| r.get("scope").is_some_and(|s| s.split(' ').any(|s| s == "offline_access")));
    {
        let mut valid = gh.valid.lock().unwrap();
        if valid.is_some() {
            *valid = Some(GH_TOKEN.into());
        }
    }
    let mut e = gh.exp.lock().unwrap();
    if !(e.on && offline) {
        return axum::Json(json!({"access_token": GH_TOKEN, "scope": "repo", "token_type": "bearer"})).into_response();
    }
    e.refresh = Some("ghr_REFRESH_0".into());
    axum::Json(
        json!({"access_token": GH_TOKEN, "scope": "repo", "token_type": "bearer", "expires_in": e.expires_in.unwrap_or(28800),
                      "refresh_token": "ghr_REFRESH_0", "refresh_token_expires_in": 15897600}),
    )
    .into_response()
}

/// The refresh token is spent on arrival, before the (possibly delayed) reply, as on GitHub.
async fn gh_refresh(gh: Gh, form: HashMap<String, String>) -> Response {
    let (answer, delay) = {
        let mut e = gh.exp.lock().unwrap();
        e.requests.push(form.clone());
        let ok = form.get("client_id").map(String::as_str) == Some("gh-client") && !form.contains_key("client_secret");
        let answer = match e.refuse {
            Some("down") => None,
            Some(_) => Some(json!({"error": "bad_refresh_token", "error_description": "The refresh token passed is incorrect or expired."})),
            None if !ok => Some(json!({"error": "incorrect_client_credentials"})),
            None if e.refresh.is_none() || form.get("refresh_token") != e.refresh.as_ref() => {
                Some(json!({"error": "bad_refresh_token", "error_description": "The refresh token passed is incorrect or expired."}))
            }
            None => {
                e.renewed += 1;
                let (access, refresh) = (format!("gho_RENEWED_{}", e.renewed), format!("ghr_REFRESH_{}", e.renewed));
                e.refresh = Some(refresh.clone());
                let mut valid = gh.valid.lock().unwrap();
                if valid.is_some() {
                    *valid = Some(access.clone());
                }
                Some(
                    json!({"access_token": access, "expires_in": e.expires_in.unwrap_or(28800), "refresh_token": refresh,
                            "refresh_token_expires_in": 15897600, "scope": "repo", "token_type": "bearer"}),
                )
            }
        };
        (answer, e.delay_ms)
    };
    tokio::time::sleep(Duration::from_millis(delay)).await;
    match answer {
        Some(v) => axum::Json(v).into_response(),
        None => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn gh_repo() -> Response {
    axum::Json(json!({"default_branch": "main"})).into_response()
}

async fn gh_compare(State(gh): State<Gh>, axum::extract::Path((_o, _r, spec)): axum::extract::Path<(String, String, String)>) -> Response {
    let head = spec.split("...").nth(1).unwrap_or("").to_string();
    // Slow on purpose, to leave time to revoke during the check.
    if head.starts_with("5555") {
        tokio::time::sleep(Duration::from_millis(600)).await;
        return axum::Json(json!({"status": "ahead"})).into_response();
    }
    if head.starts_with("dead") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let status = if gh.ahead.lock().unwrap().contains(&head) { "ahead" } else { "diverged" };
    axum::Json(json!({"status": status})).into_response()
}

async fn gh_pull(axum::extract::Path((o, r, n)): axum::extract::Path<(String, String, String)>) -> Response {
    let (repo, branch) = match n.as_str() {
        "1" => (format!("{o}/{r}"), "main"),
        "2" => (format!("{o}/{r}"), "feature"),
        _ => ("someone/fork".to_string(), "main"),
    };
    axum::Json(json!({"head": {"ref": branch, "repo": {"full_name": repo}}})).into_response()
}

async fn gh_user(State(gh): State<Gh>, headers: HeaderMap) -> Response {
    if *gh.user_limited.lock().unwrap() {
        return (StatusCode::FORBIDDEN, axum::Json(json!({"message": "API rate limit exceeded"}))).into_response();
    }
    let token = presented(headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""));
    let ok = match gh.valid.lock().unwrap().clone() {
        Some(v) => token == v,
        None => token == GH_TOKEN,
    };
    if ok {
        let login = gh.login_as.lock().unwrap().clone().unwrap_or_else(|| "owner-gh".into());
        axum::Json(json!({"login": login})).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn gh_any(State(gh): State<Gh>, req: Request) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let authorization = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = axum::body::to_bytes(req.into_body(), 64 << 20).await;
    let complete = body.is_ok();
    let body = body.unwrap_or_default();
    let token = presented(&authorization);
    gh.seen.lock().unwrap().push(Seen {
        method,
        path: path.clone(),
        query,
        authorization,
        body_len: body.len(),
        complete,
    });
    // Like GitHub's `installation` endpoint, which answers 401 to an OAuth token even when it is
    // valid.
    if path.ends_with("/installation") || gh.valid.lock().unwrap().as_ref().is_some_and(|v| *v != token) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({"message": "Bad credentials"}))).into_response();
    }
    if path.ends_with("/slow") {
        // Streamed slowly so a revocation lands mid-transfer.
        let chunks = futures_util::stream::unfold(0, |i| async move {
            if i >= 40 {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            Some((Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 1024])), i + 1))
        });
        return Response::builder().status(200).body(Body::from_stream(chunks)).unwrap();
    }
    if path.ends_with("/info/refs") {
        return Response::builder()
            .status(200)
            .header("content-type", "application/x-git-upload-pack-advertisement")
            .header("set-cookie", "gh_session=secret")
            .header("x-oauth-scopes", "repo")
            .header("x-ratelimit-remaining", "4999")
            .body(Body::from("001e# service=git-upload-pack\n0000"))
            .unwrap();
    }
    axum::Json(json!({"path": path, "received": body.len()})).into_response()
}

/// What GitHub Free answers for rulesets and branch rules on a private repo. Calls are recorded so
/// tests can assert warden never makes them.
async fn gh_rules_on_free(State(gh): State<Gh>, req: Request) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let authorization = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    gh.seen.lock().unwrap().push(Seen {
        method,
        path,
        query,
        authorization,
        body_len: 0,
        complete: true,
    });
    let said = json!({"message": "Upgrade to GitHub Pro or make this repository public to enable this feature.", "status": "403"});
    (StatusCode::FORBIDDEN, axum::Json(said)).into_response()
}

/// claude.ai OAuth as Claude Code uses it: codes bound to PKCE S256 and `state`, and single-use
/// refresh tokens.
#[derive(Default)]
struct ClaudeState {
    /// code -> (code_challenge, state, authorizing account's email)
    codes: HashMap<String, (String, String, String)>,
    bodies: Vec<Value>,
    refresh: Option<String>,
    issued: u32,
    expires_in: i64,
    /// "bad" answers `invalid_grant`, "down" a 502, "html" a 403 without JSON.
    refuse: Option<&'static str>,
    delay_ms: u64,
    /// (access token, account email) pairs the profile endpoint accepts.
    access: Vec<(String, String)>,
    /// An unrequested scope to add to the next response.
    extra_scope: Option<&'static str>,
}

#[derive(Clone, Default)]
struct ClaudeAi(Arc<Mutex<ClaudeState>>);

impl ClaudeAi {
    fn refreshes(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .bodies
            .iter()
            .filter(|b| b["grant_type"] == "refresh_token")
            .cloned()
            .collect()
    }
}

fn pair(st: &mut ClaudeState, email: &str) -> Value {
    st.issued += 1;
    let (access, refresh) = (format!("sk-ant-oat01-ACCESS_{}", st.issued), format!("sk-ant-ort01-REFRESH_{}", st.issued));
    st.refresh = Some(refresh.clone());
    st.access.push((access.clone(), email.to_string()));
    let extra = st.extra_scope.map(|s| format!(" {s}")).unwrap_or_default();
    json!({"token_type": "Bearer", "access_token": access, "refresh_token": refresh, "expires_in": st.expires_in,
           "scope": format!("user:inference user:profile user:sessions:claude_code user:mcp_servers user:file_upload{extra}"),
           "account": {"uuid": "acc-1", "email_address": email}, "organization": {"uuid": "org-1", "name": "personal"}})
}

async fn claude_token(State(c): State<ClaudeAi>, headers: HeaderMap, body: Bytes) -> Response {
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "application/json",
        "claude.ai's token endpoint takes JSON"
    );
    assert!(headers.get("user-agent").unwrap().to_str().unwrap().starts_with("claude-cli/"));
    let delay = {
        let mut st = c.0.lock().unwrap();
        st.bodies.push(v.clone());
        st.delay_ms
    };
    if v["client_id"] != "9d1c250a-e61b-44d9-88ed-5944d1962f5e" {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_client"}))).into_response();
    }
    match v["grant_type"].as_str() {
        Some("authorization_code") => {
            let mut st = c.0.lock().unwrap();
            let Some((challenge, state, email)) = st.codes.remove(v["code"].as_str().unwrap_or("")) else {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": "invalid_grant", "error_description": "unknown code"})),
                )
                    .into_response();
            };
            let verifier = v["code_verifier"].as_str().unwrap_or("");
            let s256 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(warden::util::sha256(verifier.as_bytes()));
            if s256 != challenge || v["state"] != state.as_str() || !v["redirect_uri"].as_str().unwrap_or("").ends_with("/oauth/code/callback") {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": "invalid_grant", "error_description": "PKCE, state or redirect_uri"})),
                )
                    .into_response();
            }
            axum::Json(pair(&mut st, &email)).into_response()
        }
        Some("refresh_token") => {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let mut st = c.0.lock().unwrap();
            // These fail before the refresh token is spent.
            match st.refuse {
                Some("down") => return StatusCode::BAD_GATEWAY.into_response(),
                Some("html") => return (StatusCode::FORBIDDEN, "<html>blocked</html>").into_response(),
                _ => {}
            }
            let valid = st.refuse.is_none() && st.refresh.is_some() && st.refresh.as_deref() == v["refresh_token"].as_str();
            if !valid {
                let said = format!("Refresh token {} is not valid", v["refresh_token"].as_str().unwrap_or(""));
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": "invalid_grant", "error_description": said})),
                )
                    .into_response();
            }
            axum::Json(pair(&mut st, "owner@home.example")).into_response()
        }
        _ => (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "unsupported_grant_type"}))).into_response(),
    }
}

async fn claude_profile(State(c): State<ClaudeAi>, headers: HeaderMap) -> Response {
    let token = presented(headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""));
    let email = c.0.lock().unwrap().access.iter().find(|(a, _)| *a == token).map(|(_, e)| e.clone());
    let Some(email) = email.filter(|_| headers.get("anthropic-beta").is_some()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    axum::Json(json!({"account": {"uuid": "acc-1", "email": email},
                      "organization": {"uuid": "org-1", "organization_type": "claude_max", "rate_limit_tier": "default_claude_max_20x"}}))
    .into_response()
}

async fn bind() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = format!("http://{}", l.local_addr().unwrap());
    (l, a)
}

fn spawn(l: tokio::net::TcpListener, r: Router) {
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
}

struct H {
    app: Arc<App>,
    browser: String,
    api: String,
    idp: Idp,
    gh: Gh,
    heimdall: String,
    http: reqwest::Client,
    claude: ClaudeAi,
}

async fn harness() -> H {
    harness_with(json!({})).await
}

/// `patch` replaces whole top-level config keys.
async fn harness_with(patch: Value) -> H {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("flow-{}", warden::util::new_id("t")));
    std::fs::create_dir_all(&dir).unwrap();
    let file = |name: &str, content: &str| {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    };
    let heimdall = warden::util::new_secret("hd");

    let idp = Idp::default();
    let (idp_l, idp_url) = bind().await;
    *idp.issuer.lock().unwrap() = idp_url.clone();
    spawn(
        idp_l,
        Router::new()
            .route("/.well-known/openid-configuration", get(idp_discovery))
            .route("/jwks", get(idp_jwks))
            .route("/token", post(idp_token))
            .route("/nomad/jwks", get(nomad_jwks))
            .with_state(idp.clone()),
    );
    let gh = Gh::default();
    let (gh_l, gh_url) = bind().await;
    spawn(
        gh_l,
        Router::new()
            .route("/login/device/code", post(gh_device_code))
            .route("/login/oauth/access_token", post(gh_access_token))
            .route("/user", get(gh_user))
            .route("/repos/{o}/{r}", get(gh_repo))
            .route("/repos/{o}/{r}/compare/{spec}", get(gh_compare))
            .route("/repos/{o}/{r}/pulls/{n}", get(gh_pull))
            .route("/repos/{o}/{r}/rulesets", axum::routing::any(gh_rules_on_free))
            .route("/repos/{o}/{r}/rulesets/{*rest}", axum::routing::any(gh_rules_on_free))
            .route("/repos/{o}/{r}/rules/{*rest}", axum::routing::any(gh_rules_on_free))
            .route("/applications/{cid}/token", delete(|| async { StatusCode::NO_CONTENT }))
            .fallback(gh_any)
            .with_state(gh.clone()),
    );

    let claude = ClaudeAi::default();
    claude.0.lock().unwrap().expires_in = 28800;
    let (claude_l, claude_url) = bind().await;
    spawn(
        claude_l,
        Router::new()
            .route("/v1/oauth/token", post(claude_token))
            .route("/api/oauth/profile", get(claude_profile))
            .with_state(claude.clone()),
    );

    let (browser_l, browser) = bind().await;
    let (api_l, api) = bind().await;
    let mut cfg = json!({
        "data_dir": dir.join("data"),
        "browser_listen": "127.0.0.1:1",
        "api_listen": "127.0.0.1:1",
        "public_url": browser,
        "master_key_file": file("master.key", &warden::crypto::new_master_key()),
        "heimdall_token_file": file("heimdall.token", &heimdall),
        "oidc": {"issuer": idp_url, "client_id": CLIENT_ID, "client_secret_file": file("oidc.secret", "oidc-secret"), "owner_sub": OWNER},
        "github": {"client_id": "gh-client", "expected_login": "owner-gh", "web_base": gh_url, "api_base": gh_url},
        "nomad": {"jwks_url": format!("{idp_url}/nomad/jwks"), "jobs": ["claude"], "other_namespaces": {"sandbox": ["sandbox-claude"]}},
        "webauthn": {"rp_id": RP_ID, "heimdall_origins": [HEIMDALL_ORIGIN]},
        "claude": {"authorize_url": format!("{claude_url}/oauth/authorize"), "token_url": format!("{claude_url}/v1/oauth/token"),
                   "redirect_uri": format!("{claude_url}/oauth/code/callback"), "profile_url": format!("{claude_url}/api/oauth/profile"),
                   "expected_email": "owner@home.example"},
    });
    for (k, v) in patch.as_object().unwrap() {
        cfg[k] = v.clone();
    }
    let cfg: Config = serde_json::from_value(cfg).unwrap();
    cfg.check().unwrap();
    let app = App::new(cfg).unwrap();
    spawn(browser_l, app.browser_router());
    spawn(api_l, app.api_router());
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H {
        app,
        browser,
        api,
        idp,
        gh,
        heimdall,
        http,
        claude,
    }
}

/// Cookies are kept by hand: the `__Host-` ones are Secure and these servers are plain http.
struct Browser {
    http: reqwest::Client,
    origin: String,
    cookies: HashMap<String, String>,
}

struct Page {
    status: StatusCode,
    location: String,
    body: String,
}

impl Browser {
    fn new(h: &H) -> Browser {
        Browser {
            http: h.http.clone(),
            origin: h.browser.clone(),
            cookies: HashMap::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    async fn read(&mut self, resp: reqwest::Response) -> Page {
        for v in resp.headers().get_all("set-cookie") {
            let s = v.to_str().unwrap();
            assert!(s.contains("Secure") && s.contains("HttpOnly"), "{s}");
            let (k, rest) = s.split_once('=').unwrap();
            let value = rest.split(';').next().unwrap();
            if s.contains("Max-Age=0") {
                self.cookies.remove(k)
            } else {
                self.cookies.insert(k.into(), value.into())
            };
        }
        let status = resp.status();
        let location = resp.headers().get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        Page {
            status,
            location,
            body: resp.text().await.unwrap(),
        }
    }

    async fn get(&mut self, url: &str) -> Page {
        let resp = self.http.get(url).header("cookie", self.cookie_header()).send().await.unwrap();
        self.read(resp).await
    }

    async fn post_json(&mut self, url: &str, body: &Value) -> Page {
        let resp = self
            .http
            .post(url)
            .header("cookie", self.cookie_header())
            .header("origin", &self.origin)
            .json(body)
            .send()
            .await
            .unwrap();
        self.read(resp).await
    }

    async fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Page {
        let resp = self
            .http
            .post(url)
            .header("cookie", self.cookie_header())
            .header("origin", &self.origin)
            .form(form)
            .send()
            .await
            .unwrap();
        self.read(resp).await
    }

    async fn post(&mut self, url: &str, csrf: &str) -> Page {
        let resp = self
            .http
            .post(url)
            .header("cookie", self.cookie_header())
            .header("origin", &self.origin)
            .form(&[("csrf", csrf)])
            .send()
            .await
            .unwrap();
        self.read(resp).await
    }
}

/// Sends the path byte for byte, since HTTP clients normalize `..`. Returns the status code.
async fn raw(base: &str, path: &str, auth: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).split(' ').nth(1).unwrap().parse().unwrap()
}

fn csrf_in(html: &str) -> String {
    let at = html.find("name=\"csrf\" value=\"").expect("a form with a csrf token") + "name=\"csrf\" value=\"".len();
    html[at..].split('"').next().unwrap().to_string()
}

fn csrf_in_any(html: &str) -> String {
    if html.contains("name=\"csrf\" value=\"") {
        csrf_in(html)
    } else {
        data_attr(html, "csrf")
    }
}

/// (authorize link, `flow` field, csrf) from the claude.ai connect page.
fn claude_page(html: &str) -> (String, String, String) {
    let at = html.find("<a href=\"").expect("the authorize link") + "<a href=\"".len();
    let authorize = html[at..].split('"').next().unwrap().replace("&amp;", "&");
    let at = html.find("name=\"flow\" value=\"").expect("the flow field") + "name=\"flow\" value=\"".len();
    let flow = html[at..].split('"').next().unwrap().to_string();
    (authorize, flow, csrf_in(html))
}

fn data_attr(html: &str, name: &str) -> String {
    let key = format!("data-{name}=\"");
    let at = html.find(&key).unwrap_or_else(|| panic!("no data-{name} in {html}")) + key.len();
    html[at..].split('"').next().unwrap().replace("&amp;", "&")
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url).unwrap().query_pairs().into_owned().collect()
}

/// Simulates the IdP login and callback; `patch` alters the ID token claims and `key` signs it.
async fn pocket_id(h: &H, b: &mut Browser, authorize: &str, patch: Value, key: &str) -> Page {
    let q = query(authorize);
    let code = warden::util::new_id("code");
    h.idp.issue(&code, &q["nonce"], patch, key);
    let back = format!("{}?code={code}&state={}&iss={}", q["redirect_uri"], q["state"], h.idp.issuer());
    b.get(&back).await
}

impl H {
    async fn session_as(&self, namespace: &str, job: &str, alloc: &str, task: &str) -> String {
        let at = now();
        let jwt = sign(
            IDP_KEY_B64,
            &json!({"alg": "RS256", "kid": "nomad-1"}),
            &json!({"aud": ["warden"], "iat": at, "nbf": at, "exp": at + 3600, "nomad_namespace": namespace, "nomad_job_id": job,
                    "nomad_allocation_id": alloc, "nomad_task": task}),
        );
        let r = self.http.post(format!("{}/api/sessions", self.api)).bearer_auth(jwt).send().await.unwrap();
        assert_eq!(r.status(), 201);
        let v: Value = r.json().await.unwrap();
        v["token"].as_str().unwrap().to_string()
    }

    /// `email` is the account that authorizes the code on claude.ai.
    async fn connect_claude_as(&self, b: &mut Browser, email: &str) -> Page {
        let p = b.get(&format!("{}/", self.browser)).await;
        if p.status == StatusCode::SEE_OTHER {
            let p = b.get(&format!("{}/login", self.browser)).await;
            let p = pocket_id(self, b, &p.location, json!({"auth_time": now() - 7200}), IDP_KEY_B64).await;
            assert_eq!(p.status, StatusCode::SEE_OTHER);
        }
        let p = b.get(&format!("{}/", self.browser)).await;
        assert!(p.body.contains("/connections/claude\""), "{}", p.body);
        let p = b.post(&format!("{}/connections/claude", self.browser), &csrf_in(&p.body)).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
        let q = query(&p.location);
        assert_eq!(
            (q["prompt"].as_str(), q["max_age"].as_str()),
            ("login", "0"),
            "connecting claude.ai asks for the passkey again"
        );
        let p = pocket_id(self, b, &p.location, json!({}), IDP_KEY_B64).await;
        assert_eq!(p.status, 200, "{}", p.body);
        let (authorize, flow, csrf) = claude_page(&p.body);
        let q = query(&authorize);
        let code = warden::util::new_id("code");
        self.claude
            .0
            .lock()
            .unwrap()
            .codes
            .insert(code.clone(), (q["code_challenge"].clone(), q["state"].clone(), email.to_string()));
        b.post_form(
            &format!("{}/connections/claude/code", self.browser),
            &[("csrf", &csrf), ("flow", &flow), ("code", &format!("{code}#{}", q["state"]))],
        )
        .await
    }

    async fn claude_token(&self, session: &str, have: Option<&str>) -> (u16, String) {
        let body = match have {
            Some(h) => json!({"have": h}),
            None => json!({}),
        };
        let r = self
            .http
            .post(format!("{}/api/claude/token", self.api))
            .bearer_auth(session)
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    async fn granted_claude(&self, b: &mut Browser, session: &str) -> String {
        let req = self
            .request(
                session,
                json!({"system": "claude", "powers": ["claude_session"], "duration": "720h", "reason": "Remote Control session node2 in a sandbox"}),
            )
            .await;
        assert_eq!((req["status"].as_str(), req["mode"].as_str()), (Some("pending"), Some("session")), "{req}");
        let id = req["id"].as_str().unwrap().to_string();
        let p = self.approve(b, &id, json!({})).await;
        assert_eq!(p.status, 200, "{}", p.body);
        assert!(p.body.contains("claude.ai") && p.body.contains("talks to Anthropic as you"), "{}", p.body);
        self.app.store.grant_for_request(&id).unwrap().unwrap().id
    }

    /// Makes the claude.ai token expire in `left` seconds, to trigger a renewal without waiting.
    fn age_claude(&self, left: i64) {
        let c = self.app.store.connection("claude").unwrap().unwrap();
        let plain = self.app.sealer.open(&c.sealed, warden::claude::AAD).unwrap();
        let renewed = warden::store::Renewed {
            sealed: self.app.sealer.seal(&plain, warden::claude::AAD),
            scopes: c.scopes.clone(),
            expires_at: Some(now() + left),
            refresh_expires_at: None,
        };
        let aged = warden::store::Audit::new("test", "test.aged", json!({}));
        assert!(self.app.store.renew_connection("claude", &c.sealed, &renewed, aged, now() - 7200).unwrap());
    }

    fn assert_no_claude_token_in_clear(&self) {
        let rows = format!("{:?}", self.events());
        assert!(!rows.contains("sk-ant-"), "a claude.ai token leaked into the audit");
        for f in std::fs::read_dir(&self.app.cfg.data_dir).unwrap() {
            let bytes = std::fs::read(f.unwrap().path()).unwrap();
            assert!(
                !bytes.windows(7).any(|w| w == b"sk-ant-"),
                "a claude.ai token is in clear in the database files"
            );
        }
    }

    async fn session(&self) -> String {
        let at = now();
        let jwt = sign(
            IDP_KEY_B64,
            &json!({"alg": "RS256", "kid": "nomad-1"}),
            &json!({"aud": ["warden"], "iat": at, "nbf": at, "exp": at + 3600, "nomad_namespace": "default", "nomad_job_id": "claude",
                    "nomad_allocation_id": "1a2b3c4d-1111-4222-8333-444455556666", "nomad_task": "claude"}),
        );
        let r = self.http.post(format!("{}/api/sessions", self.api)).bearer_auth(jwt).send().await.unwrap();
        assert_eq!(r.status(), 201);
        let v: Value = r.json().await.unwrap();
        assert_eq!(v["label"], "claude · 1a2b3c4d");
        v["token"].as_str().unwrap().to_string()
    }

    async fn request(&self, session: &str, body: Value) -> Value {
        let r = self
            .http
            .post(format!("{}/api/requests", self.api))
            .bearer_auth(session)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201);
        r.json().await.unwrap()
    }

    async fn connect_github(&self, b: &mut Browser) {
        let p = b.get(&format!("{}/", self.browser)).await;
        assert_eq!((p.status, p.location.as_str()), (StatusCode::SEE_OTHER, "/login"));
        let p = b.get(&format!("{}/login", self.browser)).await;
        assert!(!p.location.contains("prompt=login"), "entering the panel is a normal login");
        let p = pocket_id(self, b, &p.location, json!({"auth_time": now() - 7200}), IDP_KEY_B64).await;
        assert_eq!((p.status, p.location.as_str()), (StatusCode::SEE_OTHER, "/"));
        let p = b.get(&format!("{}/", self.browser)).await;
        assert_eq!(p.status, 200);
        assert!(p.body.contains("GitHub: not connected"));
        assert_eq!(
            self.device_connect(b, &csrf_in(&p.body)).await,
            "connected",
            "{:?}",
            self.gh.device_requests.lock().unwrap()
        );
        let req = self.gh.device_requests.lock().unwrap().last().cloned().unwrap();
        assert_eq!((req["client_id"].as_str(), req["scope"].as_str()), ("gh-client", "repo offline_access"));
        assert!(!req.contains_key("client_secret"));
    }

    /// Returns "connected", "wrong account", "still pending" or the page body.
    async fn device_connect(&self, b: &mut Browser, csrf: &str) -> String {
        let p = b.post(&format!("{}/connections/github", self.browser), csrf).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER);
        let q = query(&p.location);
        assert_eq!(
            (q["prompt"].as_str(), q["max_age"].as_str()),
            ("login", "0"),
            "connecting asks for the passkey again"
        );
        let p = pocket_id(self, b, &p.location, json!({}), IDP_KEY_B64).await;
        assert_eq!((p.status, p.location.as_str()), (StatusCode::SEE_OTHER, "/connections/github/device"));
        let p = b.get(&format!("{}/connections/github/device", self.browser)).await;
        assert!(
            p.body.contains("WDJB-MJHT") && p.body.contains("/login/device") && p.body.contains("example-org/sso"),
            "{}",
            p.body
        );
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let p = b.get(&format!("{}/connections/github/device", self.browser)).await;
            if p.body.contains("Connected as <b>owner-gh</b>") {
                return "connected".into();
            }
            if p.body.contains("Wrong account") {
                return "wrong account".into();
            }
            if !p.body.contains("WDJB-MJHT") {
                return p.body;
            }
        }
        "still pending".into()
    }

    /// Approves through the IdP with `patch` applied to the ID token claims.
    async fn approve(&self, b: &mut Browser, request: &str, patch: Value) -> Page {
        let p = b.get(&format!("{}/r/{request}", self.browser)).await;
        assert_eq!(p.status, 200);
        assert!(p.body.contains("Approve with passkey"));
        let p = b.post(&format!("{}/r/{request}/approve", self.browser), &csrf_in(&p.body)).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
        let q = query(&p.location);
        assert_eq!((q["prompt"].as_str(), q["max_age"].as_str()), ("login", "0"));
        assert_eq!(q["code_challenge_method"], "S256");
        pocket_id(self, b, &p.location, patch, IDP_KEY_B64).await
    }

    async fn git(&self, session: &str, method: reqwest::Method, path: &str) -> reqwest::Response {
        let basic = STANDARD.encode(format!("claude:{session}"));
        self.http
            .request(method, format!("{}/git/github.com/{path}", self.api))
            .header("authorization", format!("Basic {basic}"))
            .header("git-protocol", "version=2")
            .body(if path.ends_with("receive-pack") {
                "0000PACK-bytes".to_string()
            } else {
                String::new()
            })
            .send()
            .await
            .unwrap()
    }

    async fn push(&self, session: &str, repo: &str, body: Vec<u8>) -> reqwest::Response {
        let basic = STANDARD.encode(format!("claude:{session}"));
        self.http
            .post(format!("{}/git/github.com/{repo}.git/git-receive-pack", self.api))
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-git-receive-pack-request")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn rest_json(&self, session: &str, method: reqwest::Method, path: &str, body: &str) -> reqwest::Response {
        self.http
            .request(method, format!("{}/api/v3/{path}", self.api))
            .header("authorization", format!("token {session}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
    }

    async fn granted_write(&self, b: &mut Browser, session: &str, repo: &str, powers: Value) -> String {
        let req = self
            .request(
                session,
                json!({"system": "github", "scope": {"repos": [repo]}, "mode": "write", "powers": powers, "duration": "1h", "reason": "work on the branch"}),
            )
            .await;
        let id = req["id"].as_str().unwrap().to_string();
        let p = self.approve(b, &id, json!({})).await;
        assert_eq!(p.status, 200, "{}", p.body);
        self.app.store.grant_for_request(&id).unwrap().unwrap().id
    }

    fn pushes(&self) -> Vec<Seen> {
        self.gh
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path.ends_with("git-receive-pack"))
            .cloned()
            .collect()
    }

    async fn rest(&self, session: &str, method: reqwest::Method, path: &str) -> reqwest::Response {
        self.http
            .request(method, format!("{}/api/v3/{path}", self.api))
            .header("authorization", format!("token {session}"))
            .send()
            .await
            .unwrap()
    }

    async fn passkey_page(&self, b: &mut Browser, patch: Value) -> Page {
        let p = b.get(&format!("{}/", self.browser)).await;
        if p.status == StatusCode::SEE_OTHER {
            let p = b.get(&format!("{}/login", self.browser)).await;
            let p = pocket_id(self, b, &p.location, json!({"auth_time": now() - 7200}), IDP_KEY_B64).await;
            assert_eq!(p.status, StatusCode::SEE_OTHER);
        }
        let p = b.get(&format!("{}/", self.browser)).await;
        assert!(p.body.contains("warden passkey"), "{}", p.body);
        let p = b.post(&format!("{}/passkeys/new", self.browser), &csrf_in_any(&p.body)).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
        let q = query(&p.location);
        assert_eq!(
            (q["prompt"].as_str(), q["max_age"].as_str()),
            ("login", "0"),
            "adding a passkey asks for Pocket ID's again"
        );
        pocket_id(self, b, &p.location, patch, IDP_KEY_B64).await
    }

    async fn register_passkey(&self, b: &mut Browser, auth: &Authenticator, origin: &str) -> Page {
        let p = self.passkey_page(b, json!({})).await;
        assert_eq!(p.status, 200, "{}", p.body);
        let challenge = data_attr(&p.body, "challenge");
        assert_eq!(data_attr(&p.body, "rp"), RP_ID);
        let (cd, att) = auth.attest(&challenge, origin, RP_ID, UP_UV);
        let body = json!({"csrf": data_attr(&p.body, "csrf"), "name": "phone", "credential_id": b64(&auth.credential_id),
                          "client_data": b64(&cd), "attestation": b64(&att)});
        b.post_json(&format!("{}/passkeys/register", self.browser), &body).await
    }

    async fn heimdall_challenge(&self, request: &str) -> Value {
        let r = self
            .http
            .post(format!("{}/api/heimdall/requests/{request}/challenge", self.api))
            .bearer_auth(&self.heimdall)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        r.json().await.unwrap()
    }

    async fn heimdall_approve(&self, request: &str, credential_id: &[u8], (cd, ad, sig): (Vec<u8>, Vec<u8>, Vec<u8>)) -> (u16, Value) {
        let body = json!({"credential_id": b64(credential_id), "client_data": b64(&cd), "authenticator_data": b64(&ad), "signature": b64(&sig)});
        let r = self
            .http
            .post(format!("{}/api/heimdall/requests/{request}/approve", self.api))
            .bearer_auth(&self.heimdall)
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }

    fn status_of(&self, request: &str) -> String {
        self.app.store.request(request).unwrap().unwrap().status
    }

    fn last_rejection(&self) -> Value {
        self.events()
            .into_iter()
            .rev()
            .find(|r| r.event == "approval.rejected")
            .map(|r| r.detail)
            .unwrap_or(Value::Null)
    }

    fn events(&self) -> Vec<warden::store::AuditRow> {
        let mut rows = self.app.store.audit_tail(10_000).unwrap();
        rows.reverse();
        rows
    }

    fn assert_no_github_token_in_clear(&self) {
        let rows = format!("{:?}", self.events());
        for prefix in ["gho_", "ghr_"] {
            assert!(!rows.contains(prefix), "a GitHub token ({prefix}…) leaked into the audit");
        }
        for f in std::fs::read_dir(&self.app.cfg.data_dir).unwrap() {
            let bytes = std::fs::read(f.unwrap().path()).unwrap();
            for prefix in [b"gho_", b"ghr_"] {
                assert!(!bytes.windows(4).any(|w| w == prefix), "a GitHub token is in clear in the database files");
            }
        }
    }

    /// Connects GitHub with `set` applied to the fake, and returns a session with a write grant on
    /// owner/heimdall.
    async fn connected_with(&self, b: &mut Browser, set: impl FnOnce(&mut Expiring)) -> String {
        set(&mut self.gh.exp.lock().unwrap());
        *self.gh.valid.lock().unwrap() = Some(String::new());
        self.connect_github(b).await;
        let session = self.session().await;
        self.granted_write(b, &session, "owner/heimdall", json!([])).await;
        session
    }
}

#[tokio::test]
async fn request_approve_with_passkey_proxy_and_revoke_from_heimdall() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let sealed = h.app.store.connection("github").unwrap().unwrap().sealed;
    assert!(!String::from_utf8_lossy(&sealed).contains(GH_TOKEN));

    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": {"repos": ["owner/heimdall"]}, "mode": "write", "duration": "1h",
                                  "reason": "push the warden branch and open a PR"}),
        )
        .await;
    let id = req["id"].as_str().unwrap().to_string();
    assert_eq!(req["status"], "pending");

    let st: Value = h
        .http
        .get(format!("{}/api/heimdall/state", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["pending"][0]["id"], id.as_str());
    assert_eq!(st["pending"][0]["reason"], "push the warden branch and open a PR");
    assert_eq!(st["pending"][0]["session"], "claude · 1a2b3c4d");
    let nope = h.http.get(format!("{}/api/heimdall/state", h.api)).bearer_auth(&session).send().await.unwrap();
    assert_eq!(nope.status(), 401, "a session token is not heimdall's");

    let r = h
        .git(&session, reqwest::Method::GET, "owner/heimdall.git/info/refs?service=git-upload-pack")
        .await;
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("no active grant"));
    assert_eq!(h.gh.count(), 0);

    let waiting = {
        let (http, api, session, id) = (h.http.clone(), h.api.clone(), session.clone(), id.clone());
        tokio::spawn(async move {
            let r = http.get(format!("{api}/api/requests/{id}?wait=20")).bearer_auth(&session).send().await.unwrap();
            r.json::<Value>().await.unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let p = h.approve(&mut b, &id, json!({})).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert!(p.body.contains("Granted"), "{}", p.body);
    let done = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the long poll wakes up")
        .unwrap();
    assert_eq!(done["status"], "approved");
    let grant_id = done["grant"]["id"].as_str().unwrap().to_string();
    let ex = h.idp.exchanges.lock().unwrap().last().cloned().unwrap();
    assert!(ex["code_verifier"].len() >= 43);
    assert_eq!(ex["authorization"], format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:oidc-secret"))));

    let r = h
        .git(&session, reqwest::Method::GET, "owner/Heimdall.git/info/refs?service=git-upload-pack")
        .await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("set-cookie").is_none() && r.headers().get("x-oauth-scopes").is_none());
    assert_eq!(r.headers()["x-ratelimit-remaining"], "4999");
    let seen = h.gh.last();
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str(), seen.query.as_str()),
        ("GET", "/owner/Heimdall.git/info/refs", "service=git-upload-pack")
    );
    assert_eq!(seen.authorization, format!("Basic {}", STANDARD.encode(format!("x-access-token:{GH_TOKEN}"))));
    let c1 = commit_content(&[], "warden");
    let push = push_body(
        &[(ZERO_OID, &oid_of_commit(&c1), "refs/heads/warden")],
        Some(&pack(&[Obj::Plain(1, c1.clone())])),
    );
    let r = h.push(&session, "owner/heimdall", push.clone()).await;
    assert_eq!(r.status(), 200);
    let seen = h.gh.last();
    assert!(seen.complete && seen.body_len == push.len(), "a new branch goes through as it came");
    let r = h.rest(&session, reqwest::Method::POST, "repos/owner/heimdall/pulls").await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.gh.last().authorization, format!("Bearer {GH_TOKEN}"));

    let before = h.gh.count();
    for (m, p) in [
        (reqwest::Method::GET, "owner/project-a.git/info/refs?service=git-upload-pack"),
        (reqwest::Method::GET, "owner/heimdall/../other.git/info/refs?service=git-upload-pack"),
        (reqwest::Method::GET, "owner/heimdall%2F..%2Fother.git/info/refs?service=git-upload-pack"),
        (reqwest::Method::POST, "owner/heimdall.git/info/lfs/objects/batch"),
    ] {
        let r = h.git(&session, m.clone(), p).await;
        assert!(r.status().is_client_error(), "{m} {p}: {}", r.status());
    }
    for (m, p) in [
        (reqwest::Method::GET, "repos/owner/project-a/pulls"),
        (reqwest::Method::DELETE, "repos/owner/heimdall"),
        (reqwest::Method::POST, "repos/owner/heimdall/hooks"),
        (reqwest::Method::POST, "graphql"),
        (reqwest::Method::GET, "user"),
        (reqwest::Method::GET, "repos/owner/heimdall%2F..%2Fother/pulls"),
        // Even with write, nothing that can hold secrets (secret scanning, Actions variables, hook
        // deliveries) nor anything outside the allowed reads.
        (reqwest::Method::GET, "repos/owner/heimdall/secret-scanning/alerts"),
        (reqwest::Method::GET, "repos/owner/heimdall/actions/variables"),
        (reqwest::Method::GET, "repos/owner/heimdall/hooks/1/deliveries"),
        (reqwest::Method::GET, "repos/owner/heimdall/traffic/clones"),
    ] {
        let r = h.rest(&session, m.clone(), p).await;
        assert!(r.status().is_client_error(), "{m} {p}: {}", r.status());
    }
    // reqwest normalizes `..` and `%2e%2e` before sending, so only a raw socket really tests this.
    let basic = format!("Basic {}", STANDARD.encode(format!("claude:{session}")));
    for path in [
        "/git/github.com/owner/heimdall/../other.git/info/refs?service=git-upload-pack",
        "/api/v3/repos/owner/heimdall/contents/%2e%2e/%2e%2e/%2e%2e/user",
        "/api/v3/repos/owner/heimdall/contents/../../../../user",
    ] {
        assert_eq!(raw(&h.api, path, &basic).await, 400, "{path}");
    }
    assert_eq!(h.gh.count(), before, "nothing denied reached GitHub");
    // The Basic challenge makes git fall back to its credential helper.
    let r = h
        .http
        .get(format!("{}/git/github.com/owner/heimdall.git/info/refs?service=git-upload-pack", h.api))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Basic realm=\"warden\"");
    assert_eq!(
        h.git("wds_made_up", reqwest::Method::GET, "owner/heimdall.git/info/refs?service=git-upload-pack")
            .await
            .status(),
        401
    );

    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{grant_id}/revoke", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = h
        .git(&session, reqwest::Method::GET, "owner/heimdall.git/info/refs?service=git-upload-pack")
        .await;
    assert_eq!(r.status(), 403);
    assert_eq!(h.gh.count(), before);
    let st: Value = h
        .http
        .get(format!("{}/api/heimdall/state", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(st["pending"].as_array().unwrap().is_empty() && st["active"].as_array().unwrap().is_empty());

    let rows = h.events();
    let events: Vec<&str> = rows.iter().map(|r| r.event.as_str()).collect();
    for e in [
        "owner.login",
        "connection.connected",
        "session.created",
        "request.created",
        "request.approved",
        "grant.revoked",
    ] {
        assert!(events.contains(&e), "{e} in {events:?}");
    }
    let approved = rows.iter().find(|r| r.event == "request.approved").unwrap();
    assert_eq!(approved.actor, format!("owner:{OWNER}"));
    assert_eq!(approved.detail["amr"], json!(["phr"]));
    let proxied: Vec<_> = rows.iter().filter(|r| r.event == "proxy").collect();
    let allowed: Vec<_> = proxied.iter().filter(|r| r.detail["decision"] == "allowed").collect();
    assert_eq!(allowed.len(), 3);
    let push = allowed.iter().find(|r| r.detail["path"] == "/owner/heimdall.git/git-receive-pack").unwrap();
    assert_eq!(
        (push.detail["method"].as_str(), push.detail["repo"].as_str(), push.detail["status"].as_u64()),
        (Some("POST"), Some("owner/heimdall"), Some(200))
    );
    assert_eq!(push.grant_id.as_deref(), Some(grant_id.as_str()));
    let denied = proxied.iter().filter(|r| r.detail["decision"] == "denied").count();
    assert_eq!(denied, 1 + 4 + 10 + 3 + 2 + 1, "every refused proxy request is audited");
    let everything = format!("{rows:?}");
    for secret in [GH_TOKEN, session.as_str(), h.heimdall.as_str(), "oidc-secret", "gh-secret"] {
        assert!(!everything.contains(secret), "a secret leaked into the audit");
    }
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(rows.len()));
}

#[tokio::test]
async fn a_passkey_that_is_not_fresh_mine_and_for_this_flow_approves_nothing() {
    let h = harness().await;
    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "30m", "reason": "read the code"}),
        )
        .await;
    let id = req["id"].as_str().unwrap();
    let mut b = Browser::new(&h);
    for (patch, why) in [
        (json!({"auth_time": now() - 3600}), "before this approval"),
        (json!({"sub": "eve"}), "not the owner"),
        (json!({"aud": "another-client"}), "aud"),
        (json!({"iss": "https://id.evil.example"}), "issuer"),
        (json!({"nonce": "n-from-another-flow"}), "nonce"),
        (json!({"amr": ["otp"]}), "authentication method"),
    ] {
        let p = h.approve(&mut b, id, patch.clone()).await;
        assert_eq!(p.status, StatusCode::FORBIDDEN, "{patch}");
        let failed = h.events().into_iter().rev().find(|r| r.event == "approve.failed").unwrap();
        assert!(failed.detail["reason"].as_str().unwrap().contains(why), "{patch}: {}", failed.detail);
        assert_eq!(failed.request_id.as_deref(), Some(id));
    }
    let p = b.get(&format!("{}/r/{id}", h.browser)).await;
    let p = b.post(&format!("{}/r/{id}/approve", h.browser), &csrf_in(&p.body)).await;
    let p = pocket_id(&h, &mut b, &p.location, json!({}), OTHER_KEY_B64).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert_eq!(h.app.store.request(id).unwrap().unwrap().status, "pending");
    assert!(h.app.store.grant_for_request(id).unwrap().is_none());
}

#[tokio::test]
async fn approving_needs_our_page_and_the_same_browser() {
    let h = harness().await;
    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "write", "duration": "30m", "reason": "push a fix"}),
        )
        .await;
    let id = req["id"].as_str().unwrap();
    let mut a = Browser::new(&h);
    // With "no-referrer" browsers send `Origin: null` on our own POSTs; "same-origin" sends ours and
    // keeps the URL from other sites.
    let r = h.http.get(format!("{}/r/{id}", h.browser)).send().await.unwrap();
    assert_eq!(r.headers()["referrer-policy"], "same-origin");
    let p = a.get(&format!("{}/r/{id}", h.browser)).await;
    let csrf = csrf_in(&p.body);
    // Cross-site POSTs: no csrf token, or a foreign origin.
    let r = h
        .http
        .post(format!("{}/r/{id}/approve", h.browser))
        .header("cookie", a.cookie_header())
        .form(&[("csrf", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = h
        .http
        .post(format!("{}/r/{id}/approve", h.browser))
        .header("cookie", a.cookie_header())
        .header("origin", "https://heimdall.example.com")
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let p = a.post(&format!("{}/r/{id}/approve", h.browser), &csrf).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    let q = query(&p.location);
    h.idp.issue("code-1", &q["nonce"], json!({}), IDP_KEY_B64);
    let back = format!("{}?code=code-1&state={}", q["redirect_uri"], q["state"]);
    let mut other = Browser::new(&h);
    let p = other.get(&back).await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST);
    let failed = h.events().into_iter().rev().find(|r| r.event == "approve.failed").unwrap();
    assert!(failed.detail["reason"].as_str().unwrap().contains("another browser"));
    // The failed callback consumed the `state`, even for the right browser.
    let p = a.get(&back).await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST);
    assert!(p.body.contains("no longer valid"));
    assert_eq!(h.app.store.request(id).unwrap().unwrap().status, "pending");
    let p = h.approve(&mut a, id, json!({})).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert_eq!(h.app.store.request(id).unwrap().unwrap().status, "approved");
}

#[tokio::test]
async fn revoking_cuts_a_transfer_in_flight_and_expired_grants_do_not_pass() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "1h", "reason": "read a big file"}),
        )
        .await;
    let id = req["id"].as_str().unwrap();
    assert_eq!(h.approve(&mut b, id, json!({})).await.status, 200);
    let grant = h.app.store.grant_for_request(id).unwrap().unwrap();

    let r = h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/contents/slow").await;
    assert_eq!(r.status(), 200);
    let mut stream = r.bytes_stream();
    use futures_util::StreamExt;
    let first = stream.next().await.unwrap().unwrap();
    assert!(!first.is_empty());
    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{}/revoke", h.api, grant.id))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let mut got = first.len();
    let mut broke = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => got += c.len(),
            Err(_) => {
                broke = true;
                break;
            }
        }
    }
    assert!(broke && got < 40 * 1024, "the transfer was cut ({got} bytes)");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h.events().iter().any(|r| r.event == "proxy.cut" && r.detail["reason"] == "revoked"));

    // Approved two hours ago, for one hour.
    let at = now() - 7200;
    let s = h.app.store.session_by_token(&session, now()).unwrap().unwrap();
    let new = warden::scope::parse_request(
        &json!({"system": "github", "scope": "owner/old", "mode": "read", "duration": "1h", "reason": "an old grant"}),
        14400,
    )
    .unwrap();
    let old = h.app.store.create_request(&s, &new, 900, 3, at).unwrap().unwrap();
    let approval = warden::store::Approval {
        sub: OWNER.into(),
        auth_time: at,
        amr: vec!["phr".into()],
        via: warden::store::Via::PocketId,
    };
    h.app.store.approve_request(&old.id, &approval, at + 1).unwrap().unwrap();
    let before = h.gh.count();
    let r = h.git(&session, reqwest::Method::GET, "owner/old.git/info/refs?service=git-upload-pack").await;
    assert_eq!(r.status(), 403);
    assert_eq!(h.gh.count(), before);
}

#[tokio::test]
async fn sessions_come_only_from_the_allowed_job_and_see_only_their_own() {
    let h = harness().await;
    let at = now();
    let jwt = |claims: Value, key: &str| sign(key, &json!({"alg": "RS256", "kid": "nomad-1"}), &claims);
    let base = json!({"aud": ["warden"], "iat": at, "exp": at + 3600, "nomad_namespace": "default", "nomad_job_id": "claude",
                      "nomad_allocation_id": "aaaabbbb-0000", "nomad_task": "claude"});
    let with = |k: &str, v: Value| {
        let mut c = base.clone();
        c[k] = v;
        c
    };
    for (token, why) in [
        (jwt(with("nomad_job_id", json!("heimdall")), IDP_KEY_B64), "may not"),
        (jwt(with("aud", json!(["nomad.io"])), IDP_KEY_B64), "audience"),
        (jwt(base.clone(), OTHER_KEY_B64), "signature"),
    ] {
        let r = h.http.post(format!("{}/api/sessions", h.api)).bearer_auth(token).send().await.unwrap();
        assert_eq!(r.status(), 403);
        assert!(r.text().await.unwrap().contains(why), "{why}");
    }
    assert!(h.events().iter().filter(|r| r.event == "session.refused").count() == 3);

    let a = h.session().await;
    let b = h.session().await;
    h.session().await;
    // Same allocation as `h.session()`, which already opened three.
    let same_alloc = jwt(with("nomad_allocation_id", json!("1a2b3c4d-1111-4222-8333-444455556666")), IDP_KEY_B64);
    let r = h.http.post(format!("{}/api/sessions", h.api)).bearer_auth(same_alloc).send().await.unwrap();
    assert_eq!(r.status(), 429);
    let req = h
        .request(
            &a,
            json!({"system": "github", "scope": "o/r", "mode": "read", "duration": "10m", "reason": "look at it"}),
        )
        .await;
    let id = req["id"].as_str().unwrap();
    let r = h.http.get(format!("{}/api/requests/{id}", h.api)).bearer_auth(&b).send().await.unwrap();
    assert_eq!(r.status(), 404, "another session's request does not exist for b");
    let r = h.http.delete(format!("{}/api/requests/{id}", h.api)).bearer_auth(&b).send().await.unwrap();
    assert_eq!(r.status(), 404);
    // The shell helper posts a form instead of JSON.
    let r = h
        .http
        .post(format!("{}/api/requests", h.api))
        .bearer_auth(&a)
        .form(&[
            ("system", "github"),
            ("repo", "o/x,o/y"),
            ("mode", "write"),
            ("duration", "20m"),
            ("reason", "it's \"quoted\" & fine"),
            ("powers", "merge,force_push"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["repos"], json!(["o/x", "o/y"]));
    assert_eq!(v["reason"], "it's \"quoted\" & fine");
    assert_eq!(v["powers"], json!(["force_push", "merge"]));
}

#[tokio::test]
async fn nobody_without_a_token_can_fill_the_audit_log() {
    let h = harness().await;
    let start = now() / 60;
    for _ in 0..40 {
        let r = h
            .http
            .get(format!("{}/git/github.com/o/r.git/info/refs?service=git-upload-pack", h.api))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
    let minutes = (now() / 60 - start + 1) as usize;
    let anonymous = h.events().iter().filter(|r| r.actor == "anonymous").count();
    assert!(anonymous >= 1, "anonymous denials are still audited");
    // One cap per minute, and the loop may straddle a minute boundary.
    assert!(
        anonymous <= warden::app::ANONYMOUS_AUDIT_PER_MINUTE as usize * minutes,
        "{anonymous} anonymous rows"
    );
}

/// The audit log cannot be trimmed, so past its budget a session is refused (429) without doing
/// or logging anything.
#[tokio::test]
async fn a_session_cannot_fill_the_audit_log() {
    let max = 20;
    let h = harness_with(json!({"limits": {"session_audit_per_minute": 1000, "session_audit_max": max}})).await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "1h", "reason": "read the code"}),
        )
        .await;
    assert_eq!(h.approve(&mut b, req["id"].as_str().unwrap(), json!({})).await.status, 200);
    let session_id = h.app.store.session_by_token(&session, warden::util::now()).unwrap().unwrap().id;
    let rows = |h: &H| h.events().into_iter().filter(|r| r.session_id.as_deref() == Some(session_id.as_str())).count();
    let (mut ok, mut denied, mut spent) = (0, 0, None);
    for i in 0..(2 * max) {
        let path = if i % 2 == 0 {
            "repos/owner/heimdall/pulls"
        } else {
            "repos/owner/project-a/pulls"
        };
        let r = h.rest(&session, reqwest::Method::GET, path).await;
        match r.status().as_u16() {
            200 => ok += 1,
            403 => denied += 1,
            429 => {
                let msg: Value = r.json().await.unwrap();
                assert!(msg["message"].as_str().unwrap().contains("used up its 20 audited actions"), "{msg}");
                spent = Some(i);
                break;
            }
            s => panic!("unexpected {s}"),
        }
    }
    assert!(spent.is_some() && ok > 0 && denied > 0, "{ok} {denied} {spent:?}");
    let proxied = h
        .events()
        .into_iter()
        .filter(|r| r.event == "proxy" && r.session_id.as_deref() == Some(session_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        proxied.iter().filter(|r| r.detail["decision"] == "allowed").count(),
        ok,
        "every forwarded request has its line"
    );
    assert_eq!(proxied.iter().filter(|r| r.detail["decision"] == "denied").count(), denied);
    let (lines, seen) = (rows(&h), h.gh.count());
    assert!(lines <= max as usize + 2, "{lines} lines for a budget of {max}");
    for _ in 0..5 {
        assert_eq!(h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 429);
        assert_eq!(
            h.git(&session, reqwest::Method::GET, "owner/heimdall.git/info/refs?service=git-upload-pack")
                .await
                .status(),
            429
        );
        let r = h
            .http
            .post(format!("{}/api/requests", h.api))
            .bearer_auth(&session)
            .json(&json!({"system": "github", "scope": "o/r", "mode": "read", "duration": "1h", "reason": "read the code"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 429);
    }
    assert_eq!((rows(&h), h.gh.count()), (lines, seen), "nothing done and nothing written");
    assert_eq!(h.events().iter().filter(|r| r.event == "audit.budget_exhausted").count(), 1);
    // 403 (no grant), not 429: budgets are per session.
    let other = h.session().await;
    assert_eq!(h.rest(&other, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 403);
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(h.events().len()));
}

/// Without a challenge to tie them to, they fall under the anonymous audit cap.
#[tokio::test]
async fn garbage_signatures_through_heimdall_do_not_fill_the_audit_log() {
    let h = harness().await;
    let start = now() / 60;
    let junk = json!({"credential_id": "QQ", "client_data": "e30", "authenticator_data": "QQ", "signature": "QQ"});
    for _ in 0..40 {
        let r = h
            .http
            .post(format!("{}/api/heimdall/requests/req_AAAAAAAAAAAAAAAAAAAAAA/approve", h.api))
            .bearer_auth(&h.heimdall)
            .json(&junk)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }
    let minutes = (now() / 60 - start + 1) as usize;
    let rows = h.events().iter().filter(|r| r.event == "approval.rejected").count();
    assert!(rows >= 1, "they are still audited");
    assert!(rows <= warden::app::ANONYMOUS_AUDIT_PER_MINUTE as usize * minutes, "{rows} rows");
}

/// Plain write cannot touch the default branch, force push (even as delete plus create), merge or
/// approve: each needs a grant that names the power.
#[tokio::test]
async fn a_write_grant_does_not_undo_work_unless_the_request_named_that_power() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let session = h.session().await;
    let plain = h.granted_write(&mut b, &session, "owner/heimdall", json!([])).await;
    let repo = "owner/heimdall";
    let old = "a".repeat(40);
    let one = |parent: &str, msg: &str| {
        let c = commit_content(&[parent], msg);
        (oid_of_commit(&c), pack(&[Obj::Plain(1, c)]))
    };
    let status = |r: reqwest::Response| async move {
        let s = r.status().as_u16();
        (s, r.text().await.unwrap())
    };

    // Fast-forward: the pack's commit has the old tip as parent.
    let (new, p) = one(&old, "one more");
    let (s, t) = status(h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p))).await).await;
    assert_eq!(s, 200, "{t}");
    assert!(h.pushes().last().unwrap().complete);
    // Fast-forward proven by GitHub's compare API.
    let known = "b".repeat(40);
    h.gh.ahead.lock().unwrap().insert(known.clone());
    let (new, p) = one(&known, "on top of a commit GitHub has");
    assert_eq!(
        h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p)))
            .await
            .status(),
        200
    );
    let whole = |h: &H| h.pushes().iter().filter(|p| p.complete).count();
    let before = whole(&h);

    // Not a fast-forward: the pack streams almost whole, but its checksum is withheld.
    let (new, p) = one(&"c".repeat(40), "rewritten history");
    let (s, t) = status(h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p))).await).await;
    assert_eq!(s, 403);
    assert!(t.contains("force_push"), "{t}");
    // git ignores a `parent` line after `author`.
    let sneaky = format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 1700000000 +0000\nparent {old}\ncommitter A <a@b> 1700000000 +0000\n\nno history\n"
    )
    .into_bytes();
    let sneaky_push = push_body(&[(&old, &oid_of_commit(&sneaky), "refs/heads/feature")], Some(&pack(&[Obj::Plain(1, sneaky)])));
    assert_eq!(h.push(&session, repo, sneaky_push).await.status(), 403);
    // Force push with no new objects.
    let empty = pack(&[]);
    let (s, _) = status(
        h.push(&session, repo, push_body(&[(&old, &"d".repeat(40), "refs/heads/feature")], Some(&empty)))
            .await,
    )
    .await;
    assert_eq!(s, 403);
    // Thin pack: the commit is neither in the push nor on GitHub, so it cannot be checked.
    let ghost = format!("dead{}", "0".repeat(36));
    let (s, t) = status(h.push(&session, repo, push_body(&[(&old, &ghost, "refs/heads/feature")], Some(&empty))).await).await;
    assert_eq!(s, 403);
    assert!(t.contains("--no-thin"), "{t}");
    // Force push disguised as delete plus create in the same push.
    let (new, p) = one(&"e".repeat(40), "unrelated history");
    let disguised = push_body(&[(&old, ZERO_OID, "refs/heads/feature"), (ZERO_OID, &new, "refs/heads/feature")], Some(&p));
    let (s, t) = status(h.push(&session, repo, disguised.clone()).await).await;
    assert_eq!(s, 403);
    assert!(t.contains("force_push"), "{t}");
    assert_eq!(
        h.push(&session, repo, push_body(&[(old.as_str(), ZERO_OID, "refs/heads/feature")], None))
            .await
            .status(),
        403
    );
    // A tag push can trigger a release workflow (`on: push: tags`) with this branch's code and the
    // repo's secrets.
    let tag_pushes: Vec<Vec<(&str, &str, &str)>> = vec![
        vec![(ZERO_OID, old.as_str(), "refs/tags/v9.9.9")],
        vec![(ZERO_OID, old.as_str(), "refs/heads/release"), (ZERO_OID, old.as_str(), "refs/tags/v9.9.9")],
        vec![(old.as_str(), "f".repeat(40).leak() as &str, "refs/tags/v1")],
        vec![(old.as_str(), ZERO_OID, "refs/tags/v1")],
    ];
    for cmds in &tag_pushes {
        let (s, t) = status(h.push(&session, repo, push_body(cmds, Some(&empty))).await).await;
        assert_eq!(s, 403, "{cmds:?}");
        assert!(t.contains("tags"), "{t}");
    }
    let (new, p) = one(&old, "straight to main");
    for branch in ["refs/heads/main", "refs/heads/MAIN"] {
        let (s, t) = status(h.push(&session, repo, push_body(&[(&old, &new, branch)], Some(&p))).await).await;
        assert_eq!(s, 403);
        assert!(t.contains("default_branch"), "{t}");
    }
    assert_eq!(whole(&h), before, "no refused push reached GitHub whole");

    let api = reqwest::Method::PUT;
    let sha = "a".repeat(40);
    for (m, path, body, want) in [
        (api.clone(), "repos/owner/heimdall/pulls/3/merge", "{}".to_string(), 403),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews",
            r#"{"event":"APPROVE"}"#.into(),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews",
            r#"{"event":"Approve"}"#.into(),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews/7/events",
            r#"{"event":"APPROVE"}"#.into(),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews",
            r#"{"event":"COMMENT","event":"APPROVE"}"#.into(),
            400,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews",
            r#"{"event":"COMMENT","body":"looks fine"}"#.into(),
            200,
        ),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/heads/feature",
            format!(r#"{{"sha":"{sha}","force":true}}"#),
            403,
        ),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/heads/feature",
            format!(r#"{{"sha":"{sha}","force":"yes"}}"#),
            403,
        ),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/heads/feature",
            format!(r#"{{"sha":"{sha}","force":false}}"#),
            200,
        ),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/heads/ma%69n",
            format!(r#"{{"sha":"{sha}"}}"#),
            403,
        ),
        (reqwest::Method::DELETE, "repos/owner/heimdall/git/refs/heads/feature", String::new(), 403),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/tags/v1",
            format!(r#"{{"sha":"{sha}","force":false}}"#),
            403,
        ),
        (reqwest::Method::DELETE, "repos/owner/heimdall/git/refs/tags/v1", String::new(), 403),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/git/refs",
            format!(r#"{{"ref":"refs/heads/main","sha":"{sha}"}}"#),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/git/refs",
            format!(r#"{{"ref":"refs/replace/{sha}","sha":"{sha}"}}"#),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/git/refs",
            format!(r#"{{"ref":"refs/tags/v2","sha":"{sha}"}}"#),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/git/refs",
            format!(r#"{{"ref":"refs/heads/release","sha":"{sha}"}}"#),
            200,
        ),
        (
            api.clone(),
            "repos/owner/heimdall/contents/README.md",
            r#"{"message":"x","content":"eA=="}"#.into(),
            403,
        ),
        (
            api.clone(),
            "repos/owner/heimdall/contents/README.md",
            r#"{"message":"x","content":"eA==","branch":"Main"}"#.into(),
            403,
        ),
        (
            api.clone(),
            "repos/owner/heimdall/contents/README.md",
            r#"{"message":"x","content":"eA==","branch":"feature"}"#.into(),
            200,
        ),
        (
            api.clone(),
            "repos/owner/heimdall/contents/README.md",
            r#"{"message":"x","content":"eA==","branch":" "}"#.into(),
            403,
        ),
        (
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews?event=APPROVE",
            r#"{"event":"COMMENT"}"#.into(),
            400,
        ),
        // `update-branch` writes to the PR's head: PR 1 is on main, 2 on a work branch, 4 on a fork.
        (api.clone(), "repos/owner/heimdall/pulls/1/update-branch", "{}".into(), 403),
        (api.clone(), "repos/owner/heimdall/pulls/2/update-branch", "{}".into(), 200),
        (api.clone(), "repos/owner/heimdall/pulls/4/update-branch", "{}".into(), 403),
        (reqwest::Method::POST, "repos/owner/heimdall/actions/runs/9/rerun", "{}".into(), 403),
        (reqwest::Method::POST, "repos/owner/heimdall/actions/runs/9/rerun-failed-jobs", "{}".into(), 403),
        (reqwest::Method::POST, "repos/owner/heimdall/actions/jobs/9/rerun", "{}".into(), 403),
        (reqwest::Method::POST, "repos/owner/heimdall/actions/runs/9/cancel", "{}".into(), 200),
    ] {
        let r = h.rest_json(&session, m.clone(), path, &body).await;
        assert_eq!(r.status().as_u16(), want, "{m} {path} {body}");
    }

    let all = h
        .granted_write(&mut b, &session, repo, json!(["force_push", "merge", "approve", "default_branch", "rerun"]))
        .await;
    assert_ne!(all, plain);
    assert_eq!(
        h.rest_json(&session, reqwest::Method::POST, "repos/owner/heimdall/actions/runs/9/rerun", "{}")
            .await
            .status(),
        200
    );
    let (new, p) = one(&"c".repeat(40), "rewritten history");
    assert_eq!(
        h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p)))
            .await
            .status(),
        200
    );
    assert!(h.pushes().last().unwrap().complete);
    assert_eq!(h.push(&session, repo, disguised).await.status(), 200);
    let (new, p) = one(&old, "straight to main");
    assert_eq!(
        h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/main")], Some(&p))).await.status(),
        200
    );
    assert_eq!(
        h.rest_json(&session, api.clone(), "repos/owner/heimdall/pulls/3/merge", "{}").await.status(),
        200
    );
    assert_eq!(
        h.rest_json(&session, api.clone(), "repos/owner/heimdall/pulls/1/update-branch", "{}")
            .await
            .status(),
        200
    );
    assert_eq!(
        h.rest_json(&session, api.clone(), "repos/owner/heimdall/pulls/4/update-branch", "{}")
            .await
            .status(),
        403,
        "a fork is never in the grant"
    );
    assert_eq!(
        h.rest_json(
            &session,
            reqwest::Method::POST,
            "repos/owner/heimdall/pulls/3/reviews",
            r#"{"event":"APPROVE"}"#
        )
        .await
        .status(),
        200
    );
    let forced = h
        .events()
        .into_iter()
        .rev()
        .find(|r| r.event == "proxy" && r.detail["decision"] == "allowed" && r.detail["powers"] == json!(["approve"]))
        .unwrap();
    assert_eq!(forced.grant_id.as_deref(), Some(all.as_str()), "the grant that has the power is the one used");
    // No other power implies `tags`.
    for cmds in &tag_pushes {
        assert_eq!(h.push(&session, repo, push_body(cmds, Some(&empty))).await.status(), 403, "{cmds:?}");
    }
    let tag_ref = format!(r#"{{"ref":"refs/tags/v2","sha":"{sha}"}}"#);
    assert_eq!(
        h.rest_json(&session, reqwest::Method::POST, "repos/owner/heimdall/git/refs", &tag_ref)
            .await
            .status(),
        403
    );
    let tagging = h.granted_write(&mut b, &session, repo, json!(["tags"])).await;
    for cmds in &tag_pushes {
        assert_eq!(h.push(&session, repo, push_body(cmds, Some(&empty))).await.status(), 200, "{cmds:?}");
    }
    let tagged = h
        .events()
        .into_iter()
        .rev()
        .find(|r| r.event == "proxy" && r.detail["decision"] == "allowed" && r.detail["powers"] == json!(["tags"]))
        .unwrap();
    assert_eq!(tagged.grant_id.as_deref(), Some(tagging.as_str()));
    for (m, path, body) in [
        (reqwest::Method::POST, "repos/owner/heimdall/git/refs", tag_ref.clone()),
        (
            reqwest::Method::PATCH,
            "repos/owner/heimdall/git/refs/tags/v1",
            format!(r#"{{"sha":"{sha}","force":true}}"#),
        ),
        (reqwest::Method::DELETE, "repos/owner/heimdall/git/refs/tags/v1", String::new()),
    ] {
        assert_eq!(h.rest_json(&session, m.clone(), path, &body).await.status(), 200, "{m} {path}");
    }

    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": {"repos": [repo]}, "mode": "write", "powers": ["merge"], "duration": "1h", "reason": "merge the PR"}),
        )
        .await;
    assert_eq!(req["powers"], json!(["merge"]));
    let page = b.get(&format!("{}/r/{}", h.browser, req["id"].as_str().unwrap())).await;
    assert!(
        page.body.contains("asks for powers") && page.body.contains("Merge pull requests"),
        "{}",
        page.body
    );
    let st: Value = h
        .http
        .get(format!("{}/api/heimdall/state", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["pending"][0]["powers"], json!(["merge"]));
    assert!(
        st["active"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["powers"] == json!(["default_branch", "force_push", "merge", "approve", "rerun"]))
    );
    let created = h.events().into_iter().rev().find(|r| r.event == "request.created").unwrap();
    assert_eq!(created.detail["powers"], json!(["merge"]));
    let approved = h
        .events()
        .into_iter()
        .rev()
        .find(|r| r.event == "request.approved" && r.grant_id.as_deref() == Some(all.as_str()))
        .unwrap();
    assert_eq!(approved.detail["powers"], json!(["default_branch", "force_push", "merge", "approve", "rerun"]));
    let approved = h
        .events()
        .into_iter()
        .rev()
        .find(|r| r.event == "request.approved" && r.grant_id.as_deref() == Some(tagging.as_str()))
        .unwrap();
    assert_eq!(approved.detail["powers"], json!(["tags"]));
    let plain_req = h.app.store.grant(&plain).unwrap().unwrap().request_id;
    let page = b.get(&format!("{}/r/{plain_req}", h.browser)).await;
    assert!(!page.body.contains("asks for powers"));
}

/// Checking a fast-forward takes time; a revocation meanwhile withholds the pack checksum.
/// Compressed pushes cannot be inspected and are refused.
#[tokio::test]
async fn a_push_checked_after_its_grant_ended_is_not_applied() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let session = h.session().await;
    let grant = h.granted_write(&mut b, &session, "owner/heimdall", json!([])).await;
    let old = "a".repeat(40);
    let c = commit_content(&["5555555555555555555555555555555555555555"], "on a commit GitHub is slow to compare");
    let body = push_body(&[(&old, &oid_of_commit(&c), "refs/heads/feature")], Some(&pack(&[Obj::Plain(1, c)])));
    for encodings in [vec!["gzip"], vec!["identity", "gzip"]] {
        let mut r = h
            .http
            .post(format!("{}/git/github.com/owner/heimdall.git/git-receive-pack", h.api))
            .basic_auth("claude", Some(&session));
        for e in encodings {
            r = r.header("content-encoding", e);
        }
        assert_eq!(r.body(body.clone()).send().await.unwrap().status(), 400);
    }
    let pushing = {
        let (http, api, session, body) = (h.http.clone(), h.api.clone(), session.clone(), body.clone());
        tokio::spawn(async move {
            let r = http
                .post(format!("{api}/git/github.com/owner/heimdall.git/git-receive-pack"))
                .basic_auth("claude", Some(&session))
                .body(body)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        })
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{grant}/revoke", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let (status, text) = pushing.await.unwrap();
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("ended while"), "{text}");
    assert!(h.pushes().iter().all(|p| !p.complete), "GitHub never got the whole pack");
}

/// Disconnecting deletes the token here and links to revoking it on GitHub.
#[tokio::test]
async fn the_github_device_code_is_only_for_the_owner_and_their_browser() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let mut other = Browser::new(&h);
    let p = other.get(&format!("{}/connections/github/device", h.browser)).await;
    assert_eq!(p.status, StatusCode::NOT_FOUND);
    assert!(!p.body.contains("WDJB-MJHT"), "another browser never sees the code");
    *h.gh.login_as.lock().unwrap() = Some("eve".into());
    let p = b.get(&format!("{}/", h.browser)).await;
    assert_eq!(h.device_connect(&mut b, &csrf_in(&p.body)).await, "wrong account");
    assert_eq!(h.app.store.connection("github").unwrap().unwrap().account, "owner-gh");
    let failed = h.events().into_iter().rev().find(|r| r.event == "connect.failed").unwrap();
    assert_eq!(failed.detail["account"], "eve");
    *h.gh.login_as.lock().unwrap() = None;
    let p = b.get(&format!("{}/", h.browser)).await;
    let p = b.post(&format!("{}/connections/github/disconnect", h.browser), &csrf_in(&p.body)).await;
    assert_eq!(query(&p.location)["prompt"], "login");
    let p = pocket_id(&h, &mut b, &p.location, json!({}), IDP_KEY_B64).await;
    assert_eq!(p.status, 200);
    assert!(p.body.contains("settings/connections/applications/gh-client"), "{}", p.body);
    assert!(h.app.store.connection("github").unwrap().is_none());
    assert!(!format!("{:?}", h.events()).contains(GH_TOKEN));
}

#[tokio::test]
async fn the_warden_passkey_approves_from_heimdall_and_from_its_own_page() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let auth = Authenticator::es256();
    let p = h.register_passkey(&mut b, &auth, &h.browser).await;
    assert_eq!(p.status, 200, "{}", p.body);
    let passkey = h.app.store.passkeys(OWNER).unwrap().pop().expect("a registered passkey");
    assert_eq!((passkey.name.as_str(), passkey.credential_id.clone()), ("phone", b64(&auth.credential_id)));
    let registered = h.events().into_iter().rev().find(|r| r.event == "passkey.registered").unwrap();
    assert_eq!(registered.actor, format!("owner:{OWNER}"));
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(
        p.body.contains("<b>phone</b>") && p.body.contains("/passkeys/") && p.body.contains("Remove (with Pocket ID)"),
        "{}",
        p.body
    );
    let r = h.http.get(format!("{}/static/warden.js", h.browser)).send().await.unwrap();
    assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("script-src 'self'"));
    assert!(r.text().await.unwrap().contains("navigator.credentials.get"));

    let session = h.session().await;
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "write", "duration": "1h", "reason": "push the fix"}),
        )
        .await;
    let id = req["id"].as_str().unwrap().to_string();

    let ch = h.heimdall_challenge(&id).await;
    assert_eq!((ch["rp_id"].as_str(), ch["user_verification"].as_str()), (Some(RP_ID), Some("required")));
    assert_eq!(ch["allow"], json!([b64(&auth.credential_id)]));
    let (status, v) = h
        .heimdall_approve(
            &id,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(h.status_of(&id), "approved");
    let grant = h.app.store.grant_for_request(&id).unwrap().unwrap();
    assert_eq!(
        (v["grant_id"].as_str(), grant.approved_by.as_str()),
        (Some(grant.id.as_str()), format!("owner:{OWNER}").as_str())
    );
    let approved = h.events().into_iter().rev().find(|r| r.event == "request.approved").unwrap();
    assert_eq!(approved.detail["via"], "passkey");
    assert_eq!(approved.detail["channel"], "heimdall");
    assert_eq!(approved.detail["origin"], HEIMDALL_ORIGIN);
    assert_eq!(approved.detail["passkey"], passkey.id.as_str());

    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "1h", "reason": "read the code to review it"}),
        )
        .await;
    let id2 = req["id"].as_str().unwrap().to_string();
    let p = b.get(&format!("{}/r/{id2}", h.browser)).await;
    assert!(p.body.contains("id=\"wa-approve\"") && p.body.contains("/static/warden.js"), "{}", p.body);
    let csrf = data_attr(&p.body, "csrf");
    let c = b.post_json(&format!("{}/r/{id2}/passkey/challenge", h.browser), &json!({"csrf": csrf})).await;
    assert_eq!(c.status, 200, "{}", c.body);
    let ch: Value = serde_json::from_str(&c.body).unwrap();
    let (cd, ad, sig) = auth.assert(ch["challenge"].as_str().unwrap(), &h.browser, RP_ID, UP_UV, 0);
    let body =
        json!({"csrf": csrf, "credential_id": b64(&auth.credential_id), "client_data": b64(&cd), "authenticator_data": b64(&ad), "signature": b64(&sig)});
    let p = b.post_json(&format!("{}/r/{id2}/passkey/approve", h.browser), &body).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert_eq!(h.status_of(&id2), "approved");
    let approved = h.events().into_iter().rev().find(|r| r.event == "request.approved").unwrap();
    assert_eq!(
        (approved.detail["via"].as_str(), approved.detail["channel"].as_str()),
        (Some("passkey"), Some("web"))
    );
    let req = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "1h", "reason": "read the code again later"}),
        )
        .await;
    let id3 = req["id"].as_str().unwrap();
    let c = b
        .post_json(&format!("{}/r/{id3}/passkey/challenge", h.browser), &json!({"csrf": "x".repeat(43)}))
        .await;
    assert_eq!(c.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_passkey_signature_only_approves_its_request_from_its_origin_once_with_uv_and_the_registered_key() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let auth = Authenticator::es256();
    assert_eq!(h.register_passkey(&mut b, &auth, &h.browser).await.status, 200);
    let session = h.session().await;
    let mk = |reason: &str| json!({"system": "github", "scope": "owner/heimdall", "mode": "write", "duration": "1h", "reason": reason});
    let a = h.request(&session, mk("request A")).await["id"].as_str().unwrap().to_string();
    let other = h.request(&session, mk("request B")).await["id"].as_str().unwrap().to_string();
    let refused = |status: u16, v: &Value, why: &str| {
        assert_eq!(status, 403, "{why}: {v}");
        assert_eq!(h.status_of(&a), "pending", "{why}");
        let r = h.last_rejection();
        assert!(r["reason"].as_str().unwrap_or("").contains(why), "{why}: {r}");
        assert_eq!((r["via"].as_str(), r["channel"].as_str()), (Some("passkey"), Some("heimdall")));
    };

    // Any example.com subdomain can use the passkey (same RP ID), but the browser reports its own
    // origin. warden's own origin is not valid on heimdall's path either.
    for origin in ["https://evil.example.com", "https://heimdall.example.com.evil.com", h.browser.as_str()] {
        let ch = h.heimdall_challenge(&a).await;
        let (s, v) = h
            .heimdall_approve(&a, &auth.credential_id, auth.assert(ch["challenge"].as_str().unwrap(), origin, RP_ID, UP_UV, 0))
            .await;
        refused(s, &v, "origin");
    }

    let ch_b = h.heimdall_challenge(&other).await;
    let (s, v) = h
        .heimdall_approve(
            &a,
            &auth.credential_id,
            auth.assert(ch_b["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    refused(s, &v, "another request");
    assert_eq!(h.status_of(&other), "pending");

    // User presence without user verification (no PIN or biometric).
    let ch = h.heimdall_challenge(&a).await;
    let (s, v) = h
        .heimdall_approve(
            &a,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, 0x01, 0),
        )
        .await;
    refused(s, &v, "UV");

    let mut wrong = Authenticator::es256();
    wrong.credential_id = auth.credential_id.clone();
    let ch = h.heimdall_challenge(&a).await;
    let challenge = ch["challenge"].as_str().unwrap().to_string();
    let (s, v) = h
        .heimdall_approve(&a, &auth.credential_id, wrong.assert(&challenge, HEIMDALL_ORIGIN, RP_ID, UP_UV, 0))
        .await;
    refused(s, &v, "signature");

    // The failed attempt spent the challenge.
    let (s, v) = h
        .heimdall_approve(&a, &auth.credential_id, auth.assert(&challenge, HEIMDALL_ORIGIN, RP_ID, UP_UV, 0))
        .await;
    refused(s, &v, "already used");

    let ch = h.heimdall_challenge(&a).await;
    let (s, v) = h
        .heimdall_approve(
            &a,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, "evil.com", UP_UV, 0),
        )
        .await;
    refused(s, &v, "RP ID");

    let p = b.get(&format!("{}/r/{a}", h.browser)).await;
    let c = b
        .post_json(&format!("{}/r/{a}/passkey/challenge", h.browser), &json!({"csrf": data_attr(&p.body, "csrf")}))
        .await;
    let web: Value = serde_json::from_str(&c.body).unwrap();
    let (s, v) = h
        .heimdall_approve(
            &a,
            &auth.credential_id,
            auth.assert(web["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    refused(s, &v, "web path");

    // heimdall's token alone approves nothing, and it cannot register a passkey of its own.
    let r = h
        .http
        .post(format!("{}/api/heimdall/requests/{a}/approve", h.api))
        .bearer_auth(&h.heimdall)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let mine = Authenticator::es256();
    let ch = h.heimdall_challenge(&a).await;
    let (s, v) = h
        .heimdall_approve(
            &a,
            &mine.credential_id,
            mine.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    refused(s, &v, "unknown passkey");
    let (cd, att) = mine.attest("whatever", &h.browser, RP_ID, UP_UV);
    let r = h
        .http
        .post(format!("{}/passkeys/register", h.browser))
        .bearer_auth(&h.heimdall)
        .header("origin", &h.browser)
        .json(&json!({"csrf": "", "credential_id": b64(&mine.credential_id), "client_data": b64(&cd), "attestation": b64(&att)}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    for path in ["challenge", "approve"] {
        let r = h
            .http
            .post(format!("{}/api/heimdall/requests/{a}/{path}", h.api))
            .bearer_auth(&session)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "a session token is not heimdall's");
    }
    assert_eq!(h.app.store.passkeys(OWNER).unwrap().len(), 1);
    assert!(h.app.store.grant_for_request(&a).unwrap().is_none());

    // A sign counter that does not increase suggests a cloned authenticator.
    let ch = h.heimdall_challenge(&a).await;
    let (s, v) = h
        .heimdall_approve(
            &a,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 5),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let ch = h.heimdall_challenge(&other).await;
    let (s, v) = h
        .heimdall_approve(
            &other,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 5),
        )
        .await;
    assert_eq!(s, 409, "{v}");
    assert!(h.last_rejection()["reason"].as_str().unwrap().contains("counter"));
    assert_eq!(h.status_of(&other), "pending");
}

#[tokio::test]
async fn the_warden_passkey_is_added_and_removed_only_after_a_fresh_pocket_id_passkey() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let p = h.passkey_page(&mut b, json!({"auth_time": now() - 3600})).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert!(!p.body.contains("data-challenge"));

    let auth = Authenticator::es256();
    let p = h.passkey_page(&mut b, json!({})).await;
    let challenge = data_attr(&p.body, "challenge");
    let csrf = data_attr(&p.body, "csrf");
    let (cd, att) = auth.attest(&challenge, &h.browser, RP_ID, UP_UV);
    let body = json!({"csrf": csrf, "credential_id": b64(&auth.credential_id), "client_data": b64(&cd), "attestation": b64(&att)});
    let mut other = Browser::new(&h);
    other.cookies.insert("__Host-warden_csrf".into(), b.cookies["__Host-warden_csrf"].clone());
    let r = other.post_json(&format!("{}/passkeys/register", h.browser), &body).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another browser");
    assert!(h.app.store.passkeys(OWNER).unwrap().is_empty());
    let p = h.passkey_page(&mut b, json!({})).await;
    let (cd, att) = auth.attest(&data_attr(&p.body, "challenge"), HEIMDALL_ORIGIN, RP_ID, UP_UV);
    let body = json!({"csrf": data_attr(&p.body, "csrf"), "credential_id": b64(&auth.credential_id), "client_data": b64(&cd), "attestation": b64(&att)});
    assert_eq!(
        b.post_json(&format!("{}/passkeys/register", h.browser), &body).await.status,
        StatusCode::FORBIDDEN,
        "registering is only on warden's page"
    );
    assert!(h.app.store.passkeys(OWNER).unwrap().is_empty());
    assert_eq!(h.register_passkey(&mut b, &auth, &h.browser).await.status, 200);

    // A challenge issued before the passkey is removed.
    let session = h.session().await;
    let id = h
        .request(
            &session,
            json!({"system": "github", "scope": "owner/heimdall", "mode": "read", "duration": "1h", "reason": "read the code for a review"}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let ch = h.heimdall_challenge(&id).await;
    let passkey = h.app.store.passkeys(OWNER).unwrap().pop().unwrap();
    let p = b.get(&format!("{}/", h.browser)).await;
    let p = b.post(&format!("{}/passkeys/{}/revoke", h.browser, passkey.id), &csrf_in(&p.body)).await;
    let q = query(&p.location);
    assert_eq!(
        (q["prompt"].as_str(), q["max_age"].as_str()),
        ("login", "0"),
        "removing it asks for Pocket ID's passkey again"
    );
    let p = pocket_id(&h, &mut b, &p.location, json!({}), IDP_KEY_B64).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert!(h.app.store.passkeys(OWNER).unwrap().is_empty());
    assert!(h.events().iter().any(|r| r.event == "passkey.revoked"));
    let (s, _) = h
        .heimdall_approve(
            &id,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    assert_eq!(s, 403);
    assert!(h.last_rejection()["reason"].as_str().unwrap().contains("revoked"));
    let r = h
        .http
        .post(format!("{}/api/heimdall/requests/{id}/challenge", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert_eq!(h.status_of(&id), "pending");
}

const GIT_READ: &str = "owner/heimdall.git/info/refs?service=git-upload-pack";

/// Device-flow tokens are renewed without the client secret, before expiry and after a 401 for the
/// current token.
#[tokio::test]
async fn an_expiring_token_is_renewed_in_time_and_each_renewal_uses_the_rotated_refresh_token() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    // 200 s is inside the renewal margin, so the first request renews.
    let session = h
        .connected_with(&mut b, |e| {
            e.on = true;
            e.expires_in = Some(200);
        })
        .await;
    let at = now();
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.expires_at.is_some_and(|t| (t - at - 200).abs() <= 5), "{:?}", c.expires_at);
    assert!(c.refresh_expires_at.is_some_and(|t| (t - at - 15897600).abs() <= 5));
    h.gh.exp.lock().unwrap().expires_in = Some(28800);

    let r = h.git(&session, reqwest::Method::GET, GIT_READ).await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.gh.last().authorization, basic("gho_RENEWED_1"));
    let renewals = h.gh.renewals();
    assert_eq!(renewals.len(), 1);
    let first = &renewals[0];
    assert_eq!(
        (first["grant_type"].as_str(), first["refresh_token"].as_str(), first["client_id"].as_str()),
        ("refresh_token", "ghr_REFRESH_0", "gh-client")
    );
    assert!(!first.contains_key("client_secret"), "a device-flow token is renewed without the client secret");
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.expires_at.is_some_and(|t| t - now() > 28000) && c.refreshed_at.is_some() && c.broken.is_none());
    assert_eq!(h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 200);
    assert_eq!(h.gh.last().authorization, "Bearer gho_RENEWED_1");
    assert_eq!(h.gh.renewals().len(), 1);

    h.gh.reject_current_token();
    let r = h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await;
    assert_eq!(r.status(), 200);
    let renewals = h.gh.renewals();
    assert_eq!(renewals.len(), 2);
    assert_eq!(renewals[1]["refresh_token"], "ghr_REFRESH_1");
    let seen: Vec<String> = h.gh.seen.lock().unwrap().iter().rev().take(2).map(|s| s.authorization.clone()).collect();
    assert_eq!(
        seen,
        ["Bearer gho_RENEWED_2", "Bearer gho_RENEWED_1"],
        "rejected once, then repeated with the renewed token"
    );

    // A push body is streamed and cannot be replayed, so the client is asked to send it again.
    h.gh.reject_current_token();
    let c1 = commit_content(&[], "renewed");
    let push = push_body(
        &[(ZERO_OID, &oid_of_commit(&c1), "refs/heads/renewed")],
        Some(&pack(&[Obj::Plain(1, c1.clone())])),
    );
    let r = h.push(&session, "owner/heimdall", push.clone()).await;
    assert_eq!(r.status(), 503);
    assert!(r.text().await.unwrap().contains("send it again"));
    assert_eq!(h.gh.renewals()[2]["refresh_token"], "ghr_REFRESH_2");
    let r = h.push(&session, "owner/heimdall", push).await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.gh.last().authorization, basic("gho_RENEWED_3"));

    let rows = h.events();
    let renewed: Vec<_> = rows.iter().filter(|r| r.event == "connection.refreshed").collect();
    assert_eq!(
        renewed.iter().map(|r| r.detail["trigger"].as_str().unwrap()).collect::<Vec<_>>(),
        ["expiring", "rejected", "rejected"]
    );
    assert!(
        renewed
            .iter()
            .all(|r| r.actor.starts_with("session:") && r.session_id.is_some() && r.detail["expires_at"].is_i64())
    );
    let connected = rows.iter().find(|r| r.event == "connection.connected").unwrap();
    assert_eq!(connected.detail["expires"], true);
    h.assert_no_github_token_in_clear();
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(rows.len()));
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(p.body.contains("The token expires") && p.body.contains("Renewed"), "{}", p.body);
}

/// A second renewal would present the spent refresh token and break the connection.
#[tokio::test]
async fn requests_at_once_renew_the_token_once() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h
        .connected_with(&mut b, |e| {
            e.on = true;
            e.expires_in = Some(200);
            e.delay_ms = 300;
        })
        .await;
    h.gh.exp.lock().unwrap().expires_in = Some(28800);
    let all = futures_util::future::join_all((0..6).map(|i| {
        let (http, api, session) = (h.http.clone(), h.api.clone(), session.clone());
        async move {
            let path = if i % 2 == 0 {
                "repos/owner/heimdall/pulls"
            } else {
                "repos/owner/heimdall/issues"
            };
            http.get(format!("{api}/api/v3/{path}"))
                .header("authorization", format!("token {session}"))
                .send()
                .await
                .unwrap()
                .status()
        }
    }))
    .await;
    assert!(all.iter().all(|s| *s == 200), "{all:?}");
    assert_eq!(h.gh.renewals().len(), 1, "one renewal for all of them");
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.broken.is_none());
    assert!(h.gh.seen.lock().unwrap().iter().all(|s| s.authorization == "Bearer gho_RENEWED_1"));
    assert_eq!(h.events().iter().filter(|r| r.event == "connection.refreshed").count(), 1);
}

#[tokio::test]
async fn a_failed_renewal_is_said_clearly_and_a_refused_one_asks_to_reconnect() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h
        .connected_with(&mut b, |e| {
            e.on = true;
            e.expires_in = Some(200);
        })
        .await;

    h.gh.exp.lock().unwrap().refuse = Some("down");
    let r = h.git(&session, reqwest::Method::GET, GIT_READ).await;
    assert_eq!(r.status(), 502);
    assert!(r.text().await.unwrap().contains("GitHub did not renew the token"));
    assert_eq!(h.gh.count(), 0, "the token about to expire is not used");
    assert!(h.app.store.connection("github").unwrap().unwrap().broken.is_none());
    let failed = h.events().into_iter().rev().find(|r| r.event == "connection.refresh_failed").unwrap();
    assert_eq!(failed.detail["reconnect"], false);
    {
        let mut e = h.gh.exp.lock().unwrap();
        e.refuse = None;
        e.expires_in = Some(28800);
    }
    assert_eq!(h.git(&session, reqwest::Method::GET, GIT_READ).await.status(), 200);
    assert_eq!(h.gh.last().authorization, basic("gho_RENEWED_1"));

    h.gh.exp.lock().unwrap().refuse = Some("bad");
    h.gh.reject_current_token();
    let r = h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await;
    assert_eq!(r.status(), 503);
    let body = r.text().await.unwrap();
    assert!(body.contains("has to be connected again") && body.contains("bad_refresh_token"), "{body}");
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.broken.as_ref().is_some_and(|(_, why)| why.contains("bad_refresh_token")), "{:?}", c.broken);
    let failed = h.events().into_iter().rev().find(|r| r.event == "connection.refresh_failed").unwrap();
    assert_eq!(
        (failed.detail["reconnect"].as_bool(), failed.detail["trigger"].as_str()),
        (Some(true), Some("rejected"))
    );
    let (renewals, sent) = (h.gh.renewals().len(), h.gh.count());
    let r = h.git(&session, reqwest::Method::GET, GIT_READ).await;
    assert_eq!(r.status(), 503);
    assert!(r.text().await.unwrap().contains("has to be connected again"));
    assert_eq!((h.gh.renewals().len(), h.gh.count()), (renewals, sent));
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(
        p.body.contains("It has to be connected again") && p.body.contains("bad_refresh_token") && p.body.contains("Reconnect GitHub"),
        "{}",
        p.body
    );
    h.assert_no_github_token_in_clear();

    h.gh.exp.lock().unwrap().refuse = None;
    assert_eq!(h.device_connect(&mut b, &csrf_in(&p.body)).await, "connected");
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.broken.is_none() && c.refreshed_at.is_none() && c.expires_at.is_some());
    assert_eq!(h.git(&session, reqwest::Method::GET, GIT_READ).await.status(), 200);
    assert_eq!(h.gh.last().authorization, basic(GH_TOKEN));
    h.assert_no_github_token_in_clear();
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(h.events().len()));
}

#[tokio::test]
async fn a_connection_without_refresh_token_does_not_expire_and_works_as_before() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h.connected_with(&mut b, |e| e.on = false).await;
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert_eq!(
        (c.expires_at, c.refresh_expires_at, c.refreshed_at, c.broken.is_none()),
        (None, None, None, true)
    );
    assert_eq!(h.git(&session, reqwest::Method::GET, GIT_READ).await.status(), 200);
    assert_eq!(h.gh.last().authorization, basic(GH_TOKEN));
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(p.body.contains("<b>does not expire</b>") && p.body.contains("Reconnect GitHub"), "{}", p.body);
    assert!(p.body.contains("settings/connections/applications/gh-client"));
    h.gh.reject_current_token();
    let r = h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["message"], "Bad credentials");
    assert!(h.gh.renewals().is_empty());
    assert!(h.app.store.connection("github").unwrap().unwrap().broken.is_none());
    assert_eq!(h.events().iter().filter(|r| r.event.starts_with("connection.refresh")).count(), 0);
}

/// GitHub spends the refresh token on receipt, so the renewal must finish even if the client goes
/// away.
#[tokio::test]
async fn a_renewal_finishes_even_if_the_request_that_started_it_goes_away() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h
        .connected_with(&mut b, |e| {
            e.on = true;
            e.expires_in = Some(200);
            e.delay_ms = 600;
        })
        .await;
    h.gh.exp.lock().unwrap().expires_in = Some(28800);
    let impatient = reqwest::Client::builder().timeout(Duration::from_millis(150)).build().unwrap();
    let basic_session = STANDARD.encode(format!("claude:{session}"));
    let gone = impatient
        .get(format!("{}/git/github.com/{GIT_READ}", h.api))
        .header("authorization", format!("Basic {basic_session}"))
        .send()
        .await;
    assert!(gone.is_err(), "the client gave up before the renewal ended");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(h.gh.renewals().len(), 1);
    let c = h.app.store.connection("github").unwrap().unwrap();
    assert!(c.broken.is_none() && c.refreshed_at.is_some(), "{:?}", c.broken);
    assert_eq!(h.git(&session, reqwest::Method::GET, GIT_READ).await.status(), 200);
    assert_eq!(h.gh.last().authorization, basic("gho_RENEWED_1"));
    assert_eq!(h.gh.renewals().len(), 1);
}

/// Only a 401 that /user confirms triggers a renewal. Otherwise any session could force a rotation
/// per request, cutting off what other sessions have in flight.
#[tokio::test]
async fn a_401_from_a_route_that_does_not_take_the_token_does_not_renew_it() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h.connected_with(&mut b, |e| e.on = true).await;
    for _ in 0..3 {
        let r = h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/contents/installation").await;
        assert_eq!(r.status(), 401);
    }
    assert!(h.gh.renewals().is_empty());
    assert!(h.app.store.connection("github").unwrap().unwrap().refreshed_at.is_none());
    assert_eq!(h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 200);
    assert_eq!(h.gh.last().authorization, format!("Bearer {GH_TOKEN}"));
    *h.gh.user_limited.lock().unwrap() = true;
    h.gh.reject_current_token();
    assert_eq!(h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 401);
    assert!(h.gh.renewals().is_empty());
    *h.gh.user_limited.lock().unwrap() = false;
    assert_eq!(h.rest(&session, reqwest::Method::GET, "repos/owner/heimdall/pulls").await.status(), 200);
    assert_eq!(h.gh.renewals().len(), 1);
    assert_eq!(h.gh.last().authorization, "Bearer gho_RENEWED_1");
}

#[tokio::test]
async fn a_retry_after_a_renewal_rechecks_the_grant() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let session = h
        .connected_with(&mut b, |e| {
            e.on = true;
            e.delay_ms = 600;
        })
        .await;
    h.gh.reject_current_token();
    let pending = {
        let (http, api, session) = (h.http.clone(), h.api.clone(), session.clone());
        tokio::spawn(async move {
            // A buffered body, so warden can retry it after renewing.
            let r = http
                .post(format!("{api}/api/v3/repos/owner/heimdall/pulls/2/reviews"))
                .header("authorization", format!("token {session}"))
                .body(r#"{"event":"COMMENT","body":"looks fine"}"#)
                .send()
                .await
                .unwrap();
            (r.status(), r.text().await.unwrap())
        })
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    let grants = h.app.store.active_grants(now()).unwrap();
    assert_eq!(grants.len(), 1);
    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{}/revoke", h.api, grants[0].0.id))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let (status, body) = pending.await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("grant ended while the GitHub token was being renewed"), "{body}");
    assert_eq!(h.gh.renewals().len(), 1);
    let reviews: Vec<String> =
        h.gh.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path.ends_with("/reviews"))
            .map(|s| s.authorization.clone())
            .collect();
    assert_eq!(
        reviews,
        [format!("Bearer {GH_TOKEN}")],
        "only the first try, with the rejected token, reached GitHub"
    );
}

/// A private repo of the connected account on GitHub Free, where rulesets are unavailable.
const OWN_PRIVATE: &str = "owner-gh/notes";

/// The proxy is the only enforcement: warden never reads or changes the repo's GitHub protections.
#[tokio::test]
async fn a_write_grant_on_a_private_repo_of_a_free_account_is_granted_and_the_proxy_sets_the_limits() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    h.connect_github(&mut b).await;
    let session = h.session().await;
    let repo = OWN_PRIVATE;
    let protections = |h: &H| -> Vec<String> {
        h.gh.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path.contains("/rulesets") || s.path.contains("/rules/"))
            .map(|s| format!("{} {}", s.method, s.path))
            .collect()
    };

    let id = h
        .request(
            &session,
            json!({"system": "github", "scope": {"repos": [repo]}, "mode": "write", "duration": "1h", "reason": "push my notes"}),
        )
        .await;
    let id = id["id"].as_str().unwrap().to_string();
    let p = h.approve(&mut b, &id, json!({})).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert_eq!(h.status_of(&id), "approved");
    assert!(h.app.store.grant_for_request(&id).unwrap().is_some());
    let page = b.get(&format!("{}/r/{id}", h.browser)).await;
    assert!(!page.body.contains("ruleset") && !page.body.contains("“warden” rule"), "{}", page.body);

    let r = h
        .rest_json(&session, reqwest::Method::POST, &format!("repos/{repo}/issues"), r#"{"title":"x"}"#)
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.gh.last().path, format!("/repos/{repo}/issues"));
    let old = "a".repeat(40);
    let one = |parent: &str, msg: &str| {
        let c = commit_content(&[parent], msg);
        (oid_of_commit(&c), pack(&[Obj::Plain(1, c)]))
    };
    let (new, p) = one(&old, "one more note");
    assert_eq!(
        h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p)))
            .await
            .status(),
        200
    );
    assert!(h.pushes().last().unwrap().complete);

    let whole = h.pushes().iter().filter(|p| p.complete).count();
    let (new, p) = one(&old, "straight to main");
    let r = h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/main")], Some(&p))).await;
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("default_branch"));
    let (new, p) = one(&"c".repeat(40), "rewritten history");
    let r = h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/feature")], Some(&p))).await;
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("force_push"));
    assert_eq!(h.pushes().iter().filter(|p| p.complete).count(), whole, "no refused push reached GitHub whole");
    assert_eq!(
        h.rest_json(&session, reqwest::Method::PUT, &format!("repos/{repo}/pulls/3/merge"), "{}")
            .await
            .status(),
        403
    );
    assert_eq!(
        h.rest_json(
            &session,
            reqwest::Method::POST,
            &format!("repos/{repo}/pulls/3/reviews"),
            r#"{"event":"APPROVE"}"#
        )
        .await
        .status(),
        403
    );
    // Never writable, whatever the powers (`repo_protections_are_never_writable` in proxy.rs).
    assert_eq!(
        h.rest_json(&session, reqwest::Method::POST, &format!("repos/{repo}/rulesets"), "{}")
            .await
            .status(),
        403
    );

    let auth = Authenticator::es256();
    assert_eq!(h.register_passkey(&mut b, &auth, &h.browser).await.status, 200);
    let req = h
        .request(&session, json!({"system": "github", "scope": {"repos": [repo]}, "mode": "write", "powers": ["default_branch", "force_push", "merge", "approve"], "duration": "1h", "reason": "release the notes"}))
        .await;
    let id2 = req["id"].as_str().unwrap().to_string();
    let ch = h.heimdall_challenge(&id2).await;
    let (status, v) = h
        .heimdall_approve(
            &id2,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(h.status_of(&id2), "approved");
    let (new, p) = one(&old, "straight to main");
    assert_eq!(
        h.push(&session, repo, push_body(&[(&old, &new, "refs/heads/main")], Some(&p))).await.status(),
        200
    );
    assert_eq!(
        h.rest_json(&session, reqwest::Method::PUT, &format!("repos/{repo}/pulls/3/merge"), "{}")
            .await
            .status(),
        200
    );

    assert!(protections(&h).is_empty(), "{:?}", protections(&h));
    assert!(h.last_rejection().is_null(), "{}", h.last_rejection());
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(h.events().len()));
}

const ALLOC_A: &str = "aaaaaaaa-1111-4222-8333-444455556666";
const ALLOC_B: &str = "bbbbbbbb-1111-4222-8333-444455556666";

fn sha_hex(s: &str) -> String {
    warden::util::sha256_hex(s.as_bytes())
}

#[tokio::test]
async fn claude_ai_is_connected_once_with_pkce_and_the_pasted_code() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let p = h.connect_claude_as(&mut b, "owner@home.example").await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert!(
        p.body.contains("Connected as <b>owner@home.example</b>") && p.body.contains("subscription <b>max</b>"),
        "{}",
        p.body
    );
    // The fake checks the verifier against the S256 challenge.
    let bodies = h.claude.0.lock().unwrap().bodies.clone();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["grant_type"], "authorization_code");
    assert!(bodies[0]["code_verifier"].as_str().is_some_and(|v| v.len() >= 43));
    let c = h.app.store.connection("claude").unwrap().unwrap();
    assert_eq!(c.account, "owner@home.example");
    assert!(c.scopes.contains("user:sessions:claude_code") && c.broken.is_none());
    assert!(c.expires_at.is_some_and(|t| (t - now() - 28800).abs() <= 5));
    h.assert_no_claude_token_in_clear();
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(
        p.body.contains("claude.ai: <b>owner@home.example</b>") && p.body.contains("Disconnect claude.ai"),
        "{}",
        p.body
    );

    let p = b.post(&format!("{}/connections/claude", h.browser), &csrf_in(&p.body)).await;
    let p = pocket_id(&h, &mut b, &p.location, json!({}), IDP_KEY_B64).await;
    let (authorize, flow, csrf) = claude_page(&p.body);
    let q = query(&authorize);
    assert!(authorize.contains("/oauth/authorize?"));
    assert_eq!(
        (
            q["client_id"].as_str(),
            q["response_type"].as_str(),
            q["code_challenge_method"].as_str(),
            q["code"].as_str()
        ),
        ("9d1c250a-e61b-44d9-88ed-5944d1962f5e", "code", "S256", "true")
    );
    assert!(q["redirect_uri"].ends_with("/oauth/code/callback"));
    for scope in ["user:inference", "user:profile", "user:sessions:claude_code"] {
        assert!(q["scope"].split(' ').any(|s| s == scope), "{scope} in {}", q["scope"]);
    }
    assert!(
        !q["scope"].contains("org:create_api_key"),
        "a sandbox's token must not be able to mint an API key"
    );
    assert_eq!(flow, q["state"]);
    let other = b
        .post_form(
            &format!("{}/connections/claude/code", h.browser),
            &[("csrf", &csrf), ("flow", &flow), ("code", "abc#another-state")],
        )
        .await;
    assert!(other.status == 400 && other.body.contains("Wrong code"), "{}", other.body);
    // The stolen attempt also spends the flow.
    let code = warden::util::new_id("code");
    h.claude
        .0
        .lock()
        .unwrap()
        .codes
        .insert(code.clone(), (q["code_challenge"].clone(), q["state"].clone(), "owner@home.example".into()));
    let mut thief = Browser::new(&h);
    thief.cookies.insert("__Host-warden_csrf".into(), csrf.clone());
    let stolen = thief
        .post_form(
            &format!("{}/connections/claude/code", h.browser),
            &[("csrf", &csrf), ("flow", &flow), ("code", &format!("{code}#{flow}"))],
        )
        .await;
    assert!(stolen.status == 400 && stolen.body.contains("Wrong browser"), "{}", stolen.body);
    let again = b
        .post_form(
            &format!("{}/connections/claude/code", h.browser),
            &[("csrf", &csrf), ("flow", &flow), ("code", &format!("{code}#{flow}"))],
        )
        .await;
    assert!(again.status == 400 && again.body.contains("no longer valid"), "{}", again.body);

    // An unrequested scope (a long-lived API key) means the token is not stored.
    h.claude.0.lock().unwrap().extra_scope = Some("org:create_api_key");
    let p = h.connect_claude_as(&mut b, "owner@home.example").await;
    assert!(p.status == 502 && p.body.contains("org:create_api_key"), "{}", p.body);
    assert_eq!(h.app.store.connection("claude").unwrap().unwrap().sealed, c.sealed);
    h.claude.0.lock().unwrap().extra_scope = None;

    let p = h.connect_claude_as(&mut b, "owner@work.example").await;
    assert!(p.status == 403 && p.body.contains("owner@work.example"), "{}", p.body);
    assert_eq!(h.app.store.connection("claude").unwrap().unwrap().sealed, c.sealed);
    let failed: Vec<_> = h.events().into_iter().filter(|r| r.event == "connect.failed").collect();
    assert!(failed.iter().any(|r| r.detail["reason"] == "another account authorised the code"));
    h.assert_no_claude_token_in_clear();
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(h.events().len()));
}

#[tokio::test]
async fn a_sandbox_gets_only_the_access_token_and_only_with_its_claude_session_grant() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    assert_eq!(h.connect_claude_as(&mut b, "owner@home.example").await.status, 200);
    let keeper = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    let (st, body) = h.claude_token(&keeper, None).await;
    assert!(st == 403 && body.contains("claude_session") && !body.contains("sk-ant-"), "{st} {body}");
    h.connect_github(&mut Browser::new(&h)).await;
    let req = h
        .request(
            &keeper,
            json!({"system": "github", "scope": {"repos": ["owner/heimdall"]}, "mode": "write", "duration": "1h", "reason": "push the branch"}),
        )
        .await;
    assert_eq!(h.approve(&mut b, req["id"].as_str().unwrap(), json!({})).await.status, 200);
    assert_eq!(h.claude_token(&keeper, None).await.0, 403);

    let grant = h.granted_claude(&mut b, &keeper).await;
    let (st, body) = h.claude_token(&keeper, None).await;
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["access_token"], "sk-ant-oat01-ACCESS_1");
    assert_eq!(
        (v["subscription_type"].as_str(), v["rate_limit_tier"].as_str()),
        (Some("max"), Some("default_claude_max_20x"))
    );
    assert!(v["scopes"].as_array().unwrap().iter().any(|s| s == "user:sessions:claude_code"));
    assert!(v["expires_at"].as_i64().is_some_and(|t| t - now() > 28000));
    assert_eq!(v["grant_id"], grant.as_str());
    assert!(!body.contains("REFRESH") && !body.contains("refresh"), "{body}");
    // `have` matches the current token: nothing delivered or audited.
    let (st, body) = h.claude_token(&keeper, Some(&sha_hex("sk-ant-oat01-ACCESS_1"))).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(st == 200 && v["unchanged"] == true && v.get("access_token").is_none(), "{body}");
    let issued: Vec<_> = h.events().into_iter().filter(|r| r.event == "claude.token_issued").collect();
    assert_eq!(issued.len(), 1);
    assert_eq!(
        (issued[0].grant_id.as_deref(), issued[0].detail["session"].as_str()),
        (Some(grant.as_str()), Some("sandbox:sandbox-claude · aaaaaaaa"))
    );
    assert_eq!(issued[0].detail["token_sha256"], &sha_hex("sk-ant-oat01-ACCESS_1")[..16]);
    // Asking repeatedly never forces a renewal.
    for _ in 0..3 {
        assert_eq!(h.claude_token(&keeper, None).await.0, 200);
    }
    assert!(h.claude.refreshes().is_empty());

    // Sessions last hours but sandboxes weeks: a reopened session of the same task and allocation
    // keeps the grant.
    let reopened = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    assert_eq!(h.claude_token(&reopened, None).await.0, 200);
    let sandbox = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "sandbox").await;
    assert_eq!(h.claude_token(&sandbox, None).await.0, 403);
    // Only tasks in `claude.tasks` may request it.
    let r = h
        .http
        .post(format!("{}/api/requests", h.api))
        .bearer_auth(&sandbox)
        .json(&json!({"system": "claude", "powers": ["claude_session"], "duration": "720h", "reason": "Remote Control session node2 in a sandbox"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("keeper"));
    let other = h.session_as("sandbox", "sandbox-claude", ALLOC_B, "keeper").await;
    assert_eq!(h.claude_token(&other, None).await.0, 403);

    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{grant}/revoke", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(h.claude_token(&keeper, None).await.0, 403);
    assert_eq!(h.claude_token(&reopened, None).await.0, 403);
    h.assert_no_claude_token_in_clear();
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(h.events().len()));
}

async fn heimdall_state(h: &H) -> Value {
    h.http
        .get(format!("{}/api/heimdall/state", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_claude_session_request_is_shown_approved_refused_and_revoked_from_heimdall() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    let auth = Authenticator::es256();
    assert_eq!(h.register_passkey(&mut b, &auth, &h.browser).await.status, 200);
    assert_eq!(h.connect_claude_as(&mut b, "owner@home.example").await.status, 200);
    let keeper = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    let ask = json!({"system": "claude", "powers": ["claude_session"], "duration": "720h", "reason": "Remote Control session node2 in a sandbox"});
    let req = h.request(&keeper, ask.clone()).await;
    let id = req["id"].as_str().unwrap().to_string();
    assert!(req["hint"].as_str().unwrap().contains("in the companion app or on warden's page"), "{req}");

    let st = heimdall_state(&h).await;
    let p = st["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id.as_str())
        .expect("the claude.ai request reaches heimdall");
    assert_eq!(
        (p["system"].as_str(), p["mode"].as_str(), &p["powers"], &p["repos"]),
        (Some("claude"), Some("session"), &json!(["claude_session"]), &Value::Null)
    );
    assert_eq!(
        (p["duration_secs"].as_i64(), p["session"].as_str()),
        (Some(720 * 3600), Some("sandbox:sandbox-claude · aaaaaaaa"))
    );

    let ch = h.heimdall_challenge(&id).await;
    let (status, v) = h
        .heimdall_approve(
            &id,
            &auth.credential_id,
            auth.assert(ch["challenge"].as_str().unwrap(), HEIMDALL_ORIGIN, RP_ID, UP_UV, 0),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    let grant = v["grant_id"].as_str().unwrap().to_string();
    let approved = h.events().into_iter().rev().find(|r| r.event == "request.approved").unwrap();
    assert_eq!(
        (approved.detail["via"].as_str(), approved.detail["channel"].as_str()),
        (Some("passkey"), Some("heimdall"))
    );
    let st = heimdall_state(&h).await;
    assert!(st["pending"].as_array().unwrap().is_empty(), "{st}");
    let a = &st["active"][0];
    assert_eq!(
        (a["id"].as_str(), a["system"].as_str(), a["mode"].as_str(), &a["powers"]),
        (Some(grant.as_str()), Some("claude"), Some("session"), &json!(["claude_session"]))
    );
    assert_eq!(h.claude_token(&keeper, None).await.0, 200);

    let r = h
        .http
        .post(format!("{}/api/heimdall/grants/{grant}/revoke", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(h.claude_token(&keeper, None).await.0, 403);
    assert!(heimdall_state(&h).await["active"].as_array().unwrap().is_empty());

    let again = h.request(&keeper, ask).await;
    let id2 = again["id"].as_str().unwrap();
    let r = h
        .http
        .post(format!("{}/api/heimdall/requests/{id2}/refuse", h.api))
        .bearer_auth(&h.heimdall)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(h.status_of(id2), "refused");
    assert!(h.app.store.grant_for_request(id2).unwrap().is_none());
    assert_eq!(h.claude_token(&keeper, None).await.0, 403);
}

/// If claude.ai is down, the current token is served while it lasts; if it refuses, the connection
/// needs reconnecting.
#[tokio::test]
async fn the_claude_token_is_renewed_by_warden_alone_once_and_with_the_rotated_refresh_token() {
    let h = harness().await;
    let mut b = Browser::new(&h);
    assert_eq!(h.connect_claude_as(&mut b, "owner@home.example").await.status, 200);
    let one = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    let two = h.session_as("sandbox", "sandbox-claude", ALLOC_B, "keeper").await;
    h.granted_claude(&mut b, &one).await;
    h.granted_claude(&mut b, &two).await;

    h.age_claude(100);
    h.claude.0.lock().unwrap().delay_ms = 300;
    let all = futures_util::future::join_all((0..6).map(|i| {
        let (http, api, session) = (h.http.clone(), h.api.clone(), if i % 2 == 0 { one.clone() } else { two.clone() });
        async move {
            let r = http
                .post(format!("{api}/api/claude/token"))
                .bearer_auth(session)
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    }))
    .await;
    assert!(all.iter().all(|(s, v)| *s == 200 && v["access_token"] == "sk-ant-oat01-ACCESS_2"), "{all:?}");
    let refreshes = h.claude.refreshes();
    assert_eq!(refreshes.len(), 1, "one renewal for all of them");
    assert_eq!(
        (refreshes[0]["refresh_token"].as_str(), refreshes[0]["client_id"].as_str()),
        (Some("sk-ant-ort01-REFRESH_1"), Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e"))
    );
    let c = h.app.store.connection("claude").unwrap().unwrap();
    assert!(c.expires_at.is_some_and(|t| t - now() > 28000) && c.refreshed_at.is_some() && c.broken.is_none());
    h.claude.0.lock().unwrap().delay_ms = 0;
    h.age_claude(100);
    let (st, body) = h.claude_token(&one, Some(&sha_hex("sk-ant-oat01-ACCESS_2"))).await;
    assert!(st == 200 && body.contains("sk-ant-oat01-ACCESS_3"), "{body}");
    assert_eq!(h.claude.refreshes()[1]["refresh_token"], "sk-ant-ort01-REFRESH_2");

    h.claude.0.lock().unwrap().refuse = Some("down");
    h.age_claude(100);
    let (st, body) = h.claude_token(&one, None).await;
    assert!(st == 200 && body.contains("sk-ant-oat01-ACCESS_3"), "{st} {body}");
    // After a failure, renewals back off for a minute.
    let tried = h.claude.0.lock().unwrap().bodies.len();
    let (st, body) = h.claude_token(&two, None).await;
    assert!(st == 200 && body.contains("sk-ant-oat01-ACCESS_3"), "{st} {body}");
    h.age_claude(30);
    let (st, body) = h.claude_token(&one, None).await;
    assert!(st == 503 && body.contains("in a minute"), "{st} {body}");
    assert_eq!(
        h.claude.0.lock().unwrap().bodies.len(),
        tried,
        "no renewal is attempted again within the minute"
    );
    *h.app.claude_failed_at.lock().unwrap() = None;
    h.claude.0.lock().unwrap().refuse = Some("html");
    let (st, body) = h.claude_token(&one, None).await;
    assert!(st == 503 && body.contains("did not answer"), "{st} {body}");
    assert!(h.app.store.connection("claude").unwrap().unwrap().broken.is_none());
    *h.app.claude_failed_at.lock().unwrap() = None;
    h.claude.0.lock().unwrap().refuse = None;
    let (st, body) = h.claude_token(&one, None).await;
    assert!(st == 200 && body.contains("sk-ant-oat01-ACCESS_4"), "{st} {body}");
    assert_eq!(h.claude.refreshes().last().unwrap()["refresh_token"], "sk-ant-ort01-REFRESH_3");

    // A renewal with an unrequested scope is treated as a refusal.
    h.claude.0.lock().unwrap().extra_scope = Some("org:create_api_key");
    h.age_claude(100);
    let (st, body) = h.claude_token(&two, None).await;
    assert!(st == 409 && body.contains("not asked for") && !body.contains("sk-ant-"), "{st} {body}");
    h.claude.0.lock().unwrap().extra_scope = None;
    assert_eq!(h.connect_claude_as(&mut b, "owner@home.example").await.status, 200);

    h.claude.0.lock().unwrap().refuse = Some("bad");
    h.age_claude(100);
    let (st, body) = h.claude_token(&two, None).await;
    assert!(
        st == 409 && body.contains("connect claude.ai again") && !body.contains("sk-ant-"),
        "{st} {body}"
    );
    let asked = h.claude.refreshes().len();
    assert_eq!(h.claude_token(&one, None).await.0, 409);
    assert_eq!(h.claude.refreshes().len(), asked, "a broken connection does not ask claude.ai again");
    let p = b.get(&format!("{}/", h.browser)).await;
    assert!(p.body.contains("It has to be connected again"), "{}", p.body);
    h.claude.0.lock().unwrap().refuse = None;
    assert_eq!(h.connect_claude_as(&mut b, "owner@home.example").await.status, 200);
    let (st, body) = h.claude_token(&two, None).await;
    assert!(st == 200 && body.contains("sk-ant-oat01-ACCESS_7"), "{st} {body}");

    let rows = h.events();
    let refreshed = rows
        .iter()
        .filter(|r| r.event == "connection.refreshed" && r.detail["provider"] == "claude")
        .count();
    assert_eq!(refreshed, 3);
    assert!(rows.iter().any(|r| r.event == "connection.refresh_failed" && r.detail["reconnect"] == true));
    assert!(rows.iter().any(|r| r.event == "connection.refresh_failed" && r.detail["reconnect"] == false));
    h.assert_no_claude_token_in_clear();
    assert_eq!(h.app.store.verify_audit().unwrap(), Ok(rows.len()));
}

const GOOGLE_ACCESS: &str = "ya29.GOOGLE_ACCESS_never_leaves_warden";
const GOOGLE_REFRESH: &str = "1//GOOGLE_REFRESH_never_leaves_warden";
const GOOGLE_CLIENT: &str = "warden-google.apps.googleusercontent.com";
const GOOGLE_SECRET: &str = "GOCSPX-test-secret";

#[derive(Clone, Default)]
struct GoogleFake(Arc<Mutex<GoogleState>>);

#[derive(Default)]
struct GoogleState {
    /// code -> (code_challenge, account email)
    codes: HashMap<String, (String, String)>,
    email: String,
    revoked: Vec<String>,
}

async fn google_token(State(g): State<GoogleFake>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    assert_eq!(form["client_id"], GOOGLE_CLIENT);
    assert_eq!(form["client_secret"], GOOGLE_SECRET, "the secret goes in the form, from its file");
    let scope = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/devstorage.read_only";
    let mut st = g.0.lock().unwrap();
    match form["grant_type"].as_str() {
        "authorization_code" => {
            let Some((challenge, email)) = st.codes.remove(&form["code"]) else {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response();
            };
            assert_eq!(b64(&sha256(form["code_verifier"].as_bytes())), challenge, "PKCE");
            st.email = email;
            axum::Json(json!({"access_token": GOOGLE_ACCESS, "refresh_token": GOOGLE_REFRESH, "expires_in": 3599, "scope": scope, "token_type": "Bearer"}))
                .into_response()
        }
        "refresh_token" => {
            assert_eq!(form["refresh_token"], GOOGLE_REFRESH);
            axum::Json(json!({"access_token": GOOGLE_ACCESS, "expires_in": 3599, "scope": scope})).into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn google_tokeninfo(State(g): State<GoogleFake>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    assert_eq!(form["access_token"], GOOGLE_ACCESS);
    let email = g.0.lock().unwrap().email.clone();
    axum::Json(json!({"aud": GOOGLE_CLIENT, "azp": GOOGLE_CLIENT, "email": email, "email_verified": "true",
                      "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/devstorage.read_only"}))
    .into_response()
}

async fn google_revoke(State(g): State<GoogleFake>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    g.0.lock().unwrap().revoked.push(form["token"].clone());
    StatusCode::OK.into_response()
}

fn sha256(b: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, b).as_ref().to_vec()
}

/// (method, path and query, Authorization, header names)
type RegistryHit = (String, String, String, Vec<String>);

/// Requests seen, and the other host that cross-host redirects point to.
#[derive(Clone, Default)]
struct Registry(Arc<Mutex<Vec<RegistryHit>>>, Arc<Mutex<String>>);

const LAYER_OK: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LAYER_ELSEWHERE: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn registry_any(State(r): State<Registry>, req: Request) -> Response {
    let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
    let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    let names = req.headers().keys().map(|k| k.as_str().to_string()).collect();
    r.0.lock().unwrap().push((req.method().to_string(), path.clone(), auth, names));
    let image = "/v2/example-artifacts/team/app/develop";
    match path.as_str() {
        "/v2/" => ([("docker-distribution-api-version", "registry/2.0")], "{}").into_response(),
        p if p == format!("{image}/manifests/13") => (
            [
                ("content-type", "application/vnd.docker.distribution.manifest.list.v2+json"),
                ("docker-content-digest", LAYER_OK),
                ("set-cookie", "s=1"),
                ("x-goog-something", "internal"),
            ],
            "MANIFEST",
        )
            .into_response(),
        p if p == format!("{image}/blobs/{LAYER_OK}") => (
            StatusCode::FOUND,
            [("location", "/artifacts-downloads/namespaces/example-artifacts/x?sig=1")],
            "",
        )
            .into_response(),
        "/artifacts-downloads/namespaces/example-artifacts/x?sig=1" => ([("content-type", "application/octet-stream")], "LAYER").into_response(),
        p if p == format!("{image}/manifests/denied") => (StatusCode::UNAUTHORIZED, [("www-authenticate", "Bearer realm=x")], "{}").into_response(),
        p if p == format!("{image}/blobs/{LAYER_ELSEWHERE}") => {
            let elsewhere = format!("{}/stolen?sig=1", r.1.lock().unwrap());
            (StatusCode::FOUND, [("location", elsewhere)], "").into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

const IMAGE: &str = "europe-docker.pkg.dev/example-artifacts/team/app/develop";

async fn google_harness() -> (H, GoogleFake, Registry) {
    let g = GoogleFake::default();
    let (gl, gurl) = bind().await;
    spawn(
        gl,
        Router::new()
            .route("/token", post(google_token))
            .route("/tokeninfo", post(google_tokeninfo))
            .route("/revoke", post(google_revoke))
            .with_state(g.clone()),
    );
    let reg = Registry::default();
    let (rl, rurl) = bind().await;
    spawn(rl, Router::new().fallback(registry_any).with_state(reg.clone()));
    // Another host: redirects there must not be followed. Anything that arrives is recorded.
    let (sl, surl) = bind().await;
    *reg.1.lock().unwrap() = surl;
    spawn(
        sl,
        Router::new()
            .fallback(|State(r): State<Registry>, req: Request| async move {
                let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                r.0.lock().unwrap().push(("ELSEWHERE".into(), req.uri().to_string(), auth, vec![]));
                "STOLEN"
            })
            .with_state(reg.clone()),
    );
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("gsecret-{}", warden::util::new_id("t")));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("google.secret");
    std::fs::write(&secret, GOOGLE_SECRET).unwrap();
    let h = harness_with(json!({"gcp": {
        "client_id": GOOGLE_CLIENT, "client_secret_file": secret,
        "authorize_url": format!("{gurl}/auth"), "token_url": format!("{gurl}/token"),
        "tokeninfo_url": format!("{gurl}/tokeninfo"), "revoke_url": format!("{gurl}/revoke"),
        "expected_email": "owner@work.example",
        "upstreams": {"europe-docker.pkg.dev": rurl},
        "presets": {"app-env": {"description": "app", "artifacts": [IMAGE]}}
    }}))
    .await;
    (h, g, reg)
}

impl H {
    async fn connect_google_as(&self, b: &mut Browser, g: &GoogleFake, email: &str) -> Page {
        let p = b.get(&format!("{}/", self.browser)).await;
        if p.status == StatusCode::SEE_OTHER {
            let p = b.get(&format!("{}/login", self.browser)).await;
            let p = pocket_id(self, b, &p.location, json!({"auth_time": now() - 7200}), IDP_KEY_B64).await;
            assert_eq!(p.status, StatusCode::SEE_OTHER);
        }
        let p = b.get(&format!("{}/", self.browser)).await;
        assert!(p.body.contains("/connections/google\""), "{}", p.body);
        let p = b.post(&format!("{}/connections/google", self.browser), &csrf_in(&p.body)).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
        let q = query(&p.location);
        assert_eq!(
            (q["prompt"].as_str(), q["max_age"].as_str()),
            ("login", "0"),
            "connecting Google asks for the passkey again"
        );
        let p = pocket_id(self, b, &p.location, json!({}), IDP_KEY_B64).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
        let q = query(&p.location);
        assert_eq!((q["access_type"].as_str(), q["code_challenge_method"].as_str()), ("offline", "S256"));
        assert!(
            q["scope"].contains("devstorage.read_only") && !q["scope"].contains("cloud-platform"),
            "{}",
            q["scope"]
        );
        let code = warden::util::new_id("code");
        g.0.lock().unwrap().codes.insert(code.clone(), (q["code_challenge"].clone(), email.to_string()));
        b.get(&format!("{}?code={code}&state={}&scope=x", q["redirect_uri"], q["state"])).await
    }

    async fn registry(&self, session: &str, method: reqwest::Method, path: &str) -> reqwest::Response {
        self.http
            .request(method, format!("{}/registry/{path}", self.api))
            .bearer_auth(session)
            .send()
            .await
            .unwrap()
    }
}

/// Same-host redirects are followed by warden and cross-host ones refused; the grant belongs to the
/// keeper task, not the sandbox.
#[tokio::test]
async fn a_sandbox_reads_only_its_preset_through_the_registry_proxy() {
    let (h, g, reg) = google_harness().await;
    let mut b = Browser::new(&h);
    let p = h.connect_google_as(&mut b, &g, "owner@home.example").await;
    assert!(p.status == 403 && p.body.contains("not the expected one"), "{} {}", p.status, p.body);
    assert!(h.app.store.connection("google").unwrap().is_none());
    let p = h.connect_google_as(&mut b, &g, "owner@work.example").await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert!(p.body.contains("Google connected"), "{}", p.body);

    let keeper = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    let manifest = "europe-docker.pkg.dev/v2/example-artifacts/team/app/develop/manifests/13";
    let r = h.registry(&keeper, reqwest::Method::GET, manifest).await;
    assert_eq!(r.status(), 403);
    assert!(reg.0.lock().unwrap().is_empty());

    let sandbox = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "sandbox").await;
    let ask = json!({"system": "gcp", "scope": {"preset": "app-env"}, "duration": "72h", "reason": "pull the app stack in its sandbox"});
    let r = h
        .http
        .post(format!("{}/api/requests", h.api))
        .bearer_auth(&sandbox)
        .json(&ask)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let mut wider = ask.clone();
    wider["scope"]["artifacts"] = json!(["europe-docker.pkg.dev/example-artifacts/fp/other/image"]);
    let r = h
        .http
        .post(format!("{}/api/requests", h.api))
        .bearer_auth(&keeper)
        .json(&wider)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    let req = h.request(&keeper, ask).await;
    assert_eq!(
        (req["status"].as_str(), req["mode"].as_str(), req["preset"].as_str()),
        (Some("pending"), Some("read"), Some("app-env")),
        "{req}"
    );
    let id = req["id"].as_str().unwrap().to_string();
    let page = b.get(&format!("{}/r/{id}", h.browser)).await;
    assert!(
        page.body.contains(IMAGE) && page.body.contains("devstorage.read_only"),
        "the owner sees the whole list before approving: {}",
        page.body
    );
    assert_eq!(h.approve(&mut b, &id, json!({})).await.status, 200);

    let r = h.registry(&keeper, reqwest::Method::GET, manifest).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["docker-content-digest"], LAYER_OK);
    assert!(r.headers().get("set-cookie").is_none() && r.headers().get("x-goog-something").is_none());
    assert_eq!(r.text().await.unwrap(), "MANIFEST");
    {
        let seen = reg.0.lock().unwrap();
        let (method, path, auth, _) = seen.last().unwrap();
        assert_eq!((method.as_str(), path.as_str()), ("GET", "/v2/example-artifacts/team/app/develop/manifests/13"));
        assert_eq!(auth, &format!("Bearer {GOOGLE_ACCESS}"));
        assert!(
            !seen.iter().any(|(_, _, a, _)| a.contains(&keeper)),
            "the session token never reaches the registry"
        );
    }
    assert_eq!(h.registry(&keeper, reqwest::Method::GET, "europe-docker.pkg.dev/v2/").await.status(), 200);
    // A registry 401 becomes 502, or the client would take it for an expired warden session.
    let r = h
        .registry(
            &keeper,
            reqwest::Method::GET,
            "europe-docker.pkg.dev/v2/example-artifacts/team/app/develop/manifests/denied",
        )
        .await;
    assert_eq!(r.status(), 502);
    assert!(r.headers().get("www-authenticate").is_none());
    let r = h
        .registry(
            &keeper,
            reqwest::Method::GET,
            &format!("europe-docker.pkg.dev/v2/example-artifacts/team/app/develop/blobs/{LAYER_OK}"),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("location").is_none());
    assert_eq!(r.text().await.unwrap(), "LAYER");
    // Following it would send the Google token to another host.
    let r = h
        .registry(
            &keeper,
            reqwest::Method::GET,
            &format!("europe-docker.pkg.dev/v2/example-artifacts/team/app/develop/blobs/{LAYER_ELSEWHERE}"),
        )
        .await;
    assert_eq!(r.status(), 502);
    assert!(r.headers().get("location").is_none());
    assert!(
        !reg.0.lock().unwrap().iter().any(|(m, ..)| m == "ELSEWHERE"),
        "a redirect to another host was followed"
    );

    let before = reg.0.lock().unwrap().len();
    for (method, path, status) in [
        (reqwest::Method::GET, "europe-docker.pkg.dev/v2/example-artifacts/fp/other/manifests/1", 403),
        (reqwest::Method::GET, "europe-docker.pkg.dev/v2/_catalog", 403),
        (
            reqwest::Method::PUT,
            "europe-docker.pkg.dev/v2/example-artifacts/team/app/develop/manifests/13",
            405,
        ),
        (
            reqwest::Method::GET,
            "europe-west1-docker.pkg.dev/v2/example-artifacts/team/app/develop/manifests/13",
            403,
        ),
        (reqwest::Method::GET, "ghcr.io/v2/o/r/i/manifests/1", 403),
    ] {
        assert_eq!(h.registry(&keeper, method, path).await.status(), status, "{path}");
    }
    assert_eq!(
        raw(
            &h.api,
            "/registry/europe-docker.pkg.dev/v2/example-artifacts/fp/../app/develop/manifests/13",
            &format!("Bearer {keeper}")
        )
        .await,
        400
    );
    assert_eq!(reg.0.lock().unwrap().len(), before);

    assert_eq!(h.registry(&sandbox, reqwest::Method::GET, manifest).await.status(), 403);
    let reopened = h.session_as("sandbox", "sandbox-claude", ALLOC_A, "keeper").await;
    assert_eq!(h.registry(&reopened, reqwest::Method::GET, manifest).await.status(), 200);
    let other = h.session_as("sandbox", "sandbox-claude", ALLOC_B, "keeper").await;
    assert_eq!(h.registry(&other, reqwest::Method::GET, manifest).await.status(), 403);

    let grant = h.app.store.grant_for_request(&id).unwrap().unwrap();
    h.app.store.revoke_grant(&grant.id, "test", None, now()).unwrap().unwrap();
    h.app.live.revoke(&grant.id);
    assert_eq!(h.registry(&keeper, reqwest::Method::GET, manifest).await.status(), 403);

    let rows = format!("{:?}", h.events());
    assert!(!rows.contains("ya29.") && !rows.contains("1//GOOGLE"), "a Google token leaked into the audit");
    for f in std::fs::read_dir(&h.app.cfg.data_dir).unwrap() {
        let bytes = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!bytes.windows(5).any(|w| w == b"ya29."), "a Google token is in clear in the database files");
    }

    let p = b.get(&format!("{}/", h.browser)).await;
    let p = b.post(&format!("{}/connections/google/disconnect", h.browser), &csrf_in(&p.body)).await;
    let p = pocket_id(&h, &mut b, &p.location, json!({}), IDP_KEY_B64).await;
    assert!(p.body.contains("Google has revoked"), "{}", p.body);
    assert_eq!(g.0.lock().unwrap().revoked, vec![GOOGLE_REFRESH.to_string()]);
    assert!(h.app.store.connection("google").unwrap().is_none());
}
