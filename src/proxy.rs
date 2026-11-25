// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! GitHub proxy for smart-HTTP git and the REST API, limited to what a live grant of the session
//! allows. The connection's token is added here, so the client never sees it.
//!
//! `/api/v3` is the GitHub Enterprise prefix, so `gh` works with GH_HOST pointing here. GraphQL is
//! not proxied: a query can reach any repository, so it cannot be scoped.
//!
//! Every request, allowed or not, is audited and so spends the session's audit budget (budget.rs).
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{Stream, StreamExt};
use serde_json::{Value, json};

use crate::app::App;
use crate::connection::TokenError;
use crate::receive::{self, COMMANDS_MAX, PackScanner, Walk, parse_commands, walk};
use crate::scope::{Mode, Power, Repo, find_grant, scope_powers};
use crate::store::{Audit, GrantRow};
use crate::util::now;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Git,
    Api,
}

impl Surface {
    fn as_str(self) -> &'static str {
        match self {
            Surface::Git => "git",
            Surface::Api => "api",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Surface::Git => "/git/github.com/",
            Surface::Api => "/api/v3/",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Target {
    pub surface: Surface,
    pub repo: Repo,
    pub access: Mode,
    /// Path and query, relative to GitHub's base URL.
    pub upstream: String,
    /// Without the query.
    pub audit_path: String,
    /// Segments after `{owner}/{repo}`.
    pub rest: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct Deny {
    pub status: StatusCode,
    pub message: String,
}

fn deny(status: StatusCode, message: impl Into<String>) -> Deny {
    Deny {
        status,
        message: message.into(),
    }
}

/// Rejects anything that could make GitHub resolve a different repository or path than the one checked.
fn segments(path: &str, allow_percent: bool) -> Result<Vec<&str>, String> {
    if path.is_empty() {
        return Err("empty path".into());
    }
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if !allow_percent {
                    return Err("percent-encoding is not allowed in this path".into());
                }
                let (Some(h), Some(l)) = (b.get(i + 1), b.get(i + 2)) else {
                    return Err("truncated percent-encoding".into());
                };
                if !h.is_ascii_hexdigit() || !l.is_ascii_hexdigit() {
                    return Err("invalid percent-encoding".into());
                }
                let v = u8::from_str_radix(&path[i + 1..i + 3], 16).map_err(|_| "invalid percent-encoding")?;
                if matches!(v, b'/' | b'\\' | b'.' | b'%') || v < 0x20 || v == 0x7f {
                    return Err("encoded '/', '\\', '.', '%' or control characters are not allowed".into());
                }
                i += 3;
                continue;
            }
            b'\\' => return Err("'\\' is not allowed in a path".into()),
            c if c <= 0x20 || c >= 0x7f => {
                return Err("control, space or non-ASCII characters are not allowed in a path".into());
            }
            _ => {}
        }
        i += 1;
    }
    let segs: Vec<&str> = path.split('/').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return Err("empty path segment ('//')".into());
    }
    if segs.iter().any(|s| *s == "." || *s == "..") {
        return Err("'.' and '..' path segments are not allowed".into());
    }
    Ok(segs)
}

/// `path` is what follows `/git/github.com/`.
pub fn classify_git(method: &Method, path: &str, query: Option<&str>) -> Result<Target, Deny> {
    let segs = segments(path, false).map_err(|e| deny(StatusCode::BAD_REQUEST, format!("warden: {e}")))?;
    if segs.len() < 3 {
        return Err(deny(
            StatusCode::NOT_FOUND,
            "warden: not a git path; use https://<warden>/git/github.com/<owner>/<repo>.git",
        ));
    }
    let name = segs[1].strip_suffix(".git").unwrap_or(segs[1]);
    let repo = Repo::new(segs[0], name).ok_or_else(|| deny(StatusCode::BAD_REQUEST, "warden: not a valid GitHub owner/repo"))?;
    let rest = &segs[2..];
    let q = query.unwrap_or("");
    let access = match (method, rest) {
        (&Method::GET, ["info", "refs"]) => match q {
            "service=git-upload-pack" => Mode::Read,
            "service=git-receive-pack" => Mode::Write,
            _ => {
                return Err(deny(
                    StatusCode::FORBIDDEN,
                    "warden: only the smart protocol is proxied (info/refs?service=git-upload-pack or git-receive-pack)",
                ));
            }
        },
        (&Method::POST, ["git-upload-pack"]) if q.is_empty() => Mode::Read,
        (&Method::POST, ["git-receive-pack"]) if q.is_empty() => Mode::Write,
        (_, ["info", "lfs", ..]) => {
            return Err(deny(StatusCode::FORBIDDEN, "warden: Git LFS is not proxied"));
        }
        _ => {
            return Err(deny(
                StatusCode::FORBIDDEN,
                "warden: only git smart-HTTP is proxied (GET info/refs, POST git-upload-pack, POST git-receive-pack)",
            ));
        }
    };
    let audit_path = format!("/{}/{}.git/{}", repo.owner, repo.name, rest.join("/"));
    let upstream = if q.is_empty() { audit_path.clone() } else { format!("{audit_path}?{q}") };
    let rest = rest.iter().map(|s| s.to_string()).collect();
    Ok(Target {
        surface: Surface::Git,
        repo,
        access,
        upstream,
        audit_path,
        rest,
    })
}

/// API writes: code, branches, issues and PRs (what `git push` already allows), never repository
/// administration or protections. They run with the owner's token, so an admin owner bypasses branch
/// protections that allow bypassing. `#` a number, `*` one segment, `**` one or more (last only).
const WRITE_RULES: &[(&str, &str)] = &[
    ("POST", "issues"),
    ("PATCH", "issues/#"),
    ("POST", "issues/#/comments"),
    ("PATCH", "issues/comments/#"),
    ("DELETE", "issues/comments/#"),
    ("POST", "issues/#/labels"),
    ("PUT", "issues/#/labels"),
    ("DELETE", "issues/#/labels/*"),
    ("POST", "issues/#/assignees"),
    ("DELETE", "issues/#/assignees"),
    ("POST", "issues/#/reactions"),
    ("POST", "issues/comments/#/reactions"),
    ("POST", "pulls"),
    ("PATCH", "pulls/#"),
    ("PUT", "pulls/#/merge"),
    ("PUT", "pulls/#/update-branch"),
    ("POST", "pulls/#/comments"),
    ("POST", "pulls/#/comments/#/replies"),
    ("PATCH", "pulls/comments/#"),
    ("DELETE", "pulls/comments/#"),
    ("POST", "pulls/comments/#/reactions"),
    ("POST", "pulls/#/reviews"),
    ("PUT", "pulls/#/reviews/#"),
    ("POST", "pulls/#/reviews/#/events"),
    ("POST", "pulls/#/requested_reviewers"),
    ("DELETE", "pulls/#/requested_reviewers"),
    ("POST", "git/blobs"),
    ("POST", "git/trees"),
    ("POST", "git/commits"),
    ("POST", "git/refs"),
    ("PATCH", "git/refs/**"),
    ("DELETE", "git/refs/**"),
    ("PUT", "contents/**"),
    ("DELETE", "contents/**"),
    ("POST", "actions/runs/#/rerun"),
    ("POST", "actions/runs/#/rerun-failed-jobs"),
    ("POST", "actions/runs/#/cancel"),
    ("POST", "actions/jobs/#/rerun"),
];

fn rule_matches(pattern: &str, rest: &[&str]) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let mut i = 0;
    for (k, p) in pat.iter().enumerate() {
        if *p == "**" {
            return k == pat.len() - 1 && rest.len() > i;
        }
        let Some(seg) = rest.get(i) else { return false };
        let ok = match *p {
            "#" => !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_digit()),
            "*" => !seg.is_empty(),
            lit => *seg == lit,
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    i == rest.len()
}

fn write_allowed(method: &Method, rest: &[&str]) -> bool {
    WRITE_RULES.iter().any(|(m, p)| *m == method.as_str() && rule_matches(p, rest))
}

/// An allowlist, so a new GitHub endpoint stays closed until added here: a blanket GET once exposed
/// secret scanning alerts, Actions variables and webhook deliveries. `""` is the repository itself.
pub const READ_RULES: &[&str] = &[
    "",
    "contents",
    "contents/**",
    "readme",
    "readme/**",
    "git/**",
    "commits",
    "commits/**",
    "compare/**",
    "branches",
    "branches/*",
    "tags",
    "tarball",
    "tarball/**",
    "zipball",
    "zipball/**",
    "languages",
    "contributors",
    "topics",
    "license",
    "comments",
    "comments/**",
    "pulls",
    "pulls/**",
    "issues",
    "issues/**",
    "labels",
    "labels/*",
    "milestones",
    "milestones/**",
    "assignees",
    "assignees/*",
    "statuses/*",
    "check-runs/**",
    "check-suites/**",
    "actions/workflows",
    "actions/workflows/**",
    "actions/runs",
    "actions/runs/**",
    "actions/jobs/**",
    "releases",
    "releases/**",
];

/// Never readable, even if READ_RULES is widened: these hold secrets or security findings, or say who
/// has access. Listed apart so the error can say why.
pub const SENSITIVE_READS: &[&str] = &[
    "hooks",
    "secret-scanning",
    "code-scanning",
    "dependabot",
    "codespaces",
    "environments",
    "security-advisories",
    "keys",
    "collaborators",
    "invitations",
    "actions/secrets",
    "actions/variables",
    "actions/organization-secrets",
    "actions/organization-variables",
    "actions/runners",
    "actions/oidc",
];

/// Decoded and lowercased, so `secret%2Dscanning` cannot slip through a future READ_RULES entry.
fn sensitive_read(rest: &[&str]) -> bool {
    let decoded: Vec<String> = rest.iter().map(|s| percent_decode(s).to_ascii_lowercase()).collect();
    SENSITIVE_READS.iter().any(|family| {
        let f: Vec<&str> = family.split('/').collect();
        decoded.len() >= f.len() && f.iter().zip(&decoded).all(|(a, b)| a == b)
    })
}

fn read_allowed(rest: &[&str]) -> bool {
    !sensitive_read(rest) && READ_RULES.iter().any(|p| if p.is_empty() { rest.is_empty() } else { rule_matches(p, rest) })
}

/// `path` is what follows `/api/v3/`.
pub fn classify_api(method: &Method, path: &str, query: Option<&str>) -> Result<Target, Deny> {
    if path == "graphql" || path.starts_with("graphql/") {
        return Err(deny(
            StatusCode::FORBIDDEN,
            "warden: GraphQL is not proxied (a query can reach any repository, so it cannot be scoped). Use the REST API: /api/v3/repos/{owner}/{repo}/…",
        ));
    }
    // A trailing slash is ignored for matching but forwarded as sent.
    let bare = path.strip_suffix('/').unwrap_or(path);
    let segs = segments(bare, true).map_err(|e| deny(StatusCode::BAD_REQUEST, format!("warden: {e}")))?;
    if segs.len() < 3 || segs[0] != "repos" {
        return Err(deny(StatusCode::FORBIDDEN, "warden: only /api/v3/repos/{owner}/{repo}/… is proxied"));
    }
    if segs[1].contains('%') || segs[2].contains('%') {
        return Err(deny(StatusCode::BAD_REQUEST, "warden: the owner and the repository cannot be percent-encoded"));
    }
    let repo = Repo::new(segs[1], segs[2]).ok_or_else(|| deny(StatusCode::BAD_REQUEST, "warden: not a valid GitHub owner/repo"))?;
    let rest = &segs[3..];
    let access = match *method {
        Method::GET | Method::HEAD => {
            if sensitive_read(rest) {
                return Err(deny(
                    StatusCode::FORBIDDEN,
                    format!(
                        "warden: GET /repos/{repo}/{} is never proxied, with any grant: it can hold secrets or security findings, or says who has access (webhooks, secret and code scanning, Dependabot, Actions secrets, variables and runners, environments, deploy keys, collaborators)",
                        rest.join("/")
                    ),
                ));
            }
            if !read_allowed(rest) {
                return Err(deny(
                    StatusCode::FORBIDDEN,
                    format!(
                        "warden: GET /repos/{repo}/{} is not among the reads warden proxies (the repository, its contents and history, branches, tags, pull requests, issues, labels, milestones, CI status and runs, and releases)",
                        rest.join("/")
                    ),
                ));
            }
            Mode::Read
        }
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE => {
            if !write_allowed(method, rest) {
                return Err(deny(
                    StatusCode::FORBIDDEN,
                    format!(
                        "warden: {method} /repos/{repo}/{} is not allowed through warden, even with write access (only issues, pull requests, branches, file contents and re-running CI)",
                        rest.join("/")
                    ),
                ));
            }
            Mode::Write
        }
        _ => {
            return Err(deny(StatusCode::METHOD_NOT_ALLOWED, format!("warden: method {method} is not proxied")));
        }
    };
    if let Some(q) = query
        && q.bytes().any(|c| !(0x21..0x7f).contains(&c) || c == b'#')
    {
        return Err(deny(StatusCode::BAD_REQUEST, "warden: invalid query string"));
    }
    let audit_path = format!("/repos/{repo}{}", rest.iter().map(|s| format!("/{s}")).collect::<String>());
    let upstream = match query {
        Some(q) if !q.is_empty() => format!("/{path}?{q}"),
        _ => format!("/{path}"),
    };
    let rest = rest.iter().map(|s| s.to_string()).collect();
    Ok(Target {
        surface: Surface::Api,
        repo,
        access,
        upstream,
        audit_path,
        rest,
    })
}

/// `Bearer`, `token` (gh) or Basic with the token as password (git's credential helper).
pub fn presented_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = v.split_once(' ')?;
    let token = match scheme.to_ascii_lowercase().as_str() {
        "bearer" | "token" => rest.trim().to_string(),
        "basic" => {
            let raw = String::from_utf8(STANDARD.decode(rest.trim()).ok()?).ok()?;
            let (user, pass) = raw.split_once(':')?;
            if pass.is_empty() { user.to_string() } else { pass.to_string() }
        }
        _ => return None,
    };
    (!token.is_empty() && token.len() <= 200).then_some(token)
}

const REQUEST_HEADERS_GIT: &[&str] = &[
    "accept",
    "accept-encoding",
    "content-encoding",
    "content-length",
    "content-type",
    "git-protocol",
    "user-agent",
];
const REQUEST_HEADERS_API: &[&str] = &[
    "accept",
    "accept-encoding",
    "content-length",
    "content-type",
    "if-modified-since",
    "if-none-match",
    "user-agent",
    "x-github-api-version",
];
/// No cookies, and nothing that reveals the token's scopes or expiry.
const RESPONSE_HEADERS: &[&str] = &[
    "cache-control",
    "content-encoding",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "link",
    "location",
    "pragma",
    "retry-after",
    "vary",
    "x-github-media-type",
    "x-github-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
    "x-ratelimit-used",
];

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

/// git prints plain text as `remote: …` and gh prints the JSON `message`. A 401 with
/// WWW-Authenticate makes git call its credential helper.
fn refusal(surface: Surface, status: StatusCode, message: &str) -> Response {
    let mut resp = match surface {
        Surface::Git => (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], format!("{message}\n")).into_response(),
        Surface::Api => (status, axum::Json(json!({"message": message, "documentation_url": ""}))).into_response(),
    };
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"warden\""));
    }
    resp
}

pub async fn git(State(app): State<Arc<App>>, req: Request) -> Response {
    let path = req.uri().path().strip_prefix(Surface::Git.prefix()).unwrap_or("").to_string();
    forward(app, Surface::Git, path, req).await
}

pub async fn api(State(app): State<Arc<App>>, req: Request) -> Response {
    let path = req.uri().path().strip_prefix(Surface::Api.prefix()).unwrap_or("").to_string();
    forward(app, Surface::Api, path, req).await
}

struct Ctx {
    app: Arc<App>,
    surface: Surface,
    method: Method,
    at: i64,
    actor: String,
    session: Option<String>,
    detail: Value,
}

impl Ctx {
    fn record(&self, grant: Option<&str>, detail: Value) {
        let mut a = Audit::new(self.actor.clone(), "proxy", detail);
        if let Some(s) = &self.session {
            a = a.session(s);
        }
        if let Some(g) = grant {
            a = a.grant(g);
        }
        if self.session.is_none() {
            self.app.audit_anonymous(a, self.at);
            return;
        }
        if let Err(e) = self.app.store.audit(a, self.at) {
            tracing::error!(error = %e, "cannot write the audit line of a proxied request");
        }
    }

    /// For a session over its audit budget: no audit line, only a debug log (app.rs warns once a minute).
    fn refuse_unrecorded(&self, over: crate::app::OverBudget) -> Response {
        tracing::debug!(surface = self.surface.as_str(), method = %self.method, status = over.status.as_u16(), "proxy: denied without an audit line (over budget)");
        let mut resp = refusal(self.surface, over.status, &over.message);
        over.stamp(&mut resp);
        resp
    }

    fn refuse(&self, status: StatusCode, message: &str) -> Response {
        let mut detail = self.detail.clone();
        detail["decision"] = json!("denied");
        detail["status"] = json!(status.as_u16());
        detail["reason"] = json!(message);
        tracing::info!(surface = self.surface.as_str(), method = %self.method, status = status.as_u16(), reason = message, "proxy: denied");
        self.record(None, detail);
        refusal(self.surface, status, message)
    }

    fn respond(&self, resp: reqwest::Response, grant: &GrantRow) -> Response {
        let status = resp.status();
        let mut detail = self.detail.clone();
        detail["decision"] = json!("allowed");
        detail["status"] = json!(status.as_u16());
        tracing::info!(surface = self.surface.as_str(), method = %self.method, path = %detail["path"], status = status.as_u16(), "proxy: forwarded");
        self.record(Some(&grant.id), detail);
        let mut out = Response::builder().status(status.as_u16());
        for (k, v) in resp.headers() {
            if RESPONSE_HEADERS.contains(&k.as_str())
                && let Ok(name) = HeaderName::from_bytes(k.as_str().as_bytes())
            {
                out = out.header(name, v.clone());
            }
        }
        let body = guard(resp.bytes_stream(), self.app.clone(), grant.id.clone(), grant.expires_at, "download");
        out.body(Body::from_stream(body)).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
    }

    async fn send(&self, request: reqwest::RequestBuilder, token: &str, grant: &GrantRow) -> Response {
        let request = match request.build() {
            Ok(r) => r,
            Err(e) => {
                return self.refuse(
                    StatusCode::BAD_GATEWAY,
                    &format!("warden: the request to GitHub could not be made ({})", e.without_url()),
                );
            }
        };
        // Only a buffered body can be cloned; a streamed one cannot be retried.
        let again = request.try_clone();
        match self.app.http.execute(request).await {
            Ok(r) => self.answer(r, token, again, grant).await,
            Err(e) => self.refuse(StatusCode::BAD_GATEWAY, &format!("warden: GitHub did not answer ({})", e.without_url())),
        }
    }

    /// A 401 may mean `token` expired or was renewed in flight. With a newer token from connection.rs
    /// the request is retried once if replayable; with the same token GitHub's 401 passes through.
    async fn answer(&self, resp: reqwest::Response, token: &str, again: Option<reqwest::Request>, grant: &GrantRow) -> Response {
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return self.respond(resp, grant);
        }
        let current = match self.app.github_token(self.session.as_deref(), Some(token)).await {
            Ok(Some(t)) if t != token => t,
            Ok(_) => return self.respond(resp, grant),
            Err(e) => return self.token_refused(e),
        };
        let Some(mut request) = again else {
            return self.refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "warden: the GitHub token was renewed while this request was on its way, and its body cannot be sent twice; send it again",
            );
        };
        // Renewing can take a while; the grant may have ended meanwhile.
        if self.app.live.is_revoked(&grant.id) || now() >= grant.expires_at {
            return self.refuse(StatusCode::FORBIDDEN, "warden: the grant ended while the GitHub token was being renewed");
        }
        let Some(auth) = upstream_auth(self.surface, &current) else {
            return self.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: the GitHub token is not usable");
        };
        request.headers_mut().insert(reqwest::header::AUTHORIZATION, auth);
        match self.app.http.execute(request).await {
            Ok(r) => self.respond(r, grant),
            Err(e) => self.refuse(StatusCode::BAD_GATEWAY, &format!("warden: GitHub did not answer ({})", e.without_url())),
        }
    }

    fn token_refused(&self, e: TokenError) -> Response {
        match e {
            TokenError::Reconnect(why) => self.refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("warden: the GitHub connection has to be connected again (renewing its token failed: {why}); the owner does it in warden's panel"),
            ),
            TokenError::Unavailable(why) => self.refuse(
                StatusCode::BAD_GATEWAY,
                &format!("warden: GitHub did not renew the token ({why}); try again in a moment"),
            ),
            TokenError::Internal(e) => {
                tracing::error!(error = %e, "cannot open the GitHub connection");
                self.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: the GitHub connection cannot be read")
            }
        }
    }
}

/// git over HTTPS takes an OAuth token as the Basic password.
fn upstream_auth(surface: Surface, token: &str) -> Option<HeaderValue> {
    let auth = match surface {
        Surface::Git => format!("Basic {}", STANDARD.encode(format!("x-access-token:{token}"))),
        Surface::Api => format!("Bearer {token}"),
    };
    let mut v = HeaderValue::from_str(&auth).ok()?;
    v.set_sensitive(true);
    Some(v)
}

/// Room for a whole file in base64 (`contents`).
const API_BODY_MAX: usize = 32 << 20;

async fn forward(app: Arc<App>, surface: Surface, path: String, req: Request) -> Response {
    let method = req.method().clone();
    let query = req.uri().query().map(String::from);
    let mut ctx = Ctx {
        app: app.clone(),
        surface,
        method: method.clone(),
        at: now(),
        actor: "anonymous".into(),
        session: None,
        detail: json!({"surface": surface.as_str(), "method": method.as_str(), "path": clip(&format!("{}{path}", surface.prefix()), 300)}),
    };
    let at = ctx.at;

    let session = match presented_token(req.headers()).map(|t| app.store.session_by_token(&t, at)) {
        Some(Ok(Some(s))) => s,
        Some(Err(e)) => {
            tracing::error!(error = %e, "session lookup failed");
            return ctx.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: internal error");
        }
        _ => {
            return ctx.refuse(StatusCode::UNAUTHORIZED, "warden: a valid warden session token is required");
        }
    };
    ctx.actor = format!("session:{}", session.id);
    ctx.session = Some(session.id.clone());
    // Every request is audited, so the audit budget is checked before anything else.
    if let Err(over) = app.session_audit_slot(&session.id, at) {
        return ctx.refuse_unrecorded(over);
    }

    let classified = match surface {
        Surface::Git => classify_git(&method, &path, query.as_deref()),
        Surface::Api => classify_api(&method, &path, query.as_deref()),
    };
    let target = match classified {
        Ok(t) => t,
        Err(d) => return ctx.refuse(d.status, &d.message),
    };
    ctx.detail["path"] = json!(target.audit_path);
    ctx.detail["repo"] = json!(target.repo.to_string());
    ctx.detail["access"] = json!(target.access.as_str());

    // A grant without powers first, before the GitHub token is used at all.
    let grants = match app.store.grants_of_session(&session.id, at) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(error = %e, "grant lookup failed");
            return ctx.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: internal error");
        }
    };
    let grant = match find_grant(&session.id, &grants, &target.repo, target.access, &[], at) {
        Ok(g) => g.clone(),
        Err(why) => return ctx.refuse(StatusCode::FORBIDDEN, &format!("warden: {why}")),
    };
    ctx.detail["grant"] = json!(grant.id);

    let token = match app.github_token(Some(&session.id), None).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return ctx.refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "warden: GitHub is not connected; the owner has to connect it in warden first",
            );
        }
        Err(e) => return ctx.token_refused(e),
    };

    let base = match surface {
        Surface::Git => app.cfg.github.web_base.trim_end_matches('/'),
        Surface::Api => app.cfg.github.api_base.trim_end_matches('/'),
    };
    let url = match (reqwest::Url::parse(&format!("{base}{}", target.upstream)), reqwest::Url::parse(base)) {
        (Ok(u), Ok(b)) if u.scheme() == b.scheme() && u.host_str() == b.host_str() && u.port_or_known_default() == b.port_or_known_default() => u,
        _ => {
            return ctx.refuse(StatusCode::BAD_REQUEST, "warden: the upstream URL is not GitHub's");
        }
    };
    let mut headers = reqwest::header::HeaderMap::new();
    let allowed = if surface == Surface::Git { REQUEST_HEADERS_GIT } else { REQUEST_HEADERS_API };
    for (k, v) in req.headers() {
        if allowed.contains(&k.as_str()) {
            headers.append(k.clone(), v.clone());
        }
    }
    if !headers.contains_key(reqwest::header::USER_AGENT) {
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(crate::github::USER_AGENT));
    }
    let Some(auth) = upstream_auth(surface, &token) else {
        return ctx.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: the GitHub token is not usable");
    };
    headers.insert(reqwest::header::AUTHORIZATION, auth);

    if surface == Surface::Git && target.access == Mode::Write && method == Method::POST {
        return push(&mut ctx, &target, &grants, &session.id, &token, url, headers, req.into_body()).await;
    }
    let mut upstream = app.http.request(method.clone(), url).headers(headers);
    if matches!(method, Method::GET | Method::HEAD) {
        return ctx.send(upstream, &token, &grant).await;
    }
    if surface == Surface::Api && api_reads_body(&method, &target.rest) {
        // GitHub also reads fields from the query (`?event=APPROVE`), which would bypass the body check.
        if query.as_deref().is_some_and(|q| !q.is_empty()) {
            return ctx.refuse(StatusCode::BAD_REQUEST, "warden: a query string is not allowed on this write");
        }
        let body = match axum::body::to_bytes(req.into_body(), API_BODY_MAX).await {
            Ok(b) => b,
            Err(_) => {
                return ctx.refuse(StatusCode::PAYLOAD_TOO_LARGE, "warden: the request body is too large (or broken) to check");
            }
        };
        let mut needs = match api_needs(&method, &target.rest, &body) {
            Ok(n) => n,
            Err(e) => return ctx.refuse(StatusCode::BAD_REQUEST, &format!("warden: {e}")),
        };
        // `update-branch` writes to the PR's head branch, which may be the default one or in a fork.
        if let Some(number) = &needs.pull_head {
            match app.github.pull_head(&target.repo, number, &token).await {
                Ok((full, branch)) if full.eq_ignore_ascii_case(&target.repo.to_string()) => needs.branch = Some(BranchRef::Named(branch)),
                Ok(_) => {
                    return ctx.refuse(
                        StatusCode::FORBIDDEN,
                        "warden: update-branch would write to the pull request's branch in another repository, which is outside the grant",
                    );
                }
                Err(e) => {
                    return ctx.refuse(StatusCode::BAD_GATEWAY, &format!("warden: cannot read the pull request ({e})"));
                }
            }
        }
        if let Some(branch) = &needs.branch {
            let default = match app.github.default_branch(&target.repo, &token).await {
                Ok(d) => d,
                Err(e) => {
                    return ctx.refuse(
                        StatusCode::BAD_GATEWAY,
                        &format!("warden: cannot read the default branch of {} ({e})", target.repo),
                    );
                }
            };
            if matches!(branch, BranchRef::Default) || matches!(branch, BranchRef::Named(b) if b.eq_ignore_ascii_case(&default)) {
                needs.powers.insert(Power::DefaultBranch);
            }
        }
        let powers: Vec<Power> = needs.powers.into_iter().collect();
        ctx.detail["powers"] = json!(powers.iter().map(|p| p.as_str()).collect::<Vec<_>>());
        let grant = match find_grant(&session.id, &grants, &target.repo, target.access, &powers, at) {
            Ok(g) => g.clone(),
            Err(why) => return ctx.refuse(StatusCode::FORBIDDEN, &format!("warden: {why}")),
        };
        ctx.detail["grant"] = json!(grant.id);
        upstream = upstream.body(reqwest::Body::from(body));
        return ctx.send(upstream, &token, &grant).await;
    }
    let body = guard(req.into_body().into_data_stream(), app.clone(), grant.id.clone(), grant.expires_at, "upload");
    ctx.send(upstream.body(reqwest::Body::wrap_stream(body)), &token, &grant).await
}

/// Every write `api_needs` has a rule for is buffered and checked: both come from `api_route`, so a rule
/// cannot exist without its check (a rerun rule once did, and plain write grants could re-run workflows).
fn api_reads_body(method: &Method, rest: &[String]) -> bool {
    api_route(method, rest).is_some()
}

enum ApiRoute {
    Merge,
    Rerun,
    UpdateBranch(String),
    Review,
    NewRef,
    MoveRef { delete: bool, refname: String },
    Contents,
}

fn api_route(method: &Method, rest: &[String]) -> Option<ApiRoute> {
    let r: Vec<&str> = rest.iter().map(String::as_str).collect();
    Some(match (method.as_str(), r.as_slice()) {
        ("PUT", ["pulls", _, "merge"]) => ApiRoute::Merge,
        ("POST", ["actions", "runs", _, "rerun" | "rerun-failed-jobs"]) | ("POST", ["actions", "jobs", _, "rerun"]) => ApiRoute::Rerun,
        ("PUT", ["pulls", number, "update-branch"]) => ApiRoute::UpdateBranch(number.to_string()),
        ("POST", ["pulls", _, "reviews"]) | ("POST", ["pulls", _, "reviews", _, "events"]) => ApiRoute::Review,
        ("POST", ["git", "refs"]) => ApiRoute::NewRef,
        (m @ ("PATCH" | "DELETE"), ["git", "refs", tail @ ..]) => ApiRoute::MoveRef {
            delete: m == "DELETE",
            refname: percent_decode(&tail.join("/")),
        },
        ("PUT" | "DELETE", ["contents", ..]) => ApiRoute::Contents,
        _ => return None,
    })
}

/// `Named` is compared with GitHub's default branch, so it may still turn out to be the default one.
#[derive(Debug, PartialEq)]
pub enum BranchRef {
    Default,
    Named(String),
}

#[derive(Debug, Default, PartialEq)]
pub struct ApiNeeds {
    pub powers: BTreeSet<Power>,
    pub branch: Option<BranchRef>,
    /// PR number of an `update-branch`, whose head branch has to be asked from GitHub.
    pub pull_head: Option<String>,
}

/// Rejects repeated keys: with `{"event":"COMMENT","event":"APPROVE"}` it is unknown which one GitHub reads.
fn strict_object(body: &[u8]) -> Result<serde_json::Map<String, Value>, String> {
    use serde::de::{Deserializer, Error, MapAccess, Visitor};
    struct Unique(serde_json::Map<String, Value>);
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Unique, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                    let mut m = serde_json::Map::new();
                    while let Some((k, v)) = a.next_entry::<String, Value>()? {
                        if m.contains_key(&k) {
                            return Err(A::Error::custom(format!("the key «{k}» is repeated")));
                        }
                        m.insert(k, v);
                    }
                    Ok(Unique(m))
                }
            }
            d.deserialize_map(V)
        }
    }
    serde_json::from_slice::<Unique>(body)
        .map(|u| u.0)
        .map_err(|e| format!("the request body is not a JSON object warden can check ({e})"))
}

/// Case-insensitive, so anything GitHub might take for a tag needs the power.
fn is_tag_ref(refname: &str) -> bool {
    refname.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("refs/tags/"))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Refs map to powers as they would in a push (receive.rs).
pub fn api_needs(method: &Method, rest: &[String], body: &[u8]) -> Result<ApiNeeds, String> {
    let mut n = ApiNeeds::default();
    let obj = || {
        if body.iter().all(u8::is_ascii_whitespace) {
            Ok(serde_json::Map::new())
        } else {
            strict_object(body)
        }
    };
    let Some(route) = api_route(method, rest) else {
        return Ok(n);
    };
    match route {
        ApiRoute::Merge => {
            n.powers.insert(Power::Merge);
        }
        ApiRoute::Rerun => {
            n.powers.insert(Power::Rerun);
        }
        ApiRoute::UpdateBranch(number) => n.pull_head = Some(number),
        ApiRoute::Review => match obj()?.get("event") {
            None | Some(Value::Null) => {}
            Some(Value::String(e)) if e.trim().eq_ignore_ascii_case("APPROVE") => {
                n.powers.insert(Power::Approve);
            }
            Some(Value::String(_)) => {}
            Some(_) => return Err("a review \"event\" must be a string".into()),
        },
        ApiRoute::NewRef => {
            let o = obj()?;
            let refname = o.get("ref").and_then(Value::as_str).ok_or("a new ref needs \"ref\"")?;
            if let Some(b) = refname.strip_prefix("refs/heads/") {
                n.branch = Some(BranchRef::Named(b.to_string()));
            } else if is_tag_ref(refname) {
                n.powers.insert(Power::Tags);
                if !refname.starts_with("refs/tags/") {
                    n.powers.insert(Power::ForcePush);
                }
            } else {
                n.powers.insert(Power::ForcePush);
            }
        }
        ApiRoute::MoveRef { delete, refname } => {
            let refname = refname.strip_prefix("refs/").unwrap_or(&refname);
            if let Some(b) = refname.strip_prefix("heads/") {
                n.branch = Some(BranchRef::Named(b.to_string()));
            }
            if is_tag_ref(&format!("refs/{refname}")) {
                n.powers.insert(Power::Tags);
                if !refname.starts_with("tags/") {
                    n.powers.insert(Power::ForcePush);
                }
            } else if delete || !refname.starts_with("heads/") {
                n.powers.insert(Power::ForcePush);
            } else {
                match obj()?.get("force") {
                    None | Some(Value::Null) | Some(Value::Bool(false)) => {}
                    Some(_) => {
                        n.powers.insert(Power::ForcePush);
                    }
                }
            }
        }
        ApiRoute::Contents => {
            n.branch = Some(match obj()?.get("branch") {
                None | Some(Value::Null) => BranchRef::Default,
                // GitHub may take an empty branch for the default one.
                Some(Value::String(b)) if b.trim().is_empty() => BranchRef::Default,
                Some(Value::String(b)) => BranchRef::Named(b.strip_prefix("refs/heads/").unwrap_or(b).to_string()),
                Some(_) => return Err("\"branch\" must be a string".into()),
            });
        }
    }
    Ok(n)
}

/// Without `force_push`, the pack is scanned as it streams and its trailing checksum is held back until
/// every moved branch is shown to fast-forward, so GitHub applies nothing otherwise.
#[allow(clippy::too_many_arguments)]
async fn push(
    ctx: &mut Ctx,
    target: &Target,
    grants: &[GrantRow],
    session_id: &str,
    token: &str,
    url: reqwest::Url,
    headers: reqwest::header::HeaderMap,
    body: Body,
) -> Response {
    let app = ctx.app.clone();
    if headers.get_all(reqwest::header::CONTENT_ENCODING).iter().any(|v| v != "identity") {
        return ctx.refuse(StatusCode::BAD_REQUEST, "warden: a compressed push body cannot be checked");
    }
    let mut client = Box::pin(body.into_data_stream());
    let mut head: Vec<u8> = Vec::new();
    let (commands, used) = loop {
        match parse_commands(&head) {
            Err(e) => return ctx.refuse(StatusCode::BAD_REQUEST, &format!("warden: {e}")),
            Ok(Some(x)) => break x,
            Ok(None) if head.len() > COMMANDS_MAX => {
                return ctx.refuse(StatusCode::BAD_REQUEST, "warden: the push commands are too long");
            }
            Ok(None) => {}
        }
        match client.next().await {
            Some(Ok(chunk)) => head.extend_from_slice(&chunk),
            _ => {
                return ctx.refuse(StatusCode::BAD_REQUEST, "warden: the push ended before its commands");
            }
        }
    };
    ctx.detail["refs"] = json!(commands.iter().map(|c| c.refname.clone()).collect::<Vec<_>>());
    let default = if commands.iter().any(|c| c.refname.starts_with("refs/heads/")) {
        match app.github.default_branch(&target.repo, token).await {
            Ok(d) => d,
            Err(e) => {
                return ctx.refuse(
                    StatusCode::BAD_GATEWAY,
                    &format!("warden: cannot read the default branch of {} ({e})", target.repo),
                );
            }
        }
    } else {
        String::new()
    };
    let needs = receive::needs(&commands, &default);
    let mut powers: Vec<Power> = needs.powers.iter().copied().collect();
    // Prefer a grant that also allows force push, or a non-fast-forward push would be stopped even
    // though forcing was granted.
    let mut with_force = powers.clone();
    with_force.push(Power::ForcePush);
    let forcing = if needs.fast_forwards.is_empty() {
        None
    } else {
        find_grant(session_id, grants, &target.repo, Mode::Write, &with_force, ctx.at).ok()
    };
    let grant = match forcing {
        Some(g) => {
            powers = with_force;
            g.clone()
        }
        None => match find_grant(session_id, grants, &target.repo, Mode::Write, &powers, ctx.at) {
            Ok(g) => g.clone(),
            Err(why) => return ctx.refuse(StatusCode::FORBIDDEN, &format!("warden: {why}")),
        },
    };
    powers.sort();
    powers.dedup();
    ctx.detail["powers"] = json!(powers.iter().map(|p| p.as_str()).collect::<Vec<_>>());
    ctx.detail["grant"] = json!(grant.id);
    let rest = guard(client, app.clone(), grant.id.clone(), grant.expires_at, "upload");
    let request = app.http.request(Method::POST, url).headers(headers);
    if needs.fast_forwards.is_empty() || scope_powers(&grant.scope).contains(&Power::ForcePush) {
        let first = futures_util::stream::once(async move { Ok::<Bytes, std::io::Error>(Bytes::from(head)) });
        return ctx.send(request.body(reqwest::Body::wrap_stream(first.chain(rest))), token, &grant).await;
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
    let upstream = tokio::spawn(request.body(reqwest::Body::wrap_stream(stream)).send());
    let refuse_and_abort = |ctx: &Ctx, tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>, status: StatusCode, why: &str| {
        // GitHub never gets the end of the pack, so it applies nothing.
        let _ = tx.try_send(Err(std::io::Error::other("refused by warden")));
        drop(tx);
        upstream.abort();
        ctx.refuse(status, why)
    };
    let mut scanner = PackScanner::new();
    let mut held: Vec<u8> = Vec::new();
    let mut gone = false;
    let commands_part = Bytes::copy_from_slice(&head[..used]);
    if tx.send(Ok(commands_part)).await.is_err() {
        gone = true;
    }
    let mut chunks: Vec<Bytes> = vec![Bytes::copy_from_slice(&head[used..])];
    let mut rest = Box::pin(rest);
    loop {
        for chunk in chunks.drain(..) {
            if let Err(e) = scanner.feed(&chunk) {
                return refuse_and_abort(ctx, tx, StatusCode::BAD_REQUEST, &format!("warden: {e}"));
            }
            held.extend_from_slice(&chunk);
            if held.len() > 20 && !gone {
                let out: Vec<u8> = held.drain(..held.len() - 20).collect();
                if tx.send(Ok(Bytes::from(out))).await.is_err() {
                    gone = true;
                }
            }
        }
        if gone {
            break;
        }
        match rest.next().await {
            Some(Ok(c)) => chunks.push(c),
            Some(Err(_)) => {
                return refuse_and_abort(ctx, tx, StatusCode::BAD_REQUEST, "warden: the push was cut before its end");
            }
            None => break,
        }
    }
    if !gone {
        if let Err(e) = scanner.finish() {
            return refuse_and_abort(ctx, tx, StatusCode::BAD_REQUEST, &format!("warden: {e}"));
        }
        let mut asked = 0usize;
        let mut steps = receive::WALK_BUDGET;
        for (old, new, refname) in &needs.fast_forwards {
            match fast_forward(&app, &target.repo, token, &scanner, old, new, &mut asked, &mut steps).await {
                Ok(true) => {}
                Ok(false) => {
                    let why = format!(
                        "warden: {refname} would not fast-forward (a force push). A plain write grant never rewrites history; if it is really needed, ask for a grant with \"powers\":[\"force_push\"] and say why."
                    );
                    return refuse_and_abort(ctx, tx, StatusCode::FORBIDDEN, &why);
                }
                Err(e) => {
                    let why = format!("warden: cannot check that {refname} fast-forwards ({e}); if this is a normal push, try again with `git push --no-thin`");
                    return refuse_and_abort(ctx, tx, StatusCode::FORBIDDEN, &why);
                }
            }
        }
        // Checking takes time; the grant may have ended meanwhile.
        if app.live.is_revoked(&grant.id) || now() >= grant.expires_at {
            return refuse_and_abort(ctx, tx, StatusCode::FORBIDDEN, "warden: the grant ended while the push was being checked");
        }
        // Releasing the checksum lets GitHub apply the pack.
        let _ = tx.send(Ok(Bytes::from(held))).await;
    }
    drop(tx);
    match upstream.await {
        Ok(Ok(resp)) => ctx.answer(resp, token, None, &grant).await,
        Ok(Err(e)) => ctx.refuse(StatusCode::BAD_GATEWAY, &format!("warden: GitHub did not answer ({})", e.without_url())),
        Err(_) => ctx.refuse(StatusCode::BAD_GATEWAY, "warden: the push to GitHub was interrupted"),
    }
}

/// Ancestry questions to GitHub per push, across all its branches.
const COMPARES_MAX: usize = 50;

/// Uses the pack's commits, and GitHub's API for commits already there.
#[allow(clippy::too_many_arguments)]
async fn fast_forward(
    app: &App,
    repo: &Repo,
    token: &str,
    scanner: &PackScanner,
    old: &str,
    new: &str,
    asked: &mut usize,
    steps: &mut usize,
) -> Result<bool, String> {
    match walk(&scanner.commits, old, new, steps)? {
        Walk::Reached => Ok(true),
        Walk::Ask(outside) => {
            for oid in outside {
                *asked += 1;
                if *asked > COMPARES_MAX {
                    return Err("too many commits from outside the push to check".into());
                }
                if app.github.is_ancestor(repo, token, old, &oid).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Cuts the stream as soon as the grant is revoked or expires, so revoking also stops a clone or push
/// in progress.
pub(crate) fn guard<S, E>(
    inner: S,
    app: Arc<App>,
    grant_id: String,
    expires_at: i64,
    what: &'static str,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let rx = app.live.subscribe();
    let left = (expires_at - now()).max(0) as u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(left);
    let state = Some((Box::pin(inner), rx, app, grant_id, true));
    futures_util::stream::unfold(state, move |state| async move {
        let (mut inner, mut rx, app, grant_id, mut watching) = state?;
        let cut = |app: &App, grant_id: &str, why: &str| {
            let a = Audit::new("system", "proxy.cut", json!({"reason": why, "direction": what})).grant(grant_id);
            if let Err(e) = app.store.audit(a, now()) {
                tracing::error!(error = %e, "cannot write the audit line of a cut transfer");
            }
            tracing::info!(grant = grant_id, why, what, "proxy: transfer cut");
            Some((Err(std::io::Error::other(format!("warden: the grant was {why}"))), None))
        };
        loop {
            if app.live.is_revoked(&grant_id) {
                return cut(&app, &grant_id, "revoked");
            }
            tokio::select! {
                biased;
                changed = rx.changed(), if watching => {
                    // Without a sender left, only the deadline can cut.
                    if changed.is_err() {
                        watching = false;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => return cut(&app, &grant_id, "expired"),
                item = inner.next() => {
                    return match item {
                        None => None,
                        Some(Ok(b)) => Some((Ok(b), Some((inner, rx, app, grant_id, watching)))),
                        Some(Err(e)) => Some((Err(std::io::Error::other(e.to_string())), None)),
                    };
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn rerunning_a_workflow_needs_its_power() {
        let rest = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        for p in ["actions/runs/9/rerun", "actions/runs/9/rerun-failed-jobs", "actions/jobs/9/rerun"] {
            let n = super::api_needs(&super::Method::POST, &rest(p), b"").unwrap();
            assert!(n.powers.contains(&crate::scope::Power::Rerun), "{p}");
            assert!(super::api_reads_body(&super::Method::POST, &rest(p)), "{p} has a rule, so it is checked");
        }
        let cancel = super::api_needs(&super::Method::POST, &rest("actions/runs/9/cancel"), b"").unwrap();
        assert!(cancel.powers.is_empty(), "cancelling a run undoes nothing");
    }

    use super::*;

    fn get(path: &str, q: Option<&str>) -> Result<Target, Deny> {
        classify_git(&Method::GET, path, q)
    }
    fn post(path: &str) -> Result<Target, Deny> {
        classify_git(&Method::POST, path, None)
    }

    #[test]
    fn git_reads_and_writes_are_told_apart() {
        let t = get("owner/heimdall.git/info/refs", Some("service=git-upload-pack")).unwrap();
        assert_eq!((t.repo.key(), t.access), ("owner/heimdall".into(), Mode::Read));
        assert_eq!(t.upstream, "/owner/heimdall.git/info/refs?service=git-upload-pack");
        assert_eq!(get("o/r/info/refs", Some("service=git-receive-pack")).unwrap().access, Mode::Write);
        assert_eq!(post("o/r.git/git-upload-pack").unwrap().access, Mode::Read);
        let push = post("o/r.git/git-receive-pack").unwrap();
        assert_eq!((push.access, push.upstream.as_str()), (Mode::Write, "/o/r.git/git-receive-pack"));
    }

    #[test]
    fn git_path_tricks_are_refused() {
        for bad in [
            "o/r/../other/info/refs",
            "o/../x/r.git/info/refs",
            "o/./r/info/refs",
            "o//r/info/refs",
            "o/r%2F..%2Fx/info/refs",
            "o%2Fr/x/info/refs",
            "o/r%2egit/info/refs",
            "o/r\\..\\x/info/refs",
            "o/r/info/refs/",
            "o/r /info/refs",
            "../o/r/info/refs",
            "o/../../r/info/refs",
        ] {
            assert!(get(bad, Some("service=git-upload-pack")).is_err(), "{bad}");
        }
        assert!(get("-o/r/info/refs", Some("service=git-upload-pack")).is_err());
        assert!(get("o/r@x/info/refs", Some("service=git-upload-pack")).is_err());
        assert!(get("o/../info/refs", Some("service=git-upload-pack")).is_err());
    }

    #[test]
    fn only_smart_http_endpoints_pass() {
        assert!(get("o/r/info/refs", None).is_err(), "dumb protocol");
        assert!(get("o/r/info/refs", Some("service=git-upload-pack&x=1")).is_err());
        assert!(get("o/r/info/refs", Some("service=git-upload-archive")).is_err());
        assert!(get("o/r/HEAD", None).is_err());
        assert!(get("o/r/objects/info/packs", None).is_err());
        assert!(get("o/r/git-upload-pack", None).is_err(), "GET to an RPC");
        assert!(classify_git(&Method::PUT, "o/r/git-receive-pack", None).is_err());
        assert!(classify_git(&Method::POST, "o/r/git-receive-pack", Some("x=1")).is_err());
        let lfs = post("o/r.git/info/lfs/objects/batch").unwrap_err();
        assert!(lfs.message.contains("LFS"), "{}", lfs.message);
        assert!(get("o/r.git/info/lfs/locks", None).is_err());
        assert!(get("o/r", Some("service=git-upload-pack")).is_err());
    }

    fn api(m: Method, path: &str) -> Result<Target, Deny> {
        classify_api(&m, path, None)
    }

    #[test]
    fn api_reads_and_writes_only_their_allowlists() {
        let t = api(Method::GET, "repos/o/r/pulls/12/files").unwrap();
        assert_eq!((t.access, t.audit_path.as_str()), (Mode::Read, "/repos/o/r/pulls/12/files"));
        assert_eq!(api(Method::GET, "repos/o/r").unwrap().access, Mode::Read);
        assert_eq!(api(Method::HEAD, "repos/o/r/contents/").unwrap().upstream, "/repos/o/r/contents/");
        for p in [
            "repos/o/r/contents/src/main.rs",
            "repos/o/r/contents",
            "repos/o/r/readme",
            "repos/o/r/git/trees/abc",
            "repos/o/r/git/blobs/abc",
            "repos/o/r/git/ref/heads/feature/x",
            "repos/o/r/git/matching-refs/tags/v",
            "repos/o/r/commits",
            "repos/o/r/commits/abc/check-runs",
            "repos/o/r/commits/abc/status",
            "repos/o/r/compare/main...feature",
            "repos/o/r/branches",
            "repos/o/r/branches/main",
            "repos/o/r/tags",
            "repos/o/r/tarball/main",
            "repos/o/r/languages",
            "repos/o/r/pulls",
            "repos/o/r/pulls/3/reviews",
            "repos/o/r/pulls/3/comments",
            "repos/o/r/pulls/comments/9",
            "repos/o/r/issues",
            "repos/o/r/issues/3/comments",
            "repos/o/r/issues/3/timeline",
            "repos/o/r/labels",
            "repos/o/r/milestones/1",
            "repos/o/r/statuses/abc",
            "repos/o/r/check-runs/5/annotations",
            "repos/o/r/check-suites/5/check-runs",
            "repos/o/r/actions/workflows",
            "repos/o/r/actions/workflows/ci.yml/runs",
            "repos/o/r/actions/runs",
            "repos/o/r/actions/runs/7/jobs",
            "repos/o/r/actions/jobs/8/logs",
            "repos/o/r/releases",
            "repos/o/r/releases/latest",
            "repos/o/r/releases/tags/v1.0.0",
            "repos/o/r/releases/3/assets",
        ] {
            assert_eq!(api(Method::GET, p).map(|t| t.access), Ok(Mode::Read), "{p}");
            assert_eq!(api(Method::HEAD, p).map(|t| t.access), Ok(Mode::Read), "{p}");
        }
        // Off the allowlist means refused, even when not sensitive.
        for p in [
            "repos/o/r/branches/main/protection",
            "repos/o/r/rulesets",
            "repos/o/r/rules/branches/main",
            "repos/o/r/actions/permissions",
            "repos/o/r/actions/artifacts",
            "repos/o/r/actions/caches",
            "repos/o/r/traffic/views",
            "repos/o/r/events",
            "repos/o/r/deployments",
            "repos/o/r/pages",
            "repos/o/r/installation",
            "repos/o/r/something-new",
            "repos/o/r/%63ontents/x",
        ] {
            let e = api(Method::GET, p).unwrap_err();
            assert_eq!(e.status, StatusCode::FORBIDDEN, "{p}");
            assert!(e.message.contains("not among the reads"), "{p}: {}", e.message);
        }
        let q = classify_api(&Method::GET, "repos/o/r/issues", Some("state=open&per_page=100")).unwrap();
        assert_eq!(q.upstream, "/repos/o/r/issues?state=open&per_page=100");
        for (m, p) in [
            (Method::POST, "repos/o/r/pulls"),
            (Method::PATCH, "repos/o/r/pulls/3"),
            (Method::PUT, "repos/o/r/pulls/3/merge"),
            (Method::POST, "repos/o/r/issues/3/comments"),
            (Method::POST, "repos/o/r/pulls/3/comments/99/replies"),
            (Method::POST, "repos/o/r/git/refs"),
            (Method::DELETE, "repos/o/r/git/refs/heads/feature/x"),
            (Method::PUT, "repos/o/r/contents/docs/a%20b.md"),
            (Method::POST, "repos/o/r/actions/runs/123/rerun-failed-jobs"),
        ] {
            assert_eq!(api(m.clone(), p).map(|t| t.access), Ok(Mode::Write), "{m} {p}");
        }
        for (m, p) in [
            (Method::DELETE, "repos/o/r"),
            (Method::PATCH, "repos/o/r"),
            (Method::POST, "repos/o/r/hooks"),
            (Method::POST, "repos/o/r/keys"),
            (Method::PUT, "repos/o/r/collaborators/eve"),
            (Method::POST, "repos/o/r/transfer"),
            (Method::POST, "repos/o/r/forks"),
            (Method::PUT, "repos/o/r/actions/secrets/X"),
            (Method::PUT, "repos/o/r/branches/main/protection"),
            (Method::POST, "repos/o/r/actions/runners/registration-token"),
            (Method::POST, "repos/o/r/dispatches"),
            (Method::POST, "repos/o/r/pulls/abc/comments"),
            (Method::PUT, "repos/o/r/contents"),
            (Method::OPTIONS, "repos/o/r"),
        ] {
            assert!(api(m.clone(), p).is_err(), "{m} {p}");
        }
    }

    /// `classify_api` ignores grants, so this holds for every mode and power.
    #[test]
    fn repo_protections_are_never_writable() {
        let writes = [Method::POST, Method::PUT, Method::PATCH, Method::DELETE];
        for p in [
            "repos/o/r",
            "repos/o/r/rulesets",
            "repos/o/r/rulesets/42",
            "repos/o/r/rulesets/42/history",
            "repos/o/r/rules/branches/main",
            "repos/o/r/branches/main/protection",
            "repos/o/r/branches/main/protection/enforce_admins",
            "repos/o/r/branches/main/protection/required_pull_request_reviews",
            "repos/o/r/branches/main/protection/required_status_checks",
            "repos/o/r/branches/main/protection/restrictions",
            "repos/o/r/branches/main/protection/allow_deletions",
            "repos/o/r/branches/feature-x/protection",
            "repos/o/r/branches/main/rename",
            "repos/o/r/hooks",
            "repos/o/r/hooks/1",
            "repos/o/r/hooks/1/config",
            "repos/o/r/collaborators/eve",
            "repos/o/r/invitations/1",
            "repos/o/r/keys",
            "repos/o/r/keys/1",
            "repos/o/r/actions/permissions",
            "repos/o/r/actions/secrets/X",
            "repos/o/r/environments/prod",
            "repos/o/r/topics",
            "repos/o/r/vulnerability-alerts",
            "repos/o/r/automated-security-fixes",
            "repos/o/r/private-vulnerability-reporting",
        ] {
            for m in &writes {
                assert!(api(m.clone(), p).is_err(), "{m} {p} must never pass");
            }
            assert_eq!(api(Method::GET, p).is_ok(), matches!(p, "repos/o/r" | "repos/o/r/topics"), "{p}");
        }
        assert!(api(Method::POST, "graphql").is_err(), "GraphQL (createRepositoryRuleset…) never passes");
        let protections = [
            "rulesets",
            "rules",
            "branches",
            "hooks",
            "collaborators",
            "invitations",
            "keys",
            "environments",
            "topics",
        ];
        for (m, pattern) in WRITE_RULES {
            let first = pattern.split('/').next().unwrap();
            assert!(
                !protections.contains(&first) && *pattern != "**",
                "{m} {pattern} reaches what protects the repo"
            );
        }
    }

    #[test]
    fn sensitive_reads_never_pass() {
        for p in [
            "repos/o/r/secret-scanning/alerts",
            "repos/o/r/secret-scanning/alerts/1/locations",
            "repos/o/r/code-scanning/alerts",
            "repos/o/r/dependabot/alerts",
            "repos/o/r/dependabot/secrets",
            "repos/o/r/codespaces/secrets",
            "repos/o/r/environments",
            "repos/o/r/environments/prod/variables",
            "repos/o/r/security-advisories",
            "repos/o/r/hooks",
            "repos/o/r/hooks/1/config",
            "repos/o/r/hooks/1/deliveries",
            "repos/o/r/hooks/1/deliveries/2",
            "repos/o/r/keys",
            "repos/o/r/collaborators",
            "repos/o/r/collaborators/eve/permission",
            "repos/o/r/invitations",
            "repos/o/r/actions/secrets",
            "repos/o/r/actions/secrets/public-key",
            "repos/o/r/actions/variables",
            "repos/o/r/actions/variables/NPM_TOKEN",
            "repos/o/r/actions/organization-secrets",
            "repos/o/r/actions/organization-variables",
            "repos/o/r/actions/runners",
            "repos/o/r/actions/oidc/customization/sub",
            "repos/o/r/secret%2Dscanning/alerts",
            "repos/o/r/Secret-Scanning/alerts",
            "repos/o/r/actions/%76ariables",
        ] {
            for m in [Method::GET, Method::HEAD] {
                let e = api(m.clone(), p).unwrap_err();
                assert_eq!(e.status, StatusCode::FORBIDDEN, "{m} {p}");
                assert!(e.message.contains("never proxied"), "{m} {p}: {}", e.message);
            }
            let segs: Vec<&str> = p.split('/').skip(3).collect();
            assert!(sensitive_read(&segs), "{p}");
        }
        for rule in READ_RULES.iter().copied().chain(WRITE_RULES.iter().map(|(_, p)| *p)) {
            let segs: Vec<&str> = rule.split('/').filter(|s| !s.is_empty() && *s != "**" && *s != "*" && *s != "#").collect();
            assert!(segs.is_empty() || !sensitive_read(&segs), "{rule} reaches a sensitive family");
        }
        assert!(!sensitive_read(&["actions", "runs"]) && !sensitive_read(&["keysmith"]));
    }

    #[test]
    fn api_outside_repos_and_path_tricks_are_refused() {
        assert!(api(Method::POST, "graphql").unwrap_err().message.contains("GraphQL"));
        for bad in [
            "user",
            "user/repos",
            "search/code",
            "repositories/123/contents",
            "orgs/o/repos",
            "repos/o",
            "repos/o/r/../../orgs/o",
            "repos/o/r/%2e%2e/x",
            "repos/o/r/contents/..%2F..%2Fx",
            "repos/o%2Fx/r",
            "repos/o/r%2Fx",
            "repos/o//r",
            "repos/o/r/contents/%5c..",
            "repos/o/r/contents/%25252e",
            "repos/o/r/contents/%0a",
            "repos/o/r/contents/%zz",
            "repos/o/r/contents/%2",
            "repos/./r/x",
            "repos/o/r//contents",
            "repos/o/r/contents//x",
        ] {
            assert!(api(Method::GET, bad).is_err(), "{bad}");
        }
        assert!(classify_api(&Method::GET, "repos/o/r", Some("a=b#c")).is_err());
        assert!(classify_api(&Method::GET, "repos/o/r", Some("a=\nb")).is_err());
    }

    #[test]
    fn session_tokens_come_in_three_forms() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::AUTHORIZATION, HeaderValue::from_str(v).unwrap());
            presented_token(&m)
        };
        assert_eq!(h("Bearer wds_abc").as_deref(), Some("wds_abc"));
        assert_eq!(h("token wds_abc").as_deref(), Some("wds_abc"));
        assert_eq!(h(&format!("Basic {}", STANDARD.encode("claude:wds_abc"))).as_deref(), Some("wds_abc"));
        assert_eq!(h(&format!("Basic {}", STANDARD.encode("wds_abc:"))).as_deref(), Some("wds_abc"));
        assert_eq!(h("Digest x"), None);
        assert_eq!(h("Bearer "), None);
        assert_eq!(presented_token(&HeaderMap::new()), None);
    }
}
