// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Registry proxy: sandboxes read private images and packages from Artifact Registry (and from a
//! composer front for a PHP repository) through the owner's Google connection, limited to the
//! artifacts their grant lists.
//!
//!   GET|HEAD /registry/{host}/v2/                                  docker: API check
//!   GET|HEAD /registry/{host}/v2/{image}/manifests/{ref}           docker: manifest
//!   GET|HEAD /registry/{host}/v2/{image}/blobs/{digest}            docker: layer or config
//!   GET|HEAD /registry/{host}/{proj}/{repo}/@{scope}%2f{pkg}       npm: package metadata
//!   GET|HEAD /registry/{host}/{proj}/{repo}/@{scope}/{pkg}/-/…     npm: tarball
//!   GET|HEAD /registry/{host}/packages.json                        composer: repository index
//!   GET|HEAD /registry/{host}/p2/{vendor}/{pkg}[~dev].json         composer: package versions
//!   GET|HEAD /registry/{host}/dists/{vendor}/{pkg}/{v}/{ref}.zip   composer: dist
//!
//! The caller is the sandbox's guardian with its own warden session, terminating the sandbox's TLS for
//! these hosts; the sandbox sees neither that token nor Google's. Only configured hosts, read methods
//! and exact path shapes pass (no `..`, empty segments, `\`, controls, query, or `%` other than npm's
//! scoped `%2f`), and only with a live "gcp" grant naming the artifact. warden follows same-host
//! redirects itself (large layers go to `/artifacts-downloads/…`), so the sandbox never gets that URL.
//! Downloads are cut when the grant ends, and every request is audited.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::connection::TokenError;
use crate::store::{Audit, GrantRow};
use crate::util::now;

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Docker,
    Npm,
    Composer,
}

pub fn valid_host(h: &str) -> bool {
    h.contains('.')
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
        && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

pub fn valid_preset_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Covers docker image names, lowercase npm packages and composer vendor/package names.
fn name_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().last().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

fn npm_scope(s: &str) -> bool {
    s.strip_prefix('@').is_some_and(name_segment)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub host: String,
    pub kind: Kind,
    /// docker: `project/repo/image…`; npm: `project/repo/@scope/package` (scope optional); composer:
    /// `vendor/package`.
    pub name: String,
}

impl Artifact {
    pub fn parse(raw: &str, registries: &BTreeMap<String, Kind>) -> Result<Artifact, String> {
        let (host, name) = raw.split_once('/').ok_or_else(|| format!("«{raw}» is not host/name"))?;
        let kind = *registries
            .get(host)
            .ok_or_else(|| format!("«{raw}»: the host «{host}» is not in gcp.registries"))?;
        let segs: Vec<&str> = name.split('/').collect();
        let ok = match kind {
            Kind::Docker => segs.len() >= 3 && segs.iter().all(|s| name_segment(s)),
            Kind::Npm => match segs.as_slice() {
                [p, r, scope, pkg] => name_segment(p) && name_segment(r) && npm_scope(scope) && name_segment(pkg),
                [p, r, pkg] => name_segment(p) && name_segment(r) && name_segment(pkg),
                _ => false,
            },
            Kind::Composer => segs.len() == 2 && segs.iter().all(|s| name_segment(s)),
        };
        if !ok {
            let shape = match kind {
                Kind::Docker => "host/project/repository/image (lowercase)",
                Kind::Npm => "host/project/repository/@scope/package (lowercase)",
                Kind::Composer => "host/vendor/package (lowercase)",
            };
            return Err(format!("«{raw}» is not {shape}"));
        }
        Ok(Artifact {
            host: host.to_string(),
            kind,
            name: name.to_string(),
        })
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.host, self.name)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Need {
    /// docker `/v2/`: allowed with any image granted on that host.
    Ping,
    /// composer `packages.json`: allowed with any package granted on that host.
    Index,
    Artifact(String),
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

/// `%` is checked separately, because scoped npm packages need `%2f`.
fn segments(path: &str) -> Result<Vec<&str>, Deny> {
    let rest = path
        .strip_prefix('/')
        .ok_or_else(|| deny(StatusCode::BAD_REQUEST, "the path must start with /"))?;
    let segs: Vec<&str> = rest.split('/').collect();
    for s in &segs {
        if s.is_empty() || *s == "." || *s == ".." || s.contains('\\') || s.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(deny(StatusCode::BAD_REQUEST, "the path has an empty, «.», «..» or otherwise odd segment"));
        }
    }
    Ok(segs)
}

fn no_percent(segs: &[&str]) -> Result<(), Deny> {
    if segs.iter().any(|s| s.contains('%')) {
        return Err(deny(StatusCode::BAD_REQUEST, "percent-encoding is not allowed in this path"));
    }
    Ok(())
}

fn docker_ref(s: &str) -> bool {
    digest(s)
        || (!s.is_empty()
            && s.len() <= 128
            && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

fn digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// Allows only what installing needs.
pub fn classify(kind: Kind, method: &Method, path: &str, query: Option<&str>) -> Result<Need, Deny> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Err(deny(StatusCode::METHOD_NOT_ALLOWED, "only GET and HEAD: a registry grant only reads"));
    }
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(deny(StatusCode::BAD_REQUEST, "a query string is not allowed"));
    }
    match kind {
        Kind::Docker => {
            if path == "/v2/" {
                return Ok(Need::Ping);
            }
            let segs = segments(path)?;
            no_percent(&segs)?;
            let n = segs.len();
            // v2 + at least project/repo/image + manifests|blobs + ref.
            if n < 6 || segs[0] != "v2" {
                return Err(deny(StatusCode::FORBIDDEN, "only the manifests and blobs of the granted images can be read"));
            }
            let (what, r) = (segs[n - 2], segs[n - 1]);
            let name = &segs[1..n - 2];
            let ok = match what {
                "manifests" => docker_ref(r),
                "blobs" => digest(r),
                _ => false,
            };
            if !ok || !name.iter().all(|s| name_segment(s)) {
                return Err(deny(StatusCode::FORBIDDEN, "only the manifests and blobs of the granted images can be read"));
            }
            Ok(Need::Artifact(name.join("/")))
        }
        Kind::Npm => {
            let segs = segments(path)?;
            let refuse = || deny(StatusCode::FORBIDDEN, "only the metadata and tarballs of the granted npm packages can be read");
            // The only `%` allowed: `@scope%2fpackage`, which is how npm asks for a scoped package.
            let split_scoped = |s: &str| -> Option<(String, String)> {
                let (scope, pkg) = s.split_once("%2f").or_else(|| s.split_once("%2F"))?;
                (npm_scope(scope) && name_segment(pkg)).then(|| (scope.to_string(), pkg.to_string()))
            };
            let tarball = |pkg: &str, file: &str| {
                file.strip_prefix(pkg)
                    .and_then(|f| f.strip_prefix('-'))
                    .and_then(|f| f.strip_suffix(".tgz"))
                    .is_some_and(version)
            };
            let name = match segs.as_slice() {
                [p, r, s] if s.starts_with('@') => {
                    let (scope, pkg) = split_scoped(s).ok_or_else(refuse)?;
                    no_percent(&[p, r])?;
                    format!("{p}/{r}/{scope}/{pkg}")
                }
                rest => {
                    no_percent(rest)?;
                    match rest {
                        [p, r, scope, pkg] if npm_scope(scope) => format!("{p}/{r}/{scope}/{pkg}"),
                        [p, r, pkg] => format!("{p}/{r}/{pkg}"),
                        [p, r, scope, pkg, "-", file] if npm_scope(scope) && tarball(pkg, file) => {
                            format!("{p}/{r}/{scope}/{pkg}")
                        }
                        [p, r, scope, pkg, "-", scope2, file] if npm_scope(scope) && scope == scope2 && tarball(pkg, file) => {
                            format!("{p}/{r}/{scope}/{pkg}")
                        }
                        [p, r, pkg, "-", file] if tarball(pkg, file) => format!("{p}/{r}/{pkg}"),
                        _ => return Err(refuse()),
                    }
                }
            };
            if !name.split('/').all(|s| name_segment(s) || npm_scope(s)) {
                return Err(refuse());
            }
            Ok(Need::Artifact(name))
        }
        Kind::Composer => {
            let segs = segments(path)?;
            no_percent(&segs)?;
            let refuse = || {
                deny(
                    StatusCode::FORBIDDEN,
                    "only the index, metadata and dists of the granted composer packages can be read",
                )
            };
            let name = match segs.as_slice() {
                ["packages.json"] => return Ok(Need::Index),
                ["p2", vendor, file] => {
                    let pkg = file.strip_suffix("~dev.json").or_else(|| file.strip_suffix(".json")).ok_or_else(refuse)?;
                    format!("{vendor}/{pkg}")
                }
                ["dists", vendor, pkg, v, file] if version(v) && file.strip_suffix(".zip").is_some_and(version) => {
                    format!("{vendor}/{pkg}")
                }
                _ => return Err(refuse()),
            };
            if !name.split('/').all(name_segment) {
                return Err(refuse());
            }
            Ok(Need::Artifact(name))
        }
    }
}

pub fn scope_artifacts(scope: &Value) -> Vec<String> {
    scope["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str())
        .map(String::from)
        .collect()
}

pub fn covers(artifacts: &[String], host: &str, need: &Need) -> bool {
    let on_host = |a: &&String| a.split_once('/').is_some_and(|(h, _)| h == host);
    match need {
        Need::Ping | Need::Index => artifacts.iter().any(|a| on_host(&a)),
        Need::Artifact(name) => artifacts.contains(&format!("{host}/{name}")),
    }
}

const REQUEST_HEADERS: &[&str] = &["accept", "range", "if-none-match"];
/// No cookies and no `Location`: warden follows redirects itself.
const RESPONSE_HEADERS: &[&str] = &[
    "accept-ranges",
    "cache-control",
    "content-length",
    "content-range",
    "content-type",
    "docker-content-digest",
    "docker-distribution-api-version",
    "etag",
    "last-modified",
];
const MAX_HOPS: usize = 3;
const USER_AGENT: &str = "warden-registry";

/// Shaped like docker registry API errors: podman and docker show `message`; npm and composer show
/// the body.
fn refusal(status: StatusCode, message: &str) -> Response {
    let code = match status {
        StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
        StatusCode::FORBIDDEN => "DENIED",
        StatusCode::METHOD_NOT_ALLOWED => "UNSUPPORTED",
        StatusCode::TOO_MANY_REQUESTS => "TOOMANYREQUESTS",
        _ => "UNKNOWN",
    };
    (status, axum::Json(json!({"errors": [{"code": code, "message": message}]}))).into_response()
}

struct Ctx {
    app: Arc<App>,
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
            tracing::error!(error = %e, "cannot write the audit line of a registry request");
        }
    }

    fn refuse(&self, status: StatusCode, message: &str) -> Response {
        let mut detail = self.detail.clone();
        detail["decision"] = json!("denied");
        detail["status"] = json!(status.as_u16());
        detail["reason"] = json!(message);
        tracing::info!(status = status.as_u16(), reason = message, "registry: denied");
        self.record(None, detail);
        refusal(status, message)
    }

    fn token_refused(&self, e: TokenError) -> Response {
        match e {
            TokenError::Reconnect(why) => self.refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("warden: the Google connection has to be connected again ({why}); the owner does it in warden's panel"),
            ),
            TokenError::Unavailable(why) => self.refuse(
                StatusCode::BAD_GATEWAY,
                &format!("warden: Google did not renew the token ({why}); try again in a moment"),
            ),
            TokenError::Internal(e) => {
                tracing::error!(error = %e, "cannot open the Google connection");
                self.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: the Google connection cannot be read")
            }
        }
    }

    fn respond(&self, resp: reqwest::Response, grant: &GrantRow, hops: usize) -> Response {
        let status = resp.status();
        let mut detail = self.detail.clone();
        detail["decision"] = json!("allowed");
        detail["status"] = json!(status.as_u16());
        if hops > 0 {
            detail["redirects"] = json!(hops);
        }
        tracing::info!(path = %detail["path"], status = status.as_u16(), "registry: forwarded");
        self.record(Some(&grant.id), detail);
        let mut out = Response::builder().status(status.as_u16());
        for (k, v) in resp.headers() {
            if RESPONSE_HEADERS.contains(&k.as_str())
                && let Ok(name) = HeaderName::from_bytes(k.as_str().as_bytes())
            {
                out = out.header(name, v.clone());
            }
        }
        let body = crate::proxy::guard(resp.bytes_stream(), self.app.clone(), grant.id.clone(), grant.expires_at, "download");
        out.body(Body::from_stream(body)).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
    }
}

fn split_host(rest: &str) -> Option<(&str, &str)> {
    let i = rest.find('/')?;
    Some((&rest[..i], &rest[i..]))
}

fn same_origin(from: &reqwest::Url, next: &reqwest::Url) -> bool {
    next.scheme() == from.scheme() && next.host_str() == from.host_str() && next.port_or_known_default() == from.port_or_known_default()
}

pub async fn proxy(State(app): State<Arc<App>>, req: Request) -> Response {
    let method = req.method().clone();
    let query = req.uri().query().map(String::from);
    let rest = req.uri().path().strip_prefix("/registry/").unwrap_or("").to_string();
    let mut ctx = Ctx {
        app: app.clone(),
        at: now(),
        actor: "anonymous".into(),
        session: None,
        detail: json!({"surface": "registry", "method": method.as_str(), "path": clip(&format!("/registry/{rest}"), 300)}),
    };
    let at = ctx.at;

    let session = match crate::proxy::presented_token(req.headers()).map(|t| app.store.session_by_token(&t, at)) {
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
    if let Err(over) = app.session_audit_slot(&session.id, at) {
        tracing::debug!(status = over.status.as_u16(), "registry: denied without an audit line (over budget)");
        let mut resp = refusal(over.status, &over.message);
        over.stamp(&mut resp);
        return resp;
    }
    let Some(cfg) = &app.cfg.gcp else {
        return ctx.refuse(StatusCode::NOT_FOUND, "warden: the registry proxy is not enabled in this warden");
    };

    let Some((host, path)) = split_host(&rest) else {
        return ctx.refuse(StatusCode::NOT_FOUND, "warden: /registry/{host}/{path}");
    };
    let Some(&kind) = cfg.registries.get(host) else {
        return ctx.refuse(
            StatusCode::FORBIDDEN,
            &format!("warden: «{}» is not a registry this warden reads", clip(host, 80)),
        );
    };
    ctx.detail["registry"] = json!(host);

    let need = match classify(kind, &method, path, query.as_deref()) {
        Ok(n) => n,
        Err(d) => return ctx.refuse(d.status, &format!("warden: {}", d.message)),
    };
    if let Need::Artifact(name) = &need {
        ctx.detail["artifact"] = json!(format!("{host}/{name}"));
    }

    let grants = match app.store.task_grants(crate::google::SYSTEM, &session, &cfg.tasks, at) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(error = %e, "grant lookup failed");
            return ctx.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: internal error");
        }
    };
    let Some(grant) = grants.iter().find(|g| covers(&scope_artifacts(&g.scope), host, &need)).cloned() else {
        let have = if grants.is_empty() {
            "this session has no active registry grant".to_string()
        } else {
            let presets: Vec<String> = grants.iter().map(|g| g.scope["preset"].as_str().unwrap_or("?").to_string()).collect();
            format!("its active grants (presets {}) do not list it", presets.join(", "))
        };
        return ctx.refuse(StatusCode::FORBIDDEN, &format!("warden: not granted ({have})"));
    };
    ctx.detail["grant"] = json!(grant.id);

    let token = match app.google_token(&session.id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return ctx.refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "warden: Google is not connected; the owner has to connect it in warden first",
            );
        }
        Err(e) => return ctx.token_refused(e),
    };

    let base = cfg
        .upstreams
        .get(host)
        .map(|b| b.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("https://{host}"));
    let mut url = match (reqwest::Url::parse(&format!("{base}{path}")), reqwest::Url::parse(&base)) {
        (Ok(u), Ok(b)) if same_origin(&b, &u) => u,
        _ => {
            return ctx.refuse(StatusCode::BAD_REQUEST, "warden: the upstream URL is not the registry's");
        }
    };
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in req.headers() {
        if REQUEST_HEADERS.contains(&k.as_str()) {
            headers.append(k.clone(), v.clone());
        }
    }
    headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
    let Ok(mut auth) = HeaderValue::from_str(&format!("Bearer {token}")) else {
        return ctx.refuse(StatusCode::INTERNAL_SERVER_ERROR, "warden: the Google token is not usable");
    };
    auth.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, auth);

    // Follow same-host redirects here (the token is for that host), never to another host.
    let mut hops = 0;
    loop {
        let resp = match app.http.request(method.clone(), url.clone()).headers(headers.clone()).send().await {
            Ok(r) => r,
            Err(e) => {
                return ctx.refuse(StatusCode::BAD_GATEWAY, &format!("warden: the registry did not answer ({})", e.without_url()));
            }
        };
        // An upstream 401 means the registry rejects warden's Google token, not the session, so it becomes
        // a 502: a 401 from warden always means "your session is gone", and the guardian would open a new
        // one and retry for nothing.
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return ctx.refuse(
                StatusCode::BAD_GATEWAY,
                "warden: the registry did not accept warden's Google token (is the account allowed to read it?)",
            );
        }
        if !resp.status().is_redirection() {
            return ctx.respond(resp, &grant, hops);
        }
        let next = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|l| l.to_str().ok())
            .and_then(|l| url.join(l).ok());
        match next {
            Some(n) if same_origin(&url, &n) && hops < MAX_HOPS => {
                if app.live.is_revoked(&grant.id) || now() >= grant.expires_at {
                    return ctx.refuse(StatusCode::FORBIDDEN, "warden: the grant ended");
                }
                hops += 1;
                url = n;
            }
            Some(_) => {
                return ctx.refuse(
                    StatusCode::BAD_GATEWAY,
                    "warden: the registry redirected to another host, which warden does not follow",
                );
            }
            None => {
                return ctx.refuse(StatusCode::BAD_GATEWAY, "warden: the registry answered a redirect without a usable Location");
            }
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs() -> BTreeMap<String, Kind> {
        BTreeMap::from([
            ("europe-docker.pkg.dev".to_string(), Kind::Docker),
            ("europe-west1-npm.pkg.dev".to_string(), Kind::Npm),
            ("composer.example.com".to_string(), Kind::Composer),
        ])
    }

    fn get(kind: Kind, path: &str) -> Result<Need, Deny> {
        classify(kind, &Method::GET, path, None)
    }

    fn art(n: &str) -> Result<Need, Deny> {
        Ok(Need::Artifact(n.into()))
    }

    #[test]
    fn preset_artifacts_are_checked_by_registry_kind() {
        let r = regs();
        assert!(Artifact::parse("europe-docker.pkg.dev/example-artifacts/team/app/develop", &r).is_ok());
        assert!(Artifact::parse("europe-west1-npm.pkg.dev/example-shared/npm/@example-org/ui-kit", &r).is_ok());
        assert!(Artifact::parse("composer.example.com/example-vendor/logger", &r).is_ok());
        for bad in [
            "ghcr.io/o/r/i",                                           // host not in the config
            "europe-docker.pkg.dev/example-artifacts/fp",              // no image
            "europe-docker.pkg.dev/example-artifacts/FP/app",          // uppercase
            "europe-docker.pkg.dev/example-artifacts/../x/y",          // traversal
            "europe-west1-npm.pkg.dev/example-shared/npm/example/x/y", // extra npm segment
            "europe-west1-npm.pkg.dev/example-shared/npm/@/x",         // empty scope
            "composer.example.com/vendor",                             // composer without a package
            "composer.example.com/vendor/pkg/extra",
        ] {
            assert!(Artifact::parse(bad, &r).is_err(), "{bad}");
        }
    }

    #[test]
    fn docker_reads_only_manifests_and_blobs() {
        let d = "sha256:".to_string() + &"a".repeat(64);
        assert_eq!(get(Kind::Docker, "/v2/"), Ok(Need::Ping));
        assert_eq!(
            get(Kind::Docker, "/v2/example-artifacts/team/app/develop/manifests/13"),
            art("example-artifacts/team/app/develop")
        );
        assert_eq!(
            get(Kind::Docker, &format!("/v2/example-artifacts/team/app/develop/manifests/{d}")),
            art("example-artifacts/team/app/develop")
        );
        assert_eq!(
            get(Kind::Docker, &format!("/v2/example-artifacts/docker-hub/library/nginx/blobs/{d}")),
            art("example-artifacts/docker-hub/library/nginx")
        );
        for bad in [
            "/v2",
            "/v2/_catalog",
            "/v2/example-artifacts/team/app/develop/tags/list",
            "/v2/example-artifacts/team/app/develop/blobs/uploads/",
            "/v2/example-artifacts/team/app/develop/blobs/13",
            "/v2/example-artifacts/team/app/develop/manifests/a%2fb",
            "/v2/example-artifacts/fp/../develop/manifests/13",
            "/v2/example-artifacts//app/develop/manifests/13",
            "/v2/fp/develop/manifests/13",
            "/artifacts-downloads/namespaces/x",
            "/v2/example-artifacts/team/app/develop/manifests/-bad",
        ] {
            assert!(get(Kind::Docker, bad).is_err(), "{bad}");
        }
        assert_eq!(
            classify(Kind::Docker, &Method::PUT, "/v2/a/b/c/manifests/1", None).unwrap_err().status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(classify(Kind::Docker, &Method::HEAD, "/v2/a/b/c/manifests/1", None), art("a/b/c"));
        assert!(classify(Kind::Docker, &Method::GET, "/v2/a/b/c/manifests/1", Some("ns=docker.io")).is_err());
    }

    #[test]
    fn npm_reads_metadata_and_tarballs_of_one_package() {
        let pkg = "example-shared/npm/@example-org/ui-kit";
        assert_eq!(get(Kind::Npm, "/example-shared/npm/@example-org%2fui-kit"), art(pkg));
        assert_eq!(get(Kind::Npm, "/example-shared/npm/@example-org%2Fui-kit"), art(pkg));
        assert_eq!(get(Kind::Npm, "/example-shared/npm/@example-org/ui-kit"), art(pkg));
        assert_eq!(get(Kind::Npm, "/example-shared/npm/@example-org/ui-kit/-/ui-kit-1.2.3.tgz"), art(pkg));
        // pnpm lockfile shape: the scope repeated after `-`.
        assert_eq!(
            get(Kind::Npm, "/example-shared/npm/@example-org/ui-kit/-/@example-org/ui-kit-1.2.3-beta.1.tgz"),
            art(pkg)
        );
        assert_eq!(
            get(Kind::Npm, "/example-shared/npm/left-pad/-/left-pad-1.0.0.tgz"),
            art("example-shared/npm/left-pad")
        );
        for bad in [
            "/example-shared/npm/@example-org%2f..%2fx",
            "/example-shared/npm/@example-org/ui-kit/-/other-1.0.0.tgz",
            "/example-shared/npm/@example-org/ui-kit/-/@other/ui-kit-1.0.0.tgz",
            "/example-shared/npm/@example-org/ui-kit/-/ui-kit-1.0.0.tar",
            "/example-shared/npm/-/npm/v1/security/advisories/bulk",
            "/example-shared/npm/-/v1/search",
            "/example%2dshared/npm/left-pad",
            "/example-shared/npm/@example-org%2fui-kit/extra",
        ] {
            assert!(get(Kind::Npm, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn composer_reads_the_index_metadata_and_dists_of_one_package() {
        assert_eq!(get(Kind::Composer, "/packages.json"), Ok(Need::Index));
        assert_eq!(get(Kind::Composer, "/p2/example-vendor/logger.json"), art("example-vendor/logger"));
        assert_eq!(get(Kind::Composer, "/p2/example-vendor/logger~dev.json"), art("example-vendor/logger"));
        assert_eq!(
            get(
                Kind::Composer,
                "/dists/example-org/json-schema/2.0.0.0/db134bd485f0d6080530734600d024f540faaa93.zip"
            ),
            art("example-org/json-schema")
        );
        for bad in [
            "/p2/example-vendor/../x.json",
            "/p2/x.json",
            "/dists/a/b/1.0/c.tar",
            "/search.json",
            "/p/provider-latest$x.json",
            "/packages.json/x",
        ] {
            assert!(get(Kind::Composer, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_grant_covers_exactly_its_artifacts() {
        let list = vec![
            "europe-docker.pkg.dev/example-artifacts/team/app/develop".to_string(),
            "composer.example.com/example-vendor/logger".to_string(),
        ];
        assert!(covers(
            &list,
            "europe-docker.pkg.dev",
            &Need::Artifact("example-artifacts/team/app/develop".into())
        ));
        assert!(!covers(
            &list,
            "europe-docker.pkg.dev",
            &Need::Artifact("example-artifacts/team/app/develop2".into())
        ));
        assert!(!covers(&list, "europe-docker.pkg.dev", &Need::Artifact("example-artifacts/team/app".into())));
        assert!(!covers(
            &list,
            "europe-west1-docker.pkg.dev",
            &Need::Artifact("example-artifacts/team/app/develop".into())
        ));
        assert!(covers(&list, "europe-docker.pkg.dev", &Need::Ping));
        assert!(!covers(&list, "europe-west1-docker.pkg.dev", &Need::Ping));
        assert!(covers(&list, "composer.example.com", &Need::Index));
        assert!(!covers(&[], "europe-docker.pkg.dev", &Need::Ping));
    }

    #[test]
    fn the_host_comes_first_and_redirects_stay_on_it() {
        assert_eq!(split_host("europe-docker.pkg.dev/v2/"), Some(("europe-docker.pkg.dev", "/v2/")));
        assert_eq!(split_host("europe-docker.pkg.dev"), None);
        let from = reqwest::Url::parse("https://europe-docker.pkg.dev/v2/a/b/c/blobs/x").unwrap();
        assert!(same_origin(&from, &from.join("/artifacts-downloads/namespaces/x?sig=1").unwrap()));
        assert!(!same_origin(&from, &reqwest::Url::parse("https://storage.googleapis.com/x").unwrap()));
        assert!(!same_origin(&from, &reqwest::Url::parse("http://europe-docker.pkg.dev/x").unwrap()));
        assert!(!same_origin(&from, &reqwest::Url::parse("https://europe-docker.pkg.dev:8443/x").unwrap()));
    }
}
