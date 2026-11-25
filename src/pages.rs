// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Owner-facing pages, written by hand. Everything from outside (Claude's reason, repo
//! names, the audit) goes through `esc`. The only script is /static/warden.js, which reads its inputs
//! from `data-*` attributes; the CSP in app.rs allows nothing else.
use crate::scope::scope_powers;
use crate::store::{AuditRow, ConnectionRow, GrantRow, PasskeyRow, RequestRow, status_label};
use crate::util::{human_duration, iso_utc};

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { color-scheme: dark; --bg:#0f1115; --panel:#171a21; --line:#2a2f3a; --fg:#e7e9ee; --muted:#9aa1ad; --accent:#8b7cfa; --ok:#3fb27f; --warn:#e0a03a; --bad:#e5534b; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; }
main { max-width: 46rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { font-size: 1.5rem; margin: .2em 0 .8em; }
h2 { font-size: 1.1rem; margin: 1.6em 0 .6em; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1rem 1.1rem; margin: 0 0 1rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .4em 1em; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
code, .mono { font-family: ui-monospace, monospace; font-size: .92em; }
.pill { display: inline-block; padding: .05em .6em; border-radius: 999px; font-weight: 600; font-size: .9em; }
.read { background: #1f3b2f; color: #8fe0b8; }
.write { background: #4a3413; color: #ffcf7a; }
.powers { border: 1px solid var(--bad); }
.powers ul { margin: .4em 0; }
.reason { white-space: pre-wrap; background: #11141a; border-left: 3px solid var(--accent); padding: .6em .8em; border-radius: 6px; }
.row { display: flex; gap: .7rem; flex-wrap: wrap; margin-top: 1rem; }
button { font: inherit; font-weight: 600; border-radius: 10px; padding: .75em 1.3em; border: 1px solid var(--line); background: #232836; color: var(--fg); cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: #0b0b12; }
button.danger { border-color: var(--bad); color: #ffb1ab; }
.msg { border-left: 4px solid var(--accent); }
.msg.ok { border-left-color: var(--ok); }
.msg.err { border-left-color: var(--bad); }
.muted { color: var(--muted); }
table { width: 100%; border-collapse: collapse; font-size: .88em; }
td, th { text-align: left; padding: .35em .4em; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
a { color: var(--accent); }
form { display: inline; }
input { font: inherit; padding: .5em .7em; border-radius: 8px; border: 1px solid var(--line); background: #11141a; color: var(--fg); }
.bad { color: #ffb1ab; }
"#;

const SCRIPT: &str = "<script src=\"/static/warden.js\" defer></script>";

fn layout(title: &str, body: &str) -> String {
    layout_with(title, body, "")
}

fn layout_with(title: &str, body: &str, head: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">{head}<title>{} · warden</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>",
        esc(title)
    )
}

/// Orgs that enforce SAML need the OAuth App token authorized for them, as with `gh`.
const SAML: &str = "For example-org's repos: first open <a href=\"https://github.com/orgs/example-org/sso\">https://github.com/orgs/example-org/sso</a> \
    (the SAML session) and, when authorizing, press “Authorize” next to example-org (or “Request” if the org has to approve the app). \
    If it is already connected, do it from the app's page on GitHub: ";

pub fn device(user_code: &str, status: &crate::web::DeviceStatus, device_url: &str, settings_url: &str, left: i64) -> String {
    use crate::web::DeviceStatus as S;
    let settings = format!("<a href=\"{}\">{}</a>", esc(settings_url), esc(settings_url));
    let (body, refresh) = match status {
        S::Pending => (
            format!(
                "<h1>Connect GitHub</h1><div class=\"card\"><p>Open <a href=\"{u}\">{u}</a> with your GitHub account and enter this code:</p>\
                 <p class=\"mono\" style=\"font-size:2.2rem;letter-spacing:.15em;margin:.3em 0\">{c}</p>\
                 <p class=\"muted\">It expires in {left}. This page refreshes on its own.</p></div>\
                 <div class=\"card msg\"><p>{saml}{settings}</p></div>",
                u = esc(device_url),
                c = esc(user_code),
                left = human_duration(left),
                saml = SAML,
            ),
            true,
        ),
        S::Connected { account, scopes, expires_at } => (
            format!(
                "<h1>GitHub connected</h1><div class=\"card msg ok\"><p>Connected as <b>{}</b> (scopes: <code>{}</code>).</p><p>{}</p></div>\
                 <div class=\"card msg\"><p>{SAML}{settings}</p></div><p><a href=\"/\">Back to the panel</a></p>",
                esc(account),
                esc(scopes),
                match expires_at {
                    Some(_) => "The token expires every 8 h and warden renews it on its own.",
                    None => "GitHub gave no refresh token: this token does not expire.",
                },
            ),
            false,
        ),
        S::WrongAccount(account) => (
            format!(
                "<h1>Wrong account</h1><div class=\"card msg err\"><p>The code was authorized by the account <b>{}</b>, which is not the expected one: warden has not kept its token. \
                 Revoke the app on that account ({settings}) and start again from the panel.</p></div>",
                esc(account)
            ),
            false,
        ),
        S::Denied => (
            "<h1>Cancelled</h1><div class=\"card msg\"><p>It was refused on GitHub; nothing has changed.</p></div>".to_string(),
            false,
        ),
        S::Expired => (
            "<h1>Expired</h1><div class=\"card msg\"><p>The code expired before it was authorized. Start again from the panel.</p></div>".to_string(),
            false,
        ),
        S::Failed(why) => (format!("<h1>Not connected</h1><div class=\"card msg err\"><p>{}</p></div>", esc(why)), false),
    };
    layout_with("GitHub", &body, if refresh { "<meta http-equiv=\"refresh\" content=\"4\">" } else { "" })
}

/// Without a client secret warden can't revoke the token on GitHub; the owner does it there.
pub fn disconnected(gone: bool, settings_url: &str) -> String {
    let text = if gone {
        "The token has been deleted from warden."
    } else {
        "It was not connected."
    };
    layout(
        "GitHub",
        &format!(
            "<h1>GitHub disconnected</h1><div class=\"card msg ok\"><p>{text}</p></div><div class=\"card msg\"><p>To make the token stop working on GitHub too, \
             revoke the app at <a href=\"{u}\">{u}</a> (“Revoke access”).</p></div>",
            u = esc(settings_url)
        ),
    )
}

#[derive(Clone, Copy)]
pub enum Kind {
    Ok,
    Err,
    Info,
}

pub fn message(title: &str, text: &str, kind: Kind) -> String {
    let class = match kind {
        Kind::Ok => "ok",
        Kind::Err => "err",
        Kind::Info => "",
    };
    layout(
        title,
        &format!("<h1>{}</h1><div class=\"card msg {class}\"><p>{}</p></div>", esc(title), esc(text)),
    )
}

fn ago(secs: i64) -> String {
    if secs < 60 {
        "just now".into()
    } else {
        format!("{} ago", human_duration(secs))
    }
}

fn mode_pill(mode: &str) -> String {
    match mode {
        "write" => "<span class=\"pill write\">Write</span> <span class=\"muted\">(new branches or fast-forwards, PRs, issues; as you)</span>".into(),
        _ => "<span class=\"pill read\">Read</span> <span class=\"muted\">(clone, fetch, read the API)</span>".into(),
    }
}

fn repos_html(repos: &serde_json::Value) -> String {
    repos
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str())
        .map(|r| format!("<code>{}</code>", esc(r)))
        .collect::<Vec<_>>()
        .join("<br>")
}

fn system_name(s: &str) -> &str {
    match s {
        "github" => "GitHub",
        "claude" => "claude.ai",
        "gcp" => "Artifact Registry (read)",
        other => other,
    }
}

const CLAUDE_WHAT: &str = "Your claude.ai session for Claude Code: an access token that lasts a few hours at a time, which warden renews. \
    The refresh token never leaves warden.";

fn claude_warning() -> String {
    "<div class=\"card msg err powers\"><p><b>⚠ With this, whatever runs in that sandbox talks to Anthropic as you</b> (your subscription, \
     Remote Control included) for as long as the grant lasts. Revoking it stops further deliveries; a token already delivered stays valid \
     until it expires (a few hours).</p></div>"
        .into()
}

fn artifacts_html(scope: &serde_json::Value) -> String {
    let list = crate::registry::scope_artifacts(scope);
    let items: Vec<String> = list.iter().map(|a| format!("<code>{}</code>", esc(a))).collect();
    format!(
        "<dt>Preset</dt><dd><code>{}</code></dd><dt>Can read</dt><dd>{}</dd><dt>With</dt><dd>Your Google account, read-only (<code>devstorage.read_only</code>). Neither the sandbox nor its guardian sees the token.</dd>",
        esc(scope["preset"].as_str().unwrap_or("?")),
        items.join("<br>")
    )
}

fn what_html(system: &str, scope: &serde_json::Value, mode: &str) -> String {
    if system == "claude" {
        return format!("<dt>What</dt><dd>{}</dd>", esc(CLAUDE_WHAT));
    }
    if system == "gcp" {
        return artifacts_html(scope);
    }
    format!(
        "<dt>Repos</dt><dd>{}</dd><dt>Mode</dt><dd>{}</dd>",
        repos_html(&scope["repos"]),
        mode_pill(mode)
    )
}

fn what_inline(system: &str, scope: &serde_json::Value, mode: &str) -> String {
    if system == "claude" {
        return "<span class=\"pill write\">claude.ai session</span>".into();
    }
    if system == "gcp" {
        let n = crate::registry::scope_artifacts(scope).len();
        return format!(
            "<span class=\"pill read\">Registries: {} ({n})</span>",
            esc(scope["preset"].as_str().unwrap_or("?"))
        );
    }
    format!("{} {}", repos_html(&scope["repos"]), mode_pill(mode))
}

fn warnings_html(system: &str, scope: &serde_json::Value, mode: &str) -> String {
    match (system, mode) {
        ("claude", _) => claude_warning(),
        (_, "write") => format!("{WRITE_RUNS_ACTIONS}{}", powers_html(scope, mode)),
        _ => powers_html(scope, mode),
    }
}

/// A plain write already runs Actions, so this shows before approving any write, powers or not.
const WRITE_RUNS_ACTIONS: &str = "<div class=\"card msg err powers\"><p><b>⚠ Writing also runs GitHub Actions.</b> \
    Every push to a branch and every pull request runs the repo's workflows that trigger on <code>push</code> or \
    <code>pull_request</code>, with the code Claude pushes (scripts, tests, the build) and with the repo secrets \
    those workflows use. Re-running workflows is a separate power. It cannot change the files in \
    <code>.github/workflows</code>.</p></div>";

fn powers_html(scope: &serde_json::Value, mode: &str) -> String {
    if mode != "write" {
        return String::new();
    }
    let powers = scope_powers(scope);
    if powers.is_empty() {
        return "<div class=\"card msg\"><p>Writing uses your account, but with no powers: it cannot write to the \
                default branch, force-push or delete branches, create, move or delete tags (the ones that trigger release \
                workflows), merge PRs or approve reviews.</p></div>"
            .into();
    }
    let items: String = powers
        .iter()
        .map(|p| format!("<li><b>{}</b> <code>{}</code></li>", esc(p.label()), p.as_str()))
        .collect();
    format!(
        "<div class=\"card msg err powers\"><p><b>⚠ This asks for powers that can undo work, skip a review \
         or publish, with your GitHub account:</b></p><ul>{items}</ul><p class=\"muted\">If you are an admin of the repo, it also bypasses the \
         branch protections that do not have “Do not allow bypassing”.</p></div>"
    )
}

fn csrf_field(csrf: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", esc(csrf))
}

/// `passkey`: a warden passkey is registered, so approving with it is offered.
pub fn request(r: &RequestRow, grant: Option<&GrantRow>, csrf: &str, now: i64, passkey: bool) -> String {
    let status = r.status_at(now);
    let mut body = format!(
        "<h1>Claude asks for access</h1><div class=\"card\"><dl>\
         <dt>System</dt><dd>{}</dd>{}\
         <dt>For</dt><dd>{} <span class=\"muted\">from when you approve it</span></dd>\
         <dt>Who</dt><dd class=\"mono\">{}</dd><dt>Asked</dt><dd>{}</dd></dl>\
         <p class=\"muted\" style=\"margin:.9em 0 .3em\">Why:</p><div class=\"reason\">{}</div></div>",
        esc(system_name(&r.system)),
        what_html(&r.system, &r.scope, &r.mode),
        human_duration(r.duration_secs),
        esc(&r.session_label),
        ago(now - r.created_at),
        esc(&r.reason),
    );
    body.push_str(&warnings_html(&r.system, &r.scope, &r.mode));
    let mut head = "";
    match (status, grant) {
        ("pending", _) if passkey => {
            head = SCRIPT;
            body.push_str(&format!(
                "<div class=\"card\"><p>Approve with the warden passkey, or with the Pocket ID one. The request expires in {}.</p>\
                 <div class=\"row\"><button class=\"primary\" type=\"button\" id=\"wa-approve\" data-request=\"{id}\" data-csrf=\"{csrf}\">Approve with the warden passkey</button>\
                 <form method=\"post\" action=\"/r/{id}/approve\">{c}<button type=\"submit\">Approve with the Pocket ID passkey</button></form>\
                 <form method=\"post\" action=\"/r/{id}/refuse\">{c}<button class=\"danger\" type=\"submit\">Refuse</button></form></div>\
                 <p id=\"wa-status\" class=\"muted\" role=\"status\"></p></div>",
                human_duration(r.expires_at - now),
                id = esc(&r.id),
                csrf = esc(csrf),
                c = csrf_field(csrf),
            ))
        }
        ("pending", _) => body.push_str(&format!(
            "<div class=\"card\"><p>To approve, Pocket ID will ask for your passkey again. The request expires in {}.</p>\
             <div class=\"row\"><form method=\"post\" action=\"/r/{id}/approve\">{c}<button class=\"primary\" type=\"submit\">Approve with passkey</button></form>\
             <form method=\"post\" action=\"/r/{id}/refuse\">{c}<button class=\"danger\" type=\"submit\">Refuse</button></form></div></div>",
            human_duration(r.expires_at - now),
            id = esc(&r.id),
            c = csrf_field(csrf),
        )),
        ("approved", Some(g)) if g.active_at(now) => body.push_str(&format!(
            "<div class=\"card msg ok\"><p>Granted until {} ({} left).</p>\
             <form method=\"post\" action=\"/g/{}/revoke\">{}<button class=\"danger\" type=\"submit\">Revoke now</button></form></div>",
            esc(&iso_utc(g.expires_at)),
            human_duration(g.expires_at - now),
            esc(&g.id),
            csrf_field(csrf),
        )),
        ("approved", Some(g)) => body.push_str(&format!(
            "<div class=\"card msg\"><p>It was granted and has ended ({}).</p></div>",
            if g.revoked_at.is_some() { "revoked" } else { "expired" }
        )),
        (s, _) => body.push_str(&format!("<div class=\"card msg\"><p>This request is {}.</p></div>", status_label(s))),
    }
    layout_with("Access request", &body, head)
}

pub fn passkey_register(challenge: &str, rp_id: &str, user_handle: &str, exclude: &[String], csrf: &str) -> String {
    let body = format!(
        "<h1>warden passkey</h1><div class=\"card\"><p>Pocket ID has confirmed it is you. Now create the warden passkey \
         (for <code>{rp}</code>): with it you approve from the heimdall card or from the request page, without going through Pocket ID. \
         Your device will ask you to unlock it (fingerprint, face or PIN). You have 5 minutes.</p>\
         <p><label>Name: <input id=\"wa-name\" maxlength=\"40\" value=\"passkey\" autocomplete=\"off\"></label> \
         <span class=\"muted\">(“phone”, “workstation”…)</span></p>\
         <div class=\"row\"><button class=\"primary\" type=\"button\" id=\"wa-register\" data-challenge=\"{ch}\" data-rp=\"{rp}\" data-user=\"{user}\" \
         data-exclude=\"{ex}\" data-csrf=\"{csrf}\">Create the passkey</button></div><p id=\"wa-status\" class=\"muted\" role=\"status\"></p></div>\
         <p><a href=\"/\">Back to the panel</a></p>",
        rp = esc(rp_id),
        ch = esc(challenge),
        user = esc(user_handle),
        ex = esc(&exclude.join(",")),
        csrf = esc(csrf),
    );
    layout_with("warden passkey", &body, SCRIPT)
}

pub fn granted(r: &RequestRow, g: &GrantRow, now: i64) -> String {
    let body = format!(
        "<h1>Granted</h1><div class=\"card msg ok\"><dl>{}\
         <dt>Until</dt><dd>{} (in {})</dd><dt>Who</dt><dd class=\"mono\">{}</dd></dl></div>{}\
         <p class=\"muted\">You can close this tab. You can revoke it from heimdall or from <a href=\"/r/{}\">the request</a>.</p>",
        what_html(&g.system, &g.scope, &g.mode),
        esc(&iso_utc(g.expires_at)),
        human_duration(g.expires_at - now),
        esc(&r.session_label),
        warnings_html(&g.system, &g.scope, &g.mode),
        esc(&r.id),
    );
    layout("Granted", &body)
}

pub struct Dashboard {
    pub pending: Vec<RequestRow>,
    pub active: Vec<(GrantRow, String)>,
    pub github: Option<ConnectionRow>,
    /// None: not enabled; Some(None): enabled but not connected.
    pub claude: Option<Option<ConnectionRow>>,
    /// None: not enabled; otherwise (connection, expected account).
    pub google: Option<(Option<ConnectionRow>, String)>,
    pub github_settings: String,
    pub audit: Vec<AuditRow>,
    /// None: warden passkeys are not enabled.
    pub passkeys: Option<Vec<PasskeyRow>>,
    pub now: i64,
}

fn alg_name(alg: i64) -> &'static str {
    match alg {
        -7 => "ES256",
        -8 => "Ed25519",
        -257 => "RS256",
        _ => "?",
    }
}

/// `c` is the forms' CSRF field.
fn github_connection(g: &ConnectionRow, settings: &str, now: i64, c: &str) -> String {
    let reconnect = format!(
        "<form method=\"post\" action=\"/connections/github\">{c}<button class=\"primary\" type=\"submit\">Reconnect GitHub (with passkey)</button></form> "
    );
    let disconnect = format!(
        "<form method=\"post\" action=\"/connections/github/disconnect\">{c}<button class=\"danger\" type=\"submit\">Disconnect GitHub (with passkey)</button></form>"
    );
    let who = format!(
        "GitHub: <b>{}</b> <span class=\"muted\">(scopes: <code>{}</code>, connected {})</span>",
        esc(&g.account),
        esc(&g.scopes),
        ago(now - g.connected_at)
    );
    if let Some((at, why)) = &g.broken {
        return format!(
            "<p>{who}</p><div class=\"card msg err\"><p><b>It has to be connected again.</b> Renewing the token failed {}: <code>{}</code>. \
             Until then, the proxy lets nothing through to GitHub.</p></div><div class=\"row\">{reconnect}{disconnect}</div>",
            ago(now - at),
            esc(why)
        );
    }
    match g.expires_at {
        Some(exp) => {
            let renewable = g
                .refresh_expires_at
                .map(|r| format!(" If unused, it can be renewed until {}.", esc(&iso_utc(r))))
                .unwrap_or_default();
            let renewed = g.refreshed_at.map(|r| format!(" Renewed {}.", ago(now - r))).unwrap_or_default();
            format!(
                "<p>{who}</p><p class=\"muted\">The token expires: it lasts 8 h and warden renews it on its own. This one expires at {} (in {}).{renewed}{renewable}</p>{disconnect}",
                esc(&iso_utc(exp)),
                human_duration(exp - now)
            )
        }
        None => format!(
            "<p>{who}</p><p class=\"muted\">The token <b>does not expire</b>: it is a connection from before the 8 h tokens (no refresh token). \
             To move to one that expires: first “Revoke access” at <a href=\"{s}\">{s}</a> (which makes this token worthless), then “Reconnect”.</p>\
             <div class=\"row\">{reconnect}{disconnect}</div>",
            s = esc(settings)
        ),
    }
}

fn claude_connection(c: Option<&ConnectionRow>, now: i64, csrf: &str) -> String {
    let connect =
        |label: &str| format!("<form method=\"post\" action=\"/connections/claude\">{csrf}<button class=\"primary\" type=\"submit\">{label}</button></form> ");
    let disconnect = format!(
        "<form method=\"post\" action=\"/connections/claude/disconnect\">{csrf}<button class=\"danger\" type=\"submit\">Disconnect claude.ai (with passkey)</button></form>"
    );
    let Some(c) = c else {
        return format!(
            "<p>claude.ai: not connected. <span class=\"muted\">Claude Code sandboxes get their session from here, \
             with your approval.</span></p>{}",
            connect("Connect claude.ai (with passkey)")
        );
    };
    let who = format!(
        "claude.ai: <b>{}</b> <span class=\"muted\">(scopes: <code>{}</code>, connected {})</span>",
        esc(&c.account),
        esc(&c.scopes),
        ago(now - c.connected_at)
    );
    if let Some((at, why)) = &c.broken {
        return format!(
            "<p>{who}</p><div class=\"card msg err\"><p><b>It has to be connected again.</b> Renewing the token failed {}: <code>{}</code>. \
             Until then, sandboxes get no token.</p></div><div class=\"row\">{}{disconnect}</div>",
            ago(now - at),
            esc(why),
            connect("Reconnect claude.ai (with passkey)")
        );
    }
    let renewed = c.refreshed_at.map(|r| format!(" Renewed {}.", ago(now - r))).unwrap_or_default();
    let exp = c
        .expires_at
        .map(|e| format!(" The current one expires at {} (in {}).", esc(&iso_utc(e)), human_duration(e - now)))
        .unwrap_or_default();
    format!(
        "<p>{who}</p><p class=\"muted\">The refresh token lives only here and warden renews the token on its own; sandboxes with a grant get the access token.{exp}{renewed}</p>\
         <div class=\"row\">{}{disconnect}</div>",
        connect("Reconnect claude.ai (with passkey)")
    )
}

pub fn claude_connect(authorize_url: &str, flow: &str, csrf: &str) -> String {
    let body = format!(
        "<h1>Connect claude.ai</h1><div class=\"card\"><ol>\
         <li><p>Open <a href=\"{u}\" target=\"_blank\" rel=\"noopener noreferrer\">claude.ai to authorize Claude Code</a> \
         with the account you expect (if the browser is signed in to another one, switch accounts first) and press “Authorize”.</p></li>\
         <li><p>claude.ai shows you a code. Copy all of it and paste it here:</p>\
         <form method=\"post\" action=\"/connections/claude/code\" style=\"display:block\">{c}\
         <input type=\"hidden\" name=\"flow\" value=\"{f}\">\
         <p><input name=\"code\" autocomplete=\"off\" spellcheck=\"false\" required style=\"width:100%\" placeholder=\"code#…\"></p>\
         <button class=\"primary\" type=\"submit\">Connect</button></form></li></ol>\
         <p class=\"muted\">The link is valid for ten minutes, and only once. warden keeps the refresh token encrypted and is the only one that uses it.</p></div>\
         <p><a href=\"/\">Back to the panel</a></p>",
        u = esc(authorize_url),
        c = csrf_field(csrf),
        f = esc(flow),
    );
    layout("claude.ai", &body)
}

pub fn claude_connected(account: &str, scopes: &str, subscription: Option<&str>) -> String {
    let body = format!(
        "<h1>claude.ai connected</h1><div class=\"card msg ok\"><p>Connected as <b>{}</b>{} (scopes: <code>{}</code>).</p>\
         <p>The token lasts a few hours and warden renews it on its own. Claude Code sandboxes get it when you approve their grant.</p></div>\
         <p><a href=\"/\">Back to the panel</a></p>",
        esc(account),
        subscription.map(|s| format!(", subscription <b>{}</b>", esc(s))).unwrap_or_default(),
        esc(scopes)
    );
    layout("claude.ai", &body)
}

pub fn claude_disconnected(gone: bool) -> String {
    let text = if gone {
        "The session has been deleted from warden: no sandbox gets a token any more."
    } else {
        "It was not connected."
    };
    layout(
        "claude.ai",
        &format!(
            "<h1>claude.ai disconnected</h1><div class=\"card msg ok\"><p>{text}</p></div><div class=\"card msg\"><p>The last access token delivered \
             stays valid until it expires (a few hours). The refresh token is no longer used here; on claude.ai the authorization lasts until it expires \
             or you sign out of your account's sessions.</p></div>"
        ),
    )
}

fn google_connection(g: Option<&ConnectionRow>, expected: &str, now: i64, c: &str) -> String {
    let connect =
        |label: &str| format!("<form method=\"post\" action=\"/connections/google\">{c}<button class=\"primary\" type=\"submit\">{label}</button></form> ");
    let disconnect = format!(
        "<form method=\"post\" action=\"/connections/google/disconnect\">{c}<button class=\"danger\" type=\"submit\">Disconnect Google (with passkey)</button></form>"
    );
    let Some(g) = g else {
        return format!(
            "<p>Google: not connected. <span class=\"muted\">With <b>{}</b> and read-only access to GCS and Artifact Registry: sandboxes read \
             the images and packages of their preset through warden.</span></p>{}",
            esc(expected),
            connect("Connect Google (with passkey)")
        );
    };
    let who = format!(
        "Google: <b>{}</b> <span class=\"muted\">(scopes: <code>{}</code>, connected {})</span>",
        esc(&g.account),
        esc(&g.scopes),
        ago(now - g.connected_at)
    );
    if let Some((at, why)) = &g.broken {
        return format!(
            "<p>{who}</p><div class=\"card msg err\"><p><b>It has to be connected again.</b> Renewing the token failed {}: <code>{}</code>. \
             Until then, the registry proxy lets nothing through.</p></div><div class=\"row\">{}{disconnect}</div>",
            ago(now - at),
            esc(why),
            connect("Reconnect Google (with passkey)")
        );
    }
    format!("<p>{who}</p><p class=\"muted\">The access token lasts an hour and warden renews it on its own.</p>{disconnect}")
}

pub fn google_connected(account: &str, scopes: &str) -> String {
    let body = format!(
        "<h1>Google connected</h1><div class=\"card msg ok\"><p>Connected as <b>{}</b> (scopes: <code>{}</code>).</p>\
         <p>Read-only. Sandboxes read what their preset allows through warden when you approve their grant.</p></div>\
         <p><a href=\"/\">Back to the panel</a></p>",
        esc(account),
        esc(scopes)
    );
    layout("Google", &body)
}

pub fn google_disconnected(gone: bool, revoked: bool) -> String {
    let text = match (gone, revoked) {
        (false, _) => "It was not connected.",
        (true, true) => "It has been deleted from warden and Google has revoked the authorization.",
        (true, false) => {
            "It has been deleted from warden, but Google did not confirm the revocation: remove it by hand at myaccount.google.com → Security → Your connections to third-party apps &amp; services."
        }
    };
    layout(
        "Google",
        &format!("<h1>Google disconnected</h1><div class=\"card msg ok\"><p>{text}</p></div><p><a href=\"/\">Back to the panel</a></p>"),
    )
}

pub fn dashboard(d: &Dashboard, csrf: &str) -> String {
    let c = csrf_field(csrf);
    let mut body = String::from("<h1>warden</h1><h2>Connections</h2><div class=\"card\">");
    match &d.github {
        Some(g) => body.push_str(&github_connection(g, &d.github_settings, d.now, &c)),
        None => body.push_str(&format!(
            "<p>GitHub: not connected.</p><form method=\"post\" action=\"/connections/github\">{c}<button class=\"primary\" type=\"submit\">Connect GitHub (with passkey)</button></form>"
        )),
    }
    body.push_str("</div>");
    if let Some(claude) = &d.claude {
        body.push_str("<div class=\"card\">");
        body.push_str(&claude_connection(claude.as_ref(), d.now, &c));
        body.push_str("</div>");
    }
    if let Some((google, expected)) = &d.google {
        body.push_str("<div class=\"card\">");
        body.push_str(&google_connection(google.as_ref(), expected, d.now, &c));
        body.push_str("</div>");
    }
    if let Some(passkeys) = &d.passkeys {
        body.push_str("<h2>warden passkey</h2><div class=\"card\">");
        if passkeys.is_empty() {
            body.push_str("<p class=\"muted\">None: you approve with Pocket ID only. With one, you can approve from the heimdall card.</p>");
        }
        for p in passkeys {
            let used = p
                .last_used_at
                .map(|t| format!("used {}", ago(d.now - t)))
                .unwrap_or_else(|| "never used".into());
            body.push_str(&format!(
                "<p><b>{}</b> <span class=\"muted\">· created {} · {} · {}{}</span> \
                 <form method=\"post\" action=\"/passkeys/{}/revoke\">{c}<button class=\"danger\" type=\"submit\">Remove (with Pocket ID)</button></form></p>",
                esc(&p.name),
                ago(d.now - p.created_at),
                used,
                alg_name(p.alg),
                if p.backup_eligible { " · syncable" } else { "" },
                esc(&p.id),
            ));
        }
        body.push_str(&format!(
            "<form method=\"post\" action=\"/passkeys/new\">{c}<button class=\"primary\" type=\"submit\">Add a passkey (with Pocket ID)</button></form></div>"
        ));
    }
    body.push_str("<h2>Pending</h2>");
    if d.pending.is_empty() {
        body.push_str("<p class=\"muted\">Nothing.</p>");
    }
    for r in &d.pending {
        body.push_str(&format!(
            "<div class=\"card\"><a href=\"/r/{}\">{} · {}</a> · {} · <span class=\"mono\">{}</span> <div class=\"muted\">{}</div>{}</div>",
            esc(&r.id),
            esc(system_name(&r.system)),
            what_inline(&r.system, &r.scope, &r.mode),
            human_duration(r.duration_secs),
            esc(&r.session_label),
            esc(&r.reason),
            warnings_html(&r.system, &r.scope, &r.mode)
        ));
    }
    body.push_str("<h2>Granted</h2>");
    if d.active.is_empty() {
        body.push_str("<p class=\"muted\">Nothing.</p>");
    }
    for (g, label) in &d.active {
        body.push_str(&format!(
            "<div class=\"card\">{} <span class=\"muted\">· {} left · <span class=\"mono\">{}</span></span>{}\
             <div class=\"row\"><form method=\"post\" action=\"/g/{}/revoke\">{c}<button class=\"danger\" type=\"submit\">Revoke</button></form></div></div>",
            what_inline(&g.system, &g.scope, &g.mode),
            human_duration(g.expires_at - d.now),
            esc(label),
            if g.system == "claude" {
                String::new()
            } else {
                powers_html(&g.scope, &g.mode)
            },
            esc(&g.id)
        ));
    }
    body.push_str("<h2>Audit</h2><div class=\"card\"><table><tr><th>When</th><th>Who</th><th>What</th><th>Detail</th></tr>");
    for a in &d.audit {
        let detail = a.detail.to_string();
        let detail: String = detail.chars().take(240).collect();
        body.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td></tr>",
            esc(&iso_utc(a.at)),
            esc(&a.actor),
            esc(&a.event),
            esc(&detail)
        ));
    }
    body.push_str(&format!(
        "</table></div><form method=\"post\" action=\"/logout\">{c}<button type=\"submit\">Log out</button></form>"
    ));
    layout("warden", &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn what_claude_writes_is_shown_as_text() {
        let r = RequestRow {
            id: "req_abcdefgh".into(),
            session_id: "s".into(),
            session_label: "<b>claude</b>".into(),
            system: "github".into(),
            scope: json!({"repos": ["o/r\"><script>"]}),
            mode: "write".into(),
            duration_secs: 3600,
            reason: "<script>alert(1)</script> & \"x\"".into(),
            created_at: 1000,
            expires_at: 1900,
            status: "pending".into(),
            decided_at: None,
            decided_by: None,
        };
        let html = request(&r, None, "tok\"en", 1100, true);
        assert!(!html.contains("claude.ai"), "a GitHub request says nothing of claude.ai");
        assert!(
            html.contains("Writing also runs GitHub Actions") && html.contains("<code>pull_request</code>"),
            "{html}"
        );
        assert!(html.contains("create, move or delete tags"), "{html}");
        assert!(html.contains("data-csrf=\"tok&quot;en\"") && html.contains("data-request=\"req_abcdefgh\""));
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;x&quot;"));
        assert!(html.contains("&lt;b&gt;claude&lt;/b&gt;"));
        assert!(html.contains("value=\"tok&quot;en\""));
        assert!(html.contains("action=\"/r/req_abcdefgh/approve\""));
    }

    #[test]
    fn a_claude_session_request_says_what_it_gives() {
        let r = RequestRow {
            id: "req_claude01".into(),
            session_id: "s".into(),
            session_label: "sandbox:sandbox-claude · 1a2b3c4d".into(),
            system: "claude".into(),
            scope: json!({"powers": ["claude_session"]}),
            mode: "session".into(),
            duration_secs: 720 * 3600,
            reason: "Remote Control node2".into(),
            created_at: 1000,
            expires_at: 1900,
            status: "pending".into(),
            decided_at: None,
            decided_by: None,
        };
        let html = request(&r, None, "t", 1100, false);
        assert!(
            html.contains("claude.ai") && html.contains("talks to Anthropic as you") && html.contains("refresh token never leaves warden"),
            "{html}"
        );
        assert!(!html.contains(">Read<") && !html.contains(">Write<") && !html.contains("Repos"), "{html}");
        assert!(!html.contains("GitHub Actions"), "{html}");
    }

    #[test]
    fn the_actions_warning_goes_with_write_and_the_tags_power_is_named() {
        let mut r = RequestRow {
            id: "req_tags0001".into(),
            session_id: "s".into(),
            session_label: "claude".into(),
            system: "github".into(),
            scope: json!({"repos": ["o/r"], "powers": []}),
            mode: "read".into(),
            duration_secs: 3600,
            reason: "read the code".into(),
            created_at: 1000,
            expires_at: 1900,
            status: "pending".into(),
            decided_at: None,
            decided_by: None,
        };
        assert!(!request(&r, None, "t", 1100, false).contains("GitHub Actions"));
        r.mode = "write".into();
        r.scope = json!({"repos": ["o/r"], "powers": ["tags"]});
        let html = request(&r, None, "t", 1100, false);
        assert!(html.contains("Writing also runs GitHub Actions"), "{html}");
        assert!(
            html.contains("Tags: create, move or delete them") && html.contains("<code>tags</code>"),
            "{html}"
        );
    }
}
