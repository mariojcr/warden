// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Requests and grants (system, scope, mode, duration), and the one question the proxy asks: does a
//! live grant of this session allow this, on this repository, now?
//!
//! A plain write is branch work: new or advancing branches, PRs and issues. That already runs the
//! repository's `push` and `pull_request` workflows with their secrets. Anything that can undo work,
//! skip a review or publish is a separate power, named in the request and approved one by one.
use serde_json::{Value, json};

use crate::store::GrantRow;

/// Write includes read.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Mode {
    Read,
    Write,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" | "r" | "ro" | "readonly" | "read-only" | "pull" | "fetch" => Some(Mode::Read),
            "write" | "w" | "rw" | "readwrite" | "read-write" | "push" => Some(Mode::Write),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Read => "read",
            Mode::Write => "write",
        }
    }

    pub fn covers(self, need: Mode) -> bool {
        self >= need
    }
}

/// Not allowed by a write grant unless the request names it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Power {
    DefaultBranch,
    ForcePush,
    /// Apart from write because `on: push: tags` typically publishes a release with the repository's
    /// secrets: a plain write could push a changed build script and then tag it.
    Tags,
    Merge,
    Approve,
    /// A re-run uses the original commit and ref with today's secrets: an old deploy or release again.
    Rerun,
}

impl Power {
    pub const ALL: [Power; 6] = [Power::DefaultBranch, Power::ForcePush, Power::Tags, Power::Merge, Power::Approve, Power::Rerun];

    pub fn parse(s: &str) -> Option<Power> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "default_branch" => Some(Power::DefaultBranch),
            "force_push" => Some(Power::ForcePush),
            "tags" => Some(Power::Tags),
            "merge" => Some(Power::Merge),
            "approve" => Some(Power::Approve),
            "rerun" => Some(Power::Rerun),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Power::DefaultBranch => "default_branch",
            Power::ForcePush => "force_push",
            Power::Tags => "tags",
            Power::Merge => "merge",
            Power::Approve => "approve",
            Power::Rerun => "rerun",
        }
    }

    /// Shown to the owner before approving.
    pub fn label(self) -> &'static str {
        match self {
            Power::DefaultBranch => "Write to the default branch (main) directly",
            Power::ForcePush => "Force-push: rewrite a branch's history, and delete branches",
            Power::Tags => "Tags: create, move or delete them (a tag triggers release workflows, with the repo's secrets)",
            Power::Merge => "Merge pull requests",
            Power::Approve => "Approve pull request reviews, as you",
            Power::Rerun => "Re-run workflows: they run that old commit again with today's secrets (an old deploy or release)",
        }
    }
}

pub fn scope_powers(scope: &Value) -> Vec<Power> {
    let mut out: Vec<Power> = scope["powers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str())
        .filter_map(Power::parse)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// GitHub names are case-insensitive, so compare by `key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repo {
    pub owner: String,
    pub name: String,
}

pub fn valid_owner(s: &str) -> bool {
    !s.is_empty() && s.len() <= 39 && !s.starts_with('-') && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

impl Repo {
    pub fn new(owner: &str, name: &str) -> Option<Repo> {
        (valid_owner(owner) && valid_name(name)).then(|| Repo {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }

    /// Accepts `o/r`, `github.com/o/r`, `https://github.com/o/r.git` and `git@github.com:o/r.git`.
    pub fn parse(raw: &str) -> Result<Repo, String> {
        let s = raw.trim();
        let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(s);
        let s = s.strip_prefix("git@github.com:").or_else(|| s.strip_prefix("github.com/")).unwrap_or(s);
        let s = s.trim_end_matches('/');
        let s = s.strip_suffix(".git").unwrap_or(s);
        let mut parts = s.split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(o), Some(n), None) => Repo::new(o, n).ok_or_else(|| format!("«{raw}» is not a valid GitHub owner/repo")),
            _ => Err(format!("«{raw}» is not owner/repo")),
        }
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.owner.to_ascii_lowercase(), self.name.to_ascii_lowercase())
    }
}

impl std::fmt::Display for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// Per request.
pub const MAX_REPOS: usize = 10;
const REASON_MAX: usize = 600;

#[derive(Debug, Clone)]
pub struct NewRequest {
    pub system: String,
    /// GitHub only.
    pub repos: Vec<Repo>,
    /// GitHub only; see `mode_str`.
    pub mode: Mode,
    pub duration_secs: i64,
    pub reason: String,
    /// GitHub write only.
    pub powers: Vec<Power>,
    /// «gcp» only. The grant keeps this copy of the list, so later config changes never widen it.
    pub preset: Option<String>,
    pub artifacts: Vec<String>,
}

impl NewRequest {
    pub fn mode_str(&self) -> &'static str {
        if self.system == crate::claude::SYSTEM {
            "session"
        } else {
            self.mode.as_str()
        }
    }

    pub fn is_gcp(&self) -> bool {
        self.system == crate::google::SYSTEM
    }

    pub fn scope(&self) -> Value {
        if self.system == crate::claude::SYSTEM {
            json!({"powers": [crate::claude::POWER]})
        } else if self.is_gcp() {
            json!({"preset": self.preset, "artifacts": self.artifacts})
        } else {
            scope_json(&self.repos, &self.powers)
        }
    }
}

pub fn grants_claude_session(scope: &Value) -> bool {
    scope["powers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|p| p.as_str() == Some(crate::claude::POWER))
}

pub const CLAUDE_SHAPE: &str = r#"{"system":"claude", "powers":["claude_session"], "duration":"720h", "reason":"why, in one or two sentences"}"#;

pub const SHAPE: &str = r#"{"system":"github", "scope":{"repos":["owner/repo"]}, "mode":"read|write", "powers":[] (write only, any of "default_branch", "force_push", "tags", "merge", "approve", "rerun"), "duration":"30m|2h|5400", "reason":"why, in one or two sentences"}"#;

pub const GCP_SHAPE: &str = r#"{"system":"gcp", "scope":{"preset":"name-of-a-preset"}, "duration":"72h", "reason":"why, in one or two sentences"}"#;

/// GitHub only.
pub fn parse_request(v: &Value, max_duration: i64) -> Result<NewRequest, String> {
    parse_request_with(v, max_duration, None)
}

/// Also accepts «claude» when `claude_max` is set.
pub fn parse_request_with(v: &Value, max_duration: i64, claude_max: Option<i64>) -> Result<NewRequest, String> {
    parse_request_for(v, max_duration, claude_max, None)
}

/// Also accepts «gcp» when `gcp` is set.
pub fn parse_request_for(v: &Value, max_duration: i64, claude_max: Option<i64>, gcp: Option<&crate::config::GcpConfig>) -> Result<NewRequest, String> {
    let system = v["system"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    match system.as_str() {
        "github" => {}
        "claude" => {
            return match claude_max {
                Some(max) => parse_claude(v, max),
                None => Err("system «claude» is not enabled in this warden.".into()),
            };
        }
        "gcp" => {
            return match gcp {
                Some(cfg) => parse_gcp(v, cfg),
                None => Err("system «gcp» is not enabled in this warden.".into()),
            };
        }
        "google" | "nomad" => {
            return Err(format!("system «{system}» is not available yet; only \"github\" is."));
        }
        "" => return Err(format!("\"system\" is missing. Give {SHAPE}.")),
        other => {
            return Err(format!("unknown system «{other}»; only \"github\" is available."));
        }
    }
    let repos = repos_from(&v["scope"]).map_err(|e| format!("{e} Give {SHAPE}."))?;
    let mode = v["mode"]
        .as_str()
        .and_then(Mode::parse)
        .ok_or_else(|| format!("\"mode\" must be \"read\" or \"write\". Give {SHAPE}."))?;
    let duration_secs = parse_duration(&v["duration"])?;
    if duration_secs < 60 {
        return Err("\"duration\" must be at least 1 minute.".into());
    }
    if duration_secs > max_duration {
        return Err(format!(
            "\"duration\" can be at most {} (asked {}).",
            show_secs(max_duration),
            show_secs(duration_secs)
        ));
    }
    let reason: String = v["reason"].as_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.chars().count() < 8 {
        return Err("\"reason\" is missing or too short: say what you need it for, the owner reads it before approving.".into());
    }
    if reason.chars().count() > REASON_MAX {
        return Err(format!("\"reason\" is longer than {REASON_MAX} characters; keep it to one or two sentences."));
    }
    // `powers` may also come inside `scope`.
    let powers = if v["powers"].is_null() {
        powers_from(&v["scope"]["powers"])?
    } else {
        powers_from(&v["powers"])?
    };
    if !powers.is_empty() && mode != Mode::Write {
        return Err("\"powers\" only go with \"mode\": \"write\".".into());
    }
    Ok(NewRequest {
        system,
        repos,
        mode,
        duration_secs,
        reason,
        powers,
        preset: None,
        artifacts: Vec::new(),
    })
}

/// What is granted is use of the owner's subscription, so there are no repos or mode; the power is
/// implied when not named.
fn parse_claude(v: &Value, max_duration: i64) -> Result<NewRequest, String> {
    let names: Vec<String> = match &v["powers"] {
        Value::Null => vec![crate::claude::POWER.to_string()],
        Value::String(s) => s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect(),
        Value::Array(a) => a
            .iter()
            .map(|p| p.as_str().map(String::from).ok_or("each power must be a string"))
            .collect::<Result<_, _>>()?,
        _ => return Err("\"powers\" must be a list".into()),
    };
    if names.iter().any(|n| n != crate::claude::POWER) || names.is_empty() {
        return Err(format!(
            "the only power of system «claude» is \"{}\". Give {CLAUDE_SHAPE}.",
            crate::claude::POWER
        ));
    }
    let has = |k: &str| !v[k].is_null() && v[k] != json!("") && v[k] != json!([]) && v[k] != json!({}) && v[k] != json!({"repos": []});
    if has("scope") || has("mode") {
        return Err(format!("system «claude» takes neither \"scope\" nor \"mode\". Give {CLAUDE_SHAPE}."));
    }
    let duration_secs = parse_duration(&v["duration"])?;
    if duration_secs < 60 {
        return Err("\"duration\" must be at least 1 minute.".into());
    }
    if duration_secs > max_duration {
        return Err(format!(
            "\"duration\" can be at most {} (asked {}).",
            show_secs(max_duration),
            show_secs(duration_secs)
        ));
    }
    let reason: String = v["reason"].as_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.chars().count() < 8 {
        return Err("\"reason\" is missing or too short: say what you need it for, the owner reads it before approving.".into());
    }
    if reason.chars().count() > REASON_MAX {
        return Err(format!("\"reason\" is longer than {REASON_MAX} characters; keep it to one or two sentences."));
    }
    Ok(NewRequest {
        system: crate::claude::SYSTEM.into(),
        repos: Vec::new(),
        mode: Mode::Read,
        duration_secs,
        reason,
        powers: Vec::new(),
        preset: None,
        artifacts: Vec::new(),
    })
}

/// What can be read is fixed by the config's presets, never by the requester.
fn parse_gcp(v: &Value, cfg: &crate::config::GcpConfig) -> Result<NewRequest, String> {
    let has = |k: &str| !v[k].is_null() && v[k] != json!("") && v[k] != json!([]) && v[k] != json!("read");
    if has("mode") || has("powers") {
        return Err(format!("system «gcp» takes neither \"mode\" nor \"powers\": it only reads. Give {GCP_SHAPE}."));
    }
    let scope = v["scope"]
        .as_object()
        .ok_or_else(|| format!("\"scope\" must be {{\"preset\": …}}. Give {GCP_SHAPE}."))?;
    if scope.keys().any(|k| k != "preset") {
        return Err(format!(
            "\"scope\" takes only \"preset\": what can be read is fixed in warden's config. Give {GCP_SHAPE}."
        ));
    }
    let name = scope.get("preset").and_then(|p| p.as_str()).unwrap_or("").trim();
    let preset = cfg.presets.get(name).ok_or_else(|| {
        let known: Vec<&str> = cfg.presets.keys().map(String::as_str).collect();
        format!("unknown preset «{name}»; the presets are: {}.", known.join(", "))
    })?;
    let duration_secs = parse_duration(&v["duration"])?;
    if duration_secs < 60 {
        return Err("\"duration\" must be at least 1 minute.".into());
    }
    if duration_secs > cfg.max_grant_secs {
        return Err(format!(
            "\"duration\" can be at most {} (asked {}).",
            show_secs(cfg.max_grant_secs),
            show_secs(duration_secs)
        ));
    }
    let reason: String = v["reason"].as_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.chars().count() < 8 {
        return Err("\"reason\" is missing or too short: say what you need it for, the owner reads it before approving.".into());
    }
    if reason.chars().count() > REASON_MAX {
        return Err(format!("\"reason\" is longer than {REASON_MAX} characters; keep it to one or two sentences."));
    }
    let mut artifacts = preset.artifacts.clone();
    artifacts.sort();
    artifacts.dedup();
    Ok(NewRequest {
        system: crate::google::SYSTEM.into(),
        repos: Vec::new(),
        mode: Mode::Read,
        duration_secs,
        reason,
        powers: Vec::new(),
        preset: Some(name.to_string()),
        artifacts,
    })
}

/// An unknown name is an error, never ignored.
fn powers_from(v: &Value) -> Result<Vec<Power>, String> {
    let names: Vec<String> = match v {
        Value::Null => return Ok(Vec::new()),
        Value::String(s) => s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect(),
        Value::Array(a) => a
            .iter()
            .map(|p| p.as_str().map(String::from).ok_or("each power must be a string"))
            .collect::<Result<_, _>>()?,
        _ => return Err("\"powers\" must be a list".into()),
    };
    let mut out = Vec::new();
    for n in names {
        let p = Power::parse(&n).ok_or_else(|| format!("unknown power «{n}»; the powers are default_branch, force_push, tags, merge and approve."))?;
        out.push(p);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn show_secs(s: i64) -> String {
    crate::util::human_duration(s).replace(" min", "m").replace(" h", "h").replace(' ', "")
}

fn repos_from(v: &Value) -> Result<Vec<Repo>, String> {
    let list: Vec<&Value> = match v {
        Value::String(_) => vec![v],
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => match (o.get("repos"), o.get("repo")) {
            (Some(Value::Array(a)), _) => a.iter().collect(),
            (Some(r @ Value::String(_)), _) | (None, Some(r @ Value::String(_))) => vec![r],
            _ => return Err("\"scope\" needs \"repos\".".into()),
        },
        _ => return Err("\"scope\" is missing.".into()),
    };
    if list.is_empty() {
        return Err("\"scope\" names no repository.".into());
    }
    if list.len() > MAX_REPOS {
        return Err(format!("at most {MAX_REPOS} repositories per request."));
    }
    let mut out: Vec<Repo> = Vec::new();
    for item in list {
        let raw = item.as_str().ok_or("each repository must be a string \"owner/repo\".")?;
        let repo = Repo::parse(raw)?;
        if !out.iter().any(|r| r.key() == repo.key()) {
            out.push(repo);
        }
    }
    Ok(out)
}

/// `90m`, `2h`, `1h30m`, `45s` or a number of seconds.
pub fn parse_duration(v: &Value) -> Result<i64, String> {
    let bad = || "\"duration\" must be like \"30m\", \"2h\", \"1h30m\" or a number of seconds.".to_string();
    match v {
        Value::Number(n) => n.as_i64().ok_or_else(bad),
        Value::String(s) => {
            let s = s.trim().to_ascii_lowercase();
            if let Ok(n) = s.parse::<i64>() {
                return Ok(n);
            }
            let (mut total, mut digits, mut any) = (0i64, String::new(), false);
            for c in s.chars() {
                if c.is_ascii_digit() {
                    digits.push(c);
                    continue;
                }
                let unit = match c {
                    'h' => 3600,
                    'm' => 60,
                    's' => 1,
                    _ => return Err(bad()),
                };
                let n: i64 = digits.parse().map_err(|_| bad())?;
                total = total.checked_add(n.checked_mul(unit).ok_or_else(bad)?).ok_or_else(bad)?;
                digits.clear();
                any = true;
            }
            if !digits.is_empty() || !any {
                return Err(bad());
            }
            Ok(total)
        }
        _ => Err(bad()),
    }
}

pub fn scope_json(repos: &[Repo], powers: &[Power]) -> Value {
    json!({"repos": repos.iter().map(|r| r.to_string()).collect::<Vec<_>>(), "powers": powers.iter().map(|p| p.as_str()).collect::<Vec<_>>()})
}

pub fn scope_repos(scope: &Value) -> Vec<Repo> {
    scope["repos"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str())
        .filter_map(|r| Repo::parse(r).ok())
        .collect()
}

/// The error tells the client what it has and how to ask for what it lacks.
pub fn find_grant<'a>(session_id: &str, grants: &'a [GrantRow], repo: &Repo, need: Mode, powers: &[Power], now: i64) -> Result<&'a GrantRow, String> {
    let live: Vec<&GrantRow> = grants
        .iter()
        .filter(|g| g.session_id == session_id && g.system == "github")
        .filter(|g| g.revoked_at.is_none() && g.starts_at <= now && now < g.expires_at)
        .collect();
    let key = repo.key();
    let for_repo: Vec<&&GrantRow> = live.iter().filter(|g| scope_repos(&g.scope).iter().any(|r| r.key() == key)).collect();
    let mode_ok: Vec<&&&GrantRow> = for_repo.iter().filter(|g| Mode::parse(&g.mode).is_some_and(|m| m.covers(need))).collect();
    if let Some(g) = mode_ok.iter().find(|g| powers.iter().all(|p| scope_powers(&g.scope).contains(p))) {
        return Ok(g);
    }
    if !mode_ok.is_empty() {
        let names: Vec<&str> = powers.iter().map(|p| p.as_str()).collect();
        return Err(format!(
            "this needs the power(s) {} on {repo}, and no active grant of this session has them. A plain write grant never pushes to the default branch, force-pushes or deletes branches, creates, moves or deletes tags, merges or approves. If it is really needed, ask for a new grant naming it: POST /api/requests {{\"system\":\"github\",\"scope\":{{\"repos\":[\"{repo}\"]}},\"mode\":\"write\",\"powers\":[\"{}\"],\"duration\":\"30m\",\"reason\":\"…\"}}, and say why in the reason.",
            names.join(", "),
            names.join("\",\"")
        ));
    }
    let have = if live.is_empty() {
        "this session has no active grant".to_string()
    } else {
        let list: Vec<String> = live
            .iter()
            .map(|g| {
                let repos: Vec<String> = scope_repos(&g.scope).iter().map(|r| r.to_string()).collect();
                format!("{} {} for {}", repos.join(", "), g.mode, crate::util::human_duration(g.expires_at - now))
            })
            .collect();
        format!("active grants: {}", list.join("; "))
    };
    Err(format!(
        "no active grant lets this session {} {repo} ({have}). Ask for one: POST /api/requests {{\"system\":\"github\",\"scope\":{{\"repos\":[\"{repo}\"]}},\"mode\":\"{}\",\"duration\":\"1h\",\"reason\":\"…\"}} and wait for the owner's approval.",
        if need == Mode::Write { "write to" } else { "read" },
        need.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: &str, session: &str, repos: &[&str], mode: &str, starts: i64, expires: i64, revoked: Option<i64>) -> GrantRow {
        GrantRow {
            id: id.into(),
            request_id: format!("req-{id}"),
            session_id: session.into(),
            system: "github".into(),
            scope: json!({"repos": repos}),
            mode: mode.into(),
            approved_by: "owner:owner".into(),
            auth_time: starts,
            starts_at: starts,
            expires_at: expires,
            revoked_at: revoked,
        }
    }

    fn repo(s: &str) -> Repo {
        Repo::parse(s).unwrap()
    }

    #[test]
    fn a_grant_covers_its_repos_its_mode_and_its_time_only() {
        let now = 10_000;
        let gs = vec![
            grant("g1", "s1", &["owner/Heimdall"], "read", now - 60, now + 3600, None),
            grant("g2", "s1", &["owner/project-a", "owner/project-b"], "write", now - 60, now + 60, None),
        ];
        assert_eq!(find_grant("s1", &gs, &repo("owner/heimdall"), Mode::Read, &[], now).unwrap().id, "g1");
        assert_eq!(find_grant("s1", &gs, &repo("owner/project-b"), Mode::Read, &[], now).unwrap().id, "g2");
        assert_eq!(find_grant("s1", &gs, &repo("owner/project-a"), Mode::Write, &[], now).unwrap().id, "g2");
        let e = find_grant("s1", &gs, &repo("owner/heimdall"), Mode::Write, &[], now).unwrap_err();
        assert!(e.contains("write to owner/heimdall") && e.contains("owner/Heimdall read"), "{e}");
        assert!(find_grant("s1", &gs, &repo("owner/heimdall-private"), Mode::Read, &[], now).is_err());
        assert!(find_grant("s1", &gs, &repo("other/heimdall"), Mode::Read, &[], now).is_err());
        assert!(
            find_grant("s2", &gs, &repo("owner/heimdall"), Mode::Read, &[], now)
                .unwrap_err()
                .contains("no active grant")
        );
    }

    #[test]
    fn expired_future_and_revoked_grants_do_not_count() {
        let now = 10_000;
        let at = |g: GrantRow| find_grant("s1", std::slice::from_ref(&g), &repo("o/r"), Mode::Read, &[], now).is_ok();
        assert!(at(grant("g", "s1", &["o/r"], "read", now - 10, now + 10, None)));
        assert!(!at(grant("g", "s1", &["o/r"], "read", now - 100, now, None)), "expires_at is exclusive");
        assert!(!at(grant("g", "s1", &["o/r"], "read", now - 100, now - 1, None)), "expired");
        assert!(!at(grant("g", "s1", &["o/r"], "read", now + 5, now + 100, None)), "not started");
        assert!(!at(grant("g", "s1", &["o/r"], "read", now - 10, now + 10, Some(now - 1))), "revoked");
    }

    #[test]
    fn powers_come_only_from_a_grant_that_named_them() {
        let now = 10_000;
        let mut plain = grant("g1", "s1", &["o/r"], "write", now - 10, now + 10, None);
        plain.scope = json!({"repos": ["o/r"], "powers": []});
        let mut merging = grant("g2", "s1", &["o/r"], "write", now - 10, now + 10, None);
        merging.scope = json!({"repos": ["o/r"], "powers": ["merge"]});
        let both = vec![plain.clone(), merging.clone()];
        assert_eq!(find_grant("s1", &both, &repo("o/r"), Mode::Write, &[], now).unwrap().id, "g1");
        assert_eq!(find_grant("s1", &both, &repo("o/r"), Mode::Write, &[Power::Merge], now).unwrap().id, "g2");
        let e = find_grant("s1", std::slice::from_ref(&plain), &repo("o/r"), Mode::Write, &[Power::Merge], now).unwrap_err();
        assert!(e.contains("merge") && e.contains("\"powers\""), "{e}");
        assert!(find_grant("s1", &both, &repo("o/r"), Mode::Write, &[Power::Merge, Power::ForcePush], now).is_err());
        // A power on a grant for another repository does not count.
        let mut other = grant("g3", "s1", &["o/x"], "write", now - 10, now + 10, None);
        other.scope = json!({"repos": ["o/x"], "powers": ["force_push"]});
        assert!(find_grant("s1", &[plain, other], &repo("o/r"), Mode::Write, &[Power::ForcePush], now).is_err());
        let base = json!({"system": "github", "scope": "o/r", "mode": "write", "duration": "1h", "reason": "rewrite the branch"});
        let with = |p: Value, mode: &str| {
            let mut b = base.clone();
            b["powers"] = p;
            b["mode"] = json!(mode);
            parse_request(&b, 14400)
        };
        assert_eq!(
            with(json!(["merge", "force-push", "merge"]), "write").unwrap().powers,
            vec![Power::ForcePush, Power::Merge]
        );
        assert_eq!(
            with(json!("approve,default_branch"), "write").unwrap().powers,
            vec![Power::DefaultBranch, Power::Approve]
        );
        assert!(with(json!(["admin"]), "write").unwrap_err().contains("unknown power"));
        assert!(with(json!(["merge"]), "read").unwrap_err().contains("write"));
        assert!(with(Value::Null, "write").unwrap().powers.is_empty());
    }

    #[test]
    fn the_claude_session_is_asked_by_name_and_only_where_enabled() {
        let max = 4 * 3600;
        let claude_max = 30 * 24 * 3600;
        let base = json!({"system": "claude", "powers": ["claude_session"], "duration": "720h", "reason": "Remote Control session node2"});
        let ok = parse_request_with(&base, max, Some(claude_max)).unwrap();
        assert_eq!((ok.system.as_str(), ok.mode_str(), ok.duration_secs), ("claude", "session", 720 * 3600));
        assert_eq!(ok.scope(), json!({"powers": ["claude_session"]}));
        assert!(grants_claude_session(&ok.scope()));
        let mut implicit = base.clone();
        implicit.as_object_mut().unwrap().remove("powers");
        assert!(grants_claude_session(&parse_request_with(&implicit, max, Some(claude_max)).unwrap().scope()));
        assert!(!grants_claude_session(&json!({"repos": ["o/r"], "powers": ["merge"]})));
        let gh = json!({"system": "github", "scope": "o/r", "mode": "write", "powers": ["claude_session"], "duration": "1h", "reason": "push the branch"});
        assert!(parse_request_with(&gh, max, Some(claude_max)).unwrap_err().contains("unknown power"));
        // Capped by its own maximum, not GitHub's.
        assert!(parse_request(&base, max).unwrap_err().contains("not enabled"));
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            parse_request_with(&b, max, Some(claude_max))
        };
        assert!(with("duration", json!("721h")).unwrap_err().contains("at most"));
        assert!(with("powers", json!(["claude_session", "merge"])).is_err());
        assert!(with("powers", json!([])).is_err());
        assert!(with("scope", json!({"repos": ["o/r"]})).is_err());
        assert!(with("mode", json!("write")).is_err());
        assert!(with("reason", json!("pls")).is_err());
        // A web form sends an empty repository list.
        assert!(with("scope", json!({"repos": []})).is_ok());
    }

    #[test]
    fn requests_are_validated_before_anyone_sees_them() {
        let max = 4 * 3600;
        let ok = parse_request(
            &json!({"system": "github", "scope": {"repos": ["https://github.com/owner/heimdall.git", "owner/heimdall", "o/r"]},
                    "mode": "write", "duration": "1h30m", "reason": "  push the fix\n for the proxy  "}),
            max,
        )
        .unwrap();
        assert_eq!(ok.repos.len(), 2, "duplicates fold");
        assert_eq!(ok.duration_secs, 5400);
        assert_eq!(ok.reason, "push the fix for the proxy");
        assert_eq!(ok.mode, Mode::Write);
        let base = json!({"system": "github", "scope": "o/r", "mode": "read", "duration": "1h", "reason": "read the code"});
        assert!(parse_request(&base, max).is_ok());
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            parse_request(&b, max)
        };
        assert!(with("system", json!("gcp")).unwrap_err().contains("not enabled"));
        assert!(with("system", json!("google")).unwrap_err().contains("not available yet"));
        assert!(with("mode", json!("admin")).is_err());
        assert!(with("duration", json!("5h")).unwrap_err().contains("at most"));
        assert!(with("duration", json!("30s")).is_err());
        assert!(with("duration", json!("1x")).is_err());
        assert!(with("reason", json!("pls")).is_err());
        assert!(with("scope", json!(["o/r/x"])).is_err());
        assert!(with("scope", json!(["../r"])).is_err());
        assert!(with("scope", json!(["o/.."])).is_err());
        assert!(with("scope", json!((0..11).map(|i| format!("o/r{i}")).collect::<Vec<_>>())).is_err());
        assert_eq!(parse_duration(&json!(5400)).unwrap(), 5400);
        assert_eq!(parse_duration(&json!("2h")).unwrap(), 7200);
    }

    fn gcp_config() -> crate::config::GcpConfig {
        serde_json::from_value(json!({
            "client_id": "cid", "client_secret_file": "/s", "expected_email": "m@example.com", "max_grant_secs": 259200,
            "presets": {"app-env": {"description": "app", "artifacts": [
                "europe-docker.pkg.dev/example-artifacts/team/app/develop",
                "composer.example.com/example-vendor/logger",
                "europe-docker.pkg.dev/example-artifacts/team/app/develop"
            ]}}
        }))
        .unwrap()
    }

    #[test]
    fn a_registry_request_names_a_preset_and_nothing_else() {
        let cfg = gcp_config();
        let parse = |v: Value| parse_request_for(&v, 4 * 3600, None, Some(&cfg));
        let base = json!({"system": "gcp", "scope": {"preset": "app-env"}, "duration": "72h", "reason": "pull the app stack in its sandbox"});
        let ok = parse(base.clone()).unwrap();
        assert_eq!((ok.system.as_str(), ok.mode_str(), ok.duration_secs), ("gcp", "read", 72 * 3600));
        let scope = ok.scope();
        assert_eq!(scope["preset"], json!("app-env"));
        assert_eq!(
            crate::registry::scope_artifacts(&scope),
            vec![
                "composer.example.com/example-vendor/logger",
                "europe-docker.pkg.dev/example-artifacts/team/app/develop"
            ]
        );
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            parse(b)
        };
        assert!(with("scope", json!({"preset": "app-env", "artifacts": ["europe-docker.pkg.dev/a/b/c"]})).is_err());
        assert!(with("scope", json!({"preset": "other"})).unwrap_err().contains("unknown preset"));
        assert!(with("scope", json!("app-env")).is_err());
        assert!(with("mode", json!("write")).is_err());
        assert!(with("powers", json!(["merge"])).is_err());
        // Capped by `gcp.max_grant_secs`, not GitHub's maximum.
        assert!(with("duration", json!("73h")).unwrap_err().contains("at most"));
        assert!(with("reason", json!("x")).is_err());
        assert!(parse_request_for(&base, 4 * 3600, None, None).unwrap_err().contains("not enabled"));
    }
}
