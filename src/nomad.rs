// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Session bootstrap for Nomad jobs: a job brings no credentials, only its Nomad workload identity
//! (an RS256 JWT with a TTL), which warden exchanges for a session token bound to the allocation.
//! `exp` is required because an identity without a TTL would be valid forever, and the job must be
//! allowed in its own namespace (or be a dispatch/periodic child of an allowed job).
use std::time::Duration;

use serde_json::{Map, Value};

use crate::config::NomadConfig;
use crate::jwt::KeySet;

const SKEW: i64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct Workload {
    pub namespace: String,
    pub job_id: String,
    pub alloc_id: String,
    pub task: String,
}

impl Workload {
    /// Prefixed with the namespace outside `default`: the same job name in another namespace is a
    /// different workload.
    pub fn label(&self) -> String {
        let alloc: String = self.alloc_id.chars().take(8).collect();
        if self.namespace == "default" {
            format!("{} · {alloc}", self.job_id)
        } else {
            format!("{}:{} · {alloc}", self.namespace, self.job_id)
        }
    }
}

fn job_allowed(job_id: &str, jobs: &[String]) -> bool {
    jobs.iter().any(|j| {
        job_id == j
            || job_id
                .strip_prefix(j.as_str())
                .is_some_and(|rest| rest.starts_with("/dispatch-") || rest.starts_with("/periodic-"))
    })
}

pub fn check_workload(claims: &Map<String, Value>, cfg: &NomadConfig, now: i64) -> Result<Workload, String> {
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => *a == cfg.audience,
        Some(Value::Array(l)) => l.iter().any(|a| a.as_str() == Some(cfg.audience.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("the identity is not for audience «{}»", cfg.audience));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("the identity has no exp: give the job's identity block a ttl")?;
    if now > exp + SKEW {
        return Err("the identity has expired".into());
    }
    if claims.get("nbf").and_then(Value::as_i64).is_some_and(|nbf| nbf > now + SKEW) {
        return Err("the identity is not valid yet".into());
    }
    let s = |k: &str| claims.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let w = Workload {
        namespace: s("nomad_namespace"),
        job_id: s("nomad_job_id"),
        alloc_id: s("nomad_allocation_id"),
        task: s("nomad_task"),
    };
    let jobs = if w.namespace == cfg.namespace {
        Some(&cfg.jobs)
    } else {
        cfg.other_namespaces.get(&w.namespace)
    };
    let Some(jobs) = jobs else {
        return Err(format!("namespace «{}» is not allowed", w.namespace));
    };
    if !job_allowed(&w.job_id, jobs) {
        return Err(format!("job «{}» may not open warden sessions in namespace «{}»", w.job_id, w.namespace));
    }
    if w.alloc_id.is_empty() {
        return Err("the identity names no allocation".into());
    }
    Ok(w)
}

pub struct NomadIdentity {
    pub cfg: NomadConfig,
    keys: KeySet,
}

impl NomadIdentity {
    pub fn new(cfg: NomadConfig) -> anyhow::Result<NomadIdentity> {
        let mut http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca) = &cfg.ca_file {
            let pem = std::fs::read(ca).map_err(|e| anyhow::anyhow!("cannot read the Nomad CA {}: {e}", ca.display()))?;
            // Trust only the Nomad CA: no public CA should vouch for it.
            http = http.tls_built_in_root_certs(false).add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        let keys = KeySet::new(cfg.jwks_url.clone(), http.build()?);
        Ok(NomadIdentity { cfg, keys })
    }

    pub async fn verify(&self, token: &str, now: i64) -> Result<Workload, String> {
        let claims = self.keys.verify(token).await.map_err(|e| e.to_string())?;
        check_workload(&claims, &self.cfg, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> NomadConfig {
        NomadConfig {
            jwks_url: "http://unused".into(),
            ca_file: None,
            audience: "warden".into(),
            namespace: "default".into(),
            jobs: vec!["claude".into()],
            other_namespaces: [("sandbox".to_string(), vec!["sandbox-claude".to_string()])].into(),
        }
    }

    fn claims(job: &str) -> Map<String, Value> {
        json!({"aud": ["warden"], "exp": 2000, "iat": 1000, "nbf": 1000, "nomad_namespace": "default", "nomad_job_id": job,
               "nomad_allocation_id": "1a2b3c4d-0000-4000-8000-000000000000", "nomad_task": "claude",
               "sub": "global:default:claude:agent:claude:warden"})
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn the_claude_job_and_its_dispatches_open_sessions() {
        let w = check_workload(&claims("claude"), &cfg(), 1500).unwrap();
        assert_eq!(w.label(), "claude · 1a2b3c4d");
        assert!(check_workload(&claims("claude/dispatch-1700000000-ab12cd34"), &cfg(), 1500).is_ok());
        assert!(check_workload(&claims("claude/periodic-1700000000"), &cfg(), 1500).is_ok());
    }

    /// Whether Nomad reports the dispatched job or its parent, it opens a session; other jobs in that
    /// namespace don't, nor the same name elsewhere, nor a `jobs` entry moved there.
    #[test]
    fn sandbox_claude_jobs_open_sessions_and_nothing_else_in_their_namespace() {
        let with = |ns: &str, job: &str| {
            let mut c = claims(job);
            c.insert("nomad_namespace".into(), json!(ns));
            c
        };
        let w = check_workload(&with("sandbox", "sandbox-claude"), &cfg(), 1500).unwrap();
        assert_eq!(w.label(), "sandbox:sandbox-claude · 1a2b3c4d");
        assert!(check_workload(&with("sandbox", "sandbox-claude/dispatch-1700000000-ab12cd34"), &cfg(), 1500).is_ok());
        assert!(check_workload(&with("sandbox", "sandbox-vm"), &cfg(), 1500).unwrap_err().contains("may not"));
        assert!(check_workload(&with("sandbox", "sandbox-vm/dispatch-1700000000-ab12cd34"), &cfg(), 1500).is_err());
        assert!(check_workload(&with("sandbox", "claude"), &cfg(), 1500).is_err());
        assert!(check_workload(&with("default", "sandbox-claude"), &cfg(), 1500).is_err());
        assert!(
            check_workload(&with("sandbox-x", "sandbox-claude"), &cfg(), 1500)
                .unwrap_err()
                .contains("namespace")
        );
    }

    #[test]
    fn other_jobs_audiences_and_old_identities_do_not() {
        assert!(check_workload(&claims("claude-evil"), &cfg(), 1500).unwrap_err().contains("may not"));
        assert!(check_workload(&claims("claudex/dispatch-1"), &cfg(), 1500).is_err());
        assert!(check_workload(&claims("heimdall"), &cfg(), 1500).is_err());
        let mut c = claims("claude");
        c.insert("aud".into(), json!("nomad.io"));
        assert!(check_workload(&c, &cfg(), 1500).unwrap_err().contains("audience"));
        let mut c = claims("claude");
        c.remove("exp");
        assert!(check_workload(&c, &cfg(), 1500).unwrap_err().contains("ttl"));
        assert!(check_workload(&claims("claude"), &cfg(), 2100).unwrap_err().contains("expired"));
        let mut c = claims("claude");
        c.insert("nomad_namespace".into(), json!("prod"));
        assert!(check_workload(&c, &cfg(), 1500).is_err());
        let mut c = claims("claude");
        c.insert("nomad_allocation_id".into(), json!(""));
        assert!(check_workload(&c, &cfg(), 1500).is_err());
    }
}
