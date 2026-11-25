// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! warden [serve] [--config warden.json]
//! warden mint-session --label <text> [--ttl <s>] [--config …]   mint a session by hand (testing); token on stdout
//! warden audit-verify [--config …]                               verify the audit chain (needs the master key; read-only)
//! warden gen-key                                                 print a new master key (base64)
//! Config comes from `--config`, WARDEN_CONFIG or ./warden.json.
use std::path::PathBuf;

use warden::app::{App, serve};
use warden::config::Config;
use warden::crypto::{AuditKey, read_master_key};
use warden::store::Store;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    // Pin ring as the process-wide rustls provider so reqwest and the listeners agree on one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().filter(|a| !a.starts_with("--")).cloned().unwrap_or_else(|| "serve".into());
    if command == "gen-key" {
        println!("{}", warden::crypto::new_master_key());
        return Ok(());
    }
    let path = arg(&args, "--config")
        .or_else(|| std::env::var("WARDEN_CONFIG").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("warden.json"));
    let cfg = Config::load(&path)?;
    match command.as_str() {
        "serve" => {
            let app = App::new(cfg)?;
            tracing::info!(public_url = %app.cfg.public_url, "warden starting");
            serve(app).await
        }
        "mint-session" => {
            let label = arg(&args, "--label").ok_or_else(|| anyhow::anyhow!("mint-session needs --label"))?;
            let ttl = arg(&args, "--ttl")
                .map(|t| t.parse::<i64>())
                .transpose()?
                .unwrap_or(cfg.limits.session_ttl_secs);
            let key = AuditKey::derive(&read_master_key(&cfg.master_key_file)?)?;
            let store = Store::open(&cfg.data_dir.join("warden.sqlite"), key, cfg.audit_legacy_head.as_deref())?;
            let (s, token) = store
                .create_session(&label, serde_json::json!({"kind": "cli"}), None, ttl, warden::util::now())?
                .map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("session {} «{}» until {}", s.id, s.label, warden::util::iso_utc(s.expires_at));
            println!("{token}");
            Ok(())
        }
        "audit-verify" => {
            let key = AuditKey::derive(&read_master_key(&cfg.master_key_file)?)?;
            match Store::verify_file(&cfg.data_dir.join("warden.sqlite"), &key, cfg.audit_legacy_head.as_deref())? {
                Ok(c) if c.legacy_rows > 0 => {
                    println!(
                        "the audit chain holds: {} rows; the first {} are from before keyed hashes (the last one hashes to {}) and are sealed by row {} (audit.keyed), the rest are keyed with the master key",
                        c.rows,
                        c.legacy_rows,
                        c.legacy_head.as_deref().unwrap_or("?"),
                        c.legacy_rows + 1
                    );
                    Ok(())
                }
                Ok(c) => {
                    println!("the audit chain holds: {} rows, all keyed with the master key", c.rows);
                    Ok(())
                }
                Err(e) => anyhow::bail!("{e}"),
            }
        }
        other => {
            anyhow::bail!("unknown command «{other}»: serve, mint-session, audit-verify or gen-key")
        }
    }
}
