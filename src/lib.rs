// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! warden: on-demand, time-limited credentials for Claude Code sandboxes.
//!
//! A sandbox runs with no credentials of its own. When it needs one (e.g. a GitHub repo) it asks
//! warden with its session token, and the owner approves with a passkey. Grants are scoped, expire on
//! their own and can be revoked. Upstream tokens never leave warden: it proxies git and the APIs and
//! lets through only what was granted. Everything lands in an append-only audit log.
pub mod api;
pub mod app;
pub mod budget;
pub mod cbor;
pub mod claude;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod github;
pub mod google;
pub mod jwt;
pub mod nomad;
pub mod oidc;
pub mod pages;
pub mod proxy;
pub mod receive;
pub mod registry;
pub mod scope;
pub mod store;
pub mod util;
pub mod web;
pub mod webauthn;

#[cfg(test)]
mod testauthn;
#[cfg(test)]
mod testkey;
#[cfg(test)]
mod testpack;
