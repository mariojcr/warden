// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Encryption at rest for connection tokens: ChaCha20-Poly1305 under the master key, which never
//! lives on the data volume. Each envelope has a random nonce and is bound to its row through the AAD,
//! so an envelope copied to another row won't open. The audit chain key is derived from the same key.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::{hkdf, hmac};

use crate::util::random;

/// First byte of every envelope, so the format can change without guessing.
const VERSION: u8 = 1;

pub struct Sealer {
    key: LessSafeKey,
}

impl Sealer {
    pub fn from_key(raw: &[u8]) -> anyhow::Result<Sealer> {
        anyhow::ensure!(raw.len() == 32, "the master key must be 32 bytes, not {}", raw.len());
        let key = UnboundKey::new(&CHACHA20_POLY1305, raw).map_err(|_| anyhow::anyhow!("the master key was rejected"))?;
        Ok(Sealer { key: LessSafeKey::new(key) })
    }

    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Sealer> {
        Sealer::from_key(&read_master_key(path)?)
    }

    pub fn seal(&self, plain: &[u8], aad: &str) -> Vec<u8> {
        let nonce = random::<NONCE_LEN>();
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut buf)
            .expect("sealing cannot fail with a valid key");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + buf.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out
    }

    /// A wrong key, a wrong AAD and a tampered byte all fail the same way.
    pub fn open(&self, sealed: &[u8], aad: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(sealed.len() > 1 + NONCE_LEN && sealed[0] == VERSION, "not a sealed value");
        let nonce: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN].try_into().expect("checked length");
        let mut buf = sealed[1 + NONCE_LEN..].to_vec();
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut buf)
            .map_err(|_| anyhow::anyhow!("the sealed value does not open with this key"))?;
        Ok(plain.to_vec())
    }
}

/// Accepts 32 bytes of base64 in any common alphabet, padded or not.
pub fn read_master_key(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read the master key {}: {e}", path.display()))?;
    let text = text.trim();
    let raw = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(text).ok())
        .ok_or_else(|| anyhow::anyhow!("the master key in {} is not base64", path.display()))?;
    anyhow::ensure!(raw.len() == 32, "the master key must be 32 bytes, not {}", raw.len());
    Ok(raw)
}

/// Keys the audit chain: each row carries an HMAC over the previous one, so write access to the
/// database without the master key can't rewrite history. Derived with HKDF so the master key is not
/// used as-is for two purposes.
pub struct AuditKey(hmac::Key);

/// Changing this changes every MAC and breaks verification of the existing chain.
const AUDIT_KEY_INFO: &[u8] = b"warden/audit-chain/hmac-sha256/v1";

impl AuditKey {
    pub fn derive(master: &[u8]) -> anyhow::Result<AuditKey> {
        anyhow::ensure!(master.len() == 32, "the master key must be 32 bytes, not {}", master.len());
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"warden").extract(master);
        let okm = prk
            .expand(&[AUDIT_KEY_INFO], hmac::HMAC_SHA256)
            .map_err(|_| anyhow::anyhow!("cannot derive the audit key"))?;
        Ok(AuditKey(hmac::Key::from(okm)))
    }

    pub fn mac_hex(&self, data: &[u8]) -> String {
        hmac::sign(&self.0, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn verifies(&self, data: &[u8], hex: &str) -> bool {
        crate::util::ct_eq(self.mac_hex(data).as_bytes(), hex.as_bytes())
    }
}

pub fn new_master_key() -> String {
    STANDARD.encode(random::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer(byte: u8) -> Sealer {
        Sealer::from_key(&[byte; 32]).unwrap()
    }

    #[test]
    fn a_sealed_token_never_shows_and_only_opens_where_it_was_sealed() {
        let s = sealer(7);
        let token = b"gho_live_token_never_stored_in_clear";
        let sealed = s.seal(token, "warden/connection/github");
        // Not even an 8-byte fragment of the token is stored.
        assert!(!sealed.windows(8).any(|w| token.windows(8).any(|t| t == w)));
        assert_eq!(s.open(&sealed, "warden/connection/github").unwrap(), token);
        assert!(s.open(&sealed, "warden/connection/google").is_err());
        assert!(sealer(8).open(&sealed, "warden/connection/github").is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(s.open(&bad, "warden/connection/github").is_err());
        assert_ne!(sealed, s.seal(token, "warden/connection/github"));
    }

    #[test]
    fn the_audit_key_is_derived_from_the_master_key() {
        let a = AuditKey::derive(&[7; 32]).unwrap();
        let mac = a.mac_hex(b"row");
        assert_eq!(mac.len(), 64);
        assert_eq!(mac, AuditKey::derive(&[7; 32]).unwrap().mac_hex(b"row"));
        assert!(a.verifies(b"row", &mac) && !a.verifies(b"row2", &mac) && !a.verifies(b"row", &mac[..63]));
        assert_ne!(mac, AuditKey::derive(&[8; 32]).unwrap().mac_hex(b"row"));
        let raw: String = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]), b"row")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(mac, raw, "derived, not the master key itself");
        assert!(AuditKey::derive(&[7; 16]).is_err());
    }

    #[test]
    fn master_keys_must_be_32_bytes() {
        assert!(Sealer::from_key(&[1; 16]).is_err());
        let dir = std::env::temp_dir().join(format!("warden-key-{}", crate::util::new_id("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        std::fs::write(&path, format!("{}\n", new_master_key())).unwrap();
        assert!(Sealer::from_file(&path).is_ok());
        std::fs::write(&path, "not base64 at all!").unwrap();
        assert!(Sealer::from_file(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
