// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! A fake WebAuthn authenticator for tests only (ES256, Ed25519, RS256). Shared with the
//! integration tests (tests/flow.rs includes it via `#[path]`).
#![allow(dead_code)]

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};

const UP_UV_AT: u8 = 0x01 | 0x04 | 0x40;

pub enum Key {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rs256(RsaKeyPair),
}

pub struct Authenticator {
    pub key: Key,
    pub credential_id: Vec<u8>,
}

fn sha256(d: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, d).as_ref().to_vec()
}

fn random_id() -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; 20];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => {
            let mut v = vec![m | 25];
            v.extend((n as u16).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![m | 26];
            v.extend((n as u32).to_be_bytes());
            v
        }
    }
}

pub fn int(i: i64) -> Vec<u8> {
    if i >= 0 { head(0, i as u64) } else { head(1, (-1 - i) as u64) }
}

pub fn bytes(b: &[u8]) -> Vec<u8> {
    let mut v = head(2, b.len() as u64);
    v.extend_from_slice(b);
    v
}

pub fn text(s: &str) -> Vec<u8> {
    let mut v = head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

pub fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = head(5, pairs.len() as u64);
    for (k, val) in pairs {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}

pub fn cose_ec2(x: &[u8], y: &[u8], alg: i64) -> Vec<u8> {
    map(&[
        (int(1), int(2)),
        (int(3), int(alg)),
        (int(-1), int(1)),
        (int(-2), bytes(x)),
        (int(-3), bytes(y)),
    ])
}

impl Authenticator {
    pub fn es256() -> Authenticator {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Authenticator {
            key: Key::Es256(kp),
            credential_id: random_id(),
        }
    }

    pub fn ed25519() -> Authenticator {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Authenticator {
            key: Key::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()),
            credential_id: random_id(),
        }
    }

    pub fn rs256() -> Authenticator {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD.decode(crate::testkey::OTHER_KEY_B64).unwrap();
        Authenticator {
            key: Key::Rs256(RsaKeyPair::from_pkcs8(&der).unwrap()),
            credential_id: random_id(),
        }
    }

    pub fn cose(&self) -> Vec<u8> {
        match &self.key {
            Key::Es256(kp) => {
                let p = kp.public_key().as_ref();
                cose_ec2(&p[1..33], &p[33..65], -7)
            }
            Key::Ed25519(kp) => map(&[
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (int(-2), bytes(kp.public_key().as_ref())),
            ]),
            Key::Rs256(kp) => {
                let c: RsaPublicKeyComponents<Vec<u8>> = kp.public().into();
                map(&[(int(1), int(3)), (int(3), int(-257)), (int(-1), bytes(&c.n)), (int(-2), bytes(&c.e))])
            }
        }
    }

    /// `authenticatorData` for an assertion (no attested credential).
    pub fn auth_data(&self, rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut ad = sha256(rp_id.as_bytes());
        ad.push(flags);
        ad.extend(count.to_be_bytes());
        ad
    }

    pub fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut msg = auth_data.to_vec();
        msg.extend(sha256(client_data));
        let rng = SystemRandom::new();
        match &self.key {
            Key::Es256(kp) => kp.sign(&rng, &msg).unwrap().as_ref().to_vec(),
            Key::Ed25519(kp) => kp.sign(&msg).as_ref().to_vec(),
            Key::Rs256(kp) => {
                let mut sig = vec![0; kp.public().modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, &msg, &mut sig).unwrap();
                sig
            }
        }
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    /// Returns (clientDataJSON, attestationObject); the AT flag is always set.
    pub fn attest(&self, challenge: &str, origin: &str, rp_id: &str, flags: u8) -> (Vec<u8>, Vec<u8>) {
        let cd = Self::client_data("webauthn.create", challenge, origin);
        let mut ad = sha256(rp_id.as_bytes());
        ad.push(flags | 0x40);
        ad.extend(0u32.to_be_bytes());
        ad.extend([0x11; 16]);
        ad.extend((self.credential_id.len() as u16).to_be_bytes());
        ad.extend(&self.credential_id);
        ad.extend(self.cose());
        let att = map(&[(text("fmt"), text("none")), (text("attStmt"), map(&[])), (text("authData"), bytes(&ad))]);
        (cd, att)
    }

    /// Returns (clientDataJSON, authenticatorData, signature).
    pub fn assert(&self, challenge: &str, origin: &str, rp_id: &str, flags: u8, count: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let cd = Self::client_data("webauthn.get", challenge, origin);
        let ad = self.auth_data(rp_id, flags, count);
        let sig = self.sign(&ad, &cd);
        (cd, ad, sig)
    }
}

pub const REGISTER_FLAGS: u8 = UP_UV_AT & !0x40;
