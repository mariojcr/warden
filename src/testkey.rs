// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

//! Throwaway RSA keys for tests only: the fake identity provider's and an untrusted one.
//! Shared with the integration tests (tests/flow.rs includes this file via `#[path]`).
#![allow(dead_code)]

pub const IDP_KEY_B64: &str = concat!(
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClgfB1h7mvcHH7fXW6FZXiDUsgxcaps+OGqe+jn3mOrRqFrGOI",
    "1Ozc5ENCZhVzEAcWwo1lrUC3YuzEzSriMvj4ge1uuy2JxVAVoebOMip9NgKBcKmRqi4e2ZREywfOJWEQg4OZTMba/BamQ4YwdopX",
    "21xbruhWyRn5ZCTHY8nXdXbn/gg2qkw+iYDV5otpnzGynoyB1UzeFfRUBUYCbc6SYP0frSCARa3g0focYAOc8gjlEmmDNGzbYiuQ",
    "K/e0bd+a/w0FkMqox8AAQqHw5oaS1TSiMIUcD1d9t+u5uMkLMJtD8zM7HZrhAIE2FixS+Kt467havh9GllxeqJCR7nA3AgMBAAEC",
    "ggEAIedRS7Im7nJZVwwnPpxHXMweVLNO89p+xEoxZdI4Q2rgYPukVBZSAxnbUVG6GRzyZs4pyudHt4lTOSlSHI4WhEmRSrqbJHq/",
    "4f6NWjXakFWtA7kBc25qDjXB8qmoiqkLjidyoMeigJ9dQGfaqDjQNBkifUGCJK0DXhwOkK23XiREPhAlU+5g25V5AmSZ+n5i1f8U",
    "KrI3TQIWvWIZHqWpEzsB7X2kVd6v6bwHiSf0lyISAI3Hpmsc63pSD0LAL0aYHTno2XZRbHRuDzakthI8zpnQlmWD8OGUSiiT9Hct",
    "7O6YnSoA6A5oGIAI2LpgZd4oPOIKnDu5E6D0kZ/YlW9pMQKBgQDfggbfewO4qufAFL4MVoaM2iqc4lu+2U4z4eaOClFqrYaB+uH0",
    "fvMoVDTwP742aVagD6DSHrqckeKshv8Yv7t1Xm4e3LqsYxToWloDwemLTfxsoA7qD8Wtlu1BSNBIlNoTk5OOkdSSAq8EVZ5DqNN4",
    "93bCOEg4YP3E0Z0JkFnKaQKBgQC9kWWjChsSicRVJroBC+Ga07m0vhK3WxQlhWH3DdDEq7POaHo1alp6QJ/9MlF8+h7s1ftXWvcI",
    "W4N4rMB+bbZftsc8sn3ZuVDuzfWCigFLHQ6lt+nD9lk9Xci813ouRe5iZQ8JoUU3zHyFCvf+BGNImxSFR5TTZtgu2gSte1rRnwKB",
    "gGMqGIyM0rDbOulxCoUE2ruhjCiBEb2SQm0ofBdnIopXJQeEXT4SGSY6fiZd0bHoeKOZa3vuYFNZMp3jY0kCwFQpqmgM/NHBQCR6",
    "+dcS8OB6oFU9ioB0sPr8rJU7jhW13S+0WVJ3Bz4k7KvapNZWEEVqXgl72ScSeWUarzbwEbaJAoGBAJbBhZm2lLcWdtvdE3l3kHBH",
    "xt0Vd973gLsiKzmFdCyj/De/YMkQDmpA8Ls0hBem9mcU+XCMN/8egBy9Dcy9xZayzhnYPTukI9f2VTP+Om8Y6agi7bZZOLkT12tO",
    "1aztElqP0fivl1N7vN81TOlnZem84wHnXlUM6gnAeo3Ylu4zAoGAOXTuQHFzP2CAeoXkiXQZLmrrWFrgHjOmjUJ0JUH0g+jBG6X3",
    "ElFyJbv3UoLWgRfs4G4N1fExAvBAN0btuvesZbcDf5TRZeUO7Tqnjpz9xvYWdqcDb6gQ7MlMvMOcTBCc3S8MiwUcNB7EcR3kT1jQ",
    "Sizp8MuUJCxmsHUpKTWLqZk=",
);

pub const OTHER_KEY_B64: &str = concat!(
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpHOXPLKVxQQxxeScvb3ZoOOw5SlSlGWYJgyLlLK/RGr/TcCH3",
    "6R2HAln87HAlBFTPxc94829FNo8P2NWi/7TINMiekTuYW+2uzpXbfKKA+tfZzcRoolFFTosjVOTPRYvVINjGp4mlHFYsZvoQebGo",
    "UE9eMvMdw9ifCCLYpYIgo8E6m8qTIoAHqpFzFjGi2lKW/tlVlcoiN69eGEAO/1Oa92ZooBkuEzx7IBECqmyCPLWSGKlcYZKFUBVV",
    "zoaRfzxhULnRtspythQ6R+2fCRGs8Soge3ths0oP4N9a5kwd6nr+jg2/8z2QtR/pnMb69BPfyRmUKjB78OLyuFu6stRlAgMBAAEC",
    "ggEAF1hxFHcQ2xVu7tFEoA9D6iJa4JPKze83f1OrmGCMCuf67ZOQFOWzrk9xoHFRZULM+dElvDLlkZ6fruvbnitXnRXFpjeIDGyQ",
    "X26PEHmLA2wy1RNLVw3P/gCC7lyJ/l/BlylNflW4Mji7Cq59PJNYJlNOiZirUtjA9D9OyYKboqlOnI4jttpYYCHCiHcVPCqQfKrb",
    "/z4W95ppIsjMv2Ga+169IonfoRGcB649trtvoG7K+Nzt3TDun4MFTqf3ck4dflpVqL/WWGDC8oHTlHZcW7ZxRpnI/No0VPVFyyNL",
    "PawfTvP16/4H3CmIQUWpCJrjc//t466TnFF2Nri/SVnBFwKBgQDr92GdPj4Dlkup3trJZiTPmBRG3/vo1TG85aCsmWzQGxoIfyrk",
    "/L+vpvpiCbxveLIFzhrZiOcdyjM+1uGHkD61/ILYbddxM+zUXljYbNNTkxpCJIh6edKAD9CPBfLChyUe3ztyNp6CNc+4ksLC5kgs",
    "Ppcx946kTzhwVBZrW9/njwKBgQC3eHzXA7C4pMCxAhy23qwlY+enJ7amvcIwobccAbQoLdZdCBj8l6XeyPZpvLdFuqUZWShL+g1A",
    "ksDopvds0IdvpQIiNtgM3PabwLDthrQ0AkiqnjdtBEqaHloPgzop0lL1hLR0WP0EmVIKJsPEOknp4K5BW/m2rbE7Nx8jxutqywKB",
    "gAOfQoJVaEJJ1lN/NkCNLtd48Ca+XXGPhDnwFG1R1ZfEMrwap5/oOVEK8SD8IUZcxe7M4SCht1p/thWq2r9n+W51t9R2qy3zrBj+",
    "ccKwuPW5dle5k9a9c/u/QmZPoxBVXr6AkrsIF5rMFKoypoazXjw/obaEpE3lYWpoAAgZ2vAFAoGAP2lSZJIu8zJmMweS2xWNFAM6",
    "nohYVbsCMgLCodho5vYov9C7qhnTx3NXz2XdRiljRKaPCetrxySxrfd/Tsmn9ctnOGISPCfmyCBKRl4nTE55xRaX+4LfMfNJl1D4",
    "ulmqOJdcM1ZKZNuFAmMxiFHJGB+Cuq5KWXwg5GGBzsDCvw8CgYEA1Y5dLL3KUT0Ed7MKJWLrGJv5Z7dI8H1x3OO9nMsU7tlYAiYG",
    "7IsIharPtih6plbzHkAXzosuzUa6ewNj4x2rvbaKLuSLvojR5aowUa1ezX3SFWcoxlFGf/9DrglycZaVapX4Gsf2N6ANJxAPKF1x",
    "Iw9CXf/y/QlGegF++JE4TIk=",
);

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};

fn pair(b64: &str) -> RsaKeyPair {
    RsaKeyPair::from_pkcs8(&STANDARD.decode(b64).unwrap()).unwrap()
}

pub fn sign(b64: &str, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let key = pair(b64);
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig)
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

pub fn jwk(b64: &str, kid: &str) -> serde_json::Value {
    let c: RsaPublicKeyComponents<Vec<u8>> = pair(b64).public().into();
    serde_json::json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                       "n": URL_SAFE_NO_PAD.encode(&c.n), "e": URL_SAFE_NO_PAD.encode(&c.e)})
}
