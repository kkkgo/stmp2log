// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use ring::aead;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_SKEW: i64 = 5 * 60 * 1000;

const KDF_CONTEXT: &str = "stmp2log-push-v1:";

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("push payload is too short")]
    TooShort,
    #[error("push payload does not decrypt (wrong web_pass, or it was tampered with)")]
    Decrypt,
    #[error("push payload is not valid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("push payload timestamp is {0} ms away from now; check the clocks on both sides")]
    Skew(i64),
    #[error("http: {0}")]
    Http(#[from] s2l_notify::HttpError),
    #[error("the far side answered {0}: {1}")]
    Rejected(u16, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub hostname: String,

    pub ts: i64,
    pub envelope_from: String,
    #[serde(default)]
    pub rcpt: Vec<String>,

    #[serde(default)]
    pub peer: String,

    pub raw_b64: String,
}

fn derive_key(web_pass: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_CONTEXT.as_bytes());
    h.update(web_pass.as_bytes());
    h.finalize().into()
}

fn sealing_key(web_pass: &str) -> aead::LessSafeKey {
    let raw = derive_key(web_pass);
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &raw)
        .expect("CHACHA20_POLY1305 always accepts a 32-byte key");
    aead::LessSafeKey::new(unbound)
}

pub fn seal(web_pass: &str, payload: &Payload) -> Result<Vec<u8>, PushError> {
    let mut nonce = [0u8; aead::NONCE_LEN];

    if getrandom::getrandom(&mut nonce).is_err() {
        nonce[..8].copy_from_slice(&payload.ts.to_le_bytes());
    }

    let mut buf = serde_json::to_vec(payload)?;
    sealing_key(web_pass)
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut buf,
        )
        .map_err(|_| PushError::Decrypt)?;

    let mut out = Vec::with_capacity(nonce.len() + buf.len());
    out.extend_from_slice(&nonce);
    out.append(&mut buf);
    Ok(out)
}

pub fn open(web_pass: &str, body: &[u8], now_ms: i64) -> Result<Payload, PushError> {
    if body.len() <= aead::NONCE_LEN + aead::CHACHA20_POLY1305.tag_len() {
        return Err(PushError::TooShort);
    }
    let (nonce_bytes, rest) = body.split_at(aead::NONCE_LEN);
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let mut buf = rest.to_vec();
    let plain = sealing_key(web_pass)
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut buf,
        )
        .map_err(|_| PushError::Decrypt)?;

    let payload: Payload = serde_json::from_slice(plain)?;
    let skew = now_ms - payload.ts;
    if skew.abs() > MAX_SKEW {
        return Err(PushError::Skew(skew));
    }
    Ok(payload)
}

pub async fn send(
    client: &s2l_notify::Client,
    push_url: &str,
    web_pass: &str,
    payload: &Payload,
) -> Result<(), PushError> {
    let body = seal(web_pass, payload)?;
    let url = format!("{}/api/push", push_url.trim_end_matches('/'));
    let headers = [("Content-Type", "application/octet-stream".to_string())];
    let resp = client
        .send(s2l_notify::http::Request {
            method: "POST",
            url: &url,
            headers: &headers,
            body: Some(&body),
        })
        .await?;
    if !(200..300).contains(&resp.status) {
        return Err(PushError::Rejected(
            resp.status,
            resp.text().trim().chars().take(200).collect(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub url: String,

    pub pass: String,

    pub hostname: String,
}
impl Config {
    pub fn enabled(&self) -> bool {
        !self.url.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(ts: i64) -> Payload {
        Payload {
            hostname: "idc-a".into(),
            ts,
            envelope_from: "ups@idc.local".into(),
            rcpt: vec!["log@x".into()],
            peer: "10.20.0.7".into(),
            raw_b64: "U3ViamVjdDogdGVzdA==".into(),
        }
    }

    #[test]
    fn a_sealed_payload_round_trips() {
        let sealed = seal("hunter2", &payload(1000)).unwrap();
        let got = open("hunter2", &sealed, 1000).unwrap();
        assert_eq!(got.hostname, "idc-a");
        assert_eq!(got.envelope_from, "ups@idc.local");
        assert_eq!(got.peer, "10.20.0.7");
    }

    #[test]
    fn the_wire_format_never_carries_the_plaintext() {
        let mut p = payload(1000);
        p.envelope_from = "SECRET-SENDER@example.com".into();
        let sealed = seal("pw", &p).unwrap();
        let as_text = String::from_utf8_lossy(&sealed);
        assert!(!as_text.contains("SECRET-SENDER"));
        assert!(!as_text.contains("idc-a"));
    }

    #[test]
    fn a_wrong_password_cannot_decrypt() {
        let sealed = seal("right", &payload(1000)).unwrap();
        assert!(matches!(
            open("wrong", &sealed, 1000),
            Err(PushError::Decrypt)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal("pw", &payload(1000)).unwrap();
        let n = sealed.len();
        sealed[n - 20] ^= 0x01;
        assert!(matches!(open("pw", &sealed, 1000), Err(PushError::Decrypt)));
    }

    #[test]
    fn a_replayed_payload_is_refused() {
        let sealed = seal("pw", &payload(1000)).unwrap();
        let much_later = 1000 + MAX_SKEW + 1;
        assert!(matches!(
            open("pw", &sealed, much_later),
            Err(PushError::Skew(_))
        ));

        assert!(open("pw", &sealed, 1000 + MAX_SKEW - 1).is_ok());
    }

    #[test]
    fn a_payload_from_the_future_is_also_refused() {
        let sealed = seal("pw", &payload(1_000_000)).unwrap();
        let err = open("pw", &sealed, 1000).unwrap_err();
        assert!(err.to_string().contains("clocks"), "{err}");
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        for junk in [&b""[..], b"short", &[0u8; 40][..]] {
            assert!(open("pw", junk, 0).is_err());
        }
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let a = seal("pw", &payload(1000)).unwrap();
        let b = seal("pw", &payload(1000)).unwrap();
        assert_ne!(a, b);
        assert_ne!(a[..aead::NONCE_LEN], b[..aead::NONCE_LEN]);
    }

    #[test]
    fn an_empty_web_pass_still_produces_a_usable_key() {
        let sealed = seal("", &payload(1000)).unwrap();
        assert!(open("", &sealed, 1000).is_ok());
    }
}
