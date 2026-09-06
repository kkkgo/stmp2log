// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const NONCE_TTL: Duration = Duration::from_secs(60);

const MAX_NONCES: usize = 256;

const MAX_SESSIONS: usize = 64;

const FAIL_BEFORE_DELAY: u32 = 3;

pub struct Auth {
    password_hash: Option<String>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    nonces: HashMap<String, Instant>,

    sessions: HashMap<String, Instant>,

    failures: HashMap<String, (u32, Instant)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    BadNonce,

    BadProof,

    TooManyAttempts,
}

impl Auth {
    pub fn new(password: &str) -> Self {
        Self {
            password_hash: (!password.is_empty()).then(|| sha256_hex(password.as_bytes())),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn required(&self) -> bool {
        self.password_hash.is_some()
    }

    pub fn challenge(&self) -> (String, u64) {
        let nonce = random_hex();
        let mut inner = self.lock();
        inner.sweep();

        if inner.nonces.len() >= MAX_NONCES {
            if let Some(oldest) = inner
                .nonces
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                inner.nonces.remove(&oldest);
            }
        }
        inner.nonces.insert(nonce.clone(), Instant::now());
        (nonce, NONCE_TTL.as_secs())
    }

    pub fn login(&self, nonce: &str, proof: &str, from: &str) -> Result<(String, u64), LoginError> {
        let mut inner = self.lock();
        inner.sweep();

        if inner.failed_too_often(from) {
            return Err(LoginError::TooManyAttempts);
        }

        let issued = inner.nonces.remove(nonce);
        let Some(at) = issued else {
            inner.record_failure(from);
            return Err(LoginError::BadNonce);
        };
        if at.elapsed() > NONCE_TTL {
            inner.record_failure(from);
            return Err(LoginError::BadNonce);
        }

        let expect = self.expected_proof(nonce);
        if !constant_time_eq(proof.as_bytes(), expect.as_bytes()) {
            inner.record_failure(from);
            return Err(LoginError::BadProof);
        }

        inner.failures.remove(from);
        let token = random_hex();
        if inner.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = inner
                .sessions
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                inner.sessions.remove(&oldest);
            }
        }
        inner.sessions.insert(token.clone(), Instant::now());

        Ok((token, 0))
    }

    pub fn verify(&self, token: &str) -> bool {
        if self.password_hash.is_none() {
            return true;
        }
        if token.is_empty() {
            return false;
        }
        let mut inner = self.lock();
        match inner.sessions.get_mut(token) {
            Some(last) => {
                *last = Instant::now();
                true
            }
            None => false,
        }
    }

    pub fn logout(&self, token: &str) {
        self.lock().sessions.remove(token);
    }

    pub fn expected_proof(&self, nonce: &str) -> String {
        let hash = self.password_hash.as_deref().unwrap_or("");
        sha256_hex(format!("{nonce}:{hash}").as_bytes())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Inner {
    fn sweep(&mut self) {
        self.nonces.retain(|_, at| at.elapsed() <= NONCE_TTL);

        self.failures
            .retain(|_, (_, at)| at.elapsed() <= Duration::from_secs(600));
    }

    fn failed_too_often(&self, from: &str) -> bool {
        match self.failures.get(from) {
            Some((n, at)) if *n > FAIL_BEFORE_DELAY => {
                let wait = Duration::from_secs((*n - FAIL_BEFORE_DELAY).min(30) as u64);
                at.elapsed() < wait
            }
            _ => false,
        }
    }

    fn record_failure(&mut self, from: &str) {
        let e = self
            .failures
            .entry(from.to_string())
            .or_insert((0, Instant::now()));
        e.0 = e.0.saturating_add(1);
        e.1 = Instant::now();
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn random_hex() -> String {
    let mut b = [0u8; 32];
    if getrandom::getrandom(&mut b).is_err() {
        return String::new();
    }
    hex::encode(b)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::new("admin")
    }

    fn client_proof(nonce: &str, password: &str) -> String {
        sha256_hex(format!("{nonce}:{}", sha256_hex(password.as_bytes())).as_bytes())
    }

    #[test]
    fn the_documented_proof_formula_is_what_the_server_expects() {
        let a = auth();
        let (nonce, _) = a.challenge();
        assert_eq!(a.expected_proof(&nonce), client_proof(&nonce, "admin"));
    }

    #[test]
    fn a_correct_login_yields_a_working_token() {
        let a = auth();
        let (nonce, ttl) = a.challenge();
        assert!(ttl > 0);
        let (token, _) = a
            .login(&nonce, &client_proof(&nonce, "admin"), "10.0.0.1")
            .unwrap();
        assert!(a.verify(&token));
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let a = auth();
        let (nonce, _) = a.challenge();
        assert_eq!(
            a.login(&nonce, &client_proof(&nonce, "wrong"), "10.0.0.1"),
            Err(LoginError::BadProof)
        );
    }

    #[test]
    fn a_nonce_is_consumed_even_by_a_failed_attempt() {
        let a = auth();
        let (nonce, _) = a.challenge();
        assert_eq!(
            a.login(&nonce, "deadbeef", "10.0.0.1"),
            Err(LoginError::BadProof)
        );
        assert_eq!(
            a.login(&nonce, &client_proof(&nonce, "admin"), "10.0.0.1"),
            Err(LoginError::BadNonce),
            "a spent nonce must not work even with the right password"
        );
    }

    #[test]
    fn a_nonce_cannot_be_reused_after_a_successful_login() {
        let a = auth();
        let (nonce, _) = a.challenge();
        let proof = client_proof(&nonce, "admin");
        assert!(a.login(&nonce, &proof, "10.0.0.1").is_ok());
        assert_eq!(
            a.login(&nonce, &proof, "10.0.0.1"),
            Err(LoginError::BadNonce),
            "replaying a captured proof must not work twice"
        );
    }

    #[test]
    fn an_unknown_nonce_is_rejected() {
        let a = auth();
        assert_eq!(
            a.login("never-issued", "whatever", "10.0.0.1"),
            Err(LoginError::BadNonce)
        );
    }

    #[test]
    fn an_unknown_token_is_not_accepted() {
        let a = auth();
        assert!(!a.verify("not-a-real-token"));
        assert!(!a.verify(""), "an empty token must never pass");
    }

    #[test]
    fn logout_invalidates_the_token() {
        let a = auth();
        let (nonce, _) = a.challenge();
        let (token, _) = a
            .login(&nonce, &client_proof(&nonce, "admin"), "1.1.1.1")
            .unwrap();
        a.logout(&token);
        assert!(!a.verify(&token));
    }

    #[test]
    fn an_empty_password_disables_authentication_entirely() {
        let a = Auth::new("");
        assert!(!a.required());
        assert!(a.verify(""), "no token at all must pass");
        assert!(a.verify("anything"));
    }
    #[test]
    fn a_configured_password_is_required() {
        let a = Auth::new("admin");
        assert!(a.required());
        assert!(!a.verify(""));
    }

    #[test]
    fn a_session_never_expires_on_its_own() {
        let a = auth();
        let (nonce, ttl) = a.challenge();
        let (token, session_ttl) = a
            .login(&nonce, &client_proof(&nonce, "admin"), "1.1.1.1")
            .unwrap();
        assert!(ttl > 0, "the one-shot challenge still expires");
        assert_eq!(session_ttl, 0, "0 is the agreed way to say \"never\"");

        for _ in 0..1000 {
            assert!(a.verify(&token));
        }
    }

    #[test]
    fn the_session_table_still_has_a_ceiling() {
        let a = auth();
        let mut tokens = Vec::new();
        for _ in 0..(MAX_SESSIONS + 5) {
            let (n, _) = a.challenge();
            let (t, _) = a.login(&n, &client_proof(&n, "admin"), "1.1.1.1").unwrap();
            tokens.push(t);
        }
        assert!(a.lock().sessions.len() <= MAX_SESSIONS);
        assert!(a.verify(tokens.last().unwrap()), "the newest must survive");
    }
    #[test]
    fn repeated_failures_from_one_source_get_throttled() {
        let a = auth();
        for _ in 0..=FAIL_BEFORE_DELAY {
            let (n, _) = a.challenge();
            let _ = a.login(&n, "bad", "10.0.0.99");
        }
        let (n, _) = a.challenge();
        assert_eq!(
            a.login(&n, &client_proof(&n, "admin"), "10.0.0.99"),
            Err(LoginError::TooManyAttempts),
            "a brute-force source must be slowed down"
        );
    }

    #[test]
    fn throttling_is_per_source_so_one_attacker_cannot_lock_everyone_out() {
        let a = auth();
        for _ in 0..=FAIL_BEFORE_DELAY + 2 {
            let (n, _) = a.challenge();
            let _ = a.login(&n, "bad", "10.0.0.99");
        }
        let (n, _) = a.challenge();
        assert!(
            a.login(&n, &client_proof(&n, "admin"), "10.0.0.1").is_ok(),
            "an unrelated address must still be able to log in"
        );
    }

    #[test]
    fn a_successful_login_clears_the_failure_count() {
        let a = auth();
        for _ in 0..FAIL_BEFORE_DELAY {
            let (n, _) = a.challenge();
            let _ = a.login(&n, "bad", "10.0.0.5");
        }
        let (n, _) = a.challenge();
        assert!(a.login(&n, &client_proof(&n, "admin"), "10.0.0.5").is_ok());

        let (n, _) = a.challenge();
        assert_eq!(a.login(&n, "bad", "10.0.0.5"), Err(LoginError::BadProof));
    }

    #[test]
    fn nonces_are_unique_and_unpredictable_in_shape() {
        let a = auth();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let (n, _) = a.challenge();
            assert_eq!(n.len(), 64, "32 random bytes as hex");
            assert!(seen.insert(n), "a repeated nonce would allow replay");
        }
    }

    #[test]
    fn issuing_many_challenges_does_not_grow_without_bound() {
        let a = auth();
        for _ in 0..(MAX_NONCES * 2) {
            a.challenge();
        }
        assert!(a.lock().nonces.len() <= MAX_NONCES);
    }

    #[test]
    fn constant_time_eq_is_still_correct() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn the_password_is_never_stored_in_the_clear() {
        let a = Auth::new("hunter2");
        let stored = a.password_hash.as_deref().unwrap();
        assert!(!stored.contains("hunter2"));
        assert_eq!(stored.len(), 64);
    }
}
