// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::time::Duration;

pub mod http;
mod providers;
mod sign;
mod smtp;

pub use http::{Client, HttpError};
pub use providers::{Built, Channel, EmailTls, NtfyAuth, Payload, build, check};

pub const DEFAULT_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Outcome {
    pub ok: bool,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,

    pub attempts: usize,

    pub status: u16,
    pub took_ms: u64,

    pub retryable: bool,
}

pub async fn deliver(client: &Client, ch: &Channel, p: &Payload, attempts: usize) -> Outcome {
    let started = std::time::Instant::now();
    let attempts = attempts.max(1);
    let mut last_error = String::new();
    let mut last_status = 0u16;

    let mut used = 0usize;

    let mut last_retryable = false;

    for attempt in 1..=attempts {
        used = attempt;
        let ok = |status: u16| Outcome {
            ok: true,
            error: String::new(),
            attempts: attempt,
            status,
            took_ms: started.elapsed().as_millis() as u64,
            retryable: false,
        };

        let Some(built) = providers::build(ch, p, now_ms()) else {
            match smtp::send(client, ch, p, now_ms()).await {
                Ok(()) => return ok(0),
                Err(e) => {
                    last_error = e.to_string();
                    last_retryable = e.retryable();
                    if !last_retryable || attempt == attempts {
                        break;
                    }
                    backoff(attempt).await;
                    continue;
                }
            }
        };

        let headers: Vec<(&str, String)> =
            built.headers.iter().map(|(k, v)| (*k, v.clone())).collect();

        let req = http::Request {
            method: built.method,
            url: &built.url,
            headers: &headers,
            body: Some(&built.body),
        };

        let (retryable, err) = match client.send(req).await {
            Ok(resp) => {
                last_status = resp.status;
                match providers::check(ch, &resp) {
                    Ok(()) => return ok(resp.status),
                    Err(e) => (is_retryable_status(resp.status), e),
                }
            }

            Err(e) => (!matches!(e, HttpError::BadUrl(_)), e.to_string()),
        };

        last_error = err;
        last_retryable = retryable;
        if !retryable || attempt == attempts {
            break;
        }
        backoff(attempt).await;
    }

    Outcome {
        ok: false,
        error: last_error,
        attempts: used,
        status: last_status,
        took_ms: started.elapsed().as_millis() as u64,
        retryable: last_retryable,
    }
}

async fn backoff(attempt: usize) {
    let base = 500u64 << (attempt - 1).min(4);
    tokio::time::sleep(Duration::from_millis(base + jitter_ms(base / 2))).await;
}

fn is_retryable_status(status: u16) -> bool {
    status == 0 || status == 429 || (500..600).contains(&status)
}

fn jitter_ms(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    u64::from_le_bytes(b) % max
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transient_failures_are_retried() {
        assert!(is_retryable_status(0), "no response at all is transient");
        assert!(is_retryable_status(429), "rate limiting is transient");
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));

        assert!(
            !is_retryable_status(400),
            "a malformed request will never succeed"
        );
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(403));
        assert!(!is_retryable_status(404));
        assert!(
            !is_retryable_status(200),
            "a 200 that failed the body check is a config error, not a transient one"
        );
    }

    #[test]
    fn jitter_stays_in_range() {
        for _ in 0..100 {
            assert!(jitter_ms(250) < 250);
        }
        assert_eq!(jitter_ms(0), 0, "no jitter must not divide by zero");
    }

    #[tokio::test]
    async fn a_bad_url_fails_immediately_without_retrying() {
        let client = Client::new(Duration::from_secs(2));
        let ch = Channel::Feishu {
            webhook: "open.feishu.cn/missing-scheme".into(),
            secret: String::new(),
        };
        let out = deliver(&client, &ch, &Payload::default(), 3).await;
        assert!(!out.ok);
        assert_eq!(out.attempts, 1, "a malformed URL must not be retried");
        assert!(out.error.contains("bad url"), "error was {}", out.error);
        assert!(
            !out.retryable,
            "a malformed URL must not be queued for later either"
        );
    }

    #[tokio::test]
    async fn a_connection_failure_is_reported_not_panicked() {
        let client = Client::new(Duration::from_millis(1500));
        let ch = Channel::Ntfy {
            server: "http://127.0.0.1:9".into(),
            topic: "t".into(),
            priority: 5,
            auth: NtfyAuth::None,
            tags: vec![],
        };
        let out = deliver(&client, &ch, &Payload::default(), 1).await;
        assert!(!out.ok);
        assert!(!out.error.is_empty());
        assert_eq!(out.status, 0);
        assert!(
            out.retryable,
            "a connection failure is exactly what the retry queue is for"
        );
    }
}
