// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use s2l_store::{NewMessage, Store, Target};
use tokio::sync::{broadcast, mpsc};

use crate::config::Settings;
use crate::log;
use crate::push;
use crate::state::{self, State, Vars};

const NOTIFY_LOG_CAP: usize = 200;

#[derive(Debug, Clone, serde::Serialize)]
pub struct NotifyLog {
    pub at: i64,
    pub rule: String,
    pub channel: String,
    pub kind: &'static str,
    pub subject: String,
    pub ok: bool,
    pub error: String,
    pub attempts: usize,
    pub took_ms: u64,
}

pub struct Pipeline {
    pub store: Arc<Store>,
    pub state: Arc<ArcSwap<State>>,

    pub settings: Arc<ArcSwap<Settings>>,
    pub client: s2l_notify::Client,
    pub events: Option<broadcast::Sender<String>>,

    push: push::Config,

    cooldowns: Mutex<HashMap<u32, Instant>>,
    notify_log: Mutex<std::collections::VecDeque<NotifyLog>>,

    base_url: String,
}

impl Pipeline {
    pub fn new(
        store: Arc<Store>,
        state: Arc<ArcSwap<State>>,
        settings: Arc<ArcSwap<Settings>>,
        client: s2l_notify::Client,
        events: Option<broadcast::Sender<String>>,
        base_url: String,
        push: push::Config,
    ) -> Self {
        Self {
            store,
            state,
            settings,
            client,
            events,
            push,
            cooldowns: Mutex::new(HashMap::new()),
            notify_log: Mutex::new(std::collections::VecDeque::new()),
            base_url,
        }
    }

    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<s2l_smtp::Delivered>) {
        while let Some(d) = rx.recv().await {
            let me = self.clone();

            let outcome = tokio::task::spawn_blocking(move || me.ingest(d)).await;
            match outcome {
                Ok(Some(job)) => {
                    let me = self.clone();

                    tokio::spawn(async move { me.notify(job).await });
                }
                Ok(None) => {}
                Err(e) => log::error(&format!("mail ingest task panicked: {e}")),
            }
        }
    }

    fn ingest(&self, d: s2l_smtp::Delivered) -> Option<NotifyJob> {
        self.ingest_from(d, String::new())
    }

    fn ingest_from(&self, d: s2l_smtp::Delivered, origin: String) -> Option<NotifyJob> {
        let state = self.state.load();
        let settings = self.settings.load();
        let mail = s2l_mail::parse_with(
            &d.data,
            s2l_mail::Options {
                keep_attachments: settings.keep_attachments,
            },
        );

        let from = if mail.from_addr().is_empty() {
            d.envelope_from.clone()
        } else {
            mail.from_addr().to_string()
        };
        let from_user = from
            .rsplit_once('@')
            .map(|(u, _)| u)
            .unwrap_or(&from)
            .to_string();
        let from_domain = from
            .rsplit_once('@')
            .map(|(_, x)| x)
            .unwrap_or("")
            .to_string();
        let from_name = mail
            .from
            .as_ref()
            .map(|a| a.name.clone())
            .unwrap_or_default();
        let peer_ip = d.peer.ip().to_string();
        let auth_user = d.auth_user.clone().unwrap_or_default();

        let target = Target {
            from: &from,
            from_user: &from_user,
            from_domain: &from_domain,
            from_name: &from_name,
            subject: &mail.subject,
            body: &mail.text,
            rcpt: &d.rcpt,
            peer_ip: &peer_ip,
            group: "",
            auth_user: &auth_user,
            headers: &mail.headers,
        };

        if !state.access.accepts(&target) {
            log::info(&format!(
                "rejected by the access list: from={from} subject={:?} peer={peer_ip}",
                mail.subject
            ));
            return None;
        }

        let group = state.classify(&target);
        let subject = mail.subject.clone();
        let text = mail.text.clone();

        let rec = match self.store.append(NewMessage {
            received_at: log::now_ms(),
            envelope_from: d.envelope_from.clone(),
            rcpt: d.rcpt.clone(),
            peer_ip: peer_ip.clone(),
            origin: origin.clone(),
            auth_user: auth_user.clone(),
            size: d.size,
            mail,
            group,
            raw: settings.keep_raw.then(|| d.data.clone()),
        }) {
            Ok(r) => r,
            Err(e) => {
                log::error(&format!("could not store the message: {e}"));
                return Some(NotifyJob {
                    id: 0,
                    subject,
                    from,
                    from_name,
                    from_user,
                    from_domain,
                    body: text,
                    peer: peer_ip,
                    group,
                    auth_user,
                    at: log::now_ms(),
                    push: None,
                });
            }
        };

        log::info(&format!(
            "stored #{} from={} subject={:?} {} bytes{}",
            rec.id,
            rec.from,
            rec.subject,
            rec.size,
            if d.tls { " (tls)" } else { "" }
        ));

        if let Some(tx) = &self.events {
            if let Ok(json) = serde_json::to_string(&rec) {
                let _ = tx.send(json);
            }
        }

        let push = (self.push.enabled() && origin.is_empty()).then(|| {
            use base64::Engine;
            push::Payload {
                hostname: self.push.hostname.clone(),
                ts: log::now_ms(),
                envelope_from: d.envelope_from.clone(),
                rcpt: d.rcpt.clone(),
                peer: peer_ip.clone(),
                raw_b64: base64::engine::general_purpose::STANDARD.encode(&d.data),
            }
        });
        Some(NotifyJob {
            id: rec.id,
            subject,
            from,
            from_name,
            from_user,
            from_domain,
            body: text,
            peer: peer_ip,
            group,
            auth_user,
            at: rec.ts,
            push,
        })
    }

    pub fn accept_push(&self, payload: push::Payload) -> Option<NotifyJob> {
        use base64::Engine;
        let Ok(data) = base64::engine::general_purpose::STANDARD.decode(&payload.raw_b64) else {
            log::warn("a pushed message had an undecodable body");
            return None;
        };

        let peer = payload
            .peer
            .parse()
            .map(|ip| std::net::SocketAddr::new(ip, 0))
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        let d = s2l_smtp::Delivered {
            envelope_from: payload.envelope_from,
            rcpt: payload.rcpt,
            peer,
            size: data.len(),
            data,
            tls: false,
            auth_user: None,
        };
        let host = if payload.hostname.trim().is_empty() {
            "unknown".to_string()
        } else {
            payload.hostname
        };
        self.ingest_from(d, host)
    }

    pub async fn notify_job(self: Arc<Self>, job: NotifyJob) {
        self.notify(job).await
    }
    async fn notify(self: Arc<Self>, job: NotifyJob) {
        if let Some(payload) = &job.push {
            match push::send(&self.client, &self.push.url, &self.push.pass, payload).await {
                Ok(()) => log::debug(&format!("pushed #{} to {}", job.id, self.push.url)),
                Err(e) => log::warn(&format!(
                    "could not push #{} to {}: {e}",
                    job.id, self.push.url
                )),
            }
        }
        let state = self.state.load_full();
        let group_name = state.group_name(job.group);

        let group_id = job.group.map(|g| g.to_string()).unwrap_or_default();
        let time = log::fmt_local(job.at);
        let vars = Vars {
            subject: &job.subject,
            from: &job.from,
            from_name: &job.from_name,
            from_user: &job.from_user,
            from_domain: &job.from_domain,
            body: &job.body,
            time: &time,
            group: &group_name,
            peer: &job.peer,
        };
        let target = Target {
            from: &job.from,
            from_user: &job.from_user,
            from_domain: &job.from_domain,
            from_name: &job.from_name,
            subject: &job.subject,
            body: &job.body,
            rcpt: &[],
            peer_ip: &job.peer,
            group: &group_id,
            auth_user: &job.auth_user,
            headers: &[],
        };

        let url = (job.id != 0 && !self.base_url.is_empty())
            .then(|| format!("{}/#/?id={}", self.base_url, job.id));

        for rule in state.rules.iter().filter(|r| r.enabled) {
            if !rule.matcher.matches(&target) {
                continue;
            }
            if !self.take_cooldown(rule.id, rule.cooldown) {
                log::debug(&format!(
                    "rule {:?} is within its {}s cooldown, skipping",
                    rule.name, rule.cooldown
                ));
                continue;
            }

            let payload = s2l_notify::Payload {
                title: state::render(&rule.title, &vars),
                body: state::render(&rule.body, &vars),
                url: url.clone(),
            };

            for cid in &rule.channels {
                let Some(cfg) = state.channel(*cid) else {
                    log::warn(&format!(
                        "rule {:?} points at channel {cid}, which no longer exists",
                        rule.name
                    ));
                    continue;
                };
                if !cfg.enabled {
                    continue;
                }
                let outcome = s2l_notify::deliver(
                    &self.client,
                    &cfg.channel,
                    &payload,
                    s2l_notify::DEFAULT_ATTEMPTS,
                )
                .await;

                if outcome.ok {
                    log::info(&format!(
                        "notified {:?} via {} ({} ms)",
                        cfg.name,
                        cfg.channel.kind(),
                        outcome.took_ms
                    ));
                } else {
                    log::warn(&format!(
                        "notification to {:?} via {} failed after {} attempt(s): {}",
                        cfg.name,
                        cfg.channel.kind(),
                        outcome.attempts,
                        outcome.error
                    ));
                }
                self.record(NotifyLog {
                    at: log::now_ms(),
                    rule: rule.name.clone(),
                    channel: cfg.name.clone(),
                    kind: cfg.channel.kind(),
                    subject: job.subject.clone(),
                    ok: outcome.ok,
                    error: outcome.error,
                    attempts: outcome.attempts,
                    took_ms: outcome.took_ms,
                });
            }
        }
    }

    fn take_cooldown(&self, rule_id: u32, cooldown_secs: u32) -> bool {
        if cooldown_secs == 0 {
            return true;
        }
        let window = Duration::from_secs(u64::from(cooldown_secs));
        let mut map = self.cooldowns.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&rule_id) {
            Some(last) if last.elapsed() < window => false,
            _ => {
                map.insert(rule_id, Instant::now());
                true
            }
        }
    }

    fn record(&self, entry: NotifyLog) {
        let mut log = self.notify_log.lock().unwrap_or_else(|e| e.into_inner());
        if log.len() >= NOTIFY_LOG_CAP {
            log.pop_front();
        }
        log.push_back(entry);
    }

    pub fn notify_log(&self) -> Vec<NotifyLog> {
        let log = self.notify_log.lock().unwrap_or_else(|e| e.into_inner());
        log.iter().rev().cloned().collect()
    }

    pub async fn test_channel(&self, ch: &s2l_notify::Channel) -> s2l_notify::Outcome {
        let payload = s2l_notify::Payload {
            title: "stmp2log test".into(),
            body: format!(
                "This is a test notification from stmp2log at {}.",
                log::fmt_local(log::now_ms())
            ),
            url: (!self.base_url.is_empty()).then(|| format!("{}/", self.base_url)),
        };
        s2l_notify::deliver(&self.client, ch, &payload, 1).await
    }
}

pub struct NotifyJob {
    pub id: u64,
    pub subject: String,
    pub from: String,
    pub from_name: String,
    pub from_user: String,
    pub from_domain: String,
    pub body: String,
    pub peer: String,
    pub group: Option<u32>,
    pub auth_user: String,
    pub at: i64,

    pub push: Option<push::Payload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "s2l-pipe-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn pipeline(dir: &std::path::Path, state: State) -> Arc<Pipeline> {
        pipeline_with(dir, state, Settings::default_for_test())
    }
    fn pipeline_with(dir: &std::path::Path, state: State, settings: Settings) -> Arc<Pipeline> {
        let store = Arc::new(Store::open(dir, settings.retention()).unwrap());
        Arc::new(Pipeline::new(
            store,
            Arc::new(ArcSwap::from_pointee(state)),
            Arc::new(ArcSwap::from_pointee(settings)),
            s2l_notify::Client::new(Duration::from_secs(1)),
            None,
            String::new(),
            push::Config::default(),
        ))
    }

    fn delivered(from: &str, raw: &str) -> s2l_smtp::Delivered {
        s2l_smtp::Delivered {
            envelope_from: from.into(),
            rcpt: vec!["log@stmp2log".into()],
            peer: "10.20.0.7:5000".parse().unwrap(),
            size: raw.len(),
            data: raw.as_bytes().to_vec(),
            tls: false,
            auth_user: None,
        }
    }

    #[test]
    fn a_message_is_parsed_grouped_and_stored() {
        let dir = tmpdir("ingest");
        let mut state = State::default();
        state.groups.push(crate::state::Group {
            id: 5,
            name: "UPS".into(),
            color: String::new(),
            enabled: true,
            matcher: s2l_store::Matcher {
                logic: s2l_store::Logic::All,
                conditions: vec![s2l_store::Condition {
                    field: s2l_store::Field::FromUser,
                    op: s2l_store::Op::StartsWith,
                    value: "ups-".into(),
                    case_sensitive: false,
                }],
            },
        });
        let p = pipeline(&dir, state);

        let job = p.ingest(delivered(
            "ups-01@idc.local",
            "From: ups-01@idc.local\r\nSubject: =?UTF-8?B?5rip5bqm5ZGK6K2m?=\r\n\r\n48C\r\n",
        ));
        let job = job.expect("an accepted message produces a notify job");
        assert_eq!(
            job.subject, "温度告警",
            "the encoded-word subject must be decoded"
        );
        assert_eq!(job.group, Some(5));

        let page = p.store.query(&s2l_store::Query::default()).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].group, Some(5));
        assert_eq!(page.items[0].peer, "10.20.0.7");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_blacklisted_sender_is_dropped_before_storage() {
        let dir = tmpdir("blacklist");
        let mut state = State::default();
        state.access = crate::state::Access {
            mode: crate::state::AccessMode::Blacklist,
            matcher: s2l_store::Matcher {
                logic: s2l_store::Logic::All,
                conditions: vec![s2l_store::Condition {
                    field: s2l_store::Field::FromDomain,
                    op: s2l_store::Op::Equals,
                    value: "spam.local".into(),
                    case_sensitive: false,
                }],
            },
        };
        let p = pipeline(&dir, state);

        assert!(
            p.ingest(delivered("x@spam.local", "From: x@spam.local\r\n\r\nhi"))
                .is_none()
        );
        assert_eq!(p.store.len(), 0);

        assert!(
            p.ingest(delivered("x@ok.local", "From: x@ok.local\r\n\r\nhi"))
                .is_some()
        );
        assert_eq!(p.store.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_access_list_can_match_on_subject_keywords() {
        let dir = tmpdir("subjacl");
        let mut state = State::default();
        state.access = crate::state::Access {
            mode: crate::state::AccessMode::Blacklist,
            matcher: s2l_store::Matcher {
                logic: s2l_store::Logic::All,
                conditions: vec![s2l_store::Condition {
                    field: s2l_store::Field::Subject,
                    op: s2l_store::Op::Contains,
                    value: "test mail".into(),
                    case_sensitive: false,
                }],
            },
        };
        let p = pipeline(&dir, state);
        assert!(
            p.ingest(delivered("a@b.c", "Subject: Test Mail\r\n\r\nignore me"))
                .is_none()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_from_header_falls_back_to_the_envelope_for_grouping() {
        let dir = tmpdir("envgroup");
        let mut state = State::default();
        state.groups.push(crate::state::Group {
            id: 9,
            name: "NAS".into(),
            color: String::new(),
            enabled: true,
            matcher: s2l_store::Matcher {
                logic: s2l_store::Logic::All,
                conditions: vec![s2l_store::Condition {
                    field: s2l_store::Field::FromDomain,
                    op: s2l_store::Op::Equals,
                    value: "nas.local".into(),
                    case_sensitive: false,
                }],
            },
        });
        let p = pipeline(&dir, state);

        let job = p.ingest(delivered(
            "device@nas.local",
            "Subject: no from header\r\n\r\nbody",
        ));
        assert_eq!(job.unwrap().group, Some(9));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cooldown_lets_the_first_through_and_holds_the_rest() {
        let dir = tmpdir("cooldown");
        let p = pipeline(&dir, State::default());
        assert!(p.take_cooldown(1, 60));
        assert!(!p.take_cooldown(1, 60));
        assert!(!p.take_cooldown(1, 60));

        assert!(p.take_cooldown(2, 60));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_zero_cooldown_never_throttles() {
        let dir = tmpdir("nocooldown");
        let p = pipeline(&dir, State::default());
        for _ in 0..5 {
            assert!(p.take_cooldown(1, 0));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_notification_log_is_bounded_and_newest_first() {
        let dir = tmpdir("notifylog");
        let p = pipeline(&dir, State::default());
        for i in 0..(NOTIFY_LOG_CAP + 20) {
            p.record(NotifyLog {
                at: i as i64,
                rule: format!("r{i}"),
                channel: "c".into(),
                kind: "ntfy",
                subject: String::new(),
                ok: true,
                error: String::new(),
                attempts: 1,
                took_ms: 0,
            });
        }
        let log = p.notify_log();
        assert_eq!(log.len(), NOTIFY_LOG_CAP);
        assert_eq!(
            log[0].rule,
            format!("r{}", NOTIFY_LOG_CAP + 19),
            "newest first"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gbk_alerts_survive_the_whole_pipeline() {
        let dir = tmpdir("gbk");
        let p = pipeline(&dir, State::default());
        let mut raw = Vec::new();
        raw.extend_from_slice(b"From: ups@idc.local\r\n");
        raw.extend_from_slice(b"Subject: =?GB2312?B?zsK2yLjmvq8=?=\r\n");
        raw.extend_from_slice(b"Content-Type: text/plain; charset=GB2312\r\n\r\n");
        raw.extend_from_slice(&[0xCE, 0xC2, 0xB6, 0xC8, 0xB9, 0xFD, 0xB8, 0xDF]);

        let mut d = delivered("ups@idc.local", "");
        d.size = raw.len();
        d.data = raw;
        p.ingest(d).unwrap();

        let page = p
            .store
            .query(&s2l_store::Query {
                subject: Some("温度".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.total, 1, "a GBK subject must be searchable as Chinese");
        assert_eq!(page.items[0].subject, "温度告警");
        assert_eq!(page.items[0].preview, "温度过高");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn raw_source_is_stored_only_when_the_setting_is_on() {
        let dir = tmpdir("keepraw");
        let p = pipeline_with(
            &dir,
            State::default(),
            Settings {
                keep_raw: true,
                ..Settings::default_for_test()
            },
        );
        p.ingest(delivered("a@b.c", "Subject: x\r\n\r\nbody"))
            .unwrap();
        assert!(p.store.get(1).unwrap().unwrap().body.raw_b64.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }
}
