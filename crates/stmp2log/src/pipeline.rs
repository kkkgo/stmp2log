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
use crate::retry::{self, Item, Pending, QueuedNotify, QueuedPush};
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<Retry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retry {
    Queued,

    Resent,

    Dropped,
}

pub struct Pipeline {
    pub store: Arc<Store>,
    pub state: Arc<ArcSwap<State>>,

    pub settings: Arc<ArcSwap<Settings>>,
    pub client: s2l_notify::Client,
    pub events: Option<broadcast::Sender<String>>,

    push_pass: String,

    cooldowns: Mutex<HashMap<u32, Instant>>,
    notify_log: Mutex<std::collections::VecDeque<NotifyLog>>,

    retry: retry::Queue,

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
        push_pass: String,
    ) -> Self {
        Self {
            store,
            state,
            settings,
            client,
            events,
            push_pass,
            cooldowns: Mutex::new(HashMap::new()),
            notify_log: Mutex::new(std::collections::VecDeque::new()),
            retry: retry::Queue::default(),
            base_url,
        }
    }

    fn push_url(&self) -> String {
        self.settings.load().push_url.clone()
    }

    fn link_base(&self) -> String {
        let configured = &self.settings.load().web_url;
        if configured.is_empty() {
            return self.base_url.clone();
        }
        crate::config::external_base(configured)
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

        let push = (!settings.push_url.is_empty() && origin.is_empty()).then(|| {
            use base64::Engine;
            push::Payload {
                hostname: settings.stmp_hostname.clone(),
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
    async fn notify(self: Arc<Self>, mut job: NotifyJob) {
        if let Some(payload) = job.push.take() {
            self.forward(&job, payload).await;
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

        let base = self.link_base();
        let url = (job.id != 0 && !base.is_empty()).then(|| format!("{base}/#/?id={}", job.id));

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

                let aimed = rule.with_recipients(&cfg.channel);
                let outcome = s2l_notify::deliver(
                    &self.client,
                    aimed.as_ref(),
                    &payload,
                    s2l_notify::DEFAULT_ATTEMPTS,
                )
                .await;

                let mut mark = None;
                if outcome.ok {
                    log::info(&format!(
                        "notified {:?} via {} ({} ms)",
                        cfg.name,
                        cfg.channel.kind(),
                        outcome.took_ms
                    ));

                    self.retry.recovered();
                } else {
                    log::warn(&format!(
                        "notification to {:?} via {} failed after {} attempt(s): {}",
                        cfg.name,
                        cfg.channel.kind(),
                        outcome.attempts,
                        outcome.error
                    ));

                    if outcome.retryable {
                        mark = Some(Retry::Queued);
                        self.enqueue(
                            Item::Notify(QueuedNotify {
                                channel: cfg.id,
                                channel_name: cfg.name.clone(),
                                kind: cfg.channel.kind(),
                                rule: rule.name.clone(),
                                subject: job.subject.clone(),
                                payload: payload.clone(),

                                email_to: rule.email_to.clone(),
                            }),
                            job.at,
                            outcome.attempts,
                            outcome.error.clone(),
                        );
                    }
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
                    retry: mark,
                });
            }
        }
    }

    async fn forward(&self, job: &NotifyJob, payload: push::Payload) {
        let started = Instant::now();
        let url = self.push_url();
        let err = match push::send(&self.client, &url, &self.push_pass, &payload).await {
            Ok(()) => {
                log::debug(&format!("pushed #{} to {url}", job.id));
                self.retry.recovered();

                return;
            }
            Err(e) => e,
        };
        log::warn(&format!("could not push #{} to {url}: {err}", job.id));

        let item = Item::Push(QueuedPush {
            id: job.id,
            subject: job.subject.clone(),
            payload,
        });
        let mark = if err.retryable() {
            self.enqueue(item, job.at, 1, err.to_string());
            Retry::Queued
        } else {
            Retry::Dropped
        };
        self.record(NotifyLog {
            at: log::now_ms(),
            rule: String::new(),
            channel: self.push_label(),
            kind: "push",
            subject: job.subject.clone(),
            ok: false,
            error: err.to_string(),
            attempts: 1,
            took_ms: started.elapsed().as_millis() as u64,
            retry: Some(mark),
        });
    }

    fn push_label(&self) -> String {
        let url = self.push_url();
        let host = url
            .rsplit("://")
            .next()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        if host.is_empty() {
            "push".into()
        } else {
            host.to_string()
        }
    }

    fn enqueue(&self, item: Item, at: i64, attempts: usize, error: String) {
        let max = self.settings.load().retry_queue;
        let what = item.describe();
        let evicted = self.retry.push(item, at, attempts, error, max);
        log::debug(&format!(
            "queued {what} for retry, {} waiting",
            self.retry.len()
        ));
        for p in evicted {
            log::warn(&format!(
                "the retry queue is full ({max}), dropped {}: {}",
                p.item.describe(),
                p.error
            ));
            self.record(self.log_of(&p, false, p.error.clone(), 0, Retry::Dropped));
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

    pub fn retry_status(&self) -> retry::Status {
        self.retry.status(self.settings.load().retry_queue)
    }

    pub fn retry_now(&self) {
        self.retry.kick();
    }

    pub fn trim_retry(&self, max: usize) {
        for p in self.retry.trim(max) {
            log::warn(&format!(
                "the retry queue limit is now {max}, dropped {}: {}",
                p.item.describe(),
                p.error
            ));
            self.record(self.log_of(&p, false, p.error.clone(), 0, Retry::Dropped));
        }
    }

    pub async fn run_retry(self: Arc<Self>) {
        let mut delay = retry::FIRST_DELAY;
        loop {
            if self.retry.is_empty() {
                self.retry.wait_for_work().await;
                delay = retry::FIRST_DELAY;
            }
            self.retry.wait_backoff(delay).await;
            let pass = self.flush().await;

            delay = if pass.stalled && pass.sent == 0 {
                retry::next_delay(delay)
            } else {
                retry::FIRST_DELAY
            };
        }
    }

    async fn flush(&self) -> Pass {
        let mut sent = 0usize;
        while let Some(mut p) = self.retry.pop() {
            p.attempts += 1;
            match self.send_queued(&mut p).await {
                Ok(took_ms) => {
                    sent += 1;
                    log::info(&format!(
                        "re-sent {}, {}s after the alert ({} attempt(s))",
                        p.item.describe(),
                        (log::now_ms() - p.at).max(0) / 1000,
                        p.attempts
                    ));
                    self.record(self.log_of(&p, true, String::new(), took_ms, Retry::Resent));
                }
                Err(Verdict::Later(e)) => {
                    p.error = e;
                    log::debug(&format!(
                        "{} is still failing ({}), leaving it in the queue",
                        p.item.describe(),
                        p.error
                    ));
                    self.retry.requeue(p);

                    return Pass {
                        sent,
                        stalled: true,
                    };
                }
                Err(Verdict::GiveUp(e)) => {
                    log::warn(&format!("giving up on {}: {e}", p.item.describe()));
                    self.record(self.log_of(&p, false, e, 0, Retry::Dropped));
                }
            }
        }
        Pass {
            sent,
            stalled: false,
        }
    }

    async fn send_queued(&self, p: &mut Pending) -> Result<u64, Verdict> {
        match &mut p.item {
            Item::Notify(n) => {
                let (mut ch, name) = {
                    let state = self.state.load_full();
                    let Some(cfg) = state.channel(n.channel) else {
                        return Err(Verdict::GiveUp("the channel was deleted".into()));
                    };
                    if !cfg.enabled {
                        return Err(Verdict::GiveUp("the channel was disabled".into()));
                    }
                    (cfg.channel.clone(), cfg.name.clone())
                };

                state::apply_recipients(&mut ch, &n.email_to);
                n.channel_name = name;
                n.kind = ch.kind();

                let out = s2l_notify::deliver(&self.client, &ch, &n.payload, 1).await;
                if out.ok {
                    return Ok(out.took_ms);
                }
                Err(if out.retryable {
                    Verdict::Later(out.error)
                } else {
                    Verdict::GiveUp(out.error)
                })
            }
            Item::Push(q) => {
                let started = Instant::now();
                let r = push::resend(
                    &self.client,
                    &self.push_url(),
                    &self.push_pass,
                    &mut q.payload,
                    log::now_ms(),
                )
                .await;
                match r {
                    Ok(()) => Ok(started.elapsed().as_millis() as u64),
                    Err(e) if e.retryable() => Err(Verdict::Later(e.to_string())),
                    Err(e) => Err(Verdict::GiveUp(e.to_string())),
                }
            }
        }
    }

    fn log_of(&self, p: &Pending, ok: bool, error: String, took_ms: u64, mark: Retry) -> NotifyLog {
        NotifyLog {
            at: log::now_ms(),
            rule: p.item.rule(),
            channel: match &p.item {
                Item::Notify(n) => n.channel_name.clone(),
                Item::Push(_) => self.push_label(),
            },
            kind: p.item.kind(),
            subject: p.item.subject().to_string(),
            ok,
            error,
            attempts: p.attempts,
            took_ms,
            retry: Some(mark),
        }
    }

    pub async fn test_channel(&self, ch: &s2l_notify::Channel) -> s2l_notify::Outcome {
        let payload = s2l_notify::Payload {
            title: "stmp2log test".into(),
            body: format!(
                "This is a test notification from stmp2log at {}.",
                log::fmt_local(log::now_ms())
            ),

            url: None,
        };
        let outcome = s2l_notify::deliver(&self.client, ch, &payload, 1).await;

        if outcome.ok {
            log::info(&format!(
                "test notification to the {} channel went through in {} ms",
                ch.kind(),
                outcome.took_ms
            ));
        } else {
            log::warn(&format!(
                "test notification to the {} channel failed after {} ms: {}",
                ch.kind(),
                outcome.took_ms,
                outcome.error
            ));
        }
        outcome
    }
}

struct Pass {
    sent: usize,

    stalled: bool,
}

enum Verdict {
    Later(String),

    GiveUp(String),
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
        pipeline_full(dir, state, settings, String::new())
    }
    fn pipeline_full(
        dir: &std::path::Path,
        state: State,
        settings: Settings,
        auto: String,
    ) -> Arc<Pipeline> {
        let store = Arc::new(Store::open(dir, settings.retention()).unwrap());
        Arc::new(Pipeline::new(
            store,
            Arc::new(ArcSwap::from_pointee(state)),
            Arc::new(ArcSwap::from_pointee(settings)),
            s2l_notify::Client::new(Duration::from_secs(1)),
            None,
            auto,
            String::new(),
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
                retry: None,
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

    fn unreachable_channel(id: u32) -> crate::state::ChannelCfg {
        crate::state::ChannelCfg {
            id,
            name: "phone".into(),
            enabled: true,
            channel: s2l_notify::Channel::Ntfy {
                server: "http://127.0.0.1:9".into(),
                topic: "alerts".into(),
                priority: 5,
                auth: s2l_notify::NtfyAuth::None,
                tags: vec![],
            },
        }
    }

    fn notify_everything(channel: u32) -> crate::state::NotifyRule {
        crate::state::NotifyRule {
            id: 1,
            name: "all".into(),
            enabled: true,
            matcher: s2l_store::Matcher::default(),
            channels: vec![channel],
            title: "{{subject}}".into(),
            body: "{{body}}".into(),
            cooldown: 0,
            email_to: vec![],
        }
    }

    fn queued_notify(channel: u32) -> Item {
        Item::Notify(QueuedNotify {
            channel,
            channel_name: "phone".into(),
            kind: "ntfy",
            rule: "all".into(),
            subject: "temperature".into(),
            payload: s2l_notify::Payload::default(),
            email_to: vec![],
        })
    }

    #[tokio::test]
    async fn a_notification_that_cannot_go_out_now_waits_for_the_network() {
        let dir = tmpdir("retry-queue");
        let mut state = State::default();
        state.channels.push(unreachable_channel(7));
        state.rules.push(notify_everything(7));
        let p = pipeline(&dir, state);

        let job = p
            .ingest(delivered("ups@idc.local", "Subject: hot\r\n\r\n48C"))
            .unwrap();
        p.clone().notify_job(job).await;

        let s = p.retry_status();
        assert_eq!(
            s.pending, 1,
            "a connection failure must not be the end of it"
        );
        assert_eq!(s.notify, 1);
        assert_eq!(s.max, 0, "the default is no limit at all");

        let log = p.notify_log();
        assert_eq!(
            log[0].retry,
            Some(Retry::Queued),
            "the history must say it is still coming, not just 'failed'"
        );
        assert!(!log[0].ok);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_misconfigured_channel_is_never_queued() {
        let dir = tmpdir("retry-badurl");
        let mut state = State::default();
        let mut ch = unreachable_channel(7);
        ch.channel = s2l_notify::Channel::Feishu {
            webhook: "open.feishu.cn/missing-scheme".into(),
            secret: String::new(),
        };
        state.channels.push(ch);
        state.rules.push(notify_everything(7));
        let p = pipeline(&dir, state);

        let job = p
            .ingest(delivered("a@b.c", "Subject: x\r\n\r\nbody"))
            .unwrap();
        p.clone().notify_job(job).await;

        assert_eq!(p.retry_status().pending, 0);
        assert_eq!(p.notify_log()[0].retry, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_alert_dropped_by_a_full_queue_still_leaves_a_record() {
        let dir = tmpdir("retry-full");
        let p = pipeline_with(
            &dir,
            State::default(),
            Settings {
                retry_queue: 1,
                ..Settings::default_for_test()
            },
        );
        p.enqueue(queued_notify(7), 1_000, 3, "no route to host".into());
        p.enqueue(queued_notify(7), 2_000, 3, "no route to host".into());

        let s = p.retry_status();
        assert_eq!(s.pending, 1, "the newest one stays");
        assert_eq!(s.dropped, 1);
        assert_eq!(p.notify_log()[0].retry, Some(Retry::Dropped));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_queued_entry_whose_channel_is_gone_does_not_block_the_rest() {
        let dir = tmpdir("retry-gone");
        let p = pipeline(&dir, State::default());
        p.enqueue(queued_notify(99), 1_000, 3, "no route to host".into());

        let pass = p.flush().await;
        assert_eq!(pass.sent, 0);
        assert!(!pass.stalled, "a deleted channel is not a network problem");
        assert_eq!(p.retry_status().pending, 0);

        let log = p.notify_log();
        assert_eq!(log[0].retry, Some(Retry::Dropped));
        assert!(log[0].error.contains("deleted"), "error: {}", log[0].error);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_channel_that_is_still_down_keeps_its_place_in_the_queue() {
        let dir = tmpdir("retry-stall");
        let mut state = State::default();
        state.channels.push(unreachable_channel(7));
        let p = pipeline(&dir, state);
        p.enqueue(queued_notify(7), 1_000, 3, "no route to host".into());

        let pass = p.flush().await;
        assert!(pass.stalled);
        assert_eq!(p.retry_status().pending, 1);

        let left = p.retry.pop().expect("it must still be queued");
        assert_eq!(
            left.attempts, 4,
            "the count has to keep going up across retries: the history says \
             how many times we really tried"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    async fn fake_smtp() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut rcpt = Vec::new();
            w.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let up = line.trim_end().to_ascii_uppercase();
                if let Some(a) = up
                    .strip_prefix("RCPT TO:<")
                    .and_then(|a| a.strip_suffix('>'))
                {
                    rcpt.push(a.to_ascii_lowercase());
                }
                if up.starts_with("EHLO") {
                    w.write_all(b"250-fake\r\n250 8BITMIME\r\n").await.unwrap();
                } else if up == "DATA" {
                    w.write_all(b"354 go ahead\r\n").await.unwrap();
                    loop {
                        let mut l = String::new();
                        if r.read_line(&mut l).await.unwrap() == 0 || l == ".\r\n" {
                            break;
                        }
                    }
                    w.write_all(b"250 queued\r\n").await.unwrap();
                } else if up == "QUIT" {
                    w.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    w.write_all(b"250 ok\r\n").await.unwrap();
                }
            }
            rcpt
        });
        (port, handle)
    }

    fn mailbox_channel(id: u32, port: u16) -> crate::state::ChannelCfg {
        crate::state::ChannelCfg {
            id,
            name: "值班邮箱".into(),
            enabled: true,
            channel: s2l_notify::Channel::Email {
                server: "127.0.0.1".into(),
                port,
                encryption: s2l_notify::EmailTls::None,
                username: String::new(),
                password: String::new(),
                from: "alerts@idc.local".into(),
                to: vec!["default@example.com".into()],
                skip_verify: false,
                mask_urls: true,
            },
        }
    }

    #[tokio::test]
    async fn a_queued_email_still_goes_to_the_people_the_rule_named() {
        let dir = tmpdir("retry-rcpt");
        let (port, server) = fake_smtp().await;
        let mut state = State::default();
        state.channels.push(mailbox_channel(7, port));
        let p = pipeline(&dir, state);

        p.enqueue(
            Item::Notify(QueuedNotify {
                channel: 7,
                channel_name: "值班邮箱".into(),
                kind: "email",
                rule: "UPS".into(),
                subject: "battery low".into(),
                payload: s2l_notify::Payload::default(),
                email_to: vec!["boss@example.com".into()],
            }),
            1_000,
            1,
            "connection refused".into(),
        );

        let pass = p.flush().await;
        assert_eq!(pass.sent, 1, "the mailbox is up now");
        assert_eq!(
            server.await.unwrap(),
            ["boss@example.com"],
            "the rule's recipients must survive the trip through the queue"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_notification_link_follows_the_address_set_in_the_web_ui() {
        let auto = "http://10.0.0.2:8025/stmp2log";
        let d1 = tmpdir("link-auto");
        let p = pipeline_full(
            &d1,
            State::default(),
            Settings::default_for_test(),
            auto.into(),
        );
        assert_eq!(
            p.link_base(),
            auto,
            "nothing filled in: keep the address we found ourselves"
        );

        let d2 = tmpdir("link-set");
        let p = pipeline_full(
            &d2,
            State::default(),
            Settings {
                web_url: "nas.lan:8025/s2l".into(),
                ..Settings::default_for_test()
            },
            auto.into(),
        );
        assert_eq!(
            p.link_base(),
            "http://nas.lan:8025/s2l",
            "what the user typed beats what we guessed, path and all"
        );
        std::fs::remove_dir_all(&d1).ok();
        std::fs::remove_dir_all(&d2).ok();
    }

    #[test]
    fn the_push_target_follows_the_settings_without_a_restart() {
        let dir = tmpdir("push-live");
        let p = pipeline_with(
            &dir,
            State::default(),
            Settings {
                push_url: "http://up.example.com:8025/stmp2log".into(),
                ..Settings::default_for_test()
            },
        );
        assert_eq!(p.push_label(), "up.example.com:8025");

        p.settings.store(Arc::new(Settings {
            push_url: "http://other.example.com/s".into(),
            ..Settings::default_for_test()
        }));
        assert_eq!(
            p.push_url(),
            "http://other.example.com/s",
            "changing it in the web UI must not need a restart"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lowering_the_limit_drops_the_oldest_right_away() {
        let dir = tmpdir("retry-trim");
        let p = pipeline(&dir, State::default());
        for i in 0..5 {
            p.enqueue(queued_notify(7), i, 1, "timed out".into());
        }
        p.trim_retry(2);
        assert_eq!(p.retry_status().pending, 2);
        assert_eq!(p.retry_status().dropped, 3);
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
