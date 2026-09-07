// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::sync::Arc;

use arc_swap::ArcSwap;
use s2l_store::{GroupFilter, Query, Sort, Store};
use s2l_web::{Api, ApiFuture, ApiReq, Reply, respond};

use crate::config::{self, Settings};
use crate::log;
use crate::pipeline::Pipeline;
use crate::push;
use crate::state::{Access, ChannelCfg, Group, NotifyRule, State};

#[derive(Clone)]
pub struct Handler {
    pub store: Arc<Store>,
    pub state: Arc<ArcSwap<State>>,

    pub settings: Arc<ArcSwap<Settings>>,
    pub pipeline: Arc<Pipeline>,
    pub auth: Arc<ArcSwap<s2l_web::Auth>>,
    pub data_dir: std::path::PathBuf,

    pub config_path: std::path::PathBuf,

    pub push_pass: String,
    pub version: &'static str,
    pub started_at: i64,
}

impl Api for Handler {
    fn call(&self, req: ApiReq) -> ApiFuture {
        let me = self.clone();
        Box::pin(async move { me.route(req).await })
    }
}

impl Handler {
    async fn route(self, req: ApiReq) -> Reply {
        let segs = req.segments();
        let m = req.method.as_str();

        match (m, segs.as_slice()) {
            ("GET", ["auth", "challenge"]) => {
                let auth = self.auth.load();

                if !auth.required() {
                    return respond::ok(&serde_json::json!({ "required": false }));
                }
                let (nonce, ttl) = auth.challenge();
                respond::ok(&serde_json::json!({
                    "required": true, "nonce": nonce, "ttl": ttl
                }))
            }
            ("POST", ["auth", "login"]) => self.login(&req),
            ("POST", ["auth", "logout"]) => {
                self.auth.load().logout(&req.token);
                respond::ok(&serde_json::json!({ "ok": true }))
            }

            ("GET", ["info"]) => respond::ok(&serde_json::json!({
                "version": self.version,
                "started_at": self.started_at,
                "now": log::now_ms(),
                "messages": self.store.len(),
            })),

            ("GET", ["messages"]) => self.list(&req).await,
            ("DELETE", ["messages"]) => self.bulk_delete(&req).await,
            ("GET", ["messages", id]) => self.get_one(id).await,
            ("DELETE", ["messages", id]) => self.delete_one(id).await,
            ("GET", ["messages", id, "raw"]) => self.raw(id).await,
            ("GET", ["messages", id, "attachments", index]) => self.attachment(id, index).await,
            ("PUT", ["messages", id, "group"]) => self.set_group(id, &req).await,

            ("GET", ["stats"]) => {
                let store = self.store.clone();
                let stats = blocking(move || store.stats(log::now_ms())).await;
                match stats {
                    Ok(s) => respond::ok(&serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => respond::error(500, &e),
                }
            }

            ("GET", ["settings"]) => respond::ok(&json_of(&**self.settings.load())),
            ("PUT", ["settings"]) => self.put_settings(&req).await,

            ("GET", ["groups"]) => respond::ok(&json_of(&self.state.load().groups)),
            ("POST", ["groups"]) => self.add_group(&req),

            ("PUT", ["groups", "order"]) => self.reorder_groups(&req),
            ("PUT", ["groups", id]) => self.update_group(id, &req),
            ("DELETE", ["groups", id]) => self.delete_group(id),

            ("GET", ["access"]) => respond::ok(&json_of(&self.state.load().access)),
            ("PUT", ["access"]) => self.put_access(&req),

            ("GET", ["channels"]) => respond::ok(&json_of(&self.state.load().channels)),
            ("POST", ["channels"]) => self.add_channel(&req),
            ("PUT", ["channels", id]) => self.update_channel(id, &req),
            ("DELETE", ["channels", id]) => self.delete_channel(id),
            ("POST", ["channels", id, "test"]) => self.test_channel(id).await,
            ("POST", ["channels", "test"]) => self.test_unsaved(&req).await,

            ("GET", ["rules"]) => respond::ok(&json_of(&self.state.load().rules)),
            ("POST", ["rules"]) => self.add_rule(&req),
            ("PUT", ["rules", id]) => self.update_rule(id, &req),
            ("DELETE", ["rules", id]) => self.delete_rule(id),

            ("GET", ["notifications"]) => respond::ok(&json_of(&self.pipeline.notify_log())),
            ("GET", ["retry"]) => respond::ok(&json_of(&self.pipeline.retry_status())),

            ("POST", ["retry"]) => {
                self.pipeline.retry_now();
                respond::ok(&json_of(&self.pipeline.retry_status()))
            }
            ("POST", ["regroup"]) => self.regroup().await,
            ("POST", ["push"]) => self.accept_push(&req).await,

            _ => respond::error(404, "no such endpoint"),
        }
    }

    fn login(&self, req: &ApiReq) -> Reply {
        #[derive(serde::Deserialize)]
        struct Body {
            nonce: String,
            proof: String,
        }
        let Ok(b) = req.json::<Body>() else {
            return respond::error(400, "expected {nonce, proof}");
        };
        match self
            .auth
            .load()
            .login(&b.nonce, &b.proof, &req.peer.ip().to_string())
        {
            Ok((token, ttl)) => {
                log::info(&format!("web login from {}", req.peer.ip()));
                respond::ok(&serde_json::json!({ "token": token, "ttl": ttl }))
            }
            Err(s2l_web::LoginError::TooManyAttempts) => {
                respond::error(429, "too many attempts, wait a moment")
            }
            Err(e) => {
                log::warn(&format!("failed web login from {} ({e:?})", req.peer.ip()));
                respond::error(401, "invalid credentials")
            }
        }
    }

    async fn list(&self, req: &ApiReq) -> Reply {
        let q = parse_query(req);
        let store = self.store.clone();
        match blocking(move || store.query(&q)).await {
            Ok(Ok(page)) => respond::ok(&serde_json::to_value(page).unwrap_or_default()),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn get_one(&self, id: &str) -> Reply {
        let Some(id) = id.parse::<u64>().ok() else {
            return respond::error(400, "the message id must be a number");
        };
        let store = self.store.clone();
        match blocking(move || store.get(id)).await {
            Ok(Ok(Some(m))) => respond::ok(&serde_json::to_value(m).unwrap_or_default()),
            Ok(Ok(None)) => respond::error(404, "no such message"),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn raw(&self, id: &str) -> Reply {
        let Some(id) = id.parse::<u64>().ok() else {
            return respond::error(400, "the message id must be a number");
        };
        let store = self.store.clone();
        let got = match blocking(move || store.get(id)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return respond::error(500, &e.to_string()),
            Err(e) => return respond::error(500, &e),
        };
        let Some(msg) = got else {
            return respond::error(404, "no such message");
        };
        let Some(b64) = msg.body.raw_b64 else {
            return respond::error(
                404,
                "the raw source was not kept for this message; enable it in settings",
            );
        };
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(bytes) => {
                respond::bytes(bytes, "message/rfc822", Some(&format!("message-{id}.eml")))
            }
            Err(_) => respond::error(500, "the stored raw source is corrupt"),
        }
    }

    async fn delete_one(&self, id: &str) -> Reply {
        let Some(id) = id.parse::<u64>().ok() else {
            return respond::error(400, "the message id must be a number");
        };
        let store = self.store.clone();
        match blocking(move || store.delete(&[id])).await {
            Ok(Ok(n)) => respond::ok(&serde_json::json!({ "deleted": n })),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn bulk_delete(&self, req: &ApiReq) -> Reply {
        #[derive(serde::Deserialize, Default)]
        struct Body {
            #[serde(default)]
            ids: Vec<u64>,
            #[serde(default)]
            all: bool,
        }
        let b = req.json::<Body>().unwrap_or_default();
        let store = self.store.clone();
        let result = if b.all {
            blocking(move || store.clear()).await
        } else if b.ids.is_empty() {
            return respond::error(400, "expected {ids: [...]} or {all: true}");
        } else {
            blocking(move || store.delete(&b.ids)).await
        };
        match result {
            Ok(Ok(n)) => respond::ok(&serde_json::json!({ "deleted": n })),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn set_group(&self, id: &str, req: &ApiReq) -> Reply {
        #[derive(serde::Deserialize)]
        struct Body {
            group: Option<u32>,
        }
        let (Ok(id), Ok(b)) = (id.parse::<u64>(), req.json::<Body>()) else {
            return respond::error(400, "expected a numeric id and {group: <id or null>}");
        };
        let store = self.store.clone();
        match blocking(move || store.set_group(id, b.group)).await {
            Ok(Ok(true)) => respond::ok(&serde_json::json!({ "ok": true })),
            Ok(Ok(false)) => respond::error(404, "no such message"),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn regroup(&self) -> Reply {
        let store = self.store.clone();
        let state = self.state.load_full();
        let changed = blocking(move || {
            let page = store.query(&Query {
                limit: usize::MAX,
                ..Default::default()
            })?;
            let mut changed = 0usize;
            for m in page.items {
                let user = m.from.rsplit_once('@').map(|(u, _)| u).unwrap_or(&m.from);
                let domain = m.from.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                let target = s2l_store::Target {
                    from: &m.from,
                    from_user: user,
                    from_domain: domain,
                    from_name: &m.from_name,
                    subject: &m.subject,

                    body: &m.preview,
                    rcpt: &m.rcpt,
                    peer_ip: &m.peer,

                    group: "",
                    auth_user: &m.auth_user,
                    headers: &[],
                };
                let want = state.classify(&target);
                if want != m.group {
                    store.set_group(m.id, want)?;
                    changed += 1;
                }
            }
            Ok::<_, s2l_store::StoreError>(changed)
        })
        .await;

        match changed {
            Ok(Ok(n)) => respond::ok(&serde_json::json!({ "changed": n })),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn put_settings(&self, req: &ApiReq) -> Reply {
        let Ok(want) = req.json::<Settings>() else {
            return respond::error(
                400,
                "expected {max_entries, max_days, keep_raw, keep_attachments, retry_queue}",
            );
        };
        if want.max_entries == 0 {
            return respond::error(400, "max_entries must be at least 1");
        }
        if let Err(e) = config::update(&self.config_path, &want.as_ini()) {
            log::error(&format!(
                "could not write {}: {e}",
                self.config_path.display()
            ));
            return respond::error(500, &format!("could not save the configuration: {e}"));
        }
        self.settings.store(Arc::new(want));
        log::info(&format!("settings saved to {}", self.config_path.display()));

        self.pipeline.trim_retry(want.retry_queue);

        let store = self.store.clone();
        let retention = want.retention();
        if let Ok(Err(e)) = blocking(move || store.set_retention(retention)).await {
            return respond::error(500, &e.to_string());
        }
        respond::ok(&json_of(&want))
    }

    async fn attachment(&self, id: &str, index: &str) -> Reply {
        let (Ok(id), Ok(index)) = (id.parse::<u64>(), index.parse::<usize>()) else {
            return respond::error(400, "the message id and attachment index must be numbers");
        };
        let store = self.store.clone();
        let got = match blocking(move || store.get(id)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return respond::error(500, &e.to_string()),
            Err(e) => return respond::error(500, &e),
        };
        let Some(msg) = got else {
            return respond::error(404, "no such message");
        };
        let Some(meta) = msg.body.attachments.get(index) else {
            return respond::error(404, "no such attachment");
        };
        let name = meta.filename.clone();
        let mime = if meta.mime.is_empty() {
            "application/octet-stream".to_string()
        } else {
            meta.mime.clone()
        };
        let store = self.store.clone();
        match blocking(move || store.attachment(id, index)).await {
            Ok(Ok(Some(bytes))) => respond::bytes(bytes, &mime, Some(&name)),
            Ok(Ok(None)) => respond::error(
                404,
                "the attachment content was not kept; enable it in settings",
            ),
            Ok(Err(e)) => respond::error(500, &e.to_string()),
            Err(e) => respond::error(500, &e),
        }
    }

    async fn accept_push(&self, req: &ApiReq) -> Reply {
        if self.push_pass.is_empty() {
            return respond::error(
                403,
                "this instance has no web_pass, so it cannot authenticate pushes",
            );
        }
        let payload = match push::open(&self.push_pass, &req.body, log::now_ms()) {
            Ok(p) => p,
            Err(e @ push::PushError::Skew(_)) => {
                log::warn(&format!("rejected a push from {}: {e}", req.peer.ip()));
                return respond::error(400, &e.to_string());
            }
            Err(e) => {
                log::warn(&format!("rejected a push from {}: {e}", req.peer.ip()));
                return respond::error(401, "push rejected");
            }
        };
        let from = payload.hostname.clone();
        let pipe = self.pipeline.clone();
        let job = blocking(move || pipe.accept_push(payload)).await;
        match job {
            Ok(Some(job)) => {
                let pipe = self.pipeline.clone();
                tokio::spawn(async move { pipe.notify_job(job).await });
                respond::ok(&serde_json::json!({ "ok": true }))
            }

            Ok(None) => respond::ok(&serde_json::json!({ "ok": true, "stored": false })),
            Err(e) => {
                log::error(&format!("could not accept a push from {from}: {e}"));
                respond::error(500, &e)
            }
        }
    }
    fn add_group(&self, req: &ApiReq) -> Reply {
        let Ok(mut g) = req.json::<Group>() else {
            return respond::error(400, "expected a group object");
        };
        self.mutate(move |s| {
            g.id = s.take_id();
            s.groups.push(g);
            Ok(())
        })
    }

    fn update_group(&self, id: &str, req: &ApiReq) -> Reply {
        let (Ok(id), Ok(g)) = (id.parse::<u32>(), req.json::<Group>()) else {
            return respond::error(400, "expected a numeric id and a group object");
        };
        self.mutate(move |s| match s.groups.iter_mut().find(|x| x.id == id) {
            Some(slot) => {
                *slot = Group { id, ..g.clone() };
                Ok(())
            }
            None => Err("no such group".into()),
        })
    }

    fn reorder_groups(&self, req: &ApiReq) -> Reply {
        #[derive(serde::Deserialize)]
        struct Body {
            ids: Vec<u32>,
        }
        let Ok(b) = req.json::<Body>() else {
            return respond::error(400, "expected {ids: [group id, ...]}");
        };
        self.mutate(move |s| {
            s.reorder_groups(&b.ids);
            Ok(())
        })
    }

    fn delete_group(&self, id: &str) -> Reply {
        let Ok(id) = id.parse::<u32>() else {
            return respond::error(400, "the group id must be a number");
        };
        let reply = self.mutate(move |s| {
            let before = s.groups.len();
            s.groups.retain(|g| g.id != id);
            if s.groups.len() == before {
                return Err("no such group".into());
            }
            Ok(())
        });
        if reply.status == 200 {
            let store = self.store.clone();
            let ids: Vec<u64> = store
                .query(&Query {
                    group: Some(GroupFilter::Id(id)),
                    limit: usize::MAX,
                    ..Default::default()
                })
                .map(|p| p.items.iter().map(|m| m.id).collect())
                .unwrap_or_default();
            for mid in ids {
                let _ = store.set_group(mid, None);
            }
        }
        reply
    }

    fn put_access(&self, req: &ApiReq) -> Reply {
        let Ok(a) = req.json::<Access>() else {
            return respond::error(400, "expected an access object");
        };
        self.mutate(move |s| {
            s.access = a.clone();
            Ok(())
        })
    }

    fn add_channel(&self, req: &ApiReq) -> Reply {
        let Ok(mut c) = req.json::<ChannelCfg>() else {
            return respond::error(400, "expected a channel object");
        };
        self.mutate(move |s| {
            c.id = s.take_id();
            s.channels.push(c);
            Ok(())
        })
    }

    fn update_channel(&self, id: &str, req: &ApiReq) -> Reply {
        let (Ok(id), Ok(c)) = (id.parse::<u32>(), req.json::<ChannelCfg>()) else {
            return respond::error(400, "expected a numeric id and a channel object");
        };
        self.mutate(move |s| match s.channels.iter_mut().find(|x| x.id == id) {
            Some(slot) => {
                *slot = ChannelCfg { id, ..c.clone() };
                Ok(())
            }
            None => Err("no such channel".into()),
        })
    }

    fn delete_channel(&self, id: &str) -> Reply {
        let Ok(id) = id.parse::<u32>() else {
            return respond::error(400, "the channel id must be a number");
        };
        self.mutate(move |s| {
            let before = s.channels.len();
            s.channels.retain(|c| c.id != id);
            if s.channels.len() == before {
                return Err("no such channel".into());
            }

            for r in &mut s.rules {
                r.channels.retain(|c| *c != id);
            }
            Ok(())
        })
    }

    async fn test_channel(&self, id: &str) -> Reply {
        let Ok(id) = id.parse::<u32>() else {
            return respond::error(400, "the channel id must be a number");
        };
        let Some(cfg) = self.state.load().channel(id).cloned() else {
            return respond::error(404, "no such channel");
        };
        let outcome = self.pipeline.test_channel(&cfg.channel).await;
        respond::ok(&serde_json::to_value(outcome).unwrap_or_default())
    }

    async fn test_unsaved(&self, req: &ApiReq) -> Reply {
        let Ok(ch) = req.json::<s2l_notify::Channel>() else {
            return respond::error(400, "expected a channel configuration");
        };
        let outcome = self.pipeline.test_channel(&ch).await;
        respond::ok(&serde_json::to_value(outcome).unwrap_or_default())
    }

    fn add_rule(&self, req: &ApiReq) -> Reply {
        let Ok(mut r) = req.json::<NotifyRule>() else {
            return respond::error(400, "expected a rule object");
        };
        self.mutate(move |s| {
            r.id = s.take_id();
            s.rules.push(r);
            Ok(())
        })
    }

    fn update_rule(&self, id: &str, req: &ApiReq) -> Reply {
        let (Ok(id), Ok(r)) = (id.parse::<u32>(), req.json::<NotifyRule>()) else {
            return respond::error(400, "expected a numeric id and a rule object");
        };
        self.mutate(move |s| match s.rules.iter_mut().find(|x| x.id == id) {
            Some(slot) => {
                *slot = NotifyRule { id, ..r.clone() };
                Ok(())
            }
            None => Err("no such rule".into()),
        })
    }

    fn delete_rule(&self, id: &str) -> Reply {
        let Ok(id) = id.parse::<u32>() else {
            return respond::error(400, "the rule id must be a number");
        };
        self.mutate(move |s| {
            let before = s.rules.len();
            s.rules.retain(|r| r.id != id);
            if s.rules.len() == before {
                return Err("no such rule".into());
            }
            Ok(())
        })
    }

    fn mutate<F>(&self, f: F) -> Reply
    where
        F: FnOnce(&mut State) -> Result<(), String>,
    {
        let mut next = (**self.state.load()).clone();
        if let Err(e) = f(&mut next) {
            return respond::error(404, &e);
        }
        if let Err(e) = next.save(&self.data_dir) {
            log::error(&format!("could not persist state: {e}"));
            return respond::error(500, &format!("could not save the configuration: {e}"));
        }
        self.state.store(Arc::new(next));
        respond::ok(&serde_json::json!({ "ok": true }))
    }
}

fn json_of<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("worker task failed: {e}"))
}

pub fn parse_query(req: &ApiReq) -> Query {
    let s = |name: &str| req.param(name).filter(|v| !v.trim().is_empty());
    let n = |name: &str| req.param(name).and_then(|v| v.trim().parse::<i64>().ok());

    Query {
        text: s("q"),
        subject: s("subject"),
        body: s("body"),
        from: s("from"),
        from_user: s("from_user"),
        from_domain: s("from_domain"),
        peer: s("peer"),
        group: s("group").and_then(|g| match g.as_str() {
            "none" | "ungrouped" => Some(GroupFilter::Ungrouped),
            other => other.parse::<u32>().ok().map(GroupFilter::Id),
        }),
        start: n("start"),
        end: n("end"),
        has_attachment: s("has_attachment").map(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        sort: match s("sort").as_deref() {
            Some("asc") | Some("time_asc") => Sort::TimeAsc,
            _ => Sort::TimeDesc,
        },
        offset: n("offset").unwrap_or(0).max(0) as usize,
        limit: n("limit").unwrap_or(0).max(0) as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn req(query: &str) -> ApiReq {
        ApiReq {
            method: "GET".into(),
            path: "messages".into(),
            query: query.into(),
            body: Vec::new(),
            token: String::new(),
            peer: "10.0.0.1:1".parse::<SocketAddr>().unwrap(),
        }
    }

    #[test]
    fn an_empty_query_string_means_no_filters() {
        let q = parse_query(&req(""));
        assert!(q.text.is_none());
        assert!(q.subject.is_none());
        assert!(
            !q.needs_body(),
            "an empty query must not trigger a disk scan"
        );
        assert_eq!(q.sort, Sort::TimeDesc);
    }

    #[test]
    fn blank_filter_values_are_dropped() {
        let q = parse_query(&req("subject=&body=&q=%20%20"));
        assert!(q.subject.is_none());
        assert!(q.body.is_none());
        assert!(q.text.is_none());
        assert!(!q.needs_body());
    }

    #[test]
    fn parses_chinese_filter_values() {
        let q = parse_query(&req("subject=%E6%B8%A9%E5%BA%A6&from_domain=idc.local"));
        assert_eq!(q.subject.as_deref(), Some("温度"));
        assert_eq!(q.from_domain.as_deref(), Some("idc.local"));
    }

    #[test]
    fn the_ungrouped_filter_has_two_spellings() {
        for v in ["none", "ungrouped"] {
            assert_eq!(
                parse_query(&req(&format!("group={v}"))).group,
                Some(GroupFilter::Ungrouped)
            );
        }
        assert_eq!(parse_query(&req("group=7")).group, Some(GroupFilter::Id(7)));
        assert_eq!(
            parse_query(&req("group=notanumber")).group,
            None,
            "garbage must fall back to no filter rather than an empty result"
        );
    }

    #[test]
    fn paging_and_sorting_parse() {
        let q = parse_query(&req("limit=25&offset=50&sort=asc"));
        assert_eq!(q.limit, 25);
        assert_eq!(q.offset, 50);
        assert_eq!(q.sort, Sort::TimeAsc);
    }

    #[test]
    fn negative_paging_values_are_clamped_not_wrapped() {
        let q = parse_query(&req("limit=-5&offset=-1"));
        assert_eq!(q.offset, 0);
        assert_eq!(q.limit, 0, "0 means 'use the default page size'");
    }

    #[test]
    fn has_attachment_accepts_both_spellings() {
        assert_eq!(
            parse_query(&req("has_attachment=1")).has_attachment,
            Some(true)
        );
        assert_eq!(
            parse_query(&req("has_attachment=true")).has_attachment,
            Some(true)
        );
        assert_eq!(
            parse_query(&req("has_attachment=0")).has_attachment,
            Some(false)
        );
        assert_eq!(parse_query(&req("")).has_attachment, None);
    }

    #[test]
    fn a_time_range_parses_as_unix_millis() {
        let q = parse_query(&req("start=1788353161000&end=1788353261000"));
        assert_eq!(q.start, Some(1_788_353_161_000));
        assert_eq!(q.end, Some(1_788_353_261_000));
    }
}
