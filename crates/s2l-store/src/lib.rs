// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::VecDeque;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub mod match_;
mod query;
mod rec;
mod seg;

pub use match_::{Condition, Field, Logic, Matcher, Op, Target};
pub use query::{DEFAULT_LIMIT, GroupFilter, MAX_LIMIT, Query, Sort};
pub use rec::{BodyRec, MetaLine, MetaRec, PREVIEW_CHARS, preview_of};
pub use seg::Loc;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Retention {
    pub max_entries: usize,

    pub max_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_entries: 5000,
            max_days: 0,
        }
    }
}

pub struct NewMessage {
    pub received_at: i64,

    pub envelope_from: String,
    pub rcpt: Vec<String>,
    pub peer_ip: String,

    pub origin: String,

    pub auth_user: String,

    pub size: usize,
    pub mail: s2l_mail::Mail,

    pub group: Option<u32>,

    pub raw: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Message {
    #[serde(flatten)]
    pub meta: MetaRec,
    #[serde(flatten)]
    pub body: BodyRec,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Page {
    pub items: Vec<MetaRec>,

    pub total: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    pub total: usize,
    pub disk_bytes: u64,
    pub oldest: Option<i64>,
    pub newest: Option<i64>,

    pub by_group: BTreeMap<String, usize>,

    pub top_senders: Vec<(String, usize)>,

    pub last_24h: Vec<usize>,
}

pub struct Store {
    inner: Mutex<Inner>,
}

struct Inner {
    segs: seg::Segments,

    index: VecDeque<MetaRec>,
    next_id: u64,

    floor: u64,
    retention: Retention,
}

impl Store {
    pub fn open(dir: &Path, retention: Retention) -> Result<Self, StoreError> {
        let segs = seg::Segments::open(dir)?;

        let mut live: BTreeMap<u64, MetaRec> = BTreeMap::new();
        let mut floor = 0u64;
        let mut max_seen = 0u64;
        for &n in segs.nums() {
            for line in segs.read_meta(n)? {
                match line {
                    MetaLine::Msg(rec) => {
                        max_seen = max_seen.max(rec.id);
                        live.insert(rec.id, *rec);
                    }
                    MetaLine::Del { id } => {
                        max_seen = max_seen.max(id);
                        live.remove(&id);
                    }
                    MetaLine::Floor { id } => {
                        max_seen = max_seen.max(id);
                        floor = floor.max(id);
                    }
                }
            }
        }
        live.retain(|&id, _| id >= floor);

        let index: VecDeque<MetaRec> = live.into_values().collect();
        let store = Self {
            inner: Mutex::new(Inner {
                segs,
                next_id: max_seen + 1,
                floor,
                index,
                retention,
            }),
        };

        store.enforce_retention()?;
        Ok(store)
    }

    pub fn append(&self, msg: NewMessage) -> Result<MetaRec, StoreError> {
        let mut inner = self.lock();
        let id = inner.next_id;
        inner.next_id += 1;

        let from = {
            let h = msg.mail.from_addr();
            if h.is_empty() {
                msg.envelope_from.clone()
            } else {
                h.to_string()
            }
        };
        let from_name = msg
            .mail
            .from
            .as_ref()
            .map(|a| a.name.clone())
            .unwrap_or_default();

        let atts: Vec<Vec<u8>> = msg
            .mail
            .attachments
            .iter()
            .filter_map(|a| a.data.clone())
            .collect();
        let body_of = |spots: &[(u64, u32)]| BodyRec {
            id,
            text: msg.mail.text.clone(),
            html: msg.mail.html.clone(),
            attachments: msg.mail.attachments.clone(),
            headers: msg.mail.headers.clone(),
            att_spots: spots.to_vec(),
            raw_b64: msg.raw.as_ref().map(|r| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(r)
            }),
        };

        let meta_of = |loc: seg::Loc| MetaRec {
            id,
            ts: msg.received_at,
            date: msg.mail.date,
            envelope_from: msg.envelope_from.clone(),
            from: from.clone(),
            from_name: from_name.clone(),
            subject: msg.mail.subject.clone(),
            preview: preview_of(&msg.mail.text),
            rcpt: msg.rcpt.clone(),
            peer: msg.peer_ip.clone(),
            origin: msg.origin.clone(),
            auth_user: msg.auth_user.clone(),
            size: msg.size,
            attachments: msg.mail.attachments.len(),
            group: msg.group,
            has_html: msg.mail.html.is_some(),
            seg: loc.seg,
            body_off: loc.off,
            body_len: loc.len,
        };

        let mut written: Option<MetaRec> = None;
        inner.segs.append(&atts, body_of, |loc| {
            let rec = meta_of(loc);
            written = Some(rec.clone());
            MetaLine::Msg(Box::new(rec))
        })?;
        let rec = written.expect("the append callback always runs");
        inner.index.push_back(rec.clone());

        inner.enforce()?;
        Ok(rec)
    }

    pub fn query(&self, q: &Query) -> Result<Page, StoreError> {
        let mut q = q.clone();
        q.clamp();
        let inner = self.lock();

        let mut hits: Vec<MetaRec> = inner
            .index
            .iter()
            .filter(|m| q.matches_meta(m))
            .cloned()
            .collect();

        if let Some(needle) = q.body.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let keep = inner.body_matches(&hits, needle)?;
            hits.retain(|m| keep.contains(&m.id));
        }

        let total = hits.len();

        match q.sort {
            Sort::TimeDesc => hits.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id))),
            Sort::TimeAsc => hits.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.id.cmp(&b.id))),
        }

        let items = hits.into_iter().skip(q.offset).take(q.limit).collect();
        Ok(Page { items, total })
    }

    pub fn attachment(&self, id: u64, index: usize) -> Result<Option<Vec<u8>>, StoreError> {
        let inner = self.lock();
        let Some(meta) = inner.index.iter().find(|m| m.id == id) else {
            return Ok(None);
        };
        let loc = seg::Loc {
            seg: meta.seg,
            off: meta.body_off,
            len: meta.body_len,
        };
        let Some(body) = inner.segs.read_body_at(loc)? else {
            return Ok(None);
        };
        let Some(&(off, len)) = body.att_spots.get(index) else {
            return Ok(None);
        };
        inner.segs.read_att(meta.seg, off, len)
    }

    pub fn get(&self, id: u64) -> Result<Option<Message>, StoreError> {
        let inner = self.lock();
        let Some(meta) = inner.index.iter().find(|m| m.id == id).cloned() else {
            return Ok(None);
        };
        let loc = seg::Loc {
            seg: meta.seg,
            off: meta.body_off,
            len: meta.body_len,
        };
        let body = inner.segs.read_body_at(loc)?.unwrap_or(BodyRec {
            id,
            ..Default::default()
        });
        Ok(Some(Message { meta, body }))
    }

    pub fn delete(&self, ids: &[u64]) -> Result<usize, StoreError> {
        let mut inner = self.lock();
        let want: HashSet<u64> = ids.iter().copied().collect();
        let before = inner.index.len();
        inner.index.retain(|m| !want.contains(&m.id));
        let removed = before - inner.index.len();
        if removed > 0 {
            for id in ids {
                inner.segs.append_meta(&MetaLine::Del { id: *id })?;
            }
            inner.reclaim()?;
        }
        Ok(removed)
    }

    pub fn clear(&self) -> Result<usize, StoreError> {
        let mut inner = self.lock();
        let n = inner.index.len();
        inner.index.clear();
        let floor = inner.next_id;
        inner.floor = floor;
        inner.segs.append_meta(&MetaLine::Floor { id: floor })?;
        inner.reclaim()?;
        Ok(n)
    }

    pub fn set_group(&self, id: u64, group: Option<u32>) -> Result<bool, StoreError> {
        let mut inner = self.lock();
        let Some(rec) = inner.index.iter_mut().find(|m| m.id == id) else {
            return Ok(false);
        };
        if rec.group == group {
            return Ok(true);
        }
        rec.group = group;
        let line = MetaLine::Msg(Box::new(rec.clone()));
        inner.segs.append_meta(&line)?;
        Ok(true)
    }

    pub fn set_retention(&self, r: Retention) -> Result<usize, StoreError> {
        let mut inner = self.lock();
        inner.retention = r;
        let before = inner.index.len();
        inner.enforce()?;
        Ok(before - inner.index.len())
    }

    pub fn retention(&self) -> Retention {
        self.lock().retention
    }

    pub fn len(&self) -> usize {
        self.lock().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self, now_ms: i64) -> Stats {
        let inner = self.lock();
        let mut by_group: BTreeMap<String, usize> = BTreeMap::new();
        let mut senders: BTreeMap<&str, usize> = BTreeMap::new();
        let mut last_24h = vec![0usize; 24];
        let day_start = now_ms - 24 * 3600 * 1000;

        for m in &inner.index {
            let key = match m.group {
                Some(g) => g.to_string(),
                None => "none".to_string(),
            };
            *by_group.entry(key).or_default() += 1;
            *senders.entry(m.from.as_str()).or_default() += 1;
            if m.ts >= day_start && m.ts <= now_ms {
                let bucket = ((m.ts - day_start) / (3600 * 1000)) as usize;
                if let Some(slot) = last_24h.get_mut(bucket.min(23)) {
                    *slot += 1;
                }
            }
        }

        let mut top: Vec<(String, usize)> = senders
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(10);

        Stats {
            total: inner.index.len(),
            disk_bytes: inner.segs.disk_usage(),
            oldest: inner.index.front().map(|m| m.ts),
            newest: inner.index.back().map(|m| m.ts),
            by_group,
            top_senders: top,
            last_24h,
        }
    }

    fn enforce_retention(&self) -> Result<(), StoreError> {
        self.lock().enforce()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Inner {
    fn enforce(&mut self) -> Result<(), StoreError> {
        let mut evicted = false;

        while self.index.len() > self.retention.max_entries {
            self.index.pop_front();
            evicted = true;
        }

        if self.retention.max_days > 0 {
            let cutoff = now_ms() - i64::from(self.retention.max_days) * 24 * 3600 * 1000;
            while self.index.front().is_some_and(|m| m.ts < cutoff) {
                self.index.pop_front();
                evicted = true;
            }
        }

        if evicted {
            let floor = self.index.front().map(|m| m.id).unwrap_or(self.next_id);
            self.floor = floor;
            self.segs.append_meta(&MetaLine::Floor { id: floor })?;
            self.reclaim()?;
        }
        Ok(())
    }

    fn reclaim(&mut self) -> Result<(), StoreError> {
        let referenced: HashSet<u32> = self.index.iter().map(|m| m.seg).collect();
        let orphans: Vec<u32> = self
            .segs
            .nums()
            .iter()
            .copied()
            .filter(|n| !referenced.contains(n))
            .collect();
        for n in orphans {
            self.segs.drop_segment(n)?;
        }
        Ok(())
    }

    fn body_matches(
        &self,
        candidates: &[MetaRec],
        needle: &str,
    ) -> Result<HashSet<u64>, StoreError> {
        let needle = needle.to_lowercase();
        let wanted: HashSet<u64> = candidates.iter().map(|m| m.id).collect();
        let segs: HashSet<u32> = candidates.iter().map(|m| m.seg).collect();

        let mut hit = HashSet::new();
        for n in segs {
            self.segs.stream_body(n, |rec| {
                if !wanted.contains(&rec.id) {
                    return;
                }
                let in_text = rec.text.to_lowercase().contains(&needle);

                let in_html = !in_text
                    && rec
                        .html
                        .as_deref()
                        .is_some_and(|h| h.to_lowercase().contains(&needle));
                if in_text || in_html {
                    hit.insert(rec.id);
                }
            })?;
        }
        Ok(hit)
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn log_dir(data: &Path) -> PathBuf {
    data.join("log")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("s2l-store-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn msg(ts: i64, from: &str, subject: &str, body: &str) -> NewMessage {
        let mut mail = s2l_mail::Mail {
            subject: subject.into(),
            text: body.into(),
            ..Default::default()
        };
        mail.from = Some(s2l_mail::Addr {
            name: String::new(),
            addr: from.into(),
        });
        NewMessage {
            received_at: ts,
            envelope_from: from.into(),
            rcpt: vec!["log@stmp2log".into()],
            peer_ip: "10.0.0.1".into(),
            size: body.len(),
            mail,
            group: None,
            origin: String::new(),
            auth_user: String::new(),
            raw: None,
        }
    }

    fn open(dir: &Path, max: usize) -> Store {
        Store::open(
            dir,
            Retention {
                max_entries: max,
                max_days: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn append_and_query_round_trip() {
        let dir = tmpdir("rt");
        let s = open(&dir, 100);
        let rec = s
            .append(msg(1000, "a@x.com", "Disk failure", "sda died"))
            .unwrap();
        assert_eq!(rec.id, 1);

        let page = s.query(&Query::default()).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].subject, "Disk failure");
        assert_eq!(page.items[0].preview, "sda died");

        let full = s.get(1).unwrap().unwrap();
        assert_eq!(full.body.text, "sda died");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn survives_a_restart() {
        let dir = tmpdir("restart");
        {
            let s = open(&dir, 100);
            for i in 0..5 {
                s.append(msg(
                    1000 + i,
                    "a@x.com",
                    &format!("s{i}"),
                    &format!("body {i}"),
                ))
                .unwrap();
            }
        }
        let s = open(&dir, 100);
        assert_eq!(s.len(), 5);
        assert_eq!(s.get(3).unwrap().unwrap().body.text, "body 2");

        assert_eq!(s.append(msg(2000, "b@y.com", "new", "n")).unwrap().id, 6);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn newest_first_by_default() {
        let dir = tmpdir("sort");
        let s = open(&dir, 100);
        for i in 0..5 {
            s.append(msg(1000 + i, "a@x.com", &format!("s{i}"), "b"))
                .unwrap();
        }
        let page = s.query(&Query::default()).unwrap();
        assert_eq!(
            page.items[0].subject, "s4",
            "a log view shows the newest first"
        );
        let asc = s
            .query(&Query {
                sort: Sort::TimeAsc,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(asc.items[0].subject, "s0");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn paging_reports_the_unpaged_total() {
        let dir = tmpdir("page");
        let s = open(&dir, 100);
        for i in 0..30 {
            s.append(msg(1000 + i, "a@x.com", "s", "b")).unwrap();
        }
        let page = s
            .query(&Query {
                limit: 10,
                offset: 5,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.items.len(), 10);
        assert_eq!(page.total, 30);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn body_search_reads_disk_and_finds_text_not_in_the_preview() {
        let dir = tmpdir("bodysearch");
        let s = open(&dir, 100);
        let long = format!("{}NEEDLE_AT_THE_END", "x ".repeat(400));
        s.append(msg(1000, "a@x.com", "s", &long)).unwrap();
        s.append(msg(1001, "a@x.com", "s", "nothing here")).unwrap();

        let page = s
            .query(&Query {
                body: Some("needle_at_the_end".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].id, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn body_search_also_looks_inside_html() {
        let dir = tmpdir("htmlsearch");
        let s = open(&dir, 100);
        let mut m = msg(1000, "a@x.com", "s", "plain summary");
        m.mail.html = Some("<p>SPECIFIC_HTML_TOKEN</p>".into());
        s.append(m).unwrap();

        let page = s
            .query(&Query {
                body: Some("specific_html_token".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_evicts_oldest_and_survives_restart() {
        let dir = tmpdir("retention");
        {
            let s = open(&dir, 10);
            for i in 0..25 {
                s.append(msg(1000 + i, "a@x.com", &format!("s{i}"), "b"))
                    .unwrap();
            }
            assert_eq!(s.len(), 10);
            let page = s.query(&Query::default()).unwrap();
            assert_eq!(page.items[0].subject, "s24");
        }
        let s = open(&dir, 10);
        assert_eq!(
            s.len(),
            10,
            "evicted records must not come back after a restart"
        );
        assert!(s.get(1).unwrap().is_none());
        assert!(s.get(25).unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lowering_the_retention_limit_takes_effect_immediately() {
        let dir = tmpdir("lower");
        let s = open(&dir, 100);
        for i in 0..50 {
            s.append(msg(1000 + i, "a@x.com", "s", "b")).unwrap();
        }
        let dropped = s
            .set_retention(Retention {
                max_entries: 5,
                max_days: 0,
            })
            .unwrap();
        assert_eq!(dropped, 45);
        assert_eq!(s.len(), 5);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_lowered_between_runs_applies_at_startup() {
        let dir = tmpdir("lowerboot");
        {
            let s = open(&dir, 100);
            for i in 0..40 {
                s.append(msg(1000 + i, "a@x.com", "s", "b")).unwrap();
            }
        }
        let s = open(&dir, 7);
        assert_eq!(s.len(), 7);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evicting_everything_frees_the_disk() {
        let dir = tmpdir("reclaim");
        let s = open(&dir, 100_000);
        for i in 0..(seg::MAX_RECORDS as i64 * 2 + 10) {
            s.append(msg(1000 + i, "a@x.com", "s", "body text here"))
                .unwrap();
        }
        let before = s.stats(now_ms()).disk_bytes;
        s.set_retention(Retention {
            max_entries: 5,
            max_days: 0,
        })
        .unwrap();
        let after = s.stats(now_ms()).disk_bytes;
        assert!(
            after < before / 2,
            "old segments must be unlinked, not just hidden: {before} -> {after}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_and_clear() {
        let dir = tmpdir("del");
        {
            let s = open(&dir, 100);
            for i in 0..5 {
                s.append(msg(1000 + i, "a@x.com", "s", "b")).unwrap();
            }
            assert_eq!(s.delete(&[2, 4]).unwrap(), 2);
            assert_eq!(s.len(), 3);
            assert!(s.get(2).unwrap().is_none());
            assert_eq!(s.delete(&[2]).unwrap(), 0, "deleting twice is a no-op");
        }

        let s = open(&dir, 100);
        assert_eq!(s.len(), 3);
        assert!(s.get(2).unwrap().is_none());
        assert_eq!(s.clear().unwrap(), 3);
        assert_eq!(s.len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_survives_restart() {
        let dir = tmpdir("clear");
        {
            let s = open(&dir, 100);
            for i in 0..5 {
                s.append(msg(1000 + i, "a@x.com", "s", "b")).unwrap();
            }
            s.clear().unwrap();
        }
        assert_eq!(open(&dir, 100).len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn regrouping_is_persisted() {
        let dir = tmpdir("group");
        {
            let s = open(&dir, 100);
            s.append(msg(1000, "a@x.com", "s", "b")).unwrap();
            assert!(s.set_group(1, Some(7)).unwrap());
            assert!(!s.set_group(999, Some(7)).unwrap());
        }
        let s = open(&dir, 100);
        assert_eq!(s.query(&Query::default()).unwrap().items[0].group, Some(7));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn falls_back_to_the_envelope_sender_when_the_from_header_is_missing() {
        let dir = tmpdir("envelope");
        let s = open(&dir, 100);
        let mut m = msg(1000, "unused@x.com", "s", "b");
        m.mail.from = None;
        m.envelope_from = "device01@nas.local".into();
        let rec = s.append(m).unwrap();
        assert_eq!(rec.from, "device01@nas.local");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stats_counts_groups_and_senders() {
        let dir = tmpdir("stats");
        let s = open(&dir, 100);
        for i in 0..3 {
            let mut m = msg(now_ms(), "a@x.com", "s", "b");
            m.group = Some(1);
            let _ = i;
            s.append(m).unwrap();
        }
        s.append(msg(now_ms(), "b@y.com", "s", "b")).unwrap();

        let st = s.stats(now_ms());
        assert_eq!(st.total, 4);
        assert_eq!(st.by_group.get("1"), Some(&3));
        assert_eq!(st.by_group.get("none"), Some(&1));
        assert_eq!(st.top_senders[0], ("a@x.com".into(), 3));
        assert_eq!(st.last_24h.len(), 24);
        assert_eq!(st.last_24h.iter().sum::<usize>(), 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn raw_source_is_kept_only_when_asked() {
        let dir = tmpdir("raw");
        let s = open(&dir, 100);
        s.append(msg(1000, "a@x.com", "s", "b")).unwrap();
        let mut with_raw = msg(1001, "a@x.com", "s", "b");
        with_raw.raw = Some(b"From: a@x.com\r\n\r\nbody".to_vec());
        s.append(with_raw).unwrap();

        assert!(s.get(1).unwrap().unwrap().body.raw_b64.is_none());
        let kept = s.get(2).unwrap().unwrap().body.raw_b64.unwrap();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(kept)
            .unwrap();
        assert_eq!(decoded, b"From: a@x.com\r\n\r\nbody");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attachment_bytes_round_trip_and_stay_out_of_the_body_file() {
        let dir = tmpdir("att");
        let s = open(&dir, 100);
        let mut m = msg(1000, "a@x.com", "with files", "see attached");
        m.mail.attachments = vec![
            s2l_mail::AttachmentMeta {
                filename: "a.bin".into(),
                mime: "application/octet-stream".into(),
                size: 3,
                data: Some(vec![1, 2, 3]),
            },
            s2l_mail::AttachmentMeta {
                filename: "报告.pdf".into(),
                mime: "application/pdf".into(),
                size: 5,
                data: Some(b"hello".to_vec()),
            },
        ];
        s.append(m).unwrap();

        assert_eq!(s.attachment(1, 0).unwrap().unwrap(), vec![1, 2, 3]);
        assert_eq!(s.attachment(1, 1).unwrap().unwrap(), b"hello");
        assert!(
            s.attachment(1, 9).unwrap().is_none(),
            "out of range is None"
        );
        assert!(s.attachment(99, 0).unwrap().is_none(), "unknown id is None");

        let body = std::fs::read(dir.join("000001.body")).unwrap();
        assert!(
            !body.windows(5).any(|w| w == b"hello"),
            "attachment bytes leaked into the body file"
        );
        assert!(dir.join("000001.att").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attachments_survive_a_restart() {
        let dir = tmpdir("attboot");
        {
            let s = open(&dir, 100);
            let mut m = msg(1000, "a@x.com", "s", "b");
            m.mail.attachments = vec![s2l_mail::AttachmentMeta {
                filename: "f".into(),
                mime: "text/plain".into(),
                size: 4,
                data: Some(b"keep".to_vec()),
            }];
            s.append(m).unwrap();
        }
        let s = open(&dir, 100);
        assert_eq!(s.attachment(1, 0).unwrap().unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn metadata_only_attachments_leave_no_att_file() {
        let dir = tmpdir("attoff");
        let s = open(&dir, 100);
        let mut m = msg(1000, "a@x.com", "s", "b");
        m.mail.attachments = vec![s2l_mail::AttachmentMeta {
            filename: "f".into(),
            mime: "text/plain".into(),
            size: 4,
            data: None,
        }];
        s.append(m).unwrap();
        assert!(s.attachment(1, 0).unwrap().is_none());
        assert!(!dir.join("000001.att").exists());

        assert_eq!(s.query(&Query::default()).unwrap().items[0].attachments, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_store_answers_queries_without_error() {
        let dir = tmpdir("empty");
        let s = open(&dir, 100);
        assert!(s.is_empty());
        let page = s.query(&Query::default()).unwrap();
        assert_eq!(page.total, 0);
        assert!(s.get(1).unwrap().is_none());
        let st = s.stats(now_ms());
        assert_eq!(st.total, 0);
        assert_eq!(st.oldest, None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
