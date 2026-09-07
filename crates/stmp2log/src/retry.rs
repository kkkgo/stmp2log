// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use crate::push;

pub const FIRST_DELAY: Duration = Duration::from_secs(30);

pub const MAX_DELAY: Duration = Duration::from_secs(300);

pub fn next_delay(current: Duration) -> Duration {
    (current * 2).min(MAX_DELAY)
}

#[derive(Debug, Clone)]
pub struct QueuedNotify {
    pub channel: u32,

    pub channel_name: String,
    pub kind: &'static str,
    pub rule: String,
    pub subject: String,
    pub payload: s2l_notify::Payload,

    pub email_to: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QueuedPush {
    pub id: u64,
    pub subject: String,
    pub payload: push::Payload,
}

#[derive(Debug, Clone)]
pub enum Item {
    Notify(QueuedNotify),
    Push(QueuedPush),
}

impl Item {
    pub fn kind(&self) -> &'static str {
        match self {
            Item::Notify(n) => n.kind,
            Item::Push(_) => "push",
        }
    }
    pub fn subject(&self) -> &str {
        match self {
            Item::Notify(n) => &n.subject,
            Item::Push(p) => &p.subject,
        }
    }
    pub fn rule(&self) -> String {
        match self {
            Item::Notify(n) => n.rule.clone(),
            Item::Push(_) => String::new(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Item::Notify(n) => format!("notification to {:?} via {}", n.channel_name, n.kind),
            Item::Push(p) => format!("forward of #{}", p.id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub item: Item,

    pub at: i64,

    pub attempts: usize,

    pub error: String,
}

#[derive(Debug, Default)]
pub struct Queue {
    items: Mutex<VecDeque<Pending>>,

    work: Notify,

    up: Notify,

    dropped: AtomicU64,
}

impl Queue {
    pub fn push(
        &self,
        item: Item,
        at: i64,
        attempts: usize,
        error: String,
        max: usize,
    ) -> Vec<Pending> {
        let mut q = self.items.lock().unwrap_or_else(|e| e.into_inner());
        insert_by_time(
            &mut q,
            Pending {
                item,
                at,
                attempts,
                error,
            },
        );
        let evicted = evict(&mut q, max);
        drop(q);

        self.dropped
            .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        self.work.notify_one();
        evicted
    }

    pub fn trim(&self, max: usize) -> Vec<Pending> {
        let mut q = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let evicted = evict(&mut q, max);
        drop(q);
        self.dropped
            .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        evicted
    }

    pub fn pop(&self) -> Option<Pending> {
        let mut q = self.items.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }

    pub fn requeue(&self, p: Pending) {
        let mut q = self.items.lock().unwrap_or_else(|e| e.into_inner());
        q.push_front(p);
    }

    pub fn is_empty(&self) -> bool {
        self.items
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn status(&self, max: usize) -> Status {
        let q = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let oldest = q.front();
        Status {
            pending: q.len(),
            notify: q
                .iter()
                .filter(|p| matches!(p.item, Item::Notify(_)))
                .count(),
            push: q.iter().filter(|p| matches!(p.item, Item::Push(_))).count(),
            dropped: self.dropped.load(Ordering::Relaxed),
            max,
            oldest: oldest.map(|p| p.at),
            error: oldest.map(|p| p.error.clone()).unwrap_or_default(),
        }
    }

    pub async fn wait_for_work(&self) {
        self.work.notified().await;
    }

    pub async fn wait_backoff(&self, delay: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = self.up.notified() => {}
        }
    }

    pub fn kick(&self) {
        self.work.notify_one();
        self.up.notify_one();
    }

    pub fn recovered(&self) {
        if !self.is_empty() {
            self.up.notify_one();
        }
    }
}

fn insert_by_time(q: &mut VecDeque<Pending>, p: Pending) {
    let pos = q.iter().rposition(|x| x.at <= p.at).map_or(0, |i| i + 1);
    q.insert(pos, p);
}

fn evict(q: &mut VecDeque<Pending>, max: usize) -> Vec<Pending> {
    if max == 0 {
        return Vec::new();
    }
    let mut evicted = Vec::new();
    while q.len() > max {
        if let Some(p) = q.pop_front() {
            evicted.push(p);
        }
    }
    evicted
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    pub pending: usize,

    pub notify: usize,

    pub push: usize,

    pub dropped: u64,

    pub max: usize,

    pub oldest: Option<i64>,

    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(subject: &str) -> Item {
        Item::Notify(QueuedNotify {
            channel: 1,
            channel_name: "phone".into(),
            kind: "ntfy",
            rule: "all".into(),
            subject: subject.into(),
            payload: s2l_notify::Payload::default(),
            email_to: vec![],
        })
    }

    fn push_item(id: u64) -> Item {
        Item::Push(QueuedPush {
            id,
            subject: "s".into(),
            payload: push::Payload {
                hostname: "idc-a".into(),
                ts: 0,
                envelope_from: "ups@idc.local".into(),
                rcpt: vec![],
                peer: String::new(),
                raw_b64: String::new(),
            },
        })
    }

    fn fill(q: &Queue, n: usize, max: usize) -> usize {
        let mut evicted = 0;
        for i in 0..n {
            evicted += q
                .push(item(&format!("m{i}")), i as i64, 3, "no route".into(), max)
                .len();
        }
        evicted
    }

    #[test]
    fn the_queue_keeps_the_newest_when_it_overflows() {
        let q = Queue::default();
        assert_eq!(fill(&q, 25, 10), 15, "everything over the limit is evicted");
        assert_eq!(q.len(), 10);

        let first = q.pop().unwrap();
        assert_eq!(
            first.item.subject(),
            "m15",
            "the oldest survivor must be the 15th, not the 1st"
        );
    }

    #[test]
    fn a_zero_limit_never_evicts() {
        let q = Queue::default();
        assert_eq!(fill(&q, 500, 0), 0);
        assert_eq!(q.len(), 500);
        assert_eq!(q.status(0).dropped, 0);
    }

    #[test]
    fn evicted_entries_are_handed_back_so_they_can_be_logged() {
        let q = Queue::default();
        let evicted = q.push(item("a"), 1, 1, String::new(), 1);
        assert!(evicted.is_empty(), "the first one fits");
        let evicted = q.push(item("b"), 2, 1, String::new(), 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].item.subject(), "a");
        assert_eq!(q.status(1).dropped, 1);
    }

    #[test]
    fn lowering_the_limit_takes_effect_immediately() {
        let q = Queue::default();
        fill(&q, 10, 10);
        let evicted = q.trim(2);
        assert_eq!(evicted.len(), 8);
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop().unwrap().item.subject(), "m8", "the newest two stay");
    }

    #[test]
    fn a_requeued_entry_goes_back_to_the_front() {
        let q = Queue::default();
        fill(&q, 3, 0);
        let p = q.pop().unwrap();
        assert_eq!(p.item.subject(), "m0");
        q.requeue(p);
        assert_eq!(q.pop().unwrap().item.subject(), "m0");
    }

    #[test]
    fn the_status_counts_both_kinds_separately() {
        let q = Queue::default();
        q.push(item("a"), 100, 3, "no route to host".into(), 0);
        q.push(push_item(7), 200, 1, "timed out".into(), 0);

        let s = q.status(10);
        assert_eq!(s.pending, 2);
        assert_eq!(s.notify, 1);
        assert_eq!(s.push, 1);
        assert_eq!(s.max, 10);
        assert_eq!(s.oldest, Some(100), "the oldest alert, not the newest");
        assert_eq!(s.error, "no route to host");
    }

    #[test]
    fn entries_queue_up_by_when_the_alert_happened_not_when_it_failed() {
        let q = Queue::default();
        q.push(item("new"), 9_000, 1, String::new(), 0);
        q.push(item("old"), 1_000, 1, String::new(), 0);
        q.push(item("mid"), 5_000, 1, String::new(), 0);

        let order: Vec<String> = std::iter::from_fn(|| q.pop())
            .map(|p| p.item.subject().to_string())
            .collect();
        assert_eq!(
            order,
            ["old", "mid", "new"],
            "the backlog must go out in the order the alerts happened"
        );
    }

    #[test]
    fn a_late_failing_old_alert_is_the_one_that_gets_dropped() {
        let q = Queue::default();
        q.push(item("new"), 9_000, 1, String::new(), 1);
        let evicted = q.push(item("old"), 1_000, 1, String::new(), 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(
            evicted[0].item.subject(),
            "old",
            "the older alert loses even though it was queued last"
        );
    }

    #[test]
    fn the_backoff_doubles_up_to_the_cap() {
        let mut d = FIRST_DELAY;
        let mut seen = vec![d];
        for _ in 0..10 {
            d = next_delay(d);
            seen.push(d);
        }
        assert_eq!(seen[1], Duration::from_secs(60));
        assert_eq!(seen[2], Duration::from_secs(120));
        assert_eq!(*seen.last().unwrap(), MAX_DELAY);
        assert!(seen.iter().all(|d| *d <= MAX_DELAY));
    }

    #[tokio::test]
    async fn a_direct_success_cuts_the_backoff_short() {
        let q = std::sync::Arc::new(Queue::default());
        q.push(item("a"), 0, 1, String::new(), 0);

        let waiter = q.clone();
        let waited = tokio::time::timeout(Duration::from_secs(5), async move {
            waiter.wait_backoff(MAX_DELAY).await;
        });
        q.kick();
        assert!(
            waited.await.is_ok(),
            "kick() must wake the flusher instead of leaving it in the 5 minute sleep"
        );
    }
}
