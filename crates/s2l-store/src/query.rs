// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupFilter {
    Id(u32),

    Ungrouped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sort {
    #[default]
    TimeDesc,
    TimeAsc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Query {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_user: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupFilter>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_attachment: Option<bool>,
    #[serde(default)]
    pub sort: Sort,
    #[serde(default)]
    pub offset: usize,

    #[serde(default)]
    pub limit: usize,
}

pub const DEFAULT_LIMIT: usize = 50;

pub const MAX_LIMIT: usize = 500;

impl Query {
    pub fn needs_body(&self) -> bool {
        self.body.as_deref().is_some_and(|s| !s.trim().is_empty())
    }

    pub fn clamp(&mut self) {
        if self.limit == 0 {
            self.limit = DEFAULT_LIMIT;
        }
        self.limit = self.limit.min(MAX_LIMIT);
    }

    pub fn matches_meta(&self, m: &crate::MetaRec) -> bool {
        if let Some(s) = &self.start {
            if m.ts < *s {
                return false;
            }
        }
        if let Some(e) = &self.end {
            if m.ts > *e {
                return false;
            }
        }
        match self.group {
            Some(GroupFilter::Id(g)) if m.group != Some(g) => return false,
            Some(GroupFilter::Ungrouped) if m.group.is_some() => return false,
            _ => {}
        }
        if let Some(want) = self.has_attachment {
            if (m.attachments > 0) != want {
                return false;
            }
        }
        if !contains_ci(&m.subject, &self.subject) {
            return false;
        }
        if !contains_ci(&m.from, &self.from) {
            return false;
        }
        if !contains_ci(&m.peer, &self.peer) {
            return false;
        }
        if let Some(u) = non_empty(&self.from_user) {
            if !user_of(&m.from).to_lowercase().contains(&u.to_lowercase()) {
                return false;
            }
        }
        if let Some(d) = non_empty(&self.from_domain) {
            if !domain_of(&m.from)
                .to_lowercase()
                .contains(&d.to_lowercase())
            {
                return false;
            }
        }
        if let Some(t) = non_empty(&self.text) {
            let t = t.to_lowercase();
            let hit = m.subject.to_lowercase().contains(&t)
                || m.from.to_lowercase().contains(&t)
                || m.from_name.to_lowercase().contains(&t)
                || m.preview.to_lowercase().contains(&t);
            if !hit {
                return false;
            }
        }
        true
    }
}

fn non_empty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn contains_ci(hay: &str, needle: &Option<String>) -> bool {
    match non_empty(needle) {
        Some(n) => hay.to_lowercase().contains(&n.to_lowercase()),
        None => true,
    }
}

pub(crate) fn user_of(addr: &str) -> &str {
    match addr.rsplit_once('@') {
        Some((u, _)) => u,
        None => addr,
    }
}

pub(crate) fn domain_of(addr: &str) -> &str {
    addr.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetaRec;

    fn rec() -> MetaRec {
        MetaRec {
            id: 1,
            ts: 1_788_353_161_000,
            date: None,
            envelope_from: "ups-01@idc.example.com".into(),
            from: "ups-01@idc.example.com".into(),
            from_name: "UPS Monitor".into(),
            subject: "[ALERT] 温度过高".into(),
            preview: "Sensor 3 reports 48C".into(),
            rcpt: vec!["log@stmp2log".into()],
            peer: "10.20.0.7".into(),
            origin: String::new(),
            auth_user: String::new(),
            size: 800,
            attachments: 0,
            group: Some(2),
            has_html: false,
            seg: 1,
            body_off: 0,
            body_len: 100,
        }
    }

    #[test]
    fn empty_query_matches_everything() {
        assert!(Query::default().matches_meta(&rec()));
    }

    #[test]
    fn only_a_body_condition_needs_disk() {
        assert!(!Query::default().needs_body());
        let mut q = Query {
            subject: Some("温度".into()),
            from_domain: Some("idc".into()),
            ..Default::default()
        };
        assert!(
            !q.needs_body(),
            "subject and sender filters must stay in memory; that is what makes paging fast"
        );
        q.body = Some("threshold".into());
        assert!(q.needs_body());
    }

    #[test]
    fn a_blank_body_string_does_not_trigger_a_disk_scan() {
        let q = Query {
            body: Some("   ".into()),
            ..Default::default()
        };
        assert!(!q.needs_body());
        assert!(q.matches_meta(&rec()));
    }

    #[test]
    fn filters_by_domain_suffix_and_user_prefix() {
        assert!(
            Query {
                from_domain: Some("idc.example.com".into()),
                ..Default::default()
            }
            .matches_meta(&rec())
        );
        assert!(
            Query {
                from_user: Some("ups".into()),
                ..Default::default()
            }
            .matches_meta(&rec())
        );
        assert!(
            !Query {
                from_user: Some("idc".into()),
                ..Default::default()
            }
            .matches_meta(&rec()),
            "the domain must not leak into a from_user match"
        );
    }

    #[test]
    fn filters_are_case_insensitive() {
        assert!(
            Query {
                subject: Some("alert".into()),
                ..Default::default()
            }
            .matches_meta(&rec())
        );
    }

    #[test]
    fn chinese_subject_keyword() {
        assert!(
            Query {
                subject: Some("温度".into()),
                ..Default::default()
            }
            .matches_meta(&rec())
        );
    }

    #[test]
    fn time_range_is_inclusive_on_both_ends() {
        let r = rec();
        assert!(
            Query {
                start: Some(r.ts),
                end: Some(r.ts),
                ..Default::default()
            }
            .matches_meta(&r)
        );
        assert!(
            !Query {
                start: Some(r.ts + 1),
                ..Default::default()
            }
            .matches_meta(&r)
        );
    }

    #[test]
    fn ungrouped_filter_finds_only_unmatched_mail() {
        let mut r = rec();
        assert!(
            !Query {
                group: Some(GroupFilter::Ungrouped),
                ..Default::default()
            }
            .matches_meta(&r)
        );
        r.group = None;
        assert!(
            Query {
                group: Some(GroupFilter::Ungrouped),
                ..Default::default()
            }
            .matches_meta(&r)
        );
    }

    #[test]
    fn quick_text_search_spans_subject_sender_and_preview() {
        for needle in ["温度", "ups-01", "UPS Monitor", "Sensor 3"] {
            assert!(
                Query {
                    text: Some(needle.into()),
                    ..Default::default()
                }
                .matches_meta(&rec()),
                "quick search should find {needle:?}"
            );
        }
        assert!(
            !Query {
                text: Some("nonexistent".into()),
                ..Default::default()
            }
            .matches_meta(&rec())
        );
    }

    #[test]
    fn clamp_bounds_the_page_size() {
        let mut q = Query::default();
        q.clamp();
        assert_eq!(q.limit, DEFAULT_LIMIT);

        let mut q = Query {
            limit: 999_999,
            ..Default::default()
        };
        q.clamp();
        assert_eq!(
            q.limit, MAX_LIMIT,
            "?limit=999999 must not blow up a router"
        );
    }
}
