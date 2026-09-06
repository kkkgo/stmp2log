// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use serde::{Deserialize, Serialize};

pub const PREVIEW_CHARS: usize = 160;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum MetaLine {
    #[serde(rename = "m")]
    Msg(Box<MetaRec>),

    #[serde(rename = "d")]
    Del { id: u64 },

    #[serde(rename = "f")]
    Floor { id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRec {
    pub id: u64,

    pub ts: i64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    pub envelope_from: String,

    pub from: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rcpt: Vec<String>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_user: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer: String,

    pub size: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attachments: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_html: bool,

    pub seg: u32,
    pub body_off: u64,
    pub body_len: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BodyRec {
    pub id: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<s2l_mail::AttachmentMeta>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub att_spots: Vec<(u64, u32)>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_b64: Option<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

pub fn preview_of(text: &str) -> String {
    let mut out: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if out.chars().count() > PREVIEW_CHARS {
        out = out.chars().take(PREVIEW_CHARS).collect::<String>() + "…";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_collapses_blank_lines() {
        assert_eq!(preview_of("a\n\n  b  \n\nc"), "a b c");
    }

    #[test]
    fn preview_truncates_on_char_boundaries() {
        let long = "温".repeat(PREVIEW_CHARS + 40);
        let p = preview_of(&long);
        assert_eq!(
            p.chars().count(),
            PREVIEW_CHARS + 1,
            "PREVIEW_CHARS plus the ellipsis"
        );
        assert!(p.ends_with('…'));
        assert!(p.starts_with('温'), "no mojibake at the cut: {p:?}");
    }

    #[test]
    fn short_text_is_not_truncated() {
        assert_eq!(preview_of("short"), "short");
        assert_eq!(preview_of(""), "");
    }

    #[test]
    fn meta_lines_round_trip_and_stay_distinguishable() {
        let del = serde_json::to_string(&MetaLine::Del { id: 7 }).unwrap();
        assert_eq!(del, r#"{"t":"d","id":7}"#);
        let floor = serde_json::to_string(&MetaLine::Floor { id: 9 }).unwrap();
        assert_eq!(floor, r#"{"t":"f","id":9}"#);

        for line in [del, floor] {
            let back: MetaLine = serde_json::from_str(&line).unwrap();
            assert!(matches!(
                back,
                MetaLine::Del { .. } | MetaLine::Floor { .. }
            ));
        }
    }

    #[test]
    fn optional_meta_fields_are_omitted_when_empty() {
        let rec = MetaRec {
            id: 1,
            ts: 1788353161000,
            date: None,
            envelope_from: "a@b.c".into(),
            from: "a@b.c".into(),
            from_name: String::new(),
            subject: "hi".into(),
            preview: String::new(),
            rcpt: vec![],
            peer: String::new(),
            origin: String::new(),
            auth_user: String::new(),
            size: 10,
            attachments: 0,
            group: None,
            has_html: false,
            seg: 1,
            body_off: 0,
            body_len: 4,
        };
        let json = serde_json::to_string(&MetaLine::Msg(Box::new(rec))).unwrap();
        for absent in [
            "from_name",
            "preview",
            "rcpt",
            "peer",
            "attachments",
            "group",
            "has_html",
            "date",
            "origin",
            "auth_user",
        ] {
            assert!(!json.contains(absent), "{absent} should be omitted: {json}");
        }
        assert!(json.starts_with(r#"{"t":"m","#));
    }

    #[test]
    fn unknown_future_fields_do_not_break_loading() {
        let line = r#"{"t":"d","id":3,"future_field":"whatever"}"#;
        assert!(matches!(
            serde_json::from_str::<MetaLine>(line).unwrap(),
            MetaLine::Del { id: 3 }
        ));
    }
}
