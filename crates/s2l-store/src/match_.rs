// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {

    From,

    FromUser,

    FromDomain,

    FromName,
    Subject,

    Body,

    Rcpt,

    PeerIp,

    Group,

    AuthUser,

    Header(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Contains,
    NotContains,
    Equals,
    NotEquals,
    StartsWith,
    EndsWith,

    Matches,

    Empty,
    NotEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Logic {

    #[default]
    All,

    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    #[serde(default)]
    pub value: String,

    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(default)]
    pub logic: Logic,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Target<'a> {
    pub from: &'a str,
    pub from_user: &'a str,
    pub from_domain: &'a str,
    pub from_name: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub rcpt: &'a [String],
    pub peer_ip: &'a str,

    pub group: &'a str,

    pub auth_user: &'a str,
    pub headers: &'a [(String, String)],
}

impl Matcher {

    pub fn is_unconditional(&self) -> bool {
        self.conditions.is_empty()
    }

    pub fn matches(&self, t: &Target<'_>) -> bool {
        if self.conditions.is_empty() {
            return true;
        }
        match self.logic {
            Logic::All => self.conditions.iter().all(|c| c.matches(t)),
            Logic::Any => self.conditions.iter().any(|c| c.matches(t)),
        }
    }
}

impl Condition {
    pub fn matches(&self, t: &Target<'_>) -> bool {

        if matches!(self.field, Field::Rcpt) {
            return match self.op {

                Op::NotContains | Op::NotEquals => t.rcpt.iter().all(|r| self.test(r)),
                Op::Empty => t.rcpt.is_empty(),
                Op::NotEmpty => !t.rcpt.is_empty(),
                _ => t.rcpt.iter().any(|r| self.test(r)),
            };
        }
        self.test(self.extract(t))
    }

    fn extract<'a>(&self, t: &Target<'a>) -> &'a str {
        match &self.field {
            Field::From => t.from,
            Field::FromUser => t.from_user,
            Field::FromDomain => t.from_domain,
            Field::FromName => t.from_name,
            Field::Subject => t.subject,
            Field::Body => t.body,
            Field::PeerIp => t.peer_ip,
            Field::Group => t.group,
            Field::AuthUser => t.auth_user,
            Field::Header(name) => t
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .unwrap_or(""),

            Field::Rcpt => "",
        }
    }

    fn test(&self, subject: &str) -> bool {

        let (hay, needle);
        let (h, n) = if self.case_sensitive {
            (subject, self.value.as_str())
        } else {
            hay = subject.to_lowercase();
            needle = self.value.to_lowercase();
            (hay.as_str(), needle.as_str())
        };

        match self.op {
            Op::Contains => h.contains(n),
            Op::NotContains => !h.contains(n),
            Op::Equals => h == n,
            Op::NotEquals => h != n,
            Op::StartsWith => h.starts_with(n),
            Op::EndsWith => h.ends_with(n),
            Op::Matches => glob(h, n),
            Op::Empty => subject.trim().is_empty(),
            Op::NotEmpty => !subject.trim().is_empty(),
        }
    }
}

fn glob(hay: &str, pat: &str) -> bool {
    let h: Vec<char> = hay.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut hi, mut pi) = (0usize, 0usize);

    let (mut star, mut star_hi) = (usize::MAX, 0usize);

    while hi < h.len() {
        if pi < p.len() && (p[pi] == h[hi]) {
            hi += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            star_hi = hi;
            pi += 1;
        } else if star != usize::MAX {

            pi = star + 1;
            star_hi += 1;
            hi = star_hi;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target<'static> {
        static RCPT: [String; 1] = [String::new()];
        let _ = &RCPT;
        Target {
            from: "ups-01@idc.example.com",
            from_user: "ups-01",
            from_domain: "idc.example.com",
            from_name: "UPS Monitor",
            subject: "[ALERT] 温度过高",
            body: "Sensor 3 reports 48C, threshold is 40C",
            rcpt: &[],
            peer_ip: "10.20.0.7",
            group: "",
            auth_user: "",
            headers: &[],
        }
    }

    fn cond(field: Field, op: Op, value: &str) -> Condition {
        Condition {
            field,
            op,
            value: value.into(),
            case_sensitive: false,
        }
    }

    #[test]
    fn a_rule_can_target_a_group_without_repeating_its_conditions() {

        let t = Target {
            group: "5",
            ..target()
        };
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Group, Op::Equals, "5")],
        };
        assert!(m.matches(&t));

        let other = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Group, Op::Equals, "6")],
        };
        assert!(!other.matches(&t));
    }

    #[test]
    fn ungrouped_mail_is_matched_with_the_empty_operator() {
        let ungrouped = Target {
            group: "",
            ..target()
        };
        let grouped = Target {
            group: "5",
            ..target()
        };
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Group, Op::Empty, "")],
        };
        assert!(m.matches(&ungrouped));
        assert!(!m.matches(&grouped));
    }

    #[test]
    fn the_smtp_account_is_matchable() {

        let t = Target {
            auth_user: "ups-01",
            ..target()
        };
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::AuthUser, Op::StartsWith, "ups-")],
        };
        assert!(m.matches(&t));
    }

    #[test]
    fn no_conditions_means_match_everything() {

        let m = Matcher::default();
        assert!(m.is_unconditional());
        assert!(m.matches(&target()));
    }

    #[test]
    fn matches_by_domain_suffix() {
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::FromDomain, Op::Equals, "idc.example.com")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn matches_by_user_prefix() {
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::FromUser, Op::StartsWith, "ups-")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn matches_chinese_subject_keyword() {

        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Subject, Op::Contains, "温度")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn case_insensitive_by_default() {

        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Subject, Op::Contains, "alert")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn case_sensitive_when_asked() {
        let mut c = cond(Field::Subject, Op::Contains, "alert");
        c.case_sensitive = true;
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![c],
        };
        assert!(!m.matches(&target()));
    }

    #[test]
    fn all_requires_every_condition() {
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![
                cond(Field::FromUser, Op::StartsWith, "ups-"),
                cond(Field::Subject, Op::Contains, "no such text"),
            ],
        };
        assert!(!m.matches(&target()));
    }

    #[test]
    fn any_requires_only_one() {
        let m = Matcher {
            logic: Logic::Any,
            conditions: vec![
                cond(Field::FromUser, Op::StartsWith, "nope-"),
                cond(Field::Subject, Op::Contains, "温度"),
            ],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn body_keyword() {
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Body, Op::Contains, "threshold")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn header_lookup_is_case_insensitive_on_the_name() {
        let headers = [("X-Device-Id".to_string(), "NAS-07".to_string())];
        let t = Target {
            headers: &headers,
            ..target()
        };
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(
                Field::Header("x-device-id".into()),
                Op::Equals,
                "nas-07",
            )],
        };
        assert!(m.matches(&t));
    }

    #[test]
    fn a_missing_header_is_empty_not_a_match() {
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Header("x-absent".into()), Op::Empty, "")],
        };
        assert!(m.matches(&target()));
    }

    #[test]
    fn negation_on_multivalued_rcpt_requires_all_to_miss() {

        let rcpt = ["a@x.com".to_string(), "b@y.com".to_string()];
        let t = Target {
            rcpt: &rcpt,
            ..target()
        };
        let not_a = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Rcpt, Op::NotEquals, "a@x.com")],
        };
        assert!(!not_a.matches(&t));

        let not_c = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Rcpt, Op::NotEquals, "c@z.com")],
        };
        assert!(not_c.matches(&t));
    }

    #[test]
    fn rcpt_positive_match_is_any() {
        let rcpt = ["a@x.com".to_string(), "b@y.com".to_string()];
        let t = Target {
            rcpt: &rcpt,
            ..target()
        };
        let m = Matcher {
            logic: Logic::All,
            conditions: vec![cond(Field::Rcpt, Op::Equals, "b@y.com")],
        };
        assert!(m.matches(&t));
    }

    #[test]
    fn glob_basics() {
        assert!(glob("ups-01@idc.example.com", "ups-*@idc.*"));
        assert!(glob("anything", "*"));
        assert!(glob("", "*"));
        assert!(glob("abc", "abc"));
        assert!(!glob("abc", "abd"));
        assert!(glob("abc", "a*c"));
        assert!(!glob("abc", "a*d"));
        assert!(glob("abc", "*c"));
        assert!(glob("abc", "a*"));
        assert!(!glob("abc", ""));
        assert!(glob("", ""));
    }

    #[test]
    fn glob_does_not_blow_up_on_pathological_patterns() {

        let hay = "a".repeat(64);
        assert!(!glob(&hay, &format!("{}b", "*a".repeat(24))));
    }

    #[test]
    fn glob_handles_multibyte() {
        assert!(glob("[ALERT] 温度过高", "*温度*"));
    }

    #[test]
    fn round_trips_through_json() {

        let m = Matcher {
            logic: Logic::Any,
            conditions: vec![
                cond(Field::FromDomain, Op::EndsWith, ".local"),
                cond(Field::Header("X-Prio".into()), Op::Matches, "hi*"),
            ],
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Matcher>(&json).unwrap(), m);
        assert!(
            json.contains("from_domain"),
            "field naming is part of the API: {json}"
        );
        assert!(
            json.contains("ends_with"),
            "op naming is part of the API: {json}"
        );
    }
}
