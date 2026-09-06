// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use crate::word;

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Addr {

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,

    pub addr: String,
}

impl Addr {

    pub fn user(&self) -> &str {
        match self.addr.rsplit_once('@') {
            Some((u, _)) => u,
            None => &self.addr,
        }
    }

    pub fn domain(&self) -> &str {
        self.addr.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
    }
}

pub fn parse_one(raw: &[u8]) -> Addr {
    let decoded = word::decode(raw);
    let s = decoded.trim();

    if let Some(open) = s.rfind('<') {
        if let Some(close) = s[open..].find('>') {
            let addr = &s[open + 1..open + close];
            let name = s[..open].trim().trim_matches('"').trim();
            return Addr {
                name: name.to_string(),
                addr: normalize(addr),
            };
        }
    }

    if let Some(open) = s.find('(') {
        if s.ends_with(')') && s[..open].contains('@') {
            return Addr {
                name: s[open + 1..s.len() - 1].trim().to_string(),
                addr: normalize(&s[..open]),
            };
        }
    }

    Addr {
        name: String::new(),
        addr: normalize(s),
    }
}

pub fn parse_list(raw: &[u8]) -> Vec<Addr> {
    let mut out = Vec::new();
    let mut depth_angle = 0i32;
    let mut in_quote = false;
    let mut start = 0usize;

    for (i, &b) in raw.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'<' if !in_quote => depth_angle += 1,
            b'>' if !in_quote => depth_angle -= 1,
            b',' | b';' if !in_quote && depth_angle <= 0 => {
                push_if_useful(&mut out, &raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    push_if_useful(&mut out, &raw[start..]);
    out
}

fn push_if_useful(out: &mut Vec<Addr>, slice: &[u8]) {
    if slice.iter().any(|b| !b.is_ascii_whitespace()) {
        let a = parse_one(slice);
        if !a.addr.is_empty() {
            out.push(a);
        }
    }
}

fn normalize(s: &str) -> String {
    let t = s.trim().trim_matches(['<', '>', '"', '\'']).trim();
    match t.rsplit_once('@') {
        Some((user, domain)) => format!("{user}@{}", domain.to_ascii_lowercase()),
        None => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Addr {
        parse_one(s.as_bytes())
    }

    #[test]
    fn plain_address() {
        let x = a("alarm@nas.local");
        assert_eq!(x.addr, "alarm@nas.local");
        assert_eq!(x.name, "");
        assert_eq!(x.user(), "alarm");
        assert_eq!(x.domain(), "nas.local");
    }

    #[test]
    fn angle_bracket_form() {
        let x = a("UPS Monitor <ups@idc.example.com>");
        assert_eq!(x.addr, "ups@idc.example.com");
        assert_eq!(x.name, "UPS Monitor");
    }

    #[test]
    fn quoted_display_name_is_unwrapped() {
        assert_eq!(a("\"UPS Monitor\" <ups@a.com>").name, "UPS Monitor");
    }

    #[test]
    fn encoded_display_name_is_decoded() {
        let x = a("=?UTF-8?B?5rip5bqm?= <t@a.com>");
        assert_eq!(x.name, "温度");
        assert_eq!(x.addr, "t@a.com");
    }

    #[test]
    fn domain_is_lowercased_but_user_is_not() {

        let x = a("Alarm@NAS.LOCAL");
        assert_eq!(x.addr, "Alarm@nas.local");
        assert_eq!(x.user(), "Alarm");
        assert_eq!(x.domain(), "nas.local");
    }

    #[test]
    fn angle_brackets_inside_display_name() {

        let x = a("\"<admin>\" <real@host.com>");
        assert_eq!(x.addr, "real@host.com");
    }

    #[test]
    fn paren_comment_form() {
        let x = a("ups@idc.com (UPS Monitor)");
        assert_eq!(x.addr, "ups@idc.com");
        assert_eq!(x.name, "UPS Monitor");
    }

    #[test]
    fn garbage_still_yields_something() {

        let x = a("device01");
        assert_eq!(x.addr, "device01");
        assert_eq!(x.user(), "device01");
        assert_eq!(x.domain(), "");
    }

    #[test]
    fn list_splits_on_commas() {
        let l = parse_list(b"a@x.com, b@y.com; c@z.com");
        assert_eq!(l.len(), 3);
        assert_eq!(l[2].addr, "c@z.com");
    }

    #[test]
    fn list_keeps_quoted_commas_together() {
        let l = parse_list(b"\"Lastname, Firstname\" <a@x.com>, b@y.com");
        assert_eq!(l.len(), 2, "a comma inside quotes is not a separator");
        assert_eq!(l[0].addr, "a@x.com");
        assert_eq!(l[0].name, "Lastname, Firstname");
    }

    #[test]
    fn list_ignores_empty_entries() {
        assert_eq!(parse_list(b"a@x.com,,  ,b@y.com").len(), 2);
        assert!(parse_list(b"").is_empty());
    }
}
