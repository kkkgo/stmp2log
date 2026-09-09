// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::path::{Path, PathBuf};

use s2l_store::{Matcher, Target};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub id: u32,
    pub name: String,

    #[serde(default)]
    pub color: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    #[default]
    Off,

    Whitelist,

    Blacklist,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Access {
    #[serde(default)]
    pub mode: AccessMode,
    #[serde(default)]
    pub matcher: Matcher,
}

impl Access {
    pub fn accepts(&self, t: &Target<'_>) -> bool {
        match self.mode {
            AccessMode::Off => true,

            AccessMode::Whitelist => self.matcher.is_unconditional() || self.matcher.matches(t),
            AccessMode::Blacklist => self.matcher.is_unconditional() || !self.matcher.matches(t),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelCfg {
    #[serde(default)]
    pub id: u32,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(flatten)]
    pub channel: s2l_notify::Channel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotifyRule {
    pub id: u32,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,

    #[serde(default)]
    pub matcher: Matcher,

    #[serde(default)]
    pub channels: Vec<u32>,
    #[serde(default = "default_title_tpl")]
    pub title: String,
    #[serde(default = "default_body_tpl")]
    pub body: String,

    #[serde(default)]
    pub cooldown: u32,

    #[serde(default)]
    pub email_to: Vec<String>,
}

impl NotifyRule {
    pub fn with_recipients<'a>(
        &self,
        ch: &'a s2l_notify::Channel,
    ) -> std::borrow::Cow<'a, s2l_notify::Channel> {
        if self.email_to.is_empty() {
            return std::borrow::Cow::Borrowed(ch);
        }
        let mut copy = ch.clone();
        apply_recipients(&mut copy, &self.email_to);
        std::borrow::Cow::Owned(copy)
    }
}

pub fn apply_recipients(ch: &mut s2l_notify::Channel, to: &[String]) {
    if to.is_empty() {
        return;
    }
    if let s2l_notify::Channel::Email { to: dst, .. } = ch {
        *dst = to.to_vec();
    }
}

fn yes() -> bool {
    true
}

fn default_title_tpl() -> String {
    "{{subject}}".into()
}

fn default_body_tpl() -> String {
    "{{from}}\n{{body}}".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub access: Access,
    #[serde(default)]
    pub channels: Vec<ChannelCfg>,
    #[serde(default)]
    pub rules: Vec<NotifyRule>,

    #[serde(default = "one")]
    pub next_id: u32,
}

fn one() -> u32 {
    1
}

impl Default for State {
    fn default() -> Self {
        Self {
            groups: Vec::new(),
            access: Access::default(),
            channels: Vec::new(),
            rules: Vec::new(),
            next_id: 1,
        }
    }
}

impl State {
    pub fn path(data: &Path) -> PathBuf {
        data.join("state.json")
    }

    pub fn load(data: &Path) -> (Self, Vec<String>) {
        let path = Self::path(data);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Self::default(), vec![]),
            Err(e) => {
                return (
                    Self::default(),
                    vec![format!("could not read {}: {e}", path.display())],
                );
            }
        };
        match serde_json::from_str::<State>(&text) {
            Ok(s) => (s, vec![]),
            Err(e) => {
                let backup = path.with_extension("json.broken");
                let _ = std::fs::rename(&path, &backup);
                (
                    Self::default(),
                    vec![format!(
                        "{} is not valid state ({e}); it was moved to {} and defaults are in use",
                        path.display(),
                        backup.display()
                    )],
                )
            }
        }
    }

    pub fn save(&self, data: &Path) -> std::io::Result<()> {
        let path = Self::path(data);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, &text)?;
        std::fs::rename(&tmp, &path)
    }

    pub fn take_id(&mut self) -> u32 {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        id
    }

    pub fn classify(&self, t: &Target<'_>) -> Option<u32> {
        self.groups
            .iter()
            .find(|g| g.enabled && !g.matcher.is_unconditional() && g.matcher.matches(t))
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|g| g.enabled && g.matcher.is_unconditional())
            })
            .map(|g| g.id)
    }

    pub fn reorder_groups(&mut self, ids: &[u32]) {
        let mut rest = std::mem::take(&mut self.groups);
        for id in ids {
            if let Some(at) = rest.iter().position(|g| g.id == *id) {
                self.groups.push(rest.remove(at));
            }
        }
        self.groups.append(&mut rest);
    }

    pub fn group_name(&self, id: Option<u32>) -> String {
        id.and_then(|id| self.groups.iter().find(|g| g.id == id))
            .map(|g| g.name.clone())
            .unwrap_or_default()
    }

    pub fn channel(&self, id: u32) -> Option<&ChannelCfg> {
        self.channels.iter().find(|c| c.id == id)
    }
}

pub fn render(template: &str, vars: &Vars<'_>) -> String {
    let mut out = template.to_string();
    for (name, value) in [
        ("subject", vars.subject),
        ("from", vars.from),
        ("from_name", vars.from_name),
        ("from_user", vars.from_user),
        ("from_domain", vars.from_domain),
        ("body", vars.body),
        ("time", vars.time),
        ("group", vars.group),
        ("peer", vars.peer),
    ] {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
        out = out.replace(&format!("{{{{ {name} }}}}"), value);
    }
    out
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Vars<'a> {
    pub subject: &'a str,
    pub from: &'a str,
    pub from_name: &'a str,
    pub from_user: &'a str,
    pub from_domain: &'a str,
    pub body: &'a str,
    pub time: &'a str,
    pub group: &'a str,
    pub peer: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2l_store::{Condition, Field, Logic, Op};

    fn cond(field: Field, op: Op, value: &str) -> Condition {
        Condition {
            field,
            op,
            value: value.into(),
            case_sensitive: false,
        }
    }

    fn matcher(c: Condition) -> Matcher {
        Matcher {
            logic: Logic::All,
            conditions: vec![c],
        }
    }

    fn target() -> Target<'static> {
        Target {
            from: "ups-01@idc.example.com",
            from_user: "ups-01",
            from_domain: "idc.example.com",
            from_name: "UPS Monitor",
            subject: "[ALERT] 温度过高",
            body: "Sensor 3 reports 48C",
            rcpt: &[],
            peer_ip: "10.20.0.7",
            group: "",
            auth_user: "ups-01",
            headers: &[],
        }
    }

    #[test]
    fn groups_reorder_to_the_given_sequence() {
        let mut st = State {
            groups: vec![
                group(1, "ups", Matcher::default()),
                group(2, "nas", Matcher::default()),
                group(3, "fw", Matcher::default()),
            ],
            ..Default::default()
        };
        st.reorder_groups(&[3, 1, 2]);
        assert_eq!(ids(&st), vec![3, 1, 2]);
    }

    #[test]
    fn a_group_missing_from_the_order_keeps_its_place_at_the_end() {
        let mut st = State {
            groups: vec![
                group(1, "ups", Matcher::default()),
                group(2, "nas", Matcher::default()),
                group(3, "fw", Matcher::default()),
            ],
            ..Default::default()
        };

        st.reorder_groups(&[2, 1]);
        assert_eq!(ids(&st), vec![2, 1, 3]);
    }

    #[test]
    fn unknown_and_repeated_ids_are_ignored() {
        let mut st = State {
            groups: vec![
                group(1, "ups", Matcher::default()),
                group(2, "nas", Matcher::default()),
            ],
            ..Default::default()
        };
        st.reorder_groups(&[2, 2, 99, 1]);
        assert_eq!(ids(&st), vec![2, 1]);
    }

    fn ids(st: &State) -> Vec<u32> {
        st.groups.iter().map(|g| g.id).collect()
    }

    fn group(id: u32, name: &str, m: Matcher) -> Group {
        Group {
            id,
            name: name.into(),
            color: String::new(),
            enabled: true,
            matcher: m,
        }
    }

    #[test]
    fn the_first_matching_group_wins() {
        let s = State {
            groups: vec![
                group(
                    1,
                    "UPS",
                    matcher(cond(Field::FromUser, Op::StartsWith, "ups-")),
                ),
                group(
                    2,
                    "IDC",
                    matcher(cond(Field::FromDomain, Op::EndsWith, "example.com")),
                ),
            ],
            ..Default::default()
        };
        assert_eq!(s.classify(&target()), Some(1));
    }

    #[test]
    fn an_unconditional_group_is_only_a_fallback() {
        let s = State {
            groups: vec![
                group(1, "Everything", Matcher::default()),
                group(
                    2,
                    "UPS",
                    matcher(cond(Field::FromUser, Op::StartsWith, "ups-")),
                ),
            ],
            ..Default::default()
        };
        assert_eq!(
            s.classify(&target()),
            Some(2),
            "a catch-all placed first must not swallow a specific match"
        );
    }

    #[test]
    fn an_unconditional_group_still_catches_the_rest() {
        let s = State {
            groups: vec![
                group(
                    1,
                    "UPS",
                    matcher(cond(Field::FromUser, Op::StartsWith, "nope-")),
                ),
                group(2, "Everything else", Matcher::default()),
            ],
            ..Default::default()
        };
        assert_eq!(s.classify(&target()), Some(2));
    }

    #[test]
    fn a_disabled_group_never_matches() {
        let mut g = group(
            1,
            "UPS",
            matcher(cond(Field::FromUser, Op::StartsWith, "ups-")),
        );
        g.enabled = false;
        let s = State {
            groups: vec![g],
            ..Default::default()
        };
        assert_eq!(s.classify(&target()), None);
    }

    #[test]
    fn mail_matching_nothing_is_ungrouped() {
        let s = State::default();
        assert_eq!(s.classify(&target()), None);
    }

    #[test]
    fn access_off_accepts_everything() {
        assert!(Access::default().accepts(&target()));
    }

    #[test]
    fn a_whitelist_only_accepts_matches() {
        let a = Access {
            mode: AccessMode::Whitelist,
            matcher: matcher(cond(Field::FromDomain, Op::EndsWith, "example.com")),
        };
        assert!(a.accepts(&target()));

        let a = Access {
            mode: AccessMode::Whitelist,
            matcher: matcher(cond(Field::FromDomain, Op::EndsWith, "other.net")),
        };
        assert!(!a.accepts(&target()));
    }

    #[test]
    fn a_blacklist_rejects_matches() {
        let a = Access {
            mode: AccessMode::Blacklist,
            matcher: matcher(cond(Field::FromUser, Op::StartsWith, "ups-")),
        };
        assert!(!a.accepts(&target()));
    }

    #[test]
    fn an_empty_whitelist_accepts_instead_of_dropping_everything() {
        let a = Access {
            mode: AccessMode::Whitelist,
            matcher: Matcher::default(),
        };
        assert!(a.accepts(&target()));
    }

    #[test]
    fn an_empty_blacklist_accepts_too() {
        let a = Access {
            mode: AccessMode::Blacklist,
            matcher: Matcher::default(),
        };
        assert!(a.accepts(&target()));
    }

    #[test]
    fn ids_are_never_reused() {
        let mut s = State::default();
        let a = s.take_id();
        let b = s.take_id();
        assert_ne!(a, b);
        assert!(b > a);

        s.next_id = 0;
        assert!(s.take_id() >= 1, "id 0 would collide with 'no group'");
    }

    #[test]
    fn templates_render_both_spacing_styles() {
        let vars = Vars {
            subject: "温度过高",
            from: "ups@idc.com",
            body: "48C",
            group: "UPS",
            ..Default::default()
        };
        assert_eq!(render("{{subject}}", &vars), "温度过高");
        assert_eq!(render("{{ subject }}", &vars), "温度过高");
        assert_eq!(
            render("[{{group}}] {{subject}}\n{{from}}: {{body}}", &vars),
            "[UPS] 温度过高\nups@idc.com: 48C"
        );
    }

    #[test]
    fn an_unknown_placeholder_is_left_alone() {
        let vars = Vars::default();
        assert_eq!(render("{{nonexistent}}", &vars), "{{nonexistent}}");
    }

    #[test]
    fn the_default_templates_produce_something_useful() {
        let vars = Vars {
            subject: "Disk failure",
            from: "nas@lan",
            body: "sda died",
            ..Default::default()
        };
        assert_eq!(render(&default_title_tpl(), &vars), "Disk failure");
        assert_eq!(render(&default_body_tpl(), &vars), "nas@lan\nsda died");
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut s = State::default();
        s.groups.push(group(
            1,
            "UPS",
            matcher(cond(Field::FromUser, Op::StartsWith, "ups-")),
        ));
        s.channels.push(ChannelCfg {
            id: 2,
            name: "手机".into(),
            enabled: true,
            channel: s2l_notify::Channel::Bark {
                endpoint: "https://api.day.app/KEY".into(),
                group: "stmp2log".into(),
                sound: String::new(),
                level: String::new(),
            },
        });
        s.rules.push(NotifyRule {
            id: 3,
            name: "全局".into(),
            enabled: true,
            matcher: Matcher::default(),
            channels: vec![2],
            title: default_title_tpl(),
            body: default_body_tpl(),
            cooldown: 60,
            email_to: vec!["ops@example.com".into()],
        });

        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<State>(&json).unwrap(), s);

        assert!(json.contains(r#""type":"bark""#), "{json}");
    }

    #[test]
    fn an_older_state_file_without_new_fields_still_loads() {
        let s: State = serde_json::from_str("{}").unwrap();
        assert_eq!(s.next_id, 1);
        assert_eq!(s.access.mode, AccessMode::Off);

        let c: ChannelCfg = serde_json::from_str(
            r#"{"name":"值班邮箱","type":"email","server":"smtp.qq.com","to":["a@b.c"]}"#,
        )
        .expect("a channel body without an id is still a channel");
        assert_eq!(c.id, 0, "the server assigns the real one");
        assert!(c.enabled, "and it defaults to on");

        let r: NotifyRule = serde_json::from_str(
            r#"{"id":1,"name":"old","matcher":{"logic":"all","conditions":[]},"channels":[2]}"#,
        )
        .unwrap();
        assert!(r.email_to.is_empty(), "an old rule means 'use the channel'");
    }

    fn email_channel() -> s2l_notify::Channel {
        s2l_notify::Channel::Email {
            server: "smtp.example.com".into(),
            port: 465,
            encryption: s2l_notify::EmailTls::Tls,
            username: "alerts@example.com".into(),
            password: "token".into(),
            from: String::new(),
            to: vec!["oncall@example.com".into()],
            skip_verify: false,
            mask_urls: true,
        }
    }

    fn rule_to(email_to: &[&str]) -> NotifyRule {
        NotifyRule {
            id: 1,
            name: "r".into(),
            enabled: true,
            matcher: Matcher::default(),
            channels: vec![1],
            title: default_title_tpl(),
            body: default_body_tpl(),
            cooldown: 0,
            email_to: email_to.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_rule_can_send_the_same_mailbox_channel_to_someone_else() {
        let ch = email_channel();
        let aimed = rule_to(&["boss@example.com", "ops@example.com"]).with_recipients(&ch);
        let s2l_notify::Channel::Email { to, username, .. } = aimed.as_ref() else {
            panic!("still an email channel");
        };
        assert_eq!(to, &["boss@example.com", "ops@example.com"]);
        assert_eq!(username, "alerts@example.com", "the login must not change");
    }

    #[test]
    fn a_rule_without_recipients_uses_the_channels_own() {
        let ch = email_channel();
        let aimed = rule_to(&[]).with_recipients(&ch);
        assert!(
            matches!(aimed, std::borrow::Cow::Borrowed(_)),
            "the common path must not copy the channel"
        );
        let s2l_notify::Channel::Email { to, .. } = aimed.as_ref() else {
            unreachable!()
        };
        assert_eq!(to, &["oncall@example.com"]);
    }

    #[test]
    fn recipients_on_a_rule_never_touch_the_other_channel_types() {
        let bark = s2l_notify::Channel::Bark {
            endpoint: "https://api.day.app/KEY".into(),
            group: String::new(),
            sound: String::new(),
            level: String::new(),
        };
        let aimed = rule_to(&["boss@example.com"]).with_recipients(&bark);
        assert_eq!(aimed.as_ref(), &bark);
    }

    #[test]
    fn saving_and_loading_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "s2l-state-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut s = State::default();
        s.groups.push(group(7, "G", Matcher::default()));
        s.save(&dir).unwrap();

        let (back, warnings) = State::load(&dir);
        assert!(warnings.is_empty());
        assert_eq!(back, s);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_state_file_is_set_aside_rather_than_blocking_startup() {
        let dir = std::env::temp_dir().join(format!(
            "s2l-state-bad-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(State::path(&dir), b"{ this is not json").unwrap();

        let (s, warnings) = State::load(&dir);
        assert_eq!(s, State::default());
        assert!(!warnings.is_empty());
        assert!(
            dir.join("state.json.broken").exists(),
            "the unreadable file must be kept for inspection, not silently discarded"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_state_file_is_not_a_warning() {
        let dir = std::env::temp_dir().join("s2l-state-absent-xyz");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::remove_file(State::path(&dir)).ok();
        let (s, warnings) = State::load(&dir);
        assert_eq!(s, State::default());
        assert!(warnings.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
