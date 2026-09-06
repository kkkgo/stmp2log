// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_WEB_PATH: &str = "stmp2log";

pub const DEFAULT_DATA: &str = "./data";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub stmp_listen: Option<SocketAddr>,

    pub stmp_tls_listen: Option<SocketAddr>,
    pub data: PathBuf,

    pub web_listen: Option<SocketAddr>,

    pub web_pass: String,

    pub web_path: String,

    pub push_url: String,

    pub stmp_hostname: String,

    pub stmp_user: String,
    pub stmp_pass: String,

    pub stmp_maxsize: usize,

    pub max_entries: usize,
    pub max_days: u32,
    pub keep_raw: bool,
    pub keep_attachments: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stmp_listen: None,
            stmp_tls_listen: None,
            data: PathBuf::from(DEFAULT_DATA),
            web_listen: None,
            web_pass: String::new(),
            web_path: DEFAULT_WEB_PATH.into(),
            push_url: String::new(),
            stmp_hostname: default_hostname(),
            stmp_user: String::new(),
            stmp_pass: String::new(),
            stmp_maxsize: 10 * 1024 * 1024,

            max_entries: 5000,
            max_days: 0,
            keep_raw: false,
            keep_attachments: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub max_entries: usize,
    pub max_days: u32,
    pub keep_raw: bool,
    pub keep_attachments: bool,
}

impl Settings {
    #[cfg(test)]
    pub fn default_for_test() -> Self {
        Config::default().settings()
    }

    pub fn retention(&self) -> s2l_store::Retention {
        s2l_store::Retention {
            max_entries: self.max_entries,
            max_days: self.max_days,
        }
    }

    pub fn as_ini(&self) -> Vec<(&'static str, String)> {
        vec![
            ("max_entries", self.max_entries.to_string()),
            ("max_days", self.max_days.to_string()),
            ("keep_raw", bool_to_ini(self.keep_raw)),
            ("keep_attachments", bool_to_ini(self.keep_attachments)),
        ]
    }
}

impl Config {
    pub fn settings(&self) -> Settings {
        Settings {
            max_entries: self.max_entries,
            max_days: self.max_days,
            keep_raw: self.keep_raw,
            keep_attachments: self.keep_attachments,
        }
    }
}

fn default_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "stmp2log".into())
}

fn bool_to_ini(b: bool) -> String {
    if b { "1".into() } else { "0".into() }
}

#[derive(Debug)]
pub struct Parsed {
    pub config: Config,
    pub warnings: Vec<String>,
}

pub fn parse(text: &str) -> Parsed {
    let mut cfg = Config::default();
    let mut warnings = Vec::new();

    let mut bare: Vec<(&'static str, u16)> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let lineno = lineno + 1;

        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            warnings.push(format!("line {lineno}: no '=' in {line:?}, ignored"));
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = strip_inline_comment(value);

        match key.as_str() {
            "stmp_listen" => set_listen(
                &mut cfg.stmp_listen,
                value,
                lineno,
                "stmp_listen",
                &mut warnings,
                &mut bare,
            ),
            "stmp_tls_listen" => set_listen(
                &mut cfg.stmp_tls_listen,
                value,
                lineno,
                "stmp_tls_listen",
                &mut warnings,
                &mut bare,
            ),
            "web_listen" => set_listen(
                &mut cfg.web_listen,
                value,
                lineno,
                "web_listen",
                &mut warnings,
                &mut bare,
            ),

            "data" => {
                cfg.data = PathBuf::from(if value.is_empty() {
                    DEFAULT_DATA
                } else {
                    value
                });
            }
            "web_pass" => cfg.web_pass = value.to_string(),
            "web_path" => {
                cfg.web_path = if value.is_empty() {
                    DEFAULT_WEB_PATH.into()
                } else {
                    value.to_string()
                };
            }
            "push_url" => cfg.push_url = value.trim_end_matches('/').to_string(),
            "stmp_hostname" => {
                if !value.is_empty() {
                    cfg.stmp_hostname = value.to_string();
                }
            }
            "stmp_user" => cfg.stmp_user = value.to_string(),
            "stmp_pass" => cfg.stmp_pass = value.to_string(),
            "stmp_maxsize" => match parse_size(value) {
                Some(n) => cfg.stmp_maxsize = n,
                None => warnings.push(format!(
                    "line {lineno}: stmp_maxsize {value:?} is not a size, keeping {}",
                    cfg.stmp_maxsize
                )),
            },
            "max_entries" => match value.parse::<usize>() {
                Ok(n) if n > 0 => cfg.max_entries = n,
                _ => warnings.push(format!(
                    "line {lineno}: max_entries {value:?} must be a positive number, keeping {}",
                    cfg.max_entries
                )),
            },
            "max_days" => match value.parse::<u32>() {
                Ok(n) => cfg.max_days = n,
                _ => warnings.push(format!(
                    "line {lineno}: max_days {value:?} is not a number, keeping {}",
                    cfg.max_days
                )),
            },
            "keep_raw" => cfg.keep_raw = parse_bool(value),
            "keep_attachments" => cfg.keep_attachments = parse_bool(value),
            other => {
                warnings.push(format!("line {lineno}: unknown setting {other:?}, ignored"));
            }
        }
    }

    resolve_bare_ports(&mut cfg, &bare, &mut warnings);

    Parsed {
        config: cfg,
        warnings,
    }
}

fn resolve_bare_ports(cfg: &mut Config, bare: &[(&str, u16)], warnings: &mut Vec<String>) {
    for (name, port) in bare {
        let inherited = match *name {
            "stmp_tls_listen" => cfg.stmp_listen.map(|a| a.ip()),
            _ => None,
        };
        let ip = inherited.unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
        let addr = SocketAddr::new(ip, *port);
        match *name {
            "stmp_listen" => cfg.stmp_listen = Some(addr),
            "stmp_tls_listen" => cfg.stmp_tls_listen = Some(addr),
            "web_listen" => cfg.web_listen = Some(addr),
            _ => continue,
        }
        warnings.push(if inherited.is_some() {
            format!("{name} has no address; using {addr} to match stmp_listen")
        } else {
            format!("{name} has no address; assuming {addr}")
        });
    }
}

fn strip_inline_comment(value: &str) -> &str {
    let cut = value.find(['#', ';']).unwrap_or(value.len());
    value[..cut].trim().trim_matches(['"', '\''])
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn set_listen(
    slot: &mut Option<SocketAddr>,
    value: &str,
    lineno: usize,
    name: &'static str,
    warnings: &mut Vec<String>,
    bare: &mut Vec<(&'static str, u16)>,
) {
    if value.is_empty() {
        *slot = None;
        return;
    }
    if let Ok(a) = value.parse::<SocketAddr>() {
        *slot = Some(a);
        return;
    }

    if let Ok(port) = value.parse::<u16>() {
        bare.push((name, port));
        return;
    }

    let hint = if value.matches(':').count() > 1 && !value.contains('[') {
        "  (IPv6 needs brackets, e.g. [::]:25)"
    } else {
        ""
    };
    warnings.push(format!(
        "line {lineno}: {name}={value:?} is not an address:port, this listener stays off{hint}"
    ));
    *slot = None;
}

fn parse_size(value: &str) -> Option<usize> {
    let v = value.trim().to_ascii_lowercase();
    let v = v.strip_suffix('b').unwrap_or(&v).trim();
    let (num, mult) = match v.strip_suffix(['k', 'm', 'g']) {
        Some(rest) => {
            let m = match v.chars().last()? {
                'k' => 1024,
                'm' => 1024 * 1024,
                _ => 1024 * 1024 * 1024,
            };
            (rest.trim(), m)
        }
        None => (v, 1),
    };
    num.parse::<usize>().ok().map(|n| n * mult)
}

pub fn load(path: &Path) -> Parsed {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(e) => Parsed {
            config: Config::default(),
            warnings: vec![format!(
                "could not read {}: {e}; falling back to built-in defaults",
                path.display()
            )],
        },
    }
}

pub fn update(path: &Path, changes: &[(&str, String)]) -> std::io::Result<()> {
    let original = std::fs::read_to_string(path).unwrap_or_default();

    let nl = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let mut seen: Vec<&str> = Vec::new();
    let mut out: Vec<String> = Vec::new();

    for raw in original.lines() {
        let trimmed = raw.trim_start_matches('\u{feff}').trim();
        let mut replaced = None;
        if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(';') {
            if let Some((key, rest)) = trimmed.split_once('=') {
                let key = key.trim().to_ascii_lowercase();
                if let Some((name, value)) = changes.iter().find(|(n, _)| *n == key) {
                    let comment = rest
                        .find(['#', ';'])
                        .map(|i| format!(" {}", rest[i..].trim_end()))
                        .unwrap_or_default();
                    seen.push(name);
                    replaced = Some(format!("{name}={value}{comment}"));
                }
            }
        }
        out.push(replaced.unwrap_or_else(|| raw.to_string()));
    }

    let missing: Vec<&(&str, String)> = changes.iter().filter(|(n, _)| !seen.contains(n)).collect();
    if !missing.is_empty() {
        if out.last().is_some_and(|l| !l.trim().is_empty()) {
            out.push(String::new());
        }
        out.push("# 由 Web 界面写入 / written by the web UI".into());
        for (name, value) in missing {
            out.push(format!("{name}={value}"));
        }
    }

    let mut text = out.join(nl);
    text.push_str(nl);

    let tmp = path.with_extension("ini.tmp");
    std::fs::write(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Option<SocketAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn parses_the_documented_example_verbatim() {
        let p = parse(
            "stmp_listen=0.0.0.0:25 #stmp监听端口，为空的时候不启动stmp监听\n\
             data=./data #数据目录，为空默认值./data\n\
             # 服务端配置，端口为空的时候不开启web服务\n\
             web_listen=0.0.0.0:8025 #web服务端端口\n\
             web_pass=admin #web服务密码，为空的时候无密码登录\n\
             web_path=stmp2log # 后台url服务路径，为空默认为stmp2log\n\
             \n\
             # 推送到另一个stmp2log服务\n\
             push_url=http://stmp.example.com:8025/stmp2log\n",
        );
        assert_eq!(p.config.stmp_listen, addr("0.0.0.0:25"));
        assert_eq!(p.config.data, PathBuf::from("./data"));
        assert_eq!(p.config.web_listen, addr("0.0.0.0:8025"));
        assert_eq!(p.config.web_pass, "admin");
        assert_eq!(p.config.web_path, "stmp2log");
        assert_eq!(p.config.push_url, "http://stmp.example.com:8025/stmp2log");
        assert!(p.warnings.is_empty(), "warnings: {:?}", p.warnings);
    }

    #[test]
    fn an_empty_listen_disables_that_listener() {
        let p = parse("stmp_listen=\nweb_listen=\n");
        assert_eq!(p.config.stmp_listen, None);
        assert_eq!(p.config.web_listen, None);
    }

    #[test]
    fn empty_data_and_web_path_fall_back_to_their_defaults() {
        let p = parse("data=\nweb_path=\n");
        assert_eq!(p.config.data, PathBuf::from(DEFAULT_DATA));
        assert_eq!(p.config.web_path, DEFAULT_WEB_PATH);
    }

    #[test]
    fn an_empty_password_is_allowed_and_means_no_login() {
        let p = parse("web_listen=0.0.0.0:8025\nweb_pass=\n");
        assert_eq!(p.config.web_listen, addr("0.0.0.0:8025"));
        assert!(p.config.web_pass.is_empty());
        assert!(
            p.warnings.is_empty(),
            "this must not warn: {:?}",
            p.warnings
        );
    }

    #[test]
    fn a_bare_port_is_accepted_with_a_warning() {
        let p = parse("stmp_listen=25\n");
        assert_eq!(p.config.stmp_listen, addr("0.0.0.0:25"));
        assert!(p.warnings.iter().any(|w| w.contains("assuming 0.0.0.0:25")));
    }

    #[test]
    fn a_bare_tls_port_inherits_the_address_from_stmp_listen() {
        let p = parse("stmp_listen=10.20.0.5:25\nstmp_tls_listen=465\n");
        assert_eq!(p.config.stmp_tls_listen, addr("10.20.0.5:465"));
        assert!(
            p.warnings.iter().any(|w| w.contains("match stmp_listen")),
            "warnings: {:?}",
            p.warnings
        );
    }

    #[test]
    fn the_tls_port_inherits_a_wildcard_too() {
        let p = parse("stmp_listen=0.0.0.0:25\nstmp_tls_listen=465\n");
        assert_eq!(p.config.stmp_tls_listen, addr("0.0.0.0:465"));
    }

    #[test]
    fn inheritance_does_not_depend_on_the_order_of_the_lines() {
        let p = parse("stmp_tls_listen=465\nstmp_listen=127.0.0.1:25\n");
        assert_eq!(p.config.stmp_tls_listen, addr("127.0.0.1:465"));
    }

    #[test]
    fn an_explicit_tls_address_is_left_alone() {
        let p = parse("stmp_listen=10.20.0.5:25\nstmp_tls_listen=0.0.0.0:465\n");
        assert_eq!(p.config.stmp_tls_listen, addr("0.0.0.0:465"));
    }

    #[test]
    fn a_bare_tls_port_without_stmp_listen_falls_back_to_the_wildcard() {
        let p = parse("stmp_tls_listen=465\n");
        assert_eq!(p.config.stmp_tls_listen, addr("0.0.0.0:465"));
    }

    #[test]
    fn a_bare_web_port_does_not_inherit_the_smtp_address() {
        let p = parse("stmp_listen=127.0.0.1:25\nweb_listen=8025\n");
        assert_eq!(p.config.web_listen, addr("0.0.0.0:8025"));
    }

    #[test]
    fn ipv6_needs_brackets_and_says_so() {
        assert_eq!(
            parse("stmp_listen=[::]:25\n").config.stmp_listen,
            addr("[::]:25")
        );
        let p = parse("stmp_listen=::1:25\n");
        assert_eq!(p.config.stmp_listen, None);
        assert!(
            p.warnings.iter().any(|w| w.contains("brackets")),
            "warnings: {:?}",
            p.warnings
        );
    }

    #[test]
    fn tls_listener_is_off_unless_asked_for() {
        assert_eq!(parse("").config.stmp_tls_listen, None);
        assert_eq!(
            parse("stmp_tls_listen=0.0.0.0:465\n")
                .config
                .stmp_tls_listen,
            addr("0.0.0.0:465")
        );
    }

    #[test]
    fn retention_settings_come_from_the_ini() {
        let p = parse("max_entries=1234\nmax_days=7\nkeep_raw=1\nkeep_attachments=yes\n");
        assert_eq!(p.config.max_entries, 1234);
        assert_eq!(p.config.max_days, 7);
        assert!(p.config.keep_raw);
        assert!(p.config.keep_attachments);
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn booleans_accept_the_spellings_people_actually_write() {
        for yes in ["1", "true", "TRUE", "yes", "on"] {
            assert!(parse(&format!("keep_raw={yes}\n")).config.keep_raw, "{yes}");
        }
        for no in ["0", "false", "no", "off", ""] {
            assert!(
                !parse(&format!("keep_raw={no}\n")).config.keep_raw,
                "{no:?}"
            );
        }
    }

    #[test]
    fn a_zero_max_entries_is_refused_rather_than_deleting_everything() {
        let p = parse("max_entries=0\n");
        assert_eq!(p.config.max_entries, 5000);
        assert!(p.warnings.iter().any(|w| w.contains("max_entries")));
    }

    #[test]
    fn an_unknown_key_warns_but_does_not_stop_the_service() {
        let p = parse("stmp_listen=0.0.0.0:25\nweb_prot=8025\n");
        assert_eq!(p.config.stmp_listen, addr("0.0.0.0:25"));
        assert!(p.warnings.iter().any(|w| w.contains("web_prot")));
    }

    #[test]
    fn strips_the_windows_notepad_bom() {
        let p = parse("\u{feff}stmp_listen=0.0.0.0:2525\n");
        assert_eq!(p.config.stmp_listen, addr("0.0.0.0:2525"));
    }

    #[test]
    fn accepts_crlf_line_endings() {
        let p = parse("stmp_listen=0.0.0.0:2525\r\nweb_path=x\r\n");
        assert_eq!(p.config.stmp_listen, addr("0.0.0.0:2525"));
        assert_eq!(
            p.config.web_path, "x",
            "a stray CR would end up inside the value"
        );
    }

    #[test]
    fn quotes_and_whitespace_are_trimmed() {
        let p = parse("  web_pass = \"p@ss word\"  \ndata='/var/lib/stmp2log'\n");
        assert_eq!(p.config.web_pass, "p@ss word");
        assert_eq!(p.config.data, PathBuf::from("/var/lib/stmp2log"));
    }

    #[test]
    fn a_password_containing_a_hash_is_cut_at_the_comment() {
        let p = parse("web_pass=abc#def\n");
        assert_eq!(p.config.web_pass, "abc");
    }

    #[test]
    fn push_url_loses_its_trailing_slash() {
        let p = parse("push_url=http://h:8025/stmp2log/\n");
        assert_eq!(p.config.push_url, "http://h:8025/stmp2log");
    }

    #[test]
    fn maxsize_accepts_suffixes() {
        assert_eq!(
            parse("stmp_maxsize=1048576\n").config.stmp_maxsize,
            1_048_576
        );
        assert_eq!(parse("stmp_maxsize=1M\n").config.stmp_maxsize, 1_048_576);
        assert_eq!(parse("stmp_maxsize=512k\n").config.stmp_maxsize, 524_288);
        assert_eq!(
            parse("stmp_maxsize=2MB\n").config.stmp_maxsize,
            2 * 1_048_576
        );
    }

    #[test]
    fn a_missing_file_still_yields_a_runnable_default() {
        let p = load(Path::new("/nonexistent/stmp2log.ini"));
        assert_eq!(p.config.data, PathBuf::from(DEFAULT_DATA));
        assert_eq!(p.config.web_path, DEFAULT_WEB_PATH);
        assert!(!p.warnings.is_empty());
    }

    fn tmpfile(tag: &str, body: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "s2l-ini-{tag}-{}.ini",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn update_preserves_comments_order_and_blank_lines() {
        let src = "# 我的配置\n\
                   stmp_listen=0.0.0.0:25 #stmp监听端口\n\
                   \n\
                   max_entries=5000 # 最多保留\n\
                   web_pass=admin\n";
        let p = tmpfile("keep", src);
        update(&p, &[("max_entries", "999".into())]).unwrap();
        let out = std::fs::read_to_string(&p).unwrap();

        assert!(out.contains("# 我的配置"));
        assert!(out.contains("stmp_listen=0.0.0.0:25 #stmp监听端口"));
        assert!(out.contains("max_entries=999 # 最多保留"), "got:\n{out}");
        assert!(out.contains("web_pass=admin"));
        assert!(out.contains("\n\n"), "the blank line must survive");
        assert_eq!(parse(&out).config.max_entries, 999);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn update_appends_keys_that_are_not_there_yet() {
        let p = tmpfile("append", "web_pass=admin\n");
        update(
            &p,
            &[("max_entries", "77".into()), ("keep_raw", "1".into())],
        )
        .unwrap();
        let out = std::fs::read_to_string(&p).unwrap();
        let cfg = parse(&out).config;
        assert_eq!(cfg.max_entries, 77);
        assert!(cfg.keep_raw);
        assert_eq!(cfg.web_pass, "admin", "existing keys must survive");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn update_round_trips_every_web_editable_setting() {
        let p = tmpfile("roundtrip", "stmp_listen=0.0.0.0:25\n");
        let want = Settings {
            max_entries: 123,
            max_days: 45,
            keep_raw: true,
            keep_attachments: true,
        };
        update(&p, &want.as_ini()).unwrap();
        let got = parse(&std::fs::read_to_string(&p).unwrap())
            .config
            .settings();
        assert_eq!(got, want);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn update_keeps_crlf_files_as_crlf() {
        let p = tmpfile("crlf", "max_entries=1\r\nweb_pass=x\r\n");
        update(&p, &[("max_entries", "2".into())]).unwrap();
        let out = std::fs::read(&p).unwrap();
        assert!(out.windows(2).any(|w| w == b"\r\n"));
        assert!(
            !String::from_utf8_lossy(&out).contains("\n\r"),
            "line endings got mangled"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn update_on_a_missing_file_creates_one() {
        let p = std::env::temp_dir().join(format!(
            "s2l-ini-new-{}.ini",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        update(&p, &[("max_entries", "5".into())]).unwrap();
        assert_eq!(
            parse(&std::fs::read_to_string(&p).unwrap())
                .config
                .max_entries,
            5
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn update_does_not_touch_a_commented_out_key() {
        let p = tmpfile("commented", "# max_entries=1\nweb_pass=x\n");
        update(&p, &[("max_entries", "999".into())]).unwrap();
        let out = std::fs::read_to_string(&p).unwrap();
        assert!(out.contains("# max_entries=1"), "got:\n{out}");
        assert!(out.contains("max_entries=999"));
        assert_eq!(parse(&out).config.max_entries, 999);
        std::fs::remove_file(&p).ok();
    }
}
