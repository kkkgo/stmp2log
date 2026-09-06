// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub mod auth;
pub mod gz;
pub mod respond;
pub mod router;
mod server;

pub use auth::{Auth, LoginError};
pub use respond::Reply;
pub use router::Route;
pub use server::serve;

pub struct StaticAsset {
    pub plain: Arc<Vec<u8>>,
    pub gzip: Arc<Vec<u8>>,
    pub etag: String,
}

impl StaticAsset {
    pub fn new(html: &[u8], placeholder: &str, base: &str) -> Self {
        let text = String::from_utf8_lossy(html);
        let injected = text.replace(placeholder, base).into_bytes();

        let etag = format!("\"{:08x}-{:x}\"", gz::crc32(&injected), injected.len());
        let gzip = gz::compress(&injected);
        Self {
            plain: Arc::new(injected),
            gzip: Arc::new(gzip),
            etag,
        }
    }
}

pub struct ApiReq {
    pub method: String,

    pub path: String,

    pub query: String,
    pub body: Vec<u8>,

    pub token: String,
    pub peer: SocketAddr,
}

impl ApiReq {
    pub fn param(&self, name: &str) -> Option<String> {
        for pair in self.query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if urldecode(k) == name {
                return Some(urldecode(v));
            }
        }
        None
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.body).map_err(|e| e.to_string())
    }

    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }
}

pub type ApiFuture = Pin<Box<dyn std::future::Future<Output = Reply> + Send>>;

pub trait Api: Send + Sync + 'static {
    fn call(&self, req: ApiReq) -> ApiFuture;
}

pub struct ServerConfig {
    pub bind: SocketAddr,

    pub base: String,
    pub asset: Arc<StaticAsset>,
    pub api: Arc<dyn Api>,

    pub auth: Arc<arc_swap::ArcSwap<Auth>>,

    pub events: Option<tokio::sync::broadcast::Sender<String>>,
}

pub fn normalize_base(webpath: &str) -> String {
    let t = webpath.trim().trim_matches('/');
    if t.is_empty() {
        String::new()
    } else {
        format!("/{t}")
    }
}

pub fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }

                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(query: &str) -> ApiReq {
        ApiReq {
            method: "GET".into(),
            path: "messages".into(),
            query: query.into(),
            body: Vec::new(),
            token: String::new(),
            peer: "10.0.0.1:1".parse().unwrap(),
        }
    }

    #[test]
    fn normalizes_every_way_a_user_might_write_the_path() {
        for input in [
            "stmp2log",
            "/stmp2log",
            "stmp2log/",
            "/stmp2log/",
            " /stmp2log/ ",
        ] {
            assert_eq!(normalize_base(input), "/stmp2log", "input {input:?}");
        }
        assert_eq!(normalize_base(""), "");
        assert_eq!(normalize_base("/"), "");
    }

    #[test]
    fn decodes_chinese_search_terms() {
        assert_eq!(urldecode("%E6%B8%A9%E5%BA%A6"), "温度");
        assert_eq!(
            req("subject=%E6%B8%A9%E5%BA%A6")
                .param("subject")
                .as_deref(),
            Some("温度")
        );
    }

    #[test]
    fn a_lone_percent_is_not_an_error() {
        assert_eq!(urldecode("50%"), "50%");
        assert_eq!(urldecode("%zz"), "%zz");
        assert_eq!(urldecode("a%2"), "a%2");
    }

    #[test]
    fn plus_means_space_in_a_query_string() {
        assert_eq!(
            req("q=disk+failure").param("q").as_deref(),
            Some("disk failure")
        );
    }

    #[test]
    fn missing_params_are_none_and_empty_ones_are_empty() {
        let r = req("a=1&b=&c");
        assert_eq!(r.param("a").as_deref(), Some("1"));
        assert_eq!(r.param("b").as_deref(), Some(""));
        assert_eq!(r.param("c").as_deref(), Some(""));
        assert_eq!(r.param("missing"), None);
    }

    #[test]
    fn a_value_containing_an_encoded_ampersand_survives() {
        assert_eq!(req("q=a%26b").param("q").as_deref(), Some("a&b"));
    }

    #[test]
    fn segments_split_the_path() {
        let mut r = req("");
        r.path = "messages/42/raw".into();
        assert_eq!(r.segments(), ["messages", "42", "raw"]);
        r.path = "settings".into();
        assert_eq!(r.segments(), ["settings"]);
    }

    #[test]
    fn the_base_placeholder_is_fully_substituted() {
        let a = StaticAsset::new(
            br#"<base href="__S2L_BASE__/"><script>fetch("api/messages")</script>"#,
            "__S2L_BASE__",
            "/stmp2log",
        );
        let html = String::from_utf8(a.plain.to_vec()).unwrap();
        assert!(html.contains(r#"<base href="/stmp2log/">"#));
        assert!(!html.contains("__S2L_BASE__"));
    }

    #[test]
    fn an_empty_base_still_yields_a_valid_href() {
        let a = StaticAsset::new(br#"<base href="__S2L_BASE__/">"#, "__S2L_BASE__", "");
        let html = String::from_utf8(a.plain.to_vec()).unwrap();
        assert!(html.contains(r#"<base href="/">"#), "got {html}");
    }

    #[test]
    fn the_etag_tracks_both_the_content_and_the_mount_path() {
        let src = br#"<base href="__B__/">"#;
        let one = StaticAsset::new(src, "__B__", "/one");
        let two = StaticAsset::new(src, "__B__", "/two");
        let other = StaticAsset::new(b"<html>different</html>", "__B__", "/one");

        assert_ne!(one.etag, two.etag, "changing webpath must force a refetch");
        assert_ne!(
            one.etag, other.etag,
            "changing the frontend must force a refetch"
        );
        assert_eq!(
            one.etag,
            StaticAsset::new(src, "__B__", "/one").etag,
            "the same input must yield a stable ETag"
        );
        assert!(one.etag.starts_with('"') && one.etag.ends_with('"'));
    }

    #[test]
    fn the_gzip_copy_decompresses_to_the_injected_bytes() {
        let a = StaticAsset::new(b"<html>hello</html>", "__B__", "/x");
        assert_eq!(gz::decompress(&a.gzip).unwrap(), *a.plain);
    }
}
