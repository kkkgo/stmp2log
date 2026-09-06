// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 256);
        out.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).as_bytes(),
        );
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());

        out.extend_from_slice(b"Connection: close\r\n");

        out.extend_from_slice(b"X-Content-Type-Options: nosniff\r\n");
        out.extend_from_slice(b"X-Frame-Options: DENY\r\n");
        out.extend_from_slice(b"Referrer-Policy: no-referrer\r\n");
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

pub fn json(status: u16, value: &serde_json::Value) -> Reply {
    Reply {
        status,
        headers: vec![
            (
                "Content-Type".into(),
                "application/json; charset=utf-8".into(),
            ),

            ("Cache-Control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

pub fn ok(value: &serde_json::Value) -> Reply {
    json(200, value)
}

pub fn error(status: u16, message: &str) -> Reply {
    json(status, &serde_json::json!({ "error": message }))
}

pub fn html(body: Vec<u8>, gzipped: bool, etag: &str) -> Reply {
    let mut r = Reply {
        status: 200,
        headers: vec![
            ("Content-Type".into(), "text/html; charset=utf-8".into()),

            ("Cache-Control".into(), "no-cache".into()),
            ("ETag".into(), etag.into()),
        ],
        body,
    };
    if gzipped {
        r.headers.push(("Content-Encoding".into(), "gzip".into()));
    }
    r
}

pub fn not_modified(etag: &str) -> Reply {
    Reply {
        status: 304,
        headers: vec![
            ("ETag".into(), etag.into()),
            ("Cache-Control".into(), "no-cache".into()),
        ],
        body: Vec::new(),
    }
}

pub fn redirect(location: &str) -> Reply {
    Reply {
        status: 302,
        headers: vec![("Location".into(), location.into())],
        body: Vec::new(),
    }
}

pub fn bytes(body: Vec<u8>, content_type: &str, filename: Option<&str>) -> Reply {
    let mut r = Reply {
        status: 200,
        headers: vec![
            ("Content-Type".into(), content_type.into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body,
    };
    if let Some(name) = filename {

        r.headers.push((
            "Content-Disposition".into(),
            format!(
                "attachment; filename=\"{}\"; filename*=UTF-8''{}",
                name.replace(['"', '\\', '\r', '\n'], "_"),
                percent(name)
            ),
        ));
    }
    r
}

fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(r: &Reply) -> String {
        String::from_utf8_lossy(&r.to_bytes()).into_owned()
    }

    #[test]
    fn a_json_reply_has_a_content_length_matching_its_body() {

        let r = ok(&serde_json::json!({"total": 3}));
        let raw = r.to_bytes();
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, body.len());
        assert_eq!(body, r#"{"total":3}"#);
    }

    #[test]
    fn multibyte_bodies_declare_byte_length_not_char_count() {
        let r = ok(&serde_json::json!({"subject": "温度告警"}));
        let raw = r.to_bytes();
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, body.len());
        assert!(declared > body.chars().count(), "the subject is multibyte");
    }

    #[test]
    fn errors_use_one_shape_the_frontend_can_rely_on() {
        let r = error(404, "no such message");
        assert_eq!(r.status, 404);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["error"],
            "no such message"
        );
        assert!(text_of(&r).starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn html_advertises_gzip_only_when_it_is_gzipped() {
        let plain = html(b"<h1>hi</h1>".to_vec(), false, "\"abc\"");
        assert!(!text_of(&plain).contains("Content-Encoding"));

        let gz = html(vec![0x1f, 0x8b], true, "\"abc\"");
        assert!(text_of(&gz).contains("Content-Encoding: gzip"));
    }

    #[test]
    fn every_reply_carries_the_hardening_headers() {

        for r in [ok(&serde_json::json!({})), error(500, "x"), redirect("/x")] {
            let t = text_of(&r);
            assert!(t.contains("X-Frame-Options: DENY"), "{t}");
            assert!(t.contains("X-Content-Type-Options: nosniff"));
        }
    }

    #[test]
    fn list_responses_are_never_cached() {

        assert!(text_of(&ok(&serde_json::json!([]))).contains("Cache-Control: no-store"));
    }

    #[test]
    fn the_page_uses_no_cache_so_etags_can_save_the_transfer() {
        let t = text_of(&html(b"x".to_vec(), false, "\"e1\""));
        assert!(t.contains("Cache-Control: no-cache"));
        assert!(t.contains("ETag: \"e1\""));
    }

    #[test]
    fn a_304_carries_no_body() {
        let r = not_modified("\"e1\"");
        assert!(r.body.is_empty());
        assert!(text_of(&r).contains("Content-Length: 0"));
    }

    #[test]
    fn attachment_filenames_survive_chinese_and_quotes() {
        let r = bytes(b"raw".to_vec(), "message/rfc822", Some("温度告警\".eml"));
        let t = text_of(&r);
        assert!(t.contains("filename*=UTF-8''%E6%B8%A9%E5%BA%A6"), "{t}");
        assert!(
            !t.lines()
                .any(|l| l.starts_with("Content-Disposition") && l.matches('"').count() > 2),
            "an unescaped quote would let the filename break out of the header: {t}"
        );
    }

    #[test]
    fn a_filename_cannot_inject_extra_headers() {

        let r = bytes(b"x".to_vec(), "text/plain", Some("evil\r\nX-Injected: yes"));
        let t = text_of(&r);
        assert!(!t.contains("X-Injected: yes\r\n"), "{t}");
    }
}
