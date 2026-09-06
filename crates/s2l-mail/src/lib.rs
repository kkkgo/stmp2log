// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
pub mod addr;
pub mod charset;
pub mod date;
mod parse;
pub mod qp;
pub mod word;

pub use addr::Addr;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Mail {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<Addr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentMeta>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentMeta {
    pub filename: String,
    pub mime: String,

    pub size: usize,

    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub keep_attachments: bool,
}

impl Mail {
    pub fn from_addr(&self) -> &str {
        self.from.as_ref().map(|a| a.addr.as_str()).unwrap_or("")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse(raw: &[u8]) -> Mail {
    parse::parse(raw, Options::default())
}

pub fn parse_with(raw: &[u8], opts: Options) -> Mail {
    parse::parse(raw, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_alert() {
        let raw = b"From: alarm@nas.local\r\n\
                    To: log@stmp2log\r\n\
                    Subject: Disk failure\r\n\
                    Date: Tue, 2 Sep 2026 20:46:01 +0800\r\n\
                    \r\n\
                    /dev/sda has failed.\r\n";
        let m = parse(raw);
        assert_eq!(m.subject, "Disk failure");
        assert_eq!(m.from_addr(), "alarm@nas.local");
        assert_eq!(m.to[0].addr, "log@stmp2log");
        assert_eq!(m.date, Some(1788353161));
        assert!(m.text.contains("/dev/sda has failed."));
    }

    #[test]
    fn bare_lf_line_endings_still_parse() {
        let raw = b"Subject: Bare LF\nFrom: a@b.c\n\nbody here\n";
        let m = parse(raw);
        assert_eq!(m.subject, "Bare LF");
        assert!(m.text.contains("body here"), "text was {:?}", m.text);
    }

    #[test]
    fn folded_headers_are_rejoined() {
        let raw = b"Subject: a very long subject\r\n that got folded\r\n\r\nbody";
        assert_eq!(parse(raw).subject, "a very long subject that got folded");
    }

    #[test]
    fn gbk_subject_and_body() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"From: ups@idc.local\r\n");
        raw.extend_from_slice(b"Subject: =?GB2312?B?zsK2yLjmvq8=?=\r\n");
        raw.extend_from_slice(b"Content-Type: text/plain; charset=\"GB2312\"\r\n\r\n");
        raw.extend_from_slice(&[0xCE, 0xC2, 0xB6, 0xC8, 0xB9, 0xFD, 0xB8, 0xDF]);
        let m = parse(&raw);
        assert_eq!(m.subject, "温度告警");
        assert_eq!(m.text.trim(), "温度过高");
    }

    #[test]
    fn multipart_alternative_keeps_both_bodies() {
        let raw = b"Subject: Alert\r\n\
Content-Type: multipart/alternative; boundary=\"XYZ\"\r\n\
\r\n\
--XYZ\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain version\r\n\
--XYZ\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>html version</p>\r\n\
--XYZ--\r\n";
        let m = parse(raw);
        assert_eq!(m.text.trim(), "plain version");
        assert!(m.html.as_deref().unwrap().contains("html version"));
    }

    #[test]
    fn html_only_mail_gets_a_text_summary() {
        let raw = b"Subject: Alert\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><head><style>p{color:red}</style></head>\
<body><p>Temperature</p><p>too high</p></body></html>";
        let m = parse(raw);
        assert!(m.html.is_some());
        assert_eq!(m.text, "Temperature\ntoo high");
        assert!(
            !m.text.contains("color:red"),
            "style contents must not leak into the summary, got {:?}",
            m.text
        );
    }

    #[test]
    fn base64_body_is_decoded() {
        let raw = b"Subject: b64\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
5rip5bqm6L+H6auY\r\n";
        assert_eq!(parse(raw).text.trim(), "温度过高");
    }

    #[test]
    fn a_body_that_lies_about_being_base64_survives() {
        let raw = b"Content-Transfer-Encoding: base64\r\n\r\nthis is not base64!!!\r\n";
        assert!(parse(raw).text.contains("not base64"));
    }

    #[test]
    fn attachments_record_metadata_only() {
        let raw = b"Subject: with attachment\r\n\
Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
\r\n\
see attached\r\n\
--B\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
aGVsbG8gd29ybGQ=\r\n\
--B--\r\n";
        let m = parse(raw);
        assert_eq!(m.text.trim(), "see attached");
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].filename, "report.pdf");
        assert_eq!(m.attachments[0].mime, "application/pdf");
        assert_eq!(m.attachments[0].size, 11, "\"hello world\" is 11 bytes");
    }

    #[test]
    fn an_rfc2231_encoded_filename_is_decoded() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename*=utf-8''%E6%8A%A5%E5%91%8A.pdf\r\n\
\r\n\
data\r\n\
--B--\r\n";
        assert_eq!(parse(raw).attachments[0].filename, "报告.pdf");
    }

    #[test]
    fn an_rfc2231_filename_split_across_segments_is_rejoined() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment;\r\n\
\x20filename*0*=utf-8''%E6%B8%A9%E5%BA%A6;\r\n\
\x20filename*1*=%E6%8A%A5%E5%91%8A.pdf\r\n\
\r\n\
data\r\n\
--B--\r\n";
        assert_eq!(parse(raw).attachments[0].filename, "温度报告.pdf");
    }

    #[test]
    fn a_gbk_rfc2231_filename_is_decoded_with_its_own_charset() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename*=gb2312''%CE%C2%B6%C8.pdf\r\n\
\r\n\
data\r\n\
--B--\r\n";
        assert_eq!(parse(raw).attachments[0].filename, "温度.pdf");
    }

    #[test]
    fn a_plain_quoted_filename_still_works() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
\r\n\
data\r\n\
--B--\r\n";
        assert_eq!(parse(raw).attachments[0].filename, "report.pdf");
    }

    #[test]
    fn attachment_content_is_kept_only_when_asked() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: application/pdf; name=\"r.pdf\"\r\n\
Content-Disposition: attachment; filename=\"r.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
aGVsbG8gd29ybGQ=\r\n\
--B--\r\n";

        let m = parse(raw);
        assert_eq!(m.attachments[0].size, 11);
        assert!(m.attachments[0].data.is_none());

        let m = parse_with(
            raw,
            Options {
                keep_attachments: true,
            },
        );
        assert_eq!(m.attachments[0].data.as_deref(), Some(&b"hello world"[..]));
        assert_eq!(
            m.attachments[0].size, 11,
            "size must still be the decoded length"
        );
    }

    #[test]
    fn multipart_without_boundary_degrades_to_text() {
        let raw = b"Content-Type: multipart/mixed\r\n\r\nthe whole body\r\n";
        assert!(parse(raw).text.contains("the whole body"));
    }

    #[test]
    fn nested_multipart_is_walked() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"OUT\"\r\n\
\r\n\
--OUT\r\n\
Content-Type: multipart/alternative; boundary=\"IN\"\r\n\
\r\n\
--IN\r\n\
Content-Type: text/plain\r\n\
\r\n\
nested text\r\n\
--IN--\r\n\
--OUT--\r\n";
        assert!(parse(raw).text.contains("nested text"));
    }

    #[test]
    fn headerless_garbage_does_not_panic() {
        for junk in [
            &b""[..],
            b"\r\n",
            b"\r\n\r\n",
            b"no colon anywhere",
            b"Subject:",
            b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n",
            b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n",
            &[0xff, 0xfe, 0x00, 0x01][..],
        ] {
            let _ = parse(junk);
        }
    }

    #[test]
    fn line_endings_are_normalised_to_lf() {
        let m = parse(b"Subject: x\r\n\r\nline one\r\nline two\r\n");
        assert_eq!(m.text, "line one\nline two\n");
        assert!(!m.text.contains('\r'));

        let m = parse(b"Content-Type: text/html\r\n\r\n<p>a</p>\r\n<p>b</p>\r\n");
        assert!(!m.html.unwrap().contains('\r'));
    }

    #[test]
    fn a_bare_cr_is_also_treated_as_a_line_break() {
        let m = parse(b"Subject: x\r\n\r\nline one\rline two");
        assert_eq!(m.text, "line one\nline two");
    }

    #[test]
    fn envelope_only_mail_still_yields_a_record() {
        let m = parse(b"\r\nsomething happened");
        assert_eq!(m.subject, "");
        assert_eq!(m.from_addr(), "");
        assert!(m.text.contains("something happened"));
    }
}
