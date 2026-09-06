// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use crate::{AttachmentMeta, Mail, Options, addr, charset, date, qp, word};

const MAX_DEPTH: usize = 12;

const MAX_ATTACHMENTS: usize = 64;

pub fn parse(raw: &[u8], opts: Options) -> Mail {
    let (headers, body) = split_headers(raw);

    let mut mail = Mail::default();
    let mut ctype: Option<Vec<u8>> = None;
    let mut cte: Option<Vec<u8>> = None;

    for (name, value) in &headers {
        match name.to_ascii_lowercase().as_str() {
            "subject" => mail.subject = word::decode(value),
            "from" => mail.from = Some(addr::parse_one(value)),
            "to" => mail.to = addr::parse_list(value),
            "cc" => mail.cc = addr::parse_list(value),
            "date" => mail.date = date::parse(value),
            "message-id" => {
                mail.message_id = Some(
                    String::from_utf8_lossy(value)
                        .trim()
                        .trim_matches(['<', '>'])
                        .to_string(),
                );
            }
            "content-type" => ctype = Some(value.clone()),
            "content-transfer-encoding" => cte = Some(value.clone()),
            _ => {}
        }
        mail.headers.push((name.clone(), word::decode(value)));
    }

    walk(body, ctype.as_deref(), cte.as_deref(), 0, &mut mail, opts);

    if mail.text.trim().is_empty() {
        if let Some(html) = &mail.html {
            mail.text = html_to_text(html);
        }
    }
    mail
}

fn split_headers(raw: &[u8]) -> (Vec<(String, Vec<u8>)>, &[u8]) {
    if let Some(rest) = raw.strip_prefix(b"\r\n") {
        return (Vec::new(), rest);
    }
    if let Some(rest) = raw.strip_prefix(b"\n") {
        return (Vec::new(), rest);
    }

    let (head, body) = match find_blank_line(raw) {
        Some((end, body_start)) => (&raw[..end], &raw[body_start..]),
        None => (raw, &raw[raw.len()..]),
    };
    (unfold(head), body)
}

fn find_blank_line(raw: &[u8]) -> Option<(usize, usize)> {
    for i in 0..raw.len() {
        if raw[i..].starts_with(b"\r\n\r\n") {
            return Some((i, i + 4));
        }
        if raw[i..].starts_with(b"\n\n") {
            return Some((i, i + 2));
        }
    }
    None
}

fn unfold(head: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            if let Some((_, v)) = out.last_mut() {
                v.push(b' ');
                v.extend_from_slice(line.trim_ascii_start());
            }
            continue;
        }
        match line.iter().position(|&b| b == b':') {
            Some(c) => {
                let name = String::from_utf8_lossy(&line[..c]).trim().to_string();
                let value = line[c + 1..].trim_ascii_start().to_vec();
                out.push((name, value));
            }

            None => continue,
        }
    }
    out
}

fn walk(
    body: &[u8],
    ctype: Option<&[u8]>,
    cte: Option<&[u8]>,
    depth: usize,
    mail: &mut Mail,
    opts: Options,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let ct = ContentType::parse(ctype);

    if ct.mime.starts_with("multipart/") {
        let Some(boundary) = ct.param("boundary").filter(|b| !b.is_empty()) else {
            push_text(
                mail,
                &decode_body(body, cte),
                ct.param("charset").as_deref(),
            );
            return;
        };
        let parts = split_parts(body, boundary.as_bytes());
        if parts.is_empty() {
            push_text(
                mail,
                &decode_body(body, cte),
                ct.param("charset").as_deref(),
            );
            return;
        }

        for part in parts {
            let (ph, pb) = split_headers(part);
            let pct = header_of(&ph, "content-type");
            let pcte = header_of(&ph, "content-transfer-encoding");
            let pcd = header_of(&ph, "content-disposition");
            walk_part(
                pb,
                pct.as_deref(),
                pcte.as_deref(),
                pcd.as_deref(),
                depth + 1,
                mail,
                opts,
            );
        }
        return;
    }

    walk_part(body, ctype, cte, None, depth, mail, opts);
}

fn walk_part(
    body: &[u8],
    ctype: Option<&[u8]>,
    cte: Option<&[u8]>,
    cdisp: Option<&[u8]>,
    depth: usize,
    mail: &mut Mail,
    opts: Options,
) {
    let ct = ContentType::parse(ctype);
    if ct.mime.starts_with("multipart/") {
        walk(body, ctype, cte, depth, mail, opts);
        return;
    }

    let disp = ContentType::parse(cdisp);
    let filename = disp
        .param("filename")
        .or_else(|| ct.param("name"))
        .map(|f| word::decode(f.as_bytes()));

    let is_attachment =
        disp.mime == "attachment" || (filename.is_some() && !ct.mime.starts_with("text/"));

    if is_attachment {
        if mail.attachments.len() < MAX_ATTACHMENTS {
            let data = opts.keep_attachments.then(|| decode_body(body, cte));
            mail.attachments.push(AttachmentMeta {
                filename: filename.unwrap_or_else(|| "attachment".into()),
                mime: ct.mime.clone(),
                size: data
                    .as_ref()
                    .map_or_else(|| decoded_size(body, cte), Vec::len),
                data,
            });
        }
        return;
    }

    let bytes = decode_body(body, cte);
    let cs = ct.param("charset");
    if ct.mime == "text/html" {
        let html = normalize_eol(&charset::decode(&bytes, cs.as_deref()));
        match &mut mail.html {
            Some(existing) => existing.push_str(&html),
            None => mail.html = Some(html),
        }
    } else {
        push_text(mail, &bytes, cs.as_deref());
    }
}

fn push_text(mail: &mut Mail, bytes: &[u8], charset_label: Option<&str>) {
    let s = normalize_eol(&charset::decode(bytes, charset_label));
    if s.trim().is_empty() {
        return;
    }
    if !mail.text.is_empty() {
        mail.text.push('\n');
    }
    mail.text.push_str(&s);
}

fn normalize_eol(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn header_of(headers: &[(String, Vec<u8>)], name: &str) -> Option<Vec<u8>> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn split_parts<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut marker = Vec::with_capacity(boundary.len() + 2);
    marker.extend_from_slice(b"--");
    marker.extend_from_slice(boundary);

    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    let mut at_line_start = true;
    while i < body.len() {
        if at_line_start && body[i..].starts_with(&marker) {
            let after = i + marker.len();

            let is_close = body[after..].starts_with(b"--");
            let mut eol = after;
            while eol < body.len() && body[eol] != b'\n' {
                eol += 1;
            }
            bounds.push((i, (eol + 1).min(body.len())));
            if is_close {
                break;
            }
            i = eol + 1;
            at_line_start = true;
            continue;
        }
        at_line_start = body[i] == b'\n';
        i += 1;
    }

    let mut parts = Vec::new();
    for w in bounds.windows(2) {
        let start = w[0].1;
        let mut end = w[1].0;

        if end > start && body[end - 1] == b'\n' {
            end -= 1;
        }
        if end > start && body[end - 1] == b'\r' {
            end -= 1;
        }
        if end > start {
            parts.push(&body[start..end]);
        }
    }
    parts
}

fn decode_body(body: &[u8], cte: Option<&[u8]>) -> Vec<u8> {
    match cte_kind(cte) {
        Cte::Base64 => b64_lenient(body),
        Cte::QuotedPrintable => qp::decode(body, false),
        Cte::Identity => body.to_vec(),
    }
}

fn decoded_size(body: &[u8], cte: Option<&[u8]>) -> usize {
    match cte_kind(cte) {
        Cte::Base64 => {
            let n = body.iter().filter(|b| !b.is_ascii_whitespace()).count();
            let pad = body
                .iter()
                .rev()
                .take_while(|b| b.is_ascii_whitespace() || **b == b'=')
                .filter(|b| **b == b'=')
                .count()
                .min(2);
            let full = n / 4 * 3
                + match n % 4 {
                    2 => 1,
                    3 => 2,
                    _ => 0,
                };
            full.saturating_sub(pad)
        }
        Cte::QuotedPrintable => qp::decode(body, false).len(),
        Cte::Identity => body.len(),
    }
}

enum Cte {
    Base64,
    QuotedPrintable,
    Identity,
}

fn cte_kind(cte: Option<&[u8]>) -> Cte {
    let Some(v) = cte else { return Cte::Identity };
    match String::from_utf8_lossy(v)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "base64" => Cte::Base64,
        "quoted-printable" => Cte::QuotedPrintable,
        _ => Cte::Identity,
    }
}

fn b64_lenient(data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let cleaned: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(&cleaned).unwrap_or_else(|_| data.to_vec())
}

struct ContentType {
    mime: String,
    params: Vec<(String, String)>,
}

impl ContentType {
    fn parse(raw: Option<&[u8]>) -> Self {
        let Some(raw) = raw else {
            return Self {
                mime: String::new(),
                params: Vec::new(),
            };
        };
        let s = String::from_utf8_lossy(raw);
        let mut it = s.split(';');
        let mime = it.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut params = Vec::new();
        for p in it {
            if let Some((k, v)) = p.split_once('=') {
                params.push((
                    k.trim().to_ascii_lowercase(),
                    v.trim().trim_matches(['"', '\'']).to_string(),
                ));
            }
        }
        Self { mime, params }
    }

    fn param(&self, name: &str) -> Option<String> {
        let mut segs: Vec<(u32, bool, &str)> = Vec::new();
        for (k, v) in &self.params {
            let Some(rest) = k.strip_prefix(name) else {
                continue;
            };
            match rest {
                "" => segs.push((0, false, v)),

                "*" => segs.push((0, true, v)),

                r => {
                    let Some(idx) = r.strip_prefix('*') else {
                        continue;
                    };
                    let (num, extended) = match idx.strip_suffix('*') {
                        Some(n) => (n, true),
                        None => (idx, false),
                    };
                    let Ok(n) = num.parse::<u32>() else { continue };
                    segs.push((n, extended, v));
                }
            }
        }
        if segs.is_empty() {
            return None;
        }
        segs.sort_by_key(|(n, _, _)| *n);

        let extended = segs.iter().any(|(_, e, _)| *e);
        let joined: String = segs.iter().map(|(_, _, v)| *v).collect();
        if !extended {
            return Some(joined);
        }

        let (charset, encoded) = match joined.split_once('\'') {
            Some((cs, rest)) => (cs, rest.split_once('\'').map_or(rest, |(_, v)| v)),

            None => ("utf-8", joined.as_str()),
        };
        Some(charset::decode(&percent_decode(encoded), Some(charset)))
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let tag_start = i + 1;
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            let tag_end = i.min(bytes.len());
            i = (i + 1).min(bytes.len());

            let name: String = html
                .get(tag_start..tag_end)
                .unwrap_or("")
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .flat_map(|c| c.to_lowercase())
                .collect();

            match name.as_str() {
                "br" | "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "h4" | "table" => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                "td" | "th" => {
                    if !out.is_empty() && !out.ends_with(['\n', '\t']) {
                        out.push('\t');
                    }
                }

                "script" | "style" => {
                    let close = format!("</{name}");
                    if let Some(rel) = html
                        .get(i..)
                        .map(|r| r.to_ascii_lowercase())
                        .and_then(|r| r.find(&close))
                    {
                        i += rel;
                        while i < bytes.len() && bytes[i] != b'>' {
                            i += 1;
                        }
                        i = (i + 1).min(bytes.len());
                    }
                }
                _ => {}
            }
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'<' {
            i += 1;
        }
        out.push_str(&unescape(html.get(start..i).unwrap_or("")));
    }

    let mut text = String::with_capacity(out.len());
    let mut blanks = 0;
    for line in out.lines() {
        let t = line.trim_end();
        if t.trim().is_empty() {
            blanks += 1;
            if blanks > 1 {
                continue;
            }
        } else {
            blanks = 0;
        }
        text.push_str(t);
        text.push('\n');
    }
    text.trim().to_string()
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
