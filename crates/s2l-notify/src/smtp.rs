// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::http::Client;
use crate::providers::{Channel, EmailTls, Payload, civil_from_days};

const MAX_LINE: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("no recipient is configured")]
    NoRecipient,
    #[error("no sender address is configured")]
    NoSender,
    #[error("{0:?} is not a usable server name")]
    BadServer(String),
    #[error("could not resolve {0}")]
    Resolve(String),
    #[error("could not connect to {0}: {1}")]
    Connect(String, std::io::Error),
    #[error("tls handshake with {0} failed: {1} (wrong port for this encryption mode?)")]
    Tls(String, std::io::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("no reply from {0} within {1}s (is the encryption mode right for this port?)")]
    Timeout(String, u64),
    #[error("the server does not offer STARTTLS")]
    NoStartTls,
    #[error("{command} was refused: {code} {text}")]
    Refused {
        command: &'static str,
        code: u16,
        text: String,
    },
    #[error("malformed reply: {0}")]
    Protocol(String),
}

impl SmtpError {
    pub fn retryable(&self) -> bool {
        match self {
            SmtpError::Refused { code, .. } => (400..500).contains(code),
            SmtpError::Connect(..)
            | SmtpError::Resolve(_)
            | SmtpError::Io(_)
            | SmtpError::Timeout(..) => true,

            SmtpError::Tls(..) => false,
            _ => false,
        }
    }
}

pub async fn send(
    client: &Client,
    ch: &Channel,
    p: &Payload,
    now_ms: i64,
) -> Result<(), SmtpError> {
    let Channel::Email {
        server,
        port,
        encryption,
        username,
        password,
        from,
        to,
        skip_verify,
    } = ch
    else {
        return Err(SmtpError::Protocol("not an email channel".into()));
    };

    let (host, embedded_port) = split_host(server);
    if host.is_empty() {
        return Err(SmtpError::BadServer(server.clone()));
    }

    let port = match (*port, embedded_port) {
        (0, Some(p)) => p,
        (0, None) => encryption.default_port(),
        (p, _) => p,
    };

    let from = address(if from.trim().is_empty() {
        username
    } else {
        from
    });
    if from.is_empty() {
        return Err(SmtpError::NoSender);
    }
    let rcpt: Vec<String> = to
        .iter()
        .map(|t| address(t))
        .filter(|t| !t.is_empty())
        .collect();
    if rcpt.is_empty() {
        return Err(SmtpError::NoRecipient);
    }

    let mut body = p.body.clone();
    if let Some(u) = &p.url {
        body.push_str("\r\n\r\n");
        body.push_str(u);
    }
    let subject = if p.title.trim().is_empty() {
        "stmp2log alert"
    } else {
        &p.title
    };
    let message = compose(&from, &rcpt, subject, &body, now_ms);

    let budget = client.timeout();
    tokio::time::timeout(
        budget,
        converse(
            client,
            Wire {
                host: &host,
                port,
                encryption: *encryption,
                skip_verify: *skip_verify,
                username,
                password,
            },
            &from,
            &rcpt,
            &message,
        ),
    )
    .await
    .map_err(|_| SmtpError::Timeout(format!("{host}:{port}"), budget.as_secs()))?
}

struct Wire<'a> {
    host: &'a str,
    port: u16,
    encryption: EmailTls,
    skip_verify: bool,
    username: &'a str,
    password: &'a str,
}

async fn converse(
    client: &Client,
    w: Wire<'_>,
    from: &str,
    rcpt: &[String],
    message: &[u8],
) -> Result<(), SmtpError> {
    let addr = tokio::net::lookup_host((w.host, w.port))
        .await
        .map_err(|_| SmtpError::Resolve(w.host.to_string()))?
        .next()
        .ok_or_else(|| SmtpError::Resolve(w.host.to_string()))?;
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| SmtpError::Connect(addr.to_string(), e))?;
    let _ = tcp.set_nodelay(true);

    let mut io: Io = Box::new(tcp);

    if w.encryption == EmailTls::Tls {
        io = upgrade(client, io, w.host, w.skip_verify).await?;
    }

    let mut s = Session::new(io);
    s.expect("the greeting", &[220]).await?;

    let ehlo_name = from.rsplit('@').next().unwrap_or("stmp2log");
    let mut caps = s.hello(ehlo_name).await?;

    if w.encryption == EmailTls::StartTls {
        if !caps.starttls {
            return Err(SmtpError::NoStartTls);
        }
        s.cmd("STARTTLS", "STARTTLS", &[220]).await?;

        let up = upgrade(client, s.into_inner(), w.host, w.skip_verify).await?;
        s = Session::new(up);
        caps = s.hello(ehlo_name).await?;
    }

    if !w.username.is_empty() {
        s.auth(&caps, w.username, w.password).await?;
    }

    s.cmd("MAIL FROM", &format!("MAIL FROM:<{from}>"), &[250])
        .await?;
    for r in rcpt {
        s.cmd("RCPT TO", &format!("RCPT TO:<{r}>"), &[250, 251])
            .await?;
    }
    s.cmd("DATA", "DATA", &[354]).await?;
    s.write_message(message).await?;

    let _ = s.cmd("QUIT", "QUIT", &[221]).await;
    Ok(())
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
type Io = Box<dyn Duplex>;

async fn upgrade(client: &Client, io: Io, host: &str, skip_verify: bool) -> Result<Io, SmtpError> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| SmtpError::BadServer(host.to_string()))?;
    let cfg = if skip_verify {
        insecure_config()
    } else {
        client.tls()
    };
    let stream = tokio_rustls::TlsConnector::from(cfg)
        .connect(name, io)
        .await
        .map_err(|e| SmtpError::Tls(host.to_string(), e))?;
    Ok(Box::new(stream))
}

fn insecure_config() -> Arc<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(algs)))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct NoVerify(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[derive(Debug, Default, PartialEq)]
struct Caps {
    starttls: bool,
    auth: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        self.lines.join("; ")
    }
}

struct Session {
    io: BufReader<Io>,
}

impl Session {
    fn new(io: Io) -> Self {
        Self {
            io: BufReader::new(io),
        }
    }

    fn into_inner(self) -> Io {
        self.io.into_inner()
    }

    async fn line(&mut self) -> Result<String, SmtpError> {
        let mut buf = Vec::new();
        loop {
            let available = self.io.fill_buf().await?;
            if available.is_empty() {
                if buf.is_empty() {
                    return Err(SmtpError::Protocol(
                        "the server closed the connection".into(),
                    ));
                }
                break;
            }
            match available.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    buf.extend_from_slice(&available[..=i]);
                    self.io.consume(i + 1);
                    break;
                }
                None => {
                    let n = available.len();
                    buf.extend_from_slice(available);
                    self.io.consume(n);
                }
            }
            if buf.len() > MAX_LINE {
                return Err(SmtpError::Protocol("a reply line never ended".into()));
            }
        }
        Ok(String::from_utf8_lossy(&buf).trim_end().to_string())
    }

    async fn reply(&mut self) -> Result<Reply, SmtpError> {
        let mut lines = Vec::new();
        loop {
            let line = self.line().await?;
            if line.len() < 3 {
                return Err(SmtpError::Protocol(format!("short reply line {line:?}")));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| SmtpError::Protocol(format!("reply without a code: {line:?}")))?;
            lines.push(line.get(4..).unwrap_or("").to_string());

            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok(Reply { code, lines });
            }
            if lines.len() > 64 {
                return Err(SmtpError::Protocol("too many reply lines".into()));
            }
        }
    }

    async fn expect(&mut self, command: &'static str, want: &[u16]) -> Result<Reply, SmtpError> {
        let r = self.reply().await?;
        if !want.contains(&r.code) {
            return Err(SmtpError::Refused {
                command,
                code: r.code,
                text: r.text(),
            });
        }
        Ok(r)
    }

    async fn cmd(
        &mut self,
        command: &'static str,
        line: &str,
        want: &[u16],
    ) -> Result<Reply, SmtpError> {
        self.io.get_mut().write_all(line.as_bytes()).await?;
        self.io.get_mut().write_all(b"\r\n").await?;
        self.io.get_mut().flush().await?;
        self.expect(command, want).await
    }

    async fn hello(&mut self, name: &str) -> Result<Caps, SmtpError> {
        match self.cmd("EHLO", &format!("EHLO {name}"), &[250]).await {
            Ok(r) => Ok(parse_caps(&r.lines)),
            Err(SmtpError::Refused { .. }) => {
                self.cmd("HELO", &format!("HELO {name}"), &[250]).await?;
                Ok(Caps::default())
            }
            Err(e) => Err(e),
        }
    }

    async fn auth(&mut self, caps: &Caps, user: &str, pass: &str) -> Result<(), SmtpError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let has = |m: &str| caps.auth.iter().any(|a| a == m);

        if has("PLAIN") || caps.auth.is_empty() {
            let raw = format!("\0{user}\0{pass}");
            let line = format!("AUTH PLAIN {}", b64.encode(raw));
            self.cmd("AUTH", &line, &[235]).await?;
            return Ok(());
        }
        if has("LOGIN") {
            self.cmd("AUTH", "AUTH LOGIN", &[334]).await?;
            self.cmd("AUTH", &b64.encode(user), &[334]).await?;
            self.cmd("AUTH", &b64.encode(pass), &[235]).await?;
            return Ok(());
        }
        Err(SmtpError::Refused {
            command: "AUTH",
            code: 504,
            text: format!(
                "the server only offers {}, none of which this client can do",
                caps.auth.join(" ")
            ),
        })
    }

    async fn write_message(&mut self, message: &[u8]) -> Result<(), SmtpError> {
        let io = self.io.get_mut();
        io.write_all(message).await?;

        io.write_all(b".\r\n").await?;
        io.flush().await?;
        self.expect("the message body", &[250]).await?;
        Ok(())
    }
}

fn parse_caps(lines: &[String]) -> Caps {
    let mut caps = Caps::default();
    for line in lines {
        let up = line.trim().to_ascii_uppercase();
        if up == "STARTTLS" {
            caps.starttls = true;
        } else if let Some(rest) = up
            .strip_prefix("AUTH ")
            .or_else(|| up.strip_prefix("AUTH="))
        {
            caps.auth
                .extend(rest.split_whitespace().map(|m| m.to_string()));
        }
    }
    caps
}

fn address(raw: &str) -> String {
    let s = raw.trim();
    match (s.find('<'), s.rfind('>')) {
        (Some(a), Some(b)) if b > a => s[a + 1..b].trim().to_string(),
        _ => s.to_string(),
    }
}

fn split_host(server: &str) -> (String, Option<u16>) {
    let s = server.trim();
    let s = s
        .strip_prefix("smtps://")
        .or_else(|| s.strip_prefix("smtp://"))
        .or_else(|| s.strip_prefix("ssl://"))
        .unwrap_or(s);
    let s = s.trim_end_matches('/');

    if let Some(end) = s.strip_prefix('[').and_then(|r| r.find(']')) {
        let host = s[1..=end].trim_end_matches(']').to_string();
        let port = s[end + 2..].strip_prefix(':').and_then(|p| p.parse().ok());
        return (host, port);
    }
    match s.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), Some(port)),

            Err(_) => (s.to_string(), None),
        },
        None => (s.to_string(), None),
    }
}

fn compose(from: &str, to: &[String], subject: &str, body: &str, now_ms: i64) -> Vec<u8> {
    let mut out = String::with_capacity(body.len() * 2 + 512);
    out.push_str(&format!("From: {from}\r\n"));

    out.push_str(&format!("To: {}\r\n", to.join(",\r\n ")));
    out.push_str(&format!("Subject: {}\r\n", encode_word(subject)));
    out.push_str(&format!("Date: {}\r\n", rfc5322_date(now_ms)));
    out.push_str(&format!("Message-ID: {}\r\n", message_id(from, now_ms)));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: base64\r\n");

    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("X-Mailer: stmp2log\r\n");
    out.push_str("\r\n");
    out.push_str(&base64_lines(body.as_bytes()));
    out.into_bytes()
}

fn base64_lines(data: &[u8]) -> String {
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(enc.len() + enc.len() / 76 * 2 + 2);
    for chunk in enc.as_bytes().chunks(76) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push_str("\r\n");
    }
    if out.is_empty() {
        out.push_str("\r\n");
    }
    out
}

fn encode_word(s: &str) -> String {
    let s = s.replace(['\r', '\n'], " ");
    if s.is_ascii() && !s.chars().any(|c| c.is_ascii_control()) {
        return s;
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut words = Vec::new();
    let mut piece = String::new();
    for ch in s.chars() {
        if piece.len() + ch.len_utf8() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", b64.encode(&piece)));
            piece.clear();
        }
        piece.push(ch);
    }
    if !piece.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", b64.encode(&piece)));
    }

    words.join("\r\n ")
}

fn rfc5322_date(now_ms: i64) -> String {
    const DOW: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = now_ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);

    let dow = DOW[days.rem_euclid(7) as usize];
    let mon = MON[(m.clamp(1, 12) - 1) as usize];
    format!(
        "{dow}, {d} {mon} {y} {:02}:{:02}:{:02} +0000",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn message_id(from: &str, now_ms: i64) -> String {
    let domain = from.rsplit('@').next().unwrap_or("stmp2log");
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    format!("<{now_ms}.{:016x}@{domain}>", u64::from_le_bytes(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const NOW: i64 = 1_788_772_416_000;

    fn payload() -> Payload {
        Payload {
            title: "温度告警".into(),
            body: "机房温度 48C".into(),
            url: Some("http://10.0.0.2:8025/stmp2log/#/?id=7".into()),
        }
    }

    fn channel(port: u16) -> Channel {
        Channel::Email {
            server: "127.0.0.1".into(),
            port,
            encryption: EmailTls::None,
            username: "alerts@idc.local".into(),
            password: "hunter2".into(),
            from: String::new(),
            to: vec!["ops@example.com".into()],
            skip_verify: false,
        }
    }

    #[test]
    fn a_chinese_subject_is_encoded_in_pieces_that_fit_the_line_limit() {
        let long = "温度".repeat(30);
        let encoded = encode_word(&long);
        for word in encoded.split("\r\n ") {
            assert!(
                word.len() <= 75,
                "an encoded-word must fit in 75 chars, got {}: {word}",
                word.len()
            );
            let inner = word
                .strip_prefix("=?UTF-8?B?")
                .and_then(|w| w.strip_suffix("?="))
                .expect("every piece is a complete encoded-word");
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(inner)
                .expect("each piece decodes on its own");
            String::from_utf8(raw).expect("pieces must split on character boundaries");
        }
    }

    #[test]
    fn an_ascii_subject_is_left_alone() {
        assert_eq!(encode_word("UPS on battery"), "UPS on battery");
        assert_eq!(encode_word(""), "");

        assert_eq!(encode_word("a\r\nBcc: x@y"), "a  Bcc: x@y");
    }

    #[test]
    fn the_body_can_never_end_the_data_section_early() {
        let nasty = ".\r\n.\r\nSubject: injected\r\n.";
        let msg = compose("a@b.c", &["d@e.f".into()], "x", nasty, NOW);
        let text = String::from_utf8(msg).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(
            !body.lines().any(|l| l.starts_with('.')),
            "no body line may start with a dot:\n{body}"
        );
        assert!(
            !text.contains("Subject: injected"),
            "body content must not appear as a header"
        );
    }

    #[test]
    fn every_message_carries_the_headers_a_server_expects() {
        let msg = String::from_utf8(compose(
            "alerts@idc.local",
            &["a@x.com".into(), "b@y.com".into()],
            "UPS",
            "body",
            NOW,
        ))
        .unwrap();
        assert!(msg.starts_with("From: alerts@idc.local\r\n"));
        assert!(msg.contains("To: a@x.com,\r\n b@y.com\r\n"), "{msg}");
        assert!(msg.contains("Subject: UPS\r\n"));
        assert!(
            msg.contains("Date: Mon, 7 Sep 2026 09:13:36 +0000\r\n"),
            "{msg}"
        );
        assert!(
            msg.contains("@idc.local>\r\n"),
            "message-id uses the sender domain"
        );
        assert!(msg.contains("Content-Transfer-Encoding: base64\r\n"));

        assert!(msg.contains("Auto-Submitted: auto-generated\r\n"));
        assert!(msg.ends_with("\r\n"), "DATA needs a CRLF before the dot");
    }

    #[test]
    fn the_date_header_matches_rfc_5322() {
        assert_eq!(rfc5322_date(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc5322_date(NOW), "Mon, 7 Sep 2026 09:13:36 +0000");
    }

    #[test]
    fn addresses_survive_the_shapes_people_paste() {
        assert_eq!(address("  ops@example.com "), "ops@example.com");
        assert_eq!(address("张三 <boss@example.com>"), "boss@example.com");
        assert_eq!(address("<a@b.c>"), "a@b.c");
    }

    #[test]
    fn the_server_field_accepts_what_the_help_pages_tell_people_to_paste() {
        assert_eq!(split_host("smtp.qq.com"), ("smtp.qq.com".into(), None));
        assert_eq!(
            split_host("smtps://smtp.qq.com:465"),
            ("smtp.qq.com".into(), Some(465))
        );
        assert_eq!(
            split_host("smtp://mail.local:25/"),
            ("mail.local".into(), Some(25))
        );
        assert_eq!(split_host("[fd00::1]:587"), ("fd00::1".into(), Some(587)));

        assert_eq!(split_host("mail.local:"), ("mail.local:".into(), None));
    }

    #[test]
    fn the_default_port_follows_the_encryption_mode() {
        assert_eq!(EmailTls::Tls.default_port(), 465);
        assert_eq!(EmailTls::StartTls.default_port(), 587);
        assert_eq!(EmailTls::None.default_port(), 25);
    }

    #[test]
    fn capabilities_parse_in_both_spellings() {
        let caps = parse_caps(&[
            "mail.local at your service".into(),
            "SIZE 35882577".into(),
            "STARTTLS".into(),
            "AUTH LOGIN PLAIN XOAUTH2".into(),
        ]);
        assert!(caps.starttls);
        assert_eq!(caps.auth, ["LOGIN", "PLAIN", "XOAUTH2"]);

        assert_eq!(
            parse_caps(&["auth=login plain".into()]).auth,
            ["LOGIN", "PLAIN"]
        );
    }

    #[test]
    fn smtp_status_codes_decide_what_is_worth_retrying() {
        let refused = |code| SmtpError::Refused {
            command: "RCPT TO",
            code,
            text: String::new(),
        };
        assert!(refused(421).retryable(), "the server is shutting down");
        assert!(refused(451).retryable(), "greylisting");
        assert!(refused(452).retryable(), "mailbox full right now");
        assert!(!refused(535).retryable(), "a wrong password stays wrong");
        assert!(!refused(550).retryable(), "no such mailbox");
        assert!(!SmtpError::NoRecipient.retryable());
        assert!(
            !SmtpError::Tls("m".into(), std::io::Error::other("x")).retryable(),
            "a handshake failure is a config problem, not a passing outage"
        );
    }

    async fn fake_server() -> (u16, tokio::task::JoinHandle<(Vec<String>, String)>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut commands = Vec::new();
            let mut data = String::new();

            w.write_all(b"220 mail.local ESMTP\r\n").await.unwrap();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                let up = line.to_ascii_uppercase();
                commands.push(line);

                if up.starts_with("EHLO") {
                    w.write_all(b"250-mail.local\r\n250-SIZE 10240000\r\n250 AUTH PLAIN LOGIN\r\n")
                        .await
                        .unwrap();
                } else if up.starts_with("AUTH") {
                    w.write_all(b"235 2.7.0 Authentication successful\r\n")
                        .await
                        .unwrap();
                } else if up.starts_with("MAIL") || up.starts_with("RCPT") {
                    w.write_all(b"250 2.1.0 Ok\r\n").await.unwrap();
                } else if up == "DATA" {
                    w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await
                        .unwrap();
                    loop {
                        let mut l = String::new();
                        if r.read_line(&mut l).await.unwrap() == 0 {
                            break;
                        }
                        if l == ".\r\n" {
                            break;
                        }
                        data.push_str(&l);
                    }
                    w.write_all(b"250 2.0.0 Ok: queued as ABC123\r\n")
                        .await
                        .unwrap();
                } else if up == "QUIT" {
                    w.write_all(b"221 2.0.0 Bye\r\n").await.unwrap();
                    break;
                } else {
                    w.write_all(b"502 5.5.2 Command not implemented\r\n")
                        .await
                        .unwrap();
                }
            }
            (commands, data)
        });
        (port, handle)
    }

    #[tokio::test]
    async fn a_notification_goes_out_as_a_real_message() {
        let (port, server) = fake_server().await;
        let client = Client::new(Duration::from_secs(5));
        send(&client, &channel(port), &payload(), NOW)
            .await
            .unwrap();

        let (commands, data) = server.await.unwrap();
        assert!(
            commands.iter().any(|c| c == "EHLO idc.local"),
            "EHLO must name a domain, got {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.starts_with("AUTH PLAIN ")),
            "{commands:?}"
        );

        assert!(commands.contains(&"MAIL FROM:<alerts@idc.local>".to_string()));
        assert!(commands.contains(&"RCPT TO:<ops@example.com>".to_string()));
        assert!(commands.contains(&"QUIT".to_string()));

        use base64::Engine;
        let (head, body) = data.split_once("\r\n\r\n").unwrap();
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(body.replace("\r\n", ""))
                .unwrap(),
        )
        .unwrap();
        assert!(decoded.contains("机房温度 48C"), "{decoded}");
        assert!(
            decoded.contains("http://10.0.0.2:8025/stmp2log/#/?id=7"),
            "the link back to the log entry belongs in the body"
        );
        assert!(head.contains("Subject: =?UTF-8?B?"), "{head}");
    }

    #[tokio::test]
    async fn a_refusal_carries_the_servers_own_words_and_never_the_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"220 mail.local ESMTP\r\n").await.unwrap();
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            w.write_all(b"250-mail.local\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            line.clear();
            r.read_line(&mut line).await.unwrap();
            w.write_all(b"535 5.7.8 Error: authentication failed\r\n")
                .await
                .unwrap();
        });

        let client = Client::new(Duration::from_secs(5));
        let err = send(&client, &channel(port), &payload(), NOW)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("535"), "{text}");
        assert!(text.contains("authentication failed"), "{text}");
        assert!(!text.contains("hunter2"), "the password leaked: {text}");
        assert!(
            !text.contains("AUTH PLAIN"),
            "the base64 credentials leaked: {text}"
        );
        assert!(!err.retryable(), "a wrong password stays wrong");
    }

    #[tokio::test]
    async fn a_missing_recipient_fails_before_touching_the_network() {
        let mut ch = channel(1);
        let Channel::Email { to, .. } = &mut ch else {
            unreachable!()
        };
        *to = vec!["  ".into()];
        let client = Client::new(Duration::from_millis(200));
        assert!(matches!(
            send(&client, &ch, &payload(), NOW).await,
            Err(SmtpError::NoRecipient)
        ));
    }
}
