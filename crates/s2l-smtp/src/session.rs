// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{AuthPolicy, Config, Delivered};

const MAX_LINE: usize = 2048;

const MAX_RCPT: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum End {
    Done,

    StartTls,
}

pub struct Trace {
    on: bool,
    peer: SocketAddr,
    start: std::time::Instant,
}

impl Trace {
    pub fn new(on: bool, peer: SocketAddr) -> Self {
        Self {
            on,
            peer,
            start: std::time::Instant::now(),
        }
    }

    fn cmd(&self, line: &[u8]) {
        if self.on {
            self.emit('<', &redact(line));
        }
    }

    fn reply(&self, line: &str) {
        if self.on {
            self.emit('>', line);
        }
    }

    fn secret(&self, n: usize) {
        if self.on {
            self.emit('<', &format!("<credentials, {n} bytes>"));
        }
    }

    pub fn note(&self, msg: &str) {
        if self.on {
            self.emit('-', msg);
        }
    }

    fn alert(&self, msg: &str) {
        crate::warn(&format!("{} {msg}", self.peer));
    }

    fn emit(&self, dir: char, text: &str) {
        crate::info(&format!(
            "{} +{:.3}s {dir} {text}",
            self.peer,
            self.start.elapsed().as_secs_f64()
        ));
    }
}

fn redact(line: &[u8]) -> String {
    let (verb, rest) = split_verb(line);
    if verb != "AUTH" {
        return String::from_utf8_lossy(line).into_owned();
    }
    let text = String::from_utf8_lossy(rest);
    let mut parts = text.split_whitespace();
    let mech = parts.next().unwrap_or("");
    match parts.next() {
        Some(_) => format!("AUTH {mech} <initial response, {} bytes>", text.len()),
        None => format!("AUTH {mech}"),
    }
}

#[derive(Default)]
pub struct State {
    greeted: bool,

    peer_name: String,
    mail_from: Option<String>,
    rcpt: Vec<String>,
    auth_user: Option<String>,

    delivered: usize,
}

impl State {
    pub fn greeted_but_delivered_nothing(&self) -> bool {
        self.greeted && self.delivered == 0
    }
}

pub async fn run<S>(
    io: &mut S,
    st: &mut State,
    cfg: &Config,
    peer: SocketAddr,
    tls_active: bool,
    greet: bool,
    tr: &Trace,
) -> std::io::Result<End>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rd = BufReader::with_capacity(8192, io);

    if greet {
        write_line(
            &mut rd,
            tr,
            &format!("220 {} ESMTP stmp2log ready", cfg.hostname),
        )
        .await?;
    }

    let mut line = Vec::with_capacity(256);
    loop {
        line.clear();
        let n = match tokio::time::timeout(cfg.timeout, read_line(&mut rd, tr, &mut line)).await {
            Ok(r) => r?,
            Err(_) => {
                let _ = write_line(&mut rd, tr, "421 4.4.2 idle timeout, closing").await;
                return Ok(End::Done);
            }
        };
        if n == 0 {
            return Ok(End::Done);
        }

        let raw = trim_eol(&line);

        let (verb, rest) = split_verb(raw);

        match verb.as_str() {
            "EHLO" => {
                st.reset_envelope();
                st.greeted = true;
                st.peer_name = String::from_utf8_lossy(rest).trim().to_string();
                for l in ehlo_lines(cfg, offer_starttls(cfg, peer, tls_active)) {
                    write_line(&mut rd, tr, &l).await?;
                }
            }
            "HELO" => {
                st.reset_envelope();
                st.greeted = true;
                st.peer_name = String::from_utf8_lossy(rest).trim().to_string();
                write_line(&mut rd, tr, &format!("250 {}", cfg.hostname)).await?;
            }
            "STARTTLS" => {
                if tls_active {
                    write_line(&mut rd, tr, "503 5.5.1 TLS is already active").await?;
                } else if !offer_starttls(cfg, peer, tls_active) {
                    write_line(&mut rd, tr, "454 4.7.0 TLS is not available").await?;
                } else {
                    write_line(&mut rd, tr, "220 2.0.0 ready to start TLS").await?;
                    return Ok(End::StartTls);
                }
            }
            "AUTH" => {
                if !handle_auth(&mut rd, st, cfg, rest, tr).await? {
                    return Ok(End::Done);
                }
            }

            _ if matches!(verb.as_str(), "MAIL" | "RCPT" | "DATA")
                && requires_auth(cfg)
                && st.auth_user.is_none() =>
            {
                write_line(&mut rd, tr, "530 5.7.0 authentication required").await?;
            }
            "MAIL" => {
                if let Some(addr) = param_after(rest, b"FROM:") {
                    st.mail_from = Some(addr);
                    st.rcpt.clear();
                    write_line(&mut rd, tr, "250 2.1.0 sender ok").await?;
                } else {
                    write_line(&mut rd, tr, "501 5.5.4 syntax: MAIL FROM:<address>").await?;
                }
            }
            "RCPT" => match param_after(rest, b"TO:") {
                Some(addr) if st.rcpt.len() >= MAX_RCPT => {
                    let _ = addr;
                    write_line(&mut rd, tr, "452 4.5.3 too many recipients").await?;
                }
                Some(addr) => {
                    st.rcpt.push(addr);
                    write_line(&mut rd, tr, "250 2.1.5 recipient ok").await?;
                }
                None => {
                    write_line(&mut rd, tr, "501 5.5.4 syntax: RCPT TO:<address>").await?;
                }
            },
            "DATA" => {
                write_line(&mut rd, tr, "354 end data with <CR><LF>.<CR><LF>").await?;
                match read_data(&mut rd, cfg).await? {
                    Ok(data) => {
                        tr.note(&format!("<message body, {} bytes>", data.len()));
                        let msg = Delivered {
                            envelope_from: st
                                .mail_from
                                .clone()
                                .unwrap_or_else(|| format!("unknown@{}", peer.ip())),
                            rcpt: if st.rcpt.is_empty() {
                                vec![format!("postmaster@{}", cfg.hostname)]
                            } else {
                                st.rcpt.clone()
                            },
                            peer,
                            size: data.len(),
                            data,
                            tls: tls_active,
                            auth_user: st.auth_user.clone(),
                        };
                        let reply = match cfg.sink.try_send(msg) {
                            Ok(()) => {
                                st.delivered += 1;
                                "250 2.0.0 message accepted".to_string()
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                "451 4.3.1 mail queue is full, try again later".to_string()
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                "421 4.3.2 service shutting down".to_string()
                            }
                        };
                        write_line(&mut rd, tr, &reply).await?;
                    }
                    Err(TooBig) => {
                        write_line(
                            &mut rd,
                            tr,
                            &format!("552 5.3.4 message exceeds the {} byte limit", cfg.max_size),
                        )
                        .await?;
                    }
                }
                st.reset_envelope();
            }
            "RSET" => {
                st.reset_envelope();
                write_line(&mut rd, tr, "250 2.0.0 reset").await?;
            }
            "NOOP" => write_line(&mut rd, tr, "250 2.0.0 ok").await?,
            "VRFY" | "EXPN" => {
                write_line(&mut rd, tr, "252 2.5.2 cannot verify, will accept anyway").await?;
            }
            "HELP" => {
                write_line(
                    &mut rd,
                    tr,
                    "214 2.0.0 EHLO HELO MAIL RCPT DATA RSET NOOP AUTH STARTTLS QUIT",
                )
                .await?;
            }
            "QUIT" => {
                write_line(&mut rd, tr, &format!("221 2.0.0 {} closing", cfg.hostname)).await?;
                return Ok(End::Done);
            }
            "" => {}
            other => {
                write_line(&mut rd, tr, &format!("500 5.5.2 unknown command {other}")).await?;
            }
        }
    }
}

impl State {
    fn reset_envelope(&mut self) {
        self.mail_from = None;
        self.rcpt.clear();
    }
}

fn auth_line(cfg: &Config) -> String {
    let checks_password = matches!(&cfg.auth, AuthPolicy::Require { pass, .. } if !pass.is_empty());
    if checks_password {
        "AUTH LOGIN PLAIN".to_string()
    } else {
        "AUTH LOGIN PLAIN CRAM-MD5".to_string()
    }
}

fn offer_starttls(cfg: &Config, peer: SocketAddr, tls_active: bool) -> bool {
    cfg.tls.is_some() && !tls_active && !cfg.tls_trouble.contains(peer.ip())
}

fn ehlo_lines(cfg: &Config, starttls: bool) -> Vec<String> {
    let mut caps = vec![
        format!("SIZE {}", cfg.max_size),
        "8BITMIME".to_string(),
        "SMTPUTF8".to_string(),
        "PIPELINING".to_string(),
        "ENHANCEDSTATUSCODES".to_string(),
        auth_line(cfg),
    ];
    if starttls {
        caps.push("STARTTLS".to_string());
    }

    let mut out = Vec::with_capacity(caps.len() + 1);
    out.push(format!("250-{}", cfg.hostname));
    let last = caps.len() - 1;
    for (i, c) in caps.into_iter().enumerate() {
        out.push(if i == last {
            format!("250 {c}")
        } else {
            format!("250-{c}")
        });
    }
    out
}

fn requires_auth(cfg: &Config) -> bool {
    matches!(&cfg.auth, AuthPolicy::Require { user, pass } if !user.is_empty() || !pass.is_empty())
}

struct Creds {
    user: String,
    pass: Option<String>,
}

fn credentials_ok(policy: &AuthPolicy, creds: &Creds) -> bool {
    let AuthPolicy::Require { user, pass } = policy else {
        return true;
    };
    if !user.is_empty() && &creds.user != user {
        return false;
    }
    if !pass.is_empty() {
        match &creds.pass {
            Some(got) if got == pass => {}
            _ => return false,
        }
    }
    true
}

fn cram_challenge(cfg: &Config) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    format!(
        "<{:016x}.{now}@{}>",
        u64::from_le_bytes(r),
        cfg.hostname.trim()
    )
}

async fn auth_aborted<S>(rd: &mut BufReader<&mut S>, tr: &Trace) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_line(rd, tr, "501 5.7.0 authentication aborted").await?;
    Ok(true)
}

async fn handle_auth<S>(
    rd: &mut BufReader<&mut S>,
    st: &mut State,
    cfg: &Config,
    rest: &[u8],
    tr: &Trace,
) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = String::from_utf8_lossy(rest);
    let mut parts = text.split_whitespace();
    let mech = parts.next().unwrap_or("").to_ascii_uppercase();

    let initial = match parts.next() {
        None => None,
        Some("=") => Some(Vec::new()),
        Some(s) => Some(b64(s)),
    };

    macro_rules! answer {
        () => {
            match read_auth_line(rd, cfg, tr).await? {
                AuthLine::Data(v) => v,
                AuthLine::Cancelled => return auth_aborted(rd, tr).await,
                AuthLine::Gone => return Ok(false),
            }
        };
    }

    let creds = match mech.as_str() {
        "PLAIN" => {
            let payload = match initial {
                Some(p) => p,
                None => {
                    write_line(rd, tr, "334 ").await?;
                    answer!()
                }
            };

            let mut fields = payload.split(|&b| b == 0);
            let _authzid = fields.next();
            let user = fields
                .next()
                .map(|u| String::from_utf8_lossy(u).to_string())
                .unwrap_or_default();
            let pass = fields
                .next()
                .map(|p| String::from_utf8_lossy(p).to_string());
            Creds { user, pass }
        }
        "LOGIN" => {
            let user = match initial {
                Some(u) => u,
                None => {
                    write_line(rd, tr, "334 VXNlcm5hbWU6").await?;
                    answer!()
                }
            };

            write_line(rd, tr, "334 UGFzc3dvcmQ6").await?;
            let p = answer!();
            Creds {
                user: String::from_utf8_lossy(&user).to_string(),
                pass: Some(String::from_utf8_lossy(&p).to_string()),
            }
        }
        "CRAM-MD5" => {
            write_line(rd, tr, &format!("334 {}", b64_encode(cram_challenge(cfg)))).await?;
            let resp = answer!();
            Creds {
                user: String::from_utf8_lossy(&resp)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string(),
                pass: None,
            }
        }
        "" => {
            write_line(rd, tr, "501 5.5.4 syntax: AUTH <mechanism>").await?;
            return Ok(true);
        }
        other => {
            tr.alert(&format!(
                "asked for AUTH {other}, which this server does not implement; \
                 it offers LOGIN, PLAIN and CRAM-MD5"
            ));
            write_line(rd, tr, &format!("504 5.5.4 unsupported mechanism {other}")).await?;
            return Ok(true);
        }
    };

    if credentials_ok(&cfg.auth, &creds) {
        st.auth_user = Some(creds.user);
        write_line(rd, tr, "235 2.7.0 authentication successful").await?;
    } else {
        tr.alert(&format!(
            "AUTH {mech} failed for account {:?}; check stmp_user / stmp_pass",
            creds.user
        ));
        write_line(rd, tr, "535 5.7.8 authentication failed").await?;
    }
    Ok(true)
}
struct TooBig;

async fn read_data<S>(
    rd: &mut BufReader<&mut S>,
    cfg: &Config,
) -> std::io::Result<Result<Vec<u8>, TooBig>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    let mut line = Vec::with_capacity(256);
    let mut too_big = false;

    loop {
        line.clear();
        let n = tokio::time::timeout(cfg.timeout, rd.read_until(b'\n', &mut line))
            .await
            .unwrap_or(Ok(0))?;
        if n == 0 {
            break;
        }
        let body = trim_eol(&line);
        if body == b"." {
            break;
        }

        let body = if body.starts_with(b"..") {
            &body[1..]
        } else {
            body
        };

        if out.len() + body.len() + 2 > cfg.max_size {
            too_big = true;
        }
        if !too_big {
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
    }

    Ok(if too_big { Err(TooBig) } else { Ok(out) })
}

async fn read_line<S>(
    rd: &mut BufReader<&mut S>,
    tr: &Trace,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let n = rd.read_until(b'\n', buf).await?;
    if buf.len() > MAX_LINE {
        buf.truncate(MAX_LINE);
    }
    if n > 0 {
        tr.cmd(trim_eol(buf));
    }
    Ok(n)
}

enum AuthLine {
    Data(Vec<u8>),

    Cancelled,

    Gone,
}

async fn read_auth_line<S>(
    rd: &mut BufReader<&mut S>,
    cfg: &Config,
    tr: &Trace,
) -> std::io::Result<AuthLine>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = Vec::new();
    let n = match tokio::time::timeout(cfg.timeout, rd.read_until(b'\n', &mut line)).await {
        Ok(r) => r?,
        Err(_) => {
            tr.note("timed out waiting for the AUTH response");
            return Ok(AuthLine::Gone);
        }
    };
    if n == 0 {
        tr.note("peer hung up during AUTH");
        return Ok(AuthLine::Gone);
    }
    if line.len() > MAX_LINE {
        line.truncate(MAX_LINE);
    }
    let body = trim_eol(&line);
    if body == b"*" {
        tr.cmd(b"*");
        return Ok(AuthLine::Cancelled);
    }
    tr.secret(body.len());
    Ok(AuthLine::Data(b64(&String::from_utf8_lossy(body))))
}

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap_or_else(|_| s.trim().as_bytes().to_vec())
}

fn b64_encode(s: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

async fn write_line<S>(rd: &mut BufReader<&mut S>, tr: &Trace, line: &str) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tr.reply(line);
    let io = rd.get_mut();
    io.write_all(line.as_bytes()).await?;
    io.write_all(b"\r\n").await?;
    io.flush().await
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let l = line.strip_suffix(b"\n").unwrap_or(line);
    l.strip_suffix(b"\r").unwrap_or(l)
}

fn split_verb(line: &[u8]) -> (String, &[u8]) {
    let end = line
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let verb = String::from_utf8_lossy(&line[..end]).to_ascii_uppercase();
    (verb, &line[end..])
}

fn param_after(rest: &[u8], prefix: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(rest);
    let t = s.trim_start();
    let up = t.to_ascii_uppercase();
    let p = String::from_utf8_lossy(prefix).to_ascii_uppercase();
    let after = up.strip_prefix(&p).map(|_| &t[prefix.len()..])?;
    let after = after.trim();

    if let Some(open) = after.find('<') {
        let close = after[open..].find('>')?;
        return Some(after[open + 1..open + close].trim().to_string());
    }

    let addr = after.split_whitespace().next().unwrap_or("").trim();
    Some(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_both_line_endings() {
        assert_eq!(trim_eol(b"HELO x\r\n"), b"HELO x");
        assert_eq!(
            trim_eol(b"HELO x\n"),
            b"HELO x",
            "bare LF is what cheap firmware sends"
        );
        assert_eq!(trim_eol(b"HELO x"), b"HELO x");
    }

    #[test]
    fn splits_the_verb_case_insensitively() {
        assert_eq!(split_verb(b"ehlo device.local").0, "EHLO");
        assert_eq!(split_verb(b"MAIL FROM:<a@b>").0, "MAIL");
        assert_eq!(split_verb(b"QUIT").0, "QUIT");
        assert_eq!(split_verb(b"").0, "");
    }

    #[test]
    fn extracts_addresses_in_the_shapes_devices_send() {
        assert_eq!(
            param_after(b" FROM:<a@b.c>", b"FROM:").as_deref(),
            Some("a@b.c")
        );
        assert_eq!(
            param_after(b" FROM: <a@b.c>", b"FROM:").as_deref(),
            Some("a@b.c"),
            "a space after the colon is common and not legal, but must work"
        );
        assert_eq!(
            param_after(b" from:a@b.c", b"FROM:").as_deref(),
            Some("a@b.c"),
            "angle brackets are frequently omitted"
        );
        assert_eq!(
            param_after(b" FROM:<a@b.c> SIZE=1234", b"FROM:").as_deref(),
            Some("a@b.c"),
            "trailing ESMTP parameters must be ignored"
        );
        assert_eq!(
            param_after(b" TO:<>", b"TO:").as_deref(),
            Some(""),
            "the null sender is legal and must not be a syntax error"
        );
        assert_eq!(param_after(b" TO:<a@b>", b"FROM:"), None);
    }

    #[test]
    fn ehlo_terminator_uses_a_space_not_a_hyphen() {
        let cfg = Config::for_test();
        let lines = ehlo_lines(&cfg, false);
        assert!(lines.len() >= 2);
        for l in &lines[..lines.len() - 1] {
            assert!(l.starts_with("250-"), "continuation line: {l}");
        }
        let last = lines.last().unwrap();
        assert!(last.starts_with("250 "), "terminator line: {last}");
        assert!(!last.starts_with("250-"));
    }

    #[test]
    fn starttls_is_offered_only_when_it_can_actually_work() {
        let dev: SocketAddr = "10.20.0.7:41234".parse().unwrap();
        let other: SocketAddr = "10.20.0.8:41234".parse().unwrap();

        let mut cfg = Config::for_test();
        assert!(
            !offer_starttls(&cfg, dev, false),
            "must not advertise TLS we cannot do"
        );

        cfg.tls = Some(crate::tls_stub());
        assert!(offer_starttls(&cfg, dev, false));
        assert!(
            !offer_starttls(&cfg, dev, true),
            "re-advertising STARTTLS inside TLS confuses clients"
        );

        cfg.tls_trouble.remember(dev.ip());
        assert!(!offer_starttls(&cfg, dev, false));
        assert!(
            offer_starttls(&cfg, other, false),
            "one broken device must not take TLS away from the rest"
        );

        assert!(
            ehlo_lines(&cfg, true)
                .iter()
                .any(|l| l.contains("STARTTLS"))
        );
        assert!(
            !ehlo_lines(&cfg, false)
                .iter()
                .any(|l| l.contains("STARTTLS"))
        );
    }

    #[test]
    fn auth_is_always_advertised() {
        assert!(
            ehlo_lines(&Config::for_test(), false)
                .iter()
                .any(|l| l.contains("AUTH LOGIN PLAIN"))
        );
    }

    #[test]
    fn base64_falls_back_to_the_literal_bytes() {
        assert_eq!(b64("dXNlcg=="), b"user");
        assert_eq!(b64("not base64 at all"), b"not base64 at all");
    }

    #[test]
    fn the_auth_payload_never_reaches_the_trace() {
        let line = redact(b"AUTH PLAIN AGRldmljZTAxAHNlY3JldA==");
        assert!(
            !line.contains("AGRldmljZTAx"),
            "the credential blob leaked into the log: {line}"
        );
        assert!(line.starts_with("AUTH PLAIN"), "{line}");
        assert_eq!(redact(b"AUTH LOGIN"), "AUTH LOGIN");
        assert_eq!(redact(b"MAIL FROM:<a@b.c>"), "MAIL FROM:<a@b.c>");
    }

    #[test]
    fn the_cram_challenge_is_a_message_id() {
        let cfg = Config::for_test();
        let c = cram_challenge(&cfg);
        assert!(c.starts_with('<') && c.ends_with('>'), "{c}");
        assert!(c.contains(&format!("@{}>", cfg.hostname)), "{c}");
        assert_ne!(
            cram_challenge(&cfg),
            cram_challenge(&cfg),
            "a fixed challenge makes the digest a constant, which defeats the mechanism"
        );
    }
}

#[cfg(test)]
mod protocol {
    use super::*;
    use crate::{AuthPolicy, Config, Delivered};
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    fn peer() -> SocketAddr {
        "10.20.0.7:41234".parse().unwrap()
    }

    struct Harness {
        replies: String,
        got: Vec<Delivered>,
    }

    impl Harness {
        fn codes(&self) -> Vec<&str> {
            self.replies
                .lines()
                .filter(|l| l.len() >= 4 && l.as_bytes()[3] == b' ')
                .map(|l| &l[..3])
                .collect()
        }
    }

    async fn dialog(script: &[u8], cfg: Config, mut rx: mpsc::Receiver<Delivered>) -> Harness {
        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(async move {
            let mut st = State::default();
            run(
                &mut server,
                &mut st,
                &cfg,
                peer(),
                false,
                true,
                &Trace::new(false, peer()),
            )
            .await
        });

        client.write_all(script).await.unwrap();

        client.shutdown().await.unwrap();

        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();

        let mut got = Vec::new();
        while let Ok(m) = rx.try_recv() {
            got.push(m);
        }
        Harness {
            replies: String::from_utf8_lossy(&out).into_owned(),
            got,
        }
    }

    fn cfg() -> (Config, mpsc::Receiver<Delivered>) {
        let (tx, rx) = mpsc::channel(16);
        (Config::new(tx), rx)
    }

    async fn run_script(script: &[u8]) -> Harness {
        let (c, rx) = cfg();
        dialog(script, c, rx).await
    }

    async fn dialog_no_greeting(script: &[u8]) -> Harness {
        let (cfg, mut rx) = cfg();
        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(async move {
            let mut st = State::default();
            run(
                &mut server,
                &mut st,
                &cfg,
                peer(),
                true,
                false,
                &Trace::new(false, peer()),
            )
            .await
        });
        client.write_all(script).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        let mut got = Vec::new();
        while let Ok(m) = rx.try_recv() {
            got.push(m);
        }
        Harness {
            replies: String::from_utf8_lossy(&out).into_owned(),
            got,
        }
    }

    #[tokio::test]
    async fn no_greeting_is_sent_after_a_starttls_upgrade() {
        let h = dialog_no_greeting(
            b"EHLO secure\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<l@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert!(
            !h.replies.starts_with("220 "),
            "the upgraded session must not greet again: {:?}",
            h.replies
        );
        assert_eq!(
            h.codes(),
            ["250", "250", "250", "354", "250", "221"],
            "one reply per command, none extra: {:?}",
            h.replies
        );
        assert_eq!(h.got.len(), 1);
        assert!(
            h.got[0].tls,
            "mail over the upgraded connection is marked as encrypted"
        );
    }

    #[tokio::test]
    async fn the_plain_session_does_greet() {
        let h = run_script(b"QUIT\r\n").await;
        assert!(h.replies.starts_with("220 "), "{:?}", h.replies);
    }

    #[tokio::test]
    async fn starttls_is_refused_when_tls_is_already_active() {
        let h = dialog_no_greeting(b"EHLO s\r\nSTARTTLS\r\nQUIT\r\n").await;
        assert!(h.replies.contains("503 5.5.1 TLS is already active"));
        assert!(
            !h.replies.contains("250-STARTTLS"),
            "re-advertising STARTTLS inside TLS confuses clients"
        );
    }

    #[tokio::test]
    async fn a_complete_session_delivers_the_message() {
        let h = run_script(
            b"EHLO nas.local\r\n\
              MAIL FROM:<alarm@nas.local>\r\n\
              RCPT TO:<log@stmp2log>\r\n\
              DATA\r\n\
              Subject: Disk failure\r\n\
              \r\n\
              /dev/sda has failed.\r\n\
              .\r\n\
              QUIT\r\n",
        )
        .await;

        assert!(h.replies.starts_with("220 "), "greeting: {:?}", h.replies);
        assert_eq!(h.codes(), ["220", "250", "250", "250", "354", "250", "221"]);
        assert_eq!(h.got.len(), 1);
        let m = &h.got[0];
        assert_eq!(m.envelope_from, "alarm@nas.local");
        assert_eq!(m.rcpt, ["log@stmp2log"]);
        assert!(String::from_utf8_lossy(&m.data).contains("/dev/sda has failed."));
        assert!(String::from_utf8_lossy(&m.data).contains("Subject: Disk failure"));
        assert!(!m.tls);
    }

    #[tokio::test]
    async fn bare_lf_line_endings_work_end_to_end() {
        let h = run_script(
            b"EHLO dev\n\
              MAIL FROM:<a@b.c>\n\
              RCPT TO:<log@x>\n\
              DATA\n\
              Subject: bare lf\n\
              \n\
              body\n\
              .\n\
              QUIT\n",
        )
        .await;
        assert_eq!(h.got.len(), 1, "replies were: {:?}", h.replies);
        assert!(String::from_utf8_lossy(&h.got[0].data).contains("body"));
    }

    #[tokio::test]
    async fn helo_only_devices_can_still_deliver() {
        let h = run_script(
            b"HELO old-device\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert_eq!(h.got.len(), 1);
    }

    #[tokio::test]
    async fn auth_login_accepts_any_credentials() {
        let h = run_script(
            b"EHLO d\r\n\
              AUTH LOGIN\r\n\
              d2hhdGV2ZXI=\r\n\
              bm90LWEtcmVhbC1wYXNzd29yZA==\r\n\
              MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert!(h.replies.contains("235 2.7.0 authentication successful"));
        assert_eq!(h.got.len(), 1);
        assert_eq!(
            h.got[0].auth_user.as_deref(),
            Some("whatever"),
            "the username is worth recording even though it is not checked"
        );
    }

    #[tokio::test]
    async fn auth_login_takes_the_username_on_the_command_line() {
        let h = run_script(
            b"EHLO idrac\r\n\
              AUTH LOGIN dXBzLTAx\r\n\
              cGFzc3dvcmQ=\r\n\
              MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert_eq!(
            h.codes(),
            [
                "220", "250", "334", "235", "250", "250", "354", "250", "221"
            ],
            "exactly one challenge (the password) and then 235: {:?}",
            h.replies
        );
        assert_eq!(h.got.len(), 1, "replies were: {:?}", h.replies);
        assert_eq!(
            h.got[0].auth_user.as_deref(),
            Some("ups-01"),
            "the name from the command line is the account, not the next line"
        );
    }

    #[tokio::test]
    async fn a_cancelled_auth_exchange_is_refused_without_desyncing() {
        let h = run_script(b"EHLO d\r\nAUTH LOGIN\r\n*\r\nNOOP\r\nQUIT\r\n").await;
        assert!(
            h.replies.contains("501 5.7.0 authentication aborted"),
            "{:?}",
            h.replies
        );
        assert_eq!(
            h.codes(),
            ["220", "250", "334", "501", "250", "221"],
            "one reply per command, none extra: {:?}",
            h.replies
        );
    }

    #[tokio::test]
    async fn a_device_that_vanishes_mid_auth_is_not_told_it_succeeded() {
        let h = run_script(b"EHLO d\r\nAUTH LOGIN\r\n").await;
        assert!(
            !h.replies.contains("235 "),
            "nobody is there to authenticate: {:?}",
            h.replies
        );
    }

    #[tokio::test]
    async fn the_cram_challenge_on_the_wire_is_a_message_id() {
        let h = run_script(b"EHLO d\r\nAUTH CRAM-MD5\r\nZGV2aWNlMDEgYWJjZGVm\r\nQUIT\r\n").await;
        let line = h
            .replies
            .lines()
            .find(|l| l.starts_with("334 "))
            .unwrap_or_default();
        let challenge = String::from_utf8_lossy(&b64(&line[4..])).into_owned();
        assert!(
            challenge.starts_with('<') && challenge.contains('@') && challenge.ends_with('>'),
            "not a message-id: {challenge:?}"
        );
    }

    #[tokio::test]
    async fn auth_plain_with_an_initial_response() {
        let h = run_script(b"EHLO d\r\nAUTH PLAIN AGRldmljZTAxAHNlY3JldA==\r\nQUIT\r\n").await;
        assert!(h.replies.contains("235 "));
    }

    #[tokio::test]
    async fn auth_cram_md5_is_challenged_and_accepted() {
        let h = run_script(b"EHLO d\r\nAUTH CRAM-MD5\r\nZGV2aWNlMDEgYWJjZGVm\r\nQUIT\r\n").await;
        assert!(h.replies.contains("334 "));
        assert!(h.replies.contains("235 "));
    }

    async fn login_as(policy: AuthPolicy, user: &str, pass: &str) -> Harness {
        use base64::Engine;
        let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let (mut c, rx) = cfg();
        c.auth = policy;
        let script = format!(
            "EHLO d\r\nAUTH LOGIN\r\n{}\r\n{}\r\nQUIT\r\n",
            enc(user),
            enc(pass)
        );
        dialog(script.as_bytes(), c, rx).await
    }

    fn require(user: &str, pass: &str) -> AuthPolicy {
        AuthPolicy::Require {
            user: user.into(),
            pass: pass.into(),
        }
    }

    const OK: &str = "235 2.7.0 authentication successful";
    const NO: &str = "535 5.7.8 authentication failed";

    async fn deliver_anonymously(policy: AuthPolicy) -> Harness {
        let (mut c, rx) = cfg();
        c.auth = policy;
        dialog(
            b"EHLO d\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
            c,
            rx,
        )
        .await
    }

    #[tokio::test]
    async fn anonymous_delivery_is_refused_once_credentials_are_configured() {
        for p in [
            require("device01", ""),
            require("", "s3cret"),
            require("d", "s"),
        ] {
            let h = deliver_anonymously(p).await;
            assert!(
                h.replies.contains("530 5.7.0 authentication required"),
                "{}",
                h.replies
            );
            assert!(h.got.is_empty());
        }
    }

    #[tokio::test]
    async fn anonymous_delivery_is_the_normal_case_when_nothing_is_configured() {
        let h = deliver_anonymously(AuthPolicy::AcceptAny).await;
        assert_eq!(h.got.len(), 1);
        assert!(h.got[0].auth_user.is_none());
    }

    #[tokio::test]
    async fn a_device_that_fills_in_only_the_account_can_still_deliver() {
        use base64::Engine;
        let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let (c, rx) = cfg();
        let script = format!(
            "EHLO d\r\nAUTH LOGIN\r\n{}\r\n{}\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
            enc("ups-01"),
            enc("")
        );
        let h = dialog(script.as_bytes(), c, rx).await;
        assert!(h.replies.contains(OK), "{}", h.replies);
        assert_eq!(h.got.len(), 1);
        assert_eq!(h.got[0].auth_user.as_deref(), Some("ups-01"));
    }

    #[tokio::test]
    async fn only_a_configured_username_is_checked() {
        let p = || require("device01", "");
        assert!(
            login_as(p(), "device01", "anything")
                .await
                .replies
                .contains(OK)
        );
        assert!(login_as(p(), "device01", "").await.replies.contains(OK));
        assert!(
            login_as(p(), "wrong", "anything")
                .await
                .replies
                .contains(NO)
        );
    }

    #[tokio::test]
    async fn only_a_configured_password_is_checked() {
        let p = || require("", "s3cret");
        assert!(login_as(p(), "ups-01", "s3cret").await.replies.contains(OK));
        assert!(login_as(p(), "nas-07", "s3cret").await.replies.contains(OK));
        assert!(login_as(p(), "", "s3cret").await.replies.contains(OK));
        assert!(login_as(p(), "ups-01", "wrong").await.replies.contains(NO));
    }

    #[tokio::test]
    async fn both_are_checked_when_both_are_configured() {
        let p = || require("device01", "s3cret");
        assert!(
            login_as(p(), "device01", "s3cret")
                .await
                .replies
                .contains(OK)
        );
        assert!(
            login_as(p(), "device01", "wrong")
                .await
                .replies
                .contains(NO)
        );
        assert!(login_as(p(), "wrong", "s3cret").await.replies.contains(NO));
    }

    #[tokio::test]
    async fn auth_plain_carries_both_fields_too() {
        use base64::Engine;

        let payload = base64::engine::general_purpose::STANDARD.encode("\0device01\0s3cret");
        let (mut c, rx) = cfg();
        c.auth = require("device01", "s3cret");
        let h = dialog(
            format!("EHLO d\r\nAUTH PLAIN {payload}\r\nQUIT\r\n").as_bytes(),
            c,
            rx,
        )
        .await;
        assert!(h.replies.contains(OK), "{:?}", h.replies);
    }

    #[tokio::test]
    async fn cram_md5_disappears_once_a_password_is_required() {
        let mut c = Config::for_test();
        c.auth = require("", "s3cret");
        let advertised = ehlo_lines(&c, false).join("\n");
        assert!(advertised.contains("AUTH LOGIN PLAIN"));
        assert!(!advertised.contains("CRAM-MD5"), "{advertised}");

        let c = Config::for_test();
        assert!(ehlo_lines(&c, false).join("\n").contains("CRAM-MD5"));
    }

    #[tokio::test]
    async fn cram_md5_is_refused_rather_than_bypassing_the_password_check() {
        let (mut c, rx) = cfg();
        c.auth = require("", "s3cret");
        let h = dialog(
            b"EHLO d\r\nAUTH CRAM-MD5\r\nZGV2aWNlMDEgYWJjZGVm\r\nQUIT\r\n",
            c,
            rx,
        )
        .await;
        assert!(h.replies.contains(NO), "{:?}", h.replies);
    }

    #[tokio::test]
    async fn the_username_is_recorded_even_when_nothing_is_checked() {
        let h = run_script(
            b"EHLO d\r\nAUTH LOGIN\r\ndXBzLTAx\r\ncHc=\r\n\
              MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert_eq!(h.got[0].auth_user.as_deref(), Some("ups-01"));
    }

    #[tokio::test]
    async fn dot_stuffing_is_undone() {
        let h = run_script(
            b"MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\n\
              ..hidden leading dot\r\n\
              normal\r\n\
              .\r\nQUIT\r\n",
        )
        .await;
        let body = String::from_utf8_lossy(&h.got[0].data).into_owned();
        assert!(body.contains(".hidden leading dot"), "body was {body:?}");
        assert!(!body.contains("..hidden"));
    }

    #[tokio::test]
    async fn data_without_mail_from_still_yields_a_record() {
        let h = run_script(b"DATA\r\nSubject: orphan\r\n\r\nbody\r\n.\r\nQUIT\r\n").await;
        assert_eq!(h.got.len(), 1);
        assert_eq!(
            h.got[0].envelope_from, "unknown@10.20.0.7",
            "the placeholder must still say where it came from"
        );
        assert!(
            !h.got[0].rcpt.is_empty(),
            "a placeholder recipient keeps the record listable"
        );
    }

    #[tokio::test]
    async fn an_oversized_message_is_rejected_and_the_session_survives() {
        let (mut c, rx) = cfg();
        c.max_size = 64;
        let mut script = b"MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\n".to_vec();
        for _ in 0..20 {
            script.extend_from_slice(b"padding padding padding padding\r\n");
        }
        script.extend_from_slice(b".\r\nNOOP\r\nQUIT\r\n");

        let h = dialog(&script, c, rx).await;
        assert!(h.replies.contains("552 "), "replies: {:?}", h.replies);
        assert!(h.got.is_empty());
        assert!(
            h.replies.contains("250 2.0.0 ok"),
            "the NOOP after the oversized DATA must still be answered: {:?}",
            h.replies
        );
    }

    #[tokio::test]
    async fn a_full_queue_asks_the_device_to_retry() {
        let (tx, rx) = mpsc::channel(1);
        let c = Config::new(tx);

        let h = dialog(
            b"MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\none\r\n.\r\n\
              MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\ntwo\r\n.\r\nQUIT\r\n",
            c,
            rx,
        )
        .await;
        assert!(h.replies.contains("250 2.0.0 message accepted"));
        assert!(
            h.replies.contains("451 4.3.1"),
            "a full queue must ask for a retry, not silently drop: {:?}",
            h.replies
        );
    }

    #[tokio::test]
    async fn unknown_commands_do_not_end_the_session() {
        let h = run_script(b"EHLO d\r\nWHAT IS THIS\r\nNOOP\r\nQUIT\r\n").await;
        assert!(h.replies.contains("500 5.5.2 unknown command WHAT"));
        assert!(
            h.replies.contains("250 2.0.0 ok"),
            "NOOP after a bad command"
        );
        assert!(h.replies.contains("221 "));
    }

    #[tokio::test]
    async fn blank_lines_between_commands_are_ignored() {
        let h = run_script(b"EHLO d\r\n\r\n\r\nNOOP\r\nQUIT\r\n").await;
        assert!(!h.replies.contains("500 "), "replies: {:?}", h.replies);
    }

    #[tokio::test]
    async fn ehlo_resets_a_half_built_envelope() {
        let h = run_script(
            b"MAIL FROM:<first@x>\r\nRCPT TO:<a@y>\r\n\
              EHLO restart\r\n\
              MAIL FROM:<second@x>\r\nRCPT TO:<b@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert_eq!(h.got.len(), 1);
        assert_eq!(h.got[0].envelope_from, "second@x");
        assert_eq!(
            h.got[0].rcpt,
            ["b@y"],
            "the first envelope must not leak in"
        );
    }

    #[tokio::test]
    async fn rset_clears_the_envelope() {
        let h = run_script(
            b"MAIL FROM:<first@x>\r\nRCPT TO:<a@y>\r\nRSET\r\n\
              MAIL FROM:<second@x>\r\nRCPT TO:<b@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert_eq!(h.got[0].rcpt, ["b@y"]);
    }

    #[tokio::test]
    async fn multiple_messages_in_one_connection() {
        let h = run_script(
            b"EHLO d\r\n\
              MAIL FROM:<a@x>\r\nRCPT TO:<l@y>\r\nDATA\r\nfirst\r\n.\r\n\
              MAIL FROM:<b@x>\r\nRCPT TO:<l@y>\r\nDATA\r\nsecond\r\n.\r\n\
              QUIT\r\n",
        )
        .await;
        assert_eq!(h.got.len(), 2);
        assert_eq!(h.got[0].envelope_from, "a@x");
        assert_eq!(h.got[1].envelope_from, "b@x");
        assert!(String::from_utf8_lossy(&h.got[1].data).contains("second"));
    }

    #[tokio::test]
    async fn a_connection_that_dies_mid_data_still_keeps_what_arrived() {
        let h = run_script(b"MAIL FROM:<a@x>\r\nRCPT TO:<l@y>\r\nDATA\r\npartial line\r\n").await;
        assert_eq!(h.got.len(), 1);
        assert!(String::from_utf8_lossy(&h.got[0].data).contains("partial line"));
    }

    async fn state_after(script: &'static [u8]) -> State {
        let (c, _rx) = cfg();
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let mut st = State::default();
            let tr = Trace::new(false, peer());
            let _ = run(&mut server, &mut st, &c, peer(), false, true, &tr).await;
            st
        });
        client.write_all(script).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap()
    }

    #[tokio::test]
    async fn the_caller_can_tell_that_a_device_left_empty_handed() {
        assert!(
            state_after(b"EHLO idrac\r\nQUIT\r\n")
                .await
                .greeted_but_delivered_nothing()
        );
        assert!(
            !state_after(
                b"EHLO d\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n"
            )
            .await
            .greeted_but_delivered_nothing(),
            "a session that delivered a message must not look like one that gave up"
        );
    }

    #[tokio::test]
    async fn a_device_whose_handshake_failed_is_no_longer_offered_starttls() {
        let (mut c, rx) = cfg();
        c.tls = Some(crate::tls_stub());
        c.tls_trouble.remember(peer().ip());
        let h = dialog(
            b"EHLO idrac\r\nSTARTTLS\r\n\
              MAIL FROM:<a@b.c>\r\nRCPT TO:<x@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
            c,
            rx,
        )
        .await;
        assert!(
            !h.replies.contains("STARTTLS"),
            "advertising it again just makes the device fail again: {:?}",
            h.replies
        );
        assert!(
            h.replies.contains("454 4.7.0 TLS is not available"),
            "a device that asks anyway must be told no, not upgraded: {:?}",
            h.replies
        );
        assert_eq!(h.got.len(), 1, "and the alert still gets through");
    }

    #[tokio::test]
    async fn starttls_is_refused_cleanly_when_tls_is_unavailable() {
        let h = run_script(b"EHLO d\r\nSTARTTLS\r\nNOOP\r\nQUIT\r\n").await;
        assert!(h.replies.contains("454 4.7.0 TLS is not available"));
        assert!(
            h.replies.contains("250 2.0.0 ok"),
            "the session must continue"
        );
    }

    #[tokio::test]
    async fn gbk_bytes_in_the_envelope_do_not_break_the_parser() {
        let mut script = b"MAIL FROM:<\xCE\xC2\xB6\xC8@nas.local>\r\nRCPT TO:<l@y>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n".to_vec();
        script.shrink_to_fit();
        let h = run_script(&script).await;
        assert_eq!(h.got.len(), 1, "replies: {:?}", h.replies);
    }

    #[tokio::test]
    async fn too_many_recipients_is_refused_without_dropping_the_message() {
        let mut script = b"MAIL FROM:<a@x>\r\n".to_vec();
        for i in 0..(MAX_RCPT + 5) {
            script.extend_from_slice(format!("RCPT TO:<r{i}@y>\r\n").as_bytes());
        }
        script.extend_from_slice(b"DATA\r\nhi\r\n.\r\nQUIT\r\n");
        let h = run_script(&script).await;
        assert!(h.replies.contains("452 4.5.3 too many recipients"));
        assert_eq!(h.got.len(), 1, "the message itself is still accepted");
        assert_eq!(h.got[0].rcpt.len(), MAX_RCPT);
    }
}
