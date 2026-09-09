// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADERS: usize = 64;

const MAX_REDIRECTS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("bad url {0:?}")]
    BadUrl(String),
    #[error("could not resolve {0}")]
    Resolve(String),
    #[error("could not connect to {0}: {1}")]
    Connect(String, std::io::Error),
    #[error("tls handshake with {0} failed: {1}")]
    Tls(String, std::io::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed response: {0}")]
    Protocol(String),
    #[error("response body exceeds the {MAX_BODY} byte limit")]
    TooLarge,
    #[error("{0} timed out")]
    Timeout(String),
    #[error("too many redirects")]
    TooManyRedirects,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Clone)]
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
    trace: bool,
}

impl Client {
    pub fn new(timeout: Duration) -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls: Arc::new(tls),
            timeout,
            trace: false,
        }
    }

    pub fn with_trace(mut self, on: bool) -> Self {
        self.trace = on;
        self
    }
    pub(crate) fn tracing(&self) -> bool {
        self.trace
    }

    pub(crate) fn tls(&self) -> Arc<rustls::ClientConfig> {
        self.tls.clone()
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn send(&self, req: Request<'_>) -> Result<Response, HttpError> {
        let what = format!("{} {}", req.method, req.url);
        tokio::time::timeout(self.timeout, self.follow(req))
            .await
            .map_err(|_| HttpError::Timeout(what))?
    }

    async fn follow(&self, req: Request<'_>) -> Result<Response, HttpError> {
        let mut url = req.url.to_string();
        let mut method = req.method.to_string();
        let mut body = req.body.map(|b| b.to_vec());
        let headers = req.headers.to_vec();

        for _ in 0..=MAX_REDIRECTS {
            let (resp, location) = {
                let cur = Request {
                    method: &method,
                    url: &url,
                    headers: &headers,
                    body: body.as_deref(),
                };
                self.once(&cur).await?
            };

            let Some(loc) = location else {
                return Ok(resp);
            };
            match resp.status {
                301..=303 => {
                    method = "GET".into();
                    body = None;
                }

                307 | 308 => {}
                _ => return Ok(resp),
            }
            url = absolutize(&url, &loc).ok_or(HttpError::BadUrl(loc))?;
        }
        Err(HttpError::TooManyRedirects)
    }

    async fn once(&self, req: &Request<'_>) -> Result<(Response, Option<String>), HttpError> {
        let parts = Url::parse(req.url).ok_or_else(|| HttpError::BadUrl(req.url.into()))?;
        let addr = tokio::net::lookup_host((parts.host.as_str(), parts.port))
            .await
            .map_err(|_| HttpError::Resolve(parts.host.clone()))?
            .next()
            .ok_or_else(|| HttpError::Resolve(parts.host.clone()))?;

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| HttpError::Connect(addr.to_string(), e))?;
        let _ = tcp.set_nodelay(true);

        let raw = if parts.https {
            let name = rustls::pki_types::ServerName::try_from(parts.host.clone())
                .map_err(|_| HttpError::BadUrl(parts.host.clone()))?;
            let conn = tokio_rustls::TlsConnector::from(self.tls.clone());
            let stream = conn
                .connect(name, tcp)
                .await
                .map_err(|e| HttpError::Tls(parts.host.clone(), e))?;
            exchange(stream, req, &parts).await?
        } else {
            exchange(tcp, req, &parts).await?
        };

        parse_response(&raw)
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, String)],
    pub body: Option<&'a [u8]>,
}

async fn exchange<S>(mut io: S, req: &Request<'_>, url: &Url) -> Result<Vec<u8>, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: stmp2log\r\n",
        req.method, url.path, url.authority
    );
    for (k, v) in req.headers {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }

    if req.method != "GET" || req.body.is_some() {
        head.push_str(&format!(
            "Content-Length: {}\r\n",
            req.body.map(|b| b.len()).unwrap_or(0)
        ));
    }
    head.push_str("\r\n");

    io.write_all(head.as_bytes()).await?;
    if let Some(b) = req.body {
        io.write_all(b).await?;
    }
    io.flush().await?;

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = match io.read(&mut chunk).await {
            Ok(n) => n,

            Err(e) if !raw.is_empty() && is_abrupt_close(&e) => break,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_BODY {
            return Err(HttpError::TooLarge);
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    Ok(raw)
}

fn is_abrupt_close(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
    )
}

fn parse_response(raw: &[u8]) -> Result<(Response, Option<String>), HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);

    let head_len = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::Protocol(
                "incomplete response headers (peer closed early?)".into(),
            ));
        }
        Err(e) => return Err(HttpError::Protocol(e.to_string())),
    };
    let status = resp
        .code
        .ok_or_else(|| HttpError::Protocol("missing status code".into()))?;

    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_string())
    };
    let chunked =
        header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let location = header("location");

    let rest = &raw[head_len..];
    let body = if chunked {
        dechunk(rest)?
    } else {
        match header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(n) => rest.get(..n.min(rest.len())).unwrap_or(rest).to_vec(),
            None => rest.to_vec(),
        }
    };

    let redirect = if (300..400).contains(&status) {
        location
    } else {
        None
    };
    Ok((Response { status, body }, redirect))
}

fn dechunk(mut buf: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let nl = buf
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| HttpError::Protocol("unterminated chunk-size line".into()))?;
        let line = std::str::from_utf8(&buf[..nl])
            .map_err(|_| HttpError::Protocol("chunk-size line is not UTF-8".into()))?;

        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| HttpError::Protocol(format!("invalid chunk size {size_hex:?}")))?;

        buf = &buf[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if out.len() + size > MAX_BODY {
            return Err(HttpError::TooLarge);
        }
        let data = buf
            .get(..size)
            .ok_or_else(|| HttpError::Protocol("truncated chunk".into()))?;
        out.extend_from_slice(data);
        buf = buf.get(size + 2..).unwrap_or(&[]);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,

    pub authority: String,

    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> Option<Url> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else {
            let r = url.strip_prefix("http://")?;
            (false, r)
        };

        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };

        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path
        };

        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h, p.parse().ok()?),
            _ => (authority, if https { 443 } else { 80 }),
        };
        if host.is_empty() {
            return None;
        }
        Some(Url {
            https,
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            authority: authority.to_string(),
            path,
        })
    }
}

fn absolutize(base: &str, loc: &str) -> Option<String> {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return Some(loc.to_string());
    }
    let b = Url::parse(base)?;
    let scheme = if b.https { "https" } else { "http" };
    if loc.starts_with('/') {
        return Some(format!("{scheme}://{}{loc}", b.authority));
    }
    let dir = match b.path.rfind('/') {
        Some(i) => &b.path[..=i],
        None => "/",
    };
    Some(format!("{scheme}://{}{dir}{loc}", b.authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_url_shapes_the_providers_use() {
        let u = Url::parse("https://ntfy.sh/mytopic").unwrap();
        assert!(u.https);
        assert_eq!(u.host, "ntfy.sh");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/mytopic");

        let u = Url::parse("http://192.168.1.5:8080/ntfy/topic").unwrap();
        assert!(!u.https);
        assert_eq!(u.port, 8080);
        assert_eq!(u.authority, "192.168.1.5:8080", "Host: must carry the port");

        let u = Url::parse("https://oapi.dingtalk.com/robot/send?access_token=abc").unwrap();
        assert_eq!(u.path, "/robot/send?access_token=abc");

        assert_eq!(Url::parse("https://ntfy.sh").unwrap().path, "/");

        assert_eq!(Url::parse("https://h?a=b").unwrap().path, "/?a=b");
    }

    #[test]
    fn rejects_urls_without_a_scheme() {
        assert!(Url::parse("ntfy.sh/topic").is_none());
        assert!(Url::parse("https://").is_none());
        assert!(Url::parse("").is_none());
    }

    #[test]
    fn parses_ipv6_literals() {
        let u = Url::parse("http://[fd00::1]:8025/x").unwrap();
        assert_eq!(u.host, "fd00::1");
        assert_eq!(u.port, 8025);
    }

    #[test]
    fn parses_a_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"errcode\":0}\r\n";
        let (r, redir) = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["errcode"], 0);
        assert!(redir.is_none());
    }

    #[test]
    fn parses_a_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().0.text(), "hello world");
    }

    #[test]
    fn a_body_without_content_length_reads_to_eof() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n{\"code\":0}";
        assert_eq!(parse_response(raw).unwrap().0.json()["code"], 0);
    }

    #[test]
    fn a_non_json_error_page_does_not_panic() {
        let raw = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 22\r\n\r\n<html>bad gateway</html>";
        let (r, _) = parse_response(raw).unwrap();
        assert_eq!(r.status, 502);
        assert!(r.json().is_null());
    }

    #[test]
    fn redirects_are_reported_only_for_3xx() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response(raw).unwrap().1.as_deref(),
            Some("/elsewhere")
        );

        let raw = b"HTTP/1.1 200 OK\r\nLocation: /ignored\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_response(raw).unwrap().1.is_none());
    }

    #[test]
    fn absolutize_handles_all_three_location_forms() {
        let base = "https://push.example.com/api/send?k=1";
        assert_eq!(
            absolutize(base, "https://other.example/x").unwrap(),
            "https://other.example/x"
        );
        assert_eq!(
            absolutize(base, "/v2/send").unwrap(),
            "https://push.example.com/v2/send"
        );
        assert_eq!(
            absolutize(base, "send2").unwrap(),
            "https://push.example.com/api/send2"
        );
    }

    #[test]
    fn rejects_malformed_responses() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_response(b"not http at all\r\n\r\n").is_err());
        let bad_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n";
        assert!(parse_response(bad_chunk).is_err());
    }
}
