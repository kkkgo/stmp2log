// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::router::{self, Route};
use crate::{Api, ApiReq, ServerConfig, respond, respond::Reply};

const MAX_HEAD: usize = 16 * 1024;

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_HEADERS: usize = 64;

const READ_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn serve(cfg: Arc<ServerConfig>) -> std::io::Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    eprintln!("[web] listening on http://{}{}/", cfg.bind, cfg.base);

    tokio::spawn(async move {
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {

                    eprintln!("[web] WARN accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let _ = handle(sock, peer, cfg).await;
            });
        }
    });
    Ok(())
}

async fn handle(
    mut sock: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);

    let head = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut sock)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(reply)) => return write_reply(&mut sock, &reply).await,
        Err(_) => {
            return write_reply(&mut sock, &respond::error(408, "request timed out")).await;
        }
    };

    let route = router::classify(&cfg.base, &head.path);

    if matches!(route, Route::Events) {

        let ok = authorized(&cfg, &head)
            || query_param(&head.query, "token").is_some_and(|t| cfg.auth.load().verify(&t));
        if !ok {
            return write_reply(&mut sock, &respond::error(401, "unauthorized")).await;
        }
        return stream_events(sock, cfg).await;
    }

    let reply = dispatch(route, &head, peer, &cfg).await;
    write_reply(&mut sock, &reply).await
}

async fn dispatch(route: Route, head: &Head, peer: SocketAddr, cfg: &ServerConfig) -> Reply {
    match route {
        Route::Redirect => respond::redirect(&format!("{}/", cfg.base)),
        Route::Index => {
            if head.if_none_match.as_deref() == Some(cfg.asset.etag.as_str()) {
                return respond::not_modified(&cfg.asset.etag);
            }
            if head.accepts_gzip && !cfg.asset.gzip.is_empty() {
                respond::html((*cfg.asset.gzip).clone(), true, &cfg.asset.etag)
            } else {
                respond::html((*cfg.asset.plain).clone(), false, &cfg.asset.etag)
            }
        }
        Route::Api(path) => {

            let public = path == "auth/challenge" || path == "auth/login" || path == "push";
            if !public && !authorized(cfg, head) {
                return respond::error(401, "unauthorized");
            }
            cfg.api
                .call(ApiReq {
                    method: head.method.clone(),
                    path,
                    query: head.query.clone(),
                    body: head.body.clone(),
                    token: head.bearer.clone().unwrap_or_default(),
                    peer,
                })
                .await
        }
        Route::Events => respond::error(500, "unreachable"),
        Route::NotFound => respond::error(404, "no such path"),
    }
}

fn authorized(cfg: &ServerConfig, head: &Head) -> bool {
    cfg.auth.load().verify(head.bearer.as_deref().unwrap_or(""))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (crate::urldecode(k) == name).then(|| crate::urldecode(v))
    })
}

async fn stream_events(mut sock: TcpStream, cfg: Arc<ServerConfig>) -> std::io::Result<()> {
    let Some(events) = &cfg.events else {
        return write_reply(&mut sock, &respond::error(503, "events are not enabled")).await;
    };
    let mut rx = events.subscribe();

    let head = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/event-stream; charset=utf-8\r\n\
                Cache-Control: no-store\r\n\
                Connection: close\r\n\
                X-Accel-Buffering: no\r\n\r\n";
    sock.write_all(head.as_bytes()).await?;
    sock.flush().await?;

    loop {

        let next = tokio::time::timeout(Duration::from_secs(20), rx.recv()).await;
        let frame = match next {
            Ok(Ok(msg)) => format!("data: {msg}\n\n"),

            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                format!("event: lagged\ndata: {n}\n\n")
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return Ok(()),
            Err(_) => ": keepalive\n\n".to_string(),
        };
        if sock.write_all(frame.as_bytes()).await.is_err() {
            return Ok(());
        }
        if sock.flush().await.is_err() {
            return Ok(());
        }
    }
}

pub struct Head {
    pub method: String,
    pub path: String,
    pub query: String,
    pub bearer: Option<String>,
    pub if_none_match: Option<String>,
    pub accepts_gzip: bool,
    pub body: Vec<u8>,
}

async fn read_request(sock: &mut TcpStream) -> Result<Option<Head>, Reply> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 8192];

    let head_len = loop {
        let n = sock
            .read(&mut chunk)
            .await
            .map_err(|_| respond::error(400, "read failed"))?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(respond::error(400, "incomplete request"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD {
            return Err(respond::error(413, "request headers too large"));
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => break n,
            Ok(httparse::Status::Partial) => continue,
            Err(_) => return Err(respond::error(400, "malformed request")),
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(&buf), Ok(httparse::Status::Complete(_))) {
        return Err(respond::error(400, "malformed request"));
    }

    let method = req.method.unwrap_or("GET").to_string();
    let target = req.path.unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };

    let get = |name: &str| -> Option<String> {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_string())
    };

    let bearer = get("authorization").and_then(|v| {
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
            .map(|t| t.trim().to_string())
    });
    let content_length = get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(respond::error(413, "request body too large"));
    }
    let accepts_gzip = get("accept-encoding").is_some_and(|v| v.contains("gzip"));
    let if_none_match = get("if-none-match");

    let mut body = buf[head_len..].to_vec();
    while body.len() < content_length {
        let n = sock
            .read(&mut chunk)
            .await
            .map_err(|_| respond::error(400, "read failed"))?;
        if n == 0 {
            return Err(respond::error(400, "incomplete request body"));
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > MAX_BODY {
            return Err(respond::error(413, "request body too large"));
        }
    }
    body.truncate(content_length);

    Ok(Some(Head {
        method,
        path,
        query,
        bearer,
        if_none_match,
        accepts_gzip,
        body,
    }))
}

async fn write_reply(sock: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    sock.write_all(&reply.to_bytes()).await?;
    sock.flush().await
}

impl<F> Api for F
where
    F: Fn(ApiReq) -> crate::ApiFuture + Send + Sync + 'static,
{
    fn call(&self, req: ApiReq) -> crate::ApiFuture {
        self(req)
    }
}
