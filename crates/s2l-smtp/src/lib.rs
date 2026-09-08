// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

mod session;
pub mod tls;

pub use session::{End, State};

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct Delivered {
    pub envelope_from: String,
    pub rcpt: Vec<String>,
    pub peer: SocketAddr,

    pub data: Vec<u8>,
    pub size: usize,

    pub tls: bool,

    pub auth_user: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AuthPolicy {
    AcceptAny,

    Require { user: String, pass: String },
}

const MAX_TLS_TROUBLE: usize = 256;

#[derive(Clone, Default)]
pub struct TlsTrouble(Arc<Mutex<HashSet<IpAddr>>>);

impl TlsTrouble {
    pub(crate) fn remember(&self, ip: IpAddr) -> bool {
        let Ok(mut set) = self.0.lock() else {
            return false;
        };
        if set.len() >= MAX_TLS_TROUBLE {
            set.clear();
        }
        set.insert(ip)
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.0.lock().map(|s| s.contains(&ip)).unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind: Vec<SocketAddr>,

    pub tls_bind: Vec<SocketAddr>,

    pub hostname: String,
    pub max_size: usize,
    pub timeout: Duration,

    pub max_conns: usize,
    pub tls: Option<Arc<rustls::ServerConfig>>,

    pub starttls: bool,
    pub auth: AuthPolicy,

    pub tls_trouble: TlsTrouble,

    pub trace: bool,
    pub sink: mpsc::Sender<Delivered>,
}

impl Config {
    pub fn new(sink: mpsc::Sender<Delivered>) -> Self {
        Self {
            bind: Vec::new(),
            tls_bind: Vec::new(),
            hostname: "stmp2log".into(),

            max_size: 10 * 1024 * 1024,

            timeout: Duration::from_secs(300),
            max_conns: 64,
            tls: None,
            starttls: true,
            auth: AuthPolicy::AcceptAny,
            tls_trouble: TlsTrouble::default(),
            trace: false,
            sink,
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self::new(tx)
    }
}

pub async fn serve(cfg: Config) -> Result<(), SmtpError> {
    let limit = Arc::new(tokio::sync::Semaphore::new(cfg.max_conns));

    for &addr in &cfg.bind {
        let l = TcpListener::bind(addr)
            .await
            .map_err(|source| SmtpError::Bind { addr, source })?;
        info(&format!("SMTP listening on {addr}"));
        spawn_accept_loop(l, cfg.clone(), limit.clone(), false);
    }

    for &addr in &cfg.tls_bind {
        if cfg.tls.is_none() {
            warn(&format!(
                "skipping implicit-TLS listener on {addr}: TLS is not configured"
            ));
            continue;
        }
        let l = TcpListener::bind(addr)
            .await
            .map_err(|source| SmtpError::Bind { addr, source })?;
        info(&format!("SMTP listening on {addr} (implicit TLS)"));
        spawn_accept_loop(l, cfg.clone(), limit.clone(), true);
    }

    Ok(())
}

fn spawn_accept_loop(
    listener: TcpListener,
    cfg: Config,
    limit: Arc<tokio::sync::Semaphore>,
    implicit_tls: bool,
) {
    tokio::spawn(async move {
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn(&format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                let mut sock = sock;
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut sock,
                    b"421 4.7.0 too many connections\r\n",
                )
                .await;
                continue;
            };
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle(sock, peer, &cfg, implicit_tls).await {
                    let _ = e;
                }
            });
        }
    });
}

async fn handle(
    sock: TcpStream,
    peer: SocketAddr,
    cfg: &Config,
    implicit_tls: bool,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);

    let tr = session::Trace::new(cfg.trace, peer);

    if implicit_tls {
        let Some(tls) = cfg.tls.clone() else {
            return Ok(());
        };
        tr.note("connected (implicit TLS)");
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        let mut stream = match acceptor.accept(sock).await {
            Ok(s) => s,
            Err(e) => {
                handshake_failed(cfg, peer, true, &e);
                return Ok(());
            }
        };
        let mut st = State::default();

        session::run(&mut stream, &mut st, cfg, peer, true, true, &tr).await?;
        tr.note("session ended");
        return Ok(());
    }

    tr.note("connected");
    let mut sock = sock;
    let mut st = State::default();
    match session::run(&mut sock, &mut st, cfg, peer, false, true, &tr).await? {
        End::Done => {
            tr.note("session ended");
            Ok(())
        }
        End::StartTls => {
            let Some(tls) = cfg.tls.clone() else {
                return Ok(());
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(tls);
            let mut stream = match acceptor.accept(sock).await {
                Ok(s) => s,
                Err(e) => {
                    handshake_failed(cfg, peer, false, &e);
                    return Ok(());
                }
            };
            tr.note("TLS handshake done");

            let mut fresh = State::default();

            session::run(&mut stream, &mut fresh, cfg, peer, true, false, &tr).await?;
            tr.note("session ended");
            Ok(())
        }
    }
}

fn handshake_failed(cfg: &Config, peer: SocketAddr, implicit_tls: bool, e: &std::io::Error) {
    let first = cfg.tls_trouble.remember(peer.ip());

    if !first {
        warn(&format!("TLS handshake with {peer} failed again: {e}"));
        return;
    }
    let advice = if implicit_tls {
        "Point the device at the plaintext port (stmp_listen) instead.".to_string()
    } else {
        format!(
            "STARTTLS will no longer be offered to {}, so it can deliver in the clear \
             (stmp_starttls=0 hides STARTTLS from every device).",
            peer.ip()
        )
    };
    warn(&format!(
        "TLS handshake with {peer} failed: {e}. This device's TLS is older than the \
         TLS 1.2 + ECDHE that stmp2log accepts. {advice}"
    ));
}

pub fn load_tls(data: &Path, names: &[String]) -> Result<Arc<rustls::ServerConfig>, SmtpError> {
    tls::load_or_create(data, names)
}

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
fn tls_stub() -> Arc<rustls::ServerConfig> {
    install_crypto_provider();
    let dir = std::env::temp_dir().join(format!(
        "s2l-tlsstub-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cfg = tls::load_or_create(&dir, &[]).expect("stub cert");
    std::fs::remove_dir_all(&dir).ok();
    cfg
}

pub(crate) fn info(msg: &str) {
    eprintln!("[smtp] {msg}");
}

pub(crate) fn warn(msg: &str) {
    eprintln!("[smtp] WARN {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_device_is_remembered_once_and_the_set_stays_bounded() {
        let t = TlsTrouble::default();
        let dev: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(
            t.remember(dev),
            "the first failure is the one that gets the long explanation"
        );
        assert!(
            !t.remember(dev),
            "every retry after that must not repeat it"
        );
        assert!(t.contains(dev));
        assert!(
            !t.contains("10.0.0.10".parse().unwrap()),
            "one broken device must not take TLS away from the rest"
        );

        for i in 0..MAX_TLS_TROUBLE + 5 {
            t.remember(format!("10.1.{}.{}", i / 256, i % 256).parse().unwrap());
        }
        assert!(t.0.lock().unwrap().len() <= MAX_TLS_TROUBLE);
    }
}
