// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

mod compat;
mod session;
pub mod tls;

pub use compat::CompatTls;
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

    pub compat: Option<compat::CompatTls>,
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
            compat: None,
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
        tr.note("connected (implicit TLS)");
        let Some(accepted) = accept_tls(sock, peer, cfg, true, &tr).await else {
            return Ok(());
        };
        let mut st = State::default();

        run_encrypted(accepted, &mut st, cfg, peer, true, &tr).await?;
        tr.note("session ended");
        return Ok(());
    }

    tr.note("connected");
    let mut sock = sock;
    let mut st = State::default();
    match session::run(&mut sock, &mut st, cfg, peer, false, true, &tr).await? {
        End::Done => {
            tr.note("session ended");
            gave_up_without_tls(cfg, peer, &st);
            Ok(())
        }
        End::StartTls => {
            let Some(accepted) = accept_tls(sock, peer, cfg, false, &tr).await else {
                return Ok(());
            };
            tr.note("TLS handshake done");

            let mut fresh = State::default();

            run_encrypted(accepted, &mut fresh, cfg, peer, false, &tr).await?;
            tr.note("session ended");
            Ok(())
        }
    }
}

enum Accepted {
    Modern(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    Legacy(compat::CompatStream),
}

async fn peek_hello(sock: &TcpStream, cfg: &Config) -> Option<Vec<u8>> {
    let mut buf = [0u8; 1024];

    let n = tokio::time::timeout(cfg.timeout, sock.peek(&mut buf))
        .await
        .ok()?
        .ok()?;
    (n > 0).then(|| buf[..n].to_vec())
}

async fn accept_tls(
    sock: TcpStream,
    peer: SocketAddr,
    cfg: &Config,
    implicit_tls: bool,
    tr: &session::Trace,
) -> Option<Accepted> {
    let tls = cfg.tls.clone()?;

    if let Some(compat) = &cfg.compat {
        let hello = peek_hello(&sock, cfg).await.unwrap_or_default();
        if compat::wants_legacy(&hello, &tls) {
            tr.note("client hello offers nothing rustls implements: trying the legacy TLS stack");
            return match compat.accept(sock).await {
                Ok(s) => {
                    info(&format!("{peer} negotiated legacy TLS: {}", s.describe()));
                    Some(Accepted::Legacy(s))
                }
                Err(e) => {
                    let io = std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string());
                    handshake_failed(cfg, peer, implicit_tls, &io, None);
                    None
                }
            };
        }
    }

    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), sock);
    let start = match acceptor.await {
        Ok(s) => s,
        Err(e) => {
            handshake_failed(cfg, peer, implicit_tls, &e, None);
            return None;
        }
    };
    let hello = describe_client_hello(&start.client_hello(), &tls);
    tr.note(&format!("client hello: {hello}"));
    match start.into_stream(tls).await {
        Ok(s) => Some(Accepted::Modern(Box::new(s))),
        Err(e) => {
            handshake_failed(cfg, peer, implicit_tls, &e, Some(&hello));
            None
        }
    }
}

async fn run_encrypted(
    accepted: Accepted,
    st: &mut State,
    cfg: &Config,
    peer: SocketAddr,
    greet: bool,
    tr: &session::Trace,
) -> std::io::Result<()> {
    match accepted {
        Accepted::Modern(mut s) => session::run(&mut *s, st, cfg, peer, true, greet, tr).await?,
        Accepted::Legacy(mut s) => session::run(&mut s, st, cfg, peer, true, greet, tr).await?,
    };
    Ok(())
}

fn describe_client_hello(
    ch: &rustls::server::ClientHello<'_>,
    server: &rustls::ServerConfig,
) -> String {
    let groups = match ch.named_groups() {
        Some(g) if !g.is_empty() => g
            .iter()
            .map(|g| format!("{g:?}"))
            .collect::<Vec<_>>()
            .join(" "),

        Some(_) => "<empty>".to_string(),
        None => "<absent>".to_string(),
    };
    let suites = ch
        .cipher_suites()
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    let rsa_kx = ch.cipher_suites().iter().any(|s| is_static_rsa(*s));
    let common = ch
        .cipher_suites()
        .iter()
        .filter(|c| {
            server
                .crypto_provider()
                .cipher_suites
                .iter()
                .any(|s| s.suite() == **c)
        })
        .count();
    format!(
        "sni={} common-suites={common} groups=[{groups}] rsa-kx={} suites=[{suites}]",
        ch.server_name().unwrap_or("<none>"),
        if rsa_kx { "yes" } else { "no" }
    )
}

fn is_static_rsa(suite: rustls::CipherSuite) -> bool {
    matches!(
        u16::from(suite),
        0x0001..=0x000a | 0x002f | 0x0035 | 0x003b..=0x003d | 0x0041 | 0x0084 | 0x009c | 0x009d
    )
}

fn gave_up_without_tls(cfg: &Config, peer: SocketAddr, st: &State) {
    if !st.greeted_but_delivered_nothing() || !cfg.tls_trouble.contains(peer.ip()) {
        return;
    }
    warn(&format!(
        "{peer} said hello and left without delivering anything, and its TLS handshake \
         had failed earlier: this device will not send credentials over an unencrypted \
         link. Turn authentication off on the device (stmp2log does not check credentials \
         anyway), or terminate TLS in front of stmp2log."
    ));
}

fn tls_rejection(e: &std::io::Error) -> Option<&rustls::Error> {
    e.get_ref()?.downcast_ref::<rustls::Error>()
}

fn handshake_failed(
    cfg: &Config,
    peer: SocketAddr,
    implicit_tls: bool,
    e: &std::io::Error,
    hello: Option<&str>,
) {
    let Some(rejection) = tls_rejection(e) else {
        warn(&format!("TLS handshake with {peer} failed: {e}"));
        return;
    };
    let why = match rejection {
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoKxGroupsInCommon) => {
            "This device and stmp2log have no usable TLS in common; see common-suites \
             (how many of its cipher suites stmp2log implements) and rsa-kx below."
        }
        rustls::Error::PeerIncompatible(_) => {
            "This device's TLS is older than the TLS 1.2 + ECDHE that stmp2log accepts."
        }
        rustls::Error::AlertReceived(_) => {
            "The device refused the TLS session (most likely the self-signed certificate)."
        }
        _ => "The TLS session could not be established.",
    };
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

    let offered = match hello {
        Some(h) => format!(" The device offered: {h}"),
        None => String::new(),
    };
    warn(&format!(
        "TLS handshake with {peer} failed: {e}. {why} {advice}{offered}"
    ));
}

pub fn load_tls(data: &Path, names: &[String]) -> Result<Arc<rustls::ServerConfig>, SmtpError> {
    tls::load_or_create(data, names)
}

pub fn load_compat_tls(data: &Path, names: &[String]) -> Result<CompatTls, SmtpError> {
    CompatTls::load_or_create(data, names)
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

    #[test]
    fn static_rsa_suites_are_recognised_by_number() {
        use rustls::CipherSuite;

        for n in [0x002fu16, 0x0035, 0x009c, 0x000a] {
            assert!(is_static_rsa(CipherSuite::from(n)), "{n:#06x}");
        }
        for named in [
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ] {
            assert!(
                !is_static_rsa(named),
                "{named:?} is ephemeral; calling it static RSA would send people \
                 down the wrong path"
            );
        }
    }

    #[test]
    fn only_a_tls_level_rejection_counts_as_the_device_being_incompatible() {
        let blip = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(tls_rejection(&blip).is_none());

        let refused = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoKxGroupsInCommon),
        );
        assert!(
            tls_rejection(&refused).is_some(),
            "a device that cannot negotiate must be remembered"
        );
    }
}
