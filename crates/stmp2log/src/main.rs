// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

mod api;
mod assets;
mod config;
mod log;
mod pipeline;
mod push;
mod retry;
mod state;

const VERSION: &str = match option_env!("STMP2LOG_VERSION") {
    Some(v) => v,
    None => concat!(env!("CARGO_PKG_VERSION"), "-dev"),
};

const HELP: &str = "\
stmp2log — a fake-SMTP sink that logs device alerts and pushes them onward

Usage:
  stmp2log -c <config.ini>

Options:
  -c, --config <path>   configuration file (default: ./config.ini)
  -d, --debug           verbose logging, including every SMTP command and reply
  -v, --version         print the version and exit
  -h, --help            print this help and exit

Configuration file (every key is optional; see the readme):
  stmp_listen=0.0.0.0:25      SMTP listener; empty disables it
  data=./data                 data directory; empty means ./data
  web_listen=0.0.0.0:8025     web UI listener; empty disables the web UI
  web_pass=admin              web UI password; empty means no login at all
  web_path=stmp2log           web UI url prefix; empty means stmp2log
  push_url=http://host/path   forward everything to another stmp2log

  stmp_tls_listen=0.0.0.0:465 implicit-TLS SMTP listener (STARTTLS always works)
  stmp_hostname=<hostname>    SMTP greeting name, and the push source name
  stmp_user= / stmp_pass=     each is checked only if set; both empty accepts anything
  stmp_maxsize=10M            per-message size limit

  max_entries=5000            keep at most this many messages
  max_days=0                  keep at most this many days; 0 disables
  keep_raw=0                  store the raw message source
  keep_attachments=0          store attachment contents
  retry_queue=0               hold at most this many undelivered alerts while
                              the network is down and send them once it is
                              back; 0 (the default) means no limit
    (these five can also be changed in the web UI, which writes them back here)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = PathBuf::from("config.ini");
    let mut debug = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return;
            }
            "-v" | "--version" => {
                println!("stmp2log {VERSION}");
                return;
            }
            "-d" | "--debug" => debug = true,
            "-c" | "--config" => {
                i += 1;
                match args.get(i) {
                    Some(p) => config_path = PathBuf::from(p),
                    None => {
                        eprintln!("-c needs a path");
                        std::process::exit(2);
                    }
                }
            }
            other => {
                if let Some(p) = other
                    .strip_prefix("-c=")
                    .or_else(|| other.strip_prefix("--config="))
                {
                    config_path = PathBuf::from(p);
                } else {
                    eprintln!("unknown argument {other:?}\n");
                    print!("{HELP}");
                    std::process::exit(2);
                }
            }
        }
        i += 1;
    }

    log::init(debug);
    if let Err(e) = run(&config_path) {
        log::error(&e);
        std::process::exit(1);
    }
}

fn run(config_path: &std::path::Path) -> Result<(), String> {
    let parsed = config::load(config_path);
    let cfg = parsed.config;
    for w in &parsed.warnings {
        log::warn(w);
    }

    log::info(&format!("stmp2log {VERSION} starting"));
    std::fs::create_dir_all(&cfg.data).map_err(|e| {
        format!(
            "could not create the data directory {}: {e}",
            cfg.data.display()
        )
    })?;

    s2l_smtp::install_crypto_provider();

    let (state, warnings) = state::State::load(&cfg.data);
    for w in &warnings {
        log::warn(w);
    }
    let state = Arc::new(ArcSwap::from_pointee(state));

    let settings = Arc::new(ArcSwap::from_pointee(cfg.settings()));

    let store = Arc::new(
        s2l_store::Store::open(&s2l_store::log_dir(&cfg.data), cfg.settings().retention())
            .map_err(|e| format!("could not open the log store: {e}"))?,
    );
    log::info(&format!(
        "log store ready: {} message(s), {} on disk",
        store.len(),
        human_bytes(store.stats(log::now_ms()).disk_bytes)
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let config_path = config_path.to_path_buf();
    rt.block_on(async move { serve(cfg, config_path, state, settings, store).await })
}

async fn serve(
    cfg: config::Config,
    config_path: std::path::PathBuf,
    state: Arc<ArcSwap<state::State>>,
    settings: Arc<ArcSwap<config::Settings>>,
    store: Arc<s2l_store::Store>,
) -> Result<(), String> {
    let (tx, rx) = tokio::sync::mpsc::channel::<s2l_smtp::Delivered>(256);

    let base = s2l_web::normalize_base(&cfg.web_path);
    let base_url = match cfg.web_listen {
        Some(a) => format!("http://{}{}", advertised(a), base),
        None => String::new(),
    };

    let events = cfg
        .web_listen
        .map(|_| tokio::sync::broadcast::channel::<String>(64).0);

    if !cfg.push_url.is_empty() {
        log::info(&format!(
            "forwarding every accepted message to {} as {:?}",
            cfg.push_url, cfg.stmp_hostname
        ));
        if cfg.web_pass.is_empty() {
            log::warn(
                "push is configured but web_pass is empty, so the payload key is not a secret; \
                 anyone who can reach the far side can forge messages",
            );
        }
    }

    let pipe = Arc::new(pipeline::Pipeline::new(
        store.clone(),
        state.clone(),
        settings.clone(),
        s2l_notify::Client::new(Duration::from_secs(20)),
        events.clone(),
        base_url.clone(),
        push::Config {
            url: cfg.push_url.clone(),
            pass: cfg.web_pass.clone(),
            hostname: cfg.stmp_hostname.clone(),
        },
    ));
    tokio::spawn(pipe.clone().run(rx));

    tokio::spawn(pipe.clone().run_retry());

    log::info(&match cfg.retry_queue {
        0 => "undelivered alerts are queued until the network is back, with no limit".to_string(),
        n => format!("at most {n} undelivered alert(s) are queued while the network is down"),
    });

    start_smtp(&cfg, tx).await?;

    if let Some(listen) = cfg.web_listen {
        start_web(
            &cfg,
            listen,
            &config_path,
            &base,
            state,
            settings,
            store,
            pipe,
            events,
        )
        .await?;
        log::info(&format!("web UI at {base_url}/"));
        if cfg.web_pass.is_empty() {
            log::warn("web_pass is empty: the web UI is open to anyone who can reach it");
        }
        if assets::is_placeholder() {
            log::warn(
                "the embedded web UI is the placeholder page; \
                 run `bash build.sh` to build the real frontend",
            );
        }
    } else {
        log::info("the web UI is disabled (web_listen is empty)");
    }

    wait_for_shutdown().await;
    log::info("shutting down");
    Ok(())
}

async fn start_smtp(
    cfg: &config::Config,
    tx: tokio::sync::mpsc::Sender<s2l_smtp::Delivered>,
) -> Result<(), String> {
    if cfg.stmp_listen.is_none() && cfg.stmp_tls_listen.is_none() {
        log::info("SMTP is disabled (stmp_listen is empty)");
        return Ok(());
    }

    let mut smtp = s2l_smtp::Config::new(tx);
    smtp.hostname = cfg.stmp_hostname.clone();
    smtp.max_size = cfg.stmp_maxsize;

    smtp.trace = log::debug_enabled();
    if smtp.trace {
        log::info("SMTP session tracing is on (-d): every command and reply is logged");
    }

    if !cfg.stmp_user.is_empty() || !cfg.stmp_pass.is_empty() {
        smtp.auth = s2l_smtp::AuthPolicy::Require {
            user: cfg.stmp_user.clone(),
            pass: cfg.stmp_pass.clone(),
        };
        log::info(match (cfg.stmp_user.is_empty(), cfg.stmp_pass.is_empty()) {
            (false, false) => "SMTP AUTH will be checked against stmp_user and stmp_pass",
            (false, true) => "SMTP AUTH will be checked against stmp_user; any password passes",
            _ => "SMTP AUTH will be checked against stmp_pass; any account name passes",
        });
    } else {
        log::info("SMTP AUTH accepts anything, including no credentials at all");
    }
    smtp.bind = cfg.stmp_listen.into_iter().collect();
    smtp.tls_bind = cfg.stmp_tls_listen.into_iter().collect();

    match s2l_smtp::load_tls(&cfg.data, std::slice::from_ref(&cfg.stmp_hostname)) {
        Ok(tls) => smtp.tls = Some(tls),
        Err(e) => {
            log::warn(&format!(
                "TLS is unavailable ({e}); STARTTLS and the implicit-TLS port are disabled"
            ));
        }
    }

    if smtp.tls.is_some() {
        match s2l_smtp::load_compat_tls(&cfg.data, std::slice::from_ref(&cfg.stmp_hostname)) {
            Ok(c) => {
                smtp.compat = Some(c);
                log::info(
                    "devices whose TLS is too old for rustls are served by the \
                     compatibility stack",
                );
            }

            Err(e) => log::warn(&format!("the compatibility TLS stack is unavailable: {e}")),
        }
    }
    s2l_smtp::serve(smtp)
        .await
        .map_err(|e| format!("could not start the SMTP listener: {e}"))
}

#[allow(clippy::too_many_arguments)]
async fn start_web(
    cfg: &config::Config,
    listen: SocketAddr,
    config_path: &std::path::Path,
    base: &str,
    state: Arc<ArcSwap<state::State>>,
    settings: Arc<ArcSwap<config::Settings>>,
    store: Arc<s2l_store::Store>,
    pipe: Arc<pipeline::Pipeline>,
    events: Option<tokio::sync::broadcast::Sender<String>>,
) -> Result<(), String> {
    let asset = assets::prepare(base)?;
    let auth = Arc::new(ArcSwap::from_pointee(s2l_web::Auth::new(&cfg.web_pass)));

    let handler = api::Handler {
        store,
        state,
        settings,
        pipeline: pipe,
        auth: auth.clone(),
        data_dir: cfg.data.clone(),
        config_path: config_path.to_path_buf(),
        push_pass: cfg.web_pass.clone(),
        version: VERSION,
        started_at: log::now_ms(),
    };

    let server = s2l_web::ServerConfig {
        bind: listen,
        base: base.to_string(),
        asset,
        api: Arc::new(handler),
        auth,
        events,
    };
    s2l_web::serve(Arc::new(server))
        .await
        .map_err(|e| format!("could not start the web server: {e}"))
}

fn advertised(listen: SocketAddr) -> String {
    let port = listen.port();
    if listen.ip().is_unspecified() {
        if listen.is_ipv6() {
            return format!("[::1]:{port}");
        }
        return format!("127.0.0.1:{port}");
    }
    listen.to_string()
}
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_listen_is_shown_as_something_clickable() {
        let a = |s: &str| advertised(s.parse::<SocketAddr>().unwrap());
        assert_eq!(a("0.0.0.0:8025"), "127.0.0.1:8025");
        assert_eq!(a("[::]:8025"), "[::1]:8025");
        assert_eq!(a("10.0.0.2:8025"), "10.0.0.2:8025");
        assert_eq!(a("[fd00::1]:8025"), "[fd00::1]:8025");
    }

    #[test]
    fn human_bytes_reads_naturally() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn the_version_string_is_never_empty() {
        assert!(!VERSION.is_empty());
    }
}
