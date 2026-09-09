// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::SmtpError;

const CHUNK: usize = 16 * 1024;

const MAX_OUT: usize = 64 * 1024;

const RSA_BITS: u32 = 2048;

unsafe extern "C" fn rng(_ctx: *mut c_void, buf: *mut c_uchar, len: size_t) -> c_int {
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match getrandom::getrandom(out) {
        Ok(()) => 0,

        Err(_) => ERR_SSL_INTERNAL_ERROR,
    }
}

struct Shared {
    conf: Box<ssl_config>,
    crt: Box<x509_crt>,
    pk: Box<pk_context>,
}

unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Drop for Shared {
    fn drop(&mut self) {
        unsafe {
            ssl_config_free(&mut *self.conf);
            x509_crt_free(&mut *self.crt);
            pk_free(&mut *self.pk);
        }
    }
}

#[derive(Clone)]
pub struct CompatTls(Arc<Shared>);

impl CompatTls {
    pub fn load_or_create(data: &Path, names: &[String]) -> Result<Self, SmtpError> {
        let paths = Paths::in_dir(data);
        if !paths.cert.exists() || !paths.key.exists() {
            generate(&paths, names)?;
        }
        match Self::build(&paths) {
            Ok(v) => Ok(v),
            Err(e) => {
                crate::warn(&format!(
                    "the stored compatibility certificate is unusable ({e}); generating a fresh one"
                ));
                generate(&paths, names)?;
                Self::build(&paths)
            }
        }
    }

    fn build(paths: &Paths) -> Result<Self, SmtpError> {
        let mut cert_pem = std::fs::read(&paths.cert)?;
        cert_pem.push(0);
        let mut key_pem = std::fs::read(&paths.key)?;
        key_pem.push(0);

        let mut crt: Box<x509_crt> = Box::new(unsafe { std::mem::zeroed() });
        let mut pk: Box<pk_context> = Box::new(unsafe { std::mem::zeroed() });
        let mut conf: Box<ssl_config> = Box::new(unsafe { std::mem::zeroed() });

        unsafe {
            x509_crt_init(&mut *crt);
            pk_init(&mut *pk);
            ssl_config_init(&mut *conf);

            check(
                x509_crt_parse(&mut *crt, cert_pem.as_ptr(), cert_pem.len()),
                "could not parse the compatibility certificate",
            )?;
            check(
                pk_parse_key(
                    &mut *pk,
                    key_pem.as_ptr(),
                    key_pem.len(),
                    std::ptr::null(),
                    0,
                ),
                "could not parse the compatibility private key",
            )?;
            check(
                ssl_config_defaults(
                    &mut *conf,
                    SSL_IS_SERVER,
                    SSL_TRANSPORT_STREAM,
                    SSL_PRESET_DEFAULT,
                ),
                "could not set up the compatibility TLS defaults",
            )?;

            ssl_conf_rng(&mut *conf, Some(rng), std::ptr::null_mut());

            ssl_conf_authmode(&mut *conf, SSL_VERIFY_NONE);

            ssl_conf_min_version(&mut *conf, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1);
            ssl_conf_max_version(&mut *conf, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3);
            check(
                ssl_conf_own_cert(&mut *conf, &mut *crt, &mut *pk),
                "the compatibility certificate and key do not match",
            )?;
        }

        Ok(Self(Arc::new(Shared { conf, crt, pk })))
    }

    pub async fn accept(&self, sock: TcpStream) -> io::Result<CompatStream> {
        let mut stream = CompatStream::new(self.0.clone(), sock);
        std::future::poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }
}

fn check(rc: c_int, what: &str) -> Result<(), SmtpError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(SmtpError::Tls(format!("{what} (mbedtls {rc:#x})")))
    }
}

struct Paths {
    cert: PathBuf,
    key: PathBuf,
}

impl Paths {
    fn in_dir(data: &Path) -> Self {
        let dir = data.join("tls");
        Self {
            cert: dir.join("compat-cert.pem"),
            key: dir.join("compat-key.pem"),
        }
    }
}

fn generate(paths: &Paths, names: &[String]) -> Result<(), SmtpError> {
    let pkcs1 = rsa_key_der()?;
    let pkcs8 = pkcs1_to_pkcs8(&pkcs1);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &pkcs8.as_slice().into(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| SmtpError::Tls(format!("the generated RSA key is unusable: {e}")))?;
    let cert = crate::tls::self_signed(names, &key)?;

    if let Some(dir) = paths.cert.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&paths.cert, cert)?;
    crate::tls::write_private(&paths.key, key.serialize_pem().as_bytes())?;
    Ok(())
}

fn rsa_key_der() -> Result<Vec<u8>, SmtpError> {
    let mut pk: Box<pk_context> = Box::new(unsafe { std::mem::zeroed() });

    struct Guard<'a>(&'a mut pk_context);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            unsafe { pk_free(self.0) };
        }
    }

    unsafe {
        pk_init(&mut *pk);
        let guard = Guard(&mut pk);
        check(
            pk_setup(guard.0, pk_info_from_type(PK_RSA)),
            "could not set up an RSA context",
        )?;
        check(
            rsa_gen_key(
                guard.0.pk_ctx as *mut rsa_context,
                Some(rng),
                std::ptr::null_mut(),
                RSA_BITS,
                65537,
            ),
            "could not generate an RSA key",
        )?;

        let mut buf = vec![0u8; 4096];
        let n = pk_write_key_der(guard.0, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            return Err(SmtpError::Tls(format!(
                "could not serialise the RSA key (mbedtls {n:#x})"
            )));
        }
        let n = n as usize;
        Ok(buf[buf.len() - n..].to_vec())
    }
}

fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    const RSA_ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    let mut inner = vec![0x02, 0x01, 0x00];
    inner.extend_from_slice(&RSA_ALG);
    inner.push(0x04);
    der_len(&mut inner, pkcs1.len());
    inner.extend_from_slice(pkcs1);

    let mut out = vec![0x30];
    der_len(&mut out, inner.len());
    out.extend_from_slice(&inner);
    out
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    out.push(0x80 | (bytes.len() - first) as u8);
    out.extend_from_slice(&bytes[first..]);
}

pub(crate) fn wants_legacy(hello: &[u8], server: &rustls::ServerConfig) -> bool {
    let Some(offered) = offered_suites(hello) else {
        return false;
    };
    let ours = &server.crypto_provider().cipher_suites;
    !offered
        .iter()
        .any(|s| ours.iter().any(|c| u16::from(c.suite()) == *s))
}

fn offered_suites(b: &[u8]) -> Option<Vec<u16>> {
    if b.len() < 5 || b[0] != 0x16 {
        return None;
    }

    let h = b.get(5..)?;
    if h.first()? != &0x01 {
        return None;
    }

    let mut p = 4 + 2 + 32;
    let sid_len = *h.get(p)? as usize;
    p += 1 + sid_len;
    let n = u16::from_be_bytes([*h.get(p)?, *h.get(p + 1)?]) as usize;
    p += 2;
    if n == 0 || n % 2 != 0 {
        return None;
    }
    let raw = h.get(p..p + n)?;
    Some(
        raw.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
}

struct Bridge {
    sock: TcpStream,

    inbuf: Vec<u8>,
    in_pos: usize,

    outbuf: Vec<u8>,
    out_pos: usize,

    eof: bool,
}

unsafe extern "C" fn bio_recv(ctx: *mut c_void, buf: *mut c_uchar, len: size_t) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge) };
    let avail = b.inbuf.len() - b.in_pos;
    if avail == 0 {
        return if b.eof { 0 } else { ERR_SSL_WANT_READ };
    }
    let n = avail.min(len);
    unsafe { std::ptr::copy_nonoverlapping(b.inbuf[b.in_pos..].as_ptr(), buf, n) };
    b.in_pos += n;
    if b.in_pos == b.inbuf.len() {
        b.inbuf.clear();
        b.in_pos = 0;
    }
    n as c_int
}

unsafe extern "C" fn bio_send(ctx: *mut c_void, buf: *const c_uchar, len: size_t) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge) };
    if b.outbuf.len() - b.out_pos >= MAX_OUT {
        return ERR_SSL_WANT_WRITE;
    }
    b.outbuf
        .extend_from_slice(unsafe { std::slice::from_raw_parts(buf, len) });
    len as c_int
}

pub struct CompatStream {
    ssl: Box<ssl_context>,

    bridge: *mut Bridge,
    _shared: Arc<Shared>,
}

unsafe impl Send for CompatStream {}

impl CompatStream {
    fn new(shared: Arc<Shared>, sock: TcpStream) -> Self {
        let bridge = Box::into_raw(Box::new(Bridge {
            sock,
            inbuf: Vec::new(),
            in_pos: 0,
            outbuf: Vec::new(),
            out_pos: 0,
            eof: false,
        }));
        let mut ssl: Box<ssl_context> = Box::new(unsafe { std::mem::zeroed() });
        unsafe {
            ssl_init(&mut *ssl);

            ssl_setup(&mut *ssl, &*shared.conf);
            ssl_set_bio(
                &mut *ssl,
                bridge as *mut c_void,
                Some(bio_send),
                Some(bio_recv),
                None,
            );
        }
        Self {
            ssl,
            bridge,
            _shared: shared,
        }
    }

    fn bridge(&mut self) -> &mut Bridge {
        unsafe { &mut *self.bridge }
    }

    pub fn describe(&self) -> String {
        unsafe {
            let ver = ssl_get_version(&*self.ssl);
            let suite = ssl_get_ciphersuite(&*self.ssl);
            format!("{} {}", cstr(ver), cstr(suite))
        }
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_flush_out(cx))?;
            let rc = unsafe { ssl_handshake(&mut *self.ssl) };
            match rc {
                0 => return Poll::Ready(Ok(())),
                ERR_SSL_WANT_READ => ready!(self.poll_fill_in(cx))?,
                ERR_SSL_WANT_WRITE => continue,
                e => return Poll::Ready(Err(mbed_err(e))),
            }
        }
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let b = self.bridge();
            if b.out_pos >= b.outbuf.len() {
                b.outbuf.clear();
                b.out_pos = 0;
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut b.sock).poll_write(cx, &b.outbuf[b.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            b.out_pos += n;
        }
    }

    fn poll_fill_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush_out(cx))?;
        let b = self.bridge();
        let mut chunk = [0u8; CHUNK];
        let mut rb = ReadBuf::new(&mut chunk);
        ready!(Pin::new(&mut b.sock).poll_read(cx, &mut rb))?;
        if rb.filled().is_empty() {
            b.eof = true;
        } else {
            b.inbuf.extend_from_slice(rb.filled());
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for CompatStream {
    fn drop(&mut self) {
        unsafe {
            ssl_set_bio(&mut *self.ssl, std::ptr::null_mut(), None, None, None);
            ssl_free(&mut *self.ssl);
            drop(Box::from_raw(self.bridge));
        }
    }
}

impl AsyncRead for CompatStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            ready!(me.poll_flush_out(cx))?;
            let dst = buf.initialize_unfilled();
            let rc = unsafe { ssl_read(&mut *me.ssl, dst.as_mut_ptr(), dst.len()) };
            match rc {
                n if n > 0 => {
                    buf.advance(n as usize);
                    return Poll::Ready(Ok(()));
                }

                0 | ERR_SSL_PEER_CLOSE_NOTIFY | ERR_SSL_CONN_EOF => return Poll::Ready(Ok(())),
                ERR_SSL_WANT_READ => ready!(me.poll_fill_in(cx))?,
                ERR_SSL_WANT_WRITE => continue,
                e => return Poll::Ready(Err(mbed_err(e))),
            }
        }
    }
}

impl AsyncWrite for CompatStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            ready!(me.poll_flush_out(cx))?;
            let rc = unsafe { ssl_write(&mut *me.ssl, buf.as_ptr(), buf.len()) };
            match rc {
                n if n > 0 => {
                    let _ = me.poll_flush_out(cx)?;
                    return Poll::Ready(Ok(n as usize));
                }
                ERR_SSL_WANT_READ => ready!(me.poll_fill_in(cx))?,
                ERR_SSL_WANT_WRITE => continue,
                e => return Poll::Ready(Err(mbed_err(e))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.bridge().sock).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        unsafe { ssl_close_notify(&mut *me.ssl) };
        ready!(me.poll_flush_out(cx))?;
        Pin::new(&mut me.bridge().sock).poll_shutdown(cx)
    }
}

fn mbed_err(rc: c_int) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("legacy TLS failed (mbedtls {rc:#x})"),
    )
}

fn cstr(p: *const std::os::raw::c_char) -> String {
    if p.is_null() {
        return "?".into();
    }
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(suites: &[u16]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            body.extend_from_slice(&s.to_be_bytes());
        }
        body.extend_from_slice(&[0x01, 0x00]);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn rustls_config() -> rustls::ServerConfig {
        crate::install_crypto_provider();
        let dir = std::env::temp_dir().join(format!(
            "s2l-verdict-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = crate::tls::load_or_create(&dir, &[]).expect("stub");
        std::fs::remove_dir_all(&dir).ok();
        Arc::try_unwrap(cfg).unwrap_or_else(|a| (*a).clone())
    }

    #[test]
    fn the_real_idrac_hello_is_routed_to_the_legacy_stack() {
        const IDRAC: [u16; 21] = [
            0x0035, 0x003d, 0x0084, 0x002f, 0x003c, 0x0041, 0x000a, 0x0039, 0x006b, 0x0088, 0x0033,
            0x0067, 0x0045, 0x0016, 0x0038, 0x006a, 0x0087, 0x0032, 0x0040, 0x0044, 0x0013,
        ];
        let cfg = rustls_config();
        assert!(wants_legacy(&hello(&IDRAC), &cfg));
    }

    #[test]
    fn anything_rustls_can_serve_stays_on_the_main_path() {
        let cfg = rustls_config();

        assert!(!wants_legacy(&hello(&[0x1301, 0xc02b, 0x002f]), &cfg));
        assert!(!wants_legacy(&hello(&[0xc030]), &cfg));

        assert!(!wants_legacy(b"", &cfg), "empty");
        assert!(!wants_legacy(b"GET / HTTP/1.1\r\n", &cfg), "not TLS at all");
        assert!(
            !wants_legacy(&hello(&[0x002f])[..40], &cfg),
            "a hello cut short before the suite list"
        );
    }

    #[test]
    fn pkcs8_wraps_pkcs1_with_the_lengths_der_expects() {
        let short = pkcs1_to_pkcs8(&[0xaa; 4]);
        assert_eq!(short[0], 0x30, "outermost must be a SEQUENCE");
        assert_eq!(short[1] as usize, short.len() - 2, "short-form length");
        assert!(short.ends_with(&[0xaa; 4]));

        let long = pkcs1_to_pkcs8(&[0xbb; 1200]);
        assert_eq!(long[0], 0x30);
        assert_eq!(long[1], 0x82, "two length bytes follow");
        let len = u16::from_be_bytes([long[2], long[3]]) as usize;
        assert_eq!(len, long.len() - 4, "declared length must match reality");
    }

    #[test]
    fn der_lengths_use_the_shortest_form() {
        let mut out = Vec::new();
        der_len(&mut out, 0x7f);
        assert_eq!(out, [0x7f]);

        out.clear();
        der_len(&mut out, 0x80);
        assert_eq!(out, [0x81, 0x80]);

        out.clear();
        der_len(&mut out, 0x1234);
        assert_eq!(out, [0x82, 0x12, 0x34]);
    }

    #[test]
    fn a_generated_rsa_certificate_round_trips_through_mbedtls() {
        let dir = std::env::temp_dir().join(format!(
            "s2l-compat-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = Paths::in_dir(&dir);
        generate(&paths, &["nas.local".into()]).expect("generate");
        assert!(
            std::fs::read_to_string(&paths.key)
                .unwrap()
                .contains("PRIVATE KEY"),
            "the key must be written as PEM"
        );
        CompatTls::build(&paths).expect("mbedtls must accept what rcgen produced");
        std::fs::remove_dir_all(&dir).ok();
    }
}
