// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::SmtpError;

pub struct Paths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Paths {
    pub fn in_dir(data: &Path) -> Self {
        let dir = data.join("tls");
        Self {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        }
    }
}

pub fn load_or_create(data: &Path, names: &[String]) -> Result<Arc<ServerConfig>, SmtpError> {
    let paths = Paths::in_dir(data);
    if !paths.cert.exists() || !paths.key.exists() {
        generate(&paths, names)?;
    }
    match build(&paths) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {

            crate::warn(&format!(
                "the stored TLS certificate is unusable ({e}); generating a fresh self-signed one"
            ));
            generate(&paths, names)?;
            build(&paths)
        }
    }
}

fn build(paths: &Paths) -> Result<Arc<ServerConfig>, SmtpError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&paths.cert)
        .map_err(|e| SmtpError::Tls(format!("could not read {}: {e}", paths.cert.display())))?
        .collect::<Result<_, _>>()
        .map_err(|e| SmtpError::Tls(format!("malformed certificate: {e}")))?;
    if certs.is_empty() {
        return Err(SmtpError::Tls(
            "the certificate file contains no certificate".into(),
        ));
    }
    let key = PrivateKeyDer::from_pem_file(&paths.key)
        .map_err(|e| SmtpError::Tls(format!("could not read {}: {e}", paths.key.display())))?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| SmtpError::Tls(format!("the certificate and key do not match: {e}")))?;
    Ok(Arc::new(cfg))
}

fn generate(paths: &Paths, names: &[String]) -> Result<(), SmtpError> {
    let mut sans: Vec<String> = names.to_vec();

    for extra in ["stmp2log", "localhost"] {
        if !sans.iter().any(|n| n == extra) {
            sans.push(extra.to_string());
        }
    }
    sans.retain(|s| !s.trim().is_empty());

    let mut params = rcgen::CertificateParams::new(sans)
        .map_err(|e| SmtpError::Tls(format!("bad certificate subject names: {e}")))?;
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "stmp2log");
        dn.push(rcgen::DnType::OrganizationName, "stmp2log");
        dn
    };

    let key = rcgen::KeyPair::generate()
        .map_err(|e| SmtpError::Tls(format!("could not generate a key pair: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| SmtpError::Tls(format!("could not self-sign: {e}")))?;

    if let Some(dir) = paths.cert.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&paths.cert, cert.pem())?;
    write_private(&paths.key, key.serialize_pem().as_bytes())?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("s2l-tls-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn generates_a_usable_config_on_first_run() {
        let dir = tmpdir("gen");
        let cfg = load_or_create(&dir, &["nas.local".into()]).unwrap();
        assert!(!cfg.crypto_provider().cipher_suites.is_empty());
        assert!(dir.join("tls/cert.pem").exists());
        assert!(dir.join("tls/key.pem").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reuses_the_stored_certificate_across_restarts() {

        let dir = tmpdir("reuse");
        load_or_create(&dir, &[]).unwrap();
        let first = std::fs::read(dir.join("tls/cert.pem")).unwrap();
        load_or_create(&dir, &[]).unwrap();
        let second = std::fs::read(dir.join("tls/cert.pem")).unwrap();
        assert_eq!(first, second);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_certificate_is_regenerated_rather_than_fatal() {

        let dir = tmpdir("corrupt");
        load_or_create(&dir, &[]).unwrap();
        std::fs::write(dir.join("tls/cert.pem"), b"this is not a certificate").unwrap();
        let cfg = load_or_create(&dir, &[]);
        assert!(
            cfg.is_ok(),
            "a broken cert must not stop the service from starting"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perm");
        load_or_create(&dir, &[]).unwrap();
        let mode = std::fs::metadata(dir.join("tls/key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the key must not be readable by group or other"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
