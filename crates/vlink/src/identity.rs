//! The bridge's certificate: made once, kept for good.
//!
//! Its hash is the bridge's id. A bridge that loses these two files is a
//! new bridge to everybody who knew the old one.

use std::path::Path;

use anyhow::Context;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use vlink_proto::tls::Identity;

const CERT_FILE: &str = "bridge.crt";
const KEY_FILE: &str = "bridge.key";

/// A fresh certificate and key, as PEM. Nobody signs it and nothing in it
/// is checked: only its hash matters. The fields are what a server set up
/// in a hurry would have.
pub fn generate() -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "localhost");
    params.distinguished_name = name;
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2046, 1, 1);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The identity kept in `dir`, made there on the first call.
pub fn load_or_create(dir: &Path) -> anyhow::Result<Identity> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    if !cert_path.exists() || !key_path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let (cert, key) = generate()?;
        write_private(&key_path, &key)?;
        std::fs::write(&cert_path, cert).with_context(|| format!("cannot write {}", cert_path.display()))?;
    }
    let cert = std::fs::read_to_string(&cert_path).with_context(|| format!("cannot read {}", cert_path.display()))?;
    let key = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    Ok(Identity::from_pem(&cert, &key)?)
}

/// For the owner alone, where the system knows what that means.
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot write {}", path.display()))?;
        file.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}
