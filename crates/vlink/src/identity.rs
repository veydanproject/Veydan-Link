//! The bridge's key, its TLS key and the certificates over them.
//!
//! Two keys (identity v2, `vlink_proto::id`):
//!
//! - **The bridge's key** (`bridge.key`, Ed25519) is made once and kept:
//!   its hash is the bridge's id. It signs the TLS certificate and the
//!   reports to the registry, and nothing else. A bridge that loses it is
//!   a new bridge to everybody who knew the old one.
//! - **The TLS key** (`tls.key`, ECDSA P-256) is what the handshake is
//!   signed with. It is of the kind every browser takes, so a passer-by
//!   completes the handshake and gets the page of a bare web server,
//!   rather than an alert that tells the bridge apart. It may be replaced
//!   at any time, with the certificate over it (`vlink id --renew-cert`);
//!   the id does not change with it.
//!
//! `bridge.crt` holds the certificate over the TLS key, signed by the
//! bridge's key, and behind it the certificate carrying the bridge's key:
//! the chain the bridge shows, as `vlink_proto::pin` checks it.
//!
//! The chain looks like that of any server with a certificate of 90
//! days: names made up for each chain, not `localhost`, and dates of 90
//! days, issued again over the same two keys a month before the end, at
//! the start and while the bridge runs, as certbot renews. Who knows the
//! bridge pins its key, not the fields, so the id holds across each new
//! chain. That no public authority signed it still shows to whoever
//! completes a handshake (spec/protocol.md, «Порт моста»).

use std::path::Path;

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, SerialNumber, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use vlink_proto::sign::Signer;
use vlink_proto::tls::Identity;
use vlink_proto::BridgeId;

const CERT_FILE: &str = "bridge.crt";
const KEY_FILE: &str = "bridge.key";
const TLS_KEY_FILE: &str = "tls.key";

/// The bridge's files, as text: what `generate` makes and `load_or_create`
/// keeps in the data folder.
#[derive(Clone, Debug)]
pub struct Pem {
    /// The TLS certificate, then the one carrying the bridge's key.
    pub chain: String,
    pub tls_key: String,
    /// The bridge's key.
    pub key: String,
}

/// The bridge's keys, ready to use.
pub struct Keys {
    pub id: BridgeId,
    /// What TLS is served with: the chain and the TLS key.
    pub tls: Identity,
    /// The bridge's key, for the reports to the registry.
    pub signer: Signer,
}

/// A fresh bridge's key, as PEM.
pub fn generate_key() -> anyhow::Result<String> {
    Ok(KeyPair::generate_for(&PKCS_ED25519)?.serialize_pem())
}

/// A fresh TLS key, as PEM.
pub fn generate_tls_key() -> anyhow::Result<String> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?.serialize_pem())
}

/// How long a chain is issued for: as long as a certificate of Let's
/// Encrypt, rather than the twenty years nobody but a bridge would set.
pub const CERT_DAYS: u64 = 90;
/// A chain with less than this left is issued again, at the start and
/// while the bridge runs (`renew_if_due`), as certbot renews.
pub const RENEW_BEFORE_DAYS: u64 = 30;

/// What the certificate carrying the bridge's key says. The TLS
/// certificate names it as its issuer, so the same words are needed for
/// both. The name is made up anew for each chain: a fixed one, or one
/// derived from the key, would tell every chain of a bridge apart from
/// the chains of anybody else.
fn issuer_params(name: &str) -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    params.serial_number = Some(serial()?);
    dates(&mut params);
    Ok(params)
}

fn serial() -> anyhow::Result<SerialNumber> {
    let mut serial = [0u8; 16];
    ring_random(&mut serial)?;
    Ok(SerialNumber::from(serial.to_vec()))
}

/// A host name of nobody: a few syllables and a common ending,
/// `kesomara.net`. Those who call the bridge look at its key only.
fn made_up_name() -> anyhow::Result<String> {
    const CONSONANTS: &[u8] = b"bdfgklmnprstvz";
    const VOWELS: &[u8] = b"aeiou";
    const ENDINGS: &[&str] = &["com", "net", "org", "io", "dev", "app"];
    let mut random = [0u8; 10];
    ring_random(&mut random)?;
    let syllables = 2 + usize::from(random[0] % 3);
    let mut name = String::new();
    for i in 0..syllables {
        name.push(CONSONANTS[usize::from(random[1 + 2 * i]) % CONSONANTS.len()] as char);
        name.push(VOWELS[usize::from(random[2 + 2 * i]) % VOWELS.len()] as char);
    }
    Ok(format!("{name}.{}", ENDINGS[usize::from(random[9]) % ENDINGS.len()]))
}

/// The dates of the day: a day back, as the clocks of two machines never
/// quite agree, to [`CERT_DAYS`] on.
fn dates(params: &mut CertificateParams) {
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(86_400)).into();
    params.not_after = (now + std::time::Duration::from_secs(CERT_DAYS * 86_400)).into();
}

/// The chain over `tls_key_pem`, signed by `key_pem`, as PEM: the TLS
/// certificate first, the certificate carrying the bridge's key behind
/// it. Nobody else signs anything, and nothing in either is checked by
/// those who know the bridge but the signature and the dates. Each chain
/// issued is new: its own serials and names, the dates of its day.
pub fn certificate(key_pem: &str, tls_key_pem: &str) -> anyhow::Result<String> {
    let key = key_of(key_pem)?;
    let tls_key = tls_key_of(tls_key_pem)?;
    let params = issuer_params(&made_up_name()?)?;
    let own = params.self_signed(&key)?;
    let issuer = Issuer::new(params, key);
    let host = made_up_name()?;
    let mut params = CertificateParams::new(vec![host.clone()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, host);
    params.distinguished_name = name;
    params.serial_number = Some(serial()?);
    dates(&mut params);
    let tls = params.signed_by(&tls_key, &issuer)?;
    Ok(format!("{}{}", tls.pem(), own.pem()))
}

/// Whether the chain (PEM) has to be issued again at `now` (unix
/// seconds): its TLS certificate has less than [`RENEW_BEFORE_DAYS`]
/// left, or runs well past [`CERT_DAYS`] from now (the twenty years
/// bridges used to set), or cannot be read.
pub fn due(chain_pem: &str, now: u64) -> bool {
    match vlink_proto::tls::cert_from_pem(chain_pem) {
        Ok(der) => due_der(der.as_ref(), now),
        Err(_) => true,
    }
}

fn due_der(der: &[u8], now: u64) -> bool {
    match vlink_proto::tls::not_after(der) {
        Some(at) => at < now + RENEW_BEFORE_DAYS * 86_400 || at > now + (CERT_DAYS + 2) * 86_400,
        None => true,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A fresh bridge: both keys and the chain over them.
pub fn generate() -> anyhow::Result<Pem> {
    let key = generate_key()?;
    let tls_key = generate_tls_key()?;
    Ok(Pem { chain: certificate(&key, &tls_key)?, tls_key, key })
}

/// The id of the bridge whose key this is.
pub fn id_of_key(key_pem: &str) -> anyhow::Result<BridgeId> {
    Ok(BridgeId::of_key(&key_of(key_pem)?.subject_public_key_info()))
}

/// The bridge's key, when it is the kind a bridge has. A key of another
/// kind is most likely the one a bridge made before identity v2 (ECDSA
/// P-256): its id was of its certificate, which no longer means anything,
/// so there is nothing to keep.
fn key_of(key_pem: &str) -> anyhow::Result<KeyPair> {
    let key = KeyPair::from_pem(key_pem).context("not a key")?;
    anyhow::ensure!(key.algorithm() == &PKCS_ED25519, "not an Ed25519 key");
    Ok(key)
}

/// The TLS key: the kind every browser takes.
fn tls_key_of(tls_key_pem: &str) -> anyhow::Result<KeyPair> {
    let key = KeyPair::from_pem(tls_key_pem).context("not a key")?;
    anyhow::ensure!(key.algorithm() == &PKCS_ECDSA_P256_SHA256, "not a P-256 key");
    Ok(key)
}

fn ring_random(into: &mut [u8]) -> anyhow::Result<()> {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new().fill(into).map_err(|_| anyhow::anyhow!("no random bytes"))
}

impl Pem {
    /// The keys these files hold, held to the rule: the chain has to be
    /// what a client takes for the bridge of this key.
    pub fn keys(&self) -> anyhow::Result<Keys> {
        let key = key_of(&self.key)?;
        let id = BridgeId::of_key(&key.subject_public_key_info());
        let signer = Signer::from_pkcs8(&key.serialize_der())?;
        let tls = Identity::from_pem(&self.chain, &self.tls_key)?;
        anyhow::ensure!(
            tls.bridge_id()? == id,
            "the certificate is not signed by the bridge's key: run `vlink id --renew-cert` to issue one that is"
        );
        Ok(Keys { id, tls, signer })
    }
}

/// The files kept in `dir`: the bridge's key is made there on the first
/// call, and a TLS key and a chain over it whenever either is missing.
///
/// What is there is held to the rule: a bridge's key of another kind, or
/// a chain not over these keys, stops the bridge with a word on what to
/// do, rather than quietly making it another bridge.
pub fn load_or_create(dir: &Path) -> anyhow::Result<Keys> {
    let key_path = dir.join(KEY_FILE);
    let tls_key_path = dir.join(TLS_KEY_FILE);
    let cert_path = dir.join(CERT_FILE);
    if !key_path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        write_private(&key_path, &generate_key()?)?;
        // A TLS key and a certificate without the bridge's key, left over
        // from something, are of no use: new ones take their place.
        let _ = std::fs::remove_file(&tls_key_path);
        let _ = std::fs::remove_file(&cert_path);
    }
    let key = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    id_of_key(&key).with_context(|| {
        format!(
            "{}: not the key of a bridge (one made before identity v2?); remove it, {} and {} and start again: the bridge comes back as a new bridge",
            key_path.display(),
            tls_key_path.display(),
            cert_path.display()
        )
    })?;
    if !tls_key_path.exists() {
        // A chain over a TLS key that is gone is nothing; a new one is
        // issued over the new key.
        write_private(&tls_key_path, &generate_tls_key()?)?;
        let _ = std::fs::remove_file(&cert_path);
    }
    let tls_key =
        std::fs::read_to_string(&tls_key_path).with_context(|| format!("cannot read {}", tls_key_path.display()))?;
    tls_key_of(&tls_key).with_context(|| format!("{}: not the TLS key of a bridge; remove it and start again", tls_key_path.display()))?;
    if !cert_path.exists() {
        write_cert(&cert_path, &certificate(&key, &tls_key)?)?;
    }
    let chain = std::fs::read_to_string(&cert_path).with_context(|| format!("cannot read {}", cert_path.display()))?;
    let chain = reissue_if_due(&cert_path, &key, &tls_key, chain, unix_now())?.0;
    Pem { chain, tls_key, key }.keys().with_context(|| format!("{}", cert_path.display()))
}

/// The chain issued again over the same two keys when it is [`due`] and
/// is the bridge's own (the certificate behind the TLS one carries the
/// bridge's key): `(chain, whether it is new)`. A chain of somebody
/// else's is left for [`Pem::keys`] to refuse. The id and the TLS key
/// stay; only the dates, names and serials are new.
fn reissue_if_due(cert_path: &Path, key: &str, tls_key: &str, chain: String, now: u64) -> anyhow::Result<(String, bool)> {
    if !due(&chain, now) || !carries_key(&chain, key) {
        return Ok((chain, false));
    }
    let chain = certificate(key, tls_key)?;
    write_cert(cert_path, &chain)?;
    tracing::info!(file = %cert_path.display(), days = CERT_DAYS, "the certificate of the bridge was issued again");
    Ok((chain, true))
}

/// Whether the second certificate of the chain carries the bridge's key.
fn carries_key(chain_pem: &str, key_pem: &str) -> bool {
    use vlink_proto::rustls_types::pem::PemObject;
    use vlink_proto::rustls_types::CertificateDer;
    let Ok(id) = id_of_key(key_pem) else { return false };
    CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .nth(1)
        .and_then(|c| c.ok())
        .and_then(|c| BridgeId::of_cert(c.as_ref()).ok())
        == Some(id)
}

/// The chain kept in `dir` issued again when it is [`due`]: the keys of
/// the new one, to be shown from now on, or `None` when nothing changed.
/// What a running bridge asks now and then, as certbot renews.
pub fn renew_if_due(dir: &Path) -> anyhow::Result<Option<Keys>> {
    let read = |name: &str| {
        let path = dir.join(name);
        std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))
    };
    let (key, tls_key, chain) = (read(KEY_FILE)?, read(TLS_KEY_FILE)?, read(CERT_FILE)?);
    let (chain, new) = reissue_if_due(&dir.join(CERT_FILE), &key, &tls_key, chain, unix_now())?;
    if !new {
        return Ok(None);
    }
    Pem { chain, tls_key, key }.keys().map(Some)
}

/// A new TLS key and a new chain over it in place of those kept in `dir`.
/// The bridge's key, and so the id, stay; a bridge made the key first
/// when there was none.
pub fn renew(dir: &Path) -> anyhow::Result<Keys> {
    let key_path = dir.join(KEY_FILE);
    if !key_path.exists() {
        return load_or_create(dir);
    }
    let key = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    id_of_key(&key).with_context(|| format!("{}: not the key of a bridge", key_path.display()))?;
    let tls_key = generate_tls_key()?;
    let chain = certificate(&key, &tls_key)?;
    write_private(&dir.join(TLS_KEY_FILE), &tls_key)?;
    write_cert(&dir.join(CERT_FILE), &chain)?;
    Pem { chain, tls_key, key }.keys()
}

fn write_cert(path: &Path, text: &str) -> anyhow::Result<()> {
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vlink-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_id_is_of_the_key_and_survives_a_new_tls_key_and_certificate() {
        let pem = generate().unwrap();
        let keys = pem.keys().unwrap();
        assert_eq!(keys.id, id_of_key(&pem.key).unwrap());
        assert_eq!(keys.signer.bridge_id(), keys.id);
        // The chain is two certificates: the TLS one over the TLS key,
        // the bridge's key's behind it.
        assert_eq!(keys.tls.chain.len(), 2);
        assert_ne!(BridgeId::of_cert(keys.tls.chain[0].as_ref()).unwrap(), keys.id);
        assert_eq!(BridgeId::of_cert(keys.tls.chain[1].as_ref()).unwrap(), keys.id);

        // A new TLS key and a new chain: the same bridge.
        let tls_key = generate_tls_key().unwrap();
        let renewed = certificate(&pem.key, &tls_key).unwrap();
        assert_ne!(renewed, pem.chain, "a new chain is a new one");
        assert_eq!(Pem { chain: renewed, tls_key, key: pem.key.clone() }.keys().unwrap().id, keys.id);
        // Another key is another bridge.
        let other = generate().unwrap();
        assert_ne!(other.keys().unwrap().id, keys.id);
    }

    #[test]
    fn the_files_are_made_once_and_the_tls_key_may_be_renewed() {
        let dir = temp_dir("files");
        let first = load_or_create(&dir).unwrap();
        let id = first.id;
        // The same files, the same bridge.
        assert_eq!(load_or_create(&dir).unwrap().id, id);
        let cert_before = std::fs::read_to_string(dir.join(CERT_FILE)).unwrap();
        let tls_key_before = std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap();

        // Renewed: another TLS key, another chain, the same id.
        assert_eq!(renew(&dir).unwrap().id, id);
        assert_ne!(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap(), cert_before);
        assert_ne!(std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap(), tls_key_before);
        assert_eq!(load_or_create(&dir).unwrap().id, id);

        // The chain gone: made again over the same keys.
        std::fs::remove_file(dir.join(CERT_FILE)).unwrap();
        assert_eq!(load_or_create(&dir).unwrap().id, id);
        // The TLS key gone: a new one, a new chain, the same id.
        std::fs::remove_file(dir.join(TLS_KEY_FILE)).unwrap();
        assert_eq!(load_or_create(&dir).unwrap().id, id);
        assert!(dir.join(CERT_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_chain_the_key_did_not_sign_stops_the_bridge() {
        let dir = temp_dir("mismatch");
        let id = load_or_create(&dir).unwrap().id;
        // Another bridge's chain, over its own TLS key and signed by its own key.
        let other = generate().unwrap();
        std::fs::write(dir.join(CERT_FILE), &other.chain).unwrap();
        std::fs::write(dir.join(TLS_KEY_FILE), &other.tls_key).unwrap();
        let err = format!("{:#}", load_or_create(&dir).err().expect("refused"));
        assert!(err.contains("--renew-cert"), "{err}");
        // A chain over the right TLS key but signed by another key, as an
        // impostor with a copy of the TLS key would make.
        let tls_key = std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap();
        std::fs::write(dir.join(CERT_FILE), certificate(&other.key, &tls_key).unwrap()).unwrap();
        let err = format!("{:#}", load_or_create(&dir).err().expect("refused"));
        assert!(err.contains("--renew-cert"), "{err}");
        // Renewed, it is over the right keys again.
        assert_eq!(renew(&dir).unwrap().id, id);
        assert_eq!(load_or_create(&dir).unwrap().id, id);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_key_of_the_old_kind_is_refused_with_a_word() {
        let dir = temp_dir("old-key");
        std::fs::create_dir_all(&dir).unwrap();
        // A P-256 key, as a bridge before identity v2 made.
        let old = KeyPair::generate().unwrap().serialize_pem();
        std::fs::write(dir.join(KEY_FILE), old).unwrap();
        let err = format!("{:#}", load_or_create(&dir).err().expect("refused"));
        assert!(err.contains("identity v2") && err.contains("Ed25519"), "{err}");
        assert!(format!("{:#}", renew(&dir).err().expect("refused")).contains("Ed25519"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_tls_key_is_one_a_browser_takes() {
        // The point of two keys: the handshake is signed with P-256, which
        // every browser offers, while the bridge's key stays Ed25519.
        let pem = generate().unwrap();
        assert_eq!(tls_key_of(&pem.tls_key).unwrap().algorithm(), &PKCS_ECDSA_P256_SHA256);
        assert_eq!(key_of(&pem.key).unwrap().algorithm(), &PKCS_ED25519);
        // Neither kind serves as the other.
        assert!(certificate(&pem.tls_key, &pem.key).is_err());
        assert!(certificate(&pem.key, &pem.key).is_err());
    }

    fn ders(chain: &str) -> Vec<Vec<u8>> {
        use vlink_proto::rustls_types::pem::PemObject;
        use vlink_proto::rustls_types::CertificateDer;
        CertificateDer::pem_slice_iter(chain.as_bytes()).map(|c| c.unwrap().as_ref().to_vec()).collect()
    }

    #[test]
    fn a_chain_lives_ninety_days_under_a_name_of_nobody() {
        let now = unix_now();
        let pem = generate().unwrap();
        let chain = ders(&pem.chain);
        for der in &chain {
            let end = vlink_proto::tls::not_after(der).unwrap();
            assert!(end.abs_diff(now + CERT_DAYS * 86_400) < 60, "{end} is not {CERT_DAYS} days on");
            // No `localhost`: what a server set up in a hurry says.
            assert!(!der.windows(9).any(|w| w == b"localhost"));
        }
        assert!(!due(&pem.chain, now));
        // Each chain its own names.
        let other = certificate(&pem.key, &pem.tls_key).unwrap();
        assert_ne!(ders(&other)[0], chain[0]);
        for _ in 0..50 {
            let name = made_up_name().unwrap();
            let (label, ending) = name.split_once('.').unwrap();
            assert!((4..=8).contains(&label.len()) && label.bytes().all(|b| b.is_ascii_lowercase()), "{name}");
            assert!(["com", "net", "org", "io", "dev", "app"].contains(&ending), "{name}");
        }
    }

    #[test]
    fn a_chain_near_its_end_is_issued_again_and_the_bridge_stays_the_same() {
        let dir = temp_dir("due");
        let first = load_or_create(&dir).unwrap();
        let chain = std::fs::read_to_string(dir.join(CERT_FILE)).unwrap();
        let tls_key = std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap();
        let key = std::fs::read_to_string(dir.join(KEY_FILE)).unwrap();
        // Not due today: nothing changes.
        assert!(renew_if_due(&dir).unwrap().is_none());
        assert_eq!(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap(), chain);

        // Seventy days on, twenty are left: issued again, over the same two
        // keys. The id, which every client and hub pins, is the same; the
        // TLS key too; only the certificates are new.
        let later = unix_now() + 70 * 86_400;
        assert!(due(&chain, later));
        let (renewed, new) = reissue_if_due(&dir.join(CERT_FILE), &key, &tls_key, chain.clone(), later).unwrap();
        assert!(new);
        assert_ne!(renewed, chain);
        assert_eq!(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap(), renewed);
        assert_eq!(std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap(), tls_key);
        let keys = Pem { chain: renewed.clone(), tls_key: tls_key.clone(), key: key.clone() }.keys().unwrap();
        assert_eq!(keys.id, first.id);
        // As the pin of a caller checks it: the TLS certificate signed by
        // the key whose hash is the id, in its dates.
        let algorithms = vlink_proto::pin::provider().signature_verification_algorithms.all;
        let chain_der = keys.tls.chain.clone();
        let at = vlink_proto::rustls_types::UnixTime::now();
        assert_eq!(BridgeId::of_chain(&chain_der[0], &chain_der[1..], at, algorithms).unwrap(), first.id);
        assert_eq!(load_or_create(&dir).unwrap().id, first.id);

        // A chain of twenty years, as bridges made before: issued again at
        // the start (seen here from seventy days back, when this one runs
        // well past ninety days).
        assert!(due(&renewed, unix_now() - 70 * 86_400));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_due_chain_of_somebody_else_is_not_issued_again_but_refused() {
        let dir = temp_dir("due-other");
        load_or_create(&dir).unwrap();
        let other = generate().unwrap();
        std::fs::write(dir.join(CERT_FILE), &other.chain).unwrap();
        let key = std::fs::read_to_string(dir.join(KEY_FILE)).unwrap();
        let tls_key = std::fs::read_to_string(dir.join(TLS_KEY_FILE)).unwrap();
        let later = unix_now() + 70 * 86_400;
        let (kept, new) = reissue_if_due(&dir.join(CERT_FILE), &key, &tls_key, other.chain.clone(), later).unwrap();
        assert!(!new);
        assert_eq!(kept, other.chain);
        let err = format!("{:#}", load_or_create(&dir).err().expect("refused"));
        assert!(err.contains("--renew-cert"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
