//! The hubs the bridge lets in no longer: the newest list of revoked hubs
//! a registry gave (`vlink_proto::revoke`), kept in `revoked.json` of the
//! data folder so that a restart does not forget it.
//!
//! A list is taken when the root's delegation holds for it and it is newer
//! than the one kept; an older one, or one somebody else signed, changes
//! nothing. What is kept is checked again at the start, and holds after
//! the key that signed it ran out: a revocation does not lapse.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context;
use vlink_proto::list::Error;
use vlink_proto::revoke::{self, Revocations};
use vlink_proto::rustls_types::CertificateDer;

pub const FILE: &str = "revoked.json";

pub struct Store {
    path: PathBuf,
    /// The root's key, hex: the delegation of a list is checked against it.
    root: String,
    current: Option<Revocations>,
}

impl Store {
    /// What `dir` keeps, held to the root of `root` (the certificate hubs
    /// are signed by). A file that does not hold is set aside with a word
    /// and the bridge starts with none.
    pub fn open(dir: &Path, root: &CertificateDer<'_>) -> anyhow::Result<Self> {
        let root = revoke::root_key_of_cert(root.as_ref()).context("the root certificate")?;
        let path = dir.join(FILE);
        let mut current = None;
        if path.exists() {
            let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
            match serde_json::from_str::<Revocations>(&text).map_err(|e| Error::Malformed(e.to_string())).and_then(|l| l.check(&root).map(|_| l)) {
                Ok(list) => current = Some(list),
                Err(e) => tracing::warn!(file = %path.display(), error = %e, "the kept list of revoked hubs does not hold; none is in force"),
            }
        }
        Ok(Self { path, root, current })
    }

    /// The keys of the revoked hubs (`revoke::hub_key`).
    pub fn keys(&self) -> BTreeSet<[u8; 32]> {
        self.current.as_ref().map(Revocations::hub_keys).unwrap_or_default()
    }

    /// Takes the list a registry gave at `now` when it holds and is newer
    /// than the one kept, and keeps it. Returns whether the keys in force
    /// changed.
    pub fn take(&mut self, list: &Revocations, now: u64) -> anyhow::Result<bool> {
        list.verify(&self.root, now).context("the list of revoked hubs")?;
        if self.current.as_ref().is_some_and(|c| c.issued_at >= list.issued_at) {
            return Ok(false);
        }
        let before = self.keys();
        let text = serde_json::to_string_pretty(list).expect("a list is plain data");
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, text)
            .and_then(|_| std::fs::rename(&tmp, &self.path))
            .with_context(|| format!("cannot write {}", self.path.display()))?;
        self.current = Some(list.clone());
        Ok(self.keys() != before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use vlink_proto::sign::Signer;

    struct Root {
        cert: CertificateDer<'static>,
        signer: Signer,
    }

    fn root() -> Root {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&key).unwrap();
        Root { cert: cert.der().clone(), signer: Signer::from_pkcs8(&key.serialize_der()).unwrap() }
    }

    fn list_key() -> Signer {
        Signer::from_pkcs8(&KeyPair::generate_for(&PKCS_ED25519).unwrap().serialize_der()).unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vlink-revoked-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_newest_list_of_the_root_is_kept_across_a_restart() {
        let dir = temp_dir("newest");
        let (root, key) = (root(), list_key());
        let delegation = root.signer.delegate(&key.public_hex(), 10_000);
        let mut store = Store::open(&dir, &root.cert).unwrap();
        assert!(store.keys().is_empty());

        let first = key.sign_revocations(vec!["aa".repeat(32)], 1_000, &delegation);
        assert!(store.take(&first, 1_000).unwrap());
        assert_eq!(store.keys(), BTreeSet::from([[0xaa; 32]]));
        // The same again changes nothing; an older one neither.
        assert!(!store.take(&first, 1_100).unwrap());
        let older = key.sign_revocations(vec![], 900, &delegation);
        assert!(!store.take(&older, 1_100).unwrap());
        assert_eq!(store.keys().len(), 1);
        // A newer one takes its place, a hub let in again too.
        let newer = key.sign_revocations(vec!["bb".repeat(32)], 2_000, &delegation);
        assert!(store.take(&newer, 2_000).unwrap());
        assert_eq!(store.keys(), BTreeSet::from([[0xbb; 32]]));

        // After a restart, and after the delegation ran out, it holds.
        let again = Store::open(&dir, &root.cert).unwrap();
        assert_eq!(again.keys(), BTreeSet::from([[0xbb; 32]]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_list_of_another_delegation_is_refused_and_changes_nothing() {
        let dir = temp_dir("stranger");
        let (root, key) = (root(), list_key());
        let delegation = root.signer.delegate(&key.public_hex(), 10_000);
        let mut store = Store::open(&dir, &root.cert).unwrap();
        let kept = key.sign_revocations(vec!["aa".repeat(32)], 1_000, &delegation);
        store.take(&kept, 1_000).unwrap();

        // Another root's delegation, the list key of nobody, a lapsed delegation.
        let other = root_other_delegation(&key);
        let forged = key.sign_revocations(vec![], 2_000, &other);
        assert!(store.take(&forged, 2_000).is_err());
        let stranger = list_key();
        let forged = stranger.sign_revocations(vec![], 2_000, &delegation);
        assert!(store.take(&forged, 2_000).is_err());
        let late = key.sign_revocations(vec![], 10_500, &delegation);
        assert!(store.take(&late, 10_500).is_err());
        assert_eq!(store.keys(), BTreeSet::from([[0xaa; 32]]));

        // A file somebody wrote over is not believed at the start.
        std::fs::write(dir.join(FILE), serde_json::to_string(&forged).unwrap()).unwrap();
        assert!(Store::open(&dir, &root.cert).unwrap().keys().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn root_other_delegation(key: &Signer) -> vlink_proto::list::Delegation {
        root().signer.delegate(&key.public_hex(), 10_000)
    }
}
