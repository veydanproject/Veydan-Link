//! Hubs the root no longer stands behind.
//!
//! A bridge takes any hub with a certificate of the root (`tls`), and a
//! certificate cannot be taken back: a hub whose key was stolen would be
//! one until its certificate ran out. So the registry tells every bridge,
//! in the answer to each of its reports (`wire::Registered`), which hub
//! keys are revoked. The list is signed as the lists of bridges are
//! (`list`): by the list key, under the root's delegation. A bridge keeps
//! the newest list it was given (`issued_at`), lets no hub of it link,
//! and drops the links such a hub holds.
//!
//! A hub is named by the SHA-256 of the SubjectPublicKeyInfo of its
//! certificate: a certificate issued again over the same key is revoked
//! with it, and a new key is a new hub.

use std::collections::BTreeSet;

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::list::{hex, unhex, Delegation, Error};

pub const VERSION: u32 = 1;
/// What is signed is prefixed with what it is, so that a signature made
/// for one thing is never one for another.
const CONTEXT: &str = "vlink-revoked/1\n";
/// How far ahead of the bridge's clock a list may be dated.
pub const SKEW_SECS: u64 = 300;

/// The DER of a SubjectPublicKeyInfo carrying an Ed25519 key, up to the
/// 32 bytes of the key.
const ED25519_SPKI_HEADER: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The revoked hubs, signed. Times are unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocations {
    pub v: u32,
    /// SHA-256 of the SubjectPublicKeyInfo of each revoked hub's
    /// certificate, 64 lowercase hex characters, sorted.
    pub keys: Vec<String>,
    /// When the list was made; a newer list replaces an older one.
    pub issued_at: u64,
    /// The list key's signature under [`Revocations::message`], hex.
    pub sig: String,
    pub delegation: Delegation,
}

/// The name of a hub: SHA-256 of the SubjectPublicKeyInfo of the
/// certificate it shows (DER).
pub fn hub_key(cert_der: &[u8]) -> Result<[u8; 32], crate::Error> {
    // The same hash as a bridge's id, of the key a certificate carries.
    crate::BridgeId::of_cert(cert_der).map(|id| id.0)
}

/// The same, as hex.
pub fn hub_key_hex(cert_der: &[u8]) -> Result<String, crate::Error> {
    hub_key(cert_der).map(|k| hex(&k))
}

/// The root's Ed25519 key, 32 bytes as hex, from its certificate (DER):
/// what the delegation of a list is checked against.
pub fn root_key_of_cert(der: &[u8]) -> Result<String, crate::Error> {
    let cert = rustls::pki_types::CertificateDer::from(der);
    let parsed = webpki::EndEntityCert::try_from(&cert).map_err(|e| crate::Error::BadCert(e.to_string()))?;
    let spki = parsed.subject_public_key_info();
    let spki: &[u8] = spki.as_ref();
    match spki.strip_prefix(&ED25519_SPKI_HEADER[..]) {
        Some(key) if key.len() == 32 => Ok(hex(key)),
        _ => Err(crate::Error::BadCert("the root's key is not Ed25519".into())),
    }
}

fn is_key(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Revocations {
    /// The bytes the list key signs.
    pub fn message(&self) -> Vec<u8> {
        format!("{CONTEXT}{}\n{}\n{}", self.v, self.issued_at, self.keys.join(",")).into_bytes()
    }

    /// Is this the root's word, as it was when the list was made? Every
    /// signature holds, and the delegation was in force at `issued_at`.
    /// What a bridge asks of the list it kept: a revocation does not run
    /// out with the key that signed it.
    pub fn check(&self, root_hex: &str) -> Result<(), Error> {
        if self.v != VERSION {
            return Err(Error::Version(self.v));
        }
        if !self.keys.iter().all(|k| is_key(k)) {
            return Err(Error::Malformed("a revoked key is not 64 lowercase hex characters".into()));
        }
        self.delegation.verify(root_hex, self.issued_at)?;
        let key = unhex(&self.delegation.key)?;
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&self.message(), &unhex(&self.sig)?)
            .map_err(|_| Error::Signature)
    }

    /// A list just given, at `now`: [`Revocations::check`], under a
    /// delegation still in force, and not dated ahead of the clock.
    pub fn verify(&self, root_hex: &str, now: u64) -> Result<(), Error> {
        self.check(root_hex)?;
        if now >= self.delegation.expires_at {
            return Err(Error::DelegationExpired);
        }
        if self.issued_at > now + SKEW_SECS {
            return Err(Error::Malformed("the list is dated ahead of this clock".into()));
        }
        Ok(())
    }

    /// The revoked keys, as bytes.
    pub fn hub_keys(&self) -> BTreeSet<[u8; 32]> {
        self.keys
            .iter()
            .filter_map(|k| unhex(k).ok()?.try_into().ok())
            .collect()
    }
}

/// The keys as a list carries them: lowercase, each once, sorted.
pub fn normalize(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    keys.into_iter().map(|k| k.to_ascii_lowercase()).collect::<BTreeSet<_>>().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Signer;
    use ring::signature::Ed25519KeyPair;

    fn key() -> Signer {
        let rng = ring::rand::SystemRandom::new();
        Signer::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap()
    }

    fn keys() -> Vec<String> {
        normalize(["AB".repeat(32), "01".repeat(32)])
    }

    #[test]
    fn a_list_under_the_root_holds_and_survives_the_trip() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let list = list_key.sign_revocations(keys(), 1_000, &delegation);
        assert_eq!(list.keys, vec!["01".repeat(32), "ab".repeat(32)]);
        let back: Revocations = serde_json::from_str(&serde_json::to_string(&list).unwrap()).unwrap();
        assert_eq!(back.verify(&root.public_hex(), 1_100), Ok(()));
        assert_eq!(back.hub_keys().len(), 2);
        assert!(back.hub_keys().contains(&[0xab; 32]));
    }

    #[test]
    fn a_list_of_another_delegation_is_refused() {
        let (root, list_key, stranger) = (key(), key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        // A key nobody delegated, signing under the delegation of another.
        let fake = stranger.sign_revocations(keys(), 1_000, &delegation);
        assert_eq!(fake.verify(&root.public_hex(), 1_100), Err(Error::Signature));
        // A key that delegated itself.
        let own = stranger.delegate(&stranger.public_hex(), 10_000);
        let fake = stranger.sign_revocations(keys(), 1_000, &own);
        assert_eq!(fake.verify(&root.public_hex(), 1_100), Err(Error::Delegation));
        // A delegation of another root.
        let other_root = key();
        let other = other_root.delegate(&list_key.public_hex(), 10_000);
        let fake = list_key.sign_revocations(keys(), 1_000, &other);
        assert_eq!(fake.verify(&root.public_hex(), 1_100), Err(Error::Delegation));
        // A key taken off the list after signing: the signature breaks.
        let mut cut = list_key.sign_revocations(keys(), 1_000, &delegation);
        cut.keys.pop();
        assert_eq!(cut.verify(&root.public_hex(), 1_100), Err(Error::Signature));
        // Or dated anew to win over a newer one.
        let mut moved = list_key.sign_revocations(keys(), 1_000, &delegation);
        moved.issued_at = 2_000;
        assert_eq!(moved.verify(&root.public_hex(), 2_100), Err(Error::Signature));
    }

    #[test]
    fn times_are_held_to_the_delegation_and_the_clock() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let list = list_key.sign_revocations(keys(), 1_000, &delegation);
        // Given after the delegation ran out: refused; kept from before: it holds.
        assert_eq!(list.verify(&root.public_hex(), 10_000), Err(Error::DelegationExpired));
        assert_eq!(list.check(&root.public_hex()), Ok(()));
        // Made after the delegation ran out: refused even as kept.
        let late = list_key.sign_revocations(keys(), 10_000, &delegation);
        assert_eq!(late.check(&root.public_hex()), Err(Error::DelegationExpired));
        // Dated ahead of the clock.
        let ahead = list_key.sign_revocations(keys(), 5_000, &delegation);
        assert!(matches!(ahead.verify(&root.public_hex(), 5_000 - SKEW_SECS - 1), Err(Error::Malformed(_))));
        assert_eq!(ahead.verify(&root.public_hex(), 5_000 - SKEW_SECS), Ok(()));
    }

    #[test]
    fn keys_are_of_one_form() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let mut list = list_key.sign_revocations(keys(), 1_000, &delegation);
        list.keys.push("AB".repeat(32));
        assert!(matches!(list.check(&root.public_hex()), Err(Error::Malformed(_))));
    }
}
