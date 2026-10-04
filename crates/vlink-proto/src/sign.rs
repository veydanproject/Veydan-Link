//! Signing: the root delegates a list key, the list key signs lists.
//! Only the registry and the tools of the root key do this; a client only
//! checks (`list`).

use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::list::{delegation_message, hex, list_message, BridgeList, Delegation, Error, SignedList};

/// A key that signs: the root or a list key, from PKCS#8 DER.
pub struct Signer(Ed25519KeyPair);

impl Signer {
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map(Self)
            .map_err(|e| Error::Malformed(format!("not an Ed25519 key: {e}")))
    }

    /// The public half, 32 bytes as hex.
    pub fn public_hex(&self) -> String {
        hex(self.0.public_key().as_ref())
    }

    /// As the root: lets `list_key_hex` sign lists until `expires_at`.
    pub fn delegate(&self, list_key_hex: &str, expires_at: u64) -> Delegation {
        let sig = self.0.sign(&delegation_message(list_key_hex, expires_at));
        Delegation { key: list_key_hex.to_string(), expires_at, sig: hex(sig.as_ref()) }
    }

    /// As the list key: signs `list` under `delegation`.
    pub fn sign_list(&self, list: &BridgeList, delegation: &Delegation) -> SignedList {
        let text = serde_json::to_string(list).expect("a list is plain data");
        let sig = self.0.sign(&list_message(&text));
        SignedList { list: text, sig: hex(sig.as_ref()), delegation: delegation.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::VERSION;
    use crate::{BridgeId, BridgeRef};

    fn key() -> Signer {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Signer::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn list(expires_at: u64) -> BridgeList {
        let bridge = |addr: &str, seed: &[u8]| BridgeRef { addr: addr.parse().unwrap(), id: BridgeId::of_cert(seed), sni: None };
        BridgeList {
            v: VERSION,
            issued_at: 100,
            expires_at,
            bridges: vec![bridge("203.0.113.7:443", b"a"), bridge("[2001:db8::7]:8443", b"b")],
        }
    }

    #[test]
    fn a_list_signed_under_the_root_is_accepted() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        let signed = list_key.sign_list(&list(500), &delegation);
        // It survives the trip as JSON.
        let wire = serde_json::to_string(&signed).unwrap();
        let back: SignedList = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.verify(&root.public_hex(), 200).unwrap(), list(500));
    }

    #[test]
    fn keys_nobody_delegated_are_refused() {
        let (root, list_key, stranger) = (key(), key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        // A key nobody delegated, signing in the name of one that was.
        let fake = stranger.sign_list(&list(500), &delegation);
        assert_eq!(fake.verify(&root.public_hex(), 200), Err(Error::Signature));
        // A key that delegated itself.
        let own = stranger.delegate(&stranger.public_hex(), 1000);
        assert_eq!(stranger.sign_list(&list(500), &own).verify(&root.public_hex(), 200), Err(Error::Delegation));
    }

    /// `UPDATE_GOLDEN=1 cargo test -p vlink-proto golden` writes the list
    /// the clients' tests check. The keys that sign it are thrown away, so
    /// that nothing in the golden files can sign anything else.
    #[test]
    fn golden_list() {
        if std::env::var("UPDATE_GOLDEN").is_err() {
            return;
        }
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1_950_000_000);
        let mut golden = list(1_900_000_000);
        golden.issued_at = 1_790_000_000;
        let signed = list_key.sign_list(&golden, &delegation);
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../golden");
        std::fs::write(format!("{dir}/list-root.pub"), format!("{}\n", root.public_hex())).unwrap();
        std::fs::write(format!("{dir}/list-signed.json"), serde_json::to_string_pretty(&signed).unwrap() + "\n").unwrap();
    }
}
