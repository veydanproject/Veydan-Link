//! Signing: the root delegates a list key, the list key signs lists, a
//! bridge's key signs its registrations. Only the servers and the tools of
//! the root key do this; a client only checks (`list`).

use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::id::BridgeId;
use crate::list::{delegation_message, hex, list_message, BridgeList, Delegation, Error, SignedList};
use crate::wire::Registration;

/// A key that signs: the root, a list key or a bridge's key, from PKCS#8 DER.
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

    /// The id of the bridge whose key this is.
    pub fn bridge_id(&self) -> BridgeId {
        let mut public = [0u8; 32];
        public.copy_from_slice(self.0.public_key().as_ref());
        BridgeId::of_ed25519(&public)
    }

    /// As a bridge: puts the key and its signature into `registration`,
    /// whose other fields are already filled. The registry takes the
    /// address from a registration only when the key of its id signed
    /// it, so nobody else can move the bridge's id to another address.
    pub fn sign_registration(&self, registration: &mut Registration) {
        registration.key = self.public_hex();
        registration.sig = hex(self.0.sign(&registration.message()).as_ref());
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
        let bridge = |addr: &str, seed: &[u8]| BridgeRef { addr: addr.parse().unwrap(), id: BridgeId::of_key(seed), sni: None };
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

    #[test]
    fn a_registration_is_taken_from_the_key_of_its_id_only() {
        use crate::wire::Unsigned;
        let (bridge, stranger) = (key(), key());
        let mut registration = Registration {
            id: bridge.bridge_id(),
            port: 443,
            ip: Some("203.0.113.7".parse().unwrap()),
            hubs: 2,
            version: "0.2.0".into(),
            ts: 1000,
            key: String::new(),
            sig: String::new(),
        };
        // Unsigned: refused.
        assert_eq!(registration.verify(1000, 300), Err(Unsigned::Key));
        bridge.sign_registration(&mut registration);
        assert_eq!(registration.verify(1000, 300), Ok(()));
        // It survives the trip as JSON.
        let back: Registration = serde_json::from_str(&serde_json::to_string(&registration).unwrap()).unwrap();
        assert_eq!(back.verify(1200, 300), Ok(()));
        // The clocks a little apart is fine; a report from long ago is not.
        assert_eq!(registration.verify(700, 300), Ok(()));
        assert_eq!(registration.verify(1301, 300), Err(Unsigned::Clock));
        assert_eq!(registration.verify(699, 300), Err(Unsigned::Clock));

        // Somebody else's key under the bridge's id: the key is not the
        // id's, whatever it signed.
        let mut forged = registration.clone();
        stranger.sign_registration(&mut forged);
        assert_eq!(forged.verify(1000, 300), Err(Unsigned::Key));
        // The bridge's key, but the address changed after it signed.
        let mut moved = registration.clone();
        moved.ip = Some("198.51.100.9".parse().unwrap());
        assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        let mut moved = registration.clone();
        moved.port = 8443;
        assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        // Or the time, to make an old one pass.
        let mut replayed = registration.clone();
        replayed.ts = 5000;
        assert_eq!(replayed.verify(5000, 300), Err(Unsigned::Signature));
        // Or the signature itself is not one.
        let mut garbled = registration.clone();
        garbled.sig = "zz".into();
        assert_eq!(garbled.verify(1000, 300), Err(Unsigned::Signature));
        let mut short = registration.clone();
        short.key.truncate(10);
        assert_eq!(short.verify(1000, 300), Err(Unsigned::Key));
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
