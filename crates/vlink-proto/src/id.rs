//! Who a bridge is, and where.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use rustls::pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};

use crate::error::Error;

/// The DER of a SubjectPublicKeyInfo carrying an Ed25519 key, up to the
/// 32 bytes of the key: the algorithm identifier and the bit string header.
const ED25519_SPKI_HEADER: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// SHA-256 of the bridge's key: of its SubjectPublicKeyInfo in DER (the
/// way HPKP pinned keys). The key is Ed25519, made on the bridge's first
/// start and kept; it is not the key TLS runs on. The bridge serves TLS
/// with a key of the kind every browser takes (ECDSA P-256) and a
/// certificate over it that the bridge's key *signed*: the chain shown
/// is `[certificate over the TLS key, certificate carrying the bridge's
/// key]`. Whoever calls hashes the second, checks the first against it,
/// and lets TLS prove the TLS key. The TLS key and its certificate may
/// change at any time; the bridge's key, and so the id, stays.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BridgeId(pub [u8; 32]);

impl BridgeId {
    /// Of a key, given as its SubjectPublicKeyInfo in DER.
    pub fn of_key(spki_der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, spki_der);
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        Self(id)
    }

    /// Of an Ed25519 key given raw, as a registration carries it: the
    /// same id as of the certificate carrying the key.
    pub fn of_ed25519(public: &[u8; 32]) -> Self {
        let mut spki = ED25519_SPKI_HEADER.to_vec();
        spki.extend_from_slice(public);
        Self::of_key(&spki)
    }

    /// Of the key a certificate (DER) carries: the bridge's id when the
    /// certificate is the one carrying its key, the second of its chain.
    /// The certificate is read by the parser rustls checks handshake
    /// signatures with, so the key hashed here and the key TLS runs on
    /// are read the same way from the same bytes.
    pub fn of_cert(der: &[u8]) -> Result<Self, Error> {
        let cert = CertificateDer::from(der);
        let parsed = webpki::EndEntityCert::try_from(&cert).map_err(|e| Error::BadCert(e.to_string()))?;
        Ok(Self::of_key(&parsed.subject_public_key_info()))
    }

    /// Of the chain a bridge shows, once it is held to the rule: the
    /// first certificate (the TLS one) is signed by the key the second
    /// carries and is in its dates at `now`. The id is of that key.
    /// `algorithms` are the signatures understood; the provider's `all`.
    /// A chain that breaks the rule has no id: nobody's key vouched for
    /// the TLS key, whatever the second certificate says.
    pub fn of_chain(
        end_entity: &CertificateDer<'_>,
        rest: &[CertificateDer<'_>],
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<Self, Error> {
        let issuer =
            rest.first().ok_or_else(|| Error::BadCert("no certificate of the bridge's key behind the TLS one".into()))?;
        let bad = |e: webpki::Error| Error::BadCert(e.to_string());
        let anchor = webpki::anchor_from_trusted_cert(issuer).map_err(bad)?;
        let leaf = webpki::EndEntityCert::try_from(end_entity).map_err(bad)?;
        // No names are checked: a bridge is an address. Only that the key
        // in `issuer` signed `end_entity`, and that it is in its dates.
        leaf.verify_for_usage(algorithms, std::slice::from_ref(&anchor), &[], now, webpki::KeyUsage::server_auth(), None, None)
            .map_err(|e| Error::BadCert(format!("the TLS certificate is not signed by the bridge's key: {e}")))?;
        Self::of_cert(issuer.as_ref())
    }

    /// The first 8 hex characters: enough to tell bridges apart in a log.
    pub fn short(&self) -> String {
        self.to_string()[..8].to_string()
    }
}

impl fmt::Display for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BridgeId({})", self.short())
    }
}

impl FromStr for BridgeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadId(s.to_string()));
        }
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error::BadId(s.to_string()))?;
        }
        Ok(Self(id))
    }
}

impl serde::Serialize for BridgeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for BridgeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// All that is needed to reach a bridge: `203.0.113.7:443#<id>`, with
/// `?sni=name` when the TLS hello should carry a name.
///
/// A bare address has no name to show, so by default none is sent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BridgeRef {
    pub addr: SocketAddr,
    pub id: BridgeId,
    pub sni: Option<String>,
}

impl fmt::Display for BridgeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.addr, self.id)?;
        if let Some(sni) = &self.sni {
            write!(f, "?sni={sni}")?;
        }
        Ok(())
    }
}

impl FromStr for BridgeRef {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::BadRef(s.to_string());
        let s = s.trim();
        let (addr, rest) = s.split_once('#').ok_or_else(bad)?;
        let (id, sni) = match rest.split_once("?sni=") {
            Some((id, sni)) if !sni.is_empty() => (id, Some(sni.to_ascii_lowercase())),
            Some(_) => return Err(bad()),
            None => (rest, None),
        };
        Ok(Self {
            addr: addr.parse().map_err(|_| bad())?,
            id: id.parse()?,
            sni,
        })
    }
}

impl serde::Serialize for BridgeRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for BridgeRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trips_and_rejects_garbage() {
        let id = BridgeId::of_key(b"certificate");
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<BridgeId>().unwrap(), id);
        assert!("abc".parse::<BridgeId>().is_err());
        assert!("z".repeat(64).parse::<BridgeId>().is_err());
    }

    #[test]
    fn bridge_ref_round_trips() {
        let id = BridgeId::of_key(b"x");
        let plain: BridgeRef = format!("203.0.113.7:443#{id}").parse().unwrap();
        assert_eq!(plain.addr.port(), 443);
        assert_eq!(plain.sni, None);
        assert_eq!(plain.to_string().parse::<BridgeRef>().unwrap(), plain);

        let named: BridgeRef = format!("[2001:db8::1]:8443#{id}?sni=Example.org").parse().unwrap();
        assert_eq!(named.sni.as_deref(), Some("example.org"));
        assert_eq!(named.to_string().parse::<BridgeRef>().unwrap(), named);

        assert!("203.0.113.7:443".parse::<BridgeRef>().is_err());
        assert!(format!("host:443#{id}").parse::<BridgeRef>().is_err());
        assert!(format!("203.0.113.7:443#{id}?sni=").parse::<BridgeRef>().is_err());
    }
}

#[cfg(test)]
pub(crate) mod cert_tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    // Two chains of one bridge: P-256 TLS certificates over different TLS
    // keys, both signed by the same Ed25519 key, and that key's own
    // certificate behind each. And the chain of another bridge. Made for
    // this test with openssl; they guard nothing. The same ones are in
    // `crates/messenger/vlink/src/testing/certs.rs`.
    pub const CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIIBcDCCASKgAwIBAgIIEgECAwQFBgcwBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBB5SEYuVXn0OBvk
8JgDvZjmBXhKljRiizwcmR+FsaGmwQjSJVDL7hKFvLHiLCaJrtS0TLbJ8JMfRDmU
BwRZ4mejYzBhMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAJBgNVHRMEAjAAMB0GA1Ud
DgQWBBTi7QFLPRpIsYYCh2kTpKwGjEdqZDAfBgNVHSMEGDAWgBSSpKpC7ROmIhJk
WUT70j9bznyGNjAFBgMrZXADQQAZqOG7Cb/n0YlTAjj/Sipf2vKRugebIQ3u5np6
MItZBdiYrW1ssfR1Hy8f/jDlkAPDnr6i9cJvMMzayqz7H/gI
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBQDCB86ADAgECAggRAQIDBAUGBzAFBgMrZXAwFDESMBAGA1UEAwwJbG9jYWxo
b3N0MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCowBQYDK2VwAyEAma81HXyEZ69LHkAox9PHH4gHRfMzP5TPyELz
NIf/CQajYzBhMB0GA1UdDgQWBBSSpKpC7ROmIhJkWUT70j9bznyGNjAfBgNVHSME
GDAWgBSSpKpC7ROmIhJkWUT70j9bznyGNjAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIChDAFBgMrZXADQQDkQGhf0eDYbccl7Nj6TcPnQKmt6laKwFOr5yG0
G6q2QCNmMRbfAqxRF2TSVhIVFzAW9Tc+QuZrqYqsTQdvUlgK
-----END CERTIFICATE-----";
    pub const RENEWED_CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIIBcDCCASKgAwIBAgIIIgECAwQFBgcwBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC5C0VXx8b5l0BF2
ep+rvDQSS+lhHXzTu5yyyyJ9l4A9Q2ZVdZsLYj/YOusFtonsm2YgkTs3Sga8pgGI
Napqv5ujYzBhMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAJBgNVHRMEAjAAMB0GA1Ud
DgQWBBQ1nDJ46qVUSdFfVVhBLCSSDFdAbDAfBgNVHSMEGDAWgBSSpKpC7ROmIhJk
WUT70j9bznyGNjAFBgMrZXADQQA+MnaUCTcBlxcAymzlQaQ/hWskXMM5FVx8/PSG
mb+K8/qXV04P0q42IqDvdW33kKsvD/a9r8nVFtKCKEKolHIA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBQDCB86ADAgECAggRAQIDBAUGBzAFBgMrZXAwFDESMBAGA1UEAwwJbG9jYWxo
b3N0MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCowBQYDK2VwAyEAma81HXyEZ69LHkAox9PHH4gHRfMzP5TPyELz
NIf/CQajYzBhMB0GA1UdDgQWBBSSpKpC7ROmIhJkWUT70j9bznyGNjAfBgNVHSME
GDAWgBSSpKpC7ROmIhJkWUT70j9bznyGNjAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIChDAFBgMrZXADQQDkQGhf0eDYbccl7Nj6TcPnQKmt6laKwFOr5yG0
G6q2QCNmMRbfAqxRF2TSVhIVFzAW9Tc+QuZrqYqsTQdvUlgK
-----END CERTIFICATE-----";
    pub const OTHER_CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIIBcDCCASKgAwIBAgIINAECAwQFBgcwBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLpBEVebP/ppIdgM
ZDxYSJ5jvmOSypdoA7y8PgLSPSho78qWgkZOWl34aMxpAPt6bTzHSWhmHazg0yaU
mNw+u36jYzBhMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAJBgNVHRMEAjAAMB0GA1Ud
DgQWBBSc4+k5JIPlrefTCLHc5KV1sXZbyTAfBgNVHSMEGDAWgBRr5/uK/P8Sgteo
DkTAPouh367VMTAFBgMrZXADQQANmIpYd3HHipYHIW+IL9ydDQq4D+lNrn9b3O82
qsVveGt/I774IPsZIV5srHuB2PRTDqwN2aPtszU2ObIFkmEI
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBQDCB86ADAgECAggzAQIDBAUGBzAFBgMrZXAwFDESMBAGA1UEAwwJbG9jYWxo
b3N0MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCowBQYDK2VwAyEAgS57XBJBa1ugKpJyE0iXgipLthqdaI3Eh4KA
6Q/Om6ujYzBhMB0GA1UdDgQWBBRr5/uK/P8SgteoDkTAPouh367VMTAfBgNVHSME
GDAWgBRr5/uK/P8SgteoDkTAPouh367VMTAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIChDAFBgMrZXADQQAGWz2/n6j2xbw2jxtE7TNzaV6iZCJHBoVITjV4
hMSKafRt4afhpl+5M7E8LYFLEI9TOpGTQZayeB3UJqyNbSAE
-----END CERTIFICATE-----";

    pub fn chain(pem: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<_, _>>().unwrap()
    }

    fn algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.all
    }

    /// Well within the dates of every certificate here: 2030.
    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_900_000_000))
    }

    fn id_of(pem: &str) -> Result<BridgeId, Error> {
        let chain = chain(pem);
        BridgeId::of_chain(&chain[0], &chain[1..], now(), algorithms())
    }

    #[test]
    fn the_id_is_of_the_key_that_signed_the_tls_certificate() {
        // Two TLS keys, two certificates, one bridge: the key that signed
        // them is the same.
        assert_eq!(id_of(CHAIN).unwrap(), id_of(RENEWED_CHAIN).unwrap());
        assert_ne!(id_of(CHAIN).unwrap(), id_of(OTHER_CHAIN).unwrap());
        let [tls, issuer]: [CertificateDer<'static>; 2] = chain(CHAIN).try_into().ok().unwrap();
        // The id is of the second certificate's key, not of the first's,
        // and not of either certificate's bytes.
        assert_eq!(id_of(CHAIN).unwrap(), BridgeId::of_cert(issuer.as_ref()).unwrap());
        assert_ne!(id_of(CHAIN).unwrap(), BridgeId::of_cert(tls.as_ref()).unwrap());
        assert_ne!(id_of(CHAIN).unwrap(), BridgeId::of_key(issuer.as_ref()));
        // The SPKI of an Ed25519 key is 44 bytes: 12 of header, 32 of
        // key; the same id comes from the raw key.
        let spki = webpki::EndEntityCert::try_from(&issuer).unwrap().subject_public_key_info();
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..12], &ED25519_SPKI_HEADER);
        assert_eq!(id_of(CHAIN).unwrap(), BridgeId::of_ed25519(spki[12..].try_into().unwrap()));
        // The TLS key is one a browser takes: P-256, not Ed25519.
        let tls_spki = webpki::EndEntityCert::try_from(&tls).unwrap().subject_public_key_info();
        assert_ne!(&tls_spki[..12], &ED25519_SPKI_HEADER);
    }

    #[test]
    fn a_tls_certificate_the_key_did_not_sign_has_no_id() {
        let (ours, theirs) = (chain(CHAIN), chain(OTHER_CHAIN));
        let error = |r: Result<BridgeId, Error>| match r {
            Err(Error::BadCert(text)) => text,
            other => panic!("{other:?}"),
        };
        // Their TLS certificate behind our key's certificate: our key did
        // not sign it, so our id is not earned, whatever is claimed.
        assert!(error(BridgeId::of_chain(&theirs[0], &ours[1..], now(), algorithms())).contains("not signed"));
        // A TLS certificate alone, nobody's key behind it.
        assert!(error(BridgeId::of_chain(&ours[0], &[], now(), algorithms())).contains("no certificate"));
        // The certificates the wrong way round: a key's certificate is
        // not signed by a TLS key.
        assert!(BridgeId::of_chain(&ours[1], &ours[..1], now(), algorithms()).is_err());
        // Out of its dates.
        let too_early = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_000_000_000));
        assert!(BridgeId::of_chain(&ours[0], &ours[1..], too_early, algorithms()).is_err());
    }

    #[test]
    fn what_is_not_a_certificate_has_no_id() {
        assert!(matches!(BridgeId::of_cert(b"not a certificate"), Err(Error::BadCert(_))));
        assert!(matches!(BridgeId::of_cert(b""), Err(Error::BadCert(_))));
    }
}
