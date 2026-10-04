//! TLS of the bridge and of the hub. (What a client needs is in `pin`.)
//!
//! - A bridge shows the certificate it made itself and asks the caller for
//!   one without requiring it: a hub shows one signed by the VLink root, a
//!   client shows none.
//! - A hub calls a bridge as a client does, pinned to the bridge's id, and
//!   shows its certificate. A bridge accepts any hub with a certificate of
//!   the root, wherever it calls from: that is how hubs change addresses
//!   without the bridges being told.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::Error;
use crate::id::BridgeId;
use crate::pin::{self, tls, ALPN_H2};

pub use crate::pin::server_name;

/// A hub calling a bridge.
pub const ALPN_HUB: &[u8] = b"vlink-hub/1";
pub const ALPN_HTTP1: &[u8] = b"http/1.1";

/// A certificate with its key, as read from PEM files or just made.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        use rustls::pki_types::pem::PemObject;
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(tls)?;
        if chain.is_empty() {
            return Err(Error::Tls("no certificate in the file".into()));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(tls)?;
        Ok(Self { chain, key })
    }

    /// The id a bridge with this certificate has.
    pub fn bridge_id(&self) -> BridgeId {
        BridgeId::of_cert(self.chain[0].as_ref())
    }
}

/// One certificate out of a PEM text: the VLink root.
pub fn cert_from_pem(pem: &str) -> Result<CertificateDer<'static>, Error> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(tls)
}

/// How a hub calls the bridge `bridge`: its certificate shown, ALPN vlink-hub/1.
pub fn hub_config(bridge: BridgeId, hub: Identity) -> Result<ClientConfig, Error> {
    let mut config = ClientConfig::builder_with_provider(pin::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .dangerous()
        .with_custom_certificate_verifier(pin::verifier(bridge))
        .with_client_auth_cert(hub.chain, hub.key)
        .map_err(tls)?;
    config.alpn_protocols = vec![ALPN_HUB.to_vec()];
    Ok(config)
}

/// How a bridge answers. A certificate from the caller is asked for and
/// not required. A certificate that is shown and is not signed by `root`
/// ends the handshake.
pub fn bridge_config(identity: Identity, root: CertificateDer<'static>) -> Result<ServerConfig, Error> {
    let provider = pin::provider();
    let mut roots = RootCertStore::empty();
    roots.add(root).map_err(tls)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(tls)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.chain, identity.key)
        .map_err(tls)?;
    config.alpn_protocols = vec![ALPN_HUB.to_vec(), ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()];
    Ok(config)
}
