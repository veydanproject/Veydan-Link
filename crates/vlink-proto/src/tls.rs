//! TLS of the bridge and of the hub. (What a client needs is in `pin`;
//! a node's own chain and key, `Identity`, is `veydan_node::tls`.)
//!
//! - A bridge shows the TLS certificate its key signed, with the
//!   certificate of that key behind it, and asks the caller for one without
//!   requiring it: a hub shows one signed by the VLink root, a client
//!   shows none.
//! - A hub calls a bridge as a client does, pinned to the bridge's id, and
//!   shows its certificate. A bridge accepts any hub with a certificate of
//!   the root, wherever it calls from: that is how hubs change addresses
//!   without the bridges being told.

use std::sync::{Arc, RwLock};

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use veydan_node::pin::{self, tls, ALPN_H2};

pub use veydan_node::tls::{cert_from_pem, not_after, server_name, Identity};

use crate::{BridgeId, Error};

/// A hub calling a bridge.
pub const ALPN_HUB: &[u8] = b"vlink-hub/1";
pub const ALPN_HTTP1: &[u8] = b"http/1.1";

/// The id a bridge with this chain has: [`Identity::node_id`] under the
/// name the bridge calls it.
pub trait IdentityExt {
    fn bridge_id(&self) -> Result<BridgeId, Error>;
}

impl IdentityExt for Identity {
    fn bridge_id(&self) -> Result<BridgeId, Error> {
        self.node_id()
    }
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
    bridge_config_with(BridgeCert::new(identity)?, root)
}

/// The same, showing whatever `cert` holds at the time of each handshake:
/// a bridge puts a chain issued anew into it without a restart.
pub fn bridge_config_with(cert: Arc<BridgeCert>, root: CertificateDer<'static>) -> Result<ServerConfig, Error> {
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
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![ALPN_HUB.to_vec(), ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()];
    Ok(config)
}

/// The chain a bridge shows and the TLS key under it, which may be
/// replaced while the bridge runs: the handshakes after [`BridgeCert::set`]
/// show the new one.
#[derive(Debug)]
pub struct BridgeCert(RwLock<Arc<CertifiedKey>>);

impl BridgeCert {
    pub fn new(identity: Identity) -> Result<Arc<Self>, Error> {
        Ok(Arc::new(Self(RwLock::new(certified(identity)?))))
    }

    /// Shows `identity` from now on. The key has to be the one the first
    /// certificate is over, as at the start.
    pub fn set(&self, identity: Identity) -> Result<(), Error> {
        let certified = certified(identity)?;
        *self.0.write().expect("bridge cert") = certified;
        Ok(())
    }
}

fn certified(identity: Identity) -> Result<Arc<CertifiedKey>, Error> {
    CertifiedKey::from_der(identity.chain, identity.key, &pin::provider()).map(Arc::new).map_err(tls)
}

impl ResolvesServerCert for BridgeCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().expect("bridge cert").clone())
    }
}
