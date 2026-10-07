//! Calling a bridge: TLS to an address, with one key accepted.
//!
//! A bridge shows two certificates: one over the key TLS runs on, signed
//! by the bridge's own key, and one carrying that key. No authority signs
//! either; whoever calls knows the hash of the bridge's key ([`BridgeId`])
//! and accepts nothing else. So a bridge needs no name and no authority,
//! and nobody who sits on the way can answer in its place: the TLS
//! certificate has to be signed by the bridge's key, and the handshake by
//! the TLS key in it. The TLS key and its certificate may change (be
//! issued again, carry other names or dates); only the key that signed
//! them is looked at.
//!
//! The TLS key is of the kind every browser takes (ECDSA P-256), so a
//! passer-by that is not a client of VLink completes the handshake too and
//! gets the page a bare web server would give, rather than an alert that
//! tells the bridge apart.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::error::Error;
use crate::id::{BridgeId, BridgeRef};

/// A client calling a bridge: what any browser offers.
pub const ALPN_H2: &[u8] = b"h2";

/// `ring`, named explicitly: whatever the process installed as its default
/// changes nothing here.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn tls(e: impl std::fmt::Display) -> Error {
    Error::Tls(e.to_string())
}

/// Accepts exactly one key: the one whose hash is the bridge's id. The
/// TLS certificate may be any that key signed; what proves that the other
/// side holds the TLS key is the handshake signature, which rustls has
/// this verifier check against the certificate (`verify_tls13_signature`).
#[derive(Debug)]
struct Pinned {
    id: BridgeId,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match BridgeId::of_chain(end_entity, intermediates, now, self.algorithms.all) {
            Ok(id) if id == self.id => Ok(ServerCertVerified::assertion()),
            // Another bridge's key signed it: the wrong bridge, or an
            // impostor at its address.
            Ok(_) => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
            // No key vouched for the TLS certificate, or it cannot be read.
            Err(e) => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(e))))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The check every caller of the bridge `id` makes of what it shows.
pub fn verifier(id: BridgeId) -> Arc<dyn ServerCertVerifier> {
    Arc::new(Pinned { id, algorithms: provider().signature_verification_algorithms })
}

/// How a client calls the bridge `id`: h2, and nothing shown about itself.
pub fn client_config(id: BridgeId) -> Result<ClientConfig, Error> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier(id))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

/// The name the TLS hello is addressed to. A bare address has no name to
/// show, so none is sent unless the reference asks for one.
pub fn server_name(bridge: &BridgeRef) -> Result<ServerName<'static>, Error> {
    match &bridge.sni {
        Some(name) => ServerName::try_from(name.clone()).map_err(tls),
        None => Ok(ServerName::IpAddress(bridge.addr.ip().into())),
    }
}
