//! Calling a bridge: TLS to an address, with one certificate accepted.
//!
//! A bridge shows a certificate it made itself. Nobody signs it; whoever
//! calls knows its hash ([`BridgeId`]) and accepts nothing else. So a
//! bridge needs no name and no authority, and nobody who sits on the way
//! can answer in its place.

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

/// Accepts exactly one certificate: the one whose hash is the bridge's id.
#[derive(Debug)]
struct Pinned {
    id: BridgeId,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if BridgeId::of_cert(end_entity.as_ref()) == self.id {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
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

/// The check every caller of the bridge `id` makes of its certificate.
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
