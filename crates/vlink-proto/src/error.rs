//! What can be wrong with a name, an address or a certificate.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad bridge id: {0}")]
    BadId(String),
    #[error("bad bridge address: {0}")]
    BadRef(String),
    #[error("bad target: {0}")]
    BadTarget(String),
    #[error("tls: {0}")]
    Tls(String),
}
