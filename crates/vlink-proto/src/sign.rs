//! Signing: the root delegates a list key, the list key signs lists, a
//! bridge's key signs its registrations. Only the servers and the tools of
//! the root key do this; a client only checks (`list`).
//!
//! The key is `veydan_node::sign::Signer`; what it signs for the registry
//! is `registry_proto::sign::SignerExt`, in scope here so that
//! `signer.sign_registration(..)`, `.sign_list(..)` and
//! `.sign_revocations(..)` read as they always did.

pub use registry_proto::sign::SignerExt;
pub use veydan_node::sign::Signer;

use crate::BridgeId;

/// [`Signer::node_id`] under the name a bridge calls it.
pub trait BridgeSigner {
    fn bridge_id(&self) -> BridgeId;
}

impl BridgeSigner for Signer {
    fn bridge_id(&self) -> BridgeId {
        self.node_id()
    }
}
