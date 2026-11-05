//! The list of bridges a client is given, and the check of its signatures.
//!
//! The envelope and the check of the two signatures (the root's
//! delegation, the list key's signature) are `veydan_node::list`; the list
//! of bridges itself is `registry_proto::bridge`. Both are given here
//! under the names this module always had: `SignedList::verify(root,
//! now)` gives a [`BridgeList`] with [`SignedBridges`] in scope.

pub use registry_proto::bridge::{list_message, BridgeList, SignedBridges, LIST_VERSION as VERSION};
pub use veydan_node::list::{delegation_message, hex, unhex, Delegation, Error, SignedList};
