//! What the client, the bridge and the hub share.
//!
//! ```text
//! client ── TLS to the bridge's address, its key pinned ───────── h2 CONNECT host:443
//! bridge ── relays every stream into a link a hub opened ───────── h2 CONNECT host:443
//! hub    ── lets through the hosts of the manifest only ─────────── TCP to the server
//! ```
//!
//! The bridge accepts hubs and clients on one port and tells them apart by
//! ALPN. On a link the roles of h2 are reversed: the hub dialled, but the
//! bridge opens the streams.
//!
//! Who a node is (`id`, `pin`, `io`, `tls::Identity`, the signed lists) is
//! `veydan-node`; what the registry takes and says (`wire`, `list`,
//! `revoke`) is `registry-proto`; both are given here under the names
//! this crate always had, so that the bridge, the hub and the Veydan app
//! read one crate. What is VLink's alone — the TLS of a bridge and a hub,
//! the targets of a stream — lives here.

pub mod list;
pub mod revoke;
pub mod sign;
pub mod target;
pub mod tls;
pub mod wire;

pub use veydan_node::{error, io, pin};

pub use error::Error;
pub use io::H2Stream;
pub use target::Target;

/// The id of a bridge and all that is needed to reach one
/// (`203.0.113.7:443#<id>`): a node's, as every node of the network has
/// them. Given by name, not as aliases, so that `BridgeId(bytes)` builds
/// one as it always did.
pub use veydan_node::{NodeId as BridgeId, NodeRef as BridgeRef};

/// Certificate and key types, so that the crates above need no rustls of their own.
pub use veydan_node::rustls_types;

/// Header a bridge adds to a stream it relays: the client's address as the
/// bridge saw it, `ip:port`.
pub const HEADER_PEER: &str = "vlink-peer";
