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
//! The modules a client needs are whole files with nothing of the servers
//! in them (`error`, `id`, `io`, `list`, `pin`, `target`). What only the
//! bridge and the hub need is in `tls`, `sign` and `wire`. The Veydan app
//! depends on this crate as it is: there is no copy of it anywhere.

pub mod error;
pub mod id;
pub mod io;
pub mod list;
pub mod pin;
pub mod sign;
pub mod target;
pub mod tls;
pub mod wire;

pub use error::Error;
pub use id::{BridgeId, BridgeRef};
pub use io::H2Stream;
pub use target::Target;

/// Certificate and key types, so that the crates above need no rustls of their own.
pub use rustls::pki_types as rustls_types;

/// Header a bridge adds to a stream it relays: the client's address as the
/// bridge saw it, `ip:port`.
pub const HEADER_PEER: &str = "vlink-peer";
