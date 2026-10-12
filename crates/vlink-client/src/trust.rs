//! What is built into a client: whom it trusts.
//!
//! The root's key alone, read from the folder `trust/` when the crate is
//! compiled. Where to start (the registries of bridges, the first bridges)
//! is not built in: the app takes it from the signed manifest of its
//! network, the bridge from its settings (`vlink --registry`).

/// The VLink root's key, 32 bytes as hex. Lists of bridges are checked
/// against it.
pub const ROOT_PUB: &str = include_str!("../../../trust/root.pub").trim_ascii();

/// The registry of the Veydan network: where a bridge reports in when its
/// operator names no other (`vlink --registry`, `VLINK_REGISTRY`), and
/// where the tools ask by default. A network of one's own names its own.
/// The app never reads it: its registries are those of the manifest.
pub const DEFAULT_REGISTRY: &str = "https://hub.veydan.net/vlink";

// A build that trusts nobody would take no list at all.
const _: () = assert!(ROOT_PUB.len() == 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_built_in_is_well_formed() {
        assert_eq!(ROOT_PUB.len(), 64);
        assert!(ROOT_PUB.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(DEFAULT_REGISTRY.starts_with("https://") && !DEFAULT_REGISTRY.ends_with('/'));
    }
}
