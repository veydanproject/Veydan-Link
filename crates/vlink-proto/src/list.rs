//! The list of bridges a client is given, and the check of its signatures.
//!
//! The list travels through channels nobody trusts: a bridge, a push, a
//! plain URL. So it is signed, in two steps:
//!
//! - the **root** key, kept off every server, signs a *delegation*: "this
//!   key may sign lists until that day";
//! - the delegated **list key**, which lives on the registry, signs lists.
//!
//! A registry that was taken over can hand out wrong bridges until the
//! delegation runs out, and no longer. A wrong bridge cannot read what it
//! carries; it can only fail to carry it.
//!
//! This file checks; the signing is in `sign`, with the servers.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::id::BridgeRef;

pub const VERSION: u32 = 1;
/// What is signed is prefixed with what it is, so that a signature made
/// for one thing is never one for another.
const LIST_CONTEXT: &str = "vlink-list/1\n";
const DELEGATION_CONTEXT: &str = "vlink-list-key/1\n";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("the delegation is not signed by the root")]
    Delegation,
    #[error("the delegation ran out")]
    DelegationExpired,
    #[error("the list is not signed by the delegated key")]
    Signature,
    #[error("the list ran out")]
    Expired,
    #[error("list version {0} is not supported")]
    Version(u32),
}

/// The bridges, and until when the list may be used. Times are unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeList {
    pub v: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub bridges: Vec<BridgeRef>,
}

/// "The key `key` may sign lists until `expires_at`", signed by the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// The list key, 32 bytes as hex.
    pub key: String,
    pub expires_at: u64,
    /// The root's signature, hex.
    pub sig: String,
}

/// A list as it travels: the exact text that was signed, the signature,
/// and the delegation of the key that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedList {
    /// A [`BridgeList`] as JSON. Kept as text: what is verified is these
    /// very bytes, not a re-encoding of them.
    pub list: String,
    pub sig: String,
    pub delegation: Delegation,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    let bad = || Error::Malformed("not hex".into());
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(bad());
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| bad())).collect()
}

/// The bytes the root signs to delegate.
pub fn delegation_message(key_hex: &str, expires_at: u64) -> Vec<u8> {
    format!("{DELEGATION_CONTEXT}{key_hex}\n{expires_at}").into_bytes()
}

/// The bytes the list key signs.
pub fn list_message(list: &str) -> Vec<u8> {
    format!("{LIST_CONTEXT}{list}").into_bytes()
}

impl Delegation {
    /// Is this the root's word, and still in force at `now`?
    pub fn verify(&self, root_hex: &str, now: u64) -> Result<(), Error> {
        let root = unhex(root_hex)?;
        UnparsedPublicKey::new(&ED25519, &root)
            .verify(&delegation_message(&self.key, self.expires_at), &unhex(&self.sig)?)
            .map_err(|_| Error::Delegation)?;
        if now >= self.expires_at {
            return Err(Error::DelegationExpired);
        }
        Ok(())
    }
}

impl SignedList {
    /// The list, when every signature holds and nothing ran out at `now`.
    pub fn verify(&self, root_hex: &str, now: u64) -> Result<BridgeList, Error> {
        self.delegation.verify(root_hex, now)?;
        let key = unhex(&self.delegation.key)?;
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&list_message(&self.list), &unhex(&self.sig)?)
            .map_err(|_| Error::Signature)?;
        let list: BridgeList = serde_json::from_str(&self.list).map_err(|e| Error::Malformed(e.to_string()))?;
        if list.v != VERSION {
            return Err(Error::Version(list.v));
        }
        if now >= list.expires_at {
            return Err(Error::Expired);
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A list made once with keys that were thrown away, as it travels: the
    // contract with every client that was ever shipped. The signing side
    // has its own tests, in `sign`.
    const ROOT: &str = include_str!("../../../golden/list-root.pub");
    const SIGNED: &str = include_str!("../../../golden/list-signed.json");
    /// Between the list's issue and its expiry.
    const NOW: u64 = 1_800_000_000;

    fn signed() -> SignedList {
        serde_json::from_str(SIGNED).unwrap()
    }

    #[test]
    fn the_golden_list_is_accepted() {
        let list = signed().verify(ROOT.trim(), NOW).unwrap();
        assert_eq!(list.v, VERSION);
        assert_eq!(list.bridges.len(), 2);
        assert_eq!(list.bridges[0].addr.to_string(), "203.0.113.7:443");
    }

    #[test]
    fn what_ran_out_is_refused() {
        let list = signed().verify(ROOT.trim(), NOW).unwrap();
        assert_eq!(signed().verify(ROOT.trim(), list.expires_at), Err(Error::Expired));
        let delegation_end = signed().delegation.expires_at;
        assert!(delegation_end > list.expires_at, "the golden delegation outlives the list");
        assert_eq!(signed().verify(ROOT.trim(), delegation_end), Err(Error::DelegationExpired));
    }

    #[test]
    fn forgeries_are_refused() {
        // Another root.
        let other = "00".repeat(32);
        assert_eq!(signed().verify(&other, NOW), Err(Error::Delegation));
        // A changed list.
        let mut changed = signed();
        changed.list = changed.list.replace("203.0.113.7", "203.0.113.8");
        assert_eq!(changed.verify(ROOT.trim(), NOW), Err(Error::Signature));
        // A delegation stretched in time.
        let mut stretched = signed();
        stretched.delegation.expires_at += 1;
        assert_eq!(stretched.verify(ROOT.trim(), NOW), Err(Error::Delegation));
        // Garbage where a signature should be.
        let mut garbled = signed();
        garbled.sig = "zz".into();
        assert!(matches!(garbled.verify(ROOT.trim(), NOW), Err(Error::Malformed(_))));
    }
}
