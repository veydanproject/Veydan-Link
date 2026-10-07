//! What bridges, probes and hubs say to the registry, as JSON.
//!
//! ```text
//! POST /vlink/v1/register        Registration → Registered     a bridge reports in
//! GET  /vlink/v1/list            → SignedList                  bridges for a client
//! GET  /vlink/v1/hub/bridges     → Bridges                     bridges to dial (hubs)
//! GET  /vlink/v1/probe/targets   → Bridges                     bridges to probe (probes)
//! POST /vlink/v1/probe/report    ProbeReport                   what a probe found
//! ```

use std::net::{IpAddr, SocketAddr};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::list::unhex;
use crate::{BridgeId, BridgeRef};

/// What is signed is prefixed with what it is, so that a signature made
/// for one thing is never one for another.
const REGISTRATION_CONTEXT: &str = "vlink-register/1\n";

/// How far a bridge has come in the registry's eyes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Reported in; no hub has seen it prove its key yet.
    New,
    /// A hub reached it; hubs hold links to it. Not given to clients yet.
    Verified,
    /// A probe inside the country moved bytes through it: given to clients.
    Active,
    /// A probe failed; kept out of the lists until one succeeds.
    Degraded,
    /// Probes kept failing, or the bridge went silent.
    Dead,
    /// The admin's word.
    Banned,
}

/// What a bridge sends when it reports in. Signed by the bridge's key,
/// the one its id is the hash of: the registry believes an address for an
/// id only from that key, so nobody else can report the bridge at an
/// address of their own and have it struck off as unreachable there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub id: BridgeId,
    pub port: u16,
    /// The bridge's public address, when it knows it; otherwise the one
    /// the request came from is taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// Hubs with a link to the bridge right now.
    #[serde(default)]
    pub hubs: u32,
    #[serde(default)]
    pub version: String,
    /// When the bridge made the report, unix seconds: one made long ago
    /// is not taken, so a report cannot be kept and sent again later.
    #[serde(default)]
    pub ts: u64,
    /// The bridge's key, 32 bytes as hex; `id` is its hash.
    #[serde(default)]
    pub key: String,
    /// The key's signature under [`Registration::message`], hex.
    #[serde(default)]
    pub sig: String,
}

/// Why a registration is not believed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Unsigned {
    #[error("the registration is not signed by the key of its id")]
    Key,
    #[error("the signature of the registration does not hold")]
    Signature,
    #[error("the registration's time is not now: check the clock of the bridge")]
    Clock,
}

impl Registration {
    /// The bytes the bridge's key signs: everything but the signature.
    pub fn message(&self) -> Vec<u8> {
        let ip = self.ip.map(|ip| ip.to_string()).unwrap_or_default();
        format!(
            "{REGISTRATION_CONTEXT}{}\n{ip}\n{}\n{}\n{}\n{}\n{}",
            self.id, self.port, self.hubs, self.version, self.ts, self.key
        )
        .into_bytes()
    }

    /// Is this the word of the bridge `id`, made within `skew` seconds of
    /// `now`? The key has to be the one the id is the hash of, and the
    /// signature its own over every field.
    pub fn verify(&self, now: u64, skew: u64) -> Result<(), Unsigned> {
        let key: [u8; 32] = unhex(&self.key).ok().and_then(|k| k.try_into().ok()).ok_or(Unsigned::Key)?;
        if BridgeId::of_ed25519(&key) != self.id {
            return Err(Unsigned::Key);
        }
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&self.message(), &unhex(&self.sig).map_err(|_| Unsigned::Signature)?)
            .map_err(|_| Unsigned::Signature)?;
        if self.ts.abs_diff(now) > skew {
            return Err(Unsigned::Clock);
        }
        Ok(())
    }
}

/// What it is told back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub state: State,
    /// The address the registry has for the bridge.
    pub addr: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bridges {
    pub bridges: Vec<BridgeRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReport {
    pub id: BridgeId,
    pub ok: bool,
}
