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

use serde::{Deserialize, Serialize};

use crate::{BridgeId, BridgeRef};

/// How far a bridge has come in the registry's eyes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Reported in; no hub has seen its certificate yet.
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

/// What a bridge sends when it reports in.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
