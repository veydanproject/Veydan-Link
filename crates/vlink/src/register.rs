//! The bridge tells the registry that it exists, and keeps telling.
//!
//! The first report makes the bridge known; a hub then dials it and has it
//! prove its key. Later reports say it is still there and how many hubs
//! have links to it. A bridge that stops reporting is dropped from the lists.
//!
//! Every report is signed by the bridge's key, with the time it was made:
//! the registry takes an address for the bridge's id from nobody else, and
//! not from a report kept and sent again later.
//!
//! A report is a few hundred bytes. It goes straight to the registry, and
//! when that way is closed, through one of the bridges built into the binary.

use std::net::IpAddr;
use std::time::Duration;

use vlink_client::Client;
use vlink_proto::sign::Signer;
use vlink_proto::wire::{Registered, Registration, State};
use vlink_proto::{BridgeId, BridgeRef};

use crate::{https, Handle};

/// Between reports, once the registry knows the bridge.
const EVERY: Duration = Duration::from_secs(300);
/// Between attempts while it does not.
const RETRY: Duration = Duration::from_secs(30);

pub struct Registrar {
    /// Registries, `https://host/vlink`.
    pub registries: Vec<String>,
    /// Bridges to go through when a registry is not reached directly.
    pub seeds: Vec<BridgeRef>,
    pub id: BridgeId,
    /// The bridge's key, which signs every report.
    pub signer: Signer,
    pub port: u16,
    /// The bridge's public address, when the operator named it. Needed
    /// when reports go through another bridge: the registry then sees the
    /// address of a hub, not of this machine.
    pub public_ip: Option<IpAddr>,
    pub handle: Handle,
}

impl Registrar {
    /// Reports for as long as the bridge runs.
    pub async fn run(self) {
        // Our own reference is no way around: a bridge is not its own seed.
        let seeds: Vec<BridgeRef> = self.seeds.iter().filter(|s| s.id != self.id).cloned().collect();
        let through = (!seeds.is_empty()).then(|| Client::new(seeds));
        let mut known: Option<State> = None;
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            let mut heard = false;
            for registry in &self.registries {
                match self.report(registry, through.as_ref()).await {
                    Ok(reply) => {
                        heard = true;
                        if known != Some(reply.state) {
                            tracing::info!(%registry, state = ?reply.state, addr = %reply.addr, "registry knows this bridge");
                            known = Some(reply.state);
                        }
                    }
                    Err(e) => tracing::warn!(%registry, error = %format!("{e:#}"), "registry was not told"),
                }
            }
            // Until a hub has come, the bridge is of no use to anybody: ask
            // again soon. After that the reports are a heartbeat.
            let settled = heard && !matches!(known, None | Some(State::New));
            tokio::time::sleep(if settled { EVERY } else { RETRY }).await;
        }
    }

    async fn report(&self, registry: &str, through: Option<&Client>) -> anyhow::Result<Registered> {
        let mut request = Registration {
            id: self.id,
            port: self.port,
            ip: self.public_ip,
            hubs: self.handle.status().hubs.len() as u32,
            version: env!("CARGO_PKG_VERSION").to_string(),
            ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            key: String::new(),
            sig: String::new(),
        };
        self.signer.sign_registration(&mut request);
        let body = serde_json::to_vec(&request)?;
        let url = format!("{}/v1/register", registry.trim_end_matches('/'));
        let answer = match https::call("POST", &url, None, Some(&body), None).await {
            Ok(answer) => answer,
            Err(direct) => {
                // Through a bridge the registry cannot see where this
                // machine is: without a named address the report would
                // register the hub's.
                let client = through.filter(|_| self.public_ip.is_some()).ok_or(direct)?;
                https::call("POST", &url, None, Some(&body), Some(client)).await?
            }
        };
        anyhow::ensure!(answer.status == 200, "{} {}", answer.status, answer.text());
        Ok(serde_json::from_slice(&answer.body)?)
    }
}
