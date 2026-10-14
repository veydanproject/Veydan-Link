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
//! The answer may carry the list of revoked hubs (`vlink_proto::revoke`):
//! the bridge keeps the newest the root stands behind (`revoked`) and
//! drops the links of the hubs on it. A bridge that tells no registry
//! (`--private`) learns of no revocation.
//!
//! A report is a few hundred bytes. It goes straight to the registry: a
//! request that small passes even a way throttled past a few kilobytes.
//! There is no way around through another bridge: no bridge is built into
//! the binary any more.

use std::net::IpAddr;
use std::time::Duration;

use vlink_proto::revoke::Revocations;
use vlink_proto::sign::Signer;
use vlink_proto::wire::{Registered, Registration, State};
use vlink_proto::BridgeId;

use crate::revoked::Store;
use crate::{https, Handle};

/// Between reports, once the registry knows the bridge.
const EVERY: Duration = Duration::from_secs(300);
/// Between attempts while it does not.
const RETRY: Duration = Duration::from_secs(30);

pub struct Registrar {
    /// Registries, `https://host/vlink`.
    pub registries: Vec<String>,
    pub id: BridgeId,
    /// The bridge's key, which signs every report.
    pub signer: Signer,
    pub port: u16,
    /// The bridge's public address, when the operator named it: the
    /// machine's requests may leave from another one than the world
    /// reaches it at.
    pub public_ip: Option<IpAddr>,
    pub handle: Handle,
    /// The hubs revoked: each answer may carry a newer list.
    pub revoked: Store,
}

impl Registrar {
    /// Reports for as long as the bridge runs.
    pub async fn run(mut self) {
        let mut known: Option<State> = None;
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            let mut heard = false;
            for registry in &self.registries {
                match self.report(registry).await {
                    Ok(reply) => {
                        heard = true;
                        if known != Some(reply.state) {
                            tracing::info!(%registry, state = ?reply.state, addr = %reply.addr, "registry knows this bridge");
                            known = Some(reply.state);
                        }
                        if let Some(list) = &reply.revoked {
                            take_revoked(&mut self.revoked, &self.handle, registry, list);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%registry, error = %format!("{e:#}"), "registry was not told")
                    }
                }
            }
            // Until a hub has come, the bridge is of no use to anybody: ask
            // again soon. After that the reports are a heartbeat.
            let settled = heard && !matches!(known, None | Some(State::New));
            tokio::time::sleep(if settled { EVERY } else { RETRY }).await;
        }
    }

    async fn report(&self, registry: &str) -> anyhow::Result<Registered> {
        let mut request = Registration {
            id: self.id,
            port: self.port,
            ip: self.public_ip,
            hubs: self.handle.status().hubs.len() as u32,
            version: env!("CARGO_PKG_VERSION").to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            key: String::new(),
            sig: String::new(),
        };
        self.signer.sign_registration(&mut request);
        let body = serde_json::to_vec(&request)?;
        let url = format!("{}/v1/register", registry.trim_end_matches('/'));
        let answer = https::call("POST", &url, None, Some(&body), None).await?;
        anyhow::ensure!(answer.status == 200, "{} {}", answer.status, answer.text());
        Ok(serde_json::from_slice(&answer.body)?)
    }
}

/// A list of revoked hubs a registry gave: kept when it is the root's word
/// and newer than the one kept, and put in force at once; the links of the
/// hubs on it are dropped. A list that does not hold changes nothing.
fn take_revoked(store: &mut Store, handle: &Handle, registry: &str, list: &Revocations) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    match store.take(list, now) {
        Ok(true) => {
            let keys = store.keys();
            tracing::info!(%registry, revoked = keys.len(), "the list of revoked hubs changed");
            handle.set_revoked(keys);
        }
        Ok(false) => {}
        Err(e) => tracing::warn!(%registry, error = %format!("{e:#}"), "the list of revoked hubs was not taken"),
    }
}
