//! `vlink`: the bridge, and the tools to try one.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tokio::net::TcpListener;
use vlink::register::Registrar;
use vlink::{https, identity, Bridge, Config};
use vlink_client::{probe, socks, trust, Client};
use vlink_proto::list::SignedList;
use vlink_proto::wire::{Bridges, ProbeReport};
use vlink_proto::{tls, BridgeRef};

/// The certificate of the VLink root, as built into this binary: hubs are
/// known by it. The root's key, the registries and the seeds are built
/// into the client, and taken from there (`vlink_client::trust`).
const ROOT_PEM: &str = include_str!("../../../trust/root.crt");

/// What a probe moves through a bridge each way: past the size at which a
/// throttled path stalls.
const PROBE_BYTES: u64 = 512 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(40);

fn built_in_registries() -> Vec<String> {
    trust::REGISTRIES.iter().map(|r| r.to_string()).collect()
}

fn built_in_seeds() -> Vec<BridgeRef> {
    trust::SEEDS.iter().filter_map(|l| l.parse().ok()).collect()
}

#[derive(Parser)]
#[command(name = "vlink", about = "Veydan bridge", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    bridge: BridgeArgs,
}

#[derive(Args, Clone)]
struct BridgeArgs {
    /// Address to listen on.
    #[arg(long, env = "VLINK_LISTEN", default_value = "0.0.0.0:443")]
    listen: SocketAddr,
    /// Where the bridge keeps its keys and certificate.
    #[arg(long, env = "VLINK_DATA", default_value = "data")]
    data: PathBuf,
    /// Another root than the built-in one (PEM), for a network of one's own.
    #[arg(long, env = "VLINK_ROOT")]
    root: Option<PathBuf>,
    /// Connections held at once.
    #[arg(long, env = "VLINK_MAX_CONNECTIONS", default_value_t = 8192)]
    max_connections: usize,
    /// Registries to report to instead of the built-in ones; several are
    /// separated by commas.
    #[arg(long, env = "VLINK_REGISTRY", value_delimiter = ',')]
    registry: Vec<String>,
    /// Report to no registry: a bridge for those who are told its reference.
    #[arg(long, env = "VLINK_PRIVATE")]
    private: bool,
    /// The address the world reaches this machine at, when it is not the
    /// one its requests come from.
    #[arg(long, env = "VLINK_PUBLIC_IP")]
    public_ip: Option<IpAddr>,
    /// The port the world reaches the bridge at, when it is not the one it
    /// listens on (a container, a forwarded port).
    #[arg(long, env = "VLINK_PUBLIC_PORT")]
    public_port: Option<u16>,
}

#[derive(Args, Clone)]
struct BridgesArg {
    /// A bridge: `address:port#id`. May be given several times.
    #[arg(long = "bridge", required = true)]
    bridges: Vec<BridgeRef>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the bridge (what happens with no command at all).
    Bridge(BridgeArgs),
    /// Print the bridge's id; with --addr, the full reference a client takes.
    Id {
        #[arg(long, env = "VLINK_DATA", default_value = "data")]
        data: PathBuf,
        /// The public address of the bridge, `address:port`.
        #[arg(long)]
        addr: Option<SocketAddr>,
        /// Make a new TLS key and a new certificate over it, signed by
        /// the bridge's key, first. The id stays; a running bridge shows
        /// the new certificate after a restart.
        #[arg(long)]
        renew_cert: bool,
    },
    /// A local SOCKS5 door through a bridge:  curl --socks5-hostname ...
    Client {
        #[command(flatten)]
        bridges: BridgesArg,
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: SocketAddr,
    },
    /// Move bytes through a bridge both ways and time it.
    Probe {
        #[command(flatten)]
        bridges: BridgesArg,
        /// How much each way: 200k, 50m, 1g.
        #[arg(long, default_value = "200k")]
        bytes: String,
    },
    /// Probe every bridge the registry names and tell it what was found.
    /// Meant to run inside the country the bridges are for.
    Watch {
        /// The registry, `https://host/vlink`; the built-in one by default.
        #[arg(long, env = "VLINK_REGISTRY")]
        registry: Option<String>,
        /// A file with the probe token.
        #[arg(long, env = "VLINK_PROBE_TOKEN_FILE")]
        token_file: PathBuf,
        /// Seconds between rounds.
        #[arg(long, default_value_t = 300)]
        every: u64,
        /// One round, then stop.
        #[arg(long)]
        once: bool,
    },
    /// Print the link to this bridge that the app takes: veydan://vlink/...
    Link {
        #[arg(long, env = "VLINK_DATA", default_value = "data")]
        data: PathBuf,
        /// The public address of the bridge, `address:port`.
        #[arg(long)]
        addr: SocketAddr,
    },
    /// Ask the registry for bridges, as a client would, and check the signatures.
    List {
        #[arg(long, env = "VLINK_REGISTRY")]
        registry: Option<String>,
        /// Ask through this bridge instead of directly.
        #[arg(long)]
        via: Option<BridgeRef>,
    },
}

/// The bridge as a link of the app: `veydan://vlink/<id>?a=<address>`. The
/// address is percent-encoded as the app's links want it: everything but
/// letters, digits and `-_.~`.
fn bridge_link(bridge: &BridgeRef) -> String {
    let mut addr = String::new();
    for b in bridge.addr.to_string().bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            addr.push(b as char);
        } else {
            addr.push_str(&format!("%{b:02X}"));
        }
    }
    format!("veydan://vlink/{}?a={addr}", bridge.id)
}

fn parse_bytes(text: &str) -> anyhow::Result<u64> {
    let text = text.trim().to_ascii_lowercase();
    let (digits, scale) = match text.chars().last() {
        Some('k') => (&text[..text.len() - 1], 1024),
        Some('m') => (&text[..text.len() - 1], 1024 * 1024),
        Some('g') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text.as_str(), 1),
    };
    let n: u64 = digits.parse().with_context(|| format!("not a size: {text}"))?;
    Ok(n * scale)
}

fn rate(bytes: u64, time: Duration) -> String {
    let secs = time.as_secs_f64().max(0.001);
    format!("{:.2} s, {:.1} Mbit/s", secs, bytes as f64 * 8.0 / secs / 1e6)
}

fn registry_or_built_in(given: Option<String>) -> anyhow::Result<String> {
    given.or_else(|| built_in_registries().into_iter().next()).context("no registry is known: --registry")
}

async fn run_bridge(args: BridgeArgs) -> anyhow::Result<()> {
    let root_pem = match &args.root {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
        None => ROOT_PEM.to_string(),
    };
    let root = tls::cert_from_pem(&root_pem).context("the root certificate")?;
    let keys = identity::load_or_create(&args.data)?;
    let id = keys.id;
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    let bridge = Bridge::new(
        listener,
        Config {
            identity: keys.tls,
            root,
            max_connections: args.max_connections,
            link_test_bytes: vlink::LINK_TEST_BYTES,
        },
    )?;
    tracing::info!(listen = %args.listen, %id, "bridge is up");

    let registries = if args.registry.is_empty() { built_in_registries() } else { args.registry.clone() };
    if args.private || registries.is_empty() {
        tracing::info!("private bridge: no registry is told");
    } else {
        tokio::spawn(
            Registrar {
                registries,
                seeds: built_in_seeds(),
                id,
                signer: keys.signer,
                port: args.public_port.unwrap_or(args.listen.port()),
                public_ip: args.public_ip,
                handle: bridge.handle(),
            }
            .run(),
        );
    }

    let handle = bridge.handle();
    tokio::spawn(async move {
        // A line a minute: enough to see from the log that the bridge works.
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let s = handle.status();
            tracing::info!(
                hubs = s.hubs.len(),
                clients = s.clients,
                streams = s.streams,
                no_hub = s.refused_no_hub,
                hubs_refused = s.links_refused,
                up = s.bytes_up,
                down = s.bytes_down,
                "status"
            );
        }
    });

    tokio::select! {
        r = bridge.run() => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    Ok(())
}

/// One round: every bridge the registry names is tried and reported on.
async fn watch_round(registry: &str, token: &str) -> anyhow::Result<(usize, usize)> {
    let base = registry.trim_end_matches('/');
    let answer = https::call("GET", &format!("{base}/v1/probe/targets"), Some(token), None, None).await?;
    anyhow::ensure!(answer.status == 200, "targets: {} {}", answer.status, answer.text());
    let targets: Bridges = serde_json::from_slice(&answer.body)?;
    let mut good = 0;
    for bridge in &targets.bridges {
        // A client of its own for each: a probe must not fall back on
        // another bridge and call this one fine.
        let client = Client::new(vec![bridge.clone()]);
        let result = tokio::time::timeout(PROBE_TIMEOUT, probe::run(&client, PROBE_BYTES)).await;
        let ok = matches!(result, Ok(Ok(_)));
        match &result {
            Ok(Ok(r)) => tracing::info!(bridge = %bridge.addr, down = ?r.down, up = ?r.up, "bridge carries bytes"),
            Ok(Err(e)) => tracing::warn!(bridge = %bridge.addr, error = %e, "bridge failed"),
            Err(_) => tracing::warn!(bridge = %bridge.addr, "bridge stalled"),
        }
        good += usize::from(ok);
        let body = serde_json::to_vec(&ProbeReport { id: bridge.id, ok })?;
        let reported = https::call("POST", &format!("{base}/v1/probe/report"), Some(token), Some(&body), None).await;
        match reported {
            Ok(a) if a.status < 300 => {}
            Ok(a) => tracing::warn!(status = a.status, "report was not taken"),
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "report was not sent"),
        }
    }
    Ok((good, targets.bridges.len()))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        None => run_bridge(cli.bridge).await,
        Some(Command::Bridge(args)) => run_bridge(args).await,
        Some(Command::Id { data, addr, renew_cert }) => {
            let keys = if renew_cert { identity::renew(&data)? } else { identity::load_or_create(&data)? };
            let id = keys.id;
            match addr {
                Some(addr) => println!("{}", BridgeRef { addr, id, sni: None }),
                None => println!("{id}"),
            }
            Ok(())
        }
        Some(Command::Link { data, addr }) => {
            let id = identity::load_or_create(&data)?.id;
            println!("{}", bridge_link(&BridgeRef { addr, id, sni: None }));
            Ok(())
        }
        Some(Command::Client { bridges, socks: addr }) => {
            let listener = TcpListener::bind(addr).await.with_context(|| format!("cannot listen on {addr}"))?;
            tracing::info!(socks = %addr, bridges = bridges.bridges.len(), "client is up");
            let client = Client::new(bridges.bridges);
            tokio::select! {
                r = socks::serve(listener, std::sync::Arc::new(client), None) => r?,
                _ = tokio::signal::ctrl_c() => {}
            }
            Ok(())
        }
        Some(Command::Probe { bridges, bytes }) => {
            let bytes = parse_bytes(&bytes)?;
            anyhow::ensure!(bytes > 0 && bytes <= probe::MAX_BYTES, "between 1 byte and 1g");
            let client = Client::new(bridges.bridges);
            let report = probe::run(&client, bytes).await?;
            if let Some(bridge) = client.current().await {
                println!("bridge  {}", bridge.addr);
            }
            println!("bytes   {}", report.bytes);
            println!("down    {}", rate(report.bytes, report.down));
            println!("up      {}", rate(report.bytes, report.up));
            Ok(())
        }
        Some(Command::Watch { registry, token_file, every, once }) => {
            let registry = registry_or_built_in(registry)?;
            let token = std::fs::read_to_string(&token_file)
                .with_context(|| format!("cannot read {}", token_file.display()))?
                .trim()
                .to_string();
            loop {
                match watch_round(&registry, &token).await {
                    Ok((good, all)) => tracing::info!(good, all, "round done"),
                    Err(e) if once => return Err(e),
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "round failed"),
                }
                if once {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(every.max(10))).await;
            }
        }
        Some(Command::List { registry, via }) => {
            let registry = registry_or_built_in(registry)?;
            let url = format!("{}/v1/list", registry.trim_end_matches('/'));
            let through = via.map(|bridge| Client::new(vec![bridge]));
            let answer = https::call("GET", &url, None, None, through.as_ref()).await?;
            anyhow::ensure!(answer.status == 200, "{} {}", answer.status, answer.text());
            let signed: SignedList = serde_json::from_slice(&answer.body)?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let list = signed.verify(trust::ROOT_PUB, now).context("the list is not the registry's")?;
            for bridge in &list.bridges {
                println!("{bridge}");
            }
            eprintln!("{} bridge(s), signatures hold, good until unix {}", list.bridges.len(), list.expires_at);
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    // VLINK_LOG=debug shows every stream; the default says who came and went.
    let level = std::env::var("VLINK_LOG").ok().and_then(|l| l.parse().ok()).unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt().with_max_level(level).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vlink: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vlink: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "9c5f434def40ebc2879201642bab6c69063578c4a302aa92de5918b3663ffbfc";

    #[test]
    fn the_link_is_a_vlink_link_the_app_takes() {
        // The app reads these back (`messenger-links::bridge::tests`). The
        // word `bridge` is kept for bridges to other networks.
        let v4: BridgeRef = format!("45.93.201.244:443#{ID}").parse().unwrap();
        assert_eq!(bridge_link(&v4), format!("veydan://vlink/{ID}?a=45.93.201.244%3A443"));
        let v6: BridgeRef = format!("[2001:db8::1]:8443#{}", ID.to_uppercase()).parse().unwrap();
        assert_eq!(bridge_link(&v6), format!("veydan://vlink/{ID}?a=%5B2001%3Adb8%3A%3A1%5D%3A8443"));
    }
}
