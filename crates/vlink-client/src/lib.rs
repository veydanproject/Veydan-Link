//! The client side of VLink.
//!
//! [`Client::open`] gives a byte stream to a Veydan server, carried by a
//! bridge. What travels in the stream is the caller's own TLS to that
//! server: the bridge and the hub move bytes they cannot read.
//!
//! All streams share one connection to one bridge. When that bridge stops
//! answering, the next one of the list is taken.
//!
//! Nothing here touches the system: no resolver, no certificate store, no
//! files. It builds for Linux, Windows, macOS, Android and iOS alike.
//!
//! Whom a client trusts and where it starts is built in: see [`trust`].

pub mod probe;
pub mod socks;
pub mod trust;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, StatusCode};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use vlink_proto::{io, pin, BridgeRef, H2Stream, Target};

pub use vlink_proto as proto;

/// Reaching a bridge: TCP and TLS together. Short: whoever waits for the
/// stream has a deadline of its own, and another bridge is one step away.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// A stream being opened: the hub has to reach the server.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Bridges called at once when a connection is needed; the first to answer
/// is the one used.
const RACE: usize = 3;
/// How long a bridge that proved useless is called only after the others.
const BENCH: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no bridges are known")]
    NoBridges,
    #[error("no bridge answered: {0}")]
    Unreachable(String),
    /// The hub does not carry streams to this host.
    #[error("{0} is not a Veydan server")]
    Refused(Target),
    /// The hub could not reach the server.
    #[error("{0} did not answer the hub")]
    Upstream(Target),
    #[error("the bridge answered {0}")]
    Status(StatusCode),
}

struct Session {
    /// Which of `Inner::bridges` this is.
    index: usize,
    bridge: BridgeRef,
    send: SendRequest<Bytes>,
    alive: Arc<AtomicBool>,
}

struct Inner {
    bridges: Vec<BridgeRef>,
    /// Where the next search for a bridge starts: at the one that worked last.
    start: AtomicUsize,
    /// When each bridge last proved useless: it did not answer, or answered
    /// that it has no hub. Such a bridge is called only after the others.
    benched: std::sync::Mutex<Vec<Option<Instant>>>,
    session: Mutex<Option<Session>>,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

/// Why one attempt on one bridge did not give a stream.
enum Attempt {
    /// The bridge is of no use now: take another.
    Bridge(String),
    /// The answer is about the target; another bridge would say the same.
    Final(Error),
}

impl Client {
    pub fn new(bridges: Vec<BridgeRef>) -> Self {
        let benched = std::sync::Mutex::new(vec![None; bridges.len()]);
        Self {
            inner: Arc::new(Inner { bridges, start: AtomicUsize::new(0), benched, session: Mutex::new(None) }),
        }
    }

    /// The bridge in use, when there is a live connection to one.
    pub async fn current(&self) -> Option<BridgeRef> {
        let session = self.inner.session.lock().await;
        session.as_ref().filter(|s| s.alive.load(Ordering::Relaxed)).map(|s| s.bridge.clone())
    }

    /// A stream to `target`. Every bridge is tried once before giving up.
    pub async fn open(&self, target: &Target) -> Result<H2Stream, Error> {
        if self.inner.bridges.is_empty() {
            return Err(Error::NoBridges);
        }
        let mut last = String::new();
        // One more round than there are bridges: the first may be spent on
        // a connection that died since it was last used.
        for _ in 0..=self.inner.bridges.len() {
            let (index, send, alive) = match self.session().await {
                Ok(s) => s,
                Err(why) => {
                    last = why;
                    continue;
                }
            };
            match tokio::time::timeout(OPEN_TIMEOUT, open_on(send, target)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(Attempt::Final(e))) => return Err(e),
                Ok(Err(Attempt::Bridge(why))) => last = why,
                Err(_) => last = "timed out".into(),
            }
            alive.store(false, Ordering::Relaxed);
            self.bench(index);
        }
        Err(Error::Unreachable(last))
    }

    fn bench(&self, index: usize) {
        self.inner.benched.lock().expect("benched")[index] = Some(Instant::now());
    }

    /// The bridges in the order to call them, in groups called at once:
    /// first those with nothing against them, from the one that worked
    /// last; then those that proved useless a moment ago, the longest ago
    /// first. The two kinds never share a group: a bridge that is quick
    /// to answer that it cannot help would win every race.
    fn order(&self) -> Vec<Vec<usize>> {
        let count = self.inner.bridges.len();
        let start = self.inner.start.load(Ordering::Relaxed);
        let benched = self.inner.benched.lock().expect("benched");
        let fresh = |i: &usize| benched[*i].is_none_or(|at| at.elapsed() >= BENCH);
        let rotated: Vec<usize> = (0..count).map(|i| (start + i) % count).collect();
        let good: Vec<usize> = rotated.iter().copied().filter(fresh).collect();
        let mut bad: Vec<usize> = rotated.iter().copied().filter(|i| !fresh(i)).collect();
        bad.sort_by_key(|i| benched[*i]);
        good.chunks(RACE).chain(bad.chunks(RACE)).map(<[usize]>::to_vec).collect()
    }

    /// The live connection, or a new one to the first bridge that answers.
    async fn session(&self) -> Result<(usize, SendRequest<Bytes>, Arc<AtomicBool>), String> {
        let mut session = self.inner.session.lock().await;
        if let Some(s) = session.as_ref().filter(|s| s.alive.load(Ordering::Relaxed)) {
            return Ok((s.index, s.send.clone(), s.alive.clone()));
        }
        *session = None;
        let mut last = String::new();
        // A few at a time: a dead bridge then costs no waiting as long as
        // one next to it answers.
        for batch in self.order() {
            let mut calls = JoinSet::new();
            for i in batch {
                let bridge = self.inner.bridges[i].clone();
                calls.spawn(async move { (i, tokio::time::timeout(CONNECT_TIMEOUT, connect(&bridge)).await) });
            }
            while let Some(done) = calls.join_next().await {
                let Ok((i, result)) = done else { continue };
                let bridge = &self.inner.bridges[i];
                match result {
                    Ok(Ok((send, alive))) => {
                        tracing::info!(bridge = %bridge.addr, id = %bridge.id.short(), "connected to bridge");
                        self.inner.start.store(i, Ordering::Relaxed);
                        *session = Some(Session { index: i, bridge: bridge.clone(), send: send.clone(), alive: alive.clone() });
                        return Ok((i, send, alive));
                    }
                    Ok(Err(why)) => last = format!("{}: {why}", bridge.addr),
                    Err(_) => last = format!("{}: timed out", bridge.addr),
                }
                self.bench(i);
                tracing::debug!(%last, "bridge did not answer");
            }
        }
        Err(last)
    }
}

async fn connect(bridge: &BridgeRef) -> Result<(SendRequest<Bytes>, Arc<AtomicBool>), String> {
    let text = |e: &dyn std::fmt::Display| e.to_string();
    let config = pin::client_config(bridge.id).map_err(|e| text(&e))?;
    let name = pin::server_name(bridge).map_err(|e| text(&e))?;
    let tcp = TcpStream::connect(bridge.addr).await.map_err(|e| text(&e))?;
    let _ = tcp.set_nodelay(true);
    let stream = TlsConnector::from(Arc::new(config)).connect(name, tcp).await.map_err(|e| text(&e))?;
    if stream.get_ref().1.alpn_protocol() != Some(pin::ALPN_H2) {
        return Err("the bridge does not speak h2".into());
    }
    let (send, connection) = io::client_builder().handshake(stream).await.map_err(|e| text(&e))?;
    let alive = Arc::new(AtomicBool::new(true));
    let flag = alive.clone();
    tokio::spawn(async move {
        let mut connection = connection;
        let pings = connection.ping_pong().map(io::keepalive);
        tokio::select! {
            _ = &mut connection => {}
            _ = async { match pings { Some(p) => p.await, None => std::future::pending().await } } => {}
        }
        flag.store(false, Ordering::Relaxed);
    });
    Ok((send, alive))
}

async fn open_on(send: SendRequest<Bytes>, target: &Target) -> Result<H2Stream, Attempt> {
    let bridge = |e: h2::Error| Attempt::Bridge(e.to_string());
    let mut send = send.ready().await.map_err(bridge)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .body(())
        .expect("a valid target makes a valid request");
    let (response, body) = send.send_request(request, false).map_err(bridge)?;
    let response = response.await.map_err(bridge)?;
    match response.status() {
        StatusCode::OK => Ok(H2Stream::new(body, response.into_body())),
        StatusCode::FORBIDDEN => Err(Attempt::Final(Error::Refused(target.clone()))),
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => Err(Attempt::Final(Error::Upstream(target.clone()))),
        // The bridge has no hub: it is alive and useless.
        StatusCode::SERVICE_UNAVAILABLE => Err(Attempt::Bridge("the bridge has no hub".into())),
        other => Err(Attempt::Final(Error::Status(other))),
    }
}
