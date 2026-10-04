//! The bridge.
//!
//! One port, three kinds of callers, told apart after the TLS handshake:
//!
//! - a **hub** (ALPN `vlink-hub/1`, a certificate signed by the VLink root):
//!   its connection becomes a *link*. The bridge opens streams on it.
//! - a **client** (ALPN `h2`): every `CONNECT host:port` it sends is relayed
//!   into a link, byte for byte.
//! - **anybody else**: gets the page a bare web server would give.
//!
//! The bridge keeps nothing, reads nothing of what it carries, and knows no
//! address of a hub: hubs find it.

pub mod https;
pub mod identity;
pub mod register;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use vlink_proto::rustls_types::CertificateDer;
use vlink_proto::tls::{self, Identity};
use vlink_client::probe;
use vlink_proto::{io, H2Stream, Target, HEADER_PEER};

/// TLS and the first bytes after it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A hub answering whether it takes a stream: it has to reach the server.
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);
/// Streams one client may hold at once.
const CLIENT_MAX_STREAMS: u32 = 256;
/// A new link proving itself.
const LINK_TEST_TIMEOUT: Duration = Duration::from_secs(20);
/// What a new link has to move each way: well past the size at which a
/// throttled path stalls.
pub const LINK_TEST_BYTES: u64 = 512 * 1024;

pub struct Config {
    pub identity: Identity,
    /// The VLink root: hubs show certificates signed by it.
    pub root: CertificateDer<'static>,
    /// Connections held at once, of all kinds.
    pub max_connections: usize,
    /// What a new link has to move each way before clients are put on it;
    /// 0 takes every link on trust.
    pub link_test_bytes: u64,
}

struct Link {
    serial: u64,
    peer: SocketAddr,
    send: SendRequest<Bytes>,
    since: Instant,
}

#[derive(Default)]
struct Counters {
    clients: AtomicU64,
    streams: AtomicU64,
    refused_no_hub: AtomicU64,
    links_refused: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

struct State {
    links: Mutex<Vec<Link>>,
    next_link: AtomicUsize,
    link_serial: AtomicU64,
    link_test_bytes: u64,
    counters: Counters,
}

/// What the bridge is doing, for a status line.
#[derive(Debug, Clone)]
pub struct Status {
    /// Address of each hub with a link here, and how long it has been up.
    pub hubs: Vec<(SocketAddr, Duration)>,
    pub clients: u64,
    pub streams: u64,
    pub refused_no_hub: u64,
    /// Links that connected and did not carry bytes.
    pub links_refused: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

pub struct Bridge {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    slots: Arc<Semaphore>,
    state: Arc<State>,
}

/// A handle that outlives [`Bridge::run`].
#[derive(Clone)]
pub struct Handle {
    state: Arc<State>,
}

impl Handle {
    pub fn status(&self) -> Status {
        let links = self.state.links.lock().expect("links");
        let c = &self.state.counters;
        Status {
            hubs: links.iter().map(|l| (l.peer, l.since.elapsed())).collect(),
            clients: c.clients.load(Ordering::Relaxed),
            streams: c.streams.load(Ordering::Relaxed),
            refused_no_hub: c.refused_no_hub.load(Ordering::Relaxed),
            links_refused: c.links_refused.load(Ordering::Relaxed),
            bytes_up: c.bytes_up.load(Ordering::Relaxed),
            bytes_down: c.bytes_down.load(Ordering::Relaxed),
        }
    }
}

impl Bridge {
    pub fn new(listener: TcpListener, config: Config) -> anyhow::Result<Self> {
        let tls = tls::bridge_config(config.identity, config.root)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            slots: Arc::new(Semaphore::new(config.max_connections)),
            state: Arc::new(State {
                links: Mutex::new(Vec::new()),
                next_link: AtomicUsize::new(0),
                link_serial: AtomicU64::new(0),
                link_test_bytes: config.link_test_bytes,
                counters: Counters::default(),
            }),
        })
    }

    pub fn handle(&self) -> Handle {
        Handle { state: self.state.clone() }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves until the listener fails.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (tcp, peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                // Out of descriptors and the like: the next accept may work.
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(slot) = self.slots.clone().try_acquire_owned() else {
                continue; // full: the connection is dropped
            };
            let acceptor = self.acceptor.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let _ = tcp.set_nodelay(true);
                let Ok(Ok(stream)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await else {
                    return;
                };
                let (alpn, is_hub) = {
                    let conn = stream.get_ref().1;
                    (conn.alpn_protocol().map(<[u8]>::to_vec), conn.peer_certificates().is_some())
                };
                match alpn.as_deref() {
                    // rustls has checked the certificate against the root
                    // already; without one, the caller is no hub.
                    Some(tls::ALPN_HUB) if is_hub => link(stream, peer, state).await,
                    Some(tls::ALPN_HUB) => {}
                    Some(vlink_proto::pin::ALPN_H2) => client(stream, peer, state).await,
                    _ => decoy_http1(stream).await,
                }
            });
        }
    }
}

/// A hub called: its connection carries streams from now on, once it has
/// shown that it can.
async fn link(stream: TlsStream<TcpStream>, peer: SocketAddr, state: Arc<State>) {
    let Ok(Ok((send, mut connection))) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, io::client_builder().handshake::<_, Bytes>(stream)).await
    else {
        return;
    };
    let pings = connection.ping_pong().map(io::keepalive);
    let mut alive = Box::pin(async move {
        tokio::select! {
            r = &mut connection => r.err().map(|e| e.to_string()).unwrap_or_else(|| "closed".into()),
            _ = async { match pings { Some(p) => p.await, None => std::future::pending().await } } => "no answer to ping".into(),
        }
    });

    // A link may connect and still not carry bytes: on some paths whatever
    // leaves the country stalls after some tens of kilobytes. Clients are
    // put on a link only after it moved more than that, both ways.
    if state.link_test_bytes > 0 {
        let test = tokio::time::timeout(LINK_TEST_TIMEOUT, test_link(send.clone(), state.link_test_bytes));
        let failed = tokio::select! {
            // The registry's hub comes only to see the certificate, and goes.
            why = &mut alive => {
                tracing::debug!(hub = %peer, %why, "hub left before its link was tried");
                return;
            }
            r = test => match r {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e),
                Err(_) => Some("bytes stalled".to_string()),
            },
        };
        if let Some(why) = failed {
            tracing::warn!(hub = %peer, %why, "hub refused: its link does not carry bytes");
            state.counters.links_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    let serial = state.link_serial.fetch_add(1, Ordering::Relaxed);
    state.links.lock().expect("links").push(Link { serial, peer, send, since: Instant::now() });
    tracing::info!(hub = %peer, "hub connected");
    let why = alive.await;
    state.links.lock().expect("links").retain(|l| l.serial != serial);
    tracing::info!(hub = %peer, %why, "hub gone");
}

/// Moves `bytes` to the hub's probe target and back.
async fn test_link(send: SendRequest<Bytes>, bytes: u64) -> Result<(), String> {
    let (status, up_send, up_recv) =
        open_on_link(send, &Target::probe(), None).await.map_err(|e| e.to_string())?;
    if status != StatusCode::OK {
        return Err(format!("the hub answered {status} to the probe"));
    }
    let mut stream = H2Stream::new(up_send, up_recv);
    probe::exchange(&mut stream, bytes).await.map(|_| ()).map_err(|e| e.to_string())
}

/// A client called: each of its streams is relayed into a link.
async fn client(stream: TlsStream<TcpStream>, peer: SocketAddr, state: Arc<State>) {
    let mut builder = io::server_builder();
    builder.max_concurrent_streams(CLIENT_MAX_STREAMS);
    let Ok(Ok(mut connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, builder.handshake::<_, Bytes>(stream)).await
    else {
        return;
    };
    state.counters.clients.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(client = %peer, "client connected");
    while let Some(Ok((request, respond))) = connection.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = stream_of_client(request, respond, peer, &state).await {
                tracing::debug!(error = %e, "stream ended");
            }
        });
    }
}

fn refuse(respond: &mut SendResponse<Bytes>, status: StatusCode) {
    let response = Response::builder().status(status).body(()).expect("a status makes a response");
    let _ = respond.send_response(response, true);
}

async fn stream_of_client(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    state: &State,
) -> anyhow::Result<()> {
    if request.method() != Method::CONNECT {
        decoy_h2(&mut respond);
        return Ok(());
    }
    let Some(target) = request.uri().authority().and_then(|a| a.as_str().parse::<Target>().ok()) else {
        refuse(&mut respond, StatusCode::BAD_REQUEST);
        return Ok(());
    };

    // Each link gets one try: a link that just died must not cost the
    // client its stream while another is alive.
    let links: Vec<SendRequest<Bytes>> = {
        let links = state.links.lock().expect("links");
        let first = state.next_link.fetch_add(1, Ordering::Relaxed);
        (0..links.len()).map(|i| links[(first + i) % links.len()].send.clone()).collect()
    };
    let mut opened = None;
    for send in links {
        match tokio::time::timeout(OPEN_TIMEOUT, open_on_link(send, &target, Some(peer))).await {
            Ok(Ok(pair)) => {
                opened = Some(pair);
                break;
            }
            Ok(Err(e)) => tracing::debug!(error = %e, "link refused a stream"),
            Err(_) => tracing::debug!("link did not answer in time"),
        }
    }
    let Some((status, up_send, up_recv)) = opened else {
        state.counters.refused_no_hub.fetch_add(1, Ordering::Relaxed);
        refuse(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
        return Ok(());
    };
    if status != StatusCode::OK {
        // The hub's word about the target goes to the client as it is.
        refuse(&mut respond, status);
        return Ok(());
    }

    let response = Response::builder().status(StatusCode::OK).body(()).expect("response");
    let down_send = respond.send_response(response, false)?;
    state.counters.streams.fetch_add(1, Ordering::Relaxed);
    let mut down = H2Stream::new(down_send, request.into_body());
    let mut up = H2Stream::new(up_send, up_recv);
    let result = io::relay(&mut down, &mut up).await;
    if let Ok((sent, received)) = result {
        state.counters.bytes_up.fetch_add(sent, Ordering::Relaxed);
        state.counters.bytes_down.fetch_add(received, Ordering::Relaxed);
    }
    result?;
    Ok(())
}

async fn open_on_link(
    send: SendRequest<Bytes>,
    target: &Target,
    peer: Option<SocketAddr>,
) -> Result<(StatusCode, h2::SendStream<Bytes>, RecvStream), h2::Error> {
    let mut send = send.ready().await?;
    let mut request = Request::builder().method(Method::CONNECT).uri(target.to_string());
    if let Some(peer) = peer {
        request = request.header(HEADER_PEER, peer.to_string());
    }
    let request = request.body(()).expect("a valid target makes a valid request");
    let (response, body) = send.send_request(request, false)?;
    let response = response.await?;
    Ok((response.status(), body, response.into_body()))
}

// What a web server with nothing to show answers. The same words over h2
// and over HTTP/1.1, so that the bridge looks like one more idle server.
const DECOY_BODY: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

fn decoy_h2(respond: &mut SendResponse<Bytes>) {
    let response = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("server", "nginx")
        .header("content-type", "text/html")
        .header("content-length", DECOY_BODY.len())
        .body(())
        .expect("response");
    if let Ok(mut body) = respond.send_response(response, false) {
        let _ = body.send_data(Bytes::from_static(DECOY_BODY.as_bytes()), true);
    }
}

async fn decoy_http1(mut stream: TlsStream<TcpStream>) {
    // The request is read up to the end of its head, and not looked at.
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    let read = async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8 * 1024 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        true
    };
    if !matches!(tokio::time::timeout(HANDSHAKE_TIMEOUT, read).await, Ok(true)) {
        return;
    }
    let answer = format!(
        "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        DECOY_BODY.len(),
        DECOY_BODY
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}
