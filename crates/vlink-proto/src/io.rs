//! An h2 stream as a byte pipe, and the settings both ends of every h2
//! connection here use.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{Ping, PingPong, Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// h2 windows. Streams carry media, and the path is long: small windows
/// would cap the speed at window / round trip.
pub const STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub const CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// How many streams a connection may carry at once: a client to a bridge,
/// or a bridge to a hub. A cap so that one connection cannot open an
/// unbounded number of streams (and, on a hub, an unbounded number of
/// connections to the servers). Far above what one user needs.
pub const LINK_MAX_STREAMS: u32 = 1024;

/// How often an idle connection is asked whether it is alive, and how long
/// the answer may take. A connection across a throttled border may freeze
/// without closing: only a ping tells.
pub const PING_EVERY: Duration = Duration::from_secs(20);
pub const PING_WAIT: Duration = Duration::from_secs(15);

/// One write hands h2 at most this much, so that many streams share a
/// connection in turns.
const MAX_WRITE: usize = 64 * 1024;

pub fn client_builder() -> h2::client::Builder {
    let mut b = h2::client::Builder::new();
    b.initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .enable_push(false);
    b
}

pub fn server_builder() -> h2::server::Builder {
    let mut b = h2::server::Builder::new();
    b.initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(LINK_MAX_STREAMS);
    b
}

/// Returns when the other end stops answering pings.
pub async fn keepalive(mut ping_pong: PingPong) {
    loop {
        tokio::time::sleep(PING_EVERY).await;
        match tokio::time::timeout(PING_WAIT, ping_pong.ping(Ping::opaque())).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
    }
}

/// Both halves of an h2 stream as one `AsyncRead + AsyncWrite`.
///
/// Flow control reaches end to end: bytes are released to the sender only
/// as the reader takes them, and a write waits for the window.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    pending: Bytes,
    read_done: bool,
    write_done: bool,
}

impl H2Stream {
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self { send, recv, pending: Bytes::new(), read_done: false, write_done: false }
    }
}

fn to_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        return e.into_io().expect("is_io");
    }
    let kind = match e.reason() {
        Some(Reason::CANCEL) | Some(Reason::NO_ERROR) => io::ErrorKind::ConnectionAborted,
        Some(Reason::REFUSED_STREAM) => io::ErrorKind::ConnectionRefused,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e)
}

impl AsyncRead for H2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(dst.remaining());
                dst.put_slice(&self.pending[..n]);
                self.pending.advance(n);
                // The connection may be gone already; the next poll says so.
                let _ = self.recv.flow_control().release_capacity(n);
                return Poll::Ready(Ok(()));
            }
            if self.read_done {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(chunk)) => self.pending = chunk,
                Some(Err(e)) if e.reason() == Some(Reason::NO_ERROR) => self.read_done = true,
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => self.read_done = true,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, src: &[u8]) -> Poll<io::Result<usize>> {
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_done {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let want = src.len().min(MAX_WRITE);
        self.send.reserve_capacity(want);
        loop {
            // Capacity granted earlier is not announced again: look first.
            let granted = self.send.capacity();
            if granted > 0 {
                let n = granted.min(want);
                self.send.send_data(Bytes::copy_from_slice(&src[..n]), false).map_err(to_io)?;
                return Poll::Ready(Ok(n));
            }
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_done {
            self.write_done = true;
            self.send.reserve_capacity(0);
            // An end the other side already reset has nothing to close.
            let _ = self.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

/// Copies both ways until both directions are closed, with buffers large
/// enough not to be what limits the speed. Returns bytes (a→b, b→a).
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, MAX_WRITE, MAX_WRITE).await
}
