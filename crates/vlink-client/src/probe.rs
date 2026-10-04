//! Does a bridge carry bytes? Asked of the hub's probe target, which gives
//! and takes as many bytes as it is told.
//!
//! The wire is two commands on one stream, each a line:
//!
//! ```text
//! GET <n>\n            → n bytes
//! PUT <n>\n n bytes    → OK <n>\n
//! ```

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vlink_proto::Target;

use crate::{Client, Error};

/// The largest transfer one command may ask for.
pub const MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub bytes: u64,
    pub down: Duration,
    pub up: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error(transparent)]
    Open(#[from] Error),
    #[error("stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("the hub answered {0:?}")]
    Answer(String),
}

/// Takes `bytes` from the hub and gives as many back, timing both.
pub async fn run(client: &Client, bytes: u64) -> Result<Report, ProbeError> {
    let mut stream = client.open(&Target::probe()).await?;
    exchange(&mut stream, bytes).await
}

/// The same on a stream that already leads to the probe target.
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, bytes: u64) -> Result<Report, ProbeError> {
    let mut buf = vec![0u8; 64 * 1024];

    let started = Instant::now();
    stream.write_all(format!("GET {bytes}\n").as_bytes()).await?;
    let mut left = bytes;
    while left > 0 {
        let want = (left as usize).min(buf.len());
        let n = stream.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(ProbeError::Answer(format!("closed with {left} bytes missing")));
        }
        left -= n as u64;
    }
    let down = started.elapsed();

    let started = Instant::now();
    stream.write_all(format!("PUT {bytes}\n").as_bytes()).await?;
    buf.fill(0x5a);
    let mut left = bytes;
    while left > 0 {
        let n = (left as usize).min(buf.len());
        stream.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    let mut answer = Vec::new();
    while !answer.ends_with(b"\n") && answer.len() < 64 {
        let n = stream.read(&mut buf[..1]).await?;
        if n == 0 {
            break;
        }
        answer.push(buf[0]);
    }
    let up = started.elapsed();
    let answer = String::from_utf8_lossy(&answer).trim().to_string();
    if answer != format!("OK {bytes}") {
        return Err(ProbeError::Answer(answer));
    }
    let _ = stream.shutdown().await;
    Ok(Report { bytes, down, up })
}
