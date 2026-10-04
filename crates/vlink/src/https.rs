//! A small HTTPS client: one request, one answer, the connection closed.
//!
//! The bridge and the probe say a few short things to the registry. They
//! say them over a plain connection, or, when that way is closed, over a
//! stream through another bridge; this client takes either. Certificates
//! are checked against the bundled roots, so that nothing of the system is
//! needed.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use vlink_client::Client;
use vlink_proto::Target;

/// The registry answers in a few kilobytes; more is not an answer.
const MAX_ANSWER: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).trim().to_string()
    }
}

/// `https://host[:port]/path` taken apart.
struct Address {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> anyhow::Result<Address> {
    let rest = url.strip_prefix("https://").with_context(|| format!("not an https address: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().with_context(|| format!("bad port in {url}"))?),
        None => (authority, 443),
    };
    anyhow::ensure!(!host.is_empty(), "no host in {url}");
    Ok(Address { host: host.to_ascii_lowercase(), port, path: path.to_string() })
}

fn tls_config() -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// One request. `via` carries it through a bridge instead of directly.
pub async fn call(
    method: &str,
    url: &str,
    bearer: Option<&str>,
    body: Option<&[u8]>,
    via: Option<&Client>,
) -> anyhow::Result<Answer> {
    let address = parse(url)?;
    let work = async {
        match via {
            Some(client) => {
                let stream = client.open(&Target::new(&address.host, address.port)?).await?;
                exchange(stream, &address, method, bearer, body).await
            }
            None => {
                let stream = TcpStream::connect((address.host.as_str(), address.port)).await?;
                exchange(stream, &address, method, bearer, body).await
            }
        }
    };
    tokio::time::timeout(TIMEOUT, work).await.map_err(|_| anyhow::anyhow!("timed out"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    address: &Address,
    method: &str,
    bearer: Option<&str>,
    body: Option<&[u8]>,
) -> anyhow::Result<Answer> {
    let name = ServerName::try_from(address.host.clone())?;
    let mut tls = TlsConnector::from(Arc::new(tls_config()?)).connect(name, stream).await?;

    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: vlink\r\nAccept: application/json\r\nConnection: close\r\n",
        address.path, address.host
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes()).await?;
    if let Some(body) = body {
        tls.write_all(body).await?;
    }
    tls.flush().await?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // A server that closes without the TLS goodbye has still said
        // what it had to say.
        match tls.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
        anyhow::ensure!(raw.len() <= MAX_ANSWER, "the answer is too large");
    }
    read_answer(&raw)
}

fn read_answer(raw: &[u8]) -> anyhow::Result<Answer> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").context("no answer")?;
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut body = raw[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("not an HTTP answer")?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked {
        body = unchunk(&body).context("a broken chunked answer")?;
    }
    Ok(Answer { status, body })
}

fn unchunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&raw[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(raw.get(..size)?);
        raw = raw.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let a = parse("https://Example.org/vlink/v1/list").unwrap();
        assert_eq!((a.host.as_str(), a.port, a.path.as_str()), ("example.org", 443, "/vlink/v1/list"));
        let a = parse("https://example.org:8443").unwrap();
        assert_eq!((a.port, a.path.as_str()), (8443, "/"));
        assert!(parse("http://example.org/").is_err());
        assert!(parse("https://:443/").is_err());
    }

    #[test]
    fn answers() {
        let a = read_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((a.status, a.text().as_str()), (200, "{}"));
        let a = read_answer(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!((a.status, a.text().as_str()), (403, "abcde"));
        assert!(read_answer(b"garbage").is_err());
        assert!(read_answer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab").is_err());
    }
}
