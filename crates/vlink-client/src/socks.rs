//! A local SOCKS5 door to the bridge.
//!
//! Programs that cannot be handed a stream (an HTTP library, curl) connect
//! here and name the host; the connection continues through the bridge.
//! Hosts are taken by name only (`socks5h`): the hub decides by name what
//! it carries, and an address says nothing about that.
//!
//! When a login is set, nothing else on the machine can use the door.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vlink_proto::{io::relay, H2Stream, Target};

use crate::{Client, Error};

/// Whatever gives streams to named hosts: a [`Client`], or something that
/// decides first whether the host is one to carry.
pub trait Opener: Send + Sync + 'static {
    fn open<'a>(&'a self, target: &'a Target) -> Pin<Box<dyn Future<Output = Result<H2Stream, Error>> + Send + 'a>>;
}

impl Opener for Client {
    fn open<'a>(&'a self, target: &'a Target) -> Pin<Box<dyn Future<Output = Result<H2Stream, Error>> + Send + 'a>> {
        Box::pin(Client::open(self, target))
    }
}

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0x00;
const PASSWORD: u8 = 0x02;
const NO_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const ATYP_NAME: u8 = 3;

// Replies of RFC 1928.
const OK: u8 = 0;
const FAILURE: u8 = 1;
const NOT_ALLOWED: u8 = 2;
const HOST_UNREACHABLE: u8 = 4;
const COMMAND_UNSUPPORTED: u8 = 7;
const ADDRESS_UNSUPPORTED: u8 = 8;

/// Login and password a caller must present.
#[derive(Clone)]
pub struct Login {
    pub user: String,
    pub password: String,
}

/// Serves until the listener fails.
pub async fn serve(listener: TcpListener, opener: Arc<dyn Opener>, login: Option<Login>) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let client = opener.clone();
        let login = login.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, client, login).await {
                tracing::debug!(error = %e, "socks connection ended");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, client: Arc<dyn Opener>, login: Option<Login>) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let bad = |what: &'static str| io::Error::new(io::ErrorKind::InvalidData, what);

    // Greeting: the methods the caller offers.
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(bad("not socks5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    let method = match &login {
        Some(_) if methods.contains(&PASSWORD) => PASSWORD,
        None if methods.contains(&NO_AUTH) => NO_AUTH,
        _ => NO_METHOD,
    };
    stream.write_all(&[VERSION, method]).await?;
    if method == NO_METHOD {
        return Err(bad("no acceptable method"));
    }

    if let Some(login) = &login {
        // RFC 1929.
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        let mut user = vec![0u8; head[1] as usize];
        stream.read_exact(&mut user).await?;
        let mut len = [0u8; 1];
        stream.read_exact(&mut len).await?;
        let mut password = vec![0u8; len[0] as usize];
        stream.read_exact(&mut password).await?;
        let ok = head[0] == 1 && user == login.user.as_bytes() && password == login.password.as_bytes();
        stream.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            return Err(bad("wrong login"));
        }
    }

    // Request.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(bad("not socks5"));
    }
    if head[1] != CMD_CONNECT {
        reply(&mut stream, COMMAND_UNSUPPORTED).await?;
        return Err(bad("only CONNECT is served"));
    }
    if head[3] != ATYP_NAME {
        reply(&mut stream, ADDRESS_UNSUPPORTED).await?;
        return Err(bad("hosts are taken by name only (socks5h)"));
    }
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await?;
    let mut host = vec![0u8; len[0] as usize];
    stream.read_exact(&mut host).await?;
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let target = std::str::from_utf8(&host)
        .ok()
        .and_then(|h| Target::new(h, u16::from_be_bytes(port)).ok());
    let Some(target) = target else {
        reply(&mut stream, ADDRESS_UNSUPPORTED).await?;
        return Err(bad("bad host"));
    };

    let mut remote = match client.open(&target).await {
        Ok(remote) => remote,
        Err(e) => {
            let code = match &e {
                Error::Refused(_) => NOT_ALLOWED,
                Error::Upstream(_) => HOST_UNREACHABLE,
                _ => FAILURE,
            };
            reply(&mut stream, code).await?;
            return Err(io::Error::other(e));
        }
    };
    reply(&mut stream, OK).await?;
    relay(&mut stream, &mut remote).await?;
    Ok(())
}

async fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    // The bound address is of no use to the caller: zeros.
    stream.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
