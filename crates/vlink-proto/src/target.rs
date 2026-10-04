//! Where a stream wants to go.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// Hosts under this name never leave the hub: it answers them itself.
pub const INTERNAL_SUFFIX: &str = ".vlink";
/// Gives and takes bytes, to see that a bridge carries them.
pub const PROBE_HOST: &str = "probe.vlink";
/// The registry of bridges.
pub const REGISTRY_HOST: &str = "registry.vlink";
/// Internal hosts have no ports of their own; h2 wants one in the address.
pub const INTERNAL_PORT: u16 = 1;

/// `host:port` of a CONNECT. The host is a DNS name in lower case: a
/// client never names an address, so a hub cannot be pointed at one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Result<Self, Error> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !is_dns_name(&host) || port == 0 {
            return Err(Error::BadTarget(format!("{host}:{port}")));
        }
        Ok(Self { host, port })
    }

    pub fn probe() -> Self {
        Self { host: PROBE_HOST.to_string(), port: INTERNAL_PORT }
    }

    pub fn registry() -> Self {
        Self { host: REGISTRY_HOST.to_string(), port: INTERNAL_PORT }
    }

    /// Answered by the hub itself.
    pub fn is_internal(&self) -> bool {
        self.host.ends_with(INTERNAL_SUFFIX)
    }
}

/// Letters, digits and hyphens in dot-separated labels, with at least one
/// label that is not a number: `10.0.0.1` is an address, not a name.
fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let mut named = false;
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return false;
        }
        named |= !label.bytes().all(|b| b.is_ascii_digit());
    }
    named
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (host, port) = s.rsplit_once(':').ok_or_else(|| Error::BadTarget(s.to_string()))?;
        let port: u16 = port.parse().map_err(|_| Error::BadTarget(s.to_string()))?;
        Self::new(host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowered_and_addresses_refused() {
        let t: Target = "Media.Example.net:443".parse().unwrap();
        assert_eq!(t.host, "media.example.net");
        assert_eq!(t.to_string(), "media.example.net:443");
        assert!(!t.is_internal());

        for bad in ["10.0.0.1:443", "[::1]:443", "host", "host:0", "ho st:443", "-a.b:443", "a..b:443", ":443"] {
            assert!(bad.parse::<Target>().is_err(), "{bad}");
        }
    }

    #[test]
    fn internal_targets() {
        assert!(Target::probe().is_internal());
        assert!(Target::registry().is_internal());
        assert_eq!(Target::probe().to_string().parse::<Target>().unwrap(), Target::probe());
    }
}
