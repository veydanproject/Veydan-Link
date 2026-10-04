//! Who a bridge is, and where.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::error::Error;

/// SHA-256 of the bridge's certificate. The bridge makes the certificate on
/// its first start and keeps it, so the id is the bridge's identity: whoever
/// answers at the address must show the certificate with this hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BridgeId(pub [u8; 32]);

impl BridgeId {
    pub fn of_cert(der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, der);
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        Self(id)
    }

    /// The first 8 hex characters: enough to tell bridges apart in a log.
    pub fn short(&self) -> String {
        self.to_string()[..8].to_string()
    }
}

impl fmt::Display for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BridgeId({})", self.short())
    }
}

impl FromStr for BridgeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadId(s.to_string()));
        }
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error::BadId(s.to_string()))?;
        }
        Ok(Self(id))
    }
}

impl serde::Serialize for BridgeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for BridgeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// All that is needed to reach a bridge: `203.0.113.7:443#<id>`, with
/// `?sni=name` when the TLS hello should carry a name.
///
/// A bare address has no name to show, so by default none is sent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BridgeRef {
    pub addr: SocketAddr,
    pub id: BridgeId,
    pub sni: Option<String>,
}

impl fmt::Display for BridgeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.addr, self.id)?;
        if let Some(sni) = &self.sni {
            write!(f, "?sni={sni}")?;
        }
        Ok(())
    }
}

impl FromStr for BridgeRef {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::BadRef(s.to_string());
        let s = s.trim();
        let (addr, rest) = s.split_once('#').ok_or_else(bad)?;
        let (id, sni) = match rest.split_once("?sni=") {
            Some((id, sni)) if !sni.is_empty() => (id, Some(sni.to_ascii_lowercase())),
            Some(_) => return Err(bad()),
            None => (rest, None),
        };
        Ok(Self {
            addr: addr.parse().map_err(|_| bad())?,
            id: id.parse()?,
            sni,
        })
    }
}

impl serde::Serialize for BridgeRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for BridgeRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trips_and_rejects_garbage() {
        let id = BridgeId::of_cert(b"certificate");
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<BridgeId>().unwrap(), id);
        assert!("abc".parse::<BridgeId>().is_err());
        assert!("z".repeat(64).parse::<BridgeId>().is_err());
    }

    #[test]
    fn bridge_ref_round_trips() {
        let id = BridgeId::of_cert(b"x");
        let plain: BridgeRef = format!("203.0.113.7:443#{id}").parse().unwrap();
        assert_eq!(plain.addr.port(), 443);
        assert_eq!(plain.sni, None);
        assert_eq!(plain.to_string().parse::<BridgeRef>().unwrap(), plain);

        let named: BridgeRef = format!("[2001:db8::1]:8443#{id}?sni=Example.org").parse().unwrap();
        assert_eq!(named.sni.as_deref(), Some("example.org"));
        assert_eq!(named.to_string().parse::<BridgeRef>().unwrap(), named);

        assert!("203.0.113.7:443".parse::<BridgeRef>().is_err());
        assert!(format!("host:443#{id}").parse::<BridgeRef>().is_err());
        assert!(format!("203.0.113.7:443#{id}?sni=").parse::<BridgeRef>().is_err());
    }
}
