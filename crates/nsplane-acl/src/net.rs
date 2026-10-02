//! Network primitives used by ACL rules: transport protocols and IP networks.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Transport protocol of a flow.
///
/// Rules that apply to both protocols leave their protocol unset instead of
/// naming a third variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP (IP protocol number 6).
    Tcp,
    /// UDP (IP protocol number 17).
    Udp,
}

impl Protocol {
    /// Map an IP protocol number (IPv4 protocol / IPv6 next header) to a
    /// [`Protocol`]. Returns `None` for anything other than TCP and UDP.
    #[must_use]
    pub const fn from_ip_number(number: u8) -> Option<Self> {
        match number {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// An IPv4 or IPv6 network: an address plus a prefix length.
///
/// Parses from `a.b.c.d/n`, `v6addr/n`, or a bare address (a host network,
/// `/32` or `/128`). Host bits in the address are allowed and ignored for
/// matching; [`Display`](fmt::Display) prints the address as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Prefix length in bits.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The network address (the address with all host bits cleared).
    #[must_use]
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) & mask_v4(self.prefix_len)).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) & mask_v6(self.prefix_len)).into()),
        }
    }

    /// Whether `ip` lies inside this network. Addresses of the other family
    /// never match.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask_v4(self.prefix_len);
                u32::from(net) & mask == u32::from(*ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask_v6(self.prefix_len);
                u128::from(net) & mask == u128::from(*ip) & mask
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0)
}

fn mask_v6(prefix_len: u8) -> u128 {
    u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0)
}

/// Error returned when parsing an [`IpNet`] fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParseIpNetError {
    /// The address part is not a valid IPv4 or IPv6 address.
    #[error("invalid IP address")]
    Address,
    /// The prefix length is not a number or exceeds 32 (IPv4) / 128 (IPv6).
    #[error("invalid prefix length")]
    PrefixLength,
}

impl FromStr for IpNet {
    type Err = ParseIpNetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, len_part) = match s.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part.parse().map_err(|_| ParseIpNetError::Address)?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = match len_part {
            None => max,
            Some(len) => {
                if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseIpNetError::PrefixLength);
                }
                len.parse::<u8>()
                    .map_err(|_| ParseIpNetError::PrefixLength)?
            }
        };
        if prefix_len > max {
            return Err(ParseIpNetError::PrefixLength);
        }
        Ok(Self { addr, prefix_len })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn protocol_from_ip_number() {
        assert_eq!(Protocol::from_ip_number(6), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_ip_number(17), Some(Protocol::Udp));
        assert_eq!(Protocol::from_ip_number(1), None);
        assert_eq!(Protocol::from_ip_number(58), None);
    }

    #[test]
    fn protocol_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), r#""tcp""#);
        assert_eq!(
            serde_json::from_str::<Protocol>(r#""udp""#).unwrap(),
            Protocol::Udp
        );
        assert!(serde_json::from_str::<Protocol>(r#""both""#).is_err());
    }

    #[test]
    fn parse_v4_and_v6_with_prefix() {
        let v4: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(v4.prefix_len(), 24);
        assert_eq!(v4.network(), ip("10.0.0.0"));
        assert_eq!(v4.to_string(), "10.0.0.0/24");

        let v6: IpNet = "fd00::/8".parse().unwrap();
        assert_eq!(v6.prefix_len(), 8);
        assert_eq!(v6.network(), ip("fd00::"));
        assert_eq!(v6.to_string(), "fd00::/8");
    }

    #[test]
    fn parse_bare_address_is_host_network() {
        let v4: IpNet = "192.168.1.10".parse().unwrap();
        assert_eq!(v4.prefix_len(), 32);
        assert!(v4.contains(&ip("192.168.1.10")));
        assert!(!v4.contains(&ip("192.168.1.11")));

        let v6: IpNet = "fd00::1".parse().unwrap();
        assert_eq!(v6.prefix_len(), 128);
        assert!(v6.contains(&ip("fd00::1")));
        assert!(!v6.contains(&ip("fd00::2")));
    }

    #[test]
    fn host_bits_are_masked_for_matching() {
        let net: IpNet = "10.0.0.5/24".parse().unwrap();
        assert_eq!(net.network(), ip("10.0.0.0"));
        assert!(net.contains(&ip("10.0.0.200")));
        assert_eq!(net.to_string(), "10.0.0.5/24");
    }

    #[test]
    fn contains_v4() {
        let net: IpNet = "10.0.0.0/24".parse().unwrap();
        assert!(net.contains(&ip("10.0.0.0")));
        assert!(net.contains(&ip("10.0.0.255")));
        assert!(!net.contains(&ip("10.0.1.0")));
        assert!(!net.contains(&ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn contains_v6() {
        let net: IpNet = "fd00:1::/32".parse().unwrap();
        assert!(net.contains(&ip("fd00:1::1")));
        assert!(net.contains(&ip("fd00:1:ffff::1")));
        assert!(!net.contains(&ip("fd00:2::1")));
        assert!(!net.contains(&ip("10.0.0.1")));
    }

    #[test]
    fn zero_prefix_matches_whole_family() {
        let v4: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(v4.contains(&ip("1.2.3.4")));
        assert!(v4.contains(&ip("255.255.255.255")));
        assert!(!v4.contains(&ip("::1")));

        let v6: IpNet = "::/0".parse().unwrap();
        assert!(v6.contains(&ip("::1")));
        assert!(v6.contains(&ip("ffff::1")));
        assert!(!v6.contains(&ip("1.2.3.4")));
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        for bad in [
            "",
            "not-a-cidr",
            "10.0.0.0/",
            "10.0.0.0/33",
            "10.0.0.0/+8",
            "10.0.0.0/-1",
            "10.0.0.0/8/8",
            "10.0.0.0/abc",
            "10.0.0/8",
            "::/129",
            "::/999",
            "/24",
            " 10.0.0.0/8",
        ] {
            assert!(bad.parse::<IpNet>().is_err(), "{bad:?} must not parse");
        }
        assert_eq!(
            "10.0.0.0/33".parse::<IpNet>(),
            Err(ParseIpNetError::PrefixLength)
        );
        assert_eq!("x/8".parse::<IpNet>(), Err(ParseIpNetError::Address));
    }
}
