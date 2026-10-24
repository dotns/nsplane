//! MAC addresses and the IPv6 addresses derived from them.

use std::fmt;
use std::net::Ipv6Addr;

/// A 48-bit IEEE 802 MAC address, displayed as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Returns the six octets.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Whether this is the broadcast address.
    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Whether the individual/multicast bit is set (multicast, including broadcast).
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Whether the individual/multicast bit is clear.
    pub const fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    /// The ethernet multicast address of an IPv6 multicast address (RFC 2464 section 7):
    /// `33:33` followed by the low 32 bits of `addr`.
    pub const fn ipv6_multicast(addr: Ipv6Addr) -> Self {
        let [.., a, b, c, d] = addr.octets();
        Self([0x33, 0x33, a, b, c, d])
    }

    /// The `fe80::/64` link-local address whose interface identifier is derived from this MAC
    /// (RFC 4291 appendix A: `ff:fe` inserted in the middle, universal/local bit inverted).
    pub const fn link_local(self) -> Ipv6Addr {
        let mac = self.0;
        Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
            u16::from_be_bytes([mac[2], 0xff]),
            u16::from_be_bytes([0xfe, mac[3]]),
            u16::from_be_bytes([mac[4], mac[5]]),
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mac = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    #[test]
    fn display() {
        assert_eq!(GUEST.to_string(), "52:54:00:12:34:56");
        assert_eq!(MacAddr::BROADCAST.to_string(), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn classification() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::BROADCAST.is_unicast());
        assert!(GUEST.is_unicast());
        assert!(!GUEST.is_broadcast());
        assert!(MacAddr([0x33, 0x33, 0, 0, 0, 1]).is_multicast());
        assert!(MacAddr([0x01, 0x00, 0x5e, 0, 0, 1]).is_multicast());
    }

    #[test]
    fn link_local_known_vectors() {
        assert_eq!(
            GUEST.link_local(),
            "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
        );
        // RFC 4291 appendix A: the universal/local bit is inverted.
        assert_eq!(
            MacAddr([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]).link_local(),
            "fe80::21b:21ff:feaa:bbcc".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn ipv6_multicast_known_vectors() {
        let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
        assert_eq!(
            MacAddr::ipv6_multicast(all_nodes),
            MacAddr([0x33, 0x33, 0, 0, 0, 1])
        );
        let solicited: Ipv6Addr = "ff02::1:ff12:3456".parse().unwrap();
        assert_eq!(
            MacAddr::ipv6_multicast(solicited),
            MacAddr([0x33, 0x33, 0xff, 0x12, 0x34, 0x56])
        );
    }
}
