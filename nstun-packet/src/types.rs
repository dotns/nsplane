//! Plain value types shared across the data plane.

use std::net::SocketAddr;

/// Opaque identifier of a peer, suitable as a map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(u32);

impl PeerId {
    /// Wraps a raw peer id.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw peer id.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Opaque identifier of a transport (a socket or relay a packet travels over).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportId(u16);

impl TransportId {
    /// Wraps a raw transport id.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw transport id.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// ECN codepoint (RFC 3168); the discriminant is the 2-bit IP header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Ecn {
    /// Not ECN-capable transport.
    #[default]
    NotEct = 0b00,
    /// ECN-capable transport, ECT(1).
    Ect1 = 0b01,
    /// ECN-capable transport, ECT(0).
    Ect0 = 0b10,
    /// Congestion experienced.
    Ce = 0b11,
}

impl Ecn {
    /// Decodes the low two bits of `bits`; higher bits are ignored.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::NotEct,
            0b01 => Self::Ect1,
            0b10 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// Returns the 2-bit field value.
    pub const fn to_bits(self) -> u8 {
        self as u8
    }
}

/// The network path of a datagram: which transport, which remote address, and its ECN mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Path {
    /// Transport the datagram was received on or is sent over.
    pub transport: TransportId,
    /// Remote socket address.
    pub addr: SocketAddr,
    /// ECN codepoint carried by the outer datagram.
    pub ecn: Ecn,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ecn_round_trip() {
        for ecn in [Ecn::NotEct, Ecn::Ect1, Ecn::Ect0, Ecn::Ce] {
            assert_eq!(Ecn::from_bits(ecn.to_bits()), ecn);
        }
        assert_eq!(Ecn::NotEct.to_bits(), 0b00);
        assert_eq!(Ecn::Ect1.to_bits(), 0b01);
        assert_eq!(Ecn::Ect0.to_bits(), 0b10);
        assert_eq!(Ecn::Ce.to_bits(), 0b11);
    }

    #[test]
    fn ecn_from_bits_masks_high_bits() {
        assert_eq!(Ecn::from_bits(0xFF), Ecn::Ce);
        assert_eq!(Ecn::from_bits(0xFC), Ecn::NotEct);
    }

    #[test]
    fn ecn_default_is_not_ect() {
        assert_eq!(Ecn::default(), Ecn::NotEct);
    }

    #[test]
    fn ids_new_get() {
        assert_eq!(PeerId::new(7).get(), 7);
        assert_eq!(PeerId::new(u32::MAX).get(), u32::MAX);
        assert_eq!(TransportId::new(3).get(), 3);
        assert_eq!(TransportId::new(u16::MAX).get(), u16::MAX);
    }

    #[test]
    fn path_is_copy_and_hash() {
        let path = Path {
            transport: TransportId::new(1),
            addr: "192.0.2.1:51820".parse().unwrap(),
            ecn: Ecn::Ect0,
        };
        let copy = path;
        let mut set = HashSet::new();
        assert!(set.insert(path));
        assert!(!set.insert(copy));
        assert!(set.insert(Path {
            ecn: Ecn::Ce,
            ..path
        }));
        assert_eq!(set.len(), 2);
    }
}
