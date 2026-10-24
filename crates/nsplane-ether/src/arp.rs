//! ARP for IPv4 over ethernet (RFC 826).
//!
//! Only the ethernet / IPv4 form is accepted: hardware type 1, protocol type `0x0800`,
//! address lengths 6 and 4. [`reply`] answers a request for an address the adapter owns,
//! and [`ArpPacket::is_gratuitous`] spots the announcements a guest sends for its own
//! address (RFC 5227), from which the caller learns the guest MAC.

use std::fmt;
use std::net::Ipv4Addr;

use crate::MacAddr;
use crate::frame::{self, EtherType};
use crate::read::Reader;

/// Length of an ethernet / IPv4 ARP packet.
pub const PACKET_LEN: usize = 28;

/// Fixed header of an ethernet / IPv4 ARP packet: hardware type, protocol type, lengths.
const PREFIX: [u8; 6] = [0x00, 0x01, 0x08, 0x00, 6, 4];

/// ARP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArpOp {
    /// Who has the target IP (operation 1).
    Request,
    /// The sender has the sender IP (operation 2).
    Reply,
}

/// Why an ARP packet was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArpError {
    /// The buffer is shorter than an ethernet / IPv4 ARP packet.
    Truncated,
    /// The hardware or protocol type or an address length is not ethernet / IPv4.
    Unsupported,
    /// The operation is neither request nor reply.
    UnknownOperation,
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "ARP packet truncated",
            Self::Unsupported => "ARP packet not ethernet / IPv4",
            Self::UnknownOperation => "unknown ARP operation",
        })
    }
}

impl std::error::Error for ArpError {}

/// An ethernet / IPv4 ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArpPacket {
    /// Operation.
    pub op: ArpOp,
    /// Sender hardware address.
    pub sender_mac: MacAddr,
    /// Sender protocol address.
    pub sender_ip: Ipv4Addr,
    /// Target hardware address (ignored in a request).
    pub target_mac: MacAddr,
    /// Target protocol address.
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parses the ARP packet at the start of `bytes` (an ethernet payload); trailing bytes
    /// (frame padding) are ignored.
    pub fn parse(bytes: &[u8]) -> Result<Self, ArpError> {
        let mut r = Reader::new(bytes);
        let prefix = r.array::<6>().ok_or(ArpError::Truncated)?;
        let op = r.u16().ok_or(ArpError::Truncated)?;
        let (Some(sender_mac), Some(sender_ip), Some(target_mac), Some(target_ip)) =
            (r.mac(), r.ipv4(), r.mac(), r.ipv4())
        else {
            return Err(ArpError::Truncated);
        };
        if prefix != PREFIX {
            return Err(ArpError::Unsupported);
        }
        let op = match op {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            _ => return Err(ArpError::UnknownOperation),
        };
        Ok(Self {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Whether the sender announces its own address: sender IP equals target IP
    /// (gratuitous ARP request or reply).
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }

    /// Appends the [`PACKET_LEN`] bytes of this packet to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        let op: u16 = match self.op {
            ArpOp::Request => 1,
            ArpOp::Reply => 2,
        };
        out.extend_from_slice(&PREFIX);
        out.extend_from_slice(&op.to_be_bytes());
        out.extend_from_slice(&self.sender_mac.0);
        out.extend_from_slice(&self.sender_ip.octets());
        out.extend_from_slice(&self.target_mac.0);
        out.extend_from_slice(&self.target_ip.octets());
    }
}

/// The ethernet frame answering `request` if it asks for `our_ip`: an ARP reply from
/// `our_mac` / `our_ip`, unicast to the requester.
///
/// Returns `None` for replies, gratuitous announcements, requests for another address and
/// requests whose sender MAC is not unicast.
pub fn reply(request: &ArpPacket, our_mac: MacAddr, our_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if request.op != ArpOp::Request
        || request.target_ip != our_ip
        || request.is_gratuitous()
        || !request.sender_mac.is_unicast()
    {
        return None;
    }
    let answer = ArpPacket {
        op: ArpOp::Reply,
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: request.sender_mac,
        target_ip: request.sender_ip,
    };
    let mut out = frame::start(request.sender_mac, our_mac, EtherType::ARP, PACKET_LEN);
    answer.write(&mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;

    const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

    fn request(target_ip: Ipv4Addr) -> Vec<u8> {
        let mut out = Vec::new();
        ArpPacket {
            op: ArpOp::Request,
            sender_mac: GUEST_MAC,
            sender_ip: GUEST_IP,
            target_mac: MacAddr([0; 6]),
            target_ip,
        }
        .write(&mut out);
        out
    }

    #[test]
    fn request_to_reply_bytes() {
        let bytes = request(GW_IP);
        assert_eq!(bytes.len(), PACKET_LEN);
        let req = ArpPacket::parse(&bytes).unwrap();
        assert_eq!(req.op, ArpOp::Request);
        assert!(!req.is_gratuitous());

        let out = reply(&req, GW_MAC, GW_IP).unwrap();
        assert_eq!(out.len(), 42);
        // Ethernet: unicast to the requester, from us, ARP.
        assert_eq!(out[0..6], GUEST_MAC.0);
        assert_eq!(out[6..12], GW_MAC.0);
        assert_eq!(out[12..14], [0x08, 0x06]);
        // ARP: htype 1, ptype IPv4, hlen 6, plen 4, op reply.
        assert_eq!(out[14..16], [0x00, 0x01]);
        assert_eq!(out[16..18], [0x08, 0x00]);
        assert_eq!(out[18], 6);
        assert_eq!(out[19], 4);
        assert_eq!(out[20..22], [0x00, 0x02]);
        assert_eq!(out[22..28], GW_MAC.0);
        assert_eq!(out[28..32], GW_IP.octets());
        assert_eq!(out[32..38], GUEST_MAC.0);
        assert_eq!(out[38..42], GUEST_IP.octets());

        let frame = Frame::parse(&out).unwrap();
        let parsed = ArpPacket::parse(frame.payload).unwrap();
        assert_eq!(parsed.op, ArpOp::Reply);
        assert_eq!(parsed.target_ip, GUEST_IP);
    }

    #[test]
    fn padding_is_ignored() {
        let mut bytes = request(GW_IP);
        bytes.resize(46, 0);
        assert_eq!(ArpPacket::parse(&bytes).unwrap().target_ip, GW_IP);
    }

    #[test]
    fn non_matching_target_ignored() {
        let req = ArpPacket::parse(&request(Ipv4Addr::new(10, 0, 2, 3))).unwrap();
        assert_eq!(reply(&req, GW_MAC, GW_IP), None);
        let mut as_reply = ArpPacket::parse(&request(GW_IP)).unwrap();
        as_reply.op = ArpOp::Reply;
        assert_eq!(reply(&as_reply, GW_MAC, GW_IP), None);
    }

    #[test]
    fn gratuitous_detection() {
        let req = ArpPacket::parse(&request(GUEST_IP)).unwrap();
        assert!(req.is_gratuitous());
        assert_eq!(req.sender_mac, GUEST_MAC);
        assert_eq!(reply(&req, GW_MAC, GUEST_IP), None);
    }

    #[test]
    fn malformed_rejected() {
        let bytes = request(GW_IP);
        for len in 0..PACKET_LEN {
            assert_eq!(ArpPacket::parse(&bytes[..len]), Err(ArpError::Truncated));
        }
        for (index, value) in [(1, 6), (2, 0x86), (4, 8), (5, 16)] {
            let mut bad = bytes.clone();
            bad[index] = value;
            assert_eq!(ArpPacket::parse(&bad), Err(ArpError::Unsupported));
        }
        let mut bad = bytes;
        bad[7] = 3;
        assert_eq!(ArpPacket::parse(&bad), Err(ArpError::UnknownOperation));
    }
}
