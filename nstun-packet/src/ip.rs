//! Zero-copy IP and transport header views, packet parsing and flow keys.
//!
//! The header structs are `#[repr(C)]` views over packet bytes; `parse` borrows the
//! buffer and never copies or panics.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

use crate::Ecn;

/// IP protocol numbers (IPv4 protocol / IPv6 next header).
pub mod protocol {
    /// Internet Control Message Protocol (IPv4).
    pub const ICMP: u8 = 1;
    /// Transmission Control Protocol.
    pub const TCP: u8 = 6;
    /// User Datagram Protocol.
    pub const UDP: u8 = 17;
    /// Internet Control Message Protocol for IPv6.
    pub const ICMPV6: u8 = 58;
}

/// Why a header failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The buffer is shorter than the header or the length it declares.
    Truncated,
    /// The IP version nibble is not the expected one.
    BadVersion,
    /// A header length field is below its minimum.
    BadHeaderLength,
    /// The IPv4 total length is smaller than the header length.
    BadTotalLength,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "packet truncated",
            Self::BadVersion => "bad IP version",
            Self::BadHeaderLength => "bad header length",
            Self::BadTotalLength => "bad total length",
        })
    }
}

impl std::error::Error for Malformed {}

/// A header view and the bytes that follow it.
type Parsed<'a, T> = (Ref<&'a [u8], T>, &'a [u8]);

/// Splits the fixed-size header view `T` off the front of `bytes`.
fn split<T>(bytes: &[u8]) -> Result<Parsed<'_, T>, Malformed>
where
    T: FromBytes + KnownLayout + Immutable + Unaligned,
{
    Ref::from_prefix(bytes).map_err(|_| Malformed::Truncated)
}

/// Fixed 20-byte part of an IPv4 header (RFC 791).
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_len: U16,
    identification: U16,
    flags_fragment: U16,
    ttl: u8,
    protocol: u8,
    checksum: U16,
    src: [u8; 4],
    dst: [u8; 4],
}

impl Ipv4Header {
    const DF: u16 = 0x4000;
    const MF: u16 = 0x2000;
    const OFFSET_MASK: u16 = 0x1FFF;

    /// Parses an IPv4 packet, returning the header view and the transport payload
    /// (`bytes[header_len..total_len]`: options skipped, trailing padding excluded).
    pub fn parse(bytes: &[u8]) -> Result<Parsed<'_, Self>, Malformed> {
        let (header, _) = split::<Self>(bytes)?;
        if header.version() != 4 {
            return Err(Malformed::BadVersion);
        }
        if header.ihl() < 5 {
            return Err(Malformed::BadHeaderLength);
        }
        let header_len = header.header_len();
        let total_len = usize::from(header.total_len());
        if header_len > bytes.len() {
            return Err(Malformed::Truncated);
        }
        if total_len < header_len {
            return Err(Malformed::BadTotalLength);
        }
        let payload = bytes
            .get(header_len..total_len)
            .ok_or(Malformed::Truncated)?;
        Ok((header, payload))
    }

    /// IP version (4 for a valid header).
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Header length in 32-bit words.
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Header length in bytes, including options.
    pub fn header_len(&self) -> usize {
        usize::from(self.ihl()) * 4
    }

    /// Differentiated services codepoint.
    pub const fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }

    /// ECN codepoint.
    pub const fn ecn(&self) -> Ecn {
        Ecn::from_bits(self.dscp_ecn)
    }

    /// Total packet length in bytes.
    pub const fn total_len(&self) -> u16 {
        self.total_len.get()
    }

    /// Fragment identification.
    pub const fn identification(&self) -> u16 {
        self.identification.get()
    }

    /// Whether the don't-fragment flag is set.
    pub const fn dont_fragment(&self) -> bool {
        self.flags_fragment.get() & Self::DF != 0
    }

    /// Whether the more-fragments flag is set.
    pub const fn more_fragments(&self) -> bool {
        self.flags_fragment.get() & Self::MF != 0
    }

    /// Fragment offset in bytes.
    pub const fn fragment_offset(&self) -> u16 {
        (self.flags_fragment.get() & Self::OFFSET_MASK) * 8
    }

    /// Time to live.
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Transport protocol number.
    pub const fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Header checksum as carried in the packet.
    pub const fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Source address.
    pub const fn src(&self) -> Ipv4Addr {
        let [a, b, c, d] = self.src;
        Ipv4Addr::new(a, b, c, d)
    }

    /// Destination address.
    pub const fn dst(&self) -> Ipv4Addr {
        let [a, b, c, d] = self.dst;
        Ipv4Addr::new(a, b, c, d)
    }
}

/// 40-byte IPv6 fixed header (RFC 8200).
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct Ipv6Header {
    version_class_flow: U32,
    payload_len: U16,
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

impl Ipv6Header {
    const LEN: usize = 40;

    /// Parses an IPv6 packet, returning the header view and `bytes[40..40 + payload_len]`.
    /// Extension headers are not walked.
    pub fn parse(bytes: &[u8]) -> Result<Parsed<'_, Self>, Malformed> {
        let (header, _) = split::<Self>(bytes)?;
        if header.version() != 6 {
            return Err(Malformed::BadVersion);
        }
        let end = Self::LEN + usize::from(header.payload_len());
        let payload = bytes.get(Self::LEN..end).ok_or(Malformed::Truncated)?;
        Ok((header, payload))
    }

    /// IP version (6 for a valid header).
    pub const fn version(&self) -> u8 {
        self.version_class_flow.get().to_be_bytes()[0] >> 4
    }

    /// Traffic class (DSCP and ECN).
    pub const fn traffic_class(&self) -> u8 {
        let [b0, b1, ..] = self.version_class_flow.get().to_be_bytes();
        (b0 << 4) | (b1 >> 4)
    }

    /// ECN codepoint.
    pub const fn ecn(&self) -> Ecn {
        Ecn::from_bits(self.traffic_class())
    }

    /// 20-bit flow label.
    pub const fn flow_label(&self) -> u32 {
        self.version_class_flow.get() & 0x000F_FFFF
    }

    /// Payload length in bytes (everything after the fixed header).
    pub const fn payload_len(&self) -> u16 {
        self.payload_len.get()
    }

    /// Next header protocol number.
    pub const fn next_header(&self) -> u8 {
        self.next_header
    }

    /// Hop limit.
    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Source address.
    pub const fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.src)
    }

    /// Destination address.
    pub const fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.dst)
    }
}

/// 8-byte UDP header (RFC 768).
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct UdpHeader {
    src_port: U16,
    dst_port: U16,
    len: U16,
    checksum: U16,
}

impl UdpHeader {
    /// Parses a UDP header, returning the view and the bytes after it.
    pub fn parse(bytes: &[u8]) -> Result<Parsed<'_, Self>, Malformed> {
        split(bytes)
    }

    /// Source port.
    pub const fn src_port(&self) -> u16 {
        self.src_port.get()
    }

    /// Destination port.
    pub const fn dst_port(&self) -> u16 {
        self.dst_port.get()
    }

    /// Length of header and payload in bytes.
    pub const fn len(&self) -> u16 {
        self.len.get()
    }

    /// Whether the length field is zero (never valid; the minimum is 8).
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checksum as carried in the packet.
    pub const fn checksum(&self) -> u16 {
        self.checksum.get()
    }
}

/// Fixed 20-byte part of a TCP header (RFC 9293).
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct TcpHeader {
    src_port: U16,
    dst_port: U16,
    seq: U32,
    ack: U32,
    offset_reserved: u8,
    flags: u8,
    window: U16,
    checksum: U16,
    urgent_ptr: U16,
}

impl TcpHeader {
    /// Parses a TCP header, returning the view and the bytes after the options.
    pub fn parse(bytes: &[u8]) -> Result<Parsed<'_, Self>, Malformed> {
        let (header, _) = split::<Self>(bytes)?;
        if header.data_offset() < 5 {
            return Err(Malformed::BadHeaderLength);
        }
        let rest = bytes
            .get(header.header_len()..)
            .ok_or(Malformed::Truncated)?;
        Ok((header, rest))
    }

    /// Source port.
    pub const fn src_port(&self) -> u16 {
        self.src_port.get()
    }

    /// Destination port.
    pub const fn dst_port(&self) -> u16 {
        self.dst_port.get()
    }

    /// Sequence number.
    pub const fn seq(&self) -> u32 {
        self.seq.get()
    }

    /// Acknowledgment number.
    pub const fn ack(&self) -> u32 {
        self.ack.get()
    }

    /// Header length in 32-bit words.
    pub const fn data_offset(&self) -> u8 {
        self.offset_reserved >> 4
    }

    /// Header length in bytes, including options.
    pub fn header_len(&self) -> usize {
        usize::from(self.data_offset()) * 4
    }

    /// The eight flag bits, CWR (MSB) through FIN (LSB).
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Receive window.
    pub const fn window(&self) -> u16 {
        self.window.get()
    }

    /// Checksum as carried in the packet.
    pub const fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Urgent pointer.
    pub const fn urgent_ptr(&self) -> u16 {
        self.urgent_ptr.get()
    }
}

/// 8-byte ICMP header (shared by ICMP for IPv4 and IPv6): type, code, checksum and rest-of-header.
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct IcmpHeader {
    icmp_type: u8,
    code: u8,
    checksum: U16,
    identifier: U16,
    sequence: U16,
}

impl IcmpHeader {
    /// Parses an ICMP header, returning the view and the bytes after it.
    pub fn parse(bytes: &[u8]) -> Result<Parsed<'_, Self>, Malformed> {
        split(bytes)
    }

    /// Message type.
    pub const fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Message code.
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// Checksum as carried in the packet.
    pub const fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Upper half of rest-of-header (the echo identifier).
    pub const fn identifier(&self) -> u16 {
        self.identifier.get()
    }

    /// Lower half of rest-of-header (the echo sequence number).
    pub const fn sequence(&self) -> u16 {
        self.sequence.get()
    }
}

/// IPv4 fragment metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fragment {
    /// Fragment identification.
    pub id: u16,
    /// Offset of this fragment's payload in bytes.
    pub offset: u16,
    /// Whether more fragments follow.
    pub more: bool,
}

impl Fragment {
    /// Whether this is the first fragment (offset 0).
    pub const fn is_first(&self) -> bool {
        self.offset == 0
    }

    /// Whether this is the last fragment (more-fragments clear).
    pub const fn is_last(&self) -> bool {
        !self.more
    }
}

/// Flow key of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Transport protocol number.
    pub protocol: u8,
    /// Source port; the echo identifier for ICMP echo, otherwise 0 for portless protocols.
    pub src_port: u16,
    /// Destination port; the echo identifier for ICMP echo, otherwise 0 for portless protocols.
    pub dst_port: u16,
}

/// A parsed IP packet: header view plus transport payload.
#[derive(Debug)]
pub enum IpPacket<'a> {
    /// IPv4 packet.
    V4 {
        /// Header view.
        header: Ref<&'a [u8], Ipv4Header>,
        /// Transport payload.
        payload: &'a [u8],
    },
    /// IPv6 packet.
    V6 {
        /// Header view.
        header: Ref<&'a [u8], Ipv6Header>,
        /// Payload after the fixed header.
        payload: &'a [u8],
    },
}

impl<'a> IpPacket<'a> {
    /// Parses an IPv4 or IPv6 packet, dispatching on the version nibble.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Malformed> {
        match bytes.first().map(|b| b >> 4) {
            None => Err(Malformed::Truncated),
            Some(4) => {
                Ipv4Header::parse(bytes).map(|(header, payload)| Self::V4 { header, payload })
            }
            Some(6) => {
                Ipv6Header::parse(bytes).map(|(header, payload)| Self::V6 { header, payload })
            }
            Some(_) => Err(Malformed::BadVersion),
        }
    }

    /// Source address.
    pub fn src(&self) -> IpAddr {
        match self {
            Self::V4 { header, .. } => header.src().into(),
            Self::V6 { header, .. } => header.src().into(),
        }
    }

    /// Destination address.
    pub fn dst(&self) -> IpAddr {
        match self {
            Self::V4 { header, .. } => header.dst().into(),
            Self::V6 { header, .. } => header.dst().into(),
        }
    }

    /// Transport protocol (IPv4 protocol / IPv6 next header).
    pub fn protocol(&self) -> u8 {
        match self {
            Self::V4 { header, .. } => header.protocol(),
            Self::V6 { header, .. } => header.next_header(),
        }
    }

    /// Transport payload.
    pub const fn payload(&self) -> &'a [u8] {
        match self {
            Self::V4 { payload, .. } | Self::V6 { payload, .. } => payload,
        }
    }

    /// ECN codepoint.
    pub fn ecn(&self) -> Ecn {
        match self {
            Self::V4 { header, .. } => header.ecn(),
            Self::V6 { header, .. } => header.ecn(),
        }
    }

    /// IPv4 fragment metadata, or `None` for an unfragmented packet. Always `None` for IPv6.
    pub fn fragment(&self) -> Option<Fragment> {
        match self {
            Self::V4 { header, .. } if header.more_fragments() || header.fragment_offset() > 0 => {
                Some(Fragment {
                    id: header.identification(),
                    offset: header.fragment_offset(),
                    more: header.more_fragments(),
                })
            }
            _ => None,
        }
    }

    /// Flow key, or `None` for a non-first fragment or a truncated transport header.
    pub fn five_tuple(&self) -> Option<FiveTuple> {
        if self.fragment().is_some_and(|f| !f.is_first()) {
            return None;
        }
        let protocol = self.protocol();
        let payload = self.payload();
        let (src_port, dst_port) = match protocol {
            protocol::TCP => {
                let (tcp, _) = TcpHeader::parse(payload).ok()?;
                (tcp.src_port(), tcp.dst_port())
            }
            protocol::UDP => {
                let (udp, _) = UdpHeader::parse(payload).ok()?;
                (udp.src_port(), udp.dst_port())
            }
            protocol::ICMP | protocol::ICMPV6 => {
                let (icmp, _) = IcmpHeader::parse(payload).ok()?;
                let echo = match protocol {
                    protocol::ICMP => matches!(icmp.icmp_type(), 0 | 8),
                    _ => matches!(icmp.icmp_type(), 128 | 129),
                };
                let id = if echo { icmp.identifier() } else { 0 };
                (id, id)
            }
            _ => (0, 0),
        };
        Some(FiveTuple {
            src: self.src(),
            dst: self.dst(),
            protocol,
            src_port,
            dst_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    fn v6_src() -> Ipv6Addr {
        "2001:db8::1".parse().unwrap()
    }

    fn v6_dst() -> Ipv6Addr {
        "2001:db8::2".parse().unwrap()
    }

    /// Builds an IPv4 packet with `options` and `payload`; `flags_fragment` is the raw field.
    fn ipv4(protocol: u8, flags_fragment: u16, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let header_len = 20 + options.len();
        let total = u16::try_from(header_len + payload.len()).unwrap();
        let ihl = u8::try_from(header_len / 4).unwrap();
        let mut p = vec![0x40 | ihl, 0b1011_1010];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&flags_fragment.to_be_bytes());
        p.extend_from_slice(&[64, protocol, 0xab, 0xcd]);
        p.extend_from_slice(&V4_SRC.octets());
        p.extend_from_slice(&V4_DST.octets());
        p.extend_from_slice(options);
        p.extend_from_slice(payload);
        p
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        // Version 6, traffic class 0xb9 (ECN bits 01 = ECT(1)), flow label 0x12345.
        let mut p = vec![0x6b, 0x91, 0x23, 0x45];
        p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&[next_header, 33]);
        p.extend_from_slice(&v6_src().octets());
        p.extend_from_slice(&v6_dst().octets());
        p.extend_from_slice(payload);
        p
    }

    fn udp(src: u16, dst: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&src.to_be_bytes());
        p.extend_from_slice(&dst.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x0b, 0xbe, 0xef, b'a', b'b', b'c']);
        p
    }

    fn tcp(src: u16, dst: u16, options: &[u8]) -> Vec<u8> {
        let data_offset = u8::try_from((20 + options.len()) / 4).unwrap();
        let mut p = Vec::new();
        p.extend_from_slice(&src.to_be_bytes());
        p.extend_from_slice(&dst.to_be_bytes());
        p.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        p.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        p.extend_from_slice(&[data_offset << 4, 0x12]);
        p.extend_from_slice(&[0xff, 0xf0, 0x11, 0x22, 0x00, 0x07]);
        p.extend_from_slice(options);
        p.extend_from_slice(b"data");
        p
    }

    fn icmp(icmp_type: u8, id: u16) -> Vec<u8> {
        let mut p = vec![icmp_type, 0, 0x5a, 0xa5];
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x09, b'p', b'i', b'n', b'g']);
        p
    }

    #[test]
    fn ipv4_accessors() {
        let packet = ipv4(protocol::UDP, 0x4000, &[], &udp(1, 2));
        let (h, payload) = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(h.version(), 4);
        assert_eq!(h.ihl(), 5);
        assert_eq!(h.header_len(), 20);
        assert_eq!(h.dscp(), 0b10_1110);
        assert_eq!(h.ecn(), Ecn::Ect0);
        assert_eq!(usize::from(h.total_len()), packet.len());
        assert_eq!(h.identification(), 0x1234);
        assert!(h.dont_fragment());
        assert!(!h.more_fragments());
        assert_eq!(h.fragment_offset(), 0);
        assert_eq!(h.ttl(), 64);
        assert_eq!(h.protocol(), protocol::UDP);
        assert_eq!(h.checksum(), 0xabcd);
        assert_eq!(h.src(), V4_SRC);
        assert_eq!(h.dst(), V4_DST);
        assert_eq!(payload, &packet[20..]);
    }

    #[test]
    fn ipv4_options_and_padding_are_skipped() {
        let options = [0x01, 0x01, 0x01, 0x00, 0x94, 0x04, 0x00, 0x00];
        let mut packet = ipv4(protocol::UDP, 0, &options, &udp(1, 2));
        let total = packet.len();
        packet.extend_from_slice(&[0; 6]);
        let (h, payload) = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(h.ihl(), 7);
        assert_eq!(h.header_len(), 28);
        assert_eq!(payload, &packet[28..total]);
        assert_eq!(payload, udp(1, 2).as_slice());
    }

    #[test]
    fn ipv6_accessors() {
        let packet = ipv6(protocol::TCP, &tcp(1, 2, &[]));
        let (h, payload) = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(h.version(), 6);
        assert_eq!(h.traffic_class(), 0xb9);
        assert_eq!(h.ecn(), Ecn::Ect1);
        assert_eq!(h.flow_label(), 0x12345);
        assert_eq!(usize::from(h.payload_len()), packet.len() - 40);
        assert_eq!(h.next_header(), protocol::TCP);
        assert_eq!(h.hop_limit(), 33);
        assert_eq!(h.src(), v6_src());
        assert_eq!(h.dst(), v6_dst());
        assert_eq!(payload, &packet[40..]);

        let mut padded = packet.clone();
        padded.push(0);
        assert_eq!(Ipv6Header::parse(&padded).unwrap().1, &packet[40..]);
    }

    #[test]
    fn udp_accessors() {
        let segment = udp(51820, 53);
        let (h, rest) = UdpHeader::parse(&segment).unwrap();
        assert_eq!(h.src_port(), 51820);
        assert_eq!(h.dst_port(), 53);
        assert_eq!(h.len(), 11);
        assert!(!h.is_empty());
        assert_eq!(h.checksum(), 0xbeef);
        assert_eq!(rest, b"abc");
    }

    #[test]
    fn tcp_accessors_with_options() {
        let options = [0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02];
        let segment = tcp(443, 49152, &options);
        let (h, rest) = TcpHeader::parse(&segment).unwrap();
        assert_eq!(h.src_port(), 443);
        assert_eq!(h.dst_port(), 49152);
        assert_eq!(h.seq(), 0xdead_beef);
        assert_eq!(h.ack(), 0x0102_0304);
        assert_eq!(h.data_offset(), 7);
        assert_eq!(h.header_len(), 28);
        assert_eq!(h.flags(), 0x12);
        assert_eq!(h.window(), 0xfff0);
        assert_eq!(h.checksum(), 0x1122);
        assert_eq!(h.urgent_ptr(), 7);
        assert_eq!(rest, b"data");
    }

    #[test]
    fn icmp_accessors() {
        let message = icmp(8, 0x4242);
        let (h, rest) = IcmpHeader::parse(&message).unwrap();
        assert_eq!(h.icmp_type(), 8);
        assert_eq!(h.code(), 0);
        assert_eq!(h.checksum(), 0x5aa5);
        assert_eq!(h.identifier(), 0x4242);
        assert_eq!(h.sequence(), 9);
        assert_eq!(rest, b"ping");
    }

    #[test]
    fn every_truncation_is_an_error() {
        let v4 = ipv4(protocol::UDP, 0, &[1, 1, 1, 0], &udp(1, 2));
        let v6 = ipv6(protocol::UDP, &udp(1, 2));
        let tcp = tcp(1, 2, &[1, 1, 1, 1]);
        let udp = udp(1, 2);
        let icmp = icmp(8, 1);
        for len in 0..v4.len() {
            assert!(Ipv4Header::parse(&v4[..len]).is_err(), "v4 {len}");
            assert!(IpPacket::parse(&v4[..len]).is_err(), "v4 packet {len}");
        }
        for len in 0..v6.len() {
            assert!(Ipv6Header::parse(&v6[..len]).is_err(), "v6 {len}");
            assert!(IpPacket::parse(&v6[..len]).is_err(), "v6 packet {len}");
        }
        for len in 0..24 {
            assert!(TcpHeader::parse(&tcp[..len]).is_err(), "tcp {len}");
        }
        for len in 0..8 {
            assert!(UdpHeader::parse(&udp[..len]).is_err(), "udp {len}");
            assert!(IcmpHeader::parse(&icmp[..len]).is_err(), "icmp {len}");
        }
        assert_eq!(IpPacket::parse(&[]).unwrap_err(), Malformed::Truncated);
        assert_eq!(
            Ipv4Header::parse(&v4[..19]).unwrap_err(),
            Malformed::Truncated
        );
        assert_eq!(
            Ipv4Header::parse(&v4[..22]).unwrap_err(),
            Malformed::Truncated
        );
        assert_eq!(
            TcpHeader::parse(&tcp[..22]).unwrap_err(),
            Malformed::Truncated
        );
    }

    #[test]
    fn bad_versions() {
        let mut v4 = ipv4(protocol::UDP, 0, &[], &[0; 40]);
        let mut v6 = ipv6(protocol::UDP, &udp(1, 2));
        assert_eq!(Ipv6Header::parse(&v4).unwrap_err(), Malformed::BadVersion);
        assert_eq!(Ipv4Header::parse(&v6).unwrap_err(), Malformed::BadVersion);
        v4[0] = 0x55;
        v6[0] = 0x55;
        assert_eq!(Ipv4Header::parse(&v4).unwrap_err(), Malformed::BadVersion);
        assert_eq!(IpPacket::parse(&v4).unwrap_err(), Malformed::BadVersion);
        assert_eq!(IpPacket::parse(&v6).unwrap_err(), Malformed::BadVersion);
    }

    #[test]
    fn ipv4_bad_lengths() {
        let packet = ipv4(protocol::UDP, 0, &[], &udp(1, 2));

        let mut short_ihl = packet.clone();
        short_ihl[0] = 0x44;
        assert_eq!(
            Ipv4Header::parse(&short_ihl).unwrap_err(),
            Malformed::BadHeaderLength
        );

        let mut long_ihl = packet.clone();
        long_ihl[0] = 0x4f;
        assert_eq!(
            Ipv4Header::parse(&long_ihl).unwrap_err(),
            Malformed::Truncated
        );

        let mut too_long = packet.clone();
        too_long[2..4].copy_from_slice(&u16::try_from(packet.len() + 1).unwrap().to_be_bytes());
        assert_eq!(
            Ipv4Header::parse(&too_long).unwrap_err(),
            Malformed::Truncated
        );

        let mut too_short = packet;
        too_short[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(
            Ipv4Header::parse(&too_short).unwrap_err(),
            Malformed::BadTotalLength
        );
    }

    #[test]
    fn ipv6_payload_len_beyond_buffer() {
        let mut packet = ipv6(protocol::UDP, &udp(1, 2));
        let too_long = u16::try_from(packet.len()).unwrap();
        packet[4..6].copy_from_slice(&too_long.to_be_bytes());
        assert_eq!(
            Ipv6Header::parse(&packet).unwrap_err(),
            Malformed::Truncated
        );
    }

    #[test]
    fn tcp_bad_data_offset() {
        let mut segment = tcp(1, 2, &[]);
        segment[12] = 0x40;
        assert_eq!(
            TcpHeader::parse(&segment).unwrap_err(),
            Malformed::BadHeaderLength
        );
        segment[12] = 0xf0;
        assert_eq!(
            TcpHeader::parse(&segment).unwrap_err(),
            Malformed::Truncated
        );
    }

    #[test]
    fn packet_accessors() {
        let v4 = ipv4(protocol::UDP, 0, &[], &udp(1, 2));
        let packet = IpPacket::parse(&v4).unwrap();
        assert!(matches!(packet, IpPacket::V4 { .. }));
        assert_eq!(packet.src(), IpAddr::V4(V4_SRC));
        assert_eq!(packet.dst(), IpAddr::V4(V4_DST));
        assert_eq!(packet.protocol(), protocol::UDP);
        assert_eq!(packet.payload(), udp(1, 2).as_slice());
        assert_eq!(packet.ecn(), Ecn::Ect0);
        assert_eq!(packet.fragment(), None);

        let v6 = ipv6(protocol::ICMPV6, &icmp(128, 1));
        let packet = IpPacket::parse(&v6).unwrap();
        assert!(matches!(packet, IpPacket::V6 { .. }));
        assert_eq!(packet.src(), IpAddr::V6(v6_src()));
        assert_eq!(packet.dst(), IpAddr::V6(v6_dst()));
        assert_eq!(packet.protocol(), protocol::ICMPV6);
        assert_eq!(packet.payload(), icmp(128, 1).as_slice());
        assert_eq!(packet.ecn(), Ecn::Ect1);
        assert_eq!(packet.fragment(), None);
    }

    fn five_tuple(bytes: &[u8]) -> Option<FiveTuple> {
        IpPacket::parse(bytes).unwrap().five_tuple()
    }

    #[test]
    fn five_tuple_v4() {
        let expect = |protocol, src_port, dst_port| FiveTuple {
            src: V4_SRC.into(),
            dst: V4_DST.into(),
            protocol,
            src_port,
            dst_port,
        };
        let tcp = ipv4(protocol::TCP, 0, &[], &tcp(443, 50000, &[]));
        assert_eq!(five_tuple(&tcp), Some(expect(protocol::TCP, 443, 50000)));
        let udp = ipv4(protocol::UDP, 0, &[], &udp(53, 40000));
        assert_eq!(five_tuple(&udp), Some(expect(protocol::UDP, 53, 40000)));
        let request = ipv4(protocol::ICMP, 0, &[], &icmp(8, 77));
        assert_eq!(five_tuple(&request), Some(expect(protocol::ICMP, 77, 77)));
        let reply = ipv4(protocol::ICMP, 0, &[], &icmp(0, 78));
        assert_eq!(five_tuple(&reply), Some(expect(protocol::ICMP, 78, 78)));
        let unreachable = ipv4(protocol::ICMP, 0, &[], &icmp(3, 79));
        assert_eq!(five_tuple(&unreachable), Some(expect(protocol::ICMP, 0, 0)));
        let gre = ipv4(47, 0, &[], b"anything");
        assert_eq!(five_tuple(&gre), Some(expect(47, 0, 0)));
    }

    #[test]
    fn five_tuple_v6() {
        let expect = |protocol, src_port, dst_port| FiveTuple {
            src: v6_src().into(),
            dst: v6_dst().into(),
            protocol,
            src_port,
            dst_port,
        };
        let tcp = ipv6(protocol::TCP, &tcp(443, 50000, &[]));
        assert_eq!(five_tuple(&tcp), Some(expect(protocol::TCP, 443, 50000)));
        let udp = ipv6(protocol::UDP, &udp(53, 40000));
        assert_eq!(five_tuple(&udp), Some(expect(protocol::UDP, 53, 40000)));
        let request = ipv6(protocol::ICMPV6, &icmp(128, 0x0101));
        assert_eq!(
            five_tuple(&request),
            Some(expect(protocol::ICMPV6, 0x0101, 0x0101))
        );
        let reply = ipv6(protocol::ICMPV6, &icmp(129, 0x0202));
        assert_eq!(
            five_tuple(&reply),
            Some(expect(protocol::ICMPV6, 0x0202, 0x0202))
        );
        // ICMPv4 echo type numbers mean nothing for ICMPv6.
        let other = ipv6(protocol::ICMPV6, &icmp(8, 5));
        assert_eq!(five_tuple(&other), Some(expect(protocol::ICMPV6, 0, 0)));
    }

    #[test]
    fn five_tuple_truncated_l4_is_none() {
        let tcp = tcp(1, 2, &[]);
        let udp = udp(1, 2);
        let icmp = icmp(8, 1);
        assert_eq!(five_tuple(&ipv4(protocol::TCP, 0, &[], &tcp[..19])), None);
        assert_eq!(five_tuple(&ipv4(protocol::UDP, 0, &[], &udp[..7])), None);
        assert_eq!(five_tuple(&ipv4(protocol::ICMP, 0, &[], &icmp[..7])), None);
        assert_eq!(five_tuple(&ipv6(protocol::TCP, &tcp[..10])), None);
        assert_eq!(five_tuple(&ipv6(protocol::UDP, &[])), None);
        assert_eq!(five_tuple(&ipv6(protocol::ICMPV6, &icmp[..4])), None);
    }

    #[test]
    fn fragments() {
        let first = ipv4(protocol::UDP, 0x2000, &[], &udp(1, 2));
        let packet = IpPacket::parse(&first).unwrap();
        let fragment = packet.fragment().unwrap();
        assert_eq!(
            fragment,
            Fragment {
                id: 0x1234,
                offset: 0,
                more: true
            }
        );
        assert!(fragment.is_first());
        assert!(!fragment.is_last());
        assert!(packet.five_tuple().is_some());

        let middle = ipv4(protocol::UDP, 0x2000 | 0x00B9, &[], b"middle payload");
        let packet = IpPacket::parse(&middle).unwrap();
        let fragment = packet.fragment().unwrap();
        assert_eq!(fragment.offset, 1480);
        assert!(fragment.more);
        assert!(!fragment.is_first());
        assert!(!fragment.is_last());
        assert_eq!(packet.five_tuple(), None);

        let last = ipv4(protocol::UDP, 370, &[], b"tail");
        let packet = IpPacket::parse(&last).unwrap();
        let fragment = packet.fragment().unwrap();
        assert_eq!(fragment.offset, 2960);
        assert!(!fragment.more);
        assert!(fragment.is_last());
        assert_eq!(packet.five_tuple(), None);

        let max = ipv4(protocol::UDP, 0x1FFF, &[], b"x");
        assert_eq!(
            IpPacket::parse(&max).unwrap().fragment().unwrap().offset,
            65528
        );
    }

    #[test]
    fn malformed_display() {
        assert_eq!(Malformed::Truncated.to_string(), "packet truncated");
        assert_eq!(Malformed::BadVersion.to_string(), "bad IP version");
        assert_eq!(Malformed::BadHeaderLength.to_string(), "bad header length");
        assert_eq!(Malformed::BadTotalLength.to_string(), "bad total length");
    }
}
