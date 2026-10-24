//! Ethernet II framing (IEEE 802.3, DIX header).
//!
//! The header is 14 bytes: destination MAC, source MAC, `EtherType`. Frames tagged with
//! 802.1Q / 802.1ad and 802.3 length-framed frames are rejected as unsupported.

use std::fmt;

use crate::MacAddr;
use crate::read::Reader;

/// Length of the Ethernet II header.
pub const HEADER_LEN: usize = 14;

/// The protocol of an Ethernet II payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    /// IPv4.
    pub const IPV4: Self = Self(0x0800);
    /// ARP.
    pub const ARP: Self = Self(0x0806);
    /// IPv6.
    pub const IPV6: Self = Self(0x86DD);

    /// Smallest value that is an `EtherType`; smaller values are 802.3 lengths.
    const MIN: u16 = 0x0600;

    /// Whether this is a VLAN tag protocol identifier (802.1Q, 802.1ad, legacy Q-in-Q).
    const fn is_vlan_tag(self) -> bool {
        matches!(self.0, 0x8100 | 0x88A8 | 0x9100)
    }
}

/// Why a frame was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The buffer is shorter than the header.
    Truncated,
    /// The frame carries a VLAN tag.
    VlanTagged,
    /// The type field is an 802.3 length, not an `EtherType`.
    NotEthernetII,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "ethernet frame truncated",
            Self::VlanTagged => "VLAN-tagged ethernet frame",
            Self::NotEthernetII => "not an Ethernet II frame",
        })
    }
}

impl std::error::Error for FrameError {}

/// A parsed Ethernet II frame borrowing its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// Payload protocol.
    pub ethertype: EtherType,
    /// Everything after the header, including any padding to the minimum frame size.
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parses the header of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FrameError> {
        let mut r = Reader::new(bytes);
        let (Some(dst), Some(src), Some(ethertype)) = (r.mac(), r.mac(), r.u16()) else {
            return Err(FrameError::Truncated);
        };
        let ethertype = EtherType(ethertype);
        if ethertype.is_vlan_tag() {
            return Err(FrameError::VlanTagged);
        }
        if ethertype.0 < EtherType::MIN {
            return Err(FrameError::NotEthernetII);
        }
        Ok(Self {
            dst,
            src,
            ethertype,
            payload: r.rest(),
        })
    }
}

/// The header bytes for `dst`, `src` and `ethertype`.
const fn header(dst: MacAddr, src: MacAddr, ethertype: EtherType) -> [u8; HEADER_LEN] {
    let [d0, d1, d2, d3, d4, d5] = dst.0;
    let [s0, s1, s2, s3, s4, s5] = src.0;
    let [t0, t1] = ethertype.0.to_be_bytes();
    [d0, d1, d2, d3, d4, d5, s0, s1, s2, s3, s4, s5, t0, t1]
}

/// Writes the header into the first [`HEADER_LEN`] bytes of `buf`.
///
/// # Errors
///
/// Returns [`FrameError::Truncated`] if `buf` is shorter than the header; `buf` is left
/// unchanged.
pub fn write_header(
    buf: &mut [u8],
    dst: MacAddr,
    src: MacAddr,
    ethertype: EtherType,
) -> Result<(), FrameError> {
    let (head, _) = buf
        .split_first_chunk_mut::<HEADER_LEN>()
        .ok_or(FrameError::Truncated)?;
    *head = header(dst, src, ethertype);
    Ok(())
}

/// A new frame holding only the header, with room for `payload_len` more bytes.
pub(crate) fn start(
    dst: MacAddr,
    src: MacAddr,
    ethertype: EtherType,
    payload_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload_len);
    out.extend_from_slice(&header(dst, src, ethertype));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
    const B: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x00, 0x00, 0x02]);

    #[test]
    fn round_trip() {
        let mut buf = [0u8; HEADER_LEN + 3];
        write_header(&mut buf, A, B, EtherType::IPV6).unwrap();
        buf[HEADER_LEN..].copy_from_slice(b"abc");
        assert_eq!(
            buf[..HEADER_LEN],
            [0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x86, 0xdd]
        );
        let frame = Frame::parse(&buf).unwrap();
        assert_eq!(frame.dst, A);
        assert_eq!(frame.src, B);
        assert_eq!(frame.ethertype, EtherType::IPV6);
        assert_eq!(frame.payload, b"abc");

        let built = start(B, A, EtherType::ARP, 0);
        let frame = Frame::parse(&built).unwrap();
        assert_eq!((frame.dst, frame.src), (B, A));
        assert_eq!(frame.ethertype, EtherType::ARP);
        assert_eq!(frame.payload, []);
    }

    #[test]
    fn truncation() {
        let mut buf = [0u8; HEADER_LEN];
        write_header(&mut buf, A, B, EtherType::IPV4).unwrap();
        for len in 0..HEADER_LEN {
            assert_eq!(Frame::parse(&buf[..len]), Err(FrameError::Truncated));
        }
        assert!(Frame::parse(&buf).is_ok());
        let mut short = [0u8; HEADER_LEN - 1];
        assert_eq!(
            write_header(&mut short, A, B, EtherType::IPV4),
            Err(FrameError::Truncated)
        );
        assert_eq!(short, [0; HEADER_LEN - 1]);
    }

    #[test]
    fn vlan_and_length_framing_rejected() {
        let mut buf = [0u8; HEADER_LEN + 4];
        for tpid in [0x8100, 0x88a8, 0x9100] {
            write_header(&mut buf, A, B, EtherType(tpid)).unwrap();
            assert_eq!(Frame::parse(&buf), Err(FrameError::VlanTagged));
        }
        write_header(&mut buf, A, B, EtherType(0x05dc)).unwrap();
        assert_eq!(Frame::parse(&buf), Err(FrameError::NotEthernetII));
    }
}
