//! RFC 7915 header translation of whole packets, rewritten in place.
//!
//! IPv4 to IPv6 grows a packet by 20 bytes (28 with a fragment header) plus
//! the length of any IPv4 options, which are dropped; IPv6 to IPv4 shrinks it.
//! A growing packet's payload is moved inside the buffer; a packet that would
//! outgrow the buffer's capacity is first copied into a larger buffer. A
//! shrinking packet keeps its payload in place: the new header is written in
//! front of it and the packet start moves forward into the headroom.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use nsplane_packet::{PacketBuf, protocol};

use super::fragment::{Key, Outcome, Reassembly};
use super::parse::{Fragment, Ipv4, Ipv6, be16, put16};
use super::{Result, icmp, reasons};
use crate::TranslationTable;
use crate::checksum::{
    PseudoHeader, transport_checksum_v6, transport_valid, udp_wire, update_ipv6,
    update_pseudo_header, update_udp,
};

/// Size of an IPv6 fragment header.
pub(super) const FRAGMENT_HEADER_LEN: usize = 8;

/// IPv4 packets above this total length get DF when translated from an
/// unfragmented IPv6 packet (1280 minus the 20-byte header difference).
const DF_THRESHOLD: usize = 1260;

/// What happened to a translated packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Done {
    /// The packet was rewritten.
    Translated,
    /// The fragment was stored for reassembly; the buffer can be recycled.
    Pending,
}

/// The state an IPv4 to IPv6 translation reads.
#[derive(Debug, Clone, Copy)]
pub(super) struct Context<'a> {
    /// Maps the addresses quoted in ICMP errors.
    pub(super) table: &'a TranslationTable,
    pub(super) reassembly: &'a Mutex<Reassembly>,
    /// The start of the reassembly clock, read only for fragments.
    pub(super) epoch: Instant,
    /// The largest IPv6 packet a reassembled datagram may become.
    pub(super) mtu: usize,
}

/// The outer addresses of a packet on both sides of the translation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Addrs {
    pub(super) src4: Ipv4Addr,
    pub(super) dst4: Ipv4Addr,
    pub(super) src6: Ipv6Addr,
    pub(super) dst6: Ipv6Addr,
}

impl Addrs {
    /// The IPv4 pseudo-header without a length: the length and protocol are
    /// the same on both sides, so only the addresses matter for an update.
    pub(super) const fn v4(&self, protocol: u8) -> PseudoHeader {
        PseudoHeader::V4 {
            src: self.src4,
            dst: self.dst4,
            protocol,
            len: 0,
        }
    }

    /// The IPv6 counterpart of [`v4`](Self::v4).
    pub(super) const fn v6(&self, protocol: u8) -> PseudoHeader {
        PseudoHeader::V6 {
            src: self.src6,
            dst: self.dst6,
            protocol,
            len: 0,
        }
    }

    /// The full IPv4 pseudo-header of `segment`, to verify it.
    fn v4_len(&self, protocol: u8, segment: &[u8]) -> Result<PseudoHeader> {
        Ok(PseudoHeader::V4 {
            src: self.src4,
            dst: self.dst4,
            protocol,
            len: u16::try_from(segment.len()).map_err(|_| reasons::LENGTH_MISMATCH)?,
        })
    }

    /// The IPv6 counterpart of [`v4_len`](Self::v4_len).
    fn v6_len(&self, protocol: u8, segment: &[u8]) -> Result<PseudoHeader> {
        Ok(PseudoHeader::V6 {
            src: self.src6,
            dst: self.dst6,
            protocol,
            len: u32::try_from(segment.len()).map_err(|_| reasons::LENGTH_MISMATCH)?,
        })
    }
}

/// An IPv6 header to encode, optionally followed by a fragment header.
#[derive(Debug, Clone, Copy)]
pub(super) struct V6Header {
    pub(super) traffic_class: u8,
    /// Upper-layer bytes, without the fragment header.
    pub(super) upper_len: usize,
    pub(super) protocol: u8,
    pub(super) hop_limit: u8,
    pub(super) src: Ipv6Addr,
    pub(super) dst: Ipv6Addr,
    pub(super) fragment: Option<Fragment>,
}

impl V6Header {
    /// Returns the encoded header and its length (40, or 48 with a fragment
    /// header). The flow label is zero.
    pub(super) fn encode(&self) -> Result<([u8; 48], usize)> {
        let extra = if self.fragment.is_some() {
            FRAGMENT_HEADER_LEN
        } else {
            0
        };
        let payload_len =
            u16::try_from(self.upper_len + extra).map_err(|_| reasons::LENGTH_MISMATCH)?;
        let mut header = [0; 48];
        header[0] = 0x60 | (self.traffic_class >> 4);
        header[1] = self.traffic_class << 4;
        put16(&mut header, 4, payload_len);
        header[7] = self.hop_limit;
        header[8..24].copy_from_slice(&self.src.octets());
        header[24..40].copy_from_slice(&self.dst.octets());
        header[6] = self.protocol;
        if let Some(fragment) = self.fragment {
            header[6] = super::parse::FRAGMENT;
            header[40] = self.protocol;
            put16(
                &mut header,
                42,
                (fragment.offset << 3) | u16::from(fragment.more),
            );
            header[44..48].copy_from_slice(&fragment.identification.to_be_bytes());
        }
        Ok((header, 40 + extra))
    }
}

/// An IPv4 header to encode (no options).
#[derive(Debug, Clone, Copy)]
pub(super) struct V4Header {
    pub(super) tos: u8,
    /// Upper-layer bytes.
    pub(super) upper_len: usize,
    pub(super) ttl: u8,
    pub(super) protocol: u8,
    pub(super) src: Ipv4Addr,
    pub(super) dst: Ipv4Addr,
    /// The IPv6 fragment header: its low 16 identification bits, offset and M flag.
    pub(super) fragment: Option<Fragment>,
    /// Set DF on an unfragmented packet.
    pub(super) dont_fragment: bool,
}

impl V4Header {
    /// Returns the encoded header with its checksum.
    pub(super) fn encode(&self) -> Result<[u8; 20]> {
        let total = u16::try_from(20 + self.upper_len).map_err(|_| reasons::LENGTH_MISMATCH)?;
        let mut header = [0; 20];
        header[0] = 0x45;
        header[1] = self.tos;
        put16(&mut header, 2, total);
        if let Some(fragment) = self.fragment {
            let [.., hi, lo] = fragment.identification.to_be_bytes();
            header[4..6].copy_from_slice(&[hi, lo]);
            let more = if fragment.more { 0x2000 } else { 0 };
            put16(&mut header, 6, (fragment.offset & 0x1fff) | more);
        } else if self.dont_fragment {
            put16(&mut header, 6, 0x4000);
        }
        header[8] = self.ttl;
        header[9] = self.protocol;
        header[12..16].copy_from_slice(&self.src.octets());
        header[16..20].copy_from_slice(&self.dst.octets());
        let checksum = crate::checksum::ipv4_header_checksum(&header);
        put16(&mut header, 10, checksum);
        Ok(header)
    }
}

/// Translates the IPv4 packet in `packet` to IPv6 with the outer addresses
/// `src` and `dst`.
pub(super) fn v4_to_v6(
    packet: &mut PacketBuf,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    cx: Context<'_>,
) -> Result<Done> {
    let v4 = Ipv4::parse(packet.as_packet(), false)?;
    let fragmented = v4.fragmented();
    if fragmented && v4.protocol == protocol::ICMP {
        return Err(reasons::FRAGMENTED_ICMP);
    }
    let hop_limit = forwarded_hop(v4.ttl)?;
    let addrs = Addrs {
        src4: v4.src,
        dst4: v4.dst,
        src6: src,
        dst6: dst,
    };
    if fragmented
        && v4.protocol == protocol::UDP
        && let Some(done) = reassemble(packet, &v4, addrs, cx)?
    {
        return Ok(done);
    }
    let payload = &mut packet.as_packet_mut()[v4.payload.clone()];
    let body = match v4.protocol {
        protocol::TCP | protocol::UDP if v4.fragment_offset == 0 => {
            transport_v4_to_v6(payload, v4.protocol, addrs, fragmented)?;
            None
        }
        protocol::TCP | protocol::UDP => None,
        protocol::ICMP => icmp::v4_to_v6(payload, src, dst, cx.table)?,
        _ => return Err(reasons::UNSUPPORTED_PROTOCOL),
    };
    let header = V6Header {
        traffic_class: v4.tos,
        upper_len: body.as_ref().map_or_else(|| v4.payload.len(), Vec::len),
        protocol: if v4.protocol == protocol::ICMP {
            protocol::ICMPV6
        } else {
            v4.protocol
        },
        hop_limit,
        src,
        dst,
        fragment: fragmented.then_some(Fragment {
            offset: v4.fragment_offset,
            more: v4.more_fragments,
            identification: u32::from(v4.identification),
        }),
    };
    let (header, header_len) = header.encode()?;
    let header = &header[..header_len];
    match body {
        Some(body) => replace_all(packet, header, &body)?,
        None => replace_header(packet, v4.payload, header)?,
    }
    Ok(Done::Translated)
}

/// Feeds a UDP fragment to reassembly if its datagram has no checksum, or
/// may have none because its first fragment has not been seen yet.
///
/// Returns `None` for fragments that are translated one by one: the first
/// fragment of a datagram with a checksum that has nothing held, and later
/// fragments of such a datagram.
fn reassemble(
    packet: &mut PacketBuf,
    v4: &Ipv4,
    addrs: Addrs,
    cx: Context<'_>,
) -> Result<Option<Done>> {
    let payload = &packet.as_packet()[v4.payload.clone()];
    let key = Key {
        src: v4.src,
        dst: v4.dst,
        identification: v4.identification,
        protocol: v4.protocol,
    };
    let now = cx.epoch.elapsed().as_secs();
    let mut state = cx.reassembly.lock().unwrap_or_else(PoisonError::into_inner);
    state.cleanup(now);
    if v4.fragment_offset == 0 {
        if payload.len() < 8 {
            return Err(reasons::TINY_FRAGMENT);
        }
        if be16(payload, 6) != 0 && !state.contains(&key) {
            state.mark_passed(key, now);
            return Ok(None);
        }
    } else if !state.contains(&key) && state.passed(&key) {
        return Ok(None);
    }
    let len = payload.len();
    let outcome = state.observe(key, packet.as_packet(), len, now)?;
    drop(state);
    let Outcome::Complete(mut body) = outcome else {
        return Ok(Some(Done::Pending));
    };
    // The header is the first fragment's.
    let Ipv4 {
        tos,
        ttl,
        header_len,
        ..
    } = Ipv4::parse(&body, false)?;
    body.drain(..header_len);
    if body.len() + 40 > cx.mtu {
        return Err(reasons::REASSEMBLED_TOO_BIG);
    }
    transport_v4_to_v6(&mut body, protocol::UDP, addrs, false)?;
    let (header, header_len) = V6Header {
        traffic_class: tos,
        upper_len: body.len(),
        protocol: protocol::UDP,
        hop_limit: forwarded_hop(ttl)?,
        src: addrs.src6,
        dst: addrs.dst6,
        fragment: None,
    }
    .encode()?;
    replace_all(packet, &header[..header_len], &body)?;
    Ok(Some(Done::Translated))
}

/// Translates the IPv6 packet in `packet` to IPv4 with the outer addresses
/// `src` and `dst`.
pub(super) fn v6_to_v4(
    packet: &mut PacketBuf,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    table: &TranslationTable,
) -> Result<()> {
    let v6 = Ipv6::parse(packet.as_packet(), false)?;
    if v6.fragment.is_some() && v6.protocol == protocol::ICMPV6 {
        return Err(reasons::FRAGMENTED_ICMP);
    }
    let ttl = forwarded_hop(v6.hop_limit)?;
    let addrs = Addrs {
        src4: src,
        dst4: dst,
        src6: v6.src,
        dst6: v6.dst,
    };
    let payload = &mut packet.as_packet_mut()[v6.payload.clone()];
    let body = match v6.protocol {
        protocol::TCP | protocol::UDP if v6.has_transport_header() => {
            transport_v6_to_v4(payload, v6.protocol, addrs, v6.fragment.is_some())?;
            None
        }
        protocol::TCP | protocol::UDP => None,
        protocol::ICMPV6 => icmp::v6_to_v4(payload, v6.src, v6.dst, table)?,
        _ => return Err(reasons::UNSUPPORTED_PROTOCOL),
    };
    let upper_len = body.as_ref().map_or_else(|| v6.payload.len(), Vec::len);
    let header = V4Header {
        tos: v6.traffic_class,
        upper_len,
        ttl,
        protocol: if v6.protocol == protocol::ICMPV6 {
            protocol::ICMP
        } else {
            v6.protocol
        },
        src,
        dst,
        fragment: v6.fragment,
        dont_fragment: 20 + upper_len > DF_THRESHOLD,
    }
    .encode()?;
    match body {
        Some(body) => replace_all(packet, &header, &body),
        None => replace_header(packet, v6.payload, &header),
    }
}

/// Rewrites the outer addresses of the IPv6 packet in `packet` to `src` and
/// `dst`, updating the transport checksum; addresses quoted in an `ICMPv6`
/// error are passed through `quoted`.
pub(super) fn rewrite_v6(
    packet: &mut PacketBuf,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    quoted: &dyn Fn(Ipv6Addr) -> Option<Ipv6Addr>,
) -> Result<()> {
    let v6 = Ipv6::parse(packet.as_packet(), false)?;
    let bytes = packet.as_packet_mut();
    bytes[8..24].copy_from_slice(&src.octets());
    bytes[24..40].copy_from_slice(&dst.octets());
    if !v6.has_transport_header() {
        return Ok(());
    }
    let update = |checksum| update_addrs6(checksum, (v6.src, v6.dst), (src, dst));
    let segment = &mut bytes[v6.payload.clone()];
    match v6.protocol {
        protocol::TCP => {
            if segment.len() < 20 {
                return Err(reasons::TRUNCATED);
            }
            put16(segment, 16, update(be16(segment, 16)));
        }
        protocol::UDP => {
            if segment.len() < 8 {
                return Err(reasons::TRUNCATED);
            }
            put16(segment, 6, update_udp(be16(segment, 6), update));
        }
        protocol::ICMPV6 => {
            if segment.len() < 8 {
                return Err(reasons::TRUNCATED);
            }
            let mut checksum = update(be16(segment, 2));
            if segment[0] < 128 {
                checksum = icmp::rewrite_quoted_v6(&mut segment[8..], checksum, quoted);
            }
            put16(segment, 2, checksum);
        }
        _ => {}
    }
    Ok(())
}

/// Updates `checksum` for the IPv6 addresses `old` replaced by `new`.
pub(super) fn update_addrs6(
    checksum: u16,
    old: (Ipv6Addr, Ipv6Addr),
    new: (Ipv6Addr, Ipv6Addr),
) -> u16 {
    update_ipv6(update_ipv6(checksum, old.0, new.0), old.1, new.1)
}

/// Checks a TCP or UDP header and moves its checksum from the IPv4 to the
/// IPv6 pseudo-header. A UDP datagram without a checksum (only possible here
/// unfragmented or reassembled) gets a full one, as IPv6 requires it.
fn transport_v4_to_v6(
    segment: &mut [u8],
    protocol: u8,
    addrs: Addrs,
    fragmented: bool,
) -> Result<()> {
    let at = checked_transport(segment, protocol, fragmented)?;
    let old = be16(segment, at);
    if protocol == protocol::UDP && old == 0 {
        let checksum = transport_checksum_v6(addrs.src6, addrs.dst6, protocol, segment);
        put16(segment, at, udp_wire(checksum));
        return Ok(());
    }
    if old == 0 || (!fragmented && !transport_valid(addrs.v4_len(protocol, segment)?, segment)) {
        return Err(reasons::INVALID_CHECKSUM);
    }
    let new = update_pseudo_header(old, addrs.v4(protocol), addrs.v6(protocol));
    put16(segment, at, finish(protocol, new));
    Ok(())
}

/// Checks a TCP or UDP header and moves its checksum from the IPv6 to the
/// IPv4 pseudo-header. A zero checksum is invalid over IPv6.
fn transport_v6_to_v4(
    segment: &mut [u8],
    protocol: u8,
    addrs: Addrs,
    fragmented: bool,
) -> Result<()> {
    let at = checked_transport(segment, protocol, fragmented)?;
    let old = be16(segment, at);
    if old == 0 || (!fragmented && !transport_valid(addrs.v6_len(protocol, segment)?, segment)) {
        return Err(reasons::INVALID_CHECKSUM);
    }
    let new = update_pseudo_header(old, addrs.v6(protocol), addrs.v4(protocol));
    put16(segment, at, finish(protocol, new));
    Ok(())
}

/// Checks the length of a TCP or UDP header (and of an unfragmented UDP
/// datagram) and returns the offset of its checksum field.
fn checked_transport(segment: &[u8], protocol: u8, fragmented: bool) -> Result<usize> {
    let (minimum, at) = if protocol == protocol::TCP {
        (20, 16)
    } else {
        (8, 6)
    };
    if segment.len() < minimum {
        return Err(reasons::TRUNCATED);
    }
    if protocol == protocol::UDP && !fragmented && usize::from(be16(segment, 4)) != segment.len() {
        return Err(reasons::LENGTH_MISMATCH);
    }
    Ok(at)
}

/// The on-wire form of an updated checksum: UDP never sends zero.
pub(super) const fn finish(protocol: u8, checksum: u16) -> u16 {
    if protocol == protocol::UDP {
        udp_wire(checksum)
    } else {
        checksum
    }
}

/// The TTL or hop limit of a forwarded packet; it must stay above zero.
fn forwarded_hop(value: u8) -> Result<u8> {
    value
        .checked_sub(1)
        .filter(|&hop| hop > 0)
        .ok_or(reasons::HOP_LIMIT_EXCEEDED)
}

/// The longest packet a translation can produce: an IPv6 header and the
/// largest payload its length field holds.
const MAX_LEN: usize = 40 + 65535;

/// Makes room for `len` packet bytes: a buffer with less capacity is replaced
/// by a fresh one with the standard headroom that holds a copy of the packet
/// (the slow path [`TranslatorStats::grown_copies`](super::TranslatorStats)
/// counts). Fails with [`NO_ROOM`](reasons::NO_ROOM) beyond [`MAX_LEN`].
fn make_room(packet: &mut PacketBuf, len: usize) -> Result<()> {
    if len > MAX_LEN {
        return Err(reasons::NO_ROOM);
    }
    if len > packet.capacity() {
        let mut grown = PacketBuf::with_capacity(len);
        grown.set_len(packet.len());
        grown.as_packet_mut().copy_from_slice(packet.as_packet());
        *packet = grown;
    }
    Ok(())
}

/// Replaces everything in front of `payload` with `header`. A header that
/// fits in front of the payload is written there and the packet start moves
/// to it (the headroom grows); a longer one moves the payload.
fn replace_header(packet: &mut PacketBuf, payload: Range<usize>, header: &[u8]) -> Result<()> {
    if let Some(start) = payload.start.checked_sub(header.len()) {
        packet.as_packet_mut()[start..payload.start].copy_from_slice(header);
        packet.set_len(payload.end);
        return packet.advance(start).map_err(|_| reasons::TRUNCATED);
    }
    let len = header.len() + payload.len();
    make_room(packet, len)?;
    if len > packet.len() {
        packet.set_len(len);
    }
    let bytes = packet.as_packet_mut();
    bytes.copy_within(payload, header.len());
    bytes[..header.len()].copy_from_slice(header);
    packet.set_len(len);
    Ok(())
}

/// Replaces the whole packet with `header` followed by `body`.
fn replace_all(packet: &mut PacketBuf, header: &[u8], body: &[u8]) -> Result<()> {
    let len = header.len() + body.len();
    make_room(packet, len)?;
    packet.set_len(len);
    let bytes = packet.as_packet_mut();
    bytes[..header.len()].copy_from_slice(header);
    bytes[header.len()..].copy_from_slice(body);
    Ok(())
}
