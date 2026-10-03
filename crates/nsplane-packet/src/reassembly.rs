//! Sans-I/O reassembly of IPv4 fragments and IPv6 Fragment-header packets.
//!
//! A [`Reassembler`] takes whole IP packets and the caller's clock. Packets that are
//! not fragments pass through untouched; fragments are held until their datagram is
//! complete, which then comes back as one valid IP packet. State is bounded in
//! datagrams and bytes, expires after a timeout, and costs nothing until the first
//! fragment arrives: there is no allocation before it and no background task.
//!
//! Datagrams are keyed by (source, destination, protocol, identification) for IPv4
//! (RFC 791) and (source, destination, identification) for IPv6 (RFC 8200). Fragments
//! may arrive in any order and an identical retransmitted fragment is ignored, but
//! fragments that overlap with different coverage drop the whole datagram (RFC 5722;
//! the same policy applies to IPv4).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::checksum::ipv4_header_checksum;
use crate::ip::{Ipv4Header, Ipv6Header};

/// IPv6 next-header values of the extension headers that may precede a Fragment header.
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const DESTINATION_OPTIONS: u8 = 60;
/// IPv6 next-header value of the Fragment header.
const FRAGMENT: u8 = 44;
/// Length of the IPv6 fixed header and of the Fragment header.
const IPV6_HEADER_LEN: usize = 40;
const FRAGMENT_HEADER_LEN: usize = 8;
/// Largest IPv4 total length and IPv6 payload length.
const MAX_LEN_FIELD: usize = 0xFFFF;

/// Bounds of a [`Reassembler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblyConfig {
    /// Most incomplete datagrams held at once; a fragment of a further datagram is
    /// dropped and counted as overflow.
    pub max_datagrams: usize,
    /// Time after its first fragment at which an incomplete datagram is discarded.
    pub timeout: Duration,
    /// Largest reassembled packet in bytes, IP header included; a datagram that would
    /// grow beyond it is dropped and counted as overflow.
    pub max_bytes: usize,
}

impl Default for ReassemblyConfig {
    /// 64 datagrams, 30 seconds, 65 535 bytes.
    fn default() -> Self {
        Self {
            max_datagrams: 64,
            timeout: Duration::from_secs(30),
            max_bytes: 65_535,
        }
    }
}

/// Event counts of a [`Reassembler`], all monotonic.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReassemblyStats {
    /// Datagrams completed and returned.
    pub reassembled: u64,
    /// Incomplete datagrams discarded after the timeout.
    pub timeout: u64,
    /// Fragments or datagrams dropped at the datagram or byte bound.
    pub overflow: u64,
    /// Datagrams dropped for overlapping fragments.
    pub overlap: u64,
    /// Fragments dropped as invalid, and datagrams whose fragments disagree on the length.
    pub malformed: u64,
}

/// What [`Reassembler::push`] did with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Not a fragment (or not a parseable IP packet): handle the packet as it is.
    Pass,
    /// A fragment, held until its datagram is complete.
    Held,
    /// The fragment completed its datagram: the reassembled packet. IPv4 has MF and the
    /// fragment offset cleared and its total length and header checksum fixed; IPv6 has
    /// the Fragment header removed and its payload length and next header fixed. The
    /// header fields come from the first fragment.
    Complete(Vec<u8>),
    /// The fragment was dropped (and its datagram too for an overlap, a length conflict
    /// or the byte bound); see [`Reassembler::stats`].
    Dropped,
}

/// Identifies one fragmented datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        id: u16,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u32,
    },
}

/// One fragment as parsed from a packet.
struct Piece<'a> {
    key: Key,
    /// Byte offset of `data` in the datagram's fragmentable part.
    start: usize,
    more: bool,
    /// Header bytes in front of the fragmentable part, as they must appear in the
    /// reassembled packet (for IPv6, the unfragmentable part).
    header: &'a [u8],
    /// IPv6 only: position of the next-header field that names the Fragment header,
    /// and the next header the Fragment header carries.
    next_header: Option<(usize, u8)>,
    data: &'a [u8],
}

/// The parts of a datagram received so far.
#[derive(Debug)]
struct Datagram {
    first_seen: Instant,
    /// Header from the first fragment, once it arrived.
    header: Option<Vec<u8>>,
    /// See [`Piece::next_header`].
    next_header: Option<(usize, u8)>,
    /// Fragmentable part; bytes not covered by `ranges` are zero.
    data: Vec<u8>,
    /// Received byte ranges, sorted and disjoint.
    ranges: Vec<(usize, usize)>,
    /// Bytes covered by `ranges`.
    received: usize,
    /// Length of the fragmentable part, known once the last fragment arrived.
    total: Option<usize>,
}

/// Why a fragment ended its datagram.
enum Reject {
    Overlap,
    Malformed,
}

impl Datagram {
    const fn new(now: Instant) -> Self {
        Self {
            first_seen: now,
            header: None,
            next_header: None,
            data: Vec::new(),
            ranges: Vec::new(),
            received: 0,
            total: None,
        }
    }

    /// Adds `piece`, ignoring an exact duplicate.
    fn insert(&mut self, piece: &Piece<'_>) -> Result<(), Reject> {
        let (start, end) = (piece.start, piece.start + piece.data.len());
        if !piece.more {
            if self.total.is_some_and(|total| total != end)
                || self.ranges.last().is_some_and(|&(_, last)| last > end)
            {
                return Err(Reject::Malformed);
            }
            self.total = Some(end);
        } else if self.total.is_some_and(|total| end > total) {
            return Err(Reject::Malformed);
        }
        if start == 0 && self.header.is_none() {
            self.header = Some(piece.header.to_vec());
            self.next_header = piece.next_header;
        }
        if start == end {
            return Ok(());
        }
        let at = self.ranges.partition_point(|&(s, _)| s < start);
        if self.ranges.get(at) == Some(&(start, end)) {
            return Ok(());
        }
        let after = self.ranges.get(at).is_some_and(|&(s, _)| s < end);
        let before = at
            .checked_sub(1)
            .and_then(|i| self.ranges.get(i))
            .is_some_and(|&(_, e)| e > start);
        if after || before {
            return Err(Reject::Overlap);
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        if let Some(dst) = self.data.get_mut(start..end) {
            dst.copy_from_slice(piece.data);
        }
        self.ranges.insert(at, (start, end));
        self.received += end - start;
        Ok(())
    }

    /// The reassembled packet, once every byte and the first fragment are in.
    fn assemble(&self) -> Option<Vec<u8>> {
        let total = self.total?;
        if self.received != total {
            return None;
        }
        let header = self.header.as_deref()?;
        let mut packet = Vec::with_capacity(header.len() + total);
        packet.extend_from_slice(header);
        packet.extend_from_slice(self.data.get(..total)?);
        finish_header(&mut packet, header.len(), self.next_header)?;
        Some(packet)
    }
}

/// Fixes the length fields (and the IPv4 flags and checksum, or the IPv6 next header)
/// of a reassembled `packet` whose header is `header_len` bytes long.
fn finish_header(
    packet: &mut [u8],
    header_len: usize,
    next_header: Option<(usize, u8)>,
) -> Option<()> {
    if let Some((at, next)) = next_header {
        let payload_len = u16::try_from(packet.len() - IPV6_HEADER_LEN).ok()?;
        packet
            .get_mut(4..6)?
            .copy_from_slice(&payload_len.to_be_bytes());
        *packet.get_mut(at)? = next;
    } else {
        let total_len = u16::try_from(packet.len()).ok()?;
        packet
            .get_mut(2..4)?
            .copy_from_slice(&total_len.to_be_bytes());
        // Keep the reserved and DF bits; clear MF and the offset.
        *packet.get_mut(6)? &= 0xC0;
        *packet.get_mut(7)? = 0;
        let checksum = ipv4_header_checksum(packet.get(..header_len)?);
        packet
            .get_mut(10..12)?
            .copy_from_slice(&checksum.to_be_bytes());
    }
    Some(())
}

/// Bounded reassembly state for IPv4 and IPv6 fragments.
///
/// Sans-I/O: the caller passes every packet and the current time to
/// [`push`](Self::push) and may call [`expire`](Self::expire) on its own timer;
/// expiry also runs whenever a fragment arrives.
#[derive(Debug)]
pub struct Reassembler {
    config: ReassemblyConfig,
    datagrams: HashMap<Key, Datagram>,
    stats: ReassemblyStats,
}

impl Reassembler {
    /// Creates an empty reassembler; nothing is allocated until the first fragment.
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            datagrams: HashMap::new(),
            stats: ReassemblyStats::default(),
        }
    }

    /// The bounds this reassembler was created with.
    pub const fn config(&self) -> &ReassemblyConfig {
        &self.config
    }

    /// Event counts so far.
    pub const fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    /// Number of incomplete datagrams held.
    pub fn pending(&self) -> usize {
        self.datagrams.len()
    }

    /// Feeds one IP packet received at `now`.
    ///
    /// An IPv6 Fragment header with offset 0 and no more fragments (an atomic
    /// fragment, RFC 6946) completes at once.
    pub fn push(&mut self, packet: &[u8], now: Instant) -> Outcome {
        let piece = match parse(packet) {
            Ok(Some(piece)) => piece,
            Ok(None) => return Outcome::Pass,
            Err(()) => {
                self.stats.malformed += 1;
                return Outcome::Dropped;
            }
        };
        self.expire(now);
        let end = piece.header.len() + piece.start + piece.data.len();
        if end > self.config.max_bytes {
            self.datagrams.remove(&piece.key);
            self.stats.overflow += 1;
            return Outcome::Dropped;
        }
        if !self.datagrams.contains_key(&piece.key)
            && self.datagrams.len() >= self.config.max_datagrams
        {
            self.stats.overflow += 1;
            return Outcome::Dropped;
        }
        let datagram = self
            .datagrams
            .entry(piece.key)
            .or_insert_with(|| Datagram::new(now));
        if let Err(reject) = datagram.insert(&piece) {
            self.datagrams.remove(&piece.key);
            match reject {
                Reject::Overlap => self.stats.overlap += 1,
                Reject::Malformed => self.stats.malformed += 1,
            }
            return Outcome::Dropped;
        }
        let Some(header_len) = datagram.header.as_ref().map(Vec::len) else {
            return Outcome::Held;
        };
        if datagram
            .total
            .is_some_and(|total| header_len + total > self.config.max_bytes)
        {
            self.datagrams.remove(&piece.key);
            self.stats.overflow += 1;
            return Outcome::Dropped;
        }
        let Some(complete) = datagram.assemble() else {
            return Outcome::Held;
        };
        self.datagrams.remove(&piece.key);
        self.stats.reassembled += 1;
        Outcome::Complete(complete)
    }

    /// Discards the incomplete datagrams whose first fragment is at least
    /// [`timeout`](ReassemblyConfig::timeout) older than `now`, and returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        if self.datagrams.is_empty() {
            return 0;
        }
        let timeout = self.config.timeout;
        let before = self.datagrams.len();
        self.datagrams
            .retain(|_, datagram| now.saturating_duration_since(datagram.first_seen) < timeout);
        let expired = before - self.datagrams.len();
        self.stats.timeout += expired as u64;
        expired
    }
}

/// Parses `packet` as a fragment: `Ok(None)` when it is not one (or not a parseable IP
/// packet), `Err` when it is a fragment that cannot be valid.
fn parse(packet: &[u8]) -> Result<Option<Piece<'_>>, ()> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => parse_v4(packet),
        Some(6) => parse_v6(packet),
        _ => Ok(None),
    }
}

fn parse_v4(packet: &[u8]) -> Result<Option<Piece<'_>>, ()> {
    let Ok((header, data)) = Ipv4Header::parse(packet) else {
        return Ok(None);
    };
    let (more, offset) = (header.more_fragments(), header.fragment_offset());
    if !more && offset == 0 {
        return Ok(None);
    }
    let start = usize::from(offset);
    let header_len = header.header_len();
    if (more && (data.is_empty() || data.len() % 8 != 0))
        || header_len + start + data.len() > MAX_LEN_FIELD
    {
        return Err(());
    }
    Ok(Some(Piece {
        key: Key::V4 {
            src: header.src(),
            dst: header.dst(),
            protocol: header.protocol(),
            id: header.identification(),
        },
        start,
        more,
        header: packet.get(..header_len).ok_or(())?,
        next_header: None,
        data,
    }))
}

fn parse_v6(packet: &[u8]) -> Result<Option<Piece<'_>>, ()> {
    let Ok((header, payload)) = Ipv6Header::parse(packet) else {
        return Ok(None);
    };
    // Stop at the payload length: trailing bytes are not part of the packet.
    let packet = packet.get(..IPV6_HEADER_LEN + payload.len()).ok_or(())?;
    // Walk the extension headers that may precede the Fragment header.
    let mut next = header.next_header();
    let mut next_at = 6;
    let mut at = IPV6_HEADER_LEN;
    while matches!(next, HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS) {
        let (Some(&following), Some(&len)) = (packet.get(at), packet.get(at + 1)) else {
            return Ok(None);
        };
        next = following;
        next_at = at;
        at += (usize::from(len) + 1) * 8;
    }
    if next != FRAGMENT {
        return Ok(None);
    }
    let fragment = packet.get(at..at + FRAGMENT_HEADER_LEN).ok_or(())?;
    let data = packet.get(at + FRAGMENT_HEADER_LEN..).ok_or(())?;
    let &[inner, _, offset_hi, offset_lo, id0, id1, id2, id3] = fragment else {
        return Err(());
    };
    let offset_flags = u16::from_be_bytes([offset_hi, offset_lo]);
    let start = usize::from(offset_flags >> 3) * 8;
    let more = offset_flags & 1 == 1;
    if (more && (data.is_empty() || data.len() % 8 != 0))
        || at - IPV6_HEADER_LEN + start + data.len() > MAX_LEN_FIELD
    {
        return Err(());
    }
    Ok(Some(Piece {
        key: Key::V6 {
            src: header.src(),
            dst: header.dst(),
            id: u32::from_be_bytes([id0, id1, id2, id3]),
        },
        start,
        more,
        header: packet.get(..at).ok_or(())?,
        next_header: Some((next_at, inner)),
        data,
    }))
}

#[cfg(test)]
mod tests;
