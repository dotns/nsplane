//! The fragmentation stage on the engine's local path.
//!
//! A [`Fragmenter`] looks at every local packet before it enters the core and keeps packets
//! within the engine MTU: an IPv6 packet above it is answered with an `ICMPv6` Packet Too Big,
//! an IPv4 packet above its ceiling with an ICMP Fragmentation Needed (DF set) or split into
//! IPv4 fragments (DF clear). The ICMP errors are delivered to the local side as if the
//! packet's destination had sent them.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane_core::reasons::{FRAGMENT_NO_ROUTE, FRAGMENT_OVERSIZE, FRAGMENT_RATE_LIMITED};
use nsplane_packet::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{Ipv4Header, Ipv6Header, PacketBuf, PeerId, protocol};

/// IPv4 header without options.
const IPV4_HEADER: usize = 20;
/// IPv6 header.
const IPV6_HEADER: usize = 40;
/// IPv6 Fragment extension header.
const IPV6_FRAGMENT_HEADER: usize = 8;
/// How much an IPv4 packet grows when it is translated to IPv6 (without options).
const TRANSLATION_GROWTH: usize = IPV6_HEADER - IPV4_HEADER;
/// ICMP / `ICMPv6` header in front of the quoted packet.
const ICMP_HEADER: usize = 8;
/// An `ICMPv6` error, quote included, fits in the IPv6 minimum MTU.
const IPV6_MIN_MTU: usize = 1280;
/// An ICMP error, quote included, fits in the minimum reassembly size (RFC 1812 4.3.2.3).
const IPV4_ICMP_ERROR_MAX: usize = 576;
/// Hop limit / TTL of generated errors.
const HOP_LIMIT: u8 = 64;
/// Next header value of the IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;
/// Room behind each fragment for the translation growth (with a fragment header) and the
/// core's sealing tail, so neither reallocates.
const FRAGMENT_TAIL: usize = 128;
/// IPv4 flag bits and offset mask of the flags/fragment-offset word.
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const OFFSET_MASK: u16 = 0x1FFF;
/// Token bucket of the ICMP error generation: burst size and refill interval.
const ICMP_BURST: u32 = 10;
const ICMP_REFILL: Duration = Duration::from_millis(200);

/// Predicate over IPv4 destinations; see [`FragmentConfig::translated`].
type TranslatedPredicate = Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>;

/// Configuration of the engine's fragmentation stage, installed with
/// [`EngineBuilder::fragmenter`](crate::EngineBuilder::fragmenter).
///
/// The stage keeps every local packet within the engine MTU ([`PacketSource::mtu`]) before
/// it enters the core:
///
/// - An IPv6 packet above the MTU is not sent; an `ICMPv6` Packet Too Big carrying the MTU
///   is delivered to the local side instead.
/// - An IPv4 packet above its ceiling is answered with an ICMP Fragmentation Needed
///   carrying the ceiling when DF is set, and is otherwise split into IPv4 fragments that
///   enter the core one by one (an already fragmented packet keeps its offset base and MF).
///   The ceiling is the MTU for native IPv4. For destinations [`translated`] returns true
///   for, the packet becomes IPv6 in the core, so the ceiling is 20 bytes lower and
///   fragments are sized to fit the MTU once translated with an IPv6 Fragment header; a UDP
///   datagram without a checksum gets one before it is split, so each fragment translates
///   on its own.
///
/// The ICMP errors look as if the packet's destination had sent them, and are delivered as
/// coming from the peer that destination is routed to (none: no error). They are
/// rate-limited and never sent about ICMP errors, multicast or broadcast packets, or
/// fragments other than the first.
///
/// [`PacketSource::mtu`]: crate::PacketSource::mtu
/// [`translated`]: Self::translated
#[derive(Clone, Default)]
pub struct FragmentConfig {
    /// The IPv4 destinations that are translated to IPv6 on their way to the tunnel, e.g.
    /// `nsplane_nat::Translator::ipv4_translated_predicate`; `None` treats every IPv4
    /// destination as native.
    pub translated: Option<Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>>,
}

impl fmt::Debug for FragmentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FragmentConfig")
            .field("translated", &self.translated.is_some())
            .finish()
    }
}

/// Counters of the fragmentation stage since the engine started; see
/// [`EngineHandle::fragment_stats`](crate::EngineHandle::fragment_stats).
///
/// Every packet the stage drops is also counted in
/// [`EngineHandle::drop_counters`](crate::EngineHandle::drop_counters):
/// `rate_limited` under [`crate::DROP_FRAGMENT_RATE_LIMITED`], `no_route` under
/// [`crate::DROP_FRAGMENT_NO_ROUTE`] and `dropped` under [`crate::DROP_FRAGMENT_OVERSIZE`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FragmentStats {
    /// IPv4 packets split into fragments.
    pub fragmented: u64,
    /// Fragments emitted.
    pub fragments: u64,
    /// `ICMPv6` Packet Too Big errors delivered.
    pub ptb_sent: u64,
    /// ICMP Fragmentation Needed errors delivered.
    pub frag_needed_sent: u64,
    /// Oversized packets whose error was not generated because of the rate limit.
    pub rate_limited: u64,
    /// Oversized packets whose error was not generated because its destination has no
    /// route.
    pub no_route: u64,
    /// Oversized packets dropped without an error (an error about it is not allowed, or it
    /// cannot be split).
    pub dropped: u64,
}

/// What to do with a local packet.
#[derive(Debug)]
pub(crate) enum Action {
    /// Send it on unchanged.
    Send(PacketBuf),
    /// Send these fragments instead, in order.
    Fragments(Vec<PacketBuf>),
    /// Deliver this ICMP error to the local side as coming from the peer.
    Reply(PeerId, PacketBuf),
    /// Nothing is sent, for this drop reason.
    Drop(&'static str),
}

/// The fragmentation stage; see [`FragmentConfig`].
pub(crate) struct Fragmenter {
    translated: Option<TranslatedPredicate>,
    /// Tokens of the ICMP error rate limit.
    tokens: u32,
    /// When the bucket was last refilled; `None` before the first error.
    refilled: Option<Instant>,
    stats: FragmentStats,
}

impl fmt::Debug for Fragmenter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fragmenter")
            .field("translated", &self.translated.is_some())
            .field("tokens", &self.tokens)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Fragmenter {
    pub(crate) fn new(config: FragmentConfig) -> Self {
        Self {
            translated: config.translated,
            tokens: ICMP_BURST,
            refilled: None,
            stats: FragmentStats::default(),
        }
    }

    /// A snapshot of the counters.
    pub(crate) const fn stats(&self) -> FragmentStats {
        self.stats
    }

    /// Decides about `packet` under `mtu`; `route` names the peer a destination is routed to.
    pub(crate) fn process(
        &mut self,
        packet: PacketBuf,
        mtu: u16,
        now: Instant,
        route: impl FnOnce(IpAddr) -> Option<PeerId>,
    ) -> Action {
        let mtu = usize::from(mtu);
        // Within every ceiling: the common case.
        if packet.len() <= mtu.saturating_sub(TRANSLATION_GROWTH + IPV6_FRAGMENT_HEADER) {
            return Action::Send(packet);
        }
        match packet.as_packet().first().map(|b| b >> 4) {
            Some(4) => self.ipv4(packet, mtu, now, route),
            Some(6) => self.ipv6(packet, mtu, now, route),
            // Not IP: the core drops it.
            _ => Action::Send(packet),
        }
    }

    fn ipv6(
        &mut self,
        packet: PacketBuf,
        mtu: usize,
        now: Instant,
        route: impl FnOnce(IpAddr) -> Option<PeerId>,
    ) -> Action {
        let bytes = packet.as_packet();
        if bytes.len() <= mtu {
            return Action::Send(packet);
        }
        let Ok((header, payload)) = Ipv6Header::parse(bytes) else {
            return Action::Send(packet);
        };
        let (src, dst) = (header.src(), header.dst());
        if !may_answer_v6(src, dst, header.next_header(), payload) {
            return self.drop("IPv6 packet above the MTU");
        }
        let peer = match self.admit(IpAddr::V6(dst), now, route) {
            Ok(peer) => peer,
            Err(reason) => return Action::Drop(reason),
        };
        self.stats.ptb_sent += 1;
        tracing::debug!(%src, %dst, len = bytes.len(), mtu, "Packet Too Big");
        Action::Reply(peer, packet_too_big(bytes, src, dst, mtu))
    }

    fn ipv4(
        &mut self,
        packet: PacketBuf,
        mtu: usize,
        now: Instant,
        route: impl FnOnce(IpAddr) -> Option<PeerId>,
    ) -> Action {
        let bytes = packet.as_packet();
        let Ok((header, payload)) = Ipv4Header::parse(bytes) else {
            return Action::Send(packet);
        };
        let (src, dst) = (header.src(), header.dst());
        let translated = self.translated.as_ref().is_some_and(|t| t(dst));
        let fragment = header.more_fragments() || header.fragment_offset() != 0;
        let ceiling = match (translated, fragment) {
            (false, _) => mtu,
            (true, false) => mtu.saturating_sub(TRANSLATION_GROWTH),
            (true, true) => mtu.saturating_sub(TRANSLATION_GROWTH + IPV6_FRAGMENT_HEADER),
        };
        if bytes.len() <= ceiling {
            return Action::Send(packet);
        }

        if header.dont_fragment() {
            let first = header.fragment_offset() == 0;
            if !first || !may_answer_v4(src, dst, header.protocol(), payload) {
                return self.drop("IPv4 DF packet above the ceiling");
            }
            let peer = match self.admit(IpAddr::V4(dst), now, route) {
                Ok(peer) => peer,
                Err(reason) => return Action::Drop(reason),
            };
            self.stats.frag_needed_sent += 1;
            tracing::debug!(%src, %dst, len = bytes.len(), ceiling, "fragmentation needed");
            return Action::Reply(peer, fragmentation_needed(bytes, src, dst, ceiling));
        }

        let header_bytes = &bytes[..header.header_len()];
        let mut payload = payload.to_vec();
        if translated && !fragment && header.protocol() == protocol::UDP {
            fill_udp_checksum(src, dst, &mut payload);
        }
        let Some(fragments) = split_ipv4(header_bytes, &payload, mtu, translated) else {
            return self.drop("IPv4 packet cannot be split under the MTU");
        };
        self.stats.fragmented += 1;
        self.stats.fragments += fragments.len() as u64;
        tracing::trace!(%src, %dst, len = bytes.len(), fragments = fragments.len(), "fragmented");
        Action::Fragments(fragments)
    }

    fn drop(&mut self, why: &'static str) -> Action {
        self.stats.dropped += 1;
        tracing::debug!(why, "oversized local packet dropped");
        Action::Drop(FRAGMENT_OVERSIZE)
    }

    /// The peer to deliver an error about a packet to `dst` from, if it is routed and the
    /// rate limit admits it; otherwise the reason the packet is dropped.
    fn admit(
        &mut self,
        dst: IpAddr,
        now: Instant,
        route: impl FnOnce(IpAddr) -> Option<PeerId>,
    ) -> Result<PeerId, &'static str> {
        let Some(peer) = route(dst) else {
            self.stats.no_route += 1;
            tracing::debug!(%dst, "no route for an ICMP error");
            return Err(FRAGMENT_NO_ROUTE);
        };
        if !self.take_token(now) {
            self.stats.rate_limited += 1;
            return Err(FRAGMENT_RATE_LIMITED);
        }
        Ok(peer)
    }

    fn take_token(&mut self, now: Instant) -> bool {
        let refilled = *self.refilled.get_or_insert(now);
        let elapsed = now.saturating_duration_since(refilled);
        let refill = elapsed.as_nanos() / ICMP_REFILL.as_nanos();
        if refill > 0 {
            let refill = u32::try_from(refill).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(ICMP_BURST);
            self.refilled = Some(
                ICMP_REFILL
                    .checked_mul(refill)
                    .and_then(|d| refilled.checked_add(d))
                    .unwrap_or(now),
            );
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// Whether an error about an IPv6 packet from `src` to `dst` is allowed: not about an
/// `ICMPv6` error, multicast, or a fragment other than the first.
fn may_answer_v6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> bool {
    if src.is_unspecified() || src.is_multicast() || dst.is_unspecified() || dst.is_multicast() {
        return false;
    }
    let (next_header, upper) = if next_header == IPV6_FRAGMENT {
        let Some(fragment) = payload.get(..IPV6_FRAGMENT_HEADER) else {
            return false;
        };
        if u16::from_be_bytes([fragment[2], fragment[3]]) >> 3 != 0 {
            return false;
        }
        (fragment[0], &payload[IPV6_FRAGMENT_HEADER..])
    } else {
        (next_header, payload)
    };
    // ICMPv6 error messages have types below 128.
    next_header != protocol::ICMPV6 || upper.first().is_some_and(|&kind| kind >= 128)
}

/// Whether an error about an IPv4 packet from `src` to `dst` is allowed: not about an ICMP
/// error, multicast or broadcast.
fn may_answer_v4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> bool {
    let unusable = |a: Ipv4Addr| a.is_unspecified() || a.is_multicast() || a.is_broadcast();
    if unusable(src) || unusable(dst) {
        return false;
    }
    // Destination unreachable, source quench, redirect, time exceeded, parameter problem.
    protocol != protocol::ICMP
        || payload
            .first()
            .is_some_and(|k| !matches!(k, 3 | 4 | 5 | 11 | 12))
}

/// An `ICMPv6` Packet Too Big about `original` (from `src` to `dst`) carrying `mtu`, from
/// `dst` to `src`.
fn packet_too_big(original: &[u8], src: Ipv6Addr, dst: Ipv6Addr, mtu: usize) -> PacketBuf {
    let quote = &original[..original.len().min(IPV6_MIN_MTU - IPV6_HEADER - ICMP_HEADER)];
    let body_len = ICMP_HEADER + quote.len();
    let mut packet = PacketBuf::with_capacity(IPV6_HEADER + body_len);
    packet.set_len(IPV6_HEADER + body_len);
    let out = packet.as_packet_mut();
    out[0] = 0x60;
    out[4..6].copy_from_slice(&len_u16(body_len).to_be_bytes());
    out[6] = protocol::ICMPV6;
    out[7] = HOP_LIMIT;
    out[8..24].copy_from_slice(&dst.octets());
    out[24..40].copy_from_slice(&src.octets());
    out[40] = 2;
    let mtu = u32::try_from(mtu).unwrap_or(u32::MAX);
    out[44..48].copy_from_slice(&mtu.to_be_bytes());
    out[48..].copy_from_slice(quote);
    let sum = transport_checksum_v6(dst, src, protocol::ICMPV6, &out[IPV6_HEADER..]);
    out[42..44].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// An ICMP Destination Unreachable / Fragmentation Needed about `original` (from `src` to
/// `dst`) carrying the next-hop `mtu`, from `dst` to `src`.
fn fragmentation_needed(original: &[u8], src: Ipv4Addr, dst: Ipv4Addr, mtu: usize) -> PacketBuf {
    let quote = &original[..original
        .len()
        .min(IPV4_ICMP_ERROR_MAX - IPV4_HEADER - ICMP_HEADER)];
    let total = IPV4_HEADER + ICMP_HEADER + quote.len();
    let mut packet = PacketBuf::with_capacity(total);
    packet.set_len(total);
    let out = packet.as_packet_mut();
    out[0] = 0x45;
    out[2..4].copy_from_slice(&len_u16(total).to_be_bytes());
    out[8] = HOP_LIMIT;
    out[9] = protocol::ICMP;
    out[12..16].copy_from_slice(&dst.octets());
    out[16..20].copy_from_slice(&src.octets());
    let sum = ipv4_header_checksum(&out[..IPV4_HEADER]);
    out[10..12].copy_from_slice(&sum.to_be_bytes());
    let icmp = &mut out[IPV4_HEADER..];
    icmp[0] = 3;
    icmp[1] = 4;
    icmp[6..8].copy_from_slice(&len_u16(mtu).to_be_bytes());
    icmp[ICMP_HEADER..].copy_from_slice(quote);
    let sum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// Fills in the checksum of an unfragmented UDP datagram that has none.
fn fill_udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &mut [u8]) {
    if udp.len() < 8 || udp[6..8] != [0, 0] {
        return;
    }
    let sum = match transport_checksum_v4(src, dst, protocol::UDP, udp) {
        0 => 0xFFFF,
        sum => sum,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
}

/// Splits the IPv4 packet with `header` (options included) and `payload` into fragments
/// that fit `mtu`, once translated with an IPv6 Fragment header if `translated`. Keeps the
/// packet's offset base and MF flag. `None` if the MTU leaves no room for payload.
fn split_ipv4(
    header: &[u8],
    payload: &[u8],
    mtu: usize,
    translated: bool,
) -> Option<Vec<PacketBuf>> {
    let flags = u16::from_be_bytes([header[6], header[7]]);
    let base = usize::from(flags & OFFSET_MASK) * 8;
    let last_more = flags & MF != 0;
    // Later fragments carry only the options with the copied flag.
    let later_header = later_fragment_header(header);

    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let header = if offset == 0 { header } else { &later_header };
        let room = if translated {
            mtu.checked_sub(IPV6_HEADER + IPV6_FRAGMENT_HEADER)?
        } else {
            mtu.checked_sub(header.len())?
        };
        let room = room / 8 * 8;
        if room == 0 {
            return None;
        }
        let end = payload.len().min(offset + room);
        let more = end < payload.len() || last_more;
        let units = u16::try_from((base + offset) / 8)
            .ok()
            .filter(|u| *u <= OFFSET_MASK)?;

        let total = header.len() + end - offset;
        let mut fragment = PacketBuf::with_capacity(total + FRAGMENT_TAIL);
        fragment.set_len(total);
        let out = fragment.as_packet_mut();
        out[..header.len()].copy_from_slice(header);
        out[header.len()..].copy_from_slice(&payload[offset..end]);
        out[2..4].copy_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
        let flags = (flags & !(DF | MF | OFFSET_MASK)) | if more { MF } else { 0 } | units;
        out[6..8].copy_from_slice(&flags.to_be_bytes());
        let sum = ipv4_header_checksum(&out[..header.len()]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        fragments.push(fragment);
        offset = end;
    }
    Some(fragments)
}

/// The header of fragments after the first: `header` with only the options whose copied
/// flag is set, padded to a multiple of 4 bytes.
fn later_fragment_header(header: &[u8]) -> Vec<u8> {
    let mut out = header[..IPV4_HEADER].to_vec();
    let mut options = &header[IPV4_HEADER..];
    while let Some(&kind) = options.first() {
        match kind {
            // End of option list.
            0 => break,
            // No operation.
            1 => options = &options[1..],
            _ => {
                let len = options.get(1).map_or(0, |l| usize::from(*l));
                let Some(option) = options.get(..len).filter(|_| len >= 2) else {
                    break;
                };
                if kind & 0x80 != 0 {
                    out.extend_from_slice(option);
                }
                options = &options[len..];
            }
        }
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    // At most 60 bytes, so the IHL fits.
    out[0] = 0x40 | u8::try_from(out.len() / 4).unwrap_or(5);
    out
}

/// A length bounded by the packet sizes above, as a header field.
fn len_u16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const DST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const PEER: PeerId = PeerId::new(7);

    fn fragmenter(translated: bool) -> Fragmenter {
        Fragmenter::new(FragmentConfig {
            translated: translated.then(|| Arc::new(|dst| dst == DST4) as TranslatedPredicate),
        })
    }

    /// An IPv4 packet of `len` bytes with `options` and a patterned payload.
    fn ipv4(len: usize, protocol: u8, flags: u16, options: &[u8]) -> Vec<u8> {
        let header_len = IPV4_HEADER + options.len();
        let mut p = vec![0; len];
        p[0] = 0x40 | u8::try_from(header_len / 4).unwrap();
        p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6..8].copy_from_slice(&flags.to_be_bytes());
        p[8] = 64;
        p[9] = protocol;
        p[12..16].copy_from_slice(&SRC4.octets());
        p[16..20].copy_from_slice(&DST4.octets());
        p[IPV4_HEADER..header_len].copy_from_slice(options);
        for (i, b) in p[header_len..].iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        if protocol == protocol::UDP && flags & OFFSET_MASK == 0 {
            p[header_len + 4..header_len + 6]
                .copy_from_slice(&u16::try_from(len - header_len).unwrap().to_be_bytes());
            p[header_len + 6..header_len + 8].fill(0);
        }
        let sum = ipv4_header_checksum(&p[..header_len]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    fn ipv6(len: usize, next_header: u8, dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&u16::try_from(len - IPV6_HEADER).unwrap().to_be_bytes());
        p[6] = next_header;
        p[7] = 64;
        p[8..24].copy_from_slice(&SRC6.octets());
        p[24..40].copy_from_slice(&dst.octets());
        for (i, b) in p[IPV6_HEADER..].iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        if next_header == protocol::ICMPV6 {
            p[IPV6_HEADER] = 128;
        }
        p
    }

    fn run(f: &mut Fragmenter, packet: &[u8], mtu: u16, now: Instant) -> Action {
        f.process(PacketBuf::from_packet(packet), mtu, now, |_| Some(PEER))
    }

    /// Checks `fragments` of `original` (headers, offsets, sizes under `mtu`) and returns
    /// the joined payload.
    fn check_fragments(
        original: &[u8],
        fragments: &[PacketBuf],
        mtu: usize,
        translated: bool,
    ) -> Vec<u8> {
        let (orig, _) = Ipv4Header::parse(original).unwrap();
        let base = usize::from(orig.fragment_offset());
        let mut joined = Vec::new();
        for (i, fragment) in fragments.iter().enumerate() {
            let bytes = fragment.as_packet();
            let (h, payload) = Ipv4Header::parse(bytes).unwrap();
            assert_eq!(usize::from(h.total_len()), bytes.len());
            assert_eq!(ipv4_header_checksum(&bytes[..h.header_len()]), h.checksum());
            assert_eq!(internet_checksum(&bytes[..h.header_len()]), 0);
            assert_eq!(h.identification(), orig.identification());
            assert_eq!(h.ttl(), orig.ttl());
            assert!(!h.dont_fragment());
            assert_eq!(usize::from(h.fragment_offset()), base + joined.len());
            let last = i + 1 == fragments.len();
            assert_eq!(h.more_fragments(), !last || orig.more_fragments());
            if !last {
                assert_eq!(payload.len() % 8, 0);
            }
            let size = if translated {
                IPV6_HEADER + IPV6_FRAGMENT_HEADER + payload.len()
            } else {
                bytes.len()
            };
            assert!(size <= mtu, "fragment {i}: {size} > {mtu}");
            assert!(fragment.capacity() >= size + 28);
            joined.extend_from_slice(payload);
        }
        joined
    }

    #[test]
    fn native_ipv4_fragment_boundaries() {
        for mtu in [1280u16, 1420, 1500] {
            let m = usize::from(mtu);
            for len in m - 1..=m + 100 {
                let packet = ipv4(len, protocol::TCP, 0, &[]);
                let mut f = fragmenter(false);
                match run(&mut f, &packet, mtu, Instant::now()) {
                    Action::Send(p) if len <= m => assert_eq!(p.as_packet(), packet),
                    Action::Fragments(fragments) if len > m => {
                        assert_eq!(fragments.len(), 2, "{mtu} {len}");
                        let joined = check_fragments(&packet, &fragments, m, false);
                        assert_eq!(joined, packet[IPV4_HEADER..]);
                        assert_eq!(f.stats().fragmented, 1);
                        assert_eq!(f.stats().fragments, 2);
                    }
                    other => panic!("{mtu} {len}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn translated_ipv4_fragment_boundaries() {
        for mtu in [1280u16, 1420, 1500] {
            let m = usize::from(mtu);
            for len in m - 21..=m + 100 {
                let packet = ipv4(len, protocol::TCP, 0, &[]);
                let mut f = fragmenter(true);
                match run(&mut f, &packet, mtu, Instant::now()) {
                    // Translated: 20 bytes longer, still within the MTU.
                    Action::Send(p) if len + TRANSLATION_GROWTH <= m => {
                        assert_eq!(p.as_packet(), packet);
                    }
                    Action::Fragments(fragments) if len + TRANSLATION_GROWTH > m => {
                        let joined = check_fragments(&packet, &fragments, m, true);
                        assert_eq!(joined, packet[IPV4_HEADER..]);
                    }
                    other => panic!("{mtu} {len}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn large_packets_split_into_many_fragments() {
        let packet = ipv4(9000, protocol::TCP, 0, &[]);
        let Action::Fragments(fragments) =
            run(&mut fragmenter(false), &packet, 1280, Instant::now())
        else {
            panic!("not fragmented");
        };
        // 1256 payload bytes per fragment (1260 rounded down to 8).
        assert_eq!(fragments.len(), 8980usize.div_ceil(1256));
        assert_eq!(
            check_fragments(&packet, &fragments, 1280, false),
            packet[IPV4_HEADER..]
        );
    }

    #[test]
    fn later_fragments_carry_only_copied_options() {
        // Router alert (copied), NOP, record route (not copied, 7 bytes): 12 bytes.
        let options = [0x94, 4, 0, 0, 1, 7, 7, 4, 0, 0, 0, 0];
        let packet = ipv4(3000, protocol::TCP, 0, &options);
        let Action::Fragments(fragments) =
            run(&mut fragmenter(false), &packet, 1500, Instant::now())
        else {
            panic!("not fragmented");
        };
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].as_packet()[0], 0x48);
        assert_eq!(fragments[0].as_packet()[IPV4_HEADER..32], options);
        for later in &fragments[1..] {
            let bytes = later.as_packet();
            assert_eq!(bytes[0], 0x46);
            assert_eq!(bytes[IPV4_HEADER..24], [0x94, 4, 0, 0]);
        }
        assert_eq!(
            check_fragments(&packet, &fragments, 1500, false),
            packet[32..]
        );
    }

    #[test]
    fn fragments_are_refragmented_keeping_offset_and_mf() {
        for flags in [MF | 0x64, 0x64] {
            let packet = ipv4(2000, protocol::UDP, flags, &[]);
            let Action::Fragments(fragments) =
                run(&mut fragmenter(false), &packet, 1280, Instant::now())
            else {
                panic!("not fragmented");
            };
            assert_eq!(fragments.len(), 2);
            let first = Ipv4Header::parse(fragments[0].as_packet()).unwrap().0;
            assert_eq!(first.fragment_offset(), 0x64 * 8);
            assert_eq!(
                check_fragments(&packet, &fragments, 1280, false),
                packet[IPV4_HEADER..]
            );
        }
    }

    #[test]
    fn translated_fragments_leave_room_for_the_fragment_header() {
        // Already a fragment: translated with a fragment header, 28 bytes longer.
        let mtu = 1280;
        let packet = ipv4(mtu - 24, protocol::UDP, MF, &[]);
        let Action::Fragments(fragments) =
            run(&mut fragmenter(true), &packet, 1280, Instant::now())
        else {
            panic!("not fragmented");
        };
        check_fragments(&packet, &fragments, mtu, true);
        let fits = ipv4(mtu - 28, protocol::UDP, MF, &[]);
        assert!(matches!(
            run(&mut fragmenter(true), &fits, 1280, Instant::now()),
            Action::Send(_)
        ));
    }

    #[test]
    fn zero_udp_checksums_are_filled_for_translated_destinations() {
        let packet = ipv4(2000, protocol::UDP, 0, &[]);
        let udp = &packet[IPV4_HEADER..];
        let expected = transport_checksum_v4(SRC4, DST4, protocol::UDP, udp);

        let Action::Fragments(fragments) =
            run(&mut fragmenter(true), &packet, 1280, Instant::now())
        else {
            panic!("not fragmented");
        };
        let joined = check_fragments(&packet, &fragments, 1280, true);
        assert_eq!(joined[6..8], expected.to_be_bytes());
        assert_eq!(transport_checksum_v4(SRC4, DST4, protocol::UDP, &joined), 0);

        // Native destinations keep the zero checksum.
        let Action::Fragments(fragments) =
            run(&mut fragmenter(false), &packet, 1280, Instant::now())
        else {
            panic!("not fragmented");
        };
        assert_eq!(check_fragments(&packet, &fragments, 1280, false), udp);
    }

    /// Recomputes a checksum over `data` with its field at `at` zeroed.
    fn recompute(data: &[u8], at: usize, sum: impl Fn(&[u8]) -> u16) -> u16 {
        let mut data = data.to_vec();
        data[at..at + 2].fill(0);
        sum(&data)
    }

    #[test]
    fn fragmentation_needed_contents() {
        for (translated, ceiling) in [(false, 1420), (true, 1400)] {
            let packet = ipv4(1500, protocol::TCP, DF, &[]);
            let mut f = fragmenter(translated);
            let Action::Reply(peer, reply) = run(&mut f, &packet, 1420, Instant::now()) else {
                panic!("no reply");
            };
            assert_eq!(peer, PEER);
            assert_eq!(f.stats().frag_needed_sent, 1);
            let bytes = reply.as_packet();
            assert_eq!(bytes.len(), IPV4_ICMP_ERROR_MAX);
            let (h, icmp) = Ipv4Header::parse(bytes).unwrap();
            assert_eq!((h.src(), h.dst()), (DST4, SRC4));
            assert_eq!(h.protocol(), protocol::ICMP);
            assert_eq!(h.ttl(), HOP_LIMIT);
            assert_eq!(usize::from(h.total_len()), bytes.len());
            assert_eq!(h.checksum(), recompute(&bytes[..20], 10, internet_checksum));
            assert_eq!((icmp[0], icmp[1]), (3, 4));
            assert_eq!(icmp[4..6], [0, 0]);
            assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), ceiling);
            assert_eq!(
                u16::from_be_bytes([icmp[2], icmp[3]]),
                recompute(icmp, 2, internet_checksum)
            );
            assert_eq!(icmp[8..], packet[..IPV4_ICMP_ERROR_MAX - 28]);
        }
    }

    #[test]
    fn translated_df_packets_use_the_lower_ceiling() {
        let mut f = fragmenter(true);
        let fits = ipv4(1400, protocol::TCP, DF, &[]);
        assert!(matches!(
            run(&mut f, &fits, 1420, Instant::now()),
            Action::Send(_)
        ));
        let above = ipv4(1401, protocol::TCP, DF, &[]);
        assert!(matches!(
            run(&mut f, &above, 1420, Instant::now()),
            Action::Reply(..)
        ));
        // Native IPv4 keeps the full MTU.
        let mut native = fragmenter(false);
        assert!(matches!(
            run(&mut native, &above, 1420, Instant::now()),
            Action::Send(_)
        ));
    }

    #[test]
    fn packet_too_big_contents() {
        for (len, quoted) in [(1421, 1232), (1500, 1232), (9000, 1232)] {
            let packet = ipv6(len, protocol::UDP, DST6);
            let mut f = fragmenter(false);
            let Action::Reply(peer, reply) = run(&mut f, &packet, 1420, Instant::now()) else {
                panic!("no reply");
            };
            assert_eq!(peer, PEER);
            assert_eq!(f.stats().ptb_sent, 1);
            let bytes = reply.as_packet();
            assert_eq!(bytes.len(), IPV6_MIN_MTU);
            let (h, icmp) = Ipv6Header::parse(bytes).unwrap();
            assert_eq!((h.src(), h.dst()), (DST6, SRC6));
            assert_eq!(h.next_header(), protocol::ICMPV6);
            assert_eq!(h.hop_limit(), HOP_LIMIT);
            assert_eq!(icmp.len(), bytes.len() - IPV6_HEADER);
            assert_eq!((icmp[0], icmp[1]), (2, 0));
            assert_eq!(
                u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
                1420
            );
            assert_eq!(
                u16::from_be_bytes([icmp[2], icmp[3]]),
                recompute(icmp, 2, |d| transport_checksum_v6(
                    DST6,
                    SRC6,
                    protocol::ICMPV6,
                    d
                ))
            );
            assert_eq!(icmp[8..], packet[..quoted]);
        }
    }

    #[test]
    fn packet_too_big_quotes_small_packets_whole() {
        let packet = ipv6(1100, protocol::TCP, DST6);
        let Action::Reply(_, reply) = run(&mut fragmenter(false), &packet, 1000, Instant::now())
        else {
            panic!("no reply");
        };
        assert_eq!(reply.len(), IPV6_HEADER + ICMP_HEADER + 1100);
        assert_eq!(reply.as_packet()[48..], packet);
        assert_eq!(reply.as_packet()[44..48], 1000u32.to_be_bytes());
    }

    #[test]
    fn no_errors_about_errors_multicast_or_later_fragments() {
        let mut f = fragmenter(false);
        let now = Instant::now();
        let mut icmp_error = ipv4(1500, protocol::ICMP, DF, &[]);
        icmp_error[IPV4_HEADER] = 3;
        let mut multicast = ipv4(1500, protocol::TCP, DF, &[]);
        multicast[16..20].copy_from_slice(&[224, 0, 0, 1]);
        let mut broadcast = ipv4(1500, protocol::TCP, DF, &[]);
        broadcast[16..20].copy_from_slice(&[255; 4]);
        let later_fragment = ipv4(1500, protocol::TCP, DF | 0xA, &[]);
        let mut icmpv6_error = ipv6(1500, protocol::ICMPV6, DST6);
        icmpv6_error[IPV6_HEADER] = 1;
        let multicast6 = ipv6(1500, protocol::UDP, "ff02::1".parse().unwrap());
        let mut fragment6 = ipv6(1500, IPV6_FRAGMENT, DST6);
        fragment6[IPV6_HEADER..IPV6_HEADER + 8].copy_from_slice(&[17, 0, 0, 0x50, 0, 0, 0, 1]);
        for packet in [
            &icmp_error,
            &multicast,
            &broadcast,
            &later_fragment,
            &icmpv6_error,
            &multicast6,
            &fragment6,
        ] {
            assert!(matches!(
                run(&mut f, packet, 1420, now),
                Action::Drop(FRAGMENT_OVERSIZE)
            ));
        }
        assert_eq!(f.stats().dropped, 7);
        assert_eq!(f.stats().ptb_sent + f.stats().frag_needed_sent, 0);

        // ICMP echo and first fragments are answered.
        let echo = ipv4(1500, protocol::ICMP, DF, &[]);
        let echo6 = ipv6(1500, protocol::ICMPV6, DST6);
        let mut first6 = ipv6(1500, IPV6_FRAGMENT, DST6);
        first6[IPV6_HEADER..IPV6_HEADER + 8].copy_from_slice(&[17, 0, 0, 1, 0, 0, 0, 1]);
        for packet in [&echo, &echo6, &first6] {
            assert!(matches!(run(&mut f, packet, 1420, now), Action::Reply(..)));
        }
    }

    #[test]
    fn errors_are_rate_limited() {
        let mut f = fragmenter(false);
        let packet = ipv6(1500, protocol::UDP, DST6);
        let start = Instant::now();
        let replies = (0..20)
            .filter(|_| matches!(run(&mut f, &packet, 1420, start), Action::Reply(..)))
            .count();
        assert_eq!(replies, 10);
        assert_eq!(f.stats().rate_limited, 10);

        // One token per 200 ms, up to the burst.
        assert!(matches!(
            run(&mut f, &packet, 1420, start + ICMP_REFILL),
            Action::Reply(..)
        ));
        assert!(matches!(
            run(&mut f, &packet, 1420, start + ICMP_REFILL),
            Action::Drop(FRAGMENT_RATE_LIMITED)
        ));
        let later = start + Duration::from_secs(60);
        let replies = (0..20)
            .filter(|_| matches!(run(&mut f, &packet, 1420, later), Action::Reply(..)))
            .count();
        assert_eq!(replies, 10);
    }

    #[test]
    fn errors_without_a_route_are_counted() {
        let mut f = fragmenter(false);
        let packet = ipv4(1500, protocol::TCP, DF, &[]);
        let action = f.process(
            PacketBuf::from_packet(&packet),
            1420,
            Instant::now(),
            |_| None,
        );
        assert!(matches!(action, Action::Drop(FRAGMENT_NO_ROUTE)));
        assert_eq!(f.stats().no_route, 1);
        assert_eq!(f.stats().rate_limited, 0);
        assert_eq!(f.tokens, ICMP_BURST);
    }

    #[test]
    fn packets_within_the_mtu_and_non_ip_pass_unchanged() {
        let mut f = fragmenter(true);
        for packet in [
            ipv4(1400, protocol::TCP, DF, &[]),
            ipv6(1420, 6, DST6),
            vec![0; 2000],
        ] {
            let Action::Send(p) = run(&mut f, &packet, 1420, Instant::now()) else {
                panic!("not sent");
            };
            assert_eq!(p.as_packet(), packet);
        }
        assert_eq!(f.stats(), FragmentStats::default());
    }

    #[test]
    fn tiny_mtus_drop_instead_of_splitting() {
        let mut f = fragmenter(true);
        let packet = ipv4(200, protocol::TCP, 0, &[]);
        assert!(matches!(
            run(&mut f, &packet, 50, Instant::now()),
            Action::Drop(FRAGMENT_OVERSIZE)
        ));
        assert_eq!(f.stats().dropped, 1);
    }
}
