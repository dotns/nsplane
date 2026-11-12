//! Packet ownership: which ingress packets belong to the stack's connections and flows.
//!
//! The driver and the UDP handles register the tuple of every TCP connection (opening,
//! open or held half closed), bound or connected UDP socket and UDP flow in one shared table when it
//! opens and remove it when it is gone, so [`NetStackHandle::owns`](crate::NetStackHandle::owns)
//! answers with one short lock and no work per packet when it is not called.
//!
//! With reassembly, the same struct keeps a short memory per fragmented datagram: the
//! datagrams discarded with [`NetStackHandle::discard_fragments`](crate::NetStackHandle::discard_fragments),
//! whose fragments the driver drops, and the first fragments `owns` classified as a flow's.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane_packet::reassembly::ReassemblyConfig;
use nsplane_packet::{ExtensionWalker, IcmpHeader, IpPacket, UdpHeader, protocol};

use crate::config::Prefixes;
use crate::stack::tcp_segment;

/// Whether an ingress packet belongs to the stack, from
/// [`NetStackHandle::owns`](crate::NetStackHandle::owns).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ownership {
    /// The packet belongs to something the stack holds: a TCP connection (open, opening or
    /// half closed), a bound UDP socket, a connected UDP socket (from its remote only) or a
    /// UDP flow, or it is an ICMP error about a packet one of them sent.
    Flow,
    /// The packet opens something new the stack accepts: a bare TCP SYN or a UDP datagram
    /// to one of the stack's addresses, or in transparent mode to an in-prefix address.
    Listener,
    /// The packet is not the stack's.
    None,
}

/// What a registration holds. Addresses are `(local, remote)` from the stack's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Tcp(SocketAddr, SocketAddr),
    UdpFlow(SocketAddr, SocketAddr),
    UdpBound(SocketAddr),
}

/// One fragmented datagram, keyed as the reassembler keys it: the protocol only counts
/// for IPv4 (RFC 791), IPv6 identifies a datagram by its addresses and id (RFC 8200).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}

impl FragmentKey {
    const fn new(src: IpAddr, dst: IpAddr, protocol: u8, id: u32) -> Self {
        let protocol = if src.is_ipv4() { protocol } else { 0 };
        Self {
            src,
            dst,
            protocol,
            id,
        }
    }
}

/// The per-datagram memory of a stack that reassembles; entries live for the reassembly
/// timeout and each map holds at most the reassembler's `max_datagrams`.
#[derive(Debug)]
struct Fragments {
    timeout: Duration,
    limit: usize,
    /// Whether `discarded` may hold an entry, so the driver takes no lock while it is empty.
    discarding: AtomicBool,
    state: Mutex<FragmentState>,
}

#[derive(Debug, Default)]
struct FragmentState {
    /// Datagrams discarded by the handle, with the time of the call.
    discarded: HashMap<FragmentKey, Instant>,
    /// Datagrams whose first fragment `owns` classified as `Flow`, with the time.
    flows: HashMap<FragmentKey, Instant>,
}

impl Fragments {
    fn lock(&self) -> std::sync::MutexGuard<'_, FragmentState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether an entry made `at` still holds at `now`; the reassembler keeps a datagram
    /// exactly as long after its first fragment.
    fn live(&self, at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(at) < self.timeout
    }

    /// Records `key` at `now` in `map`, making room at the bound by dropping the expired
    /// entries, then the oldest one.
    fn remember(&self, map: &mut HashMap<FragmentKey, Instant>, key: FragmentKey, now: Instant) {
        if !map.contains_key(&key) && map.len() >= self.limit {
            map.retain(|_, &mut at| self.live(at, now));
            if map.len() >= self.limit
                && let Some(oldest) = map.iter().min_by_key(|&(_, &at)| at).map(|(&k, _)| k)
            {
                map.remove(&oldest);
            }
        }
        map.insert(key, now);
    }
}

/// The current time on the clock the driver gives the reassembler.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The stack's addresses and the table of registered tuples.
#[derive(Debug)]
pub(crate) struct Owners {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// The destination prefixes the stack accepts besides its addresses; only in
    /// transparent mode.
    transparent: Option<Prefixes>,
    /// Only when the stack reassembles fragments, so they are its packets too.
    fragments: Option<Fragments>,
    /// Registrations per key; a key can be held more than once (a connect registered by
    /// the handle and again by the driver).
    table: Mutex<HashMap<Key, usize>>,
}

/// One entry in the table, removed when dropped.
#[derive(Debug)]
pub(crate) struct Registration {
    owners: Arc<Owners>,
    key: Key,
}

impl Registration {
    /// Whether this registers the TCP tuple from `local` to `remote`.
    pub(crate) fn is(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.key == Key::Tcp(local, remote)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut table = self.owners.lock();
        if let Some(count) = table.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                table.remove(&self.key);
            }
        }
    }
}

/// IPv4 ICMP errors that quote the offending packet: destination unreachable, time
/// exceeded, parameter problem.
const ICMP_ERRORS: [u8; 3] = [3, 11, 12];
/// IPv6 ICMP errors that quote the offending packet: destination unreachable, packet too
/// big, time exceeded, parameter problem.
const ICMPV6_ERRORS: [u8; 4] = [1, 2, 3, 4];
/// ICMP header length before the quoted packet.
pub(crate) const ICMP_HEADER: usize = 8;

impl Owners {
    pub(crate) fn new(
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        transparent: Option<Prefixes>,
        reassembly: Option<&ReassemblyConfig>,
    ) -> Self {
        Self {
            v4,
            v6,
            transparent,
            fragments: reassembly.map(|config| Fragments {
                timeout: config.timeout,
                limit: config.max_datagrams.max(1),
                discarding: AtomicBool::new(false),
                state: Mutex::default(),
            }),
            table: Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, usize>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(self: &Arc<Self>, key: Key) -> Registration {
        *self.lock().entry(key).or_insert(0) += 1;
        Registration {
            owners: Arc::clone(self),
            key,
        }
    }

    /// Registers a TCP connection from `local` to `remote`.
    pub(crate) fn tcp(self: &Arc<Self>, local: SocketAddr, remote: SocketAddr) -> Registration {
        self.register(Key::Tcp(local, remote))
    }

    /// Registers the UDP flow from `remote` to `local`, or a UDP socket connected from
    /// `local` to `remote`.
    pub(crate) fn udp_flow(
        self: &Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Registration {
        self.register(Key::UdpFlow(local, remote))
    }

    /// Registers a UDP socket bound to `local`.
    pub(crate) fn udp_bound(self: &Arc<Self>, local: SocketAddr) -> Registration {
        self.register(Key::UdpBound(local))
    }

    /// The stack's address of `peer`'s family.
    pub(crate) fn local_for(&self, peer: IpAddr) -> Option<IpAddr> {
        match peer {
            IpAddr::V4(_) => self.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
    }

    /// Whether the stack accepts packets to `addr`: one of its addresses, or in
    /// transparent mode an in-prefix address.
    fn accepts(&self, addr: IpAddr) -> bool {
        self.local_for(addr) == Some(addr)
            || self
                .transparent
                .as_ref()
                .is_some_and(|prefixes| prefixes.contains(addr))
    }

    /// Whether the TCP tuple from `local` to `remote` is registered.
    pub(crate) fn has_tcp(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.lock().contains_key(&Key::Tcp(local, remote))
    }

    /// Classifies an ingress packet, see [`NetStackHandle::owns`](crate::NetStackHandle::owns).
    pub(crate) fn owns(&self, packet: &[u8]) -> Ownership {
        let Ok(ip) = IpPacket::parse(packet) else {
            return Ownership::None;
        };
        if !self.accepts(ip.dst()) {
            return Ownership::None;
        }
        let (src, dst) = (ip.src(), ip.dst());
        if let Some((proto, id, transport)) = fragment_transport(&ip) {
            return self
                .fragments
                .as_ref()
                .map_or(Ownership::None, |fragments| {
                    self.fragment(fragments, proto, id, src, dst, transport)
                });
        }
        // TCP first: the stack accepts TCP behind one IPv6 Hop-by-Hop header.
        if let Some(segment) = tcp_segment(packet) {
            let Some((src_port, dst_port, flags)) = tcp_ports_flags(segment) else {
                return Ownership::None;
            };
            let local = SocketAddr::new(dst, dst_port);
            let remote = SocketAddr::new(src, src_port);
            if self.lock().contains_key(&Key::Tcp(local, remote)) {
                return Ownership::Flow;
            }
            return if flags & SYN != 0 && flags & ACK == 0 {
                Ownership::Listener
            } else {
                Ownership::None
            };
        }
        match ip.protocol() {
            protocol::UDP => {
                let Ok((udp, _)) = UdpHeader::parse(ip.payload()) else {
                    return Ownership::None;
                };
                let local = SocketAddr::new(dst, udp.dst_port());
                let remote = SocketAddr::new(src, udp.src_port());
                if self.udp_registered(local, remote) {
                    Ownership::Flow
                } else {
                    Ownership::Listener
                }
            }
            protocol::ICMP if ip.src().is_ipv4() => self.icmp_error(ip.payload(), &ICMP_ERRORS),
            protocol::ICMPV6 if ip.src().is_ipv6() => self.icmp_error(ip.payload(), &ICMPV6_ERRORS),
            _ => Ownership::None,
        }
    }

    /// A TCP or UDP fragment the stack reassembles: `Flow` for a first fragment whose
    /// tuple is registered, remembered for the later fragments of its datagram, which
    /// carry no ports; `Listener` for any other.
    fn fragment(
        &self,
        fragments: &Fragments,
        proto: u8,
        id: u32,
        src: IpAddr,
        dst: IpAddr,
        transport: Option<&[u8]>,
    ) -> Ownership {
        if proto != protocol::TCP && proto != protocol::UDP {
            return Ownership::None;
        }
        let key = FragmentKey::new(src, dst, proto, id);
        let Some(transport) = transport else {
            let flow = fragments
                .lock()
                .flows
                .get(&key)
                .is_some_and(|&at| fragments.live(at, now()));
            return if flow {
                Ownership::Flow
            } else {
                Ownership::Listener
            };
        };
        let Some(&[src_hi, src_lo, dst_hi, dst_lo]) = transport.get(..4) else {
            return Ownership::Listener;
        };
        let local = SocketAddr::new(dst, u16::from_be_bytes([dst_hi, dst_lo]));
        let remote = SocketAddr::new(src, u16::from_be_bytes([src_hi, src_lo]));
        let owned = if proto == protocol::TCP {
            self.lock().contains_key(&Key::Tcp(local, remote))
        } else {
            self.udp_registered(local, remote)
        };
        if !owned {
            return Ownership::Listener;
        }
        let now = now();
        let mut state = fragments.lock();
        // A discarded datagram's later fragments are dropped, not a flow's.
        if !state
            .discarded
            .get(&key)
            .is_some_and(|&at| fragments.live(at, now))
        {
            fragments.remember(&mut state.flows, key, now);
        }
        Ownership::Flow
    }

    /// Drops what the stack knows of the datagram `(src, dst, protocol, id)` and makes the
    /// driver drop its fragments for the reassembly timeout; nothing without reassembly.
    pub(crate) fn discard_fragments(&self, src: IpAddr, dst: IpAddr, protocol: u8, id: u32) {
        let Some(fragments) = &self.fragments else {
            return;
        };
        let key = FragmentKey::new(src, dst, protocol, id);
        let mut state = fragments.lock();
        state.flows.remove(&key);
        fragments.remember(&mut state.discarded, key, now());
        fragments.discarding.store(true, Ordering::Release);
    }

    /// Whether `ip` is a fragment of a discarded datagram, at `now`. One atomic load while
    /// nothing is discarded.
    pub(crate) fn is_discarded(&self, ip: &IpPacket<'_>, now: Instant) -> bool {
        let Some(fragments) = &self.fragments else {
            return false;
        };
        if !fragments.discarding.load(Ordering::Acquire) {
            return false;
        }
        let Some((proto, id, _)) = fragment_transport(ip) else {
            return false;
        };
        let key = FragmentKey::new(ip.src(), ip.dst(), proto, id);
        fragments
            .lock()
            .discarded
            .get(&key)
            .is_some_and(|&at| fragments.live(at, now))
    }

    /// Forgets the discarded datagrams past the reassembly timeout at `now`; one atomic
    /// load while nothing is discarded.
    pub(crate) fn expire_discarded(&self, now: Instant) {
        let Some(fragments) = &self.fragments else {
            return;
        };
        if !fragments.discarding.load(Ordering::Acquire) {
            return;
        }
        let mut state = fragments.lock();
        state.discarded.retain(|_, &mut at| fragments.live(at, now));
        if state.discarded.is_empty() {
            fragments.discarding.store(false, Ordering::Release);
        }
    }

    /// Whether a UDP datagram from `remote` to `local` reaches a bound or connected socket
    /// or a flow.
    fn udp_registered(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        let unspecified = match local.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let table = self.lock();
        table.contains_key(&Key::UdpBound(local))
            || table.contains_key(&Key::UdpBound(SocketAddr::new(unspecified, local.port())))
            || table.contains_key(&Key::UdpFlow(local, remote))
    }

    /// `Flow` for an ICMP error of one of `errors` quoting a packet the stack sent on a
    /// registered tuple.
    fn icmp_error(&self, icmp: &[u8], errors: &[u8]) -> Ownership {
        let Ok((header, _)) = IcmpHeader::parse(icmp) else {
            return Ownership::None;
        };
        if !errors.contains(&header.icmp_type()) {
            return Ownership::None;
        }
        let Some((proto, local, remote, _)) = icmp.get(ICMP_HEADER..).and_then(quoted_tuple) else {
            return Ownership::None;
        };
        if !self.accepts(local.ip()) {
            return Ownership::None;
        }
        let owned = match proto {
            protocol::TCP => self.lock().contains_key(&Key::Tcp(local, remote)),
            _ => self.udp_registered(local, remote),
        };
        if owned {
            Ownership::Flow
        } else {
            Ownership::None
        }
    }
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

/// For an IPv4 fragment or an IPv6 packet with a Fragment header: the fragmented
/// protocol, the identification and, for the first fragment, the bytes the transport
/// header starts in.
fn fragment_transport<'a>(ip: &IpPacket<'a>) -> Option<(u8, u32, Option<&'a [u8]>)> {
    let payload = ip.payload();
    match ip {
        IpPacket::V4 { .. } => {
            let fragment = ip.fragment()?;
            Some((
                ip.protocol(),
                u32::from(fragment.id),
                fragment.is_first().then_some(payload),
            ))
        }
        IpPacket::V6 { .. } => {
            let mut walker = ExtensionWalker::new(payload, ip.protocol(), 0);
            while matches!(
                walker.next_header(),
                protocol::IPV6_HOP_BY_HOP
                    | protocol::IPV6_ROUTING
                    | protocol::IPV6_DESTINATION_OPTIONS
            ) {
                walker.step().ok()?;
            }
            if walker.next_header() != protocol::IPV6_FRAGMENT {
                return None;
            }
            let fragment = walker.step().ok()??.fragment()?;
            Some((
                walker.next_header(),
                fragment.id,
                fragment
                    .is_first()
                    .then(|| payload.get(walker.offset()..))
                    .flatten(),
            ))
        }
    }
}

/// Source port, destination port and flags of a TCP segment with a complete header.
fn tcp_ports_flags(segment: &[u8]) -> Option<(u16, u16, u8)> {
    let header = segment.get(..20)?;
    let data_offset = usize::from(header[12] >> 4) * 4;
    if data_offset < 20 || data_offset > segment.len() {
        return None;
    }
    Some((
        u16::from_be_bytes([header[0], header[1]]),
        u16::from_be_bytes([header[2], header[3]]),
        header[13],
    ))
}

/// The protocol, `(source, destination)` and transport header bytes of the TCP or UDP
/// packet an ICMP error quotes, which may be truncated after the ports. A non-first IPv4
/// fragment carries no ports.
pub(crate) fn quoted_tuple(quoted: &[u8]) -> Option<(u8, SocketAddr, SocketAddr, &[u8])> {
    let (proto, src, dst, transport) = match quoted.first()? >> 4 {
        4 => {
            let header = quoted.get(..20)?;
            let ihl = usize::from(header[0] & 0xf) * 4;
            let offset = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
            if ihl < 20 || offset != 0 {
                return None;
            }
            let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
            let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
            (
                header[9],
                IpAddr::V4(src),
                IpAddr::V4(dst),
                quoted.get(ihl..)?,
            )
        }
        6 => {
            let header = quoted.get(..40)?;
            let src: [u8; 16] = header[8..24].try_into().ok()?;
            let dst: [u8; 16] = header[24..40].try_into().ok()?;
            (
                header[6],
                IpAddr::V6(src.into()),
                IpAddr::V6(dst.into()),
                &quoted[40..],
            )
        }
        _ => return None,
    };
    if proto != protocol::TCP && proto != protocol::UDP {
        return None;
    }
    let ports = transport.get(..4)?;
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    Some((
        proto,
        SocketAddr::new(src, src_port),
        SocketAddr::new(dst, dst_port),
        transport,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOP_BY_HOP: u8 = protocol::IPV6_HOP_BY_HOP;
    const ROUTING: u8 = protocol::IPV6_ROUTING;
    const DESTINATION_OPTIONS: u8 = protocol::IPV6_DESTINATION_OPTIONS;
    const FRAGMENT: u8 = protocol::IPV6_FRAGMENT;

    /// An IPv6 packet whose first next header is `next` and whose payload is `payload`.
    fn v6(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&[next, 64]);
        packet.extend_from_slice(&[0xfd; 32]);
        packet.extend_from_slice(payload);
        packet
    }

    /// A Hop-by-Hop, Routing or Destination Options header of `units` 8-byte units
    /// followed by `next`.
    fn options(next: u8, units: u8) -> Vec<u8> {
        let mut header = vec![0_u8; usize::from(units) * 8];
        header[..2].copy_from_slice(&[next, units - 1]);
        header
    }

    /// A Fragment header followed by `inner`, at 8-byte unit `offset` of its datagram.
    fn fragment(inner: u8, offset: u16, id: u32) -> Vec<u8> {
        let mut header = vec![inner, 0];
        header.extend_from_slice(&((offset << 3) | 1).to_be_bytes());
        header.extend_from_slice(&id.to_be_bytes());
        header
    }

    /// [`fragment_transport`] of `packet`, the transport bytes owned.
    fn found(packet: &[u8]) -> Option<(u8, u32, Option<Vec<u8>>)> {
        let ip = IpPacket::parse(packet).unwrap();
        fragment_transport(&ip)
            .map(|(proto, id, transport)| (proto, id, transport.map(<[u8]>::to_vec)))
    }

    #[test]
    fn the_ipv6_fragment_header_is_found_behind_options_headers() {
        let data = [7_u8; 8];
        let chains = [
            Vec::new(),
            vec![options(FRAGMENT, 1)],
            vec![options(ROUTING, 255), options(FRAGMENT, 2)],
            vec![
                options(DESTINATION_OPTIONS, 1),
                options(ROUTING, 2),
                options(FRAGMENT, 1),
            ],
            vec![options(DESTINATION_OPTIONS, 1); 99]
                .into_iter()
                .chain([options(FRAGMENT, 1)])
                .collect(),
        ];
        for chain in chains {
            let first = if chain.is_empty() {
                FRAGMENT
            } else {
                HOP_BY_HOP
            };
            for (offset, transport) in [(0, Some(data.to_vec())), (3, None)] {
                let mut payload = chain.concat();
                payload.extend_from_slice(&fragment(protocol::UDP, offset, 0x0102_0304));
                payload.extend_from_slice(&data);
                assert_eq!(
                    found(&v6(first, &payload)),
                    Some((protocol::UDP, 0x0102_0304, transport)),
                    "{} headers, offset {offset}",
                    chain.len()
                );
            }
        }
        // A first fragment without data has empty transport bytes.
        assert_eq!(
            found(&v6(FRAGMENT, &fragment(protocol::TCP, 0, 9))),
            Some((protocol::TCP, 9, Some(Vec::new())))
        );
    }

    #[test]
    fn ipv6_chains_without_a_whole_fragment_header_are_not_fragments() {
        let header = fragment(protocol::UDP, 0, 5);
        let behind = |options: Vec<u8>| [options, header.clone(), vec![0; 8]].concat();
        // An options header whose length runs past the payload.
        let overlong = |next: u8| {
            let mut options = options(next, 1);
            options[1] = 9;
            options
        };
        for (name, packet) in [
            ("no extension header", v6(protocol::UDP, &[0; 8])),
            (
                "options before UDP",
                v6(HOP_BY_HOP, &behind(options(protocol::UDP, 1))),
            ),
            (
                "an Authentication Header is not walked",
                v6(51, &behind(vec![FRAGMENT, 0, 0, 0, 0, 0, 0, 0])),
            ),
            ("an empty payload", v6(HOP_BY_HOP, &[])),
            ("one byte of an options header", v6(ROUTING, &[FRAGMENT])),
            ("no Fragment header", v6(FRAGMENT, &[])),
            ("a cut Fragment header", v6(FRAGMENT, &header[..7])),
            (
                "a cut Fragment header behind options",
                v6(
                    HOP_BY_HOP,
                    &[options(FRAGMENT, 2), header[..4].to_vec()].concat(),
                ),
            ),
            (
                "an overlong options header before UDP",
                v6(HOP_BY_HOP, &behind(overlong(protocol::UDP))),
            ),
            (
                "an overlong options header before another",
                v6(DESTINATION_OPTIONS, &behind(overlong(ROUTING))),
            ),
            (
                "an overlong options header before a Fragment header",
                v6(HOP_BY_HOP, &behind(overlong(FRAGMENT))),
            ),
        ] {
            assert_eq!(found(&packet), None, "{name}");
        }
    }
}
