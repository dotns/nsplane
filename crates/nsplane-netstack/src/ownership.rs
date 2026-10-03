//! Packet ownership: which ingress packets belong to the stack's connections and flows.
//!
//! The driver and the UDP handles register the tuple of every TCP connection (opening,
//! open or held half closed), bound UDP socket and UDP flow in one shared table when it
//! opens and remove it when it is gone, so [`NetStackHandle::owns`](crate::NetStackHandle::owns)
//! answers with one short lock and no work per packet when it is not called.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane_packet::{IcmpHeader, IpPacket, UdpHeader, protocol};

use crate::stack::tcp_segment;

/// Whether an ingress packet belongs to the stack, from
/// [`NetStackHandle::owns`](crate::NetStackHandle::owns).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ownership {
    /// The packet belongs to something the stack holds: a TCP connection (open, opening or
    /// half closed), a bound UDP socket or a UDP flow, or it is an ICMP error about a
    /// packet one of them sent.
    Flow,
    /// The packet opens something new the stack accepts: a bare TCP SYN or a UDP datagram
    /// to one of the stack's addresses.
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

/// The stack's addresses and the table of registered tuples.
#[derive(Debug)]
pub(crate) struct Owners {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// Whether the stack reassembles fragments, so they are its packets too.
    reassembly: bool,
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
const ICMP_HEADER: usize = 8;

impl Owners {
    pub(crate) fn new(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, reassembly: bool) -> Self {
        Self {
            v4,
            v6,
            reassembly,
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

    /// Registers the UDP flow from `remote` to `local`.
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

    fn is_local(&self, addr: IpAddr) -> bool {
        self.local_for(addr) == Some(addr)
    }

    /// Classifies an ingress packet, see [`NetStackHandle::owns`](crate::NetStackHandle::owns).
    pub(crate) fn owns(&self, packet: &[u8]) -> Ownership {
        let Ok(ip) = IpPacket::parse(packet) else {
            return Ownership::None;
        };
        if !self.is_local(ip.dst()) {
            return Ownership::None;
        }
        let (src, dst) = (ip.src(), ip.dst());
        if let Some((proto, transport)) = fragment_transport(&ip) {
            return if self.reassembly {
                self.fragment(proto, src, dst, transport)
            } else {
                Ownership::None
            };
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
    /// tuple is registered, `Listener` for any other (a later fragment carries no ports).
    fn fragment(&self, proto: u8, src: IpAddr, dst: IpAddr, transport: Option<&[u8]>) -> Ownership {
        if proto != protocol::TCP && proto != protocol::UDP {
            return Ownership::None;
        }
        let Some(&[src_hi, src_lo, dst_hi, dst_lo]) = transport.and_then(|t| t.get(..4)) else {
            return Ownership::Listener;
        };
        let local = SocketAddr::new(dst, u16::from_be_bytes([dst_hi, dst_lo]));
        let remote = SocketAddr::new(src, u16::from_be_bytes([src_hi, src_lo]));
        let owned = if proto == protocol::TCP {
            self.lock().contains_key(&Key::Tcp(local, remote))
        } else {
            self.udp_registered(local, remote)
        };
        if owned {
            Ownership::Flow
        } else {
            Ownership::Listener
        }
    }

    /// Whether a UDP datagram from `remote` to `local` reaches a bound socket or a flow.
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
        let Some((proto, local, remote)) = icmp.get(ICMP_HEADER..).and_then(quoted_tuple) else {
            return Ownership::None;
        };
        if !self.is_local(local.ip()) {
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

/// IPv6 next-header values of the extension headers that may precede a Fragment header,
/// and of the Fragment header.
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const DESTINATION_OPTIONS: u8 = 60;
const FRAGMENT: u8 = 44;

/// For an IPv4 fragment or an IPv6 packet with a Fragment header: the fragmented
/// protocol and, for the first fragment, the bytes the transport header starts in.
fn fragment_transport<'a>(ip: &IpPacket<'a>) -> Option<(u8, Option<&'a [u8]>)> {
    let payload = ip.payload();
    match ip {
        IpPacket::V4 { .. } => {
            let fragment = ip.fragment()?;
            Some((ip.protocol(), fragment.is_first().then_some(payload)))
        }
        IpPacket::V6 { .. } => {
            let mut next = ip.protocol();
            let mut at = 0;
            while matches!(next, HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS) {
                let (&following, &len) = (payload.get(at)?, payload.get(at + 1)?);
                next = following;
                at += (usize::from(len) + 1) * 8;
            }
            if next != FRAGMENT {
                return None;
            }
            let &[inner, _, offset_hi, offset_lo, ..] = payload.get(at..at + 8)? else {
                return None;
            };
            let first = u16::from_be_bytes([offset_hi, offset_lo]) >> 3 == 0;
            Some((inner, first.then(|| payload.get(at + 8..)).flatten()))
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

/// The protocol and `(source, destination)` of the TCP or UDP packet an ICMP error quotes,
/// which may be truncated after the ports. A non-first IPv4 fragment carries no ports.
fn quoted_tuple(quoted: &[u8]) -> Option<(u8, SocketAddr, SocketAddr)> {
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
    ))
}
