//! The smoltcp device between the driver's queues and the interface.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane_packet::{PacketBuf, PacketPool};
use smoltcp::iface::{Interface, PollIngressSingleResult, PollResult, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::stats::{self, Counters};

/// Idle buffers the device keeps for reuse.
const POOL_SIZE: usize = 256;

/// RX token that hands a packet to smoltcp, then recycles its buffer for egress.
pub(crate) struct VirtualRxToken<'a> {
    packet: PacketBuf,
    pool: &'a RefCell<PacketPool>,
}

impl RxToken for VirtualRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(self.packet.as_packet());
        if let Ok(mut pool) = self.pool.try_borrow_mut() {
            pool.put(self.packet);
        }
        result
    }
}

/// Per TCP connection, keyed by `(local, remote)`: the highest acknowledgement number the
/// peer sent, once it sent one. See [`fix_ack_seq`].
pub(crate) type PeerAcks = HashMap<(SocketAddr, SocketAddr), Option<u32>>;

/// TX token that appends a packet to the bounded egress backlog.
///
/// smoltcp only asks for a TX token through [`Device::transmit`] while the backlog has
/// room. A token handed out with an RX token (an immediate reply to an ingested packet)
/// can still find the backlog full; that packet is dropped and counted. Every TCP segment
/// passes [`fix_ack_seq`] on its way out.
pub(crate) struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<PacketBuf>,
    acks: &'a PeerAcks,
    limit: usize,
    mtu: usize,
    pool: &'a RefCell<PacketPool>,
    stats: &'a Counters,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let capacity = len.max(self.mtu);
        let mut packet = self.pool.try_borrow_mut().map_or_else(
            |_| PacketBuf::with_capacity(capacity),
            |mut pool| pool.get(capacity),
        );
        packet.set_len(len);
        let result = f(packet.as_packet_mut());
        fix_ack_seq(packet.as_packet_mut(), self.acks);
        if self.queue.len() < self.limit {
            self.queue.push_back(packet);
        } else {
            stats::add(&self.stats.egress_full, 1);
            if let Ok(mut pool) = self.pool.try_borrow_mut() {
                pool.put(packet);
            }
        }
        result
    }
}

/// Virtual IP-medium device: ingress packets in, egress packets out.
pub(crate) struct VirtualDevice {
    pub(crate) rx_queue: VecDeque<PacketBuf>,
    pub(crate) tx_queue: VecDeque<PacketBuf>,
    /// See [`fix_ack_seq`]; the driver adds an entry when it hands a connection to the
    /// application and removes it when it releases the socket.
    pub(crate) peer_acks: PeerAcks,
    tx_limit: usize,
    mtu: usize,
    pool: RefCell<PacketPool>,
    stats: Arc<Counters>,
}

impl VirtualDevice {
    /// Creates a device with an `mtu`-byte MTU and an egress backlog of `tx_limit` packets.
    pub(crate) fn new(mtu: u16, tx_limit: usize, stats: Arc<Counters>) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            peer_acks: HashMap::new(),
            tx_limit,
            mtu: usize::from(mtu),
            pool: RefCell::new(PacketPool::new(POOL_SIZE)),
            stats,
        }
    }

    /// Enqueues a packet for smoltcp to receive.
    pub(crate) fn inject(&mut self, packet: PacketBuf) {
        self.rx_queue.push_back(packet);
    }

    /// Whether the egress backlog is full.
    pub(crate) fn tx_full(&self) -> bool {
        self.tx_queue.len() >= self.tx_limit
    }

    /// Ingests every queued packet, giving smoltcp one egress turn after each one (and one
    /// turn if nothing was queued).
    ///
    /// A single egress turn sends at most one packet per socket, so the work per ingested
    /// packet stays bounded and the backlog cannot be flooded by one call; smoltcp's own
    /// `poll` would drain all egress instead.
    pub(crate) fn poll_interface(
        &mut self,
        interface: &mut Interface,
        timestamp: Instant,
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        interface.poll_maintenance(timestamp);
        let mut result = PollResult::None;
        let mut ingested = false;
        loop {
            match interface.poll_ingress_single(timestamp, self, sockets) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => {
                    result = PollResult::SocketStateChanged;
                }
            }
            ingested = true;
            if interface.poll_egress(timestamp, self, sockets) == PollResult::SocketStateChanged {
                result = PollResult::SocketStateChanged;
            }
        }
        if !ingested
            && interface.poll_egress(timestamp, self, sockets) == PollResult::SocketStateChanged
        {
            result = PollResult::SocketStateChanged;
        }
        result
    }

    /// Takes every packet smoltcp wants to transmit.
    #[cfg(test)]
    pub(crate) fn drain_tx(&mut self) -> impl Iterator<Item = PacketBuf> + '_ {
        self.tx_queue.drain(..)
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        let rx = VirtualRxToken {
            packet,
            pool: &self.pool,
        };
        let tx = VirtualTxToken {
            queue: &mut self.tx_queue,
            acks: &self.peer_acks,
            limit: self.tx_limit,
            mtu: self.mtu,
            pool: &self.pool,
            stats: &self.stats,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.tx_queue.len() < self.tx_limit).then(|| VirtualTxToken {
            queue: &mut self.tx_queue,
            acks: &self.peer_acks,
            limit: self.tx_limit,
            mtu: self.mtu,
            pool: &self.pool,
            stats: &self.stats,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Records the acknowledgement number of an incoming TCP segment for its connection, if
/// the connection has an entry (see [`fix_ack_seq`]).
pub(crate) fn note_peer_ack(packet: &[u8], acks: &mut PeerAcks) {
    let Some((offset, remote, local)) = tcp_flow(packet) else {
        return;
    };
    let Some(segment) = packet.get(offset..offset + 20) else {
        return;
    };
    if segment[13] & TCP_ACK == 0 {
        return;
    }
    if let Some(high) = acks.get_mut(&(local, remote)) {
        let ack = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
        if high.is_none_or(|high| seq_after(ack, high)) {
            *high = Some(ack);
        }
    }
}

/// Moves the sequence number of an outgoing pure ACK up to the peer's acknowledgement.
///
/// After a retransmission timeout smoltcp 0.14 rewinds its next sequence number to the
/// oldest byte it saw acknowledged and stamps its pure ACKs with it. When the peer had
/// already received past that point (only its ACKs were lost), those ACKs fall before the
/// peer's receive window and the peer drops them together with the acknowledgement they
/// carry. Once both ends of a connection are in that state, each resends data the other
/// already has and neither learns that it arrived: the connection stalls for good.
///
/// The highest acknowledgement number the peer sent is where the peer's window starts,
/// and smoltcp accepts a pure ACK there whatever its window. The driver records it from
/// every incoming segment (smoltcp may drop the segment, but its acknowledgement is
/// still the peer's), and a pure ACK whose sequence number lies before it is moved up to
/// it, adjusting the checksum. Segments with data, SYN, FIN or RST pass unchanged.
pub(crate) fn fix_ack_seq(packet: &mut [u8], acks: &PeerAcks) {
    let Some((offset, local, remote)) = tcp_flow(packet) else {
        return;
    };
    let Some(&Some(peer_ack)) = acks.get(&(local, remote)) else {
        return;
    };
    let Some(segment) = packet.get_mut(offset..) else {
        return;
    };
    let header_len = segment.get(12).map_or(0, |byte| usize::from(byte >> 4) * 4);
    if header_len < 20 || segment.len() != header_len {
        return;
    }
    let flags = segment[13];
    if flags & (TCP_SYN | TCP_FIN | TCP_RST) != 0 || flags & TCP_ACK == 0 {
        return;
    }
    let seq = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    if seq_after(peer_ack, seq) {
        let sum = u16::from_be_bytes([segment[16], segment[17]]);
        let sum = adjust_checksum(sum, seq.to_be_bytes(), peer_ack.to_be_bytes());
        segment[4..8].copy_from_slice(&peer_ack.to_be_bytes());
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
    }
}

/// Whether sequence number `a` lies after `b` (modulo 2^32).
const fn seq_after(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 1 << 31
}

/// The TCP header offset and the `(source, destination)` endpoints of an IP packet that
/// carries TCP directly after its fixed header. smoltcp emits no IPv6 extension headers;
/// an incoming packet with one is not recorded, which only forgoes the fix.
fn tcp_flow(packet: &[u8]) -> Option<(usize, SocketAddr, SocketAddr)> {
    let (offset, src, dst): (usize, IpAddr, IpAddr) = match packet.first()? >> 4 {
        4 if *packet.get(9)? == nsplane_packet::protocol::TCP => {
            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            (
                usize::from(packet[0] & 0x0f) * 4,
                Ipv4Addr::from(src).into(),
                Ipv4Addr::from(dst).into(),
            )
        }
        6 if *packet.get(6)? == nsplane_packet::protocol::TCP => {
            let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            (40, Ipv6Addr::from(src).into(), Ipv6Addr::from(dst).into())
        }
        _ => return None,
    };
    let ports = packet.get(offset..offset + 4)?;
    Some((
        offset,
        SocketAddr::new(src, u16::from_be_bytes([ports[0], ports[1]])),
        SocketAddr::new(dst, u16::from_be_bytes([ports[2], ports[3]])),
    ))
}

/// The internet checksum `sum` after the 32-bit field `old` became `new` (RFC 1624).
fn adjust_checksum(sum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let mut acc = u32::from(!sum);
    for i in [0, 2] {
        acc += u32::from(!u16::from_be_bytes([old[i], old[i + 1]]));
        acc += u32::from(u16::from_be_bytes([new[i], new[i + 1]]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !u16::try_from(acc).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use nsplane_packet::HEADROOM;

    use super::*;

    fn device() -> VirtualDevice {
        VirtualDevice::new(1360, 4, Arc::default())
    }

    #[test]
    fn new_device_has_empty_queues() {
        let dev = device();
        assert!(dev.rx_queue.is_empty());
        assert!(dev.tx_queue.is_empty());
    }

    #[test]
    fn inject_enqueues_to_rx_queue() {
        let mut dev = device();
        dev.inject(PacketBuf::from_packet(&[1, 2, 3]));
        dev.inject(PacketBuf::from_packet(&[4, 5, 6]));
        assert_eq!(dev.rx_queue.len(), 2);
    }

    #[test]
    fn receive_pops_from_rx_queue_in_order() -> Result<(), &'static str> {
        let mut dev = device();
        dev.inject(PacketBuf::from_packet(&[0xAA]));
        dev.inject(PacketBuf::from_packet(&[0xBB]));

        let ts = Instant::from_millis(0);
        let (rx, _tx) = dev.receive(ts).ok_or("no packet")?;
        // First injected packet should be consumed first.
        let got = rx.consume(<[u8]>::to_vec);
        assert_eq!(got, vec![0xAA]);
        Ok(())
    }

    #[test]
    fn receive_returns_none_when_rx_queue_empty() {
        let mut dev = device();
        let ts = Instant::from_millis(0);
        assert!(dev.receive(ts).is_none());
    }

    #[test]
    fn rx_token_consume_passes_correct_bytes_and_recycles() {
        let pool = RefCell::new(PacketPool::new(1));
        let token = VirtualRxToken {
            packet: PacketBuf::from_packet(&[10, 20, 30]),
            pool: &pool,
        };
        let result = token.consume(<[u8]>::to_vec);
        assert_eq!(result, [10, 20, 30]);
        assert_eq!(pool.borrow().free_len(), 1);
    }

    #[test]
    fn tx_token_consume_appends_to_tx_queue_with_headroom() -> Result<(), &'static str> {
        let mut dev = device();
        let token = dev.transmit(Instant::from_millis(0)).ok_or("no token")?;
        token.consume(4, |buf| buf.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(dev.tx_queue.len(), 1);
        let packet = &mut dev.tx_queue[0];
        assert_eq!(packet.as_packet(), [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet.with_headroom_mut().len(), HEADROOM + 4);
        Ok(())
    }

    #[test]
    fn drain_tx_empties_tx_queue() {
        let mut dev = device();
        dev.tx_queue.push_back(PacketBuf::from_packet(&[1]));
        dev.tx_queue.push_back(PacketBuf::from_packet(&[2]));
        assert_eq!(dev.drain_tx().count(), 2);
        assert!(dev.tx_queue.is_empty());
    }

    #[test]
    fn transmit_returns_a_token_until_the_backlog_is_full() -> Result<(), &'static str> {
        let mut dev = device();
        let ts = Instant::from_millis(0);
        for _ in 0..4 {
            let token = dev.transmit(ts).ok_or("no token")?;
            token.consume(1, |buf| buf[0] = 1);
        }
        assert!(dev.tx_full());
        assert!(dev.transmit(ts).is_none());
        Ok(())
    }

    #[test]
    fn reply_token_drops_and_counts_when_the_backlog_is_full() -> Result<(), &'static str> {
        let mut dev = device();
        dev.tx_queue
            .extend((0..4).map(|i| PacketBuf::from_packet(&[i])));
        dev.inject(PacketBuf::from_packet(&[9]));
        let (_rx, tx) = dev.receive(Instant::from_millis(0)).ok_or("no packet")?;
        tx.consume(1, |buf| buf[0] = 7);
        assert_eq!(dev.tx_queue.len(), 4);
        assert_eq!(dev.stats.egress_full.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn capabilities_reports_ip_medium_and_tunnel_mtu() {
        let dev = device();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        // Must be the tunnel MTU, not a physical 1500, so smoltcp advertises an MSS that
        // survives WireGuard encapsulation.
        assert_eq!(caps.max_transmission_unit, 1360);
        assert_eq!(caps.ip_mtu(), 1360);
    }

    const LOCAL: &str = "10.0.0.1:7";
    const REMOTE: &str = "10.0.0.2:40000";

    /// An IPv4 TCP segment from `src` to `dst` with a valid checksum.
    fn tcp4(src: &str, dst: &str, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src.ip(), dst.ip()) else {
            unreachable!("IPv4 test addresses");
        };
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&src.port().to_be_bytes());
        segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
        segment[4..8].copy_from_slice(&seq.to_be_bytes());
        segment[8..12].copy_from_slice(&ack.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = flags;
        segment[14..16].copy_from_slice(&1024u16.to_be_bytes());
        segment.extend_from_slice(payload);
        let sum = nsplane_packet::checksum::transport_checksum_v4(
            src_ip,
            dst_ip,
            nsplane_packet::protocol::TCP,
            &segment,
        );
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        let total = u16::try_from(20 + segment.len()).unwrap();
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x40, 0, 64, nsplane_packet::protocol::TCP, 0, 0]);
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&dst_ip.octets());
        packet.extend_from_slice(&segment);
        packet
    }

    fn acks_with_entry() -> PeerAcks {
        let mut acks = PeerAcks::new();
        acks.insert((LOCAL.parse().unwrap(), REMOTE.parse().unwrap()), None);
        acks
    }

    #[test]
    fn pure_ack_behind_the_peer_ack_moves_up_with_a_valid_checksum() {
        let mut acks = acks_with_entry();
        // The peer acknowledges up to 5000 (its window starts there) ...
        note_peer_ack(&tcp4(REMOTE, LOCAL, 900, 5000, TCP_ACK, b"x"), &mut acks);
        // ... but the stack, rewound to 3000 after a timeout, acknowledges at 3000.
        let mut packet = tcp4(LOCAL, REMOTE, 3000, 901, TCP_ACK, b"");
        fix_ack_seq(&mut packet, &acks);
        assert_eq!(packet, tcp4(LOCAL, REMOTE, 5000, 901, TCP_ACK, b""));
    }

    #[test]
    fn peer_ack_only_grows_and_wraps() {
        let mut acks = acks_with_entry();
        note_peer_ack(
            &tcp4(REMOTE, LOCAL, 1, u32::MAX - 10, TCP_ACK, b""),
            &mut acks,
        );
        note_peer_ack(&tcp4(REMOTE, LOCAL, 1, 20, TCP_ACK, b""), &mut acks);
        note_peer_ack(&tcp4(REMOTE, LOCAL, 1, 10, TCP_ACK, b""), &mut acks);
        let key = (LOCAL.parse().unwrap(), REMOTE.parse().unwrap());
        assert_eq!(acks[&key], Some(20));
        // A segment without ACK carries no acknowledgement.
        note_peer_ack(&tcp4(REMOTE, LOCAL, 1, 30, TCP_SYN, b""), &mut acks);
        assert_eq!(acks[&key], Some(20));
    }

    #[test]
    fn other_segments_pass_unchanged() {
        let mut acks = acks_with_entry();
        note_peer_ack(&tcp4(REMOTE, LOCAL, 900, 5000, TCP_ACK, b""), &mut acks);
        for packet in [
            // Data (a retransmission from the oldest unacknowledged byte).
            tcp4(LOCAL, REMOTE, 3000, 901, TCP_ACK, b"data"),
            tcp4(LOCAL, REMOTE, 3000, 901, TCP_ACK | TCP_FIN, b""),
            tcp4(LOCAL, REMOTE, 3000, 901, TCP_ACK | TCP_RST, b""),
            // Already at or past the peer's acknowledgement.
            tcp4(LOCAL, REMOTE, 5000, 901, TCP_ACK, b""),
            tcp4(LOCAL, REMOTE, 6000, 901, TCP_ACK, b""),
            // Another connection.
            tcp4(LOCAL, "10.0.0.3:40000", 3000, 901, TCP_ACK, b""),
        ] {
            let mut fixed = packet.clone();
            fix_ack_seq(&mut fixed, &acks);
            assert_eq!(fixed, packet);
        }
    }

    #[test]
    fn connections_without_a_peer_ack_are_left_alone() {
        let mut acks = PeerAcks::new();
        note_peer_ack(&tcp4(REMOTE, LOCAL, 900, 5000, TCP_ACK, b""), &mut acks);
        assert!(
            acks.is_empty(),
            "no entry is created for an unknown connection"
        );
        let acks = acks_with_entry();
        let packet = tcp4(LOCAL, REMOTE, 3000, 901, TCP_ACK, b"");
        let mut fixed = packet.clone();
        fix_ack_seq(&mut fixed, &acks);
        assert_eq!(fixed, packet);
    }
}
