//! Connections and flows held for the application's decision under
//! [`Admission::Decide`](crate::Admission::Decide).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use nsplane_packet::{IpPacket, PacketBuf, checksum, protocol};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use crate::device::TAILROOM;

/// The transport protocol of a [`PendingFlow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingProtocol {
    /// A TCP connection, held at its bare SYN.
    Tcp,
    /// A UDP flow, held at its first datagram.
    Udp,
}

/// A new TCP connection or UDP flow the stack holds until the application decides, under
/// [`Admission::Decide`](crate::Admission::Decide); see
/// [`NetStackHandle::incoming_pending`](crate::NetStackHandle::incoming_pending).
///
/// [`accept`](Self::accept) admits it: the stack then answers the held SYN with SYN-ACK
/// (and the connection arrives on
/// [`incoming_tcp`](crate::NetStackHandle::incoming_tcp) once established) or opens the
/// flow with the held datagram on [`incoming_udp`](crate::NetStackHandle::incoming_udp),
/// as with [`Admission::Immediate`](crate::Admission::Immediate). [`reject`](Self::reject)
/// answers a TCP connection with a RST and a UDP flow with an ICMP (IPv4) or `ICMPv6`
/// (IPv6) port unreachable, both sourced from [`local_addr`](Self::local_addr). Dropping
/// the item without a decision rejects it the same way.
///
/// Both take effect on the stack's next driver turn and never wait. A decision made after
/// the connection or flow timed out, or after the stack stopped, does nothing.
#[derive(Debug)]
pub struct PendingFlow {
    key: Key,
    id: u64,
    decisions: mpsc::UnboundedSender<Decision>,
    notify: Arc<Notify>,
    /// A decision was sent, or the item was never offered.
    decided: bool,
}

impl PendingFlow {
    /// TCP or UDP.
    pub const fn protocol(&self) -> PendingProtocol {
        self.key.protocol
    }

    /// The peer's address: the source of the SYN or datagram.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.key.remote
    }

    /// The address the peer dialed: the original destination of the SYN or datagram,
    /// which the connection or flow keeps as its local address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.key.local
    }

    /// Admits the connection or flow. With
    /// [`TransparentConfig::max_connections`](crate::TransparentConfig::max_connections)
    /// reached at that point, a TCP connection is answered with a RST instead and counted
    /// in [`rejected_connection_limit`](crate::NetStackStats::rejected_connection_limit).
    pub fn accept(mut self) {
        self.decide(true);
    }

    /// Rejects the connection or flow, see [`PendingFlow`]; counted in
    /// [`rejected_hook`](crate::NetStackStats::rejected_hook).
    pub fn reject(mut self) {
        self.decide(false);
    }

    fn decide(&mut self, accept: bool) {
        if std::mem::replace(&mut self.decided, true) {
            return;
        }
        let decision = Decision {
            key: self.key,
            id: self.id,
            accept,
        };
        if self.decisions.send(decision).is_ok() {
            self.notify.notify_one();
        }
    }
}

impl Drop for PendingFlow {
    /// Rejects the connection or flow unless a decision was made.
    fn drop(&mut self) {
        self.decide(false);
    }
}

/// What identifies a held connection or flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) protocol: PendingProtocol,
    pub(crate) remote: SocketAddr,
    pub(crate) local: SocketAddr,
}

/// The application's decision on the entry `id` of `key`.
#[derive(Debug)]
pub(crate) struct Decision {
    key: Key,
    id: u64,
    pub(crate) accept: bool,
}

/// What an entry holds until the decision.
#[derive(Debug)]
pub(crate) enum Held {
    /// The bare SYN.
    Tcp(PacketBuf),
    /// The first datagram's payload and the whole packet it is a view into.
    Udp { payload: Bytes, packet: Bytes },
}

impl Held {
    /// The packet that answers a rejection, sourced from the original destination: a RST
    /// for a SYN, a port unreachable for a datagram.
    pub(crate) fn rejection(&self, mtu: u16) -> Option<PacketBuf> {
        match self {
            Self::Tcp(syn) => crate::stack::tcp_reset(syn.as_packet()),
            Self::Udp { packet, .. } => port_unreachable(packet, mtu),
        }
    }
}

#[derive(Debug)]
struct Entry {
    id: u64,
    held: Held,
}

/// What [`Pending::hold`] did with a packet.
#[derive(Debug)]
pub(crate) enum Hold {
    /// Held and offered to the application.
    Held,
    /// Not held; reject it at once.
    Full(Held),
    /// Not held: the application's stream is gone; reject it at once.
    Gone(Held),
}

/// The driver's table of held connections and flows: at most `max` entries, each with
/// the deadline `timeout` after it was held. Deadlines grow with insertion, so the
/// earliest is at the front of `deadlines`.
#[derive(Debug)]
pub(crate) struct Pending {
    timeout: Duration,
    max: usize,
    entries: HashMap<Key, Entry>,
    /// Every live entry's deadline, ascending, plus decided ones not pruned yet; pruned
    /// once it holds twice `max`.
    deadlines: VecDeque<(Instant, Key, u64)>,
    next_id: u64,
    decisions_tx: mpsc::UnboundedSender<Decision>,
    decisions: mpsc::UnboundedReceiver<Decision>,
    offer: mpsc::Sender<PendingFlow>,
    notify: Arc<Notify>,
}

impl Pending {
    /// A table of at most `max` (at least 1) entries offering them through `offer`, whose
    /// decisions wake the driver through `notify`.
    pub(crate) fn new(
        timeout: Duration,
        max: usize,
        offer: mpsc::Sender<PendingFlow>,
        notify: Arc<Notify>,
    ) -> Self {
        let (decisions_tx, decisions) = mpsc::unbounded_channel();
        Self {
            timeout,
            max,
            entries: HashMap::new(),
            deadlines: VecDeque::new(),
            next_id: 0,
            decisions_tx,
            decisions,
            offer,
            notify,
        }
    }

    /// Entries held now.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether `key` is held.
    pub(crate) fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Holds `held` for `key`, which is not held, until a decision or `now + timeout`,
    /// offering it to the application.
    pub(crate) fn hold(&mut self, key: Key, held: Held, now: Instant) -> Hold {
        if self.entries.len() >= self.max {
            return Hold::Full(held);
        }
        let id = self.next_id;
        self.next_id += 1;
        let item = PendingFlow {
            key,
            id,
            decisions: self.decisions_tx.clone(),
            notify: Arc::clone(&self.notify),
            decided: false,
        };
        if let Err(error) = self.offer.try_send(item) {
            let full = matches!(error, TrySendError::Full(_));
            let mut item = error.into_inner();
            // Never offered: its drop sends no decision.
            item.decided = true;
            return if full {
                Hold::Full(held)
            } else {
                Hold::Gone(held)
            };
        }
        self.entries.insert(key, Entry { id, held });
        if self.deadlines.len() >= self.max.saturating_mul(2) {
            let entries = &self.entries;
            self.deadlines
                .retain(|(_, key, id)| entries.get(key).is_some_and(|entry| entry.id == *id));
        }
        self.deadlines.push_back((now + self.timeout, key, id));
        Hold::Held
    }

    /// The next decision whose entry is still held, with what it holds; decisions on
    /// entries that timed out are skipped.
    pub(crate) fn next_decision(&mut self) -> Option<(Decision, Key, Held)> {
        while let Ok(decision) = self.decisions.try_recv() {
            if let Some(held) = self.remove(&decision.key, decision.id) {
                let key = decision.key;
                return Some((decision, key, held));
            }
        }
        None
    }

    /// The next entry whose deadline is at or before `now`, removed.
    pub(crate) fn next_expired(&mut self, now: Instant) -> Option<(Key, Held)> {
        while let Some(&(deadline, key, id)) = self.deadlines.front() {
            if deadline > now {
                return None;
            }
            self.deadlines.pop_front();
            if let Some(held) = self.remove(&key, id) {
                return Some((key, held));
            }
        }
        None
    }

    /// The earliest deadline of a held entry, if any.
    pub(crate) fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(&(deadline, key, id)) = self.deadlines.front() {
            if self.entries.get(&key).is_some_and(|entry| entry.id == id) {
                return Some(deadline);
            }
            self.deadlines.pop_front();
        }
        None
    }

    fn remove(&mut self, key: &Key, id: u64) -> Option<Held> {
        if self.entries.get(key)?.id != id {
            return None;
        }
        self.entries.remove(key).map(|entry| entry.held)
    }
}

/// The checksum of `segment` over the pseudo-header of `src`, `dst` and `protocol`, as
/// `checksum::transport_checksum_v4` and `_v6` compute it. The rejection replies use this
/// instead, so that the UDP egress path stays their only caller and inlines them.
pub(crate) fn pseudo_header_checksum(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let add = |acc, addr| match addr {
        IpAddr::V4(addr) => checksum::sum_words(acc, &addr.octets()),
        IpAddr::V6(addr) => checksum::sum_words(acc, &addr.octets()),
    };
    let acc = add(add(0, src), dst) + u64::from(protocol) + segment.len() as u64;
    !checksum::fold(checksum::sum_words(acc, segment))
}

/// The ICMP (IPv4) or `ICMPv6` (IPv6) port unreachable answering `packet`, from its
/// destination to its source, quoting as much of it as fits in 576 (IPv4) or 1280 (IPv6)
/// bytes and in `mtu`.
pub(crate) fn port_unreachable(packet: &[u8], mtu: u16) -> Option<PacketBuf> {
    const ICMP_HEADER: usize = 8;
    let ip = IpPacket::parse(packet).ok()?;
    let (src, dst) = (ip.dst(), ip.src());
    let (header, limit, icmp_type, code) = match src {
        IpAddr::V4(_) => (20, 576, 3, 3),
        IpAddr::V6(_) => (40, 1280, 1, 4),
    };
    let limit = usize::from(mtu).min(limit);
    let quoted = packet.len().min(limit - header - ICMP_HEADER);
    let total = header + ICMP_HEADER + quoted;
    let mut reply = PacketBuf::with_capacity(total + TAILROOM);
    reply.set_len(total);
    let bytes = reply.as_packet_mut();
    let (head, message) = bytes.split_at_mut(header);
    message[0] = icmp_type;
    message[1] = code;
    message[ICMP_HEADER..].copy_from_slice(&packet[..quoted]);
    let total_len = u16::try_from(total).ok()?;
    let sum = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            head[0] = 0x45;
            head[2..4].copy_from_slice(&total_len.to_be_bytes());
            head[8] = 64;
            head[9] = protocol::ICMP;
            head[12..16].copy_from_slice(&src.octets());
            head[16..20].copy_from_slice(&dst.octets());
            let header_checksum = checksum::ipv4_header_checksum(head);
            head[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            checksum::internet_checksum(message)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let payload_len = u16::try_from(total - header).ok()?;
            head[0] = 0x60;
            head[4..6].copy_from_slice(&payload_len.to_be_bytes());
            head[6] = protocol::ICMPV6;
            head[7] = 64;
            head[8..24].copy_from_slice(&src.octets());
            head[24..40].copy_from_slice(&dst.octets());
            pseudo_header_checksum(src.into(), dst.into(), protocol::ICMPV6, message)
        }
        _ => return None,
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}
