//! Ingress: classifying, routing and dispatching packets into the stack.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use nsplane_packet::{IpPacket, PacketBuf, protocol};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::wire::{IpEndpoint, TcpSeqNumber};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::config::Settings;
use crate::events::FlowEventReason;
use crate::flow::{FlowState, Target};
use crate::pending::{self, PendingProtocol};
use crate::pmtu::{self, Message, TooBig};
use crate::stats::{self};
use crate::udp::{self, Datagram, UdpFlow, UdpReply};

use super::wire::{tcp_dst_port, tcp_is_syn, tcp_tuple};
use super::{Driver, MAX_INJECT_PER_ITER};

/// How an ingress packet is handled.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// Into smoltcp; `syn` marks a bare SYN that needs a listener.
    Tcp { dst_port: u16, syn: bool },
    /// Into the UDP dispatch path.
    Udp,
    /// An ICMP or `ICMPv6` message: a Fragmentation Needed or Packet Too Big may lower a
    /// connection's MSS.
    Icmp,
}

/// Why an ingress packet is dropped.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reject {
    Malformed,
    NoAddress,
    /// In transparent mode: neither one of the stack's addresses nor in a prefix.
    Prefix,
    Unsupported,
}

/// Decides what to do with an ingress packet.
pub(super) fn classify(bytes: &[u8], settings: &Settings) -> Result<Class, Reject> {
    let ip = IpPacket::parse(bytes).map_err(|_| Reject::Malformed)?;
    if !settings.is_local(ip.dst()) {
        match &settings.transparent {
            None => return Err(Reject::NoAddress),
            Some(transparent) if !transparent.prefixes.contains(ip.dst()) => {
                return Err(Reject::Prefix);
            }
            Some(_) => {}
        }
    }
    if ip.fragment().is_some() {
        return Err(Reject::Unsupported);
    }
    if let Some(dst_port) = tcp_dst_port(bytes) {
        return Ok(Class::Tcp {
            dst_port,
            syn: tcp_is_syn(bytes),
        });
    }
    match ip.protocol() {
        protocol::UDP => Ok(Class::Udp),
        protocol::TCP => Err(Reject::Malformed),
        protocol::ICMP if ip.src().is_ipv4() => Ok(Class::Icmp),
        protocol::ICMPV6 if ip.src().is_ipv6() => Ok(Class::Icmp),
        _ => Err(Reject::Unsupported),
    }
}

impl Driver {
    /// Takes up to [`MAX_INJECT_PER_ITER`] ingress packets; `None` once the sink is gone.
    pub(super) fn ingest_batch(&mut self) -> Option<HashMap<u16, usize>> {
        self.flush_waiting();
        let mut demand = HashMap::new();
        if let Some(packet) = self.carried.take() {
            self.ingest(packet, &mut demand);
        }
        // Taking the queued packets at once releases their queue slots in one step rather
        // than one per packet. Without a packet the poll registers no waker that matters:
        // `wait` polls the queue again with the driver's own.
        let mut batch = std::mem::take(&mut self.batch);
        let taken = self.ingress.poll_recv_many(
            &mut Context::from_waker(Waker::noop()),
            &mut batch,
            MAX_INJECT_PER_ITER,
        );
        self.ingest_all(&mut batch, &mut demand);
        self.batch = batch;
        // After the batch, so that a SYN retransmitted in it is absorbed by its entry
        // rather than held anew once the entry is accepted.
        if self.pending.is_some() {
            self.take_decisions(&mut demand);
        }
        // Zero packets taken means the queue is closed and drained.
        (taken != Poll::Ready(0)).then_some(demand)
    }

    /// Routes the packets of `batch` in order (see [`ingest`](Self::ingest)), leaving it
    /// empty with its allocation kept.
    fn ingest_all(&mut self, batch: &mut Vec<PacketBuf>, demand: &mut HashMap<u16, usize>) {
        for packet in batch.drain(..) {
            self.ingest(packet, demand);
        }
    }

    /// Routes one ingress packet, counting the SYNs per destination port in `demand`.
    fn ingest(&mut self, packet: PacketBuf, demand: &mut HashMap<u16, usize>) {
        let Some(packet) = self.reassemble(packet) else {
            return;
        };
        match classify(packet.as_packet(), &self.settings) {
            Ok(Class::Tcp { dst_port, syn }) => {
                if syn {
                    if self.accept_full() {
                        // Unanswered, the peer retransmits it once the queue may have room.
                        return stats::add(&self.stats.syn_deferred, 1);
                    }
                    let packet = if self.settings.transparent.is_some() || self.pending.is_some() {
                        match self.admit_syn(packet, demand) {
                            Some(packet) => packet,
                            None => return,
                        }
                    } else {
                        packet
                    };
                    *demand.entry(dst_port).or_insert(0) += 1;
                    return self.device.inject(packet);
                }
                self.device.inject(packet);
            }
            Ok(Class::Udp) if self.pending.is_some() => self.ingest_held_udp(packet),
            Ok(Class::Udp) => match udp::parse_udp(packet) {
                Some(datagram) => self.dispatch_udp(datagram, None),
                None => stats::add(&self.stats.malformed, 1),
            },
            Ok(Class::Icmp) => self.icmp(packet.as_packet()),
            Err(Reject::Malformed) => stats::add(&self.stats.malformed, 1),
            Err(Reject::NoAddress) => stats::add(&self.stats.no_address, 1),
            Err(Reject::Prefix) => {
                stats::add(&self.stats.no_address, 1);
                stats::add(&self.stats.rejected_prefix, 1);
                self.emit_prefix(packet.as_packet());
            }
            Err(Reject::Unsupported) => stats::add(&self.stats.unsupported, 1),
        }
    }

    /// Routes an ingress UDP packet with `Admission::Decide`, keeping the whole packet for
    /// a flow that may be held.
    #[cold]
    #[inline(never)]
    fn ingest_held_udp(&mut self, packet: PacketBuf) {
        match udp::parse_udp_whole(packet) {
            Some((datagram, whole)) => self.dispatch_held_udp(datagram, whole),
            None => stats::add(&self.stats.malformed, 1),
        }
    }

    /// [`dispatch_udp`](Self::dispatch_udp) out of line, for the `Admission::Decide` path.
    #[cold]
    #[inline(never)]
    pub(super) fn dispatch_held_udp(&mut self, datagram: Datagram, whole: Bytes) {
        self.dispatch_udp(datagram, Some(whole));
    }

    /// Admits a bare SYN in transparent mode or under `Admission::Decide`; the SYN if it
    /// goes on into smoltcp now. A retransmitted SYN of a handshake in progress passes
    /// uncounted, and one of a held connection is absorbed; a new connection beyond
    /// `max_connections` is answered with RST. Under `Admission::Decide` a new connection
    /// is held (or, with the table full, answered with RST).
    fn admit_syn(&mut self, packet: PacketBuf, demand: &HashMap<u16, usize>) -> Option<PacketBuf> {
        let Some((remote, local)) = tcp_tuple(packet.as_packet()) else {
            return Some(packet);
        };
        if self.owners.has_tcp(local, remote) {
            return Some(packet);
        }
        let key = pending::Key {
            protocol: PendingProtocol::Tcp,
            remote,
            local,
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|table| table.contains(&key))
        {
            return None;
        }
        if self.at_connection_limit(demand) {
            self.reject_connection_limit(&key, packet.as_packet());
            return None;
        }
        if self.pending.is_some() {
            self.hold(key, pending::Held::Tcp(packet));
            return None;
        }
        stats::add(&self.stats.accepted, 1);
        self.emit(&key, FlowEventReason::Admitted);
        Some(packet)
    }

    /// Whether the stack holds `max_connections` TCP connections, counting the connections
    /// held, the handshakes in progress and the SYNs of this batch in `demand`.
    pub(super) fn at_connection_limit(&self, demand: &HashMap<u16, usize>) -> bool {
        let Some(limit) = self
            .settings
            .transparent
            .as_ref()
            .and_then(|transparent| transparent.max_connections)
        else {
            return false;
        };
        let held = self.conns.len()
            + self.connecting.len()
            + self.inbound.len()
            + demand.values().sum::<usize>();
        held >= limit
    }

    /// Appends a packet the driver answers an ingress packet with to the egress backlog,
    /// or drops and counts it while the backlog is full, as smoltcp's replies.
    pub(super) fn push_reply(&mut self, packet: PacketBuf) {
        if self.device.tx_full() {
            return stats::add(&self.stats.egress_full, 1);
        }
        self.device.tx_queue.push_back(packet);
    }

    /// Applies an ICMP Fragmentation Needed or `ICMPv6` Packet Too Big to the connection
    /// whose segment it quotes, or counts it in `icmp_ignored`; any other ICMP message
    /// counts as `unsupported`.
    fn icmp(&mut self, packet: &[u8]) {
        match pmtu::parse(packet) {
            Message::Other => stats::add(&self.stats.unsupported, 1),
            Message::Ignored => stats::add(&self.stats.icmp_ignored, 1),
            Message::TooBig(too_big) => {
                if !self.reduce_mss(&too_big) {
                    stats::add(&self.stats.icmp_ignored, 1);
                }
            }
        }
    }

    /// Lowers the MSS of the live connection `too_big` quotes; whether it did. smoltcp
    /// checks that the quoted sequence number lies within SND.UNA..SND.NXT and that the
    /// MSS goes down, and resends the data in flight at once in segments of the new size.
    /// In transparent mode the quoted tuple alone finds the connection.
    fn reduce_mss(&mut self, too_big: &TooBig) -> bool {
        if too_big.mtu >= u32::from(self.settings.mtu)
            || (self.settings.transparent.is_none() && !self.settings.is_local(too_big.local.ip()))
        {
            return false;
        }
        let (local, remote) = (
            IpEndpoint::from(too_big.local),
            IpEndpoint::from(too_big.remote),
        );
        let (now, mss) = (self.now(), too_big.mss());
        // Linear in the sockets, but only per message: no state is kept for the lookup.
        self.sockets
            .iter_mut()
            .filter_map(|(_, socket)| tcp::Socket::downcast_mut(socket))
            .find(|socket| {
                socket.local_endpoint() == Some(local) && socket.remote_endpoint() == Some(remote)
            })
            .is_some_and(|socket| {
                socket.reduce_mss(now, mss, TcpSeqNumber(too_big.seq.cast_signed()))
            })
    }

    /// Delivers a datagram to its connected socket, its bound socket, or to its flow;
    /// `whole` is the packet of an ingress datagram whose new flow may be held, `None`
    /// without `Admission::Decide`.
    #[allow(
        clippy::inline_always,
        reason = "the ingress path keeps its own copy, with `whole` a constant `None`"
    )]
    #[inline(always)]
    fn dispatch_udp(&mut self, datagram: Datagram, whole: Option<Bytes>) {
        let Datagram {
            src,
            dst,
            mut payload,
        } = datagram;
        if !self.connected.is_empty()
            && let Some((socket, _)) = self.connected.get(&(src, dst))
        {
            match socket.try_send((src, payload)) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed((_, returned))) => {
                    self.connected.remove(&(src, dst));
                    payload = returned;
                }
            }
        }
        let unspecified = match dst.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        for key in [dst, SocketAddr::new(unspecified, dst.port())] {
            let Some((socket, _)) = self.bound.get(&key) else {
                continue;
            };
            match socket.try_send((src, payload)) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed((_, returned))) => {
                    self.bound.remove(&key);
                    payload = returned;
                }
            }
        }
        self.dispatch_flow(src, dst, payload, whole);
    }

    /// Routes a datagram into the flow table, opening a flow for a new tuple, or holding it
    /// for the application's decision (see [`dispatch_udp`](Self::dispatch_udp)).
    fn dispatch_flow(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
        payload: Bytes,
        whole: Option<Bytes>,
    ) {
        let key = (remote, local);
        // Existing flow: a full queue drops the datagram (normal UDP backpressure); a
        // closed one means the application dropped the flow, so it is replaced by a new
        // flow carrying this datagram.
        let payload = match self.flows.get(&key) {
            Some((flow, _)) => match flow.try_send(payload) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    tracing::trace!(%remote, %local, "UDP flow queue full; dropping");
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed(payload)) => {
                    self.flows.remove(&key);
                    payload
                }
            },
            None => payload,
        };
        if let Some(packet) = whole {
            return self.hold_udp(remote, local, payload, packet);
        }
        if self.settings.transparent.is_some() {
            self.admit_udp(remote, local);
        }
        // Bound the table: refuse a new flow when it is full of live flows rather than
        // grow without limit under a spray of distinct tuples.
        if self.flows.len() >= self.settings.max_udp_flows {
            self.flows.retain(|_, (flow, _)| !flow.is_closed());
            if self.flows.len() >= self.settings.max_udp_flows {
                tracing::warn!(%remote, %local, "UDP flow table at capacity; dropping new flow");
                stats::add(&self.stats.udp_flow_limit, 1);
                return;
            }
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        // The queue is empty, so the first datagram always fits.
        let _ = tx.try_send(payload);
        // Registered before the application can see (and drop) the flow.
        let registration = self.owners.udp_flow(local, remote);
        let state = FlowState::new(Target::UdpFlow(key), &self.revocations);
        let flow = UdpFlow::new(
            registration,
            rx,
            UdpReply::new(local, remote, self.out.clone(), Arc::clone(&state)),
        );
        if self.accept_udp.try_send(flow).is_ok() {
            self.flows.insert(key, (tx, state));
        } else {
            tracing::debug!(%remote, %local, "incoming_udp full or gone; dropping UDP flow");
            stats::add(&self.stats.udp_not_accepted, 1);
        }
    }
}
