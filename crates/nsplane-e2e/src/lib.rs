//! End-to-end tests of the nsplane data plane.
//!
//! The integration tests under `tests/` run whole [`Engine`]s against each other through the
//! public APIs only. In-process tests (engines linked by [`ChannelTransport`]s or by
//! [`UdpTransport`]s on the loopback interface) run with every other test in `just check`.
//! Tests that need containers (TUN devices, kernel WireGuard) are `#[ignore]`d and run by
//! `just e2e-lib`.
//!
//! This library is the shared harness: packet builders, a [`Node`] wrapping one engine with
//! the test ends of its packet source and sink, constructors for linked pairs of nodes, and
//! [`Events`] for asserting on engine events. Every expectation is bounded by [`WAIT`] or
//! [`QUIET`] and fails with an error instead of hanging.
//!
//! [`StackNode`] is a node whose local side is an `nsplane_netstack::NetStack` instead of
//! the test channels, with echo servers for its TCP connections and UDP flows.

use std::error::Error;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_core::Stream;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Engine, EngineBuilder, EngineHandle,
    PacketFilter, PacketSource, Peer, Transport, UdpTransport,
};
use nsplane_core::{Event, Verdict};
use nsplane_netstack::{
    NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource, TcpConnection, UdpFlow,
};
use nsplane_packet::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{Ecn, IpPacket, PacketBuf, Path, PeerId, TransportId, protocol};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, timeout, timeout_at};

/// Upper bound for anything that is expected to happen.
pub const WAIT: Duration = Duration::from_secs(5);
/// Upper bound for a TCP connection setup or a bulk transfer through a netstack.
pub const TRANSFER: Duration = Duration::from_secs(30);
/// How long to watch for something that is expected not to happen.
pub const QUIET: Duration = Duration::from_millis(300);
/// MTU of every node's packet source.
pub const MTU: u16 = 1420;
/// Capacity of every queue the harness creates.
const CAPACITY: usize = 1024;
/// UDP ports of the packets the builders produce.
const SRC_PORT: u16 = 40000;
const DST_PORT: u16 = 9;
/// Largest UDP payload the builders accept: what fits into one IPv4 packet.
const MAX_PAYLOAD: usize = 65_507;

/// The result of harness calls and tests: any error fails the test with its message.
pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The IP version of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// A UDP header and `payload`, with the length set and the checksum field zeroed.
fn udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&len.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    segment
}

/// Writes `sum` into the checksum field of a UDP segment (`0` is sent as `0xFFFF`).
fn set_udp_checksum(segment: &mut [u8], sum: u16) {
    let sum = if sum == 0 { 0xFFFF } else { sum };
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
}

/// A UDP-in-IPv4 packet from `src` to `dst` with valid IPv4 header and UDP checksums.
///
/// # Panics
///
/// Panics if `payload` does not fit into one IPv4 packet.
pub fn udp4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    udp4_ports(src, SRC_PORT, dst, DST_PORT, payload)
}

fn udp4_ports(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD, "payload too large");
    let mut segment = udp_segment(src_port, dst_port, payload);
    let sum = transport_checksum_v4(src, dst, protocol::UDP, &segment);
    set_udp_checksum(&mut segment, sum);

    let total = u16::try_from(20 + segment.len()).unwrap_or(u16::MAX);
    let mut packet = Vec::with_capacity(20 + segment.len());
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol::UDP, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&segment);
    packet
}

/// A UDP-in-IPv6 packet from `src` to `dst` with a valid UDP checksum.
///
/// # Panics
///
/// Panics if `payload` does not fit into one IPv6 packet without a jumbogram.
pub fn udp6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    udp6_ports(src, SRC_PORT, dst, DST_PORT, payload)
}

fn udp6_ports(
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD, "payload too large");
    let mut segment = udp_segment(src_port, dst_port, payload);
    let sum = transport_checksum_v6(src, dst, protocol::UDP, &segment);
    set_udp_checksum(&mut segment, sum);

    let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    let mut packet = Vec::with_capacity(40 + segment.len());
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&[protocol::UDP, 64]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&segment);
    packet
}

/// A UDP packet from `src` to `dst` (addresses and ports) with valid checksums.
///
/// # Panics
///
/// Panics if `src` and `dst` are of different IP versions or `payload` does not fit into
/// one packet.
pub fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    assert_eq!(src.is_ipv4(), dst.is_ipv4(), "mixed IP versions");
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => udp4_ports(s, src.port(), d, dst.port(), payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => udp6_ports(s, src.port(), d, dst.port(), payload),
        _ => unreachable!("versions checked above"),
    }
}

/// An IP packet from `src` to `dst` carrying `segment` of `proto`: IPv4 with DF set, a TTL
/// of 64 and a valid header checksum, or IPv6 with a hop limit of 64.
///
/// # Panics
///
/// Panics if `src` and `dst` are of different IP versions or `segment` does not fit into
/// one packet.
pub fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) -> Vec<u8> {
    assert_eq!(src.is_ipv4(), dst.is_ipv4(), "mixed IP versions");
    assert!(segment.len() <= MAX_PAYLOAD + 8, "segment too large");
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + segment.len()).unwrap_or(u16::MAX);
            let mut packet = Vec::with_capacity(20 + segment.len());
            packet.extend_from_slice(&[0x45, 0]);
            packet.extend_from_slice(&total.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            let sum = ipv4_header_checksum(&packet);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
            packet.extend_from_slice(segment);
            packet
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
            let mut packet = Vec::with_capacity(40 + segment.len());
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&len.to_be_bytes());
            packet.extend_from_slice(&[proto, 64]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            packet.extend_from_slice(segment);
            packet
        }
        _ => unreachable!("versions checked above"),
    }
}

/// A TCP packet from `src` to `dst` with `flags`, sequence number `seq`, acknowledgment
/// number `ack`, no options and `payload`, with valid checksums.
///
/// # Panics
///
/// Panics if `src` and `dst` are of different IP versions or `payload` does not fit into
/// one packet.
pub fn tcp(
    src: SocketAddr,
    dst: SocketAddr,
    flags: u8,
    (seq, ack): (u32, u32),
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(src.is_ipv4(), dst.is_ipv4(), "mixed IP versions");
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&src.port().to_be_bytes());
    segment.extend_from_slice(&dst.port().to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let sum = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => transport_checksum_v4(s, d, protocol::TCP, &segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => transport_checksum_v6(s, d, protocol::TCP, &segment),
        _ => unreachable!("versions checked above"),
    };
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src.ip(), dst.ip(), protocol::TCP, &segment)
}

/// An ICMP (IPv4) or `ICMPv6` (IPv6) message of `kind` and `code` from `src` to `dst`, with
/// `rest` as the second header word (identifier and sequence, MTU, pointer) and `body`
/// after it, with valid checksums.
///
/// # Panics
///
/// Panics if `src` and `dst` are of different IP versions or `body` does not fit into one
/// packet.
pub fn icmp(
    src: IpAddr,
    dst: IpAddr,
    (kind, code): (u8, u8),
    rest: [u8; 4],
    body: &[u8],
) -> Vec<u8> {
    assert_eq!(src.is_ipv4(), dst.is_ipv4(), "mixed IP versions");
    let mut message = Vec::with_capacity(8 + body.len());
    message.extend_from_slice(&[kind, code, 0, 0]);
    message.extend_from_slice(&rest);
    message.extend_from_slice(body);
    let (proto, sum) = match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (protocol::ICMP, internet_checksum(&message)),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            protocol::ICMPV6,
            transport_checksum_v6(s, d, protocol::ICMPV6, &message),
        ),
        _ => unreachable!("versions checked above"),
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src, dst, proto, &message)
}

/// Checks every checksum of `packet` by recomputing it in full: the IPv4 header checksum
/// and the TCP, UDP (a zero UDP checksum only over IPv4), ICMP or `ICMPv6` checksum.
pub fn verify_checksums(packet: &[u8]) -> TestResult {
    let ip = IpPacket::parse(packet).map_err(|e| format!("malformed packet: {e:?}"))?;
    let segment = ip.payload();
    let sum = match (ip.src(), ip.dst(), ip.protocol()) {
        (IpAddr::V4(_), IpAddr::V4(_), protocol::ICMP) => internet_checksum(segment),
        (IpAddr::V4(s), IpAddr::V4(d), proto @ (protocol::TCP | protocol::UDP)) => {
            if proto == protocol::UDP && segment.get(6..8) == Some(&[0, 0]) {
                0
            } else {
                transport_checksum_v4(s, d, proto, segment)
            }
        }
        (
            IpAddr::V6(s),
            IpAddr::V6(d),
            proto @ (protocol::TCP | protocol::UDP | protocol::ICMPV6),
        ) => transport_checksum_v6(s, d, proto, segment),
        (_, _, proto) => return Err(format!("no checksum check for protocol {proto}").into()),
    };
    if sum != 0 {
        return Err(format!("invalid protocol {} checksum", ip.protocol()).into());
    }
    if let IpPacket::V4 { header, .. } = &ip
        && internet_checksum(&packet[..header.header_len()]) != 0
    {
        return Err("invalid IPv4 header checksum".into());
    }
    Ok(())
}

/// A recognisable payload of `len` bytes.
pub fn payload(len: usize) -> Vec<u8> {
    (0..=u8::MAX).cycle().take(len).collect()
}

/// A packet filter shared between the engine and the test: the engine gets a
/// `Box<SharedFilter<F>>` while the test keeps the `Arc` to reconfigure the filter or read
/// its counters.
#[derive(Debug)]
pub struct SharedFilter<F>(pub Arc<F>);

impl<F: PacketFilter> PacketFilter for SharedFilter<F> {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.inbound(peer, packet)
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.outbound(peer, packet)
    }
}

/// Settings of the engines a constructor builds.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Interval of `Event::PeerStats`; none by default.
    pub stats_interval: Option<Duration>,
}

/// One engine with the test ends of its packet source and sink.
///
/// `T` is the type of the transport the node is reached on; helpers that link two nodes
/// take nodes of one type.
pub struct Node<T: Transport> {
    /// The running engine; dropping it stops the engine.
    pub engine: Engine,
    /// A handle to the engine.
    pub handle: EngineHandle,
    /// Feeds the engine's packet source.
    pub local: mpsc::Sender<PacketBuf>,
    /// Receives what the engine's sink delivers, with the peer it came from.
    pub delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    /// Changes the MTU of the engine's packet source.
    pub mtu: watch::Sender<u16>,
    /// The node's private key.
    pub secret: StaticSecret,
    /// The node's tunnel IPv4 address.
    pub ip4: Ipv4Addr,
    /// The node's tunnel IPv6 address.
    pub ip6: Ipv6Addr,
    /// The node's own transport id and the address its peers reach it on.
    pub path: Path,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport> fmt::Debug for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("public", &self.public())
            .field("ip4", &self.ip4)
            .field("ip6", &self.ip6)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> Node<T> {
    /// Builds a node with key seed `seed` on `transport`, reachable at `addr`.
    ///
    /// The seed also picks the tunnel addresses `10.0.0.<seed>` and `fd00::<seed>`.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn new(
        seed: u8,
        id: TransportId,
        addr: SocketAddr,
        transport: T,
        options: Options,
    ) -> Self {
        match Self::with_builder(seed, id, addr, options, |builder| {
            builder.transport(transport)
        }) {
            Ok(node) => node,
            Err(e) => unreachable!("an engine with one transport builds: {e}"),
        }
    }

    /// Builds a node like [`Node::new`], with `configure` adding the transports (any number,
    /// of any types) and further settings to the engine builder. `id` and `addr` are the
    /// node's own [`Node::path`].
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn with_builder(
        seed: u8,
        id: TransportId,
        addr: SocketAddr,
        options: Options,
        configure: impl FnOnce(
            EngineBuilder<ChannelSource, ChannelSink>,
        ) -> EngineBuilder<ChannelSource, ChannelSink>,
    ) -> TestResult<Self> {
        let (source, local, mtu) = ChannelSource::new(CAPACITY, MTU);
        let (sink, delivered) = ChannelSink::new(CAPACITY);
        let mut builder =
            EngineBuilder::new(source, sink).private_key(StaticSecret::from([seed; 32]));
        if let Some(interval) = options.stats_interval {
            builder = builder.stats_interval(interval);
        }
        let engine = configure(builder).build()?;
        Ok(Self {
            handle: engine.handle(),
            engine,
            local,
            delivered,
            mtu,
            secret: StaticSecret::from([seed; 32]),
            ip4: Ipv4Addr::new(10, 0, 0, seed),
            ip6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed)),
            path: Path {
                transport: id,
                addr,
                ecn: Ecn::NotEct,
            },
            transport: PhantomData,
        })
    }

    /// The node's public key.
    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// This node as a peer of a node that reaches it over its transport `via`: both tunnel
    /// addresses as /32 and /128 allowed IPs and the node's address as the path.
    pub fn as_peer(&self, via: TransportId) -> Peer {
        Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(self.ip4),
                    cidr: 32,
                },
                AllowedIp {
                    addr: IpAddr::V6(self.ip6),
                    cidr: 128,
                },
            ],
            path: Some(Path {
                transport: via,
                ..self.path
            }),
            ..Peer::new(self.public())
        }
    }

    /// A UDP packet of `family` from this node's tunnel address to `other`'s.
    pub fn packet_to<U: Transport>(
        &self,
        other: &Node<U>,
        family: Family,
        payload: &[u8],
    ) -> Vec<u8> {
        match family {
            Family::V4 => udp4(self.ip4, other.ip4, payload),
            Family::V6 => udp6(self.ip6, other.ip6, payload),
        }
    }

    /// Hands `packet` to the engine as a local packet.
    pub async fn send(&self, packet: &[u8]) -> TestResult {
        self.local.send(PacketBuf::from_packet(packet)).await?;
        Ok(())
    }

    /// Hands `packet` to the engine as a local packet, in a buffer with 64 bytes of room
    /// beyond it, as a TUN source's buffers have (a translating filter grows the packet).
    pub async fn send_with_room(&self, packet: &[u8]) -> TestResult {
        let mut buf = PacketBuf::with_capacity(packet.len() + 64);
        buf.set_len(packet.len());
        buf.as_packet_mut().copy_from_slice(packet);
        self.local.send(buf).await?;
        Ok(())
    }

    /// The next delivered packet and the peer it came from, within [`WAIT`].
    pub async fn expect_delivery(&mut self) -> TestResult<(PeerId, Vec<u8>)> {
        match timeout(WAIT, self.delivered.recv()).await {
            Ok(Some((peer, packet))) => Ok((peer, packet.as_packet().to_vec())),
            Ok(None) => Err("sink closed".into()),
            Err(_) => Err(format!("no delivery within {WAIT:?}").into()),
        }
    }

    /// Succeeds if nothing is delivered within [`QUIET`].
    pub async fn expect_no_delivery(&mut self) -> TestResult {
        match timeout(QUIET, self.delivered.recv()).await {
            Ok(Some((peer, packet))) => Err(format!(
                "unexpected delivery of {} bytes from {peer:?}",
                packet.len()
            )
            .into()),
            Ok(None) => Err("sink closed".into()),
            Err(_) => Ok(()),
        }
    }

    /// The id this node's engine gave to `other`.
    pub async fn peer_of<U: Transport>(&self, other: &Node<U>) -> TestResult<PeerId> {
        self.handle
            .peer_id(other.public())
            .await?
            .ok_or_else(|| "unknown peer".into())
    }

    /// How many drops the engine counted under `reason`.
    pub async fn drops(&self, reason: &str) -> TestResult<u64> {
        let counters = self.handle.drop_counters().await?;
        Ok(counters.get(reason).copied().unwrap_or(0))
    }

    /// Subscribes to the engine's events from now on.
    pub async fn subscribe(&self) -> TestResult<Events> {
        Ok(Events(self.handle.subscribe().await?))
    }
}

/// Sends a `family` packet with a payload of `len` bytes from `from` to `to` and checks that
/// it arrives intact and attributed to `from`.
pub async fn transfer<T: Transport>(
    from: &Node<T>,
    to: &mut Node<T>,
    family: Family,
    len: usize,
) -> TestResult {
    let packet = from.packet_to(to, family, &payload(len));
    from.send(&packet).await?;
    let (peer, delivered) = to.expect_delivery().await?;
    if peer != to.peer_of(from).await? {
        return Err(format!("packet attributed to {peer:?}").into());
    }
    if delivered != packet {
        return Err(format!("{family:?} packet of {len} bytes changed in transit").into());
    }
    Ok(())
}

/// Exchanges IPv4 and IPv6 packets, small and of 1300 bytes, in both directions between `a`
/// and `b` with [`transfer`].
pub async fn exchange<T: Transport>(a: &mut Node<T>, b: &mut Node<T>) -> TestResult {
    for family in [Family::V4, Family::V6] {
        for len in [64, 1300] {
            transfer(a, b, family, len).await?;
            transfer(b, a, family, len).await?;
        }
    }
    Ok(())
}

/// The events of one engine since [`Node::subscribe`].
#[derive(Debug)]
pub struct Events(broadcast::Receiver<Event>);

impl Events {
    /// The next event matching `predicate`, within [`WAIT`]; other events are skipped.
    pub async fn expect(&mut self, predicate: impl FnMut(&Event) -> bool) -> TestResult<Event> {
        self.next_matching(WAIT, predicate)
            .await?
            .ok_or_else(|| format!("no matching event within {WAIT:?}").into())
    }

    /// Succeeds if no event matching `predicate` arrives within [`QUIET`], including events
    /// already queued.
    pub async fn expect_none(&mut self, predicate: impl FnMut(&Event) -> bool) -> TestResult {
        if let Some(event) = self.next_matching(QUIET, predicate).await? {
            return Err(format!("unexpected event {event:?}").into());
        }
        Ok(())
    }

    /// The next event matching `predicate` within `within`, or `None`.
    async fn next_matching(
        &mut self,
        within: Duration,
        mut predicate: impl FnMut(&Event) -> bool,
    ) -> TestResult<Option<Event>> {
        let deadline = Instant::now() + within;
        loop {
            match timeout_at(deadline, self.0.recv()).await {
                Ok(Ok(event)) if predicate(&event) => return Ok(Some(event)),
                Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) => return Err("engine stopped".into()),
                Err(_) => return Ok(None),
            }
        }
    }
}

/// Two nodes (seeds 1 and 2) linked by a [`ChannelTransport`] pair, not yet peers.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub fn channel_pair(options: Options) -> (Node<ChannelTransport>, Node<ChannelTransport>) {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a, b);
    (
        Node::new(1, a.0, a.1, link_a, options),
        Node::new(2, b.0, b.1, link_b, options),
    )
}

/// Two nodes (seeds 1 and 2) linked by a [`ChannelTransport`] pair, not yet peers, with
/// `configure` adding settings to the engine builder of each, given its seed.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub fn channel_pair_with(
    options: Options,
    mut configure: impl FnMut(
        u8,
        EngineBuilder<ChannelSource, ChannelSink>,
    ) -> EngineBuilder<ChannelSource, ChannelSink>,
) -> TestResult<(Node<ChannelTransport>, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a, b);
    let node_a = Node::with_builder(1, a.0, a.1, options, |builder| {
        configure(1, builder.transport(link_a))
    })?;
    let node_b = Node::with_builder(2, b.0, b.1, options, |builder| {
        configure(2, builder.transport(link_b))
    })?;
    Ok((node_a, node_b))
}

/// Two nodes (seeds 1 and 2) on [`UdpTransport`]s bound to `ip` with OS-chosen ports, not
/// yet peers.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub fn udp_pair(
    ip: IpAddr,
    options: Options,
) -> io::Result<(Node<UdpTransport>, Node<UdpTransport>)> {
    let node = |seed: u8| -> io::Result<Node<UdpTransport>> {
        let id = TransportId::new(u16::from(seed));
        let transport = UdpTransport::bind(id, SocketAddr::new(ip, 0))?;
        let addr = transport.local_addr();
        Ok(Node::new(seed, id, addr, transport, options))
    };
    Ok((node(1)?, node(2)?))
}

/// Makes `a` and `b` peers of each other, with `psk` on both sides if given.
pub async fn introduce<T: Transport>(
    a: &Node<T>,
    b: &Node<T>,
    psk: Option<[u8; 32]>,
) -> TestResult {
    introduce_with(a, b, psk, psk).await
}

/// Makes `a` and `b` peers of each other; `a` knows `b` with `psk_a`, `b` knows `a` with
/// `psk_b`.
pub async fn introduce_with<T: Transport>(
    a: &Node<T>,
    b: &Node<T>,
    psk_a: Option<[u8; 32]>,
    psk_b: Option<[u8; 32]>,
) -> TestResult {
    a.handle
        .add_or_update_peer(Peer {
            preshared_key: psk_a,
            ..b.as_peer(a.path.transport)
        })
        .await?;
    b.handle
        .add_or_update_peer(Peer {
            preshared_key: psk_b,
            ..a.as_peer(b.path.transport)
        })
        .await?;
    Ok(())
}

/// One engine whose local side is a [`NetStack`] holding the node's tunnel addresses.
///
/// The stack is the engine's whole local side: what the engine decrypts goes into the
/// stack and what the stack emits is encrypted to the peers. [`StackNode::stack`] opens and
/// accepts connections and flows.
pub struct StackNode {
    /// The running engine; dropping it stops the engine and with it the stack.
    pub engine: Engine,
    /// A handle to the engine.
    pub handle: EngineHandle,
    /// The application side of the node's stack.
    pub stack: NetStackHandle,
    /// The node's private key.
    pub secret: StaticSecret,
    /// The node's tunnel IPv4 address, also the stack's.
    pub ip4: Ipv4Addr,
    /// The node's tunnel IPv6 address, also the stack's.
    pub ip6: Ipv6Addr,
    /// The node's own transport id and the address its peers reach it on.
    pub path: Path,
}

impl fmt::Debug for StackNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackNode")
            .field("public", &self.public())
            .field("ip4", &self.ip4)
            .field("ip6", &self.ip6)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StackNode {
    /// Builds a node with key seed `seed` on `transport`, reachable at `addr`, whose stack
    /// runs with `mtu`.
    ///
    /// The seed also picks the tunnel addresses `10.0.0.<seed>` and `fd00::<seed>`, which
    /// are the stack's addresses.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn new<T: Transport>(
        seed: u8,
        id: TransportId,
        addr: SocketAddr,
        transport: T,
        mtu: u16,
    ) -> TestResult<Self> {
        Self::with_source(seed, id, addr, transport, mtu, |source| source)
    }

    /// Builds a node like [`StackNode::new`], with `wrap` turning the stack's egress into
    /// the source the engine reads (to observe the packets the stack emits, say).
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn with_source<T: Transport, S: PacketSource>(
        seed: u8,
        id: TransportId,
        addr: SocketAddr,
        transport: T,
        mtu: u16,
        wrap: impl FnOnce(NetStackSource) -> S,
    ) -> TestResult<Self> {
        let ip4 = Ipv4Addr::new(10, 0, 0, seed);
        let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
        let (stack, handle) = NetStack::new(NetStackConfig::new(
            vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)],
            mtu,
        ));
        let (source, sink) = stack.split();
        let engine = EngineBuilder::new(wrap(source), sink)
            .private_key(StaticSecret::from([seed; 32]))
            .transport(transport)
            .build()?;
        Ok(Self {
            handle: engine.handle(),
            engine,
            stack: handle,
            secret: StaticSecret::from([seed; 32]),
            ip4,
            ip6,
            path: Path {
                transport: id,
                addr,
                ecn: Ecn::NotEct,
            },
        })
    }

    /// Builds a node like [`StackNode::new`], with `configure` adding the transports (any
    /// number, of any types) and further settings, such as packet filters, to the engine
    /// builder. `id` and `addr` are the node's own [`StackNode::path`].
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn with_builder(
        seed: u8,
        id: TransportId,
        addr: SocketAddr,
        mtu: u16,
        configure: impl FnOnce(
            EngineBuilder<NetStackSource, NetStackSink>,
        ) -> EngineBuilder<NetStackSource, NetStackSink>,
    ) -> TestResult<Self> {
        let ip4 = Ipv4Addr::new(10, 0, 0, seed);
        let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
        let (stack, handle) = NetStack::new(NetStackConfig::new(
            vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)],
            mtu,
        ));
        let (source, sink) = stack.split();
        let builder = EngineBuilder::new(source, sink).private_key(StaticSecret::from([seed; 32]));
        let engine = configure(builder).build()?;
        Ok(Self {
            handle: engine.handle(),
            engine,
            stack: handle,
            secret: StaticSecret::from([seed; 32]),
            ip4,
            ip6,
            path: Path {
                transport: id,
                addr,
                ecn: Ecn::NotEct,
            },
        })
    }

    /// The node's public key.
    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// This node as a peer of a node that reaches it over its transport `via`: both tunnel
    /// addresses as /32 and /128 allowed IPs and the node's address as the path.
    pub fn as_peer(&self, via: TransportId) -> Peer {
        Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(self.ip4),
                    cidr: 32,
                },
                AllowedIp {
                    addr: IpAddr::V6(self.ip6),
                    cidr: 128,
                },
            ],
            path: Some(Path {
                transport: via,
                ..self.path
            }),
            ..Peer::new(self.public())
        }
    }

    /// Subscribes to the engine's events from now on.
    pub async fn subscribe(&self) -> TestResult<Events> {
        Ok(Events(self.handle.subscribe().await?))
    }

    /// The node's tunnel address of `family` with `port`.
    pub const fn socket_addr(&self, family: Family, port: u16) -> SocketAddr {
        match family {
            Family::V4 => SocketAddr::new(IpAddr::V4(self.ip4), port),
            Family::V6 => SocketAddr::new(IpAddr::V6(self.ip6), port),
        }
    }
}

/// Two stack nodes (seeds 1 and 2) linked by a [`ChannelTransport`] pair and introduced to
/// each other, with `wrap` applied to both stacks' egress (see [`StackNode::with_source`]).
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub async fn stack_pair_with<S: PacketSource>(
    mtu: u16,
    wrap: impl Fn(NetStackSource) -> S,
) -> TestResult<(StackNode, StackNode)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a, b);
    let a = StackNode::with_source(1, a.0, a.1, link_a, mtu, &wrap)?;
    let b = StackNode::with_source(2, b.0, b.1, link_b, mtu, &wrap)?;
    a.handle
        .add_or_update_peer(b.as_peer(a.path.transport))
        .await?;
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    Ok((a, b))
}

/// Two stack nodes like [`stack_pair_with`], with the stacks' egress read unchanged.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub async fn stack_pair(mtu: u16) -> TestResult<(StackNode, StackNode)> {
    stack_pair_with(mtu, |source| source).await
}

/// The next item of `stream` within `within`; fails if the stream ends.
pub async fn next_within<S: Stream + Unpin>(
    stream: &mut S,
    within: Duration,
) -> TestResult<S::Item> {
    timeout(within, poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)))
        .await
        .map_err(|_| format!("no stream item within {within:?}"))?
        .ok_or_else(|| "stream ended".into())
}

/// Echoes every byte of `conn` until EOF, then shuts its write half down.
async fn echo_tcp(conn: TcpConnection) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(conn);
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}

/// Echoes every datagram of `flow` back on the flow until the stack stops.
async fn echo_udp(mut flow: UdpFlow) -> io::Result<()> {
    let reply = flow.reply_handle();
    while let Some(datagram) = flow.recv().await {
        reply.send(&datagram).await?;
    }
    Ok(())
}

/// Accepts every inbound TCP connection of `stack` and echoes it (see `echo_tcp`) on its
/// own task until the stack stops. An echo that fails shows as missing or truncated data
/// on the client.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub fn serve_tcp_echo(stack: &NetStackHandle) {
    let mut incoming = stack.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)).await {
            tokio::spawn(echo_tcp(conn));
        }
    });
}

/// Accepts every inbound UDP flow of `stack` and echoes its datagrams on the flow, each
/// flow on its own task, until the stack stops.
///
/// Reports each accepted flow as `(remote, local)` on the returned receiver.
///
/// # Panics
///
/// Panics when called outside a tokio runtime.
pub fn serve_udp_echo(stack: &NetStackHandle) -> mpsc::UnboundedReceiver<(SocketAddr, SocketAddr)> {
    let mut incoming = stack.incoming_udp();
    let (flows, accepted) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(flow) = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)).await {
            // The test may have stopped listening; the echo still runs.
            let _ = flows.send((flow.peer_addr(), flow.local_addr()));
            tokio::spawn(echo_udp(flow));
        }
    });
    accepted
}
