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

use std::error::Error;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Engine, EngineBuilder, EngineHandle,
    Peer, Transport, UdpTransport,
};
use nsplane_core::Event;
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{Ecn, PacketBuf, Path, PeerId, TransportId, protocol};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, timeout, timeout_at};

/// Upper bound for anything that is expected to happen.
pub const WAIT: Duration = Duration::from_secs(5);
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

/// A recognisable payload of `len` bytes.
pub fn payload(len: usize) -> Vec<u8> {
    (0..=u8::MAX).cycle().take(len).collect()
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
