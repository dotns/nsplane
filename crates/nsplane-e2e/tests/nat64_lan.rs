//! `Nat64Lan` on a subnet gateway: an IPv6-only client engine reaches an IPv4 LAN host
//! behind a gateway engine whose local side is wrapped with `Nat64LanSink` /
//! `Nat64LanSource`. The client addresses the host as `MAPPED::/96` plus its IPv4 address
//! and routes the /96 to the gateway.
//!
//! With a netstack as the LAN host, TCP and UDP echoes come back through the translation;
//! with the gateway's local side as test channels, an `ICMPv6` echo is answered by hand,
//! and port exhaustion, unsafe targets and `remove_flow` are checked against
//! `Nat64Lan::stats` and the SNAT port reservations.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, Engine, EngineBuilder, PacketBuf,
    PacketSink, PacketSource, Path, Peer, PeerId, TransportId,
};
use nsplane_e2e::{
    Node, Options, QUIET, StackNode, TRANSFER, TestResult, WAIT, icmp, payload, serve_tcp_echo,
    serve_udp_echo, udp, verify_checksums,
};
use nsplane_nat::{
    DefaultSnatPorts, LanRoute, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource, SnatPorts,
};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackHandle};
use nsplane_packet::{Ipv4Header, Ipv6Header, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The IPv6 /96 the client reaches the LAN through.
const MAPPED: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x64, 0, 0, 0, 0, 0, 0);
/// The LAN behind the gateway, its host and the gateway's SNAT address on it.
const REAL: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 0);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 10);
const SNAT: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 1);
/// Key seeds of the client and the gateway; the client's tunnel address is `fd00::1`.
const CLIENT_SEED: u8 = 1;
const GATEWAY_SEED: u8 = 2;
/// Capacity of the gateway's channels and the link.
const CAPACITY: usize = 1024;
/// Client MTU; the LAN stack runs 20 bytes below it, so a translated packet fits either way.
const MTU: u16 = 1420;
const LAN_MTU: u16 = MTU - 20;

/// The client's and the gateway's transport ids and addresses.
const CLIENT_PATH: (TransportId, SocketAddr) = (
    TransportId::new(1),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000),
);
const GATEWAY_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);

/// The address of the LAN host `host` inside `MAPPED`.
fn mapped(host: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(MAPPED) | u128::from(u32::from(host)))
}

const fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

/// SNAT ports that can refuse every reservation and record every release.
#[derive(Debug, Default)]
struct Ports {
    inner: DefaultSnatPorts,
    refuse: AtomicBool,
    released: Mutex<Vec<SocketAddrV4>>,
}

impl SnatPorts for Ports {
    fn reserve(&self, protocol: u8, snat: SocketAddrV4) -> bool {
        !self.refuse.load(Ordering::Relaxed) && self.inner.reserve(protocol, snat)
    }

    fn release(&self, protocol: u8, snat: SocketAddrV4) {
        self.released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(snat);
        self.inner.release(protocol, snat);
    }
}

/// The translator of the gateway: `MAPPED::/96` to `REAL/24`, from `SNAT`, through `ports`.
fn nat(ports: Arc<Ports>) -> TestResult<Arc<Nat64Lan>> {
    let route = LanRoute::new((MAPPED, 96), (REAL, 24), SNAT)?;
    Ok(Arc::new(Nat64Lan::with_snat_ports(
        Arc::new(ArcSwap::from_pointee(vec![route])),
        Nat64LanConfig::default(),
        ports,
    )))
}

/// The gateway engine on `link` with its local side wrapped around `nat`, and `client` (the
/// client as a peer of the gateway) added.
async fn gateway<S: PacketSource, K: PacketSink>(
    (source, sink): (S, K),
    nat: &Arc<Nat64Lan>,
    link: ChannelTransport,
    client: Peer,
) -> TestResult<Engine> {
    let engine = EngineBuilder::new(
        Nat64LanSource::new(source, Arc::clone(nat)),
        Nat64LanSink::new(sink, Arc::clone(nat)),
    )
    .private_key(StaticSecret::from([GATEWAY_SEED; 32]))
    .transport(link)
    .build()?;
    engine.handle().add_or_update_peer(client).await?;
    Ok(engine)
}

/// The gateway as the client's peer: the mapped /96 is routed to it.
fn gateway_as_peer() -> Peer {
    Peer {
        allowed_ips: vec![AllowedIp {
            addr: IpAddr::V6(MAPPED),
            cidr: 96,
        }],
        path: Some(Path {
            transport: CLIENT_PATH.0,
            addr: GATEWAY_PATH.1,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(PublicKey::from(&StaticSecret::from([GATEWAY_SEED; 32])))
    }
}

/// A netstack client and a gateway whose LAN host is a netstack holding `LAN_HOST`.
struct StackSetup {
    client: StackNode,
    lan: NetStackHandle,
    nat: Arc<Nat64Lan>,
    _gateway: Engine,
}

async fn stack_setup() -> TestResult<StackSetup> {
    let (link_client, link_gateway) = ChannelTransport::pair(CAPACITY, CLIENT_PATH, GATEWAY_PATH);
    let client = StackNode::new(CLIENT_SEED, CLIENT_PATH.0, CLIENT_PATH.1, link_client, MTU)?;
    let (stack, lan) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(LAN_HOST), 24)],
        LAN_MTU,
    ));
    let nat = nat(Arc::default())?;
    let gateway = gateway(
        stack.split(),
        &nat,
        link_gateway,
        client.as_peer(GATEWAY_PATH.0),
    )
    .await?;
    client.handle.add_or_update_peer(gateway_as_peer()).await?;
    Ok(StackSetup {
        client,
        lan,
        nat,
        _gateway: gateway,
    })
}

/// A raw client and a gateway whose local side is test channels: the test plays the LAN.
struct RawSetup {
    client: Node<ChannelTransport>,
    /// Feeds the gateway's local side (LAN packets to translate back).
    lan_out: mpsc::Sender<PacketBuf>,
    /// What the gateway delivers to its local side (translated packets for the LAN).
    lan_in: mpsc::Receiver<(PeerId, PacketBuf)>,
    nat: Arc<Nat64Lan>,
    ports: Arc<Ports>,
    _gateway: Engine,
}

async fn raw_setup() -> TestResult<RawSetup> {
    let (link_client, link_gateway) = ChannelTransport::pair(CAPACITY, CLIENT_PATH, GATEWAY_PATH);
    let client = Node::new(
        CLIENT_SEED,
        CLIENT_PATH.0,
        CLIENT_PATH.1,
        link_client,
        Options::default(),
    );
    let (source, lan_out, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (sink, lan_in) = ChannelSink::new(CAPACITY);
    let ports = Arc::new(Ports::default());
    let nat = nat(Arc::clone(&ports))?;
    let gateway = gateway(
        (source, sink),
        &nat,
        link_gateway,
        client.as_peer(GATEWAY_PATH.0),
    )
    .await?;
    client.handle.add_or_update_peer(gateway_as_peer()).await?;
    Ok(RawSetup {
        client,
        lan_out,
        lan_in,
        nat,
        ports,
        _gateway: gateway,
    })
}

impl RawSetup {
    /// The next packet the gateway hands to the LAN, checked to be IPv4 from `SNAT` to `dst`
    /// with protocol `proto` and valid checksums.
    async fn expect_lan(&mut self, dst: Ipv4Addr, proto: u8) -> TestResult<Vec<u8>> {
        let (_, packet) = timeout(WAIT, self.lan_in.recv())
            .await?
            .ok_or("gateway sink closed")?;
        let packet = packet.as_packet().to_vec();
        verify_checksums(&packet)?;
        let (ip, _) = Ipv4Header::parse(&packet)?;
        assert_eq!((ip.src(), ip.dst(), ip.protocol()), (SNAT, dst, proto));
        Ok(packet)
    }

    /// Succeeds if the gateway hands nothing to the LAN within [`QUIET`].
    async fn expect_no_lan(&mut self) -> TestResult {
        match timeout(QUIET, self.lan_in.recv()).await {
            Ok(Some((_, packet))) => {
                Err(format!("unexpected LAN packet of {} bytes", packet.len()).into())
            }
            Ok(None) => Err("gateway sink closed".into()),
            Err(_) => Ok(()),
        }
    }

    /// Sends a UDP datagram from the client's port `port` to `target` (mapped).
    async fn send_udp(&self, port: u16, target: Ipv4Addr) -> TestResult {
        let packet = udp(
            v6(self.client.ip6, port),
            v6(mapped(target), 53),
            &payload(32),
        );
        self.client.send(&packet).await
    }
}

/// The SNAT port of a packet the gateway hands to the LAN (IPv4 without options): the UDP
/// or TCP source port, or the ICMP echo identifier.
const fn snat_port(packet: &[u8]) -> u16 {
    let at = if packet[9] == protocol::ICMP { 24 } else { 20 };
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

#[tokio::test]
async fn tcp_echo_through_the_gateway() -> TestResult {
    let setup = stack_setup().await?;
    serve_tcp_echo(&setup.lan);
    let target = v6(mapped(LAN_HOST), 7);
    let conn = timeout(TRANSFER, setup.client.stack.connect_tcp(target)).await??;
    let sent = payload(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(sent.len());
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    assert!(echoed == sent, "the echo changed the data");

    let stats = setup.nat.stats();
    assert!(stats.forwarded > 0 && stats.reversed > 0, "{stats:?}");
    assert_eq!(
        (stats.unsafe_target, stats.port_exhausted, stats.other_drops),
        (0, 0, 0)
    );
    assert_eq!(stats.conntrack.inserted, 1);
    Ok(())
}

#[tokio::test]
async fn udp_echo_through_the_gateway() -> TestResult {
    let setup = stack_setup().await?;
    let mut accepted = serve_udp_echo(&setup.lan);
    let target = v6(mapped(LAN_HOST), 9);
    let mut socket = timeout(WAIT, setup.client.stack.bind_udp(v6(setup.client.ip6, 0))).await??;
    for i in 0..4 {
        let datagram = format!("datagram {i}");
        socket.send_to(datagram.as_bytes(), target).await?;
        let (echoed, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!((&echoed[..], from), (datagram.as_bytes(), target));
    }
    // The LAN host saw one flow, from the SNAT address.
    let (remote, local) = timeout(WAIT, accepted.recv()).await?.ok_or("no UDP flow")?;
    assert_eq!(
        (remote.ip(), local),
        (IpAddr::V4(SNAT), SocketAddr::from((LAN_HOST, 9)))
    );
    assert!(accepted.try_recv().is_err(), "more than one flow");

    let stats = setup.nat.stats();
    assert_eq!((stats.forwarded, stats.reversed), (4, 4));
    assert_eq!(stats.conntrack.inserted, 1);
    Ok(())
}

#[tokio::test]
async fn icmpv6_echo_is_answered_through_the_gateway() -> TestResult {
    let mut setup = raw_setup().await?;
    let client6 = setup.client.ip6;
    let data = payload(56);
    let request = icmp(
        client6.into(),
        mapped(LAN_HOST).into(),
        (128, 0),
        [0x12, 0x34, 0, 1],
        &data,
    );
    setup.client.send(&request).await?;
    let translated = setup.expect_lan(LAN_HOST, protocol::ICMP).await?;
    assert_eq!(translated[20], 8, "ICMP echo request");
    let id = snat_port(&translated);

    // The LAN host answers the SNAT address with the gateway's identifier.
    let [hi, lo] = id.to_be_bytes();
    let reply = icmp(LAN_HOST.into(), SNAT.into(), (0, 0), [hi, lo, 0, 1], &data);
    setup.lan_out.send(PacketBuf::from_packet(&reply)).await?;
    let (_, packet) = setup.client.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, message) = Ipv6Header::parse(&packet)?;
    assert_eq!(
        (ip.src(), ip.dst(), ip.next_header()),
        (mapped(LAN_HOST), client6, protocol::ICMPV6)
    );
    assert_eq!(message[..2], [129, 0], "ICMPv6 echo reply");
    assert_eq!(message[4..8], [0x12, 0x34, 0, 1], "original identifier");
    assert_eq!(&message[8..], &data[..]);

    let stats = setup.nat.stats();
    assert_eq!((stats.forwarded, stats.reversed), (1, 1));
    Ok(())
}

#[tokio::test]
async fn unsafe_targets_are_rejected_and_counted() -> TestResult {
    let mut setup = raw_setup().await?;
    // The broadcast address of the LAN, loopback and an address outside it, all mapped.
    for target in [
        Ipv4Addr::new(192, 168, 50, 255),
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(192, 168, 51, 10),
    ] {
        setup.send_udp(40000, target).await?;
    }
    setup.expect_no_lan().await?;
    let stats = setup.nat.stats();
    assert_eq!((stats.unsafe_target, stats.forwarded), (3, 0));
    assert_eq!(stats.conntrack.inserted, 0);
    Ok(())
}

#[tokio::test]
async fn port_exhaustion_is_rejected_and_counted() -> TestResult {
    let mut setup = raw_setup().await?;
    setup.ports.refuse.store(true, Ordering::Relaxed);
    setup.send_udp(40000, LAN_HOST).await?;
    setup.expect_no_lan().await?;
    let stats = setup.nat.stats();
    assert_eq!((stats.port_exhausted, stats.forwarded), (1, 0));

    // Once ports are free again, the next datagram opens the flow.
    setup.ports.refuse.store(false, Ordering::Relaxed);
    setup.send_udp(40000, LAN_HOST).await?;
    setup.expect_lan(LAN_HOST, protocol::UDP).await?;
    assert_eq!(setup.nat.stats().forwarded, 1);
    Ok(())
}

#[tokio::test]
async fn remove_flow_releases_the_snat_port() -> TestResult {
    let mut setup = raw_setup().await?;
    setup.send_udp(40000, LAN_HOST).await?;
    let translated = setup.expect_lan(LAN_HOST, protocol::UDP).await?;
    let snat = SocketAddrV4::new(SNAT, snat_port(&translated));
    let target = SocketAddrV4::new(LAN_HOST, 53);

    assert!(setup.nat.remove_flow(protocol::UDP, snat, target));
    assert_eq!(
        *setup.ports.released.lock().map_err(|e| e.to_string())?,
        [snat]
    );
    assert!(setup.ports.inner.is_empty());
    assert!(!setup.nat.remove_flow(protocol::UDP, snat, target));

    // A LAN reply of the removed flow is no longer translated: it reaches no peer.
    let reply = udp(target.into(), snat.into(), &payload(16));
    setup.lan_out.send(PacketBuf::from_packet(&reply)).await?;
    setup.client.expect_no_delivery().await?;
    let stats = setup.nat.stats();
    assert_eq!((stats.reversed, stats.not_ours), (0, 1));
    assert_eq!(stats.conntrack.entries, 0);
    Ok(())
}
