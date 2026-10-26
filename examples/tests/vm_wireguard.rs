//! The `vm_wireguard` wiring end to end in one process: a scripted guest on one end of a
//! Unix socket pair (DHCP and ARP by hand, then a user-space stack whose packets travel as
//! ethernet frames), the adapter and engine of `nsplane_examples::vm` on the other end, and
//! a second engine on loopback UDP whose local side is a netstack, standing for the remote
//! WireGuard peer. Covers traffic both ways, a second host of the tunnel prefix reached
//! through the adapter's neighbor proxy, the tunnel MTU, the ACL in both directions with a
//! reload, and the IPv6 masquerade.
#![cfg(unix)]

use std::error::Error;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures_core::Stream;
use nsplane::x25519::PublicKey;
use nsplane::{
    ChannelSource, Engine, EngineBuilder, MapSink, MapVerdict, MergeSource, PacketBuf, PacketSink,
    PacketSource, PeerId, UdpTransport,
};
use nsplane_ether::dhcp::{self, option};
use nsplane_ether::frame::{self, HEADER_LEN};
use nsplane_ether::{
    ArpOp, ArpPacket, DhcpMessage, EtherType, Frame, MacAddr, MessageType, Ndp, NdpMessage, stream,
};
use nsplane_examples::node::{
    NodeArgs, PeerSpec, UDP_TRANSPORT, configure_peers, encode_key, encode_public_key,
    generate_key, parse_cidr,
};
use nsplane_examples::vm::{self, GATEWAY_MAC, VmArgs};
use nsplane_netstack::{
    NetStack, NetStackConfig, NetStackHandle, ReassemblyConfig, TransparentConfig,
};
use nsplane_packet::checksum::{internet_checksum, ipv4_header_checksum, transport_checksum_v6};
use nsplane_packet::icmp::echo_reply_in_place;
use nsplane_packet::{Ipv4Header, Ipv6Header, UdpHeader, protocol, udp_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(5);
/// Time an allowed exchange has, handshake included.
const ALLOWED: Duration = Duration::from_secs(10);
/// Time a denied exchange gets before it counts as blocked.
const DENIED: Duration = Duration::from_secs(3);
const MTU: u16 = 1420;
const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
/// The guest's tunnel address, leased by DHCP.
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
/// The remote peer's tunnel address, the guest's default gateway.
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
/// An address behind the remote peer, outside the guest's prefix.
const BEHIND: Ipv4Addr = Ipv4Addr::new(10, 66, 1, 1);
/// A second host of the guest's prefix on the remote side, on-link for the guest.
const SECOND: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 3);
/// The remote peer's IPv6 tunnel address.
const REMOTE6: Ipv6Addr = Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 1);
/// A second host of the advertised `fd66::/64` on the remote side.
const SECOND6: Ipv6Addr = Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 3);
/// The guest's IPv6 address in the advertised `fd66::/64`, as SLAAC would pick it.
const GUEST6: Ipv6Addr = Ipv6Addr::new(0xfd66, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456);
const XID: u32 = 0x0bad_cafe;

/// The `vm_wireguard` command line without its socket.
#[derive(Debug, Parser)]
struct Args {
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    vm: VmArgs,
}

/// The remote WireGuard peer: an engine on a netstack, answering pings.
struct Remote {
    engine: Engine,
    stack: NetStackHandle,
    public_key: PublicKey,
    addr: SocketAddr,
}

/// Starts the remote peer with `addresses`, the network of [`BEHIND`] and the hosts
/// [`SECOND`] and [`SECOND6`]; the VM node's key is `vm_key` and its allowed IPs
/// `vm_allowed`.
async fn remote(
    addresses: &[&str],
    vm_key: PublicKey,
    vm_allowed: &str,
) -> Result<Remote, Box<dyn Error>> {
    let key = generate_key();
    let public_key = PublicKey::from(&key);
    let addresses = addresses
        .iter()
        .map(|cidr| parse_cidr(cidr).map(|ip| (ip.addr, ip.cidr)))
        .collect::<Result<_, _>>()?;
    // The stack owns one address per family; it answers for the network behind the peer
    // and the second hosts transparently.
    let mut config = NetStackConfig::new(addresses, MTU);
    config.reassembly = Some(ReassemblyConfig::default());
    config.transparent = Some(TransparentConfig {
        prefixes: vec![
            (IpAddr::V4(BEHIND), 24),
            (IpAddr::V4(SECOND), 32),
            (IpAddr::V6(SECOND6), 128),
        ],
        ..TransparentConfig::default()
    });
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    // The stack does not answer pings: echo requests are answered here, back into the
    // engine, and never reach the stack.
    let (replies, echo_tx, _mtu) = ChannelSource::new(64, MTU);
    let source = MergeSource::new().source(source).source(replies);
    let sink = MapSink::new(sink, move |packet: &mut PacketBuf, _: PeerId| {
        if !echo_reply_in_place(packet.as_packet_mut()) {
            return MapVerdict::Keep;
        }
        let _ = echo_tx.try_send(PacketBuf::from_packet(packet.as_packet()));
        MapVerdict::Drop
    });
    let udp = UdpTransport::bind(UDP_TRANSPORT, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    let mut vm = PeerSpec::new(vm_key);
    vm.allowed_ips = vm_allowed
        .split('+')
        .map(parse_cidr)
        .collect::<Result<_, _>>()?;
    configure_peers(&engine.handle(), &[vm]).await?;
    Ok(Remote {
        engine,
        stack: handle,
        public_key,
        addr,
    })
}

/// Starts the VM node on one end of a socket pair with the `vm_wireguard` arguments
/// `extra`, connected to `remote`; returns it and the guest's end.
async fn vm_node(
    key: &nsplane::x25519::StaticSecret,
    remote: &Remote,
    allowed: &str,
    extra: &[&str],
) -> Result<(vm::Vm, Guest), Box<dyn Error>> {
    let peer = format!(
        "{},endpoint={},allowed-ips={allowed},keepalive=1",
        encode_public_key(&remote.public_key),
        remote.addr
    );
    let mut argv = vec![
        "vm_wireguard".to_owned(),
        "--private-key".to_owned(),
        encode_key(&key.to_bytes()),
        "--listen".to_owned(),
        "127.0.0.1:0".to_owned(),
        "--peer".to_owned(),
        peer,
        "--log".to_owned(),
        "warn".to_owned(),
    ];
    argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let args = Args::try_parse_from(argv)?;
    let (ours, theirs) = UnixStream::pair()?;
    let (reader, writer) = stream::unix(ours);
    let node = vm::start(reader, writer, &args.node, &args.vm).await?;
    Ok((node, Guest::new(theirs)))
}

/// The guest's end of the socket pair: frames to send and frames received.
struct Guest {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// An ethernet frame from the guest.
fn eth(dst: MacAddr, ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0; HEADER_LEN];
    frame::write_header(&mut out, dst, GUEST_MAC, ethertype).unwrap_or_default();
    out.extend_from_slice(payload);
    out
}

/// A DHCP client message of type `kind` from the guest.
fn dhcp_client(kind: MessageType, options: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![1, 1, 6, 0];
    out.extend_from_slice(&XID.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x80, 0]);
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&GUEST_MAC.0);
    out.extend_from_slice(&[0; 10 + 192]);
    out.extend_from_slice(&[99, 130, 83, 99, option::MESSAGE_TYPE, 1, kind.to_u8()]);
    for (code, data) in options {
        out.push(*code);
        out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(data);
    }
    out.push(option::END);
    out
}

/// The lease the guest got.
struct Lease {
    address: Ipv4Addr,
    mask: Vec<u8>,
    router: Vec<u8>,
    dns: Vec<u8>,
    mtu: Vec<u8>,
}

impl Guest {
    /// Runs the length-prefixed frame protocol on `stream` in two tasks.
    fn new(stream: UnixStream) -> Self {
        let (mut read, mut write) = stream.into_split();
        let (tx, mut outgoing) = mpsc::unbounded_channel::<Vec<u8>>();
        let (incoming, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(frame) = outgoing.recv().await {
                let Ok(len) = u32::try_from(frame.len()) else {
                    break;
                };
                if write.write_u32(len).await.is_err() || write.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Ok(len) = read.read_u32().await {
                let mut frame = vec![0; usize::try_from(len).unwrap_or(0)];
                if read.read_exact(&mut frame).await.is_err() || incoming.send(frame).is_err() {
                    break;
                }
            }
        });
        Self { tx, rx }
    }

    fn send(&self, dst: MacAddr, ethertype: EtherType, payload: &[u8]) -> io::Result<()> {
        self.tx
            .send(eth(dst, ethertype, payload))
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    /// Reads frames until `pick` accepts one, failing after [`WAIT`] or 64 frames.
    async fn expect<T>(
        &mut self,
        mut pick: impl FnMut(&Frame<'_>) -> Option<T>,
    ) -> Result<T, Box<dyn Error>> {
        for _ in 0..64 {
            let bytes = timeout(WAIT, self.rx.recv())
                .await
                .map_err(|_| "timed out waiting for a frame")?
                .ok_or("transport closed")?;
            let frame = Frame::parse(&bytes)?;
            if let Some(found) = pick(&frame) {
                return Ok(found);
            }
        }
        Err("expected frame never came".into())
    }

    /// Broadcasts the DHCP message `message` and returns the server's reply message.
    async fn dhcp(&mut self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let packet = udp_packet(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, dhcp::CLIENT_PORT)),
            SocketAddr::from((Ipv4Addr::BROADCAST, dhcp::SERVER_PORT)),
            message,
        )?;
        self.send(MacAddr::BROADCAST, EtherType::IPV4, packet.as_packet())?;
        self.expect(|frame| {
            let (_, payload) = Ipv4Header::parse(frame.payload).ok()?;
            let (udp, message) = UdpHeader::parse(payload).ok()?;
            (udp.dst_port() == dhcp::CLIENT_PORT).then(|| message.to_vec())
        })
        .await
    }

    /// Runs DISCOVER / OFFER / REQUEST / ACK.
    async fn lease(&mut self) -> Result<Lease, Box<dyn Error>> {
        let offer = self.dhcp(&dhcp_client(MessageType::Discover, &[])).await?;
        let offer = DhcpMessage::parse(&offer)?;
        assert_eq!(offer.message_type, MessageType::Offer);
        let server = offer.server_id().ok_or("no server id")?;
        let request = dhcp_client(
            MessageType::Request,
            &[
                (option::SERVER_ID, &server.octets()),
                (option::REQUESTED_IP, &offer.yiaddr.octets()),
            ],
        );
        let ack = self.dhcp(&request).await?;
        let ack = DhcpMessage::parse(&ack)?;
        assert_eq!(ack.message_type, MessageType::Ack);
        let get = |code| ack.option(code).unwrap_or_default().to_vec();
        Ok(Lease {
            address: ack.yiaddr,
            mask: get(option::SUBNET_MASK),
            router: get(option::ROUTER),
            dns: get(option::DNS),
            mtu: get(option::MTU),
        })
    }

    /// Resolves `target` by ARP.
    async fn arp(&mut self, target: Ipv4Addr) -> Result<MacAddr, Box<dyn Error>> {
        let mut request = Vec::new();
        ArpPacket {
            op: ArpOp::Request,
            sender_mac: GUEST_MAC,
            sender_ip: GUEST,
            target_mac: MacAddr([0; 6]),
            target_ip: target,
        }
        .write(&mut request);
        self.send(MacAddr::BROADCAST, EtherType::ARP, &request)?;
        self.expect(|frame| {
            let arp = ArpPacket::parse(frame.payload).ok()?;
            (frame.ethertype == EtherType::ARP && arp.op == ArpOp::Reply).then_some(arp.sender_mac)
        })
        .await
    }

    /// Resolves `target` by neighbor solicitation from the guest's link-local address.
    async fn ndp(&mut self, target: Ipv6Addr) -> Result<MacAddr, Box<dyn Error>> {
        let src = GUEST_MAC.link_local();
        let [.., x, y, z] = target.octets();
        let dst = Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, x, y, z]);
        let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[1, 1]);
        icmp.extend_from_slice(&GUEST_MAC.0);
        let sum = transport_checksum_v6(src, dst, protocol::ICMPV6, &icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&u16::try_from(icmp.len())?.to_be_bytes());
        packet.extend_from_slice(&[protocol::ICMPV6, 255]);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&icmp);
        self.send(MacAddr::ipv6_multicast(dst), EtherType::IPV6, &packet)?;
        self.expect(|frame| match Ndp::parse(frame.payload) {
            Ok(Some(Ndp {
                message:
                    NdpMessage::NeighborAdvertisement {
                        target: advertised,
                        target_mac,
                        ..
                    },
                ..
            })) if advertised == target => target_mac,
            _ => None,
        })
        .await
    }

    /// Pings `target` with the echo identifier `id`, sending again every half second;
    /// whether a matching echo reply came within `limit`.
    async fn ping(&mut self, target: Ipv4Addr, id: u16, limit: Duration) -> io::Result<bool> {
        let mut icmp = vec![8, 0, 0, 0];
        icmp.extend_from_slice(&id.to_be_bytes());
        icmp.extend_from_slice(&[0, 1]);
        icmp.extend_from_slice(b"ping from the guest");
        let sum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol::ICMP, 0, 0];
        packet[2..4].copy_from_slice(&u16::try_from(20 + icmp.len()).unwrap_or(0).to_be_bytes());
        packet.extend_from_slice(&GUEST.octets());
        packet.extend_from_slice(&target.octets());
        let sum = ipv4_header_checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet.extend_from_slice(&icmp);
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            self.send(GATEWAY_MAC, EtherType::IPV4, &packet)?;
            let wait = tokio::time::Instant::now() + Duration::from_millis(500);
            while let Ok(Some(bytes)) = tokio::time::timeout_at(wait, self.rx.recv()).await {
                let reply = Frame::parse(&bytes).ok().and_then(|frame| {
                    let (ip, icmp) = Ipv4Header::parse(frame.payload).ok()?;
                    Some(
                        ip.src() == target
                            && ip.protocol() == protocol::ICMP
                            && icmp.first() == Some(&0)
                            && icmp.get(4..6) == Some(&id.to_be_bytes()[..]),
                    )
                });
                if reply == Some(true) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Puts a user-space stack with `addresses` on the guest's link: its packets go to the
    /// gateway MAC, every IP packet for the guest goes to it.
    fn attach(self, addresses: Vec<(IpAddr, u8)>) -> NetStackHandle {
        let (stack, handle) = NetStack::new(NetStackConfig::new(addresses, MTU));
        let (mut source, sink) = stack.split();
        let Self { tx, mut rx } = self;
        tokio::spawn(async move {
            while let Ok(packet) = source.recv().await {
                let bytes = packet.as_packet();
                let ethertype = if bytes.first().map(|b| b >> 4) == Some(6) {
                    EtherType::IPV6
                } else {
                    EtherType::IPV4
                };
                if tx.send(eth(GATEWAY_MAC, ethertype, bytes)).is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let Ok(frame) = Frame::parse(&bytes) else {
                    continue;
                };
                if frame.dst != GUEST_MAC
                    || !matches!(frame.ethertype, EtherType::IPV4 | EtherType::IPV6)
                {
                    continue;
                }
                let packet = PacketBuf::from_packet(frame.payload);
                if sink.send(packet, PeerId::new(1)).await.is_err() {
                    break;
                }
            }
        });
        handle
    }
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Echoes every TCP connection and UDP flow `stack` accepts, whatever the port.
fn echo_all(stack: &NetStackHandle) {
    let mut connections = stack.incoming_tcp();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut connections).await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(conn);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
    });
    let mut flows = stack.incoming_udp();
    tokio::spawn(async move {
        while let Some(mut flow) = next(&mut flows).await {
            tokio::spawn(async move {
                while let Some(datagram) = flow.recv().await {
                    let _ = flow.send(&datagram).await;
                }
            });
        }
    });
}

/// Whether one TCP round trip from `stack` to the echo at `target` works within `limit`.
async fn tcp_echo(stack: &NetStackHandle, target: SocketAddr, limit: Duration) -> bool {
    let exchange = async {
        let mut conn = stack.connect_tcp(target).await?;
        conn.write_all(b"hello through the tunnel").await?;
        conn.shutdown().await?;
        let mut echoed = Vec::new();
        conn.read_to_end(&mut echoed).await?;
        io::Result::Ok(echoed == b"hello through the tunnel")
    };
    matches!(timeout(limit, exchange).await, Ok(Ok(true)))
}

/// Whether one UDP round trip from `stack`'s `local` to the echo at `target` works within
/// `limit`, sending again every half second.
async fn udp_echo(
    stack: &NetStackHandle,
    local: SocketAddr,
    target: SocketAddr,
    limit: Duration,
) -> bool {
    let Ok(mut socket) = stack.bind_udp(local).await else {
        return false;
    };
    let exchange = async {
        loop {
            socket.send_to(b"datagram", target).await?;
            if let Ok(reply) = timeout(Duration::from_millis(500), socket.recv_from()).await {
                let (payload, from) = reply?;
                return io::Result::Ok(&payload[..] == b"datagram" && from == target);
            }
        }
    };
    matches!(timeout(limit, exchange).await, Ok(Ok(true)))
}

/// A policy file path unique to this test run.
fn policy_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "nsplane-vm-{name}-{}-{nanos}.json",
        std::process::id()
    )))
}

/// A policy: the guest may open TCP to `from_guest_ports` and ping; `10.66.0.1` may open
/// TCP 2222 to the guest's IPv4 address.
fn write_policy(path: &Path, from_guest_ports: &[u16]) -> io::Result<()> {
    let ports: Vec<_> = from_guest_ports
        .iter()
        .map(|port| serde_json::json!({ "start": port, "end": port }))
        .collect();
    let policy = serde_json::json!({
        "from_guest": [
            { "id": "guest-tcp", "protocols": [{ "Tcp": { "Ranges": ports } }, { "Icmp": "Any" }] }
        ],
        "to_guest": [
            {
                "id": "remote-tcp",
                "sources": ["10.66.0.1/32"],
                "destinations": ["10.66.0.2/32"],
                "protocols": [{ "Tcp": { "Ranges": [{ "start": 2222, "end": 2222 }] } }]
            }
        ]
    });
    std::fs::write(path, serde_json::to_vec_pretty(&policy)?)
}

async fn stop(engines: [Engine; 2]) -> TestResult {
    for engine in engines {
        engine.handle().shutdown().await?;
        timeout(WAIT, engine.wait()).await??;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guest_and_remote_reach_each_other() -> TestResult {
    let vm_key = generate_key();
    let remote = remote(
        &["10.66.0.1/24", "fd66::1/64"],
        PublicKey::from(&vm_key),
        "10.66.0.2/32+fd66::/64",
    )
    .await?;
    echo_all(&remote.stack);
    let (node, mut guest) = vm_node(
        &vm_key,
        &remote,
        "10.66.0.0/24+10.66.1.0/24+fd66::/64",
        &[
            "--address",
            "10.66.0.2/24",
            "--dns",
            "10.66.0.1",
            "--ipv6-prefix",
            "fd66::/64",
        ],
    )
    .await?;

    let lease = guest.lease().await?;
    assert_eq!(lease.address, GUEST);
    assert_eq!(lease.mask, [255, 255, 255, 0]);
    assert_eq!(lease.router, REMOTE.octets());
    assert_eq!(lease.dns, REMOTE.octets());
    assert_eq!(lease.mtu, MTU.to_be_bytes());
    assert_eq!(guest.arp(REMOTE).await?, GATEWAY_MAC);
    // Another host of the prefix: the neighbor proxy answers with the gateway MAC, and the
    // packets the guest sends it reach the remote side.
    assert_eq!(guest.arp(SECOND).await?, GATEWAY_MAC);
    assert_eq!(guest.ndp(SECOND6).await?, GATEWAY_MAC);
    assert!(guest.ping(SECOND, 0x4243, ALLOWED).await?);

    let guest = guest.attach(vec![(IpAddr::V4(GUEST), 24), (IpAddr::V6(GUEST6), 64)]);
    echo_all(&guest);
    // The guest to the peer, to an address behind it, and over IPv6.
    assert!(tcp_echo(&guest, SocketAddr::from((REMOTE, 7)), ALLOWED).await);
    let local = SocketAddr::from((GUEST, 40_000));
    assert!(udp_echo(&guest, local, SocketAddr::from((BEHIND, 7)), ALLOWED).await);
    assert!(tcp_echo(&guest, SocketAddr::from((REMOTE6, 7)), ALLOWED).await);
    assert!(tcp_echo(&guest, SocketAddr::from((SECOND, 7)), ALLOWED).await);
    assert!(tcp_echo(&guest, SocketAddr::from((SECOND6, 7)), ALLOWED).await);
    // The remote side opens connections to the guest.
    assert!(tcp_echo(&remote.stack, SocketAddr::from((GUEST, 2222)), ALLOWED).await);
    assert!(tcp_echo(&remote.stack, SocketAddr::from((GUEST6, 2222)), ALLOWED).await);
    let local = SocketAddr::from((REMOTE, 40_001));
    assert!(udp_echo(&remote.stack, local, SocketAddr::from((GUEST, 53)), ALLOWED).await);

    let stats = node.ether.stats();
    assert_eq!(stats.dhcp_replies, 2);
    assert_eq!((stats.arp_replies, stats.arp_proxied), (2, 1));
    assert_eq!(stats.nd_proxied, 1);
    assert!(stats.ip_in > 0 && stats.ip_out > 0);
    assert_eq!(stats.drop_backlog, 0);
    stop([node.engine, remote.engine]).await
}

/// An IPv4 UDP packet of `len` bytes in all from the guest to `dst`, DF set or clear.
fn big_ipv4(dst: SocketAddr, len: usize, df: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let packet = udp_packet(
        SocketAddr::from((GUEST, 40_000)),
        dst,
        &vec![0x5a; len - 28],
    )?;
    let mut bytes = packet.as_packet().to_vec();
    bytes[6] = if df { 0x40 } else { 0 };
    bytes[10..12].copy_from_slice(&[0, 0]);
    let sum = ipv4_header_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_above_the_tunnel_mtu() -> TestResult {
    let vm_key = generate_key();
    let remote = remote(
        &["10.66.0.1/24", "fd66::1/64"],
        PublicKey::from(&vm_key),
        "10.66.0.2/32+fd66::/64",
    )
    .await?;
    let mut sink = remote.stack.bind_udp(SocketAddr::from((REMOTE, 9))).await?;
    let (node, mut guest) = vm_node(
        &vm_key,
        &remote,
        "10.66.0.0/24+fd66::/64",
        &["--address", "10.66.0.2/24", "--ipv6-prefix", "fd66::/64"],
    )
    .await?;
    guest.lease().await?;
    let target = SocketAddr::from((REMOTE, 9));

    // DF set: refused with an ICMP Fragmentation Needed carrying the tunnel MTU.
    guest.send(GATEWAY_MAC, EtherType::IPV4, &big_ipv4(target, 1500, true)?)?;
    let mtu = guest
        .expect(|frame| {
            let (ip, icmp) = Ipv4Header::parse(frame.payload).ok()?;
            (ip.protocol() == protocol::ICMP && icmp.first() == Some(&3) && icmp.get(1) == Some(&4))
                .then(|| u16::from_be_bytes([icmp[6], icmp[7]]))
        })
        .await?;
    assert_eq!(mtu, MTU);

    // DF clear: split into fragments that fit and reassembled by the remote stack. The first
    // datagrams may meet the handshake; send until one arrives.
    let datagram = async {
        loop {
            guest.send(
                GATEWAY_MAC,
                EtherType::IPV4,
                &big_ipv4(target, 1500, false)?,
            )?;
            if let Ok(received) = timeout(Duration::from_millis(500), sink.recv_from()).await {
                return Ok::<_, Box<dyn Error>>(received?);
            }
        }
    };
    let (payload, from) = timeout(ALLOWED, datagram).await??;
    assert_eq!(payload.len(), 1500 - 28);
    assert_eq!(from, SocketAddr::from((GUEST, 40_000)));

    // IPv6: refused with a Packet Too Big carrying the tunnel MTU.
    let six = udp_packet(
        SocketAddr::from((GUEST6, 40_000)),
        SocketAddr::from((REMOTE6, 9)),
        &[0x5a; 1500 - 48],
    )?;
    guest.send(GATEWAY_MAC, EtherType::IPV6, six.as_packet())?;
    let mtu = guest
        .expect(|frame| {
            let (ip, icmp) = Ipv6Header::parse(frame.payload).ok()?;
            (ip.next_header() == protocol::ICMPV6 && icmp.first() == Some(&2))
                .then(|| u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]))
        })
        .await?;
    assert_eq!(mtu, u32::from(MTU));

    let stats = node.engine.handle().fragment_stats().await?;
    assert!(stats.fragmented >= 1);
    assert!(stats.frag_needed_sent >= 1 && stats.ptb_sent >= 1);
    stop([node.engine, remote.engine]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_decides_both_directions_and_reloads() -> TestResult {
    let policy = policy_path("acl")?;
    write_policy(&policy, &[7])?;
    let vm_key = generate_key();
    let remote = remote(
        &["10.66.0.1/24", "fd66::1/64"],
        PublicKey::from(&vm_key),
        "10.66.0.2/32+fd66::/64",
    )
    .await?;
    echo_all(&remote.stack);
    let policy_arg = policy.to_string_lossy().into_owned();
    let (node, mut guest) = vm_node(
        &vm_key,
        &remote,
        "10.66.0.0/24+fd66::/64",
        &[
            "--address",
            "10.66.0.2/24",
            "--ipv6-prefix",
            "fd66::/64",
            "--policy",
            &policy_arg,
        ],
    )
    .await?;
    let acl = node.acl.clone().ok_or("no ACL")?;
    guest.lease().await?;
    // A ping the outbound rule accepts gets its echo reply back.
    assert!(guest.ping(REMOTE, 0x4242, ALLOWED).await?);
    assert!(acl.stats().replies > 0);
    let guest = guest.attach(vec![(IpAddr::V4(GUEST), 24), (IpAddr::V6(GUEST6), 64)]);
    echo_all(&guest);

    // From the guest: TCP 7 is allowed, TCP 8 is not.
    assert!(tcp_echo(&guest, SocketAddr::from((REMOTE, 7)), ALLOWED).await);
    assert!(!tcp_echo(&guest, SocketAddr::from((REMOTE, 8)), DENIED).await);
    let stats = acl.stats();
    assert!(stats.outbound_denied > 0, "{stats:?}");
    assert!(stats.replies > 0, "{stats:?}");

    // To the guest: TCP 2222 to its IPv4 address is allowed; another port, or the same port
    // on another destination (its IPv6 address), is not.
    assert!(tcp_echo(&remote.stack, SocketAddr::from((GUEST, 2222)), ALLOWED).await);
    let denied = acl.stats().denied;
    assert!(!tcp_echo(&remote.stack, SocketAddr::from((GUEST, 2223)), DENIED).await);
    let after_port = acl.stats().denied;
    assert!(after_port > denied);
    assert!(!tcp_echo(&remote.stack, SocketAddr::from((GUEST6, 2222)), DENIED).await);
    assert!(acl.stats().denied > after_port);
    assert!(acl.stats().accepted > 0);

    // A reload opens TCP 8 from the guest without a restart; a broken file keeps it.
    assert!(!acl.reload().await, "unchanged file");
    write_policy(&policy, &[7, 8])?;
    assert!(acl.reload().await);
    assert!(tcp_echo(&guest, SocketAddr::from((REMOTE, 8)), ALLOWED).await);
    std::fs::write(&policy, b"{ not json")?;
    assert!(!acl.reload().await);
    assert!(tcp_echo(&guest, SocketAddr::from((REMOTE, 8)), ALLOWED).await);
    let status = acl.status_json();
    assert_eq!(status["reloads"], 1);
    assert_eq!(status["reload_errors"], 1);

    std::fs::remove_file(&policy)?;
    stop([node.engine, remote.engine]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn masquerade_gives_the_guest_the_tunnel_ipv6_address() -> TestResult {
    let tunnel6 = Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 2);
    let guest6 = Ipv6Addr::new(0xfd00, 1, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456);
    let vm_key = generate_key();
    let remote = remote(
        &["10.66.0.1/24", "fd66::1/64"],
        PublicKey::from(&vm_key),
        "10.66.0.2/32+fd66::2/128",
    )
    .await?;
    let mut incoming = remote.stack.incoming_tcp();
    let (node, mut guest) = vm_node(
        &vm_key,
        &remote,
        "10.66.0.0/24+fd66::/64",
        &[
            "--address",
            "10.66.0.2/24",
            "--ipv6-prefix",
            "fd00:1::/64",
            "--masquerade",
            "fd66::2",
        ],
    )
    .await?;
    guest.lease().await?;
    let guest = guest.attach(vec![(IpAddr::V4(GUEST), 24), (IpAddr::V6(guest6), 64)]);

    let target = SocketAddr::from((REMOTE6, 80));
    let mut client = timeout(ALLOWED, guest.connect_tcp(target)).await??;
    let mut server = timeout(WAIT, next(&mut incoming))
        .await?
        .ok_or("no connection")?;
    assert_eq!(server.peer_addr().ip(), IpAddr::V6(tunnel6));
    assert_eq!(client.local_addr().ip(), IpAddr::V6(guest6));
    timeout(WAIT, server.write_all(b"to the masqueraded guest")).await??;
    timeout(WAIT, server.shutdown()).await??;
    let mut received = Vec::new();
    timeout(WAIT, client.read_to_end(&mut received)).await??;
    assert_eq!(received, b"to the masqueraded guest");

    let stats = node.masquerade.as_ref().ok_or("no masquerade")?.stats();
    assert_eq!(stats.created, 1);
    assert!(stats.forwarded > 0 && stats.reversed > 0);
    stop([node.engine, remote.engine]).await
}
