//! A scripted guest on the far end of a Unix socket pair, speaking the length-prefixed
//! frame protocol: ARP, neighbor discovery, DHCP, and TCP between two user-space stacks
//! through the adapter, through the public API only.
#![cfg(unix)]

use std::error::Error;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_ether::dhcp::{self, option};
use nsplane_ether::frame::{self, HEADER_LEN};
use nsplane_ether::stream::{self, FramedWriter};
use nsplane_ether::{
    ArpOp, ArpPacket, DhcpConfig, DhcpMessage, EtherConfig, EtherHandle, EtherSink, EtherSource,
    EtherType, Frame, MacAddr, MessageType, Ndp, NdpMessage, spawn_port,
};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::checksum::transport_checksum_v6;
use nsplane_packet::{Ipv4Header, Ipv6Header, UdpHeader, protocol, udp_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;
type Sink = EtherSink<FramedWriter<OwnedWriteHalf>>;

const WAIT: Duration = Duration::from_secs(5);
const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0);
const GW_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
const XID: u32 = 0x0bad_cafe;

fn config() -> EtherConfig {
    EtherConfig {
        gateway_ipv4: Some(GW_IP),
        gateway_ipv6: Some(GW_IPV6),
        ipv6_prefix: Some(PREFIX),
        ipv6_dns: vec![GW_IPV6],
        dhcp: Some(DhcpConfig {
            router: Some(GW_IP),
            dns: vec![GW_IP],
            ..DhcpConfig::new(GW_IP, GUEST_IP, 24)
        }),
        ..EtherConfig::new(GW_MAC)
    }
}

/// The guest end of the socket pair.
struct Guest {
    rx: OwnedReadHalf,
    tx: OwnedWriteHalf,
}

/// Writes one length-prefixed frame.
async fn write_frame(tx: &mut OwnedWriteHalf, frame: &[u8]) -> io::Result<()> {
    tx.write_u32(u32::try_from(frame.len()).map_err(io::Error::other)?)
        .await?;
    tx.write_all(frame).await
}

/// Reads one length-prefixed frame; `None` at end of stream.
async fn read_frame(rx: &mut OwnedReadHalf) -> io::Result<Option<Vec<u8>>> {
    let len = match rx.read_u32().await {
        Ok(len) => len,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut frame = vec![0; usize::try_from(len).map_err(io::Error::other)?];
    rx.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// An ethernet frame from the guest.
fn eth(dst: MacAddr, ethertype: EtherType, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = vec![0; HEADER_LEN];
    frame::write_header(&mut out, dst, GUEST_MAC, ethertype)?;
    out.extend_from_slice(payload);
    Ok(out)
}

impl Guest {
    async fn send(
        &mut self,
        dst: MacAddr,
        ethertype: EtherType,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let frame = eth(dst, ethertype, payload)?;
        write_frame(&mut self.tx, &frame).await?;
        Ok(())
    }

    /// Reads frames until `pick` accepts one, failing after [`WAIT`] or 32 frames.
    async fn expect<T>(
        &mut self,
        mut pick: impl FnMut(&Frame<'_>) -> Option<T>,
    ) -> Result<T, Box<dyn Error>> {
        for _ in 0..32 {
            let bytes = timeout(WAIT, read_frame(&mut self.rx))
                .await
                .map_err(|_| "timed out waiting for a frame")??
                .ok_or("transport closed")?;
            let frame = Frame::parse(&bytes)?;
            assert_eq!(frame.src, GW_MAC);
            if let Some(found) = pick(&frame) {
                return Ok(found);
            }
        }
        Err("expected frame never came".into())
    }
}

type Started = (Guest, EtherSource, Sink, EtherHandle);

/// An adapter on one end of a socket pair and the guest on the other.
fn start() -> io::Result<Started> {
    let (ours, theirs) = UnixStream::pair()?;
    let (reader, writer) = stream::unix(ours);
    let (source, sink, handle) = spawn_port(reader, writer, config());
    let (rx, tx) = theirs.into_split();
    Ok((Guest { rx, tx }, source, sink, handle))
}

/// An IPv6 packet carrying the `ICMPv6` message `icmp` with hop limit 255.
fn icmpv6(src: Ipv6Addr, dst: Ipv6Addr, mut icmp: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let sum = transport_checksum_v6(src, dst, protocol::ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&u16::try_from(icmp.len())?.to_be_bytes());
    out.extend_from_slice(&[protocol::ICMPV6, 255]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&icmp);
    Ok(out)
}

/// The options of the neighbor discovery message `icmp` after its `fixed`-byte header.
fn nd_options(icmp: &[u8], fixed: usize) -> Vec<(u8, Vec<u8>)> {
    let mut options = Vec::new();
    let mut rest = icmp.get(fixed..).unwrap_or_default();
    while let [kind, units, ..] = *rest {
        let len = usize::from(units) * 8;
        let Some((option, tail)) = rest.split_at_checked(len.max(2)) else {
            break;
        };
        options.push((kind, option[2..].to_vec()));
        rest = tail;
    }
    options
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
        out.extend_from_slice(&[u8::try_from(data.len()).unwrap_or(u8::MAX)]);
        out.extend_from_slice(data);
    }
    out.push(option::END);
    out
}

impl Guest {
    /// Broadcasts the DHCP message `message` and returns the server's reply message.
    async fn dhcp(&mut self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let packet = udp_packet(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, dhcp::CLIENT_PORT)),
            SocketAddr::from((Ipv4Addr::BROADCAST, dhcp::SERVER_PORT)),
            message,
        )?;
        self.send(MacAddr::BROADCAST, EtherType::IPV4, packet.as_packet())
            .await?;
        self.expect(|frame| {
            if frame.ethertype != EtherType::IPV4 {
                return None;
            }
            let (ip, payload) = Ipv4Header::parse(frame.payload).ok()?;
            let (udp, message) = UdpHeader::parse(payload).ok()?;
            (ip.src() == GW_IP && udp.dst_port() == dhcp::CLIENT_PORT).then(|| message.to_vec())
        })
        .await
    }

    /// Runs DISCOVER / OFFER / REQUEST / ACK and returns the acknowledged address.
    async fn lease(&mut self) -> Result<Ipv4Addr, Box<dyn Error>> {
        let offer = self.dhcp(&dhcp_client(MessageType::Discover, &[])).await?;
        let offer = DhcpMessage::parse(&offer)?;
        assert_eq!(offer.message_type, MessageType::Offer);
        assert_eq!(offer.xid, XID);
        assert_eq!(offer.server_id(), Some(GW_IP));

        let request = dhcp_client(
            MessageType::Request,
            &[
                (option::SERVER_ID, &GW_IP.octets()),
                (option::REQUESTED_IP, &offer.yiaddr.octets()),
            ],
        );
        let ack = self.dhcp(&request).await?;
        let ack = DhcpMessage::parse(&ack)?;
        assert_eq!(ack.message_type, MessageType::Ack);
        assert_eq!(ack.xid, XID);
        assert_eq!(ack.yiaddr, offer.yiaddr);
        assert_eq!(
            ack.option(option::SUBNET_MASK),
            Some(&[255, 255, 255, 0][..])
        );
        assert_eq!(ack.option(option::ROUTER), Some(&GW_IP.octets()[..]));
        assert_eq!(ack.option(option::DNS), Some(&GW_IP.octets()[..]));
        assert!(ack.option(option::LEASE_TIME).is_some());
        Ok(ack.yiaddr)
    }
}

#[tokio::test]
async fn arp_for_the_gateway_is_answered() -> TestResult {
    let (mut guest, _source, _sink, handle) = start()?;
    let mut request = Vec::new();
    ArpPacket {
        op: ArpOp::Request,
        sender_mac: GUEST_MAC,
        sender_ip: GUEST_IP,
        target_mac: MacAddr([0; 6]),
        target_ip: GW_IP,
    }
    .write(&mut request);
    guest
        .send(MacAddr::BROADCAST, EtherType::ARP, &request)
        .await?;
    let (dst, reply) = guest
        .expect(|frame| {
            (frame.ethertype == EtherType::ARP)
                .then(|| {
                    ArpPacket::parse(frame.payload)
                        .ok()
                        .map(|arp| (frame.dst, arp))
                })
                .flatten()
        })
        .await?;
    assert_eq!(dst, GUEST_MAC);
    assert_eq!(reply.op, ArpOp::Reply);
    assert_eq!((reply.sender_mac, reply.sender_ip), (GW_MAC, GW_IP));
    assert_eq!((reply.target_mac, reply.target_ip), (GUEST_MAC, GUEST_IP));
    assert_eq!(handle.guest_mac(), Some(GUEST_MAC));
    assert_eq!(handle.stats().arp_replies, 1);
    Ok(())
}

#[tokio::test]
async fn neighbor_and_router_solicitations_are_answered() -> TestResult {
    let (mut guest, _source, _sink, handle) = start()?;
    let guest_ll = GUEST_MAC.link_local();
    let gw_ll = GW_MAC.link_local();
    let [.., a, b, c] = gw_ll.octets();
    let solicited = Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a, b, c]);

    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&gw_ll.octets());
    ns.extend_from_slice(&[1, 1]);
    ns.extend_from_slice(&GUEST_MAC.0);
    let packet = icmpv6(guest_ll, solicited, ns)?;
    guest
        .send(MacAddr::ipv6_multicast(solicited), EtherType::IPV6, &packet)
        .await?;
    let na = guest
        .expect(|frame| match Ndp::parse(frame.payload) {
            Ok(Some(ndp)) if frame.dst == GUEST_MAC => Some(ndp),
            _ => None,
        })
        .await?;
    assert_eq!((na.src, na.dst), (gw_ll, guest_ll));
    let NdpMessage::NeighborAdvertisement {
        target,
        target_mac,
        router,
        solicited,
        ..
    } = na.message
    else {
        return Err(format!("not a neighbor advertisement: {na:?}").into());
    };
    assert_eq!(target, gw_ll);
    assert_eq!(target_mac, Some(GW_MAC));
    assert!(router && solicited);

    let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    rs.extend_from_slice(&GUEST_MAC.0);
    let packet = icmpv6(guest_ll, all_routers, rs)?;
    guest
        .send(
            MacAddr::ipv6_multicast(all_routers),
            EtherType::IPV6,
            &packet,
        )
        .await?;
    // The unsolicited advertisement on first contact goes to all-nodes; the answer to the
    // solicitation comes unicast.
    let ra = guest
        .expect(|frame| {
            let (ip, icmp) = Ipv6Header::parse(frame.payload).ok()?;
            (ip.dst() == guest_ll && icmp.first() == Some(&134)).then(|| icmp.to_vec())
        })
        .await?;
    let options = nd_options(&ra, 16);
    let prefix = options
        .iter()
        .find(|(kind, _)| *kind == 3)
        .ok_or("no prefix option")?;
    assert_eq!(prefix.1[0], 64);
    assert_eq!(prefix.1[14..30], PREFIX.octets());
    let rdnss = options
        .iter()
        .find(|(kind, _)| *kind == 25)
        .ok_or("no RDNSS option")?;
    assert_eq!(rdnss.1[6..22], GW_IPV6.octets());
    assert!(options.contains(&(1, GW_MAC.0.to_vec())));

    let stats = handle.stats();
    assert_eq!(stats.nd_replies, 3);
    assert_eq!(stats.ip_in, 0);
    Ok(())
}

#[tokio::test]
async fn dhcp_hands_out_the_lease() -> TestResult {
    let (mut guest, _source, _sink, handle) = start()?;
    assert_eq!(guest.lease().await?, GUEST_IP);
    assert_eq!(handle.stats().dhcp_replies, 2);
    Ok(())
}

/// Forwards every packet from `from` to `to`.
async fn forward(mut from: impl PacketSource, to: impl PacketSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// The next item of `stream`, failing after [`WAIT`].
async fn next<S: Stream + Unpin>(stream: &mut S) -> Result<S::Item, Box<dyn Error>> {
    let item = timeout(WAIT, poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)))
        .await
        .map_err(|_| "timed out waiting for the stream")?;
    Ok(item.ok_or("stream ended")?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_between_guest_and_host_stacks() -> TestResult {
    let (mut guest, source, sink, handle) = start()?;
    let leased = guest.lease().await?;

    // Host stack on the IP side of the adapter.
    let (host_stack, host) =
        NetStack::new(NetStackConfig::new(vec![(IpAddr::V4(GW_IP), 24)], 1500));
    let (host_source, host_sink) = host_stack.split();
    tokio::spawn(forward(source, host_sink));
    tokio::spawn(forward(host_source, sink));

    // Guest stack whose packets travel as frames over the socket pair.
    let (guest_stack, guest_net) =
        NetStack::new(NetStackConfig::new(vec![(IpAddr::V4(leased), 24)], 1500));
    let (mut guest_source, guest_sink) = guest_stack.split();
    let Guest { mut rx, mut tx } = guest;
    tokio::spawn(async move {
        while let Ok(packet) = guest_source.recv().await {
            let ethertype = if packet.as_packet().first().map(|b| b >> 4) == Some(6) {
                EtherType::IPV6
            } else {
                EtherType::IPV4
            };
            let Ok(frame) = eth(GW_MAC, ethertype, packet.as_packet()) else {
                break;
            };
            if write_frame(&mut tx, &frame).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(bytes)) = read_frame(&mut rx).await {
            let Ok(frame) = Frame::parse(&bytes) else {
                continue;
            };
            if frame.dst != GUEST_MAC || frame.ethertype != EtherType::IPV4 {
                continue;
            }
            let packet = PacketBuf::from_packet(frame.payload);
            if guest_sink.send(packet, PeerId::new(1)).await.is_err() {
                break;
            }
        }
    });

    let mut incoming = host.incoming_tcp();
    let target = SocketAddr::from((GW_IP, 8080));
    let mut client = timeout(WAIT, guest_net.connect_tcp(target)).await??;
    let mut server = next(&mut incoming).await?;
    assert_eq!(server.local_addr(), target);
    assert_eq!(server.peer_addr(), client.local_addr());
    assert_eq!(server.peer_addr().ip(), IpAddr::V4(leased));

    let upload = vec![0x5a; 64 * 1024];
    timeout(WAIT, client.write_all(&upload)).await??;
    timeout(WAIT, client.shutdown()).await??;
    let mut received = Vec::new();
    timeout(WAIT, server.read_to_end(&mut received)).await??;
    assert_eq!(received, upload);

    timeout(WAIT, server.write_all(b"hello from the host")).await??;
    timeout(WAIT, server.shutdown()).await??;
    let mut response = Vec::new();
    timeout(WAIT, client.read_to_end(&mut response)).await??;
    assert_eq!(response, b"hello from the host");

    timeout(WAIT, client.terminated()).await?;
    timeout(WAIT, server.terminated()).await?;

    let stats = handle.stats();
    assert!(stats.ip_in > 0 && stats.ip_out > 0);
    assert_eq!(stats.drop_no_guest_mac, 0);
    assert_eq!(handle.guest_mac(), Some(GUEST_MAC));
    Ok(())
}

#[tokio::test]
async fn closing_the_transport_breaks_both_sides() -> TestResult {
    let (guest, mut source, sink, _handle) = start()?;
    drop(guest);
    for _ in 0..2 {
        let err = timeout(WAIT, source.recv())
            .await?
            .err()
            .ok_or("packet after close")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
    let packet = PacketBuf::from_packet(&[0x45; 20]);
    let err = sink
        .send(packet, PeerId::new(1))
        .await
        .err()
        .ok_or("send after close")?;
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}
