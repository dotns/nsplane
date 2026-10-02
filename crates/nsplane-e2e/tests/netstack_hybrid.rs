//! A hybrid local side: node A runs a netstack next to a TUN-like channel pair, joined by a
//! `Splitter` (by destination address) and a `MergeSource`; peer B is an engine with a
//! netstack. TCP to A's stack and raw packets to and from A's TUN side flow at once.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, EngineBuilder, MergeSource,
    PacketBuf, Path, Peer, Splitter, TransportId,
};
use nsplane_e2e::{Family, StackNode, TRANSFER, TestResult, WAIT, serve_tcp_echo, udp};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Capacity of the TUN-like channels.
const CAPACITY: usize = 1024;
/// A's netstack addresses.
const A_STACK4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const A_STACK6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// A host behind A's TUN side, in A's allowed range but not A's netstack.
const A_HOST4: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 5);
const A_HOST6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 5);
/// UDP port of the host behind A's TUN side.
const HOST_PORT: u16 = 4000;
/// UDP port B's sockets are bound to.
const B_PORT: u16 = 7777;
/// TCP port of A's echo server.
const TCP_PORT: u16 = 7;
/// Bytes echoed per TCP round trip.
const BULK: usize = 1 << 20;
/// Datagrams exchanged per direction and family with A's TUN side.
const DATAGRAMS: usize = 16;

/// Whether `packet` is addressed to A's netstack.
fn to_stack(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet.get(16..20) == Some(&A_STACK4.octets()[..]),
        Some(6) => packet.get(24..40) == Some(&A_STACK6.octets()[..]),
        _ => false,
    }
}

/// Source, destination and payload of a UDP packet without IP options or extension headers.
fn udp_parts(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    let port = |at: usize| Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]));
    match packet.first()? >> 4 {
        4 => {
            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some((
                SocketAddr::new(IpAddr::from(src), port(20)?),
                SocketAddr::new(IpAddr::from(dst), port(22)?),
                packet.get(28..)?,
            ))
        }
        6 => {
            let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some((
                SocketAddr::new(IpAddr::from(src), port(40)?),
                SocketAddr::new(IpAddr::from(dst), port(42)?),
                packet.get(48..)?,
            ))
        }
        _ => None,
    }
}

/// Node A as B's peer, reached over B's transport `via` at `addr`: A's netstack addresses
/// and the ranges behind its TUN side are allowed.
fn a_as_peer(secret: &StaticSecret, via: TransportId, addr: SocketAddr) -> Peer {
    let allowed = [
        (IpAddr::V4(A_STACK4), 32),
        (IpAddr::V6(A_STACK6), 128),
        (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
        (IpAddr::V6(Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 0)), 64),
    ];
    Peer {
        allowed_ips: allowed
            .into_iter()
            .map(|(addr, cidr)| AllowedIp { addr, cidr })
            .collect(),
        path: Some(Path {
            transport: via,
            addr,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(PublicKey::from(secret))
    }
}

/// Connects from `client` to `target`, sends [`BULK`] bytes, half-closes and checks that
/// the same bytes come back, followed by EOF.
async fn tcp_round_trip(client: NetStackHandle, target: SocketAddr) -> TestResult {
    let conn = timeout(TRANSFER, client.connect_tcp(target)).await??;
    let sent: Vec<u8> = (0..BULK).map(|i| (i % 251).to_le_bytes()[0]).collect();
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(BULK);
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    if echoed != sent {
        return Err(format!("echo from {target} changed the data").into());
    }
    Ok(())
}

/// Scenario 6: TCP echo to A's netstack, B to A's TUN side and A's TUN side to B, at once.
#[tokio::test]
async fn splitter_and_merge_carry_netstack_and_tun_traffic() -> TestResult {
    let a_path = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_path = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_path, b_path);

    // Node A: netstack and TUN-like channels behind one splitter and one merge.
    let (stack, a_stack) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(A_STACK4), 32), (IpAddr::V6(A_STACK6), 128)],
        DEFAULT_MTU,
    ));
    let (stack_source, stack_sink) = stack.split();
    let (tun_source, tun_in, _tun_mtu) = ChannelSource::new(CAPACITY, DEFAULT_MTU);
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let splitter = Splitter::new(|_peer, packet| usize::from(to_stack(packet.as_packet())))
        .sink(tun_sink)
        .sink(stack_sink);
    let merge = MergeSource::new().source(tun_source).source(stack_source);
    let a_secret = StaticSecret::from([1; 32]);
    let a = EngineBuilder::new(merge, splitter)
        .private_key(a_secret.clone())
        .transport(link_a)
        .build()?;
    let b = StackNode::new(2, b_path.0, b_path.1, link_b, DEFAULT_MTU)?;

    a.handle().add_or_update_peer(b.as_peer(a_path.0)).await?;
    b.handle
        .add_or_update_peer(a_as_peer(&a_secret, b_path.0, a_path.1))
        .await?;
    let b_peer = a
        .handle()
        .peer_id(b.public())
        .await?
        .ok_or("unknown peer")?;

    // The TCP flow to A's netstack runs while the TUN traffic below is exchanged.
    serve_tcp_echo(&a_stack);
    let tcp = tokio::spawn({
        let client = b.stack.clone();
        let (v4, v6) = (
            SocketAddr::new(IpAddr::V4(A_STACK4), TCP_PORT),
            SocketAddr::new(IpAddr::V6(A_STACK6), TCP_PORT),
        );
        async move {
            tcp_round_trip(client.clone(), v4).await?;
            tcp_round_trip(client, v6).await
        }
    });

    for family in [Family::V4, Family::V6] {
        let host = match family {
            Family::V4 => SocketAddr::new(IpAddr::V4(A_HOST4), HOST_PORT),
            Family::V6 => SocketAddr::new(IpAddr::V6(A_HOST6), HOST_PORT),
        };
        let b_addr = b.socket_addr(family, B_PORT);
        let mut socket = timeout(WAIT, b.stack.bind_udp(b_addr)).await??;
        for i in 0..DATAGRAMS {
            // B's stack -> A's TUN side.
            let outbound = format!("to the TUN side {i}");
            socket.send_to(outbound.as_bytes(), host).await?;
            let (peer, packet) = timeout(WAIT, tun_out.recv())
                .await?
                .ok_or("A's TUN sink closed")?;
            assert_eq!(peer, b_peer);
            let (src, dst, payload) =
                udp_parts(packet.as_packet()).ok_or("not a UDP packet on A's TUN side")?;
            assert_eq!((src, dst), (b_addr, host));
            assert_eq!(payload, outbound.as_bytes());

            // A's TUN side -> B's stack.
            let inbound = format!("from the TUN side {i}");
            tun_in
                .send(PacketBuf::from_packet(&udp(
                    host,
                    b_addr,
                    inbound.as_bytes(),
                )))
                .await?;
            let (payload, from) = timeout(WAIT, socket.recv_from()).await??;
            assert_eq!(from, host);
            assert_eq!(&payload[..], inbound.as_bytes());
        }
    }

    timeout(TRANSFER * 2, tcp).await???;
    // None of the netstack's TCP traffic leaked to the TUN side.
    assert!(
        tun_out.try_recv().is_err(),
        "unexpected packet on A's TUN side"
    );
    Ok(())
}
