//! A producer that allocates its packets with `PipeSink::alloc` or from a
//! `ChannelSource::pool` gets the buffers back from the engine it feeds: after a warm-up,
//! it allocates nothing new.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, Engine, EngineBuilder, PacketBuf,
    PacketSink, PacketSource, Path, Peer, PeerId, TransportId, pipe,
};
use nsplane_e2e::{MTU, Node, Options, TestResult, payload, udp4};

const SEED: u8 = 1;

/// Packets sent before the producer's allocations are counted.
const WARM_UP: usize = 16;

/// Packets sent after the warm-up.
const PACKETS: usize = 10_000;

/// Engine A on `source`, linked over a `ChannelTransport` to a node B that delivers what A
/// sends; returns A (keep it alive) and B.
async fn link(source: impl PacketSource) -> TestResult<(Engine, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let (sink, _delivered) = ChannelSink::new(16);
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([SEED; 32]))
        .transport(link_a)
        .build()?;
    let node = Node::new(2, b.0, b.1, link_b, Options::default());
    engine
        .handle()
        .add_or_update_peer(node.as_peer(a.0))
        .await?;
    node.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, SEED)),
                cidr: 32,
            }],
            path: Some(Path {
                transport: b.0,
                addr: a.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(PublicKey::from(&StaticSecret::from([SEED; 32])))
        })
        .await?;
    Ok((engine, node))
}

/// Packet `n` from A's tunnel address to B's.
fn packet(node: &Node<ChannelTransport>, n: usize) -> Vec<u8> {
    udp4(
        Ipv4Addr::new(10, 0, 0, SEED),
        node.ip4,
        &payload(100 + n % 64),
    )
}

/// Copies `packet` into `buf`, which holds `packet.len()` bytes.
fn fill(mut buf: PacketBuf, packet: &[u8]) -> PacketBuf {
    buf.as_packet_mut().copy_from_slice(packet);
    buf
}

#[tokio::test]
async fn pipe_producer_reuses_the_engines_buffers() -> TestResult {
    let (sink, source) = pipe(64, MTU);
    let (_engine, mut node) = link(source).await?;

    // One packet at a time: each one's buffer is recycled into the pipe's pool when the next
    // one is read, so every allocation after the first few reuses a warm-up buffer.
    let mut warm = HashSet::new();
    for n in 0..WARM_UP + PACKETS {
        let packet = packet(&node, n);
        let mut buf = sink.alloc(packet.len());
        let base = buf.with_headroom_mut().as_ptr() as usize;
        if n < WARM_UP {
            warm.insert(base);
        } else {
            assert!(warm.contains(&base), "packet {n} got a new buffer");
        }
        sink.send(fill(buf, &packet), PeerId::new(1)).await?;
        assert_eq!(node.expect_delivery().await?.1, packet);
    }
    Ok(())
}

#[tokio::test]
async fn channel_producer_stops_allocating() -> TestResult {
    let (source, tx, _mtu) = ChannelSource::new(64, MTU);
    let pool = source.pool();
    let (_engine, mut node) = link(source).await?;

    let mut warmed = 0;
    for n in 0..WARM_UP + PACKETS {
        if n == WARM_UP {
            warmed = pool.allocated();
        }
        let packet = packet(&node, n);
        tx.send(fill(pool.alloc(packet.len()), &packet)).await?;
        assert_eq!(node.expect_delivery().await?.1, packet);
    }
    assert!(warmed > 0);
    assert_eq!(pool.allocated(), warmed);
    Ok(())
}
