//! A producer that allocates its packets with `PipeSink::alloc` or from a
//! `ChannelSource::pool` gets the buffers back from the engine it feeds, from the consumer
//! of the packets the engine delivered, or from the TUN sink a `pump` writes them to: after a
//! warm-up, it allocates nothing new.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, Engine, EngineBuilder, PacketBuf,
    PacketSink, PacketSource, Path, Peer, PeerId, SharedPacketPool, TransportId, pipe,
};
use nsplane_e2e::{MTU, Node, Options, TestResult, WAIT, channel_pair, introduce, payload, udp4};
use tokio::time::timeout;

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

#[tokio::test]
async fn consumer_returns_delivered_buffers_to_the_producer_pool() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    // A pool of its own: A's `ChannelSource` declines the engine's buffers, so only B's
    // consumer refills it.
    let pool = SharedPacketPool::new(64);
    let mut back = Vec::with_capacity(1);

    let mut warmed = 0;
    for n in 0..WARM_UP + PACKETS {
        if n == WARM_UP {
            warmed = pool.allocated();
        }
        let packet = a.packet_to(&b, nsplane_e2e::Family::V4, &payload(100 + n % 64));
        a.local
            .send(fill(pool.alloc(packet.len()), &packet))
            .await?;
        let (_, delivered) = timeout(WAIT, b.delivered.recv())
            .await?
            .ok_or("B stopped")?;
        assert_eq!(delivered.as_packet(), packet);
        back.push(delivered);
        pool.recycle(&mut back);
        back.clear();
    }
    assert!(warmed > 0);
    assert_eq!(pool.allocated(), warmed);
    Ok(())
}

/// `pump` into a `TunSink` hands the buffers it wrote back to the source's pool. No root
/// needed: the device fd is one end of a datagram socket pair.
#[cfg(target_os = "linux")]
mod pump_to_tun {
    use std::os::fd::OwnedFd;

    use nsplane::pump;
    use nsplane_tun::{Tun, TunSink};
    use tokio::net::UnixDatagram;

    use super::*;

    /// Packets per round, all sent before any is read back.
    const ROUND: usize = 8;

    /// Rounds sent before the producer's allocations are counted.
    const WARM_ROUNDS: usize = WARM_UP / ROUND;

    /// Rounds sent after the warm-up.
    const ROUNDS: usize = PACKETS / ROUND;

    /// A TUN sink over a socket pair and the host end that reads what it writes.
    fn device() -> TestResult<(TunSink, UnixDatagram)> {
        let (fd, host) = std::os::unix::net::UnixDatagram::pair()?;
        host.set_nonblocking(true)?;
        let (_source, sink) = Tun::from_fd(OwnedFd::from(fd), MTU)?.split()?;
        Ok((sink, UnixDatagram::from_std(host)?))
    }

    /// The packets of round `round`.
    fn round(round: usize) -> Vec<Vec<u8>> {
        (0..ROUND)
            .map(|i| {
                udp4(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    &payload(100 + (round * ROUND + i) % 64),
                )
            })
            .collect()
    }

    /// Reads `packets` from the host end, in order.
    async fn expect(host: &UnixDatagram, packets: &[Vec<u8>]) -> TestResult {
        let mut read = vec![0; usize::from(MTU)];
        for packet in packets {
            let len = timeout(WAIT, host.recv(&mut read)).await??;
            assert_eq!(&read[..len], packet);
        }
        Ok(())
    }

    #[tokio::test]
    async fn pipe_producer_reuses_the_written_buffers() -> TestResult {
        let (tun, host) = device()?;
        let (sink, source) = pipe(64, MTU);
        let pumping = tokio::spawn(pump(source, tun, PeerId::new(1)));

        let mut warm = HashSet::new();
        for n in 0..WARM_ROUNDS + ROUNDS {
            let packets = round(n);
            for packet in &packets {
                let mut buf = sink.alloc(packet.len());
                let base = buf.with_headroom_mut().as_ptr() as usize;
                if n < WARM_ROUNDS {
                    warm.insert(base);
                } else {
                    assert!(warm.contains(&base), "round {n} got a new buffer");
                }
                sink.send(fill(buf, packet), PeerId::new(1)).await?;
            }
            expect(&host, &packets).await?;
        }

        drop(sink);
        timeout(WAIT, pumping).await???;
        Ok(())
    }

    #[tokio::test]
    async fn channel_producer_stops_allocating() -> TestResult {
        let (tun, host) = device()?;
        let (source, tx, _mtu) = ChannelSource::new(64, MTU);
        let pool = source.pool();
        let pumping = tokio::spawn(pump(source, tun, PeerId::new(1)));

        let mut warmed = 0;
        for n in 0..WARM_ROUNDS + ROUNDS {
            if n == WARM_ROUNDS {
                warmed = pool.allocated();
            }
            let packets = round(n);
            for packet in &packets {
                tx.send(fill(pool.alloc(packet.len()), packet)).await?;
            }
            expect(&host, &packets).await?;
        }
        assert!(warmed > 0);
        assert_eq!(pool.allocated(), warmed);

        drop(tx);
        let stats = timeout(WAIT, pumping).await???;
        assert_eq!(stats.packets, ((WARM_ROUNDS + ROUNDS) * ROUND) as u64);
        Ok(())
    }
}
