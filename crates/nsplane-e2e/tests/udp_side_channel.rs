//! Two engines over [`UdpTransport`]s on the loopback interface, each transport with a side
//! channel for datagrams starting with [`PREFIX`], with segmentation offload on and off:
//! side datagrams sent both ways on the same sockets while WireGuard traffic flows arrive at
//! the other side's receiver from the right address, never reach an engine, and leave the
//! transfer intact. A side receiver that is never read drops what it cannot hold and counts
//! it.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use nsplane::{SideDatagram, SideSender, SideStats, TransportId, TransportStats, UdpTransport};
use nsplane_e2e::{Family, Node, Options, TestResult, WAIT, introduce, payload, transfer};
use nsplane_packet::PacketBuf;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

/// What the side channels take.
const PREFIX: &[u8] = b"NSGWP2P1";
/// Rounds of the mixed exchange.
const ROUNDS: u64 = 8;
/// Packets per direction and round, sent at once so their datagrams form trains.
const BURST: u64 = 32;
/// Side datagrams per direction and round, sent in the middle of the burst.
const SIDES: u64 = 4;

fn classify(datagram: &[u8]) -> bool {
    datagram.starts_with(PREFIX)
}

/// A node with key seed `seed` on a UDP transport bound to the IPv4 loopback address with
/// offload `offload`, with a side channel of `capacity`.
fn node(
    seed: u8,
    offload: bool,
    capacity: usize,
) -> io::Result<(Node<UdpTransport>, SideSender, mpsc::Receiver<SideDatagram>)> {
    let id = TransportId::new(u16::from(seed));
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let transport = UdpTransport::bind_with_offload(id, addr, offload)?;
    let addr = transport.local_addr();
    let (transport, sender, rx) = transport.with_side_channel(classify, capacity);
    Ok((
        Node::new(seed, id, addr, transport, Options::default()),
        sender,
        rx,
    ))
}

/// Side datagram `seq` from `seed`.
fn side_datagram(seed: u8, seq: u64) -> Vec<u8> {
    [PREFIX, &[seed], &seq.to_be_bytes()].concat()
}

/// The engine's counters of `node`'s own transport.
async fn transport_stats(node: &Node<UdpTransport>) -> TestResult<TransportStats> {
    node.handle
        .transport_stats()
        .await?
        .into_iter()
        .find(|stats| stats.id == node.path.transport)
        .ok_or_else(|| "unknown transport".into())
}

/// Fails if `node` counted any drop.
async fn expect_no_drops(node: &Node<UdpTransport>) -> TestResult {
    let counters = node.handle.drop_counters().await?;
    let dropped: Vec<_> = counters.iter().filter(|(_, count)| **count > 0).collect();
    if !dropped.is_empty() {
        return Err(format!("drops counted: {dropped:?}").into());
    }
    Ok(())
}

/// Receives `expected` at `node`, in order.
async fn collect(node: &mut Node<UdpTransport>, expected: &[Vec<u8>]) -> TestResult {
    for (at, packet) in expected.iter().enumerate() {
        match timeout(WAIT, node.delivered.recv()).await {
            Ok(Some((_, delivered))) if delivered.as_packet() == packet.as_slice() => {}
            Ok(Some(_)) => return Err(format!("packet {at} changed, lost or out of order").into()),
            Ok(None) => return Err("sink closed".into()),
            Err(_) => return Err(format!("packet {at} missing after {WAIT:?}").into()),
        }
    }
    Ok(())
}

/// Receives the side datagrams of `seed` numbered `0..count` at `rx`, in order, from `from`.
async fn collect_side(
    rx: &mut mpsc::Receiver<SideDatagram>,
    seed: u8,
    count: u64,
    from: SocketAddr,
) -> TestResult {
    for seq in 0..count {
        let side = timeout(WAIT, rx.recv())
            .await
            .map_err(|_| format!("side datagram {seq} missing after {WAIT:?}"))?
            .ok_or("side channel closed")?;
        if side.from != from || side.datagram != side_datagram(seed, seq) {
            return Err(format!("side datagram {seq}: got one from {}", side.from).into());
        }
    }
    Ok(())
}

async fn side_channel_beside_wireguard(offload: bool) -> TestResult {
    let capacity = usize::try_from(ROUNDS * SIDES)?;
    let (mut a, a_sender, mut a_rx) = node(1, offload, capacity)?;
    let (mut b, b_sender, mut b_rx) = node(2, offload, capacity)?;
    assert_eq!(a_sender.local_addr(), a.path.addr);
    introduce(&a, &b, None).await?;
    // The handshake first, so no packet waits for it.
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;

    for round in 0..ROUNDS {
        let packets = |from: &Node<UdpTransport>, to: &Node<UdpTransport>| -> Vec<_> {
            (0..BURST)
                .map(|seq| {
                    let mut data = payload(1300);
                    data[..8].copy_from_slice(&(round * BURST + seq).to_be_bytes());
                    from.packet_to(to, Family::V4, &data)
                })
                .collect()
        };
        let (to_b, to_a) = (packets(&a, &b), packets(&b, &a));
        for ((to_b, to_a), seq) in to_b.iter().zip(&to_a).zip(0..) {
            a.local.send(PacketBuf::from_packet(to_b)).await?;
            b.local.send(PacketBuf::from_packet(to_a)).await?;
            if seq == BURST / 2 {
                for side in round * SIDES..(round + 1) * SIDES {
                    a_sender.send_to(&side_datagram(1, side), b.path.addr)?;
                    b_sender.send_to(&side_datagram(2, side), a.path.addr)?;
                }
            }
        }
        collect(&mut b, &to_b).await?;
        collect(&mut a, &to_a).await?;
    }
    collect_side(&mut b_rx, 1, ROUNDS * SIDES, a.path.addr).await?;
    collect_side(&mut a_rx, 2, ROUNDS * SIDES, b.path.addr).await?;
    let all = SideStats {
        received: ROUNDS * SIDES,
        dropped: 0,
    };
    assert_eq!((a_sender.stats(), b_sender.stats()), (all, all));

    // No side datagram reached an engine: each received exactly what the other sent.
    for (node, peer) in [(&a, &b), (&b, &a)] {
        let deadline = Instant::now() + WAIT;
        loop {
            let rx = transport_stats(node).await?.rx_datagrams;
            let tx = transport_stats(peer).await?.tx_datagrams;
            if rx == tx {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!("{tx} datagrams sent, {rx} received").into());
            }
            sleep(WAIT / 50).await;
        }
        expect_no_drops(node).await?;
    }
    Ok(())
}

#[tokio::test]
async fn side_channel_beside_wireguard_offload_on() -> TestResult {
    side_channel_beside_wireguard(true).await
}

#[tokio::test]
async fn side_channel_beside_wireguard_offload_off() -> TestResult {
    side_channel_beside_wireguard(false).await
}

/// Side datagrams sent to a receiver of capacity 1 that is never read.
const UNREAD: u64 = 16;

async fn unread_side_receiver(offload: bool) -> TestResult {
    let (_a, a_sender, _a_rx) = node(1, offload, 1)?;
    let (b, b_sender, _b_rx) = node(2, offload, 1)?;
    for seq in 0..UNREAD {
        a_sender.send_to(&side_datagram(1, seq), b.path.addr)?;
    }
    let deadline = Instant::now() + WAIT;
    let stats = loop {
        let stats = b_sender.stats();
        if stats.received + stats.dropped == UNREAD {
            break stats;
        }
        if Instant::now() > deadline {
            return Err(format!("{UNREAD} side datagrams sent, counted {stats:?}").into());
        }
        sleep(WAIT / 50).await;
    };
    assert_eq!(
        stats,
        SideStats {
            received: 1,
            dropped: UNREAD - 1
        }
    );
    let rx = transport_stats(&b).await?.rx_datagrams;
    assert_eq!(rx, 0, "no side datagram reached the engine");
    expect_no_drops(&b).await
}

#[tokio::test]
async fn unread_side_receiver_offload_on() -> TestResult {
    unread_side_receiver(true).await
}

#[tokio::test]
async fn unread_side_receiver_offload_off() -> TestResult {
    unread_side_receiver(false).await
}
