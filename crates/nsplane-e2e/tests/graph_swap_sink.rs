//! A sink replaced per generation with cancel: an engine's sink is a
//! `SwapSink<AbortSink<ChannelSink>>`, as ns's exit encrypt sender is.
//!
//! Engine A receives packets from peer X over a `ChannelTransport`. Its sink starts empty,
//! then gets generation 1, a small channel nobody drains, so a delivery gets stuck on it.
//! Generation 2 replaces it and generation 1 is aborted: the engine keeps running, later
//! packets arrive at generation 2 in order, nothing more reaches generation 1, and the drop
//! counters account for every packet sent.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AbortSink, AllowedIp, ChannelSink, ChannelSource, ChannelTransport, DROP_SINK_CLOSED, Ecn,
    EngineBuilder, Event, PacketBuf, Path, Peer, PeerId, SwapSink, TransportId,
};
use nsplane_e2e::{Node, Options, QUIET, TestResult, WAIT, udp};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

/// Capacity of the link, the local source and generation 2's channel.
const CAPACITY: usize = 1024;
/// MTU of A's local side.
const MTU: u16 = 1420;
/// Capacity of generation 1's channel, which nobody drains.
const GEN1_CAPACITY: usize = 2;
/// Packets sent while the sink is empty, while generation 1 is installed, and after the
/// switch to generation 2.
const EMPTY: usize = 4;
const STUCK: usize = 8;
const AFTER: usize = 8;
/// Key seeds of peer X and engine A; their tunnel addresses are `10.0.0.<seed>`.
const X_SEED: u8 = 1;
const A_SEED: u8 = 2;
const X_PATH: (TransportId, SocketAddr) = (
    TransportId::new(1),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000),
);
const A_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);

type Generation = AbortSink<ChannelSink>;

const fn tunnel(seed: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, seed)
}

/// A UDP packet between the tunnel addresses of `from` and `to`.
fn packet(from: u8, to: u8, payload: &str) -> Vec<u8> {
    udp(
        SocketAddr::new(IpAddr::V4(tunnel(from)), 5000),
        SocketAddr::new(IpAddr::V4(tunnel(to)), 5000),
        payload.as_bytes(),
    )
}

/// The `i`th packet X sends to A.
fn numbered(i: usize) -> Vec<u8> {
    packet(X_SEED, A_SEED, &format!("packet {i}"))
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([seed; 32]))
}

/// Engine A as a peer reached over X's link, with every IPv4 address routed to it.
fn gateway() -> Peer {
    Peer {
        allowed_ips: vec![AllowedIp {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            cidr: 0,
        }],
        path: Some(Path {
            transport: X_PATH.0,
            addr: A_PATH.1,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(public(A_SEED))
    }
}

/// The index of a packet [`numbered`] built, read off its delivery.
fn index(delivered: &(PeerId, PacketBuf), sent: &[Vec<u8>]) -> TestResult<usize> {
    let bytes = delivered.1.as_packet();
    sent.iter()
        .position(|packet| packet[..] == *bytes)
        .ok_or_else(|| "unknown packet delivered".into())
}

/// Waits until `done` holds, polling.
async fn until(mut done: impl FnMut() -> bool) -> TestResult {
    timeout(WAIT, async {
        while !done() {
            sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

/// Whether `events` holds a drop counted under [`DROP_SINK_CLOSED`].
fn sink_closed(events: &mut broadcast::Receiver<Event>) -> bool {
    loop {
        match events.try_recv() {
            Ok(Event::Dropped { reason, .. }) if reason == DROP_SINK_CLOSED => return true,
            Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => return false,
        }
    }
}

/// Generation 1 gets stuck on its full channel, generation 2 replaces it and generation 1
/// is aborted: no packet is lost uncounted and the engine carries on.
#[tokio::test]
async fn sink_replaced_per_generation_with_cancel() -> TestResult {
    let swap = SwapSink::<Generation>::new(None);
    let (source, tun_in, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (link_x, link_a) = ChannelTransport::pair(CAPACITY, X_PATH, A_PATH);
    let mut x = Node::new(X_SEED, X_PATH.0, X_PATH.1, link_x, Options::default());
    let a = EngineBuilder::new(source, swap.clone())
        .private_key(StaticSecret::from([A_SEED; 32]))
        .transport(link_a)
        .build()?;
    a.handle().add_or_update_peer(x.as_peer(A_PATH.0)).await?;
    x.handle.add_or_update_peer(gateway()).await?;
    let mut events = a.handle().subscribe().await?;
    let sent: Vec<_> = (0..EMPTY + STUCK + AFTER).map(numbered).collect();

    // No generation yet: every packet is dropped and counted.
    for packet in &sent[..EMPTY] {
        x.send(packet).await?;
    }
    until(|| swap.dropped() == EMPTY as u64).await?;

    // Generation 1 takes two packets, then the delivery of the third waits on it.
    let (sink1, mut rx1) = ChannelSink::new(GEN1_CAPACITY);
    let (gen1, abort1) = AbortSink::new(sink1);
    assert!(swap.replace(Some(gen1)).is_none());
    for packet in &sent[EMPTY..EMPTY + STUCK] {
        x.send(packet).await?;
    }
    until(|| rx1.len() == GEN1_CAPACITY).await?;
    sleep(QUIET).await;

    // Generation 2 replaces it, and generation 1's stuck delivery is cancelled.
    let (sink2, mut rx2) = ChannelSink::new(CAPACITY);
    let (gen2, abort2) = AbortSink::new(sink2);
    let gen1 = swap.replace(Some(gen2)).ok_or("no generation 1")?;
    abort1.abort();
    for packet in &sent[EMPTY + STUCK..] {
        x.send(packet).await?;
    }

    // Generation 2 gets the stuck packets the engine had not handed over yet, then every
    // later one, in order.
    let last = sent.len() - 1;
    let mut at_gen2 = Vec::new();
    while at_gen2.last() != Some(&last) {
        let delivered = timeout(WAIT, rx2.recv())
            .await?
            .ok_or("generation 2 closed")?;
        at_gen2.push(index(&delivered, &sent)?);
    }
    assert!(at_gen2.is_sorted(), "out of order: {at_gen2:?}");
    assert!(
        at_gen2.ends_with(&(EMPTY + STUCK..sent.len()).collect::<Vec<_>>()),
        "later packets missing: {at_gen2:?}"
    );

    // Generation 1 holds the two it took, and nothing arrives once it has room again.
    let mut at_gen1 = Vec::new();
    while let Ok(delivered) = rx1.try_recv() {
        at_gen1.push(index(&delivered, &sent)?);
    }
    assert_eq!(at_gen1, [EMPTY, EMPTY + 1]);
    assert!(
        timeout(QUIET, rx1.recv()).await.is_err(),
        "delivered after abort"
    );
    assert!(rx2.is_empty());

    // Every packet sent is delivered or counted.
    assert!(gen1.dropped() >= 1, "no stuck delivery was cancelled");
    assert_eq!(swap.dropped(), EMPTY as u64);
    assert_eq!(
        (at_gen1.len() + at_gen2.len()) as u64 + gen1.dropped() + swap.dropped(),
        sent.len() as u64
    );

    // The engine keeps running: it never took the local side for gone, it still sends,
    // and it still delivers to generation 2.
    assert!(
        !sink_closed(&mut events),
        "a delivery counted as sink closed"
    );
    assert!(!abort2.is_aborted());
    let outbound = packet(A_SEED, X_SEED, "still running");
    tun_in.send(PacketBuf::from_packet(&outbound)).await?;
    let (_, delivered) = x.expect_delivery().await?;
    assert_eq!(delivered, outbound);
    let inbound = numbered(sent.len());
    x.send(&inbound).await?;
    let (_, delivered) = timeout(WAIT, rx2.recv())
        .await?
        .ok_or("generation 2 closed")?;
    assert_eq!(delivered.as_packet(), inbound);
    Ok(())
}
