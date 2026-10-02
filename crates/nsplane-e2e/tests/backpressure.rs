//! Per-transport backpressure: a hub on a fast link to `x` and a stallable link to `y`.
//! While `y`'s link stops draining, the hub's traffic to `x` keeps flowing, local packets
//! for `y` are dropped once its backlog is full instead of holding back the source, and
//! removing the stalled transport counts every datagram still queued for it. An engine with
//! a single stalled transport still holds back its source.
//!
//! The stallable link is two `ChannelTransport` pairs joined by a relay in the test: the
//! hub's end, the relay's two ends and `y`'s end. Stalling stops the relay's forwarding from
//! the hub to `y`, so the hub's end fills up while both engines keep running. Unlike
//! suspending `y`'s engine (whose receive task may still complete one read), the relay
//! stops between two datagrams, and what is left in the hub's end can be counted by
//! draining the relay's end afterwards.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane::{
    ChannelTransport, DROP_TRANSMIT_FULL, DROP_TRANSPORT_REMOVED, Ecn, Event, PacketBuf, Path,
    Peer, Transport, TransportId,
};
use nsplane_e2e::{Family, Node, Options, QUIET, TestResult, WAIT, exchange, payload, transfer};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// Nodes of different transport types share one `Node` type, so the harness helpers that
/// link two nodes apply to every pair.
type Any = Box<dyn nsplane::DynTransport>;

/// The id of the link between the hub and `x`.
const FAST: TransportId = TransportId::new(1);
/// The id of the stallable link between the hub and `y`.
const STALL: TransportId = TransportId::new(2);
/// Datagrams each end of the fast link queues.
const FAST_CAPACITY: usize = 1024;
/// Datagrams each end of the stallable link queues.
const STALL_CAPACITY: usize = 16;
/// The hub's queue capacity: each transport's transmit queue and its backlog bound.
const QUEUE: usize = 8;
/// Datagrams a stalled transport can hold in the hub without a drop: its end of the link,
/// its transmit queue, its backlog and the one datagram being sent.
const HELD: u64 = (STALL_CAPACITY + QUEUE + QUEUE + 1) as u64;
/// How much slower than the baseline without a stall the burst to `x` may be while `y` is
/// stalled; generous for scheduling noise.
const SLOWDOWN: u32 = 3;
/// Packets per round of a burst and rounds per burst.
const BURST: usize = 64;
const ROUNDS: usize = 16;
/// Packets the background sender hands to the hub for `y` per millisecond.
const Y_BATCH: usize = 32;

/// The address of the node with key seed `seed` on `transport`.
fn addr(transport: TransportId, seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 * transport.get() + u16::from(seed)))
}

const fn at(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// Makes `a` and `b` peers of each other: `a` reaches `b` on `a_to_b`, `b` reaches `a` on
/// `b_to_a`.
async fn link(a: &Node<Any>, a_to_b: Path, b: &Node<Any>, b_to_a: Path) -> TestResult {
    a.handle
        .add_or_update_peer(Peer {
            path: Some(a_to_b),
            ..b.as_peer(a_to_b.transport)
        })
        .await?;
    b.handle
        .add_or_update_peer(Peer {
            path: Some(b_to_a),
            ..a.as_peer(b_to_a.transport)
        })
        .await?;
    Ok(())
}

/// Forwards datagrams received on `from` to `to` until `stop` fires (between two datagrams)
/// or either end closes.
async fn forward(
    from: Arc<ChannelTransport>,
    to: Arc<ChannelTransport>,
    dest: Path,
    mut stop: oneshot::Receiver<()>,
) {
    let mut buf = PacketBuf::with_capacity(usize::from(u16::MAX));
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            received = from.recv(&mut buf) => {
                if received.is_err() || to.send(buf.as_packet(), &dest).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// The stallable link between the hub (seed 1) and `y` (seed 3), seen from the relay.
struct Relay {
    /// The relay's end facing the hub.
    hub_side: Arc<ChannelTransport>,
    /// The relay's end facing `y`.
    y_side: Arc<ChannelTransport>,
    /// Stops the forwarding from the hub to `y`; `None` while stalled.
    to_y: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
    /// Kept so that the forwarding from `y` to the hub never stops.
    _to_hub: oneshot::Sender<()>,
}

impl Relay {
    /// A relay and the hub's and `y`'s ends of the link, forwarding both ways.
    fn new() -> (Self, ChannelTransport, ChannelTransport) {
        let (hub, y) = (addr(STALL, 1), addr(STALL, 3));
        let (hub_end, hub_side) = ChannelTransport::pair(STALL_CAPACITY, (STALL, hub), (STALL, y));
        let (y_side, y_end) = ChannelTransport::pair(STALL_CAPACITY, (STALL, hub), (STALL, y));
        let (hub_side, y_side) = (Arc::new(hub_side), Arc::new(y_side));
        let (to_hub, stop) = oneshot::channel();
        tokio::spawn(forward(
            Arc::clone(&y_side),
            Arc::clone(&hub_side),
            at(STALL, hub),
            stop,
        ));
        let mut relay = Self {
            hub_side,
            y_side,
            to_y: None,
            _to_hub: to_hub,
        };
        relay.resume();
        (relay, hub_end, y_end)
    }

    /// Stops forwarding from the hub to `y`; returns once the forwarding has stopped.
    async fn stall(&mut self) -> TestResult {
        let (stop, task) = self.to_y.take().ok_or("already stalled")?;
        // The task may have ended already.
        let _ = stop.send(());
        task.await?;
        Ok(())
    }

    /// Forwards from the hub to `y` again.
    fn resume(&mut self) {
        let (stop, signal) = oneshot::channel();
        let task = tokio::spawn(forward(
            Arc::clone(&self.hub_side),
            Arc::clone(&self.y_side),
            at(STALL, addr(STALL, 3)),
            signal,
        ));
        self.to_y = Some((stop, task));
    }

    /// Counts the datagrams left in the hub's end of a stalled link once the hub has
    /// dropped that end.
    async fn drain_closed(&self) -> TestResult<u64> {
        let mut buf = PacketBuf::with_capacity(usize::from(u16::MAX));
        let mut left = 0;
        loop {
            match timeout(WAIT, self.hub_side.recv(&mut buf)).await {
                Ok(Ok(_)) => left += 1,
                Ok(Err(_)) => return Ok(left),
                Err(_) => return Err(format!("hub's end not closed within {WAIT:?}").into()),
            }
        }
    }
}

/// A node with key seed `seed` on `end` only.
fn node(seed: u8, id: TransportId, end: ChannelTransport) -> Node<Any> {
    Node::new(seed, id, addr(id, seed), Box::new(end), Options::default())
}

/// The hub (seed 1) with queue capacity [`QUEUE`] on a fast link to `x` (seed 2) and the
/// relayed link to `y` (seed 3); all peers, both pairs having exchanged traffic.
async fn hub_x_y() -> TestResult<(Node<Any>, Node<Any>, Node<Any>, Relay)> {
    let (hub_fast, x_fast) =
        ChannelTransport::pair(FAST_CAPACITY, (FAST, addr(FAST, 1)), (FAST, addr(FAST, 2)));
    let (relay, hub_stall, y_stall) = Relay::new();
    let mut hub = Node::<Any>::with_builder(1, FAST, addr(FAST, 1), Options::default(), |b| {
        b.queue_capacity(QUEUE)
            .transport(hub_fast)
            .transport(hub_stall)
    })?;
    let mut x = node(2, FAST, x_fast);
    let mut y = node(3, STALL, y_stall);
    link(&hub, x.path, &x, hub.path).await?;
    link(&hub, y.path, &y, at(STALL, addr(STALL, 1))).await?;
    exchange(&mut hub, &mut x).await?;
    exchange(&mut hub, &mut y).await?;
    Ok((hub, x, y, relay))
}

/// A 1300-byte packet from `from` to `to` that carries `seq`.
fn numbered(from: &Node<Any>, to: &Node<Any>, seq: usize) -> Vec<u8> {
    let mut data = payload(1300);
    data[..8].copy_from_slice(&(seq as u64).to_be_bytes());
    from.packet_to(to, Family::V4, &data)
}

/// Sends [`ROUNDS`] rounds of [`BURST`] numbered packets from `hub` to `x`, each round at
/// once and then received, checks that every packet arrives intact and in order, and
/// returns how long it took.
async fn burst(hub: &Node<Any>, x: &mut Node<Any>) -> TestResult<Duration> {
    let start = Instant::now();
    for round in 0..ROUNDS {
        let seqs = round * BURST..(round + 1) * BURST;
        for seq in seqs.clone() {
            hub.send(&numbered(hub, x, seq)).await?;
        }
        for seq in seqs {
            let (_, delivered) = x.expect_delivery().await?;
            if delivered != numbered(hub, x, seq) {
                return Err(format!("packet {seq} lost, changed or out of order").into());
            }
        }
    }
    Ok(start.elapsed())
}

/// Hands `packet` to the engine behind `local` in batches of [`Y_BATCH`] a millisecond
/// until `stop` fires; returns how many packets it handed over.
fn send_continuously(
    local: mpsc::Sender<PacketBuf>,
    packet: Vec<u8>,
) -> (oneshot::Sender<()>, JoinHandle<TestResult<u64>>) {
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut sent = 0;
        loop {
            for _ in 0..Y_BATCH {
                local.send(PacketBuf::from_packet(&packet)).await?;
                sent += 1;
            }
            tokio::select! {
                biased;
                _ = &mut stopped => return Ok(sent),
                () = sleep(Duration::from_millis(1)) => {}
            }
        }
    });
    (stop, task)
}

/// Hands `count` packets to `node` from a task; returns the task.
fn send_all(node: &Node<Any>, packet: &[u8], count: u64) -> JoinHandle<TestResult> {
    let local = node.local.clone();
    let packet = packet.to_vec();
    tokio::spawn(async move {
        for _ in 0..count {
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        Ok(())
    })
}

#[tokio::test]
async fn stalled_transport_does_not_slow_other_peers() -> TestResult {
    let (hub, mut x, y, mut relay) = hub_x_y().await?;
    let baseline = burst(&hub, &mut x).await?;

    relay.stall().await?;
    let (stop, sender) = send_continuously(
        hub.local.clone(),
        hub.packet_to(&y, Family::V4, &payload(64)),
    );
    let stalled = burst(&hub, &mut x).await?;
    // The sender was never held back: it stops when asked.
    let _ = stop.send(());
    let sent = timeout(WAIT, sender).await???;

    assert!(
        stalled <= baseline * SLOWDOWN,
        "burst to x took {stalled:?} with y stalled, baseline {baseline:?}"
    );
    // The source queue is first in, first out: once this packet arrives, the hub has
    // handled every packet for `y`.
    transfer(&hub, &mut x, Family::V4, 64).await?;
    let drops = hub.drops(DROP_TRANSMIT_FULL).await?;
    assert!(drops > 0, "no drops for the stalled transport");
    assert!(
        drops >= sent.saturating_sub(HELD),
        "{drops} drops of {sent} packets for y: more than {HELD} held"
    );
    Ok(())
}

#[tokio::test]
async fn removed_transport_counts_queued_datagrams() -> TestResult {
    let (mut hub, mut x, y, mut relay) = hub_x_y().await?;
    relay.stall().await?;

    // Enough to fill the link, the transmit queue and the backlog, and then some.
    let sent = 2 * HELD;
    let packet = hub.packet_to(&y, Family::V4, &payload(64));
    send_all(&hub, &packet, sent).await??;
    transfer(&hub, &mut x, Family::V4, 64).await?;
    let full = hub.drops(DROP_TRANSMIT_FULL).await?;
    assert!(full > 0, "the backlog never filled");

    let mut events = hub.subscribe().await?;
    hub.handle.remove_transport(STALL).await?;
    let removed = hub.drops(DROP_TRANSPORT_REMOVED).await?;
    assert!(removed > 0, "nothing was queued for the removed transport");
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_TRANSPORT_REMOVED))
        .await?;

    // With an established session every local packet for `y` became exactly one datagram
    // (no timer is due this early), and nothing was forwarded to `y` since the stall. Each
    // datagram was then dropped while its backlog was full, dropped by the removal (being
    // sent, in the transmit queue or in the backlog), or is left in the hub's end of the
    // link, which the removal closed.
    let left = relay.drain_closed().await?;
    assert_eq!(
        sent,
        full + removed + left,
        "full {full}, removed {removed}, left {left}"
    );

    exchange(&mut hub, &mut x).await?;
    Ok(())
}

#[tokio::test]
async fn single_stalled_transport_holds_back_the_source() -> TestResult {
    let (mut relay, hub_stall, y_stall) = Relay::new();
    let mut hub = Node::<Any>::with_builder(1, STALL, addr(STALL, 1), Options::default(), |b| {
        b.queue_capacity(QUEUE).transport(hub_stall)
    })?;
    let mut y = node(3, STALL, y_stall);
    link(&hub, y.path, &y, hub.path).await?;
    exchange(&mut hub, &mut y).await?;
    relay.stall().await?;

    // More than the source queue and everything the stalled transport holds: the sender
    // has to wait.
    let count = 2048;
    let packets: Vec<_> = (0..count).map(|seq| numbered(&hub, &y, seq)).collect();
    let local = hub.local.clone();
    let mut sender = tokio::spawn({
        let packets = packets.clone();
        async move {
            for packet in &packets {
                local.send(PacketBuf::from_packet(packet)).await?;
            }
            TestResult::Ok(())
        }
    });
    assert!(
        timeout(QUIET, &mut sender).await.is_err(),
        "the sender was not held back"
    );
    assert_eq!(hub.drops(DROP_TRANSMIT_FULL).await?, 0);

    relay.resume();
    for (seq, packet) in packets.iter().enumerate() {
        let (_, delivered) = y.expect_delivery().await?;
        if delivered != *packet {
            return Err(format!("packet {seq} lost, changed or out of order").into());
        }
    }
    timeout(WAIT, sender).await???;
    assert_eq!(hub.drops(DROP_TRANSMIT_FULL).await?, 0);
    Ok(())
}
